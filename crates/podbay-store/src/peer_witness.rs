//! Fresh read-only owner-epoch evidence for one bound pod identity.
//! A shared OS account or copied SQLite file is not hostile-peer isolation.
use std::path::{Path, PathBuf};
use std::time::Duration;

use podbay_core::{OwnerEpoch, OwnerEpochWitness, PodFenceIdentity, ScopeId, StoreLineageId};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

/// Each trait invocation opens a new read-only SQLite connection and reads one
/// committed WAL snapshot. No migration, manager writer lock, or cached epoch.
pub struct SqliteOwnerEpochWitness {
    database: PathBuf,
    identity: PodFenceIdentity,
}

impl SqliteOwnerEpochWitness {
    /// `identity` must be the pod's trusted persisted identity, not fields
    /// copied from an incoming control request.
    pub fn for_pod(database: impl AsRef<Path>, identity: PodFenceIdentity) -> Self {
        Self {
            database: database.as_ref().to_path_buf(),
            identity,
        }
    }

    fn open_read_only(&self) -> Option<Connection> {
        let connection =
            Connection::open_with_flags(&self.database, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
        connection.busy_timeout(Duration::from_millis(250)).ok()?;
        Some(connection)
    }

    fn fresh_lookup(&self) -> Option<OwnerEpoch> {
        let mut connection = self.open_read_only()?;
        // DEFERRED is a read snapshot. It does not take the manager's IMMEDIATE
        // writer lock; every SELECT below sees one committed revision.
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .ok()?;
        crate::store::verify_current_read_only_schema(&transaction).ok()?;
        let lineage: String = transaction
            .query_row(
                "SELECT lineage FROM store_identity WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .ok()?;
        if lineage != self.identity.store_lineage.as_str() {
            return None;
        }
        let owner: i64 = transaction
            .query_row(
                "SELECT value FROM metadata WHERE key='owner_epoch'",
                [],
                |row| row.get(0),
            )
            .ok()?;
        if owner <= 0 {
            return None;
        }
        let registered: Option<i64> = transaction
            .query_row(
                "SELECT incarnation FROM authority_pods WHERE scope_id=?1 AND pod_id=?2",
                params![
                    self.identity.scope_id.as_str(),
                    self.identity.pod_id.as_str()
                ],
                |row| row.get(0),
            )
            .optional()
            .ok()?;
        let target: Option<i64> = transaction
            .query_row(
                "SELECT epoch FROM target_epochs WHERE scope_id=?1 AND target_id=?2",
                params![
                    self.identity.scope_id.as_str(),
                    self.identity.pod_id.as_str()
                ],
                |row| row.get(0),
            )
            .optional()
            .ok()?;
        let incarnation = i64::try_from(self.identity.incarnation.get()).ok()?;
        if registered != Some(incarnation) || target != Some(incarnation) {
            return None;
        }
        transaction.commit().ok()?;
        OwnerEpoch::new(u64::try_from(owner).ok()?).ok()
    }
}

impl OwnerEpochWitness for SqliteOwnerEpochWitness {
    fn current_owner_epoch(&self, lineage: &StoreLineageId, scope: &ScopeId) -> Option<OwnerEpoch> {
        if lineage != &self.identity.store_lineage || scope != &self.identity.scope_id {
            return None;
        }
        self.fresh_lookup()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn adapter_opens_sqlite_without_write_capability() {
        let path = std::env::temp_dir().join(format!("podbay-witness-ro-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        Connection::open(&path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE marker(id INTEGER PRIMARY KEY); INSERT INTO marker VALUES(1);",
            )
            .unwrap();
        let identity = PodFenceIdentity {
            scope_id: ScopeId::try_from("scope.fixture").unwrap(),
            pod_id: podbay_core::PodId::try_from("pod.fixture").unwrap(),
            attempt_id: podbay_core::AttemptId::try_from("attempt.fixture").unwrap(),
            incarnation: podbay_core::Epoch::new(1).unwrap(),
            store_lineage: StoreLineageId::try_from("store.fixture").unwrap(),
        };
        let witness = SqliteOwnerEpochWitness::for_pod(&path, identity);
        let connection = witness.open_read_only().unwrap();
        assert!(
            connection
                .execute("INSERT INTO marker VALUES(2)", [])
                .is_err()
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM marker", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        drop(connection);
        std::fs::remove_file(path).unwrap();
    }
}
