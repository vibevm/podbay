//! One consistent passive snapshot. Rows are trusted-host assertions, not
//! signature replay, signing-time evidence, physical proof or a live grant.
#![allow(dead_code)]
use super::*;
use rusqlite::{Row, types::ValueRef};

const VERSION: u8 = 1;
const MAX_ROWS: usize = 4096;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HistoricalOwnerSnapshotV1 {
    pub(crate) version: u8,
    pub(crate) lineage: String,
    pub(crate) owner_epoch: u64,
    pub(crate) authority_revision: u64,
    pub(crate) actor: AuthorityActorRecord,
    pub(crate) verifier_version: String,
    pub(crate) public_key: [u8; 32],
    pub(crate) binding_digest: [u8; 32],
    pub(crate) revoked: bool,
    pub(crate) rotations: Vec<HistoricalRotationV1>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HistoricalRotationV1 {
    pub(crate) scope: String,
    pub(crate) actor: String,
    pub(crate) rotation_key: String,
    pub(crate) intent_digest: [u8; 32],
    pub(crate) prior_generation: u64,
    pub(crate) next_generation: u64,
    pub(crate) prior_binding: [u8; 32],
    pub(crate) prior_key: [u8; 32],
    pub(crate) next_binding: [u8; 32],
    pub(crate) next_key: [u8; 32],
    pub(crate) owner_epoch: u64,
    pub(crate) authority_revision: u64,
    pub(crate) prior_revoked: bool,
}
fn bad() -> rusqlite::Error {
    rusqlite::Error::InvalidQuery
}
fn text(row: &Row<'_>, column: usize, max: usize) -> rusqlite::Result<String> {
    let ValueRef::Text(bytes) = row.get_ref(column)? else {
        return Err(bad());
    };
    if bytes.is_empty() || bytes.len() > max || bytes.iter().any(|b| b.is_ascii_control()) {
        return Err(bad());
    }
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| bad())
}
fn positive(row: &Row<'_>, column: usize) -> rusqlite::Result<u64> {
    let ValueRef::Integer(value) = row.get_ref(column)? else {
        return Err(bad());
    };
    u64::try_from(value).ok().filter(|v| *v > 0).ok_or_else(bad)
}
fn boolean(row: &Row<'_>, column: usize) -> rusqlite::Result<bool> {
    match row.get_ref(column)? {
        ValueRef::Integer(0) => Ok(false),
        ValueRef::Integer(1) => Ok(true),
        _ => Err(bad()),
    }
}
fn blob(row: &Row<'_>, column: usize) -> rusqlite::Result<[u8; 32]> {
    let ValueRef::Blob(bytes) = row.get_ref(column)? else {
        return Err(bad());
    };
    let value: [u8; 32] = bytes.try_into().map_err(|_| bad())?;
    if value == [0; 32] {
        return Err(bad());
    }
    Ok(value)
}
fn hex(row: &Row<'_>, column: usize) -> rusqlite::Result<[u8; 32]> {
    let value = text(row, column, 64)?;
    if value.len() != 64 {
        return Err(bad());
    }
    let mut out = [0; 32];
    for (i, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let digit = |b| match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err(bad()),
        };
        out[i] = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    if out == [0; 32] {
        return Err(bad());
    }
    Ok(out)
}

impl PodBayStore {
    pub(crate) fn read_historical_owner_snapshot_v1(
        &mut self,
        lineage: &str,
        actor: &str,
        scope: &str,
    ) -> Result<HistoricalOwnerSnapshotV1, StoreError> {
        self.read_historical_owner_snapshot_using(lineage, actor, scope, || Ok(()))
    }
    fn read_historical_owner_snapshot_using(
        &mut self,
        lineage: &str,
        actor: &str,
        scope: &str,
        after_current: impl FnOnce() -> Result<(), StoreError>,
    ) -> Result<HistoricalOwnerSnapshotV1, StoreError> {
        valid_identity(lineage)?;
        valid_identity(actor)?;
        valid_identity(scope)?;
        if !self.connection.is_readonly("main")? {
            return Err(StoreError::Conflict(
                "historical snapshot requires read-only handle",
            ));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        crate::store::verify_current_read_only_schema(&tx)?;
        let (actual,owner_epoch,authority_revision)=tx.query_row("SELECT (SELECT lineage FROM store_identity WHERE singleton=1),(SELECT value FROM metadata WHERE key='owner_epoch'),(SELECT value FROM metadata WHERE key='authority_revision')",[],|r|Ok((text(r,0,256)?,positive(r,1)?,positive(r,2)?)))?;
        if actual != lineage || actual != self.store_lineage {
            return Err(StoreError::WrongScope);
        }
        let current=tx.query_row("SELECT scope_id,role,origin,parent_actor_id,pod_id,pod_incarnation,credential_generation,platform,os_identity,process_identity,start_identity,containment_identity FROM authority_actors WHERE actor_id=?1",[actor],|r|{
            if !matches!(r.get_ref(3)?,ValueRef::Null)||!matches!(r.get_ref(4)?,ValueRef::Null)||!matches!(r.get_ref(5)?,ValueRef::Null){return Err(bad());}
            Ok(AuthorityActorRecord{actor_id:actor.into(),scope_id:text(r,0,256)?,role:text(r,1,256)?,origin:text(r,2,256)?,parent_actor_id:None,pod_id:None,pod_incarnation:None,credential_generation:positive(r,6)?,platform:text(r,7,256)?,os_identity:text(r,8,256)?,process_identity:text(r,9,256)?,start_identity:positive(r,10)?,containment_identity:text(r,11,4096)?})
        })?;
        if current.scope_id != scope
            || current.role != "coordinator"
            || current.origin != "owner_cli"
            || current.platform != "linux"
        {
            return Err(StoreError::WrongScope);
        }
        let (verifier_scope,generation,verifier_version,public_key,binding_digest,revoked)=tx.query_row("SELECT scope_id,credential_generation,verifier_version,public_key,binding_digest,revoked FROM actor_verifiers WHERE actor_id=?1",[actor],|r|Ok((text(r,0,256)?,positive(r,1)?,text(r,2,256)?,blob(r,3)?,blob(r,4)?,boolean(r,5)?)))?;
        if verifier_scope != scope
            || generation != current.credential_generation
            || verifier_version != ACTOR_VERIFIER_VERSION
            || binding_digest != actor_binding_digest(&current)
        {
            return Err(StoreError::Conflict("historical verifier binding differs"));
        }
        after_current()?;
        let rotations = {
            let mut statement=tx.prepare("SELECT scope_id,actor_id,rotation_key,intent_digest,prior_generation,next_generation,prior_binding_digest,prior_public_key,next_binding_digest,next_public_key,owner_epoch,authority_revision,prior_revoked FROM owner_actor_rotations WHERE actor_id=?1 ORDER BY next_generation LIMIT 4097")?;
            let rows = statement.query_map([actor], |r| {
                Ok(HistoricalRotationV1 {
                    scope: text(r, 0, 256)?,
                    actor: text(r, 1, 256)?,
                    rotation_key: text(r, 2, 256)?,
                    intent_digest: hex(r, 3)?,
                    prior_generation: positive(r, 4)?,
                    next_generation: positive(r, 5)?,
                    prior_binding: blob(r, 6)?,
                    prior_key: blob(r, 7)?,
                    next_binding: blob(r, 8)?,
                    next_key: blob(r, 9)?,
                    owner_epoch: positive(r, 10)?,
                    authority_revision: positive(r, 11)?,
                    prior_revoked: boolean(r, 12)?,
                })
            })?;
            let mut captured = Vec::new();
            for row in rows {
                let row = row?;
                if captured.len() == MAX_ROWS {
                    return Err(StoreError::Conflict("historical rotation row bound"));
                }
                if row.scope != scope || row.actor != actor {
                    return Err(StoreError::WrongScope);
                }
                if row.prior_generation.checked_add(1) != Some(row.next_generation)
                    || !row.prior_revoked
                {
                    return Err(StoreError::Conflict("historical rotation shape differs"));
                }
                captured.push(row);
            }
            captured
        };
        tx.commit()?;
        Ok(HistoricalOwnerSnapshotV1 {
            version: VERSION,
            lineage: actual,
            owner_epoch,
            authority_revision,
            actor: current,
            verifier_version,
            public_key,
            binding_digest,
            revoked,
            rotations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    struct Fixture {
        directory: PathBuf,
        path: PathBuf,
        writer: PodBayStore,
        actor: AuthorityActorRecord,
        lineage: String,
        revision: u64,
    }
    impl Fixture {
        fn new() -> Self {
            let directory = std::env::temp_dir().join(format!(
                "podbay-private-historical-snapshot-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&directory).unwrap();
            let path = directory.join("store.sqlite");
            let mut writer = PodBayStore::open(&path).unwrap();
            let snapshot = writer.begin_authority_replay(0, 1).unwrap();
            let actor = AuthorityActorRecord {
                scope_id: "scope.main".into(),
                actor_id: "actor.owner".into(),
                role: "coordinator".into(),
                origin: "owner_cli".into(),
                parent_actor_id: None,
                pod_id: None,
                pod_incarnation: None,
                credential_generation: 1,
                platform: "linux".into(),
                os_identity: "linux.uid.1000".into(),
                process_identity: "linux.pid.123".into(),
                start_identity: 456,
                containment_identity: "/user.slice/fixture.scope".into(),
            };
            let revision = writer
                .apply_authority_mutation(
                    1,
                    snapshot.revision,
                    AuthorityMutation::PutActor(actor.clone()),
                )
                .unwrap();
            let revision = writer
                .register_actor_verifier_from_trusted_host(1, revision, &actor, [7; 32])
                .unwrap();
            let lineage = writer.store_lineage.clone();
            Self {
                directory,
                path,
                writer,
                actor,
                lineage,
                revision,
            }
        }
        fn rotate(&mut self) {
            let mut next = self.actor.clone();
            next.credential_generation += 1;
            next.process_identity = format!("linux.pid.{}", 123 + next.credential_generation);
            next.start_identity += 1;
            let proof = TrustedOwnerRotationProof {
                store_lineage: self.lineage.clone(),
                expected_owner_epoch: 1,
                expected_revision: self.revision,
                rotation_key: format!("rotation.{}", next.credential_generation),
                expected_actor: self.actor.clone(),
                expected_public_key: if self.actor.credential_generation == 1 {
                    [7; 32]
                } else {
                    [self.actor.credential_generation as u8; 32]
                },
                next_actor: next.clone(),
                next_public_key: [next.credential_generation as u8; 32],
            };
            self.revision = self
                .writer
                .rotate_owner_actor_from_trusted_host(&proof)
                .unwrap()
                .authority_revision;
            self.actor = next;
        }
        fn observer(&self) -> PodBayStore {
            PodBayStore::open_existing_read_only(&self.path).unwrap()
        }
        fn capture(
            &self,
            store: &mut PodBayStore,
        ) -> Result<HistoricalOwnerSnapshotV1, StoreError> {
            store.read_historical_owner_snapshot_v1(
                &self.lineage,
                &self.actor.actor_id,
                &self.actor.scope_id,
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
    #[test]
    fn repeated_reads_are_passive_and_capture_initial_and_rotated_rows() {
        let mut f = Fixture::new();
        let mut reader = f.observer();
        let initial = f.capture(&mut reader).unwrap();
        assert_eq!(initial.actor.credential_generation, 1);
        assert!(initial.rotations.is_empty());
        f.rotate();
        f.rotate();
        f.writer
            .connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        let before = fs::read(&f.path).unwrap();
        let expected = f.capture(&mut reader).unwrap();
        assert_eq!(expected.rotations.len(), 2);
        assert_eq!(expected.actor.credential_generation, 3);
        for _ in 0..3 {
            assert_eq!(f.capture(&mut reader).unwrap(), expected);
        }
        assert_eq!(fs::read(&f.path).unwrap(), before);
        assert_eq!(f.writer.owner_epoch().unwrap(), 1);
        assert_eq!(
            f.writer.authority_snapshot().unwrap().revision,
            expected.authority_revision
        );
    }
    #[test]
    fn writer_foreign_schema_and_malformed_rows_refuse() {
        let mut f = Fixture::new();
        assert!(
            f.writer
                .read_historical_owner_snapshot_v1(&f.lineage, &f.actor.actor_id, &f.actor.scope_id)
                .is_err()
        );
        let mut reader = f.observer();
        assert!(
            reader
                .read_historical_owner_snapshot_v1("foreign", &f.actor.actor_id, &f.actor.scope_id)
                .is_err()
        );
        assert!(
            reader
                .read_historical_owner_snapshot_v1(&f.lineage, &f.actor.actor_id, "foreign")
                .is_err()
        );
        for sql in [
            "UPDATE metadata SET value=-1 WHERE key='owner_epoch'",
            "UPDATE actor_verifiers SET public_key=zeroblob(31)",
            "UPDATE actor_verifiers SET revoked=2",
            "UPDATE authority_actors SET start_identity=-1",
            "PRAGMA user_version=25",
        ] {
            let f = Fixture::new();
            let mut reader = f.observer();
            f.writer
                .connection
                .execute_batch("PRAGMA ignore_check_constraints=ON")
                .unwrap();
            f.writer.connection.execute_batch(sql).unwrap();
            assert!(f.capture(&mut reader).is_err(), "{sql}");
        }
    }
    #[test]
    fn foreign_scope_invalid_hash_and_oversized_history_refuse() {
        for case in ["scope", "hash", "rows"] {
            let mut f = Fixture::new();
            f.rotate();
            if case == "scope" {
                f.writer
                    .connection
                    .execute("UPDATE owner_actor_rotations SET scope_id='foreign'", [])
                    .unwrap();
            } else if case == "hash" {
                f.writer
                    .connection
                    .execute(
                        "UPDATE owner_actor_rotations SET intent_digest=?1",
                        ["G".repeat(64)],
                    )
                    .unwrap();
            } else {
                let tx = f.writer.connection.transaction().unwrap();
                for generation in 3..=4098 {
                    tx.execute("INSERT INTO owner_actor_rotations SELECT scope_id,actor_id,?1,intent_digest,?2,?3,prior_binding_digest,prior_public_key,next_binding_digest,next_public_key,owner_epoch,authority_revision,prior_revoked FROM owner_actor_rotations WHERE next_generation=2",params![format!("rotation.{generation}"),generation-1,generation]).unwrap();
                }
                tx.commit().unwrap();
            }
            let mut reader = f.observer();
            assert!(f.capture(&mut reader).is_err(), "{case}");
        }
    }
    #[test]
    fn deferred_snapshot_never_mixes_current_key_with_later_rotation() {
        let mut f = Fixture::new();
        let mut reader = f.observer();
        let old = f.capture(&mut reader).unwrap();
        let lineage = f.lineage.clone();
        let actor = f.actor.actor_id.clone();
        let scope = f.actor.scope_id.clone();
        let result = reader
            .read_historical_owner_snapshot_using(&lineage, &actor, &scope, || {
                f.rotate();
                Ok(())
            })
            .unwrap();
        assert_eq!(result, old);
        let new = f.capture(&mut reader).unwrap();
        assert_eq!(new.actor.credential_generation, 2);
        assert_eq!(new.rotations.len(), 1);
    }
}
