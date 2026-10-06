//! Current manager OS-peer registration and a fresh read-only pod witness.
//! The store checks durable association; trusted host/pod adapters attest OS
//! identity and hold their own process lifetime boundaries.
use std::path::{Path, PathBuf};
use std::time::Duration;

use podbay_core::{AttestedPeer, PodFenceIdentity};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};

use crate::model::{ManagerCredentialClaim, StoreError};
use crate::store::PodBayStore;

const PEER_SCHEMA: &str = "podbay.attested-peer/1";
type PeerFields = (String, String, String, String, String);

fn stored_peer(
    transaction: &Transaction<'_>,
    lineage: &str,
    owner: i64,
    credential: i64,
) -> Result<Option<PeerFields>, StoreError> {
    transaction.query_row(
        "SELECT os_identity,process_identity,boot_identity,birth_identity,containment_identity
         FROM manager_peer_bindings WHERE store_lineage=?1 AND owner_epoch=?2 AND credential_epoch=?3
           AND peer_schema=?4",
        params![lineage, owner, credential, PEER_SCHEMA],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    ).optional().map_err(StoreError::from)
}

fn peer_fields(peer: &AttestedPeer) -> PeerFields {
    (
        peer.os_identity().into(),
        peer.native_process_id().into(),
        peer.boot_identity().into(),
        peer.birth_identity().into(),
        peer.containment_identity().into(),
    )
}

fn current_claim_matches(
    transaction: &Transaction<'_>,
    lineage: &str,
    owner: i64,
    credential: i64,
) -> Result<bool, StoreError> {
    let store_lineage: String = transaction.query_row(
        "SELECT lineage FROM store_identity WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let current_owner: i64 = transaction.query_row(
        "SELECT value FROM metadata WHERE key='owner_epoch'",
        [],
        |row| row.get(0),
    )?;
    let claim: Option<(String, i64, i64)> = transaction
        .query_row(
            "SELECT store_lineage,owner_epoch,credential_epoch
         FROM manager_credential_claims WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    Ok(store_lineage == lineage
        && current_owner == owner
        && claim == Some((lineage.to_owned(), owner, credential)))
}

fn integer(value: u64) -> Result<i64, StoreError> {
    if value == 0 {
        return Err(StoreError::InvalidInput("manager epoch must be positive"));
    }
    i64::try_from(value).map_err(|_| StoreError::InvalidInput("manager epoch exceeds SQLite range"))
}

impl PodBayStore {
    /// Low-level trusted-host primitive. The store cannot observe the caller's
    /// process or prove it holds the manager lifetime lock. The host must pass
    /// a freshly kernel-attested peer after owner replay, while holding that
    /// lock; a request body is never a valid source for this argument.
    pub fn register_current_manager_peer(
        &mut self,
        claim: &ManagerCredentialClaim,
        peer: &AttestedPeer,
    ) -> Result<(), StoreError> {
        let owner = integer(claim.owner_epoch())?;
        let credential = integer(claim.credential_epoch())?;
        if claim.store_lineage() != self.store_lineage {
            return Err(StoreError::WrongScope);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !current_claim_matches(&transaction, claim.store_lineage(), owner, credential)? {
            return Err(StoreError::StaleEpoch);
        }
        let expected = peer_fields(peer);
        if let Some(existing) = stored_peer(&transaction, claim.store_lineage(), owner, credential)?
        {
            if existing != expected {
                return Err(StoreError::Conflict(
                    "manager OS peer changed within one credential epoch",
                ));
            }
            transaction.commit()?;
            return Ok(());
        }
        transaction.execute(
            "INSERT INTO manager_peer_bindings(store_lineage,owner_epoch,credential_epoch,peer_schema,
               os_identity,process_identity,boot_identity,birth_identity,containment_identity)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![claim.store_lineage(), owner, credential, PEER_SCHEMA,
                expected.0, expected.1, expected.2, expected.3, expected.4],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Fresh same-connection readback for the host before a launch effect.
    /// Missing registration returns false; a stale claim fails closed.
    pub fn current_manager_peer_matches(
        &mut self,
        claim: &ManagerCredentialClaim,
        peer: &AttestedPeer,
    ) -> Result<bool, StoreError> {
        let owner = integer(claim.owner_epoch())?;
        let credential = integer(claim.credential_epoch())?;
        if claim.store_lineage() != self.store_lineage {
            return Err(StoreError::WrongScope);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        if !current_claim_matches(&transaction, claim.store_lineage(), owner, credential)? {
            return Err(StoreError::StaleEpoch);
        }
        let matches = stored_peer(&transaction, claim.store_lineage(), owner, credential)?
            .is_some_and(|stored| stored == peer_fields(peer));
        transaction.commit()?;
        Ok(matches)
    }
}

/// Fresh pod-side witness. Its identity comes from a trusted bound manifest,
/// and `observed_peer` must come from the connected socket's kernel evidence.
/// This does not defend against a hostile same-UID writer tampering with DB.
pub struct SqliteManagerPeerWitness {
    database: PathBuf,
    identity: PodFenceIdentity,
}

impl SqliteManagerPeerWitness {
    pub fn for_pod(database: impl AsRef<Path>, identity: PodFenceIdentity) -> Self {
        Self {
            database: database.as_ref().to_path_buf(),
            identity,
        }
    }

    pub fn matches_current(
        &self,
        owner_epoch: u64,
        credential_epoch: u64,
        observed_peer: &AttestedPeer,
    ) -> bool {
        self.fresh_matches(owner_epoch, credential_epoch, observed_peer)
            .unwrap_or(false)
    }

    fn fresh_matches(
        &self,
        owner_epoch: u64,
        credential_epoch: u64,
        observed_peer: &AttestedPeer,
    ) -> Option<bool> {
        let owner = integer(owner_epoch).ok()?;
        let credential = integer(credential_epoch).ok()?;
        let mut connection =
            Connection::open_with_flags(&self.database, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
        connection.busy_timeout(Duration::from_millis(250)).ok()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .ok()?;
        crate::store::verify_current_read_only_schema(&transaction).ok()?;
        let lineage = self.identity.store_lineage.as_str();
        if !current_claim_matches(&transaction, lineage, owner, credential).ok()? {
            return None;
        }
        let incarnation = integer(self.identity.incarnation.get()).ok()?;
        let pod: Option<i64> = transaction
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
        let attempt: Option<String> = transaction
            .query_row(
                "SELECT attempt_id FROM launch_bindings
             WHERE scope_id=?1 AND pod_id=?2 AND pod_incarnation=?3",
                params![
                    self.identity.scope_id.as_str(),
                    self.identity.pod_id.as_str(),
                    incarnation
                ],
                |row| row.get(0),
            )
            .optional()
            .ok()?;
        if pod != Some(incarnation)
            || target != Some(incarnation)
            || attempt.as_deref() != Some(self.identity.attempt_id.as_str())
        {
            return None;
        }
        let matches = stored_peer(&transaction, lineage, owner, credential)
            .ok()?
            .is_some_and(|stored| stored == peer_fields(observed_peer));
        transaction.commit().ok()?;
        Some(matches)
    }
}
