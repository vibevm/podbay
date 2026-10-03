//! Durable manager-rebind evidence for an existing pod. The SQLite ledger
//! cannot attest OS peer birth, old-manager liveness, or the manager lock.
//! Trusted host and pod ports must establish those facts before using it.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use podbay_core::{PodFenceIdentity, RebindLedger, RebindProposal};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};

use crate::model::StoreError;
use crate::store::PodBayStore;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableRebindPhase {
    Pending,
    PodAcknowledged,
    Activated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableRebindReceipt {
    pub command_key: String,
    pub request_digest: String,
    pub phase: DurableRebindPhase,
    pub pod_checkpoint_ref: Option<String>,
}

impl PodBayStore {
    /// Records a host-reviewed rebind intent after the owner/input epoch replay.
    /// It creates no pod, child, lease, grant, or provider effect.
    pub fn prepare_manager_rebind(
        &mut self,
        proposal: &RebindProposal,
    ) -> Result<DurableRebindReceipt, StoreError> {
        validate_shape(proposal)?;
        let lineage = self.store_lineage.clone();
        if proposal.identity.store_lineage.as_str() != lineage {
            return Err(StoreError::WrongScope);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((rowid, receipt)) = load_by_key(&transaction, proposal)? {
            verify_stored(&transaction, rowid, proposal, &lineage)?;
            transaction.commit()?;
            return Ok(receipt);
        }
        verify_current_fences(&transaction, proposal, &lineage)?;
        let unfinished: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM manager_rebinds WHERE scope_id=?1 AND pod_id=?2
               AND pod_incarnation=?3 AND phase!='activated'",
            params![
                proposal.identity.scope_id.as_str(),
                proposal.identity.pod_id.as_str(),
                proposal.identity.incarnation.get() as i64
            ],
            |row| row.get(0),
        )?;
        if unfinished != 0 {
            return Err(StoreError::Conflict("another manager rebind is pending"));
        }
        let latest: Option<(i64, i64)> = transaction
            .query_row(
                "SELECT next_owner_epoch,next_credential_epoch FROM manager_rebinds
             WHERE scope_id=?1 AND pod_id=?2 AND pod_incarnation=?3 AND phase='activated'
             ORDER BY next_owner_epoch DESC LIMIT 1",
                params![
                    proposal.identity.scope_id.as_str(),
                    proposal.identity.pod_id.as_str(),
                    proposal.identity.incarnation.get() as i64
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if latest.is_some_and(|(owner, credential)| {
            owner != proposal.expected_owner_epoch.get() as i64
                || credential != proposal.expected_credential_epoch.get() as i64
        }) {
            return Err(StoreError::StaleEpoch);
        }
        transaction.execute(
            "INSERT INTO manager_rebinds(
               store_lineage,scope_id,pod_id,attempt_id,pod_incarnation,
               expected_owner_epoch,next_owner_epoch,expected_credential_epoch,next_credential_epoch,
               manager_os_identity,manager_process_id,manager_boot_identity,
               manager_birth_identity,manager_containment,command_key,request_digest,
               resource_count,phase)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,'pending')",
            params![lineage,proposal.identity.scope_id.as_str(),proposal.identity.pod_id.as_str(),
                proposal.identity.attempt_id.as_str(),proposal.identity.incarnation.get() as i64,
                proposal.expected_owner_epoch.get() as i64,proposal.next_owner_epoch.get() as i64,
                proposal.expected_credential_epoch.get() as i64,proposal.next_credential_epoch.get() as i64,
                proposal.next_manager.os_identity(),proposal.next_manager.native_process_id(),
                proposal.next_manager.boot_identity(),proposal.next_manager.birth_identity(),
                proposal.next_manager.containment_identity(),proposal.command_key.as_str(),
                proposal.digest.as_str(),proposal.next_input_epochs.len() as i64],
        )?;
        let rowid = transaction.last_insert_rowid();
        for (resource_id, next) in &proposal.next_input_epochs {
            let old = proposal
                .expected_input_epochs
                .get(resource_id)
                .ok_or(StoreError::Conflict("rebind resource set differs"))?;
            transaction.execute(
                "INSERT INTO manager_rebind_resources(rebind_rowid,resource_id,
                   expected_input_epoch,next_input_epoch) VALUES(?1,?2,?3,?4)",
                params![
                    rowid,
                    resource_id.as_str(),
                    old.get() as i64,
                    next.get() as i64
                ],
            )?;
        }
        transaction.commit()?;
        Ok(receipt(proposal, DurableRebindPhase::Pending, None))
    }

    /// Records a trusted pod checkpoint reference. The store cannot prove the
    /// pod's durable fsync or native peer evidence from this string alone.
    pub fn acknowledge_pod_rebind(
        &mut self,
        proposal: &RebindProposal,
        pod_checkpoint_ref: &str,
    ) -> Result<DurableRebindReceipt, StoreError> {
        transition(
            self,
            proposal,
            pod_checkpoint_ref,
            DurableRebindPhase::PodAcknowledged,
        )
    }

    /// Activates only a previously acknowledged exact proposal; no control
    /// grant or old-manager capability is restored by this database update.
    pub fn activate_manager_rebind(
        &mut self,
        proposal: &RebindProposal,
        pod_checkpoint_ref: &str,
    ) -> Result<DurableRebindReceipt, StoreError> {
        transition(
            self,
            proposal,
            pod_checkpoint_ref,
            DurableRebindPhase::Activated,
        )
    }
}

fn transition(
    store: &mut PodBayStore,
    proposal: &RebindProposal,
    checkpoint: &str,
    target: DurableRebindPhase,
) -> Result<DurableRebindReceipt, StoreError> {
    validate_shape(proposal)?;
    if checkpoint.is_empty() || checkpoint.len() > 256 || checkpoint.chars().any(char::is_control) {
        return Err(StoreError::InvalidInput(
            "pod checkpoint reference is invalid",
        ));
    }
    let lineage = store.store_lineage.clone();
    if proposal.identity.store_lineage.as_str() != lineage {
        return Err(StoreError::WrongScope);
    }
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (rowid, prior) = load_by_key(&transaction, proposal)?.ok_or(StoreError::NotFound)?;
    verify_stored(&transaction, rowid, proposal, &lineage)?;
    if prior.phase == target {
        if prior.pod_checkpoint_ref.as_deref() != Some(checkpoint) {
            return Err(StoreError::Conflict("pod checkpoint reference changed"));
        }
        transaction.commit()?;
        return Ok(prior);
    }
    let valid = matches!(
        (prior.phase, target),
        (
            DurableRebindPhase::Pending,
            DurableRebindPhase::PodAcknowledged
        ) | (
            DurableRebindPhase::PodAcknowledged,
            DurableRebindPhase::Activated
        )
    );
    if !valid
        || (prior.phase == DurableRebindPhase::PodAcknowledged
            && prior.pod_checkpoint_ref.as_deref() != Some(checkpoint))
    {
        return Err(StoreError::Conflict("rebind phase or checkpoint differs"));
    }
    verify_current_fences(&transaction, proposal, &lineage)?;
    let phase = phase_text(target);
    let changed = transaction.execute(
        "UPDATE manager_rebinds SET phase=?1,pod_checkpoint_ref=?2
         WHERE rebind_rowid=?3 AND phase=?4",
        params![phase, checkpoint, rowid, phase_text(prior.phase)],
    )?;
    if changed != 1 {
        return Err(StoreError::Conflict("rebind phase changed"));
    }
    transaction.commit()?;
    Ok(receipt(proposal, target, Some(checkpoint.into())))
}

fn receipt(
    proposal: &RebindProposal,
    phase: DurableRebindPhase,
    checkpoint: Option<String>,
) -> DurableRebindReceipt {
    DurableRebindReceipt {
        command_key: proposal.command_key.as_str().into(),
        request_digest: proposal.digest.as_str().into(),
        phase,
        pod_checkpoint_ref: checkpoint,
    }
}
fn phase_text(phase: DurableRebindPhase) -> &'static str {
    match phase {
        DurableRebindPhase::Pending => "pending",
        DurableRebindPhase::PodAcknowledged => "pod_acknowledged",
        DurableRebindPhase::Activated => "activated",
    }
}
fn decode_phase(value: &str) -> Result<DurableRebindPhase, StoreError> {
    match value {
        "pending" => Ok(DurableRebindPhase::Pending),
        "pod_acknowledged" => Ok(DurableRebindPhase::PodAcknowledged),
        "activated" => Ok(DurableRebindPhase::Activated),
        _ => Err(StoreError::Conflict("unknown rebind phase")),
    }
}

fn sqlite_counter(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value)
        .map_err(|_| StoreError::InvalidInput("rebind counter exceeds SQLite range"))
}

fn validate_shape(proposal: &RebindProposal) -> Result<(), StoreError> {
    let old_owner = proposal.expected_owner_epoch.get();
    let next_owner = proposal.next_owner_epoch.get();
    let old_credential = proposal.expected_credential_epoch.get();
    let next_credential = proposal.next_credential_epoch.get();
    for value in [
        old_owner,
        next_owner,
        old_credential,
        next_credential,
        proposal.identity.incarnation.get(),
    ] {
        sqlite_counter(value)?;
    }
    if old_owner == 0
        || old_owner.checked_add(1) != Some(next_owner)
        || old_credential == 0
        || old_credential.checked_add(1) != Some(next_credential)
        || proposal.expected_input_epochs.is_empty()
        || proposal.expected_input_epochs.len() != proposal.next_input_epochs.len()
        || proposal.expected_input_epochs.len() > 64
    {
        return Err(StoreError::InvalidInput(
            "rebind epochs or resource set are invalid",
        ));
    }
    for (id, old) in &proposal.expected_input_epochs {
        let next = proposal
            .next_input_epochs
            .get(id)
            .ok_or(StoreError::InvalidInput(
                "rebind resource set is incomplete",
            ))?;
        sqlite_counter(old.get())?;
        sqlite_counter(next.get())?;
        if old.get() == 0 || old.get().checked_add(1) != Some(next.get()) {
            return Err(StoreError::InvalidInput(
                "rebind input epoch is not successive",
            ));
        }
    }
    Ok(())
}

fn load_by_key(
    transaction: &Transaction<'_>,
    proposal: &RebindProposal,
) -> Result<Option<(i64, DurableRebindReceipt)>, StoreError> {
    let row: Option<(i64, String, String, Option<String>)> = transaction
        .query_row(
            "SELECT rebind_rowid,request_digest,phase,pod_checkpoint_ref FROM manager_rebinds
         WHERE scope_id=?1 AND pod_id=?2 AND pod_incarnation=?3 AND command_key=?4",
            params![
                proposal.identity.scope_id.as_str(),
                proposal.identity.pod_id.as_str(),
                sqlite_counter(proposal.identity.incarnation.get())?,
                proposal.command_key.as_str()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    row.map(|(rowid, digest, phase, checkpoint)| {
        if digest != proposal.digest.as_str() {
            return Err(StoreError::Conflict("rebind command key changed content"));
        }
        Ok((
            rowid,
            DurableRebindReceipt {
                command_key: proposal.command_key.as_str().into(),
                request_digest: digest,
                phase: decode_phase(&phase)?,
                pod_checkpoint_ref: checkpoint,
            },
        ))
    })
    .transpose()
}

fn verify_stored(
    transaction: &Transaction<'_>,
    rowid: i64,
    proposal: &RebindProposal,
    lineage: &str,
) -> Result<(), StoreError> {
    let actual: (
        String,
        String,
        String,
        String,
        i64,
        i64,
        i64,
        i64,
        i64,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
    ) = transaction.query_row(
        "SELECT store_lineage,scope_id,pod_id,attempt_id,pod_incarnation,
                expected_owner_epoch,next_owner_epoch,expected_credential_epoch,
                next_credential_epoch,manager_os_identity,manager_process_id,
                manager_boot_identity,manager_birth_identity,manager_containment,
                command_key,request_digest,resource_count
         FROM manager_rebinds WHERE rebind_rowid=?1",
        [rowid],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
                row.get(10)?,
                row.get(11)?,
                row.get(12)?,
                row.get(13)?,
                row.get(14)?,
                row.get(15)?,
                row.get(16)?,
            ))
        },
    )?;
    if actual.0 != lineage
        || actual.0 != proposal.identity.store_lineage.as_str()
        || actual.1 != proposal.identity.scope_id.as_str()
        || actual.2 != proposal.identity.pod_id.as_str()
        || actual.3 != proposal.identity.attempt_id.as_str()
        || actual.4 != sqlite_counter(proposal.identity.incarnation.get())?
        || actual.5 != sqlite_counter(proposal.expected_owner_epoch.get())?
        || actual.6 != sqlite_counter(proposal.next_owner_epoch.get())?
        || actual.7 != sqlite_counter(proposal.expected_credential_epoch.get())?
        || actual.8 != sqlite_counter(proposal.next_credential_epoch.get())?
        || actual.9 != proposal.next_manager.os_identity()
        || actual.10 != proposal.next_manager.native_process_id()
        || actual.11 != proposal.next_manager.boot_identity()
        || actual.12 != proposal.next_manager.birth_identity()
        || actual.13 != proposal.next_manager.containment_identity()
        || actual.14 != proposal.command_key.as_str()
        || actual.15 != proposal.digest.as_str()
        || actual.16 != proposal.next_input_epochs.len() as i64
    {
        return Err(StoreError::Conflict(
            "rebind proposal differs from durable row",
        ));
    }
    let mut seen = BTreeMap::new();
    let mut statement = transaction.prepare(
        "SELECT resource_id,expected_input_epoch,next_input_epoch
         FROM manager_rebind_resources WHERE rebind_rowid=?1 ORDER BY resource_id",
    )?;
    let rows = statement.query_map([rowid], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;
    for row in rows {
        let (id, old, next) = row?;
        seen.insert(id, (old, next));
    }
    if seen.len() != proposal.next_input_epochs.len() {
        return Err(StoreError::Conflict(
            "durable rebind resource count differs",
        ));
    }
    for (id, old) in &proposal.expected_input_epochs {
        let next = proposal
            .next_input_epochs
            .get(id)
            .ok_or(StoreError::Conflict("rebind resource set differs"))?;
        if seen.get(id.as_str()) != Some(&(sqlite_counter(old.get())?, sqlite_counter(next.get())?))
        {
            return Err(StoreError::Conflict(
                "durable rebind resource epoch differs",
            ));
        }
    }
    Ok(())
}

fn verify_current_fences(
    transaction: &Transaction<'_>,
    proposal: &RebindProposal,
    lineage: &str,
) -> Result<(), StoreError> {
    if proposal.identity.store_lineage.as_str() != lineage {
        return Err(StoreError::WrongScope);
    }
    let committed_lineage: String = transaction.query_row(
        "SELECT lineage FROM store_identity WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if committed_lineage != lineage {
        return Err(StoreError::WrongScope);
    }
    let owner: i64 = transaction.query_row(
        "SELECT value FROM metadata WHERE key='owner_epoch'",
        [],
        |row| row.get(0),
    )?;
    if owner != sqlite_counter(proposal.next_owner_epoch.get())? {
        return Err(StoreError::StaleEpoch);
    }
    let scope = proposal.identity.scope_id.as_str();
    let pod = proposal.identity.pod_id.as_str();
    let incarnation = sqlite_counter(proposal.identity.incarnation.get())?;
    let registered: Option<(String, i64)> = transaction
        .query_row(
            "SELECT scope_id,incarnation FROM authority_pods WHERE pod_id=?1",
            [pod],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let target: Option<i64> = transaction
        .query_row(
            "SELECT epoch FROM target_epochs WHERE scope_id=?1 AND target_id=?2",
            params![scope, pod],
            |row| row.get(0),
        )
        .optional()?;
    if registered
        .as_ref()
        .is_some_and(|(found_scope, _)| found_scope != scope)
    {
        return Err(StoreError::WrongScope);
    }
    if registered != Some((scope.into(), incarnation)) || target != Some(incarnation) {
        return Err(StoreError::StaleEpoch);
    }
    let binding: Option<(String, i64)> = transaction
        .query_row(
            "SELECT attempt_id,resource_count FROM launch_bindings
         WHERE scope_id=?1 AND pod_id=?2 AND pod_incarnation=?3",
            params![scope, pod, incarnation],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if binding
        != Some((
            proposal.identity.attempt_id.as_str().into(),
            proposal.next_input_epochs.len() as i64,
        ))
    {
        return Err(StoreError::WrongScope);
    }
    let mut launch_resources = BTreeMap::new();
    let mut statement = transaction.prepare(
        "SELECT lr.resource_id,lr.resource_epoch FROM launch_resources lr
         JOIN launch_bindings b ON b.command_rowid=lr.command_rowid
         WHERE b.scope_id=?1 AND b.pod_id=?2 AND b.pod_incarnation=?3",
    )?;
    let rows = statement.query_map(params![scope, pod, incarnation], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in rows {
        let (id, epoch) = row?;
        launch_resources.insert(id, epoch);
    }
    if launch_resources.len() != proposal.next_input_epochs.len() {
        return Err(StoreError::Conflict("rebind launch resource set differs"));
    }
    let mut authorities = BTreeMap::new();
    let mut statement = transaction.prepare(
        "SELECT resource_id,scope_id,pod_incarnation,resource_epoch,input_epoch
         FROM authority_resources WHERE pod_id=?1",
    )?;
    let rows = statement.query_map([pod], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })?;
    for row in rows {
        let (id, scope_id, pod_inc, resource_epoch, input_epoch) = row?;
        authorities.insert(id, (scope_id, pod_inc, resource_epoch, input_epoch));
    }
    if authorities.len() != proposal.next_input_epochs.len() {
        return Err(StoreError::Conflict(
            "rebind authority resource set differs",
        ));
    }
    for (id, next) in &proposal.next_input_epochs {
        let old = proposal
            .expected_input_epochs
            .get(id)
            .ok_or(StoreError::Conflict("rebind resource set differs"))?;
        let resource_epoch = launch_resources
            .get(id.as_str())
            .ok_or(StoreError::Conflict("rebind launch resource is missing"))?;
        let current = authorities
            .get(id.as_str())
            .ok_or(StoreError::Conflict("rebind authority resource is missing"))?;
        if old.get().checked_add(1) != Some(next.get())
            || current
                != (&(
                    scope.into(),
                    incarnation,
                    *resource_epoch,
                    sqlite_counter(next.get())?,
                ))
        {
            return Err(StoreError::StaleEpoch);
        }
    }
    Ok(())
}

/// Fresh read-only ledger view for a pod's trusted persisted identity. A
/// copied request cannot select a different scope or pod through this witness.
pub struct SqliteRebindLedger {
    database: PathBuf,
    identity: PodFenceIdentity,
}

impl SqliteRebindLedger {
    pub fn for_pod(database: impl AsRef<Path>, identity: PodFenceIdentity) -> Self {
        Self {
            database: database.as_ref().to_path_buf(),
            identity,
        }
    }

    fn fresh_phase(&self, proposal: &RebindProposal) -> Option<DurableRebindPhase> {
        if proposal.identity != self.identity {
            return None;
        }
        let mut connection =
            Connection::open_with_flags(&self.database, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
        connection.busy_timeout(Duration::from_millis(250)).ok()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .ok()?;
        let lineage: String = transaction
            .query_row(
                "SELECT lineage FROM store_identity WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .ok()?;
        let (rowid, record) = load_by_key(&transaction, proposal).ok()??;
        verify_stored(&transaction, rowid, proposal, &lineage).ok()?;
        verify_current_fences(&transaction, proposal, &lineage).ok()?;
        transaction.commit().ok()?;
        Some(record.phase)
    }
}

impl RebindLedger for SqliteRebindLedger {
    fn pending(&self, proposal: &RebindProposal) -> bool {
        matches!(
            self.fresh_phase(proposal),
            Some(DurableRebindPhase::Pending | DurableRebindPhase::PodAcknowledged)
        )
    }
    fn activated(&self, proposal: &RebindProposal) -> bool {
        self.fresh_phase(proposal) == Some(DurableRebindPhase::Activated)
    }
}
