//! Durable manager-rebind evidence for an existing pod. The SQLite ledger
//! cannot attest OS peer birth, old-manager liveness, or the manager lock.
//! Trusted host and pod ports must establish those facts before using it.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use podbay_core::{PodFenceIdentity, RebindLedger, RebindPhase, RebindProposal};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};

use crate::model::{HostObservedPriorCheckpoint, StoreError};
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

/// Read-only recovery view of an exact proof-bearing command. This is durable
/// evidence, not permission to apply the pod-side rebind effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriorObservedRebindInspection {
    pub receipt: DurableRebindReceipt,
    pub checkpoint_digest: String,
    pub supervisor_pid: u32,
    pub supervisor_start_ticks: u64,
    pub boot_id: String,
    pub unit_name: String,
    pub cgroup_path: String,
}

const PRIOR_OBSERVATION_SCHEMA: &str = "podbay.prior-checkpoint/1";

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredPriorObservation {
    schema_version: String,
    checkpoint_digest: String,
    supervisor_pid: i64,
    supervisor_start_ticks: i64,
    boot_id: String,
    unit_name: String,
    cgroup_path: String,
}

impl StoredPriorObservation {
    fn from_host(value: &HostObservedPriorCheckpoint) -> Result<Self, StoreError> {
        Ok(Self {
            schema_version: PRIOR_OBSERVATION_SCHEMA.into(),
            checkpoint_digest: value.checkpoint_digest.clone(),
            supervisor_pid: sqlite_counter(u64::from(value.supervisor_pid))?,
            supervisor_start_ticks: sqlite_counter(value.supervisor_start_ticks)?,
            boot_id: value.boot_id.clone(),
            unit_name: value.unit_name.clone(),
            cgroup_path: value.cgroup_path.clone(),
        })
    }

    fn inspection(
        self,
        receipt: DurableRebindReceipt,
    ) -> Result<PriorObservedRebindInspection, StoreError> {
        if self.schema_version != PRIOR_OBSERVATION_SCHEMA {
            return Err(StoreError::Conflict(
                "prior checkpoint observation version differs",
            ));
        }
        Ok(PriorObservedRebindInspection {
            receipt,
            checkpoint_digest: self.checkpoint_digest,
            supervisor_pid: u32::try_from(self.supervisor_pid)
                .map_err(|_| StoreError::Conflict("prior supervisor PID is malformed"))?,
            supervisor_start_ticks: u64::try_from(self.supervisor_start_ticks)
                .map_err(|_| StoreError::Conflict("prior supervisor birth is malformed"))?,
            boot_id: self.boot_id,
            unit_name: self.unit_name,
            cgroup_path: self.cgroup_path,
        })
    }
}

impl PodBayStore {
    /// Exact-key read-only recovery of a proof-bearing rebind. A changed
    /// proposal conflicts; no live Active pod inspection is required to read
    /// the original Pending receipt after a crash.
    pub fn lookup_prior_observed_rebind(
        &mut self,
        proposal: &RebindProposal,
    ) -> Result<Option<PriorObservedRebindInspection>, StoreError> {
        let lineage = self.store_lineage.clone();
        if proposal.identity.store_lineage.as_str() != lineage {
            return Err(StoreError::WrongScope);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let Some((rowid, receipt)) = load_by_key(&transaction, proposal)? else {
            transaction.commit()?;
            return Ok(None);
        };
        verify_stored(&transaction, rowid, proposal, &lineage)?;
        let observation = read_prior_observation(&transaction, rowid)?.ok_or(
            StoreError::Conflict("legacy rebind has no prior checkpoint observation"),
        )?;
        transaction.commit()?;
        Ok(Some(observation.inspection(receipt)?))
    }

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
            if prior_observation_exists(&transaction, rowid)? {
                return Err(StoreError::Conflict(
                    "proof-bearing rebind requires observation path",
                ));
            }
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

    /// Low-level trusted-host admission of a prior pod checkpoint observed
    /// over an OS-attested live socket. This DTO is forgeable Rust data: the
    /// store proves durable association and destination fences, not the host's
    /// socket evidence, pod fsync, liveness or manager lifetime lock.
    /// A proof-bearing Pending row is intentionally invisible to the pod
    /// ledger until a later digest-before-effect prepare implementation.
    pub fn prepare_manager_rebind_from_host_observation(
        &mut self,
        proposal: &RebindProposal,
        observed: &HostObservedPriorCheckpoint,
    ) -> Result<DurableRebindReceipt, StoreError> {
        validate_host_observation(proposal, observed)?;
        let lineage = self.store_lineage.clone();
        if proposal.identity.store_lineage.as_str() != lineage {
            return Err(StoreError::WrongScope);
        }
        let expected_observation = StoredPriorObservation::from_host(observed)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((rowid, receipt)) = load_by_key(&transaction, proposal)? {
            verify_stored(&transaction, rowid, proposal, &lineage)?;
            let prior = read_prior_observation(&transaction, rowid)?.ok_or(
                StoreError::Conflict("legacy rebind has no prior checkpoint observation"),
            )?;
            if prior != expected_observation {
                return Err(StoreError::Conflict("prior checkpoint observation changed"));
            }
            // A duplicate is a readback of this manager's still-current
            // Pending intent, never a way for an older owner to revive it.
            verify_current_fences_with_mode(&transaction, proposal, &lineage, true)?;
            verify_current_manager_destination(&transaction, proposal, &lineage)?;
            transaction.commit()?;
            return Ok(receipt);
        }
        verify_current_fences_with_mode(&transaction, proposal, &lineage, true)?;
        verify_current_manager_destination(&transaction, proposal, &lineage)?;
        let unfinished: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM manager_rebinds WHERE scope_id=?1 AND pod_id=?2
               AND pod_incarnation=?3 AND phase!='activated'",
            params![
                proposal.identity.scope_id.as_str(),
                proposal.identity.pod_id.as_str(),
                sqlite_counter(proposal.identity.incarnation.get())?
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
                    sqlite_counter(proposal.identity.incarnation.get())?
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let prior_owner = sqlite_counter(proposal.expected_owner_epoch.get())?;
        let prior_credential = sqlite_counter(proposal.expected_credential_epoch.get())?;
        if latest.is_some_and(|(owner, credential)| {
            owner != prior_owner || credential != prior_credential
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
                proposal.identity.attempt_id.as_str(),sqlite_counter(proposal.identity.incarnation.get())?,
                sqlite_counter(proposal.expected_owner_epoch.get())?,sqlite_counter(proposal.next_owner_epoch.get())?,
                sqlite_counter(proposal.expected_credential_epoch.get())?,sqlite_counter(proposal.next_credential_epoch.get())?,
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
                    sqlite_counter(old.get())?,
                    sqlite_counter(next.get())?
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO manager_rebind_prior_observations(rebind_rowid,schema_version,
               checkpoint_digest,supervisor_pid,supervisor_start_ticks,boot_id,unit_name,cgroup_path)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![rowid,expected_observation.schema_version,expected_observation.checkpoint_digest,
                expected_observation.supervisor_pid,expected_observation.supervisor_start_ticks,
                expected_observation.boot_id,expected_observation.unit_name,expected_observation.cgroup_path],
        )?;
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
            false,
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
            false,
        )
    }

    /// Trusted host only: record the exact fsynced PendingPod checkpoint
    /// reported by the live, OS-attested pod. The store validates the prior
    /// observation and current destination, but cannot attest the socket.
    pub fn acknowledge_prior_observed_pod_rebind(
        &mut self,
        proposal: &RebindProposal,
        pending_checkpoint_digest: &str,
    ) -> Result<DurableRebindReceipt, StoreError> {
        transition(
            self,
            proposal,
            pending_checkpoint_digest,
            DurableRebindPhase::PodAcknowledged,
            true,
        )
    }

    /// Trusted host only: after the PendingPod fsync is acknowledged, commit
    /// the destination before asking the pod to activate. A lost pod reply
    /// leaves an explicit Activated-store/Pending-pod reconciliation state.
    pub fn activate_prior_observed_manager_rebind(
        &mut self,
        proposal: &RebindProposal,
        pending_checkpoint_digest: &str,
    ) -> Result<DurableRebindReceipt, StoreError> {
        transition(
            self,
            proposal,
            pending_checkpoint_digest,
            DurableRebindPhase::Activated,
            true,
        )
    }
}

fn transition(
    store: &mut PodBayStore,
    proposal: &RebindProposal,
    checkpoint: &str,
    target: DurableRebindPhase,
    proof_bearing: bool,
) -> Result<DurableRebindReceipt, StoreError> {
    if !proof_bearing {
        validate_shape(proposal)?;
    }
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
    if prior_observation_exists(&transaction, rowid)? != proof_bearing {
        return Err(StoreError::Conflict("rebind transition proof mode differs"));
    }
    if proof_bearing {
        if checkpoint.len() != 64
            || !checkpoint
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(StoreError::InvalidInput(
                "pending checkpoint digest is invalid",
            ));
        }
        verify_current_fences_with_mode(&transaction, proposal, &lineage, true)?;
        verify_current_manager_destination(&transaction, proposal, &lineage)?;
    }
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
    if !proof_bearing {
        verify_current_fences(&transaction, proposal, &lineage)?;
    }
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

fn validate_host_observation(
    proposal: &RebindProposal,
    observed: &HostObservedPriorCheckpoint,
) -> Result<(), StoreError> {
    if observed.identity != proposal.identity {
        return Err(StoreError::WrongScope);
    }
    if observed.owner_epoch != proposal.expected_owner_epoch
        || observed.credential_epoch != proposal.expected_credential_epoch
        || observed.input_epochs != proposal.expected_input_epochs
    {
        return Err(StoreError::Conflict(
            "prior checkpoint observation differs from proposal",
        ));
    }
    if observed.phase != RebindPhase::Active
        || observed.input_epochs.is_empty()
        || observed.input_epochs.len() > 64
        || observed.input_epochs.len() != proposal.next_input_epochs.len()
        || proposal.next_owner_epoch.get() <= proposal.expected_owner_epoch.get()
        || proposal.next_credential_epoch.get() <= proposal.expected_credential_epoch.get()
        || observed.supervisor_pid == 0
        || observed.supervisor_start_ticks == 0
        || observed.checkpoint_digest.len() != 64
        || !observed
            .checkpoint_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StoreError::InvalidInput(
            "prior Active checkpoint observation is invalid",
        ));
    }
    for value in [observed.boot_id.as_str(), observed.unit_name.as_str()] {
        if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
            return Err(StoreError::InvalidInput(
                "prior pod process evidence is invalid",
            ));
        }
    }
    if !observed.cgroup_path.starts_with('/')
        || observed.cgroup_path.len() > 4096
        || observed.cgroup_path.chars().any(char::is_control)
    {
        return Err(StoreError::InvalidInput("prior pod containment is invalid"));
    }
    for value in [
        proposal.expected_owner_epoch.get(),
        proposal.next_owner_epoch.get(),
        proposal.expected_credential_epoch.get(),
        proposal.next_credential_epoch.get(),
        u64::from(observed.supervisor_pid),
        observed.supervisor_start_ticks,
    ] {
        sqlite_counter(value)?;
    }
    for (id, old) in &observed.input_epochs {
        let next = proposal
            .next_input_epochs
            .get(id)
            .ok_or(StoreError::InvalidInput("rebind resource set differs"))?;
        sqlite_counter(old.get())?;
        sqlite_counter(next.get())?;
        if next.get() <= old.get() {
            return Err(StoreError::InvalidInput(
                "rebind input epoch did not advance",
            ));
        }
    }
    Ok(())
}

fn verify_current_manager_destination(
    transaction: &Transaction<'_>,
    proposal: &RebindProposal,
    lineage: &str,
) -> Result<(), StoreError> {
    let owner = sqlite_counter(proposal.next_owner_epoch.get())?;
    let credential = sqlite_counter(proposal.next_credential_epoch.get())?;
    let claim: Option<(String, i64, i64)> = transaction
        .query_row(
            "SELECT store_lineage,owner_epoch,credential_epoch
         FROM manager_credential_claims WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if claim != Some((lineage.into(), owner, credential)) {
        return Err(StoreError::StaleEpoch);
    }
    let peer: Option<(String, String, String, String, String)> = transaction
        .query_row(
            "SELECT os_identity,process_identity,boot_identity,birth_identity,containment_identity
         FROM manager_peer_bindings WHERE store_lineage=?1 AND owner_epoch=?2
           AND credential_epoch=?3 AND peer_schema='podbay.attested-peer/1'",
            params![lineage, owner, credential],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    if peer
        != Some((
            proposal.next_manager.os_identity().into(),
            proposal.next_manager.native_process_id().into(),
            proposal.next_manager.boot_identity().into(),
            proposal.next_manager.birth_identity().into(),
            proposal.next_manager.containment_identity().into(),
        ))
    {
        return Err(StoreError::StaleEpoch);
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

fn prior_observation_exists(transaction: &Transaction<'_>, rowid: i64) -> Result<bool, StoreError> {
    Ok(read_prior_observation(transaction, rowid)?.is_some())
}

fn read_prior_observation(
    transaction: &Transaction<'_>,
    rowid: i64,
) -> Result<Option<StoredPriorObservation>, StoreError> {
    transaction
        .query_row(
            "SELECT schema_version,checkpoint_digest,supervisor_pid,supervisor_start_ticks,
                boot_id,unit_name,cgroup_path
         FROM manager_rebind_prior_observations WHERE rebind_rowid=?1",
            [rowid],
            |row| {
                Ok(StoredPriorObservation {
                    schema_version: row.get(0)?,
                    checkpoint_digest: row.get(1)?,
                    supervisor_pid: row.get(2)?,
                    supervisor_start_ticks: row.get(3)?,
                    boot_id: row.get(4)?,
                    unit_name: row.get(5)?,
                    cgroup_path: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(StoreError::from)
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
    verify_current_fences_with_mode(transaction, proposal, lineage, false)
}

fn verify_current_fences_with_mode(
    transaction: &Transaction<'_>,
    proposal: &RebindProposal,
    lineage: &str,
    allow_skip: bool,
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
        if (if allow_skip {
            old.get() >= next.get()
        } else {
            old.get().checked_add(1) != Some(next.get())
        }) || current
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
        // V13 proof-bearing rows are durable intent only until the pod adds
        // a digest-before-effect prepare path. Legacy +1 remains the sole
        // ledger-visible path in this atom.
        validate_shape(proposal).ok()?;
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
        if prior_observation_exists(&transaction, rowid).ok()? {
            return None;
        }
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

/// Fresh read-only Pending proof for a pod that has independently verified its
/// exact fsynced PRIOR checkpoint and current supervisor process evidence.
///
/// `prior` is data, not OS attestation. Only the trusted pod runtime should
/// construct it from its checkpoint and live self observations. The runtime
/// must separately authenticate the new manager socket and enforce its lock/
/// liveness protocol. This ledger never activates a rebind or writes a row.
pub struct SqlitePriorObservedPendingLedger {
    database: PathBuf,
    prior: HostObservedPriorCheckpoint,
}

impl SqlitePriorObservedPendingLedger {
    pub fn for_pod(database: impl AsRef<Path>, prior: HostObservedPriorCheckpoint) -> Self {
        Self {
            database: database.as_ref().to_path_buf(),
            prior,
        }
    }

    fn fresh_phase(&self, proposal: &RebindProposal, activated: bool) -> Option<bool> {
        // Includes exact identity and old vector equality, Active-only prior,
        // strict destination advancement, complete key set and SQLite bounds.
        validate_host_observation(proposal, &self.prior).ok()?;
        let expected = StoredPriorObservation::from_host(&self.prior).ok()?;
        let mut connection =
            Connection::open_with_flags(&self.database, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
        connection.busy_timeout(Duration::from_millis(250)).ok()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .ok()?;
        let lineage = self.prior.identity.store_lineage.as_str();
        let (rowid, receipt) = load_by_key(&transaction, proposal).ok()??;
        let valid_reference = receipt
            .pod_checkpoint_ref
            .as_deref()
            .is_some_and(|reference| {
                reference.len() == 64
                    && reference
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            });
        let valid_phase = if activated {
            receipt.phase == DurableRebindPhase::Activated && valid_reference
        } else {
            matches!(
                (receipt.phase, receipt.pod_checkpoint_ref.as_deref()),
                (DurableRebindPhase::Pending, None)
            ) || (receipt.phase == DurableRebindPhase::PodAcknowledged && valid_reference)
        };
        if !valid_phase {
            return Some(false);
        }
        let observed = read_prior_observation(&transaction, rowid).ok()??;
        if observed != expected {
            return Some(false);
        }
        verify_stored(&transaction, rowid, proposal, lineage).ok()?;
        verify_current_fences_with_mode(&transaction, proposal, lineage, true).ok()?;
        verify_current_manager_destination(&transaction, proposal, lineage).ok()?;
        transaction.commit().ok()?;
        Some(true)
    }
}

impl RebindLedger for SqlitePriorObservedPendingLedger {
    fn pending(&self, proposal: &RebindProposal) -> bool {
        self.fresh_phase(proposal, false).unwrap_or(false)
    }

    fn activated(&self, proposal: &RebindProposal) -> bool {
        self.fresh_phase(proposal, true).unwrap_or(false)
    }
}
