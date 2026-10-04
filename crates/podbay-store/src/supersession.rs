//! Append-only manager-rebind recovery attempts. These rows are durable
//! associations, never proof that a manager is dead or a pod fsynced a file.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use podbay_core::{
    AttestedPeer, CommandKey, CredentialEpoch, Epoch, InputEpoch, OwnerEpoch,
    PendingPodProcessEvidence, PendingRebindSupersession, PodFenceIdentity, PodId, RebindPhase,
    RebindProposal, RequestDigest, ResourceId, ScopeId, StoreLineageId, SupersessionLedger,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, named_params, params};

use crate::model::{HostObservedPriorCheckpoint, StoreError};
use crate::rebind::{DurableRebindPhase, load_by_key, sqlite_counter, verify_stored};
use crate::store::PodBayStore;

const DOMAIN: &[u8] = b"podbay.rebind-supersession/1\0";
const MAX_INTENT_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupersessionStage {
    Planned,
    PodCheckpointed,
    Replaced,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupersessionReceipt {
    pub rowid: i64,
    pub predecessor_rowid: Option<i64>,
    pub command_key: String,
    pub request_digest: String,
    pub stage: SupersessionStage,
    pub recovery_checkpoint_digest: Option<String>,
}

/// Historical C Planned attempt plus A's durable manager peer. These are
/// store facts only; D must attest C's death and the live pod's exact Active
/// checkpoint before a successor transaction may use them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriorPlannedRecovery {
    pub intent: PendingRebindSupersession,
    pub receipt: SupersessionReceipt,
    pub prior_manager_peer: AttestedPeer,
}

fn decode_stage(value: &str) -> Result<SupersessionStage, StoreError> {
    match value {
        "planned" => Ok(SupersessionStage::Planned),
        "pod_checkpointed" => Ok(SupersessionStage::PodCheckpointed),
        "replaced" => Ok(SupersessionStage::Replaced),
        _ => Err(StoreError::Conflict("supersession phase differs")),
    }
}

fn put_text(bytes: &mut Vec<u8>, value: &str) -> Result<(), StoreError> {
    let length = u32::try_from(value.len())
        .map_err(|_| StoreError::InvalidInput("supersession field exceeds bound"))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_inputs(
    bytes: &mut Vec<u8>,
    inputs: &BTreeMap<podbay_core::ResourceId, podbay_core::InputEpoch>,
) -> Result<(), StoreError> {
    if inputs.is_empty() || inputs.len() > 64 {
        return Err(StoreError::InvalidInput("supersession resource count"));
    }
    bytes.extend_from_slice(&(inputs.len() as u16).to_be_bytes());
    for (id, epoch) in inputs {
        put_text(bytes, id.as_str())?;
        bytes.extend_from_slice(&epoch.get().to_be_bytes());
    }
    Ok(())
}

fn canonical_intent(intent: &PendingRebindSupersession) -> Result<Vec<u8>, StoreError> {
    let mut bytes = DOMAIN.to_vec();
    let abandoned = &intent.abandoned;
    for text in [
        abandoned.identity.store_lineage.as_str(),
        abandoned.identity.scope_id.as_str(),
        abandoned.identity.pod_id.as_str(),
        abandoned.identity.attempt_id.as_str(),
    ] {
        put_text(&mut bytes, text)?;
    }
    bytes.extend_from_slice(&abandoned.identity.incarnation.get().to_be_bytes());
    for epoch in [
        abandoned.expected_owner_epoch.get(),
        abandoned.next_owner_epoch.get(),
        abandoned.expected_credential_epoch.get(),
        abandoned.next_credential_epoch.get(),
    ] {
        bytes.extend_from_slice(&epoch.to_be_bytes());
    }
    put_inputs(&mut bytes, &abandoned.expected_input_epochs)?;
    put_inputs(&mut bytes, &abandoned.next_input_epochs)?;
    for text in [
        abandoned.next_manager.os_identity(),
        abandoned.next_manager.native_process_id(),
        abandoned.next_manager.boot_identity(),
        abandoned.next_manager.birth_identity(),
        abandoned.next_manager.containment_identity(),
        abandoned.command_key.as_str(),
        abandoned.digest.as_str(),
    ] {
        put_text(&mut bytes, text)?;
    }
    bytes.push(match intent.pending_phase {
        RebindPhase::PendingStore => 1,
        RebindPhase::PendingPod => 2,
        RebindPhase::Active => {
            return Err(StoreError::InvalidInput(
                "pending supersession cannot observe Active",
            ));
        }
    });
    put_text(&mut bytes, intent.pending_checkpoint_digest.as_str())?;
    for text in [
        intent.pending_process.supervisor_process_id.as_str(),
        intent.pending_process.supervisor_birth_identity.as_str(),
        intent.pending_process.child_process_id.as_str(),
        intent.pending_process.child_birth_identity.as_str(),
        intent.pending_process.boot_identity.as_str(),
        intent.pending_process.containment_identity.as_str(),
    ] {
        put_text(&mut bytes, text)?;
    }
    bytes.extend_from_slice(&intent.recovering_owner_epoch.get().to_be_bytes());
    bytes.extend_from_slice(&intent.recovering_credential_epoch.get().to_be_bytes());
    put_inputs(&mut bytes, &intent.recovering_input_epochs)?;
    for text in [
        intent.recovering_manager.os_identity(),
        intent.recovering_manager.native_process_id(),
        intent.recovering_manager.boot_identity(),
        intent.recovering_manager.birth_identity(),
        intent.recovering_manager.containment_identity(),
        intent.command_key.as_str(),
        intent.digest.as_str(),
    ] {
        put_text(&mut bytes, text)?;
    }
    if bytes.len() > MAX_INTENT_BYTES {
        return Err(StoreError::InvalidInput(
            "supersession intent exceeds bound",
        ));
    }
    Ok(bytes)
}

struct CanonicalReader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> CanonicalReader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], StoreError> {
        let end = self.at.checked_add(count).ok_or(StoreError::Conflict(
            "supersession canonical length overflows",
        ))?;
        let value = self.bytes.get(self.at..end).ok_or(StoreError::Conflict(
            "supersession canonical intent is truncated",
        ))?;
        self.at = end;
        Ok(value)
    }
    fn u64(&mut self) -> Result<u64, StoreError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("eight bytes"),
        ))
    }
    fn text(&mut self) -> Result<String, StoreError> {
        let len = u32::from_be_bytes(self.take(4)?.try_into().expect("four bytes")) as usize;
        if len == 0 || len > 4096 {
            return Err(StoreError::Conflict(
                "supersession canonical text size differs",
            ));
        }
        String::from_utf8(self.take(len)?.to_vec())
            .map_err(|_| StoreError::Conflict("supersession canonical text is not UTF-8"))
    }
    fn inputs(&mut self) -> Result<BTreeMap<ResourceId, InputEpoch>, StoreError> {
        let count = u16::from_be_bytes(self.take(2)?.try_into().expect("two bytes")) as usize;
        if !(1..=64).contains(&count) {
            return Err(StoreError::Conflict(
                "supersession canonical resource count differs",
            ));
        }
        let mut inputs = BTreeMap::new();
        for _ in 0..count {
            let id = ResourceId::try_from(self.text()?.as_str())
                .map_err(|_| StoreError::Conflict("supersession canonical Resource ID differs"))?;
            let epoch = InputEpoch::new(self.u64()?)
                .map_err(|_| StoreError::Conflict("supersession canonical input epoch differs"))?;
            if inputs.insert(id, epoch).is_some() {
                return Err(StoreError::Conflict("duplicate canonical Resource ID"));
            }
        }
        Ok(inputs)
    }
    fn peer(&mut self) -> Result<AttestedPeer, StoreError> {
        let os = self.text()?;
        let pid = self.text()?;
        let boot = self.text()?;
        let birth = self.text()?;
        let containment = self.text()?;
        AttestedPeer::from_port(&os, &pid, &boot, &birth, &containment)
            .map_err(|_| StoreError::Conflict("supersession canonical peer differs"))
    }
}

fn decode_canonical_intent(bytes: &[u8]) -> Result<PendingRebindSupersession, StoreError> {
    if bytes.len() > MAX_INTENT_BYTES || !bytes.starts_with(DOMAIN) {
        return Err(StoreError::Conflict(
            "supersession canonical domain differs",
        ));
    }
    let mut reader = CanonicalReader {
        bytes,
        at: DOMAIN.len(),
    };
    let identity = PodFenceIdentity {
        store_lineage: StoreLineageId::try_from(reader.text()?.as_str())
            .map_err(|_| StoreError::Conflict("supersession canonical lineage differs"))?,
        scope_id: ScopeId::try_from(reader.text()?.as_str())
            .map_err(|_| StoreError::Conflict("supersession canonical scope differs"))?,
        pod_id: PodId::try_from(reader.text()?.as_str())
            .map_err(|_| StoreError::Conflict("supersession canonical Pod differs"))?,
        attempt_id: podbay_core::AttemptId::try_from(reader.text()?.as_str())
            .map_err(|_| StoreError::Conflict("supersession canonical Attempt differs"))?,
        incarnation: Epoch::new(reader.u64()?)
            .map_err(|_| StoreError::Conflict("supersession canonical incarnation differs"))?,
    };
    let abandoned = RebindProposal {
        identity,
        expected_owner_epoch: OwnerEpoch::new(reader.u64()?)
            .map_err(|_| StoreError::Conflict("supersession canonical old owner differs"))?,
        next_owner_epoch: OwnerEpoch::new(reader.u64()?)
            .map_err(|_| StoreError::Conflict("supersession canonical next owner differs"))?,
        expected_credential_epoch: CredentialEpoch::new(reader.u64()?)
            .map_err(|_| StoreError::Conflict("supersession canonical old credential differs"))?,
        next_credential_epoch: CredentialEpoch::new(reader.u64()?)
            .map_err(|_| StoreError::Conflict("supersession canonical next credential differs"))?,
        expected_input_epochs: reader.inputs()?,
        next_input_epochs: reader.inputs()?,
        next_manager: reader.peer()?,
        command_key: CommandKey::try_from(reader.text()?.as_str())
            .map_err(|_| StoreError::Conflict("supersession canonical B key differs"))?,
        digest: RequestDigest::parse(&reader.text()?)
            .map_err(|_| StoreError::Conflict("supersession canonical B digest differs"))?,
    };
    let pending_phase = match reader.take(1)?[0] {
        1 => RebindPhase::PendingStore,
        2 => RebindPhase::PendingPod,
        _ => {
            return Err(StoreError::Conflict(
                "supersession canonical pending phase differs",
            ));
        }
    };
    let pending_checkpoint_digest = RequestDigest::parse(&reader.text()?)
        .map_err(|_| StoreError::Conflict("supersession canonical pending digest differs"))?;
    let pending_process = PendingPodProcessEvidence {
        supervisor_process_id: reader.text()?,
        supervisor_birth_identity: reader.text()?,
        child_process_id: reader.text()?,
        child_birth_identity: reader.text()?,
        boot_identity: reader.text()?,
        containment_identity: reader.text()?,
    };
    let recovering_owner_epoch = OwnerEpoch::new(reader.u64()?)
        .map_err(|_| StoreError::Conflict("supersession canonical recovery owner differs"))?;
    let recovering_credential_epoch = CredentialEpoch::new(reader.u64()?)
        .map_err(|_| StoreError::Conflict("supersession canonical recovery credential differs"))?;
    let recovering_input_epochs = reader.inputs()?;
    let recovering_manager = reader.peer()?;
    let command_key = CommandKey::try_from(reader.text()?.as_str())
        .map_err(|_| StoreError::Conflict("supersession canonical recovery key differs"))?;
    let digest = RequestDigest::parse(&reader.text()?)
        .map_err(|_| StoreError::Conflict("supersession canonical recovery digest differs"))?;
    let intent = PendingRebindSupersession {
        abandoned,
        pending_phase,
        pending_checkpoint_digest,
        pending_process,
        recovering_owner_epoch,
        recovering_credential_epoch,
        recovering_input_epochs,
        recovering_manager,
        command_key,
        digest,
    };
    if reader.at != bytes.len() || canonical_intent(&intent)? != bytes {
        return Err(StoreError::Conflict("supersession canonical bytes differ"));
    }
    Ok(intent)
}

fn validate_shape(intent: &PendingRebindSupersession) -> Result<(), StoreError> {
    let abandoned = &intent.abandoned;
    if intent.recovering_owner_epoch.get() <= abandoned.next_owner_epoch.get()
        || intent.recovering_credential_epoch.get() <= abandoned.next_credential_epoch.get()
        || intent.recovering_manager == abandoned.next_manager
        || intent.recovering_manager.containment_identity()
            != abandoned.next_manager.containment_identity()
        || intent.recovering_input_epochs.len() != abandoned.next_input_epochs.len()
        || intent.pending_process.containment_identity.len() > 4096
    {
        return Err(StoreError::InvalidInput("supersession shape differs"));
    }
    for (id, old) in &abandoned.next_input_epochs {
        let next = intent
            .recovering_input_epochs
            .get(id)
            .ok_or(StoreError::InvalidInput(
                "supersession resource set differs",
            ))?;
        if next.get() <= old.get() {
            return Err(StoreError::InvalidInput(
                "supersession input epoch did not advance",
            ));
        }
        sqlite_counter(next.get())?;
    }
    for text in [
        intent.pending_process.supervisor_process_id.as_str(),
        intent.pending_process.supervisor_birth_identity.as_str(),
        intent.pending_process.child_process_id.as_str(),
        intent.pending_process.child_birth_identity.as_str(),
        intent.pending_process.boot_identity.as_str(),
        intent.pending_process.containment_identity.as_str(),
    ] {
        if text.is_empty() || text.chars().any(char::is_control) {
            return Err(StoreError::InvalidInput(
                "supersession process evidence malformed",
            ));
        }
    }
    for value in [
        intent.recovering_owner_epoch.get(),
        intent.recovering_credential_epoch.get(),
    ] {
        sqlite_counter(value)?;
    }
    Ok(())
}

fn phase_text(phase: DurableRebindPhase) -> &'static str {
    match phase {
        DurableRebindPhase::Pending => "pending",
        DurableRebindPhase::PodAcknowledged => "pod_acknowledged",
        DurableRebindPhase::Activated => "activated",
    }
}

fn observed_text(phase: RebindPhase) -> &'static str {
    match phase {
        RebindPhase::PendingStore => "pending_store",
        RebindPhase::PendingPod => "pending_pod",
        RebindPhase::Active => "active_prior",
    }
}

fn verify_abandoned(
    transaction: &Transaction<'_>,
    intent: &PendingRebindSupersession,
    lineage: &str,
) -> Result<(i64, DurableRebindPhase, Option<String>, String, String), StoreError> {
    let (rowid, receipt) =
        load_by_key(transaction, &intent.abandoned)?.ok_or(StoreError::NotFound)?;
    verify_stored(transaction, rowid, &intent.abandoned, lineage)?;
    if receipt.phase != DurableRebindPhase::Pending
        && intent.pending_phase != RebindPhase::PendingPod
    {
        return Err(StoreError::Conflict("abandoned store/pod phases differ"));
    }
    if receipt
        .pod_checkpoint_ref
        .as_deref()
        .is_some_and(|digest| digest != intent.pending_checkpoint_digest.as_str())
    {
        return Err(StoreError::Conflict("abandoned pending checkpoint differs"));
    }
    let prior: Option<(String, i64, i64, String, String, String, String)> = transaction
        .query_row(
            "SELECT checkpoint_digest,supervisor_pid,supervisor_start_ticks,
                    boot_id,unit_name,cgroup_path,schema_version
             FROM manager_rebind_prior_observations WHERE rebind_rowid=?1",
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
                ))
            },
        )
        .optional()?;
    let (prior_digest, supervisor_pid, supervisor_birth, boot, unit, cgroup, schema) = prior
        .ok_or(StoreError::Conflict(
            "abandoned rebind lacks prior observation",
        ))?;
    if schema != "podbay.prior-checkpoint/1"
        || supervisor_pid.to_string() != intent.pending_process.supervisor_process_id
        || supervisor_birth.to_string() != intent.pending_process.supervisor_birth_identity
        || boot != intent.pending_process.boot_identity
        || cgroup != intent.pending_process.containment_identity
    {
        return Err(StoreError::Conflict(
            "pending pod process differs from prior observation",
        ));
    }
    Ok((
        rowid,
        receipt.phase,
        receipt.pod_checkpoint_ref,
        unit,
        prior_digest,
    ))
}

fn verify_current_recoverer(
    transaction: &Transaction<'_>,
    intent: &PendingRebindSupersession,
    lineage: &str,
) -> Result<(), StoreError> {
    let owner: i64 = transaction.query_row(
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
    let expected_owner = sqlite_counter(intent.recovering_owner_epoch.get())?;
    let expected_credential = sqlite_counter(intent.recovering_credential_epoch.get())?;
    if owner != expected_owner
        || claim != Some((lineage.into(), expected_owner, expected_credential))
    {
        return Err(StoreError::StaleEpoch);
    }
    let peer: Option<(String, String, String, String, String)> = transaction
        .query_row(
            "SELECT os_identity,process_identity,boot_identity,birth_identity,containment_identity
         FROM manager_peer_bindings WHERE store_lineage=?1 AND owner_epoch=?2
           AND credential_epoch=?3 AND peer_schema='podbay.attested-peer/1'",
            params![lineage, expected_owner, expected_credential],
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
            intent.recovering_manager.os_identity().into(),
            intent.recovering_manager.native_process_id().into(),
            intent.recovering_manager.boot_identity().into(),
            intent.recovering_manager.birth_identity().into(),
            intent.recovering_manager.containment_identity().into(),
        ))
    {
        return Err(StoreError::StaleEpoch);
    }
    let identity = &intent.abandoned.identity;
    let pod: Option<(String, i64)> = transaction
        .query_row(
            "SELECT scope_id,incarnation FROM authority_pods WHERE pod_id=?1",
            [identity.pod_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let target: Option<i64> = transaction
        .query_row(
            "SELECT epoch FROM target_epochs WHERE scope_id=?1 AND target_id=?2",
            params![identity.scope_id.as_str(), identity.pod_id.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    let incarnation = sqlite_counter(identity.incarnation.get())?;
    if pod != Some((identity.scope_id.as_str().into(), incarnation)) || target != Some(incarnation)
    {
        return Err(StoreError::StaleEpoch);
    }
    let bound: Option<(String, i64)> = transaction
        .query_row(
            "SELECT attempt_id,resource_count FROM launch_bindings
         WHERE scope_id=?1 AND pod_id=?2 AND pod_incarnation=?3",
            params![
                identity.scope_id.as_str(),
                identity.pod_id.as_str(),
                incarnation
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if bound
        != Some((
            identity.attempt_id.as_str().into(),
            intent.recovering_input_epochs.len() as i64,
        ))
    {
        return Err(StoreError::WrongScope);
    }
    let mut launch_resources = BTreeMap::new();
    let mut launch_statement = transaction.prepare(
        "SELECT resource.resource_id,resource.resource_epoch
         FROM launch_resources AS resource
         JOIN launch_bindings AS binding ON binding.command_rowid=resource.command_rowid
         WHERE binding.scope_id=?1 AND binding.pod_id=?2 AND binding.pod_incarnation=?3",
    )?;
    for row in launch_statement.query_map(
        params![
            identity.scope_id.as_str(),
            identity.pod_id.as_str(),
            incarnation
        ],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
    )? {
        let (id, epoch) = row?;
        if launch_resources.insert(id, epoch).is_some() {
            return Err(StoreError::Conflict("duplicate bound recovery resource"));
        }
    }
    if launch_resources.len() != intent.recovering_input_epochs.len() {
        return Err(StoreError::StaleEpoch);
    }
    let mut resources = BTreeMap::new();
    let mut statement = transaction.prepare(
        "SELECT resource_id,scope_id,pod_incarnation,resource_epoch,input_epoch
         FROM authority_resources WHERE pod_id=?1 ORDER BY resource_id",
    )?;
    let rows = statement.query_map([identity.pod_id.as_str()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })?;
    for row in rows {
        let (id, scope, pod_incarnation, resource_epoch, input_epoch) = row?;
        if resources
            .insert(id, (scope, pod_incarnation, resource_epoch, input_epoch))
            .is_some()
        {
            return Err(StoreError::Conflict("duplicate recovery resource"));
        }
    }
    if resources.len() != intent.recovering_input_epochs.len() {
        return Err(StoreError::StaleEpoch);
    }
    for (id, epoch) in &intent.recovering_input_epochs {
        if resources.get(id.as_str())
            != Some(&(
                identity.scope_id.as_str().into(),
                incarnation,
                *launch_resources
                    .get(id.as_str())
                    .ok_or(StoreError::StaleEpoch)?,
                sqlite_counter(epoch.get())?,
            ))
        {
            return Err(StoreError::StaleEpoch);
        }
    }
    Ok(())
}

fn load_attempt(
    transaction: &Transaction<'_>,
    intent: &PendingRebindSupersession,
    canonical: &[u8],
    abandoned_rowid: i64,
) -> Result<Option<SupersessionReceipt>, StoreError> {
    let identity = &intent.abandoned.identity;
    let row: Option<(
        i64,
        i64,
        Vec<u8>,
        String,
        Option<String>,
        Option<i64>,
        String,
        i64,
        i64,
    )> = transaction
        .query_row(
            "SELECT supersession_rowid,abandoned_rebind_rowid,intent_bytes,phase,
                recovery_checkpoint_digest,predecessor_rowid,request_digest,
                recovering_owner_epoch,recovering_credential_epoch
         FROM rebind_supersession_attempts
         WHERE scope_id=?1 AND pod_id=?2 AND pod_incarnation=?3 AND command_key=?4",
            params![
                identity.scope_id.as_str(),
                identity.pod_id.as_str(),
                sqlite_counter(identity.incarnation.get())?,
                intent.command_key.as_str()
            ],
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
                ))
            },
        )
        .optional()?;
    let Some((
        rowid,
        stored_abandoned,
        bytes,
        stage,
        digest,
        predecessor,
        stored_digest,
        recovering_owner,
        recovering_credential,
    )) = row
    else {
        return Ok(None);
    };
    if stored_abandoned != abandoned_rowid
        || bytes != canonical
        || stored_digest != intent.digest.as_str()
        || recovering_owner != sqlite_counter(intent.recovering_owner_epoch.get())?
        || recovering_credential != sqlite_counter(intent.recovering_credential_epoch.get())?
    {
        return Err(StoreError::Conflict(
            "supersession key changed exact intent",
        ));
    }
    let scalar_exact: i64 = transaction.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM rebind_supersession_attempts AS s
           JOIN manager_rebinds AS b ON b.rebind_rowid=s.abandoned_rebind_rowid
           JOIN manager_rebind_prior_observations AS prior
             ON prior.rebind_rowid=b.rebind_rowid
           WHERE s.supersession_rowid=:rowid AND s.store_lineage=:lineage
             AND s.scope_id=:scope AND s.pod_id=:pod AND s.attempt_id=:attempt
             AND s.pod_incarnation=:incarnation
             AND s.abandoned_request_digest=:abandoned_digest
             AND s.abandoned_phase=b.phase
             AND COALESCE(s.abandoned_checkpoint_ref,'')=COALESCE(b.pod_checkpoint_ref,'')
             AND s.prior_active_checkpoint_digest=prior.checkpoint_digest
             AND s.observed_phase=:observed_phase
             AND s.observed_checkpoint_digest=:observed_digest
             AND s.supervisor_process_id=:supervisor_pid
             AND s.supervisor_birth_identity=:supervisor_birth
             AND s.child_process_id=:child_pid AND s.child_birth_identity=:child_birth
             AND s.boot_identity=:boot AND s.unit_name=prior.unit_name
             AND s.cgroup_path=:cgroup
             AND s.recovering_os_identity=:recovering_os
             AND s.recovering_process_id=:recovering_pid
             AND s.recovering_boot_identity=:recovering_boot
             AND s.recovering_birth_identity=:recovering_birth
             AND s.recovering_containment=:recovering_containment
             AND s.command_key=:key AND s.resource_count=:resource_count)",
        named_params! {
            ":rowid": rowid,
            ":lineage": identity.store_lineage.as_str(),
            ":scope": identity.scope_id.as_str(),
            ":pod": identity.pod_id.as_str(),
            ":attempt": identity.attempt_id.as_str(),
            ":incarnation": sqlite_counter(identity.incarnation.get())?,
            ":abandoned_digest": intent.abandoned.digest.as_str(),
            ":observed_phase": observed_text(intent.pending_phase),
            ":observed_digest": intent.pending_checkpoint_digest.as_str(),
            ":supervisor_pid": intent.pending_process.supervisor_process_id.as_str(),
            ":supervisor_birth": intent.pending_process.supervisor_birth_identity.as_str(),
            ":child_pid": intent.pending_process.child_process_id.as_str(),
            ":child_birth": intent.pending_process.child_birth_identity.as_str(),
            ":boot": intent.pending_process.boot_identity.as_str(),
            ":cgroup": intent.pending_process.containment_identity.as_str(),
            ":recovering_os": intent.recovering_manager.os_identity(),
            ":recovering_pid": intent.recovering_manager.native_process_id(),
            ":recovering_boot": intent.recovering_manager.boot_identity(),
            ":recovering_birth": intent.recovering_manager.birth_identity(),
            ":recovering_containment": intent.recovering_manager.containment_identity(),
            ":key": intent.command_key.as_str(),
            ":resource_count": intent.recovering_input_epochs.len() as i64,
        },
        |row| row.get(0),
    )?;
    if scalar_exact != 1 {
        return Err(StoreError::Conflict("supersession scalar proof differs"));
    }
    let mut resources = BTreeMap::new();
    let mut statement = transaction.prepare(
        "SELECT resource_id,abandoned_input_epoch,recovering_input_epoch
         FROM rebind_supersession_resources WHERE supersession_rowid=?1 ORDER BY resource_id",
    )?;
    for row in statement.query_map([rowid], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })? {
        let (id, old, next) = row?;
        if resources.insert(id, (old, next)).is_some() {
            return Err(StoreError::Conflict("duplicate supersession resource"));
        }
    }
    if resources.len() != intent.recovering_input_epochs.len() {
        return Err(StoreError::Conflict("supersession resource count differs"));
    }
    for (id, old) in &intent.abandoned.next_input_epochs {
        let next = intent
            .recovering_input_epochs
            .get(id)
            .ok_or(StoreError::Conflict("supersession resource set differs"))?;
        if resources.get(id.as_str())
            != Some(&(sqlite_counter(old.get())?, sqlite_counter(next.get())?))
        {
            return Err(StoreError::Conflict("supersession resource vector differs"));
        }
    }
    Ok(Some(SupersessionReceipt {
        rowid,
        predecessor_rowid: predecessor,
        command_key: intent.command_key.as_str().into(),
        request_digest: intent.digest.as_str().into(),
        stage: decode_stage(&stage)?,
        recovery_checkpoint_digest: digest,
    }))
}

impl PodBayStore {
    /// Indexed read of the newest abandoned B row and its newest C Planned
    /// attempt for one store-derived Pod identity. This is historical data,
    /// not evidence that C died or that the pod fsynced recovery Active A.
    pub fn latest_planned_recovery_for_pod(
        &mut self,
        identity: &PodFenceIdentity,
    ) -> Result<Option<PriorPlannedRecovery>, StoreError> {
        if identity.store_lineage.as_str() != self.store_lineage {
            return Err(StoreError::WrongScope);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let abandoned_rowid: Option<i64> = transaction
            .query_row(
                "SELECT rebind_rowid FROM manager_rebinds
             WHERE store_lineage=?1 AND scope_id=?2 AND pod_id=?3 AND attempt_id=?4
               AND pod_incarnation=?5 ORDER BY next_owner_epoch DESC LIMIT 1",
                params![
                    identity.store_lineage.as_str(),
                    identity.scope_id.as_str(),
                    identity.pod_id.as_str(),
                    identity.attempt_id.as_str(),
                    sqlite_counter(identity.incarnation.get())?
                ],
                |row| row.get(0),
            )
            .optional()?;
        let Some(abandoned_rowid) = abandoned_rowid else {
            transaction.commit()?;
            return Ok(None);
        };
        let latest: Option<(i64, Vec<u8>, String)> = transaction
            .query_row(
                "SELECT supersession_rowid,intent_bytes,phase
             FROM rebind_supersession_attempts WHERE abandoned_rebind_rowid=?1
             ORDER BY supersession_rowid DESC LIMIT 1",
                [abandoned_rowid],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((latest_rowid, bytes, phase)) = latest else {
            transaction.commit()?;
            return Ok(None);
        };
        if phase != "planned" {
            transaction.commit()?;
            return Ok(None);
        }
        let intent = decode_canonical_intent(&bytes)?;
        if &intent.abandoned.identity != identity {
            return Err(StoreError::WrongScope);
        }
        let (verified_rowid, _, _, _, _) =
            verify_abandoned(&transaction, &intent, &self.store_lineage)?;
        if verified_rowid != abandoned_rowid {
            return Err(StoreError::Conflict(
                "latest recovery abandoned row differs",
            ));
        }
        let receipt = load_attempt(&transaction, &intent, &bytes, abandoned_rowid)?
            .ok_or(StoreError::Conflict("latest recovery attempt vanished"))?;
        if receipt.rowid != latest_rowid || receipt.stage != SupersessionStage::Planned {
            return Err(StoreError::Conflict("latest recovery attempt differs"));
        }
        let prior_peer: Option<(String,String,String,String,String)> = transaction.query_row(
            "SELECT os_identity,process_identity,boot_identity,birth_identity,containment_identity
             FROM manager_peer_bindings WHERE store_lineage=?1 AND owner_epoch=?2
               AND credential_epoch=?3 AND peer_schema='podbay.attested-peer/1'",
            params![identity.store_lineage.as_str(),
                sqlite_counter(intent.abandoned.expected_owner_epoch.get())?,
                sqlite_counter(intent.abandoned.expected_credential_epoch.get())?],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        ).optional()?;
        let (os, pid, boot, birth, containment) = prior_peer.ok_or(StoreError::Conflict(
            "prior Active manager peer is unavailable",
        ))?;
        let prior_manager_peer = AttestedPeer::from_port(&os, &pid, &boot, &birth, &containment)
            .map_err(|_| StoreError::Conflict("prior Active manager peer is malformed"))?;
        let current_owner: i64 = transaction.query_row(
            "SELECT value FROM metadata WHERE key='owner_epoch'",
            [],
            |row| row.get(0),
        )?;
        if current_owner <= sqlite_counter(intent.recovering_owner_epoch.get())? {
            return Err(StoreError::StaleEpoch);
        }
        transaction.commit()?;
        Ok(Some(PriorPlannedRecovery {
            intent,
            receipt,
            prior_manager_peer,
        }))
    }

    /// Trusted host only. The host must independently attest the live pod
    /// socket/child and abandoned manager death. This transaction verifies
    /// exact committed B row, current C owner/peer and full Resource vector;
    /// it creates no pod checkpoint or grant. `predecessor_rowid` is the
    /// latest same-abandoned-row attempt observed by the trusted host.
    pub fn plan_pending_rebind_supersession(
        &mut self,
        intent: &PendingRebindSupersession,
        predecessor_rowid: Option<i64>,
    ) -> Result<SupersessionReceipt, StoreError> {
        validate_shape(intent)?;
        let canonical = canonical_intent(intent)?;
        let lineage = self.store_lineage.clone();
        if intent.abandoned.identity.store_lineage.as_str() != lineage {
            return Err(StoreError::WrongScope);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (abandoned_rowid, abandoned_phase, abandoned_ref, unit, prior_digest) =
            verify_abandoned(&transaction, intent, &lineage)?;
        verify_current_recoverer(&transaction, intent, &lineage)?;
        if let Some(existing) = load_attempt(&transaction, intent, &canonical, abandoned_rowid)? {
            if existing.predecessor_rowid != predecessor_rowid {
                return Err(StoreError::Conflict("supersession predecessor changed"));
            }
            transaction.commit()?;
            return Ok(existing);
        }
        let latest: Option<(i64, String, i64, i64)> = transaction
            .query_row(
                "SELECT supersession_rowid,phase,recovering_owner_epoch,
                    recovering_credential_epoch FROM rebind_supersession_attempts
             WHERE abandoned_rebind_rowid=?1 ORDER BY supersession_rowid DESC LIMIT 1",
                [abandoned_rowid],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let recovering_owner = sqlite_counter(intent.recovering_owner_epoch.get())?;
        let recovering_credential = sqlite_counter(intent.recovering_credential_epoch.get())?;
        if latest.as_ref().map(|(rowid, _, _, _)| *rowid) != predecessor_rowid
            || latest
                .as_ref()
                .is_some_and(|(_, phase, owner, credential)| {
                    phase != "planned"
                        || *owner >= recovering_owner
                        || *credential >= recovering_credential
                })
        {
            return Err(StoreError::StaleEpoch);
        }
        if let Some((prior_rowid, _, _, _)) = latest {
            let mut previous_inputs = BTreeMap::new();
            let mut statement = transaction.prepare(
                "SELECT resource_id,recovering_input_epoch
                 FROM rebind_supersession_resources WHERE supersession_rowid=?1",
            )?;
            for row in statement.query_map([prior_rowid], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })? {
                let (id, epoch) = row?;
                if previous_inputs.insert(id, epoch).is_some() {
                    return Err(StoreError::Conflict("duplicate predecessor input"));
                }
            }
            if previous_inputs.len() != intent.recovering_input_epochs.len() {
                return Err(StoreError::StaleEpoch);
            }
            for (id, next) in &intent.recovering_input_epochs {
                let next = sqlite_counter(next.get())?;
                if previous_inputs
                    .get(id.as_str())
                    .is_none_or(|old| *old >= next)
                {
                    return Err(StoreError::StaleEpoch);
                }
            }
        }
        let identity = &intent.abandoned.identity;
        transaction.execute(
            "INSERT INTO rebind_supersession_attempts(
               store_lineage,scope_id,pod_id,attempt_id,pod_incarnation,
               abandoned_rebind_rowid,abandoned_request_digest,abandoned_phase,
               abandoned_checkpoint_ref,prior_active_checkpoint_digest,observed_phase,
               observed_checkpoint_digest,supervisor_process_id,supervisor_birth_identity,
               child_process_id,child_birth_identity,boot_identity,unit_name,cgroup_path,
               recovering_owner_epoch,recovering_credential_epoch,recovering_os_identity,
               recovering_process_id,recovering_boot_identity,recovering_birth_identity,
               recovering_containment,command_key,request_digest,intent_bytes,
               predecessor_rowid,resource_count,phase)
             VALUES(:lineage,:scope,:pod,:attempt,:incarnation,:abandoned,:abandoned_digest,
               :abandoned_phase,:abandoned_ref,:prior_digest,:observed_phase,:observed_digest,
               :supervisor_pid,:supervisor_birth,:child_pid,:child_birth,:boot,:unit,:cgroup,
               :recovering_owner,:recovering_credential,:recovering_os,:recovering_pid,
               :recovering_boot,:recovering_birth,:recovering_containment,:key,:digest,
               :intent_bytes,:predecessor,:resource_count,'planned')",
            named_params! {
                ":lineage": lineage,
                ":scope": identity.scope_id.as_str(),
                ":pod": identity.pod_id.as_str(),
                ":attempt": identity.attempt_id.as_str(),
                ":incarnation": sqlite_counter(identity.incarnation.get())?,
                ":abandoned": abandoned_rowid,
                ":abandoned_digest": intent.abandoned.digest.as_str(),
                ":abandoned_phase": phase_text(abandoned_phase),
                ":abandoned_ref": abandoned_ref,
                ":prior_digest": prior_digest,
                ":observed_phase": observed_text(intent.pending_phase),
                ":observed_digest": intent.pending_checkpoint_digest.as_str(),
                ":supervisor_pid": intent.pending_process.supervisor_process_id.as_str(),
                ":supervisor_birth": intent.pending_process.supervisor_birth_identity.as_str(),
                ":child_pid": intent.pending_process.child_process_id.as_str(),
                ":child_birth": intent.pending_process.child_birth_identity.as_str(),
                ":boot": intent.pending_process.boot_identity.as_str(),
                ":unit": unit,
                ":cgroup": intent.pending_process.containment_identity.as_str(),
                ":recovering_owner": sqlite_counter(intent.recovering_owner_epoch.get())?,
                ":recovering_credential": sqlite_counter(intent.recovering_credential_epoch.get())?,
                ":recovering_os": intent.recovering_manager.os_identity(),
                ":recovering_pid": intent.recovering_manager.native_process_id(),
                ":recovering_boot": intent.recovering_manager.boot_identity(),
                ":recovering_birth": intent.recovering_manager.birth_identity(),
                ":recovering_containment": intent.recovering_manager.containment_identity(),
                ":key": intent.command_key.as_str(),
                ":digest": intent.digest.as_str(),
                ":intent_bytes": canonical,
                ":predecessor": predecessor_rowid,
                ":resource_count": intent.recovering_input_epochs.len() as i64,
            },
        )?;
        let rowid = transaction.last_insert_rowid();
        for (id, old) in &intent.abandoned.next_input_epochs {
            let next = intent
                .recovering_input_epochs
                .get(id)
                .ok_or(StoreError::Conflict("supersession resource set differs"))?;
            transaction.execute(
                "INSERT INTO rebind_supersession_resources(supersession_rowid,resource_id,
                   abandoned_input_epoch,recovering_input_epoch) VALUES(?1,?2,?3,?4)",
                params![
                    rowid,
                    id.as_str(),
                    sqlite_counter(old.get())?,
                    sqlite_counter(next.get())?
                ],
            )?;
        }
        let receipt = load_attempt(&transaction, intent, &canonical, abandoned_rowid)?
            .ok_or(StoreError::Conflict("supersession insert readback missing"))?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Trusted host CAS after nonce-bound pod ACK and fsync readback. The
    /// database cannot prove that ACK from this digest alone; no caller JSON
    /// may invoke this method. An exact repeat returns the same receipt.
    pub fn acknowledge_pending_rebind_supersession(
        &mut self,
        intent: &PendingRebindSupersession,
        recovery_checkpoint_digest: &str,
    ) -> Result<SupersessionReceipt, StoreError> {
        if recovery_checkpoint_digest.len() != 64
            || !recovery_checkpoint_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(StoreError::InvalidInput(
                "recovery checkpoint digest is invalid",
            ));
        }
        let canonical = canonical_intent(intent)?;
        let lineage = self.store_lineage.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (abandoned_rowid, _, _, _, _) = verify_abandoned(&transaction, intent, &lineage)?;
        verify_current_recoverer(&transaction, intent, &lineage)?;
        let prior = load_attempt(&transaction, intent, &canonical, abandoned_rowid)?
            .ok_or(StoreError::NotFound)?;
        let latest: Option<i64> = transaction
            .query_row(
                "SELECT supersession_rowid FROM rebind_supersession_attempts
             WHERE abandoned_rebind_rowid=?1 ORDER BY supersession_rowid DESC LIMIT 1",
                [abandoned_rowid],
                |row| row.get(0),
            )
            .optional()?;
        if latest != Some(prior.rowid) {
            return Err(StoreError::StaleEpoch);
        }
        if prior.stage == SupersessionStage::PodCheckpointed {
            if prior.recovery_checkpoint_digest.as_deref() != Some(recovery_checkpoint_digest) {
                return Err(StoreError::Conflict("recovery checkpoint digest changed"));
            }
            transaction.commit()?;
            return Ok(prior);
        }
        if prior.stage != SupersessionStage::Planned {
            return Err(StoreError::StaleEpoch);
        }
        let changed = transaction.execute(
            "UPDATE rebind_supersession_attempts
             SET phase='pod_checkpointed',recovery_checkpoint_digest=?1
             WHERE supersession_rowid=?2 AND phase='planned' AND recovery_checkpoint_digest IS NULL",
            params![recovery_checkpoint_digest,prior.rowid],
        )?;
        if changed != 1 {
            return Err(StoreError::StaleEpoch);
        }
        let receipt = load_attempt(&transaction, intent, &canonical, abandoned_rowid)?
            .ok_or(StoreError::Conflict("supersession ACK readback missing"))?;
        transaction.commit()?;
        Ok(receipt)
    }
}

/// A fresh read-only pod witness for the exact latest planned attempt. The
/// pod must still attest the connected manager/child and pending checkpoint
/// before invoking `PodPeerFence::supersede_pending_rebind`.
pub struct SqliteSupersessionLedger {
    database: PathBuf,
    identity: PodFenceIdentity,
}

impl SqliteSupersessionLedger {
    pub fn for_pod(database: impl AsRef<Path>, identity: PodFenceIdentity) -> Self {
        Self {
            database: database.as_ref().to_path_buf(),
            identity,
        }
    }
}

impl SupersessionLedger for SqliteSupersessionLedger {
    fn supersedes(&self, intent: &PendingRebindSupersession) -> bool {
        if intent.abandoned.identity != self.identity {
            return false;
        }
        let Ok(canonical) = canonical_intent(intent) else {
            return false;
        };
        let Ok(mut store) = PodBayStore::open_existing_read_only(&self.database) else {
            return false;
        };
        let lineage = store.store_lineage.clone();
        let Ok(transaction) = store
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
        else {
            return false;
        };
        let Ok((abandoned_rowid, _, _, _, _)) = verify_abandoned(&transaction, intent, &lineage)
        else {
            return false;
        };
        if verify_current_recoverer(&transaction, intent, &lineage).is_err() {
            return false;
        }
        let Ok(Some(receipt)) = load_attempt(&transaction, intent, &canonical, abandoned_rowid)
        else {
            return false;
        };
        if receipt.stage != SupersessionStage::Planned {
            return false;
        }
        let latest: Option<i64> = transaction
            .query_row(
                "SELECT supersession_rowid FROM rebind_supersession_attempts
             WHERE abandoned_rebind_rowid=?1 ORDER BY supersession_rowid DESC LIMIT 1",
                [abandoned_rowid],
                |row| row.get(0),
            )
            .optional()
            .ok()
            .flatten();
        latest == Some(receipt.rowid)
    }
}

/// The only store-side exception to an abandoned unfinished/Activated B row.
/// The host must have freshly attested `observed` from the live recovered pod;
/// this query merely links that exact checkpoint to a committed v21 ACK and
/// the full current Resource vector in one SQLite snapshot.
pub(crate) fn recovered_abandoned_rowid(
    transaction: &Transaction<'_>,
    proposal: &RebindProposal,
    observed: &HostObservedPriorCheckpoint,
    lineage: &str,
) -> Result<Option<i64>, StoreError> {
    let identity = &proposal.identity;
    let mut statement = transaction.prepare(
        "SELECT s.supersession_rowid,s.abandoned_rebind_rowid,s.resource_count
         FROM rebind_supersession_attempts AS s
         JOIN manager_rebinds AS b ON b.rebind_rowid=s.abandoned_rebind_rowid
         JOIN manager_rebind_prior_observations AS prior ON prior.rebind_rowid=b.rebind_rowid
         WHERE s.store_lineage=?1 AND s.scope_id=?2 AND s.pod_id=?3
           AND s.attempt_id=?4 AND s.pod_incarnation=?5
           AND s.phase='pod_checkpointed' AND s.recovery_checkpoint_digest=?6
           AND s.recovering_owner_epoch=?7 AND s.recovering_credential_epoch=?8
           AND s.recovering_os_identity=?9 AND s.recovering_process_id=?10
           AND s.recovering_boot_identity=?11 AND s.recovering_birth_identity=?12
           AND s.recovering_containment=?13
           AND s.supervisor_process_id=?14 AND s.supervisor_birth_identity=?15
           AND s.boot_identity=?16 AND s.unit_name=?17 AND s.cgroup_path=?18
           AND b.store_lineage=s.store_lineage AND b.scope_id=s.scope_id
           AND b.pod_id=s.pod_id AND b.attempt_id=s.attempt_id
           AND b.pod_incarnation=s.pod_incarnation
           AND b.expected_owner_epoch=?19 AND b.expected_credential_epoch=?20
           AND b.request_digest=s.abandoned_request_digest AND b.phase=s.abandoned_phase
           AND COALESCE(b.pod_checkpoint_ref,'')=COALESCE(s.abandoned_checkpoint_ref,'')
           AND prior.checkpoint_digest=s.prior_active_checkpoint_digest
           AND prior.supervisor_pid=?21 AND prior.supervisor_start_ticks=?22
           AND prior.boot_id=s.boot_identity AND prior.unit_name=s.unit_name
           AND prior.cgroup_path=s.cgroup_path
         ORDER BY s.supersession_rowid DESC LIMIT 2",
    )?;
    let rows = statement
        .query_map(
            params![
                lineage,
                identity.scope_id.as_str(),
                identity.pod_id.as_str(),
                identity.attempt_id.as_str(),
                sqlite_counter(identity.incarnation.get())?,
                observed.checkpoint_digest,
                sqlite_counter(proposal.next_owner_epoch.get())?,
                sqlite_counter(proposal.next_credential_epoch.get())?,
                proposal.next_manager.os_identity(),
                proposal.next_manager.native_process_id(),
                proposal.next_manager.boot_identity(),
                proposal.next_manager.birth_identity(),
                proposal.next_manager.containment_identity(),
                observed.supervisor_pid.to_string(),
                observed.supervisor_start_ticks.to_string(),
                observed.boot_id,
                observed.unit_name,
                observed.cgroup_path,
                sqlite_counter(observed.owner_epoch.get())?,
                sqlite_counter(observed.credential_epoch.get())?,
                sqlite_counter(u64::from(observed.supervisor_pid))?,
                sqlite_counter(observed.supervisor_start_ticks)?,
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let [(attempt_rowid, abandoned_rowid, resource_count)] = rows.as_slice() else {
        return if rows.is_empty() {
            Ok(None)
        } else {
            Err(StoreError::Conflict(
                "ambiguous recovered supersession proof",
            ))
        };
    };
    let latest: Option<i64> = transaction
        .query_row(
            "SELECT supersession_rowid FROM rebind_supersession_attempts
         WHERE abandoned_rebind_rowid=?1 ORDER BY supersession_rowid DESC LIMIT 1",
            [abandoned_rowid],
            |row| row.get(0),
        )
        .optional()?;
    if latest != Some(*attempt_rowid)
        || *resource_count != observed.input_epochs.len() as i64
        || observed.input_epochs != proposal.expected_input_epochs
    {
        return Err(StoreError::StaleEpoch);
    }
    let mut resources = BTreeMap::new();
    let mut statement = transaction.prepare(
        "SELECT rr.resource_id,rr.abandoned_input_epoch,rr.recovering_input_epoch,
                br.next_input_epoch,authority.input_epoch
         FROM rebind_supersession_resources AS rr
         JOIN manager_rebind_resources AS br
           ON br.rebind_rowid=?2 AND br.resource_id=rr.resource_id
         JOIN authority_resources AS authority ON authority.resource_id=rr.resource_id
         WHERE rr.supersession_rowid=?1 ORDER BY rr.resource_id",
    )?;
    for row in statement.query_map(params![attempt_rowid, abandoned_rowid], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })? {
        let (id, old, next, b_next, authority_next) = row?;
        if resources
            .insert(id, (old, next, b_next, authority_next))
            .is_some()
        {
            return Err(StoreError::Conflict(
                "duplicate recovered supersession resource",
            ));
        }
    }
    if resources.len() != observed.input_epochs.len() {
        return Err(StoreError::StaleEpoch);
    }
    for (id, old) in &observed.input_epochs {
        let next = proposal
            .next_input_epochs
            .get(id)
            .ok_or(StoreError::StaleEpoch)?;
        let expected = (
            sqlite_counter(old.get())?,
            sqlite_counter(next.get())?,
            sqlite_counter(old.get())?,
            sqlite_counter(next.get())?,
        );
        if resources.get(id.as_str()) != Some(&expected) {
            return Err(StoreError::StaleEpoch);
        }
    }
    Ok(Some(*abandoned_rowid))
}
