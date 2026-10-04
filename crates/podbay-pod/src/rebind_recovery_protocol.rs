//! Read-only, nonce-bound inspection of a surviving pod's Pending rebind.
//! Wire bytes are observations; they cannot plan or ACK a supersession row.
use std::collections::BTreeMap;

use podbay_core::{
    AttestedPeer, CommandKey, CredentialEpoch, InputEpoch, OwnerEpoch, PendingPodProcessEvidence,
    PendingRebindSupersession, PodFenceIdentity, RebindPhase, RebindProposal, RequestDigest,
    ResourceId,
};
use serde::{Deserialize, Serialize};

use crate::manifest::PodError;
use crate::rebind_protocol::{
    PeerWire, decode_request, encode_request, peer_from_wire, peer_to_wire,
};

pub const RECOVER_INSPECT_PROTOCOL: &str = "podbay.rebind-recover-inspect/1";
pub const RECOVER_PREPARE_PROTOCOL: &str = "podbay.rebind-recover-prepare/1";
const MAX_REQUEST_BYTES: usize = 4_096;
const MAX_RESPONSE_BYTES: usize = 65_536;
const MAX_PREPARE_REQUEST_BYTES: usize = 65_536;
const MAX_PREPARE_RESPONSE_BYTES: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryInspectRequest {
    pub protocol: String,
    pub operation: String,
    pub nonce: String,
    pub scope_id: String,
    pub pod_id: String,
    pub attempt_id: String,
    pub incarnation: u64,
    pub store_lineage: String,
    pub owner_epoch: u64,
    pub credential_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryInspectReplyWire {
    protocol: String,
    nonce: String,
    scope_id: String,
    pod_id: String,
    attempt_id: String,
    incarnation: u64,
    store_lineage: String,
    phase: String,
    checkpoint_digest: String,
    prior_checkpoint_digest: String,
    abandoned_prepare_json: String,
    supervisor_pid: u32,
    supervisor_start_ticks: u64,
    child_pid: u32,
    child_start_ticks: u64,
    boot_id: String,
    unit_name: String,
    cgroup_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryProcessWire {
    supervisor_process_id: String,
    supervisor_birth_identity: String,
    child_process_id: String,
    child_birth_identity: String,
    boot_identity: String,
    containment_identity: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryPrepareWire {
    protocol: String,
    operation: String,
    nonce: String,
    prior_checkpoint_digest: String,
    abandoned_prepare_json: String,
    pending_phase: String,
    pending_checkpoint_digest: String,
    pending_process: RecoveryProcessWire,
    recovering_owner_epoch: u64,
    recovering_credential_epoch: u64,
    recovering_input_epochs: BTreeMap<String, u64>,
    recovering_manager: PeerWire,
    command_key: String,
    request_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryPrepareReplyWire {
    protocol: String,
    nonce: String,
    scope_id: String,
    pod_id: String,
    attempt_id: String,
    incarnation: u64,
    store_lineage: String,
    phase: String,
    checkpoint_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DecodedRecoveryPrepare {
    pub intent: PendingRebindSupersession,
    pub prior_checkpoint_digest: String,
    pub nonce: String,
}

/// The pod's exact Pending checkpoint and live process observation from one
/// OS-attested socket exchange. This is not an admission or liveness proof for
/// the abandoned manager; the trusted host must independently recheck both.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingRecoveryInspection {
    pub identity: PodFenceIdentity,
    pub phase: RebindPhase,
    pub checkpoint_digest: String,
    pub prior_checkpoint_digest: String,
    pub abandoned: RebindProposal,
    pub supervisor_pid: u32,
    pub supervisor_start_ticks: u64,
    pub child_pid: u32,
    pub child_start_ticks: u64,
    pub boot_id: String,
    pub unit_name: String,
    pub cgroup_path: String,
}

fn invalid() -> PodError {
    PodError::Invalid("rebind recovery inspect wire differs")
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn nonce(value: &str) -> bool {
    value.len() == 64 && digest(value)
}

fn exact_identity(
    scope: &str,
    pod: &str,
    attempt: &str,
    incarnation: u64,
    lineage: &str,
    expected: &PodFenceIdentity,
) -> bool {
    scope == expected.scope_id.as_str()
        && pod == expected.pod_id.as_str()
        && attempt == expected.attempt_id.as_str()
        && incarnation == expected.incarnation.get()
        && lineage == expected.store_lineage.as_str()
}

pub(crate) fn encode_inspect_request(
    identity: &PodFenceIdentity,
    owner_epoch: u64,
    credential_epoch: u64,
    fresh_nonce: &str,
) -> Result<Vec<u8>, PodError> {
    if !nonce(fresh_nonce) || owner_epoch == 0 || credential_epoch == 0 {
        return Err(invalid());
    }
    let wire = RecoveryInspectRequest {
        protocol: RECOVER_INSPECT_PROTOCOL.into(),
        operation: "rebind.recover.inspect".into(),
        nonce: fresh_nonce.into(),
        scope_id: identity.scope_id.as_str().into(),
        pod_id: identity.pod_id.as_str().into(),
        attempt_id: identity.attempt_id.as_str().into(),
        incarnation: identity.incarnation.get(),
        store_lineage: identity.store_lineage.as_str().into(),
        owner_epoch,
        credential_epoch,
    };
    let bytes = serde_json::to_vec(&wire)?;
    decode_inspect_request(&bytes, identity)?;
    Ok(bytes)
}

pub(crate) fn decode_inspect_request(
    bytes: &[u8],
    expected: &PodFenceIdentity,
) -> Result<RecoveryInspectRequest, PodError> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
        return Err(invalid());
    }
    let request: RecoveryInspectRequest = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if request.protocol != RECOVER_INSPECT_PROTOCOL
        || request.operation != "rebind.recover.inspect"
        || !nonce(&request.nonce)
        || request.owner_epoch == 0
        || request.credential_epoch == 0
        || !exact_identity(
            &request.scope_id,
            &request.pod_id,
            &request.attempt_id,
            request.incarnation,
            &request.store_lineage,
            expected,
        )
    {
        return Err(invalid());
    }
    Ok(request)
}

pub(crate) fn encode_pending_reply(
    inspection: &PendingRecoveryInspection,
    echoed_nonce: &str,
) -> Result<Vec<u8>, PodError> {
    if !nonce(echoed_nonce)
        || !matches!(
            inspection.phase,
            RebindPhase::PendingStore | RebindPhase::PendingPod
        )
        || !digest(&inspection.checkpoint_digest)
        || !digest(&inspection.prior_checkpoint_digest)
        || inspection.abandoned.identity != inspection.identity
    {
        return Err(invalid());
    }
    let abandoned = String::from_utf8(encode_request(
        &inspection.abandoned,
        &inspection.prior_checkpoint_digest,
        echoed_nonce,
    )?)
    .map_err(|_| invalid())?;
    let wire = RecoveryInspectReplyWire {
        protocol: RECOVER_INSPECT_PROTOCOL.into(),
        nonce: echoed_nonce.into(),
        scope_id: inspection.identity.scope_id.as_str().into(),
        pod_id: inspection.identity.pod_id.as_str().into(),
        attempt_id: inspection.identity.attempt_id.as_str().into(),
        incarnation: inspection.identity.incarnation.get(),
        store_lineage: inspection.identity.store_lineage.as_str().into(),
        phase: match inspection.phase {
            RebindPhase::PendingStore => "pending_store",
            RebindPhase::PendingPod => "pending_pod",
            RebindPhase::Active => return Err(invalid()),
        }
        .into(),
        checkpoint_digest: inspection.checkpoint_digest.clone(),
        prior_checkpoint_digest: inspection.prior_checkpoint_digest.clone(),
        abandoned_prepare_json: abandoned,
        supervisor_pid: inspection.supervisor_pid,
        supervisor_start_ticks: inspection.supervisor_start_ticks,
        child_pid: inspection.child_pid,
        child_start_ticks: inspection.child_start_ticks,
        boot_id: inspection.boot_id.clone(),
        unit_name: inspection.unit_name.clone(),
        cgroup_path: inspection.cgroup_path.clone(),
    };
    let bytes = serde_json::to_vec(&wire)?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(invalid());
    }
    decode_pending_reply(&bytes, &inspection.identity, echoed_nonce)?;
    Ok(bytes)
}

pub(crate) fn decode_pending_reply(
    bytes: &[u8],
    expected: &PodFenceIdentity,
    expected_nonce: &str,
) -> Result<PendingRecoveryInspection, PodError> {
    if bytes.is_empty() || bytes.len() > MAX_RESPONSE_BYTES || !nonce(expected_nonce) {
        return Err(invalid());
    }
    let wire: RecoveryInspectReplyWire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    let phase = match wire.phase.as_str() {
        "pending_store" => RebindPhase::PendingStore,
        "pending_pod" => RebindPhase::PendingPod,
        _ => return Err(invalid()),
    };
    if wire.protocol != RECOVER_INSPECT_PROTOCOL
        || wire.nonce != expected_nonce
        || !exact_identity(
            &wire.scope_id,
            &wire.pod_id,
            &wire.attempt_id,
            wire.incarnation,
            &wire.store_lineage,
            expected,
        )
        || !digest(&wire.checkpoint_digest)
        || !digest(&wire.prior_checkpoint_digest)
        || wire.supervisor_pid == 0
        || wire.supervisor_start_ticks == 0
        || wire.child_pid == 0
        || wire.child_start_ticks == 0
        || wire.boot_id.is_empty()
        || wire.unit_name.is_empty()
        || !wire.cgroup_path.starts_with('/')
        || wire.cgroup_path.len() > 4096
        || wire.cgroup_path.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    let abandoned = decode_request(wire.abandoned_prepare_json.as_bytes())?;
    if abandoned.nonce != expected_nonce
        || abandoned.prior_checkpoint_digest != wire.prior_checkpoint_digest
        || abandoned.proposal.identity != *expected
    {
        return Err(invalid());
    }
    Ok(PendingRecoveryInspection {
        identity: expected.clone(),
        phase,
        checkpoint_digest: wire.checkpoint_digest,
        prior_checkpoint_digest: wire.prior_checkpoint_digest,
        abandoned: abandoned.proposal,
        supervisor_pid: wire.supervisor_pid,
        supervisor_start_ticks: wire.supervisor_start_ticks,
        child_pid: wire.child_pid,
        child_start_ticks: wire.child_start_ticks,
        boot_id: wire.boot_id,
        unit_name: wire.unit_name,
        cgroup_path: wire.cgroup_path,
    })
}

pub(crate) fn encode_recovery_prepare(
    intent: &PendingRebindSupersession,
    prior_checkpoint_digest: &str,
    fresh_nonce: &str,
) -> Result<Vec<u8>, PodError> {
    if !nonce(fresh_nonce) || !digest(prior_checkpoint_digest) {
        return Err(invalid());
    }
    let abandoned_prepare_json = String::from_utf8(encode_request(
        &intent.abandoned,
        prior_checkpoint_digest,
        fresh_nonce,
    )?)
    .map_err(|_| invalid())?;
    let request = RecoveryPrepareWire {
        protocol: RECOVER_PREPARE_PROTOCOL.into(),
        operation: "rebind.recover.prepare".into(),
        nonce: fresh_nonce.into(),
        prior_checkpoint_digest: prior_checkpoint_digest.into(),
        abandoned_prepare_json,
        pending_phase: match intent.pending_phase {
            RebindPhase::PendingStore => "pending_store",
            RebindPhase::PendingPod => "pending_pod",
            RebindPhase::Active => return Err(invalid()),
        }
        .into(),
        pending_checkpoint_digest: intent.pending_checkpoint_digest.as_str().into(),
        pending_process: RecoveryProcessWire {
            supervisor_process_id: intent.pending_process.supervisor_process_id.clone(),
            supervisor_birth_identity: intent.pending_process.supervisor_birth_identity.clone(),
            child_process_id: intent.pending_process.child_process_id.clone(),
            child_birth_identity: intent.pending_process.child_birth_identity.clone(),
            boot_identity: intent.pending_process.boot_identity.clone(),
            containment_identity: intent.pending_process.containment_identity.clone(),
        },
        recovering_owner_epoch: intent.recovering_owner_epoch.get(),
        recovering_credential_epoch: intent.recovering_credential_epoch.get(),
        recovering_input_epochs: intent
            .recovering_input_epochs
            .iter()
            .map(|(id, epoch)| (id.as_str().into(), epoch.get()))
            .collect(),
        recovering_manager: peer_to_wire(&intent.recovering_manager),
        command_key: intent.command_key.as_str().into(),
        request_digest: intent.digest.as_str().into(),
    };
    let bytes = serde_json::to_vec(&request)?;
    if decode_recovery_prepare(&bytes)?.intent != *intent {
        return Err(invalid());
    }
    Ok(bytes)
}

pub(crate) fn decode_recovery_prepare(bytes: &[u8]) -> Result<DecodedRecoveryPrepare, PodError> {
    if bytes.is_empty() || bytes.len() > MAX_PREPARE_REQUEST_BYTES {
        return Err(invalid());
    }
    let wire: RecoveryPrepareWire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if wire.protocol != RECOVER_PREPARE_PROTOCOL
        || wire.operation != "rebind.recover.prepare"
        || !nonce(&wire.nonce)
        || !digest(&wire.prior_checkpoint_digest)
        || !digest(&wire.pending_checkpoint_digest)
        || !digest(&wire.request_digest)
        || wire.recovering_owner_epoch == 0
        || wire.recovering_credential_epoch == 0
        || wire.recovering_input_epochs.is_empty()
        || wire.recovering_input_epochs.len() > 64
    {
        return Err(invalid());
    }
    let abandoned = decode_request(wire.abandoned_prepare_json.as_bytes())?;
    if abandoned.nonce != wire.nonce
        || abandoned.prior_checkpoint_digest != wire.prior_checkpoint_digest
        || wire.recovering_owner_epoch <= abandoned.proposal.next_owner_epoch.get()
        || wire.recovering_credential_epoch <= abandoned.proposal.next_credential_epoch.get()
    {
        return Err(invalid());
    }
    let pending_phase = match wire.pending_phase.as_str() {
        "pending_store" => RebindPhase::PendingStore,
        "pending_pod" => RebindPhase::PendingPod,
        _ => return Err(invalid()),
    };
    let process = &wire.pending_process;
    let canonical_u32 = |value: &str| {
        value
            .parse::<u32>()
            .ok()
            .is_some_and(|number| number > 0 && number.to_string() == value)
    };
    let canonical_u64 = |value: &str| {
        value
            .parse::<u64>()
            .ok()
            .is_some_and(|number| number > 0 && number.to_string() == value)
    };
    if !canonical_u32(&process.supervisor_process_id)
        || !canonical_u64(&process.supervisor_birth_identity)
        || !canonical_u32(&process.child_process_id)
        || !canonical_u64(&process.child_birth_identity)
        || process.boot_identity.is_empty()
        || !process.containment_identity.starts_with('/')
        || process.containment_identity.len() > 4096
        || process.containment_identity.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    let mut recovering_input_epochs = BTreeMap::new();
    for (text, value) in &wire.recovering_input_epochs {
        let id = ResourceId::try_from(text.as_str()).map_err(|_| invalid())?;
        let epoch = InputEpoch::new(*value).map_err(|_| invalid())?;
        if recovering_input_epochs.insert(id, epoch).is_some() {
            return Err(invalid());
        }
    }
    if recovering_input_epochs.len() != abandoned.proposal.next_input_epochs.len() {
        return Err(invalid());
    }
    for (id, old) in &abandoned.proposal.next_input_epochs {
        if recovering_input_epochs
            .get(id)
            .is_none_or(|next| next.get() <= old.get())
        {
            return Err(invalid());
        }
    }
    let recovering_manager: AttestedPeer = peer_from_wire(&wire.recovering_manager)?;
    Ok(DecodedRecoveryPrepare {
        intent: PendingRebindSupersession {
            abandoned: abandoned.proposal,
            pending_phase,
            pending_checkpoint_digest: RequestDigest::parse(&wire.pending_checkpoint_digest)
                .map_err(|_| invalid())?,
            pending_process: PendingPodProcessEvidence {
                supervisor_process_id: process.supervisor_process_id.clone(),
                supervisor_birth_identity: process.supervisor_birth_identity.clone(),
                child_process_id: process.child_process_id.clone(),
                child_birth_identity: process.child_birth_identity.clone(),
                boot_identity: process.boot_identity.clone(),
                containment_identity: process.containment_identity.clone(),
            },
            recovering_owner_epoch: OwnerEpoch::new(wire.recovering_owner_epoch)
                .map_err(|_| invalid())?,
            recovering_credential_epoch: CredentialEpoch::new(wire.recovering_credential_epoch)
                .map_err(|_| invalid())?,
            recovering_input_epochs,
            recovering_manager,
            command_key: CommandKey::try_from(wire.command_key.as_str()).map_err(|_| invalid())?,
            digest: RequestDigest::parse(&wire.request_digest).map_err(|_| invalid())?,
        },
        prior_checkpoint_digest: wire.prior_checkpoint_digest,
        nonce: wire.nonce,
    })
}

pub(crate) fn encode_recovery_active_reply(
    identity: &PodFenceIdentity,
    echoed_nonce: &str,
    checkpoint_digest: &str,
) -> Result<Vec<u8>, PodError> {
    if !nonce(echoed_nonce) || !digest(checkpoint_digest) {
        return Err(invalid());
    }
    let reply = RecoveryPrepareReplyWire {
        protocol: RECOVER_PREPARE_PROTOCOL.into(),
        nonce: echoed_nonce.into(),
        scope_id: identity.scope_id.as_str().into(),
        pod_id: identity.pod_id.as_str().into(),
        attempt_id: identity.attempt_id.as_str().into(),
        incarnation: identity.incarnation.get(),
        store_lineage: identity.store_lineage.as_str().into(),
        phase: "active_prior".into(),
        checkpoint_digest: checkpoint_digest.into(),
    };
    let bytes = serde_json::to_vec(&reply)?;
    if bytes.len() > MAX_PREPARE_RESPONSE_BYTES {
        return Err(invalid());
    }
    decode_recovery_active_reply(&bytes, identity, echoed_nonce)?;
    Ok(bytes)
}

pub(crate) fn decode_recovery_active_reply(
    bytes: &[u8],
    expected: &PodFenceIdentity,
    expected_nonce: &str,
) -> Result<String, PodError> {
    if bytes.is_empty() || bytes.len() > MAX_PREPARE_RESPONSE_BYTES || !nonce(expected_nonce) {
        return Err(invalid());
    }
    let reply: RecoveryPrepareReplyWire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if reply.protocol != RECOVER_PREPARE_PROTOCOL
        || reply.nonce != expected_nonce
        || reply.phase != "active_prior"
        || !digest(&reply.checkpoint_digest)
        || !exact_identity(
            &reply.scope_id,
            &reply.pod_id,
            &reply.attempt_id,
            reply.incarnation,
            &reply.store_lineage,
            expected,
        )
    {
        return Err(invalid());
    }
    Ok(reply.checkpoint_digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use podbay_core::{
        AttemptId, AttestedPeer, CommandKey, CredentialEpoch, Epoch, InputEpoch, OwnerEpoch, PodId,
        RequestDigest, ResourceId, ScopeId, StoreLineageId,
    };

    fn fixture() -> PendingRecoveryInspection {
        let identity = PodFenceIdentity {
            store_lineage: StoreLineageId::try_from("lineage.fixture").unwrap(),
            scope_id: ScopeId::try_from("scope.fixture").unwrap(),
            pod_id: PodId::try_from("pod.fixture").unwrap(),
            attempt_id: AttemptId::try_from("attempt.fixture").unwrap(),
            incarnation: Epoch::new(1).unwrap(),
        };
        let resource = ResourceId::try_from("resource.fixture").unwrap();
        let abandoned = RebindProposal {
            identity: identity.clone(),
            expected_owner_epoch: OwnerEpoch::new(1).unwrap(),
            next_owner_epoch: OwnerEpoch::new(2).unwrap(),
            expected_credential_epoch: CredentialEpoch::new(1).unwrap(),
            next_credential_epoch: CredentialEpoch::new(2).unwrap(),
            expected_input_epochs: [(resource.clone(), InputEpoch::new(1).unwrap())].into(),
            next_input_epochs: [(resource, InputEpoch::new(2).unwrap())].into(),
            next_manager: AttestedPeer::from_port(
                "linux.uid.1000",
                "linux.pid.42",
                "linux.boot.01234567-89ab-cdef-0123-456789abcdef",
                "linux.start.777",
                "linux.cgroup./user.slice/manager.service",
            )
            .unwrap(),
            command_key: CommandKey::try_from("rebind.fixture").unwrap(),
            digest: RequestDigest::parse(&"a".repeat(64)).unwrap(),
        };
        PendingRecoveryInspection {
            identity,
            phase: RebindPhase::PendingPod,
            checkpoint_digest: "b".repeat(64),
            prior_checkpoint_digest: "c".repeat(64),
            abandoned,
            supervisor_pid: 100,
            supervisor_start_ticks: 200,
            child_pid: 101,
            child_start_ticks: 201,
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
            unit_name: "podbay-pod-fixture.service".into(),
            cgroup_path: "/user.slice/podbay-pod-fixture.service".into(),
        }
    }

    #[test]
    fn pending_recovery_inspect_codec_binds_nonce_identity_proposal_and_process() {
        let value = fixture();
        let nonce = "d".repeat(64);
        let request = encode_inspect_request(&value.identity, 3, 3, &nonce).unwrap();
        assert_eq!(
            decode_inspect_request(&request, &value.identity)
                .unwrap()
                .owner_epoch,
            3
        );
        let reply = encode_pending_reply(&value, &nonce).unwrap();
        assert_eq!(
            decode_pending_reply(&reply, &value.identity, &nonce).unwrap(),
            value
        );
        assert!(decode_pending_reply(&reply, &value.identity, &"e".repeat(64)).is_err());
        let mut changed = value.clone();
        changed.phase = RebindPhase::Active;
        assert!(encode_pending_reply(&changed, &nonce).is_err());
        changed = value.clone();
        changed.abandoned.command_key = CommandKey::try_from("rebind.other").unwrap();
        let changed_reply = encode_pending_reply(&changed, &nonce).unwrap();
        assert_ne!(reply, changed_reply);
    }

    #[test]
    fn recovery_inspect_codec_refuses_unknown_and_malformed_fields() {
        let value = fixture();
        let nonce = "d".repeat(64);
        let request = encode_inspect_request(&value.identity, 3, 3, &nonce).unwrap();
        let mut request_json: serde_json::Value = serde_json::from_slice(&request).unwrap();
        request_json["unexpected"] = serde_json::json!(true);
        assert!(
            decode_inspect_request(&serde_json::to_vec(&request_json).unwrap(), &value.identity,)
                .is_err()
        );
        let reply = encode_pending_reply(&value, &nonce).unwrap();
        let mut reply_json: serde_json::Value = serde_json::from_slice(&reply).unwrap();
        reply_json["child_start_ticks"] = serde_json::json!(0);
        assert!(
            decode_pending_reply(
                &serde_json::to_vec(&reply_json).unwrap(),
                &value.identity,
                &nonce,
            )
            .is_err()
        );
        reply_json["child_start_ticks"] = serde_json::json!(201);
        reply_json["unexpected"] = serde_json::json!("field");
        assert!(
            decode_pending_reply(
                &serde_json::to_vec(&reply_json).unwrap(),
                &value.identity,
                &nonce,
            )
            .is_err()
        );
    }

    #[test]
    fn recovery_prepare_codec_binds_full_intent_and_active_ack() {
        let inspected = fixture();
        let resource = ResourceId::try_from("resource.fixture").unwrap();
        let intent = PendingRebindSupersession {
            abandoned: inspected.abandoned.clone(),
            pending_phase: inspected.phase,
            pending_checkpoint_digest: RequestDigest::parse(&inspected.checkpoint_digest).unwrap(),
            pending_process: PendingPodProcessEvidence {
                supervisor_process_id: inspected.supervisor_pid.to_string(),
                supervisor_birth_identity: inspected.supervisor_start_ticks.to_string(),
                child_process_id: inspected.child_pid.to_string(),
                child_birth_identity: inspected.child_start_ticks.to_string(),
                boot_identity: inspected.boot_id.clone(),
                containment_identity: inspected.cgroup_path.clone(),
            },
            recovering_owner_epoch: OwnerEpoch::new(3).unwrap(),
            recovering_credential_epoch: CredentialEpoch::new(3).unwrap(),
            recovering_input_epochs: [(resource, InputEpoch::new(3).unwrap())].into(),
            recovering_manager: AttestedPeer::from_port(
                "linux.uid.1000",
                "linux.pid.43",
                "linux.boot.01234567-89ab-cdef-0123-456789abcdef",
                "linux.start.778",
                "linux.cgroup./user.slice/manager.service",
            )
            .unwrap(),
            command_key: CommandKey::try_from("recover.fixture").unwrap(),
            digest: RequestDigest::parse(&"e".repeat(64)).unwrap(),
        };
        let nonce = "f".repeat(64);
        let bytes =
            encode_recovery_prepare(&intent, &inspected.prior_checkpoint_digest, &nonce).unwrap();
        let decoded = decode_recovery_prepare(&bytes).unwrap();
        assert_eq!(decoded.intent, intent);
        assert_eq!(decoded.nonce, nonce);
        let ack =
            encode_recovery_active_reply(&inspected.identity, &nonce, &"a".repeat(64)).unwrap();
        assert_eq!(
            decode_recovery_active_reply(&ack, &inspected.identity, &nonce).unwrap(),
            "a".repeat(64)
        );
        assert!(decode_recovery_active_reply(&ack, &inspected.identity, &"b".repeat(64)).is_err());
        let mut changed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        changed["pending_process"]["child_birth_identity"] = serde_json::json!("0");
        assert!(decode_recovery_prepare(&serde_json::to_vec(&changed).unwrap()).is_err());
    }
}
