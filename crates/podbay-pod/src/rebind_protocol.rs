//! Bounded Linux rebind-prepare JSON. Decoding is data validation, not peer
//! authentication, ledger admission, or a control grant.
use std::collections::BTreeMap;

use podbay_core::{
    AttemptId, AttestedPeer, CommandKey, CredentialEpoch, Epoch, InputEpoch, OwnerEpoch,
    PodFenceIdentity, PodId, RebindProposal, RequestDigest, ResourceId, ScopeId, StoreLineageId,
};
use serde::{Deserialize, Serialize};

use crate::manifest::PodError;

const PROTOCOL: &str = "podbay.rebind-prepare/1";
const ACTIVATE_PROTOCOL: &str = "podbay.rebind-activate/1";
const MAX_REQUEST_BYTES: usize = 65_536;
const MAX_RESPONSE_BYTES: usize = 4_096;
const MAX_RESOURCES: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerWire {
    os_identity: String,
    process_identity: String,
    boot_identity: String,
    birth_identity: String,
    containment_identity: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceWire {
    resource_id: String,
    expected_input_epoch: u64,
    next_input_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareWire {
    protocol: String,
    operation: String,
    nonce: String,
    scope_id: String,
    pod_id: String,
    attempt_id: String,
    incarnation: u64,
    store_lineage: String,
    prior_checkpoint_digest: String,
    expected_owner_epoch: u64,
    next_owner_epoch: u64,
    expected_credential_epoch: u64,
    next_credential_epoch: u64,
    resources: Vec<ResourceWire>,
    next_manager: PeerWire,
    command_key: String,
    request_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareResponseWire {
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivateWire {
    protocol: String,
    operation: String,
    nonce: String,
    prepare: PrepareWire,
    pending_checkpoint_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DecodedActivate {
    pub proposal: RebindProposal,
    pub prior_checkpoint_digest: String,
    pub pending_checkpoint_digest: String,
    pub nonce: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DecodedPrepare {
    pub proposal: RebindProposal,
    pub prior_checkpoint_digest: String,
    pub nonce: String,
}

fn invalid() -> PodError {
    PodError::Invalid("rebind prepare wire is malformed or out of bounds")
}

fn digest(value: &str) -> Result<(), PodError> {
    RequestDigest::parse(value)
        .map(|_| ())
        .map_err(|_| invalid())
}

fn nonce(value: &str) -> Result<(), PodError> {
    // The caller must draw a fresh 256-bit value. The wire codec only proves
    // canonical shape; the runtime will bind it to the authenticated exchange.
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(invalid())
    }
}

fn positive_sqlite(value: u64) -> Result<u64, PodError> {
    if value == 0 || value > i64::MAX as u64 {
        Err(invalid())
    } else {
        Ok(value)
    }
}

fn advance(old: u64, next: u64) -> Result<(), PodError> {
    positive_sqlite(old)?;
    positive_sqlite(next)?;
    if next > old { Ok(()) } else { Err(invalid()) }
}

fn canonical_number<T>(value: &str) -> Option<T>
where
    T: std::str::FromStr + ToString,
{
    let parsed: T = value.parse().ok()?;
    (parsed.to_string() == value).then_some(parsed)
}

fn boot_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn peer_from_wire(value: &PeerWire) -> Result<AttestedPeer, PodError> {
    let uid = value
        .os_identity
        .strip_prefix("linux.uid.")
        .and_then(canonical_number::<u32>)
        .ok_or_else(invalid)?;
    let pid = value
        .process_identity
        .strip_prefix("linux.pid.")
        .and_then(canonical_number::<i32>)
        .ok_or_else(invalid)?;
    let start = value
        .birth_identity
        .strip_prefix("linux.start.")
        .and_then(canonical_number::<u64>)
        .ok_or_else(invalid)?;
    let boot = value
        .boot_identity
        .strip_prefix("linux.boot.")
        .ok_or_else(invalid)?;
    let cgroup = value
        .containment_identity
        .strip_prefix("linux.cgroup.")
        .ok_or_else(invalid)?;
    if pid <= 0
        || start == 0
        || !boot_uuid(boot)
        || !cgroup.starts_with('/')
        || cgroup.len() > 4_080
        || cgroup.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    let _ = uid;
    AttestedPeer::from_port(
        &value.os_identity,
        &value.process_identity,
        &value.boot_identity,
        &value.birth_identity,
        &value.containment_identity,
    )
    .map_err(|_| invalid())
}

fn peer_to_wire(value: &AttestedPeer) -> PeerWire {
    PeerWire {
        os_identity: value.os_identity().into(),
        process_identity: value.native_process_id().into(),
        boot_identity: value.boot_identity().into(),
        birth_identity: value.birth_identity().into(),
        containment_identity: value.containment_identity().into(),
    }
}

fn convert(wire: PrepareWire) -> Result<DecodedPrepare, PodError> {
    if wire.protocol != PROTOCOL || wire.operation != "rebind.prepare" {
        return Err(invalid());
    }
    nonce(&wire.nonce)?;
    digest(&wire.prior_checkpoint_digest)?;
    advance(wire.expected_owner_epoch, wire.next_owner_epoch)?;
    advance(wire.expected_credential_epoch, wire.next_credential_epoch)?;
    positive_sqlite(wire.incarnation)?;
    if wire.resources.is_empty() || wire.resources.len() > MAX_RESOURCES {
        return Err(invalid());
    }
    let mut expected_input_epochs = BTreeMap::new();
    let mut next_input_epochs = BTreeMap::new();
    let mut prior_id: Option<&str> = None;
    for resource in &wire.resources {
        if prior_id.is_some_and(|id| id >= resource.resource_id.as_str()) {
            return Err(invalid());
        }
        prior_id = Some(&resource.resource_id);
        advance(resource.expected_input_epoch, resource.next_input_epoch)?;
        let id = ResourceId::try_from(resource.resource_id.as_str()).map_err(|_| invalid())?;
        expected_input_epochs.insert(
            id.clone(),
            InputEpoch::new(resource.expected_input_epoch).map_err(|_| invalid())?,
        );
        next_input_epochs.insert(
            id,
            InputEpoch::new(resource.next_input_epoch).map_err(|_| invalid())?,
        );
    }
    let proposal = RebindProposal {
        identity: PodFenceIdentity {
            scope_id: ScopeId::try_from(wire.scope_id.as_str()).map_err(|_| invalid())?,
            pod_id: PodId::try_from(wire.pod_id.as_str()).map_err(|_| invalid())?,
            attempt_id: AttemptId::try_from(wire.attempt_id.as_str()).map_err(|_| invalid())?,
            incarnation: Epoch::new(wire.incarnation).map_err(|_| invalid())?,
            store_lineage: StoreLineageId::try_from(wire.store_lineage.as_str())
                .map_err(|_| invalid())?,
        },
        expected_owner_epoch: OwnerEpoch::new(wire.expected_owner_epoch).map_err(|_| invalid())?,
        next_owner_epoch: OwnerEpoch::new(wire.next_owner_epoch).map_err(|_| invalid())?,
        expected_credential_epoch: CredentialEpoch::new(wire.expected_credential_epoch)
            .map_err(|_| invalid())?,
        next_credential_epoch: CredentialEpoch::new(wire.next_credential_epoch)
            .map_err(|_| invalid())?,
        expected_input_epochs,
        next_input_epochs,
        next_manager: peer_from_wire(&wire.next_manager)?,
        command_key: CommandKey::try_from(wire.command_key.as_str()).map_err(|_| invalid())?,
        digest: RequestDigest::parse(&wire.request_digest).map_err(|_| invalid())?,
    };
    Ok(DecodedPrepare {
        proposal,
        prior_checkpoint_digest: wire.prior_checkpoint_digest,
        nonce: wire.nonce,
    })
}

pub(crate) fn decode_request(bytes: &[u8]) -> Result<DecodedPrepare, PodError> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
        return Err(invalid());
    }
    let wire: PrepareWire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    convert(wire)
}

pub(crate) fn encode_request(
    proposal: &RebindProposal,
    prior_checkpoint_digest: &str,
    fresh_nonce: &str,
) -> Result<Vec<u8>, PodError> {
    let wire = PrepareWire {
        protocol: PROTOCOL.into(),
        operation: "rebind.prepare".into(),
        nonce: fresh_nonce.into(),
        scope_id: proposal.identity.scope_id.as_str().into(),
        pod_id: proposal.identity.pod_id.as_str().into(),
        attempt_id: proposal.identity.attempt_id.as_str().into(),
        incarnation: proposal.identity.incarnation.get(),
        store_lineage: proposal.identity.store_lineage.as_str().into(),
        prior_checkpoint_digest: prior_checkpoint_digest.into(),
        expected_owner_epoch: proposal.expected_owner_epoch.get(),
        next_owner_epoch: proposal.next_owner_epoch.get(),
        expected_credential_epoch: proposal.expected_credential_epoch.get(),
        next_credential_epoch: proposal.next_credential_epoch.get(),
        resources: proposal
            .expected_input_epochs
            .iter()
            .map(|(id, old)| ResourceWire {
                resource_id: id.as_str().into(),
                expected_input_epoch: old.get(),
                next_input_epoch: proposal
                    .next_input_epochs
                    .get(id)
                    .map(|epoch| epoch.get())
                    .unwrap_or(0),
            })
            .collect(),
        next_manager: peer_to_wire(&proposal.next_manager),
        command_key: proposal.command_key.as_str().into(),
        request_digest: proposal.digest.as_str().into(),
    };
    let bytes = serde_json::to_vec(&wire).map_err(|_| invalid())?;
    if decode_request(&bytes)?.proposal != *proposal {
        return Err(invalid());
    }
    Ok(bytes)
}

pub(crate) fn encode_pending_response(
    identity: &PodFenceIdentity,
    echoed_nonce: &str,
    pending_checkpoint_digest: &str,
) -> Result<Vec<u8>, PodError> {
    let wire = PrepareResponseWire {
        protocol: PROTOCOL.into(),
        nonce: echoed_nonce.into(),
        scope_id: identity.scope_id.as_str().into(),
        pod_id: identity.pod_id.as_str().into(),
        attempt_id: identity.attempt_id.as_str().into(),
        incarnation: identity.incarnation.get(),
        store_lineage: identity.store_lineage.as_str().into(),
        phase: "pending_pod".into(),
        checkpoint_digest: pending_checkpoint_digest.into(),
    };
    let bytes = serde_json::to_vec(&wire).map_err(|_| invalid())?;
    decode_pending_response(&bytes, identity, echoed_nonce)?;
    Ok(bytes)
}

pub(crate) fn decode_pending_response(
    bytes: &[u8],
    expected: &PodFenceIdentity,
    expected_nonce: &str,
) -> Result<String, PodError> {
    if bytes.is_empty() || bytes.len() > MAX_RESPONSE_BYTES {
        return Err(invalid());
    }
    nonce(expected_nonce)?;
    let wire: PrepareResponseWire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    digest(&wire.checkpoint_digest)?;
    if wire.protocol != PROTOCOL
        || wire.phase != "pending_pod"
        || wire.nonce != expected_nonce
        || wire.scope_id != expected.scope_id.as_str()
        || wire.pod_id != expected.pod_id.as_str()
        || wire.attempt_id != expected.attempt_id.as_str()
        || wire.incarnation != expected.incarnation.get()
        || wire.store_lineage != expected.store_lineage.as_str()
    {
        return Err(invalid());
    }
    Ok(wire.checkpoint_digest)
}

pub(crate) fn encode_activate_request(
    proposal: &RebindProposal,
    prior_checkpoint_digest: &str,
    pending_checkpoint_digest: &str,
    fresh_nonce: &str,
) -> Result<Vec<u8>, PodError> {
    digest(pending_checkpoint_digest)?;
    let prepare: PrepareWire = serde_json::from_slice(&encode_request(
        proposal,
        prior_checkpoint_digest,
        fresh_nonce,
    )?)
    .map_err(|_| invalid())?;
    let bytes = serde_json::to_vec(&ActivateWire {
        protocol: ACTIVATE_PROTOCOL.into(),
        operation: "rebind.activate".into(),
        nonce: fresh_nonce.into(),
        prepare,
        pending_checkpoint_digest: pending_checkpoint_digest.into(),
    })
    .map_err(|_| invalid())?;
    if decode_activate_request(&bytes)?.proposal != *proposal {
        return Err(invalid());
    }
    Ok(bytes)
}

pub(crate) fn decode_activate_request(bytes: &[u8]) -> Result<DecodedActivate, PodError> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
        return Err(invalid());
    }
    let wire: ActivateWire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if wire.protocol != ACTIVATE_PROTOCOL || wire.operation != "rebind.activate" {
        return Err(invalid());
    }
    nonce(&wire.nonce)?;
    digest(&wire.pending_checkpoint_digest)?;
    let decoded = convert(wire.prepare)?;
    if decoded.nonce != wire.nonce {
        return Err(invalid());
    }
    Ok(DecodedActivate {
        proposal: decoded.proposal,
        prior_checkpoint_digest: decoded.prior_checkpoint_digest,
        pending_checkpoint_digest: wire.pending_checkpoint_digest,
        nonce: wire.nonce,
    })
}

pub(crate) fn encode_active_response(
    identity: &PodFenceIdentity,
    echoed_nonce: &str,
    active_checkpoint_digest: &str,
) -> Result<Vec<u8>, PodError> {
    let wire = PrepareResponseWire {
        protocol: ACTIVATE_PROTOCOL.into(),
        nonce: echoed_nonce.into(),
        scope_id: identity.scope_id.as_str().into(),
        pod_id: identity.pod_id.as_str().into(),
        attempt_id: identity.attempt_id.as_str().into(),
        incarnation: identity.incarnation.get(),
        store_lineage: identity.store_lineage.as_str().into(),
        phase: "active".into(),
        checkpoint_digest: active_checkpoint_digest.into(),
    };
    let bytes = serde_json::to_vec(&wire).map_err(|_| invalid())?;
    decode_active_response(&bytes, identity, echoed_nonce)?;
    Ok(bytes)
}

pub(crate) fn decode_active_response(
    bytes: &[u8],
    expected: &PodFenceIdentity,
    expected_nonce: &str,
) -> Result<String, PodError> {
    if bytes.is_empty() || bytes.len() > MAX_RESPONSE_BYTES {
        return Err(invalid());
    }
    nonce(expected_nonce)?;
    let wire: PrepareResponseWire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    digest(&wire.checkpoint_digest)?;
    if wire.protocol != ACTIVATE_PROTOCOL
        || wire.phase != "active"
        || wire.nonce != expected_nonce
        || wire.scope_id != expected.scope_id.as_str()
        || wire.pod_id != expected.pod_id.as_str()
        || wire.attempt_id != expected.attempt_id.as_str()
        || wire.incarnation != expected.incarnation.get()
        || wire.store_lineage != expected.store_lineage.as_str()
    {
        return Err(invalid());
    }
    Ok(wire.checkpoint_digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (RebindProposal, String, String) {
        let identity = PodFenceIdentity {
            scope_id: ScopeId::try_from("scope.fixture").unwrap(),
            pod_id: PodId::try_from("pod.fixture").unwrap(),
            attempt_id: AttemptId::try_from("attempt.fixture").unwrap(),
            incarnation: Epoch::new(3).unwrap(),
            store_lineage: StoreLineageId::try_from("lineage.fixture").unwrap(),
        };
        let peer = AttestedPeer::from_port(
            "linux.uid.1000",
            "linux.pid.1234",
            "linux.boot.12345678-1234-1234-1234-123456789abc",
            "linux.start.123456",
            "linux.cgroup./user.slice/manager.service",
        )
        .unwrap();
        let proposal = RebindProposal {
            identity,
            expected_owner_epoch: OwnerEpoch::new(1).unwrap(),
            next_owner_epoch: OwnerEpoch::new(4).unwrap(),
            expected_credential_epoch: CredentialEpoch::new(1).unwrap(),
            next_credential_epoch: CredentialEpoch::new(4).unwrap(),
            expected_input_epochs: BTreeMap::from([
                (
                    ResourceId::try_from("resource.a").unwrap(),
                    InputEpoch::new(2).unwrap(),
                ),
                (
                    ResourceId::try_from("resource.b").unwrap(),
                    InputEpoch::new(5).unwrap(),
                ),
            ]),
            next_input_epochs: BTreeMap::from([
                (
                    ResourceId::try_from("resource.a").unwrap(),
                    InputEpoch::new(6).unwrap(),
                ),
                (
                    ResourceId::try_from("resource.b").unwrap(),
                    InputEpoch::new(8).unwrap(),
                ),
            ]),
            next_manager: peer,
            command_key: CommandKey::try_from("command.fixture").unwrap(),
            digest: RequestDigest::parse(&"a".repeat(64)).unwrap(),
        };
        (proposal, "b".repeat(64), "c".repeat(64))
    }

    fn change(bytes: &[u8], f: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
        let mut value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        f(&mut value);
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn complete_skip_epoch_request_and_pending_response_roundtrip() {
        let (proposal, prior, nonce) = sample();
        let bytes = encode_request(&proposal, &prior, &nonce).unwrap();
        let decoded = decode_request(&bytes).unwrap();
        assert_eq!(decoded.proposal, proposal);
        assert_eq!(decoded.prior_checkpoint_digest, prior);
        assert_eq!(decoded.nonce, nonce);
        let response =
            encode_pending_response(&proposal.identity, &nonce, &"d".repeat(64)).unwrap();
        assert_eq!(
            decode_pending_response(&response, &proposal.identity, &nonce).unwrap(),
            "d".repeat(64)
        );
        assert!(decode_pending_response(&response, &proposal.identity, &"e".repeat(64)).is_err());
        let activate = encode_activate_request(&proposal, &prior, &"d".repeat(64), &nonce).unwrap();
        let decoded_activate = decode_activate_request(&activate).unwrap();
        assert_eq!(decoded_activate.proposal, proposal);
        assert_eq!(decoded_activate.prior_checkpoint_digest, prior);
        assert_eq!(decoded_activate.pending_checkpoint_digest, "d".repeat(64));
        let active = encode_active_response(&proposal.identity, &nonce, &"f".repeat(64)).unwrap();
        assert_eq!(
            decode_active_response(&active, &proposal.identity, &nonce).unwrap(),
            "f".repeat(64)
        );
        assert!(decode_active_response(&active, &proposal.identity, &"e".repeat(64)).is_err());
    }

    #[test]
    fn malformed_versions_unknown_fields_and_bounds_refuse() {
        let (proposal, prior, nonce) = sample();
        let bytes = encode_request(&proposal, &prior, &nonce).unwrap();
        assert!(decode_request(&[]).is_err());
        assert!(decode_request(&vec![b' '; MAX_REQUEST_BYTES + 1]).is_err());
        for field in ["protocol", "operation", "nonce"] {
            let altered = change(&bytes, |value| value[field] = "wrong".into());
            assert!(decode_request(&altered).is_err(), "{field}");
        }
        let altered = change(&bytes, |value| value["unknown"] = true.into());
        assert!(decode_request(&altered).is_err());
        let altered = change(&bytes, |value| {
            value["resources"][0]["unknown"] = true.into()
        });
        assert!(decode_request(&altered).is_err());
    }

    #[test]
    fn zero_duplicate_missing_or_unordered_resource_vectors_refuse() {
        let (proposal, prior, nonce) = sample();
        let bytes = encode_request(&proposal, &prior, &nonce).unwrap();
        for field in [
            "incarnation",
            "expected_owner_epoch",
            "next_owner_epoch",
            "expected_credential_epoch",
            "next_credential_epoch",
        ] {
            let altered = change(&bytes, |value| value[field] = 0.into());
            assert!(decode_request(&altered).is_err(), "{field}");
        }
        let altered = change(&bytes, |value| value["next_owner_epoch"] = 1.into());
        assert!(decode_request(&altered).is_err());
        let altered = change(&bytes, |value| value["resources"] = serde_json::json!([]));
        assert!(decode_request(&altered).is_err());
        let altered = change(&bytes, |value| {
            value["resources"][0]["next_input_epoch"] = 0.into()
        });
        assert!(decode_request(&altered).is_err());
        let altered = change(&bytes, |value| {
            let row = value["resources"][0].clone();
            value["resources"].as_array_mut().unwrap().push(row);
        });
        assert!(decode_request(&altered).is_err());
        let altered = change(&bytes, |value| {
            value["resources"].as_array_mut().unwrap().reverse()
        });
        assert!(decode_request(&altered).is_err());
        let altered = change(&bytes, |value| {
            value["resources"] = serde_json::json!([{
                "resource_id":"resource.a","expected_input_epoch":2
            }])
        });
        assert!(decode_request(&altered).is_err());
        let altered = change(&bytes, |value| {
            let row = value["resources"][0].clone();
            value["resources"] = serde_json::Value::Array(vec![row; MAX_RESOURCES + 1]);
        });
        assert!(decode_request(&altered).is_err());
        let mut incomplete = proposal;
        incomplete.next_input_epochs.insert(
            ResourceId::try_from("resource.extra").unwrap(),
            InputEpoch::new(9).unwrap(),
        );
        assert!(encode_request(&incomplete, &prior, &nonce).is_err());
    }

    #[test]
    fn digests_peer_shape_and_response_identity_refuse() {
        let (proposal, prior, nonce) = sample();
        let bytes = encode_request(&proposal, &prior, &nonce).unwrap();
        for field in ["prior_checkpoint_digest", "request_digest"] {
            let altered = change(&bytes, |value| value[field] = "A".repeat(64).into());
            assert!(decode_request(&altered).is_err(), "{field}");
        }
        for (field, bad) in [
            ("process_identity", "linux.pid.0"),
            ("boot_identity", "linux.boot.invalid"),
            ("birth_identity", "linux.start.0"),
            ("containment_identity", "linux.cgroup.relative"),
        ] {
            let altered = change(&bytes, |value| value["next_manager"][field] = bad.into());
            assert!(decode_request(&altered).is_err(), "{field}");
        }
        let response =
            encode_pending_response(&proposal.identity, &nonce, &"d".repeat(64)).unwrap();
        let altered = change(&response, |value| value["pod_id"] = "pod.other".into());
        assert!(decode_pending_response(&altered, &proposal.identity, &nonce).is_err());
        let altered = change(&response, |value| value["phase"] = "active".into());
        assert!(decode_pending_response(&altered, &proposal.identity, &nonce).is_err());
        let altered = change(&response, |value| value["unknown"] = true.into());
        assert!(decode_pending_response(&altered, &proposal.identity, &nonce).is_err());
        assert!(
            decode_pending_response(
                &vec![b' '; MAX_RESPONSE_BYTES + 1],
                &proposal.identity,
                &nonce
            )
            .is_err()
        );
    }
}
