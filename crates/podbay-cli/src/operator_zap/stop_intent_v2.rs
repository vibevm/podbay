//! Unwired canonical data. Neither caller metadata nor decoded bytes prove
//! origin, a grant, admission, one-send custody, signing time or terminality.
//! No production Store mutation or Pod send is reachable from this module.
#![allow(dead_code)]

use podbay_pod::{
    AttestedStopError, AttestedStopReply, LinuxPeerEvidence, OPERATOR_PROCESS_CAPABILITY,
    PodStatus, PreparedStopIdentity,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::fmt;

const INTENT_SCHEMA: &str = "podbay.operator-zap-stop-intent/2";
const OUTCOME_SCHEMA: &str = "podbay.operator-zap-stop-exchange/1";
const MAX_INTENT: usize = 16_384;
const MAX_REPLY: usize = 65_536;
const MAX_OUTCOME: usize = 196_608;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CodecError {
    Oversize,
    Malformed,
    UnsupportedSchema,
    LegacyUnsigned,
    NonCanonical,
    InvalidFields,
    IntentMismatch,
}
impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stop record refused: {self:?}")
    }
}
impl std::error::Error for CodecError {}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Configuration {
    Absent {},
    Pinned { sha256: String },
}

/// Metadata to be acquired by a future authorized writer. Supplying this DTO
/// does not verify any authority, key binding or durable launch receipt.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct IntentContext {
    pub(super) stop_key: String,
    pub(super) lineage: String,
    pub(super) actor: String,
    pub(super) scope: String,
    pub(super) owner_epoch: u64,
    /// Owner signer generation; independent of the prepared Pod manager credential_epoch.
    pub(super) actor_credential_generation: u64,
    pub(super) authority_revision: u64,
    pub(super) actor_binding_digest: String,
    pub(super) launch_command: String,
    pub(super) launch_receipt_digest: String,
    pub(super) policy_digest: String,
    pub(super) session: String,
    pub(super) run: String,
    pub(super) resource_input_epoch: u64,
    pub(super) pod_artifact: String,
    pub(super) node_artifact: String,
    pub(super) zap_artifact: String,
    pub(super) configuration: Configuration,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PeerRecord {
    pid: u32,
    uid: u32,
    gid: u32,
    birth: u64,
    boot: String,
    cgroup: String,
}
impl PeerRecord {
    fn captured(peer: &LinuxPeerEvidence) -> Self {
        Self {
            pid: peer.pid() as u32,
            uid: peer.uid(),
            gid: peer.gid(),
            birth: peer.start_ticks(),
            boot: peer.boot_id().into(),
            cgroup: peer.cgroup().into(),
        }
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PreparedRecord {
    status: PodStatus,
    peer: PeerRecord,
    manifest_file_digest: String,
    socket_device: u64,
    socket_inode: u64,
    socket_uid: u32,
    socket_mode: u32,
}
impl PreparedRecord {
    fn captured(identity: &PreparedStopIdentity<'_>) -> Self {
        Self {
            status: identity.status().clone(),
            peer: PeerRecord::captured(identity.peer()),
            manifest_file_digest: hex(identity.manifest_file_digest()),
            socket_device: identity.socket_device(),
            socket_inode: identity.socket_inode(),
            socket_uid: identity.socket_uid(),
            socket_mode: identity.socket_mode(),
        }
    }
    fn validate(&self) -> Result<(), CodecError> {
        validate_status_peer(&self.status, &self.peer)?;
        if !hash(&self.manifest_file_digest)
            || self.socket_inode == 0
            || self.socket_uid != self.peer.uid
            || self.socket_mode & !0o7777 != 0
            || self.socket_mode & 0o077 != 0
        {
            return Err(CodecError::InvalidFields);
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct IntentRecord {
    schema: String,
    context: IntentContext,
    prepared: PreparedRecord,
}
impl fmt::Debug for IntentRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IntentRecord { inert private data }")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ContentRelation {
    Identical,
    ChangedSameKey,
    DifferentKey,
}

impl IntentRecord {
    pub(super) fn from_prepared(
        context: IntentContext,
        identity: &PreparedStopIdentity<'_>,
    ) -> Result<Self, CodecError> {
        let record = Self {
            schema: INTENT_SCHEMA.into(),
            context,
            prepared: PreparedRecord::captured(identity),
        };
        record.encode()?;
        Ok(record)
    }
    fn validate(&self) -> Result<(), CodecError> {
        if self.schema == "podbay.operator-zap-stop-intent/1"
            || self.schema == "podbay.operator-zap-stop-terminal/1"
        {
            return Err(CodecError::LegacyUnsigned);
        }
        if self.schema != INTENT_SCHEMA {
            return Err(CodecError::UnsupportedSchema);
        }
        self.prepared.validate()?;
        let c = &self.context;
        let b = self
            .prepared
            .status
            .bound
            .as_ref()
            .ok_or(CodecError::InvalidFields)?;
        if [
            &c.stop_key,
            &c.lineage,
            &c.actor,
            &c.scope,
            &c.launch_command,
            &c.session,
            &c.run,
        ]
        .iter()
        .any(|s| !label(s, 160))
            || [
                &c.actor_binding_digest,
                &c.launch_receipt_digest,
                &c.policy_digest,
                &c.pod_artifact,
                &c.node_artifact,
                &c.zap_artifact,
            ]
            .iter()
            .any(|s| !hash(s))
            || [
                c.owner_epoch,
                c.actor_credential_generation,
                c.authority_revision,
                c.resource_input_epoch,
            ]
            .contains(&0)
            || c.lineage != b.store_lineage
            || c.scope != b.scope_id
            || c.owner_epoch != b.owner_epoch
            || matches!(&c.configuration, Configuration::Pinned { sha256 } if !hash(sha256))
        {
            return Err(CodecError::InvalidFields);
        }
        Ok(())
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        encode(self, MAX_INTENT)
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let record: Self = decode(bytes, MAX_INTENT, INTENT_SCHEMA)?;
        record.validate()?;
        canonical(&record, bytes, MAX_INTENT)?;
        Ok(record)
    }
    pub(super) fn digest(&self) -> Result<String, CodecError> {
        Ok(digest(
            b"podbay.operator-zap-stop-intent/2\0",
            &self.encode()?,
        ))
    }
    /// Content comparison only; Identical does not mean previously admitted.
    pub(super) fn compare(&self, candidate: &Self) -> Result<ContentRelation, CodecError> {
        let prior = self.encode()?;
        let next = candidate.encode()?;
        Ok(if self.context.stop_key != candidate.context.stop_key {
            ContentRelation::DifferentKey
        } else if prior == next {
            ContentRelation::Identical
        } else {
            ContentRelation::ChangedSameKey
        })
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ExchangeResult {
    RefusedBeforeWrite {},
    UncertainAfterWrite {},
    ReplyObserved {
        reply_hex: String,
        reply_digest: String,
        status: PodStatus,
        peer: PeerRecord,
    },
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct OutcomeRecord {
    schema: String,
    stop_key: String,
    intent_digest: String,
    result: ExchangeResult,
}
impl fmt::Debug for OutcomeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OutcomeRecord { inert exchange data }")
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplyWire {
    ok: bool,
    status: Option<PodStatus>,
    error: Option<String>,
    error_code: Option<String>,
    terminal: Option<serde_json::Value>,
}
impl OutcomeRecord {
    fn with_result(intent: &IntentRecord, result: ExchangeResult) -> Result<Self, CodecError> {
        let record = Self {
            schema: OUTCOME_SCHEMA.into(),
            stop_key: intent.context.stop_key.clone(),
            intent_digest: intent.digest()?,
            result,
        };
        record.verify_intent(intent)?;
        record.encode()?;
        Ok(record)
    }
    /// Preserves only the phase. Arbitrary error reason strings are not persisted.
    pub(super) fn from_error(
        intent: &IntentRecord,
        error: AttestedStopError,
    ) -> Result<Self, CodecError> {
        Self::with_result(
            intent,
            match error {
                AttestedStopError::RefusedBeforeWrite(_) => ExchangeResult::RefusedBeforeWrite {},
                AttestedStopError::UncertainAfterWrite(_) => ExchangeResult::UncertainAfterWrite {},
            },
        )
    }
    /// Oversize evidence refuses encoding. This is not permission to retry a send.
    pub(super) fn from_reply(
        intent: &IntentRecord,
        reply: &AttestedStopReply,
    ) -> Result<Self, CodecError> {
        if reply.reply_bytes().len() > MAX_REPLY {
            return Err(CodecError::Oversize);
        }
        Self::with_result(
            intent,
            ExchangeResult::ReplyObserved {
                reply_hex: hex(reply.reply_bytes()),
                reply_digest: digest(b"podbay.operator-zap-stop-reply/1\0", reply.reply_bytes()),
                status: reply.status().clone(),
                peer: PeerRecord::captured(reply.peer()),
            },
        )
    }
    fn validate(&self) -> Result<(), CodecError> {
        if self.schema != OUTCOME_SCHEMA {
            return Err(CodecError::UnsupportedSchema);
        }
        if !label(&self.stop_key, 160) || !hash(&self.intent_digest) {
            return Err(CodecError::InvalidFields);
        }
        if let ExchangeResult::ReplyObserved {
            reply_hex,
            reply_digest,
            status,
            peer,
        } = &self.result
        {
            let bytes = unhex(reply_hex)?;
            if !hash(reply_digest)
                || digest(b"podbay.operator-zap-stop-reply/1\0", &bytes) != *reply_digest
            {
                return Err(CodecError::InvalidFields);
            }
            let wire: ReplyWire =
                serde_json::from_slice(&bytes).map_err(|_| CodecError::Malformed)?;
            if !wire.ok
                || wire.error.is_some()
                || wire.error_code.is_some()
                || wire.terminal.is_some()
                || wire.status.as_ref() != Some(status)
            {
                return Err(CodecError::InvalidFields);
            }
            validate_status_peer(status, peer)?;
        }
        Ok(())
    }
    pub(super) fn verify_intent(&self, intent: &IntentRecord) -> Result<(), CodecError> {
        self.validate()?;
        if self.stop_key != intent.context.stop_key || self.intent_digest != intent.digest()? {
            return Err(CodecError::IntentMismatch);
        }
        if let ExchangeResult::ReplyObserved { status, peer, .. } = &self.result {
            let mut identity = status.clone();
            identity.child_running = intent.prepared.status.child_running;
            identity.exit_code = intent.prepared.status.exit_code;
            if identity != intent.prepared.status || peer != &intent.prepared.peer {
                return Err(CodecError::IntentMismatch);
            }
        }
        Ok(())
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        encode(self, MAX_OUTCOME)
    }
    /// Decode returns data, not a verified terminal or authenticated observation.
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let record: Self = decode(bytes, MAX_OUTCOME, OUTCOME_SCHEMA)?;
        record.validate()?;
        canonical(&record, bytes, MAX_OUTCOME)?;
        Ok(record)
    }
    pub(super) fn digest(&self) -> Result<String, CodecError> {
        Ok(digest(
            b"podbay.operator-zap-stop-exchange/1\0",
            &self.encode()?,
        ))
    }
}

fn validate_status_peer(s: &PodStatus, p: &PeerRecord) -> Result<(), CodecError> {
    let b = s.bound.as_ref().ok_or(CodecError::InvalidFields)?;
    if s.protocol != "podbay-pod/1"
        || [
            &s.pod_id,
            &s.attempt_id,
            &b.resource_id,
            &b.scope_id,
            &b.store_lineage,
        ]
        .iter()
        .any(|v| !label(v, 160))
        || !label(&s.unit_name, 256)
        || !path(&s.cgroup_path)
        || !boot(&s.boot_id)
        || !hash(&s.manifest_digest)
        || !hash(&b.descriptor_digest)
        || !hash(&b.effective_digest)
        || [
            s.incarnation,
            s.supervisor_start_ticks,
            s.child_start_ticks,
            b.resource_epoch,
            b.owner_epoch,
            b.credential_epoch,
        ]
        .contains(&0)
        || s.supervisor_pid == 0
        || s.child_pid == 0
        || (s.child_running && s.exit_code.is_some())
        || b.capability != OPERATOR_PROCESS_CAPABILITY
        || [
            &b.manager_os_identity,
            &b.manager_process_id,
            &b.manager_boot_identity,
            &b.manager_birth_identity,
            &b.manager_containment,
        ]
        .iter()
        .any(|v| !label(v, 256))
        || b.policy_fence
            .as_ref()
            .is_some_and(|f| f.policy_fence_epoch == 0 || f.admission_authority_revision == 0)
        || p.pid != s.supervisor_pid
        || p.birth != s.supervisor_start_ticks
        || p.boot != s.boot_id
        || p.cgroup != s.cgroup_path
    {
        return Err(CodecError::InvalidFields);
    }
    Ok(())
}
fn label(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_graphic())
}
fn path(s: &str) -> bool {
    s.starts_with('/') && s.len() <= 4096 && !s.chars().any(char::is_control)
}
fn boot(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
fn hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(s: &str) -> Result<Vec<u8>, CodecError> {
    if s.len() > 2 * MAX_REPLY {
        return Err(CodecError::Oversize);
    }
    if s.is_empty()
        || s.len() % 2 != 0
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CodecError::InvalidFields);
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            Ok(digit(pair[0]) * 16 + digit(pair[1]))
        })
        .collect()
}
fn digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(domain);
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
    hex(&h.finalize())
}
fn encode<T: Serialize>(record: &T, max: usize) -> Result<Vec<u8>, CodecError> {
    let bytes = serde_json::to_vec(record).map_err(|_| CodecError::Malformed)?;
    if bytes.len() > max {
        Err(CodecError::Oversize)
    } else {
        Ok(bytes)
    }
}
fn decode<T: DeserializeOwned>(bytes: &[u8], max: usize, schema: &str) -> Result<T, CodecError> {
    if bytes.len() > max {
        return Err(CodecError::Oversize);
    }
    // This probe only distinguishes known unsigned legacy records. It never
    // accepts a record; duplicate/unknown fields still face the typed decoder.
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| CodecError::Malformed)?;
    match value.get("schema").and_then(|s| s.as_str()) {
        Some("podbay.operator-zap-stop-intent/1" | "podbay.operator-zap-stop-terminal/1") => {
            return Err(CodecError::LegacyUnsigned);
        }
        Some(actual) if actual == schema => {}
        _ => return Err(CodecError::UnsupportedSchema),
    }
    serde_json::from_slice(bytes).map_err(|_| CodecError::Malformed)
}
fn canonical<T: Serialize>(record: &T, bytes: &[u8], max: usize) -> Result<(), CodecError> {
    if encode(record, max)? == bytes {
        Ok(())
    } else {
        Err(CodecError::NonCanonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use podbay_pod::BoundPodStatus;
    use serde_json::{Value, json};

    // Explicit codec DTO fixture, not an authenticated origin/preparation.
    pub(super) fn fixture() -> IntentRecord {
        let boot = "12345678-1234-1234-1234-123456789abc".to_owned();
        IntentRecord {
            schema: INTENT_SCHEMA.into(),
            context: IntentContext {
                stop_key: "stop.operator.fixture".into(),
                lineage: "store.fixture".into(),
                actor: "actor.fixture".into(),
                scope: "scope.fixture".into(),
                owner_epoch: 7,
                actor_credential_generation: 3,
                authority_revision: 19,
                actor_binding_digest: "a".repeat(64),
                launch_command: "command.launch.fixture".into(),
                launch_receipt_digest: "b".repeat(64),
                policy_digest: "c".repeat(64),
                session: "session.fixture".into(),
                run: "run.fixture".into(),
                resource_input_epoch: 2,
                pod_artifact: "d".repeat(64),
                node_artifact: "e".repeat(64),
                zap_artifact: "f".repeat(64),
                configuration: Configuration::Pinned {
                    sha256: "1".repeat(64),
                },
            },
            prepared: PreparedRecord {
                status: PodStatus {
                    protocol: "podbay-pod/1".into(),
                    pod_id: "pod.fixture".into(),
                    attempt_id: "attempt.fixture".into(),
                    incarnation: 2,
                    manifest_digest: "2".repeat(64),
                    supervisor_pid: 201,
                    supervisor_start_ticks: 301,
                    child_pid: 202,
                    child_start_ticks: 302,
                    boot_id: boot.clone(),
                    unit_name: "podbay-pod-fixture.service".into(),
                    cgroup_path: "/fixture/podbay-pod-fixture.service".into(),
                    child_running: true,
                    exit_code: None,
                    bound: Some(BoundPodStatus {
                        capability: OPERATOR_PROCESS_CAPABILITY.into(),
                        descriptor_digest: "3".repeat(64),
                        effective_digest: "4".repeat(64),
                        resource_id: "resource.fixture".into(),
                        resource_epoch: 5,
                        scope_id: "scope.fixture".into(),
                        store_lineage: "store.fixture".into(),
                        owner_epoch: 7,
                        credential_epoch: 3,
                        policy_fence: None,
                        manager_os_identity: "linux.uid.1000".into(),
                        manager_process_id: "linux.pid.100".into(),
                        manager_boot_identity: format!("linux.boot.{boot}"),
                        manager_birth_identity: "linux.start.200".into(),
                        manager_containment: "linux.cgroup./manager".into(),
                    }),
                },
                peer: PeerRecord {
                    pid: 201,
                    uid: 1000,
                    gid: 1000,
                    birth: 301,
                    boot,
                    cgroup: "/fixture/podbay-pod-fixture.service".into(),
                },
                manifest_file_digest: "5".repeat(64),
                socket_device: 42,
                socket_inode: 43,
                socket_uid: 1000,
                socket_mode: 0o600,
            },
        }
    }
    pub(super) fn reply_record(intent: &IntentRecord, running: bool) -> OutcomeRecord {
        let mut status = intent.prepared.status.clone();
        status.child_running = running;
        status.exit_code = if running { None } else { Some(0) };
        let bytes = serde_json::to_vec(&json!({"ok":true,"status":status,"error":null})).unwrap();
        OutcomeRecord::with_result(
            intent,
            ExchangeResult::ReplyObserved {
                reply_hex: hex(&bytes),
                reply_digest: digest(b"podbay.operator-zap-stop-reply/1\0", &bytes),
                status,
                peer: intent.prepared.peer.clone(),
            },
        )
        .unwrap()
    }
    fn leaves(value: &Value, prefix: Vec<String>, output: &mut Vec<Vec<String>>) {
        if let Value::Object(map) = value {
            for (key, child) in map {
                let mut p = prefix.clone();
                p.push(key.clone());
                leaves(child, p, output);
            }
        } else {
            output.push(prefix);
        }
    }
    fn at_mut<'a>(value: &'a mut Value, path: &[String]) -> &'a mut Value {
        if path.is_empty() {
            value
        } else {
            at_mut(&mut value[&path[0]], &path[1..])
        }
    }
    fn change(value: &mut Value) {
        *value = match value {
            Value::String(s) if hash(s) => {
                let mut s = s.clone();
                s.replace_range(..1, if s.starts_with('a') { "b" } else { "a" });
                json!(s)
            }
            Value::String(s) if boot(s) => {
                let mut s = s.clone();
                s.replace_range(..1, "f");
                json!(s)
            }
            Value::String(s) => json!(format!("{s}.changed")),
            Value::Number(n) => json!(n.as_u64().unwrap().checked_add(1).unwrap_or(1)),
            Value::Bool(b) => json!(!*b),
            Value::Null => json!(1),
            _ => unreachable!(),
        };
    }

    #[test]
    fn intent_v2_canonical_roundtrip_and_changed_same_key_are_only_content_facts() {
        let original = fixture();
        let bytes = original.encode().unwrap();
        let decoded = IntentRecord::decode(&bytes).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(
            original.compare(&decoded).unwrap(),
            ContentRelation::Identical
        );
        let mut changed = original.clone();
        changed.context.policy_digest = "9".repeat(64);
        assert_eq!(
            original.compare(&changed).unwrap(),
            ContentRelation::ChangedSameKey
        );
        assert_ne!(original.digest().unwrap(), changed.digest().unwrap());
        changed.context.stop_key.push_str(".other");
        assert_eq!(
            original.compare(&changed).unwrap(),
            ContentRelation::DifferentKey
        );
        let mut no_config = original.clone();
        no_config.context.configuration = Configuration::Absent {};
        assert_ne!(no_config.digest().unwrap(), original.digest().unwrap());
        assert_eq!(
            IntentRecord::decode(&no_config.encode().unwrap()).unwrap(),
            no_config
        );
    }

    #[test]
    fn intent_v2_every_leaf_is_bound_or_refused_including_coherent_changes() {
        let original = fixture();
        let value = serde_json::to_value(&original).unwrap();
        let mut paths = Vec::new();
        leaves(&value, vec![], &mut paths);
        assert_eq!(paths.len(), 59);
        for path in &paths {
            let mut changed = value.clone();
            change(at_mut(&mut changed, path));
            if let Ok(candidate) = serde_json::from_value::<IntentRecord>(changed) {
                if candidate.validate().is_ok() {
                    assert_ne!(
                        candidate.digest().unwrap(),
                        original.digest().unwrap(),
                        "{path:?}"
                    );
                    assert_ne!(
                        original.compare(&candidate).unwrap(),
                        ContentRelation::Identical,
                        "{path:?}"
                    );
                }
            }
        }
        let mut optional = original.clone();
        optional
            .prepared
            .status
            .bound
            .as_mut()
            .unwrap()
            .policy_fence = Some(podbay_pod::BoundPolicyFenceV3 {
            policy_fence_epoch: 1,
            admission_authority_revision: 2,
        });
        assert_eq!(
            original.compare(&optional).unwrap(),
            ContentRelation::ChangedSameKey
        );
        for field in 0..2 {
            let mut changed = optional.clone();
            let fence = changed
                .prepared
                .status
                .bound
                .as_mut()
                .unwrap()
                .policy_fence
                .as_mut()
                .unwrap();
            if field == 0 {
                fence.policy_fence_epoch += 1;
            } else {
                fence.admission_authority_revision += 1;
            }
            assert_ne!(optional.digest().unwrap(), changed.digest().unwrap());
        }
        let mut coherent = original.clone();
        coherent.context.owner_epoch += 1;
        coherent.prepared.status.bound.as_mut().unwrap().owner_epoch += 1;
        assert_eq!(
            original.compare(&coherent).unwrap(),
            ContentRelation::ChangedSameKey
        );
        let mut coherent_peer = original.clone();
        coherent_peer.prepared.status.supervisor_pid += 1;
        coherent_peer.prepared.peer.pid += 1;
        assert_eq!(
            original.compare(&coherent_peer).unwrap(),
            ContentRelation::ChangedSameKey
        );
    }

    #[test]
    fn intent_v2_rejects_duplicate_unknown_legacy_noncanonical_and_oversize() {
        let original = fixture();
        let bytes = original.encode().unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        for field in [
            "schema",
            "actor",
            "pid",
            "socket_inode",
            "supervisor_pid",
            "credential_epoch",
        ] {
            let token = format!("\"{field}\":");
            let duplicated = text.replacen(&token, &format!("\"{field}\":null,{token}"), 1);
            assert!(
                IntentRecord::decode(duplicated.as_bytes()).is_err(),
                "{field}"
            );
        }
        for object_path in [
            vec![],
            vec!["context"],
            vec!["prepared"],
            vec!["prepared", "peer"],
            vec!["prepared", "status"],
            vec!["prepared", "status", "bound"],
        ] {
            let mut value = serde_json::to_value(&original).unwrap();
            let path = object_path
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>();
            at_mut(&mut value, &path)["unexpected"] = json!("fixture-secret");
            assert_eq!(
                IntentRecord::decode(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
                CodecError::Malformed
            );
        }
        let mut whitespace = b" ".to_vec();
        whitespace.extend_from_slice(&bytes);
        assert_eq!(
            IntentRecord::decode(&whitespace).unwrap_err(),
            CodecError::NonCanonical
        );
        assert_eq!(
            IntentRecord::decode(&vec![b' '; MAX_INTENT + 1]).unwrap_err(),
            CodecError::Oversize
        );
        for schema in [
            "podbay.operator-zap-stop-intent/1",
            "podbay.operator-zap-stop-terminal/1",
        ] {
            assert_eq!(
                IntentRecord::decode(&serde_json::to_vec(&json!({"schema":schema})).unwrap())
                    .unwrap_err(),
                CodecError::LegacyUnsigned
            );
        }
        let schema = text.replace(INTENT_SCHEMA, "podbay.operator-zap-stop-intent/99");
        assert_eq!(
            IntentRecord::decode(schema.as_bytes()).unwrap_err(),
            CodecError::UnsupportedSchema
        );
        let floating = text.replacen("\"owner_epoch\":7", "\"owner_epoch\":7.0", 1);
        assert!(IntentRecord::decode(floating.as_bytes()).is_err());
    }

    #[test]
    fn intent_v2_actor_and_pod_manager_credentials_are_independent() {
        let mut original = fixture();
        original.context.actor_credential_generation = 11;
        original
            .prepared
            .status
            .bound
            .as_mut()
            .unwrap()
            .credential_epoch = 3;
        let bytes = original.encode().unwrap();
        let decoded = IntentRecord::decode(&bytes).unwrap();
        assert_eq!(decoded.context.actor_credential_generation, 11);
        assert_eq!(
            decoded
                .prepared
                .status
                .bound
                .as_ref()
                .unwrap()
                .credential_epoch,
            3
        );
        assert_eq!(decoded, original);
        for actor_counter in [true, false] {
            let mut changed = original.clone();
            if actor_counter {
                changed.context.actor_credential_generation += 1;
            } else {
                changed
                    .prepared
                    .status
                    .bound
                    .as_mut()
                    .unwrap()
                    .credential_epoch += 1;
            }
            assert_eq!(
                IntentRecord::decode(&changed.encode().unwrap()).unwrap(),
                changed
            );
            assert_ne!(changed.digest().unwrap(), original.digest().unwrap());
            assert_eq!(
                original.compare(&changed).unwrap(),
                ContentRelation::ChangedSameKey
            );
        }
        let obsolete = String::from_utf8(bytes)
            .unwrap()
            .replace("actor_credential_generation", "credential_generation");
        assert_eq!(
            IntentRecord::decode(obsolete.as_bytes()).unwrap_err(),
            CodecError::Malformed
        );
    }

    #[test]
    fn intent_v2_peer_binding_and_numeric_extremes_are_checked() {
        let mut record = fixture();
        record.context.authority_revision = u64::MAX;
        assert_eq!(
            IntentRecord::decode(&record.encode().unwrap())
                .unwrap()
                .context
                .authority_revision,
            u64::MAX
        );
        for case in 0..8 {
            let mut bad = fixture();
            match case {
                0 => bad.context.actor_credential_generation = 0,
                1 => bad.context.scope.push('x'),
                2 => bad.prepared.peer.boot.push('x'),
                3 => bad.prepared.socket_uid += 1,
                4 => bad.prepared.status.bound = None,
                5 => bad.prepared.status.child_pid = 0,
                6 => bad.prepared.status.exit_code = Some(0),
                _ => bad.prepared.status.bound.as_mut().unwrap().credential_epoch = 0,
            }
            assert_eq!(bad.encode().unwrap_err(), CodecError::InvalidFields);
        }
    }

    #[test]
    fn outcome_v1_preserves_refusal_and_uncertainty_without_error_reason_leaks() {
        let intent = fixture();
        let refused = OutcomeRecord::from_error(
            &intent,
            AttestedStopError::RefusedBeforeWrite("fixture-secret-do-not-log"),
        )
        .unwrap();
        let uncertain = OutcomeRecord::from_error(
            &intent,
            AttestedStopError::UncertainAfterWrite("fixture-secret-do-not-log"),
        )
        .unwrap();
        assert_ne!(refused.digest().unwrap(), uncertain.digest().unwrap());
        for record in [refused, uncertain] {
            let bytes = record.encode().unwrap();
            let decoded = OutcomeRecord::decode(&bytes).unwrap();
            decoded.verify_intent(&intent).unwrap();
            assert!(
                !String::from_utf8(bytes)
                    .unwrap()
                    .contains("fixture-secret-do-not-log")
            );
            assert!(!format!("{record:?}").contains("fixture-secret-do-not-log"));
        }
        let mut secret = intent;
        secret.context.actor = "fixture-secret-do-not-log".into();
        assert!(!format!("{secret:?}").contains("fixture-secret-do-not-log"));
        let error =
            OutcomeRecord::decode(b"{\"schema\":\"fixture-secret-do-not-log\"}").unwrap_err();
        assert!(!format!("{error} {error:?}").contains("fixture-secret-do-not-log"));
    }

    #[test]
    fn outcome_v1_running_and_stopped_replies_remain_reply_observations() {
        let intent = fixture();
        for running in [true, false] {
            let record = reply_record(&intent, running);
            let bytes = record.encode().unwrap();
            let decoded = OutcomeRecord::decode(&bytes).unwrap();
            decoded.verify_intent(&intent).unwrap();
            assert_eq!(decoded, record);
            let ExchangeResult::ReplyObserved {
                status, reply_hex, ..
            } = decoded.result
            else {
                panic!("reply phase lost")
            };
            assert_eq!(status.child_running, running);
            let parsed: ReplyWire = serde_json::from_slice(&unhex(&reply_hex).unwrap()).unwrap();
            assert_eq!(parsed.status, Some(status));
        }
        let mut foreign = intent.clone();
        foreign.context.policy_digest = "9".repeat(64);
        assert_eq!(
            reply_record(&intent, true)
                .verify_intent(&foreign)
                .unwrap_err(),
            CodecError::IntentMismatch
        );
    }

    #[test]
    fn outcome_v1_rejects_coherent_foreign_reply_against_original_intent() {
        let intent = fixture();
        let mut foreign = intent.clone();
        foreign.prepared.status.supervisor_pid += 1;
        foreign.prepared.peer.pid += 1;
        let mut record = reply_record(&foreign, true);
        record.intent_digest = intent.digest().unwrap(); // Coherent payload and raw digest, wrong original peer.
        record.validate().unwrap();
        assert_eq!(
            record.verify_intent(&intent).unwrap_err(),
            CodecError::IntentMismatch
        );
        let mut changed = reply_record(&intent, true);
        let ExchangeResult::ReplyObserved { peer, .. } = &mut changed.result else {
            unreachable!()
        };
        peer.gid += 1;
        changed.validate().unwrap();
        assert_eq!(
            changed.verify_intent(&intent).unwrap_err(),
            CodecError::IntentMismatch
        );
    }

    #[test]
    fn outcome_v1_every_leaf_is_bound_or_refused() {
        let intent = fixture();
        let original = reply_record(&intent, true);
        let value = serde_json::to_value(&original).unwrap();
        let mut paths = Vec::new();
        leaves(&value, vec![], &mut paths);
        assert_eq!(paths.len(), 40);
        for path in paths {
            let mut changed = value.clone();
            change(at_mut(&mut changed, &path));
            if let Ok(candidate) = serde_json::from_value::<OutcomeRecord>(changed) {
                if candidate.validate().is_ok() {
                    assert_ne!(
                        candidate.digest().unwrap(),
                        original.digest().unwrap(),
                        "{path:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn outcome_v1_strict_shape_and_reply_bounds_do_not_enable_terminal() {
        let intent = fixture();
        let record = reply_record(&intent, true);
        let canonical = record.encode().unwrap();
        let text = String::from_utf8(canonical.clone()).unwrap();
        for field in [
            "schema",
            "stop_key",
            "kind",
            "reply_hex",
            "supervisor_pid",
            "credential_epoch",
        ] {
            let token = format!("\"{field}\":");
            let duplicate = text.replacen(&token, &format!("\"{field}\":null,{token}"), 1);
            assert!(OutcomeRecord::decode(duplicate.as_bytes()).is_err());
        }
        let mut value = serde_json::to_value(&record).unwrap();
        value["result"]["kind"] = json!("terminal_observed");
        assert_eq!(
            OutcomeRecord::decode(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            CodecError::Malformed
        );
        value = serde_json::to_value(&record).unwrap();
        value["result"]["secret_extra"] = json!("fixture-secret");
        assert_eq!(
            OutcomeRecord::decode(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            CodecError::Malformed
        );
        let refused =
            OutcomeRecord::from_error(&intent, AttestedStopError::RefusedBeforeWrite("unused"))
                .unwrap();
        value = serde_json::to_value(&refused).unwrap();
        value["result"]["unknown"] = json!(true);
        assert_eq!(
            OutcomeRecord::decode(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            CodecError::Malformed
        );
        assert_eq!(
            OutcomeRecord::decode(&vec![b' '; MAX_OUTCOME + 1]).unwrap_err(),
            CodecError::Oversize
        );
        let mut padded = record;
        let ExchangeResult::ReplyObserved {
            reply_hex,
            reply_digest,
            ..
        } = &mut padded.result
        else {
            unreachable!()
        };
        let mut raw = unhex(reply_hex).unwrap();
        raw.resize(MAX_REPLY, b' ');
        *reply_hex = hex(&raw);
        *reply_digest = digest(b"podbay.operator-zap-stop-reply/1\0", &raw);
        let bytes = padded.encode().unwrap();
        OutcomeRecord::decode(&bytes)
            .unwrap()
            .verify_intent(&intent)
            .unwrap();
        let ExchangeResult::ReplyObserved { reply_hex, .. } = &mut padded.result else {
            unreachable!()
        };
        reply_hex.push_str("20");
        assert_eq!(padded.encode().unwrap_err(), CodecError::Oversize);
        let mut spaced = b" ".to_vec();
        spaced.extend_from_slice(&canonical);
        assert_eq!(
            OutcomeRecord::decode(&spaced).unwrap_err(),
            CodecError::NonCanonical
        );
    }
}

#[cfg(test)]
#[path = "stop_one_send_fixture.rs"]
mod one_send_fixture;
