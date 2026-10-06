//! Strict data contracts for a future operator FD3 observation capability.
//!
//! Construction and decoding prove shape, canonical bytes and associations.
//! They do not register a profile, admit a command, measure a file, allocate a
//! generation, authenticate a child or grant Ready. No secret, nonce, process
//! identity or future HostAccepted receipt belongs in this pre-admission data.
use std::error::Error;
use std::fmt::{Display, Formatter};

use podbay_core::{PlannedRootBinding, PodId, ResourceKind, Role, ScopeId, WorkKind};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::{
    LifetimeLimit, NativeResourceKind, NativeResourceView, NativeRole, NativeWorkKind,
    ProtocolVersion, ResourceDriver, TargetOs,
};

pub const OPERATOR_FD3_OBSERVE_PROFILE_REF: &str = "podbay.operator.process.fd3-observe.v1";
pub const OPERATOR_FD3_OBSERVE_DRIVER_REF: &str = "process.exec.fd3-observe.v1";
pub const OPERATOR_FD3_OBSERVE_CAPABILITY: &str = "operator_process_fd3_observe_v1";
pub const OPERATOR_FD3_OBSERVE_POLICY_SCHEMA: &str = "podbay.operator-fd3-observe-policy/1";
pub const LAUNCH_DESCRIPTOR_OPERATOR_FD3_OBSERVE_SCHEMA: &str =
    "podbay.launch-descriptor/operator-fd3-observe/1";
pub const EFFECTIVE_OPERATOR_FD3_OBSERVE_VERSION: &str =
    "podbay.effective-launch/operator-fd3-observe/1";
pub const OPERATOR_FD3_OBSERVE_CHILD_PROTOCOL: &str = "podbay.lens-readiness/1";
pub const OPERATOR_FD3_OBSERVE_MAX_FRAME_BYTES: u32 = 65_536;
pub const OPERATOR_FD3_OBSERVE_EXCHANGE_TIMEOUT_MS: u32 = 2_000;
pub const OPERATOR_FD3_OBSERVE_MAX_POLICY_BYTES: usize = 16_384;
pub const OPERATOR_FD3_OBSERVE_MAX_CONTRACT_BYTES: usize = 65_536;

const POLICY_DOMAIN: &[u8] = b"podbay.operator-fd3-observe-policy/1\0";
const DESCRIPTOR_DOMAIN: &[u8] = b"podbay.launch-descriptor/operator-fd3-observe/1\0";
const EFFECTIVE_DOMAIN: &[u8] = b"podbay.effective-launch/operator-fd3-observe/1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperatorFd3ContractError {
    TooLarge,
    Truncated,
    TrailingBytes,
    Malformed,
    NonCanonical,
    UnsupportedVersion,
    InvalidField(&'static str),
    DigestMismatch,
    BindingMismatch,
}
impl Display for OperatorFd3ContractError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => f.write_str("FD3 contract exceeds byte bound"),
            Self::Truncated => f.write_str("FD3 contract is truncated"),
            Self::TrailingBytes => f.write_str("FD3 contract has trailing bytes"),
            Self::Malformed => f.write_str("FD3 contract is malformed"),
            Self::NonCanonical => f.write_str("FD3 contract is not canonical"),
            Self::UnsupportedVersion => f.write_str("FD3 contract schema is unsupported"),
            Self::InvalidField(field) => write!(f, "invalid FD3 contract field: {field}"),
            Self::DigestMismatch => f.write_str("FD3 contract digest differs"),
            Self::BindingMismatch => f.write_str("FD3 contract binding differs"),
        }
    }
}
impl Error for OperatorFd3ContractError {}
type Result<T> = std::result::Result<T, OperatorFd3ContractError>;

/// A declared expected file pin. This type performs no filesystem observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperatorFilePinV1 {
    pub path: String,
    pub sha256: String,
}

/// Expected whole-tree digest using podbay.operator-artifact-tree/1, not the
/// hash of a single executable. Construction does not inspect the tree.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperatorArtifactTreePinV1 {
    pub root: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum OperatorConfigurationPinV1 {
    Absent,
    File { pin: OperatorFilePinV1 },
}

/// Logical expected subject only, never physical inode or uniqueness evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperatorWorkspaceExpectationV1 {
    pub logical_store_id: String,
    pub main_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorFd3ObservePolicyInputV1 {
    pub supervisor: OperatorFilePinV1,
    pub artifact: OperatorArtifactTreePinV1,
    pub configuration: OperatorConfigurationPinV1,
    pub public_composition_digest: String,
    pub registry_digest: String,
    pub workspace: OperatorWorkspaceExpectationV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyBody {
    transport: String,
    fd: u8,
    child_protocol: String,
    max_frame_bytes: u32,
    exchange_timeout_ms: u32,
    supervisor: OperatorFilePinV1,
    artifact: OperatorArtifactTreePinV1,
    configuration: OperatorConfigurationPinV1,
    public_composition_digest: String,
    registry_digest: String,
    workspace: OperatorWorkspaceExpectationV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyEnvelope {
    schema: String,
    digest: String,
    policy: PolicyBody,
}

/// Immutable validated expectations. Serialization is available only through
/// the canonical encoder; generic Deserialize cannot bypass validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorFd3ObservePolicyV1 {
    envelope: PolicyEnvelope,
}

impl OperatorFd3ObservePolicyV1 {
    pub fn new(input: OperatorFd3ObservePolicyInputV1) -> Result<Self> {
        let policy = PolicyBody {
            transport: "supervisorCreatedFd3".into(),
            fd: 3,
            child_protocol: OPERATOR_FD3_OBSERVE_CHILD_PROTOCOL.into(),
            max_frame_bytes: OPERATOR_FD3_OBSERVE_MAX_FRAME_BYTES,
            exchange_timeout_ms: OPERATOR_FD3_OBSERVE_EXCHANGE_TIMEOUT_MS,
            supervisor: input.supervisor,
            artifact: input.artifact,
            configuration: input.configuration,
            public_composition_digest: input.public_composition_digest,
            registry_digest: input.registry_digest,
            workspace: input.workspace,
        };
        validate_policy_body(&policy)?;
        let digest = hash(POLICY_DOMAIN, &json(&policy)?);
        let result = Self {
            envelope: PolicyEnvelope {
                schema: OPERATOR_FD3_OBSERVE_POLICY_SCHEMA.into(),
                digest,
                policy,
            },
        };
        result.encode_json()?;
        Ok(result)
    }
    pub fn decode_json(bytes: &[u8]) -> Result<Self> {
        check_size(bytes, OPERATOR_FD3_OBSERVE_MAX_POLICY_BYTES)?;
        let envelope: PolicyEnvelope =
            serde_json::from_slice(bytes).map_err(|_| OperatorFd3ContractError::Malformed)?;
        validate_policy(&envelope)?;
        let result = Self { envelope };
        require_canonical(bytes, &result.encode_json()?)?;
        Ok(result)
    }
    pub fn encode_json(&self) -> Result<Vec<u8>> {
        let bytes = json(&self.envelope)?;
        check_size(&bytes, OPERATOR_FD3_OBSERVE_MAX_POLICY_BYTES)?;
        Ok(bytes)
    }
    pub fn digest(&self) -> &str {
        &self.envelope.digest
    }
    pub fn supervisor(&self) -> &OperatorFilePinV1 {
        &self.envelope.policy.supervisor
    }
    pub fn artifact(&self) -> &OperatorArtifactTreePinV1 {
        &self.envelope.policy.artifact
    }
    pub fn configuration(&self) -> &OperatorConfigurationPinV1 {
        &self.envelope.policy.configuration
    }
    pub fn workspace(&self) -> &OperatorWorkspaceExpectationV1 {
        &self.envelope.policy.workspace
    }
    pub fn public_composition_digest(&self) -> &str {
        &self.envelope.policy.public_composition_digest
    }
    pub fn registry_digest(&self) -> &str {
        &self.envelope.policy.registry_digest
    }
}

/// Resolved-data input, not a trusted registration or authority capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorFd3ObserveEffectiveInputV1 {
    pub pod_id: PodId,
    pub scope_id: ScopeId,
    pub host_id: String,
    pub profile_generation: u64,
    pub executable: OperatorFilePinV1,
    pub cwd: String,
    pub arguments: Vec<String>,
    pub workspace_basis_ref: String,
    pub authority_grant_id: u64,
    pub lifetime: LifetimeLimit,
}

// Lossless canonical decimal strings for counters, including values above 2^53.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Counter(u64);
impl Serialize for Counter {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}
impl<'de> Deserialize<'de> for Counter {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.is_empty()
            || (text.len() > 1 && text.starts_with('0'))
            || !text.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(serde::de::Error::custom("noncanonical decimal counter"));
        }
        text.parse()
            .map(Self)
            .map_err(|_| serde::de::Error::custom("counter exceeds u64"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EffectiveBody {
    capability: String,
    pod_id: String,
    scope_id: String,
    role: NativeRole,
    work_kind: NativeWorkKind,
    parent_run_id: Option<String>,
    target_os: TargetOs,
    host_id: String,
    profile_ref: String,
    profile_generation: Counter,
    executable: OperatorFilePinV1,
    cwd: String,
    arguments: Vec<String>,
    workspace_basis_ref: String,
    workspace_access: String,
    authority_grant_id: Counter,
    model_id: String,
    reasoning_effort: String,
    fallback_approved: bool,
    tool_bundle_refs: Vec<String>,
    environment_refs: Vec<String>,
    credential_refs: Vec<String>,
    lifetime: LifetimeLimit,
    max_children: Counter,
    observation_policy: PolicyEnvelope,
}

/// Canonical frame = version/domain including NUL, u32 big-endian JSON length,
/// then canonical closed JSON body. Digest = SHA256 of that entire frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveOperatorFd3ObserveContractV1 {
    body: EffectiveBody,
    canonical: Vec<u8>,
    digest: String,
}
impl EffectiveOperatorFd3ObserveContractV1 {
    pub fn new(
        input: OperatorFd3ObserveEffectiveInputV1,
        policy: OperatorFd3ObservePolicyV1,
    ) -> Result<Self> {
        Self::from_body(EffectiveBody {
            capability: OPERATOR_FD3_OBSERVE_CAPABILITY.into(),
            pod_id: input.pod_id.as_str().into(),
            scope_id: input.scope_id.as_str().into(),
            role: NativeRole::Coordinator,
            work_kind: NativeWorkKind::Service,
            parent_run_id: None,
            target_os: TargetOs::Linux,
            host_id: input.host_id,
            profile_ref: OPERATOR_FD3_OBSERVE_PROFILE_REF.into(),
            profile_generation: Counter(input.profile_generation),
            executable: input.executable,
            cwd: input.cwd,
            arguments: input.arguments,
            workspace_basis_ref: input.workspace_basis_ref,
            workspace_access: "readWrite".into(),
            authority_grant_id: Counter(input.authority_grant_id),
            model_id: "none".into(),
            reasoning_effort: "none".into(),
            fallback_approved: false,
            tool_bundle_refs: vec![],
            environment_refs: vec![],
            credential_refs: vec![],
            lifetime: input.lifetime,
            max_children: Counter(0),
            observation_policy: policy.envelope,
        })
    }
    fn from_body(body: EffectiveBody) -> Result<Self> {
        validate_effective(&body)?;
        let payload = json(&body)?;
        let mut canonical = EFFECTIVE_DOMAIN.to_vec();
        canonical.extend_from_slice(
            &u32::try_from(payload.len())
                .map_err(|_| OperatorFd3ContractError::TooLarge)?
                .to_be_bytes(),
        );
        canonical.extend_from_slice(&payload);
        check_size(&canonical, OPERATOR_FD3_OBSERVE_MAX_CONTRACT_BYTES)?;
        let digest = hash(&[], &canonical);
        Ok(Self {
            body,
            canonical,
            digest,
        })
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        check_size(bytes, OPERATOR_FD3_OBSERVE_MAX_CONTRACT_BYTES)?;
        if !bytes.starts_with(EFFECTIVE_DOMAIN) {
            return Err(OperatorFd3ContractError::UnsupportedVersion);
        }
        let length_end = EFFECTIVE_DOMAIN.len() + 4;
        let raw = bytes
            .get(EFFECTIVE_DOMAIN.len()..length_end)
            .ok_or(OperatorFd3ContractError::Truncated)?;
        let length = u32::from_be_bytes(raw.try_into().expect("four bytes")) as usize;
        if length > OPERATOR_FD3_OBSERVE_MAX_CONTRACT_BYTES {
            return Err(OperatorFd3ContractError::TooLarge);
        }
        let end = length_end
            .checked_add(length)
            .ok_or(OperatorFd3ContractError::TooLarge)?;
        let payload = bytes
            .get(length_end..end)
            .ok_or(OperatorFd3ContractError::Truncated)?;
        if end != bytes.len() {
            return Err(OperatorFd3ContractError::TrailingBytes);
        }
        let body =
            serde_json::from_slice(payload).map_err(|_| OperatorFd3ContractError::Malformed)?;
        let result = Self::from_body(body)?;
        require_canonical(bytes, &result.canonical)?;
        Ok(result)
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn lifetime(&self) -> LifetimeLimit {
        self.body.lifetime
    }
    pub fn policy(&self) -> OperatorFd3ObservePolicyV1 {
        OperatorFd3ObservePolicyV1 {
            envelope: self.body.observation_policy.clone(),
        }
    }
    pub fn compare_with_descriptor(
        &self,
        descriptor: &ImmutableOperatorFd3ObserveDescriptorV1,
    ) -> Result<()> {
        if self.body != descriptor.body.effective
            || self.digest != descriptor.body.effective_spec_digest
        {
            return Err(OperatorFd3ContractError::BindingMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResourceBody {
    resource_id: String,
    kind: NativeResourceKind,
    epoch: Counter,
    driver: ResourceDriver,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IdentityBody {
    scope_id: String,
    actor_id: String,
    session_id: String,
    run_id: String,
    parent_run_id: Option<String>,
    role: NativeRole,
    work_kind: NativeWorkKind,
    attempt_id: String,
    attempt_ordinal: Counter,
    attempt_epoch: Counter,
    pod_id: String,
    pod_incarnation: Counter,
    resource: ResourceBody,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DescriptorBody {
    identity: IdentityBody,
    effective_spec_digest: String,
    effective: EffectiveBody,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DescriptorEnvelope {
    protocol: ProtocolVersion,
    schema: String,
    digest: String,
    descriptor: DescriptorBody,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImmutableOperatorFd3ObserveDescriptorV1 {
    body: DescriptorBody,
    digest: String,
}
impl ImmutableOperatorFd3ObserveDescriptorV1 {
    pub fn from_planned_root(
        planned: &PlannedRootBinding,
        effective: &EffectiveOperatorFd3ObserveContractV1,
    ) -> Result<Self> {
        Self::from_body(DescriptorBody {
            identity: identity_from_plan(planned)?,
            effective_spec_digest: effective.digest.clone(),
            effective: effective.body.clone(),
        })
    }
    fn from_body(body: DescriptorBody) -> Result<Self> {
        validate_identity(&body.identity)?;
        let effective = EffectiveOperatorFd3ObserveContractV1::from_body(body.effective.clone())?;
        if body.effective_spec_digest != effective.digest
            || body.identity.scope_id != body.effective.scope_id
            || body.identity.pod_id != body.effective.pod_id
        {
            return Err(OperatorFd3ContractError::BindingMismatch);
        }
        let digest = hash(DESCRIPTOR_DOMAIN, &json(&body)?);
        let result = Self { body, digest };
        result.encode_json()?;
        Ok(result)
    }
    pub fn decode_json(bytes: &[u8]) -> Result<Self> {
        check_size(bytes, OPERATOR_FD3_OBSERVE_MAX_CONTRACT_BYTES)?;
        let envelope: DescriptorEnvelope =
            serde_json::from_slice(bytes).map_err(|_| OperatorFd3ContractError::Malformed)?;
        if envelope.protocol != ProtocolVersion::V1
            || envelope.schema != LAUNCH_DESCRIPTOR_OPERATOR_FD3_OBSERVE_SCHEMA
        {
            return Err(OperatorFd3ContractError::UnsupportedVersion);
        }
        let result = Self::from_body(envelope.descriptor)?;
        if envelope.digest != result.digest {
            return Err(OperatorFd3ContractError::DigestMismatch);
        }
        require_canonical(bytes, &result.encode_json()?)?;
        Ok(result)
    }
    pub fn encode_json(&self) -> Result<Vec<u8>> {
        let bytes = json(&DescriptorEnvelope {
            protocol: ProtocolVersion::V1,
            schema: LAUNCH_DESCRIPTOR_OPERATOR_FD3_OBSERVE_SCHEMA.into(),
            digest: self.digest.clone(),
            descriptor: self.body.clone(),
        })?;
        check_size(&bytes, OPERATOR_FD3_OBSERVE_MAX_CONTRACT_BYTES)?;
        Ok(bytes)
    }
    pub fn validate_against_planned_root(&self, planned: &PlannedRootBinding) -> Result<()> {
        if self.body.identity != identity_from_plan(planned)? {
            return Err(OperatorFd3ContractError::BindingMismatch);
        }
        Ok(())
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn effective_spec_digest(&self) -> &str {
        &self.body.effective_spec_digest
    }
    pub fn scope_id(&self) -> &str {
        &self.body.identity.scope_id
    }
    pub fn actor_id(&self) -> &str {
        &self.body.identity.actor_id
    }
    pub fn session_id(&self) -> &str {
        &self.body.identity.session_id
    }
    pub fn run_id(&self) -> &str {
        &self.body.identity.run_id
    }
    pub fn attempt_id(&self) -> &str {
        &self.body.identity.attempt_id
    }
    pub fn pod_id(&self) -> &str {
        &self.body.identity.pod_id
    }
    pub fn attempt_ordinal(&self) -> u64 {
        self.body.identity.attempt_ordinal.0
    }
    pub fn attempt_epoch(&self) -> u64 {
        self.body.identity.attempt_epoch.0
    }
    pub fn pod_incarnation(&self) -> u64 {
        self.body.identity.pod_incarnation.0
    }
    pub fn lifetime(&self) -> LifetimeLimit {
        self.body.effective.lifetime
    }
    pub fn resource(&self) -> NativeResourceView<'_> {
        let resource = &self.body.identity.resource;
        NativeResourceView {
            resource_id: &resource.resource_id,
            kind: resource.kind,
            epoch: resource.epoch.0,
            driver: &resource.driver,
        }
    }
    pub fn effective(&self) -> EffectiveOperatorFd3ObserveContractV1 {
        // Validated on every construction path; no mutable body is exposed.
        EffectiveOperatorFd3ObserveContractV1::from_body(self.body.effective.clone())
            .expect("validated immutable effective body")
    }
}

fn identity_from_plan(planned: &PlannedRootBinding) -> Result<IdentityBody> {
    let binding = planned.identity();
    if binding.role() != Role::Coordinator
        || binding.work_kind() != WorkKind::Service
        || binding.parent_run_id().is_some()
        || binding.resources().len() != 1
        || binding.resources()[0].kind() != ResourceKind::Auxiliary
    {
        return Err(OperatorFd3ContractError::BindingMismatch);
    }
    let resource = &binding.resources()[0];
    let identity = IdentityBody {
        scope_id: binding.scope_id().as_str().into(),
        actor_id: binding.actor_id().as_str().into(),
        session_id: binding.session_id().as_str().into(),
        run_id: binding.run_id().as_str().into(),
        parent_run_id: None,
        role: NativeRole::Coordinator,
        work_kind: NativeWorkKind::Service,
        attempt_id: binding.attempt_id().as_str().into(),
        attempt_ordinal: Counter(binding.attempt_ordinal()),
        attempt_epoch: Counter(binding.attempt_epoch().get()),
        pod_id: binding.pod_id().as_str().into(),
        pod_incarnation: Counter(binding.pod_incarnation().get()),
        resource: ResourceBody {
            resource_id: resource.id().as_str().into(),
            kind: NativeResourceKind::Auxiliary,
            epoch: Counter(resource.epoch().get()),
            driver: ResourceDriver::Auxiliary {
                driver_ref: OPERATOR_FD3_OBSERVE_DRIVER_REF.into(),
            },
        },
    };
    validate_identity(&identity)?;
    Ok(identity)
}

fn validate_identity(body: &IdentityBody) -> Result<()> {
    if [
        &body.scope_id,
        &body.actor_id,
        &body.session_id,
        &body.run_id,
        &body.attempt_id,
        &body.pod_id,
        &body.resource.resource_id,
    ]
    .into_iter()
    .any(|s| !valid_id(s))
        || body.parent_run_id.is_some()
        || body.role != NativeRole::Coordinator
        || body.work_kind != NativeWorkKind::Service
        || body.attempt_ordinal.0 != 1
        || body.attempt_epoch.0 != 1
        || body.pod_incarnation.0 != 1
        || body.resource.epoch.0 != 1
        || body.resource.kind != NativeResourceKind::Auxiliary
        || !matches!(&body.resource.driver, ResourceDriver::Auxiliary { driver_ref }
            if driver_ref == OPERATOR_FD3_OBSERVE_DRIVER_REF)
    {
        return Err(OperatorFd3ContractError::InvalidField(
            "first-root identity/resource",
        ));
    }
    Ok(())
}

fn validate_effective(body: &EffectiveBody) -> Result<()> {
    validate_policy(&body.observation_policy)?;
    if PodId::try_from(body.pod_id.as_str()).is_err()
        || ScopeId::try_from(body.scope_id.as_str()).is_err()
        || body.capability != OPERATOR_FD3_OBSERVE_CAPABILITY
        || body.target_os != TargetOs::Linux
        || body.role != NativeRole::Coordinator
        || body.work_kind != NativeWorkKind::Service
        || body.parent_run_id.is_some()
        || body.profile_ref != OPERATOR_FD3_OBSERVE_PROFILE_REF
        || body.profile_generation.0 == 0
        || body.authority_grant_id.0 == 0
        || !valid_ref(&body.host_id)
        || !valid_ref(&body.workspace_basis_ref)
        || body.workspace_access != "readWrite"
        || body.model_id != "none"
        || body.reasoning_effort != "none"
        || body.fallback_approved
        || body.max_children.0 != 0
        || !body.tool_bundle_refs.is_empty()
        || !body.environment_refs.is_empty()
        || !body.credential_refs.is_empty()
    {
        return Err(OperatorFd3ContractError::InvalidField(
            "effective capability/profile",
        ));
    }
    validate_file_pin(&body.executable)?;
    if !valid_path(&body.cwd)
        || body.cwd != body.observation_policy.policy.artifact.root
        || body.arguments.is_empty()
        || body.arguments.len() > 64
        || body
            .arguments
            .iter()
            .any(|a| a.is_empty() || a.len() > 1024 || a.chars().any(char::is_control))
    {
        return Err(OperatorFd3ContractError::InvalidField("cwd/arguments"));
    }
    if !matches!(
        body.lifetime,
        LifetimeLimit::UntilStopped | LifetimeLimit::Finite { seconds: 30..=3600 }
    ) {
        return Err(OperatorFd3ContractError::InvalidField("lifetime"));
    }
    Ok(())
}

fn validate_policy(envelope: &PolicyEnvelope) -> Result<()> {
    if envelope.schema != OPERATOR_FD3_OBSERVE_POLICY_SCHEMA {
        return Err(OperatorFd3ContractError::UnsupportedVersion);
    }
    validate_policy_body(&envelope.policy)?;
    if envelope.digest != hash(POLICY_DOMAIN, &json(&envelope.policy)?) {
        return Err(OperatorFd3ContractError::DigestMismatch);
    }
    check_size(&json(envelope)?, OPERATOR_FD3_OBSERVE_MAX_POLICY_BYTES)
}
fn validate_policy_body(body: &PolicyBody) -> Result<()> {
    if body.transport != "supervisorCreatedFd3"
        || body.fd != 3
        || body.child_protocol != OPERATOR_FD3_OBSERVE_CHILD_PROTOCOL
        || body.max_frame_bytes != OPERATOR_FD3_OBSERVE_MAX_FRAME_BYTES
        || body.exchange_timeout_ms != OPERATOR_FD3_OBSERVE_EXCHANGE_TIMEOUT_MS
    {
        return Err(OperatorFd3ContractError::InvalidField(
            "transport/protocol/limits",
        ));
    }
    validate_file_pin(&body.supervisor)?;
    if !valid_path(&body.artifact.root) || !lower_digest(&body.artifact.sha256) {
        return Err(OperatorFd3ContractError::InvalidField("artifact tree pin"));
    }
    if let OperatorConfigurationPinV1::File { pin } = &body.configuration {
        validate_file_pin(pin)?;
    }
    if !lower_digest(&body.public_composition_digest)
        || !lower_digest(&body.registry_digest)
        || !valid_path(&body.workspace.main_path)
        || !canonical_uuid(&body.workspace.logical_store_id)
    {
        return Err(OperatorFd3ContractError::InvalidField(
            "expected startup subject",
        ));
    }
    Ok(())
}
fn validate_file_pin(pin: &OperatorFilePinV1) -> Result<()> {
    if !valid_path(&pin.path) || !lower_digest(&pin.sha256) {
        return Err(OperatorFd3ContractError::InvalidField("file pin"));
    }
    Ok(())
}
fn valid_path(value: &str) -> bool {
    value.len() > 1
        && value.len() <= 4096
        && value.starts_with('/')
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && value[1..]
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != "..")
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn valid_ref(value: &str) -> bool {
    (3..=256).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
}
fn lower_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
        && value.as_bytes()[14] == b'4'
        && b"89ab".contains(&value.as_bytes()[19])
}
fn json(value: &impl Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| OperatorFd3ContractError::Malformed)
}
fn check_size(bytes: &[u8], maximum: usize) -> Result<()> {
    if bytes.is_empty() {
        return Err(OperatorFd3ContractError::Malformed);
    }
    if bytes.len() > maximum {
        return Err(OperatorFd3ContractError::TooLarge);
    }
    Ok(())
}
fn require_canonical(actual: &[u8], expected: &[u8]) -> Result<()> {
    if actual != expected {
        return Err(OperatorFd3ContractError::NonCanonical);
    }
    Ok(())
}
fn hash(domain: &[u8], bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests;
