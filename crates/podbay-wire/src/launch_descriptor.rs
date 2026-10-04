//! Strict, platform-neutral launch descriptor derived from a complete core
//! binding and reviewed native policy. It is data, not admission or an OS effect.
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};

use podbay_core::{LaunchBinding, PlannedRootBinding, ResourceId, ResourceKind, Role, WorkKind};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::{CodexAppServerPolicyV2, MAX_FRAME_BYTES, ProtocolVersion};

pub const LAUNCH_DESCRIPTOR_SCHEMA: &str = "podbay.launch-descriptor/1";
const DIGEST_DOMAIN: &[u8] = b"podbay.launch-descriptor/1\0";
pub const LAUNCH_DESCRIPTOR_V2_SCHEMA: &str = "podbay.launch-descriptor/2";
const DIGEST_DOMAIN_V2: &[u8] = b"podbay.launch-descriptor/2\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetOs {
    Linux,
    Macos,
    Windows,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeRole {
    Coordinator,
    Worker,
    Advisor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeWorkKind {
    Task,
    Service,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeResourceKind {
    Pty,
    StructuredProvider,
    Auxiliary,
}

impl From<Role> for NativeRole {
    fn from(value: Role) -> Self {
        match value {
            Role::Coordinator => Self::Coordinator,
            Role::Worker => Self::Worker,
            Role::Advisor => Self::Advisor,
        }
    }
}
impl From<WorkKind> for NativeWorkKind {
    fn from(value: WorkKind) -> Self {
        match value {
            WorkKind::Task => Self::Task,
            WorkKind::Service => Self::Service,
        }
    }
}
impl From<ResourceKind> for NativeResourceKind {
    fn from(value: ResourceKind) -> Self {
        match value {
            ResourceKind::Pty => Self::Pty,
            ResourceKind::StructuredProvider => Self::StructuredProvider,
            ResourceKind::Auxiliary => Self::Auxiliary,
        }
    }
}

/// An explicit resource driver. A structured provider never becomes a fake PTY.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceDriver {
    Pty {
        rows: u16,
        columns: u16,
        #[serde(rename = "retentionEvents")]
        retention_events: u16,
    },
    Structured {
        #[serde(rename = "driverRef")]
        driver_ref: String,
        #[serde(rename = "protocolRef")]
        protocol_ref: String,
    },
    Auxiliary {
        #[serde(rename = "driverRef")]
        driver_ref: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewedResource {
    pub resource_id: ResourceId,
    pub kind: ResourceKind,
    pub epoch: podbay_core::Epoch,
    pub driver: ResourceDriver,
}

/// Supplied by a trusted profile/workspace/host policy resolver. This wire
/// crate checks shape and binding equality, not provenance or secret safety.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewedNativePolicy {
    pub target_os: TargetOs,
    pub host_id: String,
    pub profile_ref: String,
    pub profile_generation: u64,
    pub model_id: String,
    pub reasoning_effort: String,
    pub executable_generation: String,
    pub effective_spec_digest: String,
    pub workspace_basis_ref: String,
    pub executable: String,
    pub cwd: String,
    pub arguments: Vec<String>,
    pub environment_refs: Vec<String>,
    pub credential_refs: Vec<String>,
    pub wall_seconds: u64,
    pub max_children: u32,
    pub resources: Vec<ReviewedResource>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchDescriptorError {
    BindingMismatch,
    ResourceMismatch,
    InvalidField(&'static str),
    UnsupportedVersion,
    Malformed,
    DigestMismatch,
    NonCanonical,
    TooLarge,
}
impl Display for LaunchDescriptorError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BindingMismatch => f.write_str("launch identities differ from durable binding"),
            Self::ResourceMismatch => f.write_str("launch resource inventory differs from binding"),
            Self::InvalidField(field) => write!(f, "invalid launch descriptor field: {field}"),
            Self::UnsupportedVersion => f.write_str("unsupported launch descriptor schema"),
            Self::Malformed => f.write_str("malformed launch descriptor JSON"),
            Self::DigestMismatch => f.write_str("launch descriptor digest mismatch"),
            Self::NonCanonical => f.write_str("launch descriptor JSON is not canonical"),
            Self::TooLarge => f.write_str("launch descriptor exceeds bounded frame"),
        }
    }
}
impl Error for LaunchDescriptorError {}

/// JSON decimal string, including values above JavaScript's safe integer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Counter(u64);
impl Counter {
    fn get(self) -> u64 {
        self.0
    }
}
impl Serialize for Counter {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}
impl<'de> Deserialize<'de> for Counter {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text != "0"
            && (text.starts_with('0')
                || text.is_empty()
                || !text.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return Err(serde::de::Error::custom("noncanonical decimal counter"));
        }
        text.parse::<u64>()
            .map(Self)
            .map_err(|_| serde::de::Error::custom("counter exceeds u64"))
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
struct DescriptorBody {
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
    resources: Vec<ResourceBody>,
    target_os: TargetOs,
    host_id: String,
    profile_ref: String,
    profile_generation: Counter,
    model_id: String,
    reasoning_effort: String,
    executable_generation: String,
    effective_spec_digest: String,
    workspace_basis_ref: String,
    executable: String,
    cwd: String,
    arguments: Vec<String>,
    environment_refs: Vec<String>,
    credential_refs: Vec<String>,
    wall_seconds: Counter,
    max_children: Counter,
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
pub struct ImmutableLaunchDescriptor {
    body: DescriptorBody,
    digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeResourceView<'a> {
    pub resource_id: &'a str,
    pub kind: NativeResourceKind,
    pub epoch: u64,
    pub driver: &'a ResourceDriver,
}

impl ImmutableLaunchDescriptor {
    pub fn from_binding(
        binding: &LaunchBinding,
        policy: ReviewedNativePolicy,
    ) -> Result<Self, LaunchDescriptorError> {
        if !binding.is_admitted() {
            return Err(LaunchDescriptorError::BindingMismatch);
        }
        Self::from_identity(binding, policy)
    }

    fn from_identity(
        binding: &LaunchBinding,
        policy: ReviewedNativePolicy,
    ) -> Result<Self, LaunchDescriptorError> {
        if binding.resources().len() != policy.resources.len() {
            return Err(LaunchDescriptorError::ResourceMismatch);
        }
        let mut resources = Vec::with_capacity(policy.resources.len());
        for (bound, reviewed) in binding.resources().iter().zip(policy.resources) {
            if bound.id() != &reviewed.resource_id
                || bound.kind() != reviewed.kind
                || bound.epoch() != reviewed.epoch
            {
                return Err(LaunchDescriptorError::ResourceMismatch);
            }
            resources.push(ResourceBody {
                resource_id: reviewed.resource_id.as_str().to_owned(),
                kind: reviewed.kind.into(),
                epoch: Counter(reviewed.epoch.get()),
                driver: reviewed.driver,
            });
        }
        let body = DescriptorBody {
            scope_id: binding.scope_id().as_str().into(),
            actor_id: binding.actor_id().as_str().into(),
            session_id: binding.session_id().as_str().into(),
            run_id: binding.run_id().as_str().into(),
            parent_run_id: binding.parent_run_id().map(|value| value.as_str().into()),
            role: binding.role().into(),
            work_kind: binding.work_kind().into(),
            attempt_id: binding.attempt_id().as_str().into(),
            attempt_ordinal: Counter(binding.attempt_ordinal()),
            attempt_epoch: Counter(binding.attempt_epoch().get()),
            pod_id: binding.pod_id().as_str().into(),
            pod_incarnation: Counter(binding.pod_incarnation().get()),
            resources,
            target_os: policy.target_os,
            host_id: policy.host_id,
            profile_ref: policy.profile_ref,
            profile_generation: Counter(policy.profile_generation),
            model_id: policy.model_id,
            reasoning_effort: policy.reasoning_effort,
            executable_generation: policy.executable_generation,
            effective_spec_digest: policy.effective_spec_digest,
            workspace_basis_ref: policy.workspace_basis_ref,
            executable: policy.executable,
            cwd: policy.cwd,
            arguments: policy.arguments,
            environment_refs: policy.environment_refs,
            credential_refs: policy.credential_refs,
            wall_seconds: Counter(policy.wall_seconds),
            max_children: Counter(u64::from(policy.max_children)),
        };
        validate_body(&body)?;
        let digest = digest_body(&body)?;
        Ok(Self { body, digest })
    }

    /// Structural decode only. Before any OS effect, compare the separately
    /// committed EffectiveLaunchSpec digest and call validate_against_binding.
    pub fn decode_json(bytes: &[u8]) -> Result<Self, LaunchDescriptorError> {
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            return Err(LaunchDescriptorError::TooLarge);
        }
        let envelope: DescriptorEnvelope =
            serde_json::from_slice(bytes).map_err(|_| LaunchDescriptorError::Malformed)?;
        if envelope.protocol != ProtocolVersion::V1 || envelope.schema != LAUNCH_DESCRIPTOR_SCHEMA {
            return Err(LaunchDescriptorError::UnsupportedVersion);
        }
        validate_body(&envelope.descriptor)?;
        let digest = digest_body(&envelope.descriptor)?;
        if envelope.digest != digest {
            return Err(LaunchDescriptorError::DigestMismatch);
        }
        let result = Self {
            body: envelope.descriptor,
            digest,
        };
        if result.encode_json()? != bytes {
            return Err(LaunchDescriptorError::NonCanonical);
        }
        Ok(result)
    }

    /// Decode for a separately loaded durable binding and reviewed effective
    /// spec digest. A valid descriptor hash alone never grants launch authority.
    pub fn decode_for_binding(
        bytes: &[u8],
        binding: &LaunchBinding,
        expected_effective_spec_digest: &str,
    ) -> Result<Self, LaunchDescriptorError> {
        if !lower_digest(expected_effective_spec_digest) {
            return Err(LaunchDescriptorError::InvalidField("effectiveSpecDigest"));
        }
        let result = Self::decode_json(bytes)?;
        if result.body.effective_spec_digest != expected_effective_spec_digest {
            return Err(LaunchDescriptorError::DigestMismatch);
        }
        result.validate_against_binding(binding)?;
        Ok(result)
    }

    /// Recheck a decoded descriptor against the authoritative durable
    /// aggregate snapshot before using any of its native launch fields.
    pub fn validate_against_binding(
        &self,
        binding: &LaunchBinding,
    ) -> Result<(), LaunchDescriptorError> {
        if !binding.is_admitted() {
            return Err(LaunchDescriptorError::BindingMismatch);
        }
        self.validate_against_identity(binding)
    }

    fn validate_against_identity(
        &self,
        binding: &LaunchBinding,
    ) -> Result<(), LaunchDescriptorError> {
        let body = &self.body;
        if body.scope_id != binding.scope_id().as_str()
            || body.actor_id != binding.actor_id().as_str()
            || body.session_id != binding.session_id().as_str()
            || body.run_id != binding.run_id().as_str()
            || body.parent_run_id.as_deref() != binding.parent_run_id().map(|id| id.as_str())
            || body.role != NativeRole::from(binding.role())
            || body.work_kind != NativeWorkKind::from(binding.work_kind())
            || body.attempt_id != binding.attempt_id().as_str()
            || body.attempt_ordinal.get() != binding.attempt_ordinal()
            || body.attempt_epoch.get() != binding.attempt_epoch().get()
            || body.pod_id != binding.pod_id().as_str()
            || body.pod_incarnation.get() != binding.pod_incarnation().get()
        {
            return Err(LaunchDescriptorError::BindingMismatch);
        }
        if body.resources.len() != binding.resources().len() {
            return Err(LaunchDescriptorError::ResourceMismatch);
        }
        for (encoded, bound) in body.resources.iter().zip(binding.resources()) {
            if encoded.resource_id != bound.id().as_str()
                || encoded.kind != NativeResourceKind::from(bound.kind())
                || encoded.epoch.get() != bound.epoch().get()
            {
                return Err(LaunchDescriptorError::ResourceMismatch);
            }
        }
        Ok(())
    }

    /// Canonical descriptor body bytes, excluding its digest envelope.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LaunchDescriptorError> {
        serde_json::to_vec(&self.body).map_err(|_| LaunchDescriptorError::Malformed)
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn encode_json(&self) -> Result<Vec<u8>, LaunchDescriptorError> {
        let bytes = serde_json::to_vec(&DescriptorEnvelope {
            protocol: ProtocolVersion::V1,
            schema: LAUNCH_DESCRIPTOR_SCHEMA.into(),
            digest: self.digest.clone(),
            descriptor: self.body.clone(),
        })
        .map_err(|_| LaunchDescriptorError::Malformed)?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(LaunchDescriptorError::TooLarge);
        }
        Ok(bytes)
    }
    pub fn pod_id(&self) -> &str {
        &self.body.pod_id
    }
    pub fn scope_id(&self) -> &str {
        &self.body.scope_id
    }
    pub fn actor_id(&self) -> &str {
        &self.body.actor_id
    }
    pub fn session_id(&self) -> &str {
        &self.body.session_id
    }
    pub fn run_id(&self) -> &str {
        &self.body.run_id
    }
    pub fn parent_run_id(&self) -> Option<&str> {
        self.body.parent_run_id.as_deref()
    }
    pub fn role(&self) -> NativeRole {
        self.body.role
    }
    pub fn work_kind(&self) -> NativeWorkKind {
        self.body.work_kind
    }
    pub fn attempt_id(&self) -> &str {
        &self.body.attempt_id
    }
    pub fn attempt_ordinal(&self) -> u64 {
        self.body.attempt_ordinal.get()
    }
    pub fn attempt_epoch(&self) -> u64 {
        self.body.attempt_epoch.get()
    }
    pub fn pod_incarnation(&self) -> u64 {
        self.body.pod_incarnation.get()
    }
    pub fn target_os(&self) -> TargetOs {
        self.body.target_os
    }
    pub fn host_id(&self) -> &str {
        &self.body.host_id
    }
    pub fn profile_ref(&self) -> &str {
        &self.body.profile_ref
    }
    pub fn profile_generation(&self) -> u64 {
        self.body.profile_generation.get()
    }
    pub fn model_id(&self) -> &str {
        &self.body.model_id
    }
    pub fn reasoning_effort(&self) -> &str {
        &self.body.reasoning_effort
    }
    pub fn executable_generation(&self) -> &str {
        &self.body.executable_generation
    }
    pub fn effective_spec_digest(&self) -> &str {
        &self.body.effective_spec_digest
    }
    pub fn workspace_basis_ref(&self) -> &str {
        &self.body.workspace_basis_ref
    }
    pub fn executable(&self) -> &str {
        &self.body.executable
    }
    pub fn cwd(&self) -> &str {
        &self.body.cwd
    }
    pub fn arguments(&self) -> &[String] {
        &self.body.arguments
    }
    pub fn environment_refs(&self) -> &[String] {
        &self.body.environment_refs
    }
    pub fn credential_refs(&self) -> &[String] {
        &self.body.credential_refs
    }
    pub fn wall_seconds(&self) -> u64 {
        self.body.wall_seconds.get()
    }
    pub fn max_children(&self) -> u64 {
        self.body.max_children.get()
    }
    pub fn resources_len(&self) -> usize {
        self.body.resources.len()
    }
    pub fn resource(&self, index: usize) -> Option<NativeResourceView<'_>> {
        self.body
            .resources
            .get(index)
            .map(|value| NativeResourceView {
                resource_id: &value.resource_id,
                kind: value.kind,
                epoch: value.epoch.get(),
                driver: &value.driver,
            })
    }
    pub fn resource_id(&self, index: usize) -> Option<&str> {
        self.resource(index).map(|resource| resource.resource_id)
    }
}

fn digest_body(body: &DescriptorBody) -> Result<String, LaunchDescriptorError> {
    let bytes = serde_json::to_vec(body).map_err(|_| LaunchDescriptorError::Malformed)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(LaunchDescriptorError::TooLarge);
    }
    let mut hash = Sha256::new();
    hash.update(DIGEST_DOMAIN);
    hash.update(&bytes);
    Ok(hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
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
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
}
fn lower_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_native_path(os: TargetOs, value: &str, executable: bool) -> bool {
    if value.is_empty() || value.len() > 32_000 || value.chars().any(char::is_control) {
        return false;
    }
    match os {
        TargetOs::Linux | TargetOs::Macos => {
            if !value.starts_with('/') || value.contains('\\') || (executable && value == "/") {
                return false;
            }
            value == "/"
                || value[1..]
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != "..")
        }
        TargetOs::Windows => {
            let bytes = value.as_bytes();
            if value.contains('/') {
                return false;
            }
            if value.starts_with("\\\\") {
                let mut pieces = value[2..].split('\\');
                let Some(server) = pieces.next() else {
                    return false;
                };
                let Some(share) = pieces.next() else {
                    return false;
                };
                if !valid_windows_part(server) || !valid_windows_part(share) {
                    return false;
                }
                let remainder = pieces.collect::<Vec<_>>();
                return (!executable || !remainder.is_empty())
                    && remainder.into_iter().all(valid_windows_part);
            }
            // Require uppercase drive letters as the canonical spelling;
            // lowercase drive aliases must be normalised by trusted policy.
            if bytes.len() < 3
                || !bytes[0].is_ascii_uppercase()
                || bytes[1] != b':'
                || bytes[2] != b'\\'
                || (executable && bytes.len() == 3)
            {
                return false;
            }
            value[3..].is_empty() || value[3..].split('\\').all(valid_windows_part)
        }
    }
}

fn valid_windows_part(part: &str) -> bool {
    !part.is_empty()
        && part != "."
        && part != ".."
        && !part.ends_with([' ', '.'])
        && !part.bytes().any(|byte| b":*?<>|\"".contains(&byte))
}

fn validate_body(body: &DescriptorBody) -> Result<(), LaunchDescriptorError> {
    for value in [
        &body.scope_id,
        &body.actor_id,
        &body.session_id,
        &body.run_id,
        &body.attempt_id,
        &body.pod_id,
    ] {
        if !valid_id(value) {
            return Err(LaunchDescriptorError::InvalidField("identity"));
        }
    }
    if body
        .parent_run_id
        .as_ref()
        .is_some_and(|value| !valid_id(value))
    {
        return Err(LaunchDescriptorError::InvalidField("parentRunId"));
    }
    if body.attempt_ordinal.get() == 0
        || body.attempt_epoch.get() == 0
        || body.pod_incarnation.get() == 0
        || body.profile_generation.get() == 0
    {
        return Err(LaunchDescriptorError::InvalidField("epoch/ordinal"));
    }
    if body.resources.is_empty() || body.resources.len() > 32 {
        return Err(LaunchDescriptorError::InvalidField("resources"));
    }
    let mut seen = BTreeSet::new();
    for resource in &body.resources {
        if !valid_id(&resource.resource_id) || resource.epoch.get() == 0 {
            return Err(LaunchDescriptorError::InvalidField(
                "resource identity/epoch",
            ));
        }
        if !seen.insert(&resource.resource_id) {
            return Err(LaunchDescriptorError::InvalidField("duplicate resourceId"));
        }
        match (&resource.kind, &resource.driver) {
            (
                NativeResourceKind::Pty,
                ResourceDriver::Pty {
                    rows,
                    columns,
                    retention_events,
                },
            ) if (1..=200).contains(rows)
                && (1..=400).contains(columns)
                && (1..=4096).contains(retention_events) => {}
            (
                NativeResourceKind::StructuredProvider,
                ResourceDriver::Structured {
                    driver_ref,
                    protocol_ref,
                },
            ) if valid_ref(driver_ref) && valid_ref(protocol_ref) => {}
            (NativeResourceKind::Auxiliary, ResourceDriver::Auxiliary { driver_ref })
                if valid_ref(driver_ref) => {}
            _ => return Err(LaunchDescriptorError::InvalidField("resource driver")),
        }
    }
    if !valid_ref(&body.host_id)
        || !valid_ref(&body.profile_ref)
        || !valid_ref(&body.model_id)
        || !valid_ref(&body.reasoning_effort)
        || !valid_ref(&body.executable_generation)
        || !valid_ref(&body.workspace_basis_ref)
        || !lower_digest(&body.effective_spec_digest)
    {
        return Err(LaunchDescriptorError::InvalidField("profile/host pin"));
    }
    if !valid_native_path(body.target_os, &body.executable, true)
        || body.executable.len() > 4096
        || !valid_native_path(body.target_os, &body.cwd, false)
    {
        return Err(LaunchDescriptorError::InvalidField("native path"));
    }
    if body.arguments.len() > 256
        || body.arguments.iter().any(|value| {
            value.is_empty()
                || value.len() > 16_384
                || value.contains('\0')
                || value.chars().any(char::is_control)
        })
    {
        return Err(LaunchDescriptorError::InvalidField("arguments"));
    }
    if body.environment_refs.len() > 64
        || body.credential_refs.len() > 32
        || !sorted_unique(&body.environment_refs)
        || !sorted_unique(&body.credential_refs)
        || body
            .environment_refs
            .iter()
            .chain(&body.credential_refs)
            .any(|value| !valid_ref(value))
    {
        return Err(LaunchDescriptorError::InvalidField(
            "environment/credential refs",
        ));
    }
    if body.wall_seconds.get() == 0
        || body.wall_seconds.get() > 604_800
        || body.max_children.get() > 4096
    {
        return Err(LaunchDescriptorError::InvalidField("budget"));
    }
    Ok(())
}

/// V2 retains the complete strictly decoded V1-shaped identity and native
/// fields under `base`, but requires a separately typed Codex policy. The
/// outer schema and digest domain are distinct; a V1 descriptor never gains
/// this policy by decoding through V2.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DescriptorBodyV2 {
    base: DescriptorBody,
    codex_policy: CodexAppServerPolicyV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DescriptorEnvelopeV2 {
    protocol: ProtocolVersion,
    schema: String,
    digest: String,
    descriptor: DescriptorBodyV2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImmutableLaunchDescriptorV2 {
    body: DescriptorBodyV2,
    digest: String,
}

impl ImmutableLaunchDescriptorV2 {
    /// Review a first-root identity before its Run is admitted. This produces
    /// the exact V2 descriptor bytes; it does not itself admit a command.
    pub fn from_planned_root(
        planned: &PlannedRootBinding,
        policy: ReviewedNativePolicy,
        codex_policy: CodexAppServerPolicyV2,
    ) -> Result<Self, LaunchDescriptorError> {
        let base = ImmutableLaunchDescriptor::from_identity(planned.identity(), policy)?;
        Self::from_base(base, codex_policy)
    }

    pub fn from_binding(
        binding: &LaunchBinding,
        policy: ReviewedNativePolicy,
        codex_policy: CodexAppServerPolicyV2,
    ) -> Result<Self, LaunchDescriptorError> {
        let base = ImmutableLaunchDescriptor::from_binding(binding, policy)?;
        Self::from_base(base, codex_policy)
    }

    fn from_base(
        base: ImmutableLaunchDescriptor,
        codex_policy: CodexAppServerPolicyV2,
    ) -> Result<Self, LaunchDescriptorError> {
        let body = DescriptorBodyV2 {
            base: base.body,
            codex_policy,
        };
        validate_body_v2(&body)?;
        let digest = digest_body_v2(&body)?;
        Ok(Self { body, digest })
    }

    pub fn decode_json(bytes: &[u8]) -> Result<Self, LaunchDescriptorError> {
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            return Err(LaunchDescriptorError::TooLarge);
        }
        let envelope: DescriptorEnvelopeV2 =
            serde_json::from_slice(bytes).map_err(|_| LaunchDescriptorError::Malformed)?;
        if envelope.protocol != ProtocolVersion::V1
            || envelope.schema != LAUNCH_DESCRIPTOR_V2_SCHEMA
        {
            return Err(LaunchDescriptorError::UnsupportedVersion);
        }
        validate_body_v2(&envelope.descriptor)?;
        let digest = digest_body_v2(&envelope.descriptor)?;
        if digest != envelope.digest {
            return Err(LaunchDescriptorError::DigestMismatch);
        }
        let result = Self {
            body: envelope.descriptor,
            digest,
        };
        if result.encode_json()? != bytes {
            return Err(LaunchDescriptorError::NonCanonical);
        }
        Ok(result)
    }

    pub fn decode_for_binding(
        bytes: &[u8],
        binding: &LaunchBinding,
        expected_effective_spec_digest: &str,
    ) -> Result<Self, LaunchDescriptorError> {
        if !lower_digest(expected_effective_spec_digest) {
            return Err(LaunchDescriptorError::InvalidField("effectiveSpecDigest"));
        }
        let result = Self::decode_json(bytes)?;
        if result.effective_spec_digest() != expected_effective_spec_digest {
            return Err(LaunchDescriptorError::DigestMismatch);
        }
        result.validate_against_binding(binding)?;
        Ok(result)
    }

    pub fn validate_against_binding(
        &self,
        binding: &LaunchBinding,
    ) -> Result<(), LaunchDescriptorError> {
        let base = ImmutableLaunchDescriptor {
            digest: digest_body(&self.body.base)?,
            body: self.body.base.clone(),
        };
        base.validate_against_binding(binding)
    }

    pub fn validate_against_planned_root(
        &self,
        planned: &PlannedRootBinding,
    ) -> Result<(), LaunchDescriptorError> {
        let base = ImmutableLaunchDescriptor {
            digest: digest_body(&self.body.base)?,
            body: self.body.base.clone(),
        };
        base.validate_against_identity(planned.identity())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LaunchDescriptorError> {
        serde_json::to_vec(&self.body).map_err(|_| LaunchDescriptorError::Malformed)
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn encode_json(&self) -> Result<Vec<u8>, LaunchDescriptorError> {
        let bytes = serde_json::to_vec(&DescriptorEnvelopeV2 {
            protocol: ProtocolVersion::V1,
            schema: LAUNCH_DESCRIPTOR_V2_SCHEMA.into(),
            digest: self.digest.clone(),
            descriptor: self.body.clone(),
        })
        .map_err(|_| LaunchDescriptorError::Malformed)?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(LaunchDescriptorError::TooLarge);
        }
        Ok(bytes)
    }

    pub fn codex_policy(&self) -> &CodexAppServerPolicyV2 {
        &self.body.codex_policy
    }
    pub fn pod_id(&self) -> &str {
        &self.body.base.pod_id
    }
    pub fn scope_id(&self) -> &str {
        &self.body.base.scope_id
    }
    pub fn actor_id(&self) -> &str {
        &self.body.base.actor_id
    }
    pub fn session_id(&self) -> &str {
        &self.body.base.session_id
    }
    pub fn run_id(&self) -> &str {
        &self.body.base.run_id
    }
    pub fn parent_run_id(&self) -> Option<&str> {
        self.body.base.parent_run_id.as_deref()
    }
    pub fn role(&self) -> NativeRole {
        self.body.base.role
    }
    pub fn work_kind(&self) -> NativeWorkKind {
        self.body.base.work_kind
    }
    pub fn attempt_id(&self) -> &str {
        &self.body.base.attempt_id
    }
    pub fn attempt_ordinal(&self) -> u64 {
        self.body.base.attempt_ordinal.get()
    }
    pub fn attempt_epoch(&self) -> u64 {
        self.body.base.attempt_epoch.get()
    }
    pub fn pod_incarnation(&self) -> u64 {
        self.body.base.pod_incarnation.get()
    }
    pub fn target_os(&self) -> TargetOs {
        self.body.base.target_os
    }
    pub fn host_id(&self) -> &str {
        &self.body.base.host_id
    }
    pub fn profile_ref(&self) -> &str {
        &self.body.base.profile_ref
    }
    pub fn profile_generation(&self) -> u64 {
        self.body.base.profile_generation.get()
    }
    pub fn model_id(&self) -> &str {
        &self.body.base.model_id
    }
    pub fn reasoning_effort(&self) -> &str {
        &self.body.base.reasoning_effort
    }
    pub fn executable(&self) -> &str {
        &self.body.base.executable
    }
    pub fn executable_generation(&self) -> &str {
        &self.body.base.executable_generation
    }
    pub fn cwd(&self) -> &str {
        &self.body.base.cwd
    }
    pub fn arguments(&self) -> &[String] {
        &self.body.base.arguments
    }
    pub fn workspace_basis_ref(&self) -> &str {
        &self.body.base.workspace_basis_ref
    }
    pub fn wall_seconds(&self) -> u64 {
        self.body.base.wall_seconds.get()
    }
    pub fn max_children(&self) -> u64 {
        self.body.base.max_children.get()
    }
    pub fn environment_refs(&self) -> &[String] {
        &self.body.base.environment_refs
    }
    pub fn credential_refs(&self) -> &[String] {
        &self.body.base.credential_refs
    }
    pub fn effective_spec_digest(&self) -> &str {
        &self.body.base.effective_spec_digest
    }
    pub fn resources_len(&self) -> usize {
        self.body.base.resources.len()
    }
    pub fn resource(&self, index: usize) -> Option<NativeResourceView<'_>> {
        self.body
            .base
            .resources
            .get(index)
            .map(|value| NativeResourceView {
                resource_id: &value.resource_id,
                kind: value.kind,
                epoch: value.epoch.get(),
                driver: &value.driver,
            })
    }
}

fn validate_body_v2(body: &DescriptorBodyV2) -> Result<(), LaunchDescriptorError> {
    validate_body(&body.base)?;
    body.codex_policy
        .validate()
        .map_err(|_| LaunchDescriptorError::InvalidField("codexPolicy"))?;
    if !matches!(
        (body.base.role, body.base.work_kind),
        (NativeRole::Coordinator, NativeWorkKind::Service)
            | (NativeRole::Worker, NativeWorkKind::Task)
    ) || body.base.resources.len() != 1
        || body.base.scope_id != body.codex_policy.credential_scope()
        || body.base.credential_refs.as_slice() != [body.codex_policy.credential_ref()]
    {
        return Err(LaunchDescriptorError::InvalidField("codexPolicy binding"));
    }
    let resource = &body.base.resources[0];
    if resource.kind != NativeResourceKind::StructuredProvider {
        return Err(LaunchDescriptorError::InvalidField("codex resource kind"));
    }
    match &resource.driver {
        ResourceDriver::Structured {
            driver_ref,
            protocol_ref,
        } if driver_ref == body.codex_policy.driver_ref()
            && protocol_ref == body.codex_policy.protocol_ref() =>
        {
            Ok(())
        }
        _ => Err(LaunchDescriptorError::InvalidField("codex resource driver")),
    }
}

fn digest_body_v2(body: &DescriptorBodyV2) -> Result<String, LaunchDescriptorError> {
    let bytes = serde_json::to_vec(body).map_err(|_| LaunchDescriptorError::Malformed)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(LaunchDescriptorError::TooLarge);
    }
    let mut hash = Sha256::new();
    hash.update(DIGEST_DOMAIN_V2);
    hash.update(&bytes);
    Ok(hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
