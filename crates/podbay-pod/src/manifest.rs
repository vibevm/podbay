#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
use std::fmt;
#[cfg(target_os = "linux")]
use std::fs::{self, File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use podbay_core::AttestedPeer;
use podbay_core::{AttemptId, Epoch, PodId, ResourceId, RunId, ScopeId, SessionId};
#[cfg(target_os = "linux")]
use podbay_store::{BoundLaunchFormat, PodBayStore};
#[cfg(target_os = "linux")]
use podbay_wire::{
    EffectiveLaunchContract, EffectiveLaunchContractV2, ImmutableLaunchDescriptor,
    ImmutableLaunchDescriptorV2, NativeResourceKind, NativeRole, NativeWorkKind, ResourceDriver,
    TargetOs,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROTOCOL: &str = "podbay-pod/1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PodRole {
    Coordinator,
    Worker,
    Advisor,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchDescriptor {
    pub protocol: String,
    pub pod_id: String,
    pub attempt_id: String,
    pub session_id: String,
    pub run_id: String,
    pub scope_id: String,
    pub role: PodRole,
    pub incarnation: u64,
    pub resource_id: String,
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pty: Option<PtySpec>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PtySpec {
    pub rows: u16,
    pub cols: u16,
    pub retention_events: usize,
}

impl LaunchDescriptor {
    pub fn validate(&self) -> Result<(), PodError> {
        if self.protocol != PROTOCOL {
            return Err(PodError::Invalid("incompatible pod protocol"));
        }
        if self.role == PodRole::Advisor {
            return Err(PodError::Invalid(
                "advisor pod role is not supported by PB05",
            ));
        }
        PodId::try_from(self.pod_id.as_str()).map_err(|_| PodError::Invalid("pod ID"))?;
        AttemptId::try_from(self.attempt_id.as_str())
            .map_err(|_| PodError::Invalid("attempt ID"))?;
        SessionId::try_from(self.session_id.as_str())
            .map_err(|_| PodError::Invalid("session ID"))?;
        RunId::try_from(self.run_id.as_str()).map_err(|_| PodError::Invalid("run ID"))?;
        ScopeId::try_from(self.scope_id.as_str()).map_err(|_| PodError::Invalid("scope ID"))?;
        ResourceId::try_from(self.resource_id.as_str())
            .map_err(|_| PodError::Invalid("resource ID"))?;
        Epoch::new(self.incarnation).map_err(|_| PodError::Invalid("pod incarnation"))?;
        if !self.executable.is_absolute()
            || !self.cwd.is_absolute()
            || self.args.len() > 256
            || self.args.iter().any(|arg| arg.len() > 16_384)
        {
            return Err(PodError::Invalid("resource launch bounds"));
        }
        if let Some(pty) = self.pty
            && (pty.rows == 0
                || pty.rows > 200
                || pty.cols == 0
                || pty.cols > 400
                || !(1..=4096).contains(&pty.retention_events))
        {
            return Err(PodError::Invalid("PTY geometry or retention bounds"));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, PodError> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"podbay-pb05-launch/1\0");
        hash.update(serde_json::to_vec(self)?);
        Ok(hex(&hash.finalize()))
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PodManifest {
    pub descriptor: LaunchDescriptor,
    pub digest: String,
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub viewer_token: Option<String>,
    pub socket_path: PathBuf,
    pub unit_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_binding: Option<BoundPeerManifest>,
}

#[cfg(target_os = "linux")]
pub const PEER_BINDING_PROTOCOL: &str = "podbay.peer-binding/1";
#[cfg(target_os = "linux")]
pub const PEER_BINDING_V2_PROTOCOL: &str = "podbay.peer-binding/2";
#[cfg(target_os = "linux")]
pub const PEER_BINDING_V3_PROTOCOL: &str = "podbay.peer-binding/3";
#[cfg(target_os = "linux")]
pub const SYNTHETIC_CAPABILITY: &str = "synthetic_fixture_only";
#[cfg(target_os = "linux")]
pub const CODEX_V2_CAPABILITY: &str = "codex_app_server_v2";
#[cfg(target_os = "linux")]
pub const CODEX_V3_CAPABILITY: &str = "codex_app_server_v3";

/// Historical admission revision and independently current policy fence.
/// The global revision is never interpreted as a pod-lifetime policy epoch.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundPolicyFenceV3 {
    pub policy_fence_epoch: u64,
    pub admission_authority_revision: u64,
}

/// Host-reviewed inputs that cannot be inferred from a PB05 descriptor.
/// The manager peer itself is observed from the launcher process, never passed
/// through this structure by a request body.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
pub struct PodPeerBootstrap {
    pub store_path: PathBuf,
    pub store_lineage: String,
    pub owner_epoch: u64,
    pub credential_epoch: u64,
    pub resource_input_epochs: BTreeMap<String, u64>,
    pub canonical_executable: PathBuf,
    pub executable_sha256: String,
    pub expected_manager_peer: AttestedPeer,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundPeerManifest {
    pub protocol: String,
    pub capability: String,
    pub wire_descriptor: Vec<u8>,
    pub effective_spec: Vec<u8>,
    pub descriptor_digest: String,
    pub effective_digest: String,
    pub resource_epoch: u64,
    pub store_path: PathBuf,
    pub store_lineage: String,
    pub owner_epoch: u64,
    pub credential_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_fence: Option<BoundPolicyFenceV3>,
    pub resource_input_epochs: BTreeMap<String, u64>,
    pub manager_os_identity: String,
    pub manager_process_id: String,
    pub manager_boot_identity: String,
    pub manager_birth_identity: String,
    pub manager_containment: String,
    pub canonical_executable: PathBuf,
    pub executable_sha256: String,
    pub binding_digest: String,
}

#[cfg(target_os = "linux")]
impl BoundPeerManifest {
    pub fn manager_peer(&self) -> Result<AttestedPeer, PodError> {
        AttestedPeer::from_port(
            &self.manager_os_identity,
            &self.manager_process_id,
            &self.manager_boot_identity,
            &self.manager_birth_identity,
            &self.manager_containment,
        )
        .map_err(|_| PodError::Invalid("manager peer binding is malformed"))
    }

    pub fn digest(&self) -> Result<String, PodError> {
        let mut copy = self.clone();
        copy.binding_digest.clear();
        let mut hash = Sha256::new();
        match self.protocol.as_str() {
            PEER_BINDING_PROTOCOL => hash.update(b"podbay.peer-binding/1\0"),
            PEER_BINDING_V2_PROTOCOL => hash.update(b"podbay.peer-binding/2\0"),
            PEER_BINDING_V3_PROTOCOL => hash.update(b"podbay.peer-binding/3\0"),
            _ => return Err(PodError::Invalid("unknown peer binding version")),
        }
        hash.update(serde_json::to_vec(&copy)?);
        Ok(hex(&hash.finalize()))
    }

    pub fn validate(&self, legacy: &LaunchDescriptor, directory: &Path) -> Result<(), PodError> {
        if self.protocol == PEER_BINDING_V3_PROTOCOL || self.capability == CODEX_V3_CAPABILITY {
            return self.validate_codex_v3(legacy, directory);
        }
        if self.protocol == PEER_BINDING_V2_PROTOCOL || self.capability == CODEX_V2_CAPABILITY {
            return self.validate_codex_v2(legacy, directory);
        }
        if self.protocol != PEER_BINDING_PROTOCOL
            || self.capability != SYNTHETIC_CAPABILITY
            || self.binding_digest != self.digest()?
            || !self.store_path.is_absolute()
            || self.owner_epoch == 0
            || self.credential_epoch == 0
            || self.authority_revision.is_some()
            || self.policy_fence.is_some()
            || self.resource_input_epochs.len() != 1
        {
            return Err(PodError::Invalid(
                "peer binding version or identity changed",
            ));
        }
        self.manager_peer()?;
        let wire = ImmutableLaunchDescriptor::decode_json(&self.wire_descriptor)
            .map_err(|_| PodError::Invalid("committed launch descriptor is malformed"))?;
        let effective = EffectiveLaunchContract::decode(&self.effective_spec)
            .map_err(|_| PodError::Invalid("committed effective launch is malformed"))?;
        effective
            .compare_with_descriptor(&wire)
            .map_err(|_| PodError::Invalid("effective launch differs from descriptor"))?;
        let resource = wire
            .resource(0)
            .ok_or(PodError::Unsupported("single Auxiliary resource required"))?;
        if wire.resources_len() != 1
            || resource.kind != NativeResourceKind::Auxiliary
            || !matches!(resource.driver,ResourceDriver::Auxiliary{driver_ref}
                if driver_ref=="process.exec")
            || wire.target_os() != TargetOs::Linux
            || wire.role() != NativeRole::Worker
            || wire.work_kind() != NativeWorkKind::Task
            || wire.model_id() != "none"
            || wire.reasoning_effort() != "none"
            || wire.profile_ref() != "podbay.fixture.process.exec"
            || !wire.environment_refs().is_empty()
            || !wire.credential_refs().is_empty()
            || !effective.tool_bundle_refs().is_empty()
            || wire.max_children() != 0
            || wire.wall_seconds() != 60
            || wire.arguments() != ["60"]
            || self
                .resource_input_epochs
                .get(resource.resource_id)
                .copied()
                != Some(1)
            || resource.epoch != self.resource_epoch
            || resource.epoch != 1
            || self.descriptor_digest != wire.digest()
            || self.effective_digest != effective.digest()
            || wire.scope_id() != legacy.scope_id
            || wire.pod_id() != legacy.pod_id
            || wire.attempt_id() != legacy.attempt_id
            || wire.pod_incarnation() != legacy.incarnation
            || wire.session_id() != legacy.session_id
            || wire.run_id() != legacy.run_id
            || wire.resource_id(0) != Some(legacy.resource_id.as_str())
            || wire.executable() != legacy.executable.to_string_lossy()
            || wire.cwd() != legacy.cwd.to_string_lossy()
            || wire.arguments() != legacy.args
            || legacy.pty.is_some()
            || legacy.role != PodRole::Worker
            || legacy.cwd != directory
            || !directory.is_absolute()
        {
            return Err(PodError::Unsupported(
                "descriptor is outside synthetic process.exec subset",
            ));
        }
        let resolved = fs::canonicalize(&legacy.executable)?;
        if resolved != legacy.executable
            || resolved != self.canonical_executable
            || self.executable_sha256.len() != 64
            || !self
                .executable_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || wire.executable_generation() != format!("sha256:{}", self.executable_sha256)
        {
            return Err(PodError::Unsupported("sleep executable generation differs"));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&resolved)?;
        let mut hash = Sha256::new();
        let mut bytes = [0u8; 8192];
        loop {
            let count = file.read(&mut bytes)?;
            if count == 0 {
                break;
            }
            hash.update(&bytes[..count]);
        }
        if hex(&hash.finalize()) != self.executable_sha256 {
            return Err(PodError::Unsupported("sleep executable SHA differs"));
        }
        Ok(())
    }

    fn validate_codex_v2(
        &self,
        launch: &LaunchDescriptor,
        directory: &Path,
    ) -> Result<(), PodError> {
        if self.protocol != PEER_BINDING_V2_PROTOCOL
            || self.capability != CODEX_V2_CAPABILITY
            || self.binding_digest != self.digest()?
            || !self.store_path.is_absolute()
            || self.owner_epoch == 0
            || self.credential_epoch == 0
            || self.authority_revision.is_none_or(|revision| revision == 0)
            || self.policy_fence.is_some()
            || self.resource_input_epochs.len() != 1
            || !directory.is_absolute()
        {
            return Err(PodError::Invalid("Codex V2 peer binding changed"));
        }
        self.validate_codex_common(launch)
    }

    fn validate_codex_v3(
        &self,
        launch: &LaunchDescriptor,
        directory: &Path,
    ) -> Result<(), PodError> {
        if self.protocol != PEER_BINDING_V3_PROTOCOL
            || self.capability != CODEX_V3_CAPABILITY
            || self.binding_digest != self.digest()?
            || !self.store_path.is_absolute()
            || self.owner_epoch == 0
            || self.credential_epoch == 0
            || self.authority_revision.is_some()
            || self.policy_fence.as_ref().is_none_or(|fence| {
                fence.policy_fence_epoch == 0 || fence.admission_authority_revision == 0
            })
            || self.resource_input_epochs.len() != 1
            || !directory.is_absolute()
        {
            return Err(PodError::Invalid("Codex V3 peer binding changed"));
        }
        self.validate_codex_common(launch)
    }

    fn validate_codex_common(&self, launch: &LaunchDescriptor) -> Result<(), PodError> {
        self.manager_peer()?;
        let wire = ImmutableLaunchDescriptorV2::decode_json(&self.wire_descriptor)
            .map_err(|_| PodError::Invalid("Codex V2 descriptor is malformed"))?;
        let effective = EffectiveLaunchContractV2::decode(&self.effective_spec)
            .map_err(|_| PodError::Invalid("Codex V2 effective launch is malformed"))?;
        effective
            .compare_with_descriptor(&wire)
            .map_err(|_| PodError::Invalid("Codex V2 effective launch differs"))?;
        let role = match (wire.role(), wire.work_kind()) {
            (NativeRole::Coordinator, NativeWorkKind::Service) => PodRole::Coordinator,
            (NativeRole::Worker, NativeWorkKind::Task) => PodRole::Worker,
            _ => return Err(PodError::Unsupported("Codex V2 pod role is unavailable")),
        };
        let resource = wire
            .resource(0)
            .ok_or(PodError::Invalid("Codex V2 resource is missing"))?;
        if wire.resources_len() != 1
            || resource.kind != NativeResourceKind::StructuredProvider
            || wire.target_os() != TargetOs::Linux
            || wire.arguments() != ["app-server", "--listen", "stdio://"]
            || wire.scope_id() != launch.scope_id
            || wire.pod_id() != launch.pod_id
            || wire.attempt_id() != launch.attempt_id
            || wire.pod_incarnation() != launch.incarnation
            || wire.session_id() != launch.session_id
            || wire.run_id() != launch.run_id
            || resource.resource_id != launch.resource_id
            || resource.epoch != self.resource_epoch
            || resource.epoch != 1
            || self
                .resource_input_epochs
                .get(resource.resource_id)
                .copied()
                != Some(1)
            || wire.executable() != launch.executable.to_string_lossy()
            || wire.cwd() != launch.cwd.to_string_lossy()
            || wire.arguments() != launch.args
            || launch.pty.is_some()
            || launch.role != role
            || self.descriptor_digest != wire.digest()
            || self.effective_digest != effective.digest()
        {
            return Err(PodError::Unsupported("Codex V2 pod launch binding differs"));
        }
        if fs::canonicalize(&launch.cwd)? != launch.cwd {
            return Err(PodError::Refused("Codex workspace path changed"));
        }
        let executable = fs::canonicalize(&launch.executable)?;
        if executable != launch.executable
            || executable != self.canonical_executable
            || self.executable_sha256.len() != 64
            || !self
                .executable_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || wire.executable_generation() != format!("sha256:{}", self.executable_sha256)
        {
            return Err(PodError::Refused("Codex executable generation differs"));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&executable)?;
        let mut hash = Sha256::new();
        let mut bytes = [0u8; 8192];
        loop {
            let count = file.read(&mut bytes)?;
            if count == 0 {
                break;
            }
            hash.update(&bytes[..count]);
        }
        if hex(&hash.finalize()) != self.executable_sha256 {
            return Err(PodError::Refused("Codex executable SHA differs"));
        }
        Ok(())
    }

    /// Read-only V3 policy and topology check for an already validated bound
    /// manifest. The policy row and current Pod/Resource links are read in one
    /// SQLite snapshot. The caller must separately attest the manager peer,
    /// pod process and any effect-specific grant immediately before effect.
    /// This helper does not enable a V3 launch or control route by itself.
    pub fn check_current_codex_v3_policy(
        &self,
        launch: &LaunchDescriptor,
    ) -> Result<(), PodError> {
        if self.protocol != PEER_BINDING_V3_PROTOCOL || self.capability != CODEX_V3_CAPABILITY {
            return Err(PodError::Unsupported("current Codex V3 policy unavailable"));
        }
        let expected = self
            .policy_fence
            .as_ref()
            .ok_or(PodError::Refused("Codex V3 policy fence missing"))?;
        let mut store = PodBayStore::open_existing_read_only(&self.store_path)
            .map_err(|_| PodError::Refused("Codex V3 store witness unavailable"))?;
        let current = store
            .current_bound_pod_snapshot(&launch.scope_id, &launch.pod_id)
            .map_err(|_| PodError::Refused("Codex V3 current Pod binding unavailable"))?;
        let fence = current.current_policy_fence().ok_or(PodError::Refused(
            "Codex V3 committed policy binding unavailable",
        ))?;
        let inputs = current
            .resources()
            .iter()
            .map(|resource| {
                (
                    resource.id().as_str().to_owned(),
                    resource.input_epoch().get(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        if current.store_lineage().as_str() != self.store_lineage
            || current.owner_epoch().get() != self.owner_epoch
            || current.pod_incarnation().get() != launch.incarnation
            || current.attempt_id().as_str() != launch.attempt_id
            || current.launch().format != BoundLaunchFormat::CodexV3
            || current.launch().descriptor != self.wire_descriptor
            || current.launch().effective_spec != self.effective_spec
            || current.launch().resources.len() != 1
            || current.launch().resources[0].id != launch.resource_id
            || current.launch().resources[0].epoch != self.resource_epoch
            || current.resources().len() != 1
            || inputs != self.resource_input_epochs
            || fence.store_lineage != self.store_lineage
            || fence.policy_fence_epoch != expected.policy_fence_epoch
            || fence.admission_authority_revision != expected.admission_authority_revision
        {
            return Err(PodError::Refused(
                "Codex V3 current policy or topology changed",
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PodStatus {
    pub protocol: String,
    pub pod_id: String,
    pub attempt_id: String,
    pub incarnation: u64,
    pub manifest_digest: String,
    pub supervisor_pid: u32,
    #[serde(default)]
    pub supervisor_start_ticks: u64,
    pub child_pid: u32,
    pub child_start_ticks: u64,
    pub boot_id: String,
    pub unit_name: String,
    pub cgroup_path: String,
    pub child_running: bool,
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound: Option<BoundPodStatus>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundPodStatus {
    pub capability: String,
    pub descriptor_digest: String,
    pub effective_digest: String,
    pub resource_id: String,
    pub resource_epoch: u64,
    pub scope_id: String,
    pub store_lineage: String,
    pub owner_epoch: u64,
    pub credential_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_fence: Option<BoundPolicyFenceV3>,
    pub manager_os_identity: String,
    pub manager_process_id: String,
    pub manager_boot_identity: String,
    pub manager_birth_identity: String,
    pub manager_containment: String,
}

#[cfg(target_os = "linux")]
impl BoundPeerManifest {
    pub fn status(&self, resource_id: &str, scope_id: &str) -> BoundPodStatus {
        BoundPodStatus {
            capability: self.capability.clone(),
            descriptor_digest: self.descriptor_digest.clone(),
            effective_digest: self.effective_digest.clone(),
            resource_id: resource_id.into(),
            resource_epoch: self.resource_epoch,
            scope_id: scope_id.into(),
            store_lineage: self.store_lineage.clone(),
            owner_epoch: self.owner_epoch,
            credential_epoch: self.credential_epoch,
            policy_fence: self.policy_fence.clone(),
            manager_os_identity: self.manager_os_identity.clone(),
            manager_process_id: self.manager_process_id.clone(),
            manager_boot_identity: self.manager_boot_identity.clone(),
            manager_birth_identity: self.manager_birth_identity.clone(),
            manager_containment: self.manager_containment.clone(),
        }
    }
}

#[derive(Debug)]
pub enum PodError {
    Invalid(&'static str),
    Conflict(&'static str),
    Uncertain(&'static str),
    Refused(&'static str),
    Unsupported(&'static str),
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for PodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "invalid pod input: {message}"),
            Self::Conflict(message) => write!(f, "pod identity conflict: {message}"),
            Self::Uncertain(message) => write!(f, "pod outcome uncertain: {message}"),
            Self::Refused(message) => write!(f, "pod control refused: {message}"),
            Self::Unsupported(message) => write!(f, "pod backend unsupported: {message}"),
            Self::Io(error) => write!(f, "pod I/O failed: {error}"),
            Self::Json(error) => write!(f, "pod JSON failed: {error}"),
        }
    }
}
impl std::error::Error for PodError {}
impl From<std::io::Error> for PodError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for PodError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

pub fn manifest_path(directory: &Path, descriptor: &LaunchDescriptor) -> Result<PathBuf, PodError> {
    descriptor.validate()?;
    Ok(slot_path(
        directory,
        &descriptor.pod_id,
        &descriptor.attempt_id,
        descriptor.incarnation,
    ))
}

/// Locate an admitted pod's immutable launch manifest without reconstructing
/// a caller request or a legacy launch descriptor during manager recovery.
pub fn manifest_path_for_identity(
    directory: &Path,
    pod_id: &PodId,
    attempt_id: &AttemptId,
    incarnation: Epoch,
) -> PathBuf {
    slot_path(
        directory,
        pod_id.as_str(),
        attempt_id.as_str(),
        incarnation.get(),
    )
}

fn slot_path(directory: &Path, pod_id: &str, attempt_id: &str, incarnation: u64) -> PathBuf {
    let mut hash = Sha256::new();
    hash.update(b"podbay-pb05-slot/1\0");
    for field in [pod_id, attempt_id] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    hash.update(incarnation.to_be_bytes());
    directory.join(format!("{}.json", &hex(&hash.finalize())[..32]))
}

#[cfg(target_os = "linux")]
pub fn private_directory(directory: &Path) -> Result<(), PodError> {
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.file_type().is_dir()
        || fs::canonicalize(directory)? != directory
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != effective_uid()?
    {
        return Err(PodError::Invalid(
            "pod directory is not owned, private, and symlink-free",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn write_manifest(path: &Path, manifest: &PodManifest) -> Result<(), PodError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(&serde_json::to_vec(manifest)?)?;
    file.sync_all()?;
    File::open(path.parent().ok_or(PodError::Invalid("manifest parent"))?)?.sync_all()?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn read_manifest(path: &Path) -> Result<PodManifest, PodError> {
    private_directory(path.parent().ok_or(PodError::Invalid("manifest parent"))?)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != effective_uid()?
        || metadata.len() > 65_536
    {
        return Err(PodError::Invalid(
            "manifest is not regular, owned, private, and bounded",
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let manifest: PodManifest = serde_json::from_slice(&bytes)?;
    manifest.descriptor.validate()?;
    if manifest.digest != manifest.descriptor.digest()?
        || manifest.token.len() != 64
        || !manifest.token.bytes().all(|c| c.is_ascii_hexdigit())
        || (manifest.descriptor.pty.is_some()
            && !manifest.viewer_token.as_ref().is_some_and(|token| {
                token.len() == 64 && token.bytes().all(|c| c.is_ascii_hexdigit())
            }))
        || manifest.socket_path != path.with_extension("sock")
        || manifest.unit_name != unit_name(path)?
        || manifest_path(path.parent().unwrap(), &manifest.descriptor)? != path
    {
        return Err(PodError::Invalid("manifest identity or digest changed"));
    }
    if let Some(binding) = &manifest.peer_binding {
        binding.validate(&manifest.descriptor, path.parent().unwrap())?;
    }
    Ok(manifest)
}

#[cfg(target_os = "linux")]
pub fn unit_name(path: &Path) -> Result<String, PodError> {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or(PodError::Invalid("manifest filename"))?;
    if stem.len() != 32 || !stem.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(PodError::Invalid("manifest filename"));
    }
    Ok(format!("podbay-pod-{stem}.service"))
}

#[cfg(target_os = "linux")]
fn effective_uid() -> Result<u32, PodError> {
    let status = fs::read_to_string("/proc/self/status")?;
    let line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or(PodError::Invalid("effective UID unavailable"))?;
    line.split_whitespace()
        .nth(2)
        .and_then(|value| value.parse().ok())
        .ok_or(PodError::Invalid("effective UID unavailable"))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
