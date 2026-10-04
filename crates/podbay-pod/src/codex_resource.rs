//! Pod-owned structured Codex child startup after exact V2 manifest review.
//! Initialize is transport evidence only: no thread, turn, or provider
//! readiness is inferred here.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use podbay_adapter_codex::{
    ApprovalPolicy, ChildLaunchSpec, CodexResource, KernelChildBirthObservation, PinnedCodexConfig,
    ProcessJsonlTransport, ResourceIdentity, Sandbox,
};
use podbay_core::{AttemptId, Epoch, PodId, ResourceId, RunId, SessionId};
use podbay_wire::{
    EffectiveLaunchContractV2, ImmutableLaunchDescriptorV2, NativeResourceKind, ResourceDriver,
    TargetOs,
};

use crate::codex_credential::{
    CODEX_AUTH_CREDENTIAL_NAME, PreparedCodexHome, prepare_codex_home_from_systemd_credential,
};
use crate::linux_peer::LinuxPeerEvidence;
use crate::manifest::{
    BoundPeerManifest, CODEX_V2_CAPABILITY, LaunchDescriptor, PEER_BINDING_V2_PROTOCOL, PodError,
    manifest_path, private_directory, unit_name,
};

const IO_TIMEOUT: Duration = Duration::from_secs(30);
const ARGV: [&str; 3] = ["app-server", "--listen", "stdio://"];

/// An opaque, typed manifest preflight. Construction rechecks the V2 peer
/// binding and canonical paths; it does not prove durable store admission,
/// manager authority, or a current resource grant.
pub struct ValidatedCodexResourceLaunch {
    descriptor: ImmutableLaunchDescriptorV2,
    effective: EffectiveLaunchContractV2,
    peer_binding: BoundPeerManifest,
    legacy: LaunchDescriptor,
    pod_directory: PathBuf,
    expected_unit: String,
}

impl ValidatedCodexResourceLaunch {
    pub fn from_peer_binding(
        binding: &BoundPeerManifest,
        launch: &LaunchDescriptor,
        pod_directory: &Path,
    ) -> Result<Self, PodError> {
        private_directory(pod_directory)?;
        if binding.protocol != PEER_BINDING_V2_PROTOCOL || binding.capability != CODEX_V2_CAPABILITY
        {
            return Err(PodError::Unsupported("Codex V2 peer binding is required"));
        }
        binding.validate(launch, pod_directory)?;
        let descriptor = ImmutableLaunchDescriptorV2::decode_json(&binding.wire_descriptor)
            .map_err(|_| PodError::Invalid("Codex V2 descriptor changed"))?;
        let effective = EffectiveLaunchContractV2::decode(&binding.effective_spec)
            .map_err(|_| PodError::Invalid("Codex V2 effective launch changed"))?;
        effective
            .compare_with_descriptor(&descriptor)
            .map_err(|_| PodError::Invalid("Codex V2 launch relation changed"))?;
        let expected_unit = unit_name(&manifest_path(pod_directory, launch)?)?;
        Ok(Self {
            descriptor,
            effective,
            peer_binding: binding.clone(),
            legacy: launch.clone(),
            pod_directory: pod_directory.to_path_buf(),
            expected_unit,
        })
    }

    pub fn expected_unit(&self) -> &str {
        &self.expected_unit
    }
}

/// Owns the structured adapter and its direct child. Only observational
/// methods are exposed by this slice; it cannot submit a model turn.
pub struct PodCodexResource {
    resource: CodexResource<ProcessJsonlTransport>,
    child_birth: KernelChildBirthObservation,
    pod_boot_id: String,
    pod_cgroup: String,
}

impl PodCodexResource {
    /// Spawn the exact reviewed app-server child with only explicit HOME and
    /// CODEX_HOME. A lost initialize result is uncertain; no turn is sent.
    pub fn spawn_initialized(
        launch: ValidatedCodexResourceLaunch,
        home: PreparedCodexHome,
    ) -> Result<Self, PodError> {
        private_directory(&launch.pod_directory)?;
        launch
            .peer_binding
            .validate(&launch.legacy, &launch.pod_directory)?;
        if home.isolated_home() != launch.pod_directory.join("home")
            || home.codex_home() != launch.pod_directory.join("home/codex")
        {
            return Err(PodError::Refused("Codex HOME belongs to another pod"));
        }
        let credential = fs::read_link(home.credential_reference())?;
        if credential.file_name() != Some(CODEX_AUTH_CREDENTIAL_NAME.as_ref())
            || credential
                .parent()
                .and_then(Path::file_name)
                .is_none_or(|unit| unit != launch.expected_unit.as_str())
            || !fs::metadata(home.credential_reference())?.is_file()
        {
            return Err(PodError::Refused("Codex credential reference is stale"));
        }
        let source_directory = credential
            .parent()
            .ok_or(PodError::Refused("Codex credential directory is absent"))?;
        let rechecked_home = prepare_codex_home_from_systemd_credential(
            &launch.expected_unit,
            &launch.pod_directory,
            source_directory,
        )?;
        if rechecked_home.isolated_home() != home.isolated_home()
            || rechecked_home.codex_home() != home.codex_home()
            || rechecked_home.credential_reference() != home.credential_reference()
        {
            return Err(PodError::Refused("Codex HOME changed before spawn"));
        }
        let descriptor = &launch.descriptor;
        launch
            .effective
            .compare_with_descriptor(descriptor)
            .map_err(|_| PodError::Refused("Codex V2 launch relation changed"))?;
        let resource = descriptor
            .resource(0)
            .ok_or(PodError::Invalid("Codex V2 resource is absent"))?;
        if descriptor.target_os() != TargetOs::Linux
            || descriptor.resources_len() != 1
            || resource.kind != NativeResourceKind::StructuredProvider
            || !matches!(resource.driver, ResourceDriver::Structured { .. })
            || descriptor.arguments() != ARGV
        {
            return Err(PodError::Unsupported(
                "Codex structured child selection changed",
            ));
        }
        let identity = ResourceIdentity {
            session_id: SessionId::try_from(descriptor.session_id())
                .map_err(|_| PodError::Invalid("Codex session identity"))?,
            run_id: RunId::try_from(descriptor.run_id())
                .map_err(|_| PodError::Invalid("Codex run identity"))?,
            attempt_id: AttemptId::try_from(descriptor.attempt_id())
                .map_err(|_| PodError::Invalid("Codex attempt identity"))?,
            pod_id: PodId::try_from(descriptor.pod_id())
                .map_err(|_| PodError::Invalid("Codex pod identity"))?,
            resource_id: ResourceId::try_from(resource.resource_id)
                .map_err(|_| PodError::Invalid("Codex resource identity"))?,
            resource_epoch: Epoch::new(resource.epoch)
                .map_err(|_| PodError::Invalid("Codex resource epoch"))?,
        };
        let config = PinnedCodexConfig::new(
            descriptor.model_id(),
            descriptor.reasoning_effort(),
            PathBuf::from(descriptor.cwd()),
            ApprovalPolicy::Never,
            Sandbox::DangerFullAccess,
        )
        .map_err(|_| PodError::Invalid("Codex pinned native configuration"))?;
        let owner = LinuxPeerEvidence::for_current_process()
            .map_err(|_| PodError::Refused("pod process identity unavailable"))?;
        let pod_boot_id = owner.boot_id().to_owned();
        let pod_cgroup = owner.cgroup().to_owned();
        if pod_cgroup.rsplit('/').next() != Some(launch.expected_unit.as_str()) {
            return Err(PodError::Refused(
                "Codex child constructor is outside its pod unit",
            ));
        }
        let spec = ChildLaunchSpec::new(
            PathBuf::from(descriptor.executable()),
            ARGV.into_iter().map(OsString::from).collect(),
            PathBuf::from(descriptor.cwd()),
            home.isolated_home().to_path_buf(),
            home.codex_home().to_path_buf(),
            IO_TIMEOUT,
            IO_TIMEOUT,
        )
        .map_err(PodError::Io)?;
        let mut transport = ProcessJsonlTransport::spawn(spec)?;
        let child_birth = transport
            .attest_kernel_birth()
            .map_err(|_| PodError::Uncertain("Codex child birth unavailable after spawn"))?;
        require_child_in_pod(&child_birth, &pod_boot_id, &pod_cgroup)?;
        let mut resource = CodexResource::new(transport, identity, config);
        resource
            .initialize()
            .map_err(|_| PodError::Uncertain("Codex initialize outcome unknown"))?;
        let after = resource
            .attest_owned_child_birth()
            .map_err(|_| PodError::Uncertain("Codex child birth unavailable after initialize"))?;
        if after != child_birth {
            return Err(PodError::Refused(
                "Codex child birth changed during initialize",
            ));
        }
        require_child_in_pod(&after, &pod_boot_id, &pod_cgroup)?;
        Ok(Self {
            resource,
            child_birth,
            pod_boot_id,
            pod_cgroup,
        })
    }

    pub fn identity(&self) -> &ResourceIdentity {
        self.resource.identity()
    }

    pub fn child_birth(&self) -> &KernelChildBirthObservation {
        &self.child_birth
    }

    /// Recheck the same live direct child and exact pod boot/cgroup. A future
    /// command path must call this again at its own effect boundary.
    pub fn recheck_child(&mut self) -> Result<KernelChildBirthObservation, PodError> {
        let owner = LinuxPeerEvidence::for_current_process()
            .map_err(|_| PodError::Refused("pod process identity unavailable"))?;
        if owner.boot_id() != self.pod_boot_id || owner.cgroup() != self.pod_cgroup {
            return Err(PodError::Refused("pod boot or cgroup changed"));
        }
        let current = self
            .resource
            .attest_owned_child_birth()
            .map_err(|_| PodError::Refused("Codex child process is unavailable"))?;
        if current != self.child_birth {
            return Err(PodError::Refused("Codex child birth changed"));
        }
        require_child_in_pod(&current, &self.pod_boot_id, &self.pod_cgroup)?;
        Ok(current)
    }
}

fn require_child_in_pod(
    child: &KernelChildBirthObservation,
    boot_id: &str,
    cgroup: &str,
) -> Result<(), PodError> {
    if child.pid == 0
        || child.start_ticks == 0
        || child.boot_id != boot_id
        || child.cgroup_path != cgroup
    {
        return Err(PodError::Refused(
            "Codex child differs from pod boot or cgroup",
        ));
    }
    Ok(())
}
