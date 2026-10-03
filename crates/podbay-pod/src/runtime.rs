use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use podbay_core::{
    AttemptId, CredentialEpoch, FenceOperation, FenceTarget, GrantKind, InputEpoch, OwnerEpoch,
    OwnerEpochWitness, PeerGrant, PeerGrantId, PeerRequest, PodFenceIdentity, PodId, PodPeerFence,
    ResourceId, ScopeId, StoreLineageId,
};
use podbay_store::{BoundLaunchRecord, SqliteOwnerEpochWitness};
use podbay_wire::{EffectiveLaunchContract, ImmutableLaunchDescriptor, NativeRole};
use serde::{Deserialize, Serialize};

use crate::linux_peer::LinuxPeerEvidence;
use crate::manifest::{
    BoundPeerManifest, BoundPodStatus, LaunchDescriptor, PEER_BINDING_PROTOCOL, PROTOCOL, PodError,
    PodManifest, PodPeerBootstrap, PodRole, PodStatus, SYNTHETIC_CAPABILITY, hex, manifest_path,
    private_directory, read_manifest, unit_name, write_manifest,
};
use crate::peer_checkpoint::{PeerCheckpointError, read_peer_checkpoint, write_peer_checkpoint};
use crate::ports::{
    DurableFiles, LocalControlTransport, PodControlPort, PodObservation, SupervisorBackend,
    TerminalBackend, TerminalResource, TerminalViewerPort,
};
use crate::terminal::{PtyProcess, TerminalCommand, TerminalReply};

const FRAME_LIMIT: u64 = 1_048_576;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: String,
    pod_id: String,
    attempt_id: String,
    incarnation: u64,
    token: String,
    operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal: Option<TerminalCommand>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    ok: bool,
    status: Option<PodStatus>,
    error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal: Option<TerminalReply>,
}

enum ChildResource {
    Pipe(Child),
    Pty(Box<dyn TerminalResource>),
}

impl ChildResource {
    fn id(&self) -> Result<u32, PodError> {
        match self {
            Self::Pipe(child) => Ok(child.id()),
            Self::Pty(pty) => pty
                .process_identity()?
                .parse()
                .map_err(|_| PodError::Invalid("Linux PTY process ID")),
        }
    }
    fn try_wait(&mut self) -> Result<Option<Option<i32>>, PodError> {
        match self {
            Self::Pipe(child) => Ok(child.try_wait()?.map(|status| status.code())),
            Self::Pty(pty) => Ok(pty.try_wait()?.map(Some)),
        }
    }
    fn kill(&mut self) -> Result<(), PodError> {
        match self {
            Self::Pipe(child) => child.kill().map_err(PodError::from),
            Self::Pty(pty) => pty.stop(),
        }
    }
}

pub struct PodClient {
    manifest_path: PathBuf,
    manifest: PodManifest,
}

/// Linux backend adapter; the manifest and socket protocol retain their PB05
/// shape while public observations use portable PodBay identities.
pub struct LinuxBackend;

impl SupervisorBackend for LinuxBackend {
    fn launch(
        &self,
        descriptor: LaunchDescriptor,
        directory: &Path,
        binary: &Path,
    ) -> Result<Box<dyn PodControlPort>, PodError> {
        launch(descriptor, directory, binary)
            .map(|client| Box::new(client) as Box<dyn PodControlPort>)
    }
    fn connect(&self, path: &Path) -> Result<Box<dyn PodControlPort>, PodError> {
        PodClient::connect(path).map(|client| Box::new(client) as Box<dyn PodControlPort>)
    }
}

impl TerminalBackend for LinuxBackend {
    fn spawn(
        &self,
        descriptor: &LaunchDescriptor,
        spec: crate::manifest::PtySpec,
        manifest_path: &Path,
    ) -> Result<Box<dyn TerminalResource>, PodError> {
        PtyProcess::spawn(descriptor, spec, manifest_path)
            .map(|pty| Box::new(pty) as Box<dyn TerminalResource>)
    }
}

impl LocalControlTransport for LinuxBackend {
    fn exchange(&self, endpoint: &Path, request: &[u8]) -> Result<Vec<u8>, PodError> {
        let mut socket = UnixStream::connect(endpoint)?;
        socket.set_read_timeout(Some(Duration::from_secs(3)))?;
        socket.set_write_timeout(Some(Duration::from_secs(3)))?;
        socket.write_all(request)?;
        socket.shutdown(std::net::Shutdown::Write)?;
        let mut bytes = Vec::new();
        socket.take(FRAME_LIMIT + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > FRAME_LIMIT {
            return Err(PodError::Invalid("pod response frame exceeded bound"));
        }
        Ok(bytes)
    }
}

impl DurableFiles for LinuxBackend {
    fn create_private(&self, path: &Path, bytes: &[u8]) -> Result<(), PodError> {
        let parent = path
            .parent()
            .ok_or(PodError::Invalid("durable file parent"))?;
        private_directory(parent)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }
    fn append_durable(&self, path: &Path, bytes: &[u8]) -> Result<(), PodError> {
        let parent = path
            .parent()
            .ok_or(PodError::Invalid("durable file parent"))?;
        private_directory(parent)?;
        let mut file = OpenOptions::new()
            .append(true)
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != fs::metadata(parent)?.uid()
        {
            return Err(PodError::Invalid("durable file is not private and regular"));
        }
        file.write_all(bytes)
            .map_err(|_| PodError::Uncertain("durable append outcome unknown"))?;
        file.sync_data()
            .map_err(|_| PodError::Uncertain("durable append sync outcome unknown"))?;
        Ok(())
    }
    fn replace_durable(&self, path: &Path, bytes: &[u8]) -> Result<(), PodError> {
        let temporary = path.with_extension("podbay-new");
        self.create_private(&temporary, bytes)?;
        fs::rename(&temporary, path)
            .map_err(|_| PodError::Uncertain("durable replace outcome unknown"))?;
        File::open(
            path.parent()
                .ok_or(PodError::Invalid("durable file parent"))?,
        )?
        .sync_all()
        .map_err(|_| PodError::Uncertain("durable replace sync outcome unknown"))?;
        Ok(())
    }
}

impl PodControlPort for PodClient {
    fn status(&self) -> Result<PodObservation, PodError> {
        PodClient::status(self)
    }
    fn stop(&self) -> Result<PodObservation, PodError> {
        PodClient::stop(self)
    }
    fn terminal_control(&self, command: TerminalCommand) -> Result<TerminalReply, PodError> {
        PodClient::terminal_control(self, command)
    }
    fn viewer(&self) -> Result<Box<dyn TerminalViewerPort>, PodError> {
        PodClient::viewer(self).map(|viewer| Box::new(viewer) as Box<dyn TerminalViewerPort>)
    }
}

impl PodClient {
    pub fn connect(path: impl AsRef<Path>) -> Result<Self, PodError> {
        let path = path.as_ref();
        let manifest = read_manifest(path)?;
        if manifest.peer_binding.is_none() {
            return Err(PodError::Unsupported("unbound pod control is retired"));
        }
        let client = Self {
            manifest_path: path.to_path_buf(),
            manifest,
        };
        client.status()?;
        Ok(client)
    }

    pub fn manifest_path(&self) -> Result<&Path, PodError> {
        Ok(&self.manifest_path)
    }

    pub fn status(&self) -> Result<PodObservation, PodError> {
        self.request("status").map(Into::into)
    }

    pub fn bound_status(&self) -> Result<BoundPodStatus, PodError> {
        self.request("status")?
            .bound
            .ok_or(PodError::Invalid("bound pod status is missing"))
    }

    /// Stop is explicit and bounded; an ambiguous transport result stays uncertain.
    pub fn stop(&self) -> Result<PodObservation, PodError> {
        self.request("stop").map(Into::into)
    }

    fn request(&self, operation: &str) -> Result<PodStatus, PodError> {
        let request = Request {
            protocol: PROTOCOL.to_owned(),
            pod_id: self.manifest.descriptor.pod_id.clone(),
            attempt_id: self.manifest.descriptor.attempt_id.clone(),
            incarnation: self.manifest.descriptor.incarnation,
            token: self.manifest.token.clone(),
            operation: operation.to_owned(),
            terminal: None,
        };
        let bytes = LinuxBackend
            .exchange(&self.manifest.socket_path, &serde_json::to_vec(&request)?)
            .map_err(|error| {
                if operation == "stop" {
                    PodError::Uncertain("pod stop transport outcome unknown")
                } else {
                    error
                }
            })?;
        let response: Response = serde_json::from_slice(&bytes).map_err(|error| {
            if operation == "stop" {
                PodError::Uncertain("pod stop response malformed after possible effect")
            } else {
                PodError::Json(error)
            }
        })?;
        if !response.ok {
            return Err(PodError::Refused("pod rejected authenticated request"));
        }
        let status = response.status.ok_or(if operation == "stop" {
            PodError::Uncertain("pod stop status missing after possible effect")
        } else {
            PodError::Invalid("pod status missing")
        })?;
        attest(&self.manifest, &status).map_err(|error| {
            if operation == "stop" {
                PodError::Uncertain("pod stop identity not attested after possible effect")
            } else {
                error
            }
        })?;
        Ok(status)
    }

    pub fn viewer(&self) -> Result<TerminalViewer, PodError> {
        let token = self
            .manifest
            .viewer_token
            .clone()
            .ok_or(PodError::Refused("pod has no PTY viewer capability"))?;
        Ok(TerminalViewer {
            socket_path: self.manifest.socket_path.clone(),
            pod_id: self.manifest.descriptor.pod_id.clone(),
            attempt_id: self.manifest.descriptor.attempt_id.clone(),
            incarnation: self.manifest.descriptor.incarnation,
            resource_id: self.manifest.descriptor.resource_id.clone(),
            token,
        })
    }

    /// The caller must already hold the current manager-side control grant.
    /// A BytesWritten reply is transport evidence, never application success.
    pub fn terminal_control(&self, command: TerminalCommand) -> Result<TerminalReply, PodError> {
        let _ = command;
        Err(PodError::Unsupported(
            "terminal control has no peer-bound lease bridge",
        ))
    }
}

pub struct TerminalViewer {
    socket_path: PathBuf,
    pod_id: String,
    attempt_id: String,
    incarnation: u64,
    resource_id: String,
    token: String,
}

impl TerminalViewer {
    pub fn attach(&self) -> Result<crate::terminal::TerminalView, PodError> {
        match terminal_exchange(
            &self.socket_path,
            &self.pod_id,
            &self.attempt_id,
            self.incarnation,
            &self.token,
            TerminalCommand::Attach {
                resource_id: self.resource_id.clone(),
                incarnation: self.incarnation,
            },
        )? {
            TerminalReply::View { value } => Ok(value),
            _ => Err(PodError::Invalid("terminal attach response mismatch")),
        }
    }

    pub fn events_after(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<crate::terminal::TerminalEventPage, PodError> {
        match terminal_exchange(
            &self.socket_path,
            &self.pod_id,
            &self.attempt_id,
            self.incarnation,
            &self.token,
            TerminalCommand::Events {
                resource_id: self.resource_id.clone(),
                incarnation: self.incarnation,
                after,
                limit,
            },
        )? {
            TerminalReply::Events { value } => Ok(value),
            _ => Err(PodError::Invalid("terminal events response mismatch")),
        }
    }
}

impl TerminalViewerPort for TerminalViewer {
    fn attach(&self) -> Result<crate::terminal_protocol::TerminalView, PodError> {
        TerminalViewer::attach(self)
    }
    fn events_after(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<crate::terminal_protocol::TerminalEventPage, PodError> {
        TerminalViewer::events_after(self, after, limit)
    }
}

fn terminal_exchange(
    socket_path: &Path,
    pod_id: &str,
    attempt_id: &str,
    incarnation: u64,
    token: &str,
    command: TerminalCommand,
) -> Result<TerminalReply, PodError> {
    let mutation = !command.read_only();
    let request = Request {
        protocol: PROTOCOL.to_owned(),
        pod_id: pod_id.into(),
        attempt_id: attempt_id.into(),
        incarnation,
        token: token.into(),
        operation: "terminal".into(),
        terminal: Some(command),
    };
    let bytes = LinuxBackend
        .exchange(socket_path, &serde_json::to_vec(&request)?)
        .map_err(|error| terminal_transport(error, mutation))?;
    let response: Response = serde_json::from_slice(&bytes).map_err(|error| {
        if mutation {
            PodError::Uncertain("terminal response malformed after possible input")
        } else {
            PodError::Json(error)
        }
    })?;
    if !response.ok {
        return Err(if response.error_code.as_deref() == Some("uncertain") {
            PodError::Uncertain("terminal command may have affected the PTY; do not replay")
        } else {
            PodError::Refused("terminal command refused before effect")
        });
    }
    response
        .terminal
        .ok_or(PodError::Invalid("terminal response missing"))
}

fn terminal_transport(error: PodError, mutation: bool) -> PodError {
    if mutation {
        PodError::Uncertain("terminal transport lost after possible input; do not replay")
    } else {
        error
    }
}

/// Admits one exact manifest. Existing ambiguous state is never launched again.
pub fn launch(
    descriptor: LaunchDescriptor,
    directory: impl AsRef<Path>,
    pod_binary: impl AsRef<Path>,
) -> Result<PodClient, PodError> {
    let _ = (descriptor, directory, pod_binary);
    Err(PodError::Unsupported("unbound pod launch is retired"))
}

/// Linux OS-lifetime proof only. The committed descriptor is preserved in the
/// manifest; only the explicitly bounded synthetic process.exec subset runs.
pub fn launch_bound(
    record: BoundLaunchRecord,
    bootstrap: PodPeerBootstrap,
    directory: impl AsRef<Path>,
    pod_binary: impl AsRef<Path>,
) -> Result<PodClient, PodError> {
    let directory = directory.as_ref();
    private_directory(directory)?;
    let wire = ImmutableLaunchDescriptor::decode_json(&record.descriptor)
        .map_err(|_| PodError::Invalid("committed descriptor bytes"))?;
    let effective = EffectiveLaunchContract::decode(&record.effective_spec)
        .map_err(|_| PodError::Invalid("committed effective bytes"))?;
    effective
        .compare_with_descriptor(&wire)
        .map_err(|_| PodError::Invalid("committed descriptor/effective mismatch"))?;
    if record.scope_id != wire.scope_id()
        || record.pod_id != wire.pod_id()
        || record.attempt_id != wire.attempt_id()
        || record.pod_incarnation != wire.pod_incarnation()
        || record.resources.len() != 1
        || wire.resource_id(0) != Some(record.resources[0].id.as_str())
        || record.resources[0].epoch != wire.resource(0).map(|resource| resource.epoch).unwrap_or(0)
        || !pod_binary.as_ref().is_absolute()
    {
        return Err(PodError::Invalid("committed bound identity differs"));
    }
    let descriptor = LaunchDescriptor {
        protocol: PROTOCOL.into(),
        pod_id: wire.pod_id().into(),
        attempt_id: wire.attempt_id().into(),
        session_id: wire.session_id().into(),
        run_id: wire.run_id().into(),
        scope_id: wire.scope_id().into(),
        role: if wire.role() == NativeRole::Worker {
            PodRole::Worker
        } else {
            PodRole::Advisor
        },
        incarnation: wire.pod_incarnation(),
        resource_id: record.resources[0].id.clone(),
        executable: PathBuf::from(wire.executable()),
        args: wire.arguments().to_vec(),
        cwd: PathBuf::from(wire.cwd()),
        pty: None,
    };
    descriptor.validate()?;
    let manager = LinuxPeerEvidence::for_current_process()
        .map_err(|_| PodError::Refused("manager process identity unavailable"))?;
    let peer = manager.attested_peer();
    if peer != &bootstrap.expected_manager_peer {
        return Err(PodError::Refused(
            "manager peer changed before pod admission",
        ));
    }
    let mut bound = BoundPeerManifest {
        protocol: PEER_BINDING_PROTOCOL.into(),
        capability: SYNTHETIC_CAPABILITY.into(),
        wire_descriptor: record.descriptor,
        effective_spec: record.effective_spec,
        descriptor_digest: wire.digest().into(),
        effective_digest: effective.digest().into(),
        resource_epoch: record.resources[0].epoch,
        store_path: bootstrap.store_path,
        store_lineage: bootstrap.store_lineage,
        owner_epoch: bootstrap.owner_epoch,
        credential_epoch: bootstrap.credential_epoch,
        resource_input_epochs: bootstrap.resource_input_epochs,
        manager_os_identity: peer.os_identity().into(),
        manager_process_id: peer.native_process_id().into(),
        manager_boot_identity: peer.boot_identity().into(),
        manager_birth_identity: peer.birth_identity().into(),
        manager_containment: peer.containment_identity().into(),
        canonical_executable: bootstrap.canonical_executable,
        executable_sha256: bootstrap.executable_sha256,
        binding_digest: String::new(),
    };
    bound.binding_digest = bound.digest()?;
    bound.validate(&descriptor, directory)?;
    let identity = bound_identity(&descriptor, &bound)?;
    let witness = SqliteOwnerEpochWitness::for_pod(&bound.store_path, identity.clone());
    if witness
        .current_owner_epoch(&identity.store_lineage, &identity.scope_id)
        .map(|epoch| epoch.get())
        != Some(bound.owner_epoch)
    {
        return Err(PodError::Refused("bound store owner epoch unavailable"));
    }
    let path = manifest_path(directory, &descriptor)?;
    if fs::symlink_metadata(&path).is_ok() {
        let existing = read_manifest(&path)?;
        if existing.peer_binding.as_ref() != Some(&bound) {
            return Err(PodError::Conflict("bound manifest changed"));
        }
        return PodClient::connect(path)
            .map_err(|_| PodError::Uncertain("bound pod unreachable; no replacement launched"));
    }
    let mut token = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut token)?;
    let manifest = PodManifest {
        digest: descriptor.digest()?,
        token: hex(&token),
        viewer_token: None,
        socket_path: path.with_extension("sock"),
        unit_name: unit_name(&path)?,
        descriptor,
        peer_binding: Some(bound),
    };
    if manifest.socket_path.as_os_str().len() > 100 {
        return Err(PodError::Invalid("socket path too long"));
    }
    if serde_json::to_vec(&manifest)?.len() > 65_536 {
        return Err(PodError::Invalid(
            "bound manifest exceeds private file bound",
        ));
    }
    write_manifest(&path, &manifest)?;
    let started = Command::new("systemd-run")
        .args([
            "--user",
            "--no-ask-password",
            "--collect",
            "--service-type=exec",
            "--property=KillMode=control-group",
            "--property=NoNewPrivileges=yes",
            "--property=RuntimeMaxSec=60s",
            "--property=TasksMax=2",
        ])
        .arg(format!("--unit={}", manifest.unit_name))
        .arg(pod_binary.as_ref())
        .arg("serve")
        .arg("--manifest")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !matches!(started,Ok(status) if status.success()) {
        return Err(PodError::Uncertain(
            "systemd bound admission not attested; manifest retained",
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(client) = PodClient::connect(&path) {
            return Ok(client);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err(PodError::Uncertain(
        "bound pod socket/child not attested; manifest retained",
    ))
}

fn bound_identity(
    descriptor: &LaunchDescriptor,
    binding: &BoundPeerManifest,
) -> Result<PodFenceIdentity, PodError> {
    Ok(PodFenceIdentity {
        scope_id: ScopeId::try_from(descriptor.scope_id.as_str())
            .map_err(|_| PodError::Invalid("bound scope"))?,
        pod_id: PodId::try_from(descriptor.pod_id.as_str())
            .map_err(|_| PodError::Invalid("bound pod"))?,
        attempt_id: AttemptId::try_from(descriptor.attempt_id.as_str())
            .map_err(|_| PodError::Invalid("bound attempt"))?,
        incarnation: podbay_core::Epoch::new(descriptor.incarnation)
            .map_err(|_| PodError::Invalid("bound incarnation"))?,
        store_lineage: StoreLineageId::try_from(binding.store_lineage.as_str())
            .map_err(|_| PodError::Invalid("bound store lineage"))?,
    })
}

/// Internal systemd service entry. The authenticated socket binds before any child is spawned.
pub fn serve(manifest_path: impl AsRef<Path>) -> Result<(), PodError> {
    let manifest = read_manifest(manifest_path.as_ref())?;
    let binding = manifest.peer_binding.as_ref().ok_or(PodError::Unsupported(
        "unbound bearer-only pod service is retired",
    ))?;
    let identity = bound_identity(&manifest.descriptor, binding)?;
    let manager_peer = binding.manager_peer()?;
    let owner_epoch =
        OwnerEpoch::new(binding.owner_epoch).map_err(|_| PodError::Invalid("bound owner epoch"))?;
    let credential_epoch = CredentialEpoch::new(binding.credential_epoch)
        .map_err(|_| PodError::Invalid("bound credential epoch"))?;
    let mut inputs = BTreeMap::new();
    for (id, epoch) in &binding.resource_input_epochs {
        inputs.insert(
            ResourceId::try_from(id.as_str())
                .map_err(|_| PodError::Invalid("bound resource ID"))?,
            InputEpoch::new(*epoch).map_err(|_| PodError::Invalid("bound input epoch"))?,
        );
    }
    let witness = SqliteOwnerEpochWitness::for_pod(&binding.store_path, identity.clone());
    if witness.current_owner_epoch(&identity.store_lineage, &identity.scope_id) != Some(owner_epoch)
    {
        return Err(PodError::Refused("bound owner witness unavailable"));
    }
    match read_peer_checkpoint(manifest_path.as_ref().parent().unwrap(), &identity) {
        Ok(_) => {
            return Err(PodError::Uncertain(
                "existing peer checkpoint requires reconciliation; child not relaunched",
            ));
        }
        Err(PeerCheckpointError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(PodError::Refused(
                "peer checkpoint is unreadable; child not launched",
            ));
        }
    }
    if fs::symlink_metadata(&manifest.socket_path).is_ok() {
        return Err(PodError::Uncertain("recorded socket already exists"));
    }
    let cgroup_path = cgroup_path()?;
    if !unit_cgroup_exact(&cgroup_path, &manifest.unit_name) {
        return Err(PodError::Invalid(
            "pod process is outside its declared systemd unit",
        ));
    }
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    let mut fence = PodPeerFence::new(
        identity.clone(),
        manager_peer.clone(),
        owner_epoch,
        credential_epoch,
        inputs,
        1,
        30_001,
    )
    .map_err(|_| PodError::Invalid("initial peer fence refused"))?;
    write_peer_checkpoint(
        manifest_path.as_ref().parent().unwrap(),
        &identity,
        &fence.checkpoint(),
    )
    .map_err(|_| PodError::Uncertain("initial peer checkpoint did not settle"))?;
    fence
        .install_grant(
            &manager_peer,
            PeerGrant::new(
                PeerGrantId::try_from("grant.manager.pod.bootstrap").unwrap(),
                manager_peer.clone(),
                GrantKind::Controller,
                FenceTarget::Pod,
                BTreeSet::from([FenceOperation::ObservePod, FenceOperation::StopPod]),
                owner_epoch,
                credential_epoch,
                60_001,
            )
            .map_err(|_| PodError::Invalid("manager bootstrap grant"))?,
            &witness,
            1,
        )
        .map_err(|_| PodError::Refused("manager bootstrap grant not current"))?;
    let fence_clock = Instant::now();
    let listener = UnixListener::bind(&manifest.socket_path)?;
    fs::set_permissions(&manifest.socket_path, fs::Permissions::from_mode(0o600))?;
    let descriptor = &manifest.descriptor;
    let mut child = match descriptor.pty {
        Some(spec) => {
            ChildResource::Pty(LinuxBackend.spawn(descriptor, spec, manifest_path.as_ref())?)
        }
        None => ChildResource::Pipe(
            Command::new(&descriptor.executable)
                .args(&descriptor.args)
                .current_dir(&descriptor.cwd)
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        ),
    };
    let child_pid = child.id()?;
    let child_start_ticks = start_ticks(child_pid)?;
    let mut exit_code = None;
    let mut settled = false;
    let mut accept_failures = 0u8;
    for incoming in listener.incoming() {
        let mut stream = match incoming {
            Ok(stream) => {
                accept_failures = 0;
                stream
            }
            Err(_error) => {
                accept_failures = accept_failures.saturating_add(1);
                let shift = u32::from(accept_failures.min(6));
                let backoff = (25u64.checked_shl(shift).unwrap_or(2_000)).min(2_000);
                std::thread::sleep(Duration::from_millis(backoff));
                continue;
            }
        };
        // A malformed, stalled, disconnected, or unauthorized connection is
        // local to that connection. It may not kill the pod and its child.
        let handled = (|| -> Result<bool, PodError> {
            let peer_evidence = LinuxPeerEvidence::from_accepted(&stream);
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            stream.set_write_timeout(Some(Duration::from_secs(2)))?;
            let mut bytes = Vec::new();
            (&mut stream)
                .take(FRAME_LIMIT + 1)
                .read_to_end(&mut bytes)?;
            let parsed = if bytes.len() as u64 > FRAME_LIMIT {
                Err(PodError::Invalid("pod request frame exceeded bound"))
            } else {
                serde_json::from_slice::<Request>(&bytes).map_err(PodError::from)
            };
            let authorized = parsed.as_ref().is_ok_and(|request| {
                request.protocol == PROTOCOL
                    && request.pod_id == descriptor.pod_id
                    && request.attempt_id == descriptor.attempt_id
                    && request.incarnation == descriptor.incarnation
                    && constant_time_equal(request.token.as_bytes(), manifest.token.as_bytes())
            }) && peer_evidence
                .as_ref()
                .is_ok_and(|observed| observed.attested_peer() == &manager_peer);
            if !authorized {
                respond(
                    &mut stream,
                    Response {
                        ok: false,
                        status: None,
                        error: Some("request refused".into()),
                        error_code: None,
                        terminal: None,
                    },
                )?;
                return Ok(false);
            }
            let request = parsed.expect("checked request");
            let observed = peer_evidence.expect("checked peer");
            // This first slice has no viewer grant or atomic terminal lease bridge.
            // Even the correct manager bearer cannot enter an unimplemented path.
            if request.operation == "terminal" {
                respond(
                    &mut stream,
                    Response {
                        ok: false,
                        status: None,
                        error: Some("terminal control unavailable in synthetic fixture".into()),
                        error_code: Some("unsupported".into()),
                        terminal: None,
                    },
                )?;
                return Ok(false);
            }
            let fence_operation = match request.operation.as_str() {
                "status" => FenceOperation::ObservePod,
                "stop" => FenceOperation::StopPod,
                _ => {
                    respond(
                        &mut stream,
                        Response {
                            ok: false,
                            status: None,
                            error: Some("unsupported operation".into()),
                            error_code: Some("unsupported".into()),
                            terminal: None,
                        },
                    )?;
                    return Ok(false);
                }
            };
            let current = observed
                .recheck_before_effect(&stream, &manager_peer)
                .is_ok();
            let now = u64::try_from(fence_clock.elapsed().as_millis())
                .unwrap_or(u64::MAX)
                .saturating_add(1);
            let checked = PeerRequest {
                identity: identity.clone(),
                grant_id: PeerGrantId::try_from("grant.manager.pod.bootstrap").unwrap(),
                owner_epoch,
                credential_epoch,
                target: FenceTarget::Pod,
                operation: fence_operation,
                input_epoch: None,
            };
            if !current
                || fence
                    .authorize(observed.attested_peer(), &checked, &witness, now)
                    .is_err()
            {
                respond(
                    &mut stream,
                    Response {
                        ok: false,
                        status: None,
                        error: Some("peer or owner authority unavailable".into()),
                        error_code: Some("refused".into()),
                        terminal: None,
                    },
                )?;
                return Ok(false);
            }
            if !settled && let Some(status) = child.try_wait()? {
                settled = true;
                exit_code = status;
            }
            let stopping = request.operation == "stop";
            if stopping && !settled {
                child.kill()?;
                let deadline = Instant::now() + Duration::from_secs(2);
                while Instant::now() < deadline {
                    if let Some(status) = child.try_wait()? {
                        settled = true;
                        exit_code = status;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            if request.operation != "status" && !stopping {
                respond(
                    &mut stream,
                    Response {
                        ok: false,
                        status: None,
                        error: Some("unsupported operation".into()),
                        error_code: None,
                        terminal: None,
                    },
                )?;
                return Ok(false);
            }
            let status = PodStatus {
                protocol: PROTOCOL.to_owned(),
                pod_id: descriptor.pod_id.clone(),
                attempt_id: descriptor.attempt_id.clone(),
                incarnation: descriptor.incarnation,
                manifest_digest: manifest.digest.clone(),
                supervisor_pid: std::process::id(),
                supervisor_start_ticks: start_ticks(std::process::id())?,
                child_pid,
                child_start_ticks,
                boot_id: boot_id.clone(),
                unit_name: manifest.unit_name.clone(),
                cgroup_path: cgroup_path.clone(),
                child_running: !settled,
                exit_code,
                bound: manifest
                    .peer_binding
                    .as_ref()
                    .map(|binding| binding.status(&descriptor.resource_id, &descriptor.scope_id)),
            };
            respond(
                &mut stream,
                Response {
                    ok: true,
                    status: Some(status),
                    error: None,
                    error_code: None,
                    terminal: None,
                },
            )?;
            Ok(stopping)
        })();
        if matches!(handled, Ok(true)) {
            break;
        }
    }
    let _ = fs::remove_file(&manifest.socket_path);
    Ok(())
}

fn attest(manifest: &PodManifest, status: &PodStatus) -> Result<(), PodError> {
    if status.supervisor_start_ticks == 0 {
        return Err(PodError::Unsupported(
            "legacy Linux pod status lacks supervisor start identity",
        ));
    }
    if status.protocol != PROTOCOL
        || status.pod_id != manifest.descriptor.pod_id
        || status.attempt_id != manifest.descriptor.attempt_id
        || status.incarnation != manifest.descriptor.incarnation
        || status.manifest_digest != manifest.digest
        || status.supervisor_pid == 0
        || status.child_pid == 0
        || status.child_start_ticks == 0
        || status.boot_id.is_empty()
        || status.unit_name != manifest.unit_name
        || !unit_cgroup_exact(&status.cgroup_path, &manifest.unit_name)
        || manifest.peer_binding.as_ref().map(|binding| {
            binding.status(
                &manifest.descriptor.resource_id,
                &manifest.descriptor.scope_id,
            )
        }) != status.bound
    {
        return Err(PodError::Invalid(
            "pod identity, process start, or cgroup attestation failed",
        ));
    }
    Ok(())
}

fn respond(stream: &mut UnixStream, response: Response) -> Result<(), PodError> {
    let bytes = serde_json::to_vec(&response)?;
    if bytes.len() as u64 > FRAME_LIMIT {
        let possible_effect = matches!(
            response.terminal,
            Some(TerminalReply::BytesWritten | TerminalReply::Resized { .. })
        );
        let fallback = Response {
            ok: false,
            status: None,
            error: Some("terminal response exceeded frame bound".into()),
            error_code: Some(if possible_effect {
                "uncertain".into()
            } else {
                "refused".into()
            }),
            terminal: None,
        };
        stream.write_all(&serde_json::to_vec(&fallback)?)?;
    } else {
        stream.write_all(&bytes)?;
    }
    Ok(())
}

fn unit_cgroup_exact(cgroup: &str, unit: &str) -> bool {
    cgroup.starts_with('/') && cgroup.rsplit('/').next() == Some(unit)
}

fn cgroup_path() -> Result<String, PodError> {
    let content = fs::read_to_string("/proc/self/cgroup")?;
    content
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::to_owned)
        .ok_or(PodError::Invalid("unified cgroup evidence unavailable"))
}

fn start_ticks(pid: u32) -> Result<u64, PodError> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let after_name = stat
        .rsplit_once(") ")
        .ok_or(PodError::Invalid("child start identity"))?
        .1;
    after_name
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse().ok())
        .ok_or(PodError::Invalid("child start identity"))
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |acc, (&a, &b)| acc | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::PodRole;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn lost_response_after_possible_input_is_uncertain() {
        let error = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "synthetic");
        assert!(matches!(
            terminal_transport(PodError::Io(error), true),
            PodError::Uncertain(_)
        ));
        let read_error = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "synthetic");
        assert!(matches!(
            terminal_transport(PodError::Io(read_error), false),
            PodError::Io(_)
        ));
    }

    #[test]
    fn legacy_status_without_supervisor_start_identity_is_typed_unsupported() {
        let descriptor = LaunchDescriptor {
            protocol: PROTOCOL.into(),
            pod_id: "pod.fixture".into(),
            attempt_id: "attempt.fixture".into(),
            session_id: "session.fixture".into(),
            run_id: "run.fixture".into(),
            scope_id: "scope.fixture".into(),
            role: PodRole::Worker,
            incarnation: 1,
            resource_id: "resource.fixture".into(),
            executable: "/bin/true".into(),
            args: vec![],
            cwd: "/tmp".into(),
            pty: None,
        };
        let manifest = PodManifest {
            descriptor,
            digest: "digest".into(),
            token: "a".repeat(64),
            viewer_token: None,
            socket_path: "/tmp/fixture.sock".into(),
            unit_name: "podbay-pod-fixture.service".into(),
            peer_binding: None,
        };
        let old = serde_json::json!({"protocol":PROTOCOL,"pod_id":"pod.fixture",
            "attempt_id":"attempt.fixture","incarnation":1,"manifest_digest":"digest",
            "supervisor_pid":10,"child_pid":11,"child_start_ticks":12,
            "boot_id":"boot","unit_name":"podbay-pod-fixture.service",
            "cgroup_path":"/podbay-pod-fixture.service","child_running":true,
            "exit_code":null});
        let status: PodStatus = serde_json::from_value(old).unwrap();
        assert!(matches!(
            attest(&manifest, &status),
            Err(PodError::Unsupported(_))
        ));
    }

    #[test]
    fn unit_cgroup_match_requires_exact_final_component() {
        assert!(unit_cgroup_exact(
            "/user.slice/app.slice/podbay-fixture.service",
            "podbay-fixture.service"
        ));
        assert!(!unit_cgroup_exact(
            "/user.slice/app.slice/podbay-fixture.service-other",
            "podbay-fixture.service"
        ));
        assert!(!unit_cgroup_exact(
            "/user.slice/app.slice/other-podbay-fixture.service-extra",
            "podbay-fixture.service"
        ));
        assert!(!unit_cgroup_exact(
            "relative/podbay-fixture.service",
            "podbay-fixture.service"
        ));
    }

    #[test]
    fn linux_durable_file_port_is_private_and_refuses_symlink_append() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("podbay-files-{}-{unique}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("record");
        LinuxBackend.create_private(&path, b"a").unwrap();
        LinuxBackend.append_durable(&path, b"b").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"ab");
        LinuxBackend.replace_durable(&path, b"c").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"c");
        let link = directory.join("link");
        symlink(&path, &link).unwrap();
        assert!(LinuxBackend.append_durable(&link, b"wrong").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"c");
        fs::remove_dir_all(directory).unwrap();
    }
}
