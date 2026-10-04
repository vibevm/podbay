use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use podbay_core::{
    AttemptId, AttestedPeer, CommandId, CredentialEpoch, FenceOperation, FenceTarget, GrantKind, InputEpoch,
    ManagerLiveness, OwnerEpoch, OwnerEpochWitness, PeerGrant, PeerGrantId, PeerRequest,
    PodFenceCheckpoint,
    PodFenceIdentity, PodId, PodPeerFence, RebindLedger, RebindPhase, RebindProposal, ResourceId, ScopeId,
    StoreLineageId,
};
use podbay_store::{
    BootstrapSendSelector, BoundLaunchFormat, BoundLaunchRecord, HostObservedPriorCheckpoint,
    NativeWriterTarget, PodBayStore, SqliteManagerPeerWitness, SqliteOwnerEpochWitness,
    SqlitePriorObservedPendingLedger,
};
use podbay_wire::{EffectiveLaunchContract, ImmutableLaunchDescriptor, NativeRole, NativeWorkKind};
use serde::{Deserialize, Serialize};

use crate::codex_credential::prepare_codex_home_from_systemd_credential;
use crate::codex_bootstrap::{
    BootstrapControlReceipt, BootstrapControlRequest, BootstrapControlStage,
    CODEX_BOOTSTRAP_INSPECT_PROTOCOL, CODEX_BOOTSTRAP_PROTOCOL,
};
use crate::codex_resource::{PodCodexResource, ValidatedCodexResourceLaunch};
use crate::linux_peer::LinuxPeerEvidence;
use crate::manifest::{
    BoundPeerManifest, BoundPodStatus, CODEX_V2_CAPABILITY, LaunchDescriptor,
    OPERATOR_PROCESS_CAPABILITY, OPERATOR_PROCESS_PROFILE_REF,
    PEER_BINDING_PROTOCOL, PEER_BINDING_V2_PROTOCOL, PROTOCOL, PodError, PodManifest,
    PodPeerBootstrap, PodRole, PodStatus, SYNTHETIC_CAPABILITY, hex, manifest_path,
    private_directory, read_manifest, unit_name, write_manifest,
};
use crate::native_events::{
    CODEX_NATIVE_EVENTS_READ_PROTOCOL, NativeEventCursor, NativeEventRead,
    NativeEventsReadReply, NativeEventsReadRequest, identity_from_manifest,
};
use crate::peer_checkpoint::{
    PeerCheckpointError, read_peer_checkpoint, read_peer_checkpoint_observation,
    write_peer_checkpoint,
};
use crate::ports::{
    DurableAppendLog, DurableFileIdentity, DurableFiles, LocalControlTransport, PodControlPort,
    PodObservation, SupervisorBackend, TerminalBackend, TerminalResource, TerminalViewerPort,
};
use crate::rebind_protocol::{
    decode_activate_request, decode_active_response, decode_pending_response, decode_request,
    encode_activate_request, encode_active_response, encode_pending_response, encode_request,
};
use crate::terminal::{PtyProcess, TerminalCommand, TerminalReply};

const FRAME_LIMIT: u64 = 1_048_576;
const MAX_HELD_LOG_BYTES: u64 = 64 * 1_048_576;
const INSPECT_PROTOCOL: &str = "podbay.rebind-inspect/1";

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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RebindInspectRequest {
    protocol: String,
    operation: String,
    nonce: String,
    scope_id: String,
    pod_id: String,
    attempt_id: String,
    incarnation: u64,
    store_lineage: String,
    owner_epoch: u64,
    credential_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RebindInspection {
    pub protocol: String,
    pub nonce: String,
    pub scope_id: String,
    pub pod_id: String,
    pub attempt_id: String,
    pub incarnation: u64,
    pub store_lineage: String,
    pub prior_owner_epoch: u64,
    pub prior_credential_epoch: u64,
    pub prior_input_epochs: BTreeMap<String, u64>,
    pub checkpoint_digest: String,
    pub supervisor_pid: u32,
    pub supervisor_start_ticks: u64,
    pub child_pid: u32,
    pub child_start_ticks: u64,
    pub boot_id: String,
    pub unit_name: String,
    pub cgroup_path: String,
}

trait CurrentManagerPeerMatch {
    fn matches_current(&self, owner: u64, credential: u64, peer: &AttestedPeer) -> bool;
}
impl CurrentManagerPeerMatch for SqliteManagerPeerWitness {
    fn matches_current(&self, owner: u64, credential: u64, peer: &AttestedPeer) -> bool {
        SqliteManagerPeerWitness::matches_current(self, owner, credential, peer)
    }
}

fn valid_inspect_nonce(nonce: &str) -> bool {
    (16..=128).contains(&nonce.len())
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn inspect_allowed(
    request: &RebindInspectRequest,
    identity: &PodFenceIdentity,
    checkpoint: &PodFenceCheckpoint,
    fence: &PodPeerFence,
    observed_peer: &AttestedPeer,
    owner_witness: &impl OwnerEpochWitness,
    manager_witness: &impl CurrentManagerPeerMatch,
) -> bool {
    if !valid_inspect_nonce(&request.nonce)
        || request.protocol != INSPECT_PROTOCOL
        || request.operation != "rebind.inspect"
        || request.scope_id != identity.scope_id.as_str()
        || request.pod_id != identity.pod_id.as_str()
        || request.attempt_id != identity.attempt_id.as_str()
        || request.incarnation != identity.incarnation.get()
        || request.store_lineage != identity.store_lineage.as_str()
        || checkpoint.identity() != identity
        || checkpoint != &fence.checkpoint()
        || checkpoint.phase() != RebindPhase::Active
        || observed_peer == checkpoint.manager_peer()
        || observed_peer.containment_identity() != checkpoint.manager_containment()
        || request.owner_epoch <= checkpoint.owner_epoch().get()
        || request.credential_epoch <= checkpoint.credential_epoch().get()
    {
        return false;
    }
    let Ok(owner) = OwnerEpoch::new(request.owner_epoch) else {
        return false;
    };
    owner_witness.current_owner_epoch(&identity.store_lineage, &identity.scope_id) == Some(owner)
        && manager_witness.matches_current(
            request.owner_epoch,
            request.credential_epoch,
            observed_peer,
        )
}

fn persist_pending_rebind_checkpoint(
    fence: &mut PodPeerFence,
    proposal: &RebindProposal,
    peer: &AttestedPeer,
    old_liveness: ManagerLiveness,
    witness: &impl OwnerEpochWitness,
    ledger: &impl RebindLedger,
    now_ms: u64,
    mut persist: impl FnMut(&PodFenceCheckpoint) -> Result<String, PodError>,
) -> Result<String, PodError> {
    fence.prepare_rebind(
        proposal.clone(), peer, old_liveness, witness, ledger, now_ms,
    ).map_err(|_| PodError::Refused("V2 rebind fence refused prepare"))?;
    if fence.phase() == RebindPhase::PendingStore {
        persist(&fence.checkpoint())?;
        fence.confirm_pod_bound(proposal, peer, witness, ledger)
            .map_err(|_| PodError::Refused("V2 rebind fence refused Pod binding"))?;
    }
    if fence.phase() != RebindPhase::PendingPod {
        return Err(PodError::Refused("V2 rebind did not reach PendingPod"));
    }
    persist(&fence.checkpoint())
}

enum ChildResource {
    Pipe(Child),
    Pty(Box<dyn TerminalResource>),
    Codex(PodCodexResource),
}

impl ChildResource {
    fn id(&self) -> Result<u32, PodError> {
        match self {
            Self::Pipe(child) => Ok(child.id()),
            Self::Pty(pty) => pty
                .process_identity()?
                .parse()
                .map_err(|_| PodError::Invalid("Linux PTY process ID")),
            Self::Codex(resource) => Ok(resource.pid()),
        }
    }
    fn try_wait(&mut self) -> Result<Option<Option<i32>>, PodError> {
        match self {
            Self::Pipe(child) => Ok(child.try_wait()?.map(|status| status.code())),
            Self::Pty(pty) => Ok(pty.try_wait()?.map(Some)),
            Self::Codex(resource) => resource.try_wait(),
        }
    }
    fn kill(&mut self) -> Result<(), PodError> {
        match self {
            Self::Pipe(child) => child.kill().map_err(PodError::from),
            Self::Pty(pty) => pty.stop(),
            Self::Codex(resource) => resource.stop(),
        }
    }
}

pub struct PodClient {
    manifest_path: PathBuf,
    manifest: PodManifest,
    pinned_manifest: Option<PinnedManifest>,
}

/// Cheap per-status file proof after one full manifest/descriptor validation.
/// Every read still checks the exact path, inode, owner, mode and bytes; the
/// executable hash is checked once before polling and once on acceptance.
struct PinnedManifest {
    dev: u64,
    ino: u64,
    len: u64,
    uid: u32,
    mode: u32,
    bytes: Vec<u8>,
}

impl PinnedManifest {
    fn capture(path: &Path, manifest: &PodManifest) -> Result<Self, PodError> {
        let (metadata, bytes) = Self::read_exact(path)?;
        if bytes != serde_json::to_vec(manifest)? {
            return Err(PodError::Refused("validated pod manifest bytes differ"));
        }
        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            len: metadata.len(),
            uid: metadata.uid(),
            mode: metadata.mode() & 0o7777,
            bytes,
        })
    }

    fn recheck(&self, path: &Path) -> Result<(), PodError> {
        let (metadata, bytes) = Self::read_exact(path)
            .map_err(|_| PodError::Refused("pinned pod manifest is unavailable"))?;
        if metadata.dev() != self.dev
            || metadata.ino() != self.ino
            || metadata.len() != self.len
            || metadata.uid() != self.uid
            || metadata.mode() & 0o7777 != self.mode
            || bytes != self.bytes
        {
            return Err(PodError::Refused("pinned pod manifest changed"));
        }
        Ok(())
    }

    fn read_exact(path: &Path) -> Result<(fs::Metadata, Vec<u8>), PodError> {
        let parent = path.parent().ok_or(PodError::Invalid("manifest parent"))?;
        private_directory(parent)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        let at_path = fs::symlink_metadata(path)?;
        if !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > 65_536
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != fs::metadata(parent)?.uid()
            || metadata.nlink() != 1
            || metadata.dev() != at_path.dev()
            || metadata.ino() != at_path.ino()
            || fs::canonicalize(path)? != path
        {
            return Err(PodError::Refused("pinned pod manifest file identity changed"));
        }
        let mut bytes = vec![0; metadata.len() as usize];
        file.read_exact(&mut bytes)?;
        let after = file.metadata()?;
        let path_after = fs::symlink_metadata(path)?;
        if after.dev() != metadata.dev()
            || after.ino() != metadata.ino()
            || after.len() != metadata.len()
            || after.uid() != metadata.uid()
            || after.nlink() != metadata.nlink()
            || after.mode() & 0o7777 != metadata.mode() & 0o7777
            || path_after.dev() != metadata.dev()
            || path_after.ino() != metadata.ino()
        {
            return Err(PodError::Refused("pinned pod manifest changed during read"));
        }
        Ok((metadata, bytes))
    }
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

/// One Linux file descriptor remains pinned from open through every read and
/// append. The path and parent are checked against those identities each time;
/// a failed write/sync poisons this handle rather than inviting a retry.
struct LinuxHeldAppendLog {
    file: File,
    path: PathBuf,
    parent: PathBuf,
    parent_identity: (u64, u64),
    identity: DurableFileIdentity,
    native_identity: (u64, u64),
    max_bytes: u64,
    known_len: u64,
    poisoned: bool,
    #[cfg(test)]
    fail_next_partial: bool,
}

impl LinuxHeldAppendLog {
    fn open(path: &Path, max_bytes: u64) -> Result<Self, PodError> {
        if !path.is_absolute()
            || path.as_os_str().len() > 4_096
            || !(1..=MAX_HELD_LOG_BYTES).contains(&max_bytes)
        {
            return Err(PodError::Invalid("private append log path or bound"));
        }
        let parent = path
            .parent()
            .ok_or(PodError::Invalid("private append log parent"))?;
        private_directory(parent)?;
        let parent_metadata = fs::symlink_metadata(parent)?;
        let parent_identity = (parent_metadata.dev(), parent_metadata.ino());
        let mut created = false;
        let file = match OpenOptions::new()
            .read(true)
            .append(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(file) => {
                created = true;
                file
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => OpenOptions::new()
                .read(true)
                .append(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?,
            Err(error) => return Err(error.into()),
        };
        if created {
            file.sync_all()
                .map_err(|_| PodError::Uncertain("private append log create sync unknown"))?;
            File::open(parent)?
                .sync_all()
                .map_err(|_| PodError::Uncertain("private append log directory sync unknown"))?;
        }
        let metadata = file.metadata()?;
        let native_identity = (metadata.dev(), metadata.ino());
        let mut native = Vec::with_capacity(16);
        native.extend_from_slice(&metadata.dev().to_be_bytes());
        native.extend_from_slice(&metadata.ino().to_be_bytes());
        let mut held = Self {
            file,
            path: path.to_path_buf(),
            parent: parent.to_path_buf(),
            parent_identity,
            identity: DurableFileIdentity::from_backend("linux.dev-ino/1", native)?,
            native_identity,
            max_bytes,
            known_len: metadata.len(),
            poisoned: false,
            #[cfg(test)]
            fail_next_partial: false,
        };
        held.recheck()?;
        Ok(held)
    }

    fn recheck(&mut self) -> Result<(), PodError> {
        if self.poisoned {
            return Err(PodError::Uncertain(
                "private append log handle is uncertain",
            ));
        }
        let result = self.check_current();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn check_current(&self) -> Result<(), PodError> {
        private_directory(&self.parent)?;
        let parent = fs::symlink_metadata(&self.parent)?;
        let handle = self.file.metadata()?;
        let path = fs::symlink_metadata(&self.path)?;
        if (parent.dev(), parent.ino()) != self.parent_identity
            || !handle.is_file()
            || !path.is_file()
            || (handle.dev(), handle.ino()) != self.native_identity
            || (path.dev(), path.ino()) != self.native_identity
            || handle.uid() != parent.uid()
            || path.uid() != parent.uid()
            || handle.mode() & 0o7777 != 0o600
            || path.mode() & 0o7777 != 0o600
            || handle.nlink() != 1
            || path.nlink() != 1
            || handle.len() > self.max_bytes
            || path.len() > self.max_bytes
            || fs::canonicalize(&self.path)? != self.path
        {
            return Err(PodError::Refused(
                "private append log identity or privacy changed",
            ));
        }
        if handle.len() != self.known_len || path.len() != self.known_len {
            return Err(PodError::Uncertain(
                "private append log length changed outside owner",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    fn fail_one_partial_append(&mut self) {
        self.fail_next_partial = true;
    }
}

impl DurableAppendLog for LinuxHeldAppendLog {
    fn identity(&self) -> &DurableFileIdentity {
        &self.identity
    }

    fn len(&self) -> u64 {
        self.known_len
    }

    fn read_all_bounded(&mut self) -> Result<Vec<u8>, PodError> {
        self.recheck()?;
        if self.file.seek(SeekFrom::Start(0)).is_err() {
            self.poisoned = true;
            return Err(PodError::Uncertain(
                "private append log read position unknown",
            ));
        }
        let mut bytes = vec![0; self.known_len as usize];
        if self.file.read_exact(&mut bytes).is_err() {
            self.poisoned = true;
            return Err(PodError::Uncertain("private append log read changed"));
        }
        self.recheck()?;
        Ok(bytes)
    }

    fn append_synced(&mut self, bytes: &[u8]) -> Result<(), PodError> {
        if bytes.is_empty() || bytes.len() > FRAME_LIMIT as usize {
            return Err(PodError::Invalid("private append log record bound"));
        }
        let expected_len = self
            .known_len
            .checked_add(bytes.len() as u64)
            .filter(|value| *value <= self.max_bytes)
            .ok_or(PodError::Refused(
                "private append log retention bound reached",
            ))?;
        self.recheck()?;
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_partial) {
            let partial = bytes.len().div_ceil(2);
            let _ = self.file.write_all(&bytes[..partial]);
            self.poisoned = true;
            return Err(PodError::Uncertain(
                "synthetic private append partial write",
            ));
        }
        if self.file.write_all(bytes).is_err() || self.file.sync_data().is_err() {
            self.poisoned = true;
            return Err(PodError::Uncertain(
                "private append log write or sync unknown",
            ));
        }
        let actual_len = match self.file.metadata() {
            Ok(metadata) => metadata.len(),
            Err(_) => {
                self.poisoned = true;
                return Err(PodError::Uncertain(
                    "private append log length after write unknown",
                ));
            }
        };
        if actual_len != expected_len {
            self.poisoned = true;
            return Err(PodError::Uncertain(
                "private append log length after write unknown",
            ));
        }
        self.known_len = expected_len;
        if self.recheck().is_err() {
            self.poisoned = true;
            return Err(PodError::Uncertain(
                "private append log changed after write",
            ));
        }
        Ok(())
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

    fn open_private_append_log(
        &self,
        path: &Path,
        max_bytes: u64,
    ) -> Result<Box<dyn DurableAppendLog>, PodError> {
        LinuxHeldAppendLog::open(path, max_bytes)
            .map(|held| Box::new(held) as Box<dyn DurableAppendLog>)
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
    /// A restarted manager can inspect without the old status handshake or
    /// old manifest bearer. The pod authenticates this socket's OS peer.
    pub fn inspect_rebind(
        manifest_path: impl AsRef<Path>,
        expected: &PodFenceIdentity,
        owner_epoch: u64,
        credential_epoch: u64,
    ) -> Result<RebindInspection, PodError> {
        if owner_epoch == 0 || credential_epoch == 0 {
            return Err(PodError::Invalid("rebind inspect request bounds"));
        }
        let mut nonce_bytes = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut nonce_bytes)?;
        let nonce = hex(&nonce_bytes);
        let manifest = read_manifest(manifest_path.as_ref())?;
        let binding = manifest.peer_binding.as_ref().ok_or(PodError::Unsupported(
            "unbound rebind inspect is unavailable",
        ))?;
        if bound_identity(&manifest.descriptor, binding)? != *expected {
            return Err(PodError::Refused("rebind inspect identity differs"));
        }
        let request = RebindInspectRequest {
            protocol: INSPECT_PROTOCOL.into(),
            operation: "rebind.inspect".into(),
            nonce: nonce.clone(),
            scope_id: expected.scope_id.as_str().into(),
            pod_id: expected.pod_id.as_str().into(),
            attempt_id: expected.attempt_id.as_str().into(),
            incarnation: expected.incarnation.get(),
            store_lineage: expected.store_lineage.as_str().into(),
            owner_epoch,
            credential_epoch,
        };
        let (bytes, server_peer) =
            inspect_exchange(&manifest.socket_path, &serde_json::to_vec(&request)?)?;
        if !unit_cgroup_exact(server_peer.cgroup(), &manifest.unit_name)
            || server_peer.attested_peer().os_identity() != binding.manager_os_identity
            || server_peer.attested_peer().boot_identity() != binding.manager_boot_identity
        {
            return Err(PodError::Refused(
                "inspect server is outside bound pod identity",
            ));
        }
        let response: RebindInspection = match serde_json::from_slice(&bytes) {
            Ok(response) => response,
            Err(_) => {
                if serde_json::from_slice::<Response>(&bytes).is_ok_and(|response| !response.ok) {
                    return Err(PodError::Refused("rebind inspect refused"));
                }
                return Err(PodError::Invalid("rebind inspect response malformed"));
            }
        };
        let digest_valid = response.checkpoint_digest.len() == 64
            && response
                .checkpoint_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if response.protocol != INSPECT_PROTOCOL
            || response.nonce != nonce
            || response.scope_id != expected.scope_id.as_str()
            || response.pod_id != expected.pod_id.as_str()
            || response.attempt_id != expected.attempt_id.as_str()
            || response.incarnation != expected.incarnation.get()
            || response.store_lineage != expected.store_lineage.as_str()
            || response.prior_owner_epoch >= owner_epoch
            || response.prior_credential_epoch >= credential_epoch
            || response.prior_input_epochs.is_empty()
            || !response
                .prior_input_epochs
                .keys()
                .eq(binding.resource_input_epochs.keys())
            || response
                .prior_input_epochs
                .values()
                .any(|epoch| *epoch == 0)
            || !digest_valid
            || response.supervisor_pid == 0
            || response.supervisor_start_ticks == 0
            || response.child_pid == 0
            || response.child_start_ticks == 0
            || response.boot_id.is_empty()
            || response.unit_name != manifest.unit_name
            || !unit_cgroup_exact(&response.cgroup_path, &manifest.unit_name)
            || response.supervisor_pid != server_peer.pid() as u32
            || response.supervisor_start_ticks != server_peer.start_ticks()
            || response.boot_id != server_peer.boot_id()
            || response.cgroup_path != server_peer.cgroup()
        {
            return Err(PodError::Invalid(
                "rebind inspect response identity differs",
            ));
        }
        Ok(response)
    }

    /// A trusted manager sends only the exact already-Pending proposal; the
    /// pod authenticates this connection's OS peer and checks the durable
    /// proof itself before changing its fence. No old manifest bearer enters.
    pub fn prepare_rebind(
        manifest_path: impl AsRef<Path>,
        proposal: &RebindProposal,
        prior_checkpoint_digest: &str,
    ) -> Result<String, PodError> {
        let manifest = read_manifest(manifest_path.as_ref())?;
        let binding = manifest.peer_binding.as_ref().ok_or(PodError::Unsupported(
            "unbound rebind prepare is unavailable",
        ))?;
        if bound_identity(&manifest.descriptor, binding)? != proposal.identity {
            return Err(PodError::Refused("rebind prepare Pod identity differs"));
        }
        let mut nonce_bytes = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut nonce_bytes)?;
        let nonce = hex(&nonce_bytes);
        let request = encode_request(proposal, prior_checkpoint_digest, &nonce)?;
        let (response, peer) = inspect_exchange(&manifest.socket_path, &request)
            .map_err(|_| PodError::Uncertain("rebind prepare reply lost after possible fsync"))?;
        if !unit_cgroup_exact(peer.cgroup(), &manifest.unit_name)
            || peer.attested_peer().os_identity() != binding.manager_os_identity
            || peer.attested_peer().boot_identity() != binding.manager_boot_identity
        {
            return Err(PodError::Uncertain("rebind prepare server identity differs"));
        }
        decode_pending_response(&response, &proposal.identity, &nonce)
            .map_err(|_| PodError::Uncertain("rebind prepare reply is not an exact PendingPod proof"))
    }

    /// The store must already have committed Activated for this exact
    /// PendingPod checkpoint. A lost reply remains uncertain, never a claim
    /// that ordinary control resumed.
    pub fn activate_rebind(
        manifest_path: impl AsRef<Path>,
        proposal: &RebindProposal,
        prior_checkpoint_digest: &str,
        pending_checkpoint_digest: &str,
    ) -> Result<String, PodError> {
        let manifest = read_manifest(manifest_path.as_ref())?;
        let binding = manifest.peer_binding.as_ref().ok_or(PodError::Unsupported(
            "unbound rebind activation is unavailable",
        ))?;
        if bound_identity(&manifest.descriptor, binding)? != proposal.identity {
            return Err(PodError::Refused("rebind activation Pod identity differs"));
        }
        let mut nonce_bytes = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut nonce_bytes)?;
        let nonce = hex(&nonce_bytes);
        let request = encode_activate_request(
            proposal,
            prior_checkpoint_digest,
            pending_checkpoint_digest,
            &nonce,
        )?;
        let (response, peer) = inspect_exchange(&manifest.socket_path, &request)
            .map_err(|_| PodError::Uncertain("rebind activation reply lost after possible fsync"))?;
        if !unit_cgroup_exact(peer.cgroup(), &manifest.unit_name)
            || peer.attested_peer().os_identity() != binding.manager_os_identity
            || peer.attested_peer().boot_identity() != binding.manager_boot_identity
        {
            return Err(PodError::Uncertain("rebind activation server identity differs"));
        }
        decode_active_response(&response, &proposal.identity, &nonce)
            .map_err(|_| PodError::Uncertain("rebind activation reply is not an exact Active proof"))
    }

    pub fn connect(path: impl AsRef<Path>) -> Result<Self, PodError> {
        let path = path.as_ref();
        let manifest = read_manifest(path)?;
        if manifest.peer_binding.is_none() {
            return Err(PodError::Unsupported("unbound pod control is retired"));
        }
        let client = Self {
            manifest_path: path.to_path_buf(),
            manifest,
            pinned_manifest: None,
        };
        client.status()?;
        Ok(client)
    }

    /// Launch-only path after `read_manifest` has fully validated the
    /// descriptor, including the executable hash. Polls recheck its exact
    /// private file identity and bytes without repeating that large hash.
    pub(crate) fn from_validated_manifest(
        path: &Path,
        manifest: PodManifest,
    ) -> Result<Self, PodError> {
        if manifest.peer_binding.is_none() {
            return Err(PodError::Unsupported("unbound pod control is retired"));
        }
        let pinned_manifest = PinnedManifest::capture(path, &manifest)?;
        Ok(Self {
            manifest_path: path.to_path_buf(),
            manifest,
            pinned_manifest: Some(pinned_manifest),
        })
    }

    pub fn manifest_path(&self) -> Result<&Path, PodError> {
        Ok(&self.manifest_path)
    }

    pub fn status(&self) -> Result<PodObservation, PodError> {
        self.request("status").map(Into::into)
    }

    /// Read one status from the exact connected Unix peer, retaining its
    /// kernel PID/UID and procfs birth, boot and cgroup across the bounded
    /// exchange. The returned bound status belongs to that same reply. This
    /// proves a process in the expected unit, not systemd MainPID or hostile
    /// same-UID isolation; those require separate platform evidence.
    pub fn attested_status(&self) -> Result<PodStatus, PodError> {
        if let Some(pinned) = &self.pinned_manifest {
            pinned.recheck(&self.manifest_path)?;
        }
        let request = Request {
            protocol: PROTOCOL.to_owned(),
            pod_id: self.manifest.descriptor.pod_id.clone(),
            attempt_id: self.manifest.descriptor.attempt_id.clone(),
            incarnation: self.manifest.descriptor.incarnation,
            token: self.manifest.token.clone(),
            operation: "status".into(),
            terminal: None,
        };
        let (bytes, observed) =
            inspect_exchange(&self.manifest.socket_path, &serde_json::to_vec(&request)?)?;
        let response: Response = serde_json::from_slice(&bytes)?;
        if !response.ok {
            return Err(PodError::Refused("pod rejected authenticated status"));
        }
        let status = response
            .status
            .ok_or(PodError::Invalid("pod status missing"))?;
        attest(&self.manifest, &status)?;
        let fresh_manifest = if let Some(pinned) = &self.pinned_manifest {
            pinned.recheck(&self.manifest_path)?;
            None
        } else {
            Some(read_manifest(&self.manifest_path)?)
        };
        let metadata = fs::symlink_metadata(&self.manifest_path).map_err(|error| {
            if self.pinned_manifest.is_some() {
                PodError::Refused("pinned pod manifest path is unavailable")
            } else {
                PodError::Io(error)
            }
        })?;
        let current = LinuxPeerEvidence::for_current_process()
            .map_err(|_| PodError::Refused("client OS identity unavailable"))?;
        let manifest_changed = if let Some(fresh) = &fresh_manifest {
            serde_json::to_vec(fresh)? != serde_json::to_vec(&self.manifest)?
        } else {
            false
        };
        if manifest_changed
            || observed.uid() != metadata.uid()
            || observed.uid() != current.uid()
            || status.supervisor_pid != observed.pid() as u32
            || status.supervisor_start_ticks != observed.start_ticks()
            || status.boot_id != observed.boot_id()
            || status.cgroup_path != observed.cgroup()
            || status.unit_name != self.manifest.unit_name
            || !unit_cgroup_exact(observed.cgroup(), &self.manifest.unit_name)
        {
            return Err(PodError::Refused("pod status server OS identity differs"));
        }
        Ok(status)
    }

    /// Submit only an already-claimed bootstrap selector. The pod obtains
    /// protected prompt bytes from the committed store row. Any loss after a
    /// possible socket write is uncertain and must never cause a blind retry.
    pub fn submit_claimed_codex_bootstrap(
        &self,
        command_id: &CommandId,
        target: &NativeWriterTarget,
        writer_epoch: u64,
    ) -> Result<BootstrapControlReceipt, PodError> {
        let binding = active_codex_v2_binding(&self.manifest)?;
        if binding.protocol != PEER_BINDING_V2_PROTOCOL || binding.capability != CODEX_V2_CAPABILITY {
            return Err(PodError::Unsupported("Codex bootstrap requires V2"));
        }
        let selector = BootstrapSendSelector {
            scope_id: target.scope_id.clone(),
            command_id: command_id.clone(),
            native_target: target.clone(),
        };
        let request = BootstrapControlRequest::from_selector(&selector, writer_epoch, &self.manifest.token);
        request.checked_selector(&binding, &self.manifest.descriptor)?;
        let bytes = serde_json::to_vec(&request)?;
        if bytes.len() as u64 > FRAME_LIMIT {
            return Err(PodError::Invalid("bootstrap request exceeds frame bound"));
        }
        let mut socket = UnixStream::connect(&self.manifest.socket_path)?;
        socket.set_read_timeout(Some(Duration::from_secs(75)))?;
        socket.set_write_timeout(Some(Duration::from_secs(3)))?;
        let observed = LinuxPeerEvidence::from_connected(&socket)
            .map_err(|_| PodError::Refused("bootstrap server OS identity unavailable"))?;
        socket.write_all(&bytes).map_err(|_| PodError::Uncertain(
            "bootstrap socket write may have reached pod"))?;
        socket.shutdown(std::net::Shutdown::Write).map_err(|_| PodError::Uncertain(
            "bootstrap request completion unknown"))?;
        let mut reply = Vec::new();
        (&mut socket).take(FRAME_LIMIT + 1).read_to_end(&mut reply)
            .map_err(|_| PodError::Uncertain("bootstrap reply lost after possible effect"))?;
        if reply.len() as u64 > FRAME_LIMIT {
            return Err(PodError::Uncertain("bootstrap reply exceeds frame bound"));
        }
        observed.recheck_connected(&socket)
            .map_err(|_| PodError::Uncertain("bootstrap server changed after possible effect"))?;
        let fresh_manifest = read_manifest(&self.manifest_path)
            .map_err(|_| PodError::Uncertain("bootstrap manifest changed after possible effect"))?;
        let metadata = fs::symlink_metadata(&self.manifest_path)
            .map_err(|_| PodError::Uncertain("bootstrap manifest unavailable after possible effect"))?;
        let current = LinuxPeerEvidence::for_current_process()
            .map_err(|_| PodError::Uncertain("bootstrap client OS identity unavailable"))?;
        if serde_json::to_vec(&fresh_manifest)
            .map_err(|_| PodError::Uncertain("bootstrap manifest encoding unknown"))?
            != serde_json::to_vec(&self.manifest)
                .map_err(|_| PodError::Uncertain("bootstrap manifest encoding unknown"))?
            || observed.uid() != metadata.uid()
            || observed.uid() != current.uid()
            || !unit_cgroup_exact(observed.cgroup(), &self.manifest.unit_name)
        {
            return Err(PodError::Uncertain("bootstrap server identity differs after possible effect"));
        }
        let response: BootstrapControlReceipt = serde_json::from_slice(&reply)
            .map_err(|_| PodError::Uncertain("bootstrap reply malformed after possible effect"))?;
        if response.protocol != CODEX_BOOTSTRAP_PROTOCOL
            || response.command_id != command_id.as_str()
            || response.store_lineage != target.store_lineage.as_str()
            || response.scope_id != target.scope_id.as_str()
            || response.session_id != target.session_id.as_str()
            || response.run_id != target.run_id.as_str()
            || response.attempt_id != target.attempt_id.as_str()
            || response.pod_id != target.pod_id.as_str()
            || response.pod_incarnation != target.pod_incarnation
            || response.resource_id != target.resource_id.as_str()
            || response.resource_epoch != target.resource_epoch
            || response.resource_input_epoch != target.resource_input_epoch
            || response.writer_epoch != writer_epoch
            || response.settlement.is_some()
            || !matches!(response.stage, BootstrapControlStage::RefusedBeforeEffect)
                && !response.request_digest.as_ref().is_some_and(|digest| {
                    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
        {
            return Err(PodError::Uncertain("bootstrap reply identity differs"));
        }
        let native_id = |value: &str| {
            !value.is_empty() && value.len() <= 512 && value.trim() == value
                && !value.chars().any(char::is_control)
        };
        let ids_valid = match &response.stage {
            BootstrapControlStage::ClaimedUnobserved => false,
            BootstrapControlStage::RefusedBeforeEffect
            | BootstrapControlStage::ThreadCreateUncertain => true,
            BootstrapControlStage::ThreadCreated { native_thread_id, native_session_id }
            | BootstrapControlStage::BootstrapUncertain { native_thread_id, native_session_id } =>
                native_id(native_thread_id) && native_id(native_session_id),
            BootstrapControlStage::Submitted { native_thread_id, native_session_id, native_turn_id } =>
                native_id(native_thread_id) && native_id(native_session_id) && native_id(native_turn_id),
        };
        if !ids_valid {
            return Err(PodError::Uncertain("bootstrap native receipt identity is invalid"));
        }
        Ok(response)
    }

    /// Reconcile a previously claimed send from the exact connected pod and
    /// its held journal. This operation sends no native input and never
    /// upgrades an absent journal to provider submission.
    pub fn inspect_claimed_codex_bootstrap(
        &self,
        command_id: &CommandId,
        target: &NativeWriterTarget,
        writer_epoch: u64,
    ) -> Result<BootstrapControlReceipt, PodError> {
        let binding = active_codex_v2_binding(&self.manifest)?;
        if binding.protocol != PEER_BINDING_V2_PROTOCOL || binding.capability != CODEX_V2_CAPABILITY {
            return Err(PodError::Unsupported("Codex bootstrap inspection requires V2"));
        }
        let selector = BootstrapSendSelector {
            scope_id: target.scope_id.clone(),
            command_id: command_id.clone(),
            native_target: target.clone(),
        };
        let request = BootstrapControlRequest::for_inspection(&selector, writer_epoch, &self.manifest.token);
        request.checked_inspection_selector(&binding, &self.manifest.descriptor)?;
        let bytes = serde_json::to_vec(&request)?;
        if bytes.len() as u64 > FRAME_LIMIT {
            return Err(PodError::Invalid("bootstrap inspection request exceeds frame bound"));
        }
        let mut socket = UnixStream::connect(&self.manifest.socket_path)?;
        socket.set_read_timeout(Some(Duration::from_secs(10)))?;
        socket.set_write_timeout(Some(Duration::from_secs(3)))?;
        let observed = LinuxPeerEvidence::from_connected(&socket)
            .map_err(|_| PodError::Refused("bootstrap inspection server OS identity unavailable"))?;
        socket.write_all(&bytes).map_err(|_| PodError::Uncertain(
            "bootstrap inspection request may have reached pod"))?;
        socket.shutdown(std::net::Shutdown::Write).map_err(|_| PodError::Uncertain(
            "bootstrap inspection request completion unknown"))?;
        let mut reply = Vec::new();
        (&mut socket).take(FRAME_LIMIT + 1).read_to_end(&mut reply)
            .map_err(|_| PodError::Uncertain("bootstrap inspection reply lost"))?;
        if reply.len() as u64 > FRAME_LIMIT {
            return Err(PodError::Uncertain("bootstrap inspection reply exceeds frame bound"));
        }
        observed.recheck_connected(&socket)
            .map_err(|_| PodError::Uncertain("bootstrap inspection server changed"))?;
        let fresh_manifest = read_manifest(&self.manifest_path)
            .map_err(|_| PodError::Uncertain("bootstrap inspection manifest changed"))?;
        let metadata = fs::symlink_metadata(&self.manifest_path)
            .map_err(|_| PodError::Uncertain("bootstrap inspection manifest unavailable"))?;
        let current = LinuxPeerEvidence::for_current_process()
            .map_err(|_| PodError::Uncertain("bootstrap inspection client identity unavailable"))?;
        if serde_json::to_vec(&fresh_manifest)
            .map_err(|_| PodError::Uncertain("bootstrap inspection manifest encoding unknown"))?
            != serde_json::to_vec(&self.manifest)
                .map_err(|_| PodError::Uncertain("bootstrap inspection manifest encoding unknown"))?
            || observed.uid() != metadata.uid()
            || observed.uid() != current.uid()
            || !unit_cgroup_exact(observed.cgroup(), &self.manifest.unit_name)
        {
            return Err(PodError::Uncertain("bootstrap inspection server identity differs"));
        }
        let response: BootstrapControlReceipt = serde_json::from_slice(&reply)
            .map_err(|_| PodError::Uncertain("bootstrap inspection reply malformed"))?;
        let digest_valid = response.request_digest.as_ref().is_some_and(|digest| {
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
        if response.protocol != CODEX_BOOTSTRAP_INSPECT_PROTOCOL
            || response.command_id != command_id.as_str()
            || response.store_lineage != target.store_lineage.as_str()
            || response.scope_id != target.scope_id.as_str()
            || response.session_id != target.session_id.as_str()
            || response.run_id != target.run_id.as_str()
            || response.attempt_id != target.attempt_id.as_str()
            || response.pod_id != target.pod_id.as_str()
            || response.pod_incarnation != target.pod_incarnation
            || response.resource_id != target.resource_id.as_str()
            || response.resource_epoch != target.resource_epoch
            || response.resource_input_epoch != target.resource_input_epoch
            || response.writer_epoch != writer_epoch
            || (response.settlement.is_some()
                && !matches!(response.stage, BootstrapControlStage::Submitted { .. }))
            || (!matches!(response.stage, BootstrapControlStage::RefusedBeforeEffect) && !digest_valid)
        {
            return Err(PodError::Uncertain("bootstrap inspection reply identity differs"));
        }
        if response.stage == BootstrapControlStage::RefusedBeforeEffect {
            return Err(PodError::Refused("claimed bootstrap inspection refused"));
        }
        let native_id = |value: &str| {
            !value.is_empty() && value.len() <= 512 && value.trim() == value
                && !value.chars().any(char::is_control)
        };
        let ids_valid = match &response.stage {
            BootstrapControlStage::ClaimedUnobserved
            | BootstrapControlStage::ThreadCreateUncertain => true,
            BootstrapControlStage::ThreadCreated { native_thread_id, native_session_id }
            | BootstrapControlStage::BootstrapUncertain { native_thread_id, native_session_id } =>
                native_id(native_thread_id) && native_id(native_session_id),
            BootstrapControlStage::Submitted { native_thread_id, native_session_id, native_turn_id } =>
                native_id(native_thread_id) && native_id(native_session_id) && native_id(native_turn_id),
            BootstrapControlStage::RefusedBeforeEffect => false,
        };
        if !ids_valid {
            return Err(PodError::Uncertain("bootstrap inspection native identity is invalid"));
        }
        Ok(response)
    }

    /// One manager-only redacted snapshot and bounded events-after read. The
    /// cursor binds exact lineage/scope/Resource; no native input or replay
    /// of private JSONL occurs on this control path.
    pub fn read_codex_native_events(
        &self,
        cursor: Option<&NativeEventCursor>,
        limit: usize,
    ) -> Result<NativeEventRead, PodError> {
        let binding = self.manifest.peer_binding.as_ref()
            .ok_or(PodError::Unsupported("Codex event binding is unavailable"))?;
        if binding.protocol != PEER_BINDING_V2_PROTOCOL || binding.capability != CODEX_V2_CAPABILITY
            || !(1..=64).contains(&limit)
        {
            return Err(PodError::Unsupported("Codex event read requires bounded V2"));
        }
        let identity = identity_from_manifest(&self.manifest)?;
        if cursor.is_some_and(|cursor| cursor.identity != identity) {
            return Err(PodError::Refused("Codex event cursor belongs to another Resource"));
        }
        let request = NativeEventsReadRequest {
            protocol: CODEX_NATIVE_EVENTS_READ_PROTOCOL.into(),
            operation: "codex.events.read".into(),
            token: self.manifest.token.clone(),
            identity: identity.clone(),
            cursor: cursor.cloned(),
            limit,
        };
        let bytes = serde_json::to_vec(&request)?;
        if bytes.len() as u64 > FRAME_LIMIT {
            return Err(PodError::Invalid("Codex event read request exceeds bound"));
        }
        let mut socket = UnixStream::connect(&self.manifest.socket_path)?;
        socket.set_read_timeout(Some(Duration::from_secs(10)))?;
        socket.set_write_timeout(Some(Duration::from_secs(3)))?;
        let observed = LinuxPeerEvidence::from_connected(&socket)
            .map_err(|_| PodError::Refused("Codex event server OS identity unavailable"))?;
        socket.write_all(&bytes).map_err(|_| PodError::Uncertain("Codex event request may have reached pod"))?;
        socket.shutdown(std::net::Shutdown::Write)
            .map_err(|_| PodError::Uncertain("Codex event request completion unknown"))?;
        let mut reply = Vec::new();
        (&mut socket).take(FRAME_LIMIT + 1).read_to_end(&mut reply)
            .map_err(|_| PodError::Uncertain("Codex event reply lost"))?;
        if reply.len() as u64 > FRAME_LIMIT {
            return Err(PodError::Invalid("Codex event reply exceeds bound"));
        }
        observed.recheck_connected(&socket)
            .map_err(|_| PodError::Uncertain("Codex event server changed"))?;
        let fresh = read_manifest(&self.manifest_path)
            .map_err(|_| PodError::Uncertain("Codex event manifest changed"))?;
        let metadata = fs::symlink_metadata(&self.manifest_path)
            .map_err(|_| PodError::Uncertain("Codex event manifest unavailable"))?;
        let current = LinuxPeerEvidence::for_current_process()
            .map_err(|_| PodError::Uncertain("Codex event client identity unavailable"))?;
        if serde_json::to_vec(&fresh)? != serde_json::to_vec(&self.manifest)?
            || observed.uid() != metadata.uid()
            || observed.uid() != current.uid()
            || !unit_cgroup_exact(observed.cgroup(), &self.manifest.unit_name)
        {
            return Err(PodError::Refused("Codex event server identity differs"));
        }
        let response: NativeEventsReadReply = serde_json::from_slice(&reply)
            .map_err(|_| PodError::Invalid("Codex event reply is malformed"))?;
        if response.protocol != CODEX_NATIVE_EVENTS_READ_PROTOCOL || response.refused {
            return Err(PodError::Refused("Codex event read refused"));
        }
        let read = response.read.ok_or(PodError::Invalid("Codex event read omitted result"))?;
        if read.snapshot.identity != identity
            || read.next_cursor.identity != identity
            || read.next_cursor.sequence > read.snapshot.watermark
            || read.snapshot.earliest_retained > read.snapshot.watermark.saturating_add(1)
            || read.events.len() > limit
            || read.events.iter().any(|event| event.identity != identity
                || event.source_sequence > read.snapshot.watermark
                || event.committed_cursor != event.source_sequence
                || event.schema_version != 1
                || event.provenance != "codex.app-server.pod-observed/1"
                || event.event_id.len() != 71
                || !event.event_id.starts_with("native.")
                || !event.event_id[7..].bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(PodError::Invalid("Codex event read identity differs"));
        }
        let after = cursor.map(|cursor| cursor.sequence).unwrap_or(read.snapshot.watermark);
        if cursor.is_none() && (!read.events.is_empty() || read.gap.is_some()
            || read.next_cursor.sequence != read.snapshot.watermark)
        {
            return Err(PodError::Invalid("Codex snapshot read crossed its watermark"));
        }
        let mut expected = after.saturating_add(1);
        let mut saw_gap = false;
        for event in &read.events {
            if event.source_sequence > expected {
                if saw_gap || read.gap.as_ref().is_none_or(|gap|
                    gap.missing_from != expected
                        || gap.missing_through != event.source_sequence - 1
                        || gap.earliest_available != event.source_sequence)
                {
                    return Err(PodError::Invalid("Codex event sequence gap differs"));
                }
                saw_gap = true;
            } else if event.source_sequence != expected {
                return Err(PodError::Invalid("Codex event sequence is not monotonic"));
            }
            expected = event.source_sequence.saturating_add(1);
        }
        if saw_gap != read.gap.is_some()
            || read.next_cursor.sequence != read.events.last()
                .map(|event| event.source_sequence).unwrap_or(after)
        {
            return Err(PodError::Invalid("Codex event cursor or gap differs"));
        }
        Ok(read)
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

fn inspect_exchange(
    endpoint: &Path,
    request: &[u8],
) -> Result<(Vec<u8>, LinuxPeerEvidence), PodError> {
    if request.len() as u64 > FRAME_LIMIT {
        return Err(PodError::Invalid("inspect request exceeds bound"));
    }
    let mut socket = UnixStream::connect(endpoint)?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    socket.set_write_timeout(Some(Duration::from_secs(3)))?;
    let observed = LinuxPeerEvidence::from_connected(&socket)
        .map_err(|_| PodError::Refused("pod server OS identity unavailable"))?;
    socket.write_all(request)?;
    socket.shutdown(std::net::Shutdown::Write)?;
    let mut bytes = Vec::new();
    (&mut socket)
        .take(FRAME_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > FRAME_LIMIT {
        return Err(PodError::Invalid("inspect response exceeds bound"));
    }
    observed
        .recheck_connected(&socket)
        .map_err(|_| PodError::Refused("pod server process changed during inspect"))?;
    Ok((bytes, observed))
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
        role: match (wire.role(), wire.work_kind()) {
            (NativeRole::Worker, NativeWorkKind::Task) => PodRole::Worker,
            (NativeRole::Coordinator, NativeWorkKind::Service) => PodRole::Coordinator,
            _ => return Err(PodError::Unsupported("bound process role is unavailable")),
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
        capability: if wire.profile_ref() == OPERATOR_PROCESS_PROFILE_REF {
            OPERATOR_PROCESS_CAPABILITY.into()
        } else {
            SYNTHETIC_CAPABILITY.into()
        },
        wire_descriptor: record.descriptor,
        effective_spec: record.effective_spec,
        descriptor_digest: wire.digest().into(),
        effective_digest: effective.digest().into(),
        resource_epoch: record.resources[0].epoch,
        store_path: bootstrap.store_path,
        store_lineage: bootstrap.store_lineage,
        owner_epoch: bootstrap.owner_epoch,
        credential_epoch: bootstrap.credential_epoch,
        authority_revision: None,
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
    let operator_process = manifest.peer_binding.as_ref()
        .is_some_and(|binding| binding.capability == OPERATOR_PROCESS_CAPABILITY);
    let runtime_max = format!("--property=RuntimeMaxSec={}s", wire.wall_seconds());
    let tasks_max = if operator_process { "--property=TasksMax=128" } else { "--property=TasksMax=2" };
    let started = Command::new("systemd-run")
        .args([
            "--user",
            "--no-ask-password",
            "--collect",
            "--service-type=exec",
            "--property=KillMode=control-group",
            "--property=NoNewPrivileges=yes",
        ])
        .arg(runtime_max)
        .arg(tasks_max)
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

/// Recheck the manager's exact committed V2 launch through an existing
/// read-only store handle. The pod never becomes a second SQLite writer.
fn current_codex_v2_binding(
    binding: &BoundPeerManifest,
    descriptor: &LaunchDescriptor,
) -> Result<(), PodError> {
    let revision = binding
        .authority_revision
        .filter(|value| *value > 0)
        .ok_or(PodError::Refused("Codex V2 authority revision is missing"))?;
    let mut store = PodBayStore::open_existing_read_only(&binding.store_path)
        .map_err(|_| PodError::Refused("Codex V2 store witness unavailable"))?;
    let current = store
        .current_bound_pod_snapshot(&descriptor.scope_id, &descriptor.pod_id)
        .map_err(|_| PodError::Refused("Codex V2 committed launch is unavailable"))?;
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
    if current.store_lineage().as_str() != binding.store_lineage
        || current.owner_epoch().get() != binding.owner_epoch
        || current.authority_revision() != revision
        || current.pod_incarnation().get() != descriptor.incarnation
        || current.attempt_id().as_str() != descriptor.attempt_id
        || current.launch().format != BoundLaunchFormat::CodexV2
        || current.launch().descriptor != binding.wire_descriptor
        || current.launch().effective_spec != binding.effective_spec
        || current.launch().resources.len() != 1
        || current.launch().resources[0].id != descriptor.resource_id
        || current.launch().resources[0].epoch != binding.resource_epoch
        || current.resources().len() != 1
        || inputs != binding.resource_input_epochs
    {
        return Err(PodError::Refused("Codex V2 committed authority changed"));
    }
    Ok(())
}

/// Immutable manifest bytes still identify the original launch. Only the
/// current manager peer/epochs are projected from this pod's fsynced Active
/// checkpoint plus the exact Activated store row. This is a read-only view,
/// never a replacement manifest or an authority claim from JSON.
fn active_codex_v2_binding(manifest: &PodManifest) -> Result<BoundPeerManifest, PodError> {
    let original = manifest.peer_binding.as_ref().ok_or(PodError::Refused(
        "Codex V2 manifest binding is absent"))?;
    if original.protocol != PEER_BINDING_V2_PROTOCOL
        || original.capability != CODEX_V2_CAPABILITY
    {
        return Err(PodError::Unsupported("current Codex V2 binding unavailable"));
    }
    let identity = bound_identity(&manifest.descriptor, original)?;
    let directory = manifest.socket_path.parent().ok_or(PodError::Invalid(
        "Codex V2 socket parent is absent"))?;
    let observed = read_peer_checkpoint_observation(directory, &identity)
        .map_err(|_| PodError::Refused("current Codex V2 checkpoint unavailable"))?;
    let checkpoint = observed.checkpoint();
    if checkpoint.phase() != RebindPhase::Active {
        return Err(PodError::Refused("Codex V2 checkpoint is not Active"));
    }
    let Some(proposal) = checkpoint.last_rebind() else {
        if checkpoint.owner_epoch().get() != original.owner_epoch
            || checkpoint.credential_epoch().get() != original.credential_epoch
            || checkpoint.manager_peer() != &original.manager_peer()?
            || checkpoint.input_epochs().iter().map(|(id, epoch)| {
                (id.as_str().to_owned(), epoch.get())
            }).collect::<BTreeMap<_, _>>() != original.resource_input_epochs
        {
            return Err(PodError::Refused("initial Codex V2 checkpoint differs"));
        }
        current_codex_v2_binding(original, &manifest.descriptor)?;
        return Ok(original.clone());
    };
    if proposal.identity != identity
        || checkpoint.manager_peer() != &proposal.next_manager
        || checkpoint.owner_epoch() != proposal.next_owner_epoch
        || checkpoint.credential_epoch() != proposal.next_credential_epoch
        || checkpoint.input_epochs() != &proposal.next_input_epochs
    {
        return Err(PodError::Refused("Activated Codex V2 checkpoint differs"));
    }
    let mut store = PodBayStore::open_existing_read_only(&original.store_path)
        .map_err(|_| PodError::Refused("Activated Codex V2 store unavailable"))?;
    let row = store.lookup_prior_observed_rebind(proposal)
        .map_err(|_| PodError::Refused("Activated Codex V2 rebind proof unavailable"))?
        .ok_or(PodError::Refused("Activated Codex V2 rebind row absent"))?;
    let current = store.current_bound_pod_snapshot(
        &manifest.descriptor.scope_id, &manifest.descriptor.pod_id,
    ).map_err(|_| PodError::Refused("Activated Codex V2 target changed"))?;
    let claim = store.current_manager_credential_claim(proposal.next_owner_epoch.get())
        .map_err(|_| PodError::Refused("Activated Codex V2 manager claim changed"))?;
    if row.receipt.phase != podbay_store::DurableRebindPhase::Activated
        || row.receipt.pod_checkpoint_ref.is_none()
        || claim.store_lineage() != identity.store_lineage.as_str()
        || claim.credential_epoch() != proposal.next_credential_epoch.get()
        || !store.current_manager_peer_matches(&claim, checkpoint.manager_peer())
            .map_err(|_| PodError::Refused("Activated Codex V2 manager peer unavailable"))?
        || current.launch().descriptor != original.wire_descriptor
        || current.launch().effective_spec != original.effective_spec
    {
        return Err(PodError::Refused("Activated Codex V2 binding is stale"));
    }
    let mut live = original.clone();
    live.owner_epoch = checkpoint.owner_epoch().get();
    live.credential_epoch = checkpoint.credential_epoch().get();
    live.authority_revision = Some(current.authority_revision());
    live.resource_input_epochs = checkpoint.input_epochs().iter().map(|(id, epoch)| {
        (id.as_str().to_owned(), epoch.get())
    }).collect();
    live.manager_os_identity = checkpoint.manager_peer().os_identity().into();
    live.manager_process_id = checkpoint.manager_peer().native_process_id().into();
    live.manager_boot_identity = checkpoint.manager_peer().boot_identity().into();
    live.manager_birth_identity = checkpoint.manager_peer().birth_identity().into();
    live.manager_containment = checkpoint.manager_peer().containment_identity().into();
    live.binding_digest = live.digest()?;
    current_codex_v2_binding(&live, &manifest.descriptor)?;
    Ok(live)
}

/// Read-only dynamic manager projection for a trusted port. It grants no
/// control by itself; socket peer and current manager must still be checked.
pub fn current_bound_peer_binding(manifest_path: impl AsRef<Path>) -> Result<BoundPeerManifest, PodError> {
    let manifest = read_manifest(manifest_path.as_ref())?;
    active_codex_v2_binding(&manifest)
}

fn renew_and_authorize_manager_pod_control(
    fence: &mut PodPeerFence,
    peer: &AttestedPeer,
    request: &PeerRequest,
    owner_witness: &impl OwnerEpochWitness,
    os_peer_current: bool,
    manager_binding_current: bool,
    now_ms: u64,
) -> Result<(), podbay_core::FenceError> {
    if !os_peer_current {
        return Err(podbay_core::FenceError::WrongPeer);
    }
    if !manager_binding_current {
        return Err(podbay_core::FenceError::OwnerUnverified);
    }
    if request.identity != *fence.identity()
        || request.target != FenceTarget::Pod
        || !matches!(request.operation, FenceOperation::ObservePod | FenceOperation::StopPod)
        || request.input_epoch.is_some()
    {
        return Err(podbay_core::FenceError::WrongAssociation);
    }
    if request.owner_epoch != fence.owner_epoch()
        || request.credential_epoch != fence.credential_epoch()
    {
        return Err(podbay_core::FenceError::StaleEpoch);
    }
    fence.renew_existing_manager_pod_control(peer, &request.grant_id, owner_witness, now_ms)?;
    fence.authorize(peer, request, owner_witness, now_ms)
}

/// Capture a bounded private startup receipt without turning stdout into a
/// public terminal stream. The pod continues draining after the bound so a
/// chatty child cannot block on its pipe. This file is evidence for the local
/// process fixture, not a durable event cursor or provider acknowledgement.
fn spawn_operator_process(
    descriptor: &LaunchDescriptor,
    manifest_path: &Path,
) -> Result<Child, PodError> {
    fn private_output(path: &Path) -> Result<File, PodError> {
        Ok(OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?)
    }
    fn drain_bounded(mut reader: impl Read + Send + 'static, mut file: File) {
        std::thread::spawn(move || {
            let mut chunk = [0u8; 8192];
            let mut remaining = 1_048_576usize;
            while let Ok(count) = reader.read(&mut chunk) {
                if count == 0 { break; }
                if remaining > 0 {
                    let retained = count.min(remaining);
                    if file.write_all(&chunk[..retained]).is_ok() {
                        let _ = file.sync_data();
                        remaining -= retained;
                    } else {
                        remaining = 0;
                    }
                }
            }
        });
    }
    let stdout_file = private_output(&manifest_path.with_extension("process-output"))?;
    let stderr_file = private_output(&manifest_path.with_extension("process-error"))?;
    let mut child = Command::new(&descriptor.executable)
        .args(&descriptor.args)
        .current_dir(&descriptor.cwd)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or(PodError::Uncertain(
        "operator process stdout pipe is unavailable after spawn",
    ))?;
    let stderr = child.stderr.take().ok_or(PodError::Uncertain(
        "operator process stderr pipe is unavailable after spawn",
    ))?;
    drain_bounded(stdout, stdout_file);
    drain_bounded(stderr, stderr_file);
    Ok(child)
}

/// Internal systemd service entry. The authenticated socket binds before any child is spawned.
pub fn serve(manifest_path: impl AsRef<Path>) -> Result<(), PodError> {
    let manifest = read_manifest(manifest_path.as_ref())?;
    let binding = manifest.peer_binding.as_ref().ok_or(PodError::Unsupported(
        "unbound bearer-only pod service is retired",
    ))?;
    let codex_launch = match (binding.protocol.as_str(), binding.capability.as_str()) {
        (PEER_BINDING_PROTOCOL, SYNTHETIC_CAPABILITY) => None,
        (PEER_BINDING_PROTOCOL, OPERATOR_PROCESS_CAPABILITY) => None,
        (PEER_BINDING_V2_PROTOCOL, CODEX_V2_CAPABILITY) => {
            Some(ValidatedCodexResourceLaunch::from_peer_binding(
                binding,
                &manifest.descriptor,
                manifest_path
                    .as_ref()
                    .parent()
                    .ok_or(PodError::Invalid("manifest parent"))?,
            )?)
        }
        _ => {
            return Err(PodError::Unsupported(
                "pod resource capability is unavailable",
            ));
        }
    };
    let identity = bound_identity(&manifest.descriptor, binding)?;
    let mut manager_peer = binding.manager_peer()?;
    let mut owner_epoch =
        OwnerEpoch::new(binding.owner_epoch).map_err(|_| PodError::Invalid("bound owner epoch"))?;
    let mut credential_epoch = CredentialEpoch::new(binding.credential_epoch)
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
    let manager_witness = SqliteManagerPeerWitness::for_pod(&binding.store_path, identity.clone());
    if witness.current_owner_epoch(&identity.store_lineage, &identity.scope_id) != Some(owner_epoch)
    {
        return Err(PodError::Refused("bound owner witness unavailable"));
    }
    if !manager_witness.matches_current(owner_epoch.get(), credential_epoch.get(), &manager_peer) {
        return Err(PodError::Refused("bound manager credential changed"));
    }
    if codex_launch.is_some() {
        current_codex_v2_binding(binding, &manifest.descriptor)?;
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
    let operator_process = binding.protocol == PEER_BINDING_PROTOCOL
        && binding.capability == OPERATOR_PROCESS_CAPABILITY;
    let mut child = if let Some(reviewed) = codex_launch {
        current_codex_v2_binding(binding, descriptor)?;
        if !manager_witness.matches_current(
            owner_epoch.get(),
            credential_epoch.get(),
            &manager_peer,
        ) {
            return Err(PodError::Refused(
                "manager credential changed before Codex child",
            ));
        }
        let credentials = std::env::var_os("CREDENTIALS_DIRECTORY").ok_or(PodError::Refused(
            "systemd Codex credential directory is absent",
        ))?;
        let home = prepare_codex_home_from_systemd_credential(
            &manifest.unit_name,
            manifest_path
                .as_ref()
                .parent()
                .ok_or(PodError::Invalid("manifest parent"))?,
            Path::new(&credentials),
        )?;
        ChildResource::Codex(PodCodexResource::spawn_initialized(reviewed, home)?)
    } else {
        match descriptor.pty {
            Some(spec) => {
                ChildResource::Pty(LinuxBackend.spawn(descriptor, spec, manifest_path.as_ref())?)
            }
            None if operator_process => ChildResource::Pipe(spawn_operator_process(
                descriptor, manifest_path.as_ref(),
            )?),
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
        }
    };
    if binding.protocol == PEER_BINDING_V2_PROTOCOL {
        current_codex_v2_binding(binding, descriptor)
            .map_err(|_| PodError::Uncertain("Codex V2 authority changed after child start"))?;
        if !manager_witness.matches_current(
            owner_epoch.get(),
            credential_epoch.get(),
            &manager_peer,
        ) {
            return Err(PodError::Uncertain(
                "manager credential changed after Codex child start",
            ));
        }
    }
    let child_pid = child.id()?;
    let child_start_ticks = start_ticks(child_pid)?;
    let mut exit_code = None;
    let mut settled = false;
    let mut accept_failures = 0u8;
    let codex_pump = binding.protocol == PEER_BINDING_V2_PROTOCOL;
    if codex_pump {
        listener.set_nonblocking(true)?;
    }
    let mut native_pump_available = codex_pump;
    let mut prior_rebind_observation: Option<HostObservedPriorCheckpoint> = None;
    loop {
        // One native frame before each accept keeps control traffic from
        // starving completion observation. An idle tick does constant work.
        let processed = if native_pump_available {
            match &mut child {
                ChildResource::Codex(resource) => {
                    let tick = resource.poll_bootstrap_notification_once(|| {
                        let live = active_codex_v2_binding(&manifest)?;
                        current_codex_v2_binding(&live, descriptor)?;
                        if !manager_witness.matches_current(
                            owner_epoch.get(), credential_epoch.get(), &manager_peer,
                        ) {
                            return Err(PodError::Refused(
                                "manager claim changed before journal observation",
                            ));
                        }
                        Ok(())
                    });
                    match tick {
                        Ok(processed) => processed,
                        Err(_) => {
                            // Native or journal failure cannot erase control
                            // access or manufacture bootstrap completion.
                            resource.mark_native_events_unknown();
                            native_pump_available = false;
                            false
                        }
                    }
                }
                _ => false,
            }
        } else {
            false
        };
        let incoming = listener.accept().map(|(stream, _)| stream);
        let mut stream = match incoming {
            Ok(stream) => {
                accept_failures = 0;
                stream
            }
            Err(error) if codex_pump && error.kind() == std::io::ErrorKind::WouldBlock => {
                if !processed {
                    std::thread::sleep(Duration::from_millis(25));
                }
                continue;
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
            if bytes.len() as u64 <= FRAME_LIMIT
                && let Ok(inspect) = serde_json::from_slice::<RebindInspectRequest>(&bytes)
            {
                let observed = peer_evidence.as_ref().ok();
                let checkpoint = read_peer_checkpoint_observation(
                    manifest_path.as_ref().parent().unwrap(),
                    &identity,
                );
                let verified =
                    observed
                        .zip(checkpoint.as_ref().ok())
                        .is_some_and(|(peer, checkpoint)| {
                            peer.recheck_before_effect(&stream, peer.attested_peer())
                                .is_ok()
                                && inspect_allowed(
                                    &inspect,
                                    &identity,
                                    checkpoint.checkpoint(),
                                    &fence,
                                    peer.attested_peer(),
                                    &witness,
                                    &manager_witness,
                                )
                                && child_attested_running(
                                    &mut child,
                                    child_pid,
                                    child_start_ticks,
                                    &cgroup_path,
                                )
                                && crate::runtime::cgroup_path().ok().as_deref()
                                    == Some(cgroup_path.as_str())
                        });
                if !verified {
                    respond(
                        &mut stream,
                        Response {
                            ok: false,
                            status: None,
                            error: Some("request refused".into()),
                            error_code: Some("refused".into()),
                            terminal: None,
                        },
                    )?;
                    return Ok(false);
                }
                let checkpoint = checkpoint.expect("checked canonical checkpoint");
                let prior = checkpoint.checkpoint();
                let response = RebindInspection {
                    protocol: INSPECT_PROTOCOL.into(),
                    nonce: inspect.nonce.clone(),
                    scope_id: identity.scope_id.as_str().into(),
                    pod_id: identity.pod_id.as_str().into(),
                    attempt_id: identity.attempt_id.as_str().into(),
                    incarnation: identity.incarnation.get(),
                    store_lineage: identity.store_lineage.as_str().into(),
                    prior_owner_epoch: prior.owner_epoch().get(),
                    prior_credential_epoch: prior.credential_epoch().get(),
                    prior_input_epochs: prior
                        .input_epochs()
                        .iter()
                        .map(|(id, epoch)| (id.as_str().to_owned(), epoch.get()))
                        .collect(),
                    checkpoint_digest: checkpoint.digest().into(),
                    supervisor_pid: std::process::id(),
                    supervisor_start_ticks: start_ticks(std::process::id())?,
                    child_pid,
                    child_start_ticks,
                    boot_id: boot_id.clone(),
                    unit_name: manifest.unit_name.clone(),
                    cgroup_path: cgroup_path.clone(),
                };
                let encoded = serde_json::to_vec(&response)?;
                if encoded.len() as u64 > FRAME_LIMIT {
                    return Err(PodError::Invalid("rebind inspect response exceeds bound"));
                }
                let peer = observed.expect("checked OS peer");
                if peer
                    .recheck_before_effect(&stream, peer.attested_peer())
                    .is_err()
                    || !inspect_allowed(
                        &inspect,
                        &identity,
                        prior,
                        &fence,
                        peer.attested_peer(),
                        &witness,
                        &manager_witness,
                    )
                {
                    respond(
                        &mut stream,
                        Response {
                            ok: false,
                            status: None,
                            error: Some("request refused".into()),
                            error_code: Some("refused".into()),
                            terminal: None,
                        },
                    )?;
                    return Ok(false);
                }
                stream.write_all(&encoded)?;
                return Ok(false);
            }
            if bytes.len() as u64 <= FRAME_LIMIT
                && let Ok(read) = serde_json::from_slice::<NativeEventsReadRequest>(&bytes)
                && read.protocol == CODEX_NATIVE_EVENTS_READ_PROTOCOL
            {
                let result = (|| -> Result<NativeEventRead, PodError> {
                    let live_binding = active_codex_v2_binding(&manifest)?;
                    let binding = &live_binding;
                    if read.operation != "codex.events.read"
                        || binding.protocol != PEER_BINDING_V2_PROTOCOL
                        || binding.capability != CODEX_V2_CAPABILITY
                        || !constant_time_equal(read.token.as_bytes(), manifest.token.as_bytes())
                        || !(1..=64).contains(&read.limit)
                        || read.identity != identity_from_manifest(&manifest)?
                    {
                        return Err(PodError::Refused("Codex event read capability differs"));
                    }
                    let observed = peer_evidence.as_ref()
                        .map_err(|_| PodError::Refused("Codex event manager OS peer unavailable"))?;
                    if observed.attested_peer() != &manager_peer
                        || observed.recheck_before_effect(&stream, &manager_peer).is_err()
                        || !manager_witness.matches_current(owner_epoch.get(), credential_epoch.get(), &manager_peer)
                    {
                        return Err(PodError::Refused("Codex event manager peer is stale"));
                    }
                    current_codex_v2_binding(binding, descriptor)?;
                    let result = if let ChildResource::Codex(resource) = &mut child {
                        resource.read_native_events(read.cursor.as_ref(), read.limit)?
                    } else {
                        return Err(PodError::Refused("Codex event Resource is unavailable"));
                    };
                    observed.recheck_before_effect(&stream, &manager_peer)
                        .map_err(|_| PodError::Refused("Codex event manager peer changed"))?;
                    if !manager_witness.matches_current(owner_epoch.get(), credential_epoch.get(), &manager_peer) {
                        return Err(PodError::Refused("Codex event manager claim changed"));
                    }
                    current_codex_v2_binding(binding, descriptor)?;
                    Ok(result)
                })();
                let reply = match result {
                    Ok(read) => NativeEventsReadReply {
                        protocol: CODEX_NATIVE_EVENTS_READ_PROTOCOL.into(),
                        read: Some(read), refused: false,
                    },
                    Err(_) => NativeEventsReadReply {
                        protocol: CODEX_NATIVE_EVENTS_READ_PROTOCOL.into(),
                        read: None, refused: true,
                    },
                };
                let encoded = serde_json::to_vec(&reply)?;
                if encoded.len() as u64 > FRAME_LIMIT {
                    return Err(PodError::Invalid("Codex event reply exceeds frame bound"));
                }
                stream.write_all(&encoded)?;
                return Ok(false);
            }
            if bytes.len() as u64 <= FRAME_LIMIT
                && let Ok(prepare) = decode_request(&bytes)
            {
                let result = (|| -> Result<String, PodError> {
                    if binding.protocol != PEER_BINDING_V2_PROTOCOL
                        || binding.capability != CODEX_V2_CAPABILITY
                        || prepare.proposal.identity != identity
                    {
                        return Err(PodError::Refused("V2 rebind prepare identity differs"));
                    }
                    let peer = peer_evidence.as_ref().map_err(|_| PodError::Refused(
                        "V2 rebind manager OS peer unavailable"))?;
                    if peer.attested_peer() != &prepare.proposal.next_manager
                        || peer.recheck_before_effect(&stream, &prepare.proposal.next_manager).is_err()
                        || !manager_witness.matches_current(
                            prepare.proposal.next_owner_epoch.get(),
                            prepare.proposal.next_credential_epoch.get(),
                            &prepare.proposal.next_manager,
                        )
                        || !child_attested_running(&mut child, child_pid, child_start_ticks, &cgroup_path)
                        || crate::runtime::cgroup_path().ok().as_deref() != Some(cgroup_path.as_str())
                    {
                        return Err(PodError::Refused("V2 rebind manager or child changed"));
                    }
                    let directory = manifest_path.as_ref().parent().ok_or(PodError::Invalid(
                        "V2 rebind checkpoint directory"))?;
                    let durable = read_peer_checkpoint_observation(directory, &identity)
                        .map_err(|_| PodError::Refused("V2 rebind checkpoint unavailable"))?;
                    let prior = if fence.phase() == RebindPhase::Active {
                        if durable.checkpoint() != &fence.checkpoint()
                            || durable.digest() != prepare.prior_checkpoint_digest
                        {
                            return Err(PodError::Refused("V2 prior Active checkpoint differs"));
                        }
                        let checkpoint = durable.checkpoint();
                        let observed = HostObservedPriorCheckpoint {
                            identity: identity.clone(),
                            phase: RebindPhase::Active,
                            owner_epoch: checkpoint.owner_epoch(),
                            credential_epoch: checkpoint.credential_epoch(),
                            input_epochs: checkpoint.input_epochs().clone(),
                            checkpoint_digest: durable.digest().into(),
                            supervisor_pid: std::process::id(),
                            supervisor_start_ticks: start_ticks(std::process::id())?,
                            boot_id: boot_id.clone(),
                            unit_name: manifest.unit_name.clone(),
                            cgroup_path: cgroup_path.clone(),
                        };
                        prior_rebind_observation = Some(observed.clone());
                        observed
                    } else {
                        let cached = prior_rebind_observation.as_ref().ok_or(PodError::Refused(
                            "V2 prior checkpoint proof was lost"))?;
                        if cached.checkpoint_digest != prepare.prior_checkpoint_digest
                            || fence.checkpoint().pending_rebind() != Some(&prepare.proposal)
                            || (durable.checkpoint() != &fence.checkpoint()
                                && !(fence.phase() == RebindPhase::PendingStore
                                    && durable.checkpoint().phase() == RebindPhase::Active
                                    && durable.digest() == cached.checkpoint_digest)
                                && !(fence.phase() == RebindPhase::PendingPod
                                    && durable.checkpoint().phase() == RebindPhase::PendingStore
                                    && durable.checkpoint().pending_rebind()
                                        == Some(&prepare.proposal)))
                        {
                            return Err(PodError::Refused("V2 Pending checkpoint differs"));
                        }
                        cached.clone()
                    };
                    let ledger = SqlitePriorObservedPendingLedger::for_pod(
                        &binding.store_path, prior);
                    let now = u64::try_from(fence_clock.elapsed().as_millis())
                        .unwrap_or(u64::MAX)
                        .saturating_add(1);
                    let old_liveness = LinuxPeerEvidence::probe_pinned_manager(
                        fence.checkpoint().manager_peer());
                    let pending_digest = persist_pending_rebind_checkpoint(
                        &mut fence, &prepare.proposal, peer.attested_peer(),
                        old_liveness, &witness, &ledger, now,
                        |checkpoint| {
                            write_peer_checkpoint(directory, &identity, checkpoint)
                                .map_err(|_| PodError::Uncertain("V2 Pending checkpoint fsync unknown"))?;
                            let observed = read_peer_checkpoint_observation(directory, &identity)
                                .map_err(|_| PodError::Uncertain("V2 Pending checkpoint readback unavailable"))?;
                            if observed.checkpoint() != checkpoint {
                                return Err(PodError::Uncertain("V2 Pending checkpoint readback differs"));
                            }
                            Ok(observed.digest().into())
                        },
                    )?;
                    let pending = read_peer_checkpoint_observation(directory, &identity)
                        .map_err(|_| PodError::Uncertain("V2 PendingPod readback unavailable"))?;
                    if fence.phase() != RebindPhase::PendingPod
                        || pending.checkpoint() != &fence.checkpoint()
                        || pending.digest() != pending_digest
                        || !child_attested_running(&mut child, child_pid, child_start_ticks, &cgroup_path)
                        || peer.recheck_before_effect(&stream, &prepare.proposal.next_manager).is_err()
                        || !ledger.pending(&prepare.proposal)
                    {
                        return Err(PodError::Uncertain("V2 PendingPod proof changed"));
                    }
                    Ok(pending_digest)
                })();
                match result {
                    Ok(digest) => stream.write_all(&encode_pending_response(
                        &identity, &prepare.nonce, &digest,
                    )?)?,
                    Err(_) => respond(&mut stream, Response {
                        ok: false, status: None, error: Some("rebind prepare refused or uncertain".into()),
                        error_code: Some("uncertain".into()), terminal: None,
                    })?,
                }
                return Ok(false);
            }
            if bytes.len() as u64 <= FRAME_LIMIT
                && let Ok(activate) = decode_activate_request(&bytes)
            {
                let result = (|| -> Result<String, PodError> {
                    if binding.protocol != PEER_BINDING_V2_PROTOCOL
                        || binding.capability != CODEX_V2_CAPABILITY
                        || activate.proposal.identity != identity
                    {
                        return Err(PodError::Refused("V2 rebind activation identity differs"));
                    }
                    let peer = peer_evidence.as_ref().map_err(|_| PodError::Refused(
                        "V2 activation manager OS peer unavailable"))?;
                    if peer.attested_peer() != &activate.proposal.next_manager
                        || peer.recheck_before_effect(&stream, &activate.proposal.next_manager).is_err()
                        || !manager_witness.matches_current(
                            activate.proposal.next_owner_epoch.get(),
                            activate.proposal.next_credential_epoch.get(),
                            &activate.proposal.next_manager,
                        )
                        || !child_attested_running(&mut child, child_pid, child_start_ticks, &cgroup_path)
                    {
                        return Err(PodError::Refused("V2 activation manager or child changed"));
                    }
                    let prior = prior_rebind_observation.as_ref().ok_or(PodError::Refused(
                        "V2 prior checkpoint proof was lost"))?;
                    if prior.checkpoint_digest != activate.prior_checkpoint_digest {
                        return Err(PodError::Refused("V2 activation prior digest differs"));
                    }
                    let ledger = SqlitePriorObservedPendingLedger::for_pod(
                        &binding.store_path, prior.clone());
                    if !ledger.activated(&activate.proposal) {
                        return Err(PodError::Refused("V2 activation store proof is absent"));
                    }
                    let mut store = PodBayStore::open_existing_read_only(&binding.store_path)
                        .map_err(|_| PodError::Refused("V2 activation store unavailable"))?;
                    let stored = store.lookup_prior_observed_rebind(&activate.proposal)
                        .map_err(|_| PodError::Refused("V2 activation record unavailable"))?
                        .ok_or(PodError::Refused("V2 activation record absent"))?;
                    if stored.receipt.phase != podbay_store::DurableRebindPhase::Activated
                        || stored.receipt.pod_checkpoint_ref.as_deref()
                            != Some(activate.pending_checkpoint_digest.as_str())
                    {
                        return Err(PodError::Refused("V2 activation checkpoint ref differs"));
                    }
                    let directory = manifest_path.as_ref().parent().ok_or(PodError::Invalid(
                        "V2 rebind checkpoint directory"))?;
                    let durable = read_peer_checkpoint_observation(directory, &identity)
                        .map_err(|_| PodError::Refused("V2 activation checkpoint unavailable"))?;
                    if durable.checkpoint() != &fence.checkpoint()
                        || (fence.phase() == RebindPhase::PendingPod
                            && durable.digest() != activate.pending_checkpoint_digest)
                        || (fence.phase() == RebindPhase::Active
                            && fence.checkpoint().last_rebind() != Some(&activate.proposal))
                    {
                        return Err(PodError::Refused("V2 activation durable phase differs"));
                    }
                    fence.activate_rebind(
                        &activate.proposal, peer.attested_peer(), &witness, &ledger,
                    ).map_err(|_| PodError::Refused("V2 activation fence refused"))?;
                    write_peer_checkpoint(directory, &identity, &fence.checkpoint())
                        .map_err(|_| PodError::Uncertain("V2 Active checkpoint fsync unknown"))?;
                    let active = read_peer_checkpoint_observation(directory, &identity)
                        .map_err(|_| PodError::Uncertain("V2 Active readback unavailable"))?;
                    if active.checkpoint() != &fence.checkpoint()
                        || active.checkpoint().phase() != RebindPhase::Active
                        || !ledger.activated(&activate.proposal)
                        || peer.recheck_before_effect(&stream, &activate.proposal.next_manager).is_err()
                        || !child_attested_running(&mut child, child_pid, child_start_ticks, &cgroup_path)
                    {
                        return Err(PodError::Uncertain("V2 Active proof changed"));
                    }
                    let now = u64::try_from(fence_clock.elapsed().as_millis())
                        .unwrap_or(u64::MAX)
                        .saturating_add(1);
                    let manager_until = now.checked_add(30_000)
                        .ok_or(PodError::Uncertain("V2 manager lease overflow"))?;
                    let grant_until = now.checked_add(60_000)
                        .ok_or(PodError::Uncertain("V2 Pod grant overflow"))?;
                    fence.renew_manager_lease(peer.attested_peer(), &witness, now, manager_until)
                        .map_err(|_| PodError::Uncertain("V2 manager lease unavailable"))?;
                    let grant_id = PeerGrantId::try_from("grant.manager.pod.bootstrap").unwrap();
                    let grant = PeerGrant::new(
                        grant_id.clone(), peer.attested_peer().clone(), GrantKind::Controller,
                        FenceTarget::Pod,
                        BTreeSet::from([FenceOperation::ObservePod, FenceOperation::StopPod]),
                        activate.proposal.next_owner_epoch,
                        activate.proposal.next_credential_epoch,
                        grant_until,
                    ).map_err(|_| PodError::Uncertain("V2 manager Pod grant invalid"))?;
                    if fence.install_grant(peer.attested_peer(), grant, &witness, now).is_err() {
                        fence.renew_existing_manager_pod_control(
                            peer.attested_peer(), &grant_id, &witness, now,
                        ).map_err(|_| PodError::Uncertain("V2 manager Pod grant unavailable"))?;
                    }
                    manager_peer = activate.proposal.next_manager.clone();
                    owner_epoch = activate.proposal.next_owner_epoch;
                    credential_epoch = activate.proposal.next_credential_epoch;
                    native_pump_available = codex_pump;
                    Ok(active.digest().into())
                })();
                match result {
                    Ok(digest) => stream.write_all(&encode_active_response(
                        &identity, &activate.nonce, &digest,
                    )?)?,
                    Err(_) => respond(&mut stream, Response {
                        ok: false, status: None, error: Some("rebind activation refused or uncertain".into()),
                        error_code: Some("uncertain".into()), terminal: None,
                    })?,
                }
                return Ok(false);
            }
            if bytes.len() as u64 <= FRAME_LIMIT
                && let Ok(inspect) = serde_json::from_slice::<BootstrapControlRequest>(&bytes)
                && inspect.protocol == CODEX_BOOTSTRAP_INSPECT_PROTOCOL
            {
                let verified = (|| -> Result<_, PodError> {
                    let live_binding = active_codex_v2_binding(&manifest)?;
                    let binding = &live_binding;
                    if binding.protocol != PEER_BINDING_V2_PROTOCOL
                        || binding.capability != CODEX_V2_CAPABILITY
                        || !constant_time_equal(inspect.token.as_bytes(), manifest.token.as_bytes())
                    {
                        return Err(PodError::Refused("Codex bootstrap inspection capability unavailable"));
                    }
                    let observed = peer_evidence.as_ref().map_err(|_| PodError::Refused(
                        "bootstrap inspection manager OS peer unavailable"))?;
                    if observed.attested_peer() != &manager_peer
                        || observed.recheck_before_effect(&stream, &manager_peer).is_err()
                        || !manager_witness.matches_current(owner_epoch.get(), credential_epoch.get(), &manager_peer)
                    {
                        return Err(PodError::Refused("bootstrap inspection manager peer is stale"));
                    }
                    let (selector, expected_writer_epoch) = inspect.checked_inspection_selector(binding, descriptor)?;
                    current_codex_v2_binding(binding, descriptor)?;
                    let mut store = PodBayStore::open_existing_read_only(&binding.store_path)
                        .map_err(|_| PodError::Refused("bootstrap inspection store unavailable"))?;
                    let proof = store.inspect_claimed_bootstrap_send(&selector)
                        .map_err(|_| PodError::Refused("bootstrap inspection claimed proof stale"))?;
                    let lease = store.inspect_native_writer_lease(&selector.native_target)
                        .map_err(|_| PodError::Refused("bootstrap inspection writer lease stale"))?;
                    if proof.writer_epoch() != expected_writer_epoch
                        || proof.owner_epoch() != binding.owner_epoch
                        || proof.manager_credential_epoch() != binding.credential_epoch
                        || Some(proof.authority_revision()) != binding.authority_revision
                        || lease.writer_epoch() != proof.writer_epoch()
                        || lease.holder_actor_id() != proof.holder_actor_id()
                        || lease.holder_credential_generation() != proof.holder_credential_generation()
                        || lease.expires_at_unix_seconds() != proof.lease_expires_at_unix_seconds()
                    {
                        return Err(PodError::Refused("bootstrap inspection proof differs"));
                    }
                    Ok((selector, proof, live_binding))
                })();
                let reply = match verified {
                    Ok((selector, proof, live_binding)) => {
                        let binding = &live_binding;
                        let stage = if let ChildResource::Codex(resource) = &mut child {
                            match resource.inspect_claimed_bootstrap(&proof) {
                                Ok((stage, settlement)) => (stage, settlement),
                                Err(PodError::Refused(_) | PodError::Conflict(_) | PodError::Invalid(_)) =>
                                    (BootstrapControlStage::RefusedBeforeEffect, None),
                                Err(_) => (BootstrapControlStage::ThreadCreateUncertain, None),
                            }
                        } else {
                            (BootstrapControlStage::RefusedBeforeEffect, None)
                        };
                        let fresh = (|| -> Result<(), PodError> {
                            let observed = peer_evidence.as_ref().map_err(|_| PodError::Refused(
                                "bootstrap inspection manager OS peer unavailable"))?;
                            observed.recheck_before_effect(&stream, &manager_peer)
                                .map_err(|_| PodError::Refused("bootstrap inspection manager peer changed"))?;
                            if !manager_witness.matches_current(owner_epoch.get(), credential_epoch.get(), &manager_peer) {
                                return Err(PodError::Refused("bootstrap inspection manager claim changed"));
                            }
                            current_codex_v2_binding(binding, descriptor)?;
                            let mut store = PodBayStore::open_existing_read_only(&binding.store_path)
                                .map_err(|_| PodError::Refused("bootstrap inspection store unavailable"))?;
                            let current = store.inspect_claimed_bootstrap_send(&selector)
                                .map_err(|_| PodError::Refused("bootstrap inspection claim changed"))?;
                            let lease = store.inspect_native_writer_lease(&selector.native_target)
                                .map_err(|_| PodError::Refused("bootstrap inspection lease changed"))?;
                            if current != proof
                                || lease.writer_epoch() != proof.writer_epoch()
                                || lease.expires_at_unix_seconds() != proof.lease_expires_at_unix_seconds()
                            {
                                return Err(PodError::Refused("bootstrap inspection proof changed"));
                            }
                            Ok(())
                        })();
                        if fresh.is_ok() {
                            BootstrapControlReceipt::new(
                                &inspect, Some(&proof.receipt().request_digest), stage.0,
                            ).with_settlement(stage.1)
                        } else {
                            BootstrapControlReceipt::new(
                                &inspect, None, BootstrapControlStage::RefusedBeforeEffect,
                            )
                        }
                    }
                    Err(_) => BootstrapControlReceipt::new(
                        &inspect, None, BootstrapControlStage::RefusedBeforeEffect,
                    ),
                };
                let encoded = serde_json::to_vec(&reply)?;
                if encoded.len() as u64 > FRAME_LIMIT {
                    return Err(PodError::Invalid("bootstrap inspection reply exceeds frame bound"));
                }
                stream.write_all(&encoded)?;
                return Ok(false);
            }
            if bytes.len() as u64 <= FRAME_LIMIT
                && let Ok(bootstrap) = serde_json::from_slice::<BootstrapControlRequest>(&bytes)
            {
                let verified = (|| -> Result<_, PodError> {
                    let live_binding = active_codex_v2_binding(&manifest)?;
                    let binding = &live_binding;
                    if binding.protocol != PEER_BINDING_V2_PROTOCOL
                        || binding.capability != CODEX_V2_CAPABILITY
                        || !constant_time_equal(bootstrap.token.as_bytes(), manifest.token.as_bytes())
                    {
                        return Err(PodError::Refused("Codex bootstrap capability is unavailable"));
                    }
                    let observed = peer_evidence.as_ref().map_err(|_| PodError::Refused(
                        "bootstrap manager OS peer unavailable"))?;
                    if observed.attested_peer() != &manager_peer
                        || observed.recheck_before_effect(&stream, &manager_peer).is_err()
                        || !manager_witness.matches_current(owner_epoch.get(), credential_epoch.get(), &manager_peer)
                    {
                        return Err(PodError::Refused("bootstrap manager peer is stale"));
                    }
                    let (selector, expected_writer_epoch) = bootstrap.checked_selector(binding, descriptor)?;
                    current_codex_v2_binding(binding, descriptor)?;
                    if child.try_wait()?.is_some() {
                        return Err(PodError::Refused("Codex child is not running"));
                    }
                    let mut store = PodBayStore::open_existing_read_only(&binding.store_path)
                        .map_err(|_| PodError::Refused("bootstrap store witness unavailable"))?;
                    let proof = store.inspect_claimed_bootstrap_send(&selector)
                        .map_err(|_| PodError::Refused("claimed bootstrap is not current"))?;
                    let lease = store.inspect_native_writer_lease(&selector.native_target)
                        .map_err(|_| PodError::Refused("native writer lease is not current"))?;
                    if proof.writer_epoch() != expected_writer_epoch
                        || proof.owner_epoch() != binding.owner_epoch
                        || proof.manager_credential_epoch() != binding.credential_epoch
                        || Some(proof.authority_revision()) != binding.authority_revision
                        || lease.writer_epoch() != proof.writer_epoch()
                        || lease.holder_actor_id() != proof.holder_actor_id()
                        || lease.holder_credential_generation() != proof.holder_credential_generation()
                        || lease.expires_at_unix_seconds() != proof.lease_expires_at_unix_seconds()
                    {
                        return Err(PodError::Refused("bootstrap writer proof differs"));
                    }
                    Ok((selector, proof, live_binding))
                })();
                let reply = match verified {
                    Ok((selector, proof, live_binding)) => {
                        let binding = &live_binding;
                        if let ChildResource::Codex(resource) = &mut child {
                            let original = proof.clone();
                            let recheck = || -> Result<(), PodError> {
                                let observed = peer_evidence.as_ref().map_err(|_| PodError::Refused(
                                    "bootstrap manager OS peer unavailable"))?;
                                observed.recheck_before_effect(&stream, &manager_peer)
                                    .map_err(|_| PodError::Refused("bootstrap manager peer changed"))?;
                                if !manager_witness.matches_current(
                                    owner_epoch.get(), credential_epoch.get(), &manager_peer,
                                ) {
                                    return Err(PodError::Refused("bootstrap manager claim changed"));
                                }
                                current_codex_v2_binding(binding, descriptor)?;
                                let mut store = PodBayStore::open_existing_read_only(&binding.store_path)
                                    .map_err(|_| PodError::Refused("bootstrap store witness unavailable"))?;
                                let fresh = store.inspect_claimed_bootstrap_send(&selector)
                                    .map_err(|_| PodError::Refused("claimed bootstrap is stale"))?;
                                let lease = store.inspect_native_writer_lease(&selector.native_target)
                                    .map_err(|_| PodError::Refused("bootstrap writer lease is stale"))?;
                                if fresh != original
                                    || lease.writer_epoch() != original.writer_epoch()
                                    || lease.expires_at_unix_seconds() != original.lease_expires_at_unix_seconds()
                                {
                                    return Err(PodError::Refused("bootstrap command changed"));
                                }
                                Ok(())
                            };
                            let stage = resource.submit_claimed_bootstrap(&proof, &LinuxBackend, recheck);
                            BootstrapControlReceipt::new(
                                &bootstrap,
                                Some(&proof.receipt().request_digest),
                                stage,
                            )
                        } else {
                            BootstrapControlReceipt::new(
                                &bootstrap, None,
                                BootstrapControlStage::RefusedBeforeEffect,
                            )
                        }
                    }
                    Err(_) => {
                        // Historical journal facts may be returned only to
                        // the exact originally attested manager transport.
                        // A bad bearer or sibling peer learns no native IDs.
                        let same_transport = binding.protocol == PEER_BINDING_V2_PROTOCOL
                            && constant_time_equal(
                                bootstrap.token.as_bytes(), manifest.token.as_bytes(),
                            )
                            && peer_evidence.as_ref().is_ok_and(|observed| {
                                observed.attested_peer() == &manager_peer
                                    && observed.recheck_before_effect(&stream, &manager_peer).is_ok()
                            });
                        if same_transport && let ChildResource::Codex(resource) = &mut child {
                            if let Some((digest, stage)) = resource.prior_uncertain_stage(&bootstrap.command_id) {
                                BootstrapControlReceipt::new(&bootstrap, Some(&digest), stage)
                            } else {
                                BootstrapControlReceipt::new(
                                    &bootstrap, None, BootstrapControlStage::RefusedBeforeEffect,
                                )
                            }
                        } else {
                            BootstrapControlReceipt::new(
                                &bootstrap, None, BootstrapControlStage::RefusedBeforeEffect,
                            )
                        }
                    }
                };
                let encoded = serde_json::to_vec(&reply)?;
                if encoded.len() as u64 > FRAME_LIMIT {
                    return Err(PodError::Uncertain("bootstrap reply exceeds frame bound"));
                }
                stream.write_all(&encoded)?;
                return Ok(false);
            }
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
            // Startup may consume the original 30s/60s local timeouts. Only
            // the same kernel-attested manager with today's durable owner and
            // credential binding may refresh this exact existing Pod grant.
            let manager_current = manager_witness.matches_current(
                    owner_epoch.get(),
                    credential_epoch.get(),
                    &manager_peer,
                );
            if renew_and_authorize_manager_pod_control(
                &mut fence,
                observed.attested_peer(),
                &checked,
                &witness,
                current,
                manager_current,
                now,
            )
            .is_err() {
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
                bound: if codex_pump {
                    Some(active_codex_v2_binding(&manifest)?.status(
                        &descriptor.resource_id, &descriptor.scope_id,
                    ))
                } else {
                    manifest.peer_binding.as_ref().map(|binding| {
                        binding.status(&descriptor.resource_id, &descriptor.scope_id)
                    })
                },
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
    let expected_bound = match manifest.peer_binding.as_ref() {
        Some(binding) if binding.protocol == PEER_BINDING_V2_PROTOCOL => {
            Some(active_codex_v2_binding(manifest)?.status(
                &manifest.descriptor.resource_id,
                &manifest.descriptor.scope_id,
            ))
        }
        Some(binding) => Some(binding.status(
            &manifest.descriptor.resource_id,
            &manifest.descriptor.scope_id,
        )),
        None => None,
    };
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
        || expected_bound != status.bound
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
    process_cgroup_path(std::process::id())
}

fn process_cgroup_path(pid: u32) -> Result<String, PodError> {
    let content = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    let mut unified = content.lines().filter_map(|line| line.strip_prefix("0::"));
    let value = unified
        .next()
        .ok_or(PodError::Invalid("unified cgroup evidence unavailable"))?;
    if unified.next().is_some() || !value.starts_with('/') || value.chars().any(char::is_control) {
        return Err(PodError::Invalid("unified cgroup evidence malformed"));
    }
    Ok(value.into())
}

fn child_attested_running(
    child: &mut ChildResource,
    pid: u32,
    birth: u64,
    expected_cgroup: &str,
) -> bool {
    matches!(child.try_wait(), Ok(None))
        && start_ticks(pid).ok() == Some(birth)
        && process_cgroup_path(pid).ok().as_deref() == Some(expected_cgroup)
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

    struct PendingFixtureLedger(RebindProposal);
    impl RebindLedger for PendingFixtureLedger {
        fn pending(&self, proposal: &RebindProposal) -> bool { &self.0 == proposal }
        fn activated(&self, _: &RebindProposal) -> bool { false }
    }

    #[test]
    fn pending_checkpoint_transition_retries_after_each_partial_fsync() {
        for fail_at in [1, 2] {
            let (identity, mut fence, next, _, witness, _) = inspect_fixture();
            let resource = ResourceId::try_from("resource.inspect.fixture").unwrap();
            let proposal = RebindProposal {
                identity,
                expected_owner_epoch: OwnerEpoch::new(1).unwrap(),
                next_owner_epoch: OwnerEpoch::new(2).unwrap(),
                expected_credential_epoch: CredentialEpoch::new(1).unwrap(),
                next_credential_epoch: CredentialEpoch::new(2).unwrap(),
                expected_input_epochs: BTreeMap::from([(resource.clone(), InputEpoch::new(1).unwrap())]),
                next_input_epochs: BTreeMap::from([(resource, InputEpoch::new(2).unwrap())]),
                next_manager: next.clone(),
                command_key: podbay_core::CommandKey::try_from("rebind.partial.fixture").unwrap(),
                digest: podbay_core::RequestDigest::parse(&"a".repeat(64)).unwrap(),
            };
            let ledger = PendingFixtureLedger(proposal.clone());
            let mut calls = 0;
            let mut persisted = fence.checkpoint();
            let first = persist_pending_rebind_checkpoint(
                &mut fence, &proposal, &next, ManagerLiveness::DeadAttested,
                &witness, &ledger, 1_000,
                |checkpoint| {
                    calls += 1;
                    if calls == fail_at {
                        return Err(PodError::Uncertain("fixture interrupted fsync"));
                    }
                    persisted = checkpoint.clone();
                    Ok("b".repeat(64))
                },
            );
            assert!(first.is_err(), "failure at checkpoint write {fail_at}");
            assert_eq!(fence.phase(), if fail_at == 1 {
                RebindPhase::PendingStore
            } else {
                RebindPhase::PendingPod
            });
            assert_eq!(persisted.phase(), if fail_at == 1 {
                RebindPhase::Active
            } else {
                RebindPhase::PendingStore
            });
            let digest = persist_pending_rebind_checkpoint(
                &mut fence, &proposal, &next, ManagerLiveness::DeadAttested,
                &witness, &ledger, 1_001,
                |checkpoint| {
                    persisted = checkpoint.clone();
                    Ok("c".repeat(64))
                },
            ).unwrap();
            assert_eq!(digest, "c".repeat(64));
            assert_eq!(fence.phase(), RebindPhase::PendingPod);
            assert_eq!(persisted, fence.checkpoint());
        }
    }

    #[test]
    fn pinned_manifest_refuses_byte_mode_and_inode_replacement() {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "podbay-pinned-manifest-{}-{nonce}", std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let directory = fs::canonicalize(directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let descriptor = LaunchDescriptor {
            protocol: PROTOCOL.into(),
            pod_id: "pod.pinned.fixture".into(),
            attempt_id: "attempt.pinned.fixture".into(),
            session_id: "session.pinned.fixture".into(),
            run_id: "run.pinned.fixture".into(),
            scope_id: "scope.pinned.fixture".into(),
            role: PodRole::Worker,
            incarnation: 1,
            resource_id: "resource.pinned.fixture".into(),
            executable: PathBuf::from("/bin/true"),
            args: vec![],
            cwd: PathBuf::from("/tmp"),
            pty: None,
        };
        let path = manifest_path(&directory, &descriptor).unwrap();
        let manifest = PodManifest {
            digest: descriptor.digest().unwrap(),
            token: "a".repeat(64),
            viewer_token: None,
            socket_path: path.with_extension("sock"),
            unit_name: unit_name(&path).unwrap(),
            descriptor,
            peer_binding: None,
        };
        write_manifest(&path, &manifest).unwrap();
        let pinned = PinnedManifest::capture(&path, &manifest).unwrap();
        pinned.recheck(&path).unwrap();
        let original = fs::read(&path).unwrap();
        let mut changed = original.clone();
        let at = changed.iter().position(|byte| *byte == b'a').unwrap();
        changed[at] = b'b';
        fs::write(&path, changed).unwrap();
        assert!(matches!(pinned.recheck(&path), Err(PodError::Refused(_))));
        fs::write(&path, &original).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(pinned.recheck(&path), Err(PodError::Refused(_))));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let replacement = directory.join("replacement.json");
        fs::write(&replacement, &original).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert!(matches!(pinned.recheck(&path), Err(PodError::Refused(_))));
        fs::remove_dir_all(directory).unwrap();
    }

    struct InspectOwnerWitness {
        identity: PodFenceIdentity,
        owner: Option<OwnerEpoch>,
    }
    impl OwnerEpochWitness for InspectOwnerWitness {
        fn current_owner_epoch(
            &self,
            lineage: &StoreLineageId,
            scope: &ScopeId,
        ) -> Option<OwnerEpoch> {
            (lineage == &self.identity.store_lineage && scope == &self.identity.scope_id)
                .then_some(self.owner)
                .flatten()
        }
    }
    struct InspectManagerWitness {
        peer: Option<AttestedPeer>,
        owner: u64,
        credential: u64,
    }
    impl CurrentManagerPeerMatch for InspectManagerWitness {
        fn matches_current(&self, owner: u64, credential: u64, peer: &AttestedPeer) -> bool {
            owner == self.owner && credential == self.credential && self.peer.as_ref() == Some(peer)
        }
    }
    fn inspect_fixture() -> (
        PodFenceIdentity,
        PodPeerFence,
        AttestedPeer,
        RebindInspectRequest,
        InspectOwnerWitness,
        InspectManagerWitness,
    ) {
        let identity = PodFenceIdentity {
            scope_id: ScopeId::try_from("scope.inspect.fixture").unwrap(),
            pod_id: PodId::try_from("pod.inspect.fixture").unwrap(),
            attempt_id: AttemptId::try_from("attempt.inspect.fixture").unwrap(),
            incarnation: podbay_core::Epoch::new(1).unwrap(),
            store_lineage: StoreLineageId::try_from("store.inspect.fixture").unwrap(),
        };
        let old = AttestedPeer::from_port(
            "uid.1000",
            "pid.100",
            "boot.fixture",
            "birth.100",
            "manager.unit",
        )
        .unwrap();
        let next = AttestedPeer::from_port(
            "uid.1000",
            "pid.200",
            "boot.fixture",
            "birth.200",
            "manager.unit",
        )
        .unwrap();
        let fence = PodPeerFence::new(
            identity.clone(),
            old,
            OwnerEpoch::new(1).unwrap(),
            CredentialEpoch::new(1).unwrap(),
            BTreeMap::from([(
                ResourceId::try_from("resource.inspect.fixture").unwrap(),
                InputEpoch::new(1).unwrap(),
            )]),
            100,
            800,
        )
        .unwrap();
        let request = RebindInspectRequest {
            protocol: INSPECT_PROTOCOL.into(),
            operation: "rebind.inspect".into(),
            nonce: "nonce.rebind.0001".into(),
            scope_id: identity.scope_id.as_str().into(),
            pod_id: identity.pod_id.as_str().into(),
            attempt_id: identity.attempt_id.as_str().into(),
            incarnation: identity.incarnation.get(),
            store_lineage: identity.store_lineage.as_str().into(),
            owner_epoch: 2,
            credential_epoch: 2,
        };
        let owner = InspectOwnerWitness {
            identity: identity.clone(),
            owner: Some(OwnerEpoch::new(2).unwrap()),
        };
        let manager = InspectManagerWitness {
            peer: Some(next.clone()),
            owner: 2,
            credential: 2,
        };
        (identity, fence, next, request, owner, manager)
    }

    #[test]
    fn status_and_stop_renew_only_attested_current_manager_after_sixty_seconds() {
        let identity = PodFenceIdentity {
            scope_id: ScopeId::try_from("scope.renew.fixture").unwrap(),
            pod_id: PodId::try_from("pod.renew.fixture").unwrap(),
            attempt_id: AttemptId::try_from("attempt.renew.fixture").unwrap(),
            incarnation: podbay_core::Epoch::new(1).unwrap(),
            store_lineage: StoreLineageId::try_from("store.renew.fixture").unwrap(),
        };
        let peer = AttestedPeer::from_port(
            "uid.1000", "pid.100", "boot.fixture", "birth.100", "manager.unit",
        ).unwrap();
        let sibling = AttestedPeer::from_port(
            "uid.1000", "pid.101", "boot.fixture", "birth.101", "manager.unit",
        ).unwrap();
        let owner = OwnerEpoch::new(1).unwrap();
        let credential = CredentialEpoch::new(1).unwrap();
        let grant_id = PeerGrantId::try_from("grant.manager.pod.bootstrap").unwrap();
        let witness = InspectOwnerWitness { identity: identity.clone(), owner: Some(owner) };
        let mut fence = PodPeerFence::new(
            identity.clone(), peer.clone(), owner, credential,
            BTreeMap::from([(
                ResourceId::try_from("resource.renew.fixture").unwrap(),
                InputEpoch::new(1).unwrap(),
            )]),
            1, 30_001,
        ).unwrap();
        fence.install_grant(
            &peer,
            PeerGrant::new(
                grant_id.clone(), peer.clone(), GrantKind::Controller, FenceTarget::Pod,
                BTreeSet::from([FenceOperation::ObservePod, FenceOperation::StopPod]),
                owner, credential, 60_001,
            ).unwrap(),
            &witness, 1,
        ).unwrap();
        let status = PeerRequest {
            identity: identity.clone(), grant_id: grant_id.clone(), owner_epoch: owner,
            credential_epoch: credential, target: FenceTarget::Pod,
            operation: FenceOperation::ObservePod, input_epoch: None,
        };
        assert_eq!(
            fence.authorize(&peer, &status, &witness, 70_001),
            Err(podbay_core::FenceError::LeaseExpired),
        );
        assert_eq!(
            renew_and_authorize_manager_pod_control(
                &mut fence, &peer, &status, &witness, false, true, 70_001,
            ),
            Err(podbay_core::FenceError::WrongPeer),
        );
        assert_eq!(
            renew_and_authorize_manager_pod_control(
                &mut fence, &peer, &status, &witness, true, false, 70_001,
            ),
            Err(podbay_core::FenceError::OwnerUnverified),
        );
        assert_eq!(
            renew_and_authorize_manager_pod_control(
                &mut fence, &sibling, &status, &witness, true, true, 70_001,
            ),
            Err(podbay_core::FenceError::WrongPeer),
        );
        let changed_owner = InspectOwnerWitness {
            identity: identity.clone(), owner: Some(OwnerEpoch::new(2).unwrap()),
        };
        assert_eq!(
            renew_and_authorize_manager_pod_control(
                &mut fence, &peer, &status, &changed_owner, true, true, 70_001,
            ),
            Err(podbay_core::FenceError::OwnerUnverified),
        );
        assert_eq!(
            fence.authorize(&peer, &status, &witness, 70_001),
            Err(podbay_core::FenceError::LeaseExpired),
        );
        assert_eq!(
            renew_and_authorize_manager_pod_control(
                &mut fence, &peer, &status, &witness, true, true, 70_001,
            ),
            Ok(()),
        );
        let stop = PeerRequest { operation: FenceOperation::StopPod, ..status };
        assert_eq!(
            renew_and_authorize_manager_pod_control(
                &mut fence, &peer, &stop, &witness, true, true, 70_002,
            ),
            Ok(()),
        );
        assert_eq!(
            renew_and_authorize_manager_pod_control(
                &mut fence, &peer, &stop, &changed_owner, true, true, 130_003,
            ),
            Err(podbay_core::FenceError::OwnerUnverified),
        );
    }

    #[test]
    fn rebind_inspect_predicate_refuses_sibling_wrong_birth_or_stale_claim() {
        let (identity, fence, next, request, owner, manager) = inspect_fixture();
        let checkpoint = fence.checkpoint();
        assert!(inspect_allowed(
            &request,
            &identity,
            &checkpoint,
            &fence,
            &next,
            &owner,
            &manager
        ));
        let sibling = AttestedPeer::from_port(
            "uid.1000",
            "pid.300",
            "boot.fixture",
            "birth.300",
            "sibling.unit",
        )
        .unwrap();
        assert!(!inspect_allowed(
            &request,
            &identity,
            &checkpoint,
            &fence,
            &sibling,
            &owner,
            &manager
        ));
        let reused = AttestedPeer::from_port(
            "uid.1000",
            "pid.200",
            "boot.fixture",
            "birth.reused",
            "manager.unit",
        )
        .unwrap();
        assert!(!inspect_allowed(
            &request,
            &identity,
            &checkpoint,
            &fence,
            &reused,
            &owner,
            &manager
        ));
        let missing = InspectManagerWitness {
            peer: None,
            owner: 2,
            credential: 2,
        };
        assert!(!inspect_allowed(
            &request,
            &identity,
            &checkpoint,
            &fence,
            &next,
            &owner,
            &missing
        ));
        let stale_owner = InspectOwnerWitness {
            identity: identity.clone(),
            owner: None,
        };
        assert!(!inspect_allowed(
            &request,
            &identity,
            &checkpoint,
            &fence,
            &next,
            &stale_owner,
            &manager
        ));
        let mut wrong = request;
        wrong.store_lineage = "store.foreign".into();
        assert!(!inspect_allowed(
            &wrong,
            &identity,
            &checkpoint,
            &fence,
            &next,
            &owner,
            &manager
        ));
        wrong.store_lineage = identity.store_lineage.as_str().into();
        wrong.nonce = "short".into();
        assert!(!inspect_allowed(
            &wrong,
            &identity,
            &checkpoint,
            &fence,
            &next,
            &owner,
            &manager
        ));
        let changed = PodPeerFence::new(
            identity.clone(),
            next.clone(),
            OwnerEpoch::new(2).unwrap(),
            CredentialEpoch::new(2).unwrap(),
            BTreeMap::from([(
                ResourceId::try_from("resource.inspect.fixture").unwrap(),
                InputEpoch::new(2).unwrap(),
            )]),
            100,
            800,
        )
        .unwrap()
        .checkpoint();
        let valid = inspect_fixture().3;
        assert!(!inspect_allowed(
            &valid, &identity, &changed, &fence, &next, &owner, &manager
        ));
    }

    #[test]
    fn rebind_inspect_corrupt_file_or_exited_child_is_not_success() {
        let (identity, fence, _next, _request, _owner, _manager) = inspect_fixture();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("podbay-inspect-{}-{stamp}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(read_peer_checkpoint_observation(&directory, &identity).is_err());
        write_peer_checkpoint(&directory, &identity, &fence.checkpoint()).unwrap();
        assert_eq!(
            read_peer_checkpoint_observation(&directory, &identity)
                .unwrap()
                .checkpoint(),
            &fence.checkpoint()
        );
        let path = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|extension| extension == "chk"))
            .unwrap();
        fs::write(&path, b"corrupt checkpoint").unwrap();
        assert!(read_peer_checkpoint_observation(&directory, &identity).is_err());
        fs::remove_dir_all(directory).unwrap();
        let mut child = ChildResource::Pipe(Command::new("/bin/true").spawn().unwrap());
        let pid = child.id().unwrap();
        let birth = start_ticks(pid).unwrap_or(1);
        let deadline = Instant::now() + Duration::from_secs(2);
        while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!child_attested_running(
            &mut child,
            pid,
            birth,
            "/user.slice/fixture.service"
        ));
    }

    #[test]
    fn rebind_inspect_exchange_attests_connected_server_before_and_after_reply() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "podbay-inspect-socket-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("inspect.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"inspect.fixture");
            stream.write_all(b"response.fixture").unwrap();
        });
        let (response, peer) = inspect_exchange(&path, b"inspect.fixture").unwrap();
        worker.join().unwrap();
        assert_eq!(response, b"response.fixture");
        assert_eq!(peer.pid(), std::process::id() as i32);
        assert!(peer.start_ticks() > 0);
        assert_eq!(
            peer.cgroup(),
            process_cgroup_path(std::process::id()).unwrap()
        );
        fs::remove_dir_all(directory).unwrap();
    }

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
    fn attested_status_refuses_server_claiming_another_unit_identity() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("pb-as-{}-{unique}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let descriptor = LaunchDescriptor {
            protocol: PROTOCOL.into(),
            pod_id: "pod.attested.fixture".into(),
            attempt_id: "attempt.attested.fixture".into(),
            session_id: "session.attested.fixture".into(),
            run_id: "run.attested.fixture".into(),
            scope_id: "scope.attested.fixture".into(),
            role: PodRole::Worker,
            incarnation: 1,
            resource_id: "resource.attested.fixture".into(),
            executable: "/bin/true".into(),
            args: vec![],
            cwd: directory.clone(),
            pty: None,
        };
        let path = manifest_path(&directory, &descriptor).unwrap();
        let manifest = PodManifest {
            digest: descriptor.digest().unwrap(),
            token: "a".repeat(64),
            viewer_token: None,
            socket_path: path.with_extension("sock"),
            unit_name: unit_name(&path).unwrap(),
            descriptor,
            peer_binding: None,
        };
        write_manifest(&path, &manifest).unwrap();
        let listener = UnixListener::bind(&manifest.socket_path).unwrap();
        let current = LinuxPeerEvidence::for_current_process().unwrap();
        let claimed = PodStatus {
            protocol: PROTOCOL.into(),
            pod_id: manifest.descriptor.pod_id.clone(),
            attempt_id: manifest.descriptor.attempt_id.clone(),
            incarnation: 1,
            manifest_digest: manifest.digest.clone(),
            supervisor_pid: std::process::id(),
            supervisor_start_ticks: current.start_ticks(),
            child_pid: std::process::id(),
            child_start_ticks: current.start_ticks(),
            boot_id: current.boot_id().into(),
            unit_name: manifest.unit_name.clone(),
            cgroup_path: format!("/user.slice/{}", manifest.unit_name),
            child_running: true,
            exit_code: None,
            bound: None,
        };
        let reply = serde_json::to_vec(&Response {
            ok: true,
            status: Some(claimed),
            error: None,
            error_code: None,
            terminal: None,
        })
        .unwrap();
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                socket.read_to_end(&mut request).unwrap();
                assert!(!request.is_empty());
                socket.write_all(&reply).unwrap();
            }
        });
        let client = PodClient {
            manifest_path: path,
            manifest,
            pinned_manifest: None,
        };
        // The historical DTO path accepts the claimed cgroup. The kernel
        // peer path sees this test process's actual cgroup and refuses it.
        assert!(client.status().is_ok());
        assert!(matches!(
            client.attested_status(),
            Err(PodError::Refused(_))
        ));
        server.join().unwrap();
        fs::remove_dir_all(directory).unwrap();
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

    fn held_log_directory() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("podbay-held-log-{}-{unique}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    #[test]
    fn held_append_log_reopens_with_exact_identity_and_bounded_bytes() {
        let directory = held_log_directory();
        let path = directory.join("native.commands");
        let mut first = LinuxBackend.open_private_append_log(&path, 32).unwrap();
        let identity = first.identity().clone();
        assert_eq!(first.len(), 0);
        first.append_synced(b"intent").unwrap();
        assert_eq!(first.read_all_bounded().unwrap(), b"intent");
        drop(first);
        let mut reopened = LinuxBackend.open_private_append_log(&path, 32).unwrap();
        assert_eq!(reopened.identity(), &identity);
        reopened.append_synced(b"receipt").unwrap();
        assert_eq!(reopened.len(), 13);
        assert_eq!(reopened.read_all_bounded().unwrap(), b"intentreceipt");
        assert!(matches!(
            reopened.append_synced(&[b'x'; 20]),
            Err(PodError::Refused(_))
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn held_append_log_refuses_symlink_mode_hardlink_replacement_and_oversize() {
        let directory = held_log_directory();
        let target = directory.join("target");
        fs::write(&target, b"target").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.join("link");
        symlink(&target, &link).unwrap();
        assert!(LinuxBackend.open_private_append_log(&link, 32).is_err());
        let parent_link = directory.with_extension("link");
        symlink(&directory, &parent_link).unwrap();
        assert!(
            LinuxBackend
                .open_private_append_log(&parent_link.join("native.commands"), 32)
                .is_err()
        );
        fs::remove_file(parent_link).unwrap();

        let mode_path = directory.join("mode.commands");
        let mut mode = LinuxBackend
            .open_private_append_log(&mode_path, 32)
            .unwrap();
        fs::set_permissions(&mode_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(mode.append_synced(b"wrong-mode").is_err());
        assert!(
            LinuxBackend
                .open_private_append_log(&mode_path, 32)
                .is_err()
        );
        fs::set_permissions(&mode_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            mode.append_synced(b"retry"),
            Err(PodError::Uncertain(_))
        ));

        let hardlink_path = directory.join("hardlink.commands");
        let mut hardlink = LinuxBackend
            .open_private_append_log(&hardlink_path, 32)
            .unwrap();
        let sibling = directory.join("hardlink");
        fs::hard_link(&hardlink_path, &sibling).unwrap();
        assert!(hardlink.append_synced(b"hardlink").is_err());
        assert!(
            LinuxBackend
                .open_private_append_log(&hardlink_path, 32)
                .is_err()
        );
        fs::remove_file(&sibling).unwrap();

        let inode_path = directory.join("inode.commands");
        let mut inode = LinuxBackend
            .open_private_append_log(&inode_path, 32)
            .unwrap();
        let original = directory.join("old.commands");
        fs::rename(&inode_path, &original).unwrap();
        fs::write(&inode_path, b"replacement").unwrap();
        fs::set_permissions(&inode_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(inode.append_synced(b"wrong-inode").is_err());

        let oversized = directory.join("oversized.commands");
        fs::write(&oversized, b"123456789").unwrap();
        fs::set_permissions(&oversized, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(LinuxBackend.open_private_append_log(&oversized, 8).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn held_append_log_partial_write_is_uncertain_and_replay_keeps_raw_tail() {
        let directory = held_log_directory();
        let path = directory.join("native.commands");
        let mut held = LinuxHeldAppendLog::open(&path, 32).unwrap();
        held.append_synced(b"intent").unwrap();
        held.fail_one_partial_append();
        assert!(matches!(
            held.append_synced(b"receipt"),
            Err(PodError::Uncertain(_))
        ));
        assert!(matches!(
            held.append_synced(b"retry"),
            Err(PodError::Uncertain(_))
        ));
        drop(held);
        let mut reopened = LinuxBackend.open_private_append_log(&path, 32).unwrap();
        let raw = reopened.read_all_bounded().unwrap();
        assert_eq!(raw, b"intentrece");
        fs::remove_dir_all(directory).unwrap();
    }
}
