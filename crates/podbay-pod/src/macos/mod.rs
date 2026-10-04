//! macOS launchd user-agent backend. Its child-tree evidence is a subset only.
mod manifest;

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::manifest::{LaunchDescriptor, PROTOCOL, PodError, PtySpec, hex, manifest_path};
use crate::ports::{
    DurableFiles, LocalControlTransport, MacScopeFencing, MacTreeCoverage, PodControlPort,
    PodObservation, ProcessIdentity, SupervisorBackend, SupervisorEvidence, TerminalBackend,
    TerminalResource, TerminalViewerPort,
};
use crate::terminal::PtyProcess;
use crate::terminal_protocol::{TerminalCommand, TerminalEventPage, TerminalReply, TerminalView};
use manifest::{
    MacDurableFiles, MacManifest, MacStatus, bootstrap_domain, plist_bytes, plist_digest,
    private_directory, read_manifest, slot_label,
};

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
    status: Option<MacStatus>,
    error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
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
            Self::Pty(child) => child
                .process_identity()?
                .parse()
                .map_err(|_| PodError::Invalid("macOS PTY process ID")),
        }
    }
    fn try_wait(&mut self) -> Result<Option<Option<i32>>, PodError> {
        match self {
            Self::Pipe(child) => Ok(child.try_wait()?.map(|status| status.code())),
            Self::Pty(child) => Ok(child.try_wait()?.map(Some)),
        }
    }
    fn stop(&mut self, birth: podbay_macos_sys::ProcessBirth) -> Result<(), PodError> {
        let now = podbay_macos_sys::process_birth(birth.pid)
            .map_err(|_| PodError::Uncertain("child process birth cannot be re-attested"))?;
        if now != birth {
            return Err(PodError::Uncertain("child PID was reused before stop"));
        }
        if matches!(self, Self::Pty(_)) {
            // portable-pty starts a new session. Signal only the attested
            // child's own group; escaped descendants remain unproven.
            let boot = podbay_macos_sys::boot_time()?;
            let group = podbay_macos_sys::attest_process_group(birth, boot)
                .map_err(|_| PodError::Uncertain("PTY group leader identity changed"))?;
            group
                .signal(libc::SIGTERM)
                .map_err(|_| PodError::Uncertain("PTY group stop outcome unknown"))?;
            Ok(())
        } else {
            match self {
                Self::Pipe(child) => child
                    .kill()
                    .map_err(|_| PodError::Uncertain("child stop outcome unknown")),
                Self::Pty(_) => unreachable!(),
            }
        }
    }
    fn terminal(&mut self) -> Option<&mut dyn TerminalResource> {
        match self {
            Self::Pty(child) => Some(child.as_mut()),
            Self::Pipe(_) => None,
        }
    }
}

pub struct MacBackend;

impl SupervisorBackend for MacBackend {
    fn launch(
        &self,
        descriptor: LaunchDescriptor,
        directory: &Path,
        binary: &Path,
    ) -> Result<Box<dyn PodControlPort>, PodError> {
        launch(descriptor, directory, binary).map(|v| Box::new(v) as Box<dyn PodControlPort>)
    }
    fn connect(&self, path: &Path) -> Result<Box<dyn PodControlPort>, PodError> {
        PodClient::connect(path).map(|v| Box::new(v) as Box<dyn PodControlPort>)
    }
}

impl TerminalBackend for MacBackend {
    fn spawn(
        &self,
        descriptor: &LaunchDescriptor,
        spec: PtySpec,
        manifest_path: &Path,
    ) -> Result<Box<dyn TerminalResource>, PodError> {
        PtyProcess::spawn(descriptor, spec, manifest_path)
            .map(|v| Box::new(v) as Box<dyn TerminalResource>)
    }
}

impl LocalControlTransport for MacBackend {
    fn exchange(&self, endpoint: &Path, request: &[u8]) -> Result<Vec<u8>, PodError> {
        exchange(endpoint, request).map(|(bytes, _)| bytes)
    }
}

impl DurableFiles for MacBackend {
    fn create_private(&self, path: &Path, bytes: &[u8]) -> Result<(), PodError> {
        MacDurableFiles.create_private(path, bytes)
    }
    fn append_durable(&self, path: &Path, bytes: &[u8]) -> Result<(), PodError> {
        MacDurableFiles.append_durable(path, bytes)
    }
    fn replace_durable(&self, path: &Path, bytes: &[u8]) -> Result<(), PodError> {
        MacDurableFiles.replace_durable(path, bytes)
    }
}

fn exchange(
    endpoint: &Path,
    request: &[u8],
) -> Result<(Vec<u8>, podbay_macos_sys::PeerIdentity), PodError> {
    if request.len() as u64 > FRAME_LIMIT {
        return Err(PodError::Invalid("pod request frame exceeded bound"));
    }
    let mut socket = UnixStream::connect(endpoint)?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    socket.set_write_timeout(Some(Duration::from_secs(3)))?;
    let peer = podbay_macos_sys::peer_identity(socket.as_fd())?;
    if peer.uid != podbay_macos_sys::effective_uid() {
        return Err(PodError::Refused("pod socket peer UID differs"));
    }
    socket.write_all(request)?;
    socket.shutdown(std::net::Shutdown::Write)?;
    let mut bytes = Vec::new();
    (&mut socket)
        .take(FRAME_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > FRAME_LIMIT {
        return Err(PodError::Invalid("pod response frame exceeded bound"));
    }
    Ok((bytes, peer))
}

pub struct PodClient {
    manifest_path: PathBuf,
    manifest: MacManifest,
    supervisor_pid: u32,
    supervisor_start: String,
}

impl PodClient {
    pub fn connect(path: impl AsRef<Path>) -> Result<Self, PodError> {
        let path = path.as_ref();
        let manifest = read_manifest(path)?;
        let mut client = Self {
            manifest_path: path.to_path_buf(),
            manifest,
            supervisor_pid: 0,
            supervisor_start: String::new(),
        };
        let status = client.request_status("status")?;
        client.supervisor_pid = status.supervisor_pid;
        client.supervisor_start = status.supervisor_start;
        Ok(client)
    }
    pub fn manifest_path(&self) -> Result<&Path, PodError> {
        Ok(&self.manifest_path)
    }
    pub fn status(&self) -> Result<PodObservation, PodError> {
        self.request_status("status").map(Into::into)
    }
    pub fn stop(&self) -> Result<PodObservation, PodError> {
        self.request_status("stop").map(Into::into)
    }
    fn request_status(&self, operation: &str) -> Result<MacStatus, PodError> {
        // The stop response may outlive the service's launchd PID listing.
        // Fence registration before effect, then attest the socket peer birth.
        if operation == "stop" && launchd_pid(&self.manifest)? != self.supervisor_pid {
            return Err(PodError::Uncertain(
                "launchd supervisor changed before stop",
            ));
        }
        let request = Request {
            protocol: PROTOCOL.into(),
            pod_id: self.manifest.descriptor.pod_id.clone(),
            attempt_id: self.manifest.descriptor.attempt_id.clone(),
            incarnation: self.manifest.descriptor.incarnation,
            token: self.manifest.token.clone(),
            operation: operation.into(),
            terminal: None,
        };
        let (bytes, peer) = exchange(&self.manifest.socket_path, &serde_json::to_vec(&request)?)
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
            return Err(if response.error_code.as_deref() == Some("uncertain") {
                PodError::Uncertain("pod stop may have affected the child")
            } else {
                PodError::Refused("pod rejected authenticated request")
            });
        }
        let status = response.status.ok_or(if operation == "stop" {
            PodError::Uncertain("pod stop status absent after possible effect")
        } else {
            PodError::Invalid("pod status missing")
        })?;
        attest(&self.manifest, &status, peer, operation != "stop").map_err(|error| {
            if operation == "stop" {
                PodError::Uncertain("pod stop identity not attested after possible effect")
            } else {
                error
            }
        })?;
        if self.supervisor_pid != 0 && self.supervisor_pid != status.supervisor_pid
            || !self.supervisor_start.is_empty() && self.supervisor_start != status.supervisor_start
        {
            return Err(PodError::Uncertain("pod supervisor incarnation changed"));
        }
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
            supervisor_start: self.supervisor_start.clone(),
        })
    }
    pub fn terminal_control(&self, command: TerminalCommand) -> Result<TerminalReply, PodError> {
        if command.read_only() {
            return Err(PodError::Invalid(
                "read-only terminal command belongs to viewer",
            ));
        }
        terminal_exchange(
            &self.manifest.socket_path,
            &self.manifest.descriptor.pod_id,
            &self.manifest.descriptor.attempt_id,
            self.manifest.descriptor.incarnation,
            &self.manifest.token,
            &self.supervisor_start,
            command,
        )
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
        PodClient::viewer(self).map(|v| Box::new(v) as Box<dyn TerminalViewerPort>)
    }
}

pub struct TerminalViewer {
    socket_path: PathBuf,
    pod_id: String,
    attempt_id: String,
    incarnation: u64,
    resource_id: String,
    token: String,
    supervisor_start: String,
}

impl TerminalViewer {
    pub fn attach(&self) -> Result<TerminalView, PodError> {
        match terminal_exchange(
            &self.socket_path,
            &self.pod_id,
            &self.attempt_id,
            self.incarnation,
            &self.token,
            &self.supervisor_start,
            TerminalCommand::Attach {
                resource_id: self.resource_id.clone(),
                incarnation: self.incarnation,
            },
        )? {
            TerminalReply::View { value } => Ok(value),
            _ => Err(PodError::Invalid("terminal attach response mismatch")),
        }
    }
    pub fn events_after(&self, after: u64, limit: usize) -> Result<TerminalEventPage, PodError> {
        match terminal_exchange(
            &self.socket_path,
            &self.pod_id,
            &self.attempt_id,
            self.incarnation,
            &self.token,
            &self.supervisor_start,
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
    fn attach(&self) -> Result<TerminalView, PodError> {
        TerminalViewer::attach(self)
    }
    fn events_after(&self, after: u64, limit: usize) -> Result<TerminalEventPage, PodError> {
        TerminalViewer::events_after(self, after, limit)
    }
}

fn terminal_exchange(
    endpoint: &Path,
    pod_id: &str,
    attempt_id: &str,
    incarnation: u64,
    token: &str,
    expected_start: &str,
    command: TerminalCommand,
) -> Result<TerminalReply, PodError> {
    let mutation = !command.read_only();
    let request = Request {
        protocol: PROTOCOL.into(),
        pod_id: pod_id.into(),
        attempt_id: attempt_id.into(),
        incarnation,
        token: token.into(),
        operation: "terminal".into(),
        terminal: Some(command),
    };
    let (bytes, peer) = exchange(endpoint, &serde_json::to_vec(&request)?).map_err(|error| {
        if mutation {
            PodError::Uncertain("terminal transport lost after possible input; do not replay")
        } else {
            error
        }
    })?;
    let boot = podbay_macos_sys::boot_time()?;
    if peer.birth.identity(boot.0, boot.1) != expected_start {
        return Err(PodError::Uncertain("terminal server process birth changed"));
    }
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
    response.terminal.ok_or(if mutation {
        PodError::Uncertain("terminal mutation reply missing")
    } else {
        PodError::Invalid("terminal reply missing")
    })
}

impl From<MacStatus> for PodObservation {
    fn from(value: MacStatus) -> Self {
        Self {
            protocol: value.protocol,
            pod_id: value.pod_id,
            attempt_id: value.attempt_id,
            incarnation: value.incarnation,
            manifest_digest: value.manifest_digest,
            supervisor: ProcessIdentity {
                native_id: value.supervisor_pid.to_string(),
                start_identity: Some(value.supervisor_start),
            },
            child: ProcessIdentity {
                native_id: value.child_pid.to_string(),
                start_identity: Some(value.child_start),
            },
            child_running: value.child_running,
            exit_code: value.exit_code,
            evidence: SupervisorEvidence::MacLaunchd {
                label: value.label,
                bootstrap_domain: value.bootstrap_domain,
                plist_digest: value.plist_digest,
                tree_coverage: MacTreeCoverage::ObservedSubset,
                scope_fencing: MacScopeFencing::CooperativeUnverified,
                login_session_only: true,
            },
        }
    }
}

/// A recorded slot is never relaunched implicitly. The first launch writes
/// both private files, asks launchd to bootstrap exactly once, then attests.
pub fn launch(
    descriptor: LaunchDescriptor,
    directory: impl AsRef<Path>,
    pod_binary: impl AsRef<Path>,
) -> Result<PodClient, PodError> {
    descriptor.validate()?;
    let directory = directory.as_ref();
    let pod_binary = pod_binary.as_ref();
    private_directory(directory)?;
    if !pod_binary.is_absolute() || !pod_binary.is_file() {
        return Err(PodError::Invalid(
            "macOS pod binary is not an absolute regular file",
        ));
    }
    let path = manifest_path(directory, &descriptor)?;
    if fs::symlink_metadata(&path).is_ok() {
        let existing = read_manifest(&path)?;
        if existing.descriptor != descriptor {
            return Err(PodError::Conflict("recorded pod launch descriptor changed"));
        }
        if existing.pod_binary != pod_binary {
            return Err(PodError::Conflict("recorded pod binary path changed"));
        }
        return PodClient::connect(&path).map_err(|_| {
            PodError::Uncertain("recorded macOS pod is unreachable; no replacement was launched")
        });
    }
    let mut token = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut token)?;
    let mut viewer_token = [0u8; 32];
    if descriptor.pty.is_some() {
        File::open("/dev/urandom")?.read_exact(&mut viewer_token)?;
    }
    let plist = plist_bytes(&slot_label(&path)?, pod_binary, &path)?;
    let manifest = MacManifest {
        digest: descriptor.digest()?,
        pod_binary: pod_binary.to_path_buf(),
        token: hex(&token),
        viewer_token: descriptor.pty.map(|_| hex(&viewer_token)),
        socket_path: path.with_extension("sock"),
        plist_path: path.with_extension("plist"),
        label: slot_label(&path)?,
        bootstrap_domain: bootstrap_domain(),
        plist_digest: plist_digest(&plist),
        descriptor,
    };
    if manifest.socket_path.as_os_str().len() > 100 {
        return Err(PodError::Invalid(
            "macOS socket path exceeds sockaddr_un bound",
        ));
    }
    MacDurableFiles.create_private(&path, &serde_json::to_vec(&manifest)?)?;
    MacDurableFiles.create_private(&manifest.plist_path, &plist)?;
    let started = Command::new("/bin/launchctl")
        .arg("bootstrap")
        .arg(&manifest.bootstrap_domain)
        .arg(&manifest.plist_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !matches!(started, Ok(status) if status.success()) {
        return Err(PodError::Uncertain(
            "launchd bootstrap was not attested; files retained",
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
        "launchd pod socket and child were not attested; files retained",
    ))
}

/// Private launchd entry point. The socket is bound before any child effect.
pub fn serve(path: impl AsRef<Path>) -> Result<(), PodError> {
    let path = path.as_ref();
    let manifest = read_manifest(path)?;
    if fs::symlink_metadata(&manifest.socket_path).is_ok() {
        return Err(PodError::Uncertain("recorded macOS socket already exists"));
    }
    let listener = UnixListener::bind(&manifest.socket_path)?;
    fs::set_permissions(&manifest.socket_path, fs::Permissions::from_mode(0o600))?;
    let boot = podbay_macos_sys::boot_time()?;
    let supervisor = podbay_macos_sys::process_birth(std::process::id() as i32)?;
    let supervisor_start = supervisor.identity(boot.0, boot.1);
    if launchd_pid(&manifest)? != supervisor.pid as u32 {
        return Err(PodError::Uncertain(
            "launchd registration does not attest this supervisor",
        ));
    }
    let descriptor = &manifest.descriptor;
    let mut child = match descriptor.pty {
        Some(spec) => ChildResource::Pty(MacBackend.spawn(descriptor, spec, path)?),
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
    let child_birth = podbay_macos_sys::process_birth(child.id()? as i32)?;
    let child_start = child_birth.identity(boot.0, boot.1);
    let mut exit_code = None;
    let mut settled = false;
    for incoming in listener.incoming() {
        let mut stream = incoming?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let peer = podbay_macos_sys::peer_identity(stream.as_fd());
        let mut bytes = Vec::new();
        (&mut stream)
            .take(FRAME_LIMIT + 1)
            .read_to_end(&mut bytes)?;
        let parsed = if bytes.len() as u64 > FRAME_LIMIT {
            Err(PodError::Invalid("pod request frame exceeded bound"))
        } else {
            serde_json::from_slice::<Request>(&bytes).map_err(PodError::from)
        };
        let authorized = peer
            .as_ref()
            .is_ok_and(|peer| peer.uid == podbay_macos_sys::effective_uid())
            && parsed.as_ref().is_ok_and(|request| {
                let expected = if request.operation == "terminal"
                    && request
                        .terminal
                        .as_ref()
                        .is_some_and(TerminalCommand::read_only)
                {
                    manifest.viewer_token.as_deref()
                } else {
                    Some(manifest.token.as_str())
                };
                request.protocol == PROTOCOL
                    && request.pod_id == descriptor.pod_id
                    && request.attempt_id == descriptor.attempt_id
                    && request.incarnation == descriptor.incarnation
                    && expected.is_some_and(|token| {
                        constant_time_equal(request.token.as_bytes(), token.as_bytes())
                    })
            });
        if !authorized {
            respond(&mut stream, refusal("request refused", "refused"))?;
            continue;
        }
        let request = parsed.expect("checked request");
        if !settled && let Some(code) = child.try_wait()? {
            settled = true;
            exit_code = code;
        }
        if request.operation == "terminal" {
            let result = request
                .terminal
                .ok_or(PodError::Invalid("terminal command missing"))
                .and_then(|command| {
                    child
                        .terminal()
                        .ok_or(PodError::Refused("pod has no PTY resource"))?
                        .command(command)
                });
            match result {
                Ok(value) => respond(
                    &mut stream,
                    Response {
                        ok: true,
                        status: None,
                        error: None,
                        error_code: None,
                        terminal: Some(value),
                    },
                )?,
                Err(error) => respond(
                    &mut stream,
                    refusal(
                        "terminal command refused or uncertain",
                        if matches!(error, PodError::Uncertain(_)) {
                            "uncertain"
                        } else {
                            "refused"
                        },
                    ),
                )?,
            }
            continue;
        }
        let stopping = request.operation == "stop";
        if request.operation != "status" && !stopping {
            respond(&mut stream, refusal("unsupported operation", "refused"))?;
            continue;
        }
        if stopping && !settled {
            if child.stop(child_birth).is_err() {
                respond(
                    &mut stream,
                    refusal("child stop outcome unknown", "uncertain"),
                )?;
                continue;
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if let Some(code) = child.try_wait()? {
                    settled = true;
                    exit_code = code;
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if !settled {
                respond(
                    &mut stream,
                    refusal("child did not settle after stop", "uncertain"),
                )?;
                continue;
            }
        }
        let status = MacStatus {
            protocol: PROTOCOL.into(),
            pod_id: descriptor.pod_id.clone(),
            attempt_id: descriptor.attempt_id.clone(),
            incarnation: descriptor.incarnation,
            manifest_digest: manifest.digest.clone(),
            supervisor_pid: supervisor.pid as u32,
            supervisor_start: supervisor_start.clone(),
            child_pid: child_birth.pid as u32,
            child_start: child_start.clone(),
            label: manifest.label.clone(),
            bootstrap_domain: manifest.bootstrap_domain.clone(),
            plist_digest: manifest.plist_digest.clone(),
            child_running: !settled,
            exit_code,
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
        if stopping {
            break;
        }
    }
    let _ = fs::remove_file(&manifest.socket_path);
    Ok(())
}

fn launchd_pid(manifest: &MacManifest) -> Result<u32, PodError> {
    let service = format!("{}/{}", manifest.bootstrap_domain, manifest.label);
    let output = Command::new("/bin/launchctl")
        .arg("print")
        .arg(service)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()?;
    if !output.status.success() || output.stdout.len() > 262_144 {
        return Err(PodError::Uncertain(
            "launchd service registration unavailable",
        ));
    }
    let output = String::from_utf8(output.stdout)
        .map_err(|_| PodError::Invalid("launchd status is not UTF-8"))?;
    let pids = output
        .lines()
        .filter_map(|line| line.trim().strip_prefix("pid = "))
        .filter_map(|value| value.trim().parse::<u32>().ok())
        .collect::<Vec<_>>();
    match pids.as_slice() {
        [pid] if *pid > 0 => Ok(*pid),
        _ => Err(PodError::Uncertain(
            "launchd did not expose one attested service PID",
        )),
    }
}

fn attest(
    manifest: &MacManifest,
    status: &MacStatus,
    peer: podbay_macos_sys::PeerIdentity,
    require_registration: bool,
) -> Result<(), PodError> {
    let boot = podbay_macos_sys::boot_time()?;
    if status.protocol != PROTOCOL
        || status.pod_id != manifest.descriptor.pod_id
        || status.attempt_id != manifest.descriptor.attempt_id
        || status.incarnation != manifest.descriptor.incarnation
        || status.manifest_digest != manifest.digest
        || status.supervisor_pid != peer.birth.pid as u32
        || status.supervisor_start != peer.birth.identity(boot.0, boot.1)
        || status.child_pid == 0
        || status.child_start.is_empty()
        || status.label != manifest.label
        || status.bootstrap_domain != manifest.bootstrap_domain
        || status.plist_digest != manifest.plist_digest
        || (require_registration && launchd_pid(manifest)? != status.supervisor_pid)
    {
        return Err(PodError::Invalid(
            "macOS pod identity, birth, or launchd registration failed",
        ));
    }
    if status.child_running {
        let child = podbay_macos_sys::process_birth(status.child_pid as i32)?;
        if status.child_start != child.identity(boot.0, boot.1) {
            return Err(PodError::Invalid("macOS child birth attestation failed"));
        }
    }
    Ok(())
}

fn refusal(message: &str, code: &str) -> Response {
    Response {
        ok: false,
        status: None,
        error: Some(message.into()),
        error_code: Some(code.into()),
        terminal: None,
    }
}

fn respond(stream: &mut UnixStream, response: Response) -> Result<(), PodError> {
    let bytes = serde_json::to_vec(&response)?;
    if bytes.len() as u64 > FRAME_LIMIT {
        let possible_effect = matches!(
            response.terminal,
            Some(TerminalReply::BytesWritten | TerminalReply::Resized { .. })
        );
        let fallback = refusal(
            "terminal response exceeded frame bound",
            if possible_effect {
                "uncertain"
            } else {
                "refused"
            },
        );
        stream.write_all(&serde_json::to_vec(&fallback)?)?;
    } else {
        stream.write_all(&bytes)?;
    }
    Ok(())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}
