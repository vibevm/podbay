use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::manifest::{
    LaunchDescriptor, PROTOCOL, PodError, PodManifest, PodStatus, hex, manifest_path,
    private_directory, read_manifest, unit_name, write_manifest,
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
    Pty(PtyProcess),
}

impl ChildResource {
    fn id(&self) -> Result<u32, PodError> {
        match self {
            Self::Pipe(child) => Ok(child.id()),
            Self::Pty(pty) => pty.process_id(),
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
            Self::Pty(pty) => pty.kill(),
        }
    }
    fn terminal(&mut self) -> Option<&mut PtyProcess> {
        match self {
            Self::Pty(pty) => Some(pty),
            Self::Pipe(_) => None,
        }
    }
}

pub struct PodClient {
    manifest_path: PathBuf,
    manifest: PodManifest,
}

impl PodClient {
    pub fn connect(path: impl AsRef<Path>) -> Result<Self, PodError> {
        let path = path.as_ref();
        let manifest = read_manifest(path)?;
        let client = Self {
            manifest_path: path.to_path_buf(),
            manifest,
        };
        client.status()?;
        Ok(client)
    }

    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    pub fn status(&self) -> Result<PodStatus, PodError> {
        self.request("status")
    }

    /// Stop is explicit and bounded; an ambiguous transport result stays uncertain.
    pub fn stop(&self) -> Result<PodStatus, PodError> {
        self.request("stop")
    }

    fn request(&self, operation: &str) -> Result<PodStatus, PodError> {
        let mut socket = UnixStream::connect(&self.manifest.socket_path)?;
        socket.set_read_timeout(Some(Duration::from_secs(3)))?;
        socket.set_write_timeout(Some(Duration::from_secs(3)))?;
        let request = Request {
            protocol: PROTOCOL.to_owned(),
            pod_id: self.manifest.descriptor.pod_id.clone(),
            attempt_id: self.manifest.descriptor.attempt_id.clone(),
            incarnation: self.manifest.descriptor.incarnation,
            token: self.manifest.token.clone(),
            operation: operation.to_owned(),
            terminal: None,
        };
        socket.write_all(&serde_json::to_vec(&request)?)?;
        socket.shutdown(std::net::Shutdown::Write)?;
        let mut bytes = Vec::new();
        socket.take(FRAME_LIMIT + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > FRAME_LIMIT {
            return Err(PodError::Invalid("pod response frame exceeded bound"));
        }
        let response: Response = serde_json::from_slice(&bytes)?;
        if !response.ok {
            return Err(PodError::Refused("pod rejected authenticated request"));
        }
        let status = response
            .status
            .ok_or(PodError::Invalid("pod status missing"))?;
        attest(&self.manifest, &status)?;
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
            command,
        )
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

fn terminal_exchange(
    socket_path: &Path,
    pod_id: &str,
    attempt_id: &str,
    incarnation: u64,
    token: &str,
    command: TerminalCommand,
) -> Result<TerminalReply, PodError> {
    let mutation = !command.read_only();
    let mut socket = UnixStream::connect(socket_path)?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    socket.set_write_timeout(Some(Duration::from_secs(3)))?;
    let request = Request {
        protocol: PROTOCOL.to_owned(),
        pod_id: pod_id.into(),
        attempt_id: attempt_id.into(),
        incarnation,
        token: token.into(),
        operation: "terminal".into(),
        terminal: Some(command),
    };
    socket
        .write_all(&serde_json::to_vec(&request)?)
        .map_err(|error| terminal_transport(error, mutation))?;
    socket
        .shutdown(std::net::Shutdown::Write)
        .map_err(|error| terminal_transport(error, mutation))?;
    let mut bytes = Vec::new();
    socket
        .take(FRAME_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| terminal_transport(error, mutation))?;
    if bytes.len() as u64 > FRAME_LIMIT {
        return Err(if mutation {
            PodError::Uncertain("terminal response oversized after possible input")
        } else {
            PodError::Invalid("terminal response frame exceeded bound")
        });
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
    response
        .terminal
        .ok_or(PodError::Invalid("terminal response missing"))
}

fn terminal_transport(error: std::io::Error, mutation: bool) -> PodError {
    if mutation {
        PodError::Uncertain("terminal transport lost after possible input; do not replay")
    } else {
        PodError::Io(error)
    }
}

/// Admits one exact manifest. Existing ambiguous state is never launched again.
pub fn launch(
    descriptor: LaunchDescriptor,
    directory: impl AsRef<Path>,
    pod_binary: impl AsRef<Path>,
) -> Result<PodClient, PodError> {
    descriptor.validate()?;
    let directory = directory.as_ref();
    private_directory(directory)?;
    let path = manifest_path(directory, &descriptor)?;
    if fs::symlink_metadata(&path).is_ok() {
        let existing = read_manifest(&path)?;
        if existing.descriptor != descriptor {
            return Err(PodError::Conflict("recorded pod launch descriptor changed"));
        }
        return PodClient::connect(path).map_err(|_| {
            PodError::Uncertain("recorded pod is unreachable; no replacement was launched")
        });
    }
    let mut token = [0_u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut token)?;
    let mut viewer_token = [0_u8; 32];
    if descriptor.pty.is_some() {
        File::open("/dev/urandom")?.read_exact(&mut viewer_token)?;
    }
    let manifest = PodManifest {
        digest: descriptor.digest()?,
        token: hex(&token),
        viewer_token: descriptor.pty.map(|_| hex(&viewer_token)),
        socket_path: path.with_extension("sock"),
        unit_name: unit_name(&path)?,
        descriptor,
    };
    if manifest.socket_path.as_os_str().len() > 100 || !pod_binary.as_ref().is_absolute() {
        return Err(PodError::Invalid("socket path or pod binary is not usable"));
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
        ])
        .arg(format!("--unit={}", manifest.unit_name))
        .arg(pod_binary.as_ref())
        .arg("serve")
        .arg("--manifest")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !matches!(started, Ok(status) if status.success()) {
        return Err(PodError::Uncertain(
            "systemd admission was not attested; manifest retained",
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
        "pod socket and child were not attested; manifest retained",
    ))
}

/// Internal systemd service entry. The authenticated socket binds before any child is spawned.
pub fn serve(manifest_path: impl AsRef<Path>) -> Result<(), PodError> {
    let manifest = read_manifest(manifest_path.as_ref())?;
    if fs::symlink_metadata(&manifest.socket_path).is_ok() {
        return Err(PodError::Uncertain("recorded socket already exists"));
    }
    let listener = UnixListener::bind(&manifest.socket_path)?;
    fs::set_permissions(&manifest.socket_path, fs::Permissions::from_mode(0o600))?;
    let cgroup_path = cgroup_path()?;
    if !cgroup_path.contains(&manifest.unit_name) {
        return Err(PodError::Invalid(
            "pod process is outside its declared systemd unit",
        ));
    }
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    let descriptor = &manifest.descriptor;
    let mut child = match descriptor.pty {
        Some(spec) => {
            ChildResource::Pty(PtyProcess::spawn(descriptor, spec, manifest_path.as_ref())?)
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
    for incoming in listener.incoming() {
        let mut stream = incoming?;
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
            let expected_token = if request.operation == "terminal"
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
                && expected_token.is_some_and(|token| {
                    constant_time_equal(request.token.as_bytes(), token.as_bytes())
                })
        });
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
            continue;
        }
        let request = parsed.expect("checked request");
        if !settled && let Some(status) = child.try_wait()? {
            settled = true;
            exit_code = status;
        }
        if request.operation == "terminal" {
            let result = request
                .terminal
                .ok_or(PodError::Invalid("terminal command missing"))
                .and_then(|command| {
                    child
                        .terminal()
                        .ok_or(PodError::Refused("pod has no PTY resource"))?
                        .handle(command)
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
                    Response {
                        ok: false,
                        status: None,
                        error: Some("terminal command refused or uncertain".into()),
                        error_code: Some(if matches!(error, PodError::Uncertain(_)) {
                            "uncertain".into()
                        } else {
                            "refused".into()
                        }),
                        terminal: None,
                    },
                )?,
            }
            continue;
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
            continue;
        }
        let status = PodStatus {
            protocol: PROTOCOL.to_owned(),
            pod_id: descriptor.pod_id.clone(),
            attempt_id: descriptor.attempt_id.clone(),
            incarnation: descriptor.incarnation,
            manifest_digest: manifest.digest.clone(),
            supervisor_pid: std::process::id(),
            child_pid,
            child_start_ticks,
            boot_id: boot_id.clone(),
            unit_name: manifest.unit_name.clone(),
            cgroup_path: cgroup_path.clone(),
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

fn attest(manifest: &PodManifest, status: &PodStatus) -> Result<(), PodError> {
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
        || !status.cgroup_path.contains(&manifest.unit_name)
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

    #[test]
    fn lost_response_after_possible_input_is_uncertain() {
        let error = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "synthetic");
        assert!(matches!(
            terminal_transport(error, true),
            PodError::Uncertain(_)
        ));
        let read_error = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "synthetic");
        assert!(matches!(
            terminal_transport(read_error, false),
            PodError::Io(_)
        ));
    }
}
