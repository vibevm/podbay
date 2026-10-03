use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::manifest::{
    LaunchDescriptor, PROTOCOL, PodError, PodManifest, PodStatus, hex, manifest_path,
    private_directory, read_manifest, unit_name, write_manifest,
};

const FRAME_LIMIT: u64 = 4_096;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: String,
    pod_id: String,
    attempt_id: String,
    incarnation: u64,
    token: String,
    operation: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    ok: bool,
    status: Option<PodStatus>,
    error: Option<String>,
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
    let manifest = PodManifest {
        digest: descriptor.digest()?,
        token: hex(&token),
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
    let mut child = Command::new(&descriptor.executable)
        .args(&descriptor.args)
        .current_dir(&descriptor.cwd)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let child_start_ticks = start_ticks(child.id())?;
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
            request.protocol == PROTOCOL
                && request.pod_id == descriptor.pod_id
                && request.attempt_id == descriptor.attempt_id
                && request.incarnation == descriptor.incarnation
                && constant_time_equal(request.token.as_bytes(), manifest.token.as_bytes())
        });
        if !authorized {
            respond(
                &mut stream,
                Response {
                    ok: false,
                    status: None,
                    error: Some("request refused".into()),
                },
            )?;
            continue;
        }
        let request = parsed.expect("checked request");
        if !settled && let Some(status) = child.try_wait()? {
            settled = true;
            exit_code = status.code();
        }
        let stopping = request.operation == "stop";
        if stopping && !settled {
            child.kill()?;
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if let Some(status) = child.try_wait()? {
                    settled = true;
                    exit_code = status.code();
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
            child_pid: child.id(),
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
    stream.write_all(&serde_json::to_vec(&response)?)?;
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
