use std::fmt;
#[cfg(target_os = "linux")]
use std::fs::{self, File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use podbay_core::{AttemptId, Epoch, PodId, ResourceId, RunId, ScopeId, SessionId};
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
    let mut hash = Sha256::new();
    hash.update(b"podbay-pb05-slot/1\0");
    for field in [&descriptor.pod_id, &descriptor.attempt_id] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    hash.update(descriptor.incarnation.to_be_bytes());
    Ok(directory.join(format!("{}.json", &hex(&hash.finalize())[..32])))
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
