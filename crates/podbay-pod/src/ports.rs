//! OS-neutral pod observations and backend ports. Native evidence is explicit.
use std::io::{Read, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::manifest::{LaunchDescriptor, PodError, PtySpec};
use crate::terminal_protocol::{TerminalCommand, TerminalEventPage, TerminalReply, TerminalView};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProcessIdentity {
    /// Opaque within the backend. Never substitutes for a PodId or authority.
    pub native_id: String,
    pub start_identity: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "backend", rename_all = "snake_case")]
pub enum SupervisorEvidence {
    LinuxSystemd {
        unit_name: String,
        cgroup_path: String,
        boot_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PodObservation {
    pub protocol: String,
    pub pod_id: String,
    pub attempt_id: String,
    pub incarnation: u64,
    pub manifest_digest: String,
    pub supervisor: ProcessIdentity,
    pub child: ProcessIdentity,
    pub child_running: bool,
    pub exit_code: Option<i32>,
    pub evidence: SupervisorEvidence,
}

#[cfg(target_os = "linux")]
impl From<crate::manifest::PodStatus> for PodObservation {
    fn from(status: crate::manifest::PodStatus) -> Self {
        let child_start = format!("{}:{}", status.boot_id, status.child_start_ticks);
        Self {
            protocol: status.protocol,
            pod_id: status.pod_id,
            attempt_id: status.attempt_id,
            incarnation: status.incarnation,
            manifest_digest: status.manifest_digest,
            supervisor: ProcessIdentity {
                native_id: status.supervisor_pid.to_string(),
                start_identity: Some(format!(
                    "{}:{}",
                    status.boot_id, status.supervisor_start_ticks
                )),
            },
            child: ProcessIdentity {
                native_id: status.child_pid.to_string(),
                start_identity: Some(child_start),
            },
            child_running: status.child_running,
            exit_code: status.exit_code,
            evidence: SupervisorEvidence::LinuxSystemd {
                unit_name: status.unit_name,
                cgroup_path: status.cgroup_path,
                boot_id: status.boot_id,
            },
        }
    }
}

pub trait TerminalViewerPort {
    fn attach(&self) -> Result<TerminalView, PodError>;
    fn events_after(&self, after: u64, limit: usize) -> Result<TerminalEventPage, PodError>;
}

pub trait PodControlPort {
    fn status(&self) -> Result<PodObservation, PodError>;
    fn stop(&self) -> Result<PodObservation, PodError>;
    fn terminal_control(&self, command: TerminalCommand) -> Result<TerminalReply, PodError>;
    fn viewer(&self) -> Result<Box<dyn TerminalViewerPort>, PodError>;
}

pub trait SupervisorBackend {
    fn launch(
        &self,
        descriptor: LaunchDescriptor,
        private_directory: &Path,
        pod_binary: &Path,
    ) -> Result<Box<dyn PodControlPort>, PodError>;
    fn connect(&self, manifest_path: &Path) -> Result<Box<dyn PodControlPort>, PodError>;
}

pub trait TerminalResource: Send {
    fn process_identity(&self) -> Result<String, PodError>;
    fn try_wait(&mut self) -> Result<Option<i32>, PodError>;
    fn stop(&mut self) -> Result<(), PodError>;
    fn command(&mut self, command: TerminalCommand) -> Result<TerminalReply, PodError>;
}

pub trait TerminalBackend {
    fn spawn(
        &self,
        descriptor: &LaunchDescriptor,
        spec: PtySpec,
        manifest_path: &Path,
    ) -> Result<Box<dyn TerminalResource>, PodError>;
}

pub trait LocalConnection: Read + Write + Send {}
impl<T: Read + Write + Send> LocalConnection for T {}

pub trait LocalControlTransport {
    fn exchange(&self, endpoint: &Path, request: &[u8]) -> Result<Vec<u8>, PodError>;
}

/// Opaque identity of a held native file. Equality can detect replacement
/// across reopen; the bytes do not grant authority or encode a portable PID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableFileIdentity {
    backend: &'static str,
    native: Vec<u8>,
}

impl DurableFileIdentity {
    /// Backend-specific bytes are bounded comparison evidence, not an
    /// authority token. Native backends may construct their own stable ID.
    pub fn from_backend(backend: &'static str, native: Vec<u8>) -> Result<Self, PodError> {
        if !(3..=64).contains(&backend.len())
            || !backend.bytes().all(|byte| byte.is_ascii_graphic())
            || !(1..=64).contains(&native.len())
        {
            return Err(PodError::Invalid("durable file identity bounds"));
        }
        Ok(Self { backend, native })
    }
}

/// One held, private append log. A failed write or sync returns Uncertain and
/// poisons the handle; the caller must reopen, inspect its complete raw tail,
/// and never assume the last record was absent. Frame parsing belongs to the
/// journal, not this OS port.
pub trait DurableAppendLog: Send {
    fn identity(&self) -> &DurableFileIdentity;
    fn len(&self) -> u64;
    fn read_all_bounded(&mut self) -> Result<Vec<u8>, PodError>;
    fn append_synced(&mut self, bytes: &[u8]) -> Result<(), PodError>;
}

pub trait DurableFiles {
    fn create_private(&self, path: &Path, bytes: &[u8]) -> Result<(), PodError>;
    fn append_durable(&self, path: &Path, bytes: &[u8]) -> Result<(), PodError>;
    fn replace_durable(&self, path: &Path, bytes: &[u8]) -> Result<(), PodError>;

    /// Open or create a single-writer log with a held native file identity.
    /// Backends without private no-follow read/reopen and append durability
    /// must refuse before creating a file.
    fn open_private_append_log(
        &self,
        _path: &Path,
        _max_bytes: u64,
    ) -> Result<Box<dyn DurableAppendLog>, PodError> {
        Err(PodError::Unsupported(
            "private durable append log is unavailable on this backend",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct LegacyOnlyFiles;

    impl DurableFiles for LegacyOnlyFiles {
        fn create_private(&self, _: &Path, _: &[u8]) -> Result<(), PodError> {
            panic!("default-deny open may not create a file")
        }
        fn append_durable(&self, _: &Path, _: &[u8]) -> Result<(), PodError> {
            panic!("default-deny open may not append")
        }
        fn replace_durable(&self, _: &Path, _: &[u8]) -> Result<(), PodError> {
            panic!("default-deny open may not replace")
        }
    }

    #[test]
    fn held_append_log_defaults_to_unsupported_without_side_effect() {
        assert!(matches!(
            LegacyOnlyFiles.open_private_append_log(Path::new("unused"), 32),
            Err(PodError::Unsupported(_))
        ));
    }
}
