//! Narrow, audited PB27a Win32 process and Job Object facade.
//! A Windows native fixture is required before this backend is operational.

use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    pub pid: u32,
    /// `GetProcessTimes` creation time in 100 ns units since 1601 UTC.
    pub creation_100ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PossibleProcess {
    pub pid: u32,
    pub creation_100ns: Option<u64>,
}

#[derive(Debug)]
pub enum Win32Error {
    Invalid(&'static str),
    Unsupported(&'static str),
    Uncertain(&'static str),
    UncertainAfterCreate {
        message: &'static str,
        process: PossibleProcess,
    },
    Os(std::io::Error),
}

impl fmt::Display for Win32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "invalid Win32 launch: {message}"),
            Self::Unsupported(message) => write!(f, "unsupported Win32 containment: {message}"),
            Self::Uncertain(message) => write!(f, "uncertain Win32 process outcome: {message}"),
            Self::UncertainAfterCreate { message, process } => write!(
                f,
                "uncertain Win32 process outcome for PID {} (birth {:?}): {message}",
                process.pid, process.creation_100ns
            ),
            Self::Os(error) => write!(f, "Win32 call failed: {error}"),
        }
    }
}
impl std::error::Error for Win32Error {}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResumeFence {
    Unverified,
    IndependentPod,
    AssignedChild,
}

#[cfg(any(windows, test))]
impl ResumeFence {
    fn permits(self, expected: Self) -> Result<(), Win32Error> {
        if self == expected {
            Ok(())
        } else {
            Err(Win32Error::Unsupported(
                "process containment was not proven before resume",
            ))
        }
    }
}

#[cfg(windows)]
mod conpty;
#[cfg(any(windows, test))]
mod conpty_model;
#[cfg(windows)]
mod durable;
mod durable_model;
#[cfg(windows)]
mod overlapped;
#[cfg(any(windows, test))]
mod overlapped_model;
#[cfg(windows)]
mod pipe;
mod pipe_model;
#[cfg(windows)]
mod security;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use conpty::ConPtyProcess;
#[cfg(windows)]
pub use conpty_model::{OutputChunk, OutputPage};
#[cfg(windows)]
pub use durable::DurableDirectory;
pub use durable_model::{
    CheckpointRecovery, DurabilityEvidence, FlushReceipt, Record as DurableRecord,
    RecordKind as DurableRecordKind, Unknown as DurableUnknown, decode_log as decode_durable_log,
    recover_checkpoint,
};
#[cfg(windows)]
pub use pipe::{AcceptedPipe, PipeClient, PipeServer};
pub use pipe_model::{MAX_FRAME as MAX_PIPE_FRAME, PeerGrant, PipeAction, PipeRequest, PipeRole};
#[cfg(windows)]
pub use windows::{
    PodJob, RunningProcess, SuspendedProcess, launch_independent_suspended, open_exact_process,
};

#[cfg(not(windows))]
pub fn unsupported_on_this_host() -> Win32Error {
    Win32Error::Unsupported("PB27a requires a Windows host")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resume_needs_exact_containment_proof() {
        assert!(
            ResumeFence::Unverified
                .permits(ResumeFence::IndependentPod)
                .is_err()
        );
        assert!(
            ResumeFence::AssignedChild
                .permits(ResumeFence::IndependentPod)
                .is_err()
        );
        assert!(
            ResumeFence::IndependentPod
                .permits(ResumeFence::IndependentPod)
                .is_ok()
        );
        assert!(
            ResumeFence::AssignedChild
                .permits(ResumeFence::AssignedChild)
                .is_ok()
        );
    }

    #[test]
    fn process_identity_requires_birth_time_not_pid_only() {
        let old = ProcessIdentity {
            pid: 42,
            creation_100ns: 1,
        };
        let reused = ProcessIdentity {
            pid: 42,
            creation_100ns: 2,
        };
        assert_ne!(old, reused);
    }

    #[test]
    fn possible_effect_error_carries_reconciliation_identity() {
        let error = Win32Error::UncertainAfterCreate {
            message: "cleanup not attested",
            process: PossibleProcess {
                pid: 42,
                creation_100ns: Some(7),
            },
        };
        assert!(matches!(
            error,
            Win32Error::UncertainAfterCreate {
                process: PossibleProcess {
                    pid: 42,
                    creation_100ns: Some(7)
                },
                ..
            }
        ));
    }
}
