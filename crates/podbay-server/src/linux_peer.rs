//! Linux OS subject for one accepted Unix connection.
//! This does not bind an actor, prove a credential, or authorize a command.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::os::unix::net::UnixStream;

use podbay_host::{AuthenticatedProcessSubject, HostError};
use podbay_pod::{LinuxPeerError, LinuxPeerEvidence};

#[derive(Debug)]
pub enum LinuxAcceptedPeerError {
    Kernel(LinuxPeerError),
    InvalidPid,
    Subject(HostError),
}

impl Display for LinuxAcceptedPeerError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kernel(error) => write!(formatter, "Linux peer evidence refused: {error}"),
            Self::InvalidPid => formatter.write_str("Linux peer PID cannot be represented"),
            Self::Subject(error) => write!(formatter, "Linux process subject refused: {error:?}"),
        }
    }
}
impl Error for LinuxAcceptedPeerError {}
impl From<LinuxPeerError> for LinuxAcceptedPeerError {
    fn from(error: LinuxPeerError) -> Self {
        Self::Kernel(error)
    }
}

/// Pinned SO_PEERCRED and fresh procfs evidence for one accepted stream.
/// GID and boot identity remain in the shared evidence even though the host
/// process-subject type represents only UID, PID, start ticks, and cgroup.
pub struct LinuxAcceptedPeerEvidence {
    kernel: LinuxPeerEvidence,
    subject: AuthenticatedProcessSubject,
}

impl LinuxAcceptedPeerEvidence {
    /// The caller must pass the accepted server-side connection. Request JSON
    /// is never used to construct this subject. This is not actor authentication.
    pub fn from_accepted(socket: &UnixStream) -> Result<Self, LinuxAcceptedPeerError> {
        let kernel = LinuxPeerEvidence::from_accepted(socket)?;
        let pid = u32::try_from(kernel.pid()).map_err(|_| LinuxAcceptedPeerError::InvalidPid)?;
        let subject = AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(
            kernel.uid(),
            pid,
            kernel.start_ticks(),
            kernel.cgroup(),
        )
        .map_err(LinuxAcceptedPeerError::Subject)?;
        let result = Self { kernel, subject };
        result.recheck_before_dispatch(socket)?;
        Ok(result)
    }

    pub fn subject(&self) -> &AuthenticatedProcessSubject {
        &self.subject
    }

    pub fn kernel_evidence(&self) -> &LinuxPeerEvidence {
        &self.kernel
    }

    /// Reattest the exact socket peer, including current effective UID/GID,
    /// live state, birth, boot and cgroup, before a higher layer dispatches.
    /// The higher layer must separately verify actor credentials and grants.
    pub fn recheck_before_dispatch(
        &self,
        socket: &UnixStream,
    ) -> Result<&AuthenticatedProcessSubject, LinuxAcceptedPeerError> {
        self.kernel
            .recheck_before_effect(socket, self.kernel.attested_peer())?;
        Ok(&self.subject)
    }
}
