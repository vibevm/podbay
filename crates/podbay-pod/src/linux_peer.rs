//! Linux peer evidence for an accepted Unix control connection.
//! This adapter observes the kernel and procfs; it grants no pod authority.
use std::fmt::{Display, Formatter};
use std::fs;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use podbay_core::AttestedPeer;

#[derive(Debug)]
pub enum LinuxPeerError {
    Io(io::Error),
    InvalidEvidence(&'static str),
    EvidenceChanged,
    WrongContainment,
}

impl Display for LinuxPeerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "Linux peer evidence unavailable: {error}"),
            Self::InvalidEvidence(reason) => write!(f, "Linux peer evidence malformed: {reason}"),
            Self::EvidenceChanged => f.write_str("Linux socket peer birth or containment changed"),
            Self::WrongContainment => {
                f.write_str("Linux socket peer is outside expected containment")
            }
        }
    }
}
impl std::error::Error for LinuxPeerError {}
impl From<io::Error> for LinuxPeerError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Snapshot of a kernel-authenticated socket peer plus its procfs process
/// birth and cgroup. The request body never contributes an identity field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxPeerEvidence {
    pid: i32,
    uid: u32,
    gid: u32,
    boot_id: String,
    start_ticks: u64,
    cgroup: String,
    peer: AttestedPeer,
}

impl LinuxPeerEvidence {
    /// The launcher observes its own kernel credentials through a socketpair;
    /// no request body supplies the pinned manager process identity.
    pub fn for_current_process() -> Result<Self, LinuxPeerError> {
        let (first, _second) = UnixStream::pair()?;
        Self::from_accepted(&first)
    }

    /// `socket` must be the accepted connection, not an outgoing client socket.
    /// Failure to read any component refuses before a control effect.
    pub fn from_accepted(socket: &UnixStream) -> Result<Self, LinuxPeerError> {
        let credentials = getsockopt(socket, PeerCredentials)
            .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?;
        let pid = credentials.pid();
        if pid <= 0 {
            return Err(LinuxPeerError::InvalidEvidence("peer PID is absent"));
        }
        let uid = credentials.uid();
        let gid = credentials.gid();
        let boot_id = read_boot_id()?;
        let start_ticks = read_start_ticks(pid)?;
        let cgroup = read_cgroup(pid)?;
        if read_start_ticks(pid)? != start_ticks {
            return Err(LinuxPeerError::EvidenceChanged);
        }
        let peer = AttestedPeer::from_port(
            &format!("linux.uid.{uid}"),
            &format!("linux.pid.{pid}"),
            &format!("linux.boot.{boot_id}"),
            &format!("linux.start.{start_ticks}"),
            &format!("linux.cgroup.{cgroup}"),
        )
        .map_err(|_| LinuxPeerError::InvalidEvidence("portable peer shape refused"))?;
        Ok(Self {
            pid,
            uid,
            gid,
            boot_id,
            start_ticks,
            cgroup,
            peer,
        })
    }

    pub fn attested_peer(&self) -> &AttestedPeer {
        &self.peer
    }
    pub fn pid(&self) -> i32 {
        self.pid
    }
    pub fn uid(&self) -> u32 {
        self.uid
    }
    pub fn gid(&self) -> u32 {
        self.gid
    }
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }
    pub fn start_ticks(&self) -> u64 {
        self.start_ticks
    }
    pub fn cgroup(&self) -> &str {
        &self.cgroup
    }

    /// Exact cgroup equality is required; a unit-name substring is no proof.
    pub fn require_containment(&self, expected_cgroup: &str) -> Result<(), LinuxPeerError> {
        if self.cgroup == expected_cgroup {
            Ok(())
        } else {
            Err(LinuxPeerError::WrongContainment)
        }
    }

    /// Re-read SO_PEERCRED and procfs immediately before an effect. The caller
    /// must also supply the peer currently bound by the portable core fence.
    /// A dead/reused PID, changed birth, boot, cgroup, UID or GID refuses.
    pub fn recheck_before_effect(
        &self,
        socket: &UnixStream,
        expected: &AttestedPeer,
    ) -> Result<(), LinuxPeerError> {
        let fresh = Self::from_accepted(socket)?;
        if fresh == *self && fresh.peer == *expected {
            Ok(())
        } else {
            Err(LinuxPeerError::EvidenceChanged)
        }
    }
}

fn read_boot_id() -> Result<String, LinuxPeerError> {
    let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let value = value.trim();
    if value.len() != 36
        || !value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return Err(LinuxPeerError::InvalidEvidence("boot ID"));
    }
    Ok(value.to_owned())
}

fn read_start_ticks(pid: i32) -> Result<u64, LinuxPeerError> {
    let text = fs::read_to_string(Path::new("/proc").join(pid.to_string()).join("stat"))?;
    parse_start_ticks(&text, pid)
}

fn parse_start_ticks(text: &str, expected_pid: i32) -> Result<u64, LinuxPeerError> {
    let (prefix, tail) = text
        .rsplit_once(") ")
        .ok_or(LinuxPeerError::InvalidEvidence("process stat delimiters"))?;
    let (pid, _) = prefix
        .split_once(" (")
        .ok_or(LinuxPeerError::InvalidEvidence("process stat PID"))?;
    if pid.parse::<i32>().ok() != Some(expected_pid) {
        return Err(LinuxPeerError::InvalidEvidence("process stat PID differs"));
    }
    // After `) ` the first token is field 3 (state); starttime is field 22.
    let ticks = tail
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(LinuxPeerError::InvalidEvidence("process birth ticks"))?;
    if ticks == 0 {
        return Err(LinuxPeerError::InvalidEvidence(
            "process birth ticks are zero",
        ));
    }
    Ok(ticks)
}

fn read_cgroup(pid: i32) -> Result<String, LinuxPeerError> {
    let text = fs::read_to_string(Path::new("/proc").join(pid.to_string()).join("cgroup"))?;
    let mut unified = text.lines().filter_map(|line| line.strip_prefix("0::"));
    let value = unified
        .next()
        .ok_or(LinuxPeerError::InvalidEvidence("unified cgroup missing"))?;
    if unified.next().is_some()
        || !value.starts_with('/')
        || value.len() > 4_080
        || value.chars().any(char::is_control)
    {
        return Err(LinuxPeerError::InvalidEvidence("unified cgroup malformed"));
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socketpair_pins_current_process_birth_and_containment() {
        let observed = LinuxPeerEvidence::for_current_process().unwrap();
        assert_eq!(observed.pid(), std::process::id() as i32);
        assert!(observed.start_ticks() > 0);
        assert!(observed.cgroup().starts_with('/'));
        assert_eq!(
            observed.attested_peer().containment_identity(),
            format!("linux.cgroup.{}", observed.cgroup())
        );
    }

    #[test]
    fn stat_parser_uses_field_22_after_parenthesized_process_name() {
        let mut fields = vec!["S".to_owned(); 20];
        fields[19] = "777".into();
        let stat = format!("42 (weird ) process name) {}", fields.join(" "));
        assert_eq!(parse_start_ticks(&stat, 42).unwrap(), 777);
        assert!(parse_start_ticks(&stat, 43).is_err());
        assert!(parse_start_ticks("42 no delimiters", 42).is_err());
    }
}
