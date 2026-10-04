//! Linux peer evidence for an accepted Unix control connection.
//! This adapter observes the kernel and procfs; it grants no pod authority.
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::path::Path;

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use podbay_core::{AttestedPeer, ManagerLiveness};

const MAX_PROC_STATUS_BYTES: u64 = 64 * 1024;

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
    /// Classify a checkpoint-pinned manager using fresh kernel/procfs facts.
    /// A changed UID or cgroup with the same birth is ambiguous, never proof
    /// that the original process died. This grants no control by itself.
    pub fn probe_pinned_manager(pinned: &AttestedPeer) -> ManagerLiveness {
        let Some(expected) = PinnedLinuxPeer::parse(pinned) else {
            return ManagerLiveness::Unknown;
        };
        let Ok(boot) = read_boot_id() else {
            return ManagerLiveness::Unknown;
        };
        if boot != expected.boot_id {
            return ManagerLiveness::DeadAttested;
        }
        let first = match read_process_stat(expected.pid) {
            Ok(stat) => stat,
            Err(error) => return classify_process_read_error(&error),
        };
        if first.start_ticks != expected.start_ticks {
            return ManagerLiveness::DeadAttested;
        }
        if matches!(first.state, 'Z' | 'X' | 'x') {
            return ManagerLiveness::Unknown;
        }
        let first_uid = read_effective_uid(expected.pid);
        let first_cgroup = read_cgroup(expected.pid);
        let second = match read_process_stat(expected.pid) {
            Ok(stat) => stat,
            Err(error) => return classify_process_read_error(&error),
        };
        if second.start_ticks != expected.start_ticks {
            return ManagerLiveness::DeadAttested;
        }
        if matches!(second.state, 'Z' | 'X' | 'x') {
            return ManagerLiveness::Unknown;
        }
        let second_uid = read_effective_uid(expected.pid);
        let second_cgroup = read_cgroup(expected.pid);
        let final_stat = match read_process_stat(expected.pid) {
            Ok(stat) => stat,
            Err(error) => return classify_process_read_error(&error),
        };
        if final_stat.start_ticks != expected.start_ticks {
            return ManagerLiveness::DeadAttested;
        }
        if matches!(final_stat.state, 'Z' | 'X' | 'x')
            || read_boot_id().ok().as_deref() != Some(expected.boot_id.as_str())
        {
            return ManagerLiveness::Unknown;
        }
        match (first_uid, first_cgroup, second_uid, second_cgroup) {
            (Ok(uid_a), Ok(cgroup_a), Ok(uid_b), Ok(cgroup_b))
                if uid_a == expected.uid
                    && uid_b == expected.uid
                    && cgroup_a == expected.cgroup
                    && cgroup_b == expected.cgroup =>
            {
                ManagerLiveness::Alive
            }
            _ => ManagerLiveness::Unknown,
        }
    }

    /// The launcher observes its own kernel credentials through a socketpair;
    /// no request body supplies the pinned manager process identity.
    pub fn for_current_process() -> Result<Self, LinuxPeerError> {
        let (first, _second) = UnixStream::pair()?;
        Self::from_accepted(&first)
    }

    /// Pin the process that actually launched this manager. The parent PID
    /// comes from this process's procfs stat, never argv, env or a setup
    /// request. A changed parent, birth, boot, effective IDs or cgroup refuses.
    pub fn for_launcher_parent() -> Result<Self, LinuxPeerError> {
        let self_pid = i32::try_from(std::process::id())
            .map_err(|_| LinuxPeerError::InvalidEvidence("self PID overflows"))?;
        let self_first = read_process_stat(self_pid)?;
        let pid = self_first.ppid;
        if pid <= 1 || pid == self_pid {
            return Err(LinuxPeerError::InvalidEvidence(
                "launcher parent PID is absent",
            ));
        }
        let boot_id = read_boot_id()?;
        let first = read_process_stat(pid)?;
        require_live_state(first.state)?;
        let status_first = read_process_status(pid)?;
        require_live_state(status_first.state)?;
        let cgroup_first = read_cgroup(pid)?;
        let second = read_process_stat(pid)?;
        require_live_state(second.state)?;
        let status_second = read_process_status(pid)?;
        require_live_state(status_second.state)?;
        let cgroup_second = read_cgroup(pid)?;
        let self_second = read_process_stat(self_pid)?;
        if first.start_ticks != second.start_ticks
            || status_first.effective_uid != status_second.effective_uid
            || status_first.effective_gid != status_second.effective_gid
            || cgroup_first != cgroup_second
            || self_first.start_ticks != self_second.start_ticks
            || self_second.ppid != pid
            || read_boot_id()? != boot_id
        {
            return Err(LinuxPeerError::EvidenceChanged);
        }
        let uid = status_second.effective_uid;
        let gid = status_second.effective_gid;
        let start_ticks = second.start_ticks;
        let cgroup = cgroup_second;
        let peer = AttestedPeer::from_port(
            &format!("linux.uid.{uid}"),
            &format!("linux.pid.{pid}"),
            &format!("linux.boot.{boot_id}"),
            &format!("linux.start.{start_ticks}"),
            &format!("linux.cgroup.{cgroup}"),
        )
        .map_err(|_| LinuxPeerError::InvalidEvidence("parent peer shape refused"))?;
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

    pub fn recheck_launcher_parent(&self) -> Result<(), LinuxPeerError> {
        if Self::for_launcher_parent()? == *self {
            Ok(())
        } else {
            Err(LinuxPeerError::EvidenceChanged)
        }
    }

    /// `socket` must be the accepted connection, not an outgoing client socket.
    /// Failure to read any component refuses before a control effect.
    pub fn from_accepted(socket: &UnixStream) -> Result<Self, LinuxPeerError> {
        Self::observe_socket_peer(socket)
    }

    /// Observe the server endpoint from a connected client socket. A JSON
    /// response is not a substitute for this kernel/process evidence.
    pub fn from_connected(socket: &UnixStream) -> Result<Self, LinuxPeerError> {
        Self::observe_socket_peer(socket)
    }

    fn observe_socket_peer(socket: &UnixStream) -> Result<Self, LinuxPeerError> {
        let credentials = getsockopt(socket, PeerCredentials)
            .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?;
        let pid = credentials.pid();
        if pid <= 0 {
            return Err(LinuxPeerError::InvalidEvidence("peer PID is absent"));
        }
        let uid = credentials.uid();
        let gid = credentials.gid();
        let boot_id = read_boot_id()?;
        let first = read_process_stat(pid)?;
        require_live_state(first.state)?;
        let status = read_process_status(pid)?;
        require_current_credentials(&status, uid, gid)?;
        let cgroup = read_cgroup(pid)?;
        let second = read_process_stat(pid)?;
        require_live_state(second.state)?;
        if second.start_ticks != first.start_ticks {
            return Err(LinuxPeerError::EvidenceChanged);
        }
        let start_ticks = first.start_ticks;
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
        let fresh = Self::observe_socket_peer(socket)?;
        if fresh == *self && fresh.peer == *expected {
            Ok(())
        } else {
            Err(LinuxPeerError::EvidenceChanged)
        }
    }

    pub fn recheck_connected(&self, socket: &UnixStream) -> Result<(), LinuxPeerError> {
        let fresh = Self::from_connected(socket)?;
        if fresh == *self {
            Ok(())
        } else {
            Err(LinuxPeerError::EvidenceChanged)
        }
    }
}

fn read_boot_id() -> Result<String, LinuxPeerError> {
    let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let value = value.trim();
    if !valid_boot_id(value) {
        return Err(LinuxPeerError::InvalidEvidence("boot ID"));
    }
    Ok(value.to_owned())
}

fn valid_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn classify_process_read_error(error: &LinuxPeerError) -> ManagerLiveness {
    match error {
        LinuxPeerError::Io(error) if error.kind() == io::ErrorKind::NotFound => {
            ManagerLiveness::DeadAttested
        }
        _ => ManagerLiveness::Unknown,
    }
}

#[cfg(test)]
fn parse_start_ticks(text: &str, expected_pid: i32) -> Result<u64, LinuxPeerError> {
    Ok(parse_process_stat(text, expected_pid)?.start_ticks)
}

struct ProcessStat {
    state: char,
    ppid: i32,
    start_ticks: u64,
}

fn read_process_stat(pid: i32) -> Result<ProcessStat, LinuxPeerError> {
    let text = fs::read_to_string(Path::new("/proc").join(pid.to_string()).join("stat"))?;
    parse_process_stat(&text, pid)
}

fn parse_process_stat(text: &str, expected_pid: i32) -> Result<ProcessStat, LinuxPeerError> {
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
    let mut fields = tail.split_whitespace();
    let state = fields
        .next()
        .and_then(|value| {
            let mut chars = value.chars();
            let state = chars.next()?;
            (chars.next().is_none()
                && matches!(
                    state,
                    'R' | 'S' | 'D' | 'Z' | 'T' | 't' | 'X' | 'x' | 'K' | 'W' | 'P' | 'I'
                ))
            .then_some(state)
        })
        .ok_or(LinuxPeerError::InvalidEvidence("process state"))?;
    let ppid = tail
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|value| *value >= 0)
        .ok_or(LinuxPeerError::InvalidEvidence("process parent PID"))?;
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
    Ok(ProcessStat {
        state,
        ppid,
        start_ticks: ticks,
    })
}

fn read_effective_uid(pid: i32) -> Result<u32, LinuxPeerError> {
    let text = fs::read_to_string(Path::new("/proc").join(pid.to_string()).join("status"))?;
    let mut rows = text.lines().filter_map(|line| line.strip_prefix("Uid:"));
    let values = rows
        .next()
        .ok_or(LinuxPeerError::InvalidEvidence("process Uid missing"))?;
    if rows.next().is_some() {
        return Err(LinuxPeerError::InvalidEvidence("duplicate process Uid"));
    }
    let fields = values.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 4 {
        return Err(LinuxPeerError::InvalidEvidence("process Uid fields"));
    }
    fields[1]
        .parse()
        .map_err(|_| LinuxPeerError::InvalidEvidence("effective process Uid"))
}

struct ProcessStatus {
    state: char,
    effective_uid: u32,
    effective_gid: u32,
}

fn read_process_status(pid: i32) -> Result<ProcessStatus, LinuxPeerError> {
    let file = fs::File::open(Path::new("/proc").join(pid.to_string()).join("status"))?;
    let mut bytes = Vec::new();
    file.take(MAX_PROC_STATUS_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PROC_STATUS_BYTES {
        return Err(LinuxPeerError::InvalidEvidence("process status byte bound"));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| LinuxPeerError::InvalidEvidence("process status encoding"))?;
    parse_process_status(text)
}

fn parse_process_status(text: &str) -> Result<ProcessStatus, LinuxPeerError> {
    if text.len() as u64 > MAX_PROC_STATUS_BYTES {
        return Err(LinuxPeerError::InvalidEvidence("process status byte bound"));
    }
    let mut state = None;
    let mut uid = None;
    let mut gid = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("State:") {
            if state.is_some() {
                return Err(LinuxPeerError::InvalidEvidence("duplicate process State"));
            }
            let token = value
                .split_whitespace()
                .next()
                .ok_or(LinuxPeerError::InvalidEvidence("process State missing"))?;
            let mut chars = token.chars();
            let candidate = chars
                .next()
                .ok_or(LinuxPeerError::InvalidEvidence("process State missing"))?;
            if chars.next().is_some()
                || !matches!(
                    candidate,
                    'R' | 'S' | 'D' | 'Z' | 'T' | 't' | 'X' | 'x' | 'K' | 'W' | 'P' | 'I'
                )
            {
                return Err(LinuxPeerError::InvalidEvidence("process State malformed"));
            }
            state = Some(candidate);
        } else if let Some(value) = line.strip_prefix("Uid:") {
            if uid.is_some() {
                return Err(LinuxPeerError::InvalidEvidence("duplicate process Uid"));
            }
            uid = Some(parse_effective_id(value, "process Uid fields")?);
        } else if let Some(value) = line.strip_prefix("Gid:") {
            if gid.is_some() {
                return Err(LinuxPeerError::InvalidEvidence("duplicate process Gid"));
            }
            gid = Some(parse_effective_id(value, "process Gid fields")?);
        }
    }
    Ok(ProcessStatus {
        state: state.ok_or(LinuxPeerError::InvalidEvidence("process State missing"))?,
        effective_uid: uid.ok_or(LinuxPeerError::InvalidEvidence("process Uid missing"))?,
        effective_gid: gid.ok_or(LinuxPeerError::InvalidEvidence("process Gid missing"))?,
    })
}

fn parse_effective_id(value: &str, malformed: &'static str) -> Result<u32, LinuxPeerError> {
    let fields = value.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 4
        || fields
            .iter()
            .any(|field| field.is_empty() || !field.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(LinuxPeerError::InvalidEvidence(malformed));
    }
    let values = fields
        .iter()
        .map(|field| field.parse::<u32>().ok())
        .collect::<Option<Vec<_>>>()
        .ok_or(LinuxPeerError::InvalidEvidence(malformed))?;
    // /proc/pid/status orders real, effective, saved-set, filesystem IDs.
    Ok(values[1])
}

fn require_live_state(state: char) -> Result<(), LinuxPeerError> {
    if matches!(state, 'Z' | 'X' | 'x') {
        Err(LinuxPeerError::InvalidEvidence(
            "peer process is zombie or dead",
        ))
    } else {
        Ok(())
    }
}

fn require_current_credentials(
    status: &ProcessStatus,
    socket_uid: u32,
    socket_gid: u32,
) -> Result<(), LinuxPeerError> {
    require_live_state(status.state)?;
    if status.effective_uid != socket_uid || status.effective_gid != socket_gid {
        return Err(LinuxPeerError::EvidenceChanged);
    }
    Ok(())
}

struct PinnedLinuxPeer {
    uid: u32,
    pid: i32,
    boot_id: String,
    start_ticks: u64,
    cgroup: String,
}
impl PinnedLinuxPeer {
    fn parse(peer: &AttestedPeer) -> Option<Self> {
        let uid = peer
            .os_identity()
            .strip_prefix("linux.uid.")?
            .parse()
            .ok()?;
        let pid: i32 = peer
            .native_process_id()
            .strip_prefix("linux.pid.")?
            .parse()
            .ok()?;
        let boot_id = peer.boot_identity().strip_prefix("linux.boot.")?;
        let start_ticks: u64 = peer
            .birth_identity()
            .strip_prefix("linux.start.")?
            .parse()
            .ok()?;
        let cgroup = peer.containment_identity().strip_prefix("linux.cgroup.")?;
        if pid <= 0
            || start_ticks == 0
            || !valid_boot_id(boot_id)
            || !cgroup.starts_with('/')
            || cgroup.len() > 4080
            || cgroup.chars().any(char::is_control)
        {
            return None;
        }
        Some(Self {
            uid,
            pid,
            boot_id: boot_id.into(),
            start_ticks,
            cgroup: cgroup.into(),
        })
    }
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
    fn connected_socket_observes_and_rechecks_the_server_birth() {
        let (client, server) = UnixStream::pair().unwrap();
        let observed = LinuxPeerEvidence::from_connected(&client).unwrap();
        assert_eq!(observed.pid(), std::process::id() as i32);
        assert!(observed.start_ticks() > 0);
        observed.recheck_connected(&client).unwrap();
        let accepted = LinuxPeerEvidence::from_accepted(&server).unwrap();
        assert_eq!(observed, accepted);
    }

    #[test]
    fn launcher_parent_capture_rejects_changed_birth() {
        let parent = LinuxPeerEvidence::for_launcher_parent().unwrap();
        assert!(parent.pid() > 1);
        parent.recheck_launcher_parent().unwrap();
        let mut wrong_birth = parent;
        wrong_birth.start_ticks += 1;
        assert!(matches!(
            wrong_birth.recheck_launcher_parent(),
            Err(LinuxPeerError::EvidenceChanged)
        ));
    }

    #[test]
    fn stat_parser_uses_field_22_after_parenthesized_process_name() {
        let mut fields = vec!["S".to_owned(); 20];
        fields[1] = "7".into();
        fields[19] = "777".into();
        let stat = format!("42 (weird ) process name) {}", fields.join(" "));
        assert_eq!(parse_start_ticks(&stat, 42).unwrap(), 777);
        assert!(parse_start_ticks(&stat, 43).is_err());
        assert!(parse_start_ticks("42 no delimiters", 42).is_err());
    }

    #[test]
    fn status_parser_uses_effective_ids_and_refuses_changed_or_dead_peer() {
        let text = "State:\tS (sleeping)\nUid:\t12\t34\t56\t78\nGid:\t90\t91\t92\t93\n";
        let status = parse_process_status(text).unwrap();
        assert_eq!(status.effective_uid, 34);
        assert_eq!(status.effective_gid, 91);
        require_current_credentials(&status, 34, 91).unwrap();
        assert!(matches!(
            require_current_credentials(&status, 12, 91),
            Err(LinuxPeerError::EvidenceChanged)
        ));
        assert!(matches!(
            require_current_credentials(&status, 34, 90),
            Err(LinuxPeerError::EvidenceChanged)
        ));
        for state in ['Z', 'X', 'x'] {
            let zombie_text = text.replacen("State:\tS", &format!("State:\t{state}"), 1);
            let zombie = parse_process_status(&zombie_text).unwrap();
            assert!(require_current_credentials(&zombie, 34, 91).is_err());
        }
    }

    #[test]
    fn status_parser_fails_closed_on_missing_duplicate_or_malformed_fields() {
        let good = "State:\tR (running)\nUid:\t1 2 3 4\nGid:\t5 6 7 8\n";
        for bad in [
            good.replace("Gid:\t5 6 7 8\n", ""),
            format!("{good}Uid:\t1 2 3 4\n"),
            good.replace("Uid:\t1 2 3 4", "Uid:\t1 2 3"),
            good.replace("Gid:\t5 6 7 8", "Gid:\t5 six 7 8"),
            good.replace("State:\tR", "State:\tunknown"),
            "x".repeat(MAX_PROC_STATUS_BYTES as usize + 1),
        ] {
            assert!(parse_process_status(&bad).is_err());
        }
    }

    #[test]
    fn missing_pid_is_distinct_from_permission_or_malformed_proc_evidence() {
        assert_eq!(
            classify_process_read_error(&LinuxPeerError::Io(io::Error::from(
                io::ErrorKind::NotFound
            ))),
            ManagerLiveness::DeadAttested
        );
        assert_eq!(
            classify_process_read_error(&LinuxPeerError::Io(io::Error::from(
                io::ErrorKind::PermissionDenied
            ))),
            ManagerLiveness::Unknown
        );
        assert_eq!(
            classify_process_read_error(&LinuxPeerError::InvalidEvidence("malformed stat")),
            ManagerLiveness::Unknown
        );
    }
}
