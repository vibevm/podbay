//! Kernel/procfs evidence for this manager process, never caller-supplied identity.
use std::fs;
use std::io;

use podbay_core::AttestedPeer;

/// Captured once while the manager holds its lifetime lock. Not transferable
/// through serialization or cloning; callers must recheck before an effect.
pub(crate) struct LinuxManagerPeer {
    evidence: Evidence,
    peer: AttestedPeer,
}

#[derive(Eq, PartialEq)]
struct Evidence {
    pid: u32,
    uid: u32,
    gid: u32,
    boot_id: String,
    start_ticks: u64,
    cgroup: String,
}

impl LinuxManagerPeer {
    pub(crate) fn capture() -> io::Result<Self> {
        let evidence = Evidence::read()?;
        if evidence != Evidence::read()? {
            return Err(changed());
        }
        let peer = AttestedPeer::from_port(
            &format!("linux.uid.{}", evidence.uid),
            &format!("linux.pid.{}", evidence.pid),
            &format!("linux.boot.{}", evidence.boot_id),
            &format!("linux.start.{}", evidence.start_ticks),
            &format!("linux.cgroup.{}", evidence.cgroup),
        )
        .map_err(|_| invalid("manager peer shape refused"))?;
        Ok(Self { evidence, peer })
    }

    pub(crate) fn peer(&self) -> &AttestedPeer {
        &self.peer
    }

    /// A failed read or any changed field refuses. This is a fresh evidence
    /// check, not protection against a subsequent identity/containment change.
    pub(crate) fn recheck(&self) -> io::Result<()> {
        let fresh = Self::capture()?;
        if fresh.evidence != self.evidence {
            return Err(changed());
        }
        Ok(())
    }
}

impl Evidence {
    fn read() -> io::Result<Self> {
        let pid = std::process::id();
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(invalid("manager PID is invalid"));
        }
        // thread-self observes the executing thread's effective credentials.
        // Tgid binds those credentials to the process identity, not its TID.
        let status = fs::read_to_string("/proc/thread-self/status")?;
        let (uid, gid) = parse_credentials(&status, pid)?;
        let boot_id = parse_boot_id(&fs::read_to_string("/proc/sys/kernel/random/boot_id")?)?;
        let start_ticks = parse_start_ticks(&fs::read_to_string("/proc/self/stat")?, pid)?;
        let cgroup = parse_cgroup(&fs::read_to_string("/proc/self/cgroup")?)?;
        Ok(Self {
            pid,
            uid,
            gid,
            boot_id,
            start_ticks,
            cgroup,
        })
    }
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn changed() -> io::Error {
    io::Error::other("manager process identity or containment changed")
}

fn parse_credentials(status: &str, expected_pid: u32) -> io::Result<(u32, u32)> {
    fn fields(status: &str, key: &str, count: usize) -> io::Result<Vec<u32>> {
        let mut matching = status.lines().filter_map(|line| line.strip_prefix(key));
        let line = matching
            .next()
            .ok_or_else(|| invalid("missing manager status field"))?;
        if matching.next().is_some() {
            return Err(invalid("duplicate manager status field"));
        }
        let values = line
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid("malformed manager status field"))?;
        if values.len() != count {
            return Err(invalid("wrong manager status field length"));
        }
        Ok(values)
    }
    if fields(status, "Tgid:", 1)?[0] != expected_pid {
        return Err(invalid("manager status process ID differs"));
    }
    Ok((fields(status, "Uid:", 4)?[1], fields(status, "Gid:", 4)?[1]))
}

fn parse_boot_id(text: &str) -> io::Result<String> {
    let value = text.trim();
    if value.len() != 36
        || !value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return Err(invalid("manager boot ID is malformed"));
    }
    Ok(value.into())
}

fn parse_start_ticks(text: &str, expected_pid: u32) -> io::Result<u64> {
    let (prefix, tail) = text
        .rsplit_once(") ")
        .ok_or_else(|| invalid("manager stat delimiters"))?;
    let (pid, _) = prefix
        .split_once(" (")
        .ok_or_else(|| invalid("manager stat PID"))?;
    if pid.parse::<u32>().ok() != Some(expected_pid) {
        return Err(invalid("manager stat PID differs"));
    }
    let ticks = tail
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid("manager process birth ticks"))?;
    Ok(ticks)
}

fn parse_cgroup(text: &str) -> io::Result<String> {
    let mut unified = text.lines().filter_map(|line| line.strip_prefix("0::"));
    let value = unified
        .next()
        .ok_or_else(|| invalid("manager unified cgroup missing"))?;
    if unified.next().is_some()
        || !value.starts_with('/')
        || value.len() > 4_080
        || value.chars().any(char::is_control)
    {
        return Err(invalid("manager unified cgroup malformed"));
    }
    Ok(value.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_roundtrip_and_changed_evidence_refuses() {
        let mut captured = LinuxManagerPeer::capture().unwrap();
        captured.recheck().unwrap();
        assert_eq!(
            captured.peer().native_process_id(),
            format!("linux.pid.{}", std::process::id())
        );
        assert_eq!(
            captured.peer().os_identity(),
            format!("linux.uid.{}", captured.evidence.uid)
        );
        assert_eq!(
            captured.peer().boot_identity(),
            format!("linux.boot.{}", captured.evidence.boot_id)
        );
        assert_eq!(
            captured.peer().birth_identity(),
            format!("linux.start.{}", captured.evidence.start_ticks)
        );
        assert_eq!(
            captured.peer().containment_identity(),
            format!("linux.cgroup.{}", captured.evidence.cgroup)
        );
        captured.evidence.gid ^= 1;
        assert!(
            captured.recheck().is_err(),
            "GID is checked even though absent from AttestedPeer"
        );
    }

    #[test]
    fn status_uses_effective_ids_and_rejects_ambiguity() {
        let status = "Tgid:\t42\nUid:\t1 2 3 4\nGid:\t5 6 7 8\n";
        assert_eq!(parse_credentials(status, 42).unwrap(), (2, 6));
        assert!(parse_credentials(status, 43).is_err());
        assert!(parse_credentials(&format!("{status}Uid:\t1 2 3 4\n"), 42).is_err());
        assert!(parse_credentials("Tgid: 42\nUid: 1 2\nGid: 1 2 3 4\n", 42).is_err());
    }

    #[test]
    fn birth_parser_handles_parentheses_and_refuses_invalid_ticks() {
        let mut fields = vec!["S"; 20];
        fields[19] = "777";
        let stat = format!("42 (weird ) process name) {}", fields.join(" "));
        assert_eq!(parse_start_ticks(&stat, 42).unwrap(), 777);
        assert!(parse_start_ticks(&stat, 43).is_err());
        assert!(parse_start_ticks("42 (x) S", 42).is_err());
        fields[19] = "0";
        assert!(parse_start_ticks(&format!("42 (x) {}", fields.join(" ")), 42).is_err());
    }

    #[test]
    fn boot_and_cgroup_parsers_refuse_missing_or_ambiguous_evidence() {
        assert!(parse_boot_id("12345678-1234-1234-1234-123456789abc\n").is_ok());
        assert!(parse_boot_id("12345678x1234-1234-1234-123456789abc").is_err());
        assert_eq!(
            parse_cgroup("0::/user.slice/test.service\n").unwrap(),
            "/user.slice/test.service"
        );
        assert!(parse_cgroup("0::/first\n0::/second\n").is_err());
        assert!(parse_cgroup("1:cpu:/legacy\n").is_err());
        assert!(parse_cgroup("0::relative\n").is_err());
    }
}
