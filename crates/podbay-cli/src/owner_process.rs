//! Optional Linux lifetime fence for the direct process that launched a manager.
//! A pidfd pins the exact process across PID reuse; argv only supplies a
//! selector to compare with independently observed kernel/procfs evidence.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};

use podbay_pod::LinuxPeerEvidence;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fd::OwnedFd;
use rustix::process::{Pid, PidfdFlags, pidfd_open};

const POLL_INTERVAL: Timespec = Timespec {
    tv_sec: 0,
    tv_nsec: 20_000_000,
};
const POLL_NOW: Timespec = Timespec {
    tv_sec: 0,
    tv_nsec: 0,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerProcessSelector {
    pub pid: i32,
    pub start_ticks: u64,
    pub uid: u32,
}

impl OwnerProcessSelector {
    pub fn parse(pid: &str, start_ticks: &str, uid: &str) -> Result<Self, String> {
        let pid = pid
            .parse::<i32>()
            .map_err(|_| "owner process PID must be a positive decimal integer")?;
        let start_ticks = start_ticks
            .parse::<u64>()
            .map_err(|_| "owner process birth ticks must be a positive decimal integer")?;
        let uid = uid
            .parse::<u32>()
            .map_err(|_| "owner process UID must be a decimal integer")?;
        if pid <= 1 || start_ticks == 0 {
            return Err("owner process PID and birth ticks must be positive".into());
        }
        Ok(Self {
            pid,
            start_ticks,
            uid,
        })
    }
}

pub struct OwnerProcessWatch {
    parent: LinuxPeerEvidence,
    pidfd: Arc<OwnedFd>,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl OwnerProcessWatch {
    pub fn arm(
        selector: OwnerProcessSelector,
        parent: LinuxPeerEvidence,
        manager: &LinuxPeerEvidence,
        stop: Arc<AtomicBool>,
    ) -> Result<Self, String> {
        if parent.pid() != selector.pid
            || parent.start_ticks() != selector.start_ticks
            || parent.uid() != selector.uid
            || parent.uid() != manager.uid()
            || parent.gid() != manager.gid()
        {
            return Err("owner process selector differs from the direct launcher parent".into());
        }
        let pid = Pid::from_raw(selector.pid)
            .ok_or_else(|| "owner process PID cannot be pinned".to_owned())?;
        let pidfd = Arc::new(
            pidfd_open(pid, PidfdFlags::empty())
                .map_err(|error| format!("owner process pidfd unavailable: {error}"))?,
        );
        // The before/after parent observation closes PID reuse while opening
        // the descriptor. The descriptor itself then pins the exact process.
        parent
            .recheck_launcher_parent()
            .map_err(|error| format!("owner process changed while pinning: {error}"))?;
        require_running(&pidfd)?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_fd = pidfd.clone();
        let thread_shutdown = shutdown.clone();
        let thread = thread::Builder::new()
            .name("podbay-owner-process-watch".into())
            .spawn(move || {
                while !thread_shutdown.load(Ordering::Acquire) {
                    match poll_pidfd(&thread_fd, Some(&POLL_INTERVAL)) {
                        Ok(false) => {}
                        Ok(true) | Err(_) => {
                            stop.store(true, Ordering::Release);
                            break;
                        }
                    }
                }
            })
            .map_err(|error| format!("owner process watcher could not start: {error}"))?;
        let watch = Self {
            parent,
            pidfd,
            shutdown,
            thread: Some(thread),
        };
        watch.check_alive()?;
        Ok(watch)
    }

    pub fn check_alive(&self) -> Result<(), String> {
        require_running(&self.pidfd)?;
        self.parent
            .recheck_launcher_parent()
            .map_err(|error| format!("owner process identity changed: {error}"))?;
        require_running(&self.pidfd)
    }
}

impl Drop for OwnerProcessWatch {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn require_running(pidfd: &OwnedFd) -> Result<(), String> {
    match poll_pidfd(pidfd, Some(&POLL_NOW)) {
        Ok(false) => Ok(()),
        Ok(true) => Err("owner process exited".into()),
        Err(error) => Err(format!("owner process pidfd check failed: {error}")),
    }
}

fn poll_pidfd(pidfd: &OwnedFd, timeout: Option<&Timespec>) -> Result<bool, rustix::io::Errno> {
    let mut fds = [PollFd::new(pidfd, PollFlags::IN)];
    let ready = poll(&mut fds, timeout)?;
    Ok(ready != 0 || !fds[0].revents().is_empty())
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;

    #[test]
    fn selector_requires_complete_positive_kernel_identity() {
        assert!(OwnerProcessSelector::parse("2", "1", "0").is_ok());
        for (pid, birth, uid) in [
            ("0", "1", "0"),
            ("-1", "1", "0"),
            ("2", "0", "0"),
            ("2x", "1", "0"),
            ("2", "1x", "0"),
            ("2", "1", "-1"),
        ] {
            assert!(OwnerProcessSelector::parse(pid, birth, uid).is_err());
        }
    }

    #[test]
    fn pidfd_reports_exit_of_the_exact_pinned_process() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = Pid::from_raw(child.id() as i32).unwrap();
        let pidfd = pidfd_open(pid, PidfdFlags::empty()).unwrap();
        require_running(&pidfd).unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(require_running(&pidfd).unwrap_err(), "owner process exited");
    }
}
