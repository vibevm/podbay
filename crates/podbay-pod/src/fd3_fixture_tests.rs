//! Disposable OS process tests only. No serve/profile/store/systemd path is used.
//! This module remains under the Pod crate's forbid(unsafe_code).
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use nix::sys::socket::{MsgFlags, recv, send};
use podbay_fd3_sys::{SpawnSpec, SpawnedFd3, reserve_fd3, spawn_fd3};

const MODE: &str = "PODBAY_POD_DISPOSABLE_FD3_CASE";

struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        if self.0.try_wait().expect("private child status").is_none() {
            self.0.kill().expect("kill only owned private child");
        }
        self.0.wait().expect("reap owned private child");
    }
}

fn wait(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(Instant::now() < deadline, "private child exit deadline");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn identity(pid: u32) -> std::io::Result<(u32, u64)> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let (_, tail) = text
        .rsplit_once(") ")
        .ok_or(std::io::ErrorKind::InvalidData)?;
    let fields: Vec<_> = tail.split_whitespace().collect();
    Ok((
        fields[1]
            .parse()
            .map_err(|_| std::io::ErrorKind::InvalidData)?,
        fields[19]
            .parse()
            .map_err(|_| std::io::ErrorKind::InvalidData)?,
    ))
}

fn run_supervisor(mode: &str) {
    let mut supervisor = Reap(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "fd3_fixture_tests::disposable_pod_supervisor",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env(MODE, mode)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let status = wait(&mut supervisor.0);
    let mut output = String::new();
    supervisor
        .0
        .stdout
        .take()
        .unwrap()
        .take(8192)
        .read_to_string(&mut output)
        .unwrap();
    supervisor
        .0
        .stderr
        .take()
        .unwrap()
        .take(8192)
        .read_to_string(&mut output)
        .unwrap();
    assert!(
        status.success(),
        "private supervisor {mode}: {status}\n{output}"
    );
}

#[test]
fn supervisor_exec_uses_safe_fd3_boundary() {
    run_supervisor("normal");
}

#[test]
fn supervisor_exit_eof_timeout_are_nonobservations() {
    for mode in ["exit", "eof", "timeout"] {
        run_supervisor(mode);
    }
}

#[test]
#[ignore = "private test supervisor, never a production entry point"]
fn disposable_pod_supervisor() {
    let mode = std::env::var(MODE).unwrap();
    let slot = reserve_fd3().unwrap();
    let SpawnedFd3 { child, mut channel } = spawn_fd3(
        &slot,
        SpawnSpec {
            program: std::env::current_exe().unwrap(),
            args: [
                "--exact",
                "fd3_fixture_tests::disposable_lens_standin",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ]
            .into_iter()
            .map(OsString::from)
            .collect(),
            cwd: PathBuf::from("/"),
            env: vec![(MODE.into(), mode.clone().into())],
        },
    )
    .unwrap();
    let mut child = Reap(child);
    let pid = child.0.id();
    let initial_identity = identity(pid).ok();
    let mut report = [0; 20];
    let observed = channel.read_exact(&mut report);
    if mode != "normal" {
        let kind = observed.unwrap_err().kind();
        if mode == "timeout" {
            assert!(matches!(
                kind,
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ));
            assert!(child.0.try_wait().unwrap().is_none());
            assert_eq!(identity(pid).unwrap(), initial_identity.unwrap());
        } else {
            assert!(matches!(mode.as_str(), "exit" | "eof"));
            assert_eq!(kind, std::io::ErrorKind::UnexpectedEof);
            assert!(wait(&mut child.0).success());
            assert!(child.0.wait().unwrap().success());
        }
        drop(child);
        assert_eq!(channel.read(&mut [0]).unwrap(), 0);
        if let Some(expected) = initial_identity {
            assert!(identity(pid).map(|now| now != expected).unwrap_or(true));
        }
        return;
    }
    observed.unwrap();
    let expected = identity(pid).unwrap();
    assert_eq!(expected.0, std::process::id());
    assert!(expected.1 > 0);
    assert_eq!(u32::from_be_bytes(report[..4].try_into().unwrap()), pid);
    assert_eq!(
        u32::from_be_bytes(report[4..8].try_into().unwrap()),
        expected.0
    );
    assert_eq!(
        u64::from_be_bytes(report[8..16].try_into().unwrap()),
        expected.1
    );
    assert_eq!(&report[16..], &[0, 1, 2, 3]);
    // Private nonce echo tests transport custody only, not a readiness signature.
    let mut nonce = [0; 32];
    File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut nonce)
        .unwrap();
    assert_ne!(nonce, [0; 32]);
    for _ in 0..3 {
        channel.write_all(&nonce).unwrap();
        let mut reply = [0; 32];
        channel.read_exact(&mut reply).unwrap();
        assert_eq!(reply, nonce);
        assert_eq!(identity(pid).unwrap(), expected);
        assert!(child.0.try_wait().unwrap().is_none());
    }
    channel.write_all(&[0; 32]).unwrap();
    assert!(wait(&mut child.0).success());
    assert!(child.0.wait().unwrap().success());
    assert_eq!(channel.read(&mut [0]).unwrap(), 0);
    assert!(identity(pid).map(|now| now != expected).unwrap_or(true));
}

#[test]
#[ignore = "private FD3 endpoint; does not start Lens or touch state"]
fn disposable_lens_standin() {
    let mode = std::env::var(MODE).unwrap();
    if mode == "exit" {
        return;
    }
    let mut fds: Vec<i32> = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .map(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .parse()
                .unwrap()
        })
        .collect();
    fds.retain(|fd| std::fs::symlink_metadata(format!("/proc/self/fd/{fd}")).is_ok());
    fds.sort_unstable();
    assert_eq!(fds, [0, 1, 2, 3]);
    if mode == "eof" {
        return;
    }
    if mode == "timeout" {
        std::thread::sleep(Duration::from_secs(10));
        return;
    }
    assert_eq!(mode, "normal");
    let (ppid, birth) = identity(std::process::id()).unwrap();
    let mut report = std::process::id().to_be_bytes().to_vec();
    report.extend_from_slice(&ppid.to_be_bytes());
    report.extend_from_slice(&birth.to_be_bytes());
    report.extend_from_slice(&[0, 1, 2, 3]);
    send_all(&report);
    let mut first = None;
    loop {
        let mut bytes = [0; 32];
        let mut remaining = bytes.as_mut_slice();
        while !remaining.is_empty() {
            let n = recv(3, remaining, MsgFlags::empty()).unwrap();
            assert!(n > 0);
            remaining = &mut remaining[n..];
        }
        if bytes == [0; 32] {
            break;
        }
        if let Some(first) = first {
            assert_eq!(bytes, first);
        } else {
            first = Some(bytes);
        }
        send_all(&bytes);
    }
}

fn send_all(mut bytes: &[u8]) {
    while !bytes.is_empty() {
        let n = send(3, bytes, MsgFlags::MSG_NOSIGNAL).unwrap();
        assert!(n > 0);
        bytes = &bytes[n..];
    }
}
