#![cfg(target_os = "linux")]

use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use podbay_store::PodBayStore;
use sha2::{Digest, Sha256};

struct Fixture {
    root: PathBuf,
    state: PathBuf,
    pods: PathBuf,
    database: PathBuf,
    binary: PathBuf,
    digest: String,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("podbay-cli-manager-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let state = root.join("state");
        let pods = root.join("pods");
        for directory in [&state, &pods] {
            fs::create_dir(directory).unwrap();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let binary = root.join("pod-binary");
        let contents = b"#!/bin/sh\nexit 0\n";
        fs::write(&binary, contents).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let digest = Sha256::digest(contents)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Self {
            database: state.join("podbay.sqlite"),
            root,
            state,
            pods,
            binary,
            digest,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_podbay"));
        command
            .arg("manager")
            .arg("serve")
            .arg("--state-dir")
            .arg(&self.state)
            .arg("--database")
            .arg(&self.database)
            .arg("--pod-dir")
            .arg(&self.pods)
            .arg("--pod-binary")
            .arg(&self.binary)
            .arg("--pod-sha256")
            .arg(&self.digest)
            .stdin(Stdio::null());
        command
    }

    fn socket(&self) -> PathBuf {
        self.state.join("manager.sock")
    }

    fn owner_epoch(&self) -> u64 {
        PodBayStore::open(&self.database)
            .unwrap()
            .owner_epoch()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct Running(Child);

impl Running {
    fn spawn(fixture: &Fixture) -> Self {
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(fixture.root.join("manager.log"))
            .unwrap();
        let child = fixture
            .command()
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        Self(child)
    }

    fn wait_ready(&mut self, fixture: &Fixture) {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                let log = fs::read_to_string(fixture.root.join("manager.log")).unwrap_or_default();
                panic!("manager exited before readiness: {status}; {log}");
            }
            if fs::symlink_metadata(fixture.socket())
                .is_ok_and(|metadata| metadata.file_type().is_socket())
            {
                return;
            }
            assert!(Instant::now() < until, "manager socket did not appear");
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn stop_with(&mut self, signal: &str) -> ExitStatus {
        let sent = Command::new("kill")
            .arg(format!("-{signal}"))
            .arg(self.0.id().to_string())
            .status()
            .unwrap();
        assert!(sent.success(), "failed to signal manager");
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < until, "manager did not stop after signal");
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn run_short(fixture: &Fixture) -> (ExitStatus, String) {
    let mut child = Running(
        fixture
            .command()
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            let mut stderr = String::new();
            child
                .0
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            return (status, stderr);
        }
        assert!(
            Instant::now() < until,
            "second manager did not refuse promptly"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn exclusive_manager_stops_cleanly_restarts_and_preserves_stale_socket() {
    let fixture = Fixture::new();
    let mut first = Running::spawn(&fixture);
    first.wait_ready(&fixture);
    let owner = fixture.owner_epoch();
    assert!(owner > 0);
    let (second_status, second_error) = run_short(&fixture);
    assert!(!second_status.success());
    assert!(second_error.contains("manager owner busy"));
    assert_eq!(fixture.owner_epoch(), owner);
    assert!(first.0.try_wait().unwrap().is_none());

    assert!(first.stop_with("TERM").success());
    assert!(!fixture.socket().exists());
    let mut restarted = Running::spawn(&fixture);
    restarted.wait_ready(&fixture);
    assert_eq!(fixture.owner_epoch(), owner + 1);
    assert!(restarted.stop_with("INT").success());
    assert!(!fixture.socket().exists());
    let epoch_before_stale_socket = fixture.owner_epoch();

    let stale = UnixListener::bind(fixture.socket()).unwrap();
    let identity = fs::symlink_metadata(fixture.socket()).unwrap();
    drop(stale);
    let (failed_status, failed_error) = run_short(&fixture);
    assert!(!failed_status.success());
    assert!(failed_error.contains("existing manager socket path"));
    assert_eq!(fixture.owner_epoch(), epoch_before_stale_socket);
    let preserved = fs::symlink_metadata(fixture.socket()).unwrap();
    assert!(preserved.file_type().is_socket());
    assert_eq!(
        (preserved.dev(), preserved.ino()),
        (identity.dev(), identity.ino())
    );
    fs::remove_file(fixture.socket()).unwrap();
}

#[test]
fn nonprivate_state_directory_refuses_before_database_creation() {
    let fixture = Fixture::new();
    fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o755)).unwrap();
    let (status, error) = run_short(&fixture);
    assert!(!status.success());
    assert!(error.contains("mode 0700"));
    assert!(!fixture.database.exists());
    fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o700)).unwrap();
}
