#![cfg(target_os = "linux")]

use std::fs::{self, DirBuilder};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{self, Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use podbay_core::AttestedPeer;
use podbay_pod::{LinuxPeerError, LinuxPeerEvidence};

#[test]
fn child_connect_helper() {
    let Ok(path) = std::env::var("PODBAY_PEER_TEST_SOCKET") else {
        return;
    };
    let mut socket = UnixStream::connect(path).unwrap();
    socket
        .write_all(b"{\"pid\":1,\"birth\":\"forged\"}\n")
        .unwrap();
    let mut release = [0u8; 1];
    socket.read_exact(&mut release).unwrap();
}

struct Fixture {
    child: Child,
    stream: UnixStream,
    directory: PathBuf,
}
impl Fixture {
    fn start() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("pb-peer-{}-{nonce}", process::id()));
        DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let socket_path = directory.join("peer.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "child_connect_helper", "--nocapture"])
            .env("PODBAY_PEER_TEST_SOCKET", &socket_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "peer helper did not connect");
                    assert!(
                        child.try_wait().unwrap().is_none(),
                        "peer helper exited before connect"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("peer accept failed: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        Self {
            child,
            stream,
            directory,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.stream.write_all(b"x");
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn accepted_same_uid_child_cannot_spoof_pid_or_birth_with_request_fields() {
    let mut fixture = Fixture::start();
    let mut claim = Vec::new();
    loop {
        assert!(claim.len() < 128, "forged peer claim exceeded test bound");
        let mut byte = [0u8; 1];
        fixture.stream.read_exact(&mut byte).unwrap();
        if byte[0] == b'\n' {
            break;
        }
        claim.push(byte[0]);
    }
    let parsed: serde_json::Value = serde_json::from_slice(&claim).unwrap();
    assert_eq!(parsed["pid"], 1);
    assert_eq!(parsed["birth"], "forged");

    let evidence = LinuxPeerEvidence::from_accepted(&fixture.stream).unwrap();
    assert_eq!(evidence.pid(), fixture.child.id() as i32);
    assert_ne!(evidence.pid(), 1);
    assert_eq!(
        evidence.uid(),
        fs::metadata(&fixture.directory).unwrap().uid()
    );
    assert!(evidence.start_ticks() > 0);
    evidence.require_containment(evidence.cgroup()).unwrap();
    evidence
        .recheck_before_effect(&fixture.stream, evidence.attested_peer())
        .unwrap();

    let forged_birth = AttestedPeer::from_port(
        &format!("linux.uid.{}", evidence.uid()),
        &format!("linux.pid.{}", evidence.pid()),
        &format!("linux.boot.{}", evidence.boot_id()),
        &format!("linux.start.{}", evidence.start_ticks() + 1),
        &format!("linux.cgroup.{}", evidence.cgroup()),
    )
    .unwrap();
    assert!(matches!(
        evidence.recheck_before_effect(&fixture.stream, &forged_birth),
        Err(LinuxPeerError::EvidenceChanged)
    ));
    let forged_cgroup = AttestedPeer::from_port(
        &format!("linux.uid.{}", evidence.uid()),
        &format!("linux.pid.{}", evidence.pid()),
        &format!("linux.boot.{}", evidence.boot_id()),
        &format!("linux.start.{}", evidence.start_ticks()),
        "linux.cgroup./sibling.slice",
    )
    .unwrap();
    assert!(matches!(
        evidence.recheck_before_effect(&fixture.stream, &forged_cgroup),
        Err(LinuxPeerError::EvidenceChanged)
    ));
    assert!(matches!(
        evidence.require_containment("/sibling.slice"),
        Err(LinuxPeerError::WrongContainment)
    ));

    fixture.stream.write_all(b"x").unwrap();
    fixture.child.wait().unwrap();
    assert!(
        evidence
            .recheck_before_effect(&fixture.stream, evidence.attested_peer())
            .is_err(),
        "a disappeared peer process must not retain control evidence"
    );
}
