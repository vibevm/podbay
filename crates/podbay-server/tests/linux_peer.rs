#![cfg(target_os = "linux")]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use podbay_server::LinuxAcceptedPeerEvidence;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

#[test]
fn accepted_current_process_maps_exact_kernel_subject_and_rechecks() {
    let fixture = SocketFixture::new();
    let _client = UnixStream::connect(&fixture.socket_path).unwrap();
    let (accepted, _) = fixture.listener.accept().unwrap();
    let peer = LinuxAcceptedPeerEvidence::from_accepted(&accepted).unwrap();
    assert_eq!(peer.kernel_evidence().pid(), std::process::id() as i32);
    assert_eq!(
        peer.subject().process_identity(),
        format!("linux.pid.{}", std::process::id())
    );
    assert_eq!(
        peer.subject().os_identity(),
        format!("linux.uid.{}", peer.kernel_evidence().uid())
    );
    assert_eq!(
        peer.subject().start_identity(),
        peer.kernel_evidence().start_ticks()
    );
    assert_eq!(
        peer.subject().containment_identity(),
        peer.kernel_evidence().cgroup()
    );
    assert_eq!(
        peer.recheck_before_dispatch(&accepted).unwrap(),
        peer.subject()
    );
}

#[test]
fn accepted_sibling_ignores_forged_json_pid_and_refuses_changed_or_dead_peer() {
    let fixture = SocketFixture::new();
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "peer_child_fixture", "--nocapture"])
            .env("PODBAY_PEER_FIXTURE_SOCKET", &fixture.socket_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let (mut accepted, _) = accept_bounded(&fixture.listener, &mut child.0);
    let peer = LinuxAcceptedPeerEvidence::from_accepted(&accepted).unwrap();
    assert_eq!(peer.kernel_evidence().pid(), child.0.id() as i32);
    assert_eq!(
        peer.subject().process_identity(),
        format!("linux.pid.{}", child.0.id())
    );
    accepted
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut forged = [0_u8; 9];
    accepted.read_exact(&mut forged).unwrap();
    assert_eq!(&forged, br#"{"pid":1}"#);
    peer.recheck_before_dispatch(&accepted).unwrap();

    let (other, _other_end) = UnixStream::pair().unwrap();
    assert!(peer.recheck_before_dispatch(&other).is_err());
    child.terminate();
    assert!(peer.recheck_before_dispatch(&accepted).is_err());
}

/// Only the explicitly spawned helper connects. Its bytes are untrusted data.
#[test]
fn peer_child_fixture() {
    let Some(path) = std::env::var_os("PODBAY_PEER_FIXTURE_SOCKET") else {
        return;
    };
    let mut connection = UnixStream::connect(path).unwrap();
    connection.write_all(br#"{"pid":1}"#).unwrap();
    let mut byte = [0_u8; 1];
    let _ = connection.read(&mut byte);
}

struct SocketFixture {
    root: PathBuf,
    socket_path: PathBuf,
    listener: UnixListener,
}
impl SocketFixture {
    fn new() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "podbay-server-peer-{}-{stamp}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let socket_path = root.join("peer.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        Self {
            root,
            socket_path,
            listener,
        }
    }
}
impl Drop for SocketFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct ChildGuard(Child);
impl ChildGuard {
    fn terminate(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.terminate();
    }
}

fn accept_bounded(
    listener: &UnixListener,
    child: &mut Child,
) -> (UnixStream, std::os::unix::net::SocketAddr) {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok(pair) => return pair,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "fixture child exited before connect"
                );
                assert!(Instant::now() < deadline, "fixture child did not connect");
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("fixture accept failed: {error}"),
        }
    }
}
