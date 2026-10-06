use super::*;
use ed25519_compact::Seed;
use std::io::{Read, Write};
#[cfg(not(target_os = "linux"))]
compile_error!("disposable child/FD fixture currently supports Linux only");
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn key(byte: u8) -> KeyPair {
    KeyPair::from_seed(Seed::new([byte; 32]))
}
fn fixture() -> SubjectV1 {
    SubjectV1 {
        nonce: [1; 32],
        generation: 1,
        manager_epoch: 2,
        accepted_launch_digest: [2; 32],
        policy_digest: [3; 32],
        artifact_digest: [4; 32],
        config_digest: [5; 32],
        profile_digest: [6; 32],
        command_id: "command.fixture".into(),
        actor_id: "actor.fixture".into(),
        scope_id: "scope.fixture".into(),
        pod_id: "pod.fixture".into(),
        session_id: "session.fixture".into(),
        run_id: "run.fixture".into(),
        attempt_id: "attempt.fixture".into(),
        resource_id: "resource.fixture".into(),
        child_pid: 123,
        child_birth: 456,
        boot_id: boot(),
        requested_state_db: "/fixture/requested.sqlite".into(),
    }
}
fn boot() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap()
        .trim()
        .into()
}
fn birth(pid: u32) -> std::io::Result<u64> {
    let data = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    data[data.rfind(')').ok_or(std::io::ErrorKind::InvalidData)? + 2..]
        .split_whitespace()
        .nth(19)
        .ok_or(std::io::ErrorKind::InvalidData)?
        .parse()
        .map_err(|_| std::io::ErrorKind::InvalidData.into())
}
#[test]
fn closed_codec_authentication_and_exact_replay() {
    let expected = fixture();
    let k = key(7);
    let frame = sign(&expected, Observation::IdentityUnavailable, &k).unwrap();
    assert_eq!(verify(&frame, &expected, &k.pk).unwrap().subject, expected);
    assert_eq!(
        frame,
        sign(&expected, Observation::IdentityUnavailable, &k).unwrap()
    );
    assert_eq!(
        verify(&frame, &expected, &key(8).pk),
        Err(Refusal::Authentication)
    );
    assert_eq!(
        verify(
            &sign(&expected, Observation::ForeignOwner, &k).unwrap(),
            &expected,
            &k.pk
        ),
        Err(Refusal::ForeignOwner)
    );
    for cut in 0..frame.len() {
        assert!(verify(&frame[..cut], &expected, &k.pk).is_err());
    }
    let mut appended = frame.clone();
    appended.push(0);
    assert!(verify(&appended, &expected, &k.pk).is_err());
    for offset in [0, DOMAIN.len(), DOMAIN.len() + 1, frame.len() - 1] {
        let mut corrupt = frame.clone();
        corrupt[offset] ^= 255;
        assert!(verify(&corrupt, &expected, &k.pk).is_err());
    }
    let mut ready = body(&expected, Observation::IdentityUnavailable).unwrap();
    ready[DOMAIN.len() + 1] = 3;
    let sig = k.sk.sign(&ready, None);
    ready.extend_from_slice(sig.as_ref());
    assert!(verify(&ready, &expected, &k.pk).is_err());
    for outside in [
        b"HTTP/1.1 200 OK\r\n\r\n".as_slice(),
        b"{\"childPid\":123,\"ready\":true}",
        b"pairing-ticket",
    ] {
        assert!(verify(outside, &expected, &k.pk).is_err());
    }
}
#[test]
fn separately_trusted_subject_rejects_every_signed_binding_change() {
    let expected = fixture();
    let k = key(7);
    let mut changes = Vec::new();
    macro_rules! change {
        ($field:ident,$value:expr) => {{
            let mut s = expected.clone();
            s.$field = $value;
            changes.push(s);
        }};
    }
    change!(nonce, [9; 32]);
    change!(generation, 2);
    change!(manager_epoch, 3);
    change!(accepted_launch_digest, [9; 32]);
    change!(policy_digest, [9; 32]);
    change!(artifact_digest, [9; 32]);
    change!(config_digest, [9; 32]);
    change!(profile_digest, [9; 32]);
    change!(command_id, "command.foreign".into());
    change!(actor_id, "actor.foreign".into());
    change!(scope_id, "scope.foreign".into());
    change!(pod_id, "pod.foreign".into());
    change!(session_id, "session.foreign".into());
    change!(run_id, "run.foreign".into());
    change!(attempt_id, "attempt.foreign".into());
    change!(resource_id, "resource.foreign".into());
    change!(child_pid, 124);
    change!(child_birth, 457);
    change!(boot_id, "12345678-1234-1234-1234-123456789abc".into());
    change!(requested_state_db, "/fixture/foreign.sqlite".into());
    for changed in changes {
        assert_eq!(
            verify(
                &sign(&changed, Observation::IdentityUnavailable, &k).unwrap(),
                &expected,
                &k.pk
            ),
            Err(Refusal::Binding)
        );
    }
    let mut missing = expected.clone();
    missing.artifact_digest = [0; 32];
    assert_eq!(
        body(&missing, Observation::IdentityUnavailable),
        Err(Refusal::Malformed)
    );
    missing = expected.clone();
    missing.generation = 0;
    assert!(body(&missing, Observation::IdentityUnavailable).is_err());
    missing = expected.clone();
    missing.requested_state_db = "/fixture/../foreign".into();
    assert!(body(&missing, Observation::IdentityUnavailable).is_err());
    missing = expected.clone();
    missing.command_id = "x".repeat(ID_BOUND + 1);
    assert!(body(&missing, Observation::IdentityUnavailable).is_err());
    missing = expected.clone();
    missing.generation = u64::MAX;
    assert_eq!(
        decode(&body(&missing, Observation::IdentityUnavailable).unwrap())
            .unwrap()
            .0,
        missing
    );
}
fn send(stream: &mut UnixStream, bytes: &[u8]) -> std::io::Result<()> {
    if bytes.len() > MAX_FRAME {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)
}
fn receive(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    let mut raw = [0; 4];
    stream.read_exact(&mut raw)?;
    let n = u32::from_be_bytes(raw) as usize;
    if n > MAX_FRAME {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut bytes = vec![0; n];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}
struct ExactChild {
    process: Child,
    stream: UnixStream,
    pid: u32,
    birth: Option<u64>,
}
impl Drop for ExactChild {
    fn drop(&mut self) {
        if self
            .process
            .try_wait()
            .expect("exact child status")
            .is_none()
        {
            self.process.kill().expect("exact child kill");
        }
        self.process
            .wait()
            .expect("fixture exact child must be reaped");
        if let Some(expected) = self.birth {
            assert!(
                birth(self.pid).map(|now| now != expected).unwrap_or(true),
                "original child identity must be absent after reap"
            );
        }
    }
}
fn spawn(mode: &str) -> ExactChild {
    let (parent, child) = UnixStream::pair().unwrap();
    let fd = child.as_raw_fd();
    // Only numeric FD and test mode enter environment; fixture seed travels through the socket.
    let mut command = Command::new(std::env::current_exe().unwrap());
    let test_module = module_path!().split_once("::").expect("test module path").1;
    let endpoint = format!("{test_module}::child_endpoint");
    command
        .args([
            "--ignored",
            "--exact",
            &endpoint,
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("PODBAY_PRIVATE_FIXTURE_MODE", mode)
        .env("PODBAY_PRIVATE_FIXTURE_FD", "3")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if fd != 3 && libc::dup2(fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let process = command.spawn().unwrap();
    let pid = process.id();
    drop(child);
    let observed = birth(pid).ok();
    parent
        .set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    parent
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    ExactChild {
        process,
        stream: parent,
        pid,
        birth: observed,
    }
}
#[test]
#[ignore = "clean-exec endpoint activated only by private fixture FD"]
fn child_endpoint() {
    if std::env::var("PODBAY_PRIVATE_FIXTURE_FD").ok().as_deref() != Some("3") {
        return;
    }
    let mode = std::env::var("PODBAY_PRIVATE_FIXTURE_MODE").unwrap();
    if mode == "exit" {
        return;
    }
    let mut stream = unsafe { UnixStream::from_raw_fd(3) };
    let seed = receive(&mut stream).unwrap();
    let k = KeyPair::from_seed(Seed::from_slice(&seed).unwrap());
    let challenge = receive(&mut stream).unwrap();
    let (mut subject, _) = decode(&challenge).unwrap();
    subject.child_pid = std::process::id();
    subject.child_birth = birth(subject.child_pid).unwrap();
    subject.boot_id = boot();
    if mode == "eof" {
        return;
    }
    if mode == "timeout" {
        std::thread::sleep(Duration::from_secs(5));
        return;
    }
    if mode == "nonce" {
        subject.nonce = [9; 32];
    }
    if mode == "birth" {
        subject.child_birth += 1;
    }
    if mode == "pin" {
        subject.artifact_digest = [9; 32];
    }
    let observation = if mode == "foreign-owner" {
        Observation::ForeignOwner
    } else {
        Observation::IdentityUnavailable
    };
    let reply = sign(&subject, observation, &k).unwrap();
    send(&mut stream, &reply).unwrap();
    loop {
        let next = receive(&mut stream).unwrap();
        if next.is_empty() {
            break;
        }
        assert_eq!(
            next, challenge,
            "fixture cannot alter an existing challenge"
        );
        send(&mut stream, &reply).unwrap();
    }
}
#[test]
fn actual_exec_child_fd_nonce_birth_pin_foreign_owner_and_retry() {
    for mode in ["normal", "nonce", "birth", "pin", "foreign-owner"] {
        let mut child = spawn(mode);
        let mut expected = fixture();
        expected.child_pid = child.pid;
        expected.child_birth = child.birth.unwrap();
        assert!(child.process.try_wait().unwrap().is_none());
        let challenge = body(&expected, Observation::IdentityUnavailable).unwrap();
        send(&mut child.stream, &[7; 32]).unwrap();
        send(&mut child.stream, &challenge).unwrap();
        let reply = receive(&mut child.stream).unwrap();
        let result = verify(&reply, &expected, &key(7).pk);
        if mode == "normal" {
            assert!(result.is_ok());
            send(&mut child.stream, &challenge).unwrap();
            let replay = receive(&mut child.stream).unwrap();
            assert_eq!(reply, replay);
            assert!(verify(&replay, &expected, &key(7).pk).is_ok());
        } else {
            assert_eq!(
                result,
                Err(if mode == "foreign-owner" {
                    Refusal::ForeignOwner
                } else {
                    Refusal::Binding
                })
            );
        }
        assert_eq!(birth(child.pid).unwrap(), expected.child_birth);
        assert!(child.process.try_wait().unwrap().is_none());
        send(&mut child.stream, &[]).unwrap();
    }
}
#[test]
fn actual_exec_child_immediate_exit_eof_and_timeout_are_nonobservations() {
    let began = Instant::now();
    for mode in ["exit", "eof", "timeout"] {
        let mut child = spawn(mode);
        let mut expected = fixture();
        expected.child_pid = child.pid;
        expected.child_birth = child.birth.unwrap_or(1);
        let result = send(&mut child.stream, &[7; 32])
            .and_then(|_| {
                send(
                    &mut child.stream,
                    &body(&expected, Observation::IdentityUnavailable).unwrap(),
                )
            })
            .and_then(|_| receive(&mut child.stream));
        assert!(
            result.is_err(),
            "no authenticated observation on exit/EOF/timeout"
        );
    }
    assert!(began.elapsed() < Duration::from_secs(4));
}
