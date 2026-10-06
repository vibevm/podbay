use super::*;
use std::io::{Read, Write};
use std::process::ExitStatus;
use std::time::Instant;

const MODE: &str = "PODBAY_FD3_SYS_DISPOSABLE_CASE";

fn inventory() -> Vec<i32> {
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
    fds
}

fn children() -> String {
    std::fs::read_to_string("/proc/thread-self/children").unwrap()
}

fn flags(fd: i32) -> i32 {
    // SAFETY: F_GETFD only queries this process's descriptor table.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(flags >= 0);
    flags
}

fn identity(pid: u32) -> io::Result<(u32, u64)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let (_, tail) = stat.rsplit_once(") ").ok_or(io::ErrorKind::InvalidData)?;
    let fields: Vec<_> = tail.split_whitespace().collect();
    Ok((
        fields[1].parse().map_err(|_| io::ErrorKind::InvalidData)?,
        fields[19].parse().map_err(|_| io::ErrorKind::InvalidData)?,
    ))
}

fn send(stream: &mut UnixStream, bytes: &[u8]) {
    assert!(bytes.len() <= 128);
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(bytes).unwrap();
}

fn receive(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > 128 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn wait(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "exact fixture child exit deadline"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        if self.0.try_wait().expect("fixture child status").is_none() {
            self.0.kill().expect("kill only exact fixture child");
        }
        self.0.wait().expect("reap exact fixture child");
    }
}

fn run_case(case: &str) {
    let mut child = Reap(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "tests::disposable_supervisor",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env(MODE, case)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let status = wait(&mut child.0);
    let mut output = String::new();
    child
        .0
        .stdout
        .take()
        .unwrap()
        .take(8192)
        .read_to_string(&mut output)
        .unwrap();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .take(8192)
        .read_to_string(&mut output)
        .unwrap();
    assert!(status.success(), "disposable {case}: {status}\n{output}");
}

fn spec() -> SpawnSpec {
    SpawnSpec {
        program: std::env::current_exe().unwrap(),
        args: [
            "--ignored",
            "--exact",
            "tests::disposable_endpoint",
            "--nocapture",
            "--test-threads=1",
        ]
        .into_iter()
        .map(OsString::from)
        .collect(),
        cwd: PathBuf::from("/"),
        env: vec![(MODE.into(), "endpoint".into())],
    }
}

#[test]
fn real_child_inventory_retry_reap_and_eof() {
    run_case("transport");
}

#[test]
fn occupied_fd3_refuses_without_replacing_parent_descriptor() {
    run_case("occupied");
}

#[test]
fn exec_errors_and_close_range_faults_preserve_error_reporting_and_reap() {
    run_case("errors");
}

#[test]
fn closed_standard_descriptors_cannot_overwrite_socket_source() {
    run_case("closed-stdio");
}

#[test]
#[ignore = "private supervisor process invoked by the four tests above"]
fn disposable_supervisor() {
    let case = std::env::var(MODE).expect("private supervisor mode");
    match case.as_str() {
        "transport" => transport(&reserve_fd3().unwrap()),
        "occupied" => {
            let occupied = File::open("/dev/null").unwrap();
            assert_eq!(occupied.as_raw_fd(), 3);
            let before = inventory();
            let before_flags = flags(3);
            let before_path = std::fs::read_link("/proc/self/fd/3").unwrap();
            assert_eq!(reserve_fd3().unwrap_err().raw_os_error(), Some(libc::EBUSY));
            assert_eq!(flags(3), before_flags);
            assert_eq!(std::fs::read_link("/proc/self/fd/3").unwrap(), before_path);
            assert_eq!(inventory(), before);
            assert!(children().is_empty());
        }
        "errors" => errors(),
        "closed-stdio" => {
            let slot = reserve_fd3().unwrap();
            let restore = ClosedStdio::new();
            transport(&slot);
            drop(restore);
        }
        _ => panic!("unknown private case"),
    }
}

fn transport(slot: &Fd3Reservation) {
    let baseline = inventory();
    let before_children = children();
    let placeholder = std::fs::read_link("/proc/self/fd/3").unwrap();
    let sentinel = File::open("/dev/null").unwrap();
    // SAFETY: F_DUPFD allocates a new owned, deliberately inheritable sentinel.
    let raw = unsafe { libc::fcntl(sentinel.as_raw_fd(), libc::F_DUPFD, 64) };
    assert!(raw >= 64);
    // SAFETY: raw is a new descriptor, reconstructed exactly once.
    let sentinel_copy = unsafe { OwnedFd::from_raw_fd(raw) };
    drop(sentinel);
    assert_eq!(flags(raw) & libc::FD_CLOEXEC, 0);
    let SpawnedFd3 { child, mut channel } = spawn_fd3(slot, spec()).unwrap();
    let mut child = Reap(child);
    let pid = child.0.id();
    let expected = identity(pid).unwrap();
    assert_eq!(expected.0, std::process::id());
    assert!(expected.1 > 0);
    assert_ne!(flags(channel.as_raw_fd()) & libc::FD_CLOEXEC, 0);
    assert_ne!(flags(3) & libc::FD_CLOEXEC, 0);
    assert_eq!(std::fs::read_link("/proc/self/fd/3").unwrap(), placeholder);
    let report = receive(&mut channel).unwrap();
    assert_eq!(report.len(), 32);
    assert_eq!(&report[..8], b"FD3TEST1");
    assert_eq!(u32::from_be_bytes(report[8..12].try_into().unwrap()), pid);
    assert_eq!(
        u32::from_be_bytes(report[12..16].try_into().unwrap()),
        expected.0
    );
    assert_eq!(
        u64::from_be_bytes(report[16..24].try_into().unwrap()),
        expected.1
    );
    assert_eq!(
        i32::from_be_bytes(report[24..28].try_into().unwrap()) & libc::FD_CLOEXEC,
        0
    );
    assert_eq!(&report[28..], &[0, 1, 2, 3]);
    let mut nonce = [0; 32];
    File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut nonce)
        .unwrap();
    for _ in 0..3 {
        send(&mut channel, &nonce);
        assert_eq!(receive(&mut channel).unwrap(), nonce);
        assert_eq!(identity(pid).unwrap(), expected);
        assert!(child.0.try_wait().unwrap().is_none());
    }
    assert_eq!(
        flags(raw) & libc::FD_CLOEXEC,
        0,
        "parent sentinel was changed"
    );
    send(&mut channel, &[]);
    assert!(wait(&mut child.0).success(), "exact endpoint failed");
    assert!(child.0.wait().unwrap().success());
    let mut byte = [0];
    assert_eq!(channel.read(&mut byte).unwrap(), 0, "child endpoint leaked");
    assert!(identity(pid).map(|now| now != expected).unwrap_or(true));
    drop(child);
    drop(channel);
    drop(sentinel_copy);
    assert_eq!(inventory(), baseline, "parent leaked descriptors");
    assert_eq!(children(), before_children, "unreaped fixture child");
}

fn errors() {
    let slot = reserve_fd3().unwrap();
    let baseline = inventory();
    let before_children = children();
    for errno in [libc::ENOSYS, libc::EINVAL, libc::EPERM] {
        let error = spawn_inner(&slot, spec(), CloseRange::Fault(errno)).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(errno));
        assert_eq!(inventory(), baseline);
        assert_eq!(children(), before_children);
    }
    let mut absent = spec();
    absent.program = PathBuf::from("/proc/self/podbay-fd3-no-such-executable");
    assert_eq!(
        spawn_fd3(&slot, absent).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    let mut bad_cwd = spec();
    bad_cwd.cwd = PathBuf::from("/proc/self/podbay-fd3-no-such-directory");
    assert_eq!(
        spawn_fd3(&slot, bad_cwd).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    let mut denied = spec();
    denied.program = PathBuf::from("/dev/null");
    assert_eq!(
        spawn_fd3(&slot, denied).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(inventory(), baseline);
    assert_eq!(children(), before_children);
    transport(&slot); // failed spawns cannot poison the still-owned reservation
}

struct ClosedStdio(Vec<(i32, i32, OwnedFd)>);
impl ClosedStdio {
    fn new() -> Self {
        let mut restore = Self(Vec::new());
        for fd in 0..=2 {
            let previous_flags = flags(fd);
            // SAFETY: each original is live; duplicate ownership is independent.
            let raw = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 64) };
            assert!(raw >= 64);
            // SAFETY: this newly allocated descriptor is reconstructed once.
            restore
                .0
                .push((fd, previous_flags, unsafe { OwnedFd::from_raw_fd(raw) }));
        }
        for fd in 0..=2 {
            // SAFETY: only this private subprocess's inherited stdio is closed.
            assert_eq!(unsafe { libc::close(fd) }, 0);
        }
        restore
    }
}
impl Drop for ClosedStdio {
    fn drop(&mut self) {
        for (fd, previous_flags, saved) in &self.0 {
            // SAFETY: restore only this fixture subprocess's original stdio.
            assert_eq!(unsafe { libc::dup2(saved.as_raw_fd(), *fd) }, *fd);
            assert_eq!(
                unsafe { libc::fcntl(*fd, libc::F_SETFD, *previous_flags) },
                0
            );
        }
    }
}

#[test]
#[ignore = "private clean-exec endpoint; never an application entry point"]
fn disposable_endpoint() {
    assert_eq!(std::env::var(MODE).as_deref(), Ok("endpoint"));
    assert_eq!(inventory(), [0, 1, 2, 3]);
    // SAFETY: this isolated endpoint reconstructs the transferred FD3 once;
    // no other owner of FD3 is created in this subprocess.
    let mut stream = unsafe { UnixStream::from_raw_fd(3) };
    let (ppid, birth) = identity(std::process::id()).unwrap();
    let mut report = b"FD3TEST1".to_vec();
    report.extend_from_slice(&std::process::id().to_be_bytes());
    report.extend_from_slice(&ppid.to_be_bytes());
    report.extend_from_slice(&birth.to_be_bytes());
    report.extend_from_slice(&flags(3).to_be_bytes());
    report.extend_from_slice(&[0, 1, 2, 3]);
    send(&mut stream, &report);
    let first = receive(&mut stream).unwrap();
    assert_eq!(first.len(), 32);
    send(&mut stream, &first);
    loop {
        let next = receive(&mut stream).unwrap();
        if next.is_empty() {
            break;
        }
        assert_eq!(next, first);
        send(&mut stream, &next);
    }
}
