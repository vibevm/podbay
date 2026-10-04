//! Pod-owned child stdio transport. Only the direct child is supervised here.

use std::ffi::OsString;
use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant, SystemTime};

use crate::{JsonlTransport, MAX_FRAME_BYTES};

const MAX_ARGS: usize = 64;
const MAX_ENV: usize = 16;
const MAX_TIMEOUT: Duration = Duration::from_secs(60);
const DIRECT_CHILD_REAP_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(unix)]
const ERRNO_ESRCH: i32 = 3;
const ALLOWED_EXTRA_ENV: &[&str] = &["PATH", "LANG", "LC_ALL", "TMPDIR", "TMP", "TEMP"];

/// A reviewed pod-side launch selection. `HOME` and `CODEX_HOME` are always
/// explicit isolated directories; ambient environment is never inherited.
pub struct ChildLaunchSpec {
    executable: PathBuf,
    argv: Vec<OsString>,
    cwd: PathBuf,
    isolated_home: PathBuf,
    codex_home: PathBuf,
    extra_env: Vec<(OsString, OsString)>,
    read_timeout: Duration,
    write_timeout: Duration,
}

impl ChildLaunchSpec {
    pub fn new(
        executable: PathBuf,
        argv: Vec<OsString>,
        cwd: PathBuf,
        isolated_home: PathBuf,
        codex_home: PathBuf,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> io::Result<Self> {
        if !executable.is_absolute()
            || !cwd.is_absolute()
            || !isolated_home.is_absolute()
            || !codex_home.is_absolute()
        {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "launch paths must be absolute",
            ));
        }
        if argv.len() > MAX_ARGS || argv.iter().any(|arg| arg.to_string_lossy().len() > 16_384) {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "child argv exceeds bounds",
            ));
        }
        if read_timeout.is_zero()
            || write_timeout.is_zero()
            || read_timeout > MAX_TIMEOUT
            || write_timeout > MAX_TIMEOUT
        {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "I/O deadlines are invalid",
            ));
        }
        Ok(Self {
            executable,
            argv,
            cwd,
            isolated_home,
            codex_home,
            extra_env: Vec::new(),
            read_timeout,
            write_timeout,
        })
    }

    /// Adds an explicitly reviewed non-secret runtime variable. HOME,
    /// CODEX_HOME, account tokens, and proxy variables are never accepted here.
    pub fn with_allowed_env(mut self, name: &str, value: OsString) -> io::Result<Self> {
        if !ALLOWED_EXTRA_ENV.contains(&name)
            || self.extra_env.len() >= MAX_ENV
            || self.extra_env.iter().any(|(key, _)| key == name)
            || value.to_string_lossy().len() > 32_768
        {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "environment key or value is not allowed",
            ));
        }
        self.extra_env.push((OsString::from(name), value));
        Ok(self)
    }

    fn checked_paths(&self) -> io::Result<(PathBuf, PathBuf)> {
        if !self.cwd.is_dir() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "child cwd is not a directory",
            ));
        }
        let home = fs::canonicalize(&self.isolated_home)?;
        let codex_home = fs::canonicalize(&self.codex_home)?;
        if !home.is_dir() || !codex_home.is_dir() || !codex_home.starts_with(&home) {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "CODEX_HOME is outside isolated HOME",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&home, &codex_home] {
                if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
                    return Err(io::Error::new(
                        ErrorKind::PermissionDenied,
                        "isolated home is not private",
                    ));
                }
            }
        }
        Ok((home, codex_home))
    }
}

#[derive(Clone, Debug)]
pub struct ChildBirthObservation {
    pub pid: u32,
    /// Parent clock after spawn returned, not kernel process-birth attestation.
    pub observed_at: SystemTime,
}

/// Linux kernel evidence for the exact owned direct child at one observation.
/// This does not attest pod membership, descendants, credentials, or readiness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelChildBirthObservation {
    pub pid: u32,
    pub start_ticks: u64,
    pub boot_id: String,
    pub cgroup_path: String,
}

#[derive(Clone, Debug)]
pub struct ChildExitObservation {
    pub pid: u32,
    pub status: ExitStatus,
    pub observed_at: SystemTime,
}

/// One child, one reader, one writer. No background I/O worker can outlive the
/// transport. On unsupported targets construction refuses before launching.
pub struct ProcessJsonlTransport {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    read_buffer: Vec<u8>,
    read_timeout: Duration,
    write_timeout: Duration,
    birth: ChildBirthObservation,
    #[cfg(target_os = "linux")]
    kernel_birth: Result<KernelChildBirthObservation, ErrorKind>,
    exit: Option<ChildExitObservation>,
}

impl ProcessJsonlTransport {
    pub fn spawn(spec: ChildLaunchSpec) -> io::Result<Self> {
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = spec;
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "bounded child stdio backend is unavailable on this platform",
            ));
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use std::os::fd::AsRawFd;

            let (home, codex_home) = spec.checked_paths()?;
            let mut command = Command::new(&spec.executable);
            command
                .args(&spec.argv)
                .current_dir(&spec.cwd)
                .env_clear()
                .env("HOME", home)
                .env("CODEX_HOME", codex_home)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
            for (name, value) in &spec.extra_env {
                command.env(name, value);
            }
            let mut child = command.spawn()?;
            let Some(stdin) = child.stdin.take() else {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::other("child stdin pipe was unavailable"));
            };
            let Some(stdout) = child.stdout.take() else {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::other("child stdout pipe was unavailable"));
            };
            if let Err(error) = unix_pipe::set_nonblocking(stdin.as_raw_fd())
                .and_then(|()| unix_pipe::set_nonblocking(stdout.as_raw_fd()))
            {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
            #[cfg(target_os = "linux")]
            let kernel_birth = capture_kernel_birth(child.id())
                .and_then(|first| {
                    let second = capture_kernel_birth(child.id())?;
                    compare_kernel_birth(&first, &second)?;
                    Ok(first)
                })
                .map_err(|error| error.kind());
            Ok(Self {
                birth: ChildBirthObservation {
                    pid: child.id(),
                    observed_at: SystemTime::now(),
                },
                #[cfg(target_os = "linux")]
                kernel_birth,
                child,
                stdin: Some(stdin),
                stdout: Some(stdout),
                read_buffer: Vec::new(),
                read_timeout: spec.read_timeout,
                write_timeout: spec.write_timeout,
                exit: None,
            })
        }
    }

    pub fn birth(&self) -> &ChildBirthObservation {
        &self.birth
    }

    /// Rechecks the owned child and its kernel birth evidence immediately
    /// before returning a point-in-time receipt. A child that exited before
    /// initial capture can still be used for ordinary process I/O, but cannot
    /// yield this receipt. A PID alone is never enough.
    pub fn attest_kernel_birth(&mut self) -> io::Result<KernelChildBirthObservation> {
        #[cfg(target_os = "linux")]
        {
            let expected = self
                .kernel_birth
                .as_ref()
                .map_err(|kind| {
                    io::Error::new(*kind, "initial direct-child kernel birth was unavailable")
                })?
                .clone();
            if self.observe_exit()?.is_some() {
                return Err(io::Error::new(
                    ErrorKind::NotFound,
                    "direct child has exited",
                ));
            }
            let first = capture_kernel_birth(self.birth.pid)?;
            compare_kernel_birth(&expected, &first)?;
            if self.observe_exit()?.is_some() {
                return Err(io::Error::new(
                    ErrorKind::NotFound,
                    "direct child exited during birth attestation",
                ));
            }
            let second = capture_kernel_birth(self.birth.pid)?;
            compare_kernel_birth(&first, &second)?;
            if self.observe_exit()?.is_some() {
                return Err(io::Error::new(
                    ErrorKind::NotFound,
                    "direct child exited during birth attestation",
                ));
            }
            return Ok(second);
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                ErrorKind::Unsupported,
                "Linux kernel child-birth evidence is unavailable on this platform",
            ))
        }
    }

    pub fn observe_exit(&mut self) -> io::Result<Option<ChildExitObservation>> {
        if let Some(exit) = &self.exit {
            return Ok(Some(exit.clone()));
        }
        if let Some(status) = self.child.try_wait()? {
            let exit = self.record_exit(status);
            return Ok(Some(exit));
        }
        Ok(None)
    }

    /// Requests direct-child termination and returns a reaped exit when
    /// observed. After a successful kill, reap has a three-second bound;
    /// an error does not prove reap. Escaped descendants are not contained.
    pub fn dispose(&mut self) -> io::Result<ChildExitObservation> {
        if let Some(exit) = &self.exit {
            return Ok(exit.clone());
        }
        self.stdin.take();
        self.stdout.take();
        let status = match self.child.try_wait()? {
            Some(status) => status,
            None => {
                if let Err(kill_error) = self.child.kill() {
                    // The child may exit between try_wait and kill. Re-check
                    // before reporting failure so it is still reaped.
                    if let Some(status) = self.child.try_wait()? {
                        return Ok(self.record_exit(status));
                    }
                    #[cfg(unix)]
                    if kill_error.raw_os_error() == Some(ERRNO_ESRCH) {
                        // ESRCH on Linux/Darwin means the target is already
                        // gone; wait reaps the still-owned direct child.
                        let status = self.child.wait()?;
                        return Ok(self.record_exit(status));
                    }
                    return Err(kill_error);
                }
                self.wait_for_reap_bounded()?
            }
        };
        Ok(self.record_exit(status))
    }

    fn wait_for_reap_bounded(&mut self) -> io::Result<ExitStatus> {
        let deadline = Instant::now() + DIRECT_CHILD_REAP_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    "direct child did not exit after termination",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn record_exit(&mut self, status: ExitStatus) -> ChildExitObservation {
        let exit = ChildExitObservation {
            pid: self.birth.pid,
            status,
            observed_at: SystemTime::now(),
        };
        self.exit = Some(exit.clone());
        exit
    }

    fn abort_with(&mut self, kind: ErrorKind, message: &'static str) -> io::Error {
        match self.dispose() {
            Ok(_) => io::Error::new(kind, message),
            Err(_) => io::Error::new(
                kind,
                "child I/O failed and direct-child reap was not observed",
            ),
        }
    }
}

#[cfg(target_os = "linux")]
fn capture_kernel_birth(pid: u32) -> io::Result<KernelChildBirthObservation> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    if stat.len() > 16_384 || !stat.starts_with(&format!("{pid} (")) {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "direct child stat identity is malformed",
        ));
    }
    let end = stat
        .rfind(") ")
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "direct child stat is malformed"))?;
    let fields: Vec<_> = stat[end + 2..].split_whitespace().collect();
    // The first field after `(comm)` is stat field 3 (state); starttime is 22.
    let state = fields
        .first()
        .copied()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "direct child state is missing"))?;
    if matches!(state, "Z" | "X" | "x") {
        return Err(io::Error::new(
            ErrorKind::NotFound,
            "direct child is no longer live",
        ));
    }
    let start_ticks = fields
        .get(19)
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "direct child start is missing"))?
        .parse::<u64>()
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "direct child start is malformed"))?;
    if start_ticks == 0 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "direct child start is zero",
        ));
    }

    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let boot_id = boot_id.trim();
    if boot_id.len() != 36
        || !boot_id.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "boot ID is malformed",
        ));
    }

    let cgroups = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    if cgroups.len() > 16_384 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "direct child cgroup evidence exceeds bound",
        ));
    }
    let mut unified = cgroups.lines().filter_map(|line| line.strip_prefix("0::"));
    let cgroup_path = unified
        .next()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "unified child cgroup is missing"))?;
    if unified.next().is_some()
        || !cgroup_path.starts_with('/')
        || cgroup_path.chars().any(char::is_control)
    {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "unified child cgroup is malformed",
        ));
    }
    Ok(KernelChildBirthObservation {
        pid,
        start_ticks,
        boot_id: boot_id.to_owned(),
        cgroup_path: cgroup_path.to_owned(),
    })
}

#[cfg(target_os = "linux")]
fn compare_kernel_birth(
    expected: &KernelChildBirthObservation,
    observed: &KernelChildBirthObservation,
) -> io::Result<()> {
    if observed != expected {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "direct child kernel birth identity changed",
        ));
    }
    Ok(())
}

impl JsonlTransport for ProcessJsonlTransport {
    fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        if line.len() > MAX_FRAME_BYTES
            || line.last() != Some(&b'\n')
            || line[..line.len().saturating_sub(1)].contains(&b'\n')
        {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "outbound JSONL frame is invalid",
            ));
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = line;
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "bounded stdio backend unavailable",
            ));
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use std::os::fd::AsRawFd;

            let deadline = Instant::now() + self.write_timeout;
            let mut offset = 0;
            while offset < line.len() {
                let Some(stdin) = self.stdin.as_mut() else {
                    return Err(io::Error::new(
                        ErrorKind::BrokenPipe,
                        "child stdin is closed",
                    ));
                };
                match stdin.write(&line[offset..]) {
                    Ok(0) => {
                        return Err(self
                            .abort_with(ErrorKind::WriteZero, "child stdin closed during write"));
                    }
                    Ok(written) => offset += written,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        let fd = stdin.as_raw_fd();
                        match unix_pipe::wait_ready(fd, unix_pipe::POLLOUT, deadline) {
                            Ok(()) => {}
                            Err(error) if error.kind() == ErrorKind::TimedOut => {
                                return Err(self.abort_with(
                                    ErrorKind::TimedOut,
                                    "child stdin write timed out",
                                ));
                            }
                            Err(error) => {
                                return Err(
                                    self.abort_with(error.kind(), "child stdin poll failed")
                                );
                            }
                        }
                    }
                    Err(error) => {
                        return Err(self.abort_with(error.kind(), "child stdin write failed"));
                    }
                }
                if Instant::now() >= deadline && offset < line.len() {
                    return Err(self.abort_with(ErrorKind::TimedOut, "child stdin write timed out"));
                }
            }
            if Instant::now() >= deadline {
                return Err(self.abort_with(
                    ErrorKind::TimedOut,
                    "child stdin write completed after deadline",
                ));
            }
            Ok(())
        }
    }

    fn read_line(&mut self) -> io::Result<Option<Vec<u8>>> {
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "bounded stdio backend unavailable",
            ));
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use std::os::fd::AsRawFd;

            let deadline = Instant::now() + self.read_timeout;
            let mut scanned = 0usize;
            loop {
                if let Some(relative) = self.read_buffer[scanned..]
                    .iter()
                    .position(|byte| *byte == b'\n')
                {
                    let end = scanned + relative;
                    if end + 1 > MAX_FRAME_BYTES {
                        return Err(self.abort_with(
                            ErrorKind::InvalidData,
                            "child JSONL frame exceeded bound",
                        ));
                    }
                    return Ok(Some(self.read_buffer.drain(..=end).collect()));
                }
                scanned = self.read_buffer.len();
                if self.read_buffer.len() >= MAX_FRAME_BYTES {
                    return Err(
                        self.abort_with(ErrorKind::InvalidData, "child JSONL frame exceeded bound")
                    );
                }
                let Some(stdout) = self.stdout.as_mut() else {
                    return Err(io::Error::new(
                        ErrorKind::BrokenPipe,
                        "child stdout is closed",
                    ));
                };
                let fd = stdout.as_raw_fd();
                match unix_pipe::wait_ready(fd, unix_pipe::POLLIN, deadline) {
                    Ok(()) => {}
                    Err(error) if error.kind() == ErrorKind::TimedOut => {
                        return Err(
                            self.abort_with(ErrorKind::TimedOut, "child stdout read timed out")
                        );
                    }
                    Err(error) => {
                        return Err(self.abort_with(error.kind(), "child stdout poll failed"));
                    }
                }
                let mut chunk = [0u8; 8192];
                match stdout.read(&mut chunk) {
                    Ok(0) if self.read_buffer.is_empty() => return Ok(None),
                    Ok(0) => {
                        return Err(self.abort_with(
                            ErrorKind::UnexpectedEof,
                            "child closed a partial JSONL frame",
                        ));
                    }
                    Ok(bytes) => self.read_buffer.extend_from_slice(&chunk[..bytes]),
                    Err(error) if error.kind() == ErrorKind::WouldBlock => continue,
                    Err(error) => {
                        return Err(self.abort_with(error.kind(), "child stdout read failed"));
                    }
                }
            }
        }
    }
}

impl Drop for ProcessJsonlTransport {
    fn drop(&mut self) {
        let _ = self.dispose();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod kernel_birth_tests {
    use super::{KernelChildBirthObservation, compare_kernel_birth};
    use std::io::ErrorKind;

    #[test]
    fn pid_reuse_and_changed_boot_or_cgroup_shapes_are_refused() {
        let expected = KernelChildBirthObservation {
            pid: 123,
            start_ticks: 456,
            boot_id: "11111111-2222-3333-4444-555555555555".into(),
            cgroup_path: "/user.slice/pod.fixture".into(),
        };
        for observed in [
            KernelChildBirthObservation {
                start_ticks: 457,
                ..expected.clone()
            },
            KernelChildBirthObservation {
                pid: 124,
                ..expected.clone()
            },
            KernelChildBirthObservation {
                boot_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
                ..expected.clone()
            },
            KernelChildBirthObservation {
                cgroup_path: "/user.slice/other".into(),
                ..expected.clone()
            },
        ] {
            assert_eq!(
                compare_kernel_birth(&expected, &observed)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidData,
            );
        }
        compare_kernel_birth(&expected, &expected).unwrap();
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix_pipe {
    use std::io::{self, ErrorKind};
    use std::os::raw::{c_int, c_short};
    use std::time::Instant;

    pub const POLLIN: c_short = 0x0001;
    pub const POLLOUT: c_short = 0x0004;
    const POLLERR: c_short = 0x0008;
    const POLLNVAL: c_short = 0x0020;
    const F_GETFL: c_int = 3;
    const F_SETFL: c_int = 4;
    #[cfg(target_os = "linux")]
    const O_NONBLOCK: c_int = 0o4000;
    #[cfg(target_os = "macos")]
    const O_NONBLOCK: c_int = 0x0004;
    #[cfg(target_os = "linux")]
    type PollCount = usize;
    #[cfg(target_os = "macos")]
    type PollCount = u32;

    #[repr(C)]
    struct PollFd {
        fd: c_int,
        events: c_short,
        revents: c_short,
    }

    unsafe extern "C" {
        fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
        fn poll(fds: *mut PollFd, count: PollCount, timeout_ms: c_int) -> c_int;
    }

    pub fn set_nonblocking(fd: c_int) -> io::Result<()> {
        // SAFETY: fd is an owned child pipe and F_GETFL has no variadic value.
        let flags = unsafe { fcntl(fd, F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd remains open here; F_SETFL consumes one c_int flags value.
        if unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn wait_ready(fd: c_int, events: c_short, deadline: Instant) -> io::Result<()> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    "child pipe deadline elapsed",
                ));
            }
            let millis = remaining.as_millis().max(1).min(c_int::MAX as u128) as c_int;
            let mut item = PollFd {
                fd,
                events,
                revents: 0,
            };
            // SAFETY: item is a valid writable pollfd for exactly one element;
            // poll does not retain its pointer after returning.
            let ready = unsafe { poll(&mut item, 1, millis) };
            if ready == 0 {
                continue;
            }
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if item.revents & POLLNVAL != 0 {
                return Err(io::Error::new(
                    ErrorKind::BrokenPipe,
                    "child pipe descriptor invalid",
                ));
            }
            if item.revents & (events | POLLERR) != 0 {
                return Ok(());
            }
            // POLLHUP is handled by the following nonblocking read/write.
            if item.revents != 0 {
                return Ok(());
            }
        }
    }
}
