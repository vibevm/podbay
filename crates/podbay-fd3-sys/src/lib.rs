//! Linux FD3 exec boundary. This crate grants no launch or readiness authority.
//!
//! The caller must reserve an unused FD3 before opening other supervisor
//! resources. An occupied FD3 is refused, never overwritten in the parent.
//! The reservation remains borrowed throughout each synchronous spawn. This
//! prevents FD3 from colliding with Rust's private exec-error channel.
//!
//! Only a fresh socketpair's child endpoint survives exec as FD3. Descriptors
//! above it are marked CLOEXEC in the forked child, retaining the exec-error
//! channel until exec either succeeds or reports its error. Linux must support
//! CLOSE_RANGE_CLOEXEC; there is no fallback on unsupported or denied kernels.
//!
//! After success the caller owns the child and channel and must arrange exact
//! child cleanup. Dropping std::process::Child alone does not kill or reap it.
#![cfg(target_os = "linux")]
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Exclusive ownership of a CLOEXEC placeholder at FD3 in this process.
/// No raw descriptor, clone or ownership extraction is exposed.
#[derive(Debug)]
pub struct Fd3Reservation {
    fd: OwnedFd,
}

/// One spawn's explicit inputs. No inherited environment or shell is used.
/// Callers remain responsible for authorizing the executable and environment.
#[derive(Debug)]
pub struct SpawnSpec {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub cwd: PathBuf,
    pub env: Vec<(OsString, OsString)>,
}

/// Owned result of a successful exec. Stdin is null; stdout and stderr are
/// available through `child` as pipes. The caller must drain or close them.
#[derive(Debug)]
pub struct SpawnedFd3 {
    pub child: Child,
    /// CLOEXEC parent endpoint, initially blocking with two-second read/write
    /// timeouts. No authentication or framing is implied by this transport.
    pub channel: UnixStream,
}

/// Atomically occupy FD3 if it is unused. An occupied slot returns EBUSY and
/// leaves every existing descriptor unchanged. Only descriptors opened here
/// are closed on failure. Call this before opening other supervisor resources.
pub fn reserve_fd3() -> io::Result<Fd3Reservation> {
    let probe = File::open("/dev/null")?;
    let fd: OwnedFd = if probe.as_raw_fd() == 3 {
        probe.into()
    } else {
        duplicate_at_least(probe.as_fd(), 3)?
    };
    if fd.as_raw_fd() != 3 {
        return Err(io::Error::from_raw_os_error(libc::EBUSY));
    }
    Ok(Fd3Reservation { fd })
}

/// Execute one fresh child with exactly one additional inherited descriptor,
/// FD3. The spec is consumed; no reusable Command or pre_exec hook escapes.
/// Program and cwd must be absolute. Errors before/during exec return no child;
/// there is no fallible setup after Command::spawn succeeds.
pub fn spawn_fd3(slot: &Fd3Reservation, spec: SpawnSpec) -> io::Result<SpawnedFd3> {
    spawn_inner(slot, spec, CloseRange::Kernel)
}

#[derive(Clone, Copy)]
enum CloseRange {
    Kernel,
    #[cfg(test)]
    Fault(i32),
}

fn spawn_inner(
    slot: &Fd3Reservation,
    spec: SpawnSpec,
    close_range: CloseRange,
) -> io::Result<SpawnedFd3> {
    if !spec.program.is_absolute() || !spec.cwd.is_absolute() {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    debug_assert_eq!(slot.fd.as_raw_fd(), 3);
    let (parent, endpoint) = UnixStream::pair()?;
    // Even when inherited stdin/stdout/stderr were closed, our owned socket
    // source must not be overwritten by Command's stdio remapping.
    let parent = above_stdio(parent)?;
    let endpoint = above_stdio(endpoint)?;
    parent.set_read_timeout(Some(Duration::from_secs(2)))?;
    parent.set_write_timeout(Some(Duration::from_secs(2)))?;
    let source = endpoint.as_raw_fd();
    let mut command = Command::new(spec.program);
    command
        .args(spec.args)
        .current_dir(spec.cwd)
        .env_clear()
        .envs(spec.env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: the reservation and source owners outlive synchronous spawn.
    // FD3 cannot be assigned to Rust's exec-error pipe because it is reserved
    // before Command constructs any pipes. The forked child changes only its
    // own descriptor table. The closure uses only syscall operations and
    // allocation-free OS errors; no locks, formatting, procfs or callbacks.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(source, 3) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            match close_range {
                CloseRange::Kernel => {
                    if libc::syscall(
                        libc::SYS_close_range,
                        4u32,
                        u32::MAX,
                        libc::CLOSE_RANGE_CLOEXEC,
                    ) < 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                #[cfg(test)]
                CloseRange::Fault(errno) => return Err(io::Error::from_raw_os_error(errno)),
            }
            Ok(())
        });
    }
    let result = command.spawn();
    // The callback can never outlive the endpoint it names, including errors.
    drop(command);
    drop(endpoint);
    result.map(|child| SpawnedFd3 {
        child,
        channel: parent,
    })
}

fn above_stdio(stream: UnixStream) -> io::Result<UnixStream> {
    if stream.as_raw_fd() >= 4 {
        return Ok(stream);
    }
    duplicate_at_least(stream.as_fd(), 4).map(UnixStream::from)
}

fn duplicate_at_least(fd: BorrowedFd<'_>, minimum: i32) -> io::Result<OwnedFd> {
    // SAFETY: fd remains borrowed and live. F_DUPFD_CLOEXEC returns a fresh
    // independently owned descriptor without replacing any existing one.
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, minimum) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fcntl returned this new descriptor; reconstruct once.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

#[cfg(test)]
mod tests;
