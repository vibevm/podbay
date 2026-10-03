use std::fs::File;
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::fd::{AsRawFd, BorrowedFd};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessBirth {
    pub pid: i32,
    pub ppid: u32,
    pub pgid: u32,
    pub start_seconds: u64,
    pub start_microseconds: u64,
}

impl ProcessBirth {
    pub fn identity(self, boot_seconds: i64, boot_microseconds: i64) -> String {
        format!(
            "darwin-start-v1:{boot_seconds}:{boot_microseconds}:{}:{}",
            self.start_seconds, self.start_microseconds
        )
    }
}

/// `proc_pidinfo` writes exactly `proc_bsdinfo` bytes on success. The buffer is
/// zero-initialized; no field is read unless the returned size matches.
pub fn process_birth(pid: i32) -> io::Result<ProcessBirth> {
    if pid <= 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid PID"));
    }
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = i32::try_from(size_of::<libc::proc_bsdinfo>())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "proc info size"))?;
    // SAFETY: buffer is writable for exactly `size` bytes; the result length is
    // checked before `assume_init`, and the struct contains plain C value fields.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if written != size {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: exact-size successful `proc_pidinfo` initialized this zeroed buffer.
    let info = unsafe { info.assume_init() };
    if info.pbi_pid != pid as u32
        || info.pbi_pgid == 0
        || info.pbi_start_tvsec == 0
        || info.pbi_start_tvusec >= 1_000_000
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "process birth evidence malformed",
        ));
    }
    Ok(ProcessBirth {
        pid,
        ppid: info.pbi_ppid,
        pgid: info.pbi_pgid,
        start_seconds: info.pbi_start_tvsec,
        start_microseconds: info.pbi_start_tvusec,
    })
}

pub fn boot_time() -> io::Result<(i64, i64)> {
    let mut value = MaybeUninit::<libc::timeval>::zeroed();
    let mut size = size_of::<libc::timeval>();
    // SAFETY: static NUL-terminated key and writable timeval buffer with exact
    // length; the returned size is checked before reading fields.
    let result = unsafe {
        libc::sysctlbyname(
            c"kern.boottime".as_ptr(),
            value.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 || size != size_of::<libc::timeval>() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful exact-size sysctl initialized the zeroed timeval.
    let value = unsafe { value.assume_init() };
    let microseconds = i64::from(value.tv_usec);
    if value.tv_sec <= 0 || !(0..1_000_000).contains(&microseconds) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "boot time evidence malformed",
        ));
    }
    Ok((value.tv_sec, microseconds))
}

pub fn effective_uid() -> u32 {
    // SAFETY: getuid has no arguments and cannot access caller-provided memory.
    unsafe { libc::geteuid() }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerIdentity {
    pub uid: u32,
    pub gid: u32,
    pub birth: ProcessBirth,
}

pub fn peer_identity(socket: BorrowedFd<'_>) -> io::Result<PeerIdentity> {
    let mut uid = 0;
    let mut gid = 0;
    // SAFETY: both pointers are valid writable uid_t/gid_t locations for the
    // duration of the call on a connected Unix stream socket.
    if unsafe { libc::getpeereid(socket.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut pid: libc::pid_t = 0;
    let mut length = libc::socklen_t::try_from(size_of::<libc::pid_t>())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "peer PID size"))?;
    // SAFETY: `pid` and `length` are valid output buffers of the declared
    // size. SOL_LOCAL/LOCAL_PEERPID is kernel-provided peer identity.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&raw mut pid).cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != size_of::<libc::pid_t>() || pid <= 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerIdentity {
        uid,
        gid,
        birth: process_birth(pid)?,
    })
}

pub fn full_sync(file: &File) -> io::Result<()> {
    file.sync_all()?;
    // SAFETY: fcntl F_FULLFSYNC consumes only this valid open file descriptor.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A process group whose leader is the retained child identity. This token
/// cannot be constructed from a raw PGID. It does not prove that escaped
/// descendants belong to the group.
pub struct AttestedProcessGroup {
    birth: ProcessBirth,
    boot: (i64, i64),
}

pub fn attest_process_group(
    expected: ProcessBirth,
    boot: (i64, i64),
) -> io::Result<AttestedProcessGroup> {
    if expected.pid <= 1
        || expected.pgid != expected.pid as u32
        || boot_time()? != boot
        || process_birth(expected.pid)? != expected
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "process group leader identity changed",
        ));
    }
    Ok(AttestedProcessGroup {
        birth: expected,
        boot,
    })
}

impl AttestedProcessGroup {
    pub fn signal(&self, signal: i32) -> io::Result<()> {
        if boot_time()? != self.boot || process_birth(self.birth.pid)? != self.birth {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "process group leader identity changed",
            ));
        }
        // SAFETY: scalar PGID is the re-attested leader PID. Darwin has no
        // atomic birth-checked group signal here; callers must treat stop as
        // uncertain and never claim complete tree coverage.
        if unsafe { libc::killpg(self.birth.pid, signal) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
