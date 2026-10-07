//! Narrow Linux syscall boundary. No function here constructs cold provenance.
//!
//! Owned descriptors come only from successful syscalls and are immediately
//! transferred to File/OwnedFd. CString arguments outlive each syscall. Filter
//! arrays stay live until the kernel copies them. The feature-only native probe
//! owns its whole single-threaded child lifetime and ends with _exit after it
//! closes unrelated descriptors; it never resumes Rust code holding closed FDs.
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
#[cfg(feature = "native-test-probe")]
use std::os::fd::IntoRawFd;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
#[cfg(any(test, feature = "native-test-probe"))]
use std::path::Path;

pub(crate) fn uids() -> (u32, u32) {
    // SAFETY: getuid/geteuid have no pointer arguments or preconditions.
    unsafe { (libc::getuid(), libc::geteuid()) }
}

fn component(name: &std::ffi::OsStr) -> io::Result<CString> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    CString::new(bytes).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

fn open_at(dir: RawFd, name: &CStr, flags: i32) -> io::Result<File> {
    // SAFETY: name is terminated and live, no creation flags require mode,
    // and a successful returned FD is exclusively owned by this function.
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful openat transferred ownership of this unique FD.
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(crate) fn root() -> io::Result<File> {
    open_at(libc::AT_FDCWD, c"/", libc::O_PATH | libc::O_DIRECTORY)
}

pub(crate) fn directory_at(parent: &File, name: &std::ffi::OsStr) -> io::Result<File> {
    open_at(
        parent.as_raw_fd(),
        &component(name)?,
        libc::O_PATH | libc::O_DIRECTORY,
    )
}

/// O_PATH obtains metadata without granting a readable/writable source FD.
/// The caller must classify symlink/nonregular metadata before accepting it.
pub(crate) fn metadata_at(parent: &File, name: &std::ffi::OsStr) -> io::Result<File> {
    open_at(parent.as_raw_fd(), &component(name)?, libc::O_PATH)
}

#[cfg(test)]
pub(crate) fn fixture_anchor(path: &Path) -> io::Result<File> {
    let name = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    open_at(libc::AT_FDCWD, &name, libc::O_PATH | libc::O_DIRECTORY)
}

#[cfg(target_arch = "x86_64")]
fn statement(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

#[cfg(target_arch = "x86_64")]
fn jump(code: u16, k: u32, yes: u8, no: u8) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: yes,
        jf: no,
        k,
    }
}

/// A restrictive FD-only syscall primitive, not a complete broker seal. It
/// does not establish descriptor provenance, root vault, UID/capability drop,
/// namespace custody or early boot. Installation is irreversible for the child.
#[cfg(target_arch = "x86_64")]
fn install_fd_only_filter(
    #[cfg(feature = "native-test-probe")] mutant_allow_sendmsg: bool,
) -> io::Result<()> {
    const LD_W_ABS: u16 = 0x20;
    const JEQ_K: u16 = 0x15;
    const JSET_K: u16 = 0x45;
    const RET_K: u16 = 0x06;
    const AUDIT_ARCH_X86_64: u32 = 0xc000003e;
    let mut rules = vec![
        statement(LD_W_ABS, 4),
        jump(JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
        statement(RET_K, libc::SECCOMP_RET_KILL_PROCESS),
        statement(LD_W_ABS, 0),
        jump(JSET_K, 0x40000000, 0, 1),
        statement(RET_K, libc::SECCOMP_RET_KILL_PROCESS),
        // For write, seccomp_data.args[0] is at byte 16. Only the fixed
        // diagnostic output FD1 is writable, never the source FD3.
        jump(JEQ_K, libc::SYS_write as u32, 0, 4),
        statement(LD_W_ABS, 16),
        jump(JEQ_K, 1, 0, 1),
        statement(RET_K, libc::SECCOMP_RET_ALLOW),
        statement(RET_K, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
    ];
    for call in [
        libc::SYS_read,
        libc::SYS_pread64,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_fcntl,
        libc::SYS_poll,
        libc::SYS_clock_gettime,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_brk,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mprotect,
        libc::SYS_futex,
        libc::SYS_rt_sigreturn,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ] {
        rules.push(jump(JEQ_K, call as u32, 0, 1));
        rules.push(statement(RET_K, libc::SECCOMP_RET_ALLOW));
    }
    #[cfg(feature = "native-test-probe")]
    if mutant_allow_sendmsg {
        rules.push(jump(JEQ_K, libc::SYS_sendmsg as u32, 0, 1));
        rules.push(statement(RET_K, libc::SECCOMP_RET_ALLOW));
    }
    rules.push(statement(
        RET_K,
        libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
    ));
    let program = libc::sock_fprog {
        len: rules.len() as u16,
        filter: rules.as_mut_ptr(),
    };
    // SAFETY: scalar prctl arguments; then a correctly sized, live kernel BPF
    // program. TSYNC refuses a partial per-thread installation on incompatibility.
    let result = unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            &program as *const libc::sock_fprog,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Feature-only disposable child entry. Never called by the production CLI.
/// The file must be the fixed nonsecret test specimen; no bytes are reported.
#[cfg(all(feature = "native-test-probe", target_arch = "x86_64"))]
pub(crate) fn native_probe(path: &Path, mutant_allow_sendmsg: bool) -> ! {
    const MARKER: &[u8] = b"podbay-r1-private-probe\n";
    fn finish(code: i32) -> ! {
        // SAFETY: terminates this dedicated test child without running drops
        // for descriptors deliberately closed by close_range.
        unsafe { libc::_exit(code) }
    }
    if uids().0 == 0 || uids().1 == 0 {
        finish(90);
    }
    let path = match CString::new(path.as_os_str().as_bytes()) {
        Ok(value) => value,
        Err(_) => finish(91),
    };
    let file = match open_at(libc::AT_FDCWD, &path, libc::O_RDONLY | libc::O_NONBLOCK) {
        Ok(value) => value,
        Err(_) => finish(92),
    };
    let fd = file.into_raw_fd();
    // SAFETY: this dedicated single-threaded child transfers its only owned
    // data File above. It never returns to code owning deliberately closed
    // descriptors; subsequent Rust temporaries own memory only, and every
    // terminal path calls _exit without descriptor destructor unwinding.
    unsafe {
        if fd < 3 || libc::dup2(fd, 257) != 257 {
            finish(93);
        }
        if fd != 3 && libc::dup3(fd, 3, libc::O_CLOEXEC) != 3 {
            finish(93);
        }
        if libc::syscall(libc::SYS_close_range, 4u32, u32::MAX, 0u32) != 0 {
            finish(94);
        }
    }
    if install_fd_only_filter(mutant_allow_sendmsg).is_err() {
        finish(95);
    }
    // SAFETY: bounded stack buffer and live FD3. Invalid syscall arguments below
    // are chosen to have no useful effect even if the filter is accidentally
    // weakened. No exec/fork, network connection or namespace is created.
    unsafe {
        let mut bytes = [0u8; 64];
        if libc::pread(3, bytes.as_mut_ptr().cast(), bytes.len(), 0) != MARKER.len() as isize
            || &bytes[..MARKER.len()] != MARKER
        {
            finish(96);
        }
        if libc::fcntl(257, libc::F_GETFD) != -1
            || io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
        {
            finish(97);
        }
        let opened = libc::openat(libc::AT_FDCWD, path.as_ptr(), libc::O_RDONLY);
        if opened != -1 || io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
            if opened >= 0 {
                libc::close(opened);
            }
            finish(98);
        }
        let socket = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if socket != -1 || io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
            if socket >= 0 {
                libc::close(socket);
            }
            finish(98);
        }
        let denied = |value: libc::c_long| {
            if value != -1 || io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
                finish(98);
            }
        };
        *libc::__errno_location() = 0;
        denied(libc::syscall(
            libc::SYS_sendmsg,
            -1,
            std::ptr::null::<libc::msghdr>(),
            0,
        ));
        *libc::__errno_location() = 0;
        denied(libc::syscall(
            libc::SYS_recvmsg,
            -1,
            std::ptr::null_mut::<libc::msghdr>(),
            0,
        ));
        *libc::__errno_location() = 0;
        denied(libc::syscall(libc::SYS_setns, -1, libc::CLONE_NEWNS));
        *libc::__errno_location() = 0;
        denied(libc::syscall(libc::SYS_pidfd_getfd, -1, 0, 0));
        *libc::__errno_location() = 0;
        denied(libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0));
        *libc::__errno_location() = 0;
        denied(libc::syscall(
            libc::SYS_execve,
            std::ptr::null::<i8>(),
            std::ptr::null::<*const i8>(),
            std::ptr::null::<*const i8>(),
        ));
        // Both write variants must be filtered before the read-only FD check.
        *libc::__errno_location() = 0;
        if libc::write(3, MARKER.as_ptr().cast(), MARKER.len()) != -1
            || io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
        {
            finish(98);
        }
        *libc::__errno_location() = 0;
        if libc::pwrite(3, MARKER.as_ptr().cast(), MARKER.len(), 0) != -1
            || io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
        {
            finish(98);
        }
        let result = b"FD_ONLY_FILTER_OBSERVED_NOT_COLD_ORIGIN\n";
        if libc::write(1, result.as_ptr().cast(), result.len()) != result.len() as isize {
            finish(99);
        }
    }
    finish(0)
}
