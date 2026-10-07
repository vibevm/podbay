//! Linux owned-descriptor boundary for the separately scoped appliance reader.
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub fn root_identity() -> bool {
    unsafe {
        libc::getuid() == 0 && libc::geteuid() == 0 && libc::getgid() == 0 && libc::getegid() == 0
    }
}
pub fn pid() -> u32 {
    unsafe { libc::getpid() as u32 }
}
pub fn parent() -> u32 {
    unsafe { libc::getppid() as u32 }
}
fn error() -> io::Error {
    io::Error::last_os_error()
}
fn owned(fd: RawFd) -> io::Result<OwnedFd> {
    if fd < 0 {
        Err(error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}
pub fn open(path: &Path, flags: i32) -> io::Result<OwnedFd> {
    use std::os::unix::ffi::OsStrExt;
    let s = CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::other("NUL path"))?;
    owned(unsafe { libc::open(s.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) })
}
pub fn open_at(parent: RawFd, name: &CStr, flags: i32) -> io::Result<OwnedFd> {
    owned(unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })
}
pub fn create_attempt(parent: RawFd) -> io::Result<File> {
    let fd = owned(unsafe {
        libc::openat(
            parent,
            c"attempt".as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    })?;
    Ok(File::from(fd))
}
pub fn flock_exclusive(fd: RawFd) -> io::Result<()> {
    if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        Err(error())
    } else {
        Ok(())
    }
}
pub fn flags(fd: RawFd) -> io::Result<i32> {
    let n = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if n < 0 { Err(error()) } else { Ok(n) }
}
pub fn stat(fd: RawFd) -> io::Result<libc::stat> {
    let mut s = std::mem::MaybeUninit::uninit();
    if unsafe { libc::fstat(fd, s.as_mut_ptr()) } != 0 {
        Err(error())
    } else {
        Ok(unsafe { s.assume_init() })
    }
}
pub fn random() -> io::Result<[u8; 32]> {
    let mut n = [0; 32];
    let mut at = 0;
    while at < n.len() {
        let r = unsafe { libc::getrandom(n[at..].as_mut_ptr().cast(), n.len() - at, 0) };
        if r < 0 {
            return Err(error());
        }
        if r == 0 {
            return Err(io::Error::other("entropy short read"));
        }
        at += r as usize;
    }
    Ok(n)
}
pub fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut pair = [-1; 2];
    if unsafe { libc::pipe2(pair.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(error());
    }
    Ok((owned(pair[0])?, owned(pair[1])?))
}
pub fn pidfd(pid: u32) -> io::Result<OwnedFd> {
    owned(unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 })
}
pub fn exited(fd: RawFd) -> io::Result<bool> {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let n = unsafe { libc::poll(&mut p, 1, 0) };
    if n < 0 {
        return Err(error());
    }
    Ok(n > 0)
}
pub fn read_exact(fd: RawFd, out: &mut [u8], parent_fd: Option<RawFd>) -> io::Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut at = 0;
    while at < out.len() {
        if parent_fd.is_some_and(|p| exited(p).unwrap_or(true)) {
            return Err(io::Error::other("keeper lost"));
        }
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::other("pipe deadline"));
        }
        let mut p = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut p, 1, 100) };
        if n < 0 {
            if error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error());
        }
        if n == 0 {
            continue;
        }
        let n = unsafe { libc::read(fd, out[at..].as_mut_ptr().cast(), out.len() - at) };
        if n <= 0 {
            return Err(io::Error::other("pipe closed/failed"));
        }
        at += n as usize;
    }
    Ok(())
}
pub fn write_all(fd: RawFd, bytes: &[u8]) -> io::Result<()> {
    let mut at = 0;
    while at < bytes.len() {
        let n = unsafe { libc::write(fd, bytes[at..].as_ptr().cast(), bytes.len() - at) };
        if n <= 0 {
            return Err(error());
        }
        at += n as usize;
    }
    Ok(())
}
pub fn pread(fd: RawFd, out: &mut [u8], offset: u64) -> io::Result<usize> {
    let n = unsafe {
        libc::pread(
            fd,
            out.as_mut_ptr().cast(),
            out.len(),
            offset as libc::off_t,
        )
    };
    if n < 0 { Err(error()) } else { Ok(n as usize) }
}
pub fn metadata(fd: &OwnedFd) -> io::Result<std::fs::Metadata> {
    File::from(fd.try_clone()?).metadata()
}
pub fn same(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.mode() == b.mode()
        && a.nlink() == b.nlink()
}
pub fn finish(code: i32) -> ! {
    unsafe { libc::_exit(code) }
}
pub fn require_empty_live_pipe(fd: RawFd) -> io::Result<()> {
    let mut p=libc::pollfd {fd,events:libc::POLLIN,revents:0};
    let n=unsafe {libc::poll(&mut p,1,0)};
    if n<0 { return Err(error()); }
    if n!=0 { return Err(io::Error::other("surplus frame or lost pipe peer")); }
    Ok(())
}

pub struct Child {
    pub pid: u32,
    pub pidfd: OwnedFd,
    reaped: bool,
}
impl Child {
    pub fn kill_reap(&mut self) -> io::Result<()> {
        if self.reaped {
            return Ok(());
        }
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            );
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let mut status = 0;
            let r = unsafe { libc::waitpid(self.pid as i32, &mut status, libc::WNOHANG) };
            if r == self.pid as i32 {
                break;
            }
            if r < 0 && error().kind() != io::ErrorKind::Interrupted {
                return Err(error());
            }
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::other("exact child reap deadline"));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        self.reaped = true;
        Ok(())
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        if self.kill_reap().is_err() {
            // Unknown holder teardown must retain the caller's stack resources,
            // including its lock. The bounded VM supervisor will fail this run.
            loop { std::thread::park(); }
        }
    }
}
/// Only raw scalar/descriptor syscalls run between fork and fixed exec.
pub fn spawn_custodian(mapping: [RawFd; 6]) -> io::Result<Child> {
    let p = unsafe { libc::fork() };
    if p < 0 {
        return Err(error());
    }
    if p == 0 {
        unsafe {
            let mut high = [-1; 6];
            for i in 0..6 {
                high[i] = libc::fcntl(mapping[i], libc::F_DUPFD_CLOEXEC, 64);
                if high[i] < 0 {
                    libc::_exit(120);
                }
            }
            for i in 0..6 {
                if libc::dup2(high[i], i as i32) < 0 {
                    libc::_exit(121);
                }
            }
            if libc::syscall(libc::SYS_close_range, 6u32, u32::MAX, 0) != 0 {
                libc::_exit(122);
            }
            let program = c"/usr/local/libexec/podbay-r1-appliance-custodian";
            let argv = [program.as_ptr(), std::ptr::null()];
            let env = [
                c"PATH=/usr/bin:/bin".as_ptr(),
                c"LANG=C".as_ptr(),
                std::ptr::null(),
            ];
            libc::execve(program.as_ptr(), argv.as_ptr(), env.as_ptr());
            libc::_exit(126);
        }
    }
    match pidfd(p as u32) {
        Ok(fd) => Ok(Child {
            pid: p as u32,
            pidfd: fd,
            reaped: false,
        }),
        Err(e) => {
            unsafe {
                libc::kill(p, libc::SIGKILL);
                libc::waitpid(p, std::ptr::null_mut(), 0);
            }
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real_pipe_suffix_and_peer_loss_refuse() {
        let (r,w)=pipe().unwrap();
        write_all(w.as_raw_fd(),b"frame!").unwrap();
        let mut b=[0;5];read_exact(r.as_raw_fd(),&mut b,None).unwrap();
        assert_eq!(&b,b"frame");
        assert!(require_empty_live_pipe(r.as_raw_fd()).is_err());
        let mut suffix=[0;1];read_exact(r.as_raw_fd(),&mut suffix,None).unwrap();
        require_empty_live_pipe(r.as_raw_fd()).unwrap();
        drop(w);assert!(require_empty_live_pipe(r.as_raw_fd()).is_err());
    }
    #[test]
    fn transfer_controls_create_real_rights_and_mapping_then_drop() {
        assert!(!root_identity());
        let path=std::env::temp_dir().join(format!("r1-transfer-{}",pid()));
        std::fs::write(&path,[0u8;4096]).unwrap();
        let source=open(&path,libc::O_RDONLY).unwrap();
        let controls=transfer_controls(source.as_raw_fd()).unwrap();
        assert!(flags(257).is_ok());assert!(flags(258).is_ok());
        assert!(verify_clean_exec_mapping().is_err());
        drop(controls);
        assert_eq!(flags(257).unwrap_err().raw_os_error(),Some(libc::EBADF));
        assert_eq!(flags(258).unwrap_err().raw_os_error(),Some(libc::EBADF));
        verify_clean_exec_mapping().unwrap();
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn attempt_is_no_replace_and_survives_handle_loss() {
        assert!(!root_identity());
        let path = std::env::temp_dir().join(format!("r1-attempt-{}", pid()));
        std::fs::create_dir(&path).unwrap();
        let dir = open(&path, libc::O_PATH | libc::O_DIRECTORY).unwrap();
        let first = create_attempt(dir.as_raw_fd()).unwrap();
        let inode = first.metadata().unwrap().ino();
        assert_eq!(create_attempt(dir.as_raw_fd()).unwrap_err().raw_os_error(), Some(libc::EEXIST));
        drop(first);
        assert_eq!(create_attempt(dir.as_raw_fd()).unwrap_err().raw_os_error(), Some(libc::EEXIST));
        assert_eq!(std::fs::metadata(path.join("attempt")).unwrap().ino(), inode);
        std::fs::remove_file(path.join("attempt")).unwrap();
        std::fs::remove_dir(path).unwrap();
    }
    #[test]
    fn readonly_flock_is_real_and_contended() {
        assert!(!root_identity());
        let path = std::env::temp_dir().join(format!("r1-ro-lock-{}", pid()));
        std::fs::write(&path, b"").unwrap();
        let a = open(&path, libc::O_RDONLY).unwrap();
        let b = open(&path, libc::O_RDONLY).unwrap();
        assert_eq!(
            flags(a.as_raw_fd()).unwrap() & libc::O_ACCMODE,
            libc::O_RDONLY
        );
        flock_exclusive(a.as_raw_fd()).unwrap();
        assert_eq!(
            flock_exclusive(b.as_raw_fd()).unwrap_err().raw_os_error(),
            Some(libc::EWOULDBLOCK)
        );
        drop(a);
        flock_exclusive(b.as_raw_fd()).unwrap();
        drop(b);
        std::fs::remove_file(path).unwrap();
    }
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}
pub fn seal_identity(empty: &CStr) -> io::Result<()> {
    if !root_identity() {
        return Err(io::Error::other("root setup required"));
    }
    // Appliance policy explicitly requires nondumpable set-ID transitions.
    if std::fs::read_to_string("/proc/sys/fs/suid_dumpable")?.trim() != "0" {
        return Err(io::Error::other("unsafe set-ID dumpability policy"));
    }
    let last: u32 = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")?
        .trim()
        .parse()
        .map_err(|_| io::Error::other("cap range"))?;
    if last > 63 {
        return Err(io::Error::other("unsupported capability range"));
    }
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
            || libc::unshare(libc::CLONE_NEWNS) != 0
            || libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            ) != 0
            || libc::chroot(empty.as_ptr()) != 0
            || libc::chdir(c"/".as_ptr()) != 0
        {
            return Err(error());
        }
        for cap in 0..=last {
            if libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 {
                return Err(error());
            }
        }
        if libc::setgroups(0, std::ptr::null()) != 0
            || libc::setresgid(1000, 1000, 1000) != 0
            || libc::setresuid(1000, 1000, 1000) != 0
            || libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
            || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
        {
            return Err(error());
        }
        let header = CapHeader {
            version: 0x20080522,
            pid: 0,
        };
        let zero = [CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        if libc::syscall(libc::SYS_capset, &header as *const CapHeader, zero.as_ptr()) != 0 {
            return Err(error());
        }
        let mut actual = zero;
        if libc::syscall(
            libc::SYS_capget,
            &header as *const CapHeader,
            actual.as_mut_ptr(),
        ) != 0
            || actual
                .iter()
                .any(|c| c.effective != 0 || c.permitted != 0 || c.inheritable != 0)
            || libc::getuid() != 1000
            || libc::geteuid() != 1000
            || libc::getgid() != 1000
            || libc::getegid() != 1000
            || libc::getgroups(0, std::ptr::null_mut()) != 0
            || libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) != 0
            || libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1
        {
            return Err(io::Error::other("identity seal differs"));
        }
        for cap in 0..=last {
            if libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) != 0 {
                return Err(io::Error::other("bounding capability remains"));
            }
        }
    }
    Ok(())
}
#[cfg(target_arch = "x86_64")]
pub fn install_reader_filter() -> io::Result<()> {
    fn stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }
    fn eq(k: u32, yes: u8, no: u8) -> libc::sock_filter {
        libc::sock_filter {
            code: 0x15,
            jt: yes,
            jf: no,
            k,
        }
    }
    const LD: u16 = 0x20;
    const RET: u16 = 0x06;
    const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
    const DENY: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    let mut rules = vec![
        stmt(LD, 4),
        eq(0xc000003e, 1, 0),
        stmt(RET, libc::SECCOMP_RET_KILL_PROCESS),
        stmt(LD, 0),
        libc::sock_filter {
            code: 0x45,
            jt: 0,
            jf: 1,
            k: 0x40000000,
        },
        stmt(RET, libc::SECCOMP_RET_KILL_PROCESS),
    ];
    // A matched block always returns. An unmatched syscall keeps nr loaded.
    for (call, fd) in [
        (libc::SYS_read, 4),
        (libc::SYS_pread64, 3),
        (libc::SYS_write, 1),
    ] {
        rules.extend([
            eq(call as u32, 0, 4),
            stmt(LD, 16),
            eq(fd, 1, 0),
            stmt(RET, DENY),
            stmt(RET, ALLOW),
        ]);
    }
    rules.extend([
        eq(libc::SYS_fcntl as u32, 0, 5),
        stmt(LD, 24),
        eq(libc::F_GETFD as u32, 2, 0),
        eq(libc::F_GETFL as u32, 1, 0),
        stmt(RET, DENY),
        stmt(RET, ALLOW),
    ]);
    // Memory allocation remains anonymous/non-executable; source-backed mmap
    // is denied even though FD3 is read-only. No generic writable-FD policy.
    rules.extend([
        eq(libc::SYS_mmap as u32, 0, 8),
        stmt(LD, 32),
        libc::sock_filter {
            code: 0x45,
            jt: 0,
            jf: 1,
            k: !(libc::PROT_READ | libc::PROT_WRITE) as u32,
        },
        stmt(RET, DENY),
        stmt(LD, 40),
        stmt(
            0x54,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_SHARED) as u32,
        ),
        eq((libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u32, 1, 0),
        stmt(RET, DENY),
        stmt(RET, ALLOW),
    ]);
    rules.extend([
        eq(libc::SYS_mprotect as u32, 0, 4),
        stmt(LD, 32),
        libc::sock_filter {
            code: 0x45,
            jt: 0,
            jf: 1,
            k: !(libc::PROT_READ | libc::PROT_WRITE) as u32,
        },
        stmt(RET, DENY),
        stmt(RET, ALLOW),
    ]);
    for call in [
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_poll,
        libc::SYS_clock_gettime,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_gettid,
        libc::SYS_brk,
        libc::SYS_munmap,
        libc::SYS_futex,
        libc::SYS_rt_sigreturn,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ] {
        rules.extend([eq(call as u32, 0, 1), stmt(RET, ALLOW)]);
    }
    rules.push(stmt(RET, DENY));
    let program = libc::sock_fprog {
        len: rules.len() as u16,
        filter: rules.as_mut_ptr(),
    };
    if unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            &program as *const libc::sock_fprog,
        )
    } != 0
    {
        return Err(error());
    }
    Ok(())
}
#[cfg(not(target_arch = "x86_64"))]
pub fn install_reader_filter() -> io::Result<()> {
    Err(io::Error::other("x86_64 reader profile only"))
}

pub fn reader_denial_controls() -> io::Result<()> {
    fn denied(value: libc::c_long) -> io::Result<()> {
        if value != -1 || io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
            Err(io::Error::other("seal denial differs"))
        } else {
            Ok(())
        }
    }
    unsafe {
        if libc::fcntl(258, libc::F_GETFD) != -1
            || error().raw_os_error() != Some(libc::EBADF)
            || libc::fcntl(257, libc::F_GETFD) != -1
            || error().raw_os_error() != Some(libc::EBADF)
        {
            return Err(io::Error::other("high descriptor survived"));
        }
        denied(libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            c"/state/db.sqlite".as_ptr(),
            libc::O_RDONLY,
        ))?;
        denied(libc::syscall(
            libc::SYS_socket,
            libc::AF_UNIX,
            libc::SOCK_STREAM,
            0,
        ))?;
        denied(libc::syscall(
            libc::SYS_sendmsg,
            -1,
            std::ptr::null::<libc::msghdr>(),
            0,
        ))?;
        denied(libc::syscall(
            libc::SYS_recvmsg,
            -1,
            std::ptr::null_mut::<libc::msghdr>(),
            0,
        ))?;
        denied(libc::syscall(libc::SYS_pidfd_getfd, 5, 3, 0))?;
        denied(libc::syscall(
            libc::SYS_pidfd_send_signal,
            5,
            0,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        ))?;
        denied(libc::syscall(libc::SYS_setns, -1, libc::CLONE_NEWNS))?;
        denied(libc::syscall(libc::SYS_unshare, libc::CLONE_NEWNS))?;
        denied(libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0))?;
        denied(libc::syscall(
            libc::SYS_execve,
            std::ptr::null::<i8>(),
            std::ptr::null::<*const i8>(),
            std::ptr::null::<*const i8>(),
        ))?;
        denied(libc::syscall(libc::SYS_write, 3, c"x".as_ptr(), 1))?;
        denied(libc::syscall(libc::SYS_pwrite64, 3, c"x".as_ptr(), 1, 0))?;
        denied(libc::syscall(libc::SYS_fcntl, 3, libc::F_DUPFD_CLOEXEC, 64))?;
        let mapped = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            3,
            0,
        );
        if mapped != libc::MAP_FAILED || error().raw_os_error() != Some(libc::EPERM) {
            if mapped != libc::MAP_FAILED {
                libc::munmap(mapped, 4096);
            }
            return Err(io::Error::other("source mmap not denied"));
        }
        let mapped = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            3,
            0,
        );
        if mapped != libc::MAP_FAILED || error().raw_os_error() != Some(libc::EPERM) {
            if mapped != libc::MAP_FAILED {
                libc::munmap(mapped, 4096);
            }
            return Err(io::Error::other("shared source mmap not denied"));
        }
    }
    Ok(())
}

pub fn wait_keeper_loss(parent_fd: RawFd, command_fd: RawFd) -> io::Result<()> {
    loop {
        let mut fds = [
            libc::pollfd {
                fd: parent_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: command_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, 100) };
        if n < 0 {
            if error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error());
        }
        if fds[0].revents != 0 || fds[1].revents & libc::POLLHUP != 0 {
            return Ok(());
        }
        if fds[1].revents != 0 {
            return Err(io::Error::other("unexpected command or pipe error"));
        }
    }
}

pub fn check_fd_allowlist(maximum: RawFd) -> io::Result<()> {
    let fd = open(
        Path::new("/proc/self/fd"),
        libc::O_RDONLY | libc::O_DIRECTORY,
    )?;
    let own = fd.as_raw_fd();
    let mut buffer = [0u8; 4096];
    loop {
        let n =
            unsafe { libc::syscall(libc::SYS_getdents64, own, buffer.as_mut_ptr(), buffer.len()) };
        if n < 0 {
            return Err(error());
        }
        if n == 0 {
            return Ok(());
        }
        let mut at = 0;
        while at < n as usize {
            if at + 19 > n as usize {
                return Err(io::Error::other("fd listing truncated"));
            }
            let size = u16::from_ne_bytes([buffer[at + 16], buffer[at + 17]]) as usize;
            if size < 20 || at + size > n as usize {
                return Err(io::Error::other("fd listing bounds"));
            }
            let raw = &buffer[at + 19..at + size];
            let end = raw
                .iter()
                .position(|b| *b == 0)
                .ok_or_else(|| io::Error::other("fd listing name"))?;
            let name = std::str::from_utf8(&raw[..end])
                .map_err(|_| io::Error::other("fd listing ascii"))?;
            if name != "." && name != ".." {
                let number: i32 = name
                    .parse()
                    .map_err(|_| io::Error::other("fd listing number"))?;
                if number > maximum && number != own {
                    return Err(io::Error::other("unexpected inherited descriptor"));
                }
            }
            at += size;
        }
    }
}
pub fn readonly_fixture() -> io::Result<()> {
    let mut v = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(c"/fixture".as_ptr(), v.as_mut_ptr()) } != 0 {
        return Err(error());
    }
    if unsafe { v.assume_init() }.f_flag & libc::ST_RDONLY == 0 {
        return Err(io::Error::other("fixture not readonly"));
    }
    Ok(())
}

pub const MAPPING_CONTROL_ADDRESS: usize = 0x5000_0000_0000;
pub struct TransferControls {
    _high_source: OwnedFd,
    _high_queue: OwnedFd,
    _sender: OwnedFd,
    _receiver: OwnedFd,
    mapped: bool,
}
impl Drop for TransferControls {
    fn drop(&mut self) {
        if self.mapped {
            unsafe {
                libc::munmap(MAPPING_CONTROL_ADDRESS as *mut libc::c_void, 4096);
            }
        }
    }
}
/// Actual valid source mapping and queued SCM_RIGHTS are installed only inside
/// the already-accepted trusted setup, then removed from the final FD/map set.
pub fn transfer_controls(source: RawFd) -> io::Result<TransferControls> {
    unsafe {
        let high = owned(libc::fcntl(source, libc::F_DUPFD, 257))?;
        if high.as_raw_fd() != 257 {
            return Err(io::Error::other("control FD collision"));
        }
        let mut pair = [-1; 2];
        if libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        ) != 0
        {
            return Err(error());
        }
        let sender = owned(pair[0])?;
        let receiver = owned(pair[1])?;
        let queued = owned(libc::fcntl(receiver.as_raw_fd(), libc::F_DUPFD, 258))?;
        if queued.as_raw_fd() != 258 {
            return Err(io::Error::other("queue FD collision"));
        }
        let mut byte = b'x';
        let mut iov = libc::iovec {
            iov_base: (&mut byte as *mut u8).cast(),
            iov_len: 1,
        };
        let mut control = [0usize; 8];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(4) as usize;
        let c = libc::CMSG_FIRSTHDR(&msg);
        if c.is_null() {
            return Err(io::Error::other("rights header"));
        }
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(4) as usize;
        *libc::CMSG_DATA(c).cast::<i32>() = source;
        if libc::sendmsg(sender.as_raw_fd(), &msg, 0) != 1 {
            return Err(error());
        }
        control.fill(0);
        msg.msg_controllen = std::mem::size_of_val(&control);
        msg.msg_flags = 0;
        if libc::recvmsg(
            receiver.as_raw_fd(),
            &mut msg,
            libc::MSG_PEEK | libc::MSG_CMSG_CLOEXEC,
        ) != 1
            || msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        {
            return Err(io::Error::other("rights peek"));
        }
        let c = libc::CMSG_FIRSTHDR(&msg);
        if c.is_null()
            || (*c).cmsg_level != libc::SOL_SOCKET
            || (*c).cmsg_type != libc::SCM_RIGHTS
            || (*c).cmsg_len != libc::CMSG_LEN(4) as usize
        {
            return Err(io::Error::other("rights control mismatch"));
        }
        let peek = owned(*libc::CMSG_DATA(c).cast::<i32>())?;
        let expected = stat(source)?;
        let actual = stat(peek.as_raw_fd())?;
        if actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino {
            return Err(io::Error::other("rights wrong subject"));
        }
        drop(peek);
        let mapped = libc::mmap(
            MAPPING_CONTROL_ADDRESS as *mut libc::c_void,
            4096,
            libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_FIXED_NOREPLACE,
            source,
            0,
        );
        if mapped != MAPPING_CONTROL_ADDRESS as *mut libc::c_void {
            if mapped != libc::MAP_FAILED {
                libc::munmap(mapped, 4096);
            }
            return Err(error());
        }
        Ok(TransferControls {
            _high_source: high,
            _high_queue: queued,
            _sender: sender,
            _receiver: receiver,
            mapped: true,
        })
    }
}
pub fn verify_clean_exec_mapping() -> io::Result<()> {
    let mut vector = 0u8;
    let result = unsafe {
        libc::mincore(
            MAPPING_CONTROL_ADDRESS as *mut libc::c_void,
            4096,
            &mut vector,
        )
    };
    if result != -1 || error().raw_os_error() != Some(libc::ENOMEM) {
        return Err(io::Error::other("inherited source mapping survived exec"));
    }
    Ok(())
}
