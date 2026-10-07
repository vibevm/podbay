//! Positive resources are scoped to one accepted closed appliance. No generic
//! ColdOriginPermit, migration authority or systemd readiness is produced.
use crate::{appliance_protocol as wire, appliance_sys as sys};
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const SOURCE: &str = "/fixture/vault/state/db.sqlite";
const LOCK: &str = "/fixture/vault/state/db.sqlite.manager.lock";
const KEEPER: &str = "/usr/local/libexec/podbay-r1-appliance-keeper";
const CUSTODIAN: &str = "/usr/local/libexec/podbay-r1-appliance-custodian";
const GROUP: &str = "0::/system.slice/r1-appliance-keeper.service\n";
fn refuse(reason: &'static str) -> io::Error {
    io::Error::other(reason)
}
fn fixed_file(path: &str, uid: u32, mode: u32) -> io::Result<(OwnedFd, Metadata)> {
    let components = path
        .strip_prefix('/')
        .ok_or_else(|| refuse("absolute artifact path"))?
        .split('/')
        .collect::<Vec<_>>();
    if components
        .iter()
        .any(|p| p.is_empty() || *p == "." || *p == "..")
    {
        return Err(refuse("artifact traversal"));
    }
    let mut parent = sys::open(Path::new("/"), libc::O_PATH | libc::O_DIRECTORY)?;
    for component in &components[..components.len() - 1] {
        let name = std::ffi::CString::new(*component).map_err(|_| refuse("artifact component"))?;
        parent = sys::open_at(parent.as_raw_fd(), &name, libc::O_PATH | libc::O_DIRECTORY)?;
        let m = sys::metadata(&parent)?;
        if !m.is_dir() || m.uid() != 0 || m.gid() != 0 || m.mode() & 0o022 != 0 {
            return Err(refuse("artifact ancestor"));
        }
    }
    let name = std::ffi::CString::new(*components.last().unwrap())
        .map_err(|_| refuse("artifact component"))?;
    let fd = sys::open_at(parent.as_raw_fd(), &name, libc::O_RDONLY)?;
    let m = sys::metadata(&fd)?;
    if !m.is_file()
        || m.uid() != uid
        || m.gid() != uid
        || m.mode() & 0o7777 != mode
        || m.nlink() != 1
    {
        return Err(refuse("fixed file policy"));
    }
    Ok((fd, m))
}
fn bytes(path: &str, uid: u32, mode: u32, limit: u64) -> io::Result<Vec<u8>> {
    let (fd, before) = fixed_file(path, uid, mode)?;
    if before.len() > limit {
        return Err(refuse("file bound"));
    }
    let mut data = Vec::new();
    File::from(fd.try_clone()?)
        .take(limit + 1)
        .read_to_end(&mut data)?;
    let after = sys::metadata(&fd)?;
    if data.len() as u64 != before.len()
        || !sys::same(&before, &after)
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(refuse("captured bytes changed"));
    }
    Ok(data)
}
fn artifact(path: &str, expected: [u8; 32]) -> io::Result<()> {
    let data = bytes(path, 0, 0o755, 64 * 1024 * 1024)?;
    if <[u8; 32]>::from(Sha256::digest(&data)) != expected {
        return Err(refuse("artifact differs"));
    }
    Ok(())
}
struct Pins {
    generation: [u8; 32],
    keeper: [u8; 32],
    custodian: [u8; 32],
    systemd: [u8; 32],
    source: [u8; 32],
    size: u64,
    source_inode: u64,
    lock_inode: u64,
}
impl Pins {
    fn load() -> io::Result<Self> {
        let raw = bytes("/etc/r1-appliance/pins", 0, 0o600, 2048)?;
        let text = std::str::from_utf8(&raw).map_err(|_| refuse("pins encoding"))?;
        let keys = [
            "generation",
            "keeper_sha256",
            "custodian_sha256",
            "systemd_sha256",
            "source_sha256",
            "source_bytes",
            "source_inode",
            "lock_inode",
        ];
        let lines = text.split_terminator('\n').collect::<Vec<_>>();
        if !text.ends_with('\n') || lines.len() != keys.len() {
            return Err(refuse("pins shape"));
        }
        let mut values = Vec::new();
        for (line, key) in lines.iter().zip(keys) {
            let (k, v) = line.split_once('=').ok_or_else(|| refuse("pins field"))?;
            if k != key {
                return Err(refuse("pins key"));
            }
            values.push(v);
        }
        let digest = |i: usize| wire::digest(values[i]).ok_or_else(|| refuse("pins digest"));
        let number = |i: usize| -> io::Result<u64> {
            if values[i].is_empty()
                || values[i].starts_with('0')
                || !values[i].bytes().all(|b| b.is_ascii_digit())
            {
                return Err(refuse("pins integer"));
            }
            values[i].parse().map_err(|_| refuse("pins integer"))
        };
        let p = Self {
            generation: digest(0)?,
            keeper: digest(1)?,
            custodian: digest(2)?,
            systemd: digest(3)?,
            source: digest(4)?,
            size: number(5)?,
            source_inode: number(6)?,
            lock_inode: number(7)?,
        };
        if p.size > 64 * 1024 * 1024 || p.source_inode == p.lock_inode {
            return Err(refuse("pins subject"));
        }
        Ok(p)
    }
}
fn boot() -> io::Result<String> {
    let v = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let x = v.trim();
    if x.len() != 36
        || !x.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
    {
        return Err(refuse("boot identity"));
    }
    Ok(x.to_owned())
}
fn birth(pid: u32) -> io::Result<u64> {
    let t = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    t.rsplit_once(") ")
        .and_then(|(_, s)| s.split_whitespace().nth(19))
        .and_then(|x| x.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .ok_or_else(|| refuse("process birth"))
}
fn image_inventory() -> io::Result<()> {
    // Hashes describe this reviewed image. They are not a serialized boot grant.
    let raw = bytes("/etc/r1-appliance/image-files", 0, 0o600, 65536)?;
    let text = std::str::from_utf8(&raw).map_err(|_| refuse("inventory encoding"))?;
    let mut declared = std::collections::BTreeSet::new();
    for line in text.lines() {
        let (hash, path) = line
            .split_once("  ")
            .ok_or_else(|| refuse("inventory line"))?;
        let expected = wire::digest(hash).ok_or_else(|| refuse("inventory digest"))?;
        if !(path == "/init"
            || path.starts_with("/usr/")
            || path.starts_with("/bin/")
            || path.starts_with("/lib64/")
            || path.starts_with("/etc/systemd/"))
            || path.contains("..")
            || !declared.insert(path.to_string())
        {
            return Err(refuse("inventory path"));
        }
        let m = std::fs::symlink_metadata(path)?;
        if !m.is_file() || m.uid() != 0 || m.gid() != 0 || m.mode() & 0o022 != 0 || m.nlink() != 1 {
            return Err(refuse("inventory metadata"));
        }
        let (fd, _) = fixed_file(path, 0, m.mode() & 0o7777)?;
        let mut file = File::from(fd);
        let mut data = Vec::new();
        Read::by_ref(&mut file)
            .take(64 * 1024 * 1024 + 1)
            .read_to_end(&mut data)?;
        if data.len() > 64 * 1024 * 1024 || <[u8; 32]>::from(Sha256::digest(data)) != expected {
            return Err(refuse("inventory bytes"));
        }
    }
    fn walk(path: &Path, out: &mut std::collections::BTreeSet<String>) -> io::Result<()> {
        for e in std::fs::read_dir(path)? {
            let e = e?;
            let m = e.file_type()?;
            if m.is_dir() {
                walk(&e.path(), out)?;
            } else if m.is_file() {
                out.insert(e.path().to_string_lossy().into_owned());
            } else {
                return Err(refuse("unreviewed image entry"));
            }
        }
        Ok(())
    }
    let mut actual = std::collections::BTreeSet::new();
    for path in ["/usr", "/bin", "/lib64", "/etc/systemd"] {
        walk(Path::new(path), &mut actual)?;
    }
    let expected = declared
        .into_iter()
        .filter(|p| {
            p.starts_with("/usr/") || p.starts_with("/bin/") || p.starts_with("/lib64/") || p.starts_with("/etc/systemd/")
        })
        .collect();
    if actual != expected {
        return Err(refuse("unreviewed executable/unit closure"));
    }
    Ok(())
}
fn named_dirs() -> io::Result<Vec<OwnedFd>> {
    let root = sys::open(Path::new("/"), libc::O_PATH | libc::O_DIRECTORY)?;
    let mut held = vec![root];
    for (name, uid, mode) in [
        (c"fixture", 0, 0o700),
        (c"vault", 0, 0o700),
        (c"state", 1000, 0o700),
    ] {
        let fd = sys::open_at(
            held.last().unwrap().as_raw_fd(),
            name,
            libc::O_PATH | libc::O_DIRECTORY,
        )?;
        let m = sys::metadata(&fd)?;
        if !m.is_dir() || m.uid() != uid || m.gid() != uid || m.mode() & 0o7777 != mode {
            return Err(refuse("directory policy"));
        }
        held.push(fd);
    }
    Ok(held)
}
fn recheck_subject(dirs: &[OwnedFd], lock: &OwnedFd, source: Option<&OwnedFd>) -> io::Result<()> {
    let current = named_dirs()?;
    if current.len()!=dirs.len() { return Err(refuse("directory chain length")); }
    let device = sys::metadata(&dirs[1])?.dev();
    for (i,(old,new)) in dirs.iter().zip(current.iter()).enumerate() {
        let a=sys::metadata(old)?;
        let b=sys::metadata(new)?;
        if !sys::same(&a,&b) || (i>0 && a.dev()!=device) { return Err(refuse("directory replaced or foreign nested mount")); }
    }
    let state=dirs.last().unwrap().as_raw_fd();
    for (name,held) in [(c"db.sqlite.manager.lock",Some(lock)),(c"db.sqlite",source)] {
        if let Some(held)=held {
            let named=sys::open_at(state,name,libc::O_PATH)?;
            let a=sys::metadata(held)?;
            if a.dev()!=device || !sys::same(&a,&sys::metadata(&named)?) {return Err(refuse("leaf replaced or foreign device"));}
        }
    }
    no_companions(state)?;
    Ok(())
}
fn subject(file: &OwnedFd, p: &Pins, lock: bool) -> io::Result<wire::Subject> {
    let m = sys::metadata(file)?;
    if !m.is_file()
        || m.uid() != 1000
        || m.gid() != 1000
        || m.mode() & 0o7777 != 0o600
        || m.nlink() != 1
        || m.ino() != if lock { p.lock_inode } else { p.source_inode }
        || m.len() != if lock { 0 } else { p.size }
        || sys::flags(file.as_raw_fd())? & libc::O_ACCMODE != libc::O_RDONLY
    {
        return Err(refuse("source/lock policy"));
    }
    Ok(wire::Subject {
        device: m.dev(),
        inode: m.ino(),
        size: m.len(),
    })
}
fn no_companions(dir: RawFdAlias) -> io::Result<()> {
    for n in [
        c"stage.sqlite",
        c"db.sqlite-wal",
        c"db.sqlite-shm",
        c"db.sqlite-journal",
    ] {
        match sys::open_at(dir, n, libc::O_PATH) {
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => (),
            _ => return Err(refuse("source companion present/unknown")),
        }
    }
    Ok(())
}
type RawFdAlias = i32;

/// A live owned resource, not a generic origin/Store/Owner admission token.
struct ReadCustody {
    _attempt: File,
    _directories: Vec<OwnedFd>,
    _lock: OwnedFd,
    child: sys::Child,
    command: OwnedFd,
    reply: OwnedFd,
    subject: wire::Subject,
}
impl ReadCustody {
    fn read(&mut self, p: &Pins, nonce: [u8; 32], expected_bound: [u8;32]) -> io::Result<([u8; 32], [u8; 32])> {
        if sys::exited(self.child.pidfd.as_raw_fd())? {
            return Err(refuse("custodian lost"));
        }
        sys::write_all(
            self.command.as_raw_fd(),
            &wire::challenge(nonce, p.generation),
        )?;
        let mut out = [0; wire::RESULT_BYTES];
        sys::read_exact(self.reply.as_raw_fd(), &mut out, None)?;
        sys::require_empty_live_pipe(self.reply.as_raw_fd())?;
        let pair = wire::parse_result(&out, nonce, p.generation, self.subject).ok_or_else(|| refuse("custodian result"))?;
        if pair.0 != p.source || pair.1 != expected_bound || sys::exited(self.child.pidfd.as_raw_fd())? {
            return Err(refuse("custodian subject changed/lost"));
        }
        Ok(pair)
    }
}
impl Drop for ReadCustody {
    fn drop(&mut self) {
        // This runs before ANY field drop, particularly before the flock FD.
        if self.child.kill_reap().is_err() {
            loop { std::thread::park(); }
        }
    }
}

pub fn keeper() -> io::Result<()> {
    if !sys::root_identity() || sys::pid() == 1 {
        return Err(refuse("root appliance service only"));
    }
    sys::check_fd_allowlist(2)?;
    let p = Pins::load()?;
    artifact(KEEPER, p.keeper)?;
    artifact(CUSTODIAN, p.custodian)?;
    artifact("/usr/lib/systemd/systemd", p.systemd)?;
    image_inventory()?;
    let pid1 = std::fs::metadata("/proc/1/exe")?;
    let expected_pid1 = std::fs::metadata("/usr/lib/systemd/systemd")?;
    if !sys::same(&pid1, &expected_pid1) {
        return Err(refuse("foreign PID1 executable"));
    }
    sys::readonly_fixture()?;
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")?;
    let matching = mounts
        .lines()
        .filter(|line| line.split_whitespace().nth(4) == Some("/fixture"))
        .collect::<Vec<_>>();
    if matching.len() != 1 || !matching[0].contains(" - ext4 /dev/vda ") {
        return Err(refuse("foreign fixture mount"));
    }
    let attempt_dir = sys::open(
        Path::new("/run/r1-appliance"),
        libc::O_RDONLY | libc::O_DIRECTORY,
    )?;
    let m = sys::metadata(&attempt_dir)?;
    if m.uid() != 0 || m.gid() != 0 || m.mode() & 0o7777 != 0o700 {
        return Err(refuse("attempt directory"));
    }
    // Negative same-boot replay can be rejected before any custody side effect.
    match sys::open_at(attempt_dir.as_raw_fd(), c"attempt", libc::O_PATH) {
        Ok(_) => {
            println!("APPLIANCE_ATTEMPT_SPENT");
            return Err(refuse("attempt spent"));
        }
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => (),
        Err(e) => return Err(e),
    }
    if sys::parent() != 1
        || std::fs::read_to_string("/proc/self/cgroup")? != GROUP
        || std::fs::read_to_string("/proc/1/comm")? != "systemd\n"
    {
        return Err(refuse("foreign appliance launch"));
    }
    let boot = boot()?;
    let mut attempt = sys::create_attempt(attempt_dir.as_raw_fd())?;
    attempt.write_all(b"SPENT\n")?;
    attempt.sync_all()?;
    let dirs = named_dirs()?;
    let state = dirs.last().unwrap().as_raw_fd();
    no_companions(state)?;
    let lock = sys::open_at(state, c"db.sqlite.manager.lock", libc::O_RDONLY)?;
    let lock_id = subject(&lock, &p, true)?;
    recheck_subject(&dirs,&lock,None)?;
    sys::flock_exclusive(lock.as_raw_fd())?;
    let source = sys::open_at(state, c"db.sqlite", libc::O_RDONLY)?;
    let source_id = subject(&source, &p, false)?;
    recheck_subject(&dirs,&lock,Some(&source))?;
    if lock_id.device != source_id.device || source_id.device != sys::stat(state)?.st_dev {
        return Err(refuse("foreign source device"));
    }
    std::fs::create_dir("/run/r1-appliance/empty")?;
    let (command_read, command) = sys::pipe()?;
    let (reply, reply_write) = sys::pipe()?;
    let self_pidfd = sys::pidfd(sys::pid())?;
    let null_read = sys::open(Path::new("/dev/null"), libc::O_RDONLY)?;
    let null_write = sys::open(Path::new("/dev/null"), libc::O_WRONLY)?;
    let transfer_controls = sys::transfer_controls(source.as_raw_fd())?;
    recheck_subject(&dirs,&lock,Some(&source))?;
    let child = sys::spawn_custodian([
        null_read.as_raw_fd(),
        reply_write.as_raw_fd(),
        null_write.as_raw_fd(),
        source.as_raw_fd(),
        command_read.as_raw_fd(),
        self_pidfd.as_raw_fd(),
    ])?;
    drop(transfer_controls);
    drop(command_read);
    drop(reply_write);
    drop(self_pidfd);
    drop(null_read);
    drop(null_write);
    let child_birth = birth(child.pid)?;
    let mut sealed = [0; wire::SEALED_BYTES];
    sys::read_exact(reply.as_raw_fd(), &mut sealed, None)?;
    sys::require_empty_live_pipe(reply.as_raw_fd())?;
    if !wire::verify_sealed(&sealed, child.pid, source_id) || sys::exited(child.pidfd.as_raw_fd())?
    {
        return Err(refuse("custodian seal not observed"));
    }
    let nonce = sys::random()?;
    let mut expected = wire::bound_hasher(&nonce);
    expected.update(p.source);
    let expected_bound: [u8;32] = expected.finalize().into();
    recheck_subject(&dirs,&lock,Some(&source))?;
    drop(source);
    let mut custody = ReadCustody {
        _attempt: attempt,
        _directories: dirs,
        _lock: lock,
        child,
        command,
        reply,
        subject: source_id,
    };
    let (source_hash, bound) = custody.read(&p, nonce, expected_bound)?;
    println!(
        "APPLIANCE_READ {{\"schema\":1,\"boot_id\":\"{boot}\",\"generation\":\"{}\",\"keeper_pid\":{},\"keeper_birth\":{},\"custodian_pid\":{},\"custodian_birth\":{},\"device\":{},\"source_inode\":{},\"lock_inode\":{},\"bytes\":{},\"nonce\":\"{}\",\"source_sha256\":\"{}\",\"bound_sha256\":\"{}\",\"migration_admission\":\"UNAVAILABLE\",\"ready\":false}}",
        wire::hex(&p.generation),
        sys::pid(),
        birth(sys::pid())?,
        custody.child.pid,
        child_birth,
        custody.subject.device,
        custody.subject.inode,
        lock_id.inode,
        custody.subject.size,
        wire::hex(&nonce),
        wire::hex(&source_hash),
        wire::hex(&bound)
    );
    loop {
        sys::require_empty_live_pipe(custody.reply.as_raw_fd())?;
        if sys::exited(custody.child.pidfd.as_raw_fd())? {
            return Err(refuse("custodian exited"));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

pub fn custodian() -> io::Result<()> {
    if !sys::root_identity() || sys::parent() < 2 {
        return Err(refuse("trusted root setup only"));
    }
    sys::check_fd_allowlist(5)?;
    sys::verify_clean_exec_mapping()?;
    for (fd, mode) in [(0, libc::O_RDONLY), (2, libc::O_WRONLY)] {
        let m = sys::stat(fd)?;
        if m.st_mode & libc::S_IFMT != libc::S_IFCHR
            || m.st_rdev != libc::makedev(1, 3)
            || sys::flags(fd)? & libc::O_ACCMODE != mode
        {
            return Err(refuse("foreign standard descriptor"));
        }
    }
    let p = Pins::load()?;
    artifact(CUSTODIAN, p.custodian)?;
    let parent = sys::parent();
    let parent_exe = std::fs::read_link(format!("/proc/{parent}/exe"))?;
    if parent_exe != Path::new(KEEPER)
        || std::fs::read_to_string(format!("/proc/{parent}/cgroup"))? != GROUP
    {
        return Err(refuse("foreign keeper"));
    }
    let info = std::fs::read_to_string("/proc/self/fdinfo/5")?;
    if !info.lines().any(|l| l == format!("Pid:\t{parent}")) || sys::exited(5)? {
        return Err(refuse("wrong/dead producer pidfd"));
    }
    let meta = sys::stat(3)?;
    if meta.st_uid != 1000
        || meta.st_gid != 1000
        || meta.st_mode & 0o177777 != 0o100600
        || meta.st_nlink != 1
        || meta.st_ino != p.source_inode
        || meta.st_size < 0
        || meta.st_size as u64 != p.size
        || sys::flags(3)? & libc::O_ACCMODE != libc::O_RDONLY
    {
        return Err(refuse("bad inherited source"));
    }
    for (fd, mode) in [(1, libc::O_WRONLY), (4, libc::O_RDONLY)] {
        if sys::stat(fd)?.st_mode & libc::S_IFMT != libc::S_IFIFO
            || sys::flags(fd)? & libc::O_ACCMODE != mode
        {
            return Err(refuse("bad inherited pipe"));
        }
    }
    sys::seal_identity(c"/run/r1-appliance/empty")?;
    sys::install_reader_filter()?;
    sys::reader_denial_controls()?;
    if sys::exited(5)? {
        return Err(refuse("keeper lost before seal"));
    }
    let identity = wire::Subject {
        device: meta.st_dev,
        inode: meta.st_ino,
        size: p.size,
    };
    sys::write_all(1, &wire::sealed(sys::pid(), identity))?;
    let mut raw = [0; wire::CHALLENGE_BYTES];
    sys::read_exact(4, &mut raw, Some(5))?;
    sys::require_empty_live_pipe(4)?;
    let nonce = wire::parse_challenge(&raw, p.generation)
        .ok_or_else(|| refuse("foreign read challenge"))?;
    let mut source = Sha256::new();
    let mut bound = wire::bound_hasher(&nonce);
    let mut buffer = [0; 4096];
    let mut offset = 0;
    while offset < p.size {
        if sys::exited(5)? {
            return Err(refuse("keeper lost during read"));
        }
        let count = sys::pread(
            3,
            &mut buffer[..(p.size - offset).min(4096) as usize],
            offset,
        )?;
        if count == 0 {
            return Err(refuse("short source"));
        }
        source.update(&buffer[..count]);
        offset += count as u64;
    }
    let hash: [u8; 32] = source.finalize().into();
    if hash != p.source || sys::exited(5)? {
        return Err(refuse("source changed/keeper lost"));
    }
    bound.update(hash);
    sys::write_all(1, &wire::result(hash, bound.finalize().into(), nonce, p.generation, identity))?;
    // No additional read grants. Poll-only liveness; kernel closes FD3 on exit.
    sys::wait_keeper_loss(5, 4)?;
    Ok(())
}
