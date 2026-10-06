//! Private, test-only CLOSED-origin acquisition mechanics.
//! A handle observes one controlled custodian; it is NOT an access barrier or
//! admission capability. In particular no old-FD/mmap/SCM_RIGHTS exclusion is
//! inferred. Root/PID1 identity is distinct from disposable child identity.
use super::*;
use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags, flock, openat, statat};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const CHANNEL_MAGIC: &[u8; 8] = b"PBORIG01";
const CHANNEL_CAP: usize = MAX_BYTES + 128;
const DEADLINE: Duration = Duration::from_secs(2);
const CLOSED_RECORD: &str = "closed-origin.record";

#[derive(Debug)]
enum Error {
    Io(std::io::Error),
    Refused(&'static str),
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<rustix::io::Errno> for Error {
    fn from(e: rustix::io::Errno) -> Self {
        Self::Io(e.into())
    }
}
type Result<T> = std::result::Result<T, Error>;
fn require(v: bool, why: &'static str) -> Result<()> {
    if v { Ok(()) } else { Err(Error::Refused(why)) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Domain {
    DisposableChild = 0,
    RootPid1 = 1,
}
impl Domain {
    fn parse(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::DisposableChild),
            1 => Ok(Self::RootPid1),
            _ => Err(Error::Refused("unknown domain")),
        }
    }
    fn check(self, pid: u32, uid: u32) -> Result<()> {
        match self {
            Self::DisposableChild => require(
                pid > 1 && uid != 0,
                "disposable domain is ordinary UID only",
            ),
            Self::RootPid1 => require(pid == 1 && uid == 0, "root/PID1 identity not established"),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Peer {
    pid: u32,
    uid: u32,
    gid: u32,
    birth: u64,
}
fn birth(pid: u32) -> Result<u64> {
    let value = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let end = value.rfind(')').ok_or(Error::Refused("bad proc stat"))?;
    let fields: Vec<_> = value[end + 1..].split_whitespace().collect();
    require(fields.first().is_some_and(|v| *v != "Z"), "peer is zombie")?;
    fields
        .get(19)
        .ok_or(Error::Refused("missing birth"))?
        .parse()
        .map_err(|_| Error::Refused("bad birth"))
}
fn self_peer() -> Result<Peer> {
    let pid = std::process::id();
    Ok(Peer {
        pid,
        uid: rustix::process::geteuid().as_raw(),
        gid: rustix::process::getegid().as_raw(),
        birth: birth(pid)?,
    })
}
fn socket_peer(socket: &UnixStream) -> Result<Peer> {
    let p = rustix::net::sockopt::socket_peercred(socket)?;
    let pid = p.pid.as_raw_pid() as u32;
    Ok(Peer {
        pid,
        uid: p.uid.as_raw(),
        gid: p.gid.as_raw(),
        birth: birth(pid)?,
    })
}
fn boot_id() -> Result<String> {
    let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let value = value.trim().to_owned();
    require(
        value.len() == 36 && value.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
        "bad boot ID",
    )?;
    Ok(value)
}
fn identity(m: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: m.dev(),
        inode: m.ino(),
    }
}
fn open_directory(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    require(
        m.is_dir() && m.uid() == rustix::process::geteuid().as_raw() && m.mode() & 0o7777 == 0o700,
        "unsafe origin directory",
    )?;
    Ok(file)
}
fn open_member(directory: &File, name: &str, write: bool) -> Result<File> {
    Ok(File::from(openat(
        directory,
        name,
        (if write { OFlags::RDWR } else { OFlags::RDONLY }) | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?))
}
fn verify_member(directory: &File, name: &str, file: &File, expected: &FileIdentity) -> Result<()> {
    let m = file.metadata()?;
    let named = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
    require(
        m.is_file()
            && m.uid() == rustix::process::geteuid().as_raw()
            && m.mode() & 0o7777 == 0o600
            && m.nlink() == 1
            && identity(&m) == *expected
            && named.st_dev as u64 == m.dev()
            && named.st_ino as u64 == m.ino(),
        "file identity differs",
    )
}
fn lineage(file: &File, expected_version: i64) -> Result<String> {
    // Fixed /proc FD alias references the retained file, not a caller pathname.
    let uri = format!("file:/proc/self/fd/{}?immutable=1", file.as_raw_fd());
    let c = rusqlite::Connection::open_with_flags(
        uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|_| Error::Refused("read-only SQLite open refused"))?;
    let version: i64 = c
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|_| Error::Refused("version read failed"))?;
    require(version == expected_version, "store version differs")?;
    c.query_row(
        "SELECT lineage FROM store_identity WHERE singleton=1",
        [],
        |r| r.get(0),
    )
    .map_err(|_| Error::Refused("lineage read failed"))
}

struct HeldInputs {
    root: PathBuf,
    directory: File,
    source: File,
    staging: File,
    lock: File,
    policy: File,
    source_digest: [u8; 32],
    staging_digest: [u8; 32],
}
impl HeldInputs {
    fn acquire(root: &Path, record: &RecordV1) -> Result<Self> {
        let directory = open_directory(root)?;
        require(
            identity(&directory.metadata()?) == record.parent,
            "parent differs",
        )?;
        let s = &record.durable.subject;
        let source = open_member(&directory, &s.canonical_name, false)?;
        let staging = open_member(&directory, &s.staging_name, false)?;
        let lock = open_member(
            &directory,
            &format!("{}.manager.lock", s.canonical_name),
            true,
        )?;
        let policy = open_member(&directory, "policy.bin", false)?;
        verify_member(
            &directory,
            &format!("{}.manager.lock", s.canonical_name),
            &lock,
            &s.manager_lock,
        )?;
        // No SQLite inspection or content measurement before the exact lock.
        flock(&lock, FlockOperation::NonBlockingLockExclusive)?;
        let source_digest = hash_file(&source)?;
        let staging_digest = hash_file(&staging)?;
        let held = Self {
            root: root.into(),
            directory,
            source,
            staging,
            lock,
            policy,
            source_digest,
            staging_digest,
        };
        held.verify(record)?;
        Ok(held)
    }
    fn verify(&self, record: &RecordV1) -> Result<()> {
        let s = &record.durable.subject;
        let m = self.directory.metadata()?;
        require(
            identity(&m) == record.parent
                && m.uid() == rustix::process::geteuid().as_raw()
                && m.mode() & 0o7777 == 0o700
                && m.nlink() != 0,
            "parent changed",
        )?;
        let named = std::fs::symlink_metadata(&self.root)?;
        require(
            named.is_dir() && identity(&named) == record.parent,
            "named parent changed",
        )?;
        verify_member(&self.directory, &s.canonical_name, &self.source, &s.source)?;
        verify_member(&self.directory, &s.staging_name, &self.staging, &s.staging)?;
        verify_member(
            &self.directory,
            &format!("{}.manager.lock", s.canonical_name),
            &self.lock,
            &s.manager_lock,
        )?;
        require(
            lineage(&self.source, 24)? == s.lineage && lineage(&self.staging, 25)? == s.lineage,
            "store pair lineage differs",
        )?;
        require(
            hash_file(&self.source)? == self.source_digest
                && hash_file(&self.staging)? == self.staging_digest,
            "store bytes changed",
        )?;
        let policy_identity = identity(&self.policy.metadata()?);
        verify_member(
            &self.directory,
            "policy.bin",
            &self.policy,
            &policy_identity,
        )?;
        require(
            hash_file(&self.policy)? == s.policy_digest,
            "policy digest differs",
        )?;
        require(
            hash_file(&File::open("/proc/self/exe")?)? == s.artifact_digest,
            "artifact digest differs",
        )?;
        require(boot_id()? == s.current_boot, "current boot differs")?;
        Ok(())
    }
    fn publish_closed(&self, record: &RecordV1) -> Result<File> {
        // A new custodian never adopts matching-looking records left by another
        // process. Crash/restart origin recovery is deliberately still closed.
        let mut file = File::from(openat(
            &self.directory,
            CLOSED_RECORD,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        let bytes = encode(record).map_err(|_| Error::Refused("invalid origin record"))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        self.directory.sync_all()?;
        Ok(file)
    }
}
fn hash_file(file: &File) -> Result<[u8; 32]> {
    use std::os::unix::fs::FileExt;
    let before = file.metadata()?;
    require(
        before.is_file() && before.len() <= 256 * 1024 * 1024,
        "file byte cap",
    )?;
    let mut hash = Sha256::new();
    let mut at = 0;
    let mut buffer = [0; 65536];
    loop {
        let n = file.read_at(&mut buffer, at)?;
        if n == 0 {
            break;
        }
        at += n as u64;
        require(at <= 256 * 1024 * 1024, "file grew past cap")?;
        hash.update(&buffer[..n]);
    }
    let after = file.metadata()?;
    require(
        at == before.len()
            && after.len() == before.len()
            && after.mtime_nsec() == before.mtime_nsec()
            && after.ctime_nsec() == before.ctime_nsec()
            && after.mtime() == before.mtime()
            && after.ctime() == before.ctime(),
        "file changed during hashing",
    )?;
    Ok(hash.finalize().into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    Acquire = 0,
    Check = 1,
    MarkLateForTest = 2,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Closed = 0,
    Late = 1,
    Refused = 2,
}
struct Message {
    tag: u8,
    domain: Domain,
    sequence: u64,
    nonce: [u8; 32],
    record: RecordV1,
}
fn encode_message(m: &Message) -> Result<Vec<u8>> {
    let record = encode(&m.record).map_err(|_| Error::Refused("bad encoded subject"))?;
    let mut bytes = CHANNEL_MAGIC.to_vec();
    bytes.push(m.tag);
    bytes.push(m.domain as u8);
    bytes.extend_from_slice(&m.sequence.to_be_bytes());
    bytes.extend_from_slice(&m.nonce);
    bytes.extend_from_slice(&(record.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&record);
    require(bytes.len() <= CHANNEL_CAP, "channel cap")?;
    Ok(bytes)
}
fn decode_message(bytes: &[u8]) -> Result<Message> {
    require(bytes.len() <= CHANNEL_CAP, "channel cap")?;
    let mut r = Reader { bytes, offset: 0 };
    let parsed = (|| -> std::result::Result<_, CodecError> {
        if r.take(8)? != CHANNEL_MAGIC {
            return Err(CodecError::Tag);
        }
        let tag = r.byte()?;
        let domain = r.byte()?;
        let sequence = r.u64()?;
        let nonce = r.hash()?;
        let n = u16::from_be_bytes(r.take(2)?.try_into().unwrap()) as usize;
        let record = decode(r.take(n)?)?;
        if r.offset != bytes.len() {
            return Err(CodecError::Trailing);
        }
        Ok((tag, domain, sequence, nonce, record))
    })()
    .map_err(|_| Error::Refused("malformed channel frame"))?;
    Ok(Message {
        tag: parsed.0,
        domain: Domain::parse(parsed.1)?,
        sequence: parsed.2,
        nonce: parsed.3,
        record: parsed.4,
    })
}
fn send(stream: &mut UnixStream, message: &Message) -> Result<()> {
    let bytes = encode_message(message)?;
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    Ok(())
}
fn receive(stream: &mut UnixStream) -> Result<Message> {
    let deadline = Instant::now() + DEADLINE;
    fn exact(stream: &mut UnixStream, mut out: &mut [u8], deadline: Instant) -> Result<()> {
        while !out.is_empty() {
            let left = deadline
                .checked_duration_since(Instant::now())
                .ok_or(Error::Refused("channel deadline"))?;
            stream.set_read_timeout(Some(left))?;
            let n = stream.read(out)?;
            require(n != 0, "channel lost")?;
            out = &mut out[n..];
        }
        Ok(())
    }
    let mut n = [0; 4];
    exact(stream, &mut n, deadline)?;
    let n = u32::from_be_bytes(n) as usize;
    require(n <= CHANNEL_CAP, "channel cap before allocation")?;
    let mut bytes = vec![0; n];
    exact(stream, &mut bytes, deadline)?;
    decode_message(&bytes)
}

// Opaque, neither Clone nor serializable, and confined to this test-only module.
// No file export, SQLite write, issuer release or production conversion method.
struct ClosedOrigin {
    stream: Option<UnixStream>,
    peer: Peer,
    domain: Domain,
    nonce: [u8; 32],
    record: RecordV1,
    sequence: u64,
}
impl ClosedOrigin {
    fn acquire(
        stream: UnixStream,
        peer: Peer,
        domain: Domain,
        nonce: [u8; 32],
        record: RecordV1,
    ) -> Result<Self> {
        require(socket_peer(&stream)? == peer, "foreign custodian peer")?;
        domain.check(peer.pid, peer.uid)?;
        stream.set_write_timeout(Some(DEADLINE))?;
        let mut handle = Self {
            stream: Some(stream),
            peer,
            domain,
            nonce,
            record,
            sequence: 0,
        };
        handle.exchange(Operation::Acquire)?;
        Ok(handle)
    }
    fn verify_closed(&mut self) -> Result<()> {
        self.exchange(Operation::Check)
    }
    fn exchange(&mut self, operation: Operation) -> Result<()> {
        let mut stream = self
            .stream
            .take()
            .ok_or(Error::Refused("origin failure latched closed"))?;
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(Error::Refused("sequence overflow"))?;
        require(
            birth(self.peer.pid)? == self.peer.birth && socket_peer(&stream)? == self.peer,
            "custodian identity lost",
        )?;
        send(
            &mut stream,
            &Message {
                tag: operation as u8,
                domain: self.domain,
                sequence,
                nonce: self.nonce,
                record: self.record.clone(),
            },
        )?;
        let response = receive(&mut stream)?;
        require(
            response.domain == self.domain
                && response.sequence == sequence
                && response.nonce == self.nonce
                && response.record == self.record,
            "foreign or replayed response",
        )?;
        require(
            response.tag == Outcome::Closed as u8,
            if response.tag == Outcome::Late as u8 {
                "late engagement"
            } else {
                "custodian refused"
            },
        )?;
        require(
            birth(self.peer.pid)? == self.peer.birth,
            "custodian lost before readback",
        )?;
        self.sequence = sequence;
        self.stream = Some(stream);
        Ok(())
    }
}

fn serve(
    root: &Path,
    expected_parent: Peer,
    domain: Domain,
    nonce: [u8; 32],
    record: RecordV1,
) -> Result<()> {
    let own = self_peer()?;
    domain.check(own.pid, own.uid)?;
    require(
        record.kind == Kind::InitialClosed,
        "only initial closed origin supported",
    )?;
    let inputs = HeldInputs::acquire(root, &record)?;
    let marker = inputs.publish_closed(&record)?;
    let marker_id = identity(&marker.metadata()?);
    let mut stream = UnixStream::connect(root.join("channel.sock"))?;
    require(
        socket_peer(&stream)? == expected_parent,
        "foreign requester peer",
    )?;
    stream.set_write_timeout(Some(DEADLINE))?;
    let mut last = 0_u64;
    let mut late = false;
    loop {
        let request = receive(&mut stream)?;
        require(
            request.domain == domain
                && request.nonce == nonce
                && request.record == record
                && request.sequence
                    == last
                        .checked_add(1)
                        .ok_or(Error::Refused("sequence overflow"))?,
            "request binding or order differs",
        )?;
        require(
            (last == 0) == (request.tag == Operation::Acquire as u8),
            "acquisition order differs",
        )?;
        require(
            request.tag <= Operation::MarkLateForTest as u8,
            "unknown operation",
        )?;
        if request.tag == Operation::MarkLateForTest as u8 {
            late = true;
        }
        inputs.verify(&record)?;
        verify_member(&inputs.directory, CLOSED_RECORD, &marker, &marker_id)?;
        let marker_bytes = encode(&record).map_err(|_| Error::Refused("bad origin record"))?;
        require(
            hash_file(&marker)? == <[u8; 32]>::from(Sha256::digest(marker_bytes)),
            "origin bytes changed",
        )?;
        let tag = if late { Outcome::Late } else { Outcome::Closed };
        send(
            &mut stream,
            &Message {
                tag: tag as u8,
                domain,
                sequence: request.sequence,
                nonce,
                record: record.clone(),
            },
        )?;
        last = request.sequence;
    }
}

#[cfg(test)]
mod tests;
