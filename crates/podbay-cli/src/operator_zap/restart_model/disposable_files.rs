//! Linux test-only allocation markers. Modeled terminal data grants no authority.
//!
//! Cold recovery relies on the caller's exact private root and modeled genesis,
//! canonical complete records, and cooperating creators honoring the root lock.
//! It does not authenticate terminal assertions or prove the origin of bytes
//! against a malicious same-UID writer. Persisted model data is never a launch
//! grant. Only Allocated is supported; policy materialization, signed-terminal
//! acquisition, effect claim/reconciliation, readiness, and a production CLI
//! hook remain absent. Injected stops and actual fsyncs test error/retry order,
//! not storage hardware power-loss behavior. Partial temporary files are kept
//! and refuse recovery; there is no automatic deletion or repair of them.
//! The fixture root admits only its lock and allocation markers. A future
//! policy-directory namespace requires its own integration contract.
use super::*;
use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags, openat, renameat_with, statat};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const SCHEMA: &str = "podbay.operator-zap-restart-allocation-model/1";
const LOCK: &str = "restart-v1.lock";
const MAX_ROWS: u64 = 512;
const MAX_BYTES: usize = 16 * 1024;
#[derive(Debug)]
enum Error {
    Io(std::io::Error),
    Refused(&'static str),
    Model(Refusal),
    Injected(Point),
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
impl From<Refusal> for Error {
    fn from(e: Refusal) -> Self {
        Self::Model(e)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Point {
    BeforeCreate,
    Created,
    PartialWrite,
    Written,
    FileSynced,
    Published,
    DirectorySynced,
    Readback,
}
fn fault(selected: Option<Point>, point: Point) -> Result<(), Error> {
    if selected == Some(point) {
        Err(Error::Injected(point))
    } else {
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootBinding {
    owner: String,
    device: u64,
    inode: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pins {
    pod_artifact: [u8; 32],
    node_artifact: [u8; 32],
    zap_artifact: [u8; 32],
    configuration: [u8; 32],
    database: [u8; 32],
    profile: String,
}
impl From<&PinsV1> for Pins {
    fn from(p: &PinsV1) -> Self {
        Self {
            pod_artifact: p.pod_artifact,
            node_artifact: p.node_artifact,
            zap_artifact: p.zap_artifact,
            configuration: p.configuration,
            database: p.database,
            profile: p.profile.clone(),
        }
    }
}
impl From<&Pins> for PinsV1 {
    fn from(p: &Pins) -> Self {
        Self {
            pod_artifact: p.pod_artifact,
            node_artifact: p.node_artifact,
            zap_artifact: p.zap_artifact,
            configuration: p.configuration,
            database: p.database,
            profile: p.profile.clone(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ids {
    actor: String,
    scope: String,
    pod: String,
    session: String,
    run: String,
    attempt: String,
    resource: String,
    command: String,
}
impl From<&IdentitiesV1> for Ids {
    fn from(i: &IdentitiesV1) -> Self {
        let a = &i.0;
        Self {
            actor: a[0].clone(),
            scope: a[1].clone(),
            pod: a[2].clone(),
            session: a[3].clone(),
            run: a[4].clone(),
            attempt: a[5].clone(),
            resource: a[6].clone(),
            command: a[7].clone(),
        }
    }
}
impl From<&Ids> for IdentitiesV1 {
    fn from(i: &Ids) -> Self {
        Self([
            i.actor.clone(),
            i.scope.clone(),
            i.pod.clone(),
            i.session.clone(),
            i.run.clone(),
            i.attempt.clone(),
            i.resource.clone(),
            i.command.clone(),
        ])
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u8,
    owner: String,
    key: String,
    terminal_digest: [u8; 32],
    pins: Pins,
}
impl From<&RequestV1> for Request {
    fn from(r: &RequestV1) -> Self {
        Self {
            version: r.version,
            owner: r.owner.clone(),
            key: r.key.clone(),
            terminal_digest: r.terminal_digest,
            pins: (&r.pins).into(),
        }
    }
}
impl From<&Request> for RequestV1 {
    fn from(r: &Request) -> Self {
        Self {
            version: r.version,
            owner: r.owner.clone(),
            key: r.key.clone(),
            terminal_digest: r.terminal_digest,
            pins: (&r.pins).into(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Terminal {
    version: u8,
    owner: String,
    digest: [u8; 32],
    generation: u64,
    identities: Ids,
    pins: Pins,
}
impl From<&VerifiedTerminalV1> for Terminal {
    fn from(t: &VerifiedTerminalV1) -> Self {
        Self {
            version: t.version,
            owner: t.owner.clone(),
            digest: t.digest,
            generation: t.generation,
            identities: (&t.identities).into(),
            pins: (&t.pins).into(),
        }
    }
}
impl From<&Terminal> for VerifiedTerminalV1 {
    fn from(t: &Terminal) -> Self {
        Self {
            version: t.version,
            owner: t.owner.clone(),
            digest: t.digest,
            generation: t.generation,
            identities: (&t.identities).into(),
            pins: (&t.pins).into(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    root: RootBinding,
    request: Request,
    predecessor: Terminal,
    generation: u64,
    directory_slot: String,
    identities: Ids,
    stage: String,
}
impl Record {
    fn from_allocation(root: &RootBinding, a: &AllocationV1) -> Result<Self, Error> {
        if a.stage != StageV1::Allocated {
            return Err(Error::Refused("unsupported durable stage"));
        }
        Ok(Self {
            schema: SCHEMA.into(),
            root: root.clone(),
            request: (&a.request).into(),
            predecessor: (&a.predecessor).into(),
            generation: a.generation,
            directory_slot: a.directory_slot.clone(),
            identities: (&a.identities).into(),
            stage: "allocated".into(),
        })
    }
    fn allocation(&self) -> Result<AllocationV1, Error> {
        if self.schema != SCHEMA
            || self.stage != "allocated"
            || self.generation == 0
            || self.generation > MAX_ROWS
        {
            return Err(Error::Refused("unsupported marker"));
        }
        let a = AllocationV1 {
            version: 1,
            request: (&self.request).into(),
            predecessor: (&self.predecessor).into(),
            generation: self.generation,
            directory_slot: self.directory_slot.clone(),
            identities: (&self.identities).into(),
            stage: StageV1::Allocated,
        };
        if !literal(&self.root.owner)
            || a.request.version != 1
            || a.predecessor.version != 1
            || a.request.owner != self.root.owner
            || a.predecessor.owner != self.root.owner
            || !literal(&a.request.key)
            || !pins_valid(&a.request.pins)
            || a.request.pins != a.predecessor.pins
            || a.request.terminal_digest != a.predecessor.digest
            || a.predecessor.digest == [0; 32]
            || !ids_valid(&a.identities)
            || !ids_valid(&a.predecessor.identities)
            || !disjoint(&a.identities, &a.predecessor.identities)
            || a.predecessor.generation.checked_add(1) != Some(a.generation)
            || a.directory_slot != format!("generation-{:020}", a.generation)
        {
            return Err(Error::Refused("malformed allocation fields"));
        }
        Ok(a)
    }
}
fn encode(r: &Record) -> Result<Vec<u8>, Error> {
    let b = serde_json::to_vec(r).map_err(|_| Error::Refused("encoding failed"))?;
    if b.len() > MAX_BYTES {
        return Err(Error::Refused("marker byte bound"));
    }
    Ok(b)
}
fn decode(b: &[u8]) -> Result<Record, Error> {
    if b.is_empty() || b.len() > MAX_BYTES {
        return Err(Error::Refused("marker byte bound"));
    }
    let r: Record = serde_json::from_slice(b).map_err(|_| Error::Refused("malformed marker"))?;
    r.allocation()?;
    if encode(&r)? != b {
        return Err(Error::Refused("noncanonical marker"));
    }
    Ok(r)
}
fn names(g: u64) -> (String, String) {
    let n = format!("generation-{g:020}.json");
    (format!("{n}.writing"), n)
}
struct OwnerRoot {
    path: PathBuf,
    directory: File,
    root: RootBinding,
    uid: u32,
    genesis: VerifiedTerminalV1,
}
struct Locked<'a> {
    root: &'a OwnerRoot,
    file: File,
}
impl Drop for Locked<'_> {
    #[allow(deprecated)]
    fn drop(&mut self) {
        let _ = nix::fcntl::flock(self.file.as_raw_fd(), nix::fcntl::FlockArg::Unlock);
    }
}
impl OwnerRoot {
    fn pin(path: &Path, owner: &str, genesis: VerifiedTerminalV1) -> Result<Self, Error> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let m = directory.metadata()?;
        let root = RootBinding {
            owner: owner.into(),
            device: m.dev(),
            inode: m.ino(),
        };
        let value = Self {
            path: path.into(),
            directory,
            root,
            uid: rustix::process::geteuid().as_raw(),
            genesis,
        };
        value.check()?;
        if value.genesis.version != VERSION
            || value.genesis.generation != 0
            || value.genesis.owner != owner
            || !literal(owner)
            || !ids_valid(&value.genesis.identities)
            || !pins_valid(&value.genesis.pins)
            || value.genesis.digest == [0; 32]
        {
            return Err(Error::Refused("invalid modeled genesis"));
        }
        Ok(value)
    }
    fn check(&self) -> Result<(), Error> {
        let m = self.directory.metadata()?;
        let named = fs::symlink_metadata(&self.path)?;
        if !m.is_dir()
            || !named.is_dir()
            || m.dev() != self.root.device
            || m.ino() != self.root.inode
            || named.dev() != m.dev()
            || named.ino() != m.ino()
            || m.uid() != self.uid
            || m.mode() & 0o7777 != 0o700
            || m.nlink() == 0
        {
            return Err(Error::Refused("unsafe owner root"));
        }
        Ok(())
    }
    fn open(&self, name: &str, flags: OFlags) -> Result<File, Error> {
        Ok(File::from(openat(
            &self.directory,
            name,
            flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::from_raw_mode(0o600),
        )?))
    }
    fn exact_file(&self, name: &str, file: &File) -> Result<(), Error> {
        self.check()?;
        let m = file.metadata()?;
        let n = statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if !m.is_file()
            || m.uid() != self.uid
            || m.mode() & 0o7777 != 0o600
            || m.nlink() != 1
            || n.st_dev as u64 != m.dev()
            || n.st_ino as u64 != m.ino()
        {
            return Err(Error::Refused("unsafe or replaced marker"));
        }
        Ok(())
    }
    fn absent(&self, name: &str) -> Result<(), Error> {
        match statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => Ok(()),
            Ok(_) => Err(Error::Refused("occupied temporary marker")),
            Err(e) => Err(e.into()),
        }
    }
    #[allow(deprecated)]
    fn lock(&self) -> Result<Locked<'_>, Error> {
        self.check()?;
        let f = self.open(LOCK, OFlags::RDWR | OFlags::CREATE)?;
        self.exact_file(LOCK, &f)?;
        nix::fcntl::flock(f.as_raw_fd(), nix::fcntl::FlockArg::LockExclusive)
            .map_err(|e| Error::Io(e.into()))?;
        self.exact_file(LOCK, &f)?;
        Ok(Locked {
            root: self,
            file: f,
        })
    }
    fn read(&self, name: &str) -> Result<(Record, Vec<u8>), Error> {
        let f = self.open(name, OFlags::RDONLY)?;
        self.exact_file(name, &f)?;
        if f.metadata()?.len() > MAX_BYTES as u64 {
            return Err(Error::Refused("marker byte bound"));
        }
        let mut bytes = Vec::new();
        (&f).take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes)?;
        self.exact_file(name, &f)?;
        let r = decode(&bytes)?;
        if r.root != self.root {
            return Err(Error::Refused("foreign marker root"));
        }
        Ok((r, bytes))
    }
}
impl Locked<'_> {
    fn ledger(&self) -> Result<LedgerV1, Error> {
        self.root.check()?;
        self.root.exact_file(LOCK, &self.file)?;
        let mut generations = std::collections::BTreeSet::new();
        let mut count = 0;
        for entry in fs::read_dir(&self.root.path)? {
            count += 1;
            if count > MAX_ROWS + 1 {
                return Err(Error::Refused("directory entry bound"));
            }
            let name = entry?.file_name();
            let name = name.to_str().ok_or(Error::Refused("foreign entry"))?;
            if name == LOCK {
                continue;
            }
            let Some(n) = name
                .strip_prefix("generation-")
                .and_then(|s| s.strip_suffix(".json"))
            else {
                return Err(Error::Refused("foreign or temporary entry"));
            };
            let g: u64 = n.parse().map_err(|_| Error::Refused("foreign entry"))?;
            if g == 0 || g > MAX_ROWS || names(g).1 != name || !generations.insert(g) {
                return Err(Error::Refused("foreign entry"));
            }
        }
        self.root.check()?;
        let mut l = LedgerV1 {
            version: 1,
            owner: self.root.root.owner.clone(),
            generation: 0,
            allocations: vec![],
        };
        for g in generations {
            if g != l.generation + 1 {
                return Err(Error::Refused("generation gap"));
            }
            let (r, _) = self.root.read(&names(g).1)?;
            let a = r.allocation()?;
            let expected_terminal = if g == 1 {
                self.root.genesis.clone()
            } else {
                VerifiedTerminalV1 {
                    version: 1,
                    owner: l.owner.clone(),
                    digest: a.predecessor.digest,
                    generation: g - 1,
                    identities: l.allocations.last().unwrap().identities.clone(),
                    pins: l.allocations.last().unwrap().request.pins.clone(),
                }
            };
            if a.predecessor != expected_terminal {
                return Err(Error::Refused("foreign predecessor"));
            }
            let (next, out) = allocate(
                &l,
                &a.request,
                &TerminalInput::ModelVerified(expected_terminal),
                PriorEffect::Settled,
                PriorChild::Gone,
            )?;
            if !matches!(out,OutcomeV1::Allocated(ref expected) if expected==&a) {
                return Err(Error::Refused("foreign allocation bytes"));
            }
            l = next;
        }
        validate_ledger(&l)?;
        self.root.exact_file(LOCK, &self.file)?;
        Ok(l)
    }
    fn reserve(
        &self,
        r: &RequestV1,
        t: &TerminalInput,
        e: PriorEffect,
        c: PriorChild,
        selected: Option<Point>,
    ) -> Result<OutcomeV1, Error> {
        let l = self.ledger()?;
        let (next, out) = allocate(&l, r, t, e, c)?;
        let a = match &out {
            OutcomeV1::Allocated(a) | OutcomeV1::ExactReplay(a) => a,
            _ => return Err(Error::Refused("unsupported model result")),
        };
        if l.generation == 0 && a.predecessor != self.root.genesis {
            return Err(Error::Refused("foreign pinned genesis"));
        }
        if a.generation > MAX_ROWS {
            return Err(Error::Refused("generation bound"));
        }
        let record = Record::from_allocation(&self.root.root, a)?;
        let bytes = encode(&record)?;
        let (writing, name) = names(a.generation);
        self.root.absent(&writing)?;
        if matches!(out, OutcomeV1::ExactReplay(_)) {
            let (saved, raw) = self.root.read(&name)?;
            if saved != record || raw != bytes {
                return Err(Error::Refused("foreign replay bytes"));
            }
            let f = self.root.open(&name, OFlags::RDONLY)?;
            self.root.exact_file(&name, &f)?;
            f.sync_all()?;
            self.root.directory.sync_all()?;
            if self.root.read(&name)?.1 != bytes {
                return Err(Error::Refused("replay changed during sync"));
            }
            return Ok(out);
        }
        fault(selected, Point::BeforeCreate)?;
        self.root.exact_file(LOCK, &self.file)?;
        let mut f = self
            .root
            .open(&writing, OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL)?;
        self.root.exact_file(&writing, &f)?;
        fault(selected, Point::Created)?;
        let split = bytes.len() / 2;
        f.write_all(&bytes[..split])?;
        fault(selected, Point::PartialWrite)?;
        f.write_all(&bytes[split..])?;
        fault(selected, Point::Written)?;
        f.sync_all()?;
        fault(selected, Point::FileSynced)?;
        self.root.exact_file(&writing, &f)?;
        renameat_with(
            &self.root.directory,
            writing.as_str(),
            &self.root.directory,
            name.as_str(),
            RenameFlags::NOREPLACE,
        )?;
        fault(selected, Point::Published)?;
        self.root.directory.sync_all()?;
        fault(selected, Point::DirectorySynced)?;
        if self.root.read(&name)?.1 != bytes || self.ledger()? != next {
            return Err(Error::Refused("published readback differs"));
        }
        fault(selected, Point::Readback)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
    use std::sync::{Arc, Barrier};
    fn subject() -> VerifiedTerminalV1 {
        VerifiedTerminalV1 {
            version: 1,
            owner: "owner".into(),
            digest: [6; 32],
            generation: 0,
            identities: IdentitiesV1(std::array::from_fn(|i| format!("old.{i}"))),
            pins: PinsV1 {
                pod_artifact: [1; 32],
                node_artifact: [2; 32],
                zap_artifact: [3; 32],
                configuration: [4; 32],
                database: [5; 32],
                profile: "profile.one".into(),
            },
        }
    }
    fn request() -> RequestV1 {
        let t = subject();
        RequestV1 {
            version: 1,
            owner: t.owner.clone(),
            key: "restart.one".into(),
            terminal_digest: t.digest,
            pins: t.pins,
        }
    }
    struct Fixture {
        path: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "podbay-restart-marker-{}-{time}-{n}",
                std::process::id()
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self { path }
        }
        fn root(&self) -> OwnerRoot {
            OwnerRoot::pin(&self.path, "owner", subject()).unwrap()
        }
        fn bytes(&self) -> Vec<u8> {
            fs::read(self.path.join(names(1).1)).unwrap()
        }
    }
    // Disposable fixtures are retained; foreign/partial bytes are never deleted.
    #[test]
    fn foreign_initial_terminal_cannot_poison_pinned_root() {
        let f = Fixture::new();
        let root = f.root();
        let lock = root.lock().unwrap();
        let mut wrong_terminal = subject();
        wrong_terminal.digest = [9; 32];
        let mut wrong_request = request();
        wrong_request.terminal_digest = wrong_terminal.digest;
        assert!(matches!(
            lock.reserve(
                &wrong_request,
                &TerminalInput::ModelVerified(wrong_terminal),
                PriorEffect::Settled,
                PriorChild::Gone,
                None,
            ),
            Err(Error::Refused("foreign pinned genesis"))
        ));
        assert!(!f.path.join(names(1).0).exists());
        assert!(!f.path.join(names(1).1).exists());
        assert_eq!(lock.ledger().unwrap().generation, 0);
        assert!(matches!(
            lock.reserve(
                &request(),
                &TerminalInput::ModelVerified(subject()),
                PriorEffect::Settled,
                PriorChild::Gone,
                None,
            ),
            Ok(OutcomeV1::Allocated(_))
        ));
    }
    #[test]
    fn reserve_once_exact_cold_retry_and_reject_changed_requests() {
        let f = Fixture::new();
        let root = f.root();
        let r = request();
        let t = TerminalInput::ModelVerified(subject());
        let out = root
            .lock()
            .unwrap()
            .reserve(&r, &t, PriorEffect::Settled, PriorChild::Gone, None)
            .unwrap();
        let OutcomeV1::Allocated(a) = out else {
            panic!("fresh allocation expected")
        };
        assert_eq!(a.generation, 1);
        assert!(disjoint(&a.identities, &subject().identities));
        assert!(
            !f.path.join(&a.directory_slot).exists(),
            "allocation cannot materialize policy directory"
        );
        let before = f.bytes();
        drop(root);
        let root = f.root();
        let lock = root.lock().unwrap();
        assert_eq!(
            lock.reserve(&r, &t, PriorEffect::Unknown, PriorChild::Live, None)
                .unwrap(),
            OutcomeV1::ExactReplay(a.clone())
        );
        assert_eq!(f.bytes(), before);
        let mut changed = r.clone();
        changed.pins.configuration = [9; 32];
        assert!(matches!(
            lock.reserve(&changed, &t, PriorEffect::Settled, PriorChild::Gone, None),
            Err(Error::Model(Refusal::KeyConflict))
        ));
        changed = r.clone();
        changed.key = "alternate".into();
        assert!(matches!(
            lock.reserve(&changed, &t, PriorEffect::Settled, PriorChild::Gone, None),
            Err(Error::Model(Refusal::PredecessorConflict))
        ));
        assert_eq!(f.bytes(), before);
        drop(lock);
        drop(root);
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "operator_zap::restart_model::disposable_files::tests::cold_child",
                "--nocapture",
            ])
            .env("PODBAY_RESTART_MARKER_COLD", &f.path)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "{}",
            String::from_utf8_lossy(&child.stderr)
        );
        assert!(String::from_utf8_lossy(&child.stdout).contains("COLD_REPLAY_OK"));
        assert_eq!(f.bytes(), before);
    }
    #[test]
    fn cold_child() {
        let Some(path) = std::env::var_os("PODBAY_RESTART_MARKER_COLD") else {
            return;
        };
        let path = PathBuf::from(path);
        assert!(
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("podbay-restart-marker-")
        );
        let root = OwnerRoot::pin(&path, "owner", subject()).unwrap();
        let result = root
            .lock()
            .unwrap()
            .reserve(
                &request(),
                &TerminalInput::ModelVerified(subject()),
                PriorEffect::Unknown,
                PriorChild::Unknown,
                None,
            )
            .unwrap();
        assert!(matches!(result, OutcomeV1::ExactReplay(_)));
        println!("COLD_REPLAY_OK");
    }
    #[test]
    fn every_publication_fault_is_closed_or_exactly_recoverable() {
        for point in [
            Point::BeforeCreate,
            Point::Created,
            Point::PartialWrite,
            Point::Written,
            Point::FileSynced,
            Point::Published,
            Point::DirectorySynced,
            Point::Readback,
        ] {
            let f = Fixture::new();
            let root = f.root();
            assert!(
                matches!(root.lock().unwrap().reserve(&request(),&TerminalInput::ModelVerified(subject()),PriorEffect::Settled,PriorChild::Gone,Some(point)),Err(Error::Injected(p)) if p==point)
            );
            drop(root);
            let root = f.root();
            let result = root.lock().unwrap().reserve(
                &request(),
                &TerminalInput::ModelVerified(subject()),
                PriorEffect::Settled,
                PriorChild::Gone,
                None,
            );
            match point {
                Point::BeforeCreate => assert!(matches!(result, Ok(OutcomeV1::Allocated(_)))),
                Point::Created | Point::PartialWrite | Point::Written | Point::FileSynced => {
                    assert!(result.is_err());
                    assert!(f.path.join(names(1).0).exists());
                    assert!(!f.path.join(names(1).1).exists());
                }
                _ => assert!(matches!(result, Ok(OutcomeV1::ExactReplay(_)))),
            }
            assert!(!f.path.join("generation-00000000000000000001").exists());
        }
    }
    #[test]
    fn cooperating_creators_serialize_to_one_marker() {
        let f = Fixture::new();
        let barrier = Arc::new(Barrier::new(2));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let path = f.path.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                let root = OwnerRoot::pin(&path, "owner", subject()).unwrap();
                barrier.wait();
                let lock = root.lock().unwrap();
                lock.reserve(
                    &request(),
                    &TerminalInput::ModelVerified(subject()),
                    PriorEffect::Settled,
                    PriorChild::Gone,
                    None,
                )
                .unwrap()
            }));
        }
        let out = workers
            .into_iter()
            .map(|w| w.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            out.iter()
                .filter(|x| matches!(x, OutcomeV1::Allocated(_)))
                .count(),
            1
        );
        assert_eq!(
            out.iter()
                .filter(|x| matches!(x, OutcomeV1::ExactReplay(_)))
                .count(),
            1
        );
        let root = f.root();
        assert_eq!(root.lock().unwrap().ledger().unwrap().generation, 1);
    }
    #[test]
    #[allow(deprecated)]
    fn held_lock_excludes_another_descriptor() {
        let f = Fixture::new();
        let root = f.root();
        let _held = root.lock().unwrap();
        let peer = f.root();
        let lock = peer.open(LOCK, OFlags::RDWR).unwrap();
        assert_eq!(
            nix::fcntl::flock(
                lock.as_raw_fd(),
                nix::fcntl::FlockArg::LockExclusiveNonblock
            ),
            Err(nix::errno::Errno::EWOULDBLOCK)
        );
    }
    #[test]
    fn foreign_bytes_modes_links_and_parent_do_not_get_repaired() {
        for case in [
            "bytes",
            "mode",
            "symlink",
            "hardlink",
            "root",
            "unknown",
            "temporary",
        ] {
            let f = Fixture::new();
            let root = f.root();
            root.lock()
                .unwrap()
                .reserve(
                    &request(),
                    &TerminalInput::ModelVerified(subject()),
                    PriorEffect::Settled,
                    PriorChild::Gone,
                    None,
                )
                .unwrap();
            let path = f.path.join(names(1).1);
            match case {
                "bytes" => fs::write(&path, b"foreign").unwrap(),
                "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
                "symlink" => {
                    fs::rename(&path, f.path.join("retained")).unwrap();
                    symlink("retained", &path).unwrap()
                }
                "hardlink" => fs::hard_link(&path, f.path.join("alias")).unwrap(),
                "root" => fs::set_permissions(&f.path, fs::Permissions::from_mode(0o755)).unwrap(),
                "unknown" => fs::write(f.path.join("foreign-entry"), b"foreign").unwrap(),
                _ => fs::write(f.path.join(names(1).0), b"partial").unwrap(),
            }
            let before = fs::read(&path).unwrap();
            assert!(
                root.lock()
                    .and_then(|l| l.reserve(
                        &request(),
                        &TerminalInput::ModelVerified(subject()),
                        PriorEffect::Settled,
                        PriorChild::Gone,
                        None
                    ))
                    .is_err()
            );
            assert_eq!(
                fs::read(&path).unwrap(),
                before,
                "foreign bytes must be retained"
            );
        }
    }
    #[test]
    fn modeled_unknown_live_and_unsigned_inputs_cannot_reserve() {
        let f = Fixture::new();
        let root = f.root();
        let lock = root.lock().unwrap();
        assert!(matches!(
            lock.reserve(
                &request(),
                &TerminalInput::UnsignedOrUnknown,
                PriorEffect::Settled,
                PriorChild::Gone,
                None
            ),
            Err(Error::Model(Refusal::UnverifiedTerminal))
        ));
        assert!(matches!(
            lock.reserve(
                &request(),
                &TerminalInput::ModelVerified(subject()),
                PriorEffect::Unknown,
                PriorChild::Gone,
                None
            ),
            Err(Error::Model(Refusal::PriorUncertain))
        ));
        assert!(matches!(
            lock.reserve(
                &request(),
                &TerminalInput::ModelVerified(subject()),
                PriorEffect::Settled,
                PriorChild::Live,
                None
            ),
            Err(Error::Model(Refusal::PriorLive))
        ));
        assert!(!f.path.join(names(1).1).exists());
        assert!(!f.path.join(names(1).0).exists());
    }
    #[test]
    fn strict_codec_and_complete_eight_identity_record() {
        let f = Fixture::new();
        let root = f.root();
        let (l, _) = allocate(
            &LedgerV1 {
                version: 1,
                owner: "owner".into(),
                generation: 0,
                allocations: vec![],
            },
            &request(),
            &TerminalInput::ModelVerified(subject()),
            PriorEffect::Settled,
            PriorChild::Gone,
        )
        .unwrap();
        let r = Record::from_allocation(&root.root, &l.allocations[0]).unwrap();
        let bytes = encode(&r).unwrap();
        assert_eq!(decode(&bytes).unwrap(), r);
        assert_eq!(r.allocation().unwrap(), l.allocations[0]);
        for bad in [
            b"{}".to_vec(),
            [bytes.clone(), b"\n".to_vec()].concat(),
            vec![b' '; MAX_BYTES + 1],
        ] {
            assert!(decode(&bad).is_err())
        }
        let mut altered = r.clone();
        altered.stage = "ready".into();
        assert!(decode(&encode(&altered).unwrap()).is_err());
        let text = String::from_utf8(bytes).unwrap();
        let unknown = text.replacen("{", "{\"unknown\":1,", 1);
        assert!(decode(unknown.as_bytes()).is_err());
        let duplicate = text.replacen("{", "{\"schema\":\"other\",", 1);
        assert!(decode(duplicate.as_bytes()).is_err());
        let mut bad = r.clone();
        bad.request.version = 2;
        assert!(decode(&encode(&bad).unwrap()).is_err());
        bad = r.clone();
        bad.identities.command = bad.identities.actor.clone();
        assert!(decode(&encode(&bad).unwrap()).is_err());
        bad = r.clone();
        bad.request.pins.database = [0; 32];
        assert!(decode(&encode(&bad).unwrap()).is_err());
    }
    #[test]
    fn durable_chain_is_disjoint_and_missing_history_refuses() {
        let f = Fixture::new();
        let root = f.root();
        let OutcomeV1::Allocated(first) = root
            .lock()
            .unwrap()
            .reserve(
                &request(),
                &TerminalInput::ModelVerified(subject()),
                PriorEffect::Settled,
                PriorChild::Gone,
                None,
            )
            .unwrap()
        else {
            panic!("first allocation")
        };
        let predecessor = VerifiedTerminalV1 {
            version: 1,
            owner: "owner".into(),
            digest: [7; 32],
            generation: 1,
            identities: first.identities.clone(),
            pins: first.request.pins.clone(),
        };
        let second_request = RequestV1 {
            version: 1,
            owner: "owner".into(),
            key: "restart.two".into(),
            terminal_digest: predecessor.digest,
            pins: predecessor.pins.clone(),
        };
        let OutcomeV1::Allocated(second) = root
            .lock()
            .unwrap()
            .reserve(
                &second_request,
                &TerminalInput::ModelVerified(predecessor.clone()),
                PriorEffect::Settled,
                PriorChild::Gone,
                None,
            )
            .unwrap()
        else {
            panic!("second allocation")
        };
        assert_eq!(second.generation, 2);
        assert!(disjoint(&first.identities, &second.identities));
        assert!(disjoint(&subject().identities, &second.identities));
        drop(root);
        let root = f.root();
        assert_eq!(root.lock().unwrap().ledger().unwrap().generation, 2);
        assert!(matches!(
            root.lock().unwrap().reserve(
                &second_request,
                &TerminalInput::ModelVerified(predecessor),
                PriorEffect::Unknown,
                PriorChild::Unknown,
                None
            ),
            Ok(OutcomeV1::ExactReplay(_))
        ));
        fs::rename(f.path.join(names(1).1), f.path.join("retained-history")).unwrap();
        assert!(root.lock().unwrap().ledger().is_err());
        assert!(f.path.join(names(2).1).exists());
    }
    #[test]
    fn replaced_lock_and_canonical_foreign_identity_refuse() {
        let f = Fixture::new();
        let root = f.root();
        let lock = root.lock().unwrap();
        fs::rename(f.path.join(LOCK), f.path.join("retained-lock")).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(f.path.join(LOCK))
            .unwrap();
        assert!(lock.ledger().is_err());
        drop(lock);
        let f = Fixture::new();
        let root = f.root();
        root.lock()
            .unwrap()
            .reserve(
                &request(),
                &TerminalInput::ModelVerified(subject()),
                PriorEffect::Settled,
                PriorChild::Gone,
                None,
            )
            .unwrap();
        let path = f.path.join(names(1).1);
        let mut r = decode(&fs::read(&path).unwrap()).unwrap();
        r.identities.resource = "foreign.resource".into();
        let bytes = encode(&r).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert!(
            root.lock()
                .unwrap()
                .reserve(
                    &request(),
                    &TerminalInput::ModelVerified(subject()),
                    PriorEffect::Settled,
                    PriorChild::Gone,
                    None
                )
                .is_err()
        );
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}
