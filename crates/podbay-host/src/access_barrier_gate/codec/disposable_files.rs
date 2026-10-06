//! Linux test-only filesystem mechanics. Readback is inert data, not admission.
use super::*;
use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags, openat, renameat_with, statat};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;

const MAX_GENERATIONS: u64 = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Readback {
    record: RecordV1,
    identity: FileIdentity,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Point {
    Created,
    PartialWrite,
    Written,
    FileSynced,
    Published,
    DirectorySynced,
    Readback,
}
#[derive(Debug)]
enum Error {
    Io(std::io::Error),
    Codec(CodecError),
    Refused(&'static str),
    Injected(Point),
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<CodecError> for Error {
    fn from(e: CodecError) -> Self {
        Self::Codec(e)
    }
}
impl From<rustix::io::Errno> for Error {
    fn from(e: rustix::io::Errno) -> Self {
        Self::Io(e.into())
    }
}

struct DisposableDirectory {
    directory: File,
    identity: FileIdentity,
    uid: u32,
    known: BTreeMap<u64, Readback>,
    restore_failed: bool,
}
fn id(m: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: m.dev(),
        inode: m.ino(),
    }
}
fn names(g: u64) -> Result<(String, String), Error> {
    if !(1..=MAX_GENERATIONS).contains(&g) {
        return Err(Error::Refused("disposable generation bound"));
    }
    Ok((
        format!("gate-v1-{g:020}.writing"),
        format!("gate-v1-{g:020}.record"),
    ))
}
fn fault(selected: Option<Point>, point: Point) -> Result<(), Error> {
    if selected == Some(point) {
        Err(Error::Injected(point))
    } else {
        Ok(())
    }
}

impl DisposableDirectory {
    fn pin(directory: File) -> Result<Self, Error> {
        let m = directory.metadata()?;
        let uid = rustix::process::geteuid().as_raw();
        if !m.is_dir() || m.uid() != uid || m.mode() & 0o7777 != 0o700 || m.nlink() == 0 {
            return Err(Error::Refused("unsafe disposable directory"));
        }
        Ok(Self {
            identity: id(&m),
            directory,
            uid,
            known: BTreeMap::new(),
            restore_failed: false,
        })
    }
    fn check(&self) -> Result<(), Error> {
        if self.restore_failed {
            return Err(Error::Refused("failed restore latched closed"));
        }
        let m = self.directory.metadata()?;
        if !m.is_dir()
            || id(&m) != self.identity
            || m.uid() != self.uid
            || m.mode() & 0o7777 != 0o700
            || m.nlink() == 0
        {
            return Err(Error::Refused("directory identity changed"));
        }
        Ok(())
    }
    fn metadata_matches(
        &self,
        file: &File,
        name: &str,
        expected: &FileIdentity,
    ) -> Result<(), Error> {
        self.check()?;
        let m = file.metadata()?;
        let named = statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if !m.is_file()
            || m.uid() != self.uid
            || m.mode() & 0o7777 != 0o600
            || m.nlink() != 1
            || id(&m) != *expected
            || named.st_dev as u64 != m.dev()
            || named.st_ino as u64 != m.ino()
        {
            return Err(Error::Refused("foreign or unsafe gate inode"));
        }
        Ok(())
    }
    fn absent(&self, name: &str) -> Result<(), Error> {
        match statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => Ok(()),
            Ok(_) => Err(Error::Refused("occupied writing entry")),
            Err(e) => Err(e.into()),
        }
    }
    fn open(&self, name: &str) -> Result<File, Error> {
        Ok(File::from(openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?))
    }
    fn read_exact(&self, pin: &Readback) -> Result<RecordV1, Error> {
        let (writing, name) = names(pin.record.durable.subject.generation)?;
        self.absent(&writing)?;
        let file = self.open(&name)?;
        self.metadata_matches(&file, &name, &pin.identity)?;
        if file.metadata()?.len() > MAX_BYTES as u64 {
            return Err(Error::Refused("oversized gate file"));
        }
        let mut bytes = Vec::new();
        (&file).take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes)?;
        self.metadata_matches(&file, &name, &pin.identity)?;
        if bytes != encode(&pin.record)? {
            return Err(Error::Refused("foreign gate bytes"));
        }
        let record = decode(&bytes)?;
        if record.parent != self.identity {
            return Err(Error::Refused("foreign gate parent"));
        }
        Ok(record)
    }
    fn verify_prefix(&self, g: u64) -> Result<(), Error> {
        self.verify_pin_prefix(&self.known, g)
    }
    fn verify_pin_prefix(&self, pins: &BTreeMap<u64, Readback>, g: u64) -> Result<(), Error> {
        let mut previous = None;
        for n in 1..g {
            let pin = pins
                .get(&n)
                .ok_or(Error::Refused("missing pinned predecessor"))?;
            let r = self.read_exact(pin)?;
            if let Some(p) = previous.as_ref() {
                check_next(p, &r)?;
            }
            previous = Some(r);
        }
        Ok(())
    }
    /// Reopens only caller-retained exact readback identities; matching-looking
    /// unknown files are never adopted. This is not a crash-survival authority.
    fn restore(&mut self, pins: &[Readback]) -> Result<(), Error> {
        let proposed = (|| {
            self.check()?;
            let mut proposed = BTreeMap::new();
            for p in pins {
                let g = p.record.durable.subject.generation;
                match proposed.entry(g) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(p.clone());
                    }
                    std::collections::btree_map::Entry::Occupied(_) => {
                        return Err(Error::Refused("duplicate generation pin"));
                    }
                }
            }
            // Restore cannot discard an already retained later boundary.
            if self
                .known
                .iter()
                .any(|(g, pin)| proposed.get(g) != Some(pin))
            {
                return Err(Error::Refused("restore drops or changes retained history"));
            }
            let maximum = proposed.keys().next_back().copied().unwrap_or(0);
            self.verify_pin_prefix(
                &proposed,
                maximum
                    .checked_add(1)
                    .ok_or(Error::Refused("generation overflow"))?,
            )?;
            Ok(proposed)
        })();
        match proposed {
            Ok(proposed) => {
                self.known = proposed;
                Ok(())
            }
            Err(error) => {
                self.restore_failed = true;
                Err(error)
            }
        }
    }
    fn publish(&mut self, record: &RecordV1, selected: Option<Point>) -> Result<Readback, Error> {
        self.check()?;
        let g = record.durable.subject.generation;
        let (writing, name) = names(g)?;
        let bytes = encode(record)?;
        if record.parent != self.identity {
            return Err(Error::Refused("foreign parent"));
        }
        self.verify_prefix(g)?;
        if g > 1 {
            check_next(
                &self
                    .known
                    .get(&(g - 1))
                    .ok_or(Error::Refused("missing predecessor"))?
                    .record,
                record,
            )?;
        }
        self.absent(&writing)?;
        if let Some(pin) = self.known.get(&g) {
            if pin.record != *record {
                return Err(Error::Refused("changed same-generation request"));
            }
            self.read_exact(pin)?;
            let file = self.open(&name)?;
            file.sync_all()?;
            self.directory.sync_all()?;
            self.read_exact(pin)?;
            return Ok(pin.clone());
        }
        // Existing final bytes without a retained inode pin cannot prove origin.
        match statat(&self.directory, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            Ok(_) => return Err(Error::Refused("unrecognized final inode")),
            Err(e) => return Err(e.into()),
        }
        let mut file = File::from(openat(
            &self.directory,
            writing.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        let pin = Readback {
            record: record.clone(),
            identity: id(&file.metadata()?),
        };
        self.metadata_matches(&file, &writing, &pin.identity)?;
        fault(selected, Point::Created)?;
        let split = bytes.len() / 2;
        file.write_all(&bytes[..split])?;
        fault(selected, Point::PartialWrite)?;
        file.write_all(&bytes[split..])?;
        fault(selected, Point::Written)?;
        file.sync_all()?;
        fault(selected, Point::FileSynced)?;
        self.metadata_matches(&file, &writing, &pin.identity)?;
        renameat_with(
            &self.directory,
            writing.as_str(),
            &self.directory,
            name.as_str(),
            RenameFlags::NOREPLACE,
        )?;
        // Retain exact inode even if post-publication durability/reporting fails.
        self.known.insert(g, pin.clone());
        fault(selected, Point::Published)?;
        self.directory.sync_all()?;
        fault(selected, Point::DirectorySynced)?;
        self.read_exact(&pin)?;
        fault(selected, Point::Readback)?;
        Ok(pin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
    use std::path::PathBuf;
    struct Fixture {
        path: PathBuf,
        adapter: DisposableDirectory,
    }
    impl Fixture {
        fn new() -> Self {
            let mut nonce = [0u8; 16];
            getrandom::fill(&mut nonce).unwrap();
            let name = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
            Self::new_parent(&format!("podbay-inert-gate-test-{name}"))
        }
        fn new_parent(name: &str) -> Self {
            assert!(!name.contains(['/', '\\']) && name.starts_with("podbay-inert-gate-test-"));
            // Portable exclusive parent creation; never reuse a preexisting
            // directory or depend on a machine-specific research hierarchy.
            let temporary = std::env::temp_dir();
            let temp_fd = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)
                .unwrap();
            let metadata = temp_fd.metadata().unwrap();
            let uid = rustix::process::geteuid().as_raw();
            assert!(metadata.is_dir());
            assert!(metadata.uid() == uid || metadata.uid() == 0);
            assert!(
                metadata.mode() & 0o022 == 0
                    || (metadata.uid() == 0 && metadata.mode() & 0o1000 != 0)
            );
            rustix::fs::mkdirat(&temp_fd, name, Mode::from_raw_mode(0o700)).unwrap();
            let parent_fd = File::from(
                openat(
                    &temp_fd,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .unwrap(),
            );
            let parent = DisposableDirectory::pin(parent_fd).unwrap();
            rustix::fs::mkdirat(&parent.directory, "fixture", Mode::from_raw_mode(0o700)).unwrap();
            let fd = File::from(
                openat(
                    &parent.directory,
                    "fixture",
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .unwrap(),
            );
            let path = temporary.join(name).join("fixture");
            Self {
                path,
                adapter: DisposableDirectory::pin(fd).unwrap(),
            }
        }
        fn record(&self) -> RecordV1 {
            let mut r = super::super::tests::initial();
            r.parent = self.adapter.identity.clone();
            r.durable.subject.source.device = r.parent.device;
            r.durable.subject.staging.device = r.parent.device;
            r.durable.subject.manager_lock.device = r.parent.device;
            r
        }
    }
    // Fixtures are deliberately retained, including failed/foreign files. There
    // is no automatic deletion, recursive cleanup or production path support.
    #[test]
    fn portable_fixture_creates_a_deliberately_absent_private_parent() {
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        let hex = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let name = format!("podbay-inert-gate-test-fresh-{hex}");
        let parent = std::env::temp_dir().join(&name);
        assert!(!parent.exists());
        let mut f = Fixture::new_parent(&name);
        assert_eq!(parent.metadata().unwrap().mode() & 0o7777, 0o700);
        let record = f.record();
        let pin = f.adapter.publish(&record, None).unwrap();
        assert_eq!(f.adapter.read_exact(&pin).unwrap(), record);
        assert!(parent.exists());
    }
    #[test]
    fn durable_retry_restore_and_chain_are_exact() {
        let mut f = Fixture::new();
        let r = f.record();
        let p = f.adapter.publish(&r, None).unwrap();
        assert_eq!(f.adapter.publish(&r, None).unwrap(), p);
        let n = super::super::tests::next(&r, Kind::ForwardProgress);
        let q = f.adapter.publish(&n, None).unwrap();
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&f.path)
            .unwrap();
        let mut reopened = DisposableDirectory::pin(file).unwrap();
        reopened.restore(&[p.clone(), q.clone()]).unwrap();
        assert_eq!(reopened.publish(&n, None).unwrap(), q);
        let mut changed = n;
        changed.durable.subject.request_digest = [9; 32];
        assert!(reopened.publish(&changed, None).is_err());
        let mut gap = r;
        gap.durable.subject.generation = 4;
        gap.kind = Kind::ForwardProgress;
        gap.previous_digest = [8; 32];
        assert!(reopened.publish(&gap, None).is_err());
    }
    #[test]
    fn every_interrupted_boundary_retains_closed_files() {
        for point in [
            Point::Created,
            Point::PartialWrite,
            Point::Written,
            Point::FileSynced,
            Point::Published,
            Point::DirectorySynced,
            Point::Readback,
        ] {
            let mut f = Fixture::new();
            let r = f.record();
            assert!(
                matches!(f.adapter.publish(&r,Some(point)),Err(Error::Injected(p)) if p==point)
            );
            let (writing, record) = names(1).unwrap();
            if matches!(
                point,
                Point::Created | Point::PartialWrite | Point::Written | Point::FileSynced
            ) {
                assert!(f.path.join(writing).exists());
                assert!(!f.path.join(record).exists());
                assert!(f.adapter.publish(&r, None).is_err());
            } else {
                assert!(!f.path.join(writing).exists());
                assert!(f.path.join(record).exists());
                f.adapter.publish(&r, None).unwrap();
            }
        }
    }
    #[test]
    fn symlinks_modes_foreign_bytes_and_replacement_inode_refuse() {
        for case in ["symlink", "mode", "bytes", "inode", "hardlink", "writing"] {
            let mut f = Fixture::new();
            let r = f.record();
            let p = f.adapter.publish(&r, None).unwrap();
            let (writing, name) = names(1).unwrap();
            let path = f.path.join(name);
            match case {
                "symlink" => {
                    fs::rename(&path, f.path.join("saved")).unwrap();
                    symlink("saved", &path).unwrap();
                }
                "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
                "bytes" => {
                    fs::write(&path, b"foreign").unwrap();
                }
                "inode" => {
                    let b = fs::read(&path).unwrap();
                    fs::rename(&path, f.path.join("saved")).unwrap();
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&path)
                        .unwrap()
                        .write_all(&b)
                        .unwrap();
                }
                "hardlink" => fs::hard_link(&path, f.path.join("alias")).unwrap(),
                _ => {
                    fs::write(f.path.join(writing), b"foreign").unwrap();
                }
            }
            assert!(f.adapter.read_exact(&p).is_err(), "{case}");
            assert!(f.adapter.publish(&r, None).is_err(), "{case}");
        }
    }
    #[test]
    fn unknown_final_and_wrong_parent_are_not_adopted() {
        let mut f = Fixture::new();
        let r = f.record();
        let (_, name) = names(1).unwrap();
        let b = encode(&r).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(f.path.join(name))
            .unwrap()
            .write_all(&b)
            .unwrap();
        assert!(f.adapter.publish(&r, None).is_err());
        let mut foreign = r;
        foreign.parent.inode += 1;
        assert!(f.adapter.publish(&foreign, None).is_err());
    }

    #[test]
    fn owner_directory_and_predecessor_changes_block_progress() {
        let mut f = Fixture::new();
        let r = f.record();
        f.adapter.publish(&r, None).unwrap();
        let n = super::super::tests::next(&r, Kind::ForwardProgress);
        let expected_uid = f.adapter.uid;
        // No privileged chown: change the expected owner to exercise mismatch.
        f.adapter.uid = expected_uid.wrapping_add(1);
        assert!(f.adapter.publish(&n, None).is_err());
        f.adapter.uid = expected_uid;
        fs::set_permissions(&f.path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(f.adapter.publish(&n, None).is_err());
        fs::set_permissions(&f.path, fs::Permissions::from_mode(0o700)).unwrap();
        let (_, first) = names(1).unwrap();
        // Retain, rather than delete, the exact predecessor to create a gap.
        fs::rename(f.path.join(first), f.path.join("retained-predecessor")).unwrap();
        assert!(f.adapter.publish(&n, None).is_err());
        let (_, second) = names(2).unwrap();
        assert!(!f.path.join(second).exists());
    }

    #[test]
    fn failed_restore_cannot_seed_rollback_before_retained_activation() {
        let mut f = Fixture::new();
        let initial = f.record();
        let p1 = f.adapter.publish(&initial, None).unwrap();
        let mut published = super::super::tests::next(&initial, Kind::ForwardProgress);
        published.durable.phase = Phase::Published;
        let _p2 = f.adapter.publish(&published, None).unwrap();
        let mut activated = super::super::tests::next(&published, Kind::ActivationRecorded);
        activated.durable.phase = Phase::Activated;
        activated.durable.activation = Activation::Present;
        let p3 = f.adapter.publish(&activated, None).unwrap();
        let (_, second) = names(2).unwrap();
        fs::rename(f.path.join(second), f.path.join("retained-published")).unwrap();
        let fd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&f.path)
            .unwrap();
        let mut reopened = DisposableDirectory::pin(fd).unwrap();
        assert!(reopened.restore(&[p1, p3]).is_err());
        assert!(reopened.known.is_empty());
        assert!(reopened.restore_failed);
        let mut rollback = super::super::tests::next(&initial, Kind::RollbackRequested);
        rollback.durable.direction = Direction::Rollback;
        assert!(reopened.publish(&rollback, None).is_err());
        let (_, second) = names(2).unwrap();
        assert!(!f.path.join(second).exists());
        let (_, third) = names(3).unwrap();
        assert!(f.path.join(third).exists());
    }

    #[test]
    fn duplicate_restore_pins_preserve_installed_map() {
        let mut f = Fixture::new();
        let r = f.record();
        let pin = f.adapter.publish(&r, None).unwrap();
        let before = f.adapter.known.clone();
        assert!(f.adapter.restore(&[pin.clone(), pin]).is_err());
        assert_eq!(f.adapter.known, before);
        assert!(f.adapter.publish(&r, None).is_err());
    }
}
