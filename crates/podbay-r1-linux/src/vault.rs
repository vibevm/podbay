//! Descriptor observations only. Neither these checks nor a successful native
//! fixture inspection can construct the uninhabited cold-origin permit.
use crate::sys;
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Identity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
}
impl Identity {
    fn of(m: &Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
        }
    }
}
#[derive(Debug)]
pub(crate) enum Refusal {
    Path,
    Owner,
    Mode,
    Kind,
    Links,
    Identity,
    Companion,
    Io(io::Error),
}
impl From<io::Error> for Refusal {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
pub(crate) struct Subject {
    pub(crate) source: Identity,
    pub(crate) lock: Identity,
    pub(crate) owner: u32,
}
struct Link {
    parent: File,
    name: OsString,
    file: File,
    metadata: Metadata,
    directory_policy: Option<(u32, bool)>,
}
pub(crate) struct Observation {
    links: Vec<Link>,
    state: File,
    subject: Subject,
}

fn directory(m: &Metadata, uid: u32, exact_private: bool) -> Result<(), Refusal> {
    if !m.is_dir() {
        return Err(Refusal::Kind);
    }
    if m.uid() != uid || m.gid() != uid {
        return Err(Refusal::Owner);
    }
    if (exact_private && m.mode() & 0o7777 != 0o700) || (!exact_private && m.mode() & 0o022 != 0) {
        return Err(Refusal::Mode);
    }
    Ok(())
}
fn regular(m: &Metadata, uid: u32, expected: Identity) -> Result<(), Refusal> {
    if !m.is_file() {
        return Err(Refusal::Kind);
    }
    if m.uid() != uid || m.gid() != uid {
        return Err(Refusal::Owner);
    }
    if m.mode() & 0o7777 != 0o600 {
        return Err(Refusal::Mode);
    }
    if m.nlink() != 1 {
        return Err(Refusal::Links);
    }
    if Identity::of(m) != expected {
        return Err(Refusal::Identity);
    }
    Ok(())
}
fn companions(state: &File) -> Result<(), Refusal> {
    for name in [
        "stage.sqlite",
        "db.sqlite-wal",
        "db.sqlite-shm",
        "db.sqlite-journal",
    ] {
        match sys::metadata_at(state, OsStr::new(name)) {
            Ok(_) => return Err(Refusal::Companion),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => (),
            Err(error) => return Err(Refusal::Io(error)),
        }
    }
    Ok(())
}
fn named(
    links: &mut Vec<Link>,
    parent: &File,
    name: &OsStr,
    directory_policy: Option<(u32, bool)>,
) -> Result<File, Refusal> {
    let file = if directory_policy.is_some() {
        sys::directory_at(parent, name)?
    } else {
        sys::metadata_at(parent, name)?
    };
    let metadata = file.metadata()?;
    // The retained snapshot is the reference for recheck. Validate it before
    // a transient chmod/chown can make a later metadata read look acceptable.
    if let Some((uid, exact_private)) = directory_policy {
        directory(&metadata, uid, exact_private)?;
    }
    let result = file.try_clone()?;
    links.push(Link {
        parent: parent.try_clone()?,
        name: name.to_owned(),
        file,
        metadata,
        directory_policy,
    });
    Ok(result)
}

/// Opens metadata descriptors only. Root policy is fixed here; path traversal
/// is component-relative with retained named-parent bindings and no repairs.
pub(crate) fn inspect_protected_vault(
    path: &Path,
    subject: Subject,
) -> Result<Observation, Refusal> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.len() > 4096
        || bytes.len() < 2
        || bytes[0] != b'/'
        || bytes.contains(&0)
        || bytes.contains(&b'\\')
    {
        return Err(Refusal::Path);
    }
    let components: Vec<_> = bytes[1..].split(|b| *b == b'/').collect();
    if components.len() > 64
        || components
            .iter()
            .any(|c| c.is_empty() || *c == b"." || *c == b"..")
    {
        return Err(Refusal::Path);
    }
    let mut parent = sys::root()?;
    directory(&parent.metadata()?, 0, false)?;
    let mut links = Vec::new();
    for (index, name) in components.iter().enumerate() {
        use std::os::unix::ffi::OsStrExt;
        parent = named(
            &mut links,
            &parent,
            OsStr::from_bytes(name),
            Some((0, index + 1 == components.len())),
        )?;
        directory(&parent.metadata()?, 0, index + 1 == components.len())?;
    }
    inspect_state(links, parent, subject)
}

fn inspect_state(
    mut links: Vec<Link>,
    vault: File,
    subject: Subject,
) -> Result<Observation, Refusal> {
    if subject.owner == 0 || subject.source == subject.lock {
        return Err(Refusal::Identity);
    }
    let state = named(
        &mut links,
        &vault,
        OsStr::new("state"),
        Some((subject.owner, true)),
    )?;
    directory(&state.metadata()?, subject.owner, true)?;
    let device = vault.metadata()?.dev();
    if state.metadata()?.dev() != device
        || subject.source.device != device
        || subject.lock.device != device
    {
        return Err(Refusal::Identity);
    }
    for (name, expected) in [
        ("db.sqlite", subject.source),
        ("db.sqlite.manager.lock", subject.lock),
    ] {
        let file = named(&mut links, &state, OsStr::new(name), None)?;
        regular(&file.metadata()?, subject.owner, expected)?;
    }
    companions(&state)?;
    let result = Observation {
        links,
        state,
        subject,
    };
    result.recheck()?;
    Ok(result)
}

impl Observation {
    pub(crate) fn recheck(&self) -> Result<(), Refusal> {
        for link in &self.links {
            let now = sys::metadata_at(&link.parent, &link.name)?.metadata()?;
            let held = link.file.metadata()?;
            if let Some((uid, exact_private)) = link.directory_policy {
                directory(&link.metadata, uid, exact_private)?;
                directory(&now, uid, exact_private)?;
                directory(&held, uid, exact_private)?;
            }
            if Identity::of(&now) != Identity::of(&link.metadata)
                || Identity::of(&held) != Identity::of(&link.metadata)
                || now.mode() != link.metadata.mode()
                || now.uid() != link.metadata.uid()
                || now.gid() != link.metadata.gid()
            {
                return Err(Refusal::Identity);
            }
            if link.directory_policy.is_none() {
                regular(&now, self.subject.owner, Identity::of(&link.metadata))?;
                if now.size() != link.metadata.size()
                    || now.mtime_nsec() != link.metadata.mtime_nsec()
                    || now.mtime() != link.metadata.mtime()
                    || now.ctime_nsec() != link.metadata.ctime_nsec()
                    || now.ctime() != link.metadata.ctime()
                {
                    return Err(Refusal::Identity);
                }
            }
        }
        companions(&self.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture {
        path: std::path::PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            assert_ne!(
                sys::uids().0,
                0,
                "native fixture tests require ordinary UID"
            );
            let path = std::env::temp_dir().join(format!(
                "podbay-r1-enforcer-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            fs::create_dir(path.join("vault")).unwrap();
            fs::create_dir(path.join("vault/state")).unwrap();
            for name in ["vault", "vault/state"] {
                fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o700)).unwrap();
            }
            for name in ["db.sqlite", "db.sqlite.manager.lock"] {
                fs::write(
                    path.join("vault/state").join(name),
                    b"inert private specimen",
                )
                .unwrap();
                fs::set_permissions(
                    path.join("vault/state").join(name),
                    fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }
            Self { path }
        }
        fn subject(&self) -> Subject {
            Subject {
                source: Identity::of(
                    &fs::metadata(self.path.join("vault/state/db.sqlite")).unwrap(),
                ),
                lock: Identity::of(
                    &fs::metadata(self.path.join("vault/state/db.sqlite.manager.lock")).unwrap(),
                ),
                owner: sys::uids().0,
            }
        }
        fn inspect_metadata_only(&self) -> Result<Observation, Refusal> {
            // The ordinary-owned anchor is only a native descriptor control.
            // It deliberately does not call/claim the root-vault entry.
            let anchor = sys::fixture_anchor(&self.path)?;
            let mut links = Vec::new();
            let vault = named(
                &mut links,
                &anchor,
                OsStr::new("vault"),
                Some((sys::uids().0, true)),
            )?;
            directory(&vault.metadata()?, sys::uids().0, true)?;
            inspect_state(links, vault, self.subject())
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }

    #[test]
    fn root_entry_rejects_user_fixture_and_bad_paths() {
        let f = Fixture::new();
        assert!(inspect_protected_vault(&f.path.join("vault"), f.subject()).is_err());
        for path in [
            "relative",
            "/tmp/../vault",
            "/tmp//vault",
            "/tmp/./vault",
            "/tmp/vault/",
        ] {
            assert!(matches!(
                inspect_protected_vault(Path::new(path), f.subject()),
                Err(Refusal::Path)
            ));
        }
    }
    #[test]
    fn native_symlinks_hardlinks_modes_and_companions_refuse() {
        for variant in [
            "symlink",
            "parent-symlink",
            "hardlink",
            "mode",
            "companion",
            "directory",
        ] {
            let f = Fixture::new();
            let state = f.path.join("vault/state");
            match variant {
                "symlink" => {
                    fs::rename(state.join("db.sqlite"), state.join("held")).unwrap();
                    symlink("held", state.join("db.sqlite")).unwrap();
                }
                "parent-symlink" => {
                    fs::rename(f.path.join("vault"), f.path.join("held-vault")).unwrap();
                    symlink("held-vault", f.path.join("vault")).unwrap();
                }
                "hardlink" => fs::hard_link(state.join("db.sqlite"), state.join("alias")).unwrap(),
                "mode" => {
                    fs::set_permissions(state.join("db.sqlite"), fs::Permissions::from_mode(0o640))
                        .unwrap()
                }
                "companion" => fs::write(state.join("db.sqlite-wal"), b"foreign").unwrap(),
                _ => {
                    fs::remove_file(state.join("db.sqlite")).unwrap();
                    fs::create_dir(state.join("db.sqlite")).unwrap();
                }
            }
            assert!(f.inspect_metadata_only().is_err(), "{variant}");
        }
    }
    #[test]
    fn invalid_directory_snapshot_cannot_be_laundered_by_transient_valid_mode() {
        let fixture = Fixture::new();
        let vault_path = fixture.path.join("vault");
        let anchor = sys::fixture_anchor(&fixture.path).unwrap();
        let uid = sys::uids().0;
        fs::set_permissions(&vault_path, fs::Permissions::from_mode(0o755)).unwrap();

        // The production named() path must reject the invalid retained snapshot,
        // regardless of a later chmod that might make a separate read valid.
        let mut links = Vec::new();
        assert!(matches!(
            named(&mut links, &anchor, OsStr::new("vault"), Some((uid, true))),
            Err(Refusal::Mode)
        ));
        assert!(links.is_empty());

        // Reproduce the old check/read/check interleaving with real metadata:
        // invalid capture, transient valid policy read, then invalid again.
        let file = sys::directory_at(&anchor, OsStr::new("vault")).unwrap();
        let captured = file.metadata().unwrap();
        fs::set_permissions(&vault_path, fs::Permissions::from_mode(0o700)).unwrap();
        directory(&file.metadata().unwrap(), uid, true).unwrap();
        fs::set_permissions(&vault_path, fs::Permissions::from_mode(0o755)).unwrap();
        let state = sys::directory_at(&file, OsStr::new("state")).unwrap();
        let observation = Observation {
            links: vec![Link {
                parent: anchor,
                name: OsStr::new("vault").to_owned(),
                file,
                metadata: captured,
                directory_policy: Some((uid, true)),
            }],
            state,
            subject: fixture.subject(),
        };
        assert!(matches!(observation.recheck(), Err(Refusal::Mode)));
    }
    #[test]
    fn retained_parent_and_source_replacement_refuse() {
        let f = Fixture::new();
        let observation = f.inspect_metadata_only().unwrap();
        fs::rename(f.path.join("vault"), f.path.join("old-vault")).unwrap();
        fs::create_dir(f.path.join("vault")).unwrap();
        assert!(observation.recheck().is_err());
        let g = Fixture::new();
        let observation = g.inspect_metadata_only().unwrap();
        fs::rename(
            g.path.join("vault/state/db.sqlite"),
            g.path.join("vault/state/old"),
        )
        .unwrap();
        fs::write(g.path.join("vault/state/db.sqlite"), b"foreign").unwrap();
        assert!(observation.recheck().is_err());
    }
    #[test]
    fn metadata_fd_cannot_read_source_and_companion_drift_is_seen() {
        use std::io::Read;
        let f = Fixture::new();
        let observation = f.inspect_metadata_only().unwrap();
        let mut leaf = sys::metadata_at(&observation.state, OsStr::new("db.sqlite")).unwrap();
        assert_eq!(
            leaf.read(&mut [0u8; 1]).unwrap_err().raw_os_error(),
            Some(libc::EBADF)
        );
        fs::write(f.path.join("vault/state/stage.sqlite"), b"foreign").unwrap();
        assert!(matches!(observation.recheck(), Err(Refusal::Companion)));
    }
}
