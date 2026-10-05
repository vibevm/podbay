use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_store::{PodBayStore, StoreError};
use rusqlite::{Connection, OpenFlags};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "podbay-current-schema-{}-{nonce}",
            std::process::id(),
        ));
        fs::create_dir(&directory).unwrap();
        Self(directory)
    }

    fn database(&self) -> PathBuf {
        self.0.join("state.sqlite")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn read_only(path: &PathBuf) -> Connection {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
}

#[test]
fn fresh_open_creates_current_v23_directly_and_reopen_preserves_identity() {
    let fixture = Fixture::new();
    let path = fixture.database();
    assert!(!path.exists());
    let first = PodBayStore::open(&path).unwrap();
    assert_eq!(first.owner_epoch().unwrap(), 0);
    assert_eq!(first.policy_fence_epoch().unwrap(), 1);
    drop(first);
    let header = fs::read(&path).unwrap();
    assert_eq!(&header[..16], b"SQLite format 3\0");
    assert_eq!(u32::from_be_bytes(header[60..64].try_into().unwrap()), 24);

    let connection = read_only(&path);
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 24);
    let lineage: String = connection
        .query_row(
            "SELECT lineage FROM store_identity WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(lineage.len(), 32);
    for table in [
        "runtime_sessions",
        "launch_policy_fences",
        "rebind_supersession_attempts",
        "codex_later_turns",
        "codex_native_sources",
        "codex_native_evidence",
        "codex_native_conflicts",
    ] {
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "{table}");
    }
    drop(connection);

    let second = PodBayStore::open(&path).unwrap();
    assert_eq!(second.policy_fence_epoch().unwrap(), 1);
    drop(second);
    let observer = PodBayStore::open_existing_read_only(&path).unwrap();
    assert_eq!(observer.owner_epoch().unwrap(), 0);
    drop(observer);
    let reopened_lineage: String = read_only(&path)
        .query_row(
            "SELECT lineage FROM store_identity WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(reopened_lineage, lineage);
}

#[test]
fn existing_v19_refuses_before_file_or_directory_mutation() {
    let fixture = Fixture::new();
    let path = fixture.database();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE legacy_marker(value TEXT NOT NULL) STRICT;
             INSERT INTO legacy_marker(value) VALUES('keep');
             PRAGMA user_version=19;",
        )
        .unwrap();
    drop(connection);
    let original = fs::read(&path).unwrap();
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    let entries = || {
        let mut names = fs::read_dir(&fixture.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        names.sort();
        names
    };
    let original_entries = entries();

    assert!(matches!(
        PodBayStore::open(&path),
        Err(StoreError::UnsupportedSchema(19))
    ));
    assert!(matches!(
        PodBayStore::open_existing_read_only(&path),
        Err(StoreError::UnsupportedSchema(19))
    ));
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
    assert_eq!(entries(), original_entries);
    let connection = read_only(&path);
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    let marker: String = connection
        .query_row("SELECT value FROM legacy_marker", [], |row| row.get(0))
        .unwrap();
    assert_eq!((version, marker.as_str()), (19, "keep"));
}

#[test]
fn every_retired_schema_version_refuses_without_repair() {
    let fixture = Fixture::new();
    for version in [0, 1, 18, 20, 21, 22] {
        let path = fixture.0.join(format!("old-{version}.sqlite"));
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("CREATE TABLE legacy_marker(value TEXT NOT NULL) STRICT;")
            .unwrap();
        connection
            .pragma_update(None, "user_version", version)
            .unwrap();
        drop(connection);
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            PodBayStore::open(&path),
            Err(StoreError::UnsupportedSchema(found)) if found == version
        ));
        assert!(
            fs::read(&path).unwrap() == before,
            "version {version} changed"
        );
    }
}

#[cfg(unix)]
#[test]
fn private_zero_byte_placeholder_initializes_in_place_and_shared_paths_refuse() {
    let fixture = Fixture::new();
    fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700)).unwrap();
    let path = fixture.database();
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.sync_all().unwrap();
    drop(file);
    let before = fs::symlink_metadata(&path).unwrap();
    let first = PodBayStore::open(&path).unwrap();
    assert_eq!(first.policy_fence_epoch().unwrap(), 1);
    drop(first);
    let after = fs::symlink_metadata(&path).unwrap();
    assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
    assert_eq!(after.mode() & 0o7777, 0o600);
    drop(PodBayStore::open(&path).unwrap());

    let shared = fixture.0.join("shared.sqlite");
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&shared)
        .unwrap();
    let hardlink = fixture.0.join("hardlink.sqlite");
    fs::hard_link(&shared, &hardlink).unwrap();
    assert!(matches!(
        PodBayStore::open(&hardlink),
        Err(StoreError::Conflict(
            "empty database placeholder is not private and stable"
        ))
    ));
    let alias = fixture.0.join("alias.sqlite");
    symlink(&shared, &alias).unwrap();
    assert!(PodBayStore::open(&alias).is_err());
    assert_eq!(fs::metadata(&shared).unwrap().len(), 0);

    let loose = fixture.0.join("loose.sqlite");
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&loose)
        .unwrap();
    assert!(matches!(
        PodBayStore::open(&loose),
        Err(StoreError::Conflict(
            "empty database placeholder is not private and stable"
        ))
    ));
    assert_eq!(fs::metadata(&loose).unwrap().len(), 0);
}

#[test]
fn v19_visible_only_in_wal_refuses_without_changing_durable_bytes() {
    let fixture = Fixture::new();
    let path = fixture.database();
    drop(PodBayStore::open(&path).unwrap());
    let writer = Connection::open(&path).unwrap();
    writer.pragma_update(None, "user_version", 19).unwrap();
    // Keep the writer open so the retired version remains in WAL while the
    // main database header still says 22.
    let header = fs::read(&path).unwrap();
    assert_eq!(u32::from_be_bytes(header[60..64].try_into().unwrap()), 24);
    let wal = PathBuf::from(format!("{}-wal", path.display()));
    let before = [fs::read(&path).unwrap(), fs::read(&wal).unwrap()];
    assert!(matches!(
        PodBayStore::open(&path),
        Err(StoreError::UnsupportedSchema(19))
    ));
    let after = [fs::read(&path).unwrap(), fs::read(&wal).unwrap()];
    for (name, (old, new)) in ["database", "wal"]
        .into_iter()
        .zip(before.iter().zip(after.iter()))
    {
        assert!(new == old, "{name} changed during refused open");
    }
    drop(writer);
}
