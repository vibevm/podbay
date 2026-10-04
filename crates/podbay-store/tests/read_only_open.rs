use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_store::{PodBayStore, StoreError};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "podbay-read-only-open-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
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

#[test]
fn pod_read_only_open_preserves_writer_state_and_refuses_mutation() {
    let fixture = Fixture::new();
    let database = fixture.database();
    let mut writer = PodBayStore::open(&database).unwrap();
    writer.advance_owner_epoch(0, 1).unwrap();
    drop(writer);

    let mut observer = PodBayStore::open_existing_read_only(&database).unwrap();
    assert_eq!(observer.owner_epoch().unwrap(), 1);
    assert!(observer.advance_owner_epoch(1, 2).is_err());
    drop(observer);

    let writer = PodBayStore::open(&database).unwrap();
    assert_eq!(writer.owner_epoch().unwrap(), 1);
}

#[test]
fn pod_read_only_open_never_creates_or_migrates_a_store() {
    let fixture = Fixture::new();
    let absent = fixture.0.join("absent").join("state.sqlite");
    assert!(PodBayStore::open_existing_read_only(&absent).is_err());
    assert!(!absent.exists());
    assert!(!absent.parent().unwrap().exists());
    assert!(matches!(
        PodBayStore::open_existing_read_only("relative.sqlite"),
        Err(StoreError::InvalidInput(_))
    ));

    let database = fixture.database();
    drop(PodBayStore::open(&database).unwrap());
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection.pragma_update(None, "user_version", 13).unwrap();
    drop(connection);
    assert!(matches!(
        PodBayStore::open_existing_read_only(&database),
        Err(StoreError::UnsupportedSchema(13))
    ));
    let connection = rusqlite::Connection::open(&database).unwrap();
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 13);
}
