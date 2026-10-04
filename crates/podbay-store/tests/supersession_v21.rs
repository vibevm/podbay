use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_store::{AuthorityMutation, AuthorityPodRecord, PodBayStore, StoreError};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "podbay-v21-supersession-{}-{nonce}",
            std::process::id(),
        ));
        fs::create_dir_all(&directory).unwrap();
        Self(directory.join("store.sqlite"))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(self.0.parent().unwrap());
    }
}

fn downgrade_empty_v21_to_v20(path: &PathBuf) {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .execute_batch(
            "DROP INDEX codex_later_turns_session_v22;
         DROP TABLE codex_later_turns;
         DROP INDEX rebind_supersession_latest_v21;
         DROP TABLE rebind_supersession_resources;
         DROP TABLE rebind_supersession_attempts;
         PRAGMA user_version=20;",
        )
        .unwrap();
}

#[test]
fn fresh_v22_and_empty_v20_upgrade_create_no_recovery_evidence() {
    let fixture = Fixture::new();
    drop(PodBayStore::open(&fixture.0).unwrap());
    let read_only = PodBayStore::open_existing_read_only(&fixture.0).unwrap();
    drop(read_only);
    downgrade_empty_v21_to_v20(&fixture.0);
    drop(PodBayStore::open(&fixture.0).unwrap());
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    let attempts: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM rebind_supersession_attempts",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let resources: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM rebind_supersession_resources",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((version, attempts, resources), (22, 0, 0));
}

#[test]
fn occupied_v20_refuses_upgrade_without_changing_bytes_or_version() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.0).unwrap();
    store.advance_owner_epoch(0, 1).unwrap();
    store
        .apply_authority_mutation(
            1,
            0,
            AuthorityMutation::PutPod(AuthorityPodRecord {
                scope_id: "scope.fixture".into(),
                pod_id: "pod.fixture".into(),
                incarnation: 1,
            }),
        )
        .unwrap();
    drop(store);
    downgrade_empty_v21_to_v20(&fixture.0);
    let database = fs::read(&fixture.0).unwrap();
    let wal = fixture.0.with_extension("sqlite-wal");
    let wal_bytes = fs::read(&wal).ok();
    assert!(matches!(
        PodBayStore::open(&fixture.0),
        Err(StoreError::Conflict(
            "v20 launch state requires attested quiescence before v21 migration"
        ))
    ));
    assert_eq!(fs::read(&fixture.0).unwrap(), database);
    assert_eq!(fs::read(&wal).ok(), wal_bytes);
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 20);
    assert!(matches!(
        PodBayStore::open_existing_read_only(&fixture.0),
        Err(StoreError::UnsupportedSchema(20))
    ));
}

#[test]
fn v21_schema_mismatch_refuses_without_repair() {
    let fixture = Fixture::new();
    drop(PodBayStore::open(&fixture.0).unwrap());
    let connection = rusqlite::Connection::open(&fixture.0).unwrap();
    connection
        .execute_batch(
            "DROP INDEX rebind_supersession_latest_v21;
         CREATE INDEX rebind_supersession_latest_v21
           ON rebind_supersession_attempts(scope_id);",
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        PodBayStore::open_existing_read_only(&fixture.0),
        Err(StoreError::Conflict("v21 supersession schema differs"))
    ));
    assert!(matches!(
        PodBayStore::open(&fixture.0),
        Err(StoreError::Conflict("v21 supersession schema differs"))
    ));
}
