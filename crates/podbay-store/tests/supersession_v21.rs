use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_store::{PodBayStore, StoreError};

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
