use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_store::{PodBayStore, StoreError};

struct Fixture {
    directory: PathBuf,
    database: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "podbay-manager-credential-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        Self {
            database: directory.join("store.sqlite"),
            directory,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn current_owner_claim_mints_separate_monotonic_manager_generation() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    assert!(matches!(
        store.current_manager_credential_claim(0),
        Err(StoreError::NotFound)
    ));
    let lineage = store.initial_cursor("scope.fixture").unwrap().store_lineage;
    store.begin_authority_replay(0, 1).unwrap();
    let first = store.current_manager_credential_claim(1).unwrap();
    assert_eq!(
        (
            first.store_lineage(),
            first.owner_epoch(),
            first.credential_epoch()
        ),
        (lineage.as_str(), 1, 1)
    );
    drop(store);

    let mut reopened = PodBayStore::open(&fixture.database).unwrap();
    assert_eq!(reopened.current_manager_credential_claim(1).unwrap(), first);
    reopened.begin_authority_replay(1, 2).unwrap();
    let second = reopened.current_manager_credential_claim(2).unwrap();
    assert_eq!((second.owner_epoch(), second.credential_epoch()), (2, 2));
    assert!(matches!(
        reopened.current_manager_credential_claim(1),
        Err(StoreError::StaleEpoch)
    ));
    reopened.advance_owner_epoch(2, 3).unwrap();
    assert!(
        matches!(
            reopened.current_manager_credential_claim(3),
            Err(StoreError::StaleEpoch)
        ),
        "raw owner advance must not mint a manager claim"
    );
}

#[test]
fn competing_owner_replays_have_exactly_one_claim() {
    let fixture = Fixture::new();
    drop(PodBayStore::open(&fixture.database).unwrap());
    let barrier = Arc::new(Barrier::new(2));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let database = fixture.database.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            let mut store = PodBayStore::open(database).unwrap();
            barrier.wait();
            store.begin_authority_replay(0, 1)
        }));
    }
    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(StoreError::StaleEpoch)))
            .count(),
        1
    );
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let claim = store.current_manager_credential_claim(1).unwrap();
    assert_eq!((claim.owner_epoch(), claim.credential_epoch()), (1, 1));
}

#[test]
fn failed_owner_replay_rolls_back_manager_credential_claim() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "INSERT INTO authority_pods(pod_id,scope_id,incarnation)
           VALUES('pod.fixture','scope.fixture',1);
         INSERT INTO target_epochs(scope_id,target_id,epoch)
           VALUES('scope.fixture','pod.fixture',2);",
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        store.begin_authority_replay(0, 1),
        Err(StoreError::StaleEpoch)
    ));
    assert_eq!(store.owner_epoch().unwrap(), 0);
    assert!(matches!(
        store.current_manager_credential_claim(0),
        Err(StoreError::NotFound)
    ));
}

#[test]
fn impossible_manager_credential_row_refuses_readback_and_next_claim() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    store.begin_authority_replay(0, 1).unwrap();
    store.begin_authority_replay(1, 2).unwrap();
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute(
            "UPDATE manager_credential_claims SET credential_epoch=1",
            [],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        store.current_manager_credential_claim(2),
        Err(StoreError::StaleEpoch)
    ));
    assert!(matches!(
        store.begin_authority_replay(2, 3),
        Err(StoreError::StaleEpoch)
    ));
    assert_eq!(store.owner_epoch().unwrap(), 2);
}

#[test]
fn v9_migration_has_no_fictitious_current_manager_claim() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    store.begin_authority_replay(0, 1).unwrap();
    let lineage = store.initial_cursor("scope.fixture").unwrap().store_lineage;
    drop(store);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch("DROP TABLE manager_peer_bindings; DROP TABLE manager_credential_claims; PRAGMA user_version=9;")
        .unwrap();
    drop(connection);

    let mut migrated = PodBayStore::open(&fixture.database).unwrap();
    assert!(matches!(
        migrated.current_manager_credential_claim(1),
        Err(StoreError::NotFound)
    ));
    assert_eq!(migrated.owner_epoch().unwrap(), 1);
    assert_eq!(
        migrated
            .initial_cursor("scope.fixture")
            .unwrap()
            .store_lineage,
        lineage
    );
    migrated.begin_authority_replay(1, 2).unwrap();
    let claim = migrated.current_manager_credential_claim(2).unwrap();
    assert_eq!((claim.owner_epoch(), claim.credential_epoch()), (2, 2));
}

#[test]
fn malformed_v10_name_refuses_migration_without_owner_change() {
    let fixture = Fixture::new();
    drop(PodBayStore::open(&fixture.database).unwrap());
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "DROP TABLE manager_peer_bindings;
         DROP TABLE manager_credential_claims;
         CREATE TABLE manager_credential_claims(singleton INTEGER PRIMARY KEY) STRICT;
         PRAGMA user_version=9;",
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        PodBayStore::open(&fixture.database),
        Err(StoreError::Conflict(
            "v10 manager credential schema name already exists"
        ))
    ));
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 9);
}
