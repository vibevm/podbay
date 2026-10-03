use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_core::{
    AttemptId, Epoch, OwnerEpoch, OwnerEpochWitness, PodFenceIdentity, PodId, ScopeId,
    StoreLineageId,
};
use podbay_store::{AuthorityMutation, AuthorityPodRecord, PodBayStore, SqliteOwnerEpochWitness};

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
            "podbay-peer-witness-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let database = directory.join("podbay.sqlite");
        Self {
            directory,
            database,
        }
    }
    fn lineage(&self) -> StoreLineageId {
        let connection = rusqlite::Connection::open_with_flags(
            &self.database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let lineage: String = connection
            .query_row(
                "SELECT lineage FROM store_identity WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        StoreLineageId::try_from(lineage.as_str()).unwrap()
    }
    fn identity(&self, pod: &str, incarnation: u64) -> PodFenceIdentity {
        PodFenceIdentity {
            scope_id: ScopeId::try_from("scope.main").unwrap(),
            pod_id: PodId::try_from(pod).unwrap(),
            attempt_id: AttemptId::try_from("attempt.main").unwrap(),
            incarnation: Epoch::new(incarnation).unwrap(),
            store_lineage: self.lineage(),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
fn register(store: &mut PodBayStore, epoch: u64, revision: u64) {
    store
        .apply_authority_mutation(
            epoch,
            revision,
            AuthorityMutation::PutPod(AuthorityPodRecord {
                scope_id: "scope.main".into(),
                pod_id: "pod.main".into(),
                incarnation: 1,
            }),
        )
        .unwrap();
}

#[test]
fn each_call_sees_new_committed_owner_epoch_without_recreating_witness() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let initial = store.begin_authority_replay(0, 1).unwrap();
    register(&mut store, 1, initial.revision);
    let identity = fixture.identity("pod.main", 1);
    let witness = SqliteOwnerEpochWitness::for_pod(&fixture.database, identity.clone());
    assert_eq!(
        witness.current_owner_epoch(&identity.store_lineage, &identity.scope_id),
        Some(OwnerEpoch::new(1).unwrap())
    );
    store.begin_authority_replay(1, 2).unwrap();
    assert_eq!(
        witness.current_owner_epoch(&identity.store_lineage, &identity.scope_id),
        Some(OwnerEpoch::new(2).unwrap())
    );
}

#[test]
fn lineage_scope_and_registered_pod_incarnation_must_all_match() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let initial = store.begin_authority_replay(0, 1).unwrap();
    let identity = fixture.identity("pod.main", 1);
    let witness = SqliteOwnerEpochWitness::for_pod(&fixture.database, identity.clone());
    assert_eq!(
        witness.current_owner_epoch(&identity.store_lineage, &identity.scope_id),
        None
    );
    register(&mut store, 1, initial.revision);
    assert_eq!(
        witness.current_owner_epoch(&identity.store_lineage, &identity.scope_id),
        Some(OwnerEpoch::new(1).unwrap())
    );
    assert_eq!(
        witness.current_owner_epoch(
            &StoreLineageId::try_from("store.foreign").unwrap(),
            &identity.scope_id
        ),
        None
    );
    assert_eq!(
        witness.current_owner_epoch(
            &identity.store_lineage,
            &ScopeId::try_from("scope.foreign").unwrap()
        ),
        None
    );
    let wrong_pod =
        SqliteOwnerEpochWitness::for_pod(&fixture.database, fixture.identity("pod.other", 1));
    assert_eq!(
        wrong_pod.current_owner_epoch(&identity.store_lineage, &identity.scope_id),
        None
    );
    let wrong_incarnation =
        SqliteOwnerEpochWitness::for_pod(&fixture.database, fixture.identity("pod.main", 2));
    assert_eq!(
        wrong_incarnation.current_owner_epoch(&identity.store_lineage, &identity.scope_id),
        None
    );

    // A copied request identity cannot make a different physical database's
    // committed lineage authoritative, even with the same scope and pod row.
    let other = Fixture::new();
    let mut other_store = PodBayStore::open(&other.database).unwrap();
    let other_initial = other_store.begin_authority_replay(0, 1).unwrap();
    register(&mut other_store, 1, other_initial.revision);
    let foreign_database = SqliteOwnerEpochWitness::for_pod(&other.database, identity.clone());
    assert_eq!(
        foreign_database.current_owner_epoch(&identity.store_lineage, &identity.scope_id),
        None
    );
}

#[test]
fn missing_or_unavailable_database_fails_closed_without_creation() {
    let fixture = Fixture::new();
    PodBayStore::open(&fixture.database).unwrap();
    let identity = fixture.identity("pod.main", 1);
    let missing = fixture.directory.join("missing.sqlite");
    let witness = SqliteOwnerEpochWitness::for_pod(&missing, identity.clone());
    assert_eq!(
        witness.current_owner_epoch(&identity.store_lineage, &identity.scope_id),
        None
    );
    assert!(!missing.exists());
    let unavailable = SqliteOwnerEpochWitness::for_pod(&fixture.directory, identity.clone());
    assert_eq!(
        unavailable.current_owner_epoch(&identity.store_lineage, &identity.scope_id),
        None
    );
}
