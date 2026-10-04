use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_store::{
    AuthorityActorRecord, AuthorityGrantRecord, AuthorityMutation, AuthorityPodRecord,
    AuthorityResourceRecord, AuthorityRightRecord, PodBayStore, StoreError,
};
use rusqlite::Connection;

struct Fixture {
    directory: PathBuf,
    database: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "podbay-policy-fence-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        Self {
            database: directory.join("store.sqlite"),
            directory,
        }
    }
    fn open(&self) -> PodBayStore {
        PodBayStore::open(&self.database).unwrap()
    }
    fn connection(&self) -> Connection {
        Connection::open(&self.database).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn actor(id: &str, generation: u64) -> AuthorityActorRecord {
    AuthorityActorRecord {
        scope_id: "scope.policy.fixture".into(),
        actor_id: id.into(),
        role: "worker".into(),
        origin: "user".into(),
        parent_actor_id: None,
        pod_id: None,
        pod_incarnation: None,
        credential_generation: generation,
        platform: "linux".into(),
        os_identity: "linux.uid.1000".into(),
        process_identity: format!("linux.pid.{}", 100 + generation),
        start_identity: 200 + generation,
        containment_identity: "/user.slice/policy.fixture".into(),
    }
}

fn grant() -> AuthorityGrantRecord {
    AuthorityGrantRecord {
        grant_id: 1,
        scope_id: "scope.policy.fixture".into(),
        actor_id: "actor.policy.fixture".into(),
        credential_generation: 1,
        mode: "controller".into(),
        remaining_delegation_depth: 0,
        rights: vec![AuthorityRightRecord {
            operation: "launch_pod".into(),
            target_kind: "scope".into(),
            target_id: "scope.policy.fixture".into(),
        }],
    }
}

fn mutate(store: &mut PodBayStore, revision: u64, mutation: AuthorityMutation) -> u64 {
    store
        .apply_authority_mutation(1, revision, mutation)
        .unwrap()
}

#[test]
fn v19_upgrade_mints_positive_epoch_and_no_historical_launch_policy_row() {
    let fixture = Fixture::new();
    drop(fixture.open());
    let connection = fixture.connection();
    connection
        .execute_batch(
            "DROP TABLE launch_policy_fences;
         DELETE FROM metadata WHERE key='policy_fence_epoch';
         UPDATE metadata SET value=7 WHERE key='authority_revision';
         PRAGMA user_version=19;",
        )
        .unwrap();
    drop(connection);
    let store = fixture.open();
    assert_eq!(store.policy_fence_epoch().unwrap(), 7);
    drop(store);
    let connection = fixture.connection();
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM launch_policy_fences", [], |row| {
            row.get(0)
        })
        .unwrap();
    // The rehearsal applies v20's policy epoch/table before advancing the
    // empty store through v21 and v22 without inventing historical rows.
    assert_eq!((version, count), (22, 0));
    drop(connection);
    assert_eq!(
        PodBayStore::open_existing_read_only(&fixture.database)
            .unwrap()
            .policy_fence_epoch()
            .unwrap(),
        7
    );
}

#[test]
fn v20_table_is_exact_and_cannot_invent_unbound_launch_or_zero_epoch() {
    let fixture = Fixture::new();
    drop(fixture.open());
    let connection = fixture.connection();
    connection.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    assert!(
        connection
            .execute(
                "INSERT INTO launch_policy_fences(command_rowid,store_lineage,
           policy_fence_epoch,admission_authority_revision)
         VALUES(1,(SELECT lineage FROM store_identity WHERE singleton=1),1,1)",
                [],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "UPDATE metadata SET value=0 WHERE key='policy_fence_epoch'",
                [],
            )
            .is_ok()
    );
    drop(connection);
    assert!(matches!(
        PodBayStore::open_existing_read_only(&fixture.database),
        Err(StoreError::Conflict(
            "v20 policy fence epoch is absent or invalid"
        ))
    ));
    let connection = fixture.connection();
    connection
        .execute_batch(
            "UPDATE metadata SET value=1 WHERE key='policy_fence_epoch';
         DROP TABLE launch_policy_fences;
         CREATE TABLE launch_policy_fences(command_rowid INTEGER PRIMARY KEY) STRICT;",
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        PodBayStore::open(&fixture.database),
        Err(StoreError::Conflict(
            "v20 launch policy fence schema differs"
        ))
    ));
}

#[test]
fn malformed_v19_to_v20_preexisting_table_refuses_without_partial_epoch() {
    let fixture = Fixture::new();
    drop(fixture.open());
    let connection = fixture.connection();
    connection
        .execute_batch(
            "DROP TABLE launch_policy_fences;
         DELETE FROM metadata WHERE key='policy_fence_epoch';
         CREATE TABLE launch_policy_fences(command_rowid INTEGER PRIMARY KEY) STRICT;
         PRAGMA user_version=19;",
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        PodBayStore::open(&fixture.database),
        Err(StoreError::Conflict(
            "v20 policy fence schema name already exists"
        ))
    ));
    let connection = fixture.connection();
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    let epoch_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM metadata WHERE key='policy_fence_epoch'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((version, epoch_count), (19, 0));
}

#[test]
fn old_version_with_exact_empty_v20_table_cannot_lower_policy_below_migration_floor() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let mut revision = store.begin_authority_replay(0, 1).unwrap().revision;
    revision = mutate(
        &mut store,
        revision,
        AuthorityMutation::PutActor(actor("actor.policy.fixture", 1)),
    );
    revision = mutate(
        &mut store,
        revision,
        AuthorityMutation::PutPod(AuthorityPodRecord {
            scope_id: "scope.policy.fixture".into(),
            pod_id: "pod.policy.one".into(),
            incarnation: 1,
        }),
    );
    assert!(revision > store.policy_fence_epoch().unwrap());
    drop(store);
    fixture
        .connection()
        .execute_batch("PRAGMA user_version=19;")
        .unwrap();
    let reopened = fixture.open();
    assert_eq!(reopened.policy_fence_epoch().unwrap(), revision);
}

#[test]
fn additive_topology_actor_verifier_and_grant_hold_policy_epoch() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    assert_eq!(store.policy_fence_epoch().unwrap(), 1);
    let replay = store.begin_authority_replay(0, 1).unwrap();
    let policy = store.policy_fence_epoch().unwrap();
    assert_eq!(policy, 2);
    let mut revision = replay.revision;
    revision = mutate(
        &mut store,
        revision,
        AuthorityMutation::PutPod(AuthorityPodRecord {
            scope_id: "scope.policy.fixture".into(),
            pod_id: "pod.policy.one".into(),
            incarnation: 1,
        }),
    );
    revision = mutate(
        &mut store,
        revision,
        AuthorityMutation::PutResource(AuthorityResourceRecord {
            scope_id: "scope.policy.fixture".into(),
            resource_id: "resource.policy.one".into(),
            pod_id: "pod.policy.one".into(),
            pod_incarnation: 1,
            resource_epoch: 1,
            input_epoch: 1,
        }),
    );
    let actor = actor("actor.policy.fixture", 1);
    revision = mutate(
        &mut store,
        revision,
        AuthorityMutation::PutActor(actor.clone()),
    );
    revision = store
        .register_actor_verifier_from_trusted_host(1, revision, &actor, [7; 32])
        .unwrap();
    revision = mutate(&mut store, revision, AuthorityMutation::PutGrant(grant()));
    revision = mutate(
        &mut store,
        revision,
        AuthorityMutation::PutPod(AuthorityPodRecord {
            scope_id: "scope.policy.fixture".into(),
            pod_id: "pod.policy.two".into(),
            incarnation: 1,
        }),
    );
    assert!(revision > replay.revision);
    assert_eq!(store.policy_fence_epoch().unwrap(), policy);
}

#[test]
fn revocation_replacement_and_owner_takeover_advance_policy_epoch_atomically() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let mut revision = store.begin_authority_replay(0, 1).unwrap().revision;
    let actor = actor("actor.policy.fixture", 1);
    revision = mutate(
        &mut store,
        revision,
        AuthorityMutation::PutActor(actor.clone()),
    );
    revision = store
        .register_actor_verifier_from_trusted_host(1, revision, &actor, [7; 32])
        .unwrap();
    revision = mutate(&mut store, revision, AuthorityMutation::PutGrant(grant()));
    assert_eq!(store.policy_fence_epoch().unwrap(), 2);
    revision = mutate(&mut store, revision, AuthorityMutation::RevokeGrant(1));
    assert_eq!(store.policy_fence_epoch().unwrap(), 3);
    let mut next_actor = actor.clone();
    next_actor.credential_generation = 2;
    next_actor.process_identity = "linux.pid.202".into();
    next_actor.start_identity = 302;
    revision = mutate(
        &mut store,
        revision,
        AuthorityMutation::PutActor(next_actor.clone()),
    );
    assert_eq!(store.policy_fence_epoch().unwrap(), 4);
    revision = store
        .register_actor_verifier_from_trusted_host(1, revision, &next_actor, [8; 32])
        .unwrap();
    assert_eq!(store.policy_fence_epoch().unwrap(), 5);
    revision = store
        .revoke_actor_verifier_from_trusted_host(1, revision, &next_actor)
        .unwrap();
    assert_eq!(store.policy_fence_epoch().unwrap(), 6);
    let replay = store.begin_authority_replay(1, 2).unwrap();
    assert!(replay.revision > revision);
    assert_eq!(store.policy_fence_epoch().unwrap(), 7);
}

#[test]
fn changing_existing_pod_or_resource_fences_while_exact_repeat_does_not() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let mut revision = store.begin_authority_replay(0, 1).unwrap().revision;
    let pod = AuthorityPodRecord {
        scope_id: "scope.policy.fixture".into(),
        pod_id: "pod.policy.one".into(),
        incarnation: 1,
    };
    revision = mutate(&mut store, revision, AuthorityMutation::PutPod(pod.clone()));
    let mut resource = AuthorityResourceRecord {
        scope_id: "scope.policy.fixture".into(),
        resource_id: "resource.policy.one".into(),
        pod_id: "pod.policy.one".into(),
        pod_incarnation: 1,
        resource_epoch: 1,
        input_epoch: 1,
    };
    revision = mutate(
        &mut store,
        revision,
        AuthorityMutation::PutResource(resource.clone()),
    );
    assert_eq!(store.policy_fence_epoch().unwrap(), 2);
    revision = mutate(
        &mut store,
        revision,
        AuthorityMutation::PutResource(resource.clone()),
    );
    assert_eq!(store.policy_fence_epoch().unwrap(), 2);
    resource.input_epoch = 2;
    revision = mutate(
        &mut store,
        revision,
        AuthorityMutation::PutResource(resource),
    );
    assert_eq!(store.policy_fence_epoch().unwrap(), 3);
    revision = mutate(&mut store, revision, AuthorityMutation::PutPod(pod));
    assert_eq!(store.policy_fence_epoch().unwrap(), 3);
    mutate(
        &mut store,
        revision,
        AuthorityMutation::PutPod(AuthorityPodRecord {
            scope_id: "scope.policy.fixture".into(),
            pod_id: "pod.policy.one".into(),
            incarnation: 2,
        }),
    );
    assert_eq!(store.policy_fence_epoch().unwrap(), 4);
}

#[test]
fn policy_overflow_or_stale_cas_rolls_back_all_authority_rows_and_counters() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let mut revision = store.begin_authority_replay(0, 1).unwrap().revision;
    let actor = actor("actor.policy.fixture", 1);
    revision = mutate(&mut store, revision, AuthorityMutation::PutActor(actor));
    revision = mutate(&mut store, revision, AuthorityMutation::PutGrant(grant()));
    let before = store.authority_snapshot().unwrap();
    assert!(matches!(
        store.apply_authority_mutation(1, revision - 1, AuthorityMutation::RevokeGrant(1),),
        Err(StoreError::StaleEpoch)
    ));
    assert_eq!(store.authority_snapshot().unwrap(), before);
    let connection = fixture.connection();
    connection
        .execute(
            "UPDATE metadata SET value=?1 WHERE key='policy_fence_epoch'",
            [i64::MAX],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        store.apply_authority_mutation(1, revision, AuthorityMutation::RevokeGrant(1),),
        Err(StoreError::InvalidInput("policy fence epoch exhausted"))
    ));
    assert_eq!(store.authority_snapshot().unwrap(), before);
    assert_eq!(store.policy_fence_epoch().unwrap(), i64::MAX as u64);
}
