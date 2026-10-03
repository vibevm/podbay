use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_store::{
    AuthorityActorRecord, AuthorityGrantRecord, AuthorityMutation, AuthorityPodRecord,
    AuthorityRightRecord, PodBayStore, StoreError,
};

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
        let directory =
            std::env::temp_dir().join(format!("podbay-authority-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let database = directory.join("podbay.sqlite");
        Self {
            directory,
            database,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn actor() -> AuthorityActorRecord {
    AuthorityActorRecord {
        scope_id: "scope.main".into(),
        actor_id: "actor.worker".into(),
        role: "worker".into(),
        origin: "pod".into(),
        parent_actor_id: None,
        pod_id: Some("pod.worker".into()),
        pod_incarnation: Some(1),
        credential_generation: 1,
        platform: "linux".into(),
        os_identity: "linux.uid.1000".into(),
        process_identity: "linux.pid.123".into(),
        start_identity: 456,
        containment_identity: "/user.slice/pod-worker.scope".into(),
    }
}

fn unattached_actor(scope_id: &str) -> AuthorityActorRecord {
    let mut record = actor();
    record.scope_id = scope_id.into();
    record.pod_id = None;
    record.pod_incarnation = None;
    record.origin = "user".into();
    record
}

fn grant(
    scope_id: &str,
    actor_id: &str,
    operation: &str,
    target_kind: &str,
    target_id: &str,
) -> AuthorityGrantRecord {
    AuthorityGrantRecord {
        grant_id: 1,
        scope_id: scope_id.into(),
        actor_id: actor_id.into(),
        credential_generation: 1,
        mode: "controller".into(),
        remaining_delegation_depth: 0,
        rights: vec![AuthorityRightRecord {
            operation: operation.into(),
            target_kind: target_kind.into(),
            target_id: target_id.into(),
        }],
    }
}

#[test]
fn preissued_exact_launch_pod_grant_creates_no_pod_or_target_epoch() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    store.begin_authority_replay(0, 1).unwrap();
    let revision = store
        .apply_authority_mutation(
            1,
            1,
            AuthorityMutation::PutActor(unattached_actor("scope.main")),
        )
        .unwrap();
    let record = grant(
        "scope.main",
        "actor.worker",
        "launch_pod",
        "pod",
        "pod.proposed",
    );
    assert_eq!(
        store
            .apply_authority_mutation(1, revision, AuthorityMutation::PutGrant(record.clone()))
            .unwrap(),
        revision + 1
    );
    let snapshot = store.authority_snapshot().unwrap();
    assert_eq!(snapshot.grants, vec![record]);
    assert!(snapshot.pods.is_empty());
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let target_epochs: i64 = connection
        .query_row("SELECT COUNT(*) FROM target_epochs", [], |row| row.get(0))
        .unwrap();
    assert_eq!(target_epochs, 0);
}

#[test]
fn proposed_launch_grant_refuses_foreign_existing_pod() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    store.begin_authority_replay(0, 1).unwrap();
    let revision = store
        .apply_authority_mutation(
            1,
            1,
            AuthorityMutation::PutActor(unattached_actor("scope.main")),
        )
        .unwrap();
    let revision = store
        .apply_authority_mutation(
            1,
            revision,
            AuthorityMutation::PutPod(AuthorityPodRecord {
                scope_id: "scope.foreign".into(),
                pod_id: "pod.proposed".into(),
                incarnation: 1,
            }),
        )
        .unwrap();
    assert!(matches!(
        store.apply_authority_mutation(
            1,
            revision,
            AuthorityMutation::PutGrant(grant(
                "scope.main",
                "actor.worker",
                "launch_pod",
                "pod",
                "pod.proposed"
            ))
        ),
        Err(StoreError::WrongScope)
    ));
    let snapshot = store.authority_snapshot().unwrap();
    assert_eq!(snapshot.revision, revision);
    assert!(snapshot.grants.is_empty());
}

#[test]
fn absent_stop_pod_and_resource_rights_still_refuse() {
    for (operation, kind, target) in [
        ("stop_pod", "pod", "pod.proposed"),
        ("observe_resource", "resource", "resource.proposed"),
    ] {
        let fixture = Fixture::new();
        let mut store = PodBayStore::open(&fixture.database).unwrap();
        store.begin_authority_replay(0, 1).unwrap();
        let revision = store
            .apply_authority_mutation(
                1,
                1,
                AuthorityMutation::PutActor(unattached_actor("scope.main")),
            )
            .unwrap();
        assert!(matches!(
            store.apply_authority_mutation(
                1,
                revision,
                AuthorityMutation::PutGrant(grant(
                    "scope.main",
                    "actor.worker",
                    operation,
                    kind,
                    target
                ))
            ),
            Err(StoreError::WrongScope)
        ));
        assert!(store.authority_snapshot().unwrap().grants.is_empty());
    }
}

#[test]
fn proposed_launch_grant_requires_exact_actor_and_grant_scope() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    store.begin_authority_replay(0, 1).unwrap();
    let revision = store
        .apply_authority_mutation(
            1,
            1,
            AuthorityMutation::PutActor(unattached_actor("scope.main")),
        )
        .unwrap();
    for record in [
        grant(
            "scope.main",
            "actor.unknown",
            "launch_pod",
            "pod",
            "pod.proposed",
        ),
        grant(
            "scope.other",
            "actor.worker",
            "launch_pod",
            "pod",
            "pod.proposed",
        ),
    ] {
        assert!(matches!(
            store.apply_authority_mutation(1, revision, AuthorityMutation::PutGrant(record)),
            Err(StoreError::StaleEpoch)
        ));
    }
    assert!(store.authority_snapshot().unwrap().grants.is_empty());
}

#[test]
fn actor_identity_cannot_change_within_credential_generation() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let mut state = store.begin_authority_replay(0, 1).unwrap();
    state.revision = store
        .apply_authority_mutation(
            1,
            state.revision,
            AuthorityMutation::PutPod(AuthorityPodRecord {
                scope_id: "scope.main".into(),
                pod_id: "pod.worker".into(),
                incarnation: 1,
            }),
        )
        .unwrap();
    state.revision = store
        .apply_authority_mutation(1, state.revision, AuthorityMutation::PutActor(actor()))
        .unwrap();
    let mut spoofed = actor();
    spoofed.process_identity = "linux.pid.999".into();
    assert!(matches!(
        store.apply_authority_mutation(1, state.revision, AuthorityMutation::PutActor(spoofed)),
        Err(StoreError::Conflict(_))
    ));
    let after = store.authority_snapshot().unwrap();
    assert_eq!(after.revision, state.revision);
    assert_eq!(after.actors, vec![actor()]);
    let mut renewed = actor();
    renewed.process_identity = "linux.pid.999".into();
    renewed.credential_generation = 2;
    store
        .apply_authority_mutation(
            1,
            state.revision,
            AuthorityMutation::PutActor(renewed.clone()),
        )
        .unwrap();
    assert_eq!(store.authority_snapshot().unwrap().actors, vec![renewed]);
    let before_grant = store.authority_snapshot().unwrap();
    let grant = AuthorityGrantRecord {
        grant_id: 1,
        scope_id: "scope.main".into(),
        actor_id: "actor.worker".into(),
        credential_generation: 2,
        mode: "controller".into(),
        remaining_delegation_depth: 0,
        rights: vec![AuthorityRightRecord {
            operation: "launch_pod".into(),
            target_kind: "pod".into(),
            target_id: "pod.worker".into(),
        }],
    };
    let next_revision = store
        .apply_authority_mutation(
            1,
            before_grant.revision,
            AuthorityMutation::PutGrant(grant.clone()),
        )
        .unwrap();
    let mut broadened = grant.clone();
    broadened.rights.push(AuthorityRightRecord {
        operation: "stop_pod".into(),
        target_kind: "pod".into(),
        target_id: "pod.worker".into(),
    });
    assert!(matches!(
        store.apply_authority_mutation(1, next_revision, AuthorityMutation::PutGrant(broadened)),
        Err(StoreError::Conflict("grant id is already committed"))
    ));
    assert_eq!(store.authority_snapshot().unwrap().grants, vec![grant]);
}

#[test]
fn stale_version_with_malformed_authority_table_refuses_migration() {
    let fixture = Fixture::new();
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE authority_pods(pod_id TEXT PRIMARY KEY) STRICT;
             PRAGMA user_version=3;",
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        PodBayStore::open(&fixture.database),
        Err(StoreError::Conflict(
            "authority schema columns do not match"
        ))
    ));
}

#[test]
fn schema_three_open_adds_empty_authority_ledger_without_changing_owner_epoch() {
    let fixture = Fixture::new();
    let store = PodBayStore::open(&fixture.database).unwrap();
    assert_eq!(store.owner_epoch().unwrap(), 0);
    drop(store);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys=OFF;
             BEGIN IMMEDIATE;
             DROP TABLE manager_credential_claims;
             DROP TABLE manager_rebind_resources;
             DROP TABLE manager_rebinds;
             DROP TABLE launch_resources;
             DROP TABLE launch_bindings;
             DROP TABLE runtime_runs;
             DROP TABLE runtime_sessions;
             DROP INDEX launch_slots_binding_identity;
             DROP TABLE authority_grant_rights;
             DROP TABLE authority_grants;
             DROP TABLE authority_actors;
             DROP TABLE authority_resources;
             DROP TABLE authority_pods;
             DELETE FROM metadata WHERE key='authority_revision';
             PRAGMA user_version=3;
             COMMIT;",
        )
        .unwrap();
    drop(connection);
    let mut migrated = PodBayStore::open(&fixture.database).unwrap();
    let snapshot = migrated.authority_snapshot().unwrap();
    assert_eq!(snapshot.owner_epoch, 0);
    assert_eq!(snapshot.revision, 0);
    assert!(snapshot.pods.is_empty());
    assert!(snapshot.resources.is_empty());
    assert!(snapshot.actors.is_empty());
    assert!(snapshot.grants.is_empty());
}

#[test]
fn pod_registration_and_replay_share_command_target_epoch() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let initial = store.begin_authority_replay(0, 1).unwrap();
    let revision = store
        .apply_authority_mutation(
            1,
            initial.revision,
            AuthorityMutation::PutPod(AuthorityPodRecord {
                scope_id: "scope.main".into(),
                pod_id: "pod.worker".into(),
                incarnation: 1,
            }),
        )
        .unwrap();
    assert_eq!(store.target_epoch("scope.main", "pod.worker").unwrap(), 1);
    let restarted = store.begin_authority_replay(1, 2).unwrap();
    assert_eq!(restarted.revision, revision + 1);
    assert_eq!(store.target_epoch("scope.main", "pod.worker").unwrap(), 1);
    store
        .apply_authority_mutation(
            2,
            restarted.revision,
            AuthorityMutation::PutPod(AuthorityPodRecord {
                scope_id: "scope.main".into(),
                pod_id: "pod.worker".into(),
                incarnation: 2,
            }),
        )
        .unwrap();
    assert_eq!(store.target_epoch("scope.main", "pod.worker").unwrap(), 2);
}
