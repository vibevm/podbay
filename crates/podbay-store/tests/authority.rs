use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_store::{
    AuthorityActorRecord, AuthorityGrantRecord, AuthorityMutation, AuthorityPodRecord,
    AuthorityRightRecord, OwnerActorRotationReceipt, PodBayStore, SqliteActorVerifierWitness,
    StoreError, TrustedOwnerRotationProof,
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

fn seed_actor(store: &mut PodBayStore) -> (AuthorityActorRecord, u64) {
    let snapshot = store.begin_authority_replay(0, 1).unwrap();
    let revision = store
        .apply_authority_mutation(
            1,
            snapshot.revision,
            AuthorityMutation::PutPod(AuthorityPodRecord {
                scope_id: "scope.main".into(),
                pod_id: "pod.worker".into(),
                incarnation: 1,
            }),
        )
        .unwrap();
    let record = actor();
    let revision = store
        .apply_authority_mutation(1, revision, AuthorityMutation::PutActor(record.clone()))
        .unwrap();
    (record, revision)
}

fn owner_actor() -> AuthorityActorRecord {
    AuthorityActorRecord {
        scope_id: "scope.main".into(),
        actor_id: "actor.owner".into(),
        role: "coordinator".into(),
        origin: "owner_cli".into(),
        parent_actor_id: None,
        pod_id: None,
        pod_incarnation: None,
        credential_generation: 1,
        platform: "linux".into(),
        os_identity: "linux.uid.1000".into(),
        process_identity: "linux.pid.123".into(),
        start_identity: 456,
        containment_identity: "/user.slice/zap-old.scope".into(),
    }
}

fn seed_owner(store: &mut PodBayStore) -> (AuthorityActorRecord, u64, String) {
    let snapshot = store.begin_authority_replay(0, 1).unwrap();
    let actor = owner_actor();
    let revision = store
        .apply_authority_mutation(
            1,
            snapshot.revision,
            AuthorityMutation::PutActor(actor.clone()),
        )
        .unwrap();
    let revision = store
        .register_actor_verifier_from_trusted_host(1, revision, &actor, [7; 32])
        .unwrap();
    let lineage = store.initial_cursor("scope.main").unwrap().store_lineage;
    (actor, revision, lineage)
}

fn owner_rotation(
    actor: &AuthorityActorRecord,
    revision: u64,
    lineage: &str,
) -> TrustedOwnerRotationProof {
    let mut next_actor = actor.clone();
    next_actor.credential_generation = 2;
    next_actor.process_identity = "linux.pid.124".into();
    next_actor.start_identity = 457;
    next_actor.containment_identity = "/user.slice/zap-new.scope".into();
    TrustedOwnerRotationProof {
        store_lineage: lineage.into(),
        expected_owner_epoch: 1,
        expected_revision: revision,
        rotation_key: "rotation.owner.one".into(),
        expected_actor: actor.clone(),
        expected_public_key: [7; 32],
        next_actor,
        next_public_key: [9; 32],
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
fn scope_launch_right_persists_without_pod_and_refuses_foreign_or_stop_scope() {
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
    let scoped = grant(
        "scope.main",
        "actor.worker",
        "launch_pod",
        "scope",
        "scope.main",
    );
    let revision = store
        .apply_authority_mutation(1, revision, AuthorityMutation::PutGrant(scoped.clone()))
        .unwrap();
    assert_eq!(
        store.authority_snapshot().unwrap().grants,
        vec![scoped.clone()]
    );
    assert!(store.authority_snapshot().unwrap().pods.is_empty());
    let mut foreign = scoped.clone();
    foreign.grant_id = 2;
    foreign.rights[0].target_id = "scope.other".into();
    assert!(matches!(
        store.apply_authority_mutation(1, revision, AuthorityMutation::PutGrant(foreign)),
        Err(StoreError::WrongScope)
    ));
    let mut stop = scoped.clone();
    stop.grant_id = 3;
    stop.rights[0].operation = "stop_pod".into();
    assert!(matches!(
        store.apply_authority_mutation(1, revision, AuthorityMutation::PutGrant(stop)),
        Err(StoreError::InvalidInput(
            "scope right supports launch_pod or send_session only"
        ))
    ));
    drop(store);
    let mut reopened = PodBayStore::open(&fixture.database).unwrap();
    assert_eq!(reopened.authority_snapshot().unwrap().grants, vec![scoped]);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let targets: i64 = connection
        .query_row("SELECT COUNT(*) FROM target_epochs", [], |row| row.get(0))
        .unwrap();
    assert_eq!(targets, 0);
}

#[test]
fn scope_send_right_persists_before_session_and_refuses_foreign_scope_or_terminal_right() {
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
    let send = grant(
        "scope.main",
        "actor.worker",
        "send_session",
        "scope",
        "scope.main",
    );
    let revision = store
        .apply_authority_mutation(1, revision, AuthorityMutation::PutGrant(send.clone()))
        .unwrap();
    assert_eq!(
        store.authority_snapshot().unwrap().grants,
        vec![send.clone()]
    );
    let mut foreign = send.clone();
    foreign.grant_id = 2;
    foreign.rights[0].target_id = "scope.foreign".into();
    assert!(matches!(
        store.apply_authority_mutation(1, revision, AuthorityMutation::PutGrant(foreign)),
        Err(StoreError::WrongScope)
    ));
    let mut terminal = send.clone();
    terminal.grant_id = 3;
    terminal.rights[0].operation = "write_input".into();
    assert!(matches!(
        store.apply_authority_mutation(1, revision, AuthorityMutation::PutGrant(terminal)),
        Err(StoreError::InvalidInput(
            "scope right supports launch_pod or send_session only"
        ))
    ));
    drop(store);
    let mut reopened = PodBayStore::open(&fixture.database).unwrap();
    let snapshot = reopened.authority_snapshot().unwrap();
    assert_eq!(snapshot.grants, vec![send]);
    assert_eq!(snapshot.revision, revision);
    assert!(snapshot.pods.is_empty());
    assert!(snapshot.resources.is_empty());
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let targets: i64 = connection
        .query_row("SELECT COUNT(*) FROM target_epochs", [], |row| row.get(0))
        .unwrap();
    assert_eq!(targets, 0);
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
             DROP TABLE codex_bootstrap_sends;
             DROP TABLE native_writer_leases;
             DROP TABLE run_child_budgets;
             DROP TABLE owner_actor_rotations;
             DROP TABLE actor_verifiers;
             DROP TABLE manager_rebind_prior_observations;
             DROP TABLE manager_peer_bindings;
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

#[test]
fn v13_upgrade_keeps_existing_actor_without_inventing_a_verifier() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let (record, revision) = seed_actor(&mut store);
    drop(store);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "DROP TABLE codex_bootstrap_sends; DROP TABLE native_writer_leases;
             DROP TABLE run_child_budgets;
             DROP TABLE owner_actor_rotations; DROP TABLE actor_verifiers;
             PRAGMA user_version=13;",
        )
        .unwrap();
    drop(connection);
    let mut migrated = PodBayStore::open(&fixture.database).unwrap();
    assert_eq!(
        migrated.authority_snapshot().unwrap().actors,
        vec![record.clone()]
    );
    assert!(matches!(
        migrated.current_actor_verifier(1, revision, &record),
        Err(StoreError::NotFound)
    ));
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM actor_verifiers", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn v14_upgrade_adds_empty_owner_rotation_history_without_changing_verifier() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let (actor, revision, _) = seed_owner(&mut store);
    drop(store);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "DROP TABLE codex_bootstrap_sends; DROP TABLE native_writer_leases;
             DROP TABLE run_child_budgets;
             DROP TABLE owner_actor_rotations; PRAGMA user_version=14;",
        )
        .unwrap();
    drop(connection);
    let mut migrated = PodBayStore::open(&fixture.database).unwrap();
    assert_eq!(
        migrated.authority_snapshot().unwrap().actors,
        vec![actor.clone()]
    );
    assert_eq!(migrated.authority_snapshot().unwrap().revision, revision);
    assert_eq!(
        migrated
            .current_actor_verifier(1, revision, &actor)
            .unwrap(),
        [7; 32]
    );
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM owner_actor_rotations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!((version, count), (20, 0));
}

#[test]
fn actor_verifier_survives_reopen_but_rotation_and_revoke_fence_old_key() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let (record, revision) = seed_actor(&mut store);
    let revision = store
        .register_actor_verifier_from_trusted_host(1, revision, &record, [7; 32])
        .unwrap();
    assert_eq!(
        store
            .register_actor_verifier_from_trusted_host(1, revision, &record, [7; 32])
            .unwrap(),
        revision
    );
    assert!(matches!(
        store.register_actor_verifier_from_trusted_host(1, revision, &record, [8; 32]),
        Err(StoreError::Conflict(_))
    ));
    drop(store);

    let mut reopened = PodBayStore::open(&fixture.database).unwrap();
    assert_eq!(
        reopened
            .current_actor_verifier(1, revision, &record)
            .unwrap(),
        [7; 32]
    );
    let restart = reopened.begin_authority_replay(1, 2).unwrap();
    assert_eq!(
        reopened
            .current_actor_verifier(2, restart.revision, &record)
            .unwrap(),
        [7; 32]
    );
    assert!(matches!(
        reopened.current_actor_verifier(1, revision, &record),
        Err(StoreError::StaleEpoch)
    ));

    let mut rotated = record.clone();
    rotated.credential_generation = 2;
    rotated.process_identity = "linux.pid.124".into();
    rotated.start_identity = 457;
    let revision = reopened
        .apply_authority_mutation(
            2,
            restart.revision,
            AuthorityMutation::PutActor(rotated.clone()),
        )
        .unwrap();
    assert!(matches!(
        reopened.current_actor_verifier(2, revision, &rotated),
        Err(StoreError::StaleEpoch)
    ));
    assert!(matches!(
        reopened.register_actor_verifier_from_trusted_host(2, revision, &rotated, [7; 32]),
        Err(StoreError::Conflict(
            "actor verifier key reused across generations"
        ))
    ));
    let revision = reopened
        .register_actor_verifier_from_trusted_host(2, revision, &rotated, [9; 32])
        .unwrap();
    assert_eq!(
        reopened
            .current_actor_verifier(2, revision, &rotated)
            .unwrap(),
        [9; 32]
    );
    let revision = reopened
        .revoke_actor_verifier_from_trusted_host(2, revision, &rotated)
        .unwrap();
    assert!(matches!(
        reopened.current_actor_verifier(2, revision, &rotated),
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        reopened.register_actor_verifier_from_trusted_host(2, revision, &rotated, [9; 32]),
        Err(StoreError::Conflict("actor verifier was revoked"))
    ));
    drop(reopened);
    let mut reopened = PodBayStore::open(&fixture.database).unwrap();
    assert!(matches!(
        reopened.current_actor_verifier(2, revision, &rotated),
        Err(StoreError::NotFound)
    ));
}

#[test]
fn actor_verifier_requires_exact_scope_birth_and_current_revision() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let (record, revision) = seed_actor(&mut store);
    let mut foreign = record.clone();
    foreign.scope_id = "scope.foreign".into();
    assert!(matches!(
        store.register_actor_verifier_from_trusted_host(1, revision, &foreign, [3; 32]),
        Err(StoreError::WrongScope)
    ));
    let mut reused_pid = record.clone();
    reused_pid.start_identity += 1;
    assert!(matches!(
        store.register_actor_verifier_from_trusted_host(1, revision, &reused_pid, [3; 32]),
        Err(StoreError::StaleEpoch)
    ));
    let next = store
        .register_actor_verifier_from_trusted_host(1, revision, &record, [3; 32])
        .unwrap();
    assert!(matches!(
        store.current_actor_verifier(1, next, &foreign),
        Err(StoreError::WrongScope)
    ));
    assert!(matches!(
        store.current_actor_verifier(1, next, &reused_pid),
        Err(StoreError::StaleEpoch)
    ));
    assert!(matches!(
        store.current_actor_verifier(1, revision, &record),
        Err(StoreError::StaleEpoch)
    ));
    assert!(matches!(
        store.current_actor_verifier(2, next, &record),
        Err(StoreError::StaleEpoch)
    ));

    // A bypassed actor-row edit cannot repoint the public verifier to a new
    // process birth inside the same generation and authority revision.
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute(
            "UPDATE authority_actors SET process_identity='linux.pid.999',
               start_identity=999 WHERE actor_id='actor.worker'",
            [],
        )
        .unwrap();
    let mut substituted = record.clone();
    substituted.process_identity = "linux.pid.999".into();
    substituted.start_identity = 999;
    assert!(matches!(
        store.current_actor_verifier(1, next, &substituted),
        Err(StoreError::Conflict("actor verifier binding changed"))
    ));
}

#[test]
fn concurrent_actor_verifier_registration_never_substitutes_a_key() {
    let fixture = Fixture::new();
    let mut setup = PodBayStore::open(&fixture.database).unwrap();
    let (record, revision) = seed_actor(&mut setup);
    drop(setup);
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for key in [[11; 32], [12; 32]] {
        let path = fixture.database.clone();
        let actor = record.clone();
        let barrier = barrier.clone();
        workers.push(thread::spawn(move || {
            let mut store = PodBayStore::open(path).unwrap();
            barrier.wait();
            store.register_actor_verifier_from_trusted_host(1, revision, &actor, key)
        }));
    }
    barrier.wait();
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
    let mut reopened = PodBayStore::open(&fixture.database).unwrap();
    let public_key = reopened
        .current_actor_verifier(1, revision + 1, &record)
        .unwrap();
    assert!(public_key == [11; 32] || public_key == [12; 32]);
    let other = if public_key == [11; 32] {
        [12; 32]
    } else {
        [11; 32]
    };
    assert!(matches!(
        reopened.register_actor_verifier_from_trusted_host(1, revision + 1, &record, other),
        Err(StoreError::Conflict(_))
    ));
}

#[test]
fn actor_witness_rechecks_revision_owner_rotation_and_revocation() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let (record, revision) = seed_actor(&mut store);
    let revision = store
        .register_actor_verifier_from_trusted_host(1, revision, &record, [7; 32])
        .unwrap();
    let lineage = store.initial_cursor("scope.main").unwrap().store_lineage;
    let old = SqliteActorVerifierWitness::for_actor(
        &fixture.database,
        &lineage,
        1,
        revision,
        record.clone(),
        [7; 32],
    )
    .unwrap();
    assert!(old.is_current());
    assert!(old.is_current_actor_binding());

    let revision = store
        .apply_authority_mutation(
            1,
            revision,
            AuthorityMutation::PutPod(AuthorityPodRecord {
                scope_id: "scope.main".into(),
                pod_id: "pod.worker".into(),
                incarnation: 1,
            }),
        )
        .unwrap();
    assert!(!old.is_current());
    // A signed connection may survive an unrelated authority mutation, but
    // a new challenge still requires the exact current global revision.
    assert!(old.is_current_actor_binding());
    let current = SqliteActorVerifierWitness::for_actor(
        &fixture.database,
        &lineage,
        1,
        revision,
        record.clone(),
        [7; 32],
    )
    .unwrap();
    assert!(current.is_current());

    let replay = store.begin_authority_replay(1, 2).unwrap();
    assert!(!current.is_current());
    assert!(!current.is_current_actor_binding());
    assert!(!old.is_current_actor_binding());
    let surviving = SqliteActorVerifierWitness::for_actor(
        &fixture.database,
        &lineage,
        2,
        replay.revision,
        record.clone(),
        [7; 32],
    )
    .unwrap();
    assert!(surviving.is_current());

    let mut rotated = record;
    rotated.credential_generation = 2;
    rotated.process_identity = "linux.pid.124".into();
    rotated.start_identity = 457;
    let revision = store
        .apply_authority_mutation(
            2,
            replay.revision,
            AuthorityMutation::PutActor(rotated.clone()),
        )
        .unwrap();
    assert!(!surviving.is_current());
    assert!(!surviving.is_current_actor_binding());
    let revision = store
        .register_actor_verifier_from_trusted_host(2, revision, &rotated, [9; 32])
        .unwrap();
    let renewed = SqliteActorVerifierWitness::for_actor(
        &fixture.database,
        &lineage,
        2,
        revision,
        rotated.clone(),
        [9; 32],
    )
    .unwrap();
    assert!(renewed.is_current());
    store
        .revoke_actor_verifier_from_trusted_host(2, revision, &rotated)
        .unwrap();
    assert!(!renewed.is_current());
    assert!(!renewed.is_current_actor_binding());
}

#[test]
fn actor_witness_refuses_foreign_binding_key_and_unavailable_database() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let (record, revision) = seed_actor(&mut store);
    let revision = store
        .register_actor_verifier_from_trusted_host(1, revision, &record, [3; 32])
        .unwrap();
    let lineage = store.initial_cursor("scope.main").unwrap().store_lineage;
    assert!(matches!(
        SqliteActorVerifierWitness::for_actor(
            "relative.sqlite",
            &lineage,
            1,
            revision,
            record.clone(),
            [3; 32],
        ),
        Err(StoreError::InvalidInput(_))
    ));
    let witness =
        |database: &std::path::Path, lineage: &str, actor: AuthorityActorRecord, key: [u8; 32]| {
            SqliteActorVerifierWitness::for_actor(database, lineage, 1, revision, actor, key)
                .unwrap()
        };
    assert!(witness(&fixture.database, &lineage, record.clone(), [3; 32]).is_current());
    assert!(
        witness(&fixture.database, &lineage, record.clone(), [3; 32]).is_current_actor_binding()
    );
    assert!(
        !witness(
            &fixture.database,
            "foreign.lineage",
            record.clone(),
            [3; 32]
        )
        .is_current()
    );
    let mut foreign_scope = record.clone();
    foreign_scope.scope_id = "scope.foreign".into();
    let foreign = witness(&fixture.database, &lineage, foreign_scope, [3; 32]);
    assert!(!foreign.is_current());
    assert!(!foreign.is_current_actor_binding());
    let mut changed_birth = record.clone();
    changed_birth.start_identity += 1;
    let changed = witness(&fixture.database, &lineage, changed_birth, [3; 32]);
    assert!(!changed.is_current());
    assert!(!changed.is_current_actor_binding());
    let wrong_key = witness(&fixture.database, &lineage, record.clone(), [4; 32]);
    assert!(!wrong_key.is_current());
    assert!(!wrong_key.is_current_actor_binding());

    let missing = fixture.directory.join("missing.sqlite");
    assert!(!witness(&missing, &lineage, record.clone(), [3; 32]).is_current());
    assert!(!witness(&missing, &lineage, record.clone(), [3; 32]).is_current_actor_binding());
    assert!(!missing.exists());
    let corrupt = fixture.directory.join("corrupt.sqlite");
    std::fs::write(&corrupt, b"not a SQLite database").unwrap();
    assert!(!witness(&corrupt, &lineage, record.clone(), [3; 32]).is_current());
    assert!(!witness(&corrupt, &lineage, record.clone(), [3; 32]).is_current_actor_binding());

    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute(
            "UPDATE actor_verifiers SET binding_digest=zeroblob(32)
             WHERE actor_id='actor.worker'",
            [],
        )
        .unwrap();
    let corrupted = witness(&fixture.database, &lineage, record, [3; 32]);
    assert!(!corrupted.is_current());
    assert!(!corrupted.is_current_actor_binding());
}

#[test]
fn owner_rotation_commits_actor_verifier_revocation_and_idempotent_receipt_together() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let (old, revision, lineage) = seed_owner(&mut store);
    let before_policy = store.policy_fence_epoch().unwrap();
    let proof = owner_rotation(&old, revision, &lineage);
    let witness = SqliteActorVerifierWitness::for_actor(
        &fixture.database,
        &lineage,
        1,
        revision,
        old.clone(),
        [7; 32],
    )
    .unwrap();
    assert!(witness.is_current());
    let receipt: OwnerActorRotationReceipt =
        store.rotate_owner_actor_from_trusted_host(&proof).unwrap();
    assert_eq!(receipt.prior_generation, 1);
    assert_eq!(receipt.next_generation, 2);
    assert_eq!(receipt.authority_revision, revision + 1);
    assert_eq!(store.policy_fence_epoch().unwrap(), before_policy + 1);
    assert_eq!(receipt.intent_digest.len(), 64);
    assert!(!witness.is_current());
    assert_eq!(
        store.authority_snapshot().unwrap().actors,
        vec![proof.next_actor.clone()]
    );
    assert_eq!(
        store
            .current_actor_verifier(1, receipt.authority_revision, &proof.next_actor)
            .unwrap(),
        [9; 32]
    );
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let history: (i64, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT prior_revoked,prior_public_key,next_public_key
             FROM owner_actor_rotations WHERE actor_id='actor.owner'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(history, (1, vec![7; 32], vec![9; 32]));
    // Lost ACK: the original expected revision is stale, but the same
    // key-and-intent must return the committed receipt without a new write.
    assert!(proof.expected_revision < receipt.authority_revision);
    assert_eq!(
        store.rotate_owner_actor_from_trusted_host(&proof).unwrap(),
        receipt
    );
    assert_eq!(store.policy_fence_epoch().unwrap(), before_policy + 1);
    assert_eq!(
        store.authority_snapshot().unwrap().revision,
        receipt.authority_revision
    );
    let mut changed = proof.clone();
    changed.next_public_key = [11; 32];
    // The same key with changed normalized intent cannot claim the receipt.
    assert!(matches!(
        store.rotate_owner_actor_from_trusted_host(&changed),
        Err(StoreError::Conflict("owner rotation key changed intent"))
    ));
    drop(connection);
    drop(store);
    let mut reopened = PodBayStore::open(&fixture.database).unwrap();
    assert_eq!(
        reopened
            .rotate_owner_actor_from_trusted_host(&proof)
            .unwrap(),
        receipt
    );
    assert_eq!(
        reopened.authority_snapshot().unwrap().actors,
        vec![proof.next_actor]
    );
    assert_eq!(reopened.policy_fence_epoch().unwrap(), before_policy + 1);
}

#[test]
fn owner_rotation_refuses_stale_guards_key_reuse_and_generic_owner_replacement() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let (old, revision, lineage) = seed_owner(&mut store);
    let proof = owner_rotation(&old, revision, &lineage);
    assert!(matches!(
        store.apply_authority_mutation(
            1,
            revision,
            AuthorityMutation::PutActor(proof.next_actor.clone())
        ),
        Err(StoreError::Conflict(
            "owner actor replacement requires atomic rotation"
        ))
    ));
    let mut stale = proof.clone();
    stale.expected_revision -= 1;
    assert!(matches!(
        store.rotate_owner_actor_from_trusted_host(&stale),
        Err(StoreError::StaleEpoch)
    ));
    stale = proof.clone();
    stale.expected_owner_epoch = 2;
    assert!(matches!(
        store.rotate_owner_actor_from_trusted_host(&stale),
        Err(StoreError::StaleEpoch)
    ));
    stale = proof.clone();
    stale.expected_public_key = [8; 32];
    assert!(matches!(
        store.rotate_owner_actor_from_trusted_host(&stale),
        Err(StoreError::Conflict("old owner verifier is not current"))
    ));
    stale = proof.clone();
    stale.expected_actor.start_identity += 1;
    assert!(matches!(
        store.rotate_owner_actor_from_trusted_host(&stale),
        Err(StoreError::StaleEpoch)
    ));
    stale = proof.clone();
    stale.next_actor.credential_generation = 3;
    assert!(matches!(
        store.rotate_owner_actor_from_trusted_host(&stale),
        Err(StoreError::InvalidInput(_))
    ));
    stale = proof.clone();
    stale.next_actor.scope_id = "scope.other".into();
    assert!(matches!(
        store.rotate_owner_actor_from_trusted_host(&stale),
        Err(StoreError::InvalidInput(_))
    ));
    assert_eq!(store.authority_snapshot().unwrap().actors, vec![old]);
    let receipt = store.rotate_owner_actor_from_trusted_host(&proof).unwrap();
    let mut next = proof.clone();
    next.expected_revision = receipt.authority_revision;
    next.expected_actor = proof.next_actor.clone();
    next.expected_public_key = proof.next_public_key;
    next.next_actor.credential_generation = 3;
    next.next_actor.process_identity = "linux.pid.125".into();
    next.next_actor.start_identity = 458;
    next.next_public_key = [7; 32];
    next.rotation_key = "rotation.owner.two".into();
    assert!(matches!(
        store.rotate_owner_actor_from_trusted_host(&next),
        Err(StoreError::Conflict("owner verifier key was reused"))
    ));
}

#[test]
fn owner_rotation_faults_roll_back_actor_verifier_revision_and_receipt() {
    for trigger in [
        "CREATE TRIGGER fail_rotation BEFORE UPDATE ON actor_verifiers
         BEGIN SELECT RAISE(ABORT,'synthetic verifier fault'); END;",
        "CREATE TRIGGER fail_rotation BEFORE INSERT ON owner_actor_rotations
         BEGIN SELECT RAISE(ABORT,'synthetic receipt fault'); END;",
    ] {
        let fixture = Fixture::new();
        let mut store = PodBayStore::open(&fixture.database).unwrap();
        let (old, revision, lineage) = seed_owner(&mut store);
        let before_policy = store.policy_fence_epoch().unwrap();
        let proof = owner_rotation(&old, revision, &lineage);
        let connection = rusqlite::Connection::open(&fixture.database).unwrap();
        connection.execute_batch(trigger).unwrap();
        assert!(store.rotate_owner_actor_from_trusted_host(&proof).is_err());
        drop(store);
        let mut reopened = PodBayStore::open(&fixture.database).unwrap();
        assert_eq!(
            reopened.authority_snapshot().unwrap().actors,
            vec![old.clone()]
        );
        assert_eq!(reopened.authority_snapshot().unwrap().revision, revision);
        assert_eq!(reopened.policy_fence_epoch().unwrap(), before_policy);
        assert_eq!(
            reopened.current_actor_verifier(1, revision, &old).unwrap(),
            [7; 32]
        );
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM owner_actor_rotations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }
}
