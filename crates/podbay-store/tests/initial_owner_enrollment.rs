use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_store::{
    AuthorityActorRecord, AuthorityGrantRecord, AuthorityRightRecord, PodBayStore, StoreError,
};

struct Fixture {
    root: PathBuf,
    database: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "podbay-initial-owner-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        Self {
            database: root.join("store.sqlite"),
            root,
        }
    }

    fn opened(&self) -> (PodBayStore, String, u64) {
        let mut store = PodBayStore::open(&self.database).unwrap();
        let snapshot = store.begin_authority_replay(0, 1).unwrap();
        let lineage = store.initial_cursor("scope.initial").unwrap().store_lineage;
        (store, lineage, snapshot.revision)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn actor() -> AuthorityActorRecord {
    AuthorityActorRecord {
        scope_id: "scope.initial".into(),
        actor_id: "actor.initial.owner".into(),
        role: "coordinator".into(),
        origin: "owner_cli".into(),
        parent_actor_id: None,
        pod_id: None,
        pod_incarnation: None,
        credential_generation: 1,
        platform: "linux".into(),
        os_identity: "linux.uid.1000".into(),
        process_identity: "linux.pid.4321".into(),
        start_identity: 9876,
        containment_identity: "/user.slice/zap.scope".into(),
    }
}

fn grant() -> AuthorityGrantRecord {
    AuthorityGrantRecord {
        grant_id: 1,
        scope_id: "scope.initial".into(),
        actor_id: "actor.initial.owner".into(),
        credential_generation: 1,
        mode: "controller".into(),
        remaining_delegation_depth: 0,
        rights: vec![
            AuthorityRightRecord {
                operation: "launch_pod".into(),
                target_kind: "scope".into(),
                target_id: "scope.initial".into(),
            },
            AuthorityRightRecord {
                operation: "send_session".into(),
                target_kind: "scope".into(),
                target_id: "scope.initial".into(),
            },
            AuthorityRightRecord {
                operation: "use_credential".into(),
                target_kind: "credential".into(),
                target_id: "vault.initial".into(),
            },
        ],
    }
}

#[test]
fn atomic_owner_enrollment_replays_exact_rows_without_new_revision() {
    let fixture = Fixture::new();
    let (mut store, lineage, revision) = fixture.opened();
    let policy_epoch = store.policy_fence_epoch().unwrap();
    let actor = actor();
    let grant = grant();
    let (committed, duplicate) = store
        .enroll_initial_owner_actor_from_trusted_host(
            &lineage, 1, revision, &actor, [7; 32], &grant,
        )
        .unwrap();
    assert_eq!(committed, revision + 1);
    assert!(!duplicate);
    let snapshot = store.authority_snapshot().unwrap();
    assert_eq!(snapshot.actors, vec![actor.clone()]);
    assert_eq!(snapshot.grants, vec![grant.clone()]);
    assert_eq!(snapshot.revision, committed);
    assert_eq!(store.policy_fence_epoch().unwrap(), policy_epoch);
    assert_eq!(
        store.current_actor_verifier(1, committed, &actor).unwrap(),
        [7; 32]
    );
    assert_eq!(
        store
            .enroll_initial_owner_actor_from_trusted_host(
                &lineage, 1, committed, &actor, [7; 32], &grant,
            )
            .unwrap(),
        (committed, true)
    );
    assert_eq!(store.authority_snapshot().unwrap(), snapshot);
    assert_eq!(store.policy_fence_epoch().unwrap(), policy_epoch);
    drop(store);
    let mut reopened = PodBayStore::open(&fixture.database).unwrap();
    assert_eq!(reopened.authority_snapshot().unwrap(), snapshot);
    assert_eq!(reopened.policy_fence_epoch().unwrap(), policy_epoch);
}

#[test]
fn changed_key_birth_scope_or_owner_guard_refuses_without_mutation() {
    let fixture = Fixture::new();
    let (mut store, lineage, revision) = fixture.opened();
    let actor = actor();
    let grant = grant();
    let committed = store
        .enroll_initial_owner_actor_from_trusted_host(
            &lineage, 1, revision, &actor, [7; 32], &grant,
        )
        .unwrap()
        .0;
    let stable = store.authority_snapshot().unwrap();
    assert!(matches!(
        store.enroll_initial_owner_actor_from_trusted_host(
            &lineage, 1, committed, &actor, [8; 32], &grant,
        ),
        Err(StoreError::Conflict(_))
    ));
    let mut changed_birth = actor.clone();
    changed_birth.start_identity += 1;
    assert!(matches!(
        store.enroll_initial_owner_actor_from_trusted_host(
            &lineage,
            1,
            committed,
            &changed_birth,
            [7; 32],
            &grant,
        ),
        Err(StoreError::Conflict(_))
    ));
    let mut foreign = grant.clone();
    foreign.scope_id = "scope.other".into();
    assert!(matches!(
        store.enroll_initial_owner_actor_from_trusted_host(
            &lineage, 1, committed, &actor, [7; 32], &foreign,
        ),
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        store.enroll_initial_owner_actor_from_trusted_host(
            &lineage, 2, committed, &actor, [7; 32], &grant,
        ),
        Err(StoreError::StaleEpoch)
    ));
    let mut sibling = actor.clone();
    sibling.actor_id = "actor.sibling".into();
    sibling.scope_id = "scope.sibling".into();
    let mut sibling_grant = grant.clone();
    sibling_grant.grant_id = 2;
    sibling_grant.actor_id = sibling.actor_id.clone();
    sibling_grant.scope_id = sibling.scope_id.clone();
    for right in &mut sibling_grant.rights {
        if right.target_kind == "scope" {
            right.target_id = sibling.scope_id.clone();
        }
    }
    assert!(matches!(
        store.enroll_initial_owner_actor_from_trusted_host(
            &lineage,
            1,
            committed,
            &sibling,
            [9; 32],
            &sibling_grant,
        ),
        Err(StoreError::Conflict("process already binds another actor"))
    ));
    assert_eq!(store.authority_snapshot().unwrap(), stable);
}

#[test]
fn each_late_insert_or_revision_fault_rolls_back_all_identity_rows() {
    for trigger in [
        "CREATE TRIGGER fail_initial BEFORE INSERT ON actor_verifiers
         BEGIN SELECT RAISE(ABORT,'synthetic verifier failure'); END;",
        "CREATE TRIGGER fail_initial BEFORE INSERT ON authority_grants
         BEGIN SELECT RAISE(ABORT,'synthetic grant failure'); END;",
        "CREATE TRIGGER fail_initial BEFORE INSERT ON authority_grant_rights
         BEGIN SELECT RAISE(ABORT,'synthetic right failure'); END;",
        "CREATE TRIGGER fail_initial BEFORE UPDATE ON metadata
         WHEN NEW.key='authority_revision'
         BEGIN SELECT RAISE(ABORT,'synthetic revision failure'); END;",
    ] {
        let fixture = Fixture::new();
        let (mut store, lineage, revision) = fixture.opened();
        let before = store.authority_snapshot().unwrap();
        let connection = rusqlite::Connection::open(&fixture.database).unwrap();
        connection.execute_batch(trigger).unwrap();
        assert!(
            store
                .enroll_initial_owner_actor_from_trusted_host(
                    &lineage,
                    1,
                    revision,
                    &actor(),
                    [7; 32],
                    &grant(),
                )
                .is_err()
        );
        drop(store);
        let mut reopened = PodBayStore::open(&fixture.database).unwrap();
        assert_eq!(reopened.authority_snapshot().unwrap(), before);
        let verifier_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM actor_verifiers", [], |row| row.get(0))
            .unwrap();
        assert_eq!(verifier_count, 0);
    }
}
