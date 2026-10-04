use std::path::PathBuf;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_store::{
    Admission, AuthorityActorRecord, AuthorityMutation, CURRENT_SCOPE_ENTITY_LIMIT, CommandRequest,
    CurrentObservation, PodBayStore, StoreError, VerifiedPrincipal,
};
use rusqlite::{Connection, params};

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
            "podbay-current-snapshot-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        Self {
            database: root.join("state.sqlite"),
            root,
        }
    }

    fn connection(&self) -> Connection {
        Connection::open(&self.database).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn actor(scope: &str) -> AuthorityActorRecord {
    AuthorityActorRecord {
        scope_id: scope.into(),
        actor_id: format!("actor.{scope}"),
        role: "coordinator".into(),
        origin: "owner_cli".into(),
        parent_actor_id: None,
        pod_id: None,
        pod_incarnation: None,
        credential_generation: 1,
        platform: "linux".into(),
        os_identity: "linux.uid.fixture".into(),
        process_identity: "linux.pid.fixture".into(),
        start_identity: 100,
        containment_identity: "/fixture.scope".into(),
    }
}

fn ready(store: &mut PodBayStore, scope: &str) -> (AuthorityActorRecord, u64) {
    let initial = store.begin_authority_replay(0, 1).unwrap();
    let actor = actor(scope);
    let revision = store
        .apply_authority_mutation(
            1,
            initial.revision,
            AuthorityMutation::PutActor(actor.clone()),
        )
        .unwrap();
    (actor, revision)
}

fn admit(store: &mut PodBayStore, scope: &str, target: &str, key: &str) -> String {
    let request = CommandRequest {
        principal: VerifiedPrincipal::from_authenticated_boundary("actor.scope.main").unwrap(),
        namespace: "namespace.fixture".into(),
        command_key: key.into(),
        scope_id: scope.into(),
        target_id: target.into(),
        expected_owner_epoch: 1,
        expected_target_epoch: 1,
        canonical_request: key.as_bytes().to_vec(),
        event_kind: "command.admitted".into(),
        event_payload: b"history is not current state".to_vec(),
        effect_kind: "pod.offer".into(),
        effect_payload: b"effect history".to_vec(),
    };
    match store.admit(&request).unwrap() {
        Admission::Committed(receipt) => receipt.command_id,
        other => panic!("expected command admission: {other:?}"),
    }
}

fn insert_current_graph(fixture: &Fixture, store: &mut PodBayStore) {
    store
        .advance_target_epoch("scope.main", "pod.current", 0, 1)
        .unwrap();
    let command_id = admit(store, "scope.main", "pod.current", "key.current");
    let connection = fixture.connection();
    connection.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    let rowid: i64 = connection
        .query_row(
            "SELECT command_rowid FROM commands WHERE command_id=?1",
            [&command_id],
            |row| row.get(0),
        )
        .unwrap();
    connection.execute_batch(
        "INSERT INTO runtime_sessions(session_id,scope_id,actor_id,revision,state,current_run_id)
           VALUES('session.current','scope.main','actor.scope.main',1,'open','run.current');
         INSERT INTO runtime_runs(run_id,session_id,scope_id,role,work_kind,parent_run_id,
           revision,admission_state,desired_mode,execution_state,current_attempt_id,last_attempt_ordinal)
           VALUES('run.current','session.current','scope.main','coordinator','service',NULL,
           2,'admitted','run','starting','attempt.current',1);
         INSERT INTO authority_pods(pod_id,scope_id,incarnation)
           VALUES('pod.current','scope.main',1);"
    ).unwrap();
    connection
        .execute(
            "INSERT INTO launch_bindings(command_rowid,scope_id,session_id,run_id,attempt_id,
           attempt_ordinal,attempt_epoch,pod_id,pod_incarnation,resource_count,
           effective_spec_version,effective_spec_digest,effective_spec,
           descriptor_version,descriptor_digest,descriptor)
         VALUES(?1,'scope.main','session.current','run.current','attempt.current',
           1,1,'pod.current',1,1,'podbay.effective/2',?2,x'01','podbay.descriptor/2',?2,x'02')",
            params![rowid, "a".repeat(64)],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO launch_resources(command_rowid,resource_ordinal,resource_id,
           resource_kind,resource_epoch) VALUES(?1,0,'resource.current','structured_provider',1)",
            [rowid],
        )
        .unwrap();
    connection
        .execute_batch(
            "INSERT INTO authority_resources(resource_id,scope_id,pod_id,pod_incarnation,
           resource_epoch,input_epoch)
           VALUES('resource.current','scope.main','pod.current',1,1,1);",
        )
        .unwrap();
}

#[test]
fn current_graph_ignores_history_and_foreign_scope_without_effects() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let (actor, revision) = ready(&mut store, "scope.main");
    insert_current_graph(&fixture, &mut store);
    for index in 0..400 {
        let target = format!("target.history.{index}");
        store
            .advance_target_epoch("scope.main", &target, 0, 1)
            .unwrap();
        admit(
            &mut store,
            "scope.main",
            &target,
            &format!("key.history.{index}"),
        );
    }
    for index in 0..50 {
        let target = format!("target.foreign.{index}");
        store
            .advance_target_epoch("scope.foreign", &target, 0, 1)
            .unwrap();
        admit(
            &mut store,
            "scope.foreign",
            &target,
            &format!("key.foreign.{index}"),
        );
    }
    let before: (i64, i64) = fixture
        .connection()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM events),(SELECT COUNT(*) FROM outbox)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let current = store
        .current_scope_snapshot("scope.main", &actor, 1, 1, revision)
        .unwrap();
    assert_eq!(current.sessions.len(), 1);
    assert_eq!(current.sessions[0].session_id, "session.current");
    let run = current.sessions[0].run.as_ref().unwrap();
    assert_eq!(
        (
            run.run_id.as_str(),
            run.desired_mode.as_str(),
            run.execution_state.as_str()
        ),
        ("run.current", "run", "starting")
    );
    assert_eq!(run.observation, CurrentObservation::Unavailable);
    let attempt = run.attempt.as_ref().unwrap();
    assert_eq!(attempt.attempt_id, "attempt.current");
    assert_eq!(attempt.pod.pod_id, "pod.current");
    assert_eq!(attempt.pod.resources[0].resource_id, "resource.current");
    assert_eq!(attempt.pod.resources[0].input_epoch, 1);
    assert_eq!(current.cursor.sequence, before.0);
    assert_eq!(current.cursor.scope_id, "scope.main");
    assert_eq!(current.owner_epoch, 1);
    assert_eq!(current.authority_revision, revision);
    assert_eq!(
        before,
        fixture
            .connection()
            .query_row(
                "SELECT (SELECT COUNT(*) FROM events),(SELECT COUNT(*) FROM outbox)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    );
    assert!(matches!(
        store.current_scope_snapshot("scope.foreign", &actor, 1, 1, revision),
        Err(StoreError::NotFound)
    ));
    let stale_actor = AuthorityActorRecord {
        start_identity: 101,
        ..actor.clone()
    };
    assert!(matches!(
        store.current_scope_snapshot("scope.main", &stale_actor, 1, 1, revision),
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        store.current_scope_snapshot("scope.main", &actor, 2, 1, revision),
        Err(StoreError::StaleEpoch)
    ));
}

#[test]
fn fixed_entity_limit_refuses_without_partial_snapshot() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let (actor, revision) = ready(&mut store, "scope.main");
    let connection = fixture.connection();
    let transaction = connection.unchecked_transaction().unwrap();
    for index in 0..=CURRENT_SCOPE_ENTITY_LIMIT {
        transaction.execute(
            "INSERT INTO runtime_sessions(session_id,scope_id,actor_id,revision,state,current_run_id)
             VALUES(?1,'scope.main','actor.scope.main',0,'open',NULL)",
            [format!("session.{index}")],
        ).unwrap();
    }
    transaction.commit().unwrap();
    assert!(
        matches!(store.current_scope_snapshot("scope.main", &actor, 1, 1, revision),
        Err(StoreError::CurrentSnapshotLimitExceeded { limit }) if limit == CURRENT_SCOPE_ENTITY_LIMIT)
    );
}

#[test]
fn event_watermark_and_current_revision_share_one_sqlite_snapshot_under_writer() {
    let fixture = Fixture::new();
    let mut reader = PodBayStore::open(&fixture.database).unwrap();
    let (actor, revision) = ready(&mut reader, "scope.main");
    insert_current_graph(&fixture, &mut reader);
    let connection = fixture.connection();
    connection
        .execute_batch(
            "CREATE TRIGGER fixture_current_revision AFTER INSERT ON events
         BEGIN UPDATE runtime_sessions SET revision=NEW.sequence
               WHERE session_id='session.current'; END;",
        )
        .unwrap();
    let path = fixture.database.clone();
    let writer = thread::spawn(move || {
        let mut store = PodBayStore::open(path).unwrap();
        for index in 0..100 {
            let target = format!("target.concurrent.{index}");
            store
                .advance_target_epoch("scope.main", &target, 0, 1)
                .unwrap();
            admit(
                &mut store,
                "scope.main",
                &target,
                &format!("key.concurrent.{index}"),
            );
        }
    });
    for _ in 0..100 {
        let snapshot = reader
            .current_scope_snapshot("scope.main", &actor, 1, 1, revision)
            .unwrap();
        assert_eq!(
            snapshot.sessions[0].revision,
            snapshot.cursor.sequence as u64
        );
    }
    writer.join().unwrap();
}


#[test]
fn altered_v19_scope_index_refuses_open() {
    let fixture = Fixture::new();
    drop(PodBayStore::open(&fixture.database).unwrap());
    let connection = fixture.connection();
    connection
        .execute_batch(
            "DROP INDEX runtime_sessions_open_scope_v19;
             CREATE INDEX runtime_sessions_open_scope_v19
               ON runtime_sessions(scope_id,session_id);",
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        PodBayStore::open(&fixture.database),
        Err(StoreError::Conflict("v19 current scope index differs"))
    ));
}
