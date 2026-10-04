use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_core::{
    AttemptId, AttestedPeer, Epoch, PodFenceIdentity, PodId, ScopeId, StoreLineageId,
};
use podbay_store::{PodBayStore, SqliteManagerPeerWitness, StoreError};

struct Fixture {
    directory: PathBuf,
    database: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "podbay-manager-peer-{}-{stamp}",
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


fn peer(birth: &str) -> AttestedPeer {
    AttestedPeer::from_port(
        "linux.uid.1000",
        "linux.pid.701",
        "linux.boot.fixture",
        birth,
        "linux.cgroup.manager.fixture",
    )
    .unwrap()
}

fn seed_bound_identity(store: &mut PodBayStore, fixture: &Fixture) -> PodFenceIdentity {
    let lineage = store.initial_cursor("scope.fixture").unwrap().store_lineage;
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys=ON;
         INSERT INTO runtime_sessions(session_id,scope_id,actor_id,revision,state,current_run_id)
           VALUES('session.fixture','scope.fixture','actor.fixture',2,'open','run.fixture');
         INSERT INTO runtime_runs(run_id,session_id,scope_id,role,work_kind,revision,
           admission_state,desired_mode,execution_state,current_attempt_id,last_attempt_ordinal)
           VALUES('run.fixture','session.fixture','scope.fixture','worker','task',3,
             'admitted','run','starting','attempt.fixture',1);
         INSERT INTO commands(command_id,principal,namespace,command_key,scope_id,target_id,
           digest_version,request_digest,canonical_request,owner_epoch,target_epoch)
           VALUES('command.fixture','principal.fixture','podbay.launch','launch.fixture',
             'scope.fixture','pod.fixture','pb04-request-bytes/1',
             'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',X'01',1,1);
         INSERT INTO launch_slots(scope_id,pod_id,pod_incarnation,command_rowid)
           SELECT 'scope.fixture','pod.fixture',1,command_rowid FROM commands;
         INSERT INTO launch_bindings(command_rowid,scope_id,session_id,run_id,attempt_id,
           attempt_ordinal,attempt_epoch,pod_id,pod_incarnation,resource_count,
           effective_spec_version,effective_spec_digest,effective_spec,
           descriptor_version,descriptor_digest,descriptor)
           SELECT command_rowid,'scope.fixture','session.fixture','run.fixture','attempt.fixture',
             1,1,'pod.fixture',1,1,'podbay.effective-launch/1',
             'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',X'01',
             'podbay.launch-descriptor/1',
             'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',X'01'
           FROM commands;
         INSERT INTO launch_resources(command_rowid,resource_ordinal,resource_id,resource_kind,
           resource_epoch)
           SELECT command_rowid,0,'resource.fixture','auxiliary',1 FROM commands;
         INSERT INTO authority_pods(pod_id,scope_id,incarnation)
           VALUES('pod.fixture','scope.fixture',1);
         INSERT INTO target_epochs(scope_id,target_id,epoch)
           VALUES('scope.fixture','pod.fixture',1);",
        )
        .unwrap();
    PodFenceIdentity {
        scope_id: ScopeId::try_from("scope.fixture").unwrap(),
        pod_id: PodId::try_from("pod.fixture").unwrap(),
        attempt_id: AttemptId::try_from("attempt.fixture").unwrap(),
        incarnation: Epoch::new(1).unwrap(),
        store_lineage: StoreLineageId::try_from(lineage.as_str()).unwrap(),
    }
}

#[test]
fn exact_registration_idempotent_changed_birth_conflicts_and_old_owner_fences() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    store.begin_authority_replay(0, 1).unwrap();
    let claim = store.current_manager_credential_claim(1).unwrap();
    assert!(
        !store
            .current_manager_peer_matches(&claim, &peer("birth.one"))
            .unwrap()
    );
    store
        .register_current_manager_peer(&claim, &peer("birth.one"))
        .unwrap();
    store
        .register_current_manager_peer(&claim, &peer("birth.one"))
        .unwrap();
    assert!(
        store
            .current_manager_peer_matches(&claim, &peer("birth.one"))
            .unwrap()
    );
    assert!(
        !store
            .current_manager_peer_matches(&claim, &peer("birth.two"))
            .unwrap()
    );
    assert!(matches!(
        store.register_current_manager_peer(&claim, &peer("birth.two")),
        Err(StoreError::Conflict(
            "manager OS peer changed within one credential epoch"
        ))
    ));
    store.begin_authority_replay(1, 2).unwrap();
    assert!(matches!(
        store.current_manager_peer_matches(&claim, &peer("birth.one")),
        Err(StoreError::StaleEpoch)
    ));
    let current = store.current_manager_credential_claim(2).unwrap();
    assert!(
        !store
            .current_manager_peer_matches(&current, &peer("birth.one"))
            .unwrap()
    );
}

#[test]
fn pod_witness_uses_read_only_current_lineage_identity_and_kernel_peer_tuple() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    store.begin_authority_replay(0, 1).unwrap();
    let identity = seed_bound_identity(&mut store, &fixture);
    let witness = SqliteManagerPeerWitness::for_pod(&fixture.database, identity.clone());
    assert!(!witness.matches_current(1, 1, &peer("birth.one")));
    let claim = store.current_manager_credential_claim(1).unwrap();
    store
        .register_current_manager_peer(&claim, &peer("birth.one"))
        .unwrap();
    assert!(witness.matches_current(1, 1, &peer("birth.one")));
    assert!(!witness.matches_current(1, 1, &peer("birth.two")));
    assert!(!witness.matches_current(1, 2, &peer("birth.one")));
    let mut foreign_attempt = identity.clone();
    foreign_attempt.attempt_id = AttemptId::try_from("attempt.foreign").unwrap();
    assert!(
        !SqliteManagerPeerWitness::for_pod(&fixture.database, foreign_attempt).matches_current(
            1,
            1,
            &peer("birth.one")
        )
    );
    let mut foreign_lineage = identity.clone();
    foreign_lineage.store_lineage = StoreLineageId::try_from("store.foreign").unwrap();
    assert!(
        !SqliteManagerPeerWitness::for_pod(&fixture.database, foreign_lineage).matches_current(
            1,
            1,
            &peer("birth.one")
        )
    );
    let mut foreign_scope = identity;
    foreign_scope.scope_id = ScopeId::try_from("scope.foreign").unwrap();
    assert!(
        !SqliteManagerPeerWitness::for_pod(&fixture.database, foreign_scope).matches_current(
            1,
            1,
            &peer("birth.one")
        )
    );
    store.begin_authority_replay(1, 2).unwrap();
    assert!(!witness.matches_current(1, 1, &peer("birth.one")));
    assert!(!witness.matches_current(2, 2, &peer("birth.one")));
    let missing = fixture.directory.join("missing.sqlite");
    assert!(
        !SqliteManagerPeerWitness::for_pod(
            &missing,
            PodFenceIdentity {
                scope_id: ScopeId::try_from("scope.fixture").unwrap(),
                pod_id: PodId::try_from("pod.fixture").unwrap(),
                attempt_id: AttemptId::try_from("attempt.fixture").unwrap(),
                incarnation: Epoch::new(1).unwrap(),
                store_lineage: StoreLineageId::try_from("store.foreign").unwrap(),
            }
        )
        .matches_current(1, 1, &peer("birth.one"))
    );
    assert!(!missing.exists());
}


#[test]
fn competing_peer_registrations_have_one_winner() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    store.begin_authority_replay(0, 1).unwrap();
    drop(store);
    let barrier = Arc::new(Barrier::new(2));
    let mut workers = Vec::new();
    for birth in ["birth.one", "birth.two"] {
        let database = fixture.database.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            let mut store = PodBayStore::open(database).unwrap();
            let claim = store.current_manager_credential_claim(1).unwrap();
            barrier.wait();
            store.register_current_manager_peer(&claim, &peer(birth))
        }));
    }
    let results = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|value| value.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|value| matches!(
                value,
                Err(StoreError::Conflict(
                    "manager OS peer changed within one credential epoch"
                ))
            ))
            .count(),
        1
    );
}
