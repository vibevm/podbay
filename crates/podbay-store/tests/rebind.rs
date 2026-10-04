use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_core::{
    AttemptId, AttestedPeer, CommandKey, CredentialEpoch, Epoch, InputEpoch, OwnerEpoch,
    PendingPodProcessEvidence, PendingRebindSupersession, PodFenceIdentity, PodId, RebindLedger,
    RebindPhase, RebindProposal, RequestDigest, ResourceId, ScopeId, StoreLineageId,
    SupersessionLedger,
};
use podbay_store::{
    DurableRebindPhase, HostObservedPriorCheckpoint, PodBayStore, SqlitePriorObservedPendingLedger,
    SqliteRebindLedger, SqliteSupersessionLedger, StoreError, SupersessionStage,
};

struct Fixture {
    directory: PathBuf,
    database: PathBuf,
}
static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
impl Fixture {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "podbay-rebind-{}-{unique}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        Self {
            database: directory.join("store.sqlite"),
            directory,
        }
    }
    fn open(&self) -> PodBayStore {
        PodBayStore::open(&self.database).unwrap()
    }
    fn ledger(&self, proposal: &RebindProposal) -> SqliteRebindLedger {
        SqliteRebindLedger::for_pod(&self.database, proposal.identity.clone())
    }
    fn count(&self, table: &str) -> i64 {
        let connection = rusqlite::Connection::open(&self.database).unwrap();
        connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn owner(value: u64) -> OwnerEpoch {
    OwnerEpoch::new(value).unwrap()
}
fn credential(value: u64) -> CredentialEpoch {
    CredentialEpoch::new(value).unwrap()
}
fn input(value: u64) -> InputEpoch {
    InputEpoch::new(value).unwrap()
}
fn resource(id: &str) -> ResourceId {
    ResourceId::try_from(id).unwrap()
}

fn table_rows(connection: &rusqlite::Connection, table: &str) -> Vec<Vec<rusqlite::types::Value>> {
    let ordering = if matches!(
        table,
        "manager_rebinds" | "manager_rebind_prior_observations"
    ) {
        "rebind_rowid"
    } else {
        "rebind_rowid,resource_id"
    };
    let mut statement = connection
        .prepare(&format!("SELECT * FROM {table} ORDER BY {ordering}"))
        .unwrap();
    let columns = statement.column_count();
    statement
        .query_map([], |row| {
            (0..columns)
                .map(|index| row.get(index))
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

fn seed_existing_bound_pod(store: &mut PodBayStore, fixture: &Fixture) -> RebindProposal {
    store.advance_owner_epoch(0, 1).unwrap();
    // Synthetic committed v8 binding. Rebind must never manufacture an initial
    // launch, child, descriptor, or manager peer from these fixture rows.
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys=ON;
         INSERT INTO runtime_sessions(session_id,scope_id,actor_id,revision,state,current_run_id)
           VALUES('session.fixture','scope.fixture','actor.fixture',2,'open','run.fixture');
         INSERT INTO runtime_runs(run_id,session_id,scope_id,role,work_kind,revision,
           admission_state,desired_mode,execution_state,current_attempt_id,last_attempt_ordinal)
           VALUES('run.fixture','session.fixture','scope.fixture','coordinator','service',3,
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
             1,1,'pod.fixture',1,2,'podbay.effective-launch/1',
             'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',X'01',
             'podbay.launch-descriptor/1',
             'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',X'01'
           FROM commands;
         INSERT INTO launch_resources(command_rowid,resource_ordinal,resource_id,resource_kind,
           resource_epoch)
           SELECT command_rowid,0,'resource.pty','pty',1 FROM commands;
         INSERT INTO launch_resources(command_rowid,resource_ordinal,resource_id,resource_kind,
           resource_epoch)
           SELECT command_rowid,1,'resource.provider','structured_provider',1 FROM commands;
         INSERT INTO authority_pods(pod_id,scope_id,incarnation)
           VALUES('pod.fixture','scope.fixture',1);
         INSERT INTO target_epochs(scope_id,target_id,epoch)
           VALUES('scope.fixture','pod.fixture',1);
         INSERT INTO authority_resources(resource_id,scope_id,pod_id,pod_incarnation,
           resource_epoch,input_epoch)
           VALUES('resource.pty','scope.fixture','pod.fixture',1,1,1),
                 ('resource.provider','scope.fixture','pod.fixture',1,1,1);",
        )
        .unwrap();
    drop(connection);
    let lineage = store.initial_cursor("scope.fixture").unwrap().store_lineage;
    store.begin_authority_replay(1, 2).unwrap();
    let mut old = BTreeMap::new();
    let mut next = BTreeMap::new();
    for id in ["resource.pty", "resource.provider"] {
        old.insert(resource(id), input(1));
        next.insert(resource(id), input(2));
    }
    RebindProposal {
        identity: PodFenceIdentity {
            scope_id: ScopeId::try_from("scope.fixture").unwrap(),
            pod_id: PodId::try_from("pod.fixture").unwrap(),
            attempt_id: AttemptId::try_from("attempt.fixture").unwrap(),
            incarnation: Epoch::new(1).unwrap(),
            store_lineage: StoreLineageId::try_from(lineage.as_str()).unwrap(),
        },
        expected_owner_epoch: owner(1),
        next_owner_epoch: owner(2),
        expected_credential_epoch: credential(1),
        next_credential_epoch: credential(2),
        expected_input_epochs: old,
        next_input_epochs: next,
        next_manager: AttestedPeer::from_port(
            "linux.uid.1000",
            "pid.900",
            "boot.fixture",
            "birth.900",
            "manager.unit",
        )
        .unwrap(),
        command_key: CommandKey::try_from("rebind.fixture").unwrap(),
        digest: RequestDigest::parse(&"a".repeat(64)).unwrap(),
    }
}

fn skipped_rebind_after_live_pod_inspection(
    store: &mut PodBayStore,
    fixture: &Fixture,
) -> (RebindProposal, HostObservedPriorCheckpoint) {
    let mut proposal = seed_existing_bound_pod(store, fixture);
    store.begin_authority_replay(2, 3).unwrap();
    store.begin_authority_replay(3, 4).unwrap();
    proposal.next_owner_epoch = owner(4);
    proposal.next_credential_epoch = credential(4);
    for next in proposal.next_input_epochs.values_mut() {
        *next = input(4);
    }
    let claim = store.current_manager_credential_claim(4).unwrap();
    store
        .register_current_manager_peer(&claim, &proposal.next_manager)
        .unwrap();
    let observed = HostObservedPriorCheckpoint {
        identity: proposal.identity.clone(),
        phase: RebindPhase::Active,
        owner_epoch: proposal.expected_owner_epoch,
        credential_epoch: proposal.expected_credential_epoch,
        input_epochs: proposal.expected_input_epochs.clone(),
        checkpoint_digest: "c".repeat(64),
        supervisor_pid: 987,
        supervisor_start_ticks: 123,
        boot_id: "boot.fixture".into(),
        unit_name: "podbay-pod-fixture.service".into(),
        cgroup_path: "/user.slice/podbay-pod-fixture.service".into(),
    };
    (proposal, observed)
}

fn pending_recovery_intent(
    store: &mut PodBayStore,
    proposal: RebindProposal,
    observed: &HostObservedPriorCheckpoint,
    recovering_owner: u64,
    command_key: &str,
    digest: char,
) -> PendingRebindSupersession {
    let recovering_manager = AttestedPeer::from_port(
        "linux.uid.1000",
        &format!("pid.{}", 900 + recovering_owner),
        "boot.fixture",
        &format!("birth.{}", 900 + recovering_owner),
        "manager.unit",
    ).unwrap();
    let claim = store.current_manager_credential_claim(recovering_owner).unwrap();
    store.register_current_manager_peer(&claim, &recovering_manager).unwrap();
    let recovering_input_epochs = proposal.next_input_epochs.iter()
        .map(|(id, _)| (id.clone(), input(recovering_owner)))
        .collect();
    PendingRebindSupersession {
        abandoned: proposal,
        pending_phase: RebindPhase::PendingStore,
        pending_checkpoint_digest: RequestDigest::parse(&"d".repeat(64)).unwrap(),
        pending_process: PendingPodProcessEvidence {
            supervisor_process_id: observed.supervisor_pid.to_string(),
            supervisor_birth_identity: observed.supervisor_start_ticks.to_string(),
            child_process_id: "988".into(),
            child_birth_identity: "124".into(),
            boot_identity: observed.boot_id.clone(),
            containment_identity: observed.cgroup_path.clone(),
        },
        recovering_owner_epoch: owner(recovering_owner),
        recovering_credential_epoch: credential(recovering_owner),
        recovering_input_epochs,
        recovering_manager,
        command_key: CommandKey::try_from(command_key).unwrap(),
        digest: RequestDigest::parse(&digest.to_string().repeat(64)).unwrap(),
    }
}

#[test]
fn v21_pending_supersession_plans_once_and_pod_checkpoint_cas_is_exact() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let (proposal, observed) = skipped_rebind_after_live_pod_inspection(&mut store, &fixture);
    store.prepare_manager_rebind_from_host_observation(&proposal, &observed).unwrap();
    store.begin_authority_replay(4, 5).unwrap();
    let intent = pending_recovery_intent(
        &mut store, proposal.clone(), &observed, 5,
        "supersede.pending.c", 'e',
    );
    let first = store.plan_pending_rebind_supersession(&intent, None).unwrap();
    assert_eq!(first.stage, SupersessionStage::Planned);
    assert_eq!(store.plan_pending_rebind_supersession(&intent, None).unwrap(), first);
    assert_eq!(fixture.count("rebind_supersession_attempts"), 1);
    assert_eq!(fixture.count("rebind_supersession_resources"), 2);
    let witness = SqliteSupersessionLedger::for_pod(&fixture.database, proposal.identity.clone());
    assert!(witness.supersedes(&intent));
    let missing = fixture.directory.join("missing-supersession.sqlite");
    assert!(!SqliteSupersessionLedger::for_pod(&missing, proposal.identity.clone())
        .supersedes(&intent));
    assert!(!missing.exists());
    let corrupt = fixture.directory.join("corrupt-supersession.sqlite");
    std::fs::write(&corrupt, b"not sqlite").unwrap();
    assert!(!SqliteSupersessionLedger::for_pod(&corrupt, proposal.identity.clone())
        .supersedes(&intent));
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection.execute(
        "UPDATE rebind_supersession_attempts SET child_birth_identity='999'
         WHERE supersession_rowid=?1", [first.rowid],
    ).unwrap();
    assert!(!witness.supersedes(&intent));
    assert!(matches!(store.plan_pending_rebind_supersession(&intent, None),
        Err(StoreError::Conflict("supersession scalar proof differs"))));
    connection.execute(
        "UPDATE rebind_supersession_attempts SET child_birth_identity=?1
         WHERE supersession_rowid=?2",
        rusqlite::params![intent.pending_process.child_birth_identity.as_str(),first.rowid],
    ).unwrap();
    assert!(witness.supersedes(&intent));
    drop(connection);
    let mut changed = intent.clone();
    changed.digest = RequestDigest::parse(&"f".repeat(64)).unwrap();
    assert!(matches!(store.plan_pending_rebind_supersession(&changed, None),
        Err(StoreError::Conflict("supersession key changed exact intent"))));
    assert!(!witness.supersedes(&changed));
    let acknowledged = store.acknowledge_pending_rebind_supersession(
        &intent, &"a".repeat(64),
    ).unwrap();
    assert_eq!(acknowledged.stage, SupersessionStage::PodCheckpointed);
    assert_eq!(acknowledged.recovery_checkpoint_digest.as_deref(), Some("a".repeat(64).as_str()));
    assert_eq!(store.acknowledge_pending_rebind_supersession(
        &intent, &"a".repeat(64),
    ).unwrap(), acknowledged);
    assert!(matches!(store.acknowledge_pending_rebind_supersession(
        &intent, &"b".repeat(64),
    ), Err(StoreError::Conflict("recovery checkpoint digest changed"))));
    assert!(!witness.supersedes(&intent));
    assert_eq!(fixture.count("manager_rebinds"), 1);
}

#[test]
fn v21_later_manager_supersedes_only_latest_planned_attempt() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let (proposal, observed) = skipped_rebind_after_live_pod_inspection(&mut store, &fixture);
    store.prepare_manager_rebind_from_host_observation(&proposal, &observed).unwrap();
    store.begin_authority_replay(4, 5).unwrap();
    let c = pending_recovery_intent(&mut store, proposal.clone(), &observed, 5,
        "supersede.pending.c", 'e');
    let c_receipt = store.plan_pending_rebind_supersession(&c, None).unwrap();
    store.begin_authority_replay(5, 6).unwrap();
    let d = pending_recovery_intent(&mut store, proposal.clone(), &observed, 6,
        "supersede.pending.d", 'f');
    assert!(matches!(store.plan_pending_rebind_supersession(&d, None),
        Err(StoreError::StaleEpoch)));
    let d_receipt = store.plan_pending_rebind_supersession(&d, Some(c_receipt.rowid)).unwrap();
    assert!(d_receipt.rowid > c_receipt.rowid);
    let witness = SqliteSupersessionLedger::for_pod(&fixture.database, proposal.identity.clone());
    assert!(!witness.supersedes(&c));
    assert!(witness.supersedes(&d));
    assert!(matches!(store.acknowledge_pending_rebind_supersession(&c, &"a".repeat(64)),
        Err(StoreError::StaleEpoch)));
    store.acknowledge_pending_rebind_supersession(&d,&"a".repeat(64)).unwrap();
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let c_phase: String = connection.query_row(
        "SELECT phase FROM rebind_supersession_attempts WHERE supersession_rowid=?1",
        [c_receipt.rowid],|row|row.get(0),
    ).unwrap();
    let d_phase: String = connection.query_row(
        "SELECT phase FROM rebind_supersession_attempts WHERE supersession_rowid=?1",
        [d_receipt.rowid],|row|row.get(0),
    ).unwrap();
    assert_eq!((c_phase.as_str(),d_phase.as_str()),("planned","pod_checkpointed"));
    assert_eq!(fixture.count("manager_rebinds"), 1);
    assert_eq!(fixture.count("rebind_supersession_attempts"), 2);
}

#[test]
fn v21_d_reads_latest_c_planned_and_exact_historical_a_peer() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let (proposal, observed) = skipped_rebind_after_live_pod_inspection(&mut store, &fixture);
    let prior_peer = AttestedPeer::from_port(
        "linux.uid.1000","pid.100","boot.fixture","birth.100","manager.unit",
    ).unwrap();
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection.execute(
        "INSERT INTO manager_peer_bindings(store_lineage,owner_epoch,credential_epoch,
           peer_schema,os_identity,process_identity,boot_identity,birth_identity,containment_identity)
         VALUES(?1,1,1,'podbay.attested-peer/1',?2,?3,?4,?5,?6)",
        rusqlite::params![proposal.identity.store_lineage.as_str(),
            prior_peer.os_identity(),prior_peer.native_process_id(),prior_peer.boot_identity(),
            prior_peer.birth_identity(),prior_peer.containment_identity()],
    ).unwrap();
    drop(connection);
    store.prepare_manager_rebind_from_host_observation(&proposal, &observed).unwrap();
    store.begin_authority_replay(4,5).unwrap();
    let c = pending_recovery_intent(&mut store,proposal.clone(),&observed,5,
        "supersede.pending.c",'e');
    let receipt = store.plan_pending_rebind_supersession(&c,None).unwrap();
    store.begin_authority_replay(5,6).unwrap();
    let found = store.latest_planned_recovery_for_pod(&proposal.identity).unwrap().unwrap();
    assert_eq!(found.intent,c);
    assert_eq!(found.receipt,receipt);
    assert_eq!(found.prior_manager_peer,prior_peer);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection.execute(
        "UPDATE rebind_supersession_attempts SET intent_bytes=X'00'
         WHERE supersession_rowid=?1",[receipt.rowid],
    ).unwrap_err(); // STRICT length constraint refuses an invalid replacement.
    assert_eq!(store.latest_planned_recovery_for_pod(&proposal.identity).unwrap().unwrap(),found);
    connection.execute(
        "DELETE FROM manager_peer_bindings WHERE store_lineage=?1 AND owner_epoch=1
           AND credential_epoch=1",
        [proposal.identity.store_lineage.as_str()],
    ).unwrap();
    assert!(matches!(store.latest_planned_recovery_for_pod(&proposal.identity),
        Err(StoreError::Conflict("prior Active manager peer is unavailable"))));
}

#[test]
fn v21_supersession_rejects_foreign_peer_stale_vector_and_rolls_back_fault() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let (proposal, observed) = skipped_rebind_after_live_pod_inspection(&mut store, &fixture);
    store.prepare_manager_rebind_from_host_observation(&proposal, &observed).unwrap();
    store.begin_authority_replay(4, 5).unwrap();
    let intent = pending_recovery_intent(&mut store, proposal, &observed, 5,
        "supersede.pending.fault", 'e');
    let mut foreign = intent.clone();
    foreign.recovering_manager = AttestedPeer::from_port(
        "linux.uid.1000", "pid.999", "boot.fixture", "birth.999", "manager.unit",
    ).unwrap();
    assert!(matches!(store.plan_pending_rebind_supersession(&foreign, None),
        Err(StoreError::StaleEpoch)));
    let mut stale = intent.clone();
    stale.recovering_input_epochs.insert(resource("resource.pty"), input(4));
    assert!(matches!(store.plan_pending_rebind_supersession(&stale, None),
        Err(StoreError::InvalidInput(_))));
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection.execute_batch(
        "CREATE TRIGGER reject_supersession_child
         BEFORE INSERT ON rebind_supersession_resources
         BEGIN SELECT RAISE(ABORT,'fixture recovery rollback'); END;",
    ).unwrap();
    drop(connection);
    assert!(matches!(store.plan_pending_rebind_supersession(&intent, None),
        Err(StoreError::Storage(_))));
    assert_eq!(fixture.count("rebind_supersession_attempts"), 0);
    assert_eq!(fixture.count("rebind_supersession_resources"), 0);
    assert_eq!(fixture.count("manager_rebinds"), 1);
}

#[test]
fn v21_only_checkpointed_exact_recovery_excludes_abandoned_pending_or_activated_row() {
    for activated_store_only in [false, true] {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let (abandoned, prior) = skipped_rebind_after_live_pod_inspection(&mut store, &fixture);
        store.prepare_manager_rebind_from_host_observation(&abandoned, &prior).unwrap();
        if activated_store_only {
            store.acknowledge_prior_observed_pod_rebind(&abandoned, &"d".repeat(64)).unwrap();
            store.activate_prior_observed_manager_rebind(&abandoned, &"d".repeat(64)).unwrap();
        }
        store.begin_authority_replay(4, 5).unwrap();
        let mut intent = pending_recovery_intent(&mut store, abandoned.clone(), &prior, 5,
            "supersede.pending.c", 'e');
        if activated_store_only {
            intent.pending_phase = RebindPhase::PendingPod;
        }
        let mut recovered = prior.clone();
        recovered.input_epochs = abandoned.next_input_epochs.clone();
        recovered.checkpoint_digest = "a".repeat(64);
        let mut next = abandoned.clone();
        next.next_owner_epoch = owner(5);
        next.next_credential_epoch = credential(5);
        next.expected_input_epochs = abandoned.next_input_epochs.clone();
        next.next_input_epochs = intent.recovering_input_epochs.clone();
        next.next_manager = intent.recovering_manager.clone();
        next.command_key = CommandKey::try_from("rebind.after.recovery").unwrap();
        next.digest = RequestDigest::parse(&"b".repeat(64)).unwrap();
        assert!(store.prepare_manager_rebind_from_host_observation(&next, &recovered).is_err());
        let planned = store.plan_pending_rebind_supersession(&intent, None).unwrap();
        assert_eq!(planned.stage, SupersessionStage::Planned);
        assert!(store.prepare_manager_rebind_from_host_observation(&next, &recovered).is_err());
        store.acknowledge_pending_rebind_supersession(&intent, &recovered.checkpoint_digest)
            .unwrap();
        let mut wrong = recovered.clone();
        wrong.checkpoint_digest = "c".repeat(64);
        assert!(store.prepare_manager_rebind_from_host_observation(&next, &wrong).is_err());
        let accepted = store.prepare_manager_rebind_from_host_observation(&next, &recovered)
            .unwrap();
        assert_eq!(accepted.phase, DurableRebindPhase::Pending);
        let original = store.lookup_prior_observed_rebind(&abandoned).unwrap().unwrap();
        assert_eq!(original.receipt.phase, if activated_store_only {
            DurableRebindPhase::Activated
        } else {
            DurableRebindPhase::Pending
        });
        assert_eq!(fixture.count("manager_rebinds"), 2);
    }
}

#[test]
fn staged_rebind_reopens_at_every_phase_without_new_launch_or_child() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let proposal = seed_existing_bound_pod(&mut store, &fixture);
    let ledger = fixture.ledger(&proposal);
    assert!(!ledger.pending(&proposal));
    let first = store.prepare_manager_rebind(&proposal).unwrap();
    assert_eq!(first.phase, DurableRebindPhase::Pending);
    assert_eq!(fixture.count("manager_rebind_prior_observations"), 0);
    assert!(matches!(
        store.lookup_prior_observed_rebind(&proposal),
        Err(StoreError::Conflict(
            "legacy rebind has no prior checkpoint observation"
        ))
    ));
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    assert!(
        connection
            .execute("UPDATE manager_rebinds SET phase='activated'", [])
            .is_err()
    );
    drop(connection);
    assert!(ledger.pending(&proposal));
    assert!(!ledger.activated(&proposal));
    drop(store);
    let mut reopened = fixture.open();
    assert_eq!(reopened.prepare_manager_rebind(&proposal).unwrap(), first);
    let ack = reopened
        .acknowledge_pod_rebind(&proposal, "checkpoint.fixture")
        .unwrap();
    assert_eq!(ack.phase, DurableRebindPhase::PodAcknowledged);
    assert!(ledger.pending(&proposal));
    assert!(!ledger.activated(&proposal));
    drop(reopened);
    let mut reopened = fixture.open();
    assert_eq!(
        reopened
            .acknowledge_pod_rebind(&proposal, "checkpoint.fixture")
            .unwrap(),
        ack
    );
    let active = reopened
        .activate_manager_rebind(&proposal, "checkpoint.fixture")
        .unwrap();
    assert_eq!(active.phase, DurableRebindPhase::Activated);
    assert!(ledger.activated(&proposal));
    drop(reopened);
    let mut reopened = fixture.open();
    assert_eq!(
        reopened
            .activate_manager_rebind(&proposal, "checkpoint.fixture")
            .unwrap(),
        active
    );
    for table in [
        "commands",
        "launch_slots",
        "launch_bindings",
        "authority_pods",
        "manager_rebinds",
    ] {
        assert_eq!(fixture.count(table), 1, "{table}");
    }
    assert_eq!(fixture.count("manager_rebind_resources"), 2);
}




#[test]
fn v12_wider_checks_do_not_admit_skips_without_prior_checkpoint_proof() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let original = seed_existing_bound_pod(&mut store, &fixture);
    let mut skipped = original.clone();
    skipped.next_owner_epoch = owner(4);
    skipped.next_credential_epoch = credential(4);
    for next in skipped.next_input_epochs.values_mut() {
        *next = input(4);
    }
    skipped.command_key = CommandKey::try_from("rebind.skipped").unwrap();
    skipped.digest = RequestDigest::parse(&"b".repeat(64)).unwrap();
    assert!(matches!(
        store.prepare_manager_rebind(&skipped),
        Err(StoreError::InvalidInput(
            "rebind epochs or resource set are invalid"
        ))
    ));
    assert_eq!(fixture.count("manager_rebinds"), 0);
    assert_eq!(
        store.prepare_manager_rebind(&original).unwrap().phase,
        DurableRebindPhase::Pending
    );
}

#[test]
fn proof_bearing_skip_is_durable_but_not_yet_pod_effect_eligible() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let (proposal, observed) = skipped_rebind_after_live_pod_inspection(&mut store, &fixture);
    let receipt = store
        .prepare_manager_rebind_from_host_observation(&proposal, &observed)
        .unwrap();
    assert_eq!(receipt.phase, DurableRebindPhase::Pending);
    assert_eq!(fixture.count("manager_rebinds"), 1);
    assert_eq!(fixture.count("manager_rebind_resources"), 2);
    assert_eq!(fixture.count("manager_rebind_prior_observations"), 1);
    let readback = store
        .lookup_prior_observed_rebind(&proposal)
        .unwrap()
        .unwrap();
    assert_eq!(readback.receipt, receipt);
    assert_eq!(readback.checkpoint_digest, observed.checkpoint_digest);
    assert_eq!(readback.supervisor_pid, observed.supervisor_pid);
    assert_eq!(
        store
            .prepare_manager_rebind_from_host_observation(&proposal, &observed)
            .unwrap(),
        receipt
    );
    drop(store);
    let ledger = fixture.ledger(&proposal);
    assert!(
        !ledger.pending(&proposal),
        "v13 Pending lacks pod digest-before-effect support"
    );
    let mut reopened = fixture.open();
    assert_eq!(
        reopened
            .lookup_prior_observed_rebind(&proposal)
            .unwrap()
            .unwrap()
            .receipt,
        receipt
    );
    assert!(matches!(
        reopened.acknowledge_pod_rebind(&proposal, "checkpoint.next"),
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        reopened.activate_manager_rebind(&proposal, "checkpoint.next"),
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        reopened.prepare_manager_rebind(&proposal),
        Err(StoreError::InvalidInput(_))
    ));
}

#[test]
fn proof_bearing_duplicate_conflicts_on_changed_prior_or_command() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let (proposal, observed) = skipped_rebind_after_live_pod_inspection(&mut store, &fixture);
    let original = store
        .prepare_manager_rebind_from_host_observation(&proposal, &observed)
        .unwrap();
    let mut changed_digest = observed.clone();
    changed_digest.checkpoint_digest = "d".repeat(64);
    assert!(matches!(
        store.prepare_manager_rebind_from_host_observation(&proposal, &changed_digest),
        Err(StoreError::Conflict("prior checkpoint observation changed"))
    ));
    let mut changed_vector = observed.clone();
    *changed_vector.input_epochs.values_mut().next().unwrap() = input(2);
    assert!(matches!(
        store.prepare_manager_rebind_from_host_observation(&proposal, &changed_vector),
        Err(StoreError::Conflict(
            "prior checkpoint observation differs from proposal"
        ))
    ));
    let mut changed_command = proposal.clone();
    changed_command.digest = RequestDigest::parse(&"e".repeat(64)).unwrap();
    assert!(matches!(
        store.lookup_prior_observed_rebind(&changed_command),
        Err(StoreError::Conflict(_))
    ));
    let mut competing = proposal.clone();
    competing.command_key = CommandKey::try_from("rebind.competing.pending").unwrap();
    competing.digest = RequestDigest::parse(&"f".repeat(64)).unwrap();
    assert!(matches!(
        store.prepare_manager_rebind_from_host_observation(&competing, &observed),
        Err(StoreError::Conflict("another manager rebind is pending"))
    ));
    assert_eq!(
        store
            .lookup_prior_observed_rebind(&proposal)
            .unwrap()
            .unwrap()
            .receipt,
        original
    );
    assert_eq!(fixture.count("manager_rebinds"), 1);
    assert_eq!(fixture.count("manager_rebind_prior_observations"), 1);
}

#[test]
fn proof_bearing_pending_duplicate_refuses_after_destination_owner_changes() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let (proposal, observed) = skipped_rebind_after_live_pod_inspection(&mut store, &fixture);
    let original = store
        .prepare_manager_rebind_from_host_observation(&proposal, &observed)
        .unwrap();
    assert_eq!(original.phase, DurableRebindPhase::Pending);
    store.begin_authority_replay(4, 5).unwrap();
    assert!(matches!(
        store.prepare_manager_rebind_from_host_observation(&proposal, &observed),
        Err(StoreError::StaleEpoch)
    ));
    assert_eq!(fixture.count("manager_rebinds"), 1);
    assert_eq!(fixture.count("manager_rebind_prior_observations"), 1);
}

#[test]
fn proof_bearing_pending_pod_digest_ack_and_activation_are_exact_and_recoverable() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let (proposal, observed) = skipped_rebind_after_live_pod_inspection(&mut store, &fixture);
    let pending = store
        .prepare_manager_rebind_from_host_observation(&proposal, &observed)
        .unwrap();
    let ledger = SqlitePriorObservedPendingLedger::for_pod(&fixture.database, observed.clone());
    assert_eq!(pending.phase, DurableRebindPhase::Pending);
    assert!(ledger.pending(&proposal));
    assert!(!ledger.activated(&proposal));
    let digest = "d".repeat(64);
    let acknowledged = store
        .acknowledge_prior_observed_pod_rebind(&proposal, &digest)
        .unwrap();
    assert_eq!(acknowledged.phase, DurableRebindPhase::PodAcknowledged);
    assert_eq!(
        acknowledged.pod_checkpoint_ref.as_deref(),
        Some(digest.as_str())
    );
    assert!(ledger.pending(&proposal));
    assert!(!ledger.activated(&proposal));
    assert_eq!(
        store
            .acknowledge_prior_observed_pod_rebind(&proposal, &digest)
            .unwrap(),
        acknowledged
    );
    assert!(matches!(
        store.acknowledge_prior_observed_pod_rebind(&proposal, &"e".repeat(64)),
        Err(StoreError::Conflict(_))
    ));
    let activated = store
        .activate_prior_observed_manager_rebind(&proposal, &digest)
        .unwrap();
    assert_eq!(activated.phase, DurableRebindPhase::Activated);
    assert!(!ledger.pending(&proposal));
    assert!(ledger.activated(&proposal));
    drop(store);
    let mut reopened = fixture.open();
    assert_eq!(
        reopened
            .activate_prior_observed_manager_rebind(&proposal, &digest)
            .unwrap(),
        activated
    );
}

#[test]
fn proof_bearing_new_key_refuses_stale_destination_and_unregistered_manager_peer() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let (proposal, observed) = skipped_rebind_after_live_pod_inspection(&mut store, &fixture);
    let mut stale_owner = proposal.clone();
    stale_owner.next_owner_epoch = owner(3);
    assert!(matches!(
        store.prepare_manager_rebind_from_host_observation(&stale_owner, &observed),
        Err(StoreError::StaleEpoch)
    ));
    let mut stale_credential = proposal.clone();
    stale_credential.next_credential_epoch = credential(3);
    assert!(matches!(
        store.prepare_manager_rebind_from_host_observation(&stale_credential, &observed),
        Err(StoreError::StaleEpoch)
    ));
    let mut stale_input = proposal.clone();
    *stale_input.next_input_epochs.values_mut().next().unwrap() = input(3);
    assert!(matches!(
        store.prepare_manager_rebind_from_host_observation(&stale_input, &observed),
        Err(StoreError::StaleEpoch)
    ));
    let mut wrong_manager = proposal.clone();
    wrong_manager.next_manager = AttestedPeer::from_port(
        "linux.uid.1000",
        "pid.900",
        "boot.fixture",
        "birth.foreign",
        "manager.unit",
    )
    .unwrap();
    assert!(matches!(
        store.prepare_manager_rebind_from_host_observation(&wrong_manager, &observed),
        Err(StoreError::StaleEpoch)
    ));
    let mut foreign = observed.clone();
    foreign.identity.pod_id = PodId::try_from("pod.foreign").unwrap();
    assert!(matches!(
        store.prepare_manager_rebind_from_host_observation(&proposal, &foreign),
        Err(StoreError::WrongScope)
    ));
    let mut incomplete = observed.clone();
    incomplete.input_epochs.pop_first();
    assert!(matches!(
        store.prepare_manager_rebind_from_host_observation(&proposal, &incomplete),
        Err(StoreError::Conflict(_))
    ));
    let mut nonactive = observed.clone();
    nonactive.phase = RebindPhase::PendingStore;
    assert!(matches!(
        store.prepare_manager_rebind_from_host_observation(&proposal, &nonactive),
        Err(StoreError::InvalidInput(_))
    ));
    let mut uppercase_digest = observed.clone();
    uppercase_digest.checkpoint_digest = "A".repeat(64);
    assert!(matches!(
        store.prepare_manager_rebind_from_host_observation(&proposal, &uppercase_digest),
        Err(StoreError::InvalidInput(_))
    ));
    assert_eq!(fixture.count("manager_rebinds"), 0);
    assert_eq!(fixture.count("manager_rebind_prior_observations"), 0);
}

#[test]
fn missing_registered_manager_peer_refuses_proof_bearing_prepare() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let mut proposal = seed_existing_bound_pod(&mut store, &fixture);
    store.begin_authority_replay(2, 3).unwrap();
    store.begin_authority_replay(3, 4).unwrap();
    proposal.next_owner_epoch = owner(4);
    proposal.next_credential_epoch = credential(4);
    for next in proposal.next_input_epochs.values_mut() {
        *next = input(4);
    }
    let observed = HostObservedPriorCheckpoint {
        identity: proposal.identity.clone(),
        phase: RebindPhase::Active,
        owner_epoch: proposal.expected_owner_epoch,
        credential_epoch: proposal.expected_credential_epoch,
        input_epochs: proposal.expected_input_epochs.clone(),
        checkpoint_digest: "c".repeat(64),
        supervisor_pid: 987,
        supervisor_start_ticks: 123,
        boot_id: "boot.fixture".into(),
        unit_name: "podbay-pod-fixture.service".into(),
        cgroup_path: "/user.slice/podbay-pod-fixture.service".into(),
    };
    assert!(matches!(
        store.prepare_manager_rebind_from_host_observation(&proposal, &observed),
        Err(StoreError::StaleEpoch)
    ));
    assert_eq!(fixture.count("manager_rebinds"), 0);
}

#[test]
fn prior_observation_insert_failure_rolls_back_parent_and_resource_rows() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let (proposal, observed) = skipped_rebind_after_live_pod_inspection(&mut store, &fixture);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection.execute_batch(
        "CREATE TRIGGER reject_prior_observation BEFORE INSERT ON manager_rebind_prior_observations
         BEGIN SELECT RAISE(ABORT,'fixture rejected prior observation'); END;"
    ).unwrap();
    drop(connection);
    assert!(matches!(
        store.prepare_manager_rebind_from_host_observation(&proposal, &observed),
        Err(StoreError::Storage(_))
    ));
    assert_eq!(fixture.count("manager_rebinds"), 0);
    assert_eq!(fixture.count("manager_rebind_resources"), 0);
    assert_eq!(fixture.count("manager_rebind_prior_observations"), 0);
}


#[test]
fn owner_advances_before_pod_checkpoint_and_old_pending_witness_fails_closed() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let proposal = seed_existing_bound_pod(&mut store, &fixture);
    store.prepare_manager_rebind(&proposal).unwrap();
    store.begin_authority_replay(2, 3).unwrap();
    let ledger = fixture.ledger(&proposal);
    assert!(!ledger.pending(&proposal));
    assert!(matches!(
        store.acknowledge_pod_rebind(&proposal, "checkpoint.fixture"),
        Err(StoreError::StaleEpoch)
    ));
    assert_eq!(
        store.prepare_manager_rebind(&proposal).unwrap().phase,
        DurableRebindPhase::Pending
    );
    assert_eq!(fixture.count("manager_rebinds"), 1);
}

#[test]
fn exact_duplicate_conflict_and_foreign_identity_or_resource_set_refuse() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let proposal = seed_existing_bound_pod(&mut store, &fixture);
    let first = store.prepare_manager_rebind(&proposal).unwrap();
    assert_eq!(store.prepare_manager_rebind(&proposal).unwrap(), first);
    let mut competing = proposal.clone();
    competing.command_key = CommandKey::try_from("rebind.competing").unwrap();
    assert!(matches!(
        store.prepare_manager_rebind(&competing),
        Err(StoreError::Conflict("another manager rebind is pending"))
    ));
    let mut changed = proposal.clone();
    changed.digest = RequestDigest::parse(&"b".repeat(64)).unwrap();
    assert!(matches!(
        store.prepare_manager_rebind(&changed),
        Err(StoreError::Conflict(_))
    ));
    let mut changed = proposal.clone();
    changed.next_manager = AttestedPeer::from_port(
        "linux.uid.1000",
        "pid.901",
        "boot.fixture",
        "birth.901",
        "manager.unit",
    )
    .unwrap();
    assert!(matches!(
        store.prepare_manager_rebind(&changed),
        Err(StoreError::Conflict(_))
    ));
    let mut foreign = proposal.clone();
    foreign.identity.scope_id = ScopeId::try_from("scope.foreign").unwrap();
    assert!(!fixture.ledger(&proposal).pending(&foreign));
    assert!(matches!(
        store.prepare_manager_rebind(&foreign),
        Err(StoreError::WrongScope)
    ));
    let mut incomplete = proposal.clone();
    incomplete
        .next_input_epochs
        .remove(&resource("resource.pty"));
    assert!(matches!(
        store.prepare_manager_rebind(&incomplete),
        Err(StoreError::InvalidInput(_))
    ));
    let mut foreign_lineage = proposal.clone();
    foreign_lineage.identity.store_lineage = StoreLineageId::try_from("store.foreign").unwrap();
    assert!(!fixture.ledger(&proposal).pending(&foreign_lineage));
    assert!(matches!(
        store.prepare_manager_rebind(&foreign_lineage),
        Err(StoreError::WrongScope)
    ));
    assert_eq!(fixture.count("manager_rebinds"), 1);
}

#[test]
fn stale_resource_input_or_corrupt_peer_row_refuses_rebind_witness() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let proposal = seed_existing_bound_pod(&mut store, &fixture);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute(
            "UPDATE authority_resources SET input_epoch=3 WHERE resource_id='resource.pty'",
            [],
        )
        .unwrap();
    assert!(matches!(
        store.prepare_manager_rebind(&proposal),
        Err(StoreError::StaleEpoch)
    ));
    assert_eq!(fixture.count("manager_rebinds"), 0);
    connection
        .execute(
            "UPDATE authority_resources SET input_epoch=2 WHERE resource_id='resource.pty'",
            [],
        )
        .unwrap();
    store.prepare_manager_rebind(&proposal).unwrap();
    assert!(fixture.ledger(&proposal).pending(&proposal));
    connection
        .execute(
            "UPDATE manager_rebinds SET manager_birth_identity='birth.foreign'",
            [],
        )
        .unwrap();
    assert!(!fixture.ledger(&proposal).pending(&proposal));
    assert!(matches!(
        store.prepare_manager_rebind(&proposal),
        Err(StoreError::Conflict(_))
    ));
}

#[test]
fn missing_or_corrupt_read_only_ledger_refuses_without_creating_state() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let proposal = seed_existing_bound_pod(&mut store, &fixture);
    store.prepare_manager_rebind(&proposal).unwrap();
    let missing = SqliteRebindLedger::for_pod(
        fixture.directory.join("missing.sqlite"),
        proposal.identity.clone(),
    );
    assert!(!missing.pending(&proposal));
    assert!(!fixture.directory.join("missing.sqlite").exists());
    let corrupt_path = fixture.directory.join("corrupt.sqlite");
    std::fs::write(&corrupt_path, b"not sqlite").unwrap();
    let corrupt = SqliteRebindLedger::for_pod(corrupt_path, proposal.identity.clone());
    assert!(!corrupt.pending(&proposal));
    assert!(fixture.ledger(&proposal).pending(&proposal));
}




#[test]
fn prior_pending_ledger_exact_proof_is_read_only_and_never_activates() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let (proposal, observed) = skipped_rebind_after_live_pod_inspection(&mut store, &fixture);
    store
        .prepare_manager_rebind_from_host_observation(&proposal, &observed)
        .unwrap();
    let ledger = SqlitePriorObservedPendingLedger::for_pod(&fixture.database, observed);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let before_parent = table_rows(&connection, "manager_rebinds");
    let before_resources = table_rows(&connection, "manager_rebind_resources");
    let before_proof = table_rows(&connection, "manager_rebind_prior_observations");
    assert!(ledger.pending(&proposal));
    assert!(ledger.pending(&proposal));
    assert!(!ledger.activated(&proposal));
    assert!(!fixture.ledger(&proposal).pending(&proposal));
    assert_eq!(table_rows(&connection, "manager_rebinds"), before_parent);
    assert_eq!(
        table_rows(&connection, "manager_rebind_resources"),
        before_resources
    );
    assert_eq!(
        table_rows(&connection, "manager_rebind_prior_observations"),
        before_proof
    );

    // Emulate a future acknowledged row without opening today's ACK API.
    connection.execute("UPDATE manager_rebinds SET phase='pod_acknowledged',pod_checkpoint_ref='checkpoint.test'", []).unwrap();
    assert!(!ledger.pending(&proposal));
    assert!(!ledger.activated(&proposal));
    connection
        .execute("UPDATE manager_rebinds SET phase='activated'", [])
        .unwrap();
    assert!(!ledger.pending(&proposal));
    assert!(!ledger.activated(&proposal));
}

#[test]
fn prior_pending_ledger_refuses_changed_digest_identity_vectors_and_process_evidence() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let (proposal, observed) = skipped_rebind_after_live_pod_inspection(&mut store, &fixture);
    store
        .prepare_manager_rebind_from_host_observation(&proposal, &observed)
        .unwrap();
    macro_rules! reject_changed {
        ($field:ident, $value:expr) => {{
            let mut changed = observed.clone();
            changed.$field = $value;
            let ledger = SqlitePriorObservedPendingLedger::for_pod(&fixture.database, changed);
            assert!(!ledger.pending(&proposal), stringify!($field));
            assert!(!ledger.activated(&proposal));
        }};
    }
    reject_changed!(checkpoint_digest, "d".repeat(64));
    reject_changed!(supervisor_pid, observed.supervisor_pid + 1);
    reject_changed!(supervisor_start_ticks, observed.supervisor_start_ticks + 1);
    reject_changed!(boot_id, "boot.other".into());
    reject_changed!(unit_name, "podbay-pod-other.service".into());
    reject_changed!(
        cgroup_path,
        "/other.slice/podbay-pod-fixture.service".into()
    );
    reject_changed!(phase, RebindPhase::PendingPod);
    reject_changed!(owner_epoch, owner(2));
    reject_changed!(credential_epoch, credential(2));
    reject_changed!(input_epochs, BTreeMap::new());
    let mut foreign = observed.identity.clone();
    foreign.store_lineage = StoreLineageId::try_from("store.foreign").unwrap();
    reject_changed!(identity, foreign);

    let ledger = SqlitePriorObservedPendingLedger::for_pod(&fixture.database, observed);
    let mut changed = proposal.clone();
    changed.digest = RequestDigest::parse(&"e".repeat(64)).unwrap();
    assert!(!ledger.pending(&changed));
    changed = proposal.clone();
    changed.next_owner_epoch = owner(u64::MAX);
    assert!(!ledger.pending(&changed));
    changed = proposal.clone();
    changed.next_credential_epoch = changed.expected_credential_epoch;
    assert!(!ledger.pending(&changed));
    changed = proposal.clone();
    changed.next_input_epochs.remove(&resource("resource.pty"));
    assert!(!ledger.pending(&changed));
    assert!(ledger.pending(&proposal));
}

#[test]
fn prior_pending_ledger_refuses_fresh_destination_or_stored_proof_drift() {
    for mutation in [
        "UPDATE metadata SET value=5 WHERE key='owner_epoch'",
        "UPDATE manager_credential_claims SET credential_epoch=5",
        "UPDATE manager_peer_bindings SET birth_identity='birth.changed'",
        "UPDATE authority_resources SET input_epoch=5 WHERE resource_id='resource.pty'",
        "DELETE FROM authority_resources WHERE resource_id='resource.pty'",
        "DELETE FROM manager_rebind_resources WHERE resource_id='resource.pty'",
        "UPDATE manager_rebinds SET manager_birth_identity='birth.changed'",
        "UPDATE manager_rebind_prior_observations SET checkpoint_digest='0000000000000000000000000000000000000000000000000000000000000000'",
        "DELETE FROM manager_rebind_prior_observations",
        "PRAGMA ignore_check_constraints=ON; UPDATE manager_rebind_prior_observations SET schema_version='unknown';",
        "PRAGMA ignore_check_constraints=ON; UPDATE manager_rebinds SET phase='unknown';",
        "PRAGMA ignore_check_constraints=ON; UPDATE manager_rebinds SET pod_checkpoint_ref='unexpected';",
        "PRAGMA ignore_check_constraints=ON; UPDATE manager_rebinds SET phase='pod_acknowledged',pod_checkpoint_ref=NULL;",
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let (proposal, observed) = skipped_rebind_after_live_pod_inspection(&mut store, &fixture);
        store
            .prepare_manager_rebind_from_host_observation(&proposal, &observed)
            .unwrap();
        let ledger = SqlitePriorObservedPendingLedger::for_pod(&fixture.database, observed);
        assert!(ledger.pending(&proposal));
        let connection = rusqlite::Connection::open(&fixture.database).unwrap();
        connection.execute_batch(mutation).unwrap();
        assert!(!ledger.pending(&proposal), "{mutation}");
        assert!(!ledger.activated(&proposal));
    }
}

#[test]
fn prior_pending_ledger_refuses_legacy_and_missing_or_corrupt_database() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let proposal = seed_existing_bound_pod(&mut store, &fixture);
    store.prepare_manager_rebind(&proposal).unwrap();
    let observed = HostObservedPriorCheckpoint {
        identity: proposal.identity.clone(),
        phase: RebindPhase::Active,
        owner_epoch: proposal.expected_owner_epoch,
        credential_epoch: proposal.expected_credential_epoch,
        input_epochs: proposal.expected_input_epochs.clone(),
        checkpoint_digest: "c".repeat(64),
        supervisor_pid: 987,
        supervisor_start_ticks: 123,
        boot_id: "boot.fixture".into(),
        unit_name: "podbay-pod-fixture.service".into(),
        cgroup_path: "/user.slice/podbay-pod-fixture.service".into(),
    };
    let ledger = SqlitePriorObservedPendingLedger::for_pod(&fixture.database, observed.clone());
    assert!(!ledger.pending(&proposal));
    assert!(fixture.ledger(&proposal).pending(&proposal));
    let missing_path = fixture.directory.join("missing-prior.sqlite");
    let missing = SqlitePriorObservedPendingLedger::for_pod(&missing_path, observed.clone());
    assert!(!missing.pending(&proposal));
    assert!(!missing_path.exists());
    let corrupt_path = fixture.directory.join("corrupt-prior.sqlite");
    std::fs::write(&corrupt_path, b"not a database").unwrap();
    let corrupt = SqlitePriorObservedPendingLedger::for_pod(&corrupt_path, observed);
    assert!(!corrupt.pending(&proposal));
    assert_eq!(std::fs::read(corrupt_path).unwrap(), b"not a database");
}


fn store_only_successor(
    store: &mut PodBayStore,
    abandoned: &RebindProposal,
    owner_epoch: u64,
    key: &str,
) -> RebindProposal {
    let mut next = abandoned.clone();
    next.next_owner_epoch = owner(owner_epoch);
    next.next_credential_epoch = credential(owner_epoch);
    for epoch in next.next_input_epochs.values_mut() {
        *epoch = input(owner_epoch);
    }
    next.next_manager = AttestedPeer::from_port(
        "linux.uid.1000",
        &format!("pid.{}", 900 + owner_epoch),
        "boot.fixture",
        &format!("birth.{}", 900 + owner_epoch),
        "manager.unit",
    )
    .unwrap();
    next.command_key = CommandKey::try_from(key).unwrap();
    next.digest = RequestDigest::parse(&format!("{:064x}", owner_epoch)).unwrap();
    let claim = store.current_manager_credential_claim(owner_epoch).unwrap();
    store
        .register_current_manager_peer(&claim, &next.next_manager)
        .unwrap();
    next
}

#[test]
fn v21_active_prior_store_only_abandonment_is_atomic_exact_and_chainable() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let (b, observed) = skipped_rebind_after_live_pod_inspection(&mut store, &fixture);
    store
        .prepare_manager_rebind_from_host_observation(&b, &observed)
        .unwrap();
    assert_eq!(
        store
            .lookup_store_only_pending_rebind(&b.identity)
            .unwrap()
            .unwrap()
            .proposal,
        b
    );
    store.begin_authority_replay(4, 5).unwrap();
    let c = store_only_successor(&mut store, &b, 5, "rebind.active-prior.c");
    let first = store
        .prepare_manager_rebind_after_active_prior(&c, &observed, &b, 988, 124)
        .unwrap();
    assert_eq!(first.phase, DurableRebindPhase::Pending);
    assert_eq!(
        store
            .prepare_manager_rebind_after_active_prior(&c, &observed, &b, 988, 124,)
            .unwrap(),
        first
    );
    assert!(matches!(
        store.prepare_manager_rebind_after_active_prior(&c, &observed, &b, 989, 124,),
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(fixture.count("manager_rebinds"), 2);
    assert_eq!(fixture.count("rebind_supersession_attempts"), 1);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let recorded: (String, String, String) = connection
        .query_row(
            "SELECT observed_phase,phase,recovery_checkpoint_digest
         FROM rebind_supersession_attempts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        recorded,
        (
            "active_prior".into(),
            "pod_checkpointed".into(),
            observed.checkpoint_digest.clone()
        )
    );
    assert_eq!(
        store
            .lookup_store_only_pending_rebind(&b.identity)
            .unwrap()
            .unwrap()
            .proposal,
        c
    );
    store.begin_authority_replay(5, 6).unwrap();
    let d = store_only_successor(&mut store, &c, 6, "rebind.active-prior.d");
    assert_eq!(
        store
            .prepare_manager_rebind_after_active_prior(&d, &observed, &c, 988, 124,)
            .unwrap()
            .phase,
        DurableRebindPhase::Pending
    );
    assert_eq!(fixture.count("manager_rebinds"), 3);
    assert_eq!(fixture.count("rebind_supersession_attempts"), 2);
    assert_eq!(
        store
            .lookup_store_only_pending_rebind(&b.identity)
            .unwrap()
            .unwrap()
            .proposal,
        d
    );
}

#[test]
fn v21_active_prior_refuses_wrong_live_proof_and_rolls_back_after_side_insert() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let (b, observed) = skipped_rebind_after_live_pod_inspection(&mut store, &fixture);
    store
        .prepare_manager_rebind_from_host_observation(&b, &observed)
        .unwrap();
    store.begin_authority_replay(4, 5).unwrap();
    let c = store_only_successor(&mut store, &b, 5, "rebind.active-prior.rollback");
    let mut wrong = observed.clone();
    wrong.checkpoint_digest = "e".repeat(64);
    assert!(matches!(
        store.prepare_manager_rebind_after_active_prior(&c, &wrong, &b, 988, 124,),
        Err(StoreError::Conflict(_))
    ));
    wrong = observed.clone();
    wrong.supervisor_start_ticks += 1;
    assert!(matches!(
        store.prepare_manager_rebind_after_active_prior(&c, &wrong, &b, 988, 124,),
        Err(StoreError::Conflict(_))
    ));
    let mut old_manager = c.clone();
    old_manager.next_manager = b.next_manager.clone();
    assert!(matches!(
        store.prepare_manager_rebind_after_active_prior(&old_manager, &observed, &b, 988, 124,),
        Err(StoreError::Conflict(_))
    ));
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER reject_active_prior_c BEFORE INSERT ON manager_rebind_resources
         WHEN NEW.next_input_epoch=5 BEGIN SELECT RAISE(ABORT,'fixture insert refused'); END;",
        )
        .unwrap();
    assert!(
        store
            .prepare_manager_rebind_after_active_prior(&c, &observed, &b, 988, 124,)
            .is_err()
    );
    assert_eq!(fixture.count("manager_rebinds"), 1);
    assert_eq!(fixture.count("rebind_supersession_attempts"), 0);
    assert_eq!(fixture.count("rebind_supersession_resources"), 0);
}
