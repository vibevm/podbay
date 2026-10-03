use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_core::{
    AttemptId, AttestedPeer, CommandKey, CredentialEpoch, Epoch, InputEpoch, OwnerEpoch,
    PodFenceIdentity, PodId, RebindLedger, RebindPhase, RebindProposal, RequestDigest, ResourceId,
    ScopeId, StoreLineageId,
};
use podbay_store::{
    DurableRebindPhase, HostObservedPriorCheckpoint, PodBayStore, SqlitePriorObservedPendingLedger,
    SqliteRebindLedger, StoreError,
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

// Exact historical v9/v11 table SQL. Test fixtures rebuild the old CHECKs
// with committed rows so the production v12 migration has real work to copy.
const OLD_REBINDS: &str = "CREATE TABLE manager_rebinds (
  rebind_rowid INTEGER PRIMARY KEY AUTOINCREMENT,
  store_lineage TEXT NOT NULL REFERENCES store_identity(lineage),
  scope_id TEXT NOT NULL CHECK(length(scope_id)>0),
  pod_id TEXT NOT NULL CHECK(length(pod_id)>0),
  attempt_id TEXT NOT NULL CHECK(length(attempt_id)>0),
  pod_incarnation INTEGER NOT NULL CHECK(pod_incarnation>=1),
  expected_owner_epoch INTEGER NOT NULL CHECK(expected_owner_epoch>=1),
  next_owner_epoch INTEGER NOT NULL CHECK(next_owner_epoch=expected_owner_epoch+1),
  expected_credential_epoch INTEGER NOT NULL CHECK(expected_credential_epoch>=1),
  next_credential_epoch INTEGER NOT NULL
    CHECK(next_credential_epoch=expected_credential_epoch+1),
  manager_os_identity TEXT NOT NULL CHECK(length(manager_os_identity)>0),
  manager_process_id TEXT NOT NULL CHECK(length(manager_process_id)>0),
  manager_boot_identity TEXT NOT NULL CHECK(length(manager_boot_identity)>0),
  manager_birth_identity TEXT NOT NULL CHECK(length(manager_birth_identity)>0),
  manager_containment TEXT NOT NULL CHECK(length(manager_containment)>0),
  command_key TEXT NOT NULL CHECK(length(command_key)>0),
  request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
  resource_count INTEGER NOT NULL CHECK(resource_count>=1),
  phase TEXT NOT NULL CHECK(phase IN ('pending','pod_acknowledged','activated')),
  pod_checkpoint_ref TEXT,
  CHECK((phase='pending' AND pod_checkpoint_ref IS NULL)
    OR (phase!='pending' AND pod_checkpoint_ref IS NOT NULL
      AND length(pod_checkpoint_ref)>0)),
  FOREIGN KEY(scope_id,pod_id,pod_incarnation)
    REFERENCES launch_bindings(scope_id,pod_id,pod_incarnation),
  UNIQUE(scope_id,pod_id,pod_incarnation,next_owner_epoch),
  UNIQUE(scope_id,pod_id,pod_incarnation,command_key)
) STRICT";
const OLD_RESOURCES: &str = "CREATE TABLE manager_rebind_resources (
  rebind_rowid INTEGER NOT NULL REFERENCES manager_rebinds(rebind_rowid),
  resource_id TEXT NOT NULL CHECK(length(resource_id)>0),
  expected_input_epoch INTEGER NOT NULL CHECK(expected_input_epoch>=1),
  next_input_epoch INTEGER NOT NULL CHECK(next_input_epoch=expected_input_epoch+1),
  PRIMARY KEY(rebind_rowid,resource_id)
) STRICT";

fn restore_v11_rebind_checks(connection: &rusqlite::Connection) {
    connection
        .execute_batch("DROP TABLE manager_rebind_prior_observations;")
        .unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys=OFF;
         BEGIN IMMEDIATE;
         ALTER TABLE manager_rebind_resources RENAME TO manager_rebind_resources_new;
         ALTER TABLE manager_rebinds RENAME TO manager_rebinds_new;",
        )
        .unwrap();
    connection
        .execute_batch(&format!("{OLD_REBINDS};{OLD_RESOURCES};"))
        .unwrap();
    connection
        .execute_batch(
            "INSERT INTO manager_rebinds(
           rebind_rowid,store_lineage,scope_id,pod_id,attempt_id,pod_incarnation,
           expected_owner_epoch,next_owner_epoch,expected_credential_epoch,next_credential_epoch,
           manager_os_identity,manager_process_id,manager_boot_identity,manager_birth_identity,
           manager_containment,command_key,request_digest,resource_count,phase,pod_checkpoint_ref)
         SELECT rebind_rowid,store_lineage,scope_id,pod_id,attempt_id,pod_incarnation,
           expected_owner_epoch,next_owner_epoch,expected_credential_epoch,next_credential_epoch,
           manager_os_identity,manager_process_id,manager_boot_identity,manager_birth_identity,
           manager_containment,command_key,request_digest,resource_count,phase,pod_checkpoint_ref
         FROM manager_rebinds_new ORDER BY rebind_rowid;
         INSERT INTO manager_rebind_resources(rebind_rowid,resource_id,
           expected_input_epoch,next_input_epoch)
         SELECT rebind_rowid,resource_id,expected_input_epoch,next_input_epoch
         FROM manager_rebind_resources_new ORDER BY rebind_rowid,resource_id;
         DROP TABLE manager_rebind_resources_new;
         DROP TABLE manager_rebinds_new;
         COMMIT;
         PRAGMA foreign_keys=ON;",
        )
        .unwrap();
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
fn v9_v11_v12_to_v13_preserve_legacy_rows_without_prior_observation() {
    for old_version in [9, 11, 12] {
        for phase in [
            DurableRebindPhase::Pending,
            DurableRebindPhase::PodAcknowledged,
            DurableRebindPhase::Activated,
        ] {
            let fixture = Fixture::new();
            let mut store = fixture.open();
            let proposal = seed_existing_bound_pod(&mut store, &fixture);
            let mut receipt = store.prepare_manager_rebind(&proposal).unwrap();
            if phase != DurableRebindPhase::Pending {
                receipt = store
                    .acknowledge_pod_rebind(&proposal, "checkpoint.fixture")
                    .unwrap();
            }
            if phase == DurableRebindPhase::Activated {
                receipt = store
                    .activate_manager_rebind(&proposal, "checkpoint.fixture")
                    .unwrap();
            }
            assert_eq!(receipt.phase, phase);
            drop(store);
            let connection = rusqlite::Connection::open(&fixture.database).unwrap();
            if old_version == 12 {
                connection
                    .execute_batch("DROP TABLE manager_rebind_prior_observations;")
                    .unwrap();
            } else {
                restore_v11_rebind_checks(&connection);
            }
            if old_version == 9 {
                connection
                    .execute_batch(
                        "DROP TABLE manager_peer_bindings; DROP TABLE manager_credential_claims;",
                    )
                    .unwrap();
            }
            connection
                .execute(
                    "UPDATE sqlite_sequence SET seq=7 WHERE name='manager_rebinds'",
                    [],
                )
                .unwrap();
            connection
                .pragma_update(None, "user_version", old_version)
                .unwrap();
            let before_parent = table_rows(&connection, "manager_rebinds");
            let before_child = table_rows(&connection, "manager_rebind_resources");
            drop(connection);

            let mut migrated = fixture.open();
            assert_eq!(migrated.prepare_manager_rebind(&proposal).unwrap(), receipt);
            drop(migrated);
            let connection = rusqlite::Connection::open(&fixture.database).unwrap();
            let version: i64 = connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(version, 13);
            let prior_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM manager_rebind_prior_observations",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(prior_count, 0);
            assert_eq!(table_rows(&connection, "manager_rebinds"), before_parent);
            assert_eq!(
                table_rows(&connection, "manager_rebind_resources"),
                before_child
            );
            let sequence: i64 = connection
                .query_row(
                    "SELECT seq FROM sqlite_sequence WHERE name='manager_rebinds'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(sequence, 7);
            let foreign_keys: i64 = connection
                .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(foreign_keys, 0);
            let parent_sql: String = connection
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE name='manager_rebinds'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let child_sql: String = connection
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE name='manager_rebind_resources'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(parent_sql.contains("next_owner_epoch>expected_owner_epoch"));
            assert!(parent_sql.contains("next_credential_epoch>expected_credential_epoch"));
            assert!(child_sql.contains("next_input_epoch>expected_input_epoch"));
        }
    }
}

#[test]
fn malformed_v11_schema_refuses_before_copy_and_preserves_rows() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let proposal = seed_existing_bound_pod(&mut store, &fixture);
    store.prepare_manager_rebind(&proposal).unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    restore_v11_rebind_checks(&connection);
    connection
        .execute_batch(
            "ALTER TABLE manager_rebind_resources ADD COLUMN malformed INTEGER;
         PRAGMA user_version=11;",
        )
        .unwrap();
    let before = table_rows(&connection, "manager_rebinds");
    drop(connection);
    assert!(matches!(
        PodBayStore::open(&fixture.database),
        Err(StoreError::Conflict("v9 rebind schema differs"))
    ));
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 11);
    assert_eq!(table_rows(&connection, "manager_rebinds"), before);
}

#[test]
fn copy_failure_rolls_back_v12_table_swap_and_version() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let proposal = seed_existing_bound_pod(&mut store, &fixture);
    store.prepare_manager_rebind(&proposal).unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    restore_v11_rebind_checks(&connection);
    connection
        .execute_batch(
            "PRAGMA foreign_keys=OFF;
         INSERT INTO manager_rebind_resources(
           rebind_rowid,resource_id,expected_input_epoch,next_input_epoch)
           VALUES(9999,'resource.orphan',1,2);
         PRAGMA user_version=11;",
        )
        .unwrap();
    let before_parent = table_rows(&connection, "manager_rebinds");
    let before_child = table_rows(&connection, "manager_rebind_resources");
    drop(connection);
    assert!(PodBayStore::open(&fixture.database).is_err());
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 11);
    assert_eq!(table_rows(&connection, "manager_rebinds"), before_parent);
    assert_eq!(
        table_rows(&connection, "manager_rebind_resources"),
        before_child
    );
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
fn malformed_v13_prior_observation_schema_refuses_migration_atomically() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let proposal = seed_existing_bound_pod(&mut store, &fixture);
    store.prepare_manager_rebind(&proposal).unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "DROP TABLE manager_rebind_prior_observations;
         CREATE TABLE manager_rebind_prior_observations(rebind_rowid INTEGER PRIMARY KEY) STRICT;
         PRAGMA user_version=12;",
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        PodBayStore::open(&fixture.database),
        Err(StoreError::Conflict(
            "v13 prior observation schema name already exists"
        ))
    ));
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 12);
    assert_eq!(fixture.count("manager_rebinds"), 1);
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
fn v8_to_v9_migration_preserves_existing_launch_without_inventing_rebind() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let proposal = seed_existing_bound_pod(&mut store, &fixture);
    let owner_before = store.owner_epoch().unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "DROP TABLE manager_rebind_prior_observations;
      DROP TABLE manager_peer_bindings;
      DROP TABLE manager_credential_claims;
      DROP TABLE manager_rebind_resources;
      DROP TABLE manager_rebinds; PRAGMA user_version=8;",
        )
        .unwrap();
    drop(connection);
    let mut migrated = fixture.open();
    assert_eq!(migrated.owner_epoch().unwrap(), owner_before);
    assert_eq!(fixture.count("launch_bindings"), 1);
    assert_eq!(fixture.count("launch_slots"), 1);
    assert_eq!(fixture.count("manager_rebinds"), 0);
    assert!(!fixture.ledger(&proposal).pending(&proposal));
    assert_eq!(
        migrated.prepare_manager_rebind(&proposal).unwrap().phase,
        DurableRebindPhase::Pending
    );
    drop(migrated);
    assert_eq!(fixture.count("manager_rebinds"), 1);
}

#[test]
fn first_v10_manager_claim_stays_above_v9_pod_rebind_credential_highwater() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let mut proposal = seed_existing_bound_pod(&mut store, &fixture);
    proposal.expected_credential_epoch = credential(20);
    proposal.next_credential_epoch = credential(21);
    store.prepare_manager_rebind(&proposal).unwrap();
    drop(store);

    // Reconstruct a v9 database with a durable pod-local rebind but no v10
    // manager claim. The old rebind remains evidence, not a manager identity.
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    restore_v11_rebind_checks(&connection);
    connection
        .execute_batch("DROP TABLE manager_peer_bindings; DROP TABLE manager_credential_claims; PRAGMA user_version=9;")
        .unwrap();
    drop(connection);
    let mut migrated = fixture.open();
    assert!(matches!(
        migrated.current_manager_credential_claim(2),
        Err(StoreError::NotFound)
    ));
    migrated.begin_authority_replay(2, 3).unwrap();
    let claim = migrated.current_manager_credential_claim(3).unwrap();
    assert_eq!(claim.credential_epoch(), 22);
    assert_eq!(fixture.count("manager_rebinds"), 1);
}

#[test]
fn malformed_preexisting_v9_schema_refuses_migration_atomically() {
    let fixture = Fixture::new();
    drop(fixture.open());
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "DROP TABLE manager_rebind_prior_observations;
      DROP TABLE manager_peer_bindings;
      DROP TABLE manager_credential_claims;
      DROP TABLE manager_rebind_resources;
      DROP TABLE manager_rebinds;
      CREATE TABLE manager_rebinds(rebind_rowid INTEGER PRIMARY KEY) STRICT;
      PRAGMA user_version=8;",
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        PodBayStore::open(&fixture.database),
        Err(StoreError::Conflict("v9 rebind schema name already exists"))
    ));
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 8);
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
    assert!(ledger.pending(&proposal));
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
