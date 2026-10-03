use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_core::{
    AttemptId, AttestedPeer, CommandKey, CredentialEpoch, Epoch, InputEpoch, OwnerEpoch,
    PodFenceIdentity, PodId, RebindLedger, RebindProposal, RequestDigest, ResourceId, ScopeId,
    StoreLineageId,
};
use podbay_store::{DurableRebindPhase, PodBayStore, SqliteRebindLedger, StoreError};

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
    let ordering = if table == "manager_rebinds" {
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

#[test]
fn staged_rebind_reopens_at_every_phase_without_new_launch_or_child() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let proposal = seed_existing_bound_pod(&mut store, &fixture);
    let ledger = fixture.ledger(&proposal);
    assert!(!ledger.pending(&proposal));
    let first = store.prepare_manager_rebind(&proposal).unwrap();
    assert_eq!(first.phase, DurableRebindPhase::Pending);
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
fn v9_and_v11_to_v12_preserve_pending_ack_active_rows_and_sequence() {
    for old_version in [9, 11] {
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
            restore_v11_rebind_checks(&connection);
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
            assert_eq!(version, 12);
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
            "DROP TABLE manager_peer_bindings;
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
            "DROP TABLE manager_peer_bindings;
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
