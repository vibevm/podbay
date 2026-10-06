#![cfg(unix)]

use std::fs::{self, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_store::{PodBayStore, StoreError, V25StagingError, stage_schema_v25};
use podbay_wire::{EFFECTIVE_LAUNCH_V2_VERSION, LAUNCH_DESCRIPTOR_V2_SCHEMA};
use rusqlite::{Connection, params};

struct Fixture {
    directory: PathBuf,
    source: PathBuf,
    staging: PathBuf,
    lineage: String,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("podbay-v25-staging-{}-{nonce}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let source = directory.join("podbay.sqlite");
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&source)
            .unwrap();
        drop(PodBayStore::open(&source).unwrap());

        let connection = Connection::open(&source).unwrap();
        let lineage: String = connection
            .query_row(
                "SELECT lineage FROM store_identity WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        connection
            .execute_batch("PRAGMA foreign_keys=ON; BEGIN IMMEDIATE;")
            .unwrap();
        connection
            .execute("UPDATE metadata SET value=2 WHERE key='owner_epoch'", [])
            .unwrap();
        connection
            .execute(
                "UPDATE metadata SET value=5 WHERE key='authority_revision'",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO commands(
                   command_rowid,command_id,principal,namespace,command_key,scope_id,target_id,
                   digest_version,request_digest,canonical_request,owner_epoch,target_epoch)
                 VALUES(1,'command.pb04.launch','fixture.principal','fixture.launch','launch.key',
                   'scope.alpha','pod.alpha','sha256-v1',?1,X'01',1,1)",
                ["a".repeat(64)],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO target_epochs(scope_id,target_id,epoch)
                 VALUES('scope.alpha','pod.alpha',1)",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO authority_pods(pod_id,scope_id,incarnation)
                 VALUES('pod.alpha','scope.alpha',1)",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO launch_slots(scope_id,pod_id,pod_incarnation,command_rowid)
                 VALUES('scope.alpha','pod.alpha',1,1)",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO runtime_sessions(
                   session_id,scope_id,actor_id,revision,state,current_run_id)
                 VALUES('session.alpha','scope.alpha','actor.alpha',1,'open','run.alpha')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO runtime_runs(
                   run_id,session_id,scope_id,role,work_kind,revision,admission_state,
                   desired_mode,execution_state,current_attempt_id,last_attempt_ordinal)
                 VALUES('run.alpha','session.alpha','scope.alpha','coordinator','codex',1,
                   'admitted','active','running','attempt.alpha',1)",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO launch_bindings(
                   command_rowid,scope_id,session_id,run_id,attempt_id,attempt_ordinal,
                   attempt_epoch,pod_id,pod_incarnation,resource_count,effective_spec_version,
                   effective_spec_digest,effective_spec,descriptor_version,descriptor_digest,
                   descriptor)
                 VALUES(1,'scope.alpha','session.alpha','run.alpha','attempt.alpha',1,1,
                   'pod.alpha',1,1,?1,?2,X'01',?3,?2,X'01')",
                params![
                    EFFECTIVE_LAUNCH_V2_VERSION,
                    "b".repeat(64),
                    LAUNCH_DESCRIPTOR_V2_SCHEMA
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO manager_rebinds(
                   rebind_rowid,store_lineage,scope_id,pod_id,attempt_id,pod_incarnation,
                   expected_owner_epoch,next_owner_epoch,expected_credential_epoch,
                   next_credential_epoch,manager_os_identity,manager_process_id,
                   manager_boot_identity,manager_birth_identity,manager_containment,
                   command_key,request_digest,resource_count,phase,pod_checkpoint_ref)
                 VALUES(1,?1,'scope.alpha','pod.alpha','attempt.alpha',1,1,2,1,2,
                   'uid:1000','pid:100','boot.old','birth.100','unit.scope','rebind.key',?2,1,
                   'activated','checkpoint.alpha')",
                params![lineage, "c".repeat(64)],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO manager_rebind_prior_observations(
                   rebind_rowid,schema_version,checkpoint_digest,supervisor_pid,
                   supervisor_start_ticks,boot_id,unit_name,cgroup_path)
                 VALUES(1,'podbay.prior-checkpoint/1',?1,100,200,'boot.old',
                   'podbay-alpha.service','/podbay/alpha')",
                ["d".repeat(64)],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO commands(
                   command_rowid,command_id,principal,namespace,command_key,scope_id,target_id,
                   digest_version,request_digest,canonical_request,owner_epoch,target_epoch)
                 VALUES(2,'command.pb04.stop','fixture.principal','fixture.stop','stop.key',
                   'scope.alpha','pod.alpha','sha256-v1',?1,X'02',2,1)",
                ["e".repeat(64)],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO outbox(
                   outbox_id,command_rowid,scope_id,target_id,owner_epoch,target_epoch,kind,payload,
                   state,claim_key,claim_owner_epoch,effect_digest)
                 VALUES(1,2,'scope.alpha','pod.alpha',2,1,'pod.stop',X'03',
                   'claimed_uncertain','claim.stop',2,?1)",
                ["f".repeat(64)],
            )
            .unwrap();
        connection.execute_batch("COMMIT;").unwrap();

        let staging = directory.join("podbay.sqlite.v25-staging");
        Self {
            directory,
            source,
            staging,
            lineage,
        }
    }

    fn source_summary(&self) -> (i64, String, i64, i64, i64) {
        let connection =
            Connection::open_with_flags(&self.source, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
        (
            connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap(),
            connection
                .query_row(
                    "SELECT lineage FROM store_identity WHERE singleton=1",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
            connection
                .query_row("SELECT count(*) FROM commands", [], |row| row.get(0))
                .unwrap(),
            connection
                .query_row("SELECT max(command_rowid) FROM commands", [], |row| {
                    row.get(0)
                })
                .unwrap(),
            connection
                .query_row(
                    "SELECT seq FROM sqlite_sequence WHERE name='commands'",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn stages_representative_v24_without_changing_source() {
    let fixture = Fixture::new();
    let source = Connection::open(&fixture.source).unwrap();
    source
        .execute(
            "INSERT INTO commands(
               command_rowid,command_id,principal,namespace,command_key,scope_id,target_id,
               digest_version,request_digest,canonical_request,owner_epoch,target_epoch)
             VALUES(50,'command.pb04.deleted','fixture.principal','fixture.test','deleted.key',
               'scope.alpha','pod.deleted','sha256-v1',?1,X'04',2,1)",
            ["9".repeat(64)],
        )
        .unwrap();
    source
        .execute("DELETE FROM commands WHERE command_rowid=50", [])
        .unwrap();
    drop(source);
    let source_before = fixture.source_summary();
    assert_eq!(
        source_before.4, 50,
        "deleted high ID must remain in sqlite_sequence"
    );
    let result = stage_schema_v25(&fixture.source, &fixture.staging).unwrap();

    assert_eq!(fixture.source_summary(), source_before);
    assert_eq!(result.store_lineage, fixture.lineage);
    assert_eq!(result.source_schema_version, 24);
    assert_eq!(result.staging_schema_version, 25);
    assert!(
        result
            .preserved_tables
            .iter()
            .any(|table| table.name == "commands" && table.row_count == 2 && table.max_rowid == 2)
    );
    assert!(
        result
            .sequence_high_water
            .iter()
            .any(|sequence| sequence.table == "commands" && sequence.sequence == 50)
    );

    let staged = Connection::open(&fixture.staging).unwrap();
    let staged_summary = (
        staged
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        staged
            .query_row(
                "SELECT lineage FROM store_identity WHERE singleton=1",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        staged
            .query_row("SELECT count(*) FROM commands", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        staged
            .query_row("SELECT max(command_rowid) FROM commands", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        staged
            .query_row(
                "SELECT seq FROM sqlite_sequence WHERE name='commands'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
    );
    assert_eq!(staged_summary, (25, source_before.1, 2, 2, 50));
    assert_eq!(
        staged
            .query_row(
                "SELECT (SELECT count(*) FROM external_death_pending)
                    + (SELECT count(*) FROM external_death_final)",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        fs::symlink_metadata(&fixture.staging)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    drop(staged);
    assert!(matches!(
        PodBayStore::open_existing_read_only(&fixture.staging),
        Err(StoreError::UnsupportedSchema(25))
    ));
}

#[test]
fn stages_committed_wal_pages_not_only_the_main_file() {
    let fixture = Fixture::new();
    let writer = Connection::open(&fixture.source).unwrap();
    writer
        .execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
        .unwrap();
    writer
        .execute("UPDATE metadata SET value=13 WHERE key='owner_epoch'", [])
        .unwrap();
    let mut wal_name = fixture.source.clone().into_os_string();
    wal_name.push("-wal");
    assert!(fs::metadata(PathBuf::from(wal_name)).unwrap().len() > 0);

    stage_schema_v25(&fixture.source, &fixture.staging).unwrap();
    let staged = Connection::open(&fixture.staging).unwrap();
    let owner_epoch: i64 = staged
        .query_row(
            "SELECT value FROM metadata WHERE key='owner_epoch'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(owner_epoch, 13);
    drop(staged);
    drop(writer);
}

#[test]
fn hidden_rowid_is_part_of_preserved_table_digest() {
    let fixture = Fixture::new();
    let first = stage_schema_v25(&fixture.source, &fixture.staging).unwrap();
    let before = first
        .preserved_tables
        .iter()
        .find(|table| table.name == "metadata")
        .unwrap();
    let source = Connection::open(&fixture.source).unwrap();
    source
        .execute("UPDATE metadata SET rowid=0 WHERE rowid=1", [])
        .unwrap();
    drop(source);
    let second_path = fixture.directory.join("podbay.sqlite.v25-second");
    let second = stage_schema_v25(&fixture.source, &second_path).unwrap();
    let after = second
        .preserved_tables
        .iter()
        .find(|table| table.name == "metadata")
        .unwrap();
    assert_eq!(
        (before.row_count, before.max_rowid),
        (after.row_count, after.max_rowid)
    );
    assert_ne!(before.content_digest, after.content_digest);
}

#[test]
fn v25_constraints_bind_exact_recovery_rows() {
    let fixture = Fixture::new();
    stage_schema_v25(&fixture.source, &fixture.staging).unwrap();
    let connection = Connection::open(&fixture.staging).unwrap();
    connection.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    connection
        .execute(
            "INSERT INTO external_death_pending(
               recovery_key,store_lineage,scope_id,pod_id,pod_incarnation,
               launch_command_rowid,activated_rebind_rowid,preparing_owner_epoch,
               preparing_authority_revision,authenticated_author,request_version,canonical_request,request_digest)
             VALUES('recover.alpha',?1,'scope.alpha','pod.alpha',1,1,1,2,5,'fixture.owner','podbay.external-death-pending-request/1',X'01',?2)",
            params![fixture.lineage, "1".repeat(64)],
        )
        .unwrap();
    assert!(
        connection
            .execute(
                "INSERT INTO external_death_final(pending_rowid,proof_digest,native_outcome)
                 VALUES(1,?1,'completed')",
                ["2".repeat(64)],
            )
            .is_err()
    );
    connection
        .execute(
            "INSERT INTO external_death_final(pending_rowid,proof_digest,native_outcome)
             VALUES(1,?1,'uncertain')",
            ["2".repeat(64)],
        )
        .unwrap();
}

#[test]
fn refuses_wrong_version_schema_fk_and_current_binding() {
    let wrong_version = Fixture::new();
    Connection::open(&wrong_version.source)
        .unwrap()
        .pragma_update(None, "user_version", 23)
        .unwrap();
    assert!(matches!(
        stage_schema_v25(&wrong_version.source, &wrong_version.staging),
        Err(V25StagingError::UnsupportedSourceVersion(23))
    ));
    assert!(!wrong_version.staging.exists());

    let wrong_schema = Fixture::new();
    Connection::open(&wrong_schema.source)
        .unwrap()
        .execute("CREATE TABLE unexpected(value INTEGER) STRICT", [])
        .unwrap();
    assert!(matches!(
        stage_schema_v25(&wrong_schema.source, &wrong_schema.staging),
        Err(V25StagingError::Safety(_))
    ));
    assert!(!wrong_schema.staging.exists());

    let broken_fk = Fixture::new();
    let connection = Connection::open(&broken_fk.source).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys=OFF;")
        .unwrap();
    connection
        .execute("DELETE FROM commands WHERE command_rowid=2", [])
        .unwrap();
    assert!(matches!(
        stage_schema_v25(&broken_fk.source, &broken_fk.staging),
        Err(V25StagingError::Safety(_))
    ));
    assert!(!broken_fk.staging.exists());

    let broken_binding = Fixture::new();
    let connection = Connection::open(&broken_binding.source).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys=OFF;")
        .unwrap();
    connection
        .execute(
            "UPDATE commands SET scope_id='scope.foreign' WHERE command_rowid=1",
            [],
        )
        .unwrap();
    assert!(matches!(
        stage_schema_v25(&broken_binding.source, &broken_binding.staging),
        Err(V25StagingError::Safety(_))
    ));
    assert!(!broken_binding.staging.exists());

    let broken_epoch = Fixture::new();
    let connection = Connection::open(&broken_epoch.source).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys=OFF;")
        .unwrap();
    connection
        .execute(
            "UPDATE commands SET target_epoch=2 WHERE command_rowid=1",
            [],
        )
        .unwrap();
    assert!(matches!(
        stage_schema_v25(&broken_epoch.source, &broken_epoch.staging),
        Err(V25StagingError::Safety(_))
    ));
    assert!(!broken_epoch.staging.exists());
}

#[test]
fn refuses_sqlite_lookalike_schema_objects_before_staging() {
    let fixture = Fixture::new();
    Connection::open(&fixture.source)
        .unwrap()
        .execute_batch(
            "CREATE TABLE sqliteXextra(value INTEGER) STRICT;
             CREATE INDEX sqliteXextra_index ON sqliteXextra(value);
             CREATE TRIGGER sqliteXextra_trigger AFTER INSERT ON sqliteXextra
             BEGIN
               SELECT NEW.value;
             END;",
        )
        .unwrap();

    assert!(matches!(
        stage_schema_v25(&fixture.source, &fixture.staging),
        Err(V25StagingError::Safety(
            "source does not have the exact canonical schema-24 objects"
        ))
    ));
    assert!(!fixture.staging.exists());
}

#[test]
fn refuses_occupied_linked_and_out_of_directory_staging_paths() {
    let fixture = Fixture::new();
    fs::write(&fixture.staging, b"partial staging").unwrap();
    assert!(matches!(
        stage_schema_v25(&fixture.source, &fixture.staging),
        Err(V25StagingError::Safety("staging path is already occupied"))
    ));
    assert_eq!(fs::read(&fixture.staging).unwrap(), b"partial staging");

    let symlink_path = fixture.directory.join("staging-symlink");
    std::os::unix::fs::symlink(&fixture.staging, &symlink_path).unwrap();
    assert!(matches!(
        stage_schema_v25(&fixture.source, &symlink_path),
        Err(V25StagingError::Safety("staging path is already occupied"))
    ));

    let hardlink_path = fixture.directory.join("staging-hardlink");
    fs::hard_link(&fixture.staging, &hardlink_path).unwrap();
    assert!(matches!(
        stage_schema_v25(&fixture.source, &hardlink_path),
        Err(V25StagingError::Safety("staging path is already occupied"))
    ));

    let other_directory = fixture.directory.join("other");
    fs::create_dir(&other_directory).unwrap();
    fs::set_permissions(&other_directory, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        stage_schema_v25(&fixture.source, other_directory.join("staging")),
        Err(V25StagingError::Safety(
            "staging path must be in the source directory"
        ))
    ));
}

#[test]
fn refuses_occupied_sqlite_sidecars_without_touching_them() {
    for suffix in ["-journal", "-wal", "-shm"] {
        let fixture = Fixture::new();
        let source_before = fixture.source_summary();
        let mut name = fixture.staging.clone().into_os_string();
        name.push(suffix);
        let sidecar = PathBuf::from(name);
        let sentinel = format!("foreign sidecar {suffix}");
        fs::write(&sidecar, sentinel.as_bytes()).unwrap();
        assert!(matches!(
            stage_schema_v25(&fixture.source, &fixture.staging),
            Err(V25StagingError::Safety(
                "staging SQLite sidecar is already occupied"
            ))
        ));
        assert_eq!(fs::read(&sidecar).unwrap(), sentinel.as_bytes());
        assert!(!fixture.staging.exists());
        assert_eq!(fixture.source_summary(), source_before);
    }
}

#[test]
fn source_and_parent_privacy_are_required() {
    let fixture = Fixture::new();
    fs::set_permissions(&fixture.source, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(
        stage_schema_v25(&fixture.source, &fixture.staging),
        Err(V25StagingError::Safety(_))
    ));

    let fixture = Fixture::new();
    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o750)).unwrap();
    assert!(matches!(
        stage_schema_v25(&fixture.source, &fixture.staging),
        Err(V25StagingError::Safety(_))
    ));
}

#[test]
fn refuses_manager_lock_names_before_creating_staging() {
    let fixture = Fixture::new();
    let before = fixture.source_summary();
    let alias_parent = fixture.directory.join("alias-parent");
    std::os::unix::fs::symlink(&fixture.directory, &alias_parent).unwrap();
    for path in [
        fixture.directory.join("podbay.sqlite.manager.lock"),
        fixture.directory.join("other.sqlite.manager.lock"),
        fixture.directory.join("./podbay.sqlite.manager.lock"),
        alias_parent.join("podbay.sqlite.manager.lock"),
    ] {
        assert!(matches!(
            stage_schema_v25(&fixture.source, &path),
            Err(V25StagingError::Safety(
                "staging basename uses the reserved manager lock suffix"
            ))
        ));
        assert!(
            !path.exists(),
            "reserved entry must not be created before manager acquisition"
        );
        assert_eq!(fixture.source_summary(), before);
    }
}
