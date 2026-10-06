use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_store::{CurrentV2RebindDisposition, PodBayStore, StoreError};
use podbay_wire::{EFFECTIVE_LAUNCH_V2_VERSION, LAUNCH_DESCRIPTOR_V2_SCHEMA};
use rusqlite::{Connection, params};

struct Fixture {
    directory: PathBuf,
    database: PathBuf,
}

impl Fixture {
    fn source_command_id(index: usize) -> String {
        format!("command.pb04.{:064x}", index + 1)
    }

    fn stop_command_id(index: usize) -> String {
        format!("command.pb04.{:064x}", 10_000 + index)
    }

    fn new(count: usize) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("podbay-v2-pages-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let database = directory.join("podbay.sqlite");
        drop(PodBayStore::open(&database).unwrap());
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch("PRAGMA foreign_keys=OFF; BEGIN IMMEDIATE;")
            .unwrap();
        for index in (0..count).rev() {
            let scope = if index % 3 == 0 {
                "scope.beta"
            } else {
                "scope.alpha"
            };
            let pod = format!("pod.{index:04}");
            connection
                .execute(
                    "INSERT INTO commands(command_rowid,command_id,principal,namespace,command_key,
                       scope_id,target_id,digest_version,request_digest,canonical_request,
                       owner_epoch,target_epoch)
                     VALUES(?1,?2,'fixture.principal','fixture.launch',?3,?4,?5,
                            'sha256-v1',?6,X'',0,1)",
                    params![
                        index as i64 + 1,
                        Self::source_command_id(index),
                        format!("launch.key.{index:04}"),
                        scope,
                        pod,
                        "a".repeat(64)
                    ],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO authority_pods(pod_id,scope_id,incarnation) VALUES(?1,?2,1)",
                    params![pod, scope],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO target_epochs(scope_id,target_id,epoch) VALUES(?1,?2,1)",
                    params![scope, pod],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO launch_bindings(command_rowid,scope_id,session_id,run_id,
                   attempt_id,attempt_ordinal,attempt_epoch,pod_id,pod_incarnation,
                   resource_count,effective_spec_version,effective_spec_digest,effective_spec,
                   descriptor_version,descriptor_digest,descriptor)
                 VALUES(?1,?2,?3,?4,?5,1,1,?6,1,1,?7,?8,X'01',?9,?8,X'01')",
                    params![
                        index as i64 + 1,
                        scope,
                        format!("session.{index:04}"),
                        format!("run.{index:04}"),
                        format!("attempt.{index:04}"),
                        pod,
                        EFFECTIVE_LAUNCH_V2_VERSION,
                        "a".repeat(64),
                        LAUNCH_DESCRIPTOR_V2_SCHEMA
                    ],
                )
                .unwrap();
        }
        connection.execute_batch("COMMIT;").unwrap();
        Self {
            directory,
            database,
        }
    }

    fn insert_unresolved_stop(&self, index: usize, state: &str) {
        let scope = if index % 3 == 0 {
            "scope.beta"
        } else {
            "scope.alpha"
        };
        let pod = format!("pod.{index:04}");
        let connection = Connection::open(&self.database).unwrap();
        connection
            .execute_batch("PRAGMA foreign_keys=OFF; BEGIN IMMEDIATE;")
            .unwrap();
        connection
            .execute(
                "INSERT INTO commands(command_id,principal,namespace,command_key,scope_id,target_id,
                   digest_version,request_digest,canonical_request,owner_epoch,target_epoch)
                 VALUES(?1,'fixture.principal','fixture.stop',?2,?3,?4,
                        'sha256-v1',?5,X'',0,1)",
                params![
                    Self::stop_command_id(index),
                    format!("stop.key.{index:04}"),
                    scope,
                    pod,
                    "b".repeat(64)
                ],
            )
            .unwrap();
        let command_rowid = connection.last_insert_rowid();
        connection
            .execute(
                "INSERT INTO outbox(command_rowid,scope_id,target_id,owner_epoch,target_epoch,
                   kind,payload,effect_digest,state)
                 VALUES(?1,?2,?3,0,1,'pod.stop',X'',?4,?5)",
                params![command_rowid, scope, pod, "c".repeat(64), state],
            )
            .unwrap();
        connection.execute_batch("COMMIT;").unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn more_than_two_pages_are_ordered_and_have_no_boundary_duplicate() {
    let fixture = Fixture::new(261);
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let mut cursor = None;
    let mut lengths = Vec::new();
    let mut found = Vec::new();
    loop {
        let page = store
            .current_codex_v2_rebind_page(cursor.as_ref(), 0, 0)
            .unwrap();
        lengths.push(page.candidates().len());
        found.extend(page.candidates().iter().map(|candidate| {
            (
                candidate.scope_id().as_str().to_owned(),
                candidate.pod_id().as_str().to_owned(),
            )
        }));
        cursor = page.next_cursor().cloned();
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(lengths, [128, 128, 5]);
    assert_eq!(found.len(), 261);
    let mut expected = found.clone();
    expected.sort();
    expected.dedup();
    assert_eq!(found, expected);
    assert_eq!(
        found.first().unwrap(),
        &("scope.alpha".into(), "pod.0001".into())
    );
    assert_eq!(
        found.last().unwrap(),
        &("scope.beta".into(), "pod.0258".into())
    );
}

#[test]
fn current_candidates_keep_typed_unresolved_stop_dispositions() {
    let fixture = Fixture::new(3);
    fixture.insert_unresolved_stop(0, "claimed_uncertain");
    fixture.insert_unresolved_stop(1, "observed");
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let page = store.current_codex_v2_rebind_page(None, 0, 0).unwrap();
    assert_eq!(page.candidates().len(), 3);

    let ordinary = page
        .candidates()
        .iter()
        .find(|candidate| candidate.pod_id().as_str() == "pod.0002")
        .unwrap();
    assert_eq!(ordinary.pod_incarnation().get(), 1);
    assert_eq!(
        ordinary.source_command_id().as_str(),
        Fixture::source_command_id(2)
    );
    assert_eq!(
        ordinary.disposition(),
        &CurrentV2RebindDisposition::NeedsLiveRebind
    );

    let claimed = page
        .candidates()
        .iter()
        .find(|candidate| candidate.pod_id().as_str() == "pod.0000")
        .unwrap();
    assert_eq!(claimed.pod_incarnation().get(), 1);
    assert_eq!(
        claimed.source_command_id().as_str(),
        Fixture::source_command_id(0)
    );
    assert_eq!(
        claimed.disposition(),
        &CurrentV2RebindDisposition::StopClaimedUncertain {
            command_id: Fixture::stop_command_id(0).as_str().try_into().unwrap(),
        }
    );

    let observed = page
        .candidates()
        .iter()
        .find(|candidate| candidate.pod_id().as_str() == "pod.0001")
        .unwrap();
    assert_eq!(observed.pod_incarnation().get(), 1);
    assert_eq!(
        observed.source_command_id().as_str(),
        Fixture::source_command_id(1)
    );
    assert_eq!(
        observed.disposition(),
        &CurrentV2RebindDisposition::StopObservedUnverified {
            command_id: Fixture::stop_command_id(1).as_str().try_into().unwrap(),
        }
    );
}

#[test]
fn cross_boundary_source_or_stop_rows_fail_closed() {
    let source_fixture = Fixture::new(1);
    Connection::open(&source_fixture.database)
        .unwrap()
        .execute(
            "UPDATE commands SET scope_id='scope.foreign',target_id='pod.foreign',target_epoch=2
             WHERE command_rowid=1",
            [],
        )
        .unwrap();
    let mut source_store = PodBayStore::open(&source_fixture.database).unwrap();
    assert!(matches!(
        source_store.current_codex_v2_rebind_page(None, 0, 0),
        Err(StoreError::Conflict(
            "current V2 source command crosses launch binding"
        ))
    ));

    let stop_fixture = Fixture::new(1);
    stop_fixture.insert_unresolved_stop(0, "claimed_uncertain");
    Connection::open(&stop_fixture.database)
        .unwrap()
        .execute(
            "UPDATE outbox SET scope_id='scope.foreign',target_id='pod.foreign',target_epoch=2
             WHERE kind='pod.stop'",
            [],
        )
        .unwrap();
    let mut stop_store = PodBayStore::open(&stop_fixture.database).unwrap();
    assert!(matches!(
        stop_store.current_codex_v2_rebind_page(None, 0, 0),
        Err(StoreError::Conflict(
            "current V2 stop command or outbox crosses launch binding"
        ))
    ));
}

#[test]
fn missing_source_command_fails_closed_instead_of_disappearing() {
    let fixture = Fixture::new(1);
    let connection = Connection::open(&fixture.database).unwrap();
    connection.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
    connection
        .execute("DELETE FROM commands WHERE command_rowid=1", [])
        .unwrap();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    assert!(matches!(
        store.current_codex_v2_rebind_page(None, 0, 0),
        Err(StoreError::Conflict(
            "current V2 source command is missing"
        ))
    ));
}

#[test]
fn missing_stop_command_fails_closed_instead_of_becoming_live_rebind() {
    let fixture = Fixture::new(1);
    fixture.insert_unresolved_stop(0, "claimed_uncertain");
    let connection = Connection::open(&fixture.database).unwrap();
    connection.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
    connection
        .execute(
            "DELETE FROM commands WHERE command_id=?1",
            [Fixture::stop_command_id(0)],
        )
        .unwrap();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    assert!(matches!(
        store.current_codex_v2_rebind_page(None, 0, 0),
        Err(StoreError::Conflict(
            "current V2 stop command is missing"
        ))
    ));
}

#[test]
fn later_page_refuses_authority_revision_drift() {
    let fixture = Fixture::new(130);
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let first = store.current_codex_v2_rebind_page(None, 0, 0).unwrap();
    assert_eq!(first.candidates().len(), 128);
    let cursor = first.next_cursor().unwrap().clone();
    Connection::open(&fixture.database)
        .unwrap()
        .execute(
            "UPDATE metadata SET value=1 WHERE key='authority_revision'",
            [],
        )
        .unwrap();
    assert!(matches!(
        store.current_codex_v2_rebind_page(Some(&cursor), 0, 0),
        Err(StoreError::StaleEpoch)
    ));
    assert!(matches!(
        store.current_codex_v2_rebind_page(None, 0, 0),
        Err(StoreError::StaleEpoch)
    ));
}

#[test]
fn later_page_refuses_owner_epoch_drift() {
    let fixture = Fixture::new(130);
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let first = store.current_codex_v2_rebind_page(None, 0, 0).unwrap();
    assert_eq!(first.candidates().len(), 128);
    let cursor = first.next_cursor().unwrap().clone();
    Connection::open(&fixture.database)
        .unwrap()
        .execute("UPDATE metadata SET value=1 WHERE key='owner_epoch'", [])
        .unwrap();
    assert!(matches!(
        store.current_codex_v2_rebind_page(Some(&cursor), 0, 0),
        Err(StoreError::StaleEpoch)
    ));
}
