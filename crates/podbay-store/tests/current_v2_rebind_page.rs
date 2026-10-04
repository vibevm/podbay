use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_store::{PodBayStore, StoreError};
use podbay_wire::{EFFECTIVE_LAUNCH_V2_VERSION, LAUNCH_DESCRIPTOR_V2_SCHEMA};
use rusqlite::{Connection, params};

struct Fixture {
    directory: PathBuf,
    database: PathBuf,
}

impl Fixture {
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
        found.extend(
            page.candidates()
                .iter()
                .map(|(scope, pod)| (scope.as_str().to_owned(), pod.as_str().to_owned())),
        );
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
