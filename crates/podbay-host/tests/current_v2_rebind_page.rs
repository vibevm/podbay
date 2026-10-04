#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_host::{
    AuthorisedBoundLaunch, AuthorisedDispatch, DurableAuthority, HostDispatchPort,
    PortDispatchError, PortDispatchOutcome,
};
use podbay_store::{PodBayStore, StoreError};
use podbay_wire::{EFFECTIVE_LAUNCH_V2_VERSION, LAUNCH_DESCRIPTOR_V2_SCHEMA};
use rusqlite::{Connection, params};

struct NoopPort;
impl HostDispatchPort for NoopPort {
    type Receipt = ();
    fn dispatch(
        &mut self,
        _: AuthorisedDispatch,
    ) -> Result<PortDispatchOutcome<()>, PortDispatchError> {
        Err(PortDispatchError::RefusedBeforeEffect)
    }
    fn launch_bound(
        &mut self,
        _: AuthorisedBoundLaunch,
    ) -> Result<PortDispatchOutcome<()>, PortDispatchError> {
        Err(PortDispatchError::RefusedBeforeEffect)
    }
}

struct Fixture {
    directory: PathBuf,
    database: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("podbay-host-pages-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let database = directory.join("podbay.sqlite");
        drop(PodBayStore::open(&database).unwrap());
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch("PRAGMA foreign_keys=OFF; BEGIN IMMEDIATE;")
            .unwrap();
        for index in (0..130).rev() {
            let scope = if index % 2 == 0 {
                "scope.alpha"
            } else {
                "scope.beta"
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
fn manager_fenced_host_pages_more_than_128_current_pods_without_duplicates() {
    let fixture = Fixture::new();
    let mut host = DurableAuthority::open(&fixture.database, NoopPort).unwrap();
    let first = host.current_codex_v2_rebind_page(None).unwrap();
    assert_eq!(first.candidates().len(), 128);
    let cursor = first.next_cursor().unwrap().clone();
    let second = host.current_codex_v2_rebind_page(Some(&cursor)).unwrap();
    assert_eq!(second.candidates().len(), 2);
    assert!(second.next_cursor().is_none());
    let mut selectors = first
        .candidates()
        .iter()
        .chain(second.candidates())
        .map(|(scope, pod)| (scope.as_str().to_owned(), pod.as_str().to_owned()))
        .collect::<Vec<_>>();
    assert_eq!(selectors.len(), 130);
    selectors.sort();
    selectors.dedup();
    assert_eq!(selectors.len(), 130);

    Connection::open(&fixture.database)
        .unwrap()
        .execute(
            "UPDATE metadata SET value=value+1 WHERE key='authority_revision'",
            [],
        )
        .unwrap();
    assert!(matches!(
        host.current_codex_v2_rebind_page(Some(&cursor)),
        Err(podbay_host::RebindContextError::Store(
            StoreError::StaleEpoch
        ))
    ));
}
