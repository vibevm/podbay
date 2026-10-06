#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_host::{
    AuthorisedBoundLaunch, AuthorisedDispatch, DurableAuthority, HostDispatchPort,
    PortDispatchError, PortDispatchOutcome,
};
use podbay_store::{CurrentV2RebindDisposition, PodBayStore, StoreError};
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
    fn source_command_id(index: usize) -> String {
        format!("command.pb04.{:064x}", index + 1)
    }

    fn stop_command_id(index: usize) -> String {
        format!("command.pb04.{:064x}", 10_000 + index)
    }

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
        for (index, state) in [(0usize, "claimed_uncertain"), (1usize, "observed")] {
            let scope = if index % 2 == 0 {
                "scope.alpha"
            } else {
                "scope.beta"
            };
            let pod = format!("pod.{index:04}");
            connection
                .execute(
                    "INSERT INTO commands(command_id,principal,namespace,command_key,scope_id,
                       target_id,digest_version,request_digest,canonical_request,owner_epoch,
                       target_epoch)
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
        .map(|candidate| {
            (
                candidate.scope_id().as_str().to_owned(),
                candidate.pod_id().as_str().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(selectors.len(), 130);
    selectors.sort();
    selectors.dedup();
    assert_eq!(selectors.len(), 130);

    let claimed = first
        .candidates()
        .iter()
        .chain(second.candidates())
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
    let observed = first
        .candidates()
        .iter()
        .chain(second.candidates())
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

#[test]
fn manager_fenced_host_refuses_owner_epoch_drift() {
    let fixture = Fixture::new();
    let mut host = DurableAuthority::open(&fixture.database, NoopPort).unwrap();
    let first = host.current_codex_v2_rebind_page(None).unwrap();
    let cursor = first.next_cursor().unwrap().clone();
    Connection::open(&fixture.database)
        .unwrap()
        .execute(
            "UPDATE metadata SET value=value+1 WHERE key='owner_epoch'",
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
