//! Fresh Store fixtures only. Wire pins and principal values are injected test
//! declarations; no trusted host, executable, FD3 channel or OS effect is used.
use super::*;
use podbay_store::{
    BoundLaunchFormat, BoundLaunchRecord, BoundOperatorFd3ObserveRootProposal,
    BoundOperatorFd3ObserveRootRequest, EffectState, Receipt,
};
use podbay_wire::{
    EffectiveOperatorFd3ObserveContractV1, ImmutableOperatorFd3ObserveDescriptorV1, LifetimeLimit,
    OperatorArtifactTreePinV1, OperatorConfigurationPinV1, OperatorFd3ObserveEffectiveInputV1,
    OperatorFd3ObservePolicyInputV1, OperatorFd3ObservePolicyV1, OperatorFilePinV1,
    OperatorWorkspaceExpectationV1,
};
use rusqlite::{Connection, OpenFlags, params, types::Value};

const INTENT: &[u8] = b"fd3 observation root caller intent";
const REFUSAL: &str = "FD3-observe launch is admission-only";

struct Fd3Root {
    root: OperatorRootFixture,
    effective: EffectiveOperatorFd3ObserveContractV1,
    descriptor: ImmutableOperatorFd3ObserveDescriptorV1,
}
impl Fd3Root {
    fn new(lifetime: LifetimeLimit) -> Self {
        let root = OperatorRootFixture::new(OPERATOR_PROCESS_PROFILE_REF);
        let binding = root.planned.identity();
        let policy = OperatorFd3ObservePolicyV1::new(OperatorFd3ObservePolicyInputV1 {
            supervisor: OperatorFilePinV1 {
                path: "/fixture/unopened/podbay-pod".into(),
                sha256: "a".repeat(64),
            },
            artifact: OperatorArtifactTreePinV1 {
                root: "/fixture/unopened/lens".into(),
                sha256: "b".repeat(64),
            },
            configuration: OperatorConfigurationPinV1::Absent,
            public_composition_digest: "c".repeat(64),
            registry_digest: "d".repeat(64),
            workspace: OperatorWorkspaceExpectationV1 {
                logical_store_id: "00000000-0000-4000-8000-000000000001".into(),
                main_path: "/fixture/unopened/state/workspace.sqlite".into(),
            },
        })
        .unwrap();
        let effective = EffectiveOperatorFd3ObserveContractV1::new(
            OperatorFd3ObserveEffectiveInputV1 {
                pod_id: binding.pod_id().clone(),
                scope_id: binding.scope_id().clone(),
                host_id: "host.fixture".into(),
                profile_generation: 1,
                executable: OperatorFilePinV1 {
                    path: "/fixture/unopened/node".into(),
                    sha256: "e".repeat(64),
                },
                cwd: "/fixture/unopened/lens".into(),
                arguments: vec!["dist/wayfinder.js".into()],
                workspace_basis_ref: "basis.fixture".into(),
                authority_grant_id: 7,
                lifetime,
            },
            policy,
        )
        .unwrap();
        let descriptor =
            ImmutableOperatorFd3ObserveDescriptorV1::from_planned_root(&root.planned, &effective)
                .unwrap();
        Self {
            root,
            effective,
            descriptor,
        }
    }
    fn scope(&self) -> &str {
        self.root.planned.identity().scope_id().as_str()
    }
    fn pod(&self) -> &str {
        self.root.planned.identity().pod_id().as_str()
    }
    fn request<'a>(&'a self, key: &'a str) -> BoundOperatorFd3ObserveRootRequest<'a> {
        BoundOperatorFd3ObserveRootRequest {
            principal: principal(),
            command_key: key,
            canonical_intent: INTENT,
            scope_id: self.scope(),
            pod_id: self.pod(),
            proposal: Some(BoundOperatorFd3ObserveRootProposal {
                session: &self.root.session,
                run: &self.root.run,
                binding: &self.root.planned,
                effective_spec: &self.effective,
                descriptor: &self.descriptor,
                expected_owner_epoch: 1,
                expected_authority_revision: 0,
            }),
        }
    }
    fn lookup(&self, key: &str) -> LaunchLookupRequest {
        LaunchLookupRequest {
            principal: principal(),
            namespace: "podbay.launch".into(),
            command_key: key.into(),
            scope_id: self.scope().into(),
            target_id: self.pod().into(),
            canonical_intent: INTENT.to_vec(),
        }
    }
}
fn committed(result: BoundLaunchAdmission) -> BoundLaunchRecord {
    match result {
        BoundLaunchAdmission::Committed(record) => record,
        other => panic!("expected first admission: {other:?}"),
    }
}
fn refused<T: std::fmt::Debug>(result: Result<T, StoreError>) {
    assert!(
        matches!(result, Err(StoreError::Conflict(REFUSAL))),
        "{result:?}"
    );
}

/// One read snapshot of schema, user_version and every positional table value,
/// including rowids/sqlite_sequence. This is a mutation oracle, not origin proof.
fn snapshot(path: &PathBuf) -> (i64, Vec<Vec<Value>>, Vec<(String, Vec<Vec<Value>>)>) {
    let mut c = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let tx = c.transaction().unwrap();
    let rows = |sql: &str| {
        let mut statement = tx.prepare(sql).unwrap();
        let n = statement.column_count();
        statement
            .query_map([], |row| {
                (0..n)
                    .map(|i| row.get(i))
                    .collect::<Result<Vec<Value>, _>>()
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    let version = tx
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    let schema = rows("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name");
    let tables: Vec<String> = tx
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let contents = tables
        .into_iter()
        .map(|name| {
            let contents = rows(&format!(
                "SELECT rowid,* FROM \"{}\" ORDER BY rowid",
                name.replace('"', "\"\"")
            ));
            (name, contents)
        })
        .collect();
    (version, schema, contents)
}
fn assert_prepared(store: &PodBayStore, fixture: &Fixture, root: &Fd3Root, receipt: &Receipt) {
    let effect = store
        .load_effect(receipt.outbox_id, root.scope(), root.pod())
        .unwrap();
    assert_eq!(effect.state, EffectState::Prepared);
    assert!(effect.claim_key.is_none() && effect.claim_owner_epoch.is_none());
    assert!(effect.observation_payload.is_none() && effect.observed_stage.is_none());
    assert_eq!(
        store
            .launch_dispatch_status(receipt.outbox_id, root.scope(), root.pod())
            .unwrap()
            .stage,
        LaunchDispatchStage::Prepared
    );
    assert_eq!(count(&fixture.database, "commands"), 1);
    assert_eq!(count(&fixture.database, "outbox"), 1);
    assert_eq!(count(&fixture.database, "events"), 1);
    assert_eq!(count(&fixture.database, "launch_dispatch_outcomes"), 0);
    assert_eq!(count(&fixture.database, "launch_policy_fences"), 0);
}

#[test]
fn fd3_finite_and_until_stopped_commit_reopen_and_exact_duplicate_stay_prepared() {
    for lifetime in [
        LifetimeLimit::Finite { seconds: 30 },
        LifetimeLimit::UntilStopped,
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        setup(&mut store);
        let root = Fd3Root::new(lifetime);
        let schema_before = snapshot(&fixture.database);
        let record = committed(
            store
                .admit_bound_operator_fd3_observe_root(root.request("fd3.root"))
                .unwrap(),
        );
        assert_eq!(record.format, BoundLaunchFormat::OperatorFd3ObserveV1);
        assert_eq!(record.effective_spec, root.effective.canonical_bytes());
        assert_eq!(record.descriptor, root.descriptor.encode_json().unwrap());
        assert_eq!(
            root.root.run.admission(),
            podbay_core::AdmissionState::Queued
        );
        assert_eq!(store.authority_snapshot().unwrap().revision, 1);
        assert_prepared(&store, &fixture, &root, &record.receipt);
        let after = snapshot(&fixture.database);
        assert_eq!(after.0, 24);
        assert_eq!((after.0, &after.1), (schema_before.0, &schema_before.1));
        let current = store
            .current_bound_pod_snapshot(root.scope(), root.pod())
            .unwrap();
        assert_eq!(current.launch(), &record);
        drop(store);
        let mut reopened = fixture.open();
        let mut duplicate = root.request("fd3.root");
        duplicate.proposal = None;
        assert_eq!(
            reopened
                .admit_bound_operator_fd3_observe_root(duplicate)
                .unwrap(),
            BoundLaunchAdmission::Duplicate(record.clone())
        );
        assert_eq!(
            reopened
                .lookup_bound_launch(&root.lookup("fd3.root"))
                .unwrap(),
            Some(record.clone())
        );
        assert_eq!(
            reopened
                .lookup_admitted_launch(&root.lookup("fd3.root"))
                .unwrap()
                .binding,
            LaunchIntentBinding::BoundV8
        );
        assert_prepared(&reopened, &fixture, &root, &record.receipt);
        assert_eq!(snapshot(&fixture.database), after);
        let mut changed = root.request("fd3.root");
        changed.proposal = None;
        changed.canonical_intent = b"changed intent";
        assert!(matches!(
            reopened.admit_bound_operator_fd3_observe_root(changed),
            Err(StoreError::Conflict(_))
        ));
        assert!(matches!(
            reopened.admit_bound_operator_fd3_observe_root(root.request("fd3.other")),
            Err(StoreError::StaleEpoch | StoreError::Conflict(_))
        ));
        assert_eq!(snapshot(&fixture.database), after);
        reopened.advance_owner_epoch(1, 2).unwrap();
        Connection::open(&fixture.database)
            .unwrap()
            .execute("UPDATE runtime_runs SET desired_mode='pause'", [])
            .unwrap();
        let historical = snapshot(&fixture.database);
        let mut duplicate = root.request("fd3.root");
        duplicate.proposal = None;
        assert_eq!(
            reopened
                .admit_bound_operator_fd3_observe_root(duplicate)
                .unwrap(),
            BoundLaunchAdmission::Duplicate(record)
        );
        assert_eq!(snapshot(&fixture.database), historical);
    }
}

#[test]
fn fd3_all_claim_and_outcome_entry_points_refuse_without_mutating_prepared() {
    for lifetime in [
        LifetimeLimit::Finite { seconds: 30 },
        LifetimeLimit::UntilStopped,
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        setup(&mut store);
        let root = Fd3Root::new(lifetime);
        let record = committed(
            store
                .admit_bound_operator_fd3_observe_root(root.request("fd3.root"))
                .unwrap(),
        );
        let before = snapshot(&fixture.database);
        refused(store.claim_effect(
            record.receipt.outbox_id,
            root.scope(),
            root.pod(),
            1,
            1,
            1,
            "claim.fd3",
        ));
        for result in [
            LaunchPortResult::RefusedBeforeEffect,
            LaunchPortResult::UncertainAfterPossibleEffect { receipt_ref: None },
            LaunchPortResult::HostAccepted {
                receipt_ref: Some("receipt.fixture".into()),
            },
            LaunchPortResult::PortSettled {
                receipt_ref: Some("receipt.fixture".into()),
            },
        ] {
            refused(store.record_launch_port_result(
                record.receipt.outbox_id,
                root.scope(),
                root.pod(),
                1,
                "claim.fd3",
                result,
            ));
        }
        refused(store.observe_effect(
            record.receipt.outbox_id,
            root.scope(),
            root.pod(),
            1,
            1,
            "claim.fd3",
            &host_proof(),
        ));
        assert_prepared(&store, &fixture, &root, &record.receipt);
        assert_eq!(snapshot(&fixture.database), before);
    }
}

#[test]
fn fd3_impossible_claimed_and_observed_retry_rows_still_refuse_every_mutator() {
    for state in ["claimed_uncertain", "observed"] {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        setup(&mut store);
        let root = Fd3Root::new(LifetimeLimit::UntilStopped);
        let record = committed(
            store
                .admit_bound_operator_fd3_observe_root(root.request("fd3.root"))
                .unwrap(),
        );
        let c = Connection::open(&fixture.database).unwrap();
        // Deliberately impossible database mutants, not an actual FD3 dispatch.
        c.execute("UPDATE outbox SET state=?1,claim_key='claim.fd3',claim_owner_epoch=1 WHERE outbox_id=?2",
            params![state, record.receipt.outbox_id]).unwrap();
        c.execute("INSERT INTO launch_dispatch_outcomes(outbox_id,claim_key,stage,receipt_ref,recorded_at) VALUES(?1,'claim.fd3','host_accepted','receipt.fixture','fixture')",
            [record.receipt.outbox_id]).unwrap();
        drop(c);
        let before = snapshot(&fixture.database);
        refused(store.claim_effect(
            record.receipt.outbox_id,
            root.scope(),
            root.pod(),
            1,
            1,
            1,
            "claim.fd3",
        ));
        refused(store.record_launch_port_result(
            record.receipt.outbox_id,
            root.scope(),
            root.pod(),
            1,
            "claim.fd3",
            LaunchPortResult::HostAccepted {
                receipt_ref: Some("receipt.fixture".into()),
            },
        ));
        refused(store.observe_effect(
            record.receipt.outbox_id,
            root.scope(),
            root.pod(),
            1,
            1,
            "claim.fd3",
            &host_proof(),
        ));
        // Historical immutable lookup remains passive, not an authority grant.
        assert_eq!(
            store.lookup_bound_launch(&root.lookup("fd3.root")).unwrap(),
            Some(record)
        );
        assert_eq!(snapshot(&fixture.database), before);
    }
}

#[test]
fn fd3_cross_format_retries_refuse_without_mutation() {
    for legacy_first in [false, true] {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        setup(&mut store);
        let root = Fd3Root::new(LifetimeLimit::UntilStopped);
        if legacy_first {
            let mut request = root.root.request("same.key");
            request.canonical_intent = INTENT;
            store.admit_bound_operator_root_launch(request).unwrap();
        } else {
            store
                .admit_bound_operator_fd3_observe_root(root.request("same.key"))
                .unwrap();
        }
        let before = snapshot(&fixture.database);
        let result = if legacy_first {
            let mut request = root.request("same.key");
            request.proposal = None;
            store.admit_bound_operator_fd3_observe_root(request)
        } else {
            let mut request = root.root.request("same.key");
            request.proposal = None;
            request.canonical_intent = INTENT;
            store.admit_bound_operator_root_launch(request)
        };
        assert!(matches!(
            result,
            Err(StoreError::Conflict(
                "command key changed bound launch format"
            ))
        ));
        assert_eq!(snapshot(&fixture.database), before);
    }
}

#[test]
fn fd3_stale_fences_wrong_association_and_late_insert_failure_leave_no_rows() {
    for fault in ["owner", "revision", "effective", "outbox"] {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        setup(&mut store);
        let root = Fd3Root::new(LifetimeLimit::UntilStopped);
        let other = Fd3Root::new(LifetimeLimit::Finite { seconds: 30 });
        if fault == "outbox" {
            Connection::open(&fixture.database).unwrap().execute_batch(
                "CREATE TRIGGER fail_fd3_outbox BEFORE INSERT ON outbox WHEN NEW.kind='pod.offer' BEGIN SELECT RAISE(ABORT,'fixture failure'); END;"
            ).unwrap();
        }
        let before = snapshot(&fixture.database);
        let mut request = root.request("fd3.root");
        let proposal = request.proposal.as_mut().unwrap();
        match fault {
            "owner" => proposal.expected_owner_epoch = 2,
            "revision" => proposal.expected_authority_revision = 1,
            "effective" => proposal.effective_spec = &other.effective,
            _ => {}
        }
        assert!(
            store
                .admit_bound_operator_fd3_observe_root(request)
                .is_err(),
            "{fault}"
        );
        assert_eq!(snapshot(&fixture.database), before, "{fault}");
        assert_eq!(store.authority_snapshot().unwrap().revision, 0);
    }
}

#[test]
fn fd3_readback_refuses_mixed_versions_and_corrupted_associations_without_repair() {
    for fault in [
        "mixed",
        "legacy",
        "effective",
        "descriptor",
        "resource",
        "event",
        "outbox",
        "v3_policy",
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        setup(&mut store);
        let root = Fd3Root::new(LifetimeLimit::UntilStopped);
        store
            .admit_bound_operator_fd3_observe_root(root.request("fd3.root"))
            .unwrap();
        let c = Connection::open(&fixture.database).unwrap();
        match fault {
            "mixed" => {
                c.execute(
                    "UPDATE launch_bindings SET effective_spec_version=?1",
                    [podbay_wire::EFFECTIVE_LAUNCH_VERSION],
                )
                .unwrap();
            }
            "legacy" => {
                c.execute(
                    "UPDATE launch_bindings SET effective_spec_version=?1,descriptor_version=?2",
                    params![
                        podbay_wire::EFFECTIVE_LAUNCH_VERSION,
                        podbay_wire::LAUNCH_DESCRIPTOR_SCHEMA
                    ],
                )
                .unwrap();
            }
            "effective" => {
                let other = Fd3Root::new(LifetimeLimit::Finite { seconds: 30 });
                c.execute(
                    "UPDATE launch_bindings SET effective_spec=?1,effective_spec_digest=?2",
                    params![other.effective.canonical_bytes(), other.effective.digest()],
                )
                .unwrap();
            }
            "descriptor" => {
                c.execute("UPDATE launch_bindings SET descriptor=x'7b7d'", [])
                    .unwrap();
            }
            "resource" => {
                c.execute(
                    "UPDATE launch_resources SET resource_id='resource.foreign'",
                    [],
                )
                .unwrap();
            }
            "event" => {
                c.execute("UPDATE events SET payload=x'00'", []).unwrap();
            }
            "outbox" => {
                c.execute("UPDATE outbox SET payload=x'00'", []).unwrap();
            }
            _ => {
                c.execute("INSERT INTO launch_policy_fences SELECT command_rowid,(SELECT lineage FROM store_identity WHERE singleton=1),1,1 FROM launch_bindings", []).unwrap();
            }
        }
        drop(c);
        let before = snapshot(&fixture.database);
        assert!(
            store.lookup_bound_launch(&root.lookup("fd3.root")).is_err(),
            "{fault}"
        );
        let mut duplicate = root.request("fd3.root");
        duplicate.proposal = None;
        assert!(
            store
                .admit_bound_operator_fd3_observe_root(duplicate)
                .is_err(),
            "{fault}"
        );
        assert_eq!(snapshot(&fixture.database), before, "{fault}");
    }
}

#[test]
fn fd3_concurrent_identical_admission_has_one_commit_and_one_prepared_outbox() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    setup(&mut store);
    drop(store);
    let mut handles = Vec::new();
    let barrier = Arc::new(Barrier::new(2));
    for _ in 0..2 {
        let mut connection = fixture.open();
        let gate = barrier.clone();
        handles.push(thread::spawn(move || {
            let root = Fd3Root::new(LifetimeLimit::UntilStopped);
            gate.wait();
            connection
                .admit_bound_operator_fd3_observe_root(root.request("fd3.race"))
                .unwrap()
        }));
    }
    let values: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(
        values
            .iter()
            .filter(|v| matches!(v, BoundLaunchAdmission::Committed(_)))
            .count(),
        1
    );
    let records: Vec<_> = values
        .into_iter()
        .map(|v| match v {
            BoundLaunchAdmission::Committed(r) | BoundLaunchAdmission::Duplicate(r) => r,
        })
        .collect();
    assert_eq!(records[0], records[1]);
    let root = Fd3Root::new(LifetimeLimit::UntilStopped);
    assert_prepared(&fixture.open(), &fixture, &root, &records[0].receipt);
}

#[test]
fn fd3_relabelled_wire_bytes_cannot_borrow_a_legacy_outcome_retry() {
    for (effective_version, descriptor_version) in [
        (
            podbay_wire::EFFECTIVE_LAUNCH_VERSION,
            podbay_wire::LAUNCH_DESCRIPTOR_SCHEMA,
        ),
        (
            podbay_wire::EFFECTIVE_LAUNCH_V2_VERSION,
            podbay_wire::LAUNCH_DESCRIPTOR_V2_SCHEMA,
        ),
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        setup(&mut store);
        let root = Fd3Root::new(LifetimeLimit::UntilStopped);
        let record = committed(
            store
                .admit_bound_operator_fd3_observe_root(root.request("fd3.root"))
                .unwrap(),
        );
        let c = Connection::open(&fixture.database).unwrap();
        c.execute(
            "UPDATE launch_bindings SET effective_spec_version=?1,descriptor_version=?2",
            params![effective_version, descriptor_version],
        )
        .unwrap();
        c.execute(
            "UPDATE outbox SET state='claimed_uncertain',claim_key='claim.fd3',claim_owner_epoch=1",
            [],
        )
        .unwrap();
        drop(c);
        let before = snapshot(&fixture.database);
        assert!(
            store
                .record_launch_port_result(
                    record.receipt.outbox_id,
                    root.scope(),
                    root.pod(),
                    1,
                    "claim.fd3",
                    LaunchPortResult::HostAccepted {
                        receipt_ref: Some("receipt.fixture".into())
                    }
                )
                .is_err()
        );
        assert!(
            store
                .observe_effect(
                    record.receipt.outbox_id,
                    root.scope(),
                    root.pod(),
                    1,
                    1,
                    "claim.fd3",
                    &host_proof()
                )
                .is_err()
        );
        assert_eq!(snapshot(&fixture.database), before);
    }
}

#[test]
fn fd3_coherent_foreign_actor_descriptor_fails_plan_and_stored_association() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    setup(&mut store);
    let root = Fd3Root::new(LifetimeLimit::UntilStopped);
    let binding = root.root.planned.identity();
    let mut session = Session::new(
        binding.session_id().clone(),
        ActorId::try_from("actor.foreign").unwrap(),
        binding.scope_id().clone(),
    );
    let run = Run::new(
        binding.run_id().clone(),
        &session,
        Role::Coordinator,
        WorkKind::Service,
        None,
    );
    session.bind_run(session.revision(), &run).unwrap();
    let mut attempt = Attempt::new(
        binding.attempt_id().clone(),
        run.id().clone(),
        1,
        Epoch::new(1).unwrap(),
    )
    .unwrap();
    let mut pod = Pod::new(
        binding.pod_id().clone(),
        attempt.id().clone(),
        Epoch::new(1).unwrap(),
    );
    attempt.attach_pod(attempt.revision(), &pod).unwrap();
    let resource = Resource::new(
        binding.resources()[0].id().clone(),
        pod.id().clone(),
        ResourceKind::Auxiliary,
        Epoch::new(1).unwrap(),
    );
    pod.attach_resource(pod.revision(), &resource).unwrap();
    let foreign_plan =
        LaunchBinding::plan_first_root(&session, &run, &attempt, &pod, &[resource]).unwrap();
    let foreign =
        ImmutableOperatorFd3ObserveDescriptorV1::from_planned_root(&foreign_plan, &root.effective)
            .unwrap();
    let before = snapshot(&fixture.database);
    let mut request = root.request("fd3.root");
    request.proposal.as_mut().unwrap().descriptor = &foreign;
    assert!(matches!(
        store.admit_bound_operator_fd3_observe_root(request),
        Err(StoreError::Conflict(
            "FD3 descriptor differs from queued root"
        ))
    ));
    assert_eq!(snapshot(&fixture.database), before);
    store
        .admit_bound_operator_fd3_observe_root(root.request("fd3.root"))
        .unwrap();
    Connection::open(&fixture.database)
        .unwrap()
        .execute(
            "UPDATE launch_bindings SET descriptor=?1,descriptor_digest=?2",
            params![foreign.encode_json().unwrap(), foreign.digest()],
        )
        .unwrap();
    let mutated = snapshot(&fixture.database);
    assert!(matches!(
        store.lookup_bound_launch(&root.lookup("fd3.root")),
        Err(StoreError::Conflict(
            "stored descriptor differs from binding"
        ))
    ));
    assert_eq!(snapshot(&fixture.database), mutated);
}

fn missing_binding_mutant(port_result: bool) {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    setup(&mut store);
    let root = Fd3Root::new(LifetimeLimit::UntilStopped);
    let record = committed(
        store
            .admit_bound_operator_fd3_observe_root(root.request("fd3.root"))
            .unwrap(),
    );
    let c = Connection::open(&fixture.database).unwrap();
    // Exact reported corruption: retain the launch.bound admission event and
    // descriptor outbox while deleting the binding with FK enforcement disabled.
    c.execute_batch(
        "PRAGMA foreign_keys=OFF; DELETE FROM launch_bindings;
        UPDATE outbox SET state='claimed_uncertain',claim_key='claim.fd3',claim_owner_epoch=1;",
    )
    .unwrap();
    drop(c);
    let before = snapshot(&fixture.database);
    let result = if port_result {
        store
            .record_launch_port_result(
                record.receipt.outbox_id,
                root.scope(),
                root.pod(),
                1,
                "claim.fd3",
                LaunchPortResult::HostAccepted {
                    receipt_ref: Some("receipt.fixture".into()),
                },
            )
            .map(|_| ())
    } else {
        store
            .observe_effect(
                record.receipt.outbox_id,
                root.scope(),
                root.pod(),
                1,
                1,
                "claim.fd3",
                &host_proof(),
            )
            .map(|_| ())
    };
    assert!(
        matches!(
            result,
            Err(StoreError::Conflict(
                "launch binding is missing while bound evidence remains"
            ))
        ),
        "{result:?}"
    );
    assert_eq!(snapshot(&fixture.database), before);
}

#[test]
fn fd3_missing_binding_cannot_downgrade_into_legacy_port_result() {
    missing_binding_mutant(true);
}

#[test]
fn fd3_missing_binding_cannot_downgrade_into_legacy_effect_observation() {
    missing_binding_mutant(false);
}

fn legacy_unbound_outcome_roundtrip(event_payload: &[u8], effect_payload: &[u8]) {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    setup(&mut store);
    store
        .advance_target_epoch("scope.legacy", "pod.legacy", 0, 1)
        .unwrap();
    let request = CommandRequest {
        principal: principal(),
        namespace: "podbay.launch".into(),
        command_key: "legacy.key".into(),
        scope_id: "scope.legacy".into(),
        target_id: "pod.legacy".into(),
        expected_owner_epoch: 1,
        expected_target_epoch: 1,
        canonical_request: b"legacy caller intent".to_vec(),
        event_kind: "command.admitted".into(),
        event_payload: event_payload.to_vec(),
        effect_kind: "pod.offer".into(),
        effect_payload: effect_payload.to_vec(),
    };
    let receipt = match store.admit(&request).unwrap() {
        Admission::Committed(receipt) => receipt,
        _ => panic!("fresh legacy fixture"),
    };
    assert_eq!(count(&fixture.database, "launch_bindings"), 0);
    // Model an already-existing historical claim; no new unbound dispatch is
    // enabled or performed by this test or the public claim API.
    Connection::open(&fixture.database).unwrap().execute(
        "UPDATE outbox SET state='claimed_uncertain',claim_key='claim.legacy',claim_owner_epoch=1", []).unwrap();
    let result = LaunchPortResult::HostAccepted {
        receipt_ref: Some("legacy.receipt".into()),
    };
    assert_eq!(
        store
            .record_launch_port_result(
                receipt.outbox_id,
                "scope.legacy",
                "pod.legacy",
                1,
                "claim.legacy",
                result.clone()
            )
            .unwrap()
            .stage,
        LaunchDispatchStage::HostAccepted
    );
    assert!(matches!(
        store
            .observe_effect(
                receipt.outbox_id,
                "scope.legacy",
                "pod.legacy",
                1,
                1,
                "claim.legacy",
                &host_proof()
            )
            .unwrap(),
        EffectObservation::NewObservation(_)
    ));
    let observed = snapshot(&fixture.database);
    assert_eq!(
        store
            .record_launch_port_result(
                receipt.outbox_id,
                "scope.legacy",
                "pod.legacy",
                1,
                "claim.legacy",
                result
            )
            .unwrap()
            .stage,
        LaunchDispatchStage::HostAccepted
    );
    assert!(matches!(
        store
            .observe_effect(
                receipt.outbox_id,
                "scope.legacy",
                "pod.legacy",
                1,
                1,
                "claim.legacy",
                &host_proof()
            )
            .unwrap(),
        EffectObservation::AlreadyObserved(_)
    ));
    assert_eq!(snapshot(&fixture.database), observed);
}

#[test]
fn fd3_guard_preserves_complete_legacy_unbound_outcome_and_exact_retry() {
    let mention = b"documentation mentions podbay.launch-descriptor/1";
    let descriptor = Fd3Root::new(LifetimeLimit::UntilStopped)
        .descriptor
        .encode_json()
        .unwrap();
    let mut binary = vec![0xff; 1_048_576];
    binary[..mention.len()].copy_from_slice(mention);
    // Generic payloads are opaque. Even canonical descriptor JSON can be data
    // in a real generic admission graph; its bytes cannot prove bound origin.
    for (event, effect) in [
        (b"old-event".as_slice(), b"old-effect".as_slice()),
        (b"old-event".as_slice(), mention.as_slice()),
        (mention.as_slice(), b"old-effect".as_slice()),
        (mention.as_slice(), mention.as_slice()),
        (descriptor.as_slice(), descriptor.as_slice()),
        (b"old-event".as_slice(), binary.as_slice()),
    ] {
        legacy_unbound_outcome_roundtrip(event, effect);
    }
}

#[test]
fn fd3_legacy_fallback_requires_complete_lineage() {
    for fault in ["digest", "missing_event"] {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        setup(&mut store);
        store
            .advance_target_epoch("scope.legacy", "pod.legacy", 0, 1)
            .unwrap();
        let request = CommandRequest {
            principal: principal(),
            namespace: "podbay.launch".into(),
            command_key: "legacy.key".into(),
            scope_id: "scope.legacy".into(),
            target_id: "pod.legacy".into(),
            expected_owner_epoch: 1,
            expected_target_epoch: 1,
            canonical_request: b"legacy caller intent".to_vec(),
            event_kind: "command.admitted".into(),
            event_payload: b"old-event".to_vec(),
            effect_kind: "pod.offer".into(),
            effect_payload: b"old-effect".to_vec(),
        };
        let receipt = match store.admit(&request).unwrap() {
            Admission::Committed(receipt) => receipt,
            _ => panic!("fresh legacy fixture"),
        };
        let c = Connection::open(&fixture.database).unwrap();
        c.execute("UPDATE outbox SET state='claimed_uncertain',claim_key='claim.legacy',claim_owner_epoch=1", []).unwrap();
        if fault == "digest" {
            c.execute("UPDATE commands SET request_digest=?1", ["f".repeat(64)])
                .unwrap();
            // Keep the claimed digest association coherent so reconstruction
            // must refuse the wrong hash independently of that association.
            c.execute("UPDATE events SET source_digest=?1", ["f".repeat(64)])
                .unwrap();
        } else if fault == "missing_event" {
            c.execute_batch("PRAGMA foreign_keys=OFF; DELETE FROM events;")
                .unwrap();
        }
        drop(c);
        let before = snapshot(&fixture.database);
        let expected = "legacy unbound launch admission is not verified";
        let first = store.record_launch_port_result(
            receipt.outbox_id,
            "scope.legacy",
            "pod.legacy",
            1,
            "claim.legacy",
            LaunchPortResult::HostAccepted {
                receipt_ref: Some("legacy.receipt".into()),
            },
        );
        assert!(
            matches!(first, Err(StoreError::Conflict(reason)) if reason == expected),
            "{first:?}"
        );
        let second = store.observe_effect(
            receipt.outbox_id,
            "scope.legacy",
            "pod.legacy",
            1,
            1,
            "claim.legacy",
            &host_proof(),
        );
        assert!(
            matches!(second, Err(StoreError::Conflict(reason)) if reason == expected),
            "{second:?}"
        );
        assert_eq!(snapshot(&fixture.database), before, "{fault}");
    }
}
