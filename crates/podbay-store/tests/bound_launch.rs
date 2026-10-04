use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_core::{
    ActorId, Attempt, AttemptId, CommandAdmission, CommandId, Epoch, LaunchBinding,
    PlannedRootBinding, Pod, PodId,
    Resource, ResourceId, ResourceKind, Role, Run, RunCommandKind, RunId, ScopeId, Session,
    SessionId, WorkKind,
};
use podbay_store::{
    Admission, AuthorityActorRecord, AuthorityGrantRecord, AuthorityMutation, AuthorityPodRecord,
    AuthorityRightRecord, BoundLaunchAdmission, BoundLaunchProposal, BoundLaunchRequest,
    BoundOperatorRootLaunchProposal, BoundOperatorRootLaunchRequest,
    CommandRequest, EffectClaim, EffectObservation, HostAcceptanceProof, LaunchDispatchStage,
    LaunchIntentBinding, LaunchLookupRequest, LaunchPortResult, PodBayStore, StoreError,
    VerifiedPrincipal,
};
use podbay_wire::{
    EffectiveLaunchContract, ImmutableLaunchDescriptor, ResourceDriver, ReviewedNativePolicy,
    ReviewedResource, TargetOs, OPERATOR_PROCESS_PROFILE_REF,
};
use sha2::{Digest, Sha256};

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
        let directory =
            std::env::temp_dir().join(format!("podbay-bound-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        Self {
            database: directory.join("state.sqlite"),
            directory,
        }
    }
    fn open(&self) -> PodBayStore {
        PodBayStore::open(&self.database).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

struct Admitted;
impl CommandAdmission for Admitted {
    fn admits_run(&self, _: &CommandId, _: &RunId, kind: RunCommandKind) -> bool {
        kind == RunCommandKind::Launch
    }
}

struct ProposalFixture {
    session: Session,
    run: Run,
    binding: LaunchBinding,
    descriptor: ImmutableLaunchDescriptor,
    effective_spec: Vec<u8>,
}
fn append_string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}
fn append_list(bytes: &mut Vec<u8>, values: &[&str]) {
    bytes.extend_from_slice(&(values.len() as u32).to_be_bytes());
    for value in values {
        append_string(bytes, value);
    }
}
fn effective_fixture_bytes(role: Role, pod_name: &str) -> Vec<u8> {
    let mut bytes = b"podbay.effective-launch/1\0".to_vec();
    append_string(&mut bytes, pod_name);
    append_string(
        &mut bytes,
        match role {
            Role::Coordinator => "coordinator",
            Role::Worker => "worker",
            Role::Advisor => "advisor",
        },
    );
    bytes.push(0); // root run has no parent
    append_string(&mut bytes, "profile.fixture");
    bytes.extend_from_slice(&1u64.to_be_bytes());
    append_string(&mut bytes, "/bin/true");
    append_string(&mut bytes, "generation.fixture");
    append_list(&mut bytes, &["fixture"]);
    append_string(&mut bytes, "model.fixture");
    append_string(&mut bytes, "medium");
    bytes.push(0); // no fallback
    append_string(&mut bytes, "scope.root.fixture");
    append_string(&mut bytes, "basis.fixture");
    append_string(&mut bytes, ".");
    bytes.push(1); // read-write workspace access
    append_list(&mut bytes, &[]); // tool bundles
    bytes.extend_from_slice(&1u64.to_be_bytes()); // authority grant reference
    bytes.extend_from_slice(&60u64.to_be_bytes());
    bytes.extend_from_slice(&1u32.to_be_bytes());
    append_list(&mut bytes, &[]); // environment refs
    bytes.extend_from_slice(&0u32.to_be_bytes()); // credential refs
    assert_eq!(
        EffectiveLaunchContract::decode(&bytes)
            .unwrap()
            .canonical_bytes(),
        bytes
    );
    bytes
}
impl ProposalFixture {
    fn new(role: Role, work_kind: WorkKind, pod_name: &str) -> Self {
        let mut session = Session::new(
            SessionId::try_from("session.root.fixture").unwrap(),
            ActorId::try_from("actor.root.fixture").unwrap(),
            ScopeId::try_from("scope.root.fixture").unwrap(),
        );
        let mut run = Run::new(
            RunId::try_from("run.root.fixture").unwrap(),
            &session,
            role,
            work_kind,
            None,
        );
        run.admit(
            run.revision(),
            &CommandId::try_from("command.root.fixture").unwrap(),
            &Admitted,
        )
        .unwrap();
        session.bind_run(session.revision(), &run).unwrap();
        let mut attempt = Attempt::new(
            AttemptId::try_from("attempt.root.fixture").unwrap(),
            run.id().clone(),
            1,
            Epoch::new(1).unwrap(),
        )
        .unwrap();
        run.start_attempt(run.revision(), &attempt).unwrap();
        let mut pod = Pod::new(
            PodId::try_from(pod_name).unwrap(),
            attempt.id().clone(),
            Epoch::new(1).unwrap(),
        );
        attempt.attach_pod(attempt.revision(), &pod).unwrap();
        let resources = vec![
            Resource::new(
                ResourceId::try_from("resource.pty.fixture").unwrap(),
                pod.id().clone(),
                ResourceKind::Pty,
                Epoch::new(1).unwrap(),
            ),
            Resource::new(
                ResourceId::try_from("resource.provider.fixture").unwrap(),
                pod.id().clone(),
                ResourceKind::StructuredProvider,
                Epoch::new(1).unwrap(),
            ),
        ];
        for resource in &resources {
            pod.attach_resource(pod.revision(), resource).unwrap();
        }
        let binding =
            LaunchBinding::from_aggregates(&session, &run, &attempt, &pod, &resources).unwrap();
        let effective_spec = effective_fixture_bytes(role, pod_name);
        let digest = Sha256::digest(&effective_spec)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let policy = ReviewedNativePolicy {
            target_os: TargetOs::Linux,
            host_id: "host.fixture".into(),
            profile_ref: "profile.fixture".into(),
            profile_generation: 1,
            model_id: "model.fixture".into(),
            reasoning_effort: "medium".into(),
            executable_generation: "generation.fixture".into(),
            effective_spec_digest: digest,
            workspace_basis_ref: "basis.fixture".into(),
            executable: "/bin/true".into(),
            cwd: "/tmp".into(),
            arguments: vec!["fixture".into()],
            environment_refs: vec![],
            credential_refs: vec![],
            wall_seconds: 60,
            max_children: 1,
            resources: vec![
                ReviewedResource {
                    resource_id: resources[0].id().clone(),
                    kind: ResourceKind::Pty,
                    epoch: resources[0].epoch(),
                    driver: ResourceDriver::Pty {
                        rows: 24,
                        columns: 80,
                        retention_events: 100,
                    },
                },
                ReviewedResource {
                    resource_id: resources[1].id().clone(),
                    kind: ResourceKind::StructuredProvider,
                    epoch: resources[1].epoch(),
                    driver: ResourceDriver::Structured {
                        driver_ref: "driver.fixture".into(),
                        protocol_ref: "protocol.fixture".into(),
                    },
                },
            ],
        };
        let descriptor = ImmutableLaunchDescriptor::from_binding(&binding, policy).unwrap();
        Self {
            session,
            run,
            binding,
            descriptor,
            effective_spec,
        }
    }
    fn request<'a>(&'a self, key: &'a str, caller: &'a [u8]) -> BoundLaunchRequest<'a> {
        BoundLaunchRequest {
            principal: principal(),
            command_key: key,
            canonical_intent: caller,
            scope_id: self.binding.scope_id().as_str(),
            pod_id: self.binding.pod_id().as_str(),
            proposal: Some(BoundLaunchProposal {
                session: &self.session,
                run: &self.run,
                binding: &self.binding,
                effective_spec: &self.effective_spec,
                descriptor: &self.descriptor,
                expected_owner_epoch: 1,
                expected_authority_revision: 0,
            }),
        }
    }
}
fn policy_with_digest(proposal: &ProposalFixture, digest: String) -> ReviewedNativePolicy {
    let descriptor = &proposal.descriptor;
    ReviewedNativePolicy {
        target_os: descriptor.target_os(),
        host_id: descriptor.host_id().into(),
        profile_ref: descriptor.profile_ref().into(),
        profile_generation: descriptor.profile_generation(),
        model_id: descriptor.model_id().into(),
        reasoning_effort: descriptor.reasoning_effort().into(),
        executable_generation: descriptor.executable_generation().into(),
        effective_spec_digest: digest,
        workspace_basis_ref: descriptor.workspace_basis_ref().into(),
        executable: descriptor.executable().into(),
        cwd: descriptor.cwd().into(),
        arguments: descriptor.arguments().to_vec(),
        environment_refs: descriptor.environment_refs().to_vec(),
        credential_refs: descriptor.credential_refs().to_vec(),
        wall_seconds: descriptor.wall_seconds().expect("V1 fixture lifetime is finite"),
        max_children: descriptor.max_children() as u32,
        resources: proposal
            .binding
            .resources()
            .iter()
            .enumerate()
            .map(|(index, bound)| ReviewedResource {
                resource_id: bound.id().clone(),
                kind: bound.kind(),
                epoch: bound.epoch(),
                driver: descriptor.resource(index).unwrap().driver.clone(),
            })
            .collect(),
    }
}
fn principal() -> VerifiedPrincipal {
    VerifiedPrincipal::from_authenticated_boundary("principal.fixture").unwrap()
}
fn host_proof() -> HostAcceptanceProof {
    HostAcceptanceProof::from_authenticated_host_boundary(
        "host.fixture",
        1,
        1,
        "host-receipt.fixture",
        b"accepted",
        Some("2026-10-03T12:00:00Z"),
        "correlation.fixture",
        None,
    )
    .unwrap()
}
fn setup(store: &mut PodBayStore) {
    store.advance_owner_epoch(0, 1).unwrap();
}
fn count(path: &PathBuf, table: &str) -> i64 {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

struct OperatorRootFixture {
    session: Session,
    run: Run,
    planned: PlannedRootBinding,
    descriptor: ImmutableLaunchDescriptor,
    effective: Vec<u8>,
}

impl OperatorRootFixture {
    fn new(profile_ref: &str) -> Self {
        let mut session = Session::new(
            SessionId::try_from("session.operator.root").unwrap(),
            ActorId::try_from("actor.operator.root").unwrap(),
            ScopeId::try_from("scope.root.fixture").unwrap(),
        );
        let run = Run::new(
            RunId::try_from("run.operator.root").unwrap(),
            &session,
            Role::Coordinator,
            WorkKind::Service,
            None,
        );
        session.bind_run(session.revision(), &run).unwrap();
        let mut attempt = Attempt::new(
            AttemptId::try_from("attempt.operator.root").unwrap(),
            run.id().clone(),
            1,
            Epoch::new(1).unwrap(),
        )
        .unwrap();
        let mut pod = Pod::new(
            PodId::try_from("pod.operator.root").unwrap(),
            attempt.id().clone(),
            Epoch::new(1).unwrap(),
        );
        attempt.attach_pod(attempt.revision(), &pod).unwrap();
        let resource = Resource::new(
            ResourceId::try_from("resource.operator.root").unwrap(),
            pod.id().clone(),
            ResourceKind::Auxiliary,
            Epoch::new(1).unwrap(),
        );
        pod.attach_resource(pod.revision(), &resource).unwrap();
        let planned = LaunchBinding::plan_first_root(&session, &run, &attempt, &pod, &[resource.clone()])
            .unwrap();
        let mut effective = b"podbay.effective-launch/1\0".to_vec();
        append_string(&mut effective, "pod.operator.root");
        append_string(&mut effective, "coordinator");
        effective.push(0);
        append_string(&mut effective, profile_ref);
        effective.extend_from_slice(&1u64.to_be_bytes());
        append_string(&mut effective, "/bin/true");
        append_string(&mut effective, "generation.operator.root");
        append_list(&mut effective, &["zap-server"]);
        append_string(&mut effective, "none");
        append_string(&mut effective, "none");
        effective.push(0);
        append_string(&mut effective, "scope.root.fixture");
        append_string(&mut effective, "basis.operator.root");
        append_string(&mut effective, ".");
        effective.push(1);
        append_list(&mut effective, &[]);
        effective.extend_from_slice(&1u64.to_be_bytes());
        effective.extend_from_slice(&60u64.to_be_bytes());
        effective.extend_from_slice(&0u32.to_be_bytes());
        append_list(&mut effective, &[]);
        effective.extend_from_slice(&0u32.to_be_bytes());
        let decoded = EffectiveLaunchContract::decode(&effective).unwrap();
        let descriptor = ImmutableLaunchDescriptor::from_planned_root(
            &planned,
            ReviewedNativePolicy {
                target_os: TargetOs::Linux,
                host_id: "host.operator.root".into(),
                profile_ref: profile_ref.into(),
                profile_generation: 1,
                model_id: "none".into(),
                reasoning_effort: "none".into(),
                executable_generation: "generation.operator.root".into(),
                effective_spec_digest: decoded.digest().into(),
                workspace_basis_ref: "basis.operator.root".into(),
                executable: "/bin/true".into(),
                cwd: "/tmp".into(),
                arguments: vec!["zap-server".into()],
                environment_refs: vec![],
                credential_refs: vec![],
                wall_seconds: 60,
                max_children: 0,
                resources: vec![ReviewedResource {
                    resource_id: resource.id().clone(),
                    kind: ResourceKind::Auxiliary,
                    epoch: resource.epoch(),
                    driver: ResourceDriver::Auxiliary {
                        driver_ref: "process.exec".into(),
                    },
                }],
            },
        )
        .unwrap();
        decoded.compare_with_descriptor(&descriptor).unwrap();
        Self { session, run, planned, descriptor, effective }
    }

    fn request<'a>(&'a self, key: &'a str) -> BoundOperatorRootLaunchRequest<'a> {
        BoundOperatorRootLaunchRequest {
            principal: principal(),
            command_key: key,
            canonical_intent: b"operator root caller intent",
            scope_id: self.planned.identity().scope_id().as_str(),
            pod_id: self.planned.identity().pod_id().as_str(),
            proposal: Some(BoundOperatorRootLaunchProposal {
                session: &self.session,
                run: &self.run,
                binding: &self.planned,
                effective_spec: &self.effective,
                descriptor: &self.descriptor,
                expected_owner_epoch: 1,
                expected_authority_revision: 0,
            }),
        }
    }
}

#[test]
fn queued_operator_root_uses_inserted_command_witness_and_replays_without_another_outbox() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    setup(&mut store);
    let proposal = OperatorRootFixture::new(OPERATOR_PROCESS_PROFILE_REF);
    assert_eq!(proposal.run.admission(), podbay_core::AdmissionState::Queued);
    let first = match store.admit_bound_operator_root_launch(proposal.request("key.operator.root"))
        .unwrap() {
        BoundLaunchAdmission::Committed(record) => record,
        BoundLaunchAdmission::Duplicate(_) => panic!("first operator root was duplicate"),
    };
    assert_eq!(first.format, podbay_store::BoundLaunchFormat::V1);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let (admission, revision): (String, i64) = connection
        .query_row(
            "SELECT admission_state,revision FROM runtime_runs WHERE run_id='run.operator.root'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(admission, "admitted");
    assert_eq!(revision, 3);
    assert_eq!(count(&fixture.database, "commands"), 1);
    assert_eq!(count(&fixture.database, "outbox"), 1);
    drop(connection);
    drop(store);
    let mut reopened = fixture.open();
    let repeated = reopened
        .admit_bound_operator_root_launch(BoundOperatorRootLaunchRequest {
            principal: principal(),
            command_key: "key.operator.root",
            canonical_intent: b"operator root caller intent",
            scope_id: "scope.root.fixture",
            pod_id: "pod.operator.root",
            proposal: None,
        })
        .unwrap();
    match repeated {
        BoundLaunchAdmission::Duplicate(record) => assert_eq!(record.receipt, first.receipt),
        BoundLaunchAdmission::Committed(_) => panic!("operator duplicate committed twice"),
    }
    assert!(matches!(
        reopened.admit_bound_launch(BoundLaunchRequest {
            principal: principal(),
            command_key: "key.operator.root",
            canonical_intent: b"operator root caller intent",
            scope_id: "scope.root.fixture",
            pod_id: "pod.operator.root",
            proposal: None,
        }),
        Err(StoreError::Conflict("command key changed operator process admission path"))
    ));
    assert_eq!(count(&fixture.database, "commands"), 1);
    assert_eq!(count(&fixture.database, "outbox"), 1);
}

#[test]
fn queued_operator_root_rejects_other_profile_before_any_commit() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    setup(&mut store);
    let proposal = OperatorRootFixture::new("profile.other.root");
    assert!(matches!(
        store.admit_bound_operator_root_launch(proposal.request("key.operator.wrong-profile")),
        Err(StoreError::Conflict("operator process root shape differs"))
    ));
    for table in ["commands", "runtime_runs", "launch_bindings", "outbox"] {
        assert_eq!(count(&fixture.database, table), 0, "{table}");
    }
}

#[test]
fn queued_operator_root_rolls_back_inserted_command_if_outbox_fails() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    setup(&mut store);
    drop(store);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_operator_outbox BEFORE INSERT ON outbox
             WHEN NEW.kind='pod.offer' BEGIN SELECT RAISE(ABORT,'fixture failure'); END;",
        )
        .unwrap();
    drop(connection);
    let proposal = OperatorRootFixture::new(OPERATOR_PROCESS_PROFILE_REF);
    let mut store = fixture.open();
    assert!(store
        .admit_bound_operator_root_launch(proposal.request("key.operator.rollback"))
        .is_err());
    for table in [
        "runtime_sessions", "runtime_runs", "launch_bindings", "launch_resources",
        "authority_pods", "authority_resources", "target_epochs", "launch_slots",
        "commands", "events", "outbox",
    ] {
        assert_eq!(count(&fixture.database, table), 0, "{table}");
    }
    assert_eq!(store.authority_snapshot().unwrap().revision, 0);
}

#[test]
fn current_bound_pod_snapshot_tracks_owner_and_input_replay_without_caller_key() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    setup(&mut store);
    let proposal = ProposalFixture::new(Role::Worker, WorkKind::Task, "pod.root.fixture");
    let record = match store
        .admit_bound_launch(proposal.request("key.root.fixture", b"caller.intent"))
        .unwrap()
    {
        BoundLaunchAdmission::Committed(record) => record,
        other => panic!("{other:?}"),
    };
    let lineage = store
        .initial_cursor("scope.root.fixture")
        .unwrap()
        .store_lineage;
    let first = store
        .current_bound_pod_snapshot("scope.root.fixture", "pod.root.fixture")
        .unwrap();
    assert_eq!(first.store_lineage().as_str(), lineage);
    assert_eq!(first.owner_epoch().get(), 1);
    assert_eq!(first.authority_revision(), 1);
    assert_eq!(first.scope_id().as_str(), "scope.root.fixture");
    assert_eq!(first.pod_id().as_str(), "pod.root.fixture");
    assert_eq!(first.pod_incarnation().get(), 1);
    assert_eq!(first.attempt_id().as_str(), "attempt.root.fixture");
    assert_eq!(first.attempt_ordinal(), 1);
    assert_eq!(first.attempt_epoch().get(), 1);
    assert_eq!(first.launch(), &record);
    assert_eq!(first.resources().len(), 2);
    assert_eq!(first.resources()[0].id().as_str(), "resource.pty.fixture");
    assert_eq!(first.resources()[0].kind(), ResourceKind::Pty);
    assert_eq!(
        first.resources()[1].kind(),
        ResourceKind::StructuredProvider
    );
    assert!(
        first
            .resources()
            .iter()
            .all(|resource| resource.epoch().get() == 1 && resource.input_epoch().get() == 1)
    );
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute(
            "UPDATE runtime_runs SET execution_state='running' WHERE run_id='run.root.fixture'",
            [],
        )
        .unwrap();
    assert!(
        store
            .current_bound_pod_snapshot("scope.root.fixture", "pod.root.fixture")
            .is_ok()
    );
    store.begin_authority_replay(1, 2).unwrap();
    let replayed = store
        .current_bound_pod_snapshot("scope.root.fixture", "pod.root.fixture")
        .unwrap();
    assert_eq!(replayed.owner_epoch().get(), 2);
    assert_eq!(replayed.authority_revision(), 2);
    assert_eq!(replayed.launch(), &record);
    assert!(
        replayed
            .resources()
            .iter()
            .all(|resource| resource.input_epoch().get() == 2)
    );
}

#[test]
fn current_bound_pod_snapshot_refuses_wrong_scope_target_or_current_pointer() {
    for mutation in [
        "UPDATE runtime_sessions SET current_run_id='run.foreign' WHERE session_id='session.root.fixture'",
        "UPDATE runtime_runs SET current_attempt_id='attempt.foreign' WHERE run_id='run.root.fixture'",
        "UPDATE runtime_sessions SET state='closed' WHERE session_id='session.root.fixture'",
        "UPDATE runtime_runs SET execution_state='ended' WHERE run_id='run.root.fixture'",
        "UPDATE runtime_runs SET desired_mode='stop' WHERE run_id='run.root.fixture'",
        "UPDATE runtime_runs SET admission_state='proposed' WHERE run_id='run.root.fixture'",
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        setup(&mut store);
        let proposal = ProposalFixture::new(Role::Worker, WorkKind::Task, "pod.root.fixture");
        store
            .admit_bound_launch(proposal.request("key.root.fixture", b"caller.intent"))
            .unwrap();
        assert!(matches!(
            store.current_bound_pod_snapshot("scope.foreign", "pod.root.fixture"),
            Err(StoreError::WrongScope)
        ));
        assert!(matches!(
            store.current_bound_pod_snapshot("scope.root.fixture", "pod.missing"),
            Err(StoreError::NotFound)
        ));
        let connection = rusqlite::Connection::open(&fixture.database).unwrap();
        connection.execute_batch(mutation).unwrap();
        assert!(matches!(
            store.current_bound_pod_snapshot("scope.root.fixture", "pod.root.fixture"),
            Err(StoreError::Conflict(_))
        ));
    }
}

#[test]
fn later_attempt_ordinal_requires_a_matching_supported_immutable_binding() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    setup(&mut store);
    let proposal = ProposalFixture::new(Role::Worker, WorkKind::Task, "pod.root.fixture");
    store
        .admit_bound_launch(proposal.request("key.root.fixture", b"caller.intent"))
        .unwrap();
    // The v8 writer/readback currently admits only first root attempts. A
    // future ordinal cannot be inferred merely from Run's mutable pointer.
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "UPDATE launch_bindings SET attempt_ordinal=2;
         UPDATE runtime_runs SET last_attempt_ordinal=2;",
        )
        .unwrap();
    assert!(matches!(
        store.current_bound_pod_snapshot("scope.root.fixture", "pod.root.fixture"),
        Err(StoreError::Conflict(_))
    ));
}

#[test]
fn current_bound_pod_snapshot_refuses_stale_or_changed_authority_resources() {
    for mutation in [
        "DELETE FROM authority_resources WHERE resource_id='resource.provider.fixture'",
        "INSERT INTO authority_resources(resource_id,scope_id,pod_id,pod_incarnation,resource_epoch,input_epoch)
           VALUES('resource.extra','scope.root.fixture','pod.root.fixture',1,1,1)",
        "UPDATE authority_resources SET resource_epoch=2 WHERE resource_id='resource.pty.fixture'",
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        setup(&mut store);
        let proposal = ProposalFixture::new(Role::Worker, WorkKind::Task, "pod.root.fixture");
        store.admit_bound_launch(proposal.request("key.root.fixture", b"caller.intent")).unwrap();
        let connection = rusqlite::Connection::open(&fixture.database).unwrap();
        connection.execute_batch(mutation).unwrap();
        assert!(matches!(store.current_bound_pod_snapshot("scope.root.fixture", "pod.root.fixture"),
            Err(StoreError::Conflict(_))));
    }
    let fixture = Fixture::new();
    let mut store = fixture.open();
    setup(&mut store);
    let proposal = ProposalFixture::new(Role::Worker, WorkKind::Task, "pod.root.fixture");
    store
        .admit_bound_launch(proposal.request("key.root.fixture", b"caller.intent"))
        .unwrap();
    store
        .advance_target_epoch("scope.root.fixture", "pod.root.fixture", 1, 2)
        .unwrap();
    assert!(matches!(
        store.current_bound_pod_snapshot("scope.root.fixture", "pod.root.fixture"),
        Err(StoreError::StaleEpoch)
    ));
}

#[test]
fn coordinator_and_worker_commit_exact_multi_resource_admission() {
    for (role, kind) in [
        (Role::Coordinator, WorkKind::Service),
        (Role::Worker, WorkKind::Task),
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        setup(&mut store);
        let proposal = ProposalFixture::new(role, kind, "pod.root.fixture");
        let record = match store
            .admit_bound_launch(proposal.request("key.root.fixture", b"caller.intent"))
            .unwrap()
        {
            BoundLaunchAdmission::Committed(record) => record,
            other => panic!("expected commit: {other:?}"),
        };
        assert_eq!(
            record.descriptor,
            proposal.descriptor.encode_json().unwrap()
        );
        assert_eq!(record.effective_spec, proposal.effective_spec);
        assert_eq!(record.resources.len(), 2);
        assert_eq!(
            store
                .claim_effect(
                    record.receipt.outbox_id,
                    "scope.root.fixture",
                    "pod.root.fixture",
                    1,
                    1,
                    1,
                    "claim.root.fixture"
                )
                .unwrap(),
            EffectClaim::NewClaim
        );
        assert_eq!(store.authority_snapshot().unwrap().revision, 1);
        drop(store);
        for table in [
            "runtime_sessions",
            "runtime_runs",
            "launch_bindings",
            "authority_pods",
            "launch_slots",
            "commands",
            "events",
            "outbox",
        ] {
            assert_eq!(count(&fixture.database, table), 1, "{table}");
        }
        for table in ["launch_resources", "authority_resources"] {
            assert_eq!(count(&fixture.database, table), 2, "{table}");
        }
    }
}

#[test]
fn same_key_after_reopen_returns_original_without_proposal_or_profile() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    setup(&mut store);
    let proposal = ProposalFixture::new(Role::Coordinator, WorkKind::Service, "pod.root.fixture");
    let first = match store
        .admit_bound_launch(proposal.request("key.root.fixture", b"caller.intent"))
        .unwrap()
    {
        BoundLaunchAdmission::Committed(record) => record,
        other => panic!("{other:?}"),
    };
    drop(store);
    let mut reopened = fixture.open();
    let duplicate = reopened
        .admit_bound_launch(BoundLaunchRequest {
            principal: principal(),
            command_key: "key.root.fixture",
            canonical_intent: b"caller.intent",
            scope_id: "scope.root.fixture",
            pod_id: "pod.root.fixture",
            proposal: None,
        })
        .unwrap();
    assert_eq!(duplicate, BoundLaunchAdmission::Duplicate(first.clone()));
    let lookup = LaunchLookupRequest {
        principal: principal(),
        namespace: "podbay.launch".into(),
        command_key: "key.root.fixture".into(),
        scope_id: "scope.root.fixture".into(),
        target_id: "pod.root.fixture".into(),
        canonical_intent: b"caller.intent".to_vec(),
    };
    assert_eq!(reopened.lookup_bound_launch(&lookup).unwrap(), Some(first));
    let mut new_key = lookup.clone();
    new_key.command_key = "key.new.fixture".into();
    assert_eq!(reopened.lookup_bound_launch(&new_key).unwrap(), None);
    let mut changed = lookup.clone();
    changed.canonical_intent = b"changed".to_vec();
    assert!(matches!(
        reopened.lookup_bound_launch(&changed),
        Err(StoreError::Conflict(_))
    ));
    let mut foreign_scope = lookup.clone();
    foreign_scope.scope_id = "scope.foreign.fixture".into();
    assert!(matches!(
        reopened.lookup_bound_launch(&foreign_scope),
        Err(StoreError::NotFound)
    ));
    let inspected = reopened
        .lookup_admitted_launch(&LaunchLookupRequest {
            principal: principal(),
            namespace: "podbay.launch".into(),
            command_key: "key.root.fixture".into(),
            scope_id: "scope.root.fixture".into(),
            target_id: "pod.root.fixture".into(),
            canonical_intent: b"caller.intent".to_vec(),
        })
        .unwrap();
    assert_eq!(inspected.binding, LaunchIntentBinding::BoundV8);
    assert!(matches!(
        reopened.admit_bound_launch(BoundLaunchRequest {
            principal: principal(),
            command_key: "key.root.fixture",
            canonical_intent: b"changed",
            scope_id: "scope.root.fixture",
            pod_id: "pod.root.fixture",
            proposal: None,
        }),
        Err(StoreError::Conflict(_))
    ));
    assert!(matches!(
        reopened.admit_bound_launch(BoundLaunchRequest {
            principal: principal(),
            command_key: "key.root.fixture",
            canonical_intent: b"caller.intent",
            scope_id: "scope.foreign.fixture",
            pod_id: "pod.root.fixture",
            proposal: None,
        }),
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        reopened.admit_bound_launch(BoundLaunchRequest {
            principal: principal(),
            command_key: "key.root.fixture",
            canonical_intent: b"caller.intent",
            scope_id: "scope.root.fixture",
            pod_id: "pod.foreign.fixture",
            proposal: None,
        }),
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        reopened.admit_bound_launch(BoundLaunchRequest {
            principal: VerifiedPrincipal::from_authenticated_boundary("principal.foreign").unwrap(),
            command_key: "key.root.fixture",
            canonical_intent: b"caller.intent",
            scope_id: "scope.root.fixture",
            pod_id: "pod.root.fixture",
            proposal: None,
        }),
        Err(StoreError::InvalidInput(
            "new bound launch requires reviewed proposal"
        ))
    ));
    assert_eq!(count(&fixture.database, "commands"), 1);
}

#[test]
fn mutable_run_state_preserves_receipt_but_fences_new_claim() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    setup(&mut store);
    let proposal = ProposalFixture::new(Role::Worker, WorkKind::Task, "pod.root.fixture");
    let committed = store
        .admit_bound_launch(proposal.request("key.root.fixture", b"caller.intent"))
        .unwrap();
    let record = match committed {
        BoundLaunchAdmission::Committed(record) => record,
        other => panic!("{other:?}"),
    };
    drop(store);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute(
            "UPDATE runtime_sessions SET state='closed',revision=5 WHERE session_id=?1",
            ["session.root.fixture"],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE runtime_runs SET desired_mode='stop',execution_state='ended',
        revision=6 WHERE run_id='run.root.fixture'",
            [],
        )
        .unwrap();
    drop(connection);
    let mut reopened = fixture.open();
    assert_eq!(
        reopened
            .admit_bound_launch(BoundLaunchRequest {
                principal: principal(),
                command_key: "key.root.fixture",
                canonical_intent: b"caller.intent",
                scope_id: "scope.root.fixture",
                pod_id: "pod.root.fixture",
                proposal: None,
            })
            .unwrap(),
        BoundLaunchAdmission::Duplicate(record.clone())
    );
    assert!(matches!(
        reopened.claim_effect(
            record.receipt.outbox_id,
            "scope.root.fixture",
            "pod.root.fixture",
            1,
            1,
            1,
            "claim.root.fixture"
        ),
        Err(StoreError::Conflict(
            "bound launch is no longer dispatch eligible"
        ))
    ));
}

#[test]
fn corrupted_immutable_association_or_event_lineage_refuses_duplicate() {
    for sql in [
        "UPDATE runtime_sessions SET actor_id='actor.foreign'",
        "UPDATE events SET target_id='pod.foreign' WHERE kind='launch.bound'",
        "UPDATE outbox SET owner_epoch=4 WHERE kind='pod.offer'",
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        setup(&mut store);
        let proposal = ProposalFixture::new(Role::Worker, WorkKind::Task, "pod.root.fixture");
        store
            .admit_bound_launch(proposal.request("key.root.fixture", b"caller.intent"))
            .unwrap();
        drop(store);
        let connection = rusqlite::Connection::open(&fixture.database).unwrap();
        connection.execute(sql, []).unwrap();
        drop(connection);
        let mut reopened = fixture.open();
        assert!(
            matches!(
                reopened.admit_bound_launch(BoundLaunchRequest {
                    principal: principal(),
                    command_key: "key.root.fixture",
                    canonical_intent: b"caller.intent",
                    scope_id: "scope.root.fixture",
                    pod_id: "pod.root.fixture",
                    proposal: None,
                }),
                Err(StoreError::Conflict(_))
            ),
            "{sql}"
        );
    }
}

#[test]
fn newer_authority_incarnation_does_not_erase_old_receipt_or_reenable_claim() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    setup(&mut store);
    let proposal = ProposalFixture::new(Role::Worker, WorkKind::Task, "pod.root.fixture");
    let record = match store
        .admit_bound_launch(proposal.request("key.root.fixture", b"caller.intent"))
        .unwrap()
    {
        BoundLaunchAdmission::Committed(record) => record,
        other => panic!("{other:?}"),
    };
    drop(store);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "UPDATE authority_pods SET incarnation=2;
      UPDATE authority_resources SET pod_incarnation=2,resource_epoch=2,input_epoch=2;
      UPDATE target_epochs SET epoch=2;",
        )
        .unwrap();
    drop(connection);
    let mut reopened = fixture.open();
    assert_eq!(
        reopened
            .admit_bound_launch(BoundLaunchRequest {
                principal: principal(),
                command_key: "key.root.fixture",
                canonical_intent: b"caller.intent",
                scope_id: "scope.root.fixture",
                pod_id: "pod.root.fixture",
                proposal: None,
            })
            .unwrap(),
        BoundLaunchAdmission::Duplicate(record.clone())
    );
    assert!(matches!(
        reopened.claim_effect(
            record.receipt.outbox_id,
            "scope.root.fixture",
            "pod.root.fixture",
            1,
            1,
            1,
            "claim.root.fixture"
        ),
        Err(StoreError::StaleEpoch)
    ));
}

#[test]
fn different_key_competing_for_same_session_has_one_commit() {
    let fixture = Fixture::new();
    let mut setup_store = fixture.open();
    setup(&mut setup_store);
    drop(setup_store);
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for index in 0..2 {
        let path = fixture.database.clone();
        let barrier = barrier.clone();
        workers.push(thread::spawn(move || {
            let proposal = ProposalFixture::new(Role::Worker, WorkKind::Task, "pod.root.fixture");
            let mut store = PodBayStore::open(path).unwrap();
            barrier.wait();
            store
                .admit_bound_launch(proposal.request(&format!("key.concurrent.{index}"), b"same"))
                .map(|result| matches!(result, BoundLaunchAdmission::Committed(_)))
        }));
    }
    barrier.wait();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|item| matches!(item, Ok(true)))
            .count(),
        1
    );
    assert_eq!(results.iter().filter(|item| item.is_err()).count(), 1);
    assert_eq!(count(&fixture.database, "commands"), 1);
    assert_eq!(count(&fixture.database, "authority_pods"), 1);
}

#[test]
fn descriptor_mismatch_and_stale_authority_leave_no_rows() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    setup(&mut store);
    let proposal = ProposalFixture::new(Role::Worker, WorkKind::Task, "pod.root.fixture");
    let foreign = ProposalFixture::new(Role::Worker, WorkKind::Task, "pod.other.fixture");
    let bad = BoundLaunchRequest {
        principal: principal(),
        command_key: "key.bad.fixture",
        canonical_intent: b"bad",
        scope_id: "scope.root.fixture",
        pod_id: "pod.root.fixture",
        proposal: Some(BoundLaunchProposal {
            session: &proposal.session,
            run: &proposal.run,
            binding: &proposal.binding,
            effective_spec: &proposal.effective_spec,
            descriptor: &foreign.descriptor,
            expected_owner_epoch: 1,
            expected_authority_revision: 0,
        }),
    };
    assert!(matches!(
        store.admit_bound_launch(bad),
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(count(&fixture.database, "commands"), 0);
    let stale = BoundLaunchRequest {
        principal: principal(),
        command_key: "key.stale.fixture",
        canonical_intent: b"stale",
        scope_id: "scope.root.fixture",
        pod_id: "pod.root.fixture",
        proposal: Some(BoundLaunchProposal {
            session: &proposal.session,
            run: &proposal.run,
            binding: &proposal.binding,
            effective_spec: &proposal.effective_spec,
            descriptor: &proposal.descriptor,
            expected_owner_epoch: 1,
            expected_authority_revision: 1,
        }),
    };
    assert!(matches!(
        store.admit_bound_launch(stale),
        Err(StoreError::StaleEpoch)
    ));
    assert_eq!(count(&fixture.database, "runtime_sessions"), 0);
}

#[test]
fn typed_effective_comparison_rejects_mismatch_even_with_recalculated_digest() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    setup(&mut store);
    let proposal = ProposalFixture::new(Role::Worker, WorkKind::Task, "pod.root.fixture");
    let mut changed = proposal.effective_spec.clone();
    let original = b"model.fixture";
    let position = changed
        .windows(original.len())
        .position(|window| window == original)
        .unwrap();
    changed[position..position + original.len()].copy_from_slice(b"model.foreign");
    let effective = EffectiveLaunchContract::decode(&changed).unwrap();
    let descriptor = ImmutableLaunchDescriptor::from_binding(
        &proposal.binding,
        policy_with_digest(&proposal, effective.digest().into()),
    )
    .unwrap();
    assert!(matches!(
        store.admit_bound_launch(BoundLaunchRequest {
            principal: principal(),
            command_key: "key.mismatch.fixture",
            canonical_intent: b"caller.intent",
            scope_id: "scope.root.fixture",
            pod_id: "pod.root.fixture",
            proposal: Some(BoundLaunchProposal {
                session: &proposal.session,
                run: &proposal.run,
                binding: &proposal.binding,
                effective_spec: &changed,
                descriptor: &descriptor,
                expected_owner_epoch: 1,
                expected_authority_revision: 0
            }),
        }),
        Err(StoreError::Conflict(
            "effective launch differs from descriptor"
        ))
    ));
    assert_eq!(count(&fixture.database, "commands"), 0);
    let malformed = b"podbay.effective-launch/1\0arbitrary";
    assert!(matches!(
        store.admit_bound_launch(BoundLaunchRequest {
            principal: principal(),
            command_key: "key.malformed.fixture",
            canonical_intent: b"caller.intent",
            scope_id: "scope.root.fixture",
            pod_id: "pod.root.fixture",
            proposal: Some(BoundLaunchProposal {
                session: &proposal.session,
                run: &proposal.run,
                binding: &proposal.binding,
                effective_spec: malformed,
                descriptor: &proposal.descriptor,
                expected_owner_epoch: 1,
                expected_authority_revision: 0
            }),
        }),
        Err(StoreError::InvalidInput(
            "effective launch bytes are malformed"
        ))
    ));
    assert_eq!(count(&fixture.database, "commands"), 0);
}

#[test]
fn outbox_failure_rolls_back_identity_authority_and_command() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    setup(&mut store);
    drop(store);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_bound_outbox BEFORE INSERT ON outbox
      WHEN NEW.kind='pod.offer' BEGIN SELECT RAISE(ABORT,'fixture failure'); END;",
        )
        .unwrap();
    drop(connection);
    let proposal = ProposalFixture::new(Role::Coordinator, WorkKind::Service, "pod.root.fixture");
    let mut store = fixture.open();
    assert!(
        store
            .admit_bound_launch(proposal.request("key.root.fixture", b"caller.intent"))
            .is_err()
    );
    for table in [
        "runtime_sessions",
        "runtime_runs",
        "launch_bindings",
        "launch_resources",
        "authority_pods",
        "authority_resources",
        "target_epochs",
        "launch_slots",
        "commands",
        "events",
        "outbox",
    ] {
        assert_eq!(count(&fixture.database, table), 0, "{table}");
    }
    assert_eq!(store.authority_snapshot().unwrap().revision, 0);
}

#[test]
fn historical_unbound_command_cannot_become_bound_by_retry() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    setup(&mut store);
    store
        .advance_target_epoch("scope.root.fixture", "pod.root.fixture", 0, 1)
        .unwrap();
    let legacy = CommandRequest {
        principal: principal(),
        namespace: "podbay.launch".into(),
        command_key: "key.root.fixture".into(),
        scope_id: "scope.root.fixture".into(),
        target_id: "pod.root.fixture".into(),
        expected_owner_epoch: 1,
        expected_target_epoch: 1,
        canonical_request: b"caller.intent".to_vec(),
        event_kind: "command.admitted".into(),
        event_payload: b"old-event".to_vec(),
        effect_kind: "pod.offer".into(),
        effect_payload: b"old-effect".to_vec(),
    };
    assert!(matches!(
        store.admit(&legacy).unwrap(),
        Admission::Committed(_)
    ));
    store
        .apply_authority_mutation(
            1,
            0,
            AuthorityMutation::PutPod(AuthorityPodRecord {
                scope_id: "scope.root.fixture".into(),
                pod_id: "pod.root.fixture".into(),
                incarnation: 1,
            }),
        )
        .unwrap();
    assert!(matches!(
        store.current_bound_pod_snapshot("scope.root.fixture", "pod.root.fixture"),
        Err(StoreError::Conflict(
            "historical launch has no bound v8 descriptor"
        ))
    ));
    let result = store.admit_bound_launch(BoundLaunchRequest {
        principal: principal(),
        command_key: "key.root.fixture",
        canonical_intent: b"caller.intent",
        scope_id: "scope.root.fixture",
        pod_id: "pod.root.fixture",
        proposal: None,
    });
    assert!(matches!(
        result,
        Err(StoreError::Conflict(
            "historical launch has no bound v8 descriptor"
        ))
    ));
    assert!(matches!(
        store.lookup_bound_launch(&LaunchLookupRequest {
            principal: principal(),
            namespace: "podbay.launch".into(),
            command_key: "key.root.fixture".into(),
            scope_id: "scope.root.fixture".into(),
            target_id: "pod.root.fixture".into(),
            canonical_intent: b"caller.intent".to_vec(),
        }),
        Err(StoreError::Conflict(
            "historical launch has no bound v8 descriptor"
        ))
    ));
    let old_outbox: i64 = rusqlite::Connection::open(&fixture.database)
        .unwrap()
        .query_row("SELECT outbox_id FROM outbox", [], |row| row.get(0))
        .unwrap();
    assert!(matches!(
        store.claim_effect(
            old_outbox,
            "scope.root.fixture",
            "pod.root.fixture",
            1,
            1,
            1,
            "claim.root.fixture"
        ),
        Err(StoreError::Conflict(
            "historical launch has no bound v8 descriptor"
        ))
    ));
    assert_eq!(count(&fixture.database, "launch_bindings"), 0);
}

#[test]
fn bound_claim_survives_reopen_and_host_observation_adds_event() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    setup(&mut store);
    let proposal = ProposalFixture::new(Role::Coordinator, WorkKind::Service, "pod.root.fixture");
    let record = match store
        .admit_bound_launch(proposal.request("key.root.fixture", b"caller.intent"))
        .unwrap()
    {
        BoundLaunchAdmission::Committed(record) => record,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        store
            .claim_effect(
                record.receipt.outbox_id,
                "scope.root.fixture",
                "pod.root.fixture",
                1,
                1,
                1,
                "claim.root.fixture"
            )
            .unwrap(),
        EffectClaim::NewClaim
    );
    drop(store);
    let mut reopened = fixture.open();
    assert_eq!(
        reopened
            .claim_effect(
                record.receipt.outbox_id,
                "scope.root.fixture",
                "pod.root.fixture",
                1,
                1,
                1,
                "claim.root.fixture"
            )
            .unwrap(),
        EffectClaim::ExistingUncertain
    );
    assert!(matches!(
        reopened.claim_effect(
            record.receipt.outbox_id,
            "scope.root.fixture",
            "pod.root.fixture",
            1,
            1,
            1,
            "claim.foreign.fixture"
        ),
        Err(StoreError::Conflict(_))
    ));
    let observed = reopened
        .observe_effect(
            record.receipt.outbox_id,
            "scope.root.fixture",
            "pod.root.fixture",
            1,
            1,
            "claim.root.fixture",
            &host_proof(),
        )
        .unwrap();
    assert!(matches!(observed, EffectObservation::NewObservation(_)));
    assert_eq!(
        reopened
            .scope_snapshot("scope.root.fixture")
            .unwrap()
            .receipts,
        vec![record.receipt]
    );
    assert_eq!(
        reopened
            .events_after(
                "scope.root.fixture",
                &reopened.initial_cursor("scope.root.fixture").unwrap(),
                10
            )
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn bound_owner_takeover_fences_old_owner_and_keeps_admission_lineage() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    setup(&mut store);
    let proposal = ProposalFixture::new(Role::Worker, WorkKind::Task, "pod.root.fixture");
    let record = match store
        .admit_bound_launch(proposal.request("key.root.fixture", b"caller.intent"))
        .unwrap()
    {
        BoundLaunchAdmission::Committed(record) => record,
        other => panic!("{other:?}"),
    };
    store.advance_owner_epoch(1, 2).unwrap();
    assert!(matches!(
        store.claim_effect(
            record.receipt.outbox_id,
            "scope.root.fixture",
            "pod.root.fixture",
            1,
            1,
            1,
            "claim.root.fixture"
        ),
        Err(StoreError::StaleEpoch)
    ));
    assert_eq!(
        store
            .claim_effect(
                record.receipt.outbox_id,
                "scope.root.fixture",
                "pod.root.fixture",
                2,
                1,
                1,
                "claim.root.fixture"
            )
            .unwrap(),
        EffectClaim::NewClaim
    );
    let effect = store
        .load_effect(
            record.receipt.outbox_id,
            "scope.root.fixture",
            "pod.root.fixture",
        )
        .unwrap();
    assert_eq!(effect.admission_owner_epoch, 1);
    assert_eq!(effect.claim_owner_epoch, Some(2));
}

#[test]
fn prepared_bound_launch_survives_authority_replay_input_epoch_advance() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    setup(&mut store);
    let proposal = ProposalFixture::new(Role::Coordinator, WorkKind::Service, "pod.root.fixture");
    let record = match store
        .admit_bound_launch(proposal.request("key.root.fixture", b"caller.intent"))
        .unwrap()
    {
        BoundLaunchAdmission::Committed(record) => record,
        other => panic!("{other:?}"),
    };
    drop(store);
    let mut reopened = fixture.open();
    let authority = reopened.begin_authority_replay(1, 2).unwrap();
    assert!(
        authority
            .resources
            .iter()
            .all(|resource| resource.input_epoch == 2)
    );
    let lookup = LaunchLookupRequest {
        principal: principal(),
        namespace: "podbay.launch".into(),
        command_key: "key.root.fixture".into(),
        scope_id: "scope.root.fixture".into(),
        target_id: "pod.root.fixture".into(),
        canonical_intent: b"caller.intent".to_vec(),
    };
    assert_eq!(
        reopened.lookup_bound_launch(&lookup).unwrap(),
        Some(record.clone())
    );
    assert!(matches!(
        reopened.claim_effect(
            record.receipt.outbox_id,
            "scope.root.fixture",
            "pod.root.fixture",
            1,
            1,
            2,
            "claim.root.fixture"
        ),
        Err(StoreError::StaleEpoch)
    ));
    assert_eq!(
        reopened
            .claim_effect(
                record.receipt.outbox_id,
                "scope.root.fixture",
                "pod.root.fixture",
                2,
                1,
                2,
                "claim.root.fixture"
            )
            .unwrap(),
        EffectClaim::NewClaim
    );
    assert_eq!(
        reopened
            .claim_effect(
                record.receipt.outbox_id,
                "scope.root.fixture",
                "pod.root.fixture",
                2,
                1,
                2,
                "claim.root.fixture"
            )
            .unwrap(),
        EffectClaim::ExistingUncertain
    );
}

#[test]
fn grant_revocation_between_review_and_claim_refuses_new_effect() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    setup(&mut store);
    let proposal = ProposalFixture::new(Role::Worker, WorkKind::Task, "pod.root.fixture");
    let record = match store
        .admit_bound_launch(proposal.request("key.root.fixture", b"caller.intent"))
        .unwrap()
    {
        BoundLaunchAdmission::Committed(record) => record,
        other => panic!("{other:?}"),
    };
    let actor = AuthorityActorRecord {
        scope_id: "scope.root.fixture".into(),
        actor_id: "actor.root.fixture".into(),
        role: "worker".into(),
        origin: "pod".into(),
        parent_actor_id: None,
        pod_id: Some("pod.root.fixture".into()),
        pod_incarnation: Some(1),
        credential_generation: 1,
        platform: "linux".into(),
        os_identity: "linux.uid.1000".into(),
        process_identity: "linux.pid.123".into(),
        start_identity: 456,
        containment_identity: "/user.slice/pod-root.scope".into(),
    };
    assert_eq!(
        store
            .apply_authority_mutation(1, 1, AuthorityMutation::PutActor(actor))
            .unwrap(),
        2
    );
    let grant = AuthorityGrantRecord {
        grant_id: 1,
        scope_id: "scope.root.fixture".into(),
        actor_id: "actor.root.fixture".into(),
        credential_generation: 1,
        mode: "controller".into(),
        remaining_delegation_depth: 0,
        rights: vec![AuthorityRightRecord {
            operation: "launch_pod".into(),
            target_kind: "pod".into(),
            target_id: "pod.root.fixture".into(),
        }],
    };
    let reviewed_revision = store
        .apply_authority_mutation(1, 2, AuthorityMutation::PutGrant(grant))
        .unwrap();
    assert_eq!(reviewed_revision, 3);
    assert_eq!(
        store
            .apply_authority_mutation(1, 3, AuthorityMutation::RevokeGrant(1))
            .unwrap(),
        4
    );
    assert!(matches!(
        store.claim_effect(
            record.receipt.outbox_id,
            "scope.root.fixture",
            "pod.root.fixture",
            1,
            1,
            reviewed_revision,
            "claim.root.fixture"
        ),
        Err(StoreError::StaleEpoch)
    ));
    assert_eq!(
        store.effect_state(record.receipt.outbox_id).unwrap(),
        podbay_store::EffectState::Prepared
    );
    // The store fences the stale review; only the host can prove a new grant.
}

#[test]
fn bound_port_refusal_is_durable_without_os_call() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    setup(&mut store);
    let proposal = ProposalFixture::new(Role::Worker, WorkKind::Task, "pod.root.fixture");
    let record = match store
        .admit_bound_launch(proposal.request("key.root.fixture", b"caller.intent"))
        .unwrap()
    {
        BoundLaunchAdmission::Committed(record) => record,
        other => panic!("{other:?}"),
    };
    store
        .claim_effect(
            record.receipt.outbox_id,
            "scope.root.fixture",
            "pod.root.fixture",
            1,
            1,
            1,
            "claim.root.fixture",
        )
        .unwrap();
    assert_eq!(
        store
            .record_launch_port_result(
                record.receipt.outbox_id,
                "scope.root.fixture",
                "pod.root.fixture",
                1,
                "claim.root.fixture",
                LaunchPortResult::RefusedBeforeEffect
            )
            .unwrap()
            .stage,
        LaunchDispatchStage::RefusedBeforeEffect
    );
    drop(store);
    assert_eq!(
        fixture
            .open()
            .launch_dispatch_status(
                record.receipt.outbox_id,
                "scope.root.fixture",
                "pod.root.fixture"
            )
            .unwrap()
            .stage,
        LaunchDispatchStage::RefusedBeforeEffect
    );
}
