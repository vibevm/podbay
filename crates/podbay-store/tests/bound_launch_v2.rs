use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_core::{
    ActorId, Attempt, AttemptId, CommandAdmission, CommandId, Epoch, LaunchBinding,
    PlannedRootBinding, Pod, PodId, Resource, ResourceId, ResourceKind, Role, Run, RunCommandKind,
    RunId, ScopeId, Session, SessionId, WorkKind,
};
use podbay_store::{
    BoundLaunchAdmission, BoundLaunchFormat, BoundLaunchProposal, BoundLaunchRequest,
    BoundRootLaunchProposalV2, BoundRootLaunchRequestV2, LaunchKeyLookupRequest,
    LaunchLookupRequest, PodBayStore, StoreError, VerifiedPrincipal,
};
use podbay_wire::{
    CodexAppServerPolicyV2, EffectiveLaunchContract, EffectiveLaunchContractV2,
    ImmutableLaunchDescriptor, ImmutableLaunchDescriptorV2, ResourceDriver, ReviewedNativePolicy,
    ReviewedResource, TargetOs,
};

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
            std::env::temp_dir().join(format!("podbay-bound-v2-{}-{stamp}", std::process::id()));
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

fn principal() -> VerifiedPrincipal {
    VerifiedPrincipal::from_authenticated_boundary("principal.codex.fixture").unwrap()
}

fn decode_hex(text: &str) -> Vec<u8> {
    let digits = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    digits
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn replace_encoded_string(bytes: &mut Vec<u8>, old: &str, new: &str) {
    let mut before = (old.len() as u32).to_be_bytes().to_vec();
    before.extend_from_slice(old.as_bytes());
    let at = bytes
        .windows(before.len())
        .position(|window| window == before)
        .unwrap();
    let mut after = (new.len() as u32).to_be_bytes().to_vec();
    after.extend_from_slice(new.as_bytes());
    bytes.splice(at..at + before.len(), after);
}

fn codex_policy() -> CodexAppServerPolicyV2 {
    CodexAppServerPolicyV2::new(
        &ScopeId::try_from("scope.launch").unwrap(),
        "vault.allowed.one".into(),
        "driver.codex.app-server".into(),
        "protocol.codex.app-server".into(),
    )
    .unwrap()
}

fn v2_effective(role: Role) -> EffectiveLaunchContractV2 {
    if role == Role::Coordinator {
        return EffectiveLaunchContractV2::decode(&decode_hex(include_str!(
            "../../podbay-wire/tests/effective_launch_v2.hex"
        )))
        .unwrap();
    }
    let mut bytes = decode_hex(include_str!(
        "../../podbay-wire/tests/effective_launch_v1.hex"
    ));
    replace_encoded_string(&mut bytes, "model.alpha", "gpt-6-sol");
    let base = EffectiveLaunchContract::decode(&bytes).unwrap();
    EffectiveLaunchContractV2::from_v1(base, codex_policy()).unwrap()
}

fn reviewed_policy(binding: &LaunchBinding, digest: &str) -> ReviewedNativePolicy {
    ReviewedNativePolicy {
        target_os: TargetOs::Linux,
        host_id: "host.codex.fixture".into(),
        profile_ref: "profile.fixture".into(),
        profile_generation: 1,
        model_id: "gpt-6-sol".into(),
        reasoning_effort: "medium".into(),
        executable_generation: "sha256.fakegeneration1".into(),
        effective_spec_digest: digest.into(),
        workspace_basis_ref: "basis.commit.one".into(),
        executable: "/opt/podbay/bin/fake-agent".into(),
        cwd: "/work/src".into(),
        arguments: vec!["--managed".into(), "--safe".into()],
        environment_refs: vec!["env.clean".into()],
        credential_refs: vec!["vault.allowed.one".into()],
        wall_seconds: 60,
        max_children: 2,
        resources: binding
            .resources()
            .iter()
            .map(|resource| ReviewedResource {
                resource_id: resource.id().clone(),
                kind: resource.kind(),
                epoch: resource.epoch(),
                driver: ResourceDriver::Structured {
                    driver_ref: "driver.codex.app-server".into(),
                    protocol_ref: "protocol.codex.app-server".into(),
                },
            })
            .collect(),
    }
}

struct ProposalFixture {
    session: Session,
    run: Run,
    binding: LaunchBinding,
    planned: Option<PlannedRootBinding>,
    effective: EffectiveLaunchContractV2,
    descriptor: ImmutableLaunchDescriptorV2,
}

impl ProposalFixture {
    fn new(role: Role, work: WorkKind) -> Self {
        Self::with_state(role, work, false)
    }

    fn legacy(role: Role, work: WorkKind) -> Self {
        Self::with_state(role, work, true)
    }

    fn with_state(role: Role, work: WorkKind, preadmitted: bool) -> Self {
        let mut session = Session::new(
            SessionId::try_from("session.codex.fixture").unwrap(),
            ActorId::try_from("actor.codex.fixture").unwrap(),
            ScopeId::try_from("scope.launch").unwrap(),
        );
        let mut run = Run::new(
            RunId::try_from("run.codex.fixture").unwrap(),
            &session,
            role,
            work,
            None,
        );
        if preadmitted {
            run.admit(
                run.revision(),
                &CommandId::try_from("command.legacy.fixture").unwrap(),
                &Admitted,
            )
            .unwrap();
        }
        session.bind_run(session.revision(), &run).unwrap();
        let mut attempt = Attempt::new(
            AttemptId::try_from("attempt.codex.fixture").unwrap(),
            run.id().clone(),
            1,
            Epoch::new(1).unwrap(),
        )
        .unwrap();
        if preadmitted {
            run.start_attempt(run.revision(), &attempt).unwrap();
        }
        let mut pod = Pod::new(
            PodId::try_from("pod.launch").unwrap(),
            attempt.id().clone(),
            Epoch::new(1).unwrap(),
        );
        attempt.attach_pod(attempt.revision(), &pod).unwrap();
        let resource = Resource::new(
            ResourceId::try_from("resource.codex.fixture").unwrap(),
            pod.id().clone(),
            ResourceKind::StructuredProvider,
            Epoch::new(1).unwrap(),
        );
        pod.attach_resource(pod.revision(), &resource).unwrap();
        let planned = if preadmitted {
            None
        } else {
            Some(
                LaunchBinding::plan_first_root(&session, &run, &attempt, &pod, &[resource.clone()])
                    .unwrap(),
            )
        };
        let binding = if let Some(plan) = &planned {
            plan.identity().clone()
        } else {
            LaunchBinding::from_aggregates(&session, &run, &attempt, &pod, &[resource]).unwrap()
        };
        let effective = v2_effective(role);
        let descriptor = if role == Role::Coordinator {
            ImmutableLaunchDescriptorV2::decode_json(
                include_str!("../../podbay-wire/tests/launch_descriptor_v2.json")
                    .trim_end()
                    .as_bytes(),
            )
            .unwrap()
        } else {
            if let Some(plan) = &planned {
                ImmutableLaunchDescriptorV2::from_planned_root(
                    plan,
                    reviewed_policy(&binding, effective.digest()),
                    codex_policy(),
                )
                .unwrap()
            } else {
                ImmutableLaunchDescriptorV2::from_binding(
                    &binding,
                    reviewed_policy(&binding, effective.digest()),
                    codex_policy(),
                )
                .unwrap()
            }
        };
        effective.compare_with_descriptor(&descriptor).unwrap();
        if let Some(plan) = &planned {
            descriptor.validate_against_planned_root(plan).unwrap();
        } else {
            descriptor.validate_against_binding(&binding).unwrap();
        }
        Self {
            session,
            run,
            binding,
            planned,
            effective,
            descriptor,
        }
    }

    fn request<'a>(&'a self, key: &'a str, intent: &'a [u8]) -> BoundRootLaunchRequestV2<'a> {
        BoundRootLaunchRequestV2 {
            principal: principal(),
            command_key: key,
            canonical_intent: intent,
            scope_id: self.binding.scope_id().as_str(),
            pod_id: self.binding.pod_id().as_str(),
            proposal: Some(BoundRootLaunchProposalV2 {
                session: &self.session,
                run: &self.run,
                binding: self.planned.as_ref().expect("new V2 proposal is planned"),
                effective_spec: &self.effective,
                descriptor: &self.descriptor,
                expected_owner_epoch: 1,
                expected_authority_revision: 0,
            }),
        }
    }
}

fn lookup(key: &str, intent: &[u8]) -> LaunchLookupRequest {
    LaunchLookupRequest {
        principal: principal(),
        namespace: "podbay.launch".into(),
        command_key: key.into(),
        scope_id: "scope.launch".into(),
        target_id: "pod.launch".into(),
        canonical_intent: intent.to_vec(),
    }
}

fn lookup_by_key(key: &str, intent: &[u8]) -> LaunchKeyLookupRequest {
    LaunchKeyLookupRequest {
        principal: principal(),
        command_key: key.into(),
        scope_id: "scope.launch".into(),
        canonical_intent: intent.to_vec(),
    }
}

#[test]
fn codex_v2_root_coordinator_and_root_worker_commit_with_exact_snapshot_and_duplicate() {
    // Both variants create a new Session and its first root Run. The Worker
    // case does not model a delegated child of an existing parent Run.
    for (role, work) in [
        (Role::Coordinator, WorkKind::Service),
        (Role::Worker, WorkKind::Task),
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        store.advance_owner_epoch(0, 1).unwrap();
        let proposal = ProposalFixture::new(role, work);
        let record = match store
            .admit_bound_root_launch_v2(proposal.request("key.codex.v2", b"intent.codex.v2"))
            .unwrap()
        {
            BoundLaunchAdmission::Committed(record) => record,
            other => panic!("expected V2 commit, got {other:?}"),
        };
        assert_eq!(record.format, BoundLaunchFormat::CodexV2);
        assert_eq!(record.resources.len(), 1);
        assert_eq!(record.resources[0].kind, "structured_provider");
        assert_eq!(record.effective_spec, proposal.effective.canonical_bytes());
        assert_eq!(
            record.descriptor,
            proposal.descriptor.encode_json().unwrap()
        );
        let snapshot = store
            .current_bound_pod_snapshot("scope.launch", "pod.launch")
            .unwrap();
        assert_eq!(snapshot.launch(), &record);
        assert_eq!(snapshot.resources().len(), 1);
        assert_eq!(
            snapshot.resources()[0].kind(),
            ResourceKind::StructuredProvider
        );
        assert_eq!(
            store
                .lookup_bound_launch(&lookup("key.codex.v2", b"intent.codex.v2"))
                .unwrap(),
            Some(record.clone())
        );
        assert_eq!(
            store
                .lookup_bound_launch_by_key(&lookup_by_key("key.codex.v2", b"intent.codex.v2"))
                .unwrap(),
            Some(record.clone())
        );
        assert_eq!(
            store
                .lookup_bound_launch_by_key(&lookup_by_key("key.new", b"intent.new"))
                .unwrap(),
            None
        );
        assert!(matches!(
            store.lookup_bound_launch_by_key(&lookup_by_key("key.codex.v2", b"intent.changed")),
            Err(StoreError::Conflict(_))
        ));
        let mut foreign_scope = lookup_by_key("key.codex.v2", b"intent.codex.v2");
        foreign_scope.scope_id = "scope.other".into();
        assert!(matches!(
            store.lookup_bound_launch_by_key(&foreign_scope),
            Err(StoreError::NotFound)
        ));
        let mut foreign_actor = lookup_by_key("key.codex.v2", b"intent.codex.v2");
        foreign_actor.principal =
            VerifiedPrincipal::from_authenticated_boundary("principal.other").unwrap();
        assert_eq!(
            store.lookup_bound_launch_by_key(&foreign_actor).unwrap(),
            None
        );
        assert_eq!(
            store
                .admit_bound_root_launch_v2(BoundRootLaunchRequestV2 {
                    principal: principal(),
                    command_key: "key.codex.v2",
                    canonical_intent: b"intent.codex.v2",
                    scope_id: "scope.launch",
                    pod_id: "pod.launch",
                    proposal: None,
                })
                .unwrap(),
            BoundLaunchAdmission::Duplicate(record.clone())
        );
        let connection = rusqlite::Connection::open(&fixture.database).unwrap();
        let slots: i64 = connection
            .query_row("SELECT COUNT(*) FROM launch_slots", [], |row| row.get(0))
            .unwrap();
        assert_eq!(slots, 1);
    }
}

#[test]
fn changed_key_intent_and_v1_v2_cross_format_replay_refuse() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    store.advance_owner_epoch(0, 1).unwrap();
    let proposal = ProposalFixture::new(Role::Worker, WorkKind::Task);
    store
        .admit_bound_root_launch_v2(proposal.request("key.codex.v2", b"intent.codex.v2"))
        .unwrap();
    assert!(matches!(
        store.admit_bound_root_launch_v2(BoundRootLaunchRequestV2 {
            principal: principal(),
            command_key: "key.codex.v2",
            canonical_intent: b"intent.changed",
            scope_id: "scope.launch",
            pod_id: "pod.launch",
            proposal: None,
        }),
        Err(StoreError::Conflict(_))
    ));
    assert!(matches!(
        store.admit_bound_launch(BoundLaunchRequest {
            principal: principal(),
            command_key: "key.codex.v2",
            canonical_intent: b"intent.codex.v2",
            scope_id: "scope.launch",
            pod_id: "pod.launch",
            proposal: None,
        }),
        Err(StoreError::Conflict(
            "command key changed bound launch format"
        ))
    ));

    let fixture = Fixture::new();
    let mut store = fixture.open();
    store.advance_owner_epoch(0, 1).unwrap();
    let proposal = ProposalFixture::legacy(Role::Coordinator, WorkKind::Service);
    let base = proposal.effective.base();
    let legacy = ImmutableLaunchDescriptor::from_binding(
        &proposal.binding,
        reviewed_policy(&proposal.binding, base.digest()),
    )
    .unwrap();
    store
        .admit_bound_launch(BoundLaunchRequest {
            principal: principal(),
            command_key: "key.legacy.v1",
            canonical_intent: b"intent.legacy.v1",
            scope_id: "scope.launch",
            pod_id: "pod.launch",
            proposal: Some(BoundLaunchProposal {
                session: &proposal.session,
                run: &proposal.run,
                binding: &proposal.binding,
                effective_spec: base.canonical_bytes(),
                descriptor: &legacy,
                expected_owner_epoch: 1,
                expected_authority_revision: 0,
            }),
        })
        .unwrap();
    assert!(matches!(
        store.admit_bound_root_launch_v2(BoundRootLaunchRequestV2 {
            principal: principal(),
            command_key: "key.legacy.v1",
            canonical_intent: b"intent.legacy.v1",
            scope_id: "scope.launch",
            pod_id: "pod.launch",
            proposal: None,
        }),
        Err(StoreError::Conflict(
            "command key changed bound launch format"
        ))
    ));
    assert_eq!(
        store
            .current_bound_pod_snapshot("scope.launch", "pod.launch")
            .unwrap()
            .launch()
            .format,
        BoundLaunchFormat::V1
    );
}

#[test]
fn changed_v2_effective_digest_or_version_pair_refuses_without_new_slot() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    store.advance_owner_epoch(0, 1).unwrap();
    let mut proposal = ProposalFixture::new(Role::Coordinator, WorkKind::Service);
    proposal.descriptor = ImmutableLaunchDescriptorV2::from_planned_root(
        proposal.planned.as_ref().unwrap(),
        reviewed_policy(&proposal.binding, &"a".repeat(64)),
        codex_policy(),
    )
    .unwrap();
    assert!(matches!(
        store.admit_bound_root_launch_v2(proposal.request("key.bad.v2", b"intent.bad.v2")),
        Err(StoreError::Conflict(
            "V2 effective launch differs from descriptor"
        ))
    ));
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let slots: i64 = connection
        .query_row("SELECT COUNT(*) FROM launch_slots", [], |row| row.get(0))
        .unwrap();
    assert_eq!(slots, 0);
    drop(connection);

    let mut wrong_binding = ProposalFixture::new(Role::Coordinator, WorkKind::Service);
    wrong_binding.descriptor = ProposalFixture::new(Role::Worker, WorkKind::Task).descriptor;
    assert!(matches!(
        store.admit_bound_root_launch_v2(
            wrong_binding.request("key.wrong.binding", b"intent.wrong.binding")
        ),
        Err(StoreError::Conflict(
            "V2 descriptor differs from launch binding"
        ))
    ));
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let slots: i64 = connection
        .query_row("SELECT COUNT(*) FROM launch_slots", [], |row| row.get(0))
        .unwrap();
    assert_eq!(slots, 0);
    drop(connection);

    let proposal = ProposalFixture::new(Role::Coordinator, WorkKind::Service);
    store
        .admit_bound_root_launch_v2(proposal.request("key.good.v2", b"intent.good.v2"))
        .unwrap();
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute(
            "UPDATE launch_bindings SET descriptor_version='podbay.launch-descriptor/1'",
            [],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        store.lookup_bound_launch(&lookup("key.good.v2", b"intent.good.v2")),
        Err(StoreError::Conflict("bound launch version pair differs"))
    ));
    assert!(matches!(
        store.current_bound_pod_snapshot("scope.launch", "pod.launch"),
        Err(StoreError::Conflict("bound launch version pair differs"))
    ));
}

#[test]
fn caller_preadmitted_v2_run_cannot_create_a_command_or_launch_slot() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    store.advance_owner_epoch(0, 1).unwrap();
    let mut proposal = ProposalFixture::new(Role::Coordinator, WorkKind::Service);
    proposal
        .run
        .admit(
            proposal.run.revision(),
            &CommandId::try_from("command.forged.fixture").unwrap(),
            &Admitted,
        )
        .unwrap();
    assert!(matches!(
        store.admit_bound_root_launch_v2(proposal.request("key.forged.v2", b"intent.forged.v2")),
        Err(StoreError::Conflict("V2 root Run is not a queued plan"))
    ));
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    for table in [
        "commands",
        "runtime_sessions",
        "runtime_runs",
        "launch_slots",
        "outbox",
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table} persisted after forged preadmission");
    }
}

#[test]
fn planned_identity_cannot_enter_v1_admitted_binding_paths() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    store.advance_owner_epoch(0, 1).unwrap();
    let mut proposal = ProposalFixture::new(Role::Coordinator, WorkKind::Service);
    assert!(proposal.binding.is_planned());
    assert!(
        ImmutableLaunchDescriptorV2::from_binding(
            &proposal.binding,
            reviewed_policy(&proposal.binding, proposal.effective.digest()),
            codex_policy(),
        )
        .is_err()
    );
    proposal
        .run
        .admit(
            proposal.run.revision(),
            &CommandId::try_from("command.v1.fake").unwrap(),
            &Admitted,
        )
        .unwrap();
    let attempt = Attempt::new(
        proposal.binding.attempt_id().clone(),
        proposal.run.id().clone(),
        1,
        Epoch::new(1).unwrap(),
    )
    .unwrap();
    proposal
        .run
        .start_attempt(proposal.run.revision(), &attempt)
        .unwrap();
    let legacy = ProposalFixture::legacy(Role::Coordinator, WorkKind::Service);
    let base = proposal.effective.base();
    let descriptor = ImmutableLaunchDescriptor::from_binding(
        &legacy.binding,
        reviewed_policy(&legacy.binding, base.digest()),
    )
    .unwrap();
    assert!(matches!(
        store.admit_bound_launch(BoundLaunchRequest {
            principal: principal(),
            command_key: "key.planned.v1",
            canonical_intent: b"intent.planned.v1",
            scope_id: "scope.launch",
            pod_id: "pod.launch",
            proposal: Some(BoundLaunchProposal {
                session: &proposal.session,
                run: &proposal.run,
                binding: &proposal.binding,
                effective_spec: base.canonical_bytes(),
                descriptor: &descriptor,
                expected_owner_epoch: 1,
                expected_authority_revision: 0,
            }),
        }),
        Err(StoreError::Conflict("launch binding is not admitted"))
    ));
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn failure_after_command_insert_rolls_back_every_v2_admission_row() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    store.advance_owner_epoch(0, 1).unwrap();
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_launch_slot BEFORE INSERT ON launch_slots
             BEGIN SELECT RAISE(ABORT, 'fixture after command insert'); END;",
        )
        .unwrap();
    let proposal = ProposalFixture::new(Role::Worker, WorkKind::Task);
    assert!(
        store
            .admit_bound_root_launch_v2(proposal.request("key.rollback.v2", b"intent.rollback.v2"))
            .is_err()
    );
    drop(store);
    let reopened = fixture.open();
    assert_eq!(reopened.owner_epoch().unwrap(), 1);
    for table in [
        "commands",
        "runtime_sessions",
        "runtime_runs",
        "authority_pods",
        "target_epochs",
        "launch_slots",
        "launch_bindings",
        "launch_resources",
        "events",
        "outbox",
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table} escaped the failed transaction");
    }
    drop(reopened);
    connection
        .execute_batch("DROP TRIGGER fail_launch_slot")
        .unwrap();
    let mut store = fixture.open();
    assert!(matches!(
        store
            .admit_bound_root_launch_v2(proposal.request("key.rollback.v2", b"intent.rollback.v2")),
        Ok(BoundLaunchAdmission::Committed(_))
    ));
}
