use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_core::{
    ActorId, Attempt, AttemptId, CommandAdmission, CommandId, Epoch, LaunchBinding,
    PlannedRootBinding, Pod, PodId, Resource, ResourceId, ResourceKind, Role, Run, RunCommandKind,
    RunId, ScopeId, Session, SessionId, WorkKind,
};
use podbay_store::{
    Admission, AuthorityActorRecord, AuthorityGrantRecord, AuthorityMutation,
    AuthorityRightRecord, BootstrapSendSelector,
    BoundLaunchAdmission, BoundLaunchFormat, BoundLaunchProposal, BoundLaunchRequest,
    BoundRootLaunchProposalV2, BoundRootLaunchRequestV2, CommandLookupSelector, EffectClaim,
    LaunchDispatchStage, LaunchKeyLookupRequest, LaunchLookupRequest, LaunchPortResult,
    LaterCodexSendSelector, NativeWriterRenewalRequest, NativeWriterTarget, PodBayStore, StoreError, TrustedBootstrapSendRequest,
    NativeEvidenceEvent, NativeEvidenceIdentity, NativeEvidencePage, NativeEvidenceSnapshot,
    TrustedNativeEvidenceAdmission,
    TrustedLaterCodexSendRequest,
    TrustedNativeWriterLeaseRequest, VerifiedPrincipal,
};
use sha2::{Digest, Sha256};
use podbay_wire::{
    CodexAppServerPolicyV2, CommandBody, CommandEnvelope, ContentBlock, DecimalString,
    EffectiveLaunchContract, EffectiveLaunchContractV2, Guard, ImmutableLaunchDescriptor,
    ImmutableLaunchDescriptorV2, ResourceDriver, ReviewedNativePolicy, ReviewedResource,
    SendPolicy, SessionSendBody, Target, TargetOs,
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
fn command_lookup_reads_bound_launch_outcome_in_one_snapshot() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    store.advance_owner_epoch(0, 1).unwrap();
    let proposal = ProposalFixture::new(Role::Coordinator, WorkKind::Service);
    let record = match store
        .admit_bound_root_launch_v2(proposal.request("key.readback.v2", b"intent.readback.v2"))
        .unwrap()
    {
        BoundLaunchAdmission::Committed(record) => record,
        other => panic!("expected V2 admission: {other:?}"),
    };
    let selector = CommandLookupSelector::Key {
        key: "key.readback.v2".into(),
    };
    let prepared = store
        .lookup_command("scope.launch", &principal(), &selector)
        .unwrap();
    assert_eq!(prepared.receipt, record.receipt);
    assert_eq!(
        prepared.launch_dispatch_status.unwrap().stage,
        LaunchDispatchStage::Prepared
    );
    let revision = store.authority_snapshot().unwrap().revision;
    assert_eq!(
        store
            .claim_effect(
                record.receipt.outbox_id,
                "scope.launch",
                "pod.launch",
                1,
                1,
                revision,
                "claim.readback.v2",
            )
            .unwrap(),
        EffectClaim::NewClaim
    );
    let claimed = store
        .lookup_command("scope.launch", &principal(), &selector)
        .unwrap();
    assert_eq!(
        claimed.launch_dispatch_status.unwrap().stage,
        LaunchDispatchStage::ClaimedUncertain
    );
    store
        .record_launch_port_result(
            record.receipt.outbox_id,
            "scope.launch",
            "pod.launch",
            1,
            "claim.readback.v2",
            LaunchPortResult::HostAccepted {
                receipt_ref: Some("host.receipt.readback".into()),
            },
        )
        .unwrap();
    let accepted = store
        .lookup_command("scope.launch", &principal(), &selector)
        .unwrap();
    assert_eq!(accepted.receipt, record.receipt);
    assert_eq!(
        accepted.launch_dispatch_status.unwrap().stage,
        LaunchDispatchStage::HostAccepted
    );
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
        let budget = store
            .inspect_run_child_budget(
                &ScopeId::try_from("scope.launch").unwrap(),
                &RunId::try_from("run.codex.fixture").unwrap(),
            )
            .unwrap();
        assert_eq!(budget.max_children(), 2);
        assert_eq!(budget.reserved_children(), 0);
        assert_eq!(budget.scope_id().as_str(), "scope.launch");
        assert_eq!(budget.run_id().as_str(), "run.codex.fixture");
        assert!(matches!(
            store.inspect_run_child_budget(
                &ScopeId::try_from("scope.other").unwrap(),
                &RunId::try_from("run.codex.fixture").unwrap(),
            ),
            Err(StoreError::NotFound)
        ));
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
fn v3_policy_row_commits_with_binding_and_survives_additive_global_revision() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    store.advance_owner_epoch(0, 1).unwrap();
    let policy_epoch = store.policy_fence_epoch().unwrap();
    let proposal = ProposalFixture::new(Role::Coordinator, WorkKind::Service);
    let record = match store
        .admit_bound_root_launch_v3(
            proposal.request("key.codex.v3", b"intent.codex.v3"),
            policy_epoch,
        )
        .unwrap()
    {
        BoundLaunchAdmission::Committed(record) => record,
        other => panic!("expected V3 policy-bound commit: {other:?}"),
    };
    assert_eq!(record.format, BoundLaunchFormat::CodexV3);
    let first = store.current_launch_policy_fence(&record).unwrap();
    assert!(matches!(
        store.lookup_bound_root_v2_by_command_id(
            &principal(),
            &ScopeId::try_from(record.scope_id.as_str()).unwrap(),
            &CommandId::try_from(record.receipt.command_id.as_str()).unwrap(),
        ),
        Err(StoreError::Conflict("indexed V2 root binding differs"))
    ));
    assert_eq!(
        store.lookup_bound_root_v3_by_command_id(
            &principal(),
            &ScopeId::try_from(record.scope_id.as_str()).unwrap(),
            &CommandId::try_from(record.receipt.command_id.as_str()).unwrap(),
        ).unwrap(),
        Some(record.clone())
    );
    assert_eq!(first.policy_fence_epoch, policy_epoch);
    assert_eq!(first.admission_authority_revision, 1);
    assert_eq!(first.current_authority_revision, 1);
    assert_eq!(
        store
            .current_bound_pod_snapshot(&record.scope_id, &record.pod_id)
            .unwrap()
            .current_policy_fence(),
        Some(&first)
    );
    let next_revision = store
        .apply_authority_mutation(
            1,
            1,
            AuthorityMutation::PutActor(writer_actor("actor.additive.policy")),
        )
        .unwrap();
    assert_eq!(next_revision, 2);
    assert_eq!(store.policy_fence_epoch().unwrap(), policy_epoch);
    let after = store.current_launch_policy_fence(&record).unwrap();
    assert_eq!(
        after.admission_authority_revision,
        first.admission_authority_revision
    );
    assert_eq!(after.current_authority_revision, 2);
    assert_eq!(
        store
            .current_bound_pod_snapshot(&record.scope_id, &record.pod_id)
            .unwrap()
            .current_policy_fence(),
        Some(&after)
    );
    let next_revision = store
        .apply_authority_mutation(
            1,
            next_revision,
            AuthorityMutation::PutGrant(AuthorityGrantRecord {
                grant_id: 1,
                scope_id: "scope.launch".into(),
                actor_id: "actor.additive.policy".into(),
                credential_generation: 1,
                mode: "controller".into(),
                remaining_delegation_depth: 0,
                rights: vec![AuthorityRightRecord {
                    operation: "launch_pod".into(),
                    target_kind: "scope".into(),
                    target_id: "scope.launch".into(),
                }],
            }),
        )
        .unwrap();
    assert_eq!(store.policy_fence_epoch().unwrap(), policy_epoch);
    assert_eq!(
        store.current_launch_policy_fence(&record)
            .unwrap()
            .current_authority_revision,
        next_revision
    );
    let mut duplicate = proposal.request("key.codex.v3", b"intent.codex.v3");
    duplicate.proposal = None;
    assert_eq!(
        store
            .admit_bound_root_launch_v3(duplicate, policy_epoch)
            .unwrap(),
        BoundLaunchAdmission::Duplicate(record.clone())
    );
    let mut wrong_version = proposal.request("key.codex.v3", b"intent.codex.v3");
    wrong_version.proposal = None;
    assert!(matches!(
        store.admit_bound_root_launch_v2(wrong_version),
        Err(StoreError::Conflict(
            "command key changed bound launch format"
        ))
    ));
    store
        .apply_authority_mutation(1, next_revision, AuthorityMutation::RevokeGrant(1))
        .unwrap();
    assert_eq!(store.policy_fence_epoch().unwrap(), policy_epoch + 1);
    assert!(matches!(
        store.current_launch_policy_fence(&record),
        Err(StoreError::StaleEpoch)
    ));
    assert!(matches!(
        store.current_bound_pod_snapshot(&record.scope_id, &record.pod_id),
        Err(StoreError::StaleEpoch)
    ));
}

#[test]
fn historical_v2_duplicate_cannot_acquire_v3_policy_row() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    store.advance_owner_epoch(0, 1).unwrap();
    let proposal = ProposalFixture::new(Role::Coordinator, WorkKind::Service);
    let record = match store
        .admit_bound_root_launch_v2(
            proposal.request("key.codex.v2.history", b"intent.codex.v2.history"),
        )
        .unwrap()
    {
        BoundLaunchAdmission::Committed(record) => record,
        other => panic!("expected V2 commit: {other:?}"),
    };
    assert!(matches!(
        store.current_launch_policy_fence(&record),
        Err(StoreError::NotFound)
    ));
    let mut duplicate = proposal.request("key.codex.v2.history", b"intent.codex.v2.history");
    duplicate.proposal = None;
    assert!(matches!(
        store.admit_bound_root_launch_v3(duplicate, store.policy_fence_epoch().unwrap(),),
        Err(StoreError::Conflict(
            "command key changed bound launch format"
        ))
    ));
}

#[test]
fn v3_policy_insert_fault_rolls_back_command_binding_event_and_outbox() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    store.advance_owner_epoch(0, 1).unwrap();
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER reject_v3_policy BEFORE INSERT ON launch_policy_fences
         BEGIN SELECT RAISE(ABORT,'fixture rejects V3 policy row'); END;",
        )
        .unwrap();
    drop(connection);
    let proposal = ProposalFixture::new(Role::Coordinator, WorkKind::Service);
    assert!(matches!(
        store.admit_bound_root_launch_v3(
            proposal.request("key.codex.v3.rollback", b"intent.codex.v3.rollback"),
            store.policy_fence_epoch().unwrap(),
        ),
        Err(StoreError::Storage(_))
    ));
    assert!(
        store
            .scope_snapshot("scope.launch")
            .unwrap()
            .receipts
            .is_empty()
    );
    assert_eq!(store.authority_snapshot().unwrap().revision, 0);
    assert_eq!(store.policy_fence_epoch().unwrap(), 2);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let bound: i64 = connection
        .query_row("SELECT COUNT(*) FROM launch_bindings", [], |row| row.get(0))
        .unwrap();
    let policy: i64 = connection
        .query_row("SELECT COUNT(*) FROM launch_policy_fences", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!((bound, policy), (0, 0));
}

#[test]
fn delegating_parent_preflight_requires_current_coordinator_and_rechecks_revision() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    store.advance_owner_epoch(0, 1).unwrap();
    let proposal = ProposalFixture::new(Role::Coordinator, WorkKind::Service);
    store
        .admit_bound_root_launch_v2(proposal.request("key.parent.preflight", b"intent.parent"))
        .unwrap();
    let scope = ScopeId::try_from("scope.launch").unwrap();
    let run = RunId::try_from("run.codex.fixture").unwrap();
    let pod = PodId::try_from("pod.launch").unwrap();
    let witness = store
        .preflight_delegating_parent(&scope, &run, &pod)
        .unwrap();
    assert_eq!(witness.parent_run_id(), &run);
    assert_eq!(
        witness.parent_session_id().as_str(),
        "session.codex.fixture"
    );
    assert_eq!(witness.current_pod().pod_id(), &pod);
    assert_eq!(
        (
            witness.budget().max_children(),
            witness.budget().reserved_children()
        ),
        (2, 0)
    );
    store.recheck_delegating_parent(&witness).unwrap();
    assert!(matches!(
        store.preflight_delegating_parent(&ScopeId::try_from("scope.other").unwrap(), &run, &pod,),
        Err(StoreError::WrongScope | StoreError::NotFound)
    ));
    assert!(matches!(
        store.preflight_delegating_parent(&scope, &RunId::try_from("run.other").unwrap(), &pod,),
        Err(StoreError::WrongScope)
    ));
    drop(store);
    let mut reopened = fixture.open();
    reopened.recheck_delegating_parent(&witness).unwrap();
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute(
            "UPDATE runtime_runs SET revision=revision+1 WHERE run_id=?1",
            [run.as_str()],
        )
        .unwrap();
    assert!(matches!(
        reopened.recheck_delegating_parent(&witness),
        Err(StoreError::StaleEpoch)
    ));
}

#[test]
fn delegating_parent_preflight_refuses_root_worker_and_zero_lifetime_budget() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    store.advance_owner_epoch(0, 1).unwrap();
    let worker = ProposalFixture::new(Role::Worker, WorkKind::Task);
    store
        .admit_bound_root_launch_v2(worker.request("key.parent.worker", b"intent.worker"))
        .unwrap();
    let scope = ScopeId::try_from("scope.launch").unwrap();
    let run = RunId::try_from("run.codex.fixture").unwrap();
    let pod = PodId::try_from("pod.launch").unwrap();
    assert!(matches!(
        store.preflight_delegating_parent(&scope, &run, &pod),
        Err(StoreError::Conflict(_))
    ));

    let fixture = Fixture::new();
    let mut store = fixture.open();
    store.advance_owner_epoch(0, 1).unwrap();
    let coordinator = ProposalFixture::new(Role::Coordinator, WorkKind::Service);
    store
        .admit_bound_root_launch_v2(coordinator.request("key.parent.zero", b"intent.zero"))
        .unwrap();
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute(
            "UPDATE run_child_budgets SET max_children=0 WHERE run_id=?1",
            [run.as_str()],
        )
        .unwrap();
    assert!(matches!(
        store.preflight_delegating_parent(&scope, &run, &pod),
        Err(StoreError::Conflict("parent child budget is exhausted"))
    ));
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
    let budget = store
        .inspect_run_child_budget(
            &ScopeId::try_from("scope.launch").unwrap(),
            &RunId::try_from("run.codex.fixture").unwrap(),
        )
        .unwrap();
    assert_eq!((budget.max_children(), budget.reserved_children()), (0, 0));
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
        "run_child_budgets",
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
    assert!(matches!(
        reopened.inspect_run_child_budget(
            &ScopeId::try_from("scope.launch").unwrap(),
            &RunId::try_from("run.codex.fixture").unwrap(),
        ),
        Err(StoreError::NotFound)
    ));
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


#[test]
fn v16_run_budget_schema_is_verified_exactly() {
    let fixture = Fixture::new();
    drop(fixture.open());
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "DROP TABLE run_child_budgets;
             CREATE TABLE run_child_budgets (
               run_id TEXT PRIMARY KEY,
               max_children INTEGER,
               reserved_children INTEGER
             ) STRICT;",
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        PodBayStore::open_existing_read_only(&fixture.database),
        Err(StoreError::Conflict("v16 run budget schema differs"))
    ));
    assert!(matches!(
        PodBayStore::open(&fixture.database),
        Err(StoreError::Conflict("v16 run budget schema differs"))
    ));
}

#[test]
fn missing_budget_row_refuses_exact_run_inspection() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    store.advance_owner_epoch(0, 1).unwrap();
    let proposal = ProposalFixture::new(Role::Coordinator, WorkKind::Service);
    store
        .admit_bound_root_launch_v2(
            proposal.request("key.budget.missing", b"intent.budget.missing"),
        )
        .unwrap();
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute(
            "DELETE FROM run_child_budgets WHERE run_id='run.codex.fixture'",
            [],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        store.inspect_run_child_budget(
            &ScopeId::try_from("scope.launch").unwrap(),
            &RunId::try_from("run.codex.fixture").unwrap(),
        ),
        Err(StoreError::Conflict("Run child budget is missing"))
    ));
}

fn writer_actor(id: &str) -> AuthorityActorRecord {
    AuthorityActorRecord {
        scope_id: "scope.launch".into(),
        actor_id: id.into(),
        role: "coordinator".into(),
        origin: "owner_cli".into(),
        parent_actor_id: None,
        pod_id: None,
        pod_incarnation: None,
        credential_generation: 1,
        platform: "linux".into(),
        os_identity: "linux.uid.1000".into(),
        process_identity: "linux.pid.123".into(),
        start_identity: 456,
        containment_identity: "/user.slice/writer-fixture.scope".into(),
    }
}

fn admitted_writer_target(fixture: &Fixture) -> (PodBayStore, NativeWriterTarget, u64) {
    admitted_writer_target_for_format(fixture, false)
}

fn admitted_writer_target_for_format(
    fixture: &Fixture,
    v3: bool,
) -> (PodBayStore, NativeWriterTarget, u64) {
    let mut store = fixture.open();
    let replay = store.begin_authority_replay(0, 1).unwrap();
    let revision = store
        .apply_authority_mutation(
            1,
            replay.revision,
            AuthorityMutation::PutActor(writer_actor("actor.codex.fixture")),
        )
        .unwrap();
    let revision = store
        .apply_authority_mutation(
            1,
            revision,
            AuthorityMutation::PutActor(writer_actor("actor.codex.other")),
        )
        .unwrap();
    let proposal = ProposalFixture::new(Role::Coordinator, WorkKind::Service);
    let mut request = proposal.request("key.writer.launch", b"intent.writer.launch");
    request
        .proposal
        .as_mut()
        .unwrap()
        .expected_authority_revision = revision;
    let admission = if v3 {
        let epoch = store.policy_fence_epoch().unwrap();
        store.admit_bound_root_launch_v3(request, epoch).unwrap()
    } else {
        store.admit_bound_root_launch_v2(request).unwrap()
    };
    assert!(matches!(admission, BoundLaunchAdmission::Committed(_)));
    let current = store
        .current_bound_pod_snapshot("scope.launch", "pod.launch")
        .unwrap();
    let resource = &current.resources()[0];
    let target = NativeWriterTarget {
        store_lineage: current.store_lineage().clone(),
        scope_id: current.scope_id().clone(),
        session_id: SessionId::try_from(current.launch().session_id.as_str()).unwrap(),
        run_id: RunId::try_from(current.launch().run_id.as_str()).unwrap(),
        attempt_id: current.attempt_id().clone(),
        pod_id: current.pod_id().clone(),
        pod_incarnation: current.pod_incarnation().get(),
        resource_id: resource.id().clone(),
        resource_epoch: resource.epoch().get(),
        resource_input_epoch: resource.input_epoch().get(),
    };
    let manager_credential = store.current_manager_credential_claim(1).unwrap();
    (store, target, manager_credential.credential_epoch())
}

fn writer_request(
    store: &mut PodBayStore,
    target: NativeWriterTarget,
    manager_credential_epoch: u64,
) -> TrustedNativeWriterLeaseRequest {
    TrustedNativeWriterLeaseRequest {
        target,
        holder_actor_id: ActorId::try_from("actor.codex.fixture").unwrap(),
        holder_credential_generation: 1,
        expected_owner_epoch: 1,
        expected_manager_credential_epoch: manager_credential_epoch,
        expected_authority_revision: store.authority_snapshot().unwrap().revision,
        expected_writer_epoch: None,
        ttl_seconds: 60,
    }
}

#[test]
fn v3_writer_lease_survives_additive_revision_and_revocation_fences_it() {
    let fixture = Fixture::new();
    let (mut store, target, manager_credential) =
        admitted_writer_target_for_format(&fixture, true);
    let request = writer_request(&mut store, target.clone(), manager_credential);
    let lease = store.acquire_native_writer_lease_from_trusted_host(&request).unwrap();
    let policy_epoch = store.policy_fence_epoch().unwrap();
    let current_revision = store.authority_snapshot().unwrap().revision;
    let added_revision = store.apply_authority_mutation(
        1,
        current_revision,
        AuthorityMutation::PutGrant(AuthorityGrantRecord {
            grant_id: 17,
            scope_id: "scope.launch".into(),
            actor_id: "actor.codex.other".into(),
            credential_generation: 1,
            mode: "controller".into(),
            remaining_delegation_depth: 0,
            rights: vec![AuthorityRightRecord {
                operation: "launch_pod".into(),
                target_kind: "scope".into(),
                target_id: "scope.launch".into(),
            }],
        }),
    ).unwrap();
    assert!(added_revision > lease.authority_revision());
    assert_eq!(store.policy_fence_epoch().unwrap(), policy_epoch);
    assert_eq!(store.inspect_native_writer_lease(&target).unwrap(), lease);
    assert_eq!(
        store.current_native_writer_target_for_session(&target.scope_id, &target.session_id)
            .unwrap().0,
        target
    );
    store.apply_authority_mutation(1, added_revision, AuthorityMutation::RevokeGrant(17))
        .unwrap();
    assert_eq!(store.policy_fence_epoch().unwrap(), policy_epoch + 1);
    assert!(matches!(store.inspect_native_writer_lease(&target), Err(StoreError::StaleEpoch)));
}

#[test]
fn v17_writer_lease_acquire_is_exclusive_and_takeover_fences_old_epoch() {
    let fixture = Fixture::new();
    let (mut store, target, manager_credential) = admitted_writer_target(&fixture);
    assert!(matches!(
        store.inspect_native_writer_lease(&target),
        Err(StoreError::NotFound)
    ));
    let request = writer_request(&mut store, target.clone(), manager_credential);
    let first = store
        .acquire_native_writer_lease_from_trusted_host(&request)
        .unwrap();
    assert_eq!(first.writer_epoch(), 1);
    assert!(first.expires_at_unix_seconds() > 0);
    assert_eq!(store.inspect_native_writer_lease(&target).unwrap(), first);
    let mut competing = request.clone();
    competing.holder_actor_id = ActorId::try_from("actor.codex.other").unwrap();
    assert!(matches!(
        store.acquire_native_writer_lease_from_trusted_host(&competing),
        Err(StoreError::Conflict("native writer already held"))
    ));
    competing.expected_writer_epoch = Some(1);
    let second = store
        .acquire_native_writer_lease_from_trusted_host(&competing)
        .unwrap();
    assert_eq!(second.writer_epoch(), 2);
    assert_eq!(second.holder_actor_id().as_str(), "actor.codex.other");
    assert_eq!(store.inspect_native_writer_lease(&target).unwrap(), second);
    assert!(matches!(
        store.acquire_native_writer_lease_from_trusted_host(&competing),
        Err(StoreError::StaleEpoch)
    ));
    let mut foreign = target.clone();
    foreign.scope_id = ScopeId::try_from("scope.other").unwrap();
    assert!(matches!(
        store.inspect_native_writer_lease(&foreign),
        Err(StoreError::WrongScope)
    ));
}

#[test]
fn current_writer_renewal_extends_once_without_changing_epoch() {
    let fixture = Fixture::new();
    let (mut store, target, manager_credential) = admitted_writer_target(&fixture);
    let request = writer_request(&mut store, target.clone(), manager_credential);
    let first = store.acquire_native_writer_lease_from_trusted_host(&request).unwrap();
    let renewed = store.renew_native_writer_lease_from_trusted_host(&first, 120).unwrap();
    assert_eq!(renewed.writer_epoch(), first.writer_epoch());
    assert!(renewed.expires_at_unix_seconds() > first.expires_at_unix_seconds());
    assert_eq!(store.inspect_native_writer_lease(&target).unwrap(), renewed);
    assert!(matches!(
        store.renew_native_writer_lease_from_trusted_host(&first, 120),
        Err(StoreError::StaleEpoch)
    ));
    assert!(matches!(
        store.renew_native_writer_lease_from_trusted_host(&renewed, 0),
        Err(StoreError::InvalidInput(_))
    ));
}

#[test]
fn keyed_writer_renewal_commits_once_and_replays_exact_expiry() {
    let fixture = Fixture::new();
    let (mut store, target, manager_credential) = admitted_writer_target(&fixture);
    let acquire = writer_request(&mut store, target.clone(), manager_credential);
    let first = store.acquire_native_writer_lease_from_trusted_host(&acquire).unwrap();
    let principal = VerifiedPrincipal::from_authenticated_boundary(
        first.holder_actor_id().as_str()).unwrap();
    let request = NativeWriterRenewalRequest {
        principal: principal.clone(),
        command_key: "key.writer.renew.one".into(),
        canonical_request: b"writer-renew-digest-one".to_vec(),
        target: target.clone(),
        holder_actor_id: first.holder_actor_id().clone(),
        holder_credential_generation: first.holder_credential_generation(),
        owner_epoch: first.owner_epoch(),
        manager_credential_epoch: first.manager_credential_epoch(),
        authority_revision: first.authority_revision(),
        expected_writer_epoch: first.writer_epoch(),
        expected_expiry: first.expires_at_unix_seconds(),
        ttl_seconds: 120,
    };
    let committed = store.renew_native_writer_lease_with_receipt(&request).unwrap();
    assert!(!committed.duplicate);
    assert!(committed.expires_at_unix_seconds > request.expected_expiry);
    let mut rival = request.clone();
    rival.command_key = "key.writer.renew.rival".into();
    assert!(matches!(store.renew_native_writer_lease_with_receipt(&rival),
        Err(StoreError::StaleEpoch)));
    let replay = store.renew_native_writer_lease_with_receipt(&request).unwrap();
    assert!(replay.duplicate);
    assert_eq!(replay.command, committed.command);
    assert_eq!(replay.expires_at_unix_seconds, committed.expires_at_unix_seconds);
    rusqlite::Connection::open(&fixture.database).unwrap().execute(
        "UPDATE native_writer_leases SET expires_at_unix_seconds=1 WHERE resource_id=?1",
        [target.resource_id.as_str()],
    ).unwrap();
    let late_replay = store.renew_native_writer_lease_with_receipt(&request).unwrap();
    assert_eq!(late_replay.command, committed.command);
    assert_eq!(late_replay.expires_at_unix_seconds, committed.expires_at_unix_seconds);
    let mut new_key = request.clone();
    new_key.command_key = "key.writer.renew.two".into();
    assert!(matches!(store.renew_native_writer_lease_with_receipt(&new_key),
        Err(StoreError::StaleEpoch)));
    let inspection = store.lookup_command(target.scope_id.as_str(), &principal,
        &CommandLookupSelector::Key { key: request.command_key.clone() }).unwrap();
    assert_eq!(inspection.receipt, committed.command);
    assert_eq!(inspection.effect_state, podbay_store::EffectState::Observed);
    assert_eq!(inspection.observed_stage, Some(podbay_store::ObservedStage::LeaseRenewed));
    assert!(!store.pending_effects(target.scope_id.as_str(), 0, 10).unwrap()
        .iter().any(|effect| effect.outbox_id == committed.command.outbox_id));
    assert!(store.claim_effect(committed.command.outbox_id,
        target.scope_id.as_str(), target.session_id.as_str(),
        request.owner_epoch, target.resource_epoch, request.authority_revision,
        "claim.writer.renew").is_err());
    let mut changed = request.clone();
    changed.canonical_request = b"writer-renew-digest-two".to_vec();
    assert!(matches!(store.renew_native_writer_lease_with_receipt(&changed),
        Err(StoreError::Conflict(_))));
}

#[test]
fn expired_writer_cannot_be_renewed() {
    let fixture = Fixture::new();
    let (mut store, target, manager_credential) = admitted_writer_target(&fixture);
    let request = writer_request(&mut store, target, manager_credential);
    let first = store.acquire_native_writer_lease_from_trusted_host(&request).unwrap();
    rusqlite::Connection::open(&fixture.database).unwrap().execute(
        "UPDATE native_writer_leases SET expires_at_unix_seconds=1",
        [],
    ).unwrap();
    assert!(matches!(
        store.renew_native_writer_lease_from_trusted_host(&first, 120),
        Err(StoreError::StaleEpoch)
    ));
}

#[test]
fn v17_writer_lease_rechecks_target_manager_actor_and_expiry() {
    let fixture = Fixture::new();
    let (mut store, target, manager_credential) = admitted_writer_target(&fixture);
    let request = writer_request(&mut store, target.clone(), manager_credential);
    for ttl in [0, 3_601] {
        let mut invalid = request.clone();
        invalid.ttl_seconds = ttl;
        assert!(matches!(
            store.acquire_native_writer_lease_from_trusted_host(&invalid),
            Err(StoreError::InvalidInput("native writer lease bounds"))
        ));
    }
    let mut stale = request.clone();
    stale.expected_authority_revision -= 1;
    assert!(matches!(
        store.acquire_native_writer_lease_from_trusted_host(&stale),
        Err(StoreError::StaleEpoch)
    ));
    stale = request.clone();
    stale.expected_manager_credential_epoch += 1;
    assert!(matches!(
        store.acquire_native_writer_lease_from_trusted_host(&stale),
        Err(StoreError::StaleEpoch)
    ));
    stale = request.clone();
    stale.holder_credential_generation += 1;
    assert!(matches!(
        store.acquire_native_writer_lease_from_trusted_host(&stale),
        Err(StoreError::StaleEpoch)
    ));
    stale = request.clone();
    stale.target.resource_epoch += 1;
    assert!(matches!(
        store.acquire_native_writer_lease_from_trusted_host(&stale),
        Err(StoreError::NotFound)
    ));
    let first = store
        .acquire_native_writer_lease_from_trusted_host(&request)
        .unwrap();
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute(
            "UPDATE native_writer_leases SET expires_at_unix_seconds=1",
            [],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        store.inspect_native_writer_lease(&target),
        Err(StoreError::StaleEpoch)
    ));
    let mut takeover = request;
    takeover.expected_writer_epoch = Some(first.writer_epoch());
    assert_eq!(
        store
            .acquire_native_writer_lease_from_trusted_host(&takeover)
            .unwrap()
            .writer_epoch(),
        2
    );
}

#[test]
fn v17_writer_lease_concurrent_initial_acquire_has_one_holder() {
    let fixture = Fixture::new();
    let (mut store, target, manager_credential) = admitted_writer_target(&fixture);
    let request = writer_request(&mut store, target, manager_credential);
    drop(store);
    let barrier = Arc::new(Barrier::new(3));
    let workers = (0..2)
        .map(|_| {
            let path = fixture.database.clone();
            let request = request.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                let mut connection = PodBayStore::open(path).unwrap();
                barrier.wait();
                connection.acquire_native_writer_lease_from_trusted_host(&request)
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                Err(StoreError::Conflict("native writer already held"))
            ))
            .count(),
        1
    );
}

#[test]
fn v17_writer_lease_schema_is_verified_exactly() {
    let fixture = Fixture::new();
    drop(fixture.open());
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "DROP INDEX codex_later_turns_session_v22;
             DROP TABLE codex_later_turns;
             DROP TABLE codex_bootstrap_sends;
             DROP TABLE native_writer_leases;
             CREATE TABLE native_writer_leases(resource_id TEXT PRIMARY KEY) STRICT;",
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        PodBayStore::open_existing_read_only(&fixture.database),
        Err(StoreError::Conflict("v17 writer lease schema differs"))
    ));
    assert!(matches!(
        PodBayStore::open(&fixture.database),
        Err(StoreError::Conflict("v17 writer lease schema differs"))
    ));
}


fn bootstrap_ready(fixture: &Fixture) -> (PodBayStore, NativeWriterTarget, u64, u64) {
    bootstrap_ready_for_format(fixture, false)
}

fn bootstrap_ready_for_format(
    fixture: &Fixture,
    v3: bool,
) -> (PodBayStore, NativeWriterTarget, u64, u64) {
    let (mut store, target, manager_credential) = admitted_writer_target_for_format(fixture, v3);
    let launch = store
        .current_bound_pod_snapshot("scope.launch", "pod.launch")
        .unwrap();
    let launch_receipt = launch.launch().receipt.clone();
    let revision = launch.authority_revision();
    assert_eq!(
        store
            .claim_effect(
                launch_receipt.outbox_id,
                "scope.launch",
                "pod.launch",
                1,
                1,
                revision,
                &format!("claim.{}", launch_receipt.command_id),
            )
            .unwrap(),
        EffectClaim::NewClaim
    );
    store
        .record_launch_port_result(
            launch_receipt.outbox_id,
            "scope.launch",
            "pod.launch",
            1,
            &format!("claim.{}", launch_receipt.command_id),
            LaunchPortResult::HostAccepted {
                receipt_ref: Some("receipt.pod.running".into()),
            },
        )
        .unwrap();
    let lease_request = writer_request(&mut store, target.clone(), manager_credential);
    let lease = store
        .acquire_native_writer_lease_from_trusted_host(&lease_request)
        .unwrap();
    (store, target, manager_credential, lease.writer_epoch())
}

fn decimal(value: u64) -> DecimalString {
    DecimalString::new(value)
}

fn bootstrap_envelope(
    key: &str,
    request_id: &str,
    text: &str,
    session_revision: u64,
    writer_epoch: u64,
) -> CommandEnvelope {
    CommandEnvelope::new(
        request_id,
        key,
        Target::Session {
            session_id: "session.codex.fixture".into(),
        },
        Some(Guard {
            manager_epoch: Some(decimal(1)),
            pod_epoch: Some(decimal(1)),
            resource_epoch: Some(decimal(1)),
            writer_epoch: Some(decimal(writer_epoch)),
            lease_epoch: None,
            target_revision: Some(decimal(session_revision)),
        }),
        None,
        CommandBody::SessionSend(SessionSendBody {
            content: vec![ContentBlock::Text { text: text.into() }],
            policy: SendPolicy::WhenIdle,
        }),
    )
    .unwrap()
}

fn bootstrap_request<'a>(
    store: &mut PodBayStore,
    target: NativeWriterTarget,
    manager_credential: u64,
    envelope: &'a CommandEnvelope,
) -> TrustedBootstrapSendRequest<'a> {
    TrustedBootstrapSendRequest {
        principal: VerifiedPrincipal::from_authenticated_boundary("actor.codex.fixture").unwrap(),
        scope_id: target.scope_id.clone(),
        envelope,
        native_target: target,
        holder_actor_id: ActorId::try_from("actor.codex.fixture").unwrap(),
        holder_credential_generation: 1,
        expected_owner_epoch: 1,
        expected_manager_credential_epoch: manager_credential,
        expected_authority_revision: store.authority_snapshot().unwrap().revision,
    }
}

#[test]
fn v3_claimed_send_keeps_current_policy_after_additive_revision_and_refuses_revocation() {
    let fixture = Fixture::new();
    let (mut store, target, manager_credential, writer_epoch) =
        bootstrap_ready_for_format(&fixture, true);
    let lease = store.inspect_native_writer_lease(&target).unwrap();
    let policy_epoch = store.policy_fence_epoch().unwrap();
    let current_revision = store.authority_snapshot().unwrap().revision;
    let next_revision = store.apply_authority_mutation(
        1,
        current_revision,
        AuthorityMutation::PutGrant(AuthorityGrantRecord {
            grant_id: 18,
            scope_id: "scope.launch".into(),
            actor_id: "actor.codex.other".into(),
            credential_generation: 1,
            mode: "controller".into(),
            remaining_delegation_depth: 0,
            rights: vec![AuthorityRightRecord {
                operation: "launch_pod".into(),
                target_kind: "scope".into(),
                target_id: "scope.launch".into(),
            }],
        }),
    ).unwrap();
    assert!(next_revision > lease.authority_revision());
    assert_eq!(store.policy_fence_epoch().unwrap(), policy_epoch);
    assert_eq!(store.inspect_native_writer_lease(&target).unwrap(), lease);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let session_revision: i64 = connection.query_row(
        "SELECT revision FROM runtime_sessions WHERE session_id='session.codex.fixture'",
        [], |row| row.get(0),
    ).unwrap();
    drop(connection);
    let envelope = bootstrap_envelope(
        "key.bootstrap.v3.additive", "request.bootstrap.v3.additive", "First turn",
        session_revision as u64, writer_epoch,
    );
    let mut stale = bootstrap_request(&mut store, target.clone(), manager_credential, &envelope);
    stale.expected_authority_revision = lease.authority_revision();
    assert!(matches!(store.admit_bootstrap_send(&stale), Err(StoreError::StaleEpoch)));
    let fresh = bootstrap_request(&mut store, target.clone(), manager_credential, &envelope);
    let receipt = match store.admit_bootstrap_send(&fresh).unwrap() {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected V3 bootstrap command: {other:?}"),
    };
    let selector = BootstrapSendSelector {
        scope_id: target.scope_id.clone(),
        command_id: CommandId::try_from(receipt.command_id.as_str()).unwrap(),
        native_target: target.clone(),
    };
    assert_eq!(store.claim_bootstrap_send(&selector).unwrap(), EffectClaim::NewClaim);
    let proof = store.inspect_claimed_bootstrap_send(&selector).unwrap();
    assert_eq!(proof.authority_revision(), next_revision);
    store.apply_authority_mutation(1, next_revision, AuthorityMutation::RevokeGrant(18))
        .unwrap();
    assert_eq!(store.policy_fence_epoch().unwrap(), policy_epoch + 1);
    assert!(matches!(store.inspect_claimed_bootstrap_send(&selector), Err(StoreError::StaleEpoch)));
}

#[test]
fn v18_bootstrap_send_commits_once_claims_once_and_pod_reads_exact_proof() {
    let fixture = Fixture::new();
    let (mut store, target, manager_credential, writer_epoch) = bootstrap_ready(&fixture);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let revision: i64 = connection
        .query_row(
            "SELECT revision FROM runtime_sessions WHERE session_id='session.codex.fixture'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);
    let envelope = bootstrap_envelope(
        "key.bootstrap.one",
        "request.bootstrap.one",
        "First real turn",
        revision as u64,
        writer_epoch,
    );
    let request = bootstrap_request(&mut store, target.clone(), manager_credential, &envelope);
    let receipt = match store.admit_bootstrap_send(&request).unwrap() {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected committed bootstrap: {other:?}"),
    };
    let selector = BootstrapSendSelector {
        scope_id: target.scope_id.clone(),
        command_id: CommandId::try_from(receipt.command_id.as_str()).unwrap(),
        native_target: target.clone(),
    };
    let inspection = store
        .lookup_command(
            "scope.launch",
            &VerifiedPrincipal::from_authenticated_boundary("actor.codex.fixture").unwrap(),
            &CommandLookupSelector::Id {
                command_id: receipt.command_id.clone(),
            },
        )
        .unwrap();
    assert_eq!(inspection.receipt, receipt);
    assert_eq!(inspection.effect_state, podbay_store::EffectState::Prepared);
    let principal = VerifiedPrincipal::from_authenticated_boundary("actor.codex.fixture").unwrap();
    assert_eq!(
        store
            .claimed_bootstrap_selector_for_command(
                &principal,
                &target.scope_id,
                &selector.command_id,
            )
            .unwrap(),
        None,
    );
    assert!(matches!(
        store.inspect_claimed_bootstrap_send(&selector),
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(
        store.claim_bootstrap_send(&selector).unwrap(),
        EffectClaim::NewClaim
    );
    assert_eq!(
        store.claim_bootstrap_send(&selector).unwrap(),
        EffectClaim::ExistingUncertain
    );
    assert_eq!(
        store
            .claimed_bootstrap_selector_for_command(
                &principal,
                &target.scope_id,
                &selector.command_id,
            )
            .unwrap(),
        Some((selector.clone(), writer_epoch)),
    );
    let wrong_principal = VerifiedPrincipal::from_authenticated_boundary("actor.other").unwrap();
    assert_eq!(
        store
            .claimed_bootstrap_selector_for_command(
                &wrong_principal,
                &target.scope_id,
                &selector.command_id,
            )
            .unwrap(),
        None,
    );
    let mut pod_read = PodBayStore::open_existing_read_only(&fixture.database).unwrap();
    let proof = pod_read.inspect_claimed_bootstrap_send(&selector).unwrap();
    assert_eq!(proof.receipt(), &receipt);
    assert_eq!(proof.prompt_text(), "First real turn");
    assert_eq!(proof.native_target(), &target);
    assert_eq!(proof.writer_epoch(), writer_epoch);
    assert_eq!(proof.wire_payload_digest(), envelope.payload_digest);
    drop(pod_read);
    let retry = bootstrap_envelope(
        "key.bootstrap.one",
        "request.bootstrap.retry",
        "First real turn",
        revision as u64,
        writer_epoch,
    );
    let duplicate = bootstrap_request(&mut store, target.clone(), manager_credential, &retry);
    assert_eq!(
        store.admit_bootstrap_send(&duplicate).unwrap(),
        Admission::Duplicate(receipt.clone())
    );
    let changed = bootstrap_envelope(
        "key.bootstrap.one",
        "request.bootstrap.changed",
        "Changed turn",
        revision as u64,
        writer_epoch,
    );
    let changed_request =
        bootstrap_request(&mut store, target.clone(), manager_credential, &changed);
    assert!(matches!(
        store.admit_bootstrap_send(&changed_request),
        Err(StoreError::Conflict(_))
    ));
    let second_key = bootstrap_envelope(
        "key.bootstrap.two",
        "request.bootstrap.two",
        "Another turn",
        revision as u64,
        writer_epoch,
    );
    let second_request = bootstrap_request(&mut store, target, manager_credential, &second_key);
    assert!(matches!(
        store.admit_bootstrap_send(&second_request),
        Err(StoreError::Conflict("Session already has a bootstrap send"))
    ));
}

#[test]
fn v18_bootstrap_requires_host_accepted_launch_and_current_writer() {
    let fixture = Fixture::new();
    let (mut store, target, manager_credential) = admitted_writer_target(&fixture);
    let lease_request = writer_request(&mut store, target.clone(), manager_credential);
    store
        .acquire_native_writer_lease_from_trusted_host(&lease_request)
        .unwrap();
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let revision: i64 = connection
        .query_row(
            "SELECT revision FROM runtime_sessions WHERE session_id='session.codex.fixture'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);
    let envelope = bootstrap_envelope(
        "key.before.accepted",
        "request.before.accepted",
        "Prompt",
        revision as u64,
        1,
    );
    let request = bootstrap_request(&mut store, target.clone(), manager_credential, &envelope);
    assert!(matches!(
        store.admit_bootstrap_send(&request),
        Err(StoreError::Conflict("Codex V2 launch is not HostAccepted"))
    ));
    drop(store);
    let second_fixture = Fixture::new();
    let (mut store, target, manager_credential, _) = bootstrap_ready(&second_fixture);
    // A fresh key with a stale native writer epoch cannot be admitted.
    let mut takeover = writer_request(&mut store, target.clone(), manager_credential);
    takeover.expected_writer_epoch = Some(1);
    store
        .acquire_native_writer_lease_from_trusted_host(&takeover)
        .unwrap();
    let envelope = bootstrap_envelope(
        "key.stale.writer",
        "request.stale.writer",
        "Prompt",
        revision as u64,
        1,
    );
    let request = bootstrap_request(&mut store, target, manager_credential, &envelope);
    assert!(matches!(
        store.admit_bootstrap_send(&request),
        Err(StoreError::StaleEpoch)
    ));
}

#[test]
fn v18_bootstrap_rollback_and_prepared_reopen_are_truthful() {
    let fixture = Fixture::new();
    let (mut store, target, manager_credential, writer_epoch) = bootstrap_ready(&fixture);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let revision: i64 = connection
        .query_row(
            "SELECT revision FROM runtime_sessions WHERE session_id='session.codex.fixture'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_bootstrap_binding AFTER INSERT ON codex_bootstrap_sends
         BEGIN SELECT RAISE(ABORT,'injected bootstrap failure'); END;",
        )
        .unwrap();
    let envelope = bootstrap_envelope(
        "key.bootstrap.rollback",
        "request.rollback.one",
        "Prompt",
        revision as u64,
        writer_epoch,
    );
    let request = bootstrap_request(&mut store, target.clone(), manager_credential, &envelope);
    assert!(matches!(
        store.admit_bootstrap_send(&request),
        Err(StoreError::Storage(_))
    ));
    for table in ["codex_bootstrap_sends", "commands", "events", "outbox"] {
        let expected = if table == "codex_bootstrap_sends" {
            0
        } else {
            1
        };
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            count, expected,
            "{table} escaped failed bootstrap transaction"
        );
    }
    connection
        .execute_batch("DROP TRIGGER fail_bootstrap_binding")
        .unwrap();
    let receipt = match store.admit_bootstrap_send(&request).unwrap() {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected committed bootstrap: {other:?}"),
    };
    drop(connection);
    drop(store);
    let mut reopened = fixture.open();
    let retry = bootstrap_envelope(
        "key.bootstrap.rollback",
        "request.rollback.retry",
        "Prompt",
        revision as u64,
        writer_epoch,
    );
    let duplicate = bootstrap_request(&mut reopened, target.clone(), manager_credential, &retry);
    assert_eq!(
        reopened.admit_bootstrap_send(&duplicate).unwrap(),
        Admission::Duplicate(receipt.clone())
    );
    let selector = BootstrapSendSelector {
        scope_id: target.scope_id.clone(),
        command_id: CommandId::try_from(receipt.command_id.as_str()).unwrap(),
        native_target: target,
    };
    assert_eq!(
        reopened.claim_bootstrap_send(&selector).unwrap(),
        EffectClaim::NewClaim
    );
    drop(reopened);
    let mut pod_read = PodBayStore::open_existing_read_only(&fixture.database).unwrap();
    assert_eq!(
        pod_read
            .inspect_claimed_bootstrap_send(&selector)
            .unwrap()
            .prompt_text(),
        "Prompt"
    );
}


#[test]
fn v19_with_historical_v2_refuses_open_without_changing_database() {
    let fixture = Fixture::new();
    let (mut store, target, manager_credential, writer_epoch) = bootstrap_ready(&fixture);
    let before = store
        .current_bound_pod_snapshot(target.scope_id.as_str(), target.pod_id.as_str())
        .unwrap();
    let revision = store.authority_snapshot().unwrap().revision;
    drop(store);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "DROP TABLE launch_policy_fences;
         DELETE FROM metadata WHERE key='policy_fence_epoch';
         PRAGMA user_version=19;",
        )
        .unwrap();
    drop(connection);
    let original_database = std::fs::read(&fixture.database).unwrap();
    let wal_path = fixture.database.with_extension("sqlite-wal");
    let original_wal = std::fs::read(&wal_path).ok();
    assert!(matches!(
        PodBayStore::open(&fixture.database),
        Err(StoreError::UnsupportedSchema(19))
    ));
    assert_eq!(std::fs::read(&fixture.database).unwrap(), original_database);
    assert_eq!(std::fs::read(&wal_path).ok(), original_wal);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0)).unwrap();
    let descriptor: Vec<u8> = connection.query_row(
        "SELECT descriptor FROM launch_bindings LIMIT 1", [], |row| row.get(0),
    ).unwrap();
    let lease: i64 = connection.query_row(
        "SELECT writer_epoch FROM native_writer_leases LIMIT 1", [], |row| row.get(0),
    ).unwrap();
    assert_eq!(version, 19);
    assert_eq!(descriptor, before.launch().descriptor);
    assert_eq!(lease as u64, writer_epoch);
    assert!(revision > 0 && manager_credential > 0);
    assert_eq!(target.pod_id.as_str(), before.pod_id().as_str());
}


#[test]
fn v18_bootstrap_schema_is_verified_exactly() {
    let fixture = Fixture::new();
    drop(fixture.open());
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "DROP INDEX codex_later_turns_session_v22;
             DROP TABLE codex_later_turns;
             DROP TABLE codex_bootstrap_sends;
         CREATE TABLE codex_bootstrap_sends(command_rowid INTEGER PRIMARY KEY) STRICT;",
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        PodBayStore::open_existing_read_only(&fixture.database),
        Err(StoreError::Conflict("v18 bootstrap schema differs"))
    ));
    assert!(matches!(
        PodBayStore::open(&fixture.database),
        Err(StoreError::Conflict("v18 bootstrap schema differs"))
    ));
}

#[test]
fn v18_bootstrap_binding_tamper_refuses_claim_and_exact_lookup() {
    let fixture = Fixture::new();
    let (mut store, target, manager_credential, writer_epoch) = bootstrap_ready(&fixture);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let revision: i64 = connection
        .query_row(
            "SELECT revision FROM runtime_sessions WHERE session_id='session.codex.fixture'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let envelope = bootstrap_envelope(
        "key.bootstrap.tamper",
        "request.bootstrap.tamper",
        "Prompt",
        revision as u64,
        writer_epoch,
    );
    let request = bootstrap_request(&mut store, target.clone(), manager_credential, &envelope);
    let receipt = match store.admit_bootstrap_send(&request).unwrap() {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected committed bootstrap: {other:?}"),
    };
    connection
        .execute(
            "UPDATE codex_bootstrap_sends SET resource_input_epoch=2",
            [],
        )
        .unwrap();
    drop(connection);
    let selector = BootstrapSendSelector {
        scope_id: target.scope_id.clone(),
        command_id: CommandId::try_from(receipt.command_id.as_str()).unwrap(),
        native_target: target,
    };
    assert!(matches!(
        store.claim_bootstrap_send(&selector),
        Err(StoreError::Conflict("bootstrap binding digest differs"))
    ));
    assert!(matches!(
        store.inspect_claimed_bootstrap_send(&selector),
        Err(StoreError::Conflict("bootstrap binding digest differs"))
    ));
    assert_eq!(
        store.effect_state(receipt.outbox_id).unwrap(),
        podbay_store::EffectState::Prepared
    );
}

#[test]
fn v18_bootstrap_rejects_artifact_and_steering_before_admission() {
    let fixture = Fixture::new();
    let (mut store, target, manager_credential, writer_epoch) = bootstrap_ready(&fixture);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let revision: i64 = connection
        .query_row(
            "SELECT revision FROM runtime_sessions WHERE session_id='session.codex.fixture'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);
    let base = bootstrap_envelope(
        "key.unsupported.base",
        "request.unsupported.base",
        "Prompt",
        revision as u64,
        writer_epoch,
    );
    for (key, body) in [
        (
            "key.unsupported.artifact",
            SessionSendBody {
                content: vec![ContentBlock::Artifact {
                    artifact_ref: "artifact.fixture".into(),
                }],
                policy: SendPolicy::WhenIdle,
            },
        ),
        (
            "key.unsupported.steer",
            SessionSendBody {
                content: vec![ContentBlock::Text {
                    text: "Prompt".into(),
                }],
                policy: SendPolicy::Steer {
                    expected_interval_id: "interval.fixture".into(),
                },
            },
        ),
    ] {
        let envelope = CommandEnvelope::new(
            "request.unsupported",
            key,
            base.target.clone(),
            base.guard.clone(),
            None,
            CommandBody::SessionSend(body),
        )
        .unwrap();
        let request = bootstrap_request(&mut store, target.clone(), manager_credential, &envelope);
        assert!(matches!(
            store.admit_bootstrap_send(&request),
            Err(StoreError::InvalidInput(_))
        ));
    }
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM codex_bootstrap_sends", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
}

fn later_ready(
    fixture: &Fixture,
    v3: bool,
) -> (PodBayStore, NativeWriterTarget, u64, u64, CommandId) {
    let (mut store, target, manager_credential, writer_epoch) =
        bootstrap_ready_for_format(fixture, v3);
    let (_, revision) = store
        .current_native_writer_target_for_session(&target.scope_id, &target.session_id)
        .unwrap();
    let envelope = bootstrap_envelope(
        "key.v22.bootstrap", "request.v22.bootstrap", "First turn", revision, writer_epoch,
    );
    let request = bootstrap_request(&mut store, target.clone(), manager_credential, &envelope);
    let receipt = match store.admit_bootstrap_send(&request).unwrap() {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected bootstrap intent: {other:?}"),
    };
    let bootstrap_id = CommandId::try_from(receipt.command_id.as_str()).unwrap();
    let selector = BootstrapSendSelector {
        scope_id: target.scope_id.clone(),
        command_id: bootstrap_id.clone(),
        native_target: target.clone(),
    };
    assert_eq!(store.claim_bootstrap_send(&selector).unwrap(), EffectClaim::NewClaim);
    (store, target, manager_credential, writer_epoch, bootstrap_id)
}

fn later_request<'a>(
    store: &mut PodBayStore,
    target: NativeWriterTarget,
    manager_credential: u64,
    bootstrap_command_id: CommandId,
    native_thread_id: &'a str,
    envelope: &'a CommandEnvelope,
) -> TrustedLaterCodexSendRequest<'a> {
    TrustedLaterCodexSendRequest {
        principal: VerifiedPrincipal::from_authenticated_boundary("actor.codex.fixture").unwrap(),
        scope_id: target.scope_id.clone(), envelope, native_target: target,
        bootstrap_command_id, native_thread_id,
        holder_actor_id: ActorId::try_from("actor.codex.fixture").unwrap(),
        holder_credential_generation: 1, expected_owner_epoch: 1,
        expected_manager_credential_epoch: manager_credential,
        expected_authority_revision: store.authority_snapshot().unwrap().revision,
    }
}

#[test]
fn v22_later_turn_admits_exact_intent_and_reopens_without_provider_effect() {
    let fixture = Fixture::new();
    let (mut store, target, manager_credential, writer_epoch, bootstrap_id) =
        later_ready(&fixture, false);
    let (_, revision) = store
        .current_native_writer_target_for_session(&target.scope_id, &target.session_id)
        .unwrap();
    let thread_id = "0199a0c8-ced1-7df2-8d90-000000000001";
    let envelope = bootstrap_envelope(
        "key.v22.turn.one", "request.v22.turn.one", "Second turn", revision, writer_epoch,
    );
    let request = later_request(&mut store, target.clone(), manager_credential,
        bootstrap_id.clone(), thread_id, &envelope);
    let receipt = match store.admit_later_codex_send(&request).unwrap() {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected later turn intent: {other:?}"),
    };
    let command_id = CommandId::try_from(receipt.command_id.as_str()).unwrap();
    let record = store.inspect_later_codex_send(
        &request.principal, &target.scope_id, &command_id,
    ).unwrap();
    assert_eq!(record.receipt(), &receipt);
    assert_eq!(record.native_target(), &target);
    assert_eq!(record.bootstrap_command_id(), &bootstrap_id);
    assert_eq!(record.native_thread_id(), thread_id);
    assert_eq!(record.prompt_text(), "Second turn");
    assert_eq!(record.effect_state(), podbay_store::EffectState::Prepared);
    assert_eq!(store.effect_state(receipt.outbox_id).unwrap(), podbay_store::EffectState::Prepared);
    assert_eq!(store.lookup_later_codex_send_by_key(
        &request.principal, &target.scope_id, &envelope, &bootstrap_id, thread_id,
    ).unwrap(), Some(record.clone()));
    drop(store);
    let mut reopened = PodBayStore::open_existing_read_only(&fixture.database).unwrap();
    assert_eq!(reopened.inspect_later_codex_send(
        &request.principal, &target.scope_id, &command_id,
    ).unwrap(), record);
}

#[test]
fn v22_later_turn_duplicate_precedes_mutable_fences_but_changed_digest_conflicts() {
    let fixture = Fixture::new();
    let (mut store, target, manager_credential, writer_epoch, bootstrap_id) =
        later_ready(&fixture, false);
    let (_, revision) = store.current_native_writer_target_for_session(
        &target.scope_id, &target.session_id,
    ).unwrap();
    let envelope = bootstrap_envelope(
        "key.v22.duplicate", "request.v22.original", "Second turn", revision, writer_epoch,
    );
    let request = later_request(&mut store, target.clone(), manager_credential,
        bootstrap_id.clone(), "thread.v22.one", &envelope);
    let receipt = match store.admit_later_codex_send(&request).unwrap() {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected later turn intent: {other:?}"),
    };
    let retry = bootstrap_envelope(
        "key.v22.duplicate", "request.v22.retry", "Second turn", revision, writer_epoch,
    );
    let mut duplicate = later_request(&mut store, target.clone(), manager_credential,
        bootstrap_id.clone(), "thread.v22.one", &retry);
    duplicate.expected_authority_revision = 0;
    assert_eq!(store.admit_later_codex_send(&duplicate).unwrap(), Admission::Duplicate(receipt.clone()));
    let changed = bootstrap_envelope(
        "key.v22.duplicate", "request.v22.changed", "Changed turn", revision, writer_epoch,
    );
    let changed_request = later_request(&mut store, target.clone(), manager_credential,
        bootstrap_id.clone(), "thread.v22.one", &changed);
    assert!(matches!(store.admit_later_codex_send(&changed_request),
        Err(StoreError::Conflict("later turn key changed canonical payload"))));
    let wrong_thread = later_request(&mut store, target.clone(), manager_credential,
        bootstrap_id.clone(), "thread.v22.other", &retry);
    assert!(matches!(store.admit_later_codex_send(&wrong_thread),
        Err(StoreError::Conflict("later turn key changed canonical payload"))));
    let second = bootstrap_envelope(
        "key.v22.turn.two", "request.v22.turn.two", "Third turn", revision, writer_epoch,
    );
    let second_request = later_request(&mut store, target.clone(), manager_credential,
        bootstrap_id.clone(), "thread.v22.one", &second);
    assert!(matches!(store.admit_later_codex_send(&second_request), Ok(Admission::Committed(_))));
    let changed_anchor = bootstrap_envelope(
        "key.v22.turn.three", "request.v22.turn.three", "Fourth turn", revision, writer_epoch,
    );
    let changed_anchor_request = later_request(&mut store, target.clone(), manager_credential,
        bootstrap_id, "thread.v22.other", &changed_anchor);
    assert!(matches!(store.admit_later_codex_send(&changed_anchor_request),
        Err(StoreError::Conflict("later turn native thread anchor differs"))));
    let foreign = VerifiedPrincipal::from_authenticated_boundary("actor.foreign.fixture").unwrap();
    assert!(matches!(store.inspect_later_codex_send(&foreign, &target.scope_id,
        &CommandId::try_from(receipt.command_id.as_str()).unwrap()), Err(StoreError::NotFound)));
    let mut foreign_scope = later_request(&mut store, target.clone(), manager_credential,
        CommandId::try_from("command.v22.bootstrap.foreign").unwrap(),
        "thread.v22.one", &retry);
    foreign_scope.scope_id = ScopeId::try_from("scope.foreign").unwrap();
    foreign_scope.native_target.scope_id = foreign_scope.scope_id.clone();
    assert!(matches!(store.admit_later_codex_send(&foreign_scope), Err(StoreError::NotFound)));
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let rows: i64 = connection.query_row("SELECT COUNT(*) FROM codex_later_turns", [], |row| row.get(0)).unwrap();
    assert_eq!(rows, 2);
}

#[test]
fn v22_later_turn_requires_current_writer_bootstrap_anchor_and_when_idle() {
    let fixture = Fixture::new();
    let (mut store, target, manager_credential, writer_epoch, bootstrap_id) =
        later_ready(&fixture, true);
    let (_, revision) = store.current_native_writer_target_for_session(
        &target.scope_id, &target.session_id,
    ).unwrap();
    let envelope = bootstrap_envelope(
        "key.v22.fence", "request.v22.fence", "Second turn", revision, writer_epoch,
    );
    let mut wrong_bootstrap = later_request(&mut store, target.clone(), manager_credential,
        CommandId::try_from("command.not.bootstrap").unwrap(), "thread.v22.one", &envelope);
    assert!(matches!(store.admit_later_codex_send(&wrong_bootstrap), Err(StoreError::NotFound)));
    wrong_bootstrap.bootstrap_command_id = bootstrap_id.clone();
    wrong_bootstrap.expected_authority_revision += 1;
    assert!(matches!(store.admit_later_codex_send(&wrong_bootstrap), Err(StoreError::StaleEpoch)));
    let mut stale_writer = later_request(&mut store, target.clone(), manager_credential,
        bootstrap_id.clone(), "thread.v22.one", &envelope);
    stale_writer.envelope = &envelope;
    stale_writer.holder_credential_generation += 1;
    assert!(matches!(store.admit_later_codex_send(&stale_writer), Err(StoreError::StaleEpoch)));
    let mut steer = envelope.clone();
    steer.body = CommandBody::SessionSend(SessionSendBody {
        content: vec![ContentBlock::Text { text: "Second turn".into() }],
        policy: SendPolicy::Steer { expected_interval_id: "interval.fixture".into() },
    });
    let steer_request = later_request(&mut store, target, manager_credential,
        bootstrap_id, "thread.v22.one", &steer);
    assert!(matches!(store.admit_later_codex_send(&steer_request), Err(StoreError::InvalidInput(_))));
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let rows: i64 = connection.query_row("SELECT COUNT(*) FROM codex_later_turns", [], |row| row.get(0)).unwrap();
    assert_eq!(rows, 0);
}

#[test]
fn v22_v3_later_turn_requires_current_policy_fence() {
    let fixture = Fixture::new();
    let (mut store, target, manager_credential, writer_epoch, bootstrap_id) =
        later_ready(&fixture, true);
    let policy_epoch = store.policy_fence_epoch().unwrap();
    let revision = store.authority_snapshot().unwrap().revision;
    let revision = store.apply_authority_mutation(1, revision,
        AuthorityMutation::PutGrant(AuthorityGrantRecord {
            grant_id: 17, scope_id: "scope.launch".into(),
            actor_id: "actor.codex.other".into(), credential_generation: 1,
            mode: "controller".into(), remaining_delegation_depth: 0,
            rights: vec![AuthorityRightRecord {
                operation: "launch_pod".into(), target_kind: "scope".into(),
                target_id: "scope.launch".into(),
            }],
        }),
    ).unwrap();
    assert_eq!(store.policy_fence_epoch().unwrap(), policy_epoch);
    let (_, session_revision) = store.current_native_writer_target_for_session(
        &target.scope_id, &target.session_id,
    ).unwrap();
    let envelope = bootstrap_envelope(
        "key.v22.policy.additive", "request.v22.policy.additive", "Second turn",
        session_revision, writer_epoch,
    );
    let request = later_request(&mut store, target.clone(), manager_credential,
        bootstrap_id.clone(), "thread.v22.policy", &envelope);
    assert_eq!(request.expected_authority_revision, revision);
    assert!(matches!(store.admit_later_codex_send(&request), Ok(Admission::Committed(_))));
    store.apply_authority_mutation(1, revision, AuthorityMutation::RevokeGrant(17)).unwrap();
    assert_eq!(store.policy_fence_epoch().unwrap(), policy_epoch + 1);
    let after = bootstrap_envelope(
        "key.v22.policy.revoked", "request.v22.policy.revoked", "Third turn",
        session_revision, writer_epoch,
    );
    let fresh = later_request(&mut store, target, manager_credential,
        bootstrap_id, "thread.v22.policy", &after);
    assert!(matches!(store.admit_later_codex_send(&fresh), Err(StoreError::StaleEpoch)));
}

#[test]
fn v22_later_turn_refuses_unclaimed_bootstrap_intent() {
    let fixture = Fixture::new();
    let (mut store, target, manager_credential, writer_epoch) = bootstrap_ready(&fixture);
    let (_, revision) = store.current_native_writer_target_for_session(
        &target.scope_id, &target.session_id,
    ).unwrap();
    let first = bootstrap_envelope(
        "key.v22.unclaimed.bootstrap", "request.v22.unclaimed.bootstrap",
        "First turn", revision, writer_epoch,
    );
    let first_request = bootstrap_request(&mut store, target.clone(), manager_credential, &first);
    let receipt = match store.admit_bootstrap_send(&first_request).unwrap() {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected bootstrap intent: {other:?}"),
    };
    let next = bootstrap_envelope(
        "key.v22.after.unclaimed", "request.v22.after.unclaimed",
        "Second turn", revision, writer_epoch,
    );
    let request = later_request(&mut store, target, manager_credential,
        CommandId::try_from(receipt.command_id.as_str()).unwrap(), "thread.v22.unclaimed", &next);
    assert!(matches!(store.admit_later_codex_send(&request),
        Err(StoreError::Conflict("later turn bootstrap anchor differs"))));
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let turns: i64 = connection.query_row("SELECT COUNT(*) FROM codex_later_turns", [], |row| row.get(0)).unwrap();
    assert_eq!(turns, 0);
}

#[test]
fn v22_later_turn_claim_once_survives_lost_reply_and_reopen() {
    let fixture = Fixture::new();
    let (mut store, target, manager_credential, writer_epoch, bootstrap_id) =
        later_ready(&fixture, false);
    let (_, revision) = store.current_native_writer_target_for_session(
        &target.scope_id, &target.session_id,
    ).unwrap();
    let envelope = bootstrap_envelope(
        "key.v22.claim", "request.v22.claim", "Second turn", revision, writer_epoch,
    );
    let request = later_request(&mut store, target.clone(), manager_credential,
        bootstrap_id, "thread.v22.claim", &envelope);
    let receipt = match store.admit_later_codex_send(&request).unwrap() {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected later-turn intent: {other:?}"),
    };
    let selector = LaterCodexSendSelector {
        scope_id: target.scope_id.clone(),
        command_id: CommandId::try_from(receipt.command_id.as_str()).unwrap(),
        native_target: target.clone(),
    };
    assert!(store.claimed_later_turn_selector_for_command(
        &request.principal, &target.scope_id, &selector.command_id,
    ).unwrap().is_none());
    assert!(matches!(store.inspect_claimed_later_codex_send(&selector), Err(StoreError::Conflict(_))));
    assert_eq!(store.claim_later_codex_send(&selector).unwrap(), EffectClaim::NewClaim);
    assert_eq!(store.claimed_later_turn_selector_for_command(
        &request.principal, &target.scope_id, &selector.command_id,
    ).unwrap(), Some((selector.clone(), writer_epoch)));
    let claimed = store.inspect_claimed_later_codex_send(&selector).unwrap();
    assert_eq!(claimed.receipt(), &receipt);
    assert_eq!(claimed.prompt_text(), "Second turn");
    assert_eq!(claimed.effect_state(), podbay_store::EffectState::ClaimedUncertain);
    assert_eq!(store.claim_later_codex_send(&selector).unwrap(), EffectClaim::ExistingUncertain);
    drop(store);
    let mut reopened = fixture.open();
    assert_eq!(reopened.claim_later_codex_send(&selector).unwrap(), EffectClaim::ExistingUncertain);
    assert_eq!(reopened.inspect_claimed_later_codex_send(&selector).unwrap(), claimed);
    let retry = bootstrap_envelope(
        "key.v22.claim", "request.v22.claim.retry", "Second turn", revision, writer_epoch,
    );
    let duplicate = later_request(&mut reopened, target, manager_credential,
        claimed.bootstrap_command_id().clone(), "thread.v22.claim", &retry);
    assert_eq!(reopened.admit_later_codex_send(&duplicate).unwrap(), Admission::Duplicate(receipt));
}

#[test]
fn v22_later_turn_claim_refuses_authority_drift_after_admission() {
    let fixture = Fixture::new();
    let (mut store, target, manager_credential, writer_epoch, bootstrap_id) =
        later_ready(&fixture, true);
    let (_, session_revision) = store.current_native_writer_target_for_session(
        &target.scope_id, &target.session_id,
    ).unwrap();
    let envelope = bootstrap_envelope(
        "key.v22.claim.stale", "request.v22.claim.stale", "Second turn",
        session_revision, writer_epoch,
    );
    let request = later_request(&mut store, target.clone(), manager_credential,
        bootstrap_id, "thread.v22.claim.stale", &envelope);
    let receipt = match store.admit_later_codex_send(&request).unwrap() {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected later-turn intent: {other:?}"),
    };
    let selector = LaterCodexSendSelector {
        scope_id: target.scope_id.clone(),
        command_id: CommandId::try_from(receipt.command_id.as_str()).unwrap(),
        native_target: target,
    };
    let revision = store.authority_snapshot().unwrap().revision;
    store.apply_authority_mutation(1, revision, AuthorityMutation::PutGrant(AuthorityGrantRecord {
        grant_id: 17, scope_id: "scope.launch".into(), actor_id: "actor.codex.other".into(),
        credential_generation: 1, mode: "controller".into(), remaining_delegation_depth: 0,
        rights: vec![AuthorityRightRecord {
            operation: "launch_pod".into(), target_kind: "scope".into(),
            target_id: "scope.launch".into(),
        }],
    })).unwrap();
    assert!(matches!(store.claim_later_codex_send(&selector), Err(StoreError::StaleEpoch)));
    assert_eq!(store.effect_state(receipt.outbox_id).unwrap(), podbay_store::EffectState::Prepared);
}


#[test]
fn v22_later_turn_failed_binding_insert_rolls_back_command_event_and_outbox() {
    let fixture = Fixture::new();
    let (mut store, target, manager_credential, writer_epoch, bootstrap_id) =
        later_ready(&fixture, false);
    let (_, revision) = store.current_native_writer_target_for_session(
        &target.scope_id, &target.session_id,
    ).unwrap();
    let envelope = bootstrap_envelope(
        "key.v22.rollback", "request.v22.rollback", "Second turn", revision, writer_epoch,
    );
    let request = later_request(&mut store, target, manager_credential,
        bootstrap_id, "thread.v22.one", &envelope);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let count = |table: &str| -> i64 {
        connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0)).unwrap()
    };
    let before = [count("commands"), count("events"), count("outbox"), count("codex_later_turns")];
    connection.execute_batch(
        "CREATE TRIGGER fail_later_binding AFTER INSERT ON codex_later_turns
         BEGIN SELECT RAISE(ABORT,'injected later-turn failure'); END;",
    ).unwrap();
    assert!(matches!(store.admit_later_codex_send(&request), Err(StoreError::Storage(_))));
    let after = [count("commands"), count("events"), count("outbox"), count("codex_later_turns")];
    assert_eq!(after, before);
    connection.execute_batch("DROP TRIGGER fail_later_binding").unwrap();
    assert!(matches!(store.admit_later_codex_send(&request), Ok(Admission::Committed(_))));
}

#[test]
fn v22_schema_tamper_refuses_both_open_modes() {
    let fixture = Fixture::new();
    drop(fixture.open());
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection.execute_batch(
        "DROP INDEX codex_later_turns_session_v22;
         CREATE INDEX codex_later_turns_session_v22 ON codex_later_turns(resource_id);",
    ).unwrap();
    drop(connection);
    assert!(matches!(PodBayStore::open_existing_read_only(&fixture.database),
        Err(StoreError::Conflict("v22 later turn schema differs"))));
    assert!(matches!(PodBayStore::open(&fixture.database),
        Err(StoreError::Conflict("v22 later turn schema differs"))));
}

fn native_fixture_page(target: &NativeWriterTarget, raw: &[u8]) -> NativeEvidencePage {
    let mut raw = raw.to_vec();
    raw.push(b'\n');
    let identity = NativeEvidenceIdentity {
        store_lineage: target.store_lineage.as_str().into(),
        scope_id: target.scope_id.as_str().into(),
        session_id: target.session_id.as_str().into(),
        run_id: target.run_id.as_str().into(),
        attempt_id: target.attempt_id.as_str().into(),
        pod_id: target.pod_id.as_str().into(),
        pod_incarnation: target.pod_incarnation,
        resource_id: target.resource_id.as_str().into(),
        resource_epoch: target.resource_epoch,
    };
    let content_digest = Sha256::digest(&raw).iter()
        .map(|byte| format!("{byte:02x}")).collect();
    NativeEvidencePage {
        snapshot: NativeEvidenceSnapshot {
            identity, watermark: 1, earliest_retained: 1, last_status: None,
            output_events: 1, question_events: 0, permission_events: 0,
            opaque_events: 0, external_conflict: false,
            fidelity: "exact".into(), quarantined: false,
        },
        events: vec![NativeEvidenceEvent {
            event_id: "event.native.fixture.1".into(), source_sequence: 1,
            kind: "output".into(), status: None, recorded_at_unix_millis: 123,
            provenance: "codex.app-server.pod-observed/1".into(),
            external_conflict: false, content_digest, raw_jsonl: raw,
        }],
        next_source_sequence: 1, gap: None,
    }
}

fn native_input<'a>(
    actor: &'a AuthorityActorRecord,
    owner: u64,
    credential: u64,
    revision: u64,
    effective_digest: &'a str,
    descriptor_digest: &'a str,
    page: &'a NativeEvidencePage,
) -> TrustedNativeEvidenceAdmission<'a> {
    TrustedNativeEvidenceAdmission {
        actor, expected_owner_epoch: owner,
        expected_manager_credential_epoch: credential,
        expected_authority_revision: revision,
        effective_digest, descriptor_digest, after: 0, limit: 2, page,
    }
}

#[test]
fn v23_native_evidence_is_exact_once_private_and_reopen_replays() {
    let fixture = Fixture::new();
    let (mut store, target, credential_epoch) = admitted_writer_target(&fixture);
    let actor = writer_actor("actor.codex.fixture");
    let revision = store.authority_snapshot().unwrap().revision;
    let bound = store.current_bound_pod_snapshot("scope.launch", "pod.launch").unwrap();
    let effective = EffectiveLaunchContractV2::decode(&bound.launch().effective_spec).unwrap();
    let descriptor = ImmutableLaunchDescriptorV2::decode_json(&bound.launch().descriptor).unwrap();
    let raw = br#"{"method":"item/completed","params":{"text":"private fixture output"}}"#;
    let page = native_fixture_page(&target, raw);
    let make_input = |page| native_input(&actor, 1, credential_epoch, revision,
        effective.digest(), descriptor.digest(), page);
    let before_generic: i64 = rusqlite::Connection::open(&fixture.database).unwrap()
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0)).unwrap();
    assert_eq!(store.admit_native_evidence_page(make_input(&page)).unwrap(), page);
    assert_eq!(store.admit_native_evidence_page(make_input(&page)).unwrap(), page);
    drop(store);
    let mut reopened = fixture.open();
    assert_eq!(reopened.native_evidence_after(&actor, 1, credential_epoch, revision,
        &page.snapshot.identity, effective.digest(), descriptor.digest(), 0, 2)
        .unwrap(), Some(page.clone()));
    let after_generic: i64 = rusqlite::Connection::open(&fixture.database).unwrap()
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0)).unwrap();
    assert_eq!(after_generic, before_generic, "raw native output entered generic history");
    let mut changed = page.clone();
    changed.events[0].raw_jsonl = b"{\"method\":\"changed\"}\n".to_vec();
    changed.events[0].content_digest = Sha256::digest(&changed.events[0].raw_jsonl)
        .iter().map(|byte| format!("{byte:02x}")).collect();
    assert!(matches!(reopened.admit_native_evidence_page(make_input(&changed)),
        Err(StoreError::SourceIdentityQuarantined)));
    assert!(matches!(reopened.native_evidence_after(&actor, 1, credential_epoch, revision,
        &page.snapshot.identity, effective.digest(), descriptor.digest(), 0, 2),
        Err(StoreError::SourceIdentityQuarantined)));
}

#[test]
fn v23_native_evidence_retains_observed_large_codex_output_but_bounds_one_frame() {
    let fixture = Fixture::new();
    let (mut store, target, credential_epoch) = admitted_writer_target(&fixture);
    let actor = writer_actor("actor.codex.fixture");
    let revision = store.authority_snapshot().unwrap().revision;
    let bound = store.current_bound_pod_snapshot("scope.launch", "pod.launch").unwrap();
    let effective = EffectiveLaunchContractV2::decode(&bound.launch().effective_spec).unwrap();
    let descriptor = ImmutableLaunchDescriptorV2::decode_json(&bound.launch().descriptor).unwrap();
    let raw = format!("{{\"method\":\"item/completed\",\"params\":{{\"output\":\"{}\"}}}}",
        "x".repeat(624_000)).into_bytes();
    assert!(raw.len() > 262_144 && raw.len() <= 4_194_304);
    let page = native_fixture_page(&target, &raw);
    let input = native_input(&actor, 1, credential_epoch, revision,
        effective.digest(), descriptor.digest(), &page);
    assert_eq!(store.admit_native_evidence_page(input).unwrap(), page);
    assert_eq!(store.native_evidence_after(&actor, 1, credential_epoch, revision,
        &page.snapshot.identity, effective.digest(), descriptor.digest(), 0, 2)
        .unwrap(), Some(page.clone()));
    let oversized = format!("{{\"method\":\"item/completed\",\"params\":{{\"output\":\"{}\"}}}}",
        "x".repeat(4_194_304)).into_bytes();
    assert!(oversized.len() > 4_194_304);
    let too_large = native_fixture_page(&target, &oversized);
    assert!(matches!(store.admit_native_evidence_page(native_input(
        &actor, 1, credential_epoch, revision, effective.digest(), descriptor.digest(), &too_large,
    )), Err(StoreError::InvalidInput(_))));
}

#[test]
fn v23_native_evidence_refuses_foreign_actor_stale_owner_and_wrong_resource() {
    let fixture = Fixture::new();
    let (mut store, target, credential_epoch) = admitted_writer_target(&fixture);
    let actor = writer_actor("actor.codex.fixture");
    let revision = store.authority_snapshot().unwrap().revision;
    let bound = store.current_bound_pod_snapshot("scope.launch", "pod.launch").unwrap();
    let effective = EffectiveLaunchContractV2::decode(&bound.launch().effective_spec).unwrap();
    let descriptor = ImmutableLaunchDescriptorV2::decode_json(&bound.launch().descriptor).unwrap();
    let page = native_fixture_page(&target, br#"{"method":"turn/completed"}"#);
    let mut foreign = writer_actor("actor.codex.other");
    foreign.scope_id = "scope.other".into();
    assert!(store.admit_native_evidence_page(native_input(&foreign, 1, credential_epoch,
        revision, effective.digest(), descriptor.digest(), &page)).is_err());
    assert!(matches!(store.admit_native_evidence_page(native_input(&actor, 2,
        credential_epoch, revision, effective.digest(), descriptor.digest(), &page)),
        Err(StoreError::StaleEpoch)));
    let mut wrong = page.clone();
    wrong.snapshot.identity.resource_id = "resource.other".into();
    assert!(matches!(store.admit_native_evidence_page(native_input(&actor, 1,
        credential_epoch, revision, effective.digest(), descriptor.digest(), &wrong)),
        Err(StoreError::NotFound)));
    let count: i64 = rusqlite::Connection::open(&fixture.database).unwrap()
        .query_row("SELECT COUNT(*) FROM codex_native_evidence", [], |row| row.get(0)).unwrap();
    assert_eq!(count, 0);
}

#[test]
fn v23_native_evidence_failed_insert_rolls_back_source_and_rejects_schema_tamper() {
    let fixture = Fixture::new();
    let (mut store, target, credential_epoch) = admitted_writer_target(&fixture);
    let actor = writer_actor("actor.codex.fixture");
    let revision = store.authority_snapshot().unwrap().revision;
    let bound = store.current_bound_pod_snapshot("scope.launch", "pod.launch").unwrap();
    let effective = EffectiveLaunchContractV2::decode(&bound.launch().effective_spec).unwrap();
    let descriptor = ImmutableLaunchDescriptorV2::decode_json(&bound.launch().descriptor).unwrap();
    let page = native_fixture_page(&target, br#"{"method":"item/completed"}"#);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection.execute_batch(
        "CREATE TRIGGER fail_native_event AFTER INSERT ON codex_native_evidence
         BEGIN SELECT RAISE(ABORT,'injected native event failure'); END;",
    ).unwrap();
    let input = || native_input(&actor, 1, credential_epoch, revision,
        effective.digest(), descriptor.digest(), &page);
    assert!(matches!(store.admit_native_evidence_page(input()), Err(StoreError::Storage(_))));
    for table in ["codex_native_sources", "codex_native_evidence"] {
        let count: i64 = connection.query_row(&format!("SELECT COUNT(*) FROM {table}"),
            [], |row| row.get(0)).unwrap();
        assert_eq!(count, 0, "{table} partially committed");
    }
    connection.execute_batch("DROP TRIGGER fail_native_event").unwrap();
    assert_eq!(store.admit_native_evidence_page(input()).unwrap(), page);
    drop(store);
    connection.execute_batch("DROP TABLE codex_native_conflicts").unwrap();
    drop(connection);
    assert!(matches!(PodBayStore::open_existing_read_only(&fixture.database),
        Err(StoreError::Conflict("v23 Codex native evidence schema differs"))));
}

#[test]
fn v23_native_gap_only_advances_cursor_and_partial_replay_grows() {
    let fixture = Fixture::new();
    let (mut store, target, credential_epoch) = admitted_writer_target(&fixture);
    let actor = writer_actor("actor.codex.fixture");
    let revision = store.authority_snapshot().unwrap().revision;
    let bound = store.current_bound_pod_snapshot("scope.launch", "pod.launch").unwrap();
    let effective = EffectiveLaunchContractV2::decode(&bound.launch().effective_spec).unwrap();
    let descriptor = ImmutableLaunchDescriptorV2::decode_json(&bound.launch().descriptor).unwrap();
    let mut empty = native_fixture_page(&target, b"{\"method\":\"fixture\"}");
    empty.events.clear();
    empty.snapshot.watermark = 5;
    empty.snapshot.earliest_retained = 6;
    empty.snapshot.output_events = 5;
    empty.snapshot.fidelity = "partial".into();
    empty.next_source_sequence = 5;
    empty.gap = Some(podbay_store::NativeEvidenceGap {
        missing_from: 1, missing_through: 5, earliest_available: 6,
    });
    let admitted = store.admit_native_evidence_page(native_input(&actor, 1,
        credential_epoch, revision, effective.digest(), descriptor.digest(), &empty)).unwrap();
    assert!(admitted.events.is_empty());
    assert_eq!(admitted.next_source_sequence, 5);
    assert_eq!(admitted.gap, empty.gap);

    let mut sixth = native_fixture_page(&target, br#"{"method":"item/agentMessage/delta","delta":"six"}"#);
    sixth.events[0].source_sequence = 6;
    sixth.events[0].event_id = "event.native.fixture.6".into();
    sixth.snapshot.watermark = 6;
    sixth.snapshot.earliest_retained = 6;
    sixth.snapshot.output_events = 6;
    sixth.snapshot.fidelity = "partial".into();
    sixth.next_source_sequence = 6;
    sixth.gap = None;
    let admitted = store.admit_native_evidence_page(TrustedNativeEvidenceAdmission {
        actor: &actor, expected_owner_epoch: 1,
        expected_manager_credential_epoch: credential_epoch,
        expected_authority_revision: revision,
        effective_digest: effective.digest(), descriptor_digest: descriptor.digest(),
        after: 5, limit: 2, page: &sixth,
    }).unwrap();
    assert_eq!(admitted.events.len(), 1);
    let first = store.native_evidence_after(&actor, 1, credential_epoch, revision,
        &sixth.snapshot.identity, effective.digest(), descriptor.digest(), 0, 2)
        .unwrap().unwrap();
    assert_eq!(first.events[0].source_sequence, 6);
    assert_eq!(first.gap.unwrap().missing_through, 5);
    assert_eq!(first.next_source_sequence, 6);

    let mut seventh = sixth.clone();
    seventh.events[0].source_sequence = 7;
    seventh.events[0].event_id = "event.native.fixture.7".into();
    seventh.snapshot.watermark = 7;
    seventh.snapshot.earliest_retained = 6;
    seventh.snapshot.output_events = 7;
    seventh.next_source_sequence = 7;
    store.admit_native_evidence_page(TrustedNativeEvidenceAdmission {
        actor: &actor, expected_owner_epoch: 1,
        expected_manager_credential_epoch: credential_epoch,
        expected_authority_revision: revision,
        effective_digest: effective.digest(), descriptor_digest: descriptor.digest(),
        after: 6, limit: 2, page: &seventh,
    }).unwrap();
    let grown = store.native_evidence_after(&actor, 1, credential_epoch, revision,
        &seventh.snapshot.identity, effective.digest(), descriptor.digest(), 0, 2)
        .unwrap().unwrap();
    assert_eq!(grown.events.iter().map(|event| event.source_sequence).collect::<Vec<_>>(), [6, 7]);
}
