use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use podbay_core::{
    ActorId, Attempt, AttemptId, CommandAdmission, CommandId, Epoch, LaunchBinding, Pod, PodId,
    Resource, ResourceId, ResourceKind, Role, Run, RunCommandKind, RunId, ScopeId, Session,
    SessionId, WorkKind,
};
use podbay_host::{
    ActorRegistration, AuthenticatedPeer, AuthenticatedProcessSubject, AuthenticatedTransport,
    AuthorisedBoundLaunch, AuthorisedDispatch, BoundHostLaunchProposal, BoundLaunchPodRequest,
    CredentialGeneration, CredentialRef, DurableAuthority, DurableAuthorityError, GrantId,
    GrantMode, GrantSpec, GuardSet, HostAction, HostDispatchPort, HostError, HostRequest,
    LaunchPodError, LaunchSelection, ManagerEpoch, Operation, PodIncarnation, PortDispatchError,
    PortDispatchOutcome, PortReceiptRef, RegisteredLaunchProfile, Right, Target,
    TrustedLaunchProfileInput, WorkspaceAccess, WorkspaceSelection,
};
use podbay_store::{
    EffectClaim, LaunchDispatchStage, LaunchLookupRequest, PodBayStore, StoreError,
    VerifiedPrincipal,
};
use podbay_wire::{
    ImmutableLaunchDescriptor, NativeRole, ResourceDriver, ReviewedNativePolicy, ReviewedResource,
    TargetOs,
};

struct Fixture {
    directory: PathBuf,
    database: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("podbay-launch-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        Self {
            database: directory.join("podbay.sqlite"),
            directory,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Accepted = 0,
    Refused = 1,
    LostReply = 2,
    Settled = 3,
}

struct FakeLaunchPort {
    mode: Arc<AtomicU8>,
    port_calls: Arc<AtomicUsize>,
    possible_effects: Arc<AtomicUsize>,
    reviewed: Mutex<Vec<AuthorisedBoundLaunch>>,
    fixture_opt_in: bool,
}

impl FakeLaunchPort {
    fn new(mode: Mode) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let port_calls = Arc::new(AtomicUsize::new(0));
        let possible_effects = Arc::new(AtomicUsize::new(0));
        (
            Self {
                mode: Arc::new(AtomicU8::new(mode as u8)),
                port_calls: port_calls.clone(),
                possible_effects: possible_effects.clone(),
                reviewed: Mutex::new(Vec::new()),
                fixture_opt_in: true,
            },
            port_calls,
            possible_effects,
        )
    }

    fn without_fixture_opt_in(mut self) -> Self {
        self.fixture_opt_in = false;
        self
    }
}

impl HostDispatchPort for FakeLaunchPort {
    type Receipt = PortReceiptRef;

    fn allow_unverified_native_launch_for_fixture(&self) -> bool {
        self.fixture_opt_in
    }

    fn dispatch(
        &mut self,
        _action: AuthorisedDispatch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        Err(PortDispatchError::RefusedBeforeEffect)
    }

    fn launch_bound(
        &mut self,
        launch: AuthorisedBoundLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        self.reviewed.lock().unwrap().push(launch);
        self.port_calls.fetch_add(1, Ordering::SeqCst);
        match self.mode.load(Ordering::SeqCst) {
            1 => Err(PortDispatchError::RefusedBeforeEffect),
            2 => {
                self.possible_effects.fetch_add(1, Ordering::SeqCst);
                Err(PortDispatchError::UncertainAfterPossibleEffect {
                    receipt_ref: Some(PortReceiptRef::from_port("receipt.launch.one").unwrap()),
                })
            }
            3 => {
                self.possible_effects.fetch_add(1, Ordering::SeqCst);
                Ok(PortDispatchOutcome::Settled(
                    PortReceiptRef::from_port("receipt.launch.one").unwrap(),
                ))
            }
            _ => {
                self.possible_effects.fetch_add(1, Ordering::SeqCst);
                Ok(PortDispatchOutcome::Accepted(
                    PortReceiptRef::from_port("receipt.launch.one").unwrap(),
                ))
            }
        }
    }
}

#[derive(Clone)]
struct FakeTransport(AuthenticatedPeer);

impl AuthenticatedTransport for FakeTransport {
    fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError> {
        Ok(self.0.clone())
    }
}

struct Identity {
    scope: ScopeId,
    pod: PodId,
    actor: ActorId,
    process: AuthenticatedProcessSubject,
    transport: FakeTransport,
}

fn identity() -> Identity {
    let scope = ScopeId::try_from("scope.launch").unwrap();
    let pod = PodId::try_from("pod.launch").unwrap();
    let actor = ActorId::try_from("actor.launcher").unwrap();
    let process = AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(
        1000,
        701,
        801,
        "/user.slice/session-launch.scope",
    )
    .unwrap();
    let transport = FakeTransport(AuthenticatedPeer::owner_cli_from_authenticated_transport(
        process.clone(),
        CredentialGeneration::new(1).unwrap(),
    ));
    Identity {
        scope,
        pod,
        actor,
        process,
        transport,
    }
}

fn profile_input(who: &Identity) -> TrustedLaunchProfileInput {
    TrustedLaunchProfileInput {
        profile_ref: "profile.fixture".into(),
        profile_generation: 1,
        executable: "/opt/podbay/bin/fake-agent".into(),
        binary_generation: "sha256.fakegeneration1".into(),
        fixed_arguments: vec!["--managed".into()],
        permitted_extra_arguments: BTreeSet::from(["--safe".to_owned(), "--verbose".to_owned()]),
        default_model: "model.alpha".into(),
        allowed_models: BTreeSet::from(["model.alpha".into(), "model.beta".into()]),
        default_effort: "medium".into(),
        allowed_efforts: BTreeSet::from(["medium".into(), "high".into()]),
        workspace_scope: who.scope.clone(),
        workspace_basis_ref: "basis.commit.one".into(),
        allowed_cwd_prefix: ".".into(),
        allow_write: true,
        allowed_tool_bundle_refs: BTreeSet::from(["tools.base".into(), "tools.extra".into()]),
        environment_refs: vec!["env.clean".into()],
        credential_refs: vec![
            CredentialRef::from_trusted_vault(who.scope.clone(), "vault.allowed.one").unwrap(),
            CredentialRef::from_trusted_vault(who.scope.clone(), "vault.allowed.two").unwrap(),
        ],
        max_wall_seconds: 120,
        max_children: 4,
        allow_fallback: false,
    }
}

fn profile(who: &Identity) -> RegisteredLaunchProfile {
    RegisteredLaunchProfile::from_trusted_policy(profile_input(who)).unwrap()
}

fn initial_authority(
    path: &PathBuf,
    port: FakeLaunchPort,
    who: &Identity,
) -> (DurableAuthority<FakeLaunchPort>, GrantId) {
    let mut host = DurableAuthority::open(path, port).unwrap();
    host.register_actor_from_trusted_policy(ActorRegistration::owner_cli_from_trusted_policy(
        who.actor.clone(),
        who.scope.clone(),
        who.process.clone(),
        CredentialGeneration::new(1).unwrap(),
    ))
    .unwrap();
    let grant = host
        .install_grant_from_trusted_policy(
            &who.actor,
            GrantSpec {
                scope_id: who.scope.clone(),
                mode: GrantMode::Controller,
                rights: [Right::new(
                    Operation::LaunchPod,
                    Target::Pod(who.pod.clone()),
                )]
                .into_iter()
                .collect::<BTreeSet<_>>(),
                remaining_delegation_depth: 0,
            },
        )
        .unwrap();
    host.register_launch_profile_from_trusted_policy(profile(who))
        .unwrap();
    (host, grant)
}

fn replay(host: &mut DurableAuthority<FakeLaunchPort>, who: &Identity, grant: GrantId) {
    host.reattest_actor_from_trusted_replay(
        &who.transport,
        ActorRegistration::owner_cli_from_trusted_policy(
            who.actor.clone(),
            who.scope.clone(),
            who.process.clone(),
            CredentialGeneration::new(1).unwrap(),
        ),
    )
    .unwrap();
    host.activate_grant_from_trusted_replay(grant).unwrap();
    host.register_launch_profile_from_trusted_policy(profile(who))
        .unwrap();
}

fn launch_request(
    who: &Identity,
    grant: GrantId,
    current_owner: u64,
    _admission_owner: u64,
    body: &[u8],
) -> BoundLaunchPodRequest {
    let selection = LaunchSelection {
        profile_ref: "profile.fixture".into(),
        profile_generation: 1,
        model_id: Some("model.alpha".into()),
        reasoning_effort: Some("medium".into()),
        fallback_approved: false,
        workspace: WorkspaceSelection {
            scope_id: who.scope.clone(),
            basis_ref: "basis.commit.one".into(),
            relative_cwd: "src".into(),
            access: WorkspaceAccess::ReadWrite,
        },
        arguments: vec!["--safe".into()],
        tool_bundle_refs: vec!["tools.base".into()],
        authority_ref: format!("grant.{}", grant.get()),
        wall_seconds: 60,
        max_children: 2,
        parent_run_id: None,
    };
    BoundLaunchPodRequest {
        host_request: HostRequest {
            scope_id: who.scope.clone(),
            grant_id: grant,
            guards: GuardSet {
                manager_epoch: ManagerEpoch::new(current_owner).unwrap(),
                pod_incarnation: PodIncarnation::new(1).unwrap(),
                resource_epoch: None,
                credential_generation: CredentialGeneration::new(1).unwrap(),
            },
            command_key: "launch.same-key".into(),
            correlation_id: "correlation.launch".into(),
            deadline: Instant::now() + Duration::from_secs(30),
            action: HostAction::LaunchPod {
                pod_id: who.pod.clone(),
                role: Role::Worker,
                credential: None,
            },
        },
        canonical_request: body.to_vec(),
        proposal: Some(bound_proposal(who, &who.pod, Role::Worker, selection, None)),
    }
}

struct Admitted;
impl CommandAdmission for Admitted {
    fn admits_run(&self, _: &CommandId, _: &RunId, kind: RunCommandKind) -> bool {
        kind == RunCommandKind::Launch
    }
}

fn bound_proposal(
    who: &Identity,
    pod_id: &PodId,
    role: Role,
    selection: LaunchSelection,
    selected_credential: Option<&CredentialRef>,
) -> BoundHostLaunchProposal {
    let mut session = Session::new(
        SessionId::try_from(format!("session.{}", pod_id.as_str())).unwrap(),
        who.actor.clone(),
        who.scope.clone(),
    );
    let mut run = Run::new(
        RunId::try_from(format!("run.{}", pod_id.as_str())).unwrap(),
        &session,
        role,
        if role == Role::Coordinator {
            WorkKind::Service
        } else {
            WorkKind::Task
        },
        None,
    );
    run.admit(
        run.revision(),
        &CommandId::try_from("command.fixture").unwrap(),
        &Admitted,
    )
    .unwrap();
    session.bind_run(session.revision(), &run).unwrap();
    let mut attempt = Attempt::new(
        AttemptId::try_from(format!("attempt.{}", pod_id.as_str())).unwrap(),
        run.id().clone(),
        1,
        Epoch::new(1).unwrap(),
    )
    .unwrap();
    run.start_attempt(run.revision(), &attempt).unwrap();
    let mut pod = Pod::new(pod_id.clone(), attempt.id().clone(), Epoch::new(1).unwrap());
    attempt.attach_pod(attempt.revision(), &pod).unwrap();
    let resources = vec![
        Resource::new(
            ResourceId::try_from(format!("resource.pty.{}", pod_id.as_str())).unwrap(),
            pod.id().clone(),
            ResourceKind::Pty,
            Epoch::new(1).unwrap(),
        ),
        Resource::new(
            ResourceId::try_from(format!("resource.provider.{}", pod_id.as_str())).unwrap(),
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
    let native_policy = ReviewedNativePolicy {
        target_os: TargetOs::Linux,
        host_id: "host.fixture".into(),
        profile_ref: "profile.fixture".into(),
        profile_generation: 1,
        model_id: "model.alpha".into(),
        reasoning_effort: "medium".into(),
        executable_generation: "sha256.fakegeneration1".into(),
        effective_spec_digest: "0".repeat(64),
        workspace_basis_ref: "basis.commit.one".into(),
        executable: "/opt/podbay/bin/fake-agent".into(),
        cwd: "/tmp".into(),
        arguments: vec!["--managed".into(), "--safe".into()],
        environment_refs: vec!["env.clean".into()],
        credential_refs: selected_credential
            .map(|value| vec![value.as_str().to_owned()])
            .unwrap_or_default(),
        wall_seconds: 60,
        max_children: 2,
        resources: resources
            .iter()
            .map(|resource| ReviewedResource {
                resource_id: resource.id().clone(),
                kind: resource.kind(),
                epoch: resource.epoch(),
                driver: match resource.kind() {
                    ResourceKind::Pty => ResourceDriver::Pty {
                        rows: 24,
                        columns: 80,
                        retention_events: 100,
                    },
                    ResourceKind::StructuredProvider => ResourceDriver::Structured {
                        driver_ref: "driver.fixture".into(),
                        protocol_ref: "protocol.fixture".into(),
                    },
                    ResourceKind::Auxiliary => unreachable!(),
                },
            })
            .collect(),
    };
    BoundHostLaunchProposal {
        session,
        run,
        binding,
        selection,
        native_policy,
    }
}

#[test]
fn malformed_committed_readback_refuses_while_outbox_stays_prepared() {
    let fixture = Fixture::new();
    let who = identity();
    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, grant) = initial_authority(&fixture.database, port, &who);
    let request = launch_request(&who, grant, 1, 1, b"canonical.corrupt-readback");
    let admitted = host
        .admit_bound_pod(&who.transport, request.clone())
        .unwrap();
    assert_eq!(admitted.status.stage, LaunchDispatchStage::Prepared);
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let mut record = store
        .lookup_bound_launch(&LaunchLookupRequest {
            principal: VerifiedPrincipal::from_authenticated_boundary(who.actor.as_str()).unwrap(),
            namespace: "podbay.launch".into(),
            command_key: request.host_request.command_key.clone(),
            scope_id: who.scope.as_str().into(),
            target_id: who.pod.as_str().into(),
            canonical_intent: request.canonical_request,
        })
        .unwrap()
        .unwrap();
    record.descriptor = br#"{}"#.to_vec();
    let authorised = AuthorisedDispatch {
        actor_id: who.actor.clone(),
        role: Role::Worker,
        scope_id: who.scope.clone(),
        command_key: "launch.same-key".into(),
        correlation_id: "correlation.launch".into(),
        action: HostAction::LaunchPod {
            pod_id: who.pod.clone(),
            role: Role::Worker,
            credential: None,
        },
    };
    assert!(matches!(
        AuthorisedBoundLaunch::from_committed(&authorised, record),
        Err(HostError::StaleGuard)
    ));
    assert_eq!(
        store
            .launch_dispatch_status(
                admitted.receipt.outbox_id,
                who.scope.as_str(),
                who.pod.as_str(),
            )
            .unwrap()
            .stage,
        LaunchDispatchStage::Prepared
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn unverified_native_policy_is_held_prepared_without_fixture_opt_in() {
    let fixture = Fixture::new();
    let who = identity();
    let (port, calls, effects) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, grant) =
        initial_authority(&fixture.database, port.without_fixture_opt_in(), &who);
    let request = launch_request(&who, grant, 1, 1, b"canonical.unverified-native");
    assert!(matches!(
        host.launch_bound_pod(&who.transport, request.clone()),
        Err(LaunchPodError::Host(HostError::NativeResolutionUnverified))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    let inspected = host.admit_bound_pod(&who.transport, request).unwrap();
    assert!(inspected.duplicate);
    assert_eq!(inspected.status.stage, LaunchDispatchStage::Prepared);
    assert!(!inspected.port_called);
}

#[test]
fn launch_admits_once_and_retries_return_original_receipt() {
    let fixture = Fixture::new();
    let who = identity();
    let (port, calls, effects) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, grant) = initial_authority(&fixture.database, port, &who);
    let request = launch_request(&who, grant, 1, 1, b"canonical.launch.one");
    let first = host
        .launch_bound_pod(&who.transport, request.clone())
        .unwrap();
    assert!(!first.duplicate);
    assert!(first.port_called);
    assert_eq!(first.status.stage, LaunchDispatchStage::HostAccepted);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    let reviewed = host.port().reviewed.lock().unwrap();
    assert_eq!(reviewed.len(), 1);
    assert_eq!(
        reviewed[0].effective().executable(),
        "/opt/podbay/bin/fake-agent"
    );
    assert_eq!(
        reviewed[0].effective().executable_generation(),
        "sha256.fakegeneration1"
    );
    assert_eq!(reviewed[0].effective().model_id(), "model.alpha");
    assert_eq!(
        reviewed[0].effective().arguments(),
        &["--managed", "--safe"]
    );
    assert_eq!(reviewed[0].effective().relative_cwd(), "src");
    assert!(reviewed[0].effective().credential_refs().is_empty());
    let effect_bytes = reviewed[0].descriptor_bytes().to_vec();
    let expected_digest = reviewed[0].descriptor().digest().to_owned();
    drop(reviewed);
    let store = PodBayStore::open(&fixture.database).unwrap();
    let stored = store
        .load_effect(
            first.receipt.outbox_id,
            who.scope.as_str(),
            who.pod.as_str(),
        )
        .unwrap();
    assert_eq!(stored.payload, effect_bytes);
    assert_eq!(
        ImmutableLaunchDescriptor::decode_json(&stored.payload)
            .unwrap()
            .digest(),
        expected_digest
    );
    assert!(
        !stored
            .payload
            .windows(b"vault.allowed.one".len())
            .any(|window| window == b"vault.allowed.one")
    );
    drop(store);
    let retry = host
        .launch_bound_pod(&who.transport, request.clone())
        .unwrap();
    assert!(retry.duplicate);
    assert!(!retry.port_called);
    assert_eq!(retry.receipt, first.receipt);
    assert_eq!(retry.status, first.status);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let mut changed = request;
    changed.canonical_request = b"changed.launch.body".to_vec();
    assert!(matches!(
        host.launch_bound_pod(&who.transport, changed),
        Err(LaunchPodError::Store(StoreError::Conflict(_)))
    ));
    let mut selection_changed = launch_request(&who, grant, 1, 1, b"canonical.launch.one");
    selection_changed
        .proposal
        .as_mut()
        .unwrap()
        .selection
        .model_id = Some("model.beta".into());
    assert_eq!(
        host.launch_bound_pod(&who.transport, selection_changed)
            .unwrap()
            .receipt,
        first.receipt
    );
    let mut workspace_changed = launch_request(&who, grant, 1, 1, b"canonical.launch.one");
    workspace_changed
        .proposal
        .as_mut()
        .unwrap()
        .selection
        .workspace
        .relative_cwd = "src/subdir".into();
    assert_eq!(
        host.launch_bound_pod(&who.transport, workspace_changed)
            .unwrap()
            .receipt,
        first.receipt
    );
    let mut arguments_changed = launch_request(&who, grant, 1, 1, b"canonical.launch.one");
    arguments_changed
        .proposal
        .as_mut()
        .unwrap()
        .selection
        .arguments = vec!["--verbose".into()];
    assert_eq!(
        host.launch_bound_pod(&who.transport, arguments_changed)
            .unwrap()
            .receipt,
        first.receipt
    );
    let mut revised_profile = profile_input(&who);
    revised_profile.profile_generation = 2;
    revised_profile.binary_generation = "sha256.fakegeneration2".into();
    revised_profile.executable = "/opt/podbay/bin/fake-agent-v2".into();
    host.register_launch_profile_from_trusted_policy(
        RegisteredLaunchProfile::from_trusted_policy(revised_profile).unwrap(),
    )
    .unwrap();
    let mut binary_changed = launch_request(&who, grant, 1, 1, b"canonical.launch.one");
    binary_changed
        .proposal
        .as_mut()
        .unwrap()
        .selection
        .profile_generation = 2;
    assert_eq!(
        host.launch_bound_pod(&who.transport, binary_changed)
            .unwrap()
            .receipt,
        first.receipt
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    host.revoke_grant_from_trusted_policy(grant).unwrap();
    let revoked_grant_retry = host
        .launch_bound_pod(
            &who.transport,
            launch_request(&who, grant, 1, 1, b"canonical.launch.one"),
        )
        .unwrap();
    assert!(revoked_grant_retry.duplicate);
    assert_eq!(revoked_grant_retry.receipt, first.receipt);
    assert!(!revoked_grant_retry.port_called);
    assert_eq!(
        host.dispatch(
            &who.transport,
            launch_request(&who, grant, 1, 1, b"canonical.launch.one").host_request,
        ),
        Err(HostError::Unsupported)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn different_key_cannot_launch_same_pod_incarnation_before_port() {
    let fixture = Fixture::new();
    let who = identity();
    let (port, calls, effects) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, grant) = initial_authority(&fixture.database, port, &who);
    let first = host
        .launch_bound_pod(
            &who.transport,
            launch_request(&who, grant, 1, 1, b"canonical.first"),
        )
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let mut second = launch_request(&who, grant, 1, 1, b"canonical.second");
    second.host_request.command_key = "launch.other-key".into();
    let duplicate_slot = host.launch_bound_pod(&who.transport, second);
    assert!(
        matches!(
            duplicate_slot,
            Err(LaunchPodError::Store(StoreError::Conflict(_)))
        ),
        "{duplicate_slot:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    let store = PodBayStore::open(&fixture.database).unwrap();
    assert_eq!(
        store
            .launch_dispatch_status(
                first.receipt.outbox_id,
                who.scope.as_str(),
                who.pod.as_str()
            )
            .unwrap()
            .stage,
        LaunchDispatchStage::HostAccepted
    );
    drop(store);
    host.advance_pod_incarnation_from_trusted_policy(
        &who.pod,
        PodIncarnation::new(1).unwrap(),
        PodIncarnation::new(2).unwrap(),
    )
    .unwrap();
    let mut next = launch_request(&who, grant, 1, 1, b"canonical.next-incarnation");
    next.host_request.command_key = "launch.next-incarnation".into();
    next.host_request.guards.pod_incarnation = PodIncarnation::new(2).unwrap();
    assert!(matches!(
        host.launch_bound_pod(&who.transport, next),
        Err(LaunchPodError::Host(HostError::StaleGuard))
            | Err(LaunchPodError::Host(HostError::Unauthorised))
    ));
    let old_key = host
        .launch_bound_pod(
            &who.transport,
            launch_request(&who, grant, 1, 1, b"canonical.first"),
        )
        .unwrap();
    assert!(old_key.duplicate);
    assert_eq!(old_key.receipt, first.receipt);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn prepared_intent_survives_restart_and_dispatches_once_after_replay() {
    let fixture = Fixture::new();
    let who = identity();
    let (first_port, first_calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut first, grant) = initial_authority(&fixture.database, first_port, &who);
    let original = launch_request(&who, grant, 1, 1, b"canonical.prepared");
    let persisted = first.admit_bound_pod(&who.transport, original).unwrap();
    assert_eq!(persisted.status.stage, LaunchDispatchStage::Prepared);
    assert!(!persisted.port_called);
    assert_eq!(first_calls.load(Ordering::SeqCst), 0);
    drop(first);

    let (second_port, second_calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let mut second = DurableAuthority::open(&fixture.database, second_port).unwrap();
    assert_eq!(second.owner_epoch().get(), 2);
    replay(&mut second, &who, grant);
    let inspected = second
        .launch_bound_pod(
            &who.transport,
            launch_request(&who, grant, 2, 1, b"canonical.prepared"),
        )
        .unwrap();
    assert!(inspected.duplicate);
    assert!(!inspected.port_called);
    assert_eq!(inspected.status.stage, LaunchDispatchStage::Prepared);
    assert_eq!(second_calls.load(Ordering::SeqCst), 0);
    let resumed = second
        .resume_prepared_bound_pod(
            &who.transport,
            launch_request(&who, grant, 2, 1, b"canonical.prepared"),
        )
        .unwrap();
    assert!(resumed.duplicate);
    assert!(resumed.port_called);
    assert_eq!(resumed.receipt, persisted.receipt);
    assert_eq!(resumed.status.stage, LaunchDispatchStage::HostAccepted);
    assert_eq!(second_calls.load(Ordering::SeqCst), 1);
    let replayed = second
        .launch_bound_pod(
            &who.transport,
            launch_request(&who, grant, 2, 1, b"canonical.prepared"),
        )
        .unwrap();
    assert!(!replayed.port_called);
    assert_eq!(second_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn lost_reply_remains_uncertain_across_manager_restart() {
    let fixture = Fixture::new();
    let who = identity();
    let (first_port, first_calls, first_effects) = FakeLaunchPort::new(Mode::LostReply);
    let (mut first, grant) = initial_authority(&fixture.database, first_port, &who);
    let first_result = first
        .launch_bound_pod(
            &who.transport,
            launch_request(&who, grant, 1, 1, b"canonical.uncertain"),
        )
        .unwrap();
    assert_eq!(
        first_result.status.stage,
        LaunchDispatchStage::UncertainAfterPossibleEffect
    );
    assert_eq!(first_calls.load(Ordering::SeqCst), 1);
    assert_eq!(first_effects.load(Ordering::SeqCst), 1);
    drop(first);

    let (second_port, second_calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let mut second = DurableAuthority::open(&fixture.database, second_port).unwrap();
    replay(&mut second, &who, grant);
    let replayed = second
        .launch_bound_pod(
            &who.transport,
            launch_request(&who, grant, 2, 1, b"canonical.uncertain"),
        )
        .unwrap();
    assert!(replayed.duplicate);
    assert!(!replayed.port_called);
    assert_eq!(replayed.receipt, first_result.receipt);
    assert_eq!(replayed.status, first_result.status);
    assert_eq!(second_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn refusal_is_recorded_and_second_manager_cannot_overlap_launch() {
    let fixture = Fixture::new();
    let who = identity();
    let (port, calls, effects) = FakeLaunchPort::new(Mode::Refused);
    let (mut first, grant) = initial_authority(&fixture.database, port, &who);
    assert!(matches!(
        DurableAuthority::open(&fixture.database, FakeLaunchPort::new(Mode::Accepted).0),
        Err(DurableAuthorityError::Busy)
    ));
    let result = first
        .launch_bound_pod(
            &who.transport,
            launch_request(&who, grant, 1, 1, b"canonical.refused"),
        )
        .unwrap();
    assert_eq!(
        result.status.stage,
        LaunchDispatchStage::RefusedBeforeEffect
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    let again = first
        .launch_bound_pod(
            &who.transport,
            launch_request(&who, grant, 1, 1, b"canonical.refused"),
        )
        .unwrap();
    assert!(!again.port_called);
    assert_eq!(again.status.stage, LaunchDispatchStage::RefusedBeforeEffect);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn port_settled_stage_does_not_claim_run_completion() {
    let fixture = Fixture::new();
    let who = identity();
    let (port, calls, effects) = FakeLaunchPort::new(Mode::Settled);
    let (mut host, grant) = initial_authority(&fixture.database, port, &who);
    let result = host
        .launch_bound_pod(
            &who.transport,
            launch_request(&who, grant, 1, 1, b"canonical.port-settled"),
        )
        .unwrap();
    assert_eq!(result.status.stage, LaunchDispatchStage::PortSettled);
    assert_eq!(
        result.status.receipt_ref.as_deref(),
        Some("receipt.launch.one")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(effects.load(Ordering::SeqCst), 1);
}

#[test]
fn profile_workspace_and_path_mismatch_refuse_before_admission() {
    let fixture = Fixture::new();
    let who = identity();
    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, grant) = initial_authority(&fixture.database, port, &who);
    let mut stale_profile = launch_request(&who, grant, 1, 1, b"canonical.profile");
    stale_profile
        .proposal
        .as_mut()
        .unwrap()
        .selection
        .profile_generation = 2;
    assert!(matches!(
        host.launch_bound_pod(&who.transport, stale_profile),
        Err(LaunchPodError::Host(HostError::Unauthorised))
    ));
    let mut sibling_scope = launch_request(&who, grant, 1, 1, b"canonical.profile");
    sibling_scope
        .proposal
        .as_mut()
        .unwrap()
        .selection
        .workspace
        .scope_id = ScopeId::try_from("scope.sibling").unwrap();
    assert!(matches!(
        host.launch_bound_pod(&who.transport, sibling_scope),
        Err(LaunchPodError::Host(HostError::Unauthorised))
    ));
    let mut drive_like_cwd = launch_request(&who, grant, 1, 1, b"canonical.profile");
    drive_like_cwd
        .proposal
        .as_mut()
        .unwrap()
        .selection
        .workspace
        .relative_cwd = "C:temp".into();
    assert!(matches!(
        host.launch_bound_pod(&who.transport, drive_like_cwd),
        Err(LaunchPodError::Host(HostError::Unauthorised))
    ));
    let mut relative_executable = profile_input(&who);
    relative_executable.executable = "bin/untrusted".into();
    assert!(matches!(
        RegisteredLaunchProfile::from_trusted_policy(relative_executable),
        Err(HostError::InvalidInput)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn coordinator_and_worker_use_same_reviewed_port_path() {
    let fixture = Fixture::new();
    let who = identity();
    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, grant) = initial_authority(&fixture.database, port, &who);
    host.launch_bound_pod(
        &who.transport,
        launch_request(&who, grant, 1, 1, b"canonical.worker"),
    )
    .unwrap();
    let coordinator_pod = PodId::try_from("pod.coordinator").unwrap();
    let coordinator_grant = host
        .install_grant_from_trusted_policy(
            &who.actor,
            GrantSpec {
                scope_id: who.scope.clone(),
                mode: GrantMode::Controller,
                rights: BTreeSet::from([Right::new(
                    Operation::LaunchPod,
                    Target::Pod(coordinator_pod.clone()),
                )]),
                remaining_delegation_depth: 0,
            },
        )
        .unwrap();
    let mut coordinator = launch_request(&who, coordinator_grant, 1, 1, b"canonical.coordinator");
    coordinator.host_request.command_key = "launch.coordinator".into();
    coordinator.host_request.action = HostAction::LaunchPod {
        pod_id: coordinator_pod.clone(),
        role: Role::Coordinator,
        credential: None,
    };
    coordinator.proposal = Some(bound_proposal(
        &who,
        &coordinator_pod,
        Role::Coordinator,
        coordinator.proposal.as_ref().unwrap().selection.clone(),
        None,
    ));
    host.launch_bound_pod(&who.transport, coordinator).unwrap();
    let reviewed = host.port().reviewed.lock().unwrap();
    assert_eq!(reviewed.len(), 2);
    assert_eq!(reviewed[0].effective().role(), NativeRole::Worker);
    assert_eq!(reviewed[1].effective().role(), NativeRole::Coordinator);
    assert_ne!(
        reviewed[0].effective().pod_id(),
        reviewed[1].effective().pod_id()
    );
    assert_eq!(
        reviewed[0].effective().executable(),
        reviewed[1].effective().executable()
    );
    assert_eq!(
        reviewed[0].effective().executable_generation(),
        reviewed[1].effective().executable_generation()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn only_selected_authorised_credential_reaches_effect_and_port() {
    let fixture = Fixture::new();
    let who = identity();
    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, grant) = initial_authority(&fixture.database, port, &who);
    let selected =
        CredentialRef::from_trusted_vault(who.scope.clone(), "vault.allowed.one").unwrap();
    let mut denied = launch_request(&who, grant, 1, 1, b"canonical.credential");
    denied.host_request.action = HostAction::LaunchPod {
        pod_id: who.pod.clone(),
        role: Role::Worker,
        credential: Some(selected.clone()),
    };
    assert!(matches!(
        host.launch_bound_pod(&who.transport, denied),
        Err(LaunchPodError::Host(HostError::Unauthorised))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let credential_grant = host
        .install_grant_from_trusted_policy(
            &who.actor,
            GrantSpec {
                scope_id: who.scope.clone(),
                mode: GrantMode::Controller,
                rights: BTreeSet::from([
                    Right::new(Operation::LaunchPod, Target::Pod(who.pod.clone())),
                    Right::new(
                        Operation::UseCredential,
                        Target::Credential(selected.clone()),
                    ),
                ]),
                remaining_delegation_depth: 0,
            },
        )
        .unwrap();
    let mut request = launch_request(&who, credential_grant, 1, 1, b"canonical.credential");
    request.host_request.action = HostAction::LaunchPod {
        pod_id: who.pod.clone(),
        role: Role::Worker,
        credential: Some(selected.clone()),
    };
    request
        .proposal
        .as_mut()
        .unwrap()
        .native_policy
        .credential_refs = vec![selected.as_str().to_owned()];
    let receipt = host.launch_bound_pod(&who.transport, request).unwrap();
    let reviewed = host.port().reviewed.lock().unwrap();
    assert_eq!(reviewed.len(), 1);
    assert_eq!(reviewed[0].effective().credential_refs().len(), 1);
    assert_eq!(
        reviewed[0].effective().credential_refs()[0].scope_id(),
        &who.scope
    );
    assert_eq!(
        reviewed[0].effective().credential_refs()[0].reference(),
        selected.as_str()
    );
    drop(reviewed);
    let store = PodBayStore::open(&fixture.database).unwrap();
    let effect = store
        .load_effect(
            receipt.receipt.outbox_id,
            who.scope.as_str(),
            who.pod.as_str(),
        )
        .unwrap();
    assert!(
        !effect
            .payload
            .windows(b"vault.allowed.two".len())
            .any(|window| window == b"vault.allowed.two")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn committed_claim_without_port_result_is_not_replayed() {
    let fixture = Fixture::new();
    let who = identity();
    let (first_port, first_calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut first, grant) = initial_authority(&fixture.database, first_port, &who);
    let admitted = first
        .admit_bound_pod(
            &who.transport,
            launch_request(&who, grant, 1, 1, b"canonical.claim-crash"),
        )
        .unwrap();
    assert_eq!(first_calls.load(Ordering::SeqCst), 0);
    drop(first);

    // This is the crash window after the claim commits but before a port call
    // or outcome write. Recovery cannot infer that the effect did not happen.
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let current_authority_revision = store.authority_snapshot().unwrap().revision;
    assert_eq!(
        store
            .claim_effect(
                admitted.receipt.outbox_id,
                who.scope.as_str(),
                who.pod.as_str(),
                1,
                1,
                current_authority_revision,
                &format!("claim.{}", admitted.receipt.command_id),
            )
            .unwrap(),
        EffectClaim::NewClaim
    );
    drop(store);

    let (second_port, second_calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let mut second = DurableAuthority::open(&fixture.database, second_port).unwrap();
    replay(&mut second, &who, grant);
    let recovered = second
        .launch_bound_pod(
            &who.transport,
            launch_request(&who, grant, 2, 1, b"canonical.claim-crash"),
        )
        .unwrap();
    assert!(recovered.duplicate);
    assert!(!recovered.port_called);
    assert_eq!(
        recovered.status.stage,
        LaunchDispatchStage::ClaimedUncertain
    );
    assert_eq!(second_calls.load(Ordering::SeqCst), 0);
}
