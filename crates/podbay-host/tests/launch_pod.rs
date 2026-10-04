use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
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
    CredentialGeneration, CredentialRef, DurableAuthority, DurableAuthorityError, ExecutionMode,
    GrantId, GrantMode, GrantSpec, GuardSet, HostAction, HostDispatchPort, HostError, HostRequest,
    LaunchPodError, LaunchSelection, ManagerEpoch, Operation, PodIncarnation, PortDispatchError,
    PortDispatchOutcome, PortReceiptRef, RebindContextError, RegisteredLaunchProfile,
    ResolvedNativeCodexLaunch, ResolvedNativeLaunch, Right, Target, TrustedDriverTemplate,
    TrustedLaunchProfileInput, TrustedNativeHostConfig, TrustedWireRootLaunchPolicy,
    WorkspaceAccess, WorkspaceSelection,
};
use podbay_store::{
    BoundLaunchFormat, EffectClaim, LaunchDispatchStage, LaunchLookupRequest, PodBayStore,
    StoreError, VerifiedPrincipal,
};
use podbay_wire::{
    CodexAppServerPolicyV2, CommandBody, CommandEnvelope, ContentBlock, DecimalString,
    FallbackPolicy, Guard as WireGuard, ImmutableLaunchDescriptor, LaunchBody, LaunchLimits,
    LaunchRole, LaunchSelection as WireLaunchSelection, LaunchWork, NativeRole, RequestedAuthority,
    ResourceDriver, SessionChoice, Target as WireTarget, TargetOs, WorkKind as WireWorkKind,
    WorkspaceAccess as WireWorkspaceAccess, WorkspaceBinding,
};
use sha2::{Digest, Sha256};

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

struct ResolvedManagerSeen {
    store_path: PathBuf,
    claim: (String, u64, u64),
    peer: podbay_core::AttestedPeer,
    inputs: std::collections::BTreeMap<String, u64>,
    outbox_id: i64,
    descriptor: Vec<u8>,
    effective: Vec<u8>,
}

struct FakeLaunchPort {
    mode: Arc<AtomicU8>,
    port_calls: Arc<AtomicUsize>,
    possible_effects: Arc<AtomicUsize>,
    reviewed: Mutex<Vec<AuthorisedBoundLaunch>>,
    fixture_opt_in: bool,
    resolved_opt_in: bool,
    codex_v2_opt_in: bool,
    resolved_seen: Mutex<Vec<(PathBuf, PathBuf, String)>>,
    manager_seen: Mutex<Vec<ResolvedManagerSeen>>,
    preclaim_change: Mutex<Option<(PathBuf, bool)>>,
    preclaim_replace: Mutex<Option<PathBuf>>,
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
                resolved_opt_in: false,
                codex_v2_opt_in: false,
                resolved_seen: Mutex::new(Vec::new()),
                manager_seen: Mutex::new(Vec::new()),
                preclaim_change: Mutex::new(None),
                preclaim_replace: Mutex::new(None),
            },
            port_calls,
            possible_effects,
        )
    }

    fn without_fixture_opt_in(mut self) -> Self {
        self.fixture_opt_in = false;
        self
    }

    fn resolved_only(mut self) -> Self {
        self.fixture_opt_in = false;
        self.resolved_opt_in = true;
        self
    }

    fn codex_v2(mut self) -> Self {
        self.codex_v2_opt_in = true;
        self
    }
}

impl HostDispatchPort for FakeLaunchPort {
    type Receipt = PortReceiptRef;

    fn allow_unverified_native_launch_for_fixture(&self) -> bool {
        self.fixture_opt_in
    }

    fn accepts_resolved_native_launch(&self) -> bool {
        if let Some(path) = self.preclaim_replace.lock().unwrap().take() {
            let original = path.with_extension("original");
            std::fs::rename(&path, &original).unwrap();
            std::fs::copy(&original, &path).unwrap();
        }
        if let Some((path, replay)) = self.preclaim_change.lock().unwrap().take() {
            let mut other = PodBayStore::open(path).unwrap();
            let snapshot = other.authority_snapshot().unwrap();
            if replay {
                other
                    .begin_authority_replay(snapshot.owner_epoch, snapshot.owner_epoch + 1)
                    .unwrap();
            } else {
                let mut resource = snapshot.resources[0].clone();
                resource.input_epoch += 1;
                other
                    .apply_authority_mutation(
                        snapshot.owner_epoch,
                        snapshot.revision,
                        podbay_store::AuthorityMutation::PutResource(resource),
                    )
                    .unwrap();
            }
        }
        self.resolved_opt_in
    }

    fn accepts_resolved_codex_v2(&self) -> bool {
        self.codex_v2_opt_in
    }

    fn launch_resolved_codex_v2(
        &mut self,
        launch: ResolvedNativeCodexLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        assert!(self.codex_v2_opt_in);
        assert_eq!(launch.committed_record().format, BoundLaunchFormat::CodexV2);
        assert_eq!(
            launch.descriptor_bytes(),
            launch.committed_record().descriptor
        );
        assert_eq!(
            launch.effective_spec_bytes(),
            launch.committed_record().effective_spec
        );
        self.port_calls.fetch_add(1, Ordering::SeqCst);
        let receipt = PortReceiptRef::from_port("receipt.codex.v2").unwrap();
        match self.mode.load(Ordering::SeqCst) {
            1 => Err(PortDispatchError::RefusedBeforeEffect),
            2 => {
                self.possible_effects.fetch_add(1, Ordering::SeqCst);
                Err(PortDispatchError::UncertainAfterPossibleEffect {
                    receipt_ref: Some(receipt),
                })
            }
            3 => {
                self.possible_effects.fetch_add(1, Ordering::SeqCst);
                Ok(PortDispatchOutcome::Settled(receipt))
            }
            _ => {
                self.possible_effects.fetch_add(1, Ordering::SeqCst);
                Ok(PortDispatchOutcome::Accepted(receipt))
            }
        }
    }

    fn launch_resolved(
        &mut self,
        launch: ResolvedNativeLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        self.manager_seen.lock().unwrap().push(ResolvedManagerSeen {
            store_path: launch.store_path().to_path_buf(),
            claim: (
                launch.store_lineage().to_owned(),
                launch.owner_epoch(),
                launch.credential_epoch(),
            ),
            peer: launch.manager_peer().clone(),
            inputs: launch.resource_input_epochs().clone(),
            outbox_id: launch.outbox_id(),
            descriptor: launch.descriptor_bytes().to_vec(),
            effective: launch.effective_spec_bytes().to_vec(),
        });
        self.resolved_seen.lock().unwrap().push((
            launch.cwd().to_path_buf(),
            launch.executable().to_path_buf(),
            launch.executable_sha256().to_owned(),
        ));
        self.port_calls.fetch_add(1, Ordering::SeqCst);
        Ok(PortDispatchOutcome::Accepted(
            PortReceiptRef::from_port("receipt.resolved.one").unwrap(),
        ))
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
    workspace_root: PathBuf,
    executable: PathBuf,
    executable_sha256: String,
}

fn identity(fixture: &Fixture) -> Identity {
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
    let workspace_root = fixture.directory.join("workspace");
    std::fs::create_dir_all(workspace_root.join("src")).unwrap();
    let executable = fixture.directory.join("agent.sh");
    let content = b"#!/bin/sh\nexit 0\n";
    std::fs::write(&executable, content).unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let executable_sha256 = Sha256::digest(content)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Identity {
        scope,
        pod,
        actor,
        process,
        transport,
        workspace_root,
        executable,
        executable_sha256,
    }
}

fn profile_input(who: &Identity) -> TrustedLaunchProfileInput {
    TrustedLaunchProfileInput {
        profile_ref: "profile.fixture".into(),
        profile_generation: 1,
        executable: who.executable.to_string_lossy().into_owned(),
        binary_generation: format!("sha256:{}", who.executable_sha256),
        executable_sha256: who.executable_sha256.clone(),
        workspace_root: who.workspace_root.clone(),
        resource_layout: vec![
            TrustedDriverTemplate {
                kind: ResourceKind::Pty,
                driver: ResourceDriver::Pty {
                    rows: 24,
                    columns: 80,
                    retention_events: 100,
                },
            },
            TrustedDriverTemplate {
                kind: ResourceKind::StructuredProvider,
                driver: ResourceDriver::Structured {
                    driver_ref: "driver.fixture".into(),
                    protocol_ref: "protocol.fixture".into(),
                },
            },
        ],
        execution_mode: ExecutionMode::LinuxCooperative,
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

fn codex_profile_input(who: &Identity) -> TrustedLaunchProfileInput {
    let mut input = profile_input(who);
    input.profile_generation = 2;
    input.default_model = "gpt-6-sol".into();
    input.allowed_models = BTreeSet::from(["gpt-6-sol".into()]);
    input.allowed_efforts = BTreeSet::from(["medium".into()]);
    input.resource_layout.remove(0);
    input.credential_refs.truncate(1);
    input
}

fn codex_policy(who: &Identity) -> CodexAppServerPolicyV2 {
    CodexAppServerPolicyV2::new(
        &who.scope,
        "vault.allowed.one".into(),
        "driver.fixture".into(),
        "protocol.fixture".into(),
    )
    .unwrap()
}

fn profile(who: &Identity) -> RegisteredLaunchProfile {
    RegisteredLaunchProfile::from_trusted_policy(profile_input(who)).unwrap()
}

fn native_host_config() -> TrustedNativeHostConfig {
    TrustedNativeHostConfig::for_compiled_backend("host.fixture".into())
        .unwrap()
        .with_structured_driver("driver.fixture".into(), "protocol.fixture".into())
        .unwrap()
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
    host.register_native_host_from_trusted_policy(native_host_config())
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
    host.register_native_host_from_trusted_policy(native_host_config())
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
        proposal: Some(bound_proposal(who, &who.pod, Role::Worker, selection)),
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
) -> BoundHostLaunchProposal {
    bound_proposal_with_resources(
        who,
        pod_id,
        role,
        selection,
        &[ResourceKind::Pty, ResourceKind::StructuredProvider],
        false,
    )
}

fn bound_codex_root_proposal(
    who: &Identity,
    pod_id: &PodId,
    role: Role,
    selection: LaunchSelection,
) -> BoundHostLaunchProposal {
    bound_proposal_with_resources(
        who,
        pod_id,
        role,
        selection,
        &[ResourceKind::StructuredProvider],
        true,
    )
}

fn bound_proposal_with_resources(
    who: &Identity,
    pod_id: &PodId,
    role: Role,
    selection: LaunchSelection,
    resource_kinds: &[ResourceKind],
    planned_root: bool,
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
    if !planned_root {
        run.admit(
            run.revision(),
            &CommandId::try_from("command.fixture").unwrap(),
            &Admitted,
        )
        .unwrap();
    }
    session.bind_run(session.revision(), &run).unwrap();
    let mut attempt = Attempt::new(
        AttemptId::try_from(format!("attempt.{}", pod_id.as_str())).unwrap(),
        run.id().clone(),
        1,
        Epoch::new(1).unwrap(),
    )
    .unwrap();
    if !planned_root {
        run.start_attempt(run.revision(), &attempt).unwrap();
    }
    let mut pod = Pod::new(pod_id.clone(), attempt.id().clone(), Epoch::new(1).unwrap());
    attempt.attach_pod(attempt.revision(), &pod).unwrap();
    let resources = resource_kinds
        .iter()
        .map(|kind| {
            let label = match kind {
                ResourceKind::Pty => "pty",
                ResourceKind::StructuredProvider => "provider",
                ResourceKind::Auxiliary => "auxiliary",
            };
            Resource::new(
                ResourceId::try_from(format!("resource.{label}.{}", pod_id.as_str())).unwrap(),
                pod.id().clone(),
                *kind,
                Epoch::new(1).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    for resource in &resources {
        pod.attach_resource(pod.revision(), resource).unwrap();
    }
    let binding = if planned_root {
        LaunchBinding::plan_first_root(&session, &run, &attempt, &pod, &resources)
            .unwrap()
            .identity()
            .clone()
    } else {
        LaunchBinding::from_aggregates(&session, &run, &attempt, &pod, &resources).unwrap()
    };
    BoundHostLaunchProposal {
        session,
        run,
        binding,
        selection,
    }
}

fn assert_command_not_admitted(fixture: &Fixture, who: &Identity, request: &BoundLaunchPodRequest) {
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let result = store
        .lookup_bound_launch(&LaunchLookupRequest {
            principal: VerifiedPrincipal::from_authenticated_boundary(who.actor.as_str()).unwrap(),
            namespace: "podbay.launch".into(),
            command_key: request.host_request.command_key.clone(),
            scope_id: who.scope.as_str().into(),
            target_id: who.pod.as_str().into(),
            canonical_intent: request.canonical_request.clone(),
        })
        .unwrap();
    assert!(result.is_none());
}

fn install_codex_root_policy(
    host: &mut DurableAuthority<FakeLaunchPort>,
    who: &Identity,
) -> GrantId {
    install_codex_root_policy_with_input(host, who, codex_profile_input(who))
}

fn install_codex_root_policy_with_input(
    host: &mut DurableAuthority<FakeLaunchPort>,
    who: &Identity,
    input: TrustedLaunchProfileInput,
) -> GrantId {
    let codex = RegisteredLaunchProfile::from_trusted_policy(input)
        .unwrap()
        .with_codex_policy_from_trusted_policy(codex_policy(who))
        .unwrap();
    host.register_launch_profile_from_trusted_policy(codex)
        .unwrap();
    let credential =
        CredentialRef::from_trusted_vault(who.scope.clone(), "vault.allowed.one").unwrap();
    host.install_grant_from_trusted_policy(
        &who.actor,
        GrantSpec {
            scope_id: who.scope.clone(),
            mode: GrantMode::Controller,
            rights: BTreeSet::from([
                Right::new(Operation::LaunchPod, Target::Pod(who.pod.clone())),
                Right::new(Operation::UseCredential, Target::Credential(credential)),
            ]),
            remaining_delegation_depth: 0,
        },
    )
    .unwrap()
}

fn codex_root_request(
    who: &Identity,
    grant: GrantId,
    role: Role,
    body: &[u8],
) -> BoundLaunchPodRequest {
    let mut request = launch_request(who, grant, 1, 1, body);
    request.host_request.command_key = format!("launch.codex.{}", who.pod.as_str());
    request.host_request.action = HostAction::LaunchPod {
        pod_id: who.pod.clone(),
        role,
        credential: Some(
            CredentialRef::from_trusted_vault(who.scope.clone(), "vault.allowed.one").unwrap(),
        ),
    };
    let mut selection = request.proposal.as_ref().unwrap().selection.clone();
    selection.profile_generation = 2;
    selection.model_id = Some("gpt-6-sol".into());
    request.proposal = Some(bound_codex_root_proposal(who, &who.pod, role, selection));
    request
}

fn wire_root_body(grant: GrantId, model: &str) -> LaunchBody {
    LaunchBody {
        session: SessionChoice::New,
        role: LaunchRole::Coordinator,
        work: LaunchWork {
            kind: WireWorkKind::Service,
            input: None,
            task_ref: None,
            result_contract_ref: "result.none".into(),
        },
        parent_run_id: None,
        profile_ref: "profile.fixture".into(),
        selection: WireLaunchSelection {
            model_id: Some(model.into()),
            reasoning_effort: Some("medium".into()),
            fallback: FallbackPolicy::None,
        },
        workspace: WorkspaceBinding {
            scope_id: "scope.launch".into(),
            relative_cwd: ".".into(),
            basis_ref: Some("basis.commit.one".into()),
            access: WireWorkspaceAccess::ReadWrite,
        },
        tool_bundle_refs: Vec::new(),
        authority: RequestedAuthority {
            grant_ref: format!("grant.{}", grant.get()),
        },
        limits: LaunchLimits {
            wall_seconds: DecimalString::new(60),
            max_children: DecimalString::new(1),
        },
    }
}

fn wire_root_request(id: &str, key: &str, body: LaunchBody) -> CommandEnvelope {
    CommandEnvelope::new(
        id,
        key,
        WireTarget::Scope {
            scope_id: "scope.launch".into(),
        },
        None,
        None,
        CommandBody::Launch(body),
    )
    .unwrap()
}

fn install_wire_root_policy(
    host: &mut DurableAuthority<FakeLaunchPort>,
    who: &Identity,
) -> (GrantId, TrustedWireRootLaunchPolicy) {
    host.register_launch_profile_from_trusted_policy(
        RegisteredLaunchProfile::from_trusted_policy(codex_profile_input(who))
            .unwrap()
            .with_codex_policy_from_trusted_policy(codex_policy(who))
            .unwrap(),
    )
    .unwrap();
    let credential =
        CredentialRef::from_trusted_vault(who.scope.clone(), "vault.allowed.one").unwrap();
    let grant = host
        .install_grant_from_trusted_policy(
            &who.actor,
            GrantSpec {
                scope_id: who.scope.clone(),
                mode: GrantMode::Controller,
                rights: BTreeSet::from([
                    Right::new(Operation::LaunchPod, Target::Scope(who.scope.clone())),
                    Right::new(Operation::UseCredential, Target::Credential(credential)),
                ]),
                remaining_delegation_depth: 0,
            },
        )
        .unwrap();
    let policy = TrustedWireRootLaunchPolicy::from_trusted_policy(
        grant,
        Instant::now() + Duration::from_secs(30),
        "result.none",
    )
    .unwrap();
    (grant, policy)
}

#[test]
fn wire_root_planner_admits_once_and_reads_duplicate_before_new_ids() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, calls, effects) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, _) = initial_authority(&fixture.database, port.codex_v2(), &who);
    let (grant, policy) = install_wire_root_policy(&mut host, &who);
    let first_wire = wire_root_request(
        "request.wire.first",
        "key.wire.root",
        wire_root_body(grant, "gpt-6-sol"),
    );
    let first = host
        .launch_new_root_codex_v2_from_wire(&who.transport, first_wire.clone(), &policy)
        .unwrap();
    assert_eq!(first.status.stage, LaunchDispatchStage::HostAccepted);
    assert!(first.port_called);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    assert_eq!(host.recorded_snapshot().pods.len(), 1);
    let minted_pod = &host.recorded_snapshot().pods[0].pod_id;
    assert!(minted_pod.starts_with("pod."));
    assert_ne!(minted_pod, who.pod.as_str());
    let duplicated = wire_root_request(
        "request.wire.second",
        "key.wire.root",
        wire_root_body(grant, "gpt-6-sol"),
    );
    assert_eq!(first_wire.payload_digest, duplicated.payload_digest);
    assert_ne!(first_wire.request_id, duplicated.request_id);
    let again = host
        .launch_new_root_codex_v2_from_wire(&who.transport, duplicated, &policy)
        .unwrap();
    assert!(again.duplicate);
    assert!(!again.port_called);
    assert_eq!(again.receipt, first.receipt);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(host.recorded_snapshot().pods.len(), 1);
    let stale_transport = FakeTransport(AuthenticatedPeer::owner_cli_from_authenticated_transport(
        who.process.clone(),
        CredentialGeneration::new(2).unwrap(),
    ));
    assert!(matches!(
        host.launch_new_root_codex_v2_from_wire(
            &stale_transport,
            wire_root_request(
                "request.stale.actor",
                "key.wire.root",
                wire_root_body(grant, "gpt-6-sol")
            ),
            &policy,
        ),
        Err(LaunchPodError::Host(HostError::Unauthenticated))
    ));
    let changed = wire_root_request(
        "request.wire.changed",
        "key.wire.root",
        wire_root_body(grant, "model.other"),
    );
    assert!(matches!(
        host.launch_new_root_codex_v2_from_wire(&who.transport, changed, &policy),
        Err(LaunchPodError::Store(StoreError::Conflict(_)))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(host.recorded_snapshot().pods.len(), 1);
}

#[test]
fn wire_root_planner_refuses_unsupported_shapes_and_untrusted_grants() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, _) = initial_authority(&fixture.database, port.codex_v2(), &who);
    let (grant, policy) = install_wire_root_policy(&mut host, &who);
    for (index, mutation) in [(0, "session"), (1, "parent"), (2, "worker"), (3, "input")] {
        let mut body = wire_root_body(grant, "gpt-6-sol");
        match mutation {
            "session" => {
                body.session = SessionChoice::Existing {
                    session_id: "session.other".into(),
                }
            }
            "parent" => body.parent_run_id = Some("run.parent".into()),
            "worker" => body.role = LaunchRole::Worker,
            "input" => {
                body.work.input = Some(vec![ContentBlock::Text {
                    text: "ignored".into(),
                }])
            }
            _ => unreachable!(),
        }
        let wire = wire_root_request(
            &format!("request.unsupported.{index}"),
            &format!("key.unsupported.{index}"),
            body,
        );
        assert!(matches!(
            host.launch_new_root_codex_v2_from_wire(&who.transport, wire, &policy),
            Err(LaunchPodError::Host(HostError::Unsupported))
        ));
    }
    let mut wrong_alias = wire_root_body(grant, "gpt-6-sol");
    wrong_alias.authority.grant_ref = "grant.99999".into();
    assert!(matches!(
        host.launch_new_root_codex_v2_from_wire(
            &who.transport,
            wire_root_request("request.alias", "key.alias", wrong_alias),
            &policy,
        ),
        Err(LaunchPodError::Host(HostError::Unauthorised))
    ));
    let foreign = CommandEnvelope::new(
        "request.foreign.scope",
        "key.foreign.scope",
        WireTarget::Scope {
            scope_id: "scope.foreign".into(),
        },
        None,
        None,
        CommandBody::Launch(wire_root_body(grant, "gpt-6-sol")),
    )
    .unwrap();
    assert!(matches!(
        host.launch_new_root_codex_v2_from_wire(&who.transport, foreign, &policy),
        Err(LaunchPodError::Host(HostError::Unauthorised))
    ));
    let explicit_utc = CommandEnvelope::new(
        "request.utc.deadline",
        "key.utc.deadline",
        WireTarget::Scope {
            scope_id: who.scope.as_str().into(),
        },
        None,
        Some("2099-01-01T00:00:00Z".into()),
        CommandBody::Launch(wire_root_body(grant, "gpt-6-sol")),
    )
    .unwrap();
    assert!(matches!(
        host.launch_new_root_codex_v2_from_wire(&who.transport, explicit_utc, &policy),
        Err(LaunchPodError::Host(HostError::Unsupported))
    ));
    let stale_guard = CommandEnvelope::new(
        "request.stale.guard",
        "key.stale.guard",
        WireTarget::Scope {
            scope_id: who.scope.as_str().into(),
        },
        Some(WireGuard {
            manager_epoch: Some(DecimalString::new(2)),
            ..WireGuard::default()
        }),
        None,
        CommandBody::Launch(wire_root_body(grant, "gpt-6-sol")),
    )
    .unwrap();
    assert!(matches!(
        host.launch_new_root_codex_v2_from_wire(&who.transport, stale_guard, &policy),
        Err(LaunchPodError::Host(HostError::StaleGuard))
    ));
    let scope_only = host
        .install_grant_from_trusted_policy(
            &who.actor,
            GrantSpec {
                scope_id: who.scope.clone(),
                mode: GrantMode::Controller,
                rights: BTreeSet::from([Right::new(
                    Operation::LaunchPod,
                    Target::Scope(who.scope.clone()),
                )]),
                remaining_delegation_depth: 0,
            },
        )
        .unwrap();
    let no_credential_policy = TrustedWireRootLaunchPolicy::from_trusted_policy(
        scope_only,
        Instant::now() + Duration::from_secs(30),
        "result.none",
    )
    .unwrap();
    assert!(matches!(
        host.launch_new_root_codex_v2_from_wire(
            &who.transport,
            wire_root_request(
                "request.no.credential",
                "key.no.credential",
                wire_root_body(scope_only, "gpt-6-sol")
            ),
            &no_credential_policy,
        ),
        Err(LaunchPodError::Host(HostError::Unauthorised))
    ));
    assert!(host.recorded_snapshot().pods.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn wire_root_planner_returns_committed_receipt_when_dispatch_cannot_start() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, _) = initial_authority(&fixture.database, port, &who);
    let (grant, policy) = install_wire_root_policy(&mut host, &who);
    let request = wire_root_request(
        "request.prepared",
        "key.prepared",
        wire_root_body(grant, "gpt-6-sol"),
    );
    let prepared = host
        .launch_new_root_codex_v2_from_wire(&who.transport, request.clone(), &policy)
        .unwrap();
    assert_eq!(prepared.status.stage, LaunchDispatchStage::Prepared);
    assert!(!prepared.port_called);
    assert!(!prepared.receipt.command_id.is_empty());
    let duplicate = host
        .launch_new_root_codex_v2_from_wire(
            &who.transport,
            wire_root_request(
                "request.prepared.retry",
                "key.prepared",
                wire_root_body(grant, "gpt-6-sol"),
            ),
            &policy,
        )
        .unwrap();
    assert_eq!(duplicate.receipt, prepared.receipt);
    assert!(duplicate.duplicate);
    assert!(!duplicate.port_called);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn wire_root_planner_keeps_uncertain_dispatch_and_original_receipt() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, calls, effects) = FakeLaunchPort::new(Mode::LostReply);
    let (mut host, _) = initial_authority(&fixture.database, port.codex_v2(), &who);
    let (grant, policy) = install_wire_root_policy(&mut host, &who);
    let first = host
        .launch_new_root_codex_v2_from_wire(
            &who.transport,
            wire_root_request(
                "request.uncertain",
                "key.uncertain",
                wire_root_body(grant, "gpt-6-sol"),
            ),
            &policy,
        )
        .unwrap();
    assert_eq!(
        first.status.stage,
        LaunchDispatchStage::UncertainAfterPossibleEffect
    );
    assert!(first.port_called);
    let duplicate = host
        .launch_new_root_codex_v2_from_wire(
            &who.transport,
            wire_root_request(
                "request.uncertain.retry",
                "key.uncertain",
                wire_root_body(grant, "gpt-6-sol"),
            ),
            &policy,
        )
        .unwrap();
    assert_eq!(duplicate.receipt, first.receipt);
    assert_eq!(duplicate.status, first.status);
    assert!(!duplicate.port_called);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(effects.load(Ordering::SeqCst), 1);
}

#[test]
fn codex_v2_root_coordinator_and_root_worker_commit_without_port_effect() {
    for role in [Role::Coordinator, Role::Worker] {
        let fixture = Fixture::new();
        let who = identity(&fixture);
        let (port, calls, effects) = FakeLaunchPort::new(Mode::Accepted);
        let (mut host, _) = initial_authority(&fixture.database, port, &who);
        let grant = install_codex_root_policy(&mut host, &who);
        let request = codex_root_request(&who, grant, role, b"canonical.codex-v2-root");
        let receipt = host
            .admit_bound_root_codex_v2(&who.transport, request.clone())
            .unwrap();
        assert_eq!(receipt.status.stage, LaunchDispatchStage::Prepared);
        assert!(!receipt.duplicate);
        assert!(!receipt.port_called);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(effects.load(Ordering::SeqCst), 0);
        let mut store = PodBayStore::open(&fixture.database).unwrap();
        let record = store
            .lookup_bound_launch(&LaunchLookupRequest {
                principal: VerifiedPrincipal::from_authenticated_boundary(who.actor.as_str())
                    .unwrap(),
                namespace: "podbay.launch".into(),
                command_key: request.host_request.command_key.clone(),
                scope_id: who.scope.as_str().into(),
                target_id: who.pod.as_str().into(),
                canonical_intent: request.canonical_request.clone(),
            })
            .unwrap()
            .unwrap();
        assert_eq!(record.format, BoundLaunchFormat::CodexV2);
        assert_eq!(record.resources.len(), 1);
        let effective =
            podbay_wire::EffectiveLaunchContractV2::decode(&record.effective_spec).unwrap();
        let descriptor =
            podbay_wire::ImmutableLaunchDescriptorV2::decode_json(&record.descriptor).unwrap();
        effective.compare_with_descriptor(&descriptor).unwrap();
        assert_eq!(effective.base().model_id(), "gpt-6-sol");
        assert_eq!(effective.base().reasoning_effort(), "medium");
        assert_eq!(effective.codex_policy(), &codex_policy(&who));
        assert_eq!(descriptor.host_id(), "host.fixture");
        assert_eq!(descriptor.resources_len(), 1);
        assert_eq!(descriptor.role(), NativeRole::from(role));

        assert_eq!(
            host.lookup_bound_root_codex_v2_by_key(
                &who.transport,
                &who.scope,
                &request.host_request.command_key,
                &request.canonical_request,
            )
            .unwrap(),
            Some(record.clone())
        );
        assert_eq!(
            host.lookup_bound_root_codex_v2_by_key(
                &who.transport,
                &who.scope,
                "key.absent",
                b"new.intent",
            )
            .unwrap(),
            None
        );
        assert!(matches!(
            host.lookup_bound_root_codex_v2_by_key(
                &who.transport,
                &who.scope,
                &request.host_request.command_key,
                b"changed.intent",
            ),
            Err(LaunchPodError::Store(StoreError::Conflict(_)))
        ));

        // The same authenticated caller can inspect the exact original after
        // profile/grant changes, without re-running native review or the port.
        host.revoke_grant_from_trusted_policy(grant).unwrap();
        assert_eq!(
            host.lookup_bound_root_codex_v2_by_key(
                &who.transport,
                &who.scope,
                &request.host_request.command_key,
                &request.canonical_request,
            )
            .unwrap(),
            Some(record.clone())
        );
        let mut duplicate = request.clone();
        duplicate.proposal = None;
        let retried = host
            .admit_bound_root_codex_v2(&who.transport, duplicate)
            .unwrap();
        assert!(retried.duplicate);
        assert_eq!(retried.receipt, receipt.receipt);
        assert!(!retried.port_called);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(matches!(
            host.admit_bound_pod(&who.transport, request),
            Err(LaunchPodError::Host(HostError::Unauthorised))
        ));
        assert!(matches!(
            host.resume_prepared_bound_pod(
                &who.transport,
                codex_root_request(&who, grant, role, b"canonical.codex-v2-root")
            ),
            Err(LaunchPodError::Host(HostError::Unauthorised))
        ));
    }
}

#[test]
fn scope_launch_grant_admits_new_pod_and_replays_original_receipt() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, calls, effects) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, _) = initial_authority(&fixture.database, port, &who);
    install_codex_root_policy(&mut host, &who);
    let credential =
        CredentialRef::from_trusted_vault(who.scope.clone(), "vault.allowed.one").unwrap();
    let scoped = host
        .install_grant_from_trusted_policy(
            &who.actor,
            GrantSpec {
                scope_id: who.scope.clone(),
                mode: GrantMode::Controller,
                rights: BTreeSet::from([
                    Right::new(Operation::LaunchPod, Target::Scope(who.scope.clone())),
                    Right::new(Operation::UseCredential, Target::Credential(credential)),
                ]),
                remaining_delegation_depth: 0,
            },
        )
        .unwrap();
    let launch_only = host
        .install_grant_from_trusted_policy(
            &who.actor,
            GrantSpec {
                scope_id: who.scope.clone(),
                mode: GrantMode::Controller,
                rights: BTreeSet::from([Right::new(
                    Operation::LaunchPod,
                    Target::Scope(who.scope.clone()),
                )]),
                remaining_delegation_depth: 0,
            },
        )
        .unwrap();
    let missing_credential = codex_root_request(
        &who,
        launch_only,
        Role::Coordinator,
        b"scope.missing.credential",
    );
    assert!(matches!(
        host.admit_bound_root_codex_v2(&who.transport, missing_credential.clone()),
        Err(LaunchPodError::Host(HostError::Unauthorised))
    ));
    assert_command_not_admitted(&fixture, &who, &missing_credential);
    assert!(host.recorded_snapshot().pods.is_empty());
    drop(host);
    let (port, reopened_calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let mut reopened = DurableAuthority::open(&fixture.database, port).unwrap();
    replay(&mut reopened, &who, scoped);
    reopened
        .register_launch_profile_from_trusted_policy(
            RegisteredLaunchProfile::from_trusted_policy(codex_profile_input(&who))
                .unwrap()
                .with_codex_policy_from_trusted_policy(codex_policy(&who))
                .unwrap(),
        )
        .unwrap();
    let mut request = codex_root_request(&who, scoped, Role::Coordinator, b"scope.launch.intent");
    request.host_request.guards.manager_epoch = ManagerEpoch::new(2).unwrap();
    let mut foreign = request.clone();
    foreign.host_request.scope_id = ScopeId::try_from("scope.foreign").unwrap();
    assert!(matches!(
        reopened.admit_bound_root_codex_v2(&who.transport, foreign),
        Err(LaunchPodError::Host(HostError::Unauthorised))
    ));
    assert_command_not_admitted(&fixture, &who, &request);

    let first = reopened
        .admit_bound_root_codex_v2(&who.transport, request.clone())
        .unwrap();
    assert_eq!(first.status.stage, LaunchDispatchStage::Prepared);
    assert!(!first.duplicate);
    assert!(!first.port_called);
    let mut stop = request.host_request.clone();
    stop.command_key = "stop.scope.grant".into();
    stop.action = HostAction::StopPod {
        pod_id: who.pod.clone(),
    };
    assert!(matches!(
        reopened.dispatch(&who.transport, stop),
        Err(HostError::Unauthorised)
    ));
    let mut duplicate = request.clone();
    duplicate.proposal = None;
    let again = reopened
        .admit_bound_root_codex_v2(&who.transport, duplicate.clone())
        .unwrap();
    assert!(again.duplicate);
    assert_eq!(again.receipt, first.receipt);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    assert_eq!(reopened_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn codex_v2_dispatch_claims_once_for_concurrent_same_key_and_never_retries_port() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, calls, effects) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, _) = initial_authority(&fixture.database, port.codex_v2(), &who);
    let grant = install_codex_root_policy(&mut host, &who);
    let request = codex_root_request(&who, grant, Role::Coordinator, b"canonical.dispatch.v2");
    let prepared = host
        .admit_bound_root_codex_v2(&who.transport, request.clone())
        .unwrap();
    assert_eq!(prepared.status.stage, LaunchDispatchStage::Prepared);
    let shared = Mutex::new(host);
    let (first, second) = std::thread::scope(|scope| {
        let one = request.clone();
        let two = request.clone();
        let first = scope.spawn(|| {
            shared
                .lock()
                .unwrap()
                .dispatch_prepared_bound_root_codex_v2(&who.transport, one)
                .unwrap()
        });
        let second = scope.spawn(|| {
            shared
                .lock()
                .unwrap()
                .dispatch_prepared_bound_root_codex_v2(&who.transport, two)
                .unwrap()
        });
        (first.join().unwrap(), second.join().unwrap())
    });
    assert_eq!(first.receipt, prepared.receipt);
    assert_eq!(second.receipt, prepared.receipt);
    assert_eq!(first.status.stage, LaunchDispatchStage::HostAccepted);
    assert_eq!(second.status.stage, LaunchDispatchStage::HostAccepted);
    assert_eq!(
        u8::from(first.port_called) + u8::from(second.port_called),
        1
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    let mut host = shared.into_inner().unwrap();
    let mut retry = request.clone();
    retry.proposal = None;
    let original = host
        .dispatch_prepared_bound_root_codex_v2(&who.transport, retry)
        .unwrap();
    assert!(original.duplicate);
    assert!(!original.port_called);
    assert_eq!(original.receipt, prepared.receipt);
    let mut changed = request;
    changed.canonical_request = b"different.caller.intent".to_vec();
    assert!(matches!(
        host.dispatch_prepared_bound_root_codex_v2(&who.transport, changed),
        Err(LaunchPodError::Store(StoreError::Conflict(_)))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn codex_v2_dispatch_preserves_ambiguous_port_result_without_relaunch() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, calls, effects) = FakeLaunchPort::new(Mode::LostReply);
    let (mut host, _) = initial_authority(&fixture.database, port.codex_v2(), &who);
    let grant = install_codex_root_policy(&mut host, &who);
    let request = codex_root_request(&who, grant, Role::Worker, b"canonical.dispatch.uncertain");
    host.admit_bound_root_codex_v2(&who.transport, request.clone())
        .unwrap();
    let first = host
        .dispatch_prepared_bound_root_codex_v2(&who.transport, request.clone())
        .unwrap();
    assert_eq!(
        first.status.stage,
        LaunchDispatchStage::UncertainAfterPossibleEffect
    );
    assert!(first.port_called);
    let mut retry = request;
    retry.proposal = None;
    let again = host
        .dispatch_prepared_bound_root_codex_v2(&who.transport, retry)
        .unwrap();
    assert_eq!(again.receipt, first.receipt);
    assert_eq!(again.status, first.status);
    assert!(again.duplicate);
    assert!(!again.port_called);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(effects.load(Ordering::SeqCst), 1);
}

#[test]
fn codex_v2_dispatch_records_refusal_and_settlement_truthfully() {
    for (mode, expected_stage, expected_effects) in [
        (Mode::Refused, LaunchDispatchStage::RefusedBeforeEffect, 0),
        (Mode::Settled, LaunchDispatchStage::PortSettled, 1),
    ] {
        let fixture = Fixture::new();
        let who = identity(&fixture);
        let (port, calls, effects) = FakeLaunchPort::new(mode);
        let (mut host, _) = initial_authority(&fixture.database, port.codex_v2(), &who);
        let grant = install_codex_root_policy(&mut host, &who);
        let request = codex_root_request(
            &who,
            grant,
            Role::Coordinator,
            b"canonical.dispatch.outcome",
        );
        host.admit_bound_root_codex_v2(&who.transport, request.clone())
            .unwrap();
        let first = host
            .dispatch_prepared_bound_root_codex_v2(&who.transport, request.clone())
            .unwrap();
        assert_eq!(first.status.stage, expected_stage);
        assert!(first.port_called);
        let mut repeat = request;
        repeat.proposal = None;
        let again = host
            .dispatch_prepared_bound_root_codex_v2(&who.transport, repeat)
            .unwrap();
        assert_eq!(again.status, first.status);
        assert!(!again.port_called);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(effects.load(Ordering::SeqCst), expected_effects);
    }
}

#[test]
fn codex_v2_dispatch_refuses_unsupported_port_and_stale_authority_before_claim() {
    for case in [
        "unsupported",
        "grant",
        "profile",
        "credential",
        "generation",
        "owner",
        "revision",
    ] {
        let fixture = Fixture::new();
        let who = identity(&fixture);
        let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
        let port = if case == "unsupported" {
            port
        } else {
            port.codex_v2()
        };
        let (mut host, _) = initial_authority(&fixture.database, port, &who);
        let grant = install_codex_root_policy(&mut host, &who);
        let mut request =
            codex_root_request(&who, grant, Role::Coordinator, b"canonical.dispatch.refuse");
        let prepared = host
            .admit_bound_root_codex_v2(&who.transport, request.clone())
            .unwrap();
        request.proposal = None;
        match case {
            "grant" => host.revoke_grant_from_trusted_policy(grant).unwrap(),
            "profile" => {
                let mut input = codex_profile_input(&who);
                input.profile_generation = 3;
                host.register_launch_profile_from_trusted_policy(
                    RegisteredLaunchProfile::from_trusted_policy(input)
                        .unwrap()
                        .with_codex_policy_from_trusted_policy(codex_policy(&who))
                        .unwrap(),
                )
                .unwrap();
            }
            "credential" => {
                if let HostAction::LaunchPod { credential, .. } = &mut request.host_request.action {
                    *credential = Some(
                        CredentialRef::from_trusted_vault(who.scope.clone(), "vault.allowed.two")
                            .unwrap(),
                    );
                }
            }
            "generation" => {
                request.host_request.guards.credential_generation =
                    CredentialGeneration::new(2).unwrap();
            }
            "owner" => {
                let mut store = PodBayStore::open(&fixture.database).unwrap();
                store.begin_authority_replay(1, 2).unwrap();
            }
            "revision" => {
                let mut store = PodBayStore::open(&fixture.database).unwrap();
                let snapshot = store.authority_snapshot().unwrap();
                store
                    .apply_authority_mutation(
                        snapshot.owner_epoch,
                        snapshot.revision,
                        podbay_store::AuthorityMutation::PutActor(snapshot.actors[0].clone()),
                    )
                    .unwrap();
            }
            _ => {}
        }
        assert!(
            host.dispatch_prepared_bound_root_codex_v2(&who.transport, request)
                .is_err()
        );
        let store = PodBayStore::open(&fixture.database).unwrap();
        assert_eq!(
            store
                .launch_dispatch_status(
                    prepared.receipt.outbox_id,
                    who.scope.as_str(),
                    who.pod.as_str(),
                )
                .unwrap()
                .stage,
            LaunchDispatchStage::Prepared,
            "{case}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0, "{case}");
    }
}

#[test]
fn codex_v2_prepared_dispatch_reopens_without_original_proposal() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, first_calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut first, _) = initial_authority(&fixture.database, port.codex_v2(), &who);
    let grant = install_codex_root_policy(&mut first, &who);
    let request = codex_root_request(&who, grant, Role::Coordinator, b"canonical.dispatch.reopen");
    let prepared = first
        .admit_bound_root_codex_v2(&who.transport, request)
        .unwrap();
    drop(first);
    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let mut reopened = DurableAuthority::open(&fixture.database, port.codex_v2()).unwrap();
    replay(&mut reopened, &who, grant);
    reopened
        .register_launch_profile_from_trusted_policy(
            RegisteredLaunchProfile::from_trusted_policy(codex_profile_input(&who))
                .unwrap()
                .with_codex_policy_from_trusted_policy(codex_policy(&who))
                .unwrap(),
        )
        .unwrap();
    let mut resume =
        codex_root_request(&who, grant, Role::Coordinator, b"canonical.dispatch.reopen");
    resume.host_request.guards.manager_epoch = ManagerEpoch::new(2).unwrap();
    resume.proposal = None;
    let accepted = reopened
        .dispatch_prepared_bound_root_codex_v2(&who.transport, resume)
        .unwrap();
    assert_eq!(accepted.receipt, prepared.receipt);
    assert_eq!(accepted.status.stage, LaunchDispatchStage::HostAccepted);
    assert!(accepted.port_called);
    assert_eq!(first_calls.load(Ordering::SeqCst), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn codex_v2_root_accepts_explicit_nondefault_trusted_model_and_effort() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, _) = initial_authority(&fixture.database, port, &who);
    let mut input = codex_profile_input(&who);
    input.allowed_models.insert("gpt-6-astra".into());
    input.allowed_efforts.insert("high".into());
    let grant = install_codex_root_policy_with_input(&mut host, &who, input);
    let mut request = codex_root_request(
        &who,
        grant,
        Role::Coordinator,
        b"canonical.codex-v2-explicit",
    );
    let selection = &mut request.proposal.as_mut().unwrap().selection;
    selection.model_id = Some("gpt-6-astra".into());
    selection.reasoning_effort = Some("high".into());
    let receipt = host
        .admit_bound_root_codex_v2(&who.transport, request.clone())
        .unwrap();
    assert_eq!(receipt.status.stage, LaunchDispatchStage::Prepared);
    assert!(!receipt.port_called);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let record = store
        .lookup_bound_launch(&LaunchLookupRequest {
            principal: VerifiedPrincipal::from_authenticated_boundary(who.actor.as_str()).unwrap(),
            namespace: "podbay.launch".into(),
            command_key: request.host_request.command_key,
            scope_id: who.scope.as_str().into(),
            target_id: who.pod.as_str().into(),
            canonical_intent: request.canonical_request,
        })
        .unwrap()
        .unwrap();
    let effective = podbay_wire::EffectiveLaunchContractV2::decode(&record.effective_spec).unwrap();
    assert_eq!(effective.base().model_id(), "gpt-6-astra");
    assert_eq!(effective.base().reasoning_effort(), "high");
    let proof = host
        .inspect_committed_root_codex_v2(&who.scope, &who.pod)
        .unwrap();
    assert_eq!(proof.effective().base().model_id(), "gpt-6-astra");
    assert_eq!(proof.effective().base().reasoning_effort(), "high");
}

#[test]
fn committed_codex_v2_root_inspection_returns_exact_readback_without_effect() {
    for role in [Role::Coordinator, Role::Worker] {
        let fixture = Fixture::new();
        let who = identity(&fixture);
        let (port, calls, effects) = FakeLaunchPort::new(Mode::Accepted);
        let (mut host, _) = initial_authority(&fixture.database, port, &who);
        let grant = install_codex_root_policy(&mut host, &who);
        host.admit_bound_root_codex_v2(
            &who.transport,
            codex_root_request(&who, grant, role, b"canonical.inspect-v2"),
        )
        .unwrap();
        let before = host.recorded_snapshot().clone();
        let proof = host
            .inspect_committed_root_codex_v2(&who.scope, &who.pod)
            .unwrap();
        let mut store = PodBayStore::open(&fixture.database).unwrap();
        let snapshot = store
            .current_bound_pod_snapshot(who.scope.as_str(), who.pod.as_str())
            .unwrap();
        assert_eq!(
            store
                .launch_dispatch_status(proof.outbox_id(), who.scope.as_str(), who.pod.as_str())
                .unwrap()
                .stage,
            LaunchDispatchStage::Prepared
        );
        assert_eq!(
            proof.effective_spec_bytes(),
            snapshot.launch().effective_spec
        );
        assert_eq!(proof.descriptor_bytes(), snapshot.launch().descriptor);
        assert_eq!(proof.descriptor().role(), NativeRole::from(role));
        assert_eq!(proof.effective().codex_policy(), &codex_policy(&who));
        assert_eq!(proof.cwd(), who.workspace_root.join("src"));
        assert_eq!(proof.executable(), who.executable);
        assert_eq!(proof.executable_sha256(), who.executable_sha256);
        assert_eq!(proof.owner_epoch(), 1);
        assert_eq!(proof.authority_revision(), before.revision);
        assert_eq!(proof.resource_input_epochs().len(), 1);
        assert_eq!(host.recorded_snapshot(), &before);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(effects.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn committed_codex_v2_root_inspection_rechecks_reopened_manager_generation() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, first_calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut first, _) = initial_authority(&fixture.database, port, &who);
    let grant = install_codex_root_policy(&mut first, &who);
    first
        .admit_bound_root_codex_v2(
            &who.transport,
            codex_root_request(&who, grant, Role::Coordinator, b"canonical.inspect-reopen"),
        )
        .unwrap();
    drop(first);
    let (port, later_calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let mut reopened = DurableAuthority::open(&fixture.database, port).unwrap();
    reopened
        .register_launch_profile_from_trusted_policy(
            RegisteredLaunchProfile::from_trusted_policy(codex_profile_input(&who))
                .unwrap()
                .with_codex_policy_from_trusted_policy(codex_policy(&who))
                .unwrap(),
        )
        .unwrap();
    reopened
        .register_native_host_from_trusted_policy(native_host_config())
        .unwrap();
    let proof = reopened
        .inspect_committed_root_codex_v2(&who.scope, &who.pod)
        .unwrap();
    assert_eq!(proof.owner_epoch(), 2);
    assert_eq!(
        proof.authority_revision(),
        reopened.recorded_snapshot().revision
    );
    assert_eq!(proof.descriptor().model_id(), "gpt-6-sol");
    assert_eq!(first_calls.load(Ordering::SeqCst), 0);
    assert_eq!(later_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn committed_codex_v2_inspection_refuses_v1_profile_driver_and_binary_drift() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, grant) = initial_authority(&fixture.database, port, &who);
    host.admit_bound_pod(
        &who.transport,
        launch_request(&who, grant, 1, 1, b"canonical.inspect-v1"),
    )
    .unwrap();
    assert!(matches!(
        host.inspect_committed_root_codex_v2(&who.scope, &who.pod),
        Err(RebindContextError::Host(HostError::Unsupported))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    for drift in ["profile", "driver", "binary"] {
        let fixture = Fixture::new();
        let who = identity(&fixture);
        let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
        let (mut host, _) = initial_authority(&fixture.database, port, &who);
        let grant = install_codex_root_policy(&mut host, &who);
        host.admit_bound_root_codex_v2(
            &who.transport,
            codex_root_request(&who, grant, Role::Coordinator, b"canonical.inspect-drift"),
        )
        .unwrap();
        match drift {
            "profile" => {
                let mut input = codex_profile_input(&who);
                input.profile_generation = 3;
                let changed = RegisteredLaunchProfile::from_trusted_policy(input)
                    .unwrap()
                    .with_codex_policy_from_trusted_policy(codex_policy(&who))
                    .unwrap();
                host.register_launch_profile_from_trusted_policy(changed)
                    .unwrap();
            }
            "driver" => host
                .register_native_host_from_trusted_policy(
                    TrustedNativeHostConfig::for_compiled_backend("host.fixture".into()).unwrap(),
                )
                .unwrap(),
            "binary" => std::fs::write(&who.executable, b"#!/bin/sh\nexit 1\n").unwrap(),
            _ => unreachable!(),
        }
        assert!(matches!(
            host.inspect_committed_root_codex_v2(&who.scope, &who.pod),
            Err(RebindContextError::Host(_))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn committed_codex_v2_inspection_rejects_changed_model_effort_and_credential_policy() {
    for drift in ["model", "effort", "credential"] {
        let fixture = Fixture::new();
        let who = identity(&fixture);
        let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
        let (mut first, _) = initial_authority(&fixture.database, port, &who);
        let grant = install_codex_root_policy(&mut first, &who);
        first
            .admit_bound_root_codex_v2(
                &who.transport,
                codex_root_request(&who, grant, Role::Coordinator, b"canonical.inspect-policy"),
            )
            .unwrap();
        drop(first);
        let (port, later_calls, _) = FakeLaunchPort::new(Mode::Accepted);
        let mut reopened = DurableAuthority::open(&fixture.database, port).unwrap();
        let mut input = codex_profile_input(&who);
        let mut policy = codex_policy(&who);
        match drift {
            "model" => {
                input.default_model = "model.other".into();
                input.allowed_models = BTreeSet::from(["model.other".into()]);
            }
            "effort" => {
                input.default_effort = "high".into();
                input.allowed_efforts = BTreeSet::from(["high".into()]);
            }
            "credential" => {
                input.credential_refs = vec![
                    CredentialRef::from_trusted_vault(who.scope.clone(), "vault.allowed.two")
                        .unwrap(),
                ];
                policy = CodexAppServerPolicyV2::new(
                    &who.scope,
                    "vault.allowed.two".into(),
                    "driver.fixture".into(),
                    "protocol.fixture".into(),
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        reopened
            .register_launch_profile_from_trusted_policy(
                RegisteredLaunchProfile::from_trusted_policy(input)
                    .unwrap()
                    .with_codex_policy_from_trusted_policy(policy)
                    .unwrap(),
            )
            .unwrap();
        reopened
            .register_native_host_from_trusted_policy(native_host_config())
            .unwrap();
        assert!(matches!(
            reopened.inspect_committed_root_codex_v2(&who.scope, &who.pod),
            Err(RebindContextError::Host(HostError::StaleGuard))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(later_calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn committed_codex_v2_inspection_refuses_external_authority_revision() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, _) = initial_authority(&fixture.database, port, &who);
    let grant = install_codex_root_policy(&mut host, &who);
    host.admit_bound_root_codex_v2(
        &who.transport,
        codex_root_request(
            &who,
            grant,
            Role::Coordinator,
            b"canonical.inspect-revision",
        ),
    )
    .unwrap();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let snapshot = store.authority_snapshot().unwrap();
    let mut resource = snapshot.resources[0].clone();
    resource.input_epoch += 1;
    store
        .apply_authority_mutation(
            snapshot.owner_epoch,
            snapshot.revision,
            podbay_store::AuthorityMutation::PutResource(resource),
        )
        .unwrap();
    assert!(matches!(
        host.inspect_committed_root_codex_v2(&who.scope, &who.pod),
        Err(RebindContextError::Host(HostError::StaleGuard))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn codex_v2_root_refuses_unreviewed_selection_and_credential() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, legacy_grant) = initial_authority(&fixture.database, port, &who);
    let grant = install_codex_root_policy(&mut host, &who);
    let valid = codex_root_request(
        &who,
        grant,
        Role::Coordinator,
        b"canonical.codex-v2-refused",
    );
    let mut cases = Vec::new();
    let mut implicit_model = valid.clone();
    implicit_model.proposal.as_mut().unwrap().selection.model_id = None;
    cases.push(implicit_model);
    let mut changed_model = valid.clone();
    changed_model.proposal.as_mut().unwrap().selection.model_id = Some("model.beta".into());
    cases.push(changed_model);
    let mut implicit_effort = valid.clone();
    implicit_effort
        .proposal
        .as_mut()
        .unwrap()
        .selection
        .reasoning_effort = None;
    cases.push(implicit_effort);
    let mut read_only = valid.clone();
    read_only
        .proposal
        .as_mut()
        .unwrap()
        .selection
        .workspace
        .access = WorkspaceAccess::ReadOnly;
    cases.push(read_only);
    let mut missing_credential = valid.clone();
    if let HostAction::LaunchPod { credential, .. } = &mut missing_credential.host_request.action {
        *credential = None;
    }
    cases.push(missing_credential);
    let mut legacy_profile = valid.clone();
    legacy_profile
        .proposal
        .as_mut()
        .unwrap()
        .selection
        .profile_generation = 1;
    cases.push(legacy_profile);
    let mut wrong_resource = valid.clone();
    wrong_resource.proposal = Some(bound_proposal(
        &who,
        &who.pod,
        Role::Coordinator,
        wrong_resource.proposal.as_ref().unwrap().selection.clone(),
    ));
    cases.push(wrong_resource);
    let mut missing_grant = valid.clone();
    missing_grant.host_request.grant_id = legacy_grant;
    missing_grant
        .proposal
        .as_mut()
        .unwrap()
        .selection
        .authority_ref = format!("grant.{}", legacy_grant.get());
    cases.push(missing_grant);
    for request in cases {
        assert!(matches!(
            host.admit_bound_root_codex_v2(&who.transport, request.clone()),
            Err(LaunchPodError::Host(_))
        ));
        assert_command_not_admitted(&fixture, &who, &request);
    }
    std::fs::write(&who.executable, b"#!/bin/sh\nexit 1\n").unwrap();
    assert!(matches!(
        host.admit_bound_root_codex_v2(&who.transport, valid.clone()),
        Err(LaunchPodError::Host(_))
    ));
    assert_command_not_admitted(&fixture, &who, &valid);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(host.recorded_snapshot().pods.is_empty());
}

#[test]
fn codex_v2_root_rejects_v1_duplicate_and_stale_owner() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, grant) = initial_authority(&fixture.database, port, &who);
    let v1 = launch_request(&who, grant, 1, 1, b"canonical.v1-first");
    host.admit_bound_pod(&who.transport, v1.clone()).unwrap();
    assert!(matches!(
        host.admit_bound_root_codex_v2(&who.transport, v1),
        Err(LaunchPodError::Host(HostError::Unauthorised))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let other = Fixture::new();
    let who = identity(&other);
    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, _) = initial_authority(&other.database, port, &who);
    let grant = install_codex_root_policy(&mut host, &who);
    let request = codex_root_request(&who, grant, Role::Coordinator, b"canonical.stale-owner");
    let mut store = PodBayStore::open(&other.database).unwrap();
    store.begin_authority_replay(1, 2).unwrap();
    assert!(matches!(
        host.admit_bound_root_codex_v2(&who.transport, request.clone()),
        Err(LaunchPodError::Host(HostError::StaleGuard))
    ));
    assert_command_not_admitted(&other, &who, &request);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn resolved_port_receives_only_host_derived_native_paths() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, grant) = initial_authority(&fixture.database, port.resolved_only(), &who);
    let result = host
        .launch_bound_pod(
            &who.transport,
            launch_request(&who, grant, 1, 1, b"canonical.resolved"),
        )
        .unwrap();
    assert_eq!(result.status.stage, LaunchDispatchStage::HostAccepted);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let seen = host.port().resolved_seen.lock().unwrap();
    assert_eq!(
        seen.as_slice(),
        &[(
            who.workspace_root.join("src"),
            who.executable.clone(),
            who.executable_sha256.clone(),
        )]
    );
    assert!(host.port().reviewed.lock().unwrap().is_empty());
    let manager_seen = host.port().manager_seen.lock().unwrap();
    let manager = &manager_seen[0];
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    assert_eq!(
        manager.store_path,
        std::fs::canonicalize(&fixture.database).unwrap()
    );
    let claim = store.current_manager_credential_claim(1).unwrap();
    assert!(
        store
            .current_manager_peer_matches(&claim, &manager.peer)
            .unwrap()
    );
    let sibling = podbay_core::AttestedPeer::from_port(
        manager.peer.os_identity(),
        "linux.pid.999999999",
        manager.peer.boot_identity(),
        manager.peer.birth_identity(),
        manager.peer.containment_identity(),
    )
    .unwrap();
    assert!(
        !store
            .current_manager_peer_matches(&claim, &sibling)
            .unwrap()
    );
    assert!(matches!(
        store.register_current_manager_peer(&claim, &sibling),
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(
        manager.claim,
        (
            claim.store_lineage().to_owned(),
            claim.owner_epoch(),
            claim.credential_epoch()
        )
    );
    assert_eq!(
        manager.peer.native_process_id(),
        format!("linux.pid.{}", std::process::id())
    );
    assert!(manager.peer.os_identity().starts_with("linux.uid."));
    assert!(manager.peer.boot_identity().starts_with("linux.boot."));
    assert!(manager.peer.birth_identity().starts_with("linux.start."));
    assert!(
        manager
            .peer
            .containment_identity()
            .starts_with("linux.cgroup./")
    );
    let inputs = store
        .authority_snapshot()
        .unwrap()
        .resources
        .into_iter()
        .map(|resource| (resource.resource_id, resource.input_epoch))
        .collect();
    assert_eq!(manager.inputs, inputs);
    assert_eq!(manager.outbox_id, result.receipt.outbox_id);
    let request = launch_request(&who, grant, 1, 1, b"canonical.resolved");
    let record = store
        .lookup_bound_launch(&LaunchLookupRequest {
            principal: VerifiedPrincipal::from_authenticated_boundary(who.actor.as_str()).unwrap(),
            namespace: "podbay.launch".into(),
            command_key: request.host_request.command_key,
            scope_id: who.scope.as_str().into(),
            target_id: who.pod.as_str().into(),
            canonical_intent: request.canonical_request,
        })
        .unwrap()
        .unwrap();
    assert_eq!(manager.descriptor, record.descriptor);
    assert_eq!(manager.effective, record.effective_spec);
}

#[test]
fn native_symlink_and_parent_escape_refuse_before_admission() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, grant) = initial_authority(&fixture.database, port, &who);
    let mut parent = launch_request(&who, grant, 1, 1, b"canonical.parent-escape");
    parent
        .proposal
        .as_mut()
        .unwrap()
        .selection
        .workspace
        .relative_cwd = "src/../../outside".into();
    assert!(matches!(
        host.launch_bound_pod(&who.transport, parent.clone()),
        Err(LaunchPodError::Host(HostError::Unauthorised))
    ));
    assert_command_not_admitted(&fixture, &who, &parent);

    let mut read_only = launch_request(&who, grant, 1, 1, b"canonical.read-only");
    read_only
        .proposal
        .as_mut()
        .unwrap()
        .selection
        .workspace
        .access = WorkspaceAccess::ReadOnly;
    assert!(matches!(
        host.launch_bound_pod(&who.transport, read_only.clone()),
        Err(LaunchPodError::Host(HostError::Unsupported))
    ));
    assert_command_not_admitted(&fixture, &who, &read_only);

    std::fs::remove_dir_all(who.workspace_root.join("src")).unwrap();
    let outside = fixture.directory.join("workspace-sibling");
    std::fs::create_dir_all(&outside).unwrap();
    symlink(&outside, who.workspace_root.join("src")).unwrap();
    let symlinked = launch_request(&who, grant, 1, 1, b"canonical.symlink-escape");
    assert!(matches!(
        host.launch_bound_pod(&who.transport, symlinked.clone()),
        Err(LaunchPodError::Host(HostError::Unauthorised))
    ));
    assert_command_not_admitted(&fixture, &who, &symlinked);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn changed_executable_and_wrong_ordered_layout_refuse_before_admission() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, grant) = initial_authority(&fixture.database, port, &who);
    let content = b"#!/bin/sh\nexit 7\n";
    std::fs::write(&who.executable, content).unwrap();
    let changed = launch_request(&who, grant, 1, 1, b"canonical.changed-binary");
    assert!(matches!(
        host.launch_bound_pod(&who.transport, changed.clone()),
        Err(LaunchPodError::Host(HostError::StaleGuard))
    ));
    assert_command_not_admitted(&fixture, &who, &changed);
    std::fs::write(&who.executable, b"#!/bin/sh\nexit 0\n").unwrap();

    let mut reordered = profile_input(&who);
    reordered.profile_generation = 2;
    reordered.resource_layout.reverse();
    host.register_launch_profile_from_trusted_policy(
        RegisteredLaunchProfile::from_trusted_policy(reordered).unwrap(),
    )
    .unwrap();
    let mut layout = launch_request(&who, grant, 1, 1, b"canonical.layout-order");
    layout
        .proposal
        .as_mut()
        .unwrap()
        .selection
        .profile_generation = 2;
    assert!(matches!(
        host.launch_bound_pod(&who.transport, layout.clone()),
        Err(LaunchPodError::Host(HostError::Unauthorised))
    ));
    assert_command_not_admitted(&fixture, &who, &layout);
    let mut unavailable = profile_input(&who);
    unavailable.profile_generation = 3;
    unavailable.resource_layout[1].driver = ResourceDriver::Structured {
        driver_ref: "driver.not-installed".into(),
        protocol_ref: "protocol.fixture".into(),
    };
    host.register_launch_profile_from_trusted_policy(
        RegisteredLaunchProfile::from_trusted_policy(unavailable).unwrap(),
    )
    .unwrap();
    let mut unsupported = launch_request(&who, grant, 1, 1, b"canonical.driver-unavailable");
    unsupported
        .proposal
        .as_mut()
        .unwrap()
        .selection
        .profile_generation = 3;
    assert!(matches!(
        host.launch_bound_pod(&who.transport, unsupported.clone()),
        Err(LaunchPodError::Host(HostError::Unsupported))
    ));
    assert_command_not_admitted(&fixture, &who, &unsupported);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn malformed_committed_readback_refuses_while_outbox_stays_prepared() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
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
    let who = identity(&fixture);
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
    let who = identity(&fixture);
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
        who.executable.to_string_lossy()
    );
    assert_eq!(
        reviewed[0].effective().executable_generation(),
        format!("sha256:{}", who.executable_sha256)
    );
    assert_eq!(reviewed[0].effective().model_id(), "model.alpha");
    assert_eq!(
        reviewed[0].effective().arguments(),
        &["--managed", "--safe"]
    );
    assert_eq!(reviewed[0].effective().relative_cwd(), "src");
    assert!(reviewed[0].effective().credential_refs().is_empty());
    assert_eq!(reviewed[0].descriptor().target_os(), TargetOs::Linux);
    assert_eq!(reviewed[0].descriptor().host_id(), "host.fixture");
    assert_eq!(
        reviewed[0].descriptor().cwd(),
        who.workspace_root.join("src").to_string_lossy()
    );
    assert_eq!(reviewed[0].descriptor().resources_len(), 2);
    assert_eq!(
        reviewed[0].descriptor().resource(0).unwrap().driver,
        &ResourceDriver::Pty {
            rows: 24,
            columns: 80,
            retention_events: 100
        }
    );
    assert_eq!(
        reviewed[0].descriptor().resource(1).unwrap().driver,
        &ResourceDriver::Structured {
            driver_ref: "driver.fixture".into(),
            protocol_ref: "protocol.fixture".into()
        }
    );
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
    let who = identity(&fixture);
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
fn prepared_launch_rechecks_executable_before_claim() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, grant) = initial_authority(&fixture.database, port, &who);
    let request = launch_request(&who, grant, 1, 1, b"canonical.preclaim-binary");
    let prepared = host
        .admit_bound_pod(&who.transport, request.clone())
        .unwrap();
    std::fs::write(&who.executable, b"#!/bin/sh\nexit 9\n").unwrap();
    assert!(matches!(
        host.resume_prepared_bound_pod(&who.transport, request),
        Err(LaunchPodError::Host(HostError::StaleGuard))
    ));
    let store = PodBayStore::open(&fixture.database).unwrap();
    assert_eq!(
        store
            .launch_dispatch_status(
                prepared.receipt.outbox_id,
                who.scope.as_str(),
                who.pod.as_str()
            )
            .unwrap()
            .stage,
        LaunchDispatchStage::Prepared
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn changed_trusted_binary_hash_on_restart_blocks_prepared_recovery() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (first_port, _, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut first, grant) = initial_authority(&fixture.database, first_port, &who);
    let request = launch_request(&who, grant, 1, 1, b"canonical.restart-binary");
    let prepared = first
        .admit_bound_pod(&who.transport, request.clone())
        .unwrap();
    drop(first);

    let new_bytes = b"#!/bin/sh\nexit 5\n";
    std::fs::write(&who.executable, new_bytes).unwrap();
    let new_hash = Sha256::digest(new_bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let (second_port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let mut second = DurableAuthority::open(&fixture.database, second_port).unwrap();
    second
        .reattest_actor_from_trusted_replay(
            &who.transport,
            ActorRegistration::owner_cli_from_trusted_policy(
                who.actor.clone(),
                who.scope.clone(),
                who.process.clone(),
                CredentialGeneration::new(1).unwrap(),
            ),
        )
        .unwrap();
    second.activate_grant_from_trusted_replay(grant).unwrap();
    second
        .register_native_host_from_trusted_policy(native_host_config())
        .unwrap();
    let mut changed_profile = profile_input(&who);
    changed_profile.executable_sha256 = new_hash.clone();
    assert!(matches!(
        RegisteredLaunchProfile::from_trusted_policy(changed_profile.clone()),
        Err(HostError::InvalidInput)
    ));
    // The immutable descriptor carries this digest even with the same
    // profile reference and numeric generation.
    changed_profile.binary_generation = format!("sha256:{new_hash}");
    second
        .register_launch_profile_from_trusted_policy(
            RegisteredLaunchProfile::from_trusted_policy(changed_profile).unwrap(),
        )
        .unwrap();
    let mut retry = launch_request(&who, grant, 2, 1, b"canonical.restart-binary");
    retry.proposal = None;
    let inspected = second.launch_bound_pod(&who.transport, retry).unwrap();
    assert!(inspected.duplicate);
    assert_eq!(inspected.receipt, prepared.receipt);
    assert_eq!(inspected.status.stage, LaunchDispatchStage::Prepared);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        second.resume_prepared_bound_pod(
            &who.transport,
            launch_request(&who, grant, 2, 1, b"canonical.restart-binary")
        ),
        Err(LaunchPodError::Host(HostError::StaleGuard))
    ));
    let store = PodBayStore::open(&fixture.database).unwrap();
    assert_eq!(
        store
            .launch_dispatch_status(
                prepared.receipt.outbox_id,
                who.scope.as_str(),
                who.pod.as_str()
            )
            .unwrap()
            .stage,
        LaunchDispatchStage::Prepared
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn prepared_intent_survives_restart_and_dispatches_once_after_replay() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
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
    let who = identity(&fixture);
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
    let who = identity(&fixture);
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
    let who = identity(&fixture);
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
    let who = identity(&fixture);
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
fn codex_policy_opt_in_requires_exact_reviewed_profile_shape() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let policy = codex_policy(&who);
    let legacy = RegisteredLaunchProfile::from_trusted_policy(codex_profile_input(&who)).unwrap();
    assert!(legacy.codex_policy().is_none());
    let opted = legacy
        .with_codex_policy_from_trusted_policy(policy.clone())
        .unwrap();
    assert_eq!(opted.codex_policy(), Some(&policy));
    assert_eq!(
        opted.with_codex_policy_from_trusted_policy(policy.clone()),
        Err(HostError::InvalidInput)
    );

    let mut invalid = Vec::new();
    let mut extra_resource = codex_profile_input(&who);
    extra_resource
        .resource_layout
        .insert(0, profile_input(&who).resource_layout[0].clone());
    invalid.push(extra_resource);
    let mut wrong_kind = codex_profile_input(&who);
    wrong_kind.resource_layout[0] = profile_input(&who).resource_layout[0].clone();
    invalid.push(wrong_kind);
    let mut wrong_driver = codex_profile_input(&who);
    wrong_driver.resource_layout[0].driver = ResourceDriver::Structured {
        driver_ref: "driver.other".into(),
        protocol_ref: "protocol.fixture".into(),
    };
    invalid.push(wrong_driver);
    let mut wrong_protocol = codex_profile_input(&who);
    wrong_protocol.resource_layout[0].driver = ResourceDriver::Structured {
        driver_ref: "driver.fixture".into(),
        protocol_ref: "protocol.other".into(),
    };
    invalid.push(wrong_protocol);
    let mut no_credential = codex_profile_input(&who);
    no_credential.credential_refs.clear();
    invalid.push(no_credential);
    let mut extra_credential = codex_profile_input(&who);
    extra_credential
        .credential_refs
        .push(CredentialRef::from_trusted_vault(who.scope.clone(), "vault.allowed.two").unwrap());
    invalid.push(extra_credential);
    let mut no_write = codex_profile_input(&who);
    no_write.allow_write = false;
    invalid.push(no_write);
    for input in invalid {
        assert_eq!(
            RegisteredLaunchProfile::from_trusted_policy(input)
                .unwrap()
                .with_codex_policy_from_trusted_policy(policy.clone()),
            Err(HostError::Unauthorised)
        );
    }
    let foreign = CodexAppServerPolicyV2::new(
        &ScopeId::try_from("scope.other").unwrap(),
        "vault.allowed.one".into(),
        "driver.fixture".into(),
        "protocol.fixture".into(),
    )
    .unwrap();
    assert_eq!(
        RegisteredLaunchProfile::from_trusted_policy(codex_profile_input(&who))
            .unwrap()
            .with_codex_policy_from_trusted_policy(foreign),
        Err(HostError::Unauthorised)
    );
}

#[test]
fn codex_opted_profile_refuses_existing_v1_launch_before_admission() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, grant) = initial_authority(&fixture.database, port, &who);
    let codex = RegisteredLaunchProfile::from_trusted_policy(codex_profile_input(&who))
        .unwrap()
        .with_codex_policy_from_trusted_policy(codex_policy(&who))
        .unwrap();
    host.register_launch_profile_from_trusted_policy(codex)
        .unwrap();

    let mut request = launch_request(&who, grant, 1, 1, b"canonical.codex-v1-refused");
    request.host_request.command_key = "launch.codex.v1.refused".into();
    request
        .proposal
        .as_mut()
        .unwrap()
        .selection
        .profile_generation = 2;
    assert!(matches!(
        host.launch_bound_pod(&who.transport, request),
        Err(LaunchPodError::Host(HostError::Unsupported))
    ));
    assert!(host.recorded_snapshot().pods.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn coordinator_and_worker_use_same_reviewed_port_path() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
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
    let who = identity(&fixture);
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
    let who = identity(&fixture);
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

#[test]
fn resolved_manager_handoff_uses_replayed_manager_epoch_not_actor_generation() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, _, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut first, grant) = initial_authority(&fixture.database, port.resolved_only(), &who);
    let request = launch_request(&who, grant, 1, 1, b"canonical.manager-replay");
    let prepared = first.admit_bound_pod(&who.transport, request).unwrap();
    drop(first);

    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let mut second = DurableAuthority::open(&fixture.database, port.resolved_only()).unwrap();
    replay(&mut second, &who, grant);
    let request = launch_request(&who, grant, 2, 1, b"canonical.manager-replay");
    assert_eq!(request.host_request.guards.credential_generation.get(), 1);
    let result = second
        .resume_prepared_bound_pod(&who.transport, request)
        .unwrap();
    assert_eq!(result.receipt, prepared.receipt);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let seen = second.port().manager_seen.lock().unwrap();
    assert_eq!(seen[0].claim.1, 2);
    assert_eq!(seen[0].claim.2, 2);
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let claim = store.current_manager_credential_claim(2).unwrap();
    assert!(
        store
            .current_manager_peer_matches(&claim, &seen[0].peer)
            .unwrap()
    );
    assert_eq!(seen[0].inputs.len(), 2);
    assert!(seen[0].inputs.values().all(|epoch| *epoch == 2));
}

#[test]
fn resolved_manager_handoff_refuses_external_replay_or_resource_change_before_claim() {
    for change_owner in [true, false] {
        let fixture = Fixture::new();
        let who = identity(&fixture);
        let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
        let port = port.resolved_only();
        *port.preclaim_change.lock().unwrap() = Some((fixture.database.clone(), change_owner));
        let (mut host, grant) = initial_authority(&fixture.database, port, &who);
        let request = launch_request(&who, grant, 1, 1, b"canonical.manager-stale");
        let prepared = host
            .admit_bound_pod(&who.transport, request.clone())
            .unwrap();
        assert!(matches!(
            host.resume_prepared_bound_pod(&who.transport, request),
            Err(LaunchPodError::Store(StoreError::StaleEpoch))
                | Err(LaunchPodError::Host(HostError::StaleGuard))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(host.port().manager_seen.lock().unwrap().is_empty());
        let store = PodBayStore::open(&fixture.database).unwrap();
        assert_eq!(
            store
                .launch_dispatch_status(
                    prepared.receipt.outbox_id,
                    who.scope.as_str(),
                    who.pod.as_str()
                )
                .unwrap()
                .stage,
            LaunchDispatchStage::Prepared
        );
    }
}

#[test]
fn resolved_manager_handoff_refuses_replaced_database_path_before_claim() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let port = port.resolved_only();
    *port.preclaim_replace.lock().unwrap() = Some(fixture.database.clone());
    let (mut host, grant) = initial_authority(&fixture.database, port, &who);
    let request = launch_request(&who, grant, 1, 1, b"canonical.manager-db-replaced");
    host.admit_bound_pod(&who.transport, request.clone())
        .unwrap();
    assert!(matches!(
        host.resume_prepared_bound_pod(&who.transport, request),
        Err(LaunchPodError::Host(HostError::StaleGuard))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(host.port().manager_seen.lock().unwrap().is_empty());
}

#[test]
fn rebind_context_derives_exact_snapshot_without_actor_reactivation_or_mutation() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, _, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut first, grant) = initial_authority(&fixture.database, port, &who);
    let request = launch_request(&who, grant, 1, 1, b"canonical.rebind-context");
    let prepared = first.admit_bound_pod(&who.transport, request).unwrap();
    drop(first);
    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let mut second = DurableAuthority::open(&fixture.database, port).unwrap();
    // Actor credential remains generation 1 and is inert; context is manager
    // recovery state, not an actor grant or credential.
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let before = store.authority_snapshot().unwrap();
    assert_eq!(before.actors[0].credential_generation, 1);
    let snapshot = store
        .current_bound_pod_snapshot(who.scope.as_str(), who.pod.as_str())
        .unwrap();
    let claim = store.current_manager_credential_claim(2).unwrap();
    let mut context = second.rebind_context(&who.scope, &who.pod).unwrap();
    assert_eq!(
        context.store_path(),
        std::fs::canonicalize(&fixture.database).unwrap()
    );
    assert_eq!(context.store_lineage(), claim.store_lineage());
    assert_eq!(context.owner_epoch(), 2);
    assert_eq!(context.credential_epoch(), claim.credential_epoch());
    assert_eq!(context.credential_epoch(), 2);
    assert!(
        store
            .current_manager_peer_matches(&claim, context.manager_peer())
            .unwrap()
    );
    assert_eq!(context.identity().attempt_id, *snapshot.attempt_id());
    assert_eq!(context.identity().incarnation, snapshot.pod_incarnation());
    assert_eq!(context.identity().scope_id, who.scope);
    assert_eq!(context.identity().pod_id, who.pod);
    assert_eq!(context.launch(), snapshot.launch());
    assert_eq!(context.launch().receipt, prepared.receipt);
    assert_eq!(context.authority_revision(), snapshot.authority_revision());
    let expected = snapshot
        .resources()
        .iter()
        .map(|resource| (resource.id().clone(), resource.input_epoch()))
        .collect();
    assert_eq!(context.resource_input_epochs(), &expected);
    assert!(
        context
            .resource_input_epochs()
            .values()
            .all(|epoch| epoch.get() == 2)
    );
    context.recheck_current().unwrap();
    context.recheck_current().unwrap();
    assert_eq!(store.authority_snapshot().unwrap(), before);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn rebind_context_recheck_refuses_fresh_owner_or_resource_drift() {
    for change_owner in [true, false] {
        let fixture = Fixture::new();
        let who = identity(&fixture);
        let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
        let (mut host, grant) = initial_authority(&fixture.database, port, &who);
        host.admit_bound_pod(
            &who.transport,
            launch_request(&who, grant, 1, 1, b"canonical.rebind-drift"),
        )
        .unwrap();
        let mut context = host.rebind_context(&who.scope, &who.pod).unwrap();
        let mut store = PodBayStore::open(&fixture.database).unwrap();
        let snapshot = store.authority_snapshot().unwrap();
        if change_owner {
            store.begin_authority_replay(1, 2).unwrap();
        } else {
            let mut resource = snapshot.resources[0].clone();
            resource.input_epoch += 1;
            store
                .apply_authority_mutation(
                    1,
                    snapshot.revision,
                    podbay_store::AuthorityMutation::PutResource(resource),
                )
                .unwrap();
        }
        assert!(context.recheck_current().is_err());
        drop(context);
        assert!(host.rebind_context(&who.scope, &who.pod).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn rebind_context_refuses_foreign_selector_and_new_unbound_target_incarnation() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, grant) = initial_authority(&fixture.database, port, &who);
    host.admit_bound_pod(
        &who.transport,
        launch_request(&who, grant, 1, 1, b"canonical.rebind-target"),
    )
    .unwrap();
    assert!(
        host.rebind_context(&ScopeId::try_from("scope.foreign").unwrap(), &who.pod)
            .is_err()
    );
    assert!(
        host.rebind_context(&who.scope, &PodId::try_from("pod.foreign").unwrap())
            .is_err()
    );
    host.advance_pod_incarnation_from_trusted_policy(
        &who.pod,
        PodIncarnation::new(1).unwrap(),
        PodIncarnation::new(2).unwrap(),
    )
    .unwrap();
    assert!(host.rebind_context(&who.scope, &who.pod).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn rebind_context_recheck_refuses_replaced_database_file() {
    let fixture = Fixture::new();
    let who = identity(&fixture);
    let (port, calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, grant) = initial_authority(&fixture.database, port, &who);
    host.admit_bound_pod(
        &who.transport,
        launch_request(&who, grant, 1, 1, b"canonical.rebind-file"),
    )
    .unwrap();
    let mut context = host.rebind_context(&who.scope, &who.pod).unwrap();
    let original = fixture.database.with_extension("original");
    std::fs::rename(&fixture.database, &original).unwrap();
    std::fs::copy(original, &fixture.database).unwrap();
    assert!(context.recheck_current().is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
