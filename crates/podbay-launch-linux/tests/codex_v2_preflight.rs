#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use podbay_core::{
    ActorId, Attempt, AttemptId, CommandId, Epoch, LaunchBinding, Pod, PodId, Resource, ResourceId,
    RebindPhase, ResourceKind, Role, Run, RunId, ScopeId, Session, SessionId, StoreLineageId,
    WorkKind,
};
use podbay_host::{
    ActorRegistration, AuthenticatedPeer, AuthenticatedProcessSubject, AuthenticatedTransport,
    AuthorisedBoundLaunch, AuthorisedDispatch, BootstrapNativeStage, BootstrapPortObservation,
    CommandNativeObservation, LaterTurnNativeStage,
    BootstrapSendError,
    BoundHostLaunchProposal, BoundLaunchPodRequest, CredentialGeneration, CredentialRef,
    DurableAuthority, ExecutionMode, GrantId, GrantMode, GrantSpec, GuardSet, HostAction, HostDispatchPort,
    HostError, HostRequest, LaunchSelection, ManagerEpoch, Operation, PodIncarnation,
    PortDispatchError, PortDispatchOutcome, PortRebindObservation, PortReceiptRef,
    PreparedCodexV2Rebind, RebindCompletionStage, RecoveryCompletionStage,
    RegisteredLaunchProfile, ResolvedNativeCodexLaunch, Right, Target, TrustedBootstrapSendPolicy,
    TrustedDriverTemplate, TrustedLaunchProfileInput, TrustedNativeHostConfig,
    TrustedWireRootLaunchPolicy, WorkspaceAccess, WorkspaceSelection,
};
use podbay_launch_linux::{
    CodexV2Preflight, LinuxLaunchPort, TrustedCodexCredentialSource, TrustedLinuxLaunchConfig,
    preflight_committed_codex_v2, preflight_committed_codex_v2_read_only,
    TrustedNativeEventDirectory, read_committed_codex_native_evidence,
};
use podbay_pod::{
    BootstrapControlStage, BootstrapSettlementStage, CODEX_V2_CAPABILITY, CODEX_V3_CAPABILITY,
    CodexCommandJournal,
    CodexJournalIdentity, CodexJournalStage, LinuxBackend, NativeEventCursor, NativeEventKind,
    LaterTurnControlStage, PodClient, PodError, codex_private_slot_directory, launch_bound_codex_v2,
    manifest_path_for_identity,
};
use podbay_store::{
    CommandLookupSelector, EffectClaim, LaterCodexSendSelector, LaunchDispatchStage, PodBayStore,
    TrustedNativeWriterLeaseRequest,
};
use podbay_wire::{
    CodexAppServerPolicyV2, CommandBody, CommandEnvelope, ContentBlock, DecimalString,
    FallbackPolicy, Guard, LaunchBody, LaunchLimits, LaunchRole,
    LaunchSelection as WireLaunchSelection, LaunchWork, RequestedAuthority, ResourceDriver,
    SendPolicy, SessionChoice, SessionSendBody, Target as WireTarget, WorkKind as WireWorkKind,
    WorkspaceAccess as WireWorkspaceAccess, WorkspaceBinding,
};
use sha2::{Digest, Sha256};

struct Fixture {
    directory: PathBuf,
    database: PathBuf,
    executable: PathBuf,
    source: PathBuf,
    scope: ScopeId,
    pod: PodId,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "podbay-codex-preflight-{}-{nonce}",
            std::process::id(),
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let workspace = directory.join("workspace");
        fs::create_dir(&workspace).unwrap();
        let executable = directory.join("agent.sh");
        fs::write(
            &executable,
            br##"#!/bin/sh
set -eu
[ "$1" = app-server ]
[ "$2" = --listen ]
[ "$3" = stdio:// ]
[ -r "$CODEX_HOME/auth.json" ]
read -r initialize
printf '%s\n' "$initialize" > "$CODEX_HOME/frames.log"
printf '{"id":1,"result":{"codexHome":"%s","platformFamily":"unix","platformOs":"linux","userAgent":"fixture"}}\n' "$CODEX_HOME"
read -r initialized
printf '%s\n' "$initialized" >> "$CODEX_HOME/frames.log"
read -r start
printf '%s\n' "$start" >> "$CODEX_HOME/frames.log"
printf '{"id":2,"result":{"thread":{"id":"thread.fixture","sessionId":"native.session.fixture","cwd":"%s","status":{"type":"idle"},"turns":[]},"model":"gpt-6-sol","reasoningEffort":"medium","approvalPolicy":"never","sandbox":{"type":"dangerFullAccess"},"cwd":"%s"}}\n' "$(pwd)" "$(pwd)"
read -r inspect
printf '%s\n' "$inspect" >> "$CODEX_HOME/frames.log"
printf '{"id":3,"result":{"thread":{"id":"thread.fixture","sessionId":"native.session.fixture","cwd":"%s","status":{"type":"idle"},"turns":[]}}}\n' "$(pwd)"
read -r turn
printf '%s\n' "$turn" >> "$CODEX_HOME/frames.log"
printf '{"id":4,"result":{"turn":{"id":"turn.fixture","status":"inProgress"}}}\n'
printf '{"method":"item/agentMessage/delta","params":{"threadId":"thread.fixture","delta":"private manager evidence"}}\n'
sleep 30
"##,
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let source = directory.join("credential.key");
        fs::write(&source, b"fixture-private-credential").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            database: directory.join("store.sqlite"),
            executable,
            source,
            scope: ScopeId::try_from("scope.codex.preflight").unwrap(),
            pod: PodId::try_from(format!("pod.codex.preflight.{nonce}").as_str()).unwrap(),
            directory,
        }
    }

    fn from_shared() -> Self {
        let directory = PathBuf::from(std::env::var_os("PODBAY_REBIND_FIXTURE_DIR").unwrap());
        let pod =
            PodId::try_from(std::env::var("PODBAY_REBIND_FIXTURE_POD").unwrap().as_str()).unwrap();
        Self {
            database: directory.join("store.sqlite"),
            executable: directory.join("agent.sh"),
            source: directory.join("credential.key"),
            scope: ScopeId::try_from("scope.codex.preflight").unwrap(),
            pod,
            directory,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Ok(entries) = fs::read_dir(&self.directory) {
            for path in entries.filter_map(Result::ok).map(|entry| entry.path()) {
                if path
                    .extension()
                    .is_some_and(|extension| extension == "json")
                    && let Some(stem) = path.file_stem().and_then(|value| value.to_str())
                    && stem.len() == 32
                    && stem.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    let _ = Command::new("systemctl")
                        .args(["--user", "stop", &format!("podbay-pod-{stem}.service")])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
            }
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// A real provider test can fail after launch while the pod still owns a
/// credentialed child. Stop that exact disposable unit before the fixture
/// directory is removed, including during panic unwinding.
struct DisposableUnitGuard(String);

impl DisposableUnitGuard {
    fn for_manifest(path: &Path) -> Self {
        let stem = path.file_stem().and_then(|value| value.to_str()).unwrap();
        assert!(stem.len() == 32 && stem.bytes().all(|byte| byte.is_ascii_hexdigit()));
        Self(format!("podbay-pod-{stem}.service"))
    }
}

impl Drop for DisposableUnitGuard {
    fn drop(&mut self) {
        let _ = Command::new("systemctl")
            .args(["--user", "stop", &self.0])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

struct NoPort(Arc<AtomicUsize>);

/// Test-only interruption after the real pod has fsynced PendingPod. The
/// trusted host sees uncertainty and cannot ACK or activate B by inference.
struct PendingThenLostPort(LinuxLaunchPort);

/// B's store reaches Activated, but the test port withholds the pod Activate
/// call. The pod remains fsynced PendingPod and B must never be called Active.
struct ActivatedThenLostPort(LinuxLaunchPort);

/// D's first two Active inspections succeed, but the test withholds the
/// post-Plan inspection. D dies with a successor Planned, never ACKed.
struct AdoptionThenLostPort(LinuxLaunchPort, AtomicUsize);

/// C's pod fsync/readback succeeds, but its store ACK is interrupted by a
/// test-only lost port reply. Manager D must prove the existing Active file.
struct RecoveryThenLostPort(LinuxLaunchPort);

impl HostDispatchPort for PendingThenLostPort {
    type Receipt = PortReceiptRef;

    fn dispatch(
        &mut self,
        _: AuthorisedDispatch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        Err(PortDispatchError::RefusedBeforeEffect)
    }

    fn launch_bound(
        &mut self,
        _: AuthorisedBoundLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        Err(PortDispatchError::RefusedBeforeEffect)
    }

    fn inspect_existing_codex_v2_rebind(
        &self,
        launch: &ResolvedNativeCodexLaunch,
    ) -> Result<PortRebindObservation, HostError> {
        <LinuxLaunchPort as HostDispatchPort>::inspect_existing_codex_v2_rebind(&self.0, launch)
    }

    fn prepare_existing_codex_v2_rebind(
        &self,
        prepared: &PreparedCodexV2Rebind,
    ) -> Result<String, HostError> {
        let _fsynced = <LinuxLaunchPort as HostDispatchPort>::prepare_existing_codex_v2_rebind(
            &self.0, prepared,
        )?;
        Err(HostError::UncertainAfterPossibleEffect {
            command_key: prepared.proposal().command_key.as_str().into(),
            receipt_ref: None,
        })
    }
}

impl HostDispatchPort for ActivatedThenLostPort {
    type Receipt = PortReceiptRef;

    fn dispatch(
        &mut self,
        _: AuthorisedDispatch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        Err(PortDispatchError::RefusedBeforeEffect)
    }

    fn launch_bound(
        &mut self,
        _: AuthorisedBoundLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        Err(PortDispatchError::RefusedBeforeEffect)
    }

    fn inspect_existing_codex_v2_rebind(
        &self,
        launch: &ResolvedNativeCodexLaunch,
    ) -> Result<PortRebindObservation, HostError> {
        <LinuxLaunchPort as HostDispatchPort>::inspect_existing_codex_v2_rebind(&self.0, launch)
    }

    fn prepare_existing_codex_v2_rebind(
        &self,
        prepared: &PreparedCodexV2Rebind,
    ) -> Result<String, HostError> {
        <LinuxLaunchPort as HostDispatchPort>::prepare_existing_codex_v2_rebind(&self.0, prepared)
    }

    fn activate_existing_codex_v2_rebind(
        &self,
        prepared: &PreparedCodexV2Rebind,
        _: &str,
    ) -> Result<String, HostError> {
        Err(HostError::UncertainAfterPossibleEffect {
            command_key: prepared.proposal().command_key.as_str().into(),
            receipt_ref: None,
        })
    }
}

impl HostDispatchPort for AdoptionThenLostPort {
    type Receipt = PortReceiptRef;

    fn dispatch(
        &mut self,
        _: AuthorisedDispatch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        Err(PortDispatchError::RefusedBeforeEffect)
    }

    fn launch_bound(
        &mut self,
        _: AuthorisedBoundLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        Err(PortDispatchError::RefusedBeforeEffect)
    }

    fn inspect_recovered_active_codex_v2(
        &self,
        launch: &ResolvedNativeCodexLaunch,
        prior: &podbay_store::PriorPlannedRecovery,
    ) -> Result<podbay_host::PortRecoveredActiveObservation, HostError> {
        if self.1.fetch_add(1, Ordering::SeqCst) >= 2 {
            return Err(HostError::StaleGuard);
        }
        <LinuxLaunchPort as HostDispatchPort>::inspect_recovered_active_codex_v2(
            &self.0, launch, prior,
        )
    }
}

impl HostDispatchPort for RecoveryThenLostPort {
    type Receipt = PortReceiptRef;

    fn dispatch(&mut self, _: AuthorisedDispatch)
        -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        Err(PortDispatchError::RefusedBeforeEffect)
    }

    fn launch_bound(&mut self, _: AuthorisedBoundLaunch)
        -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        Err(PortDispatchError::RefusedBeforeEffect)
    }

    fn inspect_pending_codex_v2_recovery(
        &self,
        launch: &ResolvedNativeCodexLaunch,
    ) -> Result<podbay_host::PortPendingRecoveryObservation, HostError> {
        <LinuxLaunchPort as HostDispatchPort>::inspect_pending_codex_v2_recovery(&self.0,launch)
    }

    fn prepare_pending_codex_v2_recovery(
        &self,
        prepared: &podbay_host::PreparedPendingRecovery,
    ) -> Result<String, HostError> {
        let _fsynced = <LinuxLaunchPort as HostDispatchPort>::prepare_pending_codex_v2_recovery(
            &self.0,prepared,
        )?;
        Err(HostError::UncertainAfterPossibleEffect {
            command_key: prepared.intent().command_key.as_str().into(),
            receipt_ref: None,
        })
    }
}

impl HostDispatchPort for NoPort {
    type Receipt = PortReceiptRef;

    fn dispatch(
        &mut self,
        _: AuthorisedDispatch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(PortDispatchError::RefusedBeforeEffect)
    }

    fn launch_bound(
        &mut self,
        _: AuthorisedBoundLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(PortDispatchError::RefusedBeforeEffect)
    }
}

#[derive(Clone)]
struct Transport(AuthenticatedPeer);

impl AuthenticatedTransport for Transport {
    fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError> {
        Ok(self.0.clone())
    }
}

fn setup(
    role: Role,
) -> (
    Fixture,
    DurableAuthority<NoPort>,
    ResolvedNativeCodexLaunch,
    TrustedCodexCredentialSource,
    Arc<AtomicUsize>,
) {
    let fixture = Fixture::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let (fixture, host, proof, source, _, _) = setup_with_port(
        role,
        fixture,
        NoPort(calls.clone()),
        Duration::from_secs(30),
        60,
    );
    (fixture, host, proof, source, calls)
}

fn setup_with_port<P: HostDispatchPort>(
    role: Role,
    fixture: Fixture,
    port: P,
    launch_budget: Duration,
    wall_seconds: u64,
) -> (
    Fixture,
    DurableAuthority<P>,
    ResolvedNativeCodexLaunch,
    TrustedCodexCredentialSource,
    Transport,
    BoundLaunchPodRequest,
) {
    let mut host = DurableAuthority::open(&fixture.database, port).unwrap();
    let actor = ActorId::try_from("actor.codex.preflight").unwrap();
    let process = AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(
        1000,
        4242,
        777,
        "/user.slice/preflight.scope",
    )
    .unwrap();
    let transport = Transport(AuthenticatedPeer::owner_cli_from_authenticated_transport(
        process.clone(),
        CredentialGeneration::new(1).unwrap(),
    ));
    host.register_actor_from_trusted_policy(ActorRegistration::owner_cli_from_trusted_policy(
        actor.clone(),
        fixture.scope.clone(),
        process,
        CredentialGeneration::new(1).unwrap(),
    ))
    .unwrap();
    let credential =
        CredentialRef::from_trusted_vault(fixture.scope.clone(), "vault.codex.preflight").unwrap();
    let grant = host
        .install_grant_from_trusted_policy(
            &actor,
            GrantSpec {
                scope_id: fixture.scope.clone(),
                mode: GrantMode::Controller,
                rights: BTreeSet::from([
                    Right::new(Operation::LaunchPod, Target::Pod(fixture.pod.clone())),
                    Right::new(
                        Operation::UseCredential,
                        Target::Credential(credential.clone()),
                    ),
                    Right::new(Operation::SendSession, Target::Scope(fixture.scope.clone())),
                ]),
                remaining_delegation_depth: 0,
            },
        )
        .unwrap();
    let executable_bytes = fs::read(&fixture.executable).unwrap();
    let executable_sha256 = Sha256::digest(executable_bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let profile = TrustedLaunchProfileInput {
        profile_ref: "profile.codex.preflight".into(),
        profile_generation: 1,
        executable: fixture.executable.to_string_lossy().into_owned(),
        binary_generation: format!("sha256:{executable_sha256}"),
        executable_sha256,
        workspace_root: fixture.directory.join("workspace"),
        resource_layout: vec![TrustedDriverTemplate {
            kind: ResourceKind::StructuredProvider,
            driver: ResourceDriver::Structured {
                driver_ref: "driver.codex".into(),
                protocol_ref: "protocol.codex".into(),
            },
        }],
        execution_mode: ExecutionMode::LinuxCooperative,
        fixed_arguments: vec!["app-server".into(), "--listen".into(), "stdio://".into()],
        permitted_extra_arguments: BTreeSet::new(),
        default_model: "gpt-6-sol".into(),
        allowed_models: BTreeSet::from(["gpt-6-sol".into()]),
        default_effort: "medium".into(),
        allowed_efforts: BTreeSet::from(["medium".into()]),
        workspace_scope: fixture.scope.clone(),
        workspace_basis_ref: "basis.codex".into(),
        allowed_cwd_prefix: ".".into(),
        allow_write: true,
        allowed_tool_bundle_refs: BTreeSet::new(),
        environment_refs: Vec::new(),
        credential_refs: vec![credential.clone()],
        max_wall_seconds: wall_seconds.max(120),
        max_children: 2,
        allow_fallback: false,
    };
    let policy = CodexAppServerPolicyV2::new(
        &fixture.scope,
        credential.as_str().into(),
        "driver.codex".into(),
        "protocol.codex".into(),
    )
    .unwrap();
    host.register_launch_profile_from_trusted_policy(
        RegisteredLaunchProfile::from_trusted_policy(profile)
            .unwrap()
            .with_codex_policy_from_trusted_policy(policy)
            .unwrap(),
    )
    .unwrap();
    host.register_native_host_from_trusted_policy(
        TrustedNativeHostConfig::for_compiled_backend("host.codex.preflight".into())
            .unwrap()
            .with_structured_driver("driver.codex".into(), "protocol.codex".into())
            .unwrap(),
    )
    .unwrap();
    let mut session = Session::new(
        SessionId::try_from("session.codex.preflight").unwrap(),
        actor,
        fixture.scope.clone(),
    );
    let run = Run::new(
        RunId::try_from("run.codex.preflight").unwrap(),
        &session,
        role,
        if role == Role::Coordinator {
            WorkKind::Service
        } else {
            WorkKind::Task
        },
        None,
    );
    session.bind_run(session.revision(), &run).unwrap();
    let mut attempt = Attempt::new(
        AttemptId::try_from("attempt.codex.preflight").unwrap(),
        run.id().clone(),
        1,
        Epoch::new(1).unwrap(),
    )
    .unwrap();
    let mut pod = Pod::new(
        fixture.pod.clone(),
        attempt.id().clone(),
        Epoch::new(1).unwrap(),
    );
    attempt.attach_pod(attempt.revision(), &pod).unwrap();
    let resource = Resource::new(
        ResourceId::try_from("resource.codex.preflight").unwrap(),
        fixture.pod.clone(),
        ResourceKind::StructuredProvider,
        Epoch::new(1).unwrap(),
    );
    pod.attach_resource(pod.revision(), &resource).unwrap();
    let binding = LaunchBinding::plan_first_root(&session, &run, &attempt, &pod, &[resource])
        .unwrap()
        .identity()
        .clone();
    let request = BoundLaunchPodRequest {
        host_request: HostRequest {
            scope_id: fixture.scope.clone(),
            grant_id: grant,
            guards: GuardSet {
                manager_epoch: ManagerEpoch::new(1).unwrap(),
                pod_incarnation: PodIncarnation::new(1).unwrap(),
                resource_epoch: None,
                credential_generation: CredentialGeneration::new(1).unwrap(),
            },
            command_key: "launch.codex.preflight".into(),
            correlation_id: "correlation.codex.preflight".into(),
            deadline: Instant::now() + launch_budget,
            action: HostAction::LaunchPod {
                pod_id: fixture.pod.clone(),
                role,
                credential: Some(credential.clone()),
            },
        },
        canonical_request: b"codex root preflight".to_vec(),
        proposal: Some(BoundHostLaunchProposal {
            session,
            run,
            binding,
            selection: LaunchSelection {
                profile_ref: "profile.codex.preflight".into(),
                profile_generation: 1,
                model_id: Some("gpt-6-sol".into()),
                reasoning_effort: Some("medium".into()),
                fallback_approved: false,
                workspace: WorkspaceSelection {
                    scope_id: fixture.scope.clone(),
                    basis_ref: "basis.codex".into(),
                    relative_cwd: ".".into(),
                    access: WorkspaceAccess::ReadWrite,
                },
                arguments: Vec::new(),
                tool_bundle_refs: Vec::new(),
                authority_ref: format!("grant.{}", grant.get()),
                wall_seconds,
                max_children: 1,
                parent_run_id: None,
            },
        }),
    };
    let receipt = host
        .admit_bound_root_codex_v2(&transport, request.clone())
        .unwrap();
    assert_eq!(receipt.status.stage, LaunchDispatchStage::Prepared);
    let proof = host
        .inspect_committed_root_codex_v2(&fixture.scope, &fixture.pod)
        .unwrap();
    let source =
        TrustedCodexCredentialSource::from_trusted_policy(credential, fixture.source.clone())
            .unwrap();
    (fixture, host, proof, source, transport, request)
}

fn launch_from_review(
    fixture: &Fixture,
    proof: &ResolvedNativeCodexLaunch,
    reviewed: &CodexV2Preflight,
    pod_binary: &Path,
    source: &Path,
) -> Result<podbay_pod::PodClient, PodError> {
    launch_bound_codex_v2(
        proof.committed_record().clone(),
        reviewed.bootstrap().clone(),
        proof.authority_revision(),
        proof.store_file_identity(),
        &fixture.directory,
        pod_binary,
        source,
        reviewed.credential_source_identity(),
    )
}

fn port_for(fixture: &Fixture, binary: &Path) -> LinuxLaunchPort {
    let binary = fs::canonicalize(binary).unwrap();
    let digest = Sha256::digest(fs::read(&binary).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    LinuxLaunchPort::new(
        TrustedLinuxLaunchConfig::from_trusted_policy(
            binary,
            digest,
            fs::canonicalize(&fixture.directory).unwrap(),
        )
        .unwrap(),
    )
}

fn v3_wire_root_body(fixture: &Fixture, grant: GrantId) -> LaunchBody {
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
        profile_ref: "profile.codex.preflight".into(),
        selection: WireLaunchSelection {
            model_id: Some("gpt-6-sol".into()),
            reasoning_effort: Some("medium".into()),
            fallback: FallbackPolicy::None,
        },
        workspace: WorkspaceBinding {
            scope_id: fixture.scope.as_str().into(),
            relative_cwd: ".".into(),
            basis_ref: Some("basis.codex".into()),
            access: WireWorkspaceAccess::ReadWrite,
        },
        tool_bundle_refs: Vec::new(),
        authority: RequestedAuthority { grant_ref: format!("grant.{}", grant.get()) },
        limits: LaunchLimits {
            wall_seconds: DecimalString::new(90),
            max_children: DecimalString::new(1),
        },
    }
}

fn v3_wire_root(fixture: &Fixture, grant: GrantId, request_id: &str, key: &str) -> CommandEnvelope {
    CommandEnvelope::new(
        request_id,
        key,
        WireTarget::Scope { scope_id: fixture.scope.as_str().into() },
        None,
        None,
        CommandBody::Launch(v3_wire_root_body(fixture, grant)),
    ).unwrap()
}

fn setup_v3_wire_port(
    binary: &Path,
) -> (
    Fixture,
    DurableAuthority<LinuxLaunchPort>,
    Transport,
    GrantId,
    TrustedWireRootLaunchPolicy,
) {
    let fixture = Fixture::new();
    assert!(!fixture.database.exists());
    assert!(slot_manifest(&fixture).is_none());
    let mut port = port_for(&fixture, binary);
    let credential = CredentialRef::from_trusted_vault(
        fixture.scope.clone(), "vault.codex.preflight",
    ).unwrap();
    port.register_codex_credential_source_from_trusted_policy(
        TrustedCodexCredentialSource::from_trusted_policy(
            credential.clone(), fixture.source.clone(),
        ).unwrap(),
    ).unwrap();
    let mut host = DurableAuthority::open(&fixture.database, port).unwrap();
    PodBayStore::open_existing_read_only(&fixture.database)
        .expect("native V3 fixture must start on a fresh v21 store");
    let actor = ActorId::try_from("actor.codex.preflight").unwrap();
    let process = AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(
        1000, 4242, 777, "/user.slice/preflight.scope",
    ).unwrap();
    let transport = Transport(AuthenticatedPeer::owner_cli_from_authenticated_transport(
        process.clone(), CredentialGeneration::new(1).unwrap(),
    ));
    host.register_actor_from_trusted_policy(
        ActorRegistration::owner_cli_from_trusted_policy(
            actor.clone(), fixture.scope.clone(), process,
            CredentialGeneration::new(1).unwrap(),
        ),
    ).unwrap();
    let grant = host.install_grant_from_trusted_policy(
        &actor,
        GrantSpec {
            scope_id: fixture.scope.clone(),
            mode: GrantMode::Controller,
            rights: BTreeSet::from([
                Right::new(Operation::LaunchPod, Target::Scope(fixture.scope.clone())),
                Right::new(Operation::UseCredential, Target::Credential(credential)),
                Right::new(Operation::SendSession, Target::Scope(fixture.scope.clone())),
            ]),
            remaining_delegation_depth: 0,
        },
    ).unwrap();
    register_restarted_codex_profile(&mut host, &fixture);
    let policy = TrustedWireRootLaunchPolicy::from_trusted_policy(
        grant, Instant::now() + Duration::from_secs(120), "result.none",
    ).unwrap();
    (fixture, host, transport, grant, policy)
}

fn register_restarted_codex_profile<P: HostDispatchPort>(
    host: &mut DurableAuthority<P>,
    fixture: &Fixture,
) {
    let executable_sha256 = Sha256::digest(fs::read(&fixture.executable).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let credential =
        CredentialRef::from_trusted_vault(fixture.scope.clone(), "vault.codex.preflight").unwrap();
    let profile = TrustedLaunchProfileInput {
        profile_ref: "profile.codex.preflight".into(),
        profile_generation: 1,
        executable: fixture.executable.to_string_lossy().into_owned(),
        binary_generation: format!("sha256:{executable_sha256}"),
        executable_sha256,
        workspace_root: fixture.directory.join("workspace"),
        resource_layout: vec![TrustedDriverTemplate {
            kind: ResourceKind::StructuredProvider,
            driver: ResourceDriver::Structured {
                driver_ref: "driver.codex".into(),
                protocol_ref: "protocol.codex".into(),
            },
        }],
        execution_mode: ExecutionMode::LinuxCooperative,
        fixed_arguments: vec!["app-server".into(), "--listen".into(), "stdio://".into()],
        permitted_extra_arguments: BTreeSet::new(),
        default_model: "gpt-6-sol".into(),
        allowed_models: BTreeSet::from(["gpt-6-sol".into()]),
        default_effort: "medium".into(),
        allowed_efforts: BTreeSet::from(["medium".into()]),
        workspace_scope: fixture.scope.clone(),
        workspace_basis_ref: "basis.codex".into(),
        allowed_cwd_prefix: ".".into(),
        allow_write: true,
        allowed_tool_bundle_refs: BTreeSet::new(),
        environment_refs: Vec::new(),
        credential_refs: vec![credential.clone()],
        max_wall_seconds: 120,
        max_children: 2,
        allow_fallback: false,
    };
    let policy = CodexAppServerPolicyV2::new(
        &fixture.scope,
        credential.as_str().into(),
        "driver.codex".into(),
        "protocol.codex".into(),
    )
    .unwrap();
    host.register_launch_profile_from_trusted_policy(
        RegisteredLaunchProfile::from_trusted_policy(profile)
            .unwrap()
            .with_codex_policy_from_trusted_policy(policy)
            .unwrap(),
    )
    .unwrap();
    host.register_native_host_from_trusted_policy(
        TrustedNativeHostConfig::for_compiled_backend("host.codex.preflight".into())
            .unwrap()
            .with_structured_driver("driver.codex".into(), "protocol.codex".into())
            .unwrap(),
    )
    .unwrap();
}

fn claim_for_port(fixture: &Fixture, proof: &ResolvedNativeCodexLaunch) {
    let record = proof.committed_record();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    assert_eq!(
        store
            .claim_effect(
                proof.outbox_id(),
                &record.scope_id,
                &record.pod_id,
                proof.owner_epoch(),
                record.pod_incarnation,
                proof.authority_revision(),
                &format!("claim.{}", record.receipt.command_id),
            )
            .unwrap(),
        EffectClaim::NewClaim
    );
}

fn slot_manifest(fixture: &Fixture) -> Option<PathBuf> {
    fs::read_dir(&fixture.directory)
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
                && path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .is_some_and(|stem| {
                        stem.len() == 32 && stem.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
        })
}

fn fixture_codex_slot(fixture: &Fixture) -> PathBuf {
    let manifest = slot_manifest(fixture).expect("committed Codex manifest slot");
    let stem = manifest.file_stem().and_then(|value| value.to_str()).unwrap();
    codex_private_slot_directory(
        &fixture.directory, &format!("podbay-pod-{stem}.service"), false,
    ).unwrap()
}

fn required_real_test_path(name: &str) -> PathBuf {
    let raw = PathBuf::from(std::env::var_os(name).expect("real Codex smoke path is required"));
    assert!(raw.is_absolute(), "real Codex smoke path must be absolute");
    let path = fs::canonicalize(raw).expect("real Codex smoke path is unavailable");
    assert!(
        fs::metadata(&path).unwrap().is_file(),
        "real Codex smoke path must name a regular file"
    );
    path
}

fn reopened_bootstrap_journal(fixture: &Fixture) -> podbay_pod::CodexJournalView {
    let store = PodBayStore::open(&fixture.database).unwrap();
    let lineage = store
        .initial_cursor(fixture.scope.as_str())
        .unwrap()
        .store_lineage;
    let identity = CodexJournalIdentity::from_resource(
        &StoreLineageId::try_from(lineage.as_str()).unwrap(),
        &fixture.scope,
        &SessionId::try_from("session.codex.preflight").unwrap(),
        &RunId::try_from("run.codex.preflight").unwrap(),
        &AttemptId::try_from("attempt.codex.preflight").unwrap(),
        &fixture.pod,
        Epoch::new(1).unwrap(),
        &ResourceId::try_from("resource.codex.preflight").unwrap(),
        Epoch::new(1).unwrap(),
    );
    CodexCommandJournal::open(
        &LinuxBackend,
        &fixture_codex_slot(fixture).join("codex.commands.log"),
        identity,
    )
    .unwrap()
    .view()
}

#[test]
fn preflight_returns_exact_bootstrap_and_private_source_without_port_effect() {
    for role in [Role::Coordinator, Role::Worker] {
        let (fixture, _host, proof, source, calls) = setup(role);
        let reviewed = preflight_committed_codex_v2(&proof, &source).unwrap();
        assert_eq!(reviewed.credential_source(), fixture.source);
        assert_eq!(reviewed.bootstrap().store_path, fixture.database);
        assert_eq!(reviewed.bootstrap().owner_epoch, proof.owner_epoch());
        assert_eq!(
            reviewed.bootstrap().credential_epoch,
            proof.credential_epoch()
        );
        assert_eq!(
            reviewed.bootstrap().resource_input_epochs,
            *proof.resource_input_epochs()
        );
        assert_eq!(
            reviewed.bootstrap().canonical_executable,
            fixture.executable
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let store = PodBayStore::open(&fixture.database).unwrap();
        assert_eq!(
            store
                .launch_dispatch_status(
                    proof.outbox_id(),
                    fixture.scope.as_str(),
                    fixture.pod.as_str()
                )
                .unwrap()
                .stage,
            LaunchDispatchStage::Prepared
        );
    }
}

#[test]
fn rebind_preflight_is_read_only_and_refuses_stale_profile_path() {
    let (fixture, _host, proof, source, calls) = setup(Role::Coordinator);
    let before_bytes = fs::read(&fixture.database).unwrap();
    let before_modified = fs::metadata(&fixture.database).unwrap().modified().unwrap();
    let wal_path = PathBuf::from(format!("{}-wal", fixture.database.display()));
    let before_wal = fs::read(&wal_path).ok();
    let before_wal_modified = fs::metadata(&wal_path)
        .ok()
        .and_then(|value| value.modified().ok());
    let mut before_store = PodBayStore::open_existing_read_only(&fixture.database).unwrap();
    let before_revision = before_store.authority_snapshot().unwrap().revision;
    drop(before_store);

    preflight_committed_codex_v2_read_only(&proof, &source).unwrap();
    let after_bytes = fs::read(&fixture.database).unwrap();
    let after_modified = fs::metadata(&fixture.database).unwrap().modified().unwrap();
    let mut after_store = PodBayStore::open_existing_read_only(&fixture.database).unwrap();
    assert_eq!(
        after_store.authority_snapshot().unwrap().revision,
        before_revision
    );
    assert_eq!(after_bytes, before_bytes);
    assert_eq!(after_modified, before_modified);
    assert_eq!(fs::read(&wal_path).ok(), before_wal);
    assert_eq!(
        fs::metadata(&wal_path)
            .ok()
            .and_then(|value| value.modified().ok()),
        before_wal_modified
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    fs::write(&fixture.executable, b"stale profile executable").unwrap();
    assert!(preflight_committed_codex_v2_read_only(&proof, &source).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn preflight_refuses_wrong_or_changed_credential_source() {
    let (fixture, _host, proof, source, calls) = setup(Role::Coordinator);
    let wrong = TrustedCodexCredentialSource::from_trusted_policy(
        CredentialRef::from_trusted_vault(fixture.scope.clone(), "vault.other").unwrap(),
        fixture.source.clone(),
    )
    .unwrap();
    assert!(preflight_committed_codex_v2(&proof, &wrong).is_err());
    let wrong_scope = TrustedCodexCredentialSource::from_trusted_policy(
        CredentialRef::from_trusted_vault(
            ScopeId::try_from("scope.other").unwrap(),
            "vault.codex.preflight",
        )
        .unwrap(),
        fixture.source.clone(),
    )
    .unwrap();
    assert!(preflight_committed_codex_v2(&proof, &wrong_scope).is_err());
    let link = fixture.directory.join("credential.link");
    symlink(&fixture.source, &link).unwrap();
    assert!(
        TrustedCodexCredentialSource::from_trusted_policy(
            CredentialRef::from_trusted_vault(fixture.scope.clone(), "vault.codex.preflight")
                .unwrap(),
            link,
        )
        .is_err()
    );
    fs::set_permissions(&fixture.source, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(preflight_committed_codex_v2(&proof, &source).is_err());
    fs::set_permissions(&fixture.source, fs::Permissions::from_mode(0o600)).unwrap();
    let old = fixture.directory.join("old.credential");
    fs::rename(&fixture.source, old).unwrap();
    fs::write(&fixture.source, b"replacement").unwrap();
    fs::set_permissions(&fixture.source, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(preflight_committed_codex_v2(&proof, &source).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn preflight_refuses_stale_authority_binary_and_store_file() {
    let (fixture, _host, proof, source, calls) = setup(Role::Coordinator);
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
    assert!(preflight_committed_codex_v2(&proof, &source).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let (fixture, _host, proof, source, calls) = setup(Role::Coordinator);
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    store.begin_authority_replay(1, 2).unwrap();
    assert!(preflight_committed_codex_v2(&proof, &source).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let (fixture, _host, proof, source, calls) = setup(Role::Coordinator);
    fs::write(&fixture.executable, b"#!/bin/sh\nexit 1\n").unwrap();
    assert!(preflight_committed_codex_v2(&proof, &source).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let (fixture, _host, proof, source, calls) = setup(Role::Coordinator);
    let original = fixture.directory.join("original.sqlite");
    fs::rename(&fixture.database, &original).unwrap();
    fs::copy(&original, &fixture.database).unwrap();
    assert!(preflight_committed_codex_v2(&proof, &source).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn private_source_has_finite_size_and_parent_boundary() {
    let (fixture, _host, _proof, _source, _) = setup(Role::Coordinator);
    let reference =
        CredentialRef::from_trusted_vault(fixture.scope.clone(), "vault.codex.preflight").unwrap();
    let oversized = fixture.directory.join("oversized.key");
    fs::write(&oversized, vec![b'x'; 1_048_577]).unwrap();
    fs::set_permissions(&oversized, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        TrustedCodexCredentialSource::from_trusted_policy(reference.clone(), oversized).is_err()
    );
    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        TrustedCodexCredentialSource::from_trusted_policy(reference, fixture.source.clone())
            .is_err()
    );
}

#[test]
fn v2_port_requires_registered_current_scoped_source_before_manifest() {
    let binary = fs::canonicalize("/bin/true").unwrap();
    let (fixture, _host, proof, _source, calls) = setup(Role::Coordinator);
    let mut port = port_for(&fixture, &binary);
    let outbox_id = proof.outbox_id();
    assert!(!port.accepts_resolved_codex_v2());
    let store = PodBayStore::open(&fixture.database).unwrap();
    assert_eq!(
        store
            .launch_dispatch_status(outbox_id, fixture.scope.as_str(), fixture.pod.as_str())
            .unwrap()
            .stage,
        LaunchDispatchStage::Prepared
    );
    assert!(matches!(
        port.launch_resolved_codex_v2(proof),
        Err(PortDispatchError::RefusedBeforeEffect)
    ));
    assert_eq!(
        store
            .launch_dispatch_status(outbox_id, fixture.scope.as_str(), fixture.pod.as_str())
            .unwrap()
            .stage,
        LaunchDispatchStage::Prepared
    );
    assert!(slot_manifest(&fixture).is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let (fixture, _host, proof, _source, calls) = setup(Role::Coordinator);
    let mut port = port_for(&fixture, &binary);
    let wrong_scope = TrustedCodexCredentialSource::from_trusted_policy(
        CredentialRef::from_trusted_vault(
            ScopeId::try_from("scope.other").unwrap(),
            "vault.codex.preflight",
        )
        .unwrap(),
        fixture.source.clone(),
    )
    .unwrap();
    port.register_codex_credential_source_from_trusted_policy(wrong_scope)
        .unwrap();
    assert!(matches!(
        port.launch_resolved_codex_v2(proof),
        Err(PortDispatchError::RefusedBeforeEffect)
    ));
    assert!(slot_manifest(&fixture).is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let (fixture, _host, proof, source, calls) = setup(Role::Worker);
    claim_for_port(&fixture, &proof);
    let mut port = port_for(&fixture, &binary);
    port.register_codex_credential_source_from_trusted_policy(source)
        .unwrap();
    assert!(port.accepts_resolved_codex_v2());
    fs::set_permissions(&fixture.source, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        port.launch_resolved_codex_v2(proof),
        Err(PortDispatchError::RefusedBeforeEffect)
    ));
    assert!(slot_manifest(&fixture).is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn v2_port_rejects_duplicate_credential_registration() {
    let binary = fs::canonicalize("/bin/true").unwrap();
    let (fixture, _host, _proof, source, _) = setup(Role::Coordinator);
    let mut port = port_for(&fixture, &binary);
    port.register_codex_credential_source_from_trusted_policy(source)
        .unwrap();
    let duplicate = TrustedCodexCredentialSource::from_trusted_policy(
        CredentialRef::from_trusted_vault(fixture.scope.clone(), "vault.codex.preflight").unwrap(),
        fixture.source.clone(),
    )
    .unwrap();
    assert!(matches!(
        port.register_codex_credential_source_from_trusted_policy(duplicate),
        Err(PodError::Conflict(_))
    ));
}

#[test]
fn launch_entry_refuses_revision_store_and_credential_syntax_drift_before_manifest() {
    let binary = fs::canonicalize("/bin/true").unwrap();
    let (fixture, _host, proof, source, calls) = setup(Role::Coordinator);
    let reviewed = preflight_committed_codex_v2(&proof, &source).unwrap();
    let colon = fixture.directory.join("credential:ambiguous.key");
    assert!(matches!(
        launch_from_review(&fixture, &proof, &reviewed, &binary, &colon),
        Err(PodError::Invalid("systemd credential source path"))
    ));
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let snapshot = store.authority_snapshot().unwrap();
    store
        .apply_authority_mutation(
            snapshot.owner_epoch,
            snapshot.revision,
            podbay_store::AuthorityMutation::PutActor(snapshot.actors[0].clone()),
        )
        .unwrap();
    let after = store.authority_snapshot().unwrap();
    assert_eq!(after.resources, snapshot.resources);
    assert!(after.revision > snapshot.revision);
    assert!(matches!(
        launch_from_review(
            &fixture,
            &proof,
            &reviewed,
            &binary,
            reviewed.credential_source()
        ),
        Err(PodError::Refused("current Codex V2 authority changed"))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(
        !fs::read_dir(&fixture.directory)
            .unwrap()
            .flatten()
            .any(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
    );

    let (fixture, _host, proof, source, calls) = setup(Role::Coordinator);
    let reviewed = preflight_committed_codex_v2(&proof, &source).unwrap();
    let original = fixture.directory.join("old.sqlite");
    fs::rename(&fixture.database, &original).unwrap();
    fs::copy(&original, &fixture.database).unwrap();
    assert!(matches!(
        launch_from_review(
            &fixture,
            &proof,
            &reviewed,
            &binary,
            reviewed.credential_source()
        ),
        Err(PodError::Refused("Codex V2 store file identity changed"))
    ));
    let trusted_directory =
        TrustedNativeEventDirectory::from_trusted_policy(fixture.directory.clone()).unwrap();
    assert!(matches!(
        read_committed_codex_native_evidence(&proof, &source, &trusted_directory, None, 16),
        Err(PodError::Refused(_)),
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
#[ignore = "requires disposable user systemd and PODBAY_TEST_POD_BINARY"]
fn disposable_codex_v2_launch_serve_status_stop_without_model_turn() {
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let (fixture, _host, proof, source, calls) = setup(Role::Coordinator);
    let reviewed = preflight_committed_codex_v2(&proof, &source).unwrap();
    let record = proof.committed_record();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let claim = store
        .claim_effect(
            proof.outbox_id(),
            &record.scope_id,
            &record.pod_id,
            proof.owner_epoch(),
            record.pod_incarnation,
            proof.authority_revision(),
            &format!("claim.{}", record.receipt.command_id),
        )
        .unwrap();
    assert_eq!(claim, EffectClaim::NewClaim);
    let client = launch_from_review(
        &fixture,
        &proof,
        &reviewed,
        &binary,
        reviewed.credential_source(),
    )
    .unwrap();
    assert!(client.status().unwrap().child_running);
    assert_eq!(
        client.bound_status().unwrap().capability,
        CODEX_V2_CAPABILITY
    );
    let duplicate = launch_from_review(
        &fixture,
        &proof,
        &reviewed,
        &binary,
        reviewed.credential_source(),
    )
    .unwrap();
    assert!(duplicate.status().unwrap().child_running);
    assert_eq!(
        duplicate.bound_status().unwrap(),
        client.bound_status().unwrap()
    );
    let frames = fixture_codex_slot(&fixture).join("home/codex/frames.log");
    assert_eq!(fs::read_to_string(frames).unwrap().lines().count(), 2);
    assert!(!client.stop().unwrap().child_running);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
#[ignore = "requires disposable user systemd and PODBAY_TEST_POD_BINARY"]
fn disposable_codex_v2_port_admits_and_reattaches_without_duplicate_child() {
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let (fixture, mut host, proof, source, calls) = setup(Role::Coordinator);
    claim_for_port(&fixture, &proof);
    let mut port = port_for(&fixture, &binary);
    port.register_codex_credential_source_from_trusted_policy(source)
        .unwrap();
    assert!(matches!(
        port.launch_resolved_codex_v2(proof),
        Ok(PortDispatchOutcome::Accepted(_))
    ));
    let manifest = slot_manifest(&fixture).expect("port wrote one immutable manifest");
    let client = PodClient::connect(&manifest).unwrap();
    let attested = client.attested_status().unwrap();
    assert!(attested.child_running);
    assert_eq!(attested.bound.unwrap().capability, CODEX_V2_CAPABILITY);
    let duplicate = host
        .inspect_committed_root_codex_v2(&fixture.scope, &fixture.pod)
        .unwrap();
    assert!(matches!(
        port.launch_resolved_codex_v2(duplicate),
        Ok(PortDispatchOutcome::Accepted(_))
    ));
    assert_eq!(
        fs::read_to_string(fixture_codex_slot(&fixture).join("home/codex/frames.log"))
            .unwrap()
            .lines()
            .count(),
        2
    );
    assert!(client.attested_status().unwrap().child_running);
    assert!(!client.stop().unwrap().child_running);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
#[ignore = "requires disposable user systemd and PODBAY_TEST_POD_BINARY"]
fn disposable_codex_v3_two_roots_hold_policy_until_revocation() {
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let (fixture, mut host, transport, grant, policy) = setup_v3_wire_port(&binary);
    let epoch = PodBayStore::open_existing_read_only(&fixture.database)
        .unwrap().policy_fence_epoch().unwrap();
    let first = host.launch_new_root_codex_v3_from_wire(
        &transport,
        v3_wire_root(&fixture, grant, "request.v3.root.a", "key.v3.root.a"),
        &policy,
    ).unwrap();
    assert_eq!(first.status.stage, LaunchDispatchStage::HostAccepted);
    let snapshot_a = host.recorded_snapshot();
    assert_eq!(snapshot_a.pods.len(), 1);
    let pod_a = PodId::try_from(snapshot_a.pods[0].pod_id.as_str()).unwrap();
    let revision_a = snapshot_a.revision;
    let proof_a = host.inspect_committed_root_codex_v3(&fixture.scope, &pod_a).unwrap();
    let path_a = manifest_path_for_identity(
        &fixture.directory, &pod_a,
        &AttemptId::try_from(proof_a.committed_record().attempt_id.as_str()).unwrap(),
        Epoch::new(proof_a.committed_record().pod_incarnation).unwrap(),
    );
    let guard_a = DisposableUnitGuard::for_manifest(&path_a);
    let client_a = PodClient::connect(&path_a).unwrap();
    let status_a = client_a.attested_status().unwrap();
    assert!(status_a.child_running);
    assert_eq!(status_a.bound.as_ref().unwrap().capability, CODEX_V3_CAPABILITY);
    assert_eq!(status_a.bound.as_ref().unwrap().policy_fence.as_ref().unwrap().policy_fence_epoch, epoch);

    let second = host.launch_new_root_codex_v3_from_wire(
        &transport,
        v3_wire_root(&fixture, grant, "request.v3.root.b", "key.v3.root.b"),
        &policy,
    ).unwrap();
    assert_eq!(second.status.stage, LaunchDispatchStage::HostAccepted);
    let snapshot_b = host.recorded_snapshot();
    assert!(snapshot_b.revision > revision_a);
    assert_eq!(snapshot_b.pods.len(), 2);
    assert_eq!(PodBayStore::open_existing_read_only(&fixture.database)
        .unwrap().policy_fence_epoch().unwrap(), epoch);
    let pod_b = PodId::try_from(snapshot_b.pods.iter()
        .find(|pod| pod.pod_id != pod_a.as_str()).unwrap().pod_id.as_str()).unwrap();
    let proof_b = host.inspect_committed_root_codex_v3(&fixture.scope, &pod_b).unwrap();
    let path_b = manifest_path_for_identity(
        &fixture.directory, &pod_b,
        &AttemptId::try_from(proof_b.committed_record().attempt_id.as_str()).unwrap(),
        Epoch::new(proof_b.committed_record().pod_incarnation).unwrap(),
    );
    let guard_b = DisposableUnitGuard::for_manifest(&path_b);
    let client_b = PodClient::connect(&path_b).unwrap();
    let status_b = client_b.attested_status().unwrap();
    assert!(status_b.child_running);
    let still_a = client_a.attested_status().unwrap();
    assert!(still_a.child_running);
    assert_eq!((still_a.supervisor_pid, still_a.child_pid, still_a.child_start_ticks),
        (status_a.supervisor_pid, status_a.child_pid, status_a.child_start_ticks));

    let send_policy = TrustedBootstrapSendPolicy::from_trusted_policy(
        grant, Instant::now() + Duration::from_secs(75),
    ).unwrap();
    let session_b = SessionId::try_from(proof_b.committed_record().session_id.as_str()).unwrap();
    let lease_b = host.acquire_initial_bootstrap_writer_lease(
        &transport, &session_b, &send_policy, 90,
    ).unwrap();
    let (target_b, revision_b) = PodBayStore::open_existing_read_only(&fixture.database)
        .unwrap().current_native_writer_target_for_session(&fixture.scope, &session_b).unwrap();
    let send_b = CommandEnvelope::new(
        "request.v3.send.b", "key.v3.send.b",
        WireTarget::Session { session_id: session_b.as_str().into() },
        Some(Guard {
            manager_epoch: Some(DecimalString::new(lease_b.owner_epoch())),
            pod_epoch: Some(DecimalString::new(target_b.pod_incarnation)),
            resource_epoch: Some(DecimalString::new(target_b.resource_epoch)),
            writer_epoch: Some(DecimalString::new(lease_b.writer_epoch())),
            lease_epoch: None,
            target_revision: Some(DecimalString::new(revision_b)),
        }),
        None,
        CommandBody::SessionSend(SessionSendBody {
            content: vec![ContentBlock::Text { text: "fixture B first turn".into() }],
            policy: SendPolicy::WhenIdle,
        }),
    ).unwrap();
    let submitted = host.send_first_codex_bootstrap_from_wire(
        &transport, send_b, &send_policy,
    ).unwrap();
    assert!(submitted.port_called);
    assert!(matches!(submitted.port_observation, Some(BootstrapPortObservation::PodAccepted(_))));
    assert!(client_a.attested_status().unwrap().child_running);

    let session_a = SessionId::try_from(proof_a.committed_record().session_id.as_str()).unwrap();
    let lease_a = host.acquire_initial_bootstrap_writer_lease(
        &transport, &session_a, &send_policy, 90,
    ).unwrap();
    let (target_a, revision_a) = PodBayStore::open_existing_read_only(&fixture.database)
        .unwrap().current_native_writer_target_for_session(&fixture.scope, &session_a).unwrap();
    let make_send_a = |request_id: &str, key: &str, prompt: &str| CommandEnvelope::new(
        request_id, key,
        WireTarget::Session { session_id: session_a.as_str().into() },
        Some(Guard {
            manager_epoch: Some(DecimalString::new(lease_a.owner_epoch())),
            pod_epoch: Some(DecimalString::new(target_a.pod_incarnation)),
            resource_epoch: Some(DecimalString::new(target_a.resource_epoch)),
            writer_epoch: Some(DecimalString::new(lease_a.writer_epoch())),
            lease_epoch: None,
            target_revision: Some(DecimalString::new(revision_a)),
        }),
        None,
        CommandBody::SessionSend(SessionSendBody {
            content: vec![ContentBlock::Text { text: prompt.into() }],
            policy: SendPolicy::WhenIdle,
        }),
    ).unwrap();
    let submitted_a = host.send_first_codex_bootstrap_from_wire(
        &transport,
        make_send_a("request.v3.send.a.first", "key.v3.send.a.first", "A after B admission"),
        &send_policy,
    ).unwrap();
    assert!(submitted_a.port_called);
    assert!(matches!(submitted_a.port_observation,
        Some(BootstrapPortObservation::PodAccepted(_))));
    assert!(client_a.attested_status().unwrap().child_running);
    let home_a = codex_private_slot_directory(&fixture.directory, &guard_a.0, false)
        .unwrap().join("home/codex/frames.log");
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if fs::read_to_string(&home_a).unwrap_or_default().lines().count() == 5 { break; }
        assert!(Instant::now() < deadline, "A did not receive its first native turn after B");
        std::thread::sleep(Duration::from_millis(10));
    }
    host.revoke_grant_from_trusted_policy(grant).unwrap();
    assert_eq!(PodBayStore::open_existing_read_only(&fixture.database)
        .unwrap().policy_fence_epoch().unwrap(), epoch + 1);
    assert!(client_a.attested_status().is_err());
    assert!(matches!(host.send_first_codex_bootstrap_from_wire(
        &transport,
        make_send_a("request.v3.send.a.after-revoke", "key.v3.send.a.after-revoke",
            "must not reach native A"),
        &send_policy,
    ), Err(BootstrapSendError::Host(HostError::Unauthorised))));
    assert_eq!(fs::read_to_string(home_a).unwrap().lines().count(), 5);

    for unit in [&guard_a.0, &guard_b.0] {
        assert!(Command::new("systemctl").args(["--user", "stop", unit])
            .status().unwrap().success());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let state = Command::new("systemctl")
                .args(["--user", "show", "--property=LoadState", "--value", unit])
                .output().unwrap();
            assert!(state.status.success());
            if String::from_utf8_lossy(&state.stdout).trim() == "not-found" { break; }
            assert!(Instant::now() < deadline, "V3 disposable unit remained loaded: {unit}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[test]
#[ignore = "helper for disposable two-process V2 rebind fixture"]
fn rebind_first_manager_process_helper() {
    let fixture = Fixture::from_shared();
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let mut port = port_for(&fixture, &binary);
    let reference =
        CredentialRef::from_trusted_vault(fixture.scope.clone(), "vault.codex.preflight").unwrap();
    port.register_codex_credential_source_from_trusted_policy(
        TrustedCodexCredentialSource::from_trusted_policy(reference, fixture.source.clone())
            .unwrap(),
    )
    .unwrap();
    let (fixture, mut host, _, _, transport, request) = setup_with_port(
        Role::Coordinator,
        fixture,
        port,
        Duration::from_secs(30),
        60,
    );
    let accepted = host
        .dispatch_prepared_bound_root_codex_v2(&transport, request)
        .unwrap();
    assert_eq!(accepted.status.stage, LaunchDispatchStage::HostAccepted);
    let manifest = slot_manifest(&fixture).unwrap();
    let before = PodClient::connect(&manifest)
        .unwrap()
        .attested_status()
        .unwrap();
    assert!(before.child_running);
    fs::write(
        fixture.directory.join("rebind.first.pid"),
        before.child_pid.to_string(),
    )
    .unwrap();
    fs::write(
        fixture.directory.join("rebind.first.births"),
        format!("{}:{}:{}",before.supervisor_pid,before.supervisor_start_ticks,
            before.child_start_ticks),
    ).unwrap();
    drop(host);
    std::mem::forget(fixture);
}

#[test]
#[ignore = "helper for disposable two-process V2 rebind fixture"]
fn rebind_second_manager_process_helper() {
    let fixture = Fixture::from_shared();
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let mut port = port_for(&fixture, &binary);
    let reference =
        CredentialRef::from_trusted_vault(fixture.scope.clone(), "vault.codex.preflight").unwrap();
    port.register_codex_credential_source_from_trusted_policy(
        TrustedCodexCredentialSource::from_trusted_policy(reference, fixture.source.clone())
            .unwrap(),
    )
    .unwrap();
    let mut host = DurableAuthority::open(&fixture.database, port).unwrap();
    register_restarted_codex_profile(&mut host, &fixture);
    let frames = fixture_codex_slot(&fixture).join("home/codex/frames.log");
    assert_eq!(fs::read_to_string(&frames).unwrap().lines().count(), 2);
    let actor = ActorId::try_from("actor.codex.preflight").unwrap();
    let process = AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(
        1000,
        4242,
        777,
        "/user.slice/preflight.scope",
    )
    .unwrap();
    let transport = Transport(AuthenticatedPeer::owner_cli_from_authenticated_transport(
        process.clone(),
        CredentialGeneration::new(1).unwrap(),
    ));
    host.reattest_actor_from_trusted_replay(
        &transport,
        ActorRegistration::owner_cli_from_trusted_policy(
            actor.clone(),
            fixture.scope.clone(),
            process,
            CredentialGeneration::new(1).unwrap(),
        ),
    )
    .unwrap();
    let recorded_id = host.recorded_snapshot().grants[0].grant_id;
    let grant_id = host
        .activate_recorded_grant_for_actor_from_trusted_replay(&actor, &fixture.scope, recorded_id)
        .unwrap();
    let policy = TrustedBootstrapSendPolicy::from_trusted_policy(
        grant_id,
        Instant::now() + Duration::from_secs(45),
    )
    .unwrap();
    let session_id = SessionId::try_from("session.codex.preflight").unwrap();
    let lease = host
        .acquire_initial_bootstrap_writer_lease(&transport, &session_id, &policy, 60)
        .unwrap();
    let (target, session_revision) = PodBayStore::open(&fixture.database)
        .unwrap()
        .current_native_writer_target_for_session(&fixture.scope, &session_id)
        .unwrap();
    let send = CommandEnvelope::new(
        "request.rebind.bootstrap.one",
        "key.rebind.bootstrap.one",
        WireTarget::Session {
            session_id: session_id.as_str().into(),
        },
        Some(Guard {
            manager_epoch: Some(DecimalString::new(lease.owner_epoch())),
            pod_epoch: Some(DecimalString::new(target.pod_incarnation)),
            resource_epoch: Some(DecimalString::new(target.resource_epoch)),
            writer_epoch: Some(DecimalString::new(lease.writer_epoch())),
            lease_epoch: None,
            target_revision: Some(DecimalString::new(session_revision)),
        }),
        None,
        CommandBody::SessionSend(SessionSendBody {
            content: vec![ContentBlock::Text {
                text: "first turn after manager rebind".into(),
            }],
            policy: SendPolicy::WhenIdle,
        }),
    )
    .unwrap();
    let pending = host
        .prepare_current_codex_v2_rebind(&fixture.scope, &fixture.pod, "rebind.native.v2.one")
        .unwrap();
    assert_eq!(pending.phase, podbay_store::DurableRebindPhase::Pending);
    assert!(matches!(
        host.send_first_codex_bootstrap_from_wire(&transport, send.clone(), &policy),
        Err(podbay_host::BootstrapSendError::Store(
            podbay_store::StoreError::Conflict("Codex V2 launch is not HostAccepted")
        ))
    ));
    assert_eq!(fs::read_to_string(&frames).unwrap().lines().count(), 2);
    let completed = host
        .complete_current_codex_v2_rebind(&fixture.scope, &fixture.pod, "rebind.native.v2.one")
        .unwrap();
    assert_eq!(
        completed.durable.phase,
        podbay_store::DurableRebindPhase::Activated
    );
    assert_eq!(completed.stage, RebindCompletionStage::PodActive);
    let repeated = host
        .complete_current_codex_v2_rebind(&fixture.scope, &fixture.pod, "rebind.native.v2.one")
        .unwrap();
    assert_eq!(repeated.durable, completed.durable);
    assert_eq!(repeated.stage, RebindCompletionStage::PodActive);
    assert_eq!(
        repeated.active_checkpoint_digest,
        completed.active_checkpoint_digest
    );
    let manifest = slot_manifest(&fixture).unwrap();
    let client = PodClient::connect(&manifest).unwrap();
    let after = client.attested_status().unwrap();
    let before_pid: u32 = fs::read_to_string(fixture.directory.join("rebind.first.pid"))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(after.pod_id, fixture.pod.as_str());
    assert_eq!(after.child_pid, before_pid);
    assert!(after.child_running);
    run_rebind_manager_helper("rebind_sibling_status_process_helper", &fixture, &binary);
    let submitted = host
        .send_first_codex_bootstrap_from_wire(&transport, send.clone(), &policy)
        .unwrap();
    assert!(
        matches!(
            submitted.port_observation,
            Some(BootstrapPortObservation::PodAccepted(_))
        ),
        "rebound bootstrap observation: {:?}",
        submitted.port_observation,
    );
    let duplicate = host
        .send_first_codex_bootstrap_from_wire(&transport, send, &policy)
        .unwrap();
    assert_eq!(duplicate.receipt, submitted.receipt);
    assert!(
        !duplicate.port_called,
        "same-key replay cannot send a second native turn"
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    while fs::read_to_string(&frames)
        .unwrap_or_default()
        .lines()
        .count()
        != 5
    {
        assert!(
            Instant::now() < deadline,
            "rebound manager did not send one fake turn"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(client.attested_status().unwrap().child_pid, before_pid);
    let events = client.read_codex_native_events(None, 16).unwrap();
    assert_eq!(events.snapshot.identity.pod_id, fixture.pod.as_str());
    let rebound_proof = host
        .inspect_committed_root_codex_v2(&fixture.scope, &fixture.pod)
        .unwrap();
    let read_source = TrustedCodexCredentialSource::from_trusted_policy(
        CredentialRef::from_trusted_vault(
            fixture.scope.clone(),
            "vault.codex.preflight",
        )
        .unwrap(),
        fixture.source.clone(),
    )
    .unwrap();
    let trusted_directory =
        TrustedNativeEventDirectory::from_trusted_policy(fixture.directory.clone()).unwrap();
    let manager_events = read_committed_codex_native_evidence(
        &rebound_proof,
        &read_source,
        &trusted_directory,
        None,
        16,
    )
    .unwrap();
    assert_eq!(manager_events.redacted().snapshot.identity.pod_id, fixture.pod.as_str());
    assert!(!client.stop().unwrap().child_running);
    fs::write(
        fixture.directory.join("rebind.second.done"),
        before_pid.to_string(),
    )
    .unwrap();
    drop(host);
    std::mem::forget(fixture);
}

#[test]
#[ignore = "helper for disposable B store-only Pending / pod Active A fixture"]
fn rebind_second_store_only_pending_active_prior_helper() {
    let fixture = Fixture::from_shared();
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let mut port = port_for(&fixture, &binary);
    let reference =
        CredentialRef::from_trusted_vault(fixture.scope.clone(), "vault.codex.preflight").unwrap();
    port.register_codex_credential_source_from_trusted_policy(
        TrustedCodexCredentialSource::from_trusted_policy(reference, fixture.source.clone())
            .unwrap(),
    )
    .unwrap();
    let mut host = DurableAuthority::open(&fixture.database, port).unwrap();
    register_restarted_codex_profile(&mut host, &fixture);

    // B commits Pending in the store, then dies before calling the pod's
    // Prepare operation. The pod must still expose A's Active checkpoint.
    let pending = host
        .prepare_current_codex_v2_rebind(
            &fixture.scope,
            &fixture.pod,
            "rebind.native.v21.active-prior.b",
        )
        .unwrap();
    assert_eq!(pending.phase, podbay_store::DurableRebindPhase::Pending);
    assert_eq!(
        PodBayStore::open_existing_read_only(&fixture.database)
            .unwrap()
            .owner_epoch()
            .unwrap(),
        2
    );
    let context = host.rebind_context(&fixture.scope, &fixture.pod).unwrap();
    let checkpoint = podbay_pod::read_peer_checkpoint(&fixture.directory, context.identity())
        .unwrap()
        .checkpoint();
    assert_eq!(checkpoint.phase(), RebindPhase::Active);
    assert_eq!(checkpoint.owner_epoch().get(), 1);
    assert!(checkpoint.pending_rebind().is_none());
    assert_eq!(
        fs::read_to_string(fixture_codex_slot(&fixture).join("home/codex/frames.log"))
            .unwrap()
            .lines()
            .count(),
        2
    );
    fs::write(
        fixture.directory.join("rebind.second.store_only_pending"),
        b"store_pending_pod_active_a",
    )
    .unwrap();
    drop(context);
    drop(host);
    std::mem::forget(fixture);
}

#[test]
#[ignore = "helper for disposable C store-only Pending after B was abandoned"]
fn rebind_third_store_only_pending_active_prior_helper() {
    let fixture = Fixture::from_shared();
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let mut port = port_for(&fixture, &binary);
    let reference =
        CredentialRef::from_trusted_vault(fixture.scope.clone(), "vault.codex.preflight").unwrap();
    port.register_codex_credential_source_from_trusted_policy(
        TrustedCodexCredentialSource::from_trusted_policy(reference, fixture.source.clone())
            .unwrap(),
    )
    .unwrap();
    let mut host = DurableAuthority::open(&fixture.database, port).unwrap();
    register_restarted_codex_profile(&mut host, &fixture);
    let pending = host.prepare_current_codex_v2_rebind(
        &fixture.scope, &fixture.pod, "rebind.native.v21.active-prior.c.store-only",
    ).unwrap();
    assert_eq!(pending.phase, podbay_store::DurableRebindPhase::Pending);
    let context = host.rebind_context(&fixture.scope, &fixture.pod).unwrap();
    let checkpoint = podbay_pod::read_peer_checkpoint(&fixture.directory, context.identity())
        .unwrap().checkpoint();
    assert_eq!(checkpoint.phase(), RebindPhase::Active);
    assert_eq!(checkpoint.owner_epoch().get(), 1);
    assert!(checkpoint.pending_rebind().is_none());
    assert_eq!(fs::read_to_string(fixture_codex_slot(&fixture).join("home/codex/frames.log"))
        .unwrap().lines().count(), 2);
    fs::write(fixture.directory.join("rebind.third.store_only_pending"),
        b"c_pending_pod_active_a").unwrap();
    drop(context);
    drop(host);
    std::mem::forget(fixture);
}

#[test]
#[ignore = "helper for disposable C active-prior normal rebind fixture"]
fn rebind_third_active_prior_rebind_manager_process_helper() {
    let fixture = Fixture::from_shared();
    let expected_owner = std::env::var("PODBAY_RECOVERY_OWNER")
        .ok().and_then(|value| value.parse::<u64>().ok()).unwrap_or(3);
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let mut port = port_for(&fixture, &binary);
    let reference =
        CredentialRef::from_trusted_vault(fixture.scope.clone(), "vault.codex.preflight").unwrap();
    port.register_codex_credential_source_from_trusted_policy(
        TrustedCodexCredentialSource::from_trusted_policy(reference, fixture.source.clone())
            .unwrap(),
    )
    .unwrap();
    let mut host = DurableAuthority::open(&fixture.database, port).unwrap();
    register_restarted_codex_profile(&mut host, &fixture);
    let frames = fixture_codex_slot(&fixture).join("home/codex/frames.log");
    assert_eq!(fs::read_to_string(&frames).unwrap().lines().count(), 2);

    // The current manager uses its own key. The host/store reconcile the
    // latest store-only Pending against A's still-Active pod checkpoint.
    let key = format!("rebind.native.v21.active-prior.owner{expected_owner}");
    let pending = host
        .prepare_current_codex_v2_rebind(&fixture.scope, &fixture.pod, &key)
        .unwrap();
    assert_eq!(pending.phase, podbay_store::DurableRebindPhase::Pending);
    let completed = host
        .complete_current_codex_v2_rebind(&fixture.scope, &fixture.pod, &key)
        .unwrap();
    assert_eq!(completed.stage, RebindCompletionStage::PodActive);
    assert_eq!(
        completed.durable.phase,
        podbay_store::DurableRebindPhase::Activated
    );
    let manifest = slot_manifest(&fixture).unwrap();
    let client = PodClient::connect(&manifest).unwrap();
    let active = client.attested_status().unwrap();
    assert_eq!(active.pod_id, fixture.pod.as_str());
    assert!(active.child_running);
    let original_pid: u32 = fs::read_to_string(fixture.directory.join("rebind.first.pid"))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(active.child_pid, original_pid);
    assert_eq!(
        fs::read_to_string(fixture.directory.join("rebind.first.births")).unwrap(),
        format!(
            "{}:{}:{}",
            active.supervisor_pid, active.supervisor_start_ticks, active.child_start_ticks
        )
    );
    let context = host.rebind_context(&fixture.scope, &fixture.pod).unwrap();
    let checkpoint = podbay_pod::read_peer_checkpoint(&fixture.directory, context.identity())
        .unwrap()
        .checkpoint();
    assert_eq!(checkpoint.phase(), RebindPhase::Active);
    assert_eq!(checkpoint.owner_epoch().get(), expected_owner);
    assert!(checkpoint.pending_rebind().is_none());
    drop(context);
    run_rebind_manager_helper("rebind_sibling_status_process_helper", &fixture, &binary);

    let actor = ActorId::try_from("actor.codex.preflight").unwrap();
    let process = AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(
        1000,
        4242,
        777,
        "/user.slice/preflight.scope",
    )
    .unwrap();
    let transport = Transport(AuthenticatedPeer::owner_cli_from_authenticated_transport(
        process.clone(),
        CredentialGeneration::new(1).unwrap(),
    ));
    host.reattest_actor_from_trusted_replay(
        &transport,
        ActorRegistration::owner_cli_from_trusted_policy(
            actor.clone(),
            fixture.scope.clone(),
            process,
            CredentialGeneration::new(1).unwrap(),
        ),
    )
    .unwrap();
    let recorded_id = host.recorded_snapshot().grants[0].grant_id;
    let grant_id = host
        .activate_recorded_grant_for_actor_from_trusted_replay(&actor, &fixture.scope, recorded_id)
        .unwrap();
    let policy = TrustedBootstrapSendPolicy::from_trusted_policy(
        grant_id,
        Instant::now() + Duration::from_secs(45),
    )
    .unwrap();
    let session_id = SessionId::try_from("session.codex.preflight").unwrap();
    let lease = host
        .acquire_initial_bootstrap_writer_lease(&transport, &session_id, &policy, 60)
        .unwrap();
    let (target, session_revision) = PodBayStore::open_existing_read_only(&fixture.database)
        .unwrap()
        .current_native_writer_target_for_session(&fixture.scope, &session_id)
        .unwrap();
    let send = CommandEnvelope::new(
        &format!("request.rebind.active-prior.owner{expected_owner}.first-turn"),
        &format!("key.rebind.active-prior.owner{expected_owner}.first-turn"),
        WireTarget::Session {
            session_id: session_id.as_str().into(),
        },
        Some(Guard {
            manager_epoch: Some(DecimalString::new(lease.owner_epoch())),
            pod_epoch: Some(DecimalString::new(target.pod_incarnation)),
            resource_epoch: Some(DecimalString::new(target.resource_epoch)),
            writer_epoch: Some(DecimalString::new(lease.writer_epoch())),
            lease_epoch: None,
            target_revision: Some(DecimalString::new(session_revision)),
        }),
        None,
        CommandBody::SessionSend(SessionSendBody {
            content: vec![ContentBlock::Text {
                text: format!("first turn after Active A / Pending prior owner {expected_owner}"),
            }],
            policy: SendPolicy::WhenIdle,
        }),
    )
    .unwrap();
    let submitted = host
        .send_first_codex_bootstrap_from_wire(&transport, send.clone(), &policy)
        .unwrap();
    assert!(matches!(
        submitted.port_observation,
        Some(BootstrapPortObservation::PodAccepted(_))
    ));
    assert!(submitted.port_called);
    let duplicate = host
        .send_first_codex_bootstrap_from_wire(&transport, send, &policy)
        .unwrap();
    assert!(duplicate.duplicate);
    assert!(!duplicate.port_called);
    assert_eq!(duplicate.receipt, submitted.receipt);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if fs::read_to_string(&frames).unwrap_or_default().lines().count() == 5 {
            break;
        }
        assert!(Instant::now() < deadline, "last manager did not submit one fake native turn");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(client.attested_status().unwrap().child_pid, original_pid);
    assert!(!client.stop().unwrap().child_running);
    fs::write(
        fixture.directory.join(format!("rebind.owner{expected_owner}.active_prior.done")),
        original_pid.to_string(),
    )
    .unwrap();
    drop(host);
    std::mem::forget(fixture);
}

#[test]
#[ignore = "helper for disposable three-manager pending recovery inspect fixture"]
fn rebind_second_pending_manager_process_helper() {
    let fixture = Fixture::from_shared();
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let mut port = port_for(&fixture, &binary);
    let reference = CredentialRef::from_trusted_vault(
        fixture.scope.clone(), "vault.codex.preflight",
    ).unwrap();
    port.register_codex_credential_source_from_trusted_policy(
        TrustedCodexCredentialSource::from_trusted_policy(
            reference, fixture.source.clone(),
        ).unwrap(),
    ).unwrap();
    let mut host = DurableAuthority::open(&fixture.database, PendingThenLostPort(port)).unwrap();
    register_restarted_codex_profile(&mut host, &fixture);
    let pending = host.prepare_current_codex_v2_rebind(
        &fixture.scope, &fixture.pod, "rebind.native.v21.pending",
    ).unwrap();
    assert_eq!(pending.phase, podbay_store::DurableRebindPhase::Pending);
    let completed = host.complete_current_codex_v2_rebind(
        &fixture.scope, &fixture.pod, "rebind.native.v21.pending",
    ).unwrap();
    assert_eq!(completed.durable.phase, podbay_store::DurableRebindPhase::Pending);
    assert_eq!(completed.stage, RebindCompletionStage::PendingPodUnknown);
    let context = host.rebind_context(&fixture.scope, &fixture.pod).unwrap();
    let checkpoint = podbay_pod::read_peer_checkpoint(
        &fixture.directory, context.identity(),
    ).unwrap();
    assert_eq!(checkpoint.phase(), RebindPhase::PendingPod);
    assert!(checkpoint.checkpoint().pending_rebind().is_some());
    fs::write(fixture.directory.join("rebind.second.pending"), b"pending_pod").unwrap();
    drop(context);
    drop(host);
    std::mem::forget(fixture);
}

#[test]
#[ignore = "helper for disposable B fsynced PendingStore crash fixture"]
fn rebind_second_pending_store_manager_process_helper() {
    let fixture = Fixture::from_shared();
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let mut port = port_for(&fixture, &binary);
    let reference =
        CredentialRef::from_trusted_vault(fixture.scope.clone(), "vault.codex.preflight").unwrap();
    port.register_codex_credential_source_from_trusted_policy(
        TrustedCodexCredentialSource::from_trusted_policy(reference, fixture.source.clone())
            .unwrap(),
    )
    .unwrap();
    let mut host = DurableAuthority::open(&fixture.database, PendingThenLostPort(port)).unwrap();
    register_restarted_codex_profile(&mut host, &fixture);
    let pending = host
        .prepare_current_codex_v2_rebind(
            &fixture.scope,
            &fixture.pod,
            "rebind.native.v21.pending-store",
        )
        .unwrap();
    assert_eq!(pending.phase, podbay_store::DurableRebindPhase::Pending);
    let completed = host
        .complete_current_codex_v2_rebind(
            &fixture.scope,
            &fixture.pod,
            "rebind.native.v21.pending-store",
        )
        .unwrap();
    assert_eq!(completed.durable.phase, podbay_store::DurableRebindPhase::Pending);
    assert_eq!(completed.stage, RebindCompletionStage::PendingPodUnknown);
    let context = host.rebind_context(&fixture.scope, &fixture.pod).unwrap();
    let checkpoint = podbay_pod::read_peer_checkpoint(&fixture.directory, context.identity())
        .unwrap()
        .checkpoint();
    assert_eq!(checkpoint.phase(), RebindPhase::PendingStore);
    assert!(checkpoint.pending_rebind().is_some());
    fs::write(
        fixture.directory.join("rebind.second.pending_store"),
        b"pending_store",
    )
    .unwrap();
    drop(context);
    drop(host);
    std::mem::forget(fixture);
}

#[test]
#[ignore = "helper for disposable B store-Activated/pod-PendingPod fixture"]
fn rebind_second_store_activated_manager_process_helper() {
    let fixture = Fixture::from_shared();
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let mut port = port_for(&fixture, &binary);
    let reference =
        CredentialRef::from_trusted_vault(fixture.scope.clone(), "vault.codex.preflight").unwrap();
    port.register_codex_credential_source_from_trusted_policy(
        TrustedCodexCredentialSource::from_trusted_policy(reference, fixture.source.clone())
            .unwrap(),
    )
    .unwrap();
    let mut host = DurableAuthority::open(&fixture.database, ActivatedThenLostPort(port)).unwrap();
    register_restarted_codex_profile(&mut host, &fixture);
    let pending = host
        .prepare_current_codex_v2_rebind(
            &fixture.scope,
            &fixture.pod,
            "rebind.native.v21.store-activated",
        )
        .unwrap();
    assert_eq!(pending.phase, podbay_store::DurableRebindPhase::Pending);
    let completed = host
        .complete_current_codex_v2_rebind(
            &fixture.scope,
            &fixture.pod,
            "rebind.native.v21.store-activated",
        )
        .unwrap();
    assert_eq!(
        completed.durable.phase,
        podbay_store::DurableRebindPhase::Activated
    );
    assert_eq!(
        completed.stage,
        RebindCompletionStage::StoreActivatedPodUnconfirmed
    );
    let context = host.rebind_context(&fixture.scope, &fixture.pod).unwrap();
    let checkpoint = podbay_pod::read_peer_checkpoint(&fixture.directory, context.identity())
        .unwrap()
        .checkpoint();
    assert_eq!(checkpoint.phase(), RebindPhase::PendingPod);
    assert_eq!(checkpoint.owner_epoch().get(), 1);
    assert!(checkpoint.pending_rebind().is_some());
    drop(context);
    fs::write(
        fixture.directory.join("rebind.second.activated"),
        b"store_activated_pod_pending",
    )
    .unwrap();
    drop(host);
    std::mem::forget(fixture);
}

#[test]
#[ignore = "helper for disposable three-manager pending recovery inspect fixture"]
fn rebind_third_recover_manager_process_helper() {
    let fixture = Fixture::from_shared();
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let mut port = port_for(&fixture, &binary);
    let reference = CredentialRef::from_trusted_vault(
        fixture.scope.clone(), "vault.codex.preflight",
    ).unwrap();
    port.register_codex_credential_source_from_trusted_policy(
        TrustedCodexCredentialSource::from_trusted_policy(
            reference, fixture.source.clone(),
        ).unwrap(),
    ).unwrap();
    let mut host = DurableAuthority::open(&fixture.database, port).unwrap();
    register_restarted_codex_profile(&mut host, &fixture);
    let proof = host.inspect_pending_codex_v2_recovery(&fixture.scope, &fixture.pod).unwrap();
    let expected_phase = if fixture.directory.join("rebind.second.pending_store").exists() {
        RebindPhase::PendingStore
    } else {
        RebindPhase::PendingPod
    };
    assert_eq!(proof.pending_phase(), expected_phase);
    assert_eq!(proof.abandoned().identity.pod_id, fixture.pod);
    assert_eq!(proof.pending_process().child_process_id,
        fs::read_to_string(fixture.directory.join("rebind.first.pid")).unwrap());
    let planned = host.plan_current_codex_v2_recovery(
        &fixture.scope, &fixture.pod, "recover.native.v21.c",
    ).unwrap();
    assert_eq!(planned.stage, podbay_store::SupersessionStage::Planned);
    let completed = host.complete_current_codex_v2_recovery(
        &fixture.scope, &fixture.pod, "recover.native.v21.c",
    ).unwrap();
    assert_eq!(completed.stage, RecoveryCompletionStage::PodCheckpointed);
    assert_eq!(completed.durable.stage, podbay_store::SupersessionStage::PodCheckpointed);
    assert!(completed.active_checkpoint_digest.is_some());
    let context = host.rebind_context(&fixture.scope, &fixture.pod).unwrap();
    let recovered = podbay_pod::read_peer_checkpoint(&fixture.directory, context.identity())
        .unwrap().checkpoint();
    assert_eq!(recovered.phase(), RebindPhase::Active);
    assert_eq!(recovered.owner_epoch().get(), 1);
    assert_eq!(recovered.credential_epoch().get(), 1);
    assert_eq!(recovered.input_epochs().values().next().unwrap().get(), 2);
    assert!(recovered.pending_rebind().is_none());
    assert!(recovered.last_rebind().is_none());
    drop(context);
    let next = host.prepare_current_codex_v2_rebind(
        &fixture.scope, &fixture.pod, "rebind.after.recovery.c",
    ).unwrap();
    assert_eq!(next.phase, podbay_store::DurableRebindPhase::Pending);
    let store = PodBayStore::open_existing_read_only(&fixture.database).unwrap();
    assert_eq!(store.owner_epoch().unwrap(), 3);
    fs::write(fixture.directory.join("rebind.third.inspected"),
        completed.active_checkpoint_digest.as_deref().unwrap()).unwrap();
    drop(store);
    drop(host);
    std::mem::forget(fixture);
}

#[test]
#[ignore = "helper for disposable four-manager C lost-ACK fixture"]
fn rebind_third_lost_recovery_ack_helper() {
    let fixture = Fixture::from_shared();
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let mut port = port_for(&fixture,&binary);
    let reference = CredentialRef::from_trusted_vault(
        fixture.scope.clone(),"vault.codex.preflight",
    ).unwrap();
    port.register_codex_credential_source_from_trusted_policy(
        TrustedCodexCredentialSource::from_trusted_policy(
            reference,fixture.source.clone(),
        ).unwrap(),
    ).unwrap();
    let mut host = DurableAuthority::open(&fixture.database,RecoveryThenLostPort(port)).unwrap();
    register_restarted_codex_profile(&mut host,&fixture);
    let planned = host.plan_current_codex_v2_recovery(
        &fixture.scope,&fixture.pod,"recover.native.v21.c.lost",
    ).unwrap();
    assert_eq!(planned.stage,podbay_store::SupersessionStage::Planned);
    let result = host.complete_current_codex_v2_recovery(
        &fixture.scope,&fixture.pod,"recover.native.v21.c.lost",
    ).unwrap();
    assert_eq!(result.stage,RecoveryCompletionStage::PodRecoveryUnknown);
    assert_eq!(result.durable.stage,podbay_store::SupersessionStage::Planned);
    let context = host.rebind_context(&fixture.scope,&fixture.pod).unwrap();
    let checkpoint = podbay_pod::read_peer_checkpoint(&fixture.directory,context.identity())
        .unwrap().checkpoint();
    assert_eq!(checkpoint.phase(),RebindPhase::Active);
    assert_eq!(checkpoint.owner_epoch().get(),1);
    assert_eq!(checkpoint.input_epochs().values().next().unwrap().get(),2);
    assert!(checkpoint.pending_rebind().is_none());
    assert!(checkpoint.last_rebind().is_none());
    drop(context);
    fs::write(fixture.directory.join("rebind.third.lost"),b"active_a_store_planned").unwrap();
    drop(host);
    std::mem::forget(fixture);
}

#[test]
#[ignore = "helper for disposable D successor Planned-before-ACK crash"]
fn rebind_fourth_lost_adoption_ack_helper() {
    let fixture = Fixture::from_shared();
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let mut port = port_for(&fixture, &binary);
    let reference =
        CredentialRef::from_trusted_vault(fixture.scope.clone(), "vault.codex.preflight").unwrap();
    port.register_codex_credential_source_from_trusted_policy(
        TrustedCodexCredentialSource::from_trusted_policy(reference, fixture.source.clone())
            .unwrap(),
    )
    .unwrap();
    let mut host = DurableAuthority::open(
        &fixture.database,
        AdoptionThenLostPort(port, AtomicUsize::new(0)),
    )
    .unwrap();
    register_restarted_codex_profile(&mut host, &fixture);
    let outcome = host
        .adopt_recovered_active_codex_v2(
            &fixture.scope,
            &fixture.pod,
            "recover.native.v21.d.lost-ack",
        )
        .unwrap();
    assert_eq!(outcome.stage, RecoveryCompletionStage::PodRecoveryUnknown);
    assert_eq!(
        outcome.durable.stage,
        podbay_store::SupersessionStage::Planned
    );
    assert_eq!(host.port().1.load(Ordering::SeqCst), 3);
    let identity = host
        .rebind_context(&fixture.scope, &fixture.pod)
        .unwrap()
        .identity()
        .clone();
    let checkpoint = podbay_pod::read_peer_checkpoint(&fixture.directory, &identity)
        .unwrap()
        .checkpoint();
    assert_eq!(checkpoint.phase(), RebindPhase::Active);
    assert_eq!(checkpoint.owner_epoch().get(), 1);
    assert_eq!(checkpoint.input_epochs().values().next().unwrap().get(), 2);
    fs::write(
        fixture.directory.join("rebind.fourth.lost"),
        b"d_planned_no_ack",
    )
    .unwrap();
    drop(host);
    std::mem::forget(fixture);
}

#[test]
#[ignore = "helper for disposable four-manager D adoption fixture"]
fn rebind_fourth_adopt_manager_process_helper() {
    let fixture = Fixture::from_shared();
    let expected_owner = std::env::var("PODBAY_RECOVERY_OWNER")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(4);
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let mut port = port_for(&fixture, &binary);
    let reference =
        CredentialRef::from_trusted_vault(fixture.scope.clone(), "vault.codex.preflight").unwrap();
    port.register_codex_credential_source_from_trusted_policy(
        TrustedCodexCredentialSource::from_trusted_policy(reference, fixture.source.clone())
            .unwrap(),
    )
    .unwrap();
    let mut host = DurableAuthority::open(&fixture.database, port).unwrap();
    register_restarted_codex_profile(&mut host, &fixture);
    let adopt_key = format!("recover.native.v21.owner{expected_owner}.adopt");
    let rebind_key = format!("rebind.after.recovery.owner{expected_owner}");
    let adopted = host
        .adopt_recovered_active_codex_v2(&fixture.scope, &fixture.pod, &adopt_key)
        .unwrap();
    assert_eq!(adopted.stage, RecoveryCompletionStage::PodCheckpointed);
    assert_eq!(
        adopted.durable.stage,
        podbay_store::SupersessionStage::PodCheckpointed
    );
    let next = host
        .prepare_current_codex_v2_rebind(&fixture.scope, &fixture.pod, &rebind_key)
        .unwrap();
    assert_eq!(next.phase, podbay_store::DurableRebindPhase::Pending);
    let completed = host
        .complete_current_codex_v2_rebind(&fixture.scope, &fixture.pod, &rebind_key)
        .unwrap();
    assert_eq!(completed.stage, RebindCompletionStage::PodActive);
    let manifest = slot_manifest(&fixture).unwrap();
    let client = PodClient::connect(&manifest).unwrap();
    let active = client.attested_status().unwrap();
    assert!(active.child_running);
    run_rebind_manager_helper("rebind_sibling_status_process_helper", &fixture, &binary);
    let original_pid: u32 = fs::read_to_string(fixture.directory.join("rebind.first.pid"))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(active.child_pid, original_pid);
    let births = fs::read_to_string(fixture.directory.join("rebind.first.births")).unwrap();
    assert_eq!(
        births,
        format!(
            "{}:{}:{}",
            active.supervisor_pid, active.supervisor_start_ticks, active.child_start_ticks
        )
    );
    let identity = host
        .rebind_context(&fixture.scope, &fixture.pod)
        .unwrap()
        .identity()
        .clone();
    let checkpoint = podbay_pod::read_peer_checkpoint(&fixture.directory, &identity)
        .unwrap()
        .checkpoint();
    assert_eq!(checkpoint.owner_epoch().get(), expected_owner);
    assert_eq!(
        checkpoint.input_epochs().values().next().unwrap().get(),
        expected_owner
    );
    let actor = ActorId::try_from("actor.codex.preflight").unwrap();
    let process = AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(
        1000,
        4242,
        777,
        "/user.slice/preflight.scope",
    )
    .unwrap();
    let transport = Transport(AuthenticatedPeer::owner_cli_from_authenticated_transport(
        process.clone(),
        CredentialGeneration::new(1).unwrap(),
    ));
    host.reattest_actor_from_trusted_replay(
        &transport,
        ActorRegistration::owner_cli_from_trusted_policy(
            actor.clone(),
            fixture.scope.clone(),
            process,
            CredentialGeneration::new(1).unwrap(),
        ),
    )
    .unwrap();
    let recorded_id = host.recorded_snapshot().grants[0].grant_id;
    let grant = host
        .activate_recorded_grant_for_actor_from_trusted_replay(&actor, &fixture.scope, recorded_id)
        .unwrap();
    let send_policy = TrustedBootstrapSendPolicy::from_trusted_policy(
        grant,
        Instant::now() + Duration::from_secs(45),
    )
    .unwrap();
    let session_id = SessionId::try_from("session.codex.preflight").unwrap();
    let lease = host
        .acquire_initial_bootstrap_writer_lease(&transport, &session_id, &send_policy, 60)
        .unwrap();
    let (target, revision) = PodBayStore::open_existing_read_only(&fixture.database)
        .unwrap()
        .current_native_writer_target_for_session(&fixture.scope, &session_id)
        .unwrap();
    let turn_request = format!("request.rebind.owner{expected_owner}.turn");
    let turn_key = format!("key.rebind.owner{expected_owner}.turn");
    let send = CommandEnvelope::new(
        &turn_request,
        &turn_key,
        WireTarget::Session {
            session_id: session_id.as_str().into(),
        },
        Some(Guard {
            manager_epoch: Some(DecimalString::new(lease.owner_epoch())),
            pod_epoch: Some(DecimalString::new(target.pod_incarnation)),
            resource_epoch: Some(DecimalString::new(target.resource_epoch)),
            writer_epoch: Some(DecimalString::new(lease.writer_epoch())),
            lease_epoch: None,
            target_revision: Some(DecimalString::new(revision)),
        }),
        None,
        CommandBody::SessionSend(SessionSendBody {
            content: vec![ContentBlock::Text {
                text: format!("one turn after manager {expected_owner}"),
            }],
            policy: SendPolicy::WhenIdle,
        }),
    )
    .unwrap();
    let submitted = host
        .send_first_codex_bootstrap_from_wire(&transport, send.clone(), &send_policy)
        .unwrap();
    assert!(matches!(
        submitted.port_observation,
        Some(BootstrapPortObservation::PodAccepted(_))
    ));
    let duplicate = host
        .send_first_codex_bootstrap_from_wire(&transport, send, &send_policy)
        .unwrap();
    assert_eq!(duplicate.receipt, submitted.receipt);
    assert!(!duplicate.port_called);
    let frames = fixture_codex_slot(&fixture).join("home/codex/frames.log");
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if fs::read_to_string(&frames)
            .unwrap_or_default()
            .lines()
            .count()
            == 5
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "last manager did not submit one fake turn"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(client.attested_status().unwrap().child_pid, original_pid);
    fs::write(
        fixture
            .directory
            .join(format!("rebind.owner{expected_owner}.done")),
        original_pid.to_string(),
    )
    .unwrap();
    drop(host);
    std::mem::forget(fixture);
}

#[test]
#[ignore = "helper for disposable two-process V2 rebind fixture"]
fn rebind_sibling_status_process_helper() {
    let fixture = Fixture::from_shared();
    let manifest = slot_manifest(&fixture).unwrap();
    let refused = PodClient::connect(&manifest).is_err();
    std::mem::forget(fixture);
    assert!(
        refused,
        "same-UID sibling cannot inherit rebound manager control"
    );
}

fn run_rebind_manager_helper(name: &str, fixture: &Fixture, binary: &Path) {
    run_rebind_manager_helper_with_owner(name, fixture, binary, None);
}

fn run_rebind_manager_helper_with_owner(
    name: &str,
    fixture: &Fixture,
    binary: &Path,
    owner: Option<u64>,
) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--ignored", "--exact", name, "--nocapture"])
        .env("PODBAY_REBIND_FIXTURE_DIR", &fixture.directory)
        .env("PODBAY_REBIND_FIXTURE_POD", fixture.pod.as_str())
        .env("PODBAY_TEST_POD_BINARY", binary)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(owner) = owner {
        command.env("PODBAY_RECOVERY_OWNER", owner.to_string());
    } else {
        command.env_remove("PODBAY_RECOVERY_OWNER");
    }
    let mut process = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if let Some(status) = process.try_wait().unwrap() {
            assert!(status.success(), "{name} failed with {status}");
            return;
        }
        if Instant::now() >= deadline {
            let _ = process.kill();
            let _ = process.wait();
            panic!("{name} exceeded disposable fixture deadline");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "requires disposable user systemd and PODBAY_TEST_POD_BINARY"]
fn disposable_v2_rebind_keeps_exact_pod_and_child_across_two_manager_processes() {
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let fixture = Fixture::new();
    run_rebind_manager_helper("rebind_first_manager_process_helper", &fixture, &binary);
    let manifest = slot_manifest(&fixture).expect("first manager left one bound manifest");
    let first_pid: u32 = fs::read_to_string(fixture.directory.join("rebind.first.pid"))
        .unwrap()
        .parse()
        .unwrap();
    assert!(PathBuf::from(format!("/proc/{first_pid}/stat")).exists());
    run_rebind_manager_helper("rebind_second_manager_process_helper", &fixture, &binary);
    assert_eq!(
        fs::read_to_string(fixture.directory.join("rebind.second.done")).unwrap(),
        first_pid.to_string()
    );
    let saved: podbay_pod::PodManifest =
        serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while saved.socket_path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        !saved.socket_path.exists(),
        "disposable pod socket remained after stop"
    );
}

#[test]
#[ignore = "requires disposable user systemd and PODBAY_TEST_POD_BINARY"]
fn disposable_v21_store_only_pending_b_rebinds_active_prior_a_in_c() {
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let fixture = Fixture::new();
    run_rebind_manager_helper("rebind_first_manager_process_helper", &fixture, &binary);
    let manifest = slot_manifest(&fixture).expect("A left one immutable pod manifest");
    let guard = DisposableUnitGuard::for_manifest(&manifest);
    let first_pid: u32 = fs::read_to_string(fixture.directory.join("rebind.first.pid"))
        .unwrap()
        .parse()
        .unwrap();
    let first_births = fs::read_to_string(fixture.directory.join("rebind.first.births")).unwrap();

    run_rebind_manager_helper(
        "rebind_second_store_only_pending_active_prior_helper",
        &fixture,
        &binary,
    );
    assert_eq!(
        fs::read_to_string(fixture.directory.join("rebind.second.store_only_pending")).unwrap(),
        "store_pending_pod_active_a"
    );
    assert!(Path::new(&format!("/proc/{first_pid}/stat")).exists());
    assert_eq!(
        fs::read_to_string(fixture_codex_slot(&fixture).join("home/codex/frames.log"))
            .unwrap()
            .lines()
            .count(),
        2,
        "B must not submit provider input"
    );

    run_rebind_manager_helper(
        "rebind_third_active_prior_rebind_manager_process_helper",
        &fixture,
        &binary,
    );
    assert_eq!(
        fs::read_to_string(fixture.directory.join("rebind.owner3.active_prior.done")).unwrap(),
        first_pid.to_string()
    );
    assert_eq!(
        fs::read_to_string(fixture.directory.join("rebind.first.births")).unwrap(),
        first_births
    );
    assert_eq!(
        fs::read_to_string(fixture_codex_slot(&fixture).join("home/codex/frames.log"))
            .unwrap()
            .lines()
            .count(),
        5,
        "C must submit exactly one fake native turn"
    );
    assert_eq!(
        PodBayStore::open_existing_read_only(&fixture.database)
            .unwrap()
            .owner_epoch()
            .unwrap(),
        3
    );
    let saved: podbay_pod::PodManifest =
        serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let state = Command::new("systemctl")
            .args(["--user", "show", "--property=LoadState", "--value", &guard.0])
            .output()
            .unwrap();
        assert!(state.status.success());
        if String::from_utf8_lossy(&state.stdout).trim() == "not-found"
            && !saved.socket_path.exists()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Active-prior disposable unit or socket remained after stop"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "requires disposable user systemd and PODBAY_TEST_POD_BINARY"]
fn disposable_v21_two_store_only_crashes_rebind_active_a_in_d() {
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let fixture = Fixture::new();
    run_rebind_manager_helper("rebind_first_manager_process_helper", &fixture, &binary);
    let manifest = slot_manifest(&fixture).expect("A left one immutable pod manifest");
    let guard = DisposableUnitGuard::for_manifest(&manifest);
    let first_pid: u32 = fs::read_to_string(fixture.directory.join("rebind.first.pid"))
        .unwrap().parse().unwrap();
    let first_births = fs::read_to_string(fixture.directory.join("rebind.first.births")).unwrap();
    run_rebind_manager_helper(
        "rebind_second_store_only_pending_active_prior_helper", &fixture, &binary,
    );
    run_rebind_manager_helper(
        "rebind_third_store_only_pending_active_prior_helper", &fixture, &binary,
    );
    assert_eq!(fs::read_to_string(fixture.directory.join("rebind.third.store_only_pending"))
        .unwrap(), "c_pending_pod_active_a");
    assert!(Path::new(&format!("/proc/{first_pid}/stat")).exists());
    run_rebind_manager_helper_with_owner(
        "rebind_third_active_prior_rebind_manager_process_helper",
        &fixture, &binary, Some(4),
    );
    assert_eq!(fs::read_to_string(fixture.directory.join("rebind.owner4.active_prior.done"))
        .unwrap(), first_pid.to_string());
    assert_eq!(fs::read_to_string(fixture.directory.join("rebind.first.births")).unwrap(),
        first_births);
    assert_eq!(fs::read_to_string(fixture_codex_slot(&fixture).join("home/codex/frames.log"))
        .unwrap().lines().count(), 5, "D must submit one native turn without earlier resend");
    assert_eq!(PodBayStore::open_existing_read_only(&fixture.database)
        .unwrap().owner_epoch().unwrap(), 4);
    let saved: podbay_pod::PodManifest =
        serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let state = Command::new("systemctl")
            .args(["--user", "show", "--property=LoadState", "--value", &guard.0])
            .output().unwrap();
        assert!(state.status.success());
        if String::from_utf8_lossy(&state.stdout).trim() == "not-found"
            && !saved.socket_path.exists() { break; }
        assert!(Instant::now() < deadline,
            "repeated store-only crash fixture left unit or socket");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "requires disposable user systemd and PODBAY_TEST_POD_BINARY"]
fn disposable_v21_pending_recovery_checkpoint_keeps_same_child_across_three_managers() {
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let fixture = Fixture::new();
    run_rebind_manager_helper("rebind_first_manager_process_helper", &fixture, &binary);
    let manifest = slot_manifest(&fixture).expect("A left one bound manifest");
    let guard = DisposableUnitGuard::for_manifest(&manifest);
    let child_pid: u32 = fs::read_to_string(fixture.directory.join("rebind.first.pid"))
        .unwrap().parse().unwrap();
    run_rebind_manager_helper("rebind_second_pending_manager_process_helper", &fixture, &binary);
    assert_eq!(fs::read_to_string(fixture.directory.join("rebind.second.pending")).unwrap(),
        "pending_pod");
    assert!(Path::new(&format!("/proc/{child_pid}/stat")).exists());
    run_rebind_manager_helper("rebind_third_recover_manager_process_helper", &fixture, &binary);
    let digest = fs::read_to_string(fixture.directory.join("rebind.third.inspected")).unwrap();
    assert_eq!(digest.len(), 64);
    assert!(Path::new(&format!("/proc/{child_pid}/stat")).exists());
    let frames = fixture_codex_slot(&fixture).join("home/codex/frames.log");
    assert_eq!(fs::read_to_string(frames).unwrap().lines().count(), 2,
        "recovery inspection must not submit provider input");
    let store = PodBayStore::open_existing_read_only(&fixture.database).unwrap();
    assert_eq!(store.owner_epoch().unwrap(), 3);
    drop(store);
    assert!(Command::new("systemctl").args(["--user", "stop", &guard.0])
        .status().unwrap().success());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let state = Command::new("systemctl")
            .args(["--user", "show", "--property=LoadState", "--value", &guard.0])
            .output().unwrap();
        assert!(state.status.success());
        if String::from_utf8_lossy(&state.stdout).trim() == "not-found" { break; }
        assert!(Instant::now() < deadline, "three-manager disposable unit remained loaded");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "requires disposable user systemd and pod binary built with native-rebind-test-hook"]
fn disposable_v21_pending_store_fsync_survives_b_crash() {
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let fixture = Fixture::new();
    run_rebind_manager_helper("rebind_first_manager_process_helper", &fixture, &binary);
    let manifest = slot_manifest(&fixture).expect("A left one bound manifest");
    let guard = DisposableUnitGuard::for_manifest(&manifest);
    let child_pid: u32 = fs::read_to_string(fixture.directory.join("rebind.first.pid"))
        .unwrap().parse().unwrap();
    let original_births = fs::read_to_string(fixture.directory.join("rebind.first.births"))
        .unwrap();
    let marker = fixture.directory.join(".podbay-test-break-after-pending-store");
    fs::write(&marker, b"one-shot disposable fault").unwrap();
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
    run_rebind_manager_helper(
        "rebind_second_pending_store_manager_process_helper", &fixture, &binary,
    );
    assert!(!marker.exists(), "fixture pod did not consume the one-shot fault");
    assert_eq!(fs::read_to_string(fixture.directory.join("rebind.second.pending_store"))
        .unwrap(), "pending_store");
    assert!(Path::new(&format!("/proc/{child_pid}/stat")).exists());
    run_rebind_manager_helper("rebind_third_recover_manager_process_helper", &fixture, &binary);
    assert_eq!(fs::read_to_string(fixture.directory.join("rebind.third.inspected"))
        .unwrap().len(), 64);
    assert_eq!(fs::read_to_string(fixture.directory.join("rebind.first.births"))
        .unwrap(), original_births);
    let frames = fixture_codex_slot(&fixture).join("home/codex/frames.log");
    assert_eq!(fs::read_to_string(frames).unwrap().lines().count(), 2,
        "PendingStore recovery must not resend native input");
    assert!(Command::new("systemctl").args(["--user", "stop", &guard.0])
        .status().unwrap().success());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let state = Command::new("systemctl")
            .args(["--user", "show", "--property=LoadState", "--value", &guard.0])
            .output().unwrap();
        assert!(state.status.success());
        if String::from_utf8_lossy(&state.stdout).trim() == "not-found" { break; }
        assert!(Instant::now() < deadline, "PendingStore disposable unit remained loaded");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "requires disposable user systemd and PODBAY_TEST_POD_BINARY"]
fn disposable_v21_four_managers_reconcile_c_lost_recovery_ack() {
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let fixture = Fixture::new();
    run_rebind_manager_helper("rebind_first_manager_process_helper",&fixture,&binary);
    let manifest = slot_manifest(&fixture).expect("A left one immutable pod manifest");
    let guard = DisposableUnitGuard::for_manifest(&manifest);
    let child_pid: u32 = fs::read_to_string(fixture.directory.join("rebind.first.pid"))
        .unwrap().parse().unwrap();
    run_rebind_manager_helper("rebind_second_pending_manager_process_helper",&fixture,&binary);
    run_rebind_manager_helper("rebind_third_lost_recovery_ack_helper",&fixture,&binary);
    assert_eq!(fs::read_to_string(fixture.directory.join("rebind.third.lost")).unwrap(),
        "active_a_store_planned");
    assert!(Path::new(&format!("/proc/{child_pid}/stat")).exists());
    run_rebind_manager_helper("rebind_fourth_adopt_manager_process_helper",&fixture,&binary);
    assert_eq!(fs::read_to_string(fixture.directory.join("rebind.owner4.done")).unwrap(),
        child_pid.to_string());
    let frames = fixture_codex_slot(&fixture).join("home/codex/frames.log");
    assert_eq!(fs::read_to_string(frames).unwrap().lines().count(),5,
        "four-manager recovery must submit one turn without resend");
    let store = PodBayStore::open_existing_read_only(&fixture.database).unwrap();
    assert_eq!(store.owner_epoch().unwrap(),4);
    drop(store);
    assert!(Command::new("systemctl").args(["--user","stop",&guard.0])
        .status().unwrap().success());
    let deadline = Instant::now()+Duration::from_secs(5);
    loop {
        let state = Command::new("systemctl")
            .args(["--user","show","--property=LoadState","--value",&guard.0])
            .output().unwrap();
        assert!(state.status.success());
        if String::from_utf8_lossy(&state.stdout).trim()=="not-found" { break; }
        assert!(Instant::now()<deadline,"four-manager disposable unit remained loaded");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "requires disposable user systemd and PODBAY_TEST_POD_BINARY"]
fn disposable_v21_store_activated_b_never_claims_pod_active() {
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let fixture = Fixture::new();
    run_rebind_manager_helper("rebind_first_manager_process_helper", &fixture, &binary);
    let manifest = slot_manifest(&fixture).expect("A left one immutable pod manifest");
    let guard = DisposableUnitGuard::for_manifest(&manifest);
    let child_pid: u32 = fs::read_to_string(fixture.directory.join("rebind.first.pid"))
        .unwrap()
        .parse()
        .unwrap();
    run_rebind_manager_helper(
        "rebind_second_store_activated_manager_process_helper",
        &fixture,
        &binary,
    );
    assert_eq!(
        fs::read_to_string(fixture.directory.join("rebind.second.activated")).unwrap(),
        "store_activated_pod_pending"
    );
    assert!(Path::new(&format!("/proc/{child_pid}/stat")).exists());
    run_rebind_manager_helper("rebind_third_lost_recovery_ack_helper", &fixture, &binary);
    run_rebind_manager_helper(
        "rebind_fourth_adopt_manager_process_helper",
        &fixture,
        &binary,
    );
    assert_eq!(
        fs::read_to_string(fixture.directory.join("rebind.owner4.done")).unwrap(),
        child_pid.to_string()
    );
    let frames = fixture_codex_slot(&fixture).join("home/codex/frames.log");
    assert_eq!(fs::read_to_string(frames).unwrap().lines().count(), 5);
    assert!(
        Command::new("systemctl")
            .args(["--user", "stop", &guard.0])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let state = Command::new("systemctl")
            .args([
                "--user",
                "show",
                "--property=LoadState",
                "--value",
                &guard.0,
            ])
            .output()
            .unwrap();
        assert!(state.status.success());
        if String::from_utf8_lossy(&state.stdout).trim() == "not-found" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "activated-B disposable unit remained loaded"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "requires disposable user systemd and PODBAY_TEST_POD_BINARY"]
fn disposable_v21_five_managers_reconcile_successor_planned_lost_ack() {
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let fixture = Fixture::new();
    run_rebind_manager_helper("rebind_first_manager_process_helper", &fixture, &binary);
    let manifest = slot_manifest(&fixture).expect("A left one immutable pod manifest");
    let guard = DisposableUnitGuard::for_manifest(&manifest);
    let child_pid: u32 = fs::read_to_string(fixture.directory.join("rebind.first.pid"))
        .unwrap()
        .parse()
        .unwrap();
    let original_births =
        fs::read_to_string(fixture.directory.join("rebind.first.births")).unwrap();
    run_rebind_manager_helper(
        "rebind_second_pending_manager_process_helper",
        &fixture,
        &binary,
    );
    run_rebind_manager_helper("rebind_third_lost_recovery_ack_helper", &fixture, &binary);
    run_rebind_manager_helper("rebind_fourth_lost_adoption_ack_helper", &fixture, &binary);
    assert_eq!(
        fs::read_to_string(fixture.directory.join("rebind.fourth.lost")).unwrap(),
        "d_planned_no_ack"
    );
    assert!(Path::new(&format!("/proc/{child_pid}/stat")).exists());
    run_rebind_manager_helper_with_owner(
        "rebind_fourth_adopt_manager_process_helper",
        &fixture,
        &binary,
        Some(5),
    );
    assert_eq!(
        fs::read_to_string(fixture.directory.join("rebind.owner5.done")).unwrap(),
        child_pid.to_string()
    );
    let frames = fixture_codex_slot(&fixture).join("home/codex/frames.log");
    assert_eq!(
        fs::read_to_string(frames).unwrap().lines().count(),
        5,
        "E must send one native turn without replaying the original two frames"
    );
    assert_eq!(
        fs::read_to_string(fixture.directory.join("rebind.first.births")).unwrap(),
        original_births
    );
    let store = PodBayStore::open_existing_read_only(&fixture.database).unwrap();
    assert_eq!(store.owner_epoch().unwrap(), 5);
    drop(store);
    assert!(
        Command::new("systemctl")
            .args(["--user", "stop", &guard.0])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let state = Command::new("systemctl")
            .args([
                "--user",
                "show",
                "--property=LoadState",
                "--value",
                &guard.0,
            ])
            .output()
            .unwrap();
        assert!(state.status.success());
        if String::from_utf8_lossy(&state.stdout).trim() == "not-found" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "five-manager disposable unit remained loaded"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "requires disposable user systemd and PODBAY_TEST_POD_BINARY"]
fn disposable_codex_v2_durable_dispatch_records_one_real_pod_launch() {
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let fixture = Fixture::new();
    let mut port = port_for(&fixture, &binary);
    let reference =
        CredentialRef::from_trusted_vault(fixture.scope.clone(), "vault.codex.preflight").unwrap();
    port.register_codex_credential_source_from_trusted_policy(
        TrustedCodexCredentialSource::from_trusted_policy(reference, fixture.source.clone())
            .unwrap(),
    )
    .unwrap();
    let (fixture, mut host, proof, _, transport, request) = setup_with_port(
        Role::Coordinator,
        fixture,
        port,
        Duration::from_secs(30),
        60,
    );
    let outbox_id = proof.outbox_id();
    let prepared = PodBayStore::open(&fixture.database)
        .unwrap()
        .launch_dispatch_status(outbox_id, fixture.scope.as_str(), fixture.pod.as_str())
        .unwrap();
    assert_eq!(prepared.stage, LaunchDispatchStage::Prepared);

    let accepted = host
        .dispatch_prepared_bound_root_codex_v2(&transport, request.clone())
        .unwrap();
    assert_eq!(accepted.status.stage, LaunchDispatchStage::HostAccepted);
    assert!(accepted.port_called);
    let durable = PodBayStore::open(&fixture.database)
        .unwrap()
        .launch_dispatch_status(outbox_id, fixture.scope.as_str(), fixture.pod.as_str())
        .unwrap();
    assert_eq!(durable, accepted.status);
    let manifest = slot_manifest(&fixture).expect("one durable pod manifest");
    let client = PodClient::connect(&manifest).unwrap();
    let first = client.attested_status().unwrap();
    assert!(first.child_running);
    assert_eq!(
        first.bound.as_ref().unwrap().capability,
        CODEX_V2_CAPABILITY
    );

    let mut duplicate = request;
    duplicate.proposal = None;
    let repeated = host
        .dispatch_prepared_bound_root_codex_v2(&transport, duplicate)
        .unwrap();
    assert!(repeated.duplicate);
    assert!(!repeated.port_called);
    assert_eq!(repeated.receipt, accepted.receipt);
    assert_eq!(repeated.status, durable);
    let second = client.attested_status().unwrap();
    assert!(second.child_running);
    assert_eq!(second.supervisor_pid, first.supervisor_pid);
    assert_eq!(second.supervisor_start_ticks, first.supervisor_start_ticks);
    assert_eq!(second.child_pid, first.child_pid);
    assert_eq!(second.child_start_ticks, first.child_start_ticks);
    assert_eq!(
        fs::read_to_string(fixture_codex_slot(&fixture).join("home/codex/frames.log"))
            .unwrap()
            .lines()
            .count(),
        2
    );

    assert!(!client.stop().unwrap().child_running);
    let unit = format!(
        "podbay-pod-{}.service",
        manifest.file_stem().unwrap().to_str().unwrap()
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let state = Command::new("systemctl")
            .args(["--user", "show", "--property=LoadState", "--value", &unit])
            .output()
            .unwrap();
        assert!(state.status.success(), "systemd unit state unavailable");
        if String::from_utf8_lossy(&state.stdout).trim() == "not-found" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "disposable pod unit remained loaded"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "requires disposable user systemd and PODBAY_TEST_POD_BINARY"]
fn disposable_codex_v2_claimed_bootstrap_sends_one_fake_native_turn() {
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let fixture = Fixture::new();
    let mut port = port_for(&fixture, &binary);
    let reference =
        CredentialRef::from_trusted_vault(fixture.scope.clone(), "vault.codex.preflight").unwrap();
    port.register_codex_credential_source_from_trusted_policy(
        TrustedCodexCredentialSource::from_trusted_policy(reference, fixture.source.clone())
            .unwrap(),
    )
    .unwrap();
    let (fixture, mut host, proof, source, transport, launch_request) = setup_with_port(
        Role::Coordinator,
        fixture,
        port,
        Duration::from_secs(30),
        60,
    );
    let accepted = host
        .dispatch_prepared_bound_root_codex_v2(&transport, launch_request.clone())
        .unwrap();
    assert_eq!(accepted.status.stage, LaunchDispatchStage::HostAccepted);
    let manifest = slot_manifest(&fixture).expect("one committed V2 pod manifest");
    let _unit_guard = DisposableUnitGuard::for_manifest(&manifest);
    let client = PodClient::connect(&manifest).unwrap();
    assert!(client.attested_status().unwrap().child_running);

    let session_id = SessionId::try_from("session.codex.preflight").unwrap();
    let policy = TrustedBootstrapSendPolicy::from_trusted_policy(
        launch_request.host_request.grant_id,
        Instant::now() + Duration::from_secs(45),
    )
    .unwrap();
    let lease = host
        .acquire_initial_bootstrap_writer_lease(&transport, &session_id, &policy, 60)
        .unwrap();
    let (target, session_revision) = PodBayStore::open(&fixture.database)
        .unwrap()
        .current_native_writer_target_for_session(&fixture.scope, &session_id)
        .unwrap();
    assert_eq!(lease.target(), &target);
    let envelope = CommandEnvelope::new(
        "request.codex.bootstrap.one",
        "key.codex.bootstrap.one",
        WireTarget::Session {
            session_id: session_id.as_str().into(),
        },
        Some(Guard {
            manager_epoch: Some(DecimalString::new(lease.owner_epoch())),
            pod_epoch: Some(DecimalString::new(target.pod_incarnation)),
            resource_epoch: Some(DecimalString::new(target.resource_epoch)),
            writer_epoch: Some(DecimalString::new(lease.writer_epoch())),
            lease_epoch: None,
            target_revision: Some(DecimalString::new(session_revision)),
        }),
        None,
        CommandBody::SessionSend(SessionSendBody {
            content: vec![ContentBlock::Text {
                text: "fixture first turn".into(),
            }],
            policy: SendPolicy::WhenIdle,
        }),
    )
    .unwrap();
    let submitted = host
        .send_first_codex_bootstrap_from_wire(&transport, envelope.clone(), &policy)
        .unwrap();
    assert!(submitted.port_called);
    assert_eq!(
        submitted.effect_state,
        podbay_store::EffectState::ClaimedUncertain
    );
    assert!(matches!(
        submitted.port_observation,
        Some(BootstrapPortObservation::PodAccepted(_))
    ));
    assert!(fixture_codex_slot(&fixture).join("codex.commands.log").is_file());
    let journal = reopened_bootstrap_journal(&fixture);
    assert_eq!(journal.stage, CodexJournalStage::BootstrapSubmitted);
    assert_eq!(journal.native_turn_id.as_deref(), Some("turn.fixture"));
    let frames = fixture_codex_slot(&fixture).join("home/codex/frames.log");
    let deadline = Instant::now() + Duration::from_secs(3);
    let methods = loop {
        let content = fs::read_to_string(&frames).unwrap_or_default();
        if content.lines().count() == 5 {
            break content
                .lines()
                .map(|line| {
                    serde_json::from_str::<serde_json::Value>(line).unwrap()["method"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                })
                .collect::<Vec<_>>();
        }
        assert!(
            Instant::now() < deadline,
            "fake app-server did not receive one turn"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(
        methods,
        [
            "initialize",
            "initialized",
            "thread/start",
            "thread/read",
            "turn/start"
        ]
    );

    let trusted_directory =
        TrustedNativeEventDirectory::from_trusted_policy(fixture.directory.clone()).unwrap();
    let event_deadline = Instant::now() + Duration::from_secs(3);
    let snapshot = loop {
        let read =
            read_committed_codex_native_evidence(&proof, &source, &trusted_directory, None, 16)
                .unwrap();
        if read.redacted().snapshot.watermark > 0 {
            break read;
        }
        assert!(
            Instant::now() < event_deadline,
            "fake native output was not spooled"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(snapshot.redacted().events.is_empty());
    let cursor = NativeEventCursor {
        identity: snapshot.redacted().snapshot.identity.clone(),
        sequence: 0,
    };
    let evidence = read_committed_codex_native_evidence(
        &proof,
        &source,
        &trusted_directory,
        Some(&cursor),
        16,
    )
    .unwrap();
    assert_eq!(evidence.redacted().events.len(), 1);
    assert_eq!(evidence.redacted().events[0].kind, NativeEventKind::Output);
    assert!(evidence.redacted().gap.is_none());
    assert_eq!(evidence.private_evidence().len(), 1);
    let slot = fixture_codex_slot(&fixture);
    assert!(slot.join("native-events.checkpoint").is_file());
    assert!(!slot.join("codex.native-events.log").exists());
    assert!(
        String::from_utf8_lossy(evidence.private_evidence()[0].private_jsonl())
            .contains("private manager evidence")
    );
    let repeated = read_committed_codex_native_evidence(
        &proof, &source, &trusted_directory, Some(&cursor), 16,
    ).unwrap();
    assert_eq!(repeated.redacted(), evidence.redacted());
    assert_eq!(repeated.private_evidence().len(), 1);
    assert!(!format!("{evidence:?}").contains("private manager evidence"));
    assert!(
        !serde_json::to_string(evidence.redacted())
            .unwrap()
            .contains("private manager evidence")
    );
    let mut foreign = cursor.clone();
    foreign.identity.scope_id = "scope.other".into();
    assert!(
        read_committed_codex_native_evidence(
            &proof,
            &source,
            &trusted_directory,
            Some(&foreign),
            16,
        )
        .is_err()
    );

    // Treat the original port reply as lost. commands.get must recover the
    // submitted fact from the held pod journal without resending native input.
    let command_selector = CommandLookupSelector::Id {
        command_id: submitted.receipt.command_id.clone(),
    };
    for _ in 0..2 {
        let (durable, native) = host
            .lookup_command_with_native_observation(&transport, &fixture.scope, &command_selector)
            .unwrap();
        assert_eq!(durable.receipt, submitted.receipt);
        assert_eq!(
            durable.effect_state,
            podbay_store::EffectState::ClaimedUncertain
        );
        let native = native.expect("attested pod journal observation");
        assert_eq!(native.request_digest(), submitted.receipt.request_digest);
        assert_eq!(native.writer_epoch(), lease.writer_epoch());
        assert!(matches!(
            native.stage(),
            BootstrapNativeStage::Submitted {
                native_thread_id,
                native_session_id,
                native_turn_id,
            } if native_thread_id == "thread.fixture"
                && native_session_id == "native.session.fixture"
                && native_turn_id == "turn.fixture"
        ));
        assert_eq!(fs::read_to_string(&frames).unwrap().lines().count(), 5);
    }

    let mut retry = envelope;
    retry.request_id = "request.codex.bootstrap.retry".into();
    let duplicate = host
        .send_first_codex_bootstrap_from_wire(&transport, retry, &policy)
        .unwrap();
    assert!(duplicate.duplicate);
    assert!(!duplicate.port_called);
    assert_eq!(duplicate.receipt, submitted.receipt);
    assert_eq!(reopened_bootstrap_journal(&fixture), journal);
    assert_eq!(fs::read_to_string(&frames).unwrap().lines().count(), 5);

    // A new writer epoch removes the supplemental observation. The durable
    // command receipt remains readable, and inspection cannot send again.
    let takeover = PodBayStore::open(&fixture.database)
        .unwrap()
        .acquire_native_writer_lease_from_trusted_host(&TrustedNativeWriterLeaseRequest {
            target: target.clone(),
            holder_actor_id: lease.holder_actor_id().clone(),
            holder_credential_generation: lease.holder_credential_generation(),
            expected_owner_epoch: lease.owner_epoch(),
            expected_manager_credential_epoch: lease.manager_credential_epoch(),
            expected_authority_revision: lease.authority_revision(),
            expected_writer_epoch: Some(lease.writer_epoch()),
            ttl_seconds: 60,
        })
        .unwrap();
    assert_eq!(takeover.writer_epoch(), lease.writer_epoch() + 1);
    let (durable, native) = host
        .lookup_command_with_native_observation(&transport, &fixture.scope, &command_selector)
        .unwrap();
    assert_eq!(durable.receipt, submitted.receipt);
    assert!(native.is_none());
    assert_eq!(fs::read_to_string(&frames).unwrap().lines().count(), 5);
    assert!(!client.stop().unwrap().child_running);
}

fn install_fake_completed_then_second_turn(fixture: &Fixture, lost_reply: bool, delay_seconds: u64) {
    let original = fs::read_to_string(&fixture.executable).unwrap();
    let replacement = r#"sleep 1
printf '{"method":"turn/completed","params":{"threadId":"thread.fixture","turn":{"id":"turn.fixture","status":"completed","items":[]}}}\n'
printf '{"method":"thread/status/changed","params":{"threadId":"thread.fixture","status":{"type":"idle"}}}\n'
read -r completion_read
printf '%s\n' "$completion_read" >> "$CODEX_HOME/frames.log"
printf '{"id":5,"result":{"thread":{"id":"thread.fixture","sessionId":"native.session.fixture","cwd":"%s","status":{"type":"idle"},"turns":[]}}}\n' "$(pwd)"
read -r later_read
printf '%s\n' "$later_read" >> "$CODEX_HOME/frames.log"
printf '{"id":6,"result":{"thread":{"id":"thread.fixture","sessionId":"native.session.fixture","cwd":"%s","status":{"type":"idle"},"turns":[]}}}\n' "$(pwd)"
read -r later_turn
printf '%s\n' "$later_turn" >> "$CODEX_HOME/frames.log"
__LATER_TURN_DELAY__
__LATER_TURN_REPLY__
sleep __WAIT_AFTER_TURN__
"#;
    let response = if lost_reply { "" } else {
        "printf '{\"id\":7,\"result\":{\"turn\":{\"id\":\"turn.later.fixture\",\"status\":\"inProgress\",\"items\":[]}}}\\n'"
    };
    let delay = if delay_seconds == 0 { String::new() }
        else { format!("sleep {delay_seconds}") };
    let replacement = replacement.replace("__LATER_TURN_DELAY__", &delay)
        .replace("__LATER_TURN_REPLY__", response)
        .replace("__WAIT_AFTER_TURN__", if lost_reply { "40" } else { "30" });
    let updated = original.replacen("sleep 30\n", &replacement, 1);
    assert_ne!(updated, original);
    fs::write(&fixture.executable, updated).unwrap();
}

fn run_disposable_codex_v22_second_turn(lost_reply: bool, long_prompt: bool) {
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let fixture = Fixture::new();
    install_fake_completed_then_second_turn(&fixture, lost_reply,
        if lost_reply { 0 } else { 6 });
    let mut port = port_for(&fixture, &binary);
    let reference = CredentialRef::from_trusted_vault(
        fixture.scope.clone(), "vault.codex.preflight",
    ).unwrap();
    port.register_codex_credential_source_from_trusted_policy(
        TrustedCodexCredentialSource::from_trusted_policy(reference, fixture.source.clone()).unwrap(),
    ).unwrap();
    let (fixture, mut host, _, _, transport, launch_request) = setup_with_port(
        Role::Coordinator, fixture, port, Duration::from_secs(45), 90,
    );
    let accepted = host.dispatch_prepared_bound_root_codex_v2(
        &transport, launch_request.clone(),
    ).unwrap();
    assert_eq!(accepted.status.stage, LaunchDispatchStage::HostAccepted);
    let manifest = slot_manifest(&fixture).unwrap();
    let _unit_guard = DisposableUnitGuard::for_manifest(&manifest);
    let client = PodClient::connect(&manifest).unwrap();
    assert!(client.attested_status().unwrap().child_running);
    let session = SessionId::try_from("session.codex.preflight").unwrap();
    let policy = TrustedBootstrapSendPolicy::from_trusted_policy(
        launch_request.host_request.grant_id, Instant::now() + Duration::from_secs(75),
    ).unwrap();
    let lease = host.acquire_initial_bootstrap_writer_lease(&transport, &session, &policy, 90).unwrap();
    let (target, revision) = PodBayStore::open(&fixture.database).unwrap()
        .current_native_writer_target_for_session(&fixture.scope, &session).unwrap();
    let guard = Some(Guard {
        manager_epoch: Some(DecimalString::new(lease.owner_epoch())),
        pod_epoch: Some(DecimalString::new(target.pod_incarnation)),
        resource_epoch: Some(DecimalString::new(target.resource_epoch)),
        writer_epoch: Some(DecimalString::new(lease.writer_epoch())),
        lease_epoch: None, target_revision: Some(DecimalString::new(revision)),
    });
    let first = CommandEnvelope::new(
        "request.v22.first", "key.v22.first",
        WireTarget::Session { session_id: session.as_str().into() }, guard.clone(), None,
        CommandBody::SessionSend(SessionSendBody {
            content: vec![ContentBlock::Text { text: "fixture first turn".into() }],
            policy: SendPolicy::WhenIdle,
        }),
    ).unwrap();
    let first_receipt = host.send_codex_session_from_wire(&transport, first, &policy).unwrap();
    assert!(matches!(first_receipt.port_observation, Some(BootstrapPortObservation::PodAccepted(_))));
    let begin_status = Instant::now();
    assert!(client.attested_status().unwrap().child_running);
    assert!(begin_status.elapsed() < Duration::from_secs(2));
    let first_id = CommandId::try_from(first_receipt.receipt.command_id.as_str()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let observed = client.inspect_claimed_codex_bootstrap(&first_id, &target, lease.writer_epoch()).unwrap();
        if observed.settlement == Some(BootstrapSettlementStage::Completed) { break; }
        assert!(Instant::now() < deadline, "bootstrap did not durably complete");
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(reopened_bootstrap_journal(&fixture).stage, CodexJournalStage::BootstrapCompleted);
    let second_text = if long_prompt { "x".repeat(450) }
        else { "fixture second turn".into() };
    let second = CommandEnvelope::new(
        "request.v22.second", "key.v22.second",
        WireTarget::Session { session_id: session.as_str().into() }, guard.clone(), None,
        CommandBody::SessionSend(SessionSendBody {
            content: vec![ContentBlock::Text { text: second_text.clone() }],
            policy: SendPolicy::WhenIdle,
        }),
    ).unwrap();
    let begin_send = Instant::now();
    let second_receipt = host.send_codex_session_from_wire(&transport, second.clone(), &policy).unwrap();
    if !long_prompt {
        assert!(begin_send.elapsed() < Duration::from_secs(3),
            "atomic second-turn IPC blocked on a native RPC: elapsed={:?}, observation={:?}",
            begin_send.elapsed(), second_receipt.port_observation);
        assert!(matches!(second_receipt.port_observation,
            Some(BootstrapPortObservation::UncertainAfterPossibleEffect(_))));
    } else if lost_reply {
        assert!(matches!(second_receipt.port_observation,
            Some(BootstrapPortObservation::UncertainAfterPossibleEffect(_))));
    } else {
        assert!(matches!(second_receipt.port_observation,
            Some(BootstrapPortObservation::PodAccepted(_))));
    }
    let second_id = CommandId::try_from(second_receipt.receipt.command_id.as_str()).unwrap();
    let selector = LaterCodexSendSelector {
        scope_id: fixture.scope.clone(), command_id: second_id,
        native_target: target.clone(),
    };
    let frames = fixture_codex_slot(&fixture).join("home/codex/frames.log");
    let deadline = Instant::now() + Duration::from_secs(if lost_reply { 40 } else { 15 });
    let mut status_during_native_reply = None;
    loop {
        let observed = client.inspect_claimed_codex_turn(
            &selector, lease.writer_epoch(), &second_receipt.receipt.request_digest,
            "thread.fixture",
        ).unwrap();
        let starts = fs::read_to_string(&frames).unwrap_or_default().lines()
            .filter(|line| line.contains("\"method\":\"turn/start\"")).count();
        if !long_prompt && starts == 2 && status_during_native_reply.is_none() {
            let before_status = Instant::now();
            let status = client.attested_status().unwrap();
            let latency = before_status.elapsed();
            assert!(status.protocol == "podbay-pod/1");
            assert!(latency < Duration::from_millis(500),
                "status blocked during native reply: {latency:?}");
            eprintln!("later-turn delayed-reply status latency={latency:?}");
            status_during_native_reply = Some(latency);
        }
        let done = if lost_reply {
            matches!(observed.stage, LaterTurnControlStage::SubmissionUncertain)
        } else {
            matches!(observed.stage, LaterTurnControlStage::Submitted { ref native_turn_id }
                if native_turn_id == "turn.later.fixture")
        };
        if done { break; }
        assert!(Instant::now() < deadline,
            "later turn did not settle its native reply uncertainty: {:?}", observed.stage);
        std::thread::sleep(Duration::from_millis(25));
    }
    if !long_prompt { assert!(status_during_native_reply.is_some()); }
    let command_selector = CommandLookupSelector::Key { key: "key.v22.second".into() };
    for _ in 0..2 {
        let (durable, native) = host.lookup_command_with_any_native_observation(
            &transport, &fixture.scope, &command_selector,
        ).unwrap();
        assert_eq!(durable.receipt, second_receipt.receipt);
        assert_eq!(durable.effect_state, podbay_store::EffectState::ClaimedUncertain);
        let native = native.expect("current pod journal later-turn observation");
        match native {
            CommandNativeObservation::LaterTurn(value) if lost_reply =>
                assert!(matches!(value.stage(), LaterTurnNativeStage::SubmissionUncertain)),
            CommandNativeObservation::LaterTurn(value) => assert!(matches!(value.stage(),
                LaterTurnNativeStage::Submitted { native_turn_id, .. }
                    if native_turn_id == "turn.later.fixture")),
            _ => panic!("later command was projected as bootstrap"),
        }
    }
    let methods = fs::read_to_string(&frames).unwrap().lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["method"]
            .as_str().unwrap().to_owned()).collect::<Vec<_>>();
    assert_eq!(methods.iter().filter(|method| method.as_str() == "turn/start").count(), 2);
    let mut retry = second;
    retry.request_id = "request.v22.second.retry".into();
    let duplicate = host.send_codex_session_from_wire(&transport, retry, &policy).unwrap();
    assert!(duplicate.duplicate && !duplicate.port_called);
    assert_eq!(duplicate.receipt, second_receipt.receipt);
    let after = fs::read_to_string(&frames).unwrap();
    assert_eq!(after.lines().count(), methods.len());
    let wrong_scope = ScopeId::try_from("scope.foreign").unwrap();
    assert!(host.lookup_command_with_any_native_observation(
        &transport, &wrong_scope, &command_selector,
    ).is_err());
    if lost_reply {
        let takeover = PodBayStore::open(&fixture.database).unwrap()
            .acquire_native_writer_lease_from_trusted_host(&TrustedNativeWriterLeaseRequest {
                target: target.clone(), holder_actor_id: lease.holder_actor_id().clone(),
                holder_credential_generation: lease.holder_credential_generation(),
                expected_owner_epoch: lease.owner_epoch(),
                expected_manager_credential_epoch: lease.manager_credential_epoch(),
                expected_authority_revision: lease.authority_revision(),
                expected_writer_epoch: Some(lease.writer_epoch()), ttl_seconds: 60,
            }).unwrap();
        assert_eq!(takeover.writer_epoch(), lease.writer_epoch() + 1);
        let (durable, native) = host.lookup_command_with_any_native_observation(
            &transport, &fixture.scope, &command_selector,
        ).unwrap();
        assert_eq!(durable.receipt, second_receipt.receipt);
        assert!(native.is_none(), "stale writer must hide supplemental stage");
    } else {
        let journal_path = fixture_codex_slot(&fixture).join("codex.turns.log");
        let bytes = fs::read(&journal_path).unwrap();
        fs::rename(&journal_path, journal_path.with_extension("log.old")).unwrap();
        fs::write(&journal_path, bytes).unwrap();
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();
        let (durable, native) = host.lookup_command_with_any_native_observation(
            &transport, &fixture.scope, &command_selector,
        ).unwrap();
        assert_eq!(durable.receipt, second_receipt.receipt);
        assert!(!matches!(native,
            Some(CommandNativeObservation::LaterTurn(value))
                if matches!(value.stage(), LaterTurnNativeStage::Submitted { .. }
                    | LaterTurnNativeStage::Settled { .. })));
    }
    assert_eq!(fs::read_to_string(&frames).unwrap().lines().count(), methods.len());
    let final_status = client.attested_status().unwrap();
    if !lost_reply { assert!(final_status.child_running); }
    assert!(!client.stop().unwrap().child_running);
}

#[test]
#[ignore = "requires disposable user systemd and PODBAY_TEST_POD_BINARY; fake app-server only"]
fn disposable_codex_v22_second_turn_claims_once_and_reconciles_without_resend() {
    run_disposable_codex_v22_second_turn(false, false);
}

#[test]
#[ignore = "requires disposable user systemd and PODBAY_TEST_POD_BINARY; fake app-server only"]
fn disposable_codex_v22_lost_second_reply_is_uncertain_and_never_resends() {
    run_disposable_codex_v22_second_turn(true, false);
}

#[test]
#[ignore = "requires disposable user systemd and PODBAY_TEST_POD_BINARY; fake app-server only"]
fn disposable_codex_v22_large_second_turn_uses_checked_fallback_once() {
    run_disposable_codex_v22_second_turn(false, true);
}

#[test]
#[ignore = "requires disposable user systemd and PODBAY_TEST_POD_BINARY; fake app-server only"]
fn disposable_codex_v22_large_lost_reply_is_uncertain_without_resend() {
    run_disposable_codex_v22_second_turn(true, true);
}

#[test]
#[ignore = "helper for disposable v22 completed-bootstrap A process"]
fn rebind_v22_first_completed_manager_process_helper() {
    let fixture = Fixture::from_shared();
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let mut port = port_for(&fixture, &binary);
    let reference = CredentialRef::from_trusted_vault(
        fixture.scope.clone(), "vault.codex.preflight",
    ).unwrap();
    port.register_codex_credential_source_from_trusted_policy(
        TrustedCodexCredentialSource::from_trusted_policy(reference, fixture.source.clone()).unwrap(),
    ).unwrap();
    let (fixture, mut host, _, _, transport, request) = setup_with_port(
        Role::Coordinator, fixture, port, Duration::from_secs(45), 90,
    );
    let accepted = host.dispatch_prepared_bound_root_codex_v2(&transport, request.clone()).unwrap();
    assert_eq!(accepted.status.stage, LaunchDispatchStage::HostAccepted);
    let manifest = slot_manifest(&fixture).unwrap();
    let client = PodClient::connect(&manifest).unwrap();
    let status = client.attested_status().unwrap();
    assert!(status.child_running);
    fs::write(fixture.directory.join("rebind.v22.first.pid"), status.child_pid.to_string()).unwrap();
    let session = SessionId::try_from("session.codex.preflight").unwrap();
    let policy = TrustedBootstrapSendPolicy::from_trusted_policy(
        request.host_request.grant_id, Instant::now() + Duration::from_secs(60),
    ).unwrap();
    let lease = host.acquire_initial_bootstrap_writer_lease(&transport, &session, &policy, 90).unwrap();
    fs::write(fixture.directory.join("rebind.v22.first.writer_epoch"),
        lease.writer_epoch().to_string()).unwrap();
    let (target, revision) = PodBayStore::open(&fixture.database).unwrap()
        .current_native_writer_target_for_session(&fixture.scope, &session).unwrap();
    let send = CommandEnvelope::new(
        "request.v22.rebind.first", "key.v22.rebind.first",
        WireTarget::Session { session_id: session.as_str().into() },
        Some(Guard {
            manager_epoch: Some(DecimalString::new(lease.owner_epoch())),
            pod_epoch: Some(DecimalString::new(target.pod_incarnation)),
            resource_epoch: Some(DecimalString::new(target.resource_epoch)),
            writer_epoch: Some(DecimalString::new(lease.writer_epoch())),
            lease_epoch: None, target_revision: Some(DecimalString::new(revision)),
        }), None,
        CommandBody::SessionSend(SessionSendBody {
            content: vec![ContentBlock::Text { text: "fixture first turn".into() }],
            policy: SendPolicy::WhenIdle,
        }),
    ).unwrap();
    let first = host.send_codex_session_from_wire(&transport, send, &policy).unwrap();
    assert!(matches!(first.port_observation, Some(BootstrapPortObservation::PodAccepted(_))));
    let id = CommandId::try_from(first.receipt.command_id.as_str()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let observed = client.inspect_claimed_codex_bootstrap(&id, &target, lease.writer_epoch()).unwrap();
        if observed.settlement == Some(BootstrapSettlementStage::Completed) { break; }
        assert!(Instant::now() < deadline, "A bootstrap did not complete before rebind");
        std::thread::sleep(Duration::from_millis(25));
    }
    fs::write(fixture.directory.join("rebind.v22.first.done"), first.receipt.command_id).unwrap();
    drop(host);
    std::mem::forget(fixture);
}

#[test]
#[ignore = "helper for disposable v22 later turn after A to B rebind"]
fn rebind_v22_second_later_manager_process_helper() {
    let fixture = Fixture::from_shared();
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let mut port = port_for(&fixture, &binary);
    let reference = CredentialRef::from_trusted_vault(
        fixture.scope.clone(), "vault.codex.preflight",
    ).unwrap();
    port.register_codex_credential_source_from_trusted_policy(
        TrustedCodexCredentialSource::from_trusted_policy(reference, fixture.source.clone()).unwrap(),
    ).unwrap();
    let mut host = DurableAuthority::open(&fixture.database, port).unwrap();
    register_restarted_codex_profile(&mut host, &fixture);
    let actor = ActorId::try_from("actor.codex.preflight").unwrap();
    let process = AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(
        1000, 4242, 777, "/user.slice/preflight.scope",
    ).unwrap();
    let transport = Transport(AuthenticatedPeer::owner_cli_from_authenticated_transport(
        process.clone(), CredentialGeneration::new(1).unwrap(),
    ));
    host.reattest_actor_from_trusted_replay(&transport,
        ActorRegistration::owner_cli_from_trusted_policy(
            actor.clone(), fixture.scope.clone(), process, CredentialGeneration::new(1).unwrap(),
        ),
    ).unwrap();
    let recorded_id = host.recorded_snapshot().grants[0].grant_id;
    let grant = host.activate_recorded_grant_for_actor_from_trusted_replay(
        &actor, &fixture.scope, recorded_id,
    ).unwrap();
    let key = "rebind.native.v22.second";
    assert_eq!(host.prepare_current_codex_v2_rebind(&fixture.scope, &fixture.pod, key)
        .unwrap().phase, podbay_store::DurableRebindPhase::Pending);
    let completed = host.complete_current_codex_v2_rebind(&fixture.scope, &fixture.pod, key).unwrap();
    assert_eq!(completed.stage, RebindCompletionStage::PodActive);
    let session = SessionId::try_from("session.codex.preflight").unwrap();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let (target, revision) = store.current_native_writer_target_for_session(&fixture.scope, &session).unwrap();
    let owner = store.owner_epoch().unwrap();
    let manager_credential = store.current_manager_credential_claim(owner).unwrap().credential_epoch();
    let prior_epoch: u64 = fs::read_to_string(
        fixture.directory.join("rebind.v22.first.writer_epoch"),
    ).unwrap().parse().unwrap();
    let lease = store.acquire_native_writer_lease_from_trusted_host(&TrustedNativeWriterLeaseRequest {
        target: target.clone(), holder_actor_id: actor.clone(), holder_credential_generation: 1,
        expected_owner_epoch: owner,
        expected_manager_credential_epoch: manager_credential,
        expected_authority_revision: host.recorded_snapshot().revision,
        expected_writer_epoch: Some(prior_epoch), ttl_seconds: 90,
    }).unwrap();
    drop(store);
    assert_eq!(lease.writer_epoch(), prior_epoch + 1);
    let policy = TrustedBootstrapSendPolicy::from_trusted_policy(
        grant, Instant::now() + Duration::from_secs(60),
    ).unwrap();
    let second = CommandEnvelope::new(
        "request.v22.rebind.second", "key.v22.rebind.second",
        WireTarget::Session { session_id: session.as_str().into() },
        Some(Guard {
            manager_epoch: Some(DecimalString::new(owner)),
            pod_epoch: Some(DecimalString::new(target.pod_incarnation)),
            resource_epoch: Some(DecimalString::new(target.resource_epoch)),
            writer_epoch: Some(DecimalString::new(lease.writer_epoch())),
            lease_epoch: None, target_revision: Some(DecimalString::new(revision)),
        }), None,
        CommandBody::SessionSend(SessionSendBody {
            content: vec![ContentBlock::Text { text: "fixture second turn".into() }],
            policy: SendPolicy::WhenIdle,
        }),
    ).unwrap();
    let submitted = host.send_codex_session_from_wire(&transport, second.clone(), &policy).unwrap();
    assert!(matches!(submitted.port_observation, Some(BootstrapPortObservation::UncertainAfterPossibleEffect(_))),
        "B second-turn observation: {:?}", submitted.port_observation);
    let manifest = slot_manifest(&fixture).unwrap();
    let client = PodClient::connect(&manifest).unwrap();
    let status = client.attested_status().unwrap();
    assert_eq!(status.child_pid.to_string(), fs::read_to_string(
        fixture.directory.join("rebind.v22.first.pid")).unwrap());
    let selector = LaterCodexSendSelector {
        scope_id: fixture.scope.clone(),
        command_id: CommandId::try_from(submitted.receipt.command_id.as_str()).unwrap(),
        native_target: target,
    };
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let observed = client.inspect_claimed_codex_turn(&selector, lease.writer_epoch(),
            &submitted.receipt.request_digest, "thread.fixture").unwrap();
        if matches!(observed.stage, LaterTurnControlStage::Submitted { .. }) { break; }
        assert!(Instant::now() < deadline, "rebound later-turn native reply stayed unknown");
        std::thread::sleep(Duration::from_millis(20));
    }
    for _ in 0..2 {
        let (durable, native) = host.lookup_command_with_any_native_observation(
            &transport, &fixture.scope,
            &CommandLookupSelector::Id { command_id: submitted.receipt.command_id.clone() },
        ).unwrap();
        assert_eq!(durable.receipt, submitted.receipt);
        assert!(matches!(native, Some(CommandNativeObservation::LaterTurn(value))
            if matches!(value.stage(), LaterTurnNativeStage::Submitted { native_turn_id, .. }
                if native_turn_id == "turn.later.fixture")));
    }
    let mut retry = second;
    retry.request_id = "request.v22.rebind.second.retry".into();
    let duplicate = host.send_codex_session_from_wire(&transport, retry, &policy).unwrap();
    assert!(duplicate.duplicate && !duplicate.port_called);
    assert_eq!(duplicate.receipt, submitted.receipt);
    let frames = fs::read_to_string(fixture_codex_slot(&fixture).join("home/codex/frames.log")).unwrap();
    assert_eq!(frames.lines().filter(|line| line.contains("\"method\":\"turn/start\"")).count(), 2);
    assert!(!client.stop().unwrap().child_running);
    fs::write(fixture.directory.join("rebind.v22.second.done"), b"one_second_turn").unwrap();
    drop(host);
    std::mem::forget(fixture);
}

#[test]
#[ignore = "requires disposable user systemd and PODBAY_TEST_POD_BINARY; fake app-server only"]
fn disposable_codex_v22_second_turn_after_a_to_b_rebind_uses_current_anchor() {
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let fixture = Fixture::new();
    install_fake_completed_then_second_turn(&fixture, false, 0);
    run_rebind_manager_helper("rebind_v22_first_completed_manager_process_helper", &fixture, &binary);
    let manifest = slot_manifest(&fixture).unwrap();
    let _unit_guard = DisposableUnitGuard::for_manifest(&manifest);
    assert!(fixture.directory.join("rebind.v22.first.done").is_file());
    run_rebind_manager_helper("rebind_v22_second_later_manager_process_helper", &fixture, &binary);
    assert!(fixture.directory.join("rebind.v22.second.done").is_file());
}

#[test]
#[ignore = "requires disposable user systemd and PODBAY_TEST_POD_BINARY, PODBAY_TEST_REAL_CODEX_BINARY, PODBAY_TEST_REAL_AUTH_SOURCE; submits one real model turn"]
fn disposable_codex_v2_real_first_bootstrap_has_one_fsynced_submitted_turn() {
    let smoke_start = Instant::now();
    let pod_binary = required_real_test_path("PODBAY_TEST_POD_BINARY");
    let codex_binary = required_real_test_path("PODBAY_TEST_REAL_CODEX_BINARY");
    let auth_source = required_real_test_path("PODBAY_TEST_REAL_AUTH_SOURCE");
    assert_eq!(
        fs::metadata(&auth_source).unwrap().permissions().mode() & 0o077,
        0,
        "real Codex auth source must be private"
    );
    let mut fixture = Fixture::new();
    fixture.executable = codex_binary;
    fs::set_permissions(
        fixture.directory.join("workspace"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fixture.source = auth_source;

    let mut port = port_for(&fixture, &pod_binary);
    let reference =
        CredentialRef::from_trusted_vault(fixture.scope.clone(), "vault.codex.preflight").unwrap();
    port.register_codex_credential_source_from_trusted_policy(
        TrustedCodexCredentialSource::from_trusted_policy(reference, fixture.source.clone())
            .unwrap(),
    )
    .unwrap();
    let (fixture, mut host, _, _, transport, launch_request) = setup_with_port(
        Role::Coordinator,
        fixture,
        port,
        Duration::from_secs(300),
        600,
    );
    eprintln!("real smoke setup_ms={}", smoke_start.elapsed().as_millis());
    let accepted = host
        .dispatch_prepared_bound_root_codex_v2(&transport, launch_request.clone())
        .unwrap();
    eprintln!("real smoke launch_ms={}", smoke_start.elapsed().as_millis());
    if accepted.status.stage != LaunchDispatchStage::HostAccepted {
        let manifest = slot_manifest(&fixture);
        let pod_status = manifest.as_ref().map(|path| {
            PodClient::connect(path)
                .and_then(|client| client.attested_status())
                .map(|status| {
                    format!(
                        "child_running={}, bound={}",
                        status.child_running,
                        status.bound.is_some()
                    )
                })
                .map_err(|error| error.to_string())
        });
        if let Some(path) = manifest {
            if let Some(stem) = path.file_stem().and_then(|value| value.to_str()) {
                let _ = Command::new("systemctl")
                    .args(["--user", "stop", &format!("podbay-pod-{stem}.service")])
                    .status();
            }
        }
        panic!(
            "real Codex launch did not reach HostAccepted: {:?}; pod={pod_status:?}",
            accepted.status
        );
    }
    let manifest = slot_manifest(&fixture).expect("one committed V2 pod manifest");
    let _unit_guard = DisposableUnitGuard::for_manifest(&manifest);
    let client = PodClient::connect(&manifest).unwrap();
    assert!(client.attested_status().unwrap().child_running);

    let session_id = SessionId::try_from("session.codex.preflight").unwrap();
    let policy = TrustedBootstrapSendPolicy::from_trusted_policy(
        launch_request.host_request.grant_id,
        Instant::now() + Duration::from_secs(180),
    )
    .unwrap();
    let lease = host
        .acquire_initial_bootstrap_writer_lease(&transport, &session_id, &policy, 300)
        .unwrap();
    eprintln!("real smoke lease_ms={}", smoke_start.elapsed().as_millis());
    let (target, session_revision) = PodBayStore::open(&fixture.database)
        .unwrap()
        .current_native_writer_target_for_session(&fixture.scope, &session_id)
        .unwrap();
    assert_eq!(lease.target(), &target);
    let envelope = CommandEnvelope::new(
        "request.codex.real-bootstrap.one",
        "key.codex.real-bootstrap.one",
        WireTarget::Session {
            session_id: session_id.as_str().into(),
        },
        Some(Guard {
            manager_epoch: Some(DecimalString::new(lease.owner_epoch())),
            pod_epoch: Some(DecimalString::new(target.pod_incarnation)),
            resource_epoch: Some(DecimalString::new(target.resource_epoch)),
            writer_epoch: Some(DecimalString::new(lease.writer_epoch())),
            lease_epoch: None,
            target_revision: Some(DecimalString::new(session_revision)),
        }),
        None,
        CommandBody::SessionSend(SessionSendBody {
            content: vec![ContentBlock::Text {
                text: "Reply with one short sentence.".into(),
            }],
            policy: SendPolicy::WhenIdle,
        }),
    )
    .unwrap();
    let submitted = host
        .send_first_codex_bootstrap_from_wire(&transport, envelope.clone(), &policy)
        .unwrap();
    eprintln!("real smoke send_ms={}", smoke_start.elapsed().as_millis());
    assert!(submitted.port_called);
    assert!(
        matches!(
            submitted.port_observation,
            Some(BootstrapPortObservation::PodAccepted(_))
        ),
        "first send port observation: {:?}",
        submitted.port_observation
    );
    let durable = reopened_bootstrap_journal(&fixture);
    assert!(matches!(
        durable.stage,
        CodexJournalStage::BootstrapSubmitted | CodexJournalStage::BootstrapCompleted
    ));
    assert_eq!(
        durable.command_key.as_deref(),
        Some(submitted.receipt.command_id.as_str())
    );
    let native_turn_id = durable
        .native_turn_id
        .as_deref()
        .expect("native turn ID is durable");
    assert!(!native_turn_id.is_empty());

    let mut retry = envelope;
    retry.request_id = "request.codex.real-bootstrap.retry".into();
    let duplicate = host
        .send_first_codex_bootstrap_from_wire(&transport, retry, &policy)
        .unwrap();
    assert!(duplicate.duplicate);
    assert!(!duplicate.port_called);
    assert_eq!(duplicate.receipt, submitted.receipt);
    let after_retry = reopened_bootstrap_journal(&fixture);
    assert!(matches!(
        after_retry.stage,
        CodexJournalStage::BootstrapSubmitted | CodexJournalStage::BootstrapCompleted
    ));
    assert_eq!(after_retry.command_key, durable.command_key);
    assert_eq!(after_retry.native_turn_id, durable.native_turn_id);
    let command_id = CommandId::try_from(submitted.receipt.command_id.as_str()).unwrap();
    let completion_deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let observed = client
            .inspect_claimed_codex_bootstrap(&command_id, &target, lease.writer_epoch())
            .unwrap();
        assert!(matches!(
            observed.stage,
            BootstrapControlStage::Submitted {
                ref native_turn_id,
                ..
            } if native_turn_id == durable.native_turn_id.as_ref().unwrap()
        ));
        match observed.settlement {
            Some(BootstrapSettlementStage::Completed) => break,
            Some(BootstrapSettlementStage::Failed | BootstrapSettlementStage::Interrupted) => {
                panic!(
                    "real Codex bootstrap reported terminal failure: {:?}",
                    observed.settlement
                );
            }
            None | Some(BootstrapSettlementStage::CompletionObservedPendingIdleProof) => {}
        }
        assert!(
            Instant::now() < completion_deadline,
            "real Codex bootstrap did not prove idle completion: {:?}",
            observed.settlement
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        reopened_bootstrap_journal(&fixture).stage,
        CodexJournalStage::BootstrapCompleted,
    );
    eprintln!(
        "real smoke completed_ms={}",
        smoke_start.elapsed().as_millis()
    );
    assert!(!client.stop().unwrap().child_running);
}
