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
    ResourceKind, Role, Run, RunId, ScopeId, Session, SessionId, StoreLineageId, WorkKind,
};
use podbay_host::{
    ActorRegistration, AuthenticatedPeer, AuthenticatedProcessSubject, AuthenticatedTransport,
    AuthorisedBoundLaunch, AuthorisedDispatch, BootstrapNativeStage, BootstrapPortObservation,
    BoundHostLaunchProposal, BoundLaunchPodRequest, CredentialGeneration, CredentialRef,
    DurableAuthority, ExecutionMode, GrantMode, GrantSpec, GuardSet, HostAction, HostDispatchPort,
    HostError, HostRequest, LaunchSelection, ManagerEpoch, Operation, PodIncarnation,
    PortDispatchError, PortDispatchOutcome, PortReceiptRef, RegisteredLaunchProfile,
    ResolvedNativeCodexLaunch, Right, Target, TrustedBootstrapSendPolicy, TrustedDriverTemplate,
    TrustedLaunchProfileInput, TrustedNativeHostConfig, WorkspaceAccess, WorkspaceSelection,
};
use podbay_launch_linux::{
    CodexV2Preflight, LinuxLaunchPort, TrustedCodexCredentialSource, TrustedLinuxLaunchConfig,
    preflight_committed_codex_v2, preflight_committed_codex_v2_read_only,
};
use podbay_pod::{
    BootstrapControlStage, BootstrapSettlementStage, CODEX_V2_CAPABILITY, CodexCommandJournal,
    CodexJournalIdentity, CodexJournalStage, LinuxBackend, PodClient, PodError,
    launch_bound_codex_v2,
};
use podbay_store::{
    CommandLookupSelector, EffectClaim, LaunchDispatchStage, PodBayStore,
    TrustedNativeWriterLeaseRequest,
};
use podbay_wire::{
    CodexAppServerPolicyV2, CommandBody, CommandEnvelope, ContentBlock, DecimalString, Guard,
    ResourceDriver, SendPolicy, SessionSendBody, Target as WireTarget,
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
        &fixture.directory.join("codex.commands.log"),
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
    let frames = fixture.directory.join("home/codex/frames.log");
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
        fs::read_to_string(fixture.directory.join("home/codex/frames.log"))
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
        fs::read_to_string(fixture.directory.join("home/codex/frames.log"))
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
    let (fixture, mut host, _, _, transport, launch_request) = setup_with_port(
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
    assert!(fixture.directory.join("codex.commands.log").is_file());
    let journal = reopened_bootstrap_journal(&fixture);
    assert_eq!(journal.stage, CodexJournalStage::BootstrapSubmitted);
    assert_eq!(journal.native_turn_id.as_deref(), Some("turn.fixture"));
    let frames = fixture.directory.join("home/codex/frames.log");
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
