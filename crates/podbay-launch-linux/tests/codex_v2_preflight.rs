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
    ActorId, Attempt, AttemptId, CommandAdmission, CommandId, Epoch, LaunchBinding, Pod, PodId,
    Resource, ResourceId, ResourceKind, Role, Run, RunCommandKind, RunId, ScopeId, Session,
    SessionId, WorkKind,
};
use podbay_host::{
    ActorRegistration, AuthenticatedPeer, AuthenticatedProcessSubject, AuthenticatedTransport,
    AuthorisedBoundLaunch, AuthorisedDispatch, BoundHostLaunchProposal, BoundLaunchPodRequest,
    CredentialGeneration, CredentialRef, DurableAuthority, ExecutionMode, GrantMode, GrantSpec,
    GuardSet, HostAction, HostDispatchPort, HostError, HostRequest, LaunchSelection, ManagerEpoch,
    Operation, PodIncarnation, PortDispatchError, PortDispatchOutcome, PortReceiptRef,
    RegisteredLaunchProfile, ResolvedNativeCodexLaunch, Right, Target, TrustedDriverTemplate,
    TrustedLaunchProfileInput, TrustedNativeHostConfig, WorkspaceAccess, WorkspaceSelection,
};
use podbay_launch_linux::{
    CodexV2Preflight, TrustedCodexCredentialSource, preflight_committed_codex_v2,
};
use podbay_pod::{CODEX_V2_CAPABILITY, PodError, launch_bound_codex_v2};
use podbay_store::{EffectClaim, LaunchDispatchStage, PodBayStore};
use podbay_wire::{CodexAppServerPolicyV2, ResourceDriver};
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
        let directory = std::env::temp_dir().join(format!(
            "podbay-codex-preflight-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let workspace = directory.join("workspace");
        fs::create_dir(&workspace).unwrap();
        let executable = directory.join("agent.sh");
        fs::write(
            &executable,
            b"#!/bin/sh\nset -eu\n[ \"$1\" = app-server ]\n[ \"$2\" = --listen ]\n[ \"$3\" = stdio:// ]\n[ -r \"$CODEX_HOME/auth.json\" ]\nread -r initialize\nprintf '%s\\n' \"$initialize\" > \"$CODEX_HOME/frames.log\"\nprintf '{\"id\":1,\"result\":{\"codexHome\":\"%s\",\"platformFamily\":\"unix\",\"platformOs\":\"linux\",\"userAgent\":\"fixture\"}}\\n' \"$CODEX_HOME\"\nread -r initialized\nprintf '%s\\n' \"$initialized\" >> \"$CODEX_HOME/frames.log\"\nsleep 30\n",
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
            pod: PodId::try_from("pod.codex.preflight").unwrap(),
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

struct Admitted;

impl CommandAdmission for Admitted {
    fn admits_run(&self, _: &CommandId, _: &RunId, kind: RunCommandKind) -> bool {
        kind == RunCommandKind::Launch
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
    let mut host = DurableAuthority::open(&fixture.database, NoPort(calls.clone())).unwrap();
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
    let mut session = Session::new(
        SessionId::try_from("session.codex.preflight").unwrap(),
        actor,
        fixture.scope.clone(),
    );
    let mut run = Run::new(
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
    run.admit(
        run.revision(),
        &CommandId::try_from("command.codex.preflight").unwrap(),
        &Admitted,
    )
    .unwrap();
    session.bind_run(session.revision(), &run).unwrap();
    let mut attempt = Attempt::new(
        AttemptId::try_from("attempt.codex.preflight").unwrap(),
        run.id().clone(),
        1,
        Epoch::new(1).unwrap(),
    )
    .unwrap();
    run.start_attempt(run.revision(), &attempt).unwrap();
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
    let binding =
        LaunchBinding::from_aggregates(&session, &run, &attempt, &pod, &[resource]).unwrap();
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
            deadline: Instant::now() + Duration::from_secs(30),
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
                wall_seconds: 60,
                max_children: 1,
                parent_run_id: None,
            },
        }),
    };
    let receipt = host.admit_bound_root_codex_v2(&transport, request).unwrap();
    assert_eq!(receipt.status.stage, LaunchDispatchStage::Prepared);
    let proof = host
        .inspect_committed_root_codex_v2(&fixture.scope, &fixture.pod)
        .unwrap();
    let source =
        TrustedCodexCredentialSource::from_trusted_policy(credential, fixture.source.clone())
            .unwrap();
    (fixture, host, proof, source, calls)
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
