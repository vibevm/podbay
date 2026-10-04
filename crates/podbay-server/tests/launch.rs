#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_compact::{KeyPair, Seed};
use podbay_client::{LinuxClientAuthLimits, authenticate_existing_linux_stream_with_limits};
use podbay_core::{ActorId, ResourceKind, ScopeId, SessionId};
use podbay_host::{
    ActorRegistration, AuthenticatedPeer, AuthenticatedProcessSubject, AuthenticatedTransport,
    AuthorisedBoundLaunch, AuthorisedDispatch, BootstrapNativeObservation, BootstrapNativeStage,
    BootstrapObservationError, CredentialGeneration, CredentialRef, DurableAuthority,
    DurableAuthorityError, ExecutionMode, GrantMode, GrantSpec, HostDispatchPort, HostError,
    Operation, PortDispatchError, PortDispatchOutcome, PortReceiptRef, RegisteredLaunchProfile,
    ResolvedClaimedBootstrap, ResolvedClaimedBootstrapInspection, ResolvedNativeCodexLaunch, Right,
    Target as HostTarget, TrustedBootstrapSendPolicy, TrustedDriverTemplate,
    TrustedLaunchProfileInput, TrustedNativeHostConfig, TrustedWireRootLaunchPolicy,
};
use podbay_server::{
    LinuxAcceptedPeerEvidence, LinuxManagerCommandsGetListener, LinuxServeOneFault, ServerFault,
    TrustedBootstrapSendTemplate, TrustedWireRootLaunchTemplate,
    serve_authenticated_linux_launch_one,
};
use podbay_store::{
    AuthorityMutation, BoundLaunchFormat, CommandLookupSelector, PodBayStore,
    TrustedNativeWriterLeaseRequest,
};
use podbay_wire::{
    CommandEnvelope, Guard, MutationOperation, ReadEnvelope, ReadOperation, ResourceDriver,
    Target as WireTarget,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

struct Fixture {
    root: PathBuf,
    database: PathBuf,
    executable: PathBuf,
    workspace: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "podbay-server-launch-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let workspace = root.join("workspace");
        fs::create_dir(&workspace).unwrap();
        let executable = root.join("fake-app-server");
        fs::write(&executable, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            database: root.join("store.sqlite"),
            root,
            executable,
            workspace,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Clone, Copy)]
enum PortMode {
    Accepted,
    SlowAccepted,
    SlowSend,
    SendLostReply,
    LostReply,
}

struct FakePort {
    calls: Arc<AtomicUsize>,
    inspect_calls: Arc<AtomicUsize>,
    observe_stage: Arc<std::sync::atomic::AtomicU8>,
    mode: PortMode,
}

impl HostDispatchPort for FakePort {
    type Receipt = PortReceiptRef;

    fn dispatch(
        &mut self,
        _: AuthorisedDispatch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        panic!("wire root fixture must not use generic dispatch")
    }

    fn launch_bound(
        &mut self,
        _: AuthorisedBoundLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        panic!("wire root fixture must not use legacy launch")
    }

    fn accepts_resolved_codex_v2(&self) -> bool {
        true
    }

    fn launch_resolved_codex_v2(
        &mut self,
        launch: ResolvedNativeCodexLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        assert_eq!(launch.committed_record().format, BoundLaunchFormat::CodexV2);
        self.calls.fetch_add(1, Ordering::SeqCst);
        let receipt = PortReceiptRef::from_port("receipt.fake.codex").unwrap();
        match self.mode {
            PortMode::Accepted | PortMode::SlowSend | PortMode::SendLostReply => {
                Ok(PortDispatchOutcome::Accepted(receipt))
            }
            PortMode::SlowAccepted => {
                thread::sleep(Duration::from_millis(2_300));
                Ok(PortDispatchOutcome::Accepted(receipt))
            }
            PortMode::LostReply => Err(PortDispatchError::UncertainAfterPossibleEffect {
                receipt_ref: Some(receipt),
            }),
        }
    }

    fn accepts_claimed_codex_bootstrap(&self) -> bool {
        true
    }

    fn send_claimed_codex_bootstrap(
        &mut self,
        _: ResolvedClaimedBootstrap,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let receipt = PortReceiptRef::from_port("receipt.fake.bootstrap").unwrap();
        match self.mode {
            PortMode::Accepted | PortMode::SlowAccepted => {
                Ok(PortDispatchOutcome::Accepted(receipt))
            }
            PortMode::SlowSend => {
                thread::sleep(Duration::from_secs(31));
                Ok(PortDispatchOutcome::Accepted(receipt))
            }
            PortMode::SendLostReply => Err(PortDispatchError::UncertainAfterPossibleEffect {
                receipt_ref: Some(receipt),
            }),
            PortMode::LostReply => Err(PortDispatchError::UncertainAfterPossibleEffect {
                receipt_ref: Some(receipt),
            }),
        }
    }

    fn inspect_claimed_codex_bootstrap(
        &self,
        inspection: ResolvedClaimedBootstrapInspection,
    ) -> Result<BootstrapNativeObservation, BootstrapObservationError> {
        self.inspect_calls.fetch_add(1, Ordering::SeqCst);
        let metadata = fs::metadata(inspection.store_path())
            .map_err(|_| BootstrapObservationError::Unavailable)?;
        if (metadata.dev(), metadata.ino()) != inspection.store_file_identity() {
            return Err(BootstrapObservationError::Unavailable);
        }
        let mut store = PodBayStore::open_existing_read_only(inspection.store_path())
            .map_err(|_| BootstrapObservationError::Unavailable)?;
        let proof = store
            .inspect_claimed_bootstrap_send(inspection.selector())
            .map_err(|_| BootstrapObservationError::Unavailable)?;
        if proof.writer_epoch() != inspection.writer_epoch()
            || proof.receipt().request_digest != inspection.expected_request_digest()
        {
            return Err(BootstrapObservationError::Invalid);
        }
        let mode = self.observe_stage.load(Ordering::SeqCst);
        let stage = match mode {
            1 | 3 | 4 => BootstrapNativeStage::Submitted {
                native_thread_id: "thread.native.one".into(),
                native_session_id: "session.native.one".into(),
                native_turn_id: "turn.native.one".into(),
            },
            2 => BootstrapNativeStage::ClaimedUnobserved,
            _ => return Err(BootstrapObservationError::Unsupported),
        };
        let mut selector = inspection.selector().clone();
        if mode == 4 {
            selector.native_target.pod_incarnation += 1;
        }
        let digest = if mode == 3 {
            "0".repeat(64)
        } else {
            inspection.expected_request_digest().into()
        };
        BootstrapNativeObservation::from_attested_pod(
            "podbay.codex-bootstrap.inspect/1",
            selector,
            inspection.writer_epoch(),
            digest,
            stage,
        )
    }
}

struct ReplayTransport(AuthenticatedPeer);
impl AuthenticatedTransport for ReplayTransport {
    fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError> {
        Ok(self.0.clone())
    }
}

fn prepared_authority(
    fixture: &Fixture,
    mode: PortMode,
) -> (
    DurableAuthority<FakePort>,
    ActorId,
    podbay_host::GrantId,
    Arc<AtomicUsize>,
    ReplayTransport,
) {
    let (server, _client) = UnixStream::pair().unwrap();
    let process = LinuxAcceptedPeerEvidence::from_accepted(&server)
        .unwrap()
        .subject()
        .clone();
    let actor = ActorId::try_from("actor.server.launch").unwrap();
    let scope = ScopeId::try_from("scope.server.launch").unwrap();
    let generation = CredentialGeneration::new(1).unwrap();
    let registration = ActorRegistration::owner_cli_from_trusted_policy(
        actor.clone(),
        scope.clone(),
        process.clone(),
        generation,
    );
    let transport = ReplayTransport(AuthenticatedPeer::owner_cli_from_authenticated_transport(
        process, generation,
    ));
    let calls = Arc::new(AtomicUsize::new(0));
    let inspect_calls = Arc::new(AtomicUsize::new(0));
    let observe_stage = Arc::new(std::sync::atomic::AtomicU8::new(0));
    let mut first = DurableAuthority::open(
        &fixture.database,
        FakePort {
            calls: calls.clone(),
            inspect_calls: inspect_calls.clone(),
            observe_stage: observe_stage.clone(),
            mode,
        },
    )
    .unwrap();
    first
        .register_actor_from_trusted_policy(registration.clone())
        .unwrap();
    let actor_record = first.recorded_snapshot().actors[0].clone();
    drop(first);

    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let snapshot = store.authority_snapshot().unwrap();
    let signer = KeyPair::from_seed(Seed::new([7; 32]));
    store
        .register_actor_verifier_from_trusted_host(
            snapshot.owner_epoch,
            snapshot.revision,
            &actor_record,
            *signer.pk,
        )
        .unwrap();
    drop(store);

    let mut authority = DurableAuthority::open(
        &fixture.database,
        FakePort {
            calls: calls.clone(),
            inspect_calls,
            observe_stage,
            mode,
        },
    )
    .unwrap();
    authority
        .reattest_actor_from_trusted_replay(&transport, registration)
        .unwrap();
    let credential = CredentialRef::from_trusted_vault(scope.clone(), "vault.server").unwrap();
    let digest = Sha256::digest(fs::read(&fixture.executable).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let profile = TrustedLaunchProfileInput {
        profile_ref: "profile.server.codex".into(),
        profile_generation: 1,
        executable: fixture.executable.to_string_lossy().into_owned(),
        binary_generation: format!("sha256:{digest}"),
        executable_sha256: digest,
        workspace_root: fixture.workspace.clone(),
        resource_layout: vec![TrustedDriverTemplate {
            kind: ResourceKind::StructuredProvider,
            driver: ResourceDriver::Structured {
                driver_ref: "driver.server.codex".into(),
                protocol_ref: "protocol.server.codex".into(),
            },
        }],
        execution_mode: ExecutionMode::LinuxCooperative,
        fixed_arguments: vec!["app-server".into(), "--listen".into(), "stdio://".into()],
        permitted_extra_arguments: BTreeSet::new(),
        default_model: "gpt-6-sol".into(),
        allowed_models: BTreeSet::from(["gpt-6-sol".into()]),
        default_effort: "medium".into(),
        allowed_efforts: BTreeSet::from(["medium".into()]),
        workspace_scope: scope.clone(),
        workspace_basis_ref: "basis.server".into(),
        allowed_cwd_prefix: ".".into(),
        allow_write: true,
        allowed_tool_bundle_refs: BTreeSet::new(),
        environment_refs: Vec::new(),
        credential_refs: vec![credential.clone()],
        max_wall_seconds: 60,
        max_children: 2,
        allow_fallback: false,
    };
    let codex_policy = podbay_wire::CodexAppServerPolicyV2::new(
        &scope,
        credential.as_str().into(),
        "driver.server.codex".into(),
        "protocol.server.codex".into(),
    )
    .unwrap();
    authority
        .register_launch_profile_from_trusted_policy(
            RegisteredLaunchProfile::from_trusted_policy(profile)
                .unwrap()
                .with_codex_policy_from_trusted_policy(codex_policy)
                .unwrap(),
        )
        .unwrap();
    authority
        .register_native_host_from_trusted_policy(
            TrustedNativeHostConfig::for_compiled_backend("host.server".into())
                .unwrap()
                .with_structured_driver(
                    "driver.server.codex".into(),
                    "protocol.server.codex".into(),
                )
                .unwrap(),
        )
        .unwrap();
    let grant = authority
        .install_grant_from_trusted_policy(
            &actor,
            GrantSpec {
                scope_id: scope.clone(),
                mode: GrantMode::Controller,
                rights: BTreeSet::from([
                    Right::new(Operation::LaunchPod, HostTarget::Scope(scope.clone())),
                    Right::new(Operation::UseCredential, HostTarget::Credential(credential)),
                    Right::new(Operation::SendSession, HostTarget::Scope(scope.clone())),
                ]),
                remaining_delegation_depth: 0,
            },
        )
        .unwrap();
    (authority, actor, grant, calls, transport)
}

fn launch_request(
    request_id: &str,
    key: &str,
    grant: podbay_host::GrantId,
    model: &str,
) -> CommandEnvelope {
    CommandEnvelope::new_json(
        request_id,
        key,
        WireTarget::Scope {
            scope_id: "scope.server.launch".into(),
        },
        None,
        None,
        MutationOperation::Launch,
        json!({
            "session": {"kind": "new"},
            "role": "coordinator",
            "work": {"kind": "service", "resultContractRef": "result.none"},
            "profileRef": "profile.server.codex",
            "selection": {"modelId": model, "reasoningEffort": "medium", "fallback": "none"},
            "workspace": {
                "scopeId": "scope.server.launch", "relativeCwd": ".",
                "basisRef": "basis.server", "access": "read_write"
            },
            "toolBundleRefs": [],
            "authority": {"grantRef": format!("grant.{}", grant.get())},
            "limits": {"wallSeconds": "30", "maxChildren": "1"}
        }),
    )
    .unwrap()
}

fn read_by_key(request_id: &str, key: &str) -> ReadEnvelope {
    ReadEnvelope::new_json(
        request_id,
        WireTarget::Scope {
            scope_id: "scope.server.launch".into(),
        },
        ReadOperation::CommandsGet,
        json!({"selector":{"kind":"key","key":key}}),
    )
    .unwrap()
}

fn authenticate(socket: UnixStream, actor: &str) -> impl Read + Write {
    let signer = KeyPair::from_seed(Seed::new([7; 32]));
    authenticate_existing_linux_stream_with_limits(
        socket,
        actor,
        LinuxClientAuthLimits::new(Duration::from_secs(5), Duration::from_secs(90)).unwrap(),
        |challenge| {
            let signature = signer.sk.sign(challenge.bytes, None);
            let mut bytes = [0_u8; 64];
            bytes.copy_from_slice(signature.as_ref());
            Some(bytes)
        },
    )
    .unwrap()
}

fn exchange(mut stream: impl Read + Write, bytes: &[u8]) -> Value {
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(bytes).unwrap();
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).unwrap();
    let size = u32::from_be_bytes(prefix) as usize;
    assert!(size <= 1_048_576);
    let mut response = vec![0_u8; size];
    stream.read_exact(&mut response).unwrap();
    serde_json::from_slice(&response).unwrap()
}

struct StopOnDrop(Arc<AtomicBool>);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn serve_batch(
    listener: &mut LinuxManagerCommandsGetListener,
    authority: &mut DurableAuthority<FakePort>,
    actor: &ActorId,
    requests: Vec<Vec<u8>>,
    template: Option<&TrustedWireRootLaunchTemplate>,
    send_template: Option<&TrustedBootstrapSendTemplate>,
) -> Vec<Value> {
    let path = listener.path().to_path_buf();
    let actor_name = actor.as_str().to_owned();
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = stop.clone();
    let worker = thread::spawn(move || {
        let _stop = StopOnDrop(worker_stop);
        requests
            .into_iter()
            .map(|request| {
                let socket = UnixStream::connect(&path).unwrap();
                exchange(authenticate(socket, &actor_name), &request)
            })
            .collect::<Vec<_>>()
    });
    let report = if let (Some(template), Some(send_template)) = (template, send_template) {
        listener
            .serve_until_with_launch_and_first_send(authority, &stop, template, send_template)
            .unwrap()
    } else if let Some(template) = template {
        listener
            .serve_until_with_launch(authority, &stop, template)
            .unwrap()
    } else {
        listener.serve_until(authority, &stop).unwrap()
    };
    let responses = worker.join().unwrap();
    assert_eq!(report.accepted as usize, responses.len());
    assert_eq!(report.completed, report.accepted);
    assert!(report.last_failure.is_none());
    responses
}

#[test]
fn default_read_only_then_opt_in_launch_dedup_conflict_and_readback() {
    let fixture = Fixture::new();
    let (mut authority, actor, grant, calls, _) = prepared_authority(&fixture, PortMode::Accepted);
    let mut listener = LinuxManagerCommandsGetListener::bind(&fixture.root).unwrap();
    let launch = launch_request("request.first", "key.server.launch", grant, "gpt-6-sol");
    let read_only = serve_batch(
        &mut listener,
        &mut authority,
        &actor,
        vec![launch.encode_json().unwrap()],
        None,
        None,
    );
    assert_eq!(read_only[0]["error"]["code"], "unsupported");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(authority.recorded_snapshot().pods.is_empty());
    listener.shutdown().unwrap();

    let mut listener = LinuxManagerCommandsGetListener::bind(&fixture.root).unwrap();
    let template = TrustedWireRootLaunchTemplate::from_trusted_policy(
        grant,
        Duration::from_secs(30),
        "result.none",
    )
    .unwrap();
    let duplicate = launch_request("request.second", "key.server.launch", grant, "gpt-6-sol");
    let changed = launch_request("request.changed", "key.server.launch", grant, "model.other");
    let responses = serve_batch(
        &mut listener,
        &mut authority,
        &actor,
        vec![
            launch.encode_json().unwrap(),
            duplicate.encode_json().unwrap(),
            changed.encode_json().unwrap(),
            read_by_key("request.lookup", "key.server.launch")
                .encode_json()
                .unwrap(),
        ],
        Some(&template),
        None,
    );
    let first = &responses[0]["ok"];
    assert_eq!(first["state"], "host_accepted");
    assert_eq!(first["value"]["launchStage"], "host_accepted");
    assert_eq!(first["value"]["revisionKind"], "admission_event_sequence");
    assert_eq!(first["revision"], first["cursor"]["sequence"]);
    assert_eq!(first["revision"], first["value"]["eventSequence"]);
    assert_eq!(first["cursor"]["scopeId"], "scope.server.launch");
    assert!(first["cursor"]["storeLineage"].as_str().is_some());
    assert_eq!(first["value"]["duplicate"], false);
    assert_eq!(first["value"]["portCalled"], true);
    assert_eq!(first["value"]["scopeId"], "scope.server.launch");
    for (field, prefix) in [
        ("sessionId", "session."),
        ("runId", "run."),
        ("attemptId", "attempt."),
        ("podId", "pod."),
    ] {
        assert!(first["value"][field].as_str().unwrap().starts_with(prefix));
    }
    assert_eq!(first["value"]["podIncarnation"], "1");
    assert_eq!(first["value"]["resources"].as_array().unwrap().len(), 1);
    assert_eq!(
        first["value"]["resources"][0]["kind"],
        "structured_provider"
    );
    assert!(
        first["value"]["resources"][0]["resourceId"]
            .as_str()
            .unwrap()
            .starts_with("resource.")
    );
    let replay = &responses[1]["ok"];
    assert_eq!(replay["commandId"], first["commandId"]);
    assert_eq!(replay["revision"], first["revision"]);
    assert_eq!(replay["cursor"], first["cursor"]);
    for field in [
        "scopeId",
        "sessionId",
        "runId",
        "attemptId",
        "podId",
        "podIncarnation",
        "resources",
    ] {
        assert_eq!(replay["value"][field], first["value"][field]);
    }
    assert_eq!(replay["value"]["duplicate"], true);
    assert_eq!(replay["value"]["portCalled"], false);
    assert_eq!(responses[2]["error"]["code"], "conflict");
    assert_eq!(responses[2]["requestId"], "request.changed");
    assert_eq!(
        responses[3]["ok"]["receipt"]["commandId"],
        first["commandId"]
    );
    // commands.get joins the durable launch outcome into the same read
    // snapshot; the raw outbox remains claimed, but host acceptance is known.
    assert_eq!(responses[3]["ok"]["state"], "host_accepted");
    assert_eq!(responses[3]["ok"]["effectState"], "host_accepted");
    assert_eq!(responses[3]["ok"]["launchStage"], "host_accepted");
    assert_eq!(responses[3]["ok"]["outboxState"], "claimed_uncertain");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(authority.recorded_snapshot().pods.len(), 1);
    listener.shutdown().unwrap();
}

#[test]
fn authenticated_first_send_is_claimed_once_and_keeps_native_result_separate() {
    let fixture = Fixture::new();
    let (mut authority, actor, grant, calls, transport) =
        prepared_authority(&fixture, PortMode::Accepted);
    let mut listener = LinuxManagerCommandsGetListener::bind(&fixture.root).unwrap();
    let launch_template = TrustedWireRootLaunchTemplate::from_trusted_policy(
        grant,
        Duration::from_secs(30),
        "result.none",
    )
    .unwrap();
    let send_template =
        TrustedBootstrapSendTemplate::from_trusted_policy(grant, Duration::from_secs(30))
            .unwrap()
            .with_initial_writer_lease_seconds(120)
            .unwrap();
    let launched = serve_batch(
        &mut listener,
        &mut authority,
        &actor,
        vec![
            launch_request(
                "request.bootstrap.launch",
                "key.bootstrap.launch",
                grant,
                "gpt-6-sol",
            )
            .encode_json()
            .unwrap(),
            launch_request(
                "request.bootstrap.launch.retry",
                "key.bootstrap.launch",
                grant,
                "gpt-6-sol",
            )
            .encode_json()
            .unwrap(),
            read_by_key("request.bootstrap.launch.read", "key.bootstrap.launch")
                .encode_json()
                .unwrap(),
        ],
        Some(&launch_template),
        Some(&send_template),
    );
    assert_eq!(launched[0]["ok"]["state"], "host_accepted");
    let first_guard = &launched[0]["ok"]["value"]["bootstrapGuard"];
    assert_eq!(first_guard["available"], true);
    assert_eq!(
        first_guard["guard"]["managerEpoch"],
        authority.owner_epoch().get().to_string()
    );
    assert_eq!(first_guard["guard"]["podEpoch"], "1");
    assert_eq!(first_guard["guard"]["resourceEpoch"], "1");
    assert_eq!(first_guard["guard"]["writerEpoch"], "1");
    assert_eq!(
        launched[1]["ok"]["commandId"],
        launched[0]["ok"]["commandId"]
    );
    assert_eq!(launched[1]["ok"]["value"]["duplicate"], true);
    assert_eq!(launched[1]["ok"]["value"]["portCalled"], false);
    assert_eq!(launched[1]["ok"]["value"]["bootstrapGuard"], *first_guard);
    assert_eq!(launched[2]["ok"]["state"], "host_accepted");
    assert_eq!(launched[2]["ok"]["bootstrapGuard"]["available"], false);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let session_id =
        SessionId::try_from(launched[0]["ok"]["value"]["sessionId"].as_str().unwrap()).unwrap();
    let scope = ScopeId::try_from("scope.server.launch").unwrap();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let (target, revision) = store
        .current_native_writer_target_for_session(&scope, &session_id)
        .unwrap();
    drop(store);
    let policy = TrustedBootstrapSendPolicy::from_trusted_policy(
        grant,
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    let lease = authority
        .acquire_initial_bootstrap_writer_lease(&transport, &session_id, &policy, 120)
        .unwrap();
    assert_eq!(lease.writer_epoch(), 1);
    assert_eq!(first_guard["guard"]["targetRevision"], revision.to_string());
    assert_eq!(first_guard["resourceId"], target.resource_id.as_str());
    let guard: Guard = serde_json::from_value(first_guard["guard"].clone()).unwrap();
    let send = |request_id: &str, text: &str| {
        CommandEnvelope::new_json(
            request_id,
            "key.bootstrap.send",
            WireTarget::Session {
                session_id: session_id.as_str().into(),
            },
            Some(guard.clone()),
            None,
            MutationOperation::SessionSend,
            json!({"content":[{"kind":"text","text":text}], "policy":{"kind":"when_idle"}}),
        )
        .unwrap()
    };
    let responses = serve_batch(
        &mut listener,
        &mut authority,
        &actor,
        vec![
            send("request.bootstrap.send", "hello bootstrap")
                .encode_json()
                .unwrap(),
            send("request.bootstrap.replay", "hello bootstrap")
                .encode_json()
                .unwrap(),
            read_by_key("request.bootstrap.read", "key.bootstrap.send")
                .encode_json()
                .unwrap(),
            send("request.bootstrap.changed", "different text")
                .encode_json()
                .unwrap(),
        ],
        Some(&launch_template),
        Some(&send_template),
    );
    let first = &responses[0]["ok"];
    assert_eq!(first["state"], "uncertain");
    assert_eq!(first["value"]["effectState"], "claimed_uncertain");
    assert_eq!(first["value"]["portObservation"]["kind"], "pod_accepted");
    assert_eq!(
        first["value"]["portObservation"]["durability"],
        "pod_journal_only"
    );
    assert_eq!(first["cursor"]["scopeId"], "scope.server.launch");
    assert_eq!(responses[1]["ok"]["commandId"], first["commandId"]);
    assert_eq!(responses[1]["ok"]["value"]["duplicate"], true);
    assert_eq!(responses[1]["ok"]["value"]["portCalled"], false);
    assert_eq!(
        responses[2]["ok"]["receipt"]["commandId"],
        first["commandId"]
    );
    assert_eq!(responses[2]["ok"]["state"], "uncertain");
    assert_eq!(responses[3]["error"]["code"], "conflict");
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    let inspect_calls = authority.port().inspect_calls.clone();
    let observe_stage = authority.port().observe_stage.clone();
    let command_id = first["commandId"].as_str().unwrap().to_owned();
    let request_digest = first["value"]["requestDigest"].as_str().unwrap().to_owned();
    let before = PodBayStore::open(&fixture.database)
        .unwrap()
        .scope_snapshot(scope.as_str())
        .unwrap();
    let baseline_inspections = inspect_calls.load(Ordering::SeqCst);
    observe_stage.store(1, Ordering::SeqCst);
    let submitted = serve_batch(
        &mut listener,
        &mut authority,
        &actor,
        vec![
            read_by_key("request.bootstrap.submitted", "key.bootstrap.send")
                .encode_json()
                .unwrap(),
        ],
        Some(&launch_template),
        Some(&send_template),
    );
    let submitted = &submitted[0]["ok"];
    assert_eq!(submitted["receipt"]["commandId"], command_id);
    assert_eq!(submitted["receipt"]["requestDigest"], request_digest);
    assert_eq!(submitted["state"], "uncertain");
    assert_eq!(submitted["effectState"], "claimed_uncertain");
    assert_eq!(submitted["nativeObservation"]["source"], "pod_journal");
    assert_eq!(submitted["nativeObservation"]["stage"], "submitted");
    assert_eq!(
        submitted["nativeObservation"]["requestDigest"],
        request_digest
    );
    assert_eq!(
        submitted["nativeObservation"]["nativeThreadId"],
        "thread.native.one"
    );
    assert_eq!(
        submitted["nativeObservation"]["nativeSessionId"],
        "session.native.one"
    );
    assert_eq!(
        submitted["nativeObservation"]["nativeTurnId"],
        "turn.native.one"
    );
    assert_eq!(
        inspect_calls.load(Ordering::SeqCst),
        baseline_inspections + 1
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    observe_stage.store(2, Ordering::SeqCst);
    let unobserved = serve_batch(
        &mut listener,
        &mut authority,
        &actor,
        vec![
            read_by_key("request.bootstrap.unobserved", "key.bootstrap.send")
                .encode_json()
                .unwrap(),
        ],
        Some(&launch_template),
        Some(&send_template),
    );
    assert_eq!(unobserved[0]["ok"]["state"], "uncertain");
    assert_eq!(unobserved[0]["ok"]["effectState"], "claimed_uncertain");
    assert_eq!(
        unobserved[0]["ok"]["nativeObservation"]["stage"],
        "claimed_unobserved"
    );
    assert!(
        unobserved[0]["ok"]["nativeObservation"]
            .get("nativeTurnId")
            .is_none()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    for (mode, request_id) in [
        (3, "request.bootstrap.wrong.digest"),
        (4, "request.bootstrap.wrong.target"),
    ] {
        observe_stage.store(mode, Ordering::SeqCst);
        let refused = serve_batch(
            &mut listener,
            &mut authority,
            &actor,
            vec![
                read_by_key(request_id, "key.bootstrap.send")
                    .encode_json()
                    .unwrap(),
            ],
            Some(&launch_template),
            Some(&send_template),
        );
        assert_eq!(refused[0]["ok"]["state"], "uncertain");
        assert!(refused[0]["ok"].get("nativeObservation").is_none());
    }

    let wrong_process = AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(
        1000,
        99_991,
        123_456,
        "/user.slice/foreign.scope",
    )
    .unwrap();
    let wrong_actor = ReplayTransport(AuthenticatedPeer::owner_cli_from_authenticated_transport(
        wrong_process,
        CredentialGeneration::new(1).unwrap(),
    ));
    let before_wrong_actor = inspect_calls.load(Ordering::SeqCst);
    assert!(matches!(
        authority.lookup_command_with_native_observation(
            &wrong_actor,
            &scope,
            &CommandLookupSelector::Id {
                command_id: command_id.clone()
            },
        ),
        Err(DurableAuthorityError::Host(HostError::Unauthenticated))
    ));
    assert_eq!(inspect_calls.load(Ordering::SeqCst), before_wrong_actor);

    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let snapshot = store.authority_snapshot().unwrap();
    let manager = store
        .current_manager_credential_claim(snapshot.owner_epoch)
        .unwrap();
    store
        .acquire_native_writer_lease_from_trusted_host(&TrustedNativeWriterLeaseRequest {
            target,
            holder_actor_id: actor.clone(),
            holder_credential_generation: 1,
            expected_owner_epoch: snapshot.owner_epoch,
            expected_manager_credential_epoch: manager.credential_epoch(),
            expected_authority_revision: snapshot.revision,
            expected_writer_epoch: Some(lease.writer_epoch()),
            ttl_seconds: 120,
        })
        .unwrap();
    drop(store);
    let before_stale = inspect_calls.load(Ordering::SeqCst);
    observe_stage.store(1, Ordering::SeqCst);
    let stale = serve_batch(
        &mut listener,
        &mut authority,
        &actor,
        vec![
            read_by_key("request.bootstrap.stale.writer", "key.bootstrap.send")
                .encode_json()
                .unwrap(),
        ],
        Some(&launch_template),
        Some(&send_template),
    );
    assert_eq!(stale[0]["ok"]["receipt"]["commandId"], command_id);
    assert_eq!(stale[0]["ok"]["state"], "uncertain");
    assert!(stale[0]["ok"].get("nativeObservation").is_none());
    assert_eq!(inspect_calls.load(Ordering::SeqCst), before_stale);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        PodBayStore::open(&fixture.database)
            .unwrap()
            .scope_snapshot(scope.as_str())
            .unwrap(),
        before
    );
    listener.shutdown().unwrap();
}

struct ReadySend {
    authority: DurableAuthority<FakePort>,
    listener: LinuxManagerCommandsGetListener,
    actor: ActorId,
    calls: Arc<AtomicUsize>,
    launch_template: TrustedWireRootLaunchTemplate,
    send_template: TrustedBootstrapSendTemplate,
    session_id: String,
    guard: Guard,
}

impl ReadySend {
    fn new(fixture: &Fixture, mode: PortMode) -> Self {
        let (mut authority, actor, grant, calls, _) = prepared_authority(fixture, mode);
        let mut listener = LinuxManagerCommandsGetListener::bind(&fixture.root).unwrap();
        let launch_template = TrustedWireRootLaunchTemplate::from_trusted_policy(
            grant,
            Duration::from_secs(30),
            "result.none",
        )
        .unwrap();
        let send_template =
            TrustedBootstrapSendTemplate::from_trusted_policy(grant, Duration::from_secs(30))
                .unwrap()
                .with_initial_writer_lease_seconds(120)
                .unwrap();
        let launch = serve_batch(
            &mut listener,
            &mut authority,
            &actor,
            vec![
                launch_request(
                    "request.ready.launch",
                    "key.ready.launch",
                    grant,
                    "gpt-6-sol",
                )
                .encode_json()
                .unwrap(),
            ],
            Some(&launch_template),
            Some(&send_template),
        );
        assert_eq!(launch[0]["ok"]["state"], "host_accepted");
        assert_eq!(
            launch[0]["ok"]["value"]["bootstrapGuard"]["available"],
            true
        );
        let session_id = launch[0]["ok"]["value"]["sessionId"]
            .as_str()
            .unwrap()
            .to_owned();
        let guard =
            serde_json::from_value(launch[0]["ok"]["value"]["bootstrapGuard"]["guard"].clone())
                .unwrap();
        Self {
            authority,
            listener,
            actor,
            calls,
            launch_template,
            send_template,
            session_id,
            guard,
        }
    }

    fn send(&self, request_id: &str) -> Vec<u8> {
        CommandEnvelope::new_json(
            request_id,
            "key.ready.send",
            WireTarget::Session {
                session_id: self.session_id.clone(),
            },
            Some(self.guard.clone()),
            None,
            MutationOperation::SessionSend,
            json!({"content":[{"kind":"text","text":"hello native"}],
                "policy":{"kind":"when_idle"}}),
        )
        .unwrap()
        .encode_json()
        .unwrap()
    }
}

#[test]
fn delayed_fake_send_outlives_old_exchange_deadline_without_duplicate_effect() {
    let fixture = Fixture::new();
    let mut ready = ReadySend::new(&fixture, PortMode::SlowSend);
    let first_request = ready.send("request.ready.send");
    let first = serve_batch(
        &mut ready.listener,
        &mut ready.authority,
        &ready.actor,
        vec![first_request],
        Some(&ready.launch_template),
        Some(&ready.send_template),
    );
    assert_eq!(first[0]["ok"]["state"], "uncertain");
    assert_eq!(
        first[0]["ok"]["value"]["portObservation"]["kind"],
        "pod_accepted"
    );
    assert_eq!(ready.calls.load(Ordering::SeqCst), 2); // one launch and one send
    let original = first[0]["ok"]["commandId"].clone();
    let retry = ready.send("request.ready.send.retry");
    let duplicate = serve_batch(
        &mut ready.listener,
        &mut ready.authority,
        &ready.actor,
        vec![retry],
        Some(&ready.launch_template),
        Some(&ready.send_template),
    );
    assert_eq!(duplicate[0]["ok"]["commandId"], original);
    assert_eq!(duplicate[0]["ok"]["value"]["duplicate"], true);
    assert_eq!(duplicate[0]["ok"]["value"]["portCalled"], false);
    assert_eq!(ready.calls.load(Ordering::SeqCst), 2);
    ready.listener.shutdown().unwrap();
}

#[test]
fn lost_fake_send_reply_stays_uncertain_and_is_not_resent() {
    let fixture = Fixture::new();
    let mut ready = ReadySend::new(&fixture, PortMode::SendLostReply);
    let first_request = ready.send("request.ready.lost");
    let first = serve_batch(
        &mut ready.listener,
        &mut ready.authority,
        &ready.actor,
        vec![first_request],
        Some(&ready.launch_template),
        Some(&ready.send_template),
    );
    assert_eq!(first[0]["ok"]["state"], "uncertain");
    assert_eq!(
        first[0]["ok"]["value"]["portObservation"]["kind"],
        "uncertain_after_possible_effect"
    );
    let original = first[0]["ok"]["commandId"].clone();
    let retry = ready.send("request.ready.lost.retry");
    let duplicate = serve_batch(
        &mut ready.listener,
        &mut ready.authority,
        &ready.actor,
        vec![retry],
        Some(&ready.launch_template),
        Some(&ready.send_template),
    );
    assert_eq!(duplicate[0]["ok"]["commandId"], original);
    assert_eq!(duplicate[0]["ok"]["value"]["portCalled"], false);
    assert_eq!(ready.calls.load(Ordering::SeqCst), 2);
    ready.listener.shutdown().unwrap();
}

#[test]
fn accepted_launch_keeps_receipt_when_guard_expires_then_duplicate_gets_one_lease() {
    let fixture = Fixture::new();
    let (mut authority, actor, grant, calls, _) =
        prepared_authority(&fixture, PortMode::SlowAccepted);
    let mut listener = LinuxManagerCommandsGetListener::bind(&fixture.root).unwrap();
    let launch_template = TrustedWireRootLaunchTemplate::from_trusted_policy(
        grant,
        Duration::from_secs(30),
        "result.none",
    )
    .unwrap();
    let send_template =
        TrustedBootstrapSendTemplate::from_trusted_policy(grant, Duration::from_secs(2))
            .unwrap()
            .with_initial_writer_lease_seconds(120)
            .unwrap();
    let first = serve_batch(
        &mut listener,
        &mut authority,
        &actor,
        vec![
            launch_request(
                "request.guard.first",
                "key.guard.launch",
                grant,
                "gpt-6-sol",
            )
            .encode_json()
            .unwrap(),
        ],
        Some(&launch_template),
        Some(&send_template),
    );
    let first = &first[0]["ok"];
    assert_eq!(first["state"], "host_accepted");
    assert_eq!(first["value"]["launchStage"], "host_accepted");
    assert_eq!(first["value"]["bootstrapGuard"]["available"], false);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let original_command = first["commandId"].clone();
    let session_id = first["value"]["sessionId"].as_str().unwrap().to_owned();

    let duplicate = serve_batch(
        &mut listener,
        &mut authority,
        &actor,
        vec![
            launch_request(
                "request.guard.retry",
                "key.guard.launch",
                grant,
                "gpt-6-sol",
            )
            .encode_json()
            .unwrap(),
        ],
        Some(&launch_template),
        Some(&send_template),
    );
    let duplicate = &duplicate[0]["ok"];
    assert_eq!(duplicate["commandId"], original_command);
    assert_eq!(duplicate["state"], "host_accepted");
    assert_eq!(duplicate["value"]["duplicate"], true);
    assert_eq!(duplicate["value"]["portCalled"], false);
    assert_eq!(duplicate["value"]["bootstrapGuard"]["available"], true);
    assert_eq!(
        duplicate["value"]["bootstrapGuard"]["guard"]["writerEpoch"],
        "1"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let scope = ScopeId::try_from("scope.server.launch").unwrap();
    let session = SessionId::try_from(session_id.as_str()).unwrap();
    let (target, _) = store
        .current_native_writer_target_for_session(&scope, &session)
        .unwrap();
    assert_eq!(
        store
            .inspect_native_writer_lease(&target)
            .unwrap()
            .writer_epoch(),
        1
    );
    assert_eq!(
        store.scope_snapshot(scope.as_str()).unwrap().receipts.len(),
        1
    );
    listener.shutdown().unwrap();
}

#[test]
fn authenticated_refusal_uncertainty_and_lost_reply_preserve_one_command() {
    let fixture = Fixture::new();
    let (mut authority, actor, grant, calls, _) = prepared_authority(&fixture, PortMode::LostReply);
    let mut listener = LinuxManagerCommandsGetListener::bind(&fixture.root).unwrap();
    let template = TrustedWireRootLaunchTemplate::from_trusted_policy(
        grant,
        Duration::from_secs(30),
        "result.none",
    )
    .unwrap();
    let mut unsupported =
        launch_request("request.unsupported", "key.unsupported", grant, "gpt-6-sol")
            .encode_json()
            .unwrap();
    let mut value: Value = serde_json::from_slice(&unsupported).unwrap();
    value["body"]["role"] = json!("worker");
    let changed = CommandEnvelope::new_json(
        "request.unsupported",
        "key.unsupported",
        WireTarget::Scope {
            scope_id: "scope.server.launch".into(),
        },
        None,
        None,
        MutationOperation::Launch,
        value["body"].clone(),
    )
    .unwrap();
    unsupported = changed.encode_json().unwrap();
    let mut wrong_grant_body: Value = serde_json::from_slice(
        &launch_request("request.wrong.grant", "key.wrong.grant", grant, "gpt-6-sol")
            .encode_json()
            .unwrap(),
    )
    .unwrap();
    wrong_grant_body["body"]["authority"]["grantRef"] = json!("grant.99999");
    let wrong_grant = CommandEnvelope::new_json(
        "request.wrong.grant",
        "key.wrong.grant",
        WireTarget::Scope {
            scope_id: "scope.server.launch".into(),
        },
        None,
        None,
        MutationOperation::Launch,
        wrong_grant_body["body"].clone(),
    )
    .unwrap();
    let first = launch_request("request.uncertain", "key.uncertain", grant, "gpt-6-sol");
    let responses = serve_batch(
        &mut listener,
        &mut authority,
        &actor,
        vec![
            unsupported,
            wrong_grant.encode_json().unwrap(),
            first.encode_json().unwrap(),
            launch_request(
                "request.uncertain.retry",
                "key.uncertain",
                grant,
                "gpt-6-sol",
            )
            .encode_json()
            .unwrap(),
        ],
        Some(&template),
        None,
    );
    assert_eq!(responses[0]["error"]["code"], "unsupported");
    assert_eq!(responses[1]["error"]["code"], "forbidden");
    let uncertain = &responses[2]["ok"];
    assert_eq!(uncertain["state"], "uncertain");
    assert_eq!(uncertain["value"]["duplicate"], false);
    assert_eq!(
        uncertain["value"]["launchStage"],
        "uncertain_after_possible_effect"
    );
    assert_eq!(responses[3]["ok"]["commandId"], uncertain["commandId"]);
    assert_eq!(responses[3]["ok"]["revision"], uncertain["revision"]);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    listener.shutdown().unwrap();

    // A disconnected reply does not cause a second host effect. The server
    // retains the original key and CommandId in ResponseLost for reconciliation.
    let fixture = Fixture::new();
    let (mut authority, actor, grant, calls, _) = prepared_authority(&fixture, PortMode::Accepted);
    let path = fixture.root.join("lost.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let policy = TrustedWireRootLaunchPolicy::from_trusted_policy(
        grant,
        Instant::now() + Duration::from_secs(30),
        "result.none",
    )
    .unwrap();
    let actor_name = actor.as_str().to_owned();
    let client = thread::spawn(move || {
        let socket = UnixStream::connect(path).unwrap();
        let mut authenticated = authenticate(socket.try_clone().unwrap(), &actor_name);
        let request = launch_request("request.lost", "key.lost", grant, "gpt-6-sol")
            .encode_json()
            .unwrap();
        authenticated
            .write_all(&(request.len() as u32).to_be_bytes())
            .unwrap();
        socket.shutdown(Shutdown::Read).unwrap();
        authenticated.write_all(&request).unwrap();
    });
    let (server, _) = listener.accept().unwrap();
    let result = serve_authenticated_linux_launch_one(server, &mut authority, &policy);
    client.join().unwrap();
    assert!(matches!(
        result,
        Err(LinuxServeOneFault::Exchange(ServerFault::ResponseLost {
            key: Some(ref key),
            command_id: Some(_),
            ..
        })) if key == "key.lost"
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let snapshot = PodBayStore::open(&fixture.database)
        .unwrap()
        .scope_snapshot("scope.server.launch")
        .unwrap();
    assert_eq!(snapshot.receipts.len(), 1);
}

#[test]
fn external_authority_revision_drift_refuses_before_port_effect() {
    let fixture = Fixture::new();
    let (mut authority, actor, grant, calls, _) = prepared_authority(&fixture, PortMode::Accepted);
    let path = fixture.root.join("drift.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let policy = TrustedWireRootLaunchPolicy::from_trusted_policy(
        grant,
        Instant::now() + Duration::from_secs(30),
        "result.none",
    )
    .unwrap();
    let actor_name = actor.as_str().to_owned();
    let database = fixture.database.clone();
    let client = thread::spawn(move || {
        let socket = UnixStream::connect(path).unwrap();
        let authenticated = authenticate(socket, &actor_name);
        // This revocation happens after the actor's signature is accepted but
        // before durable admission. Actor/key stay exact; the manager must
        // reject its stale grant snapshot before any port effect.
        let mut store = PodBayStore::open(database).unwrap();
        let snapshot = store.authority_snapshot().unwrap();
        store
            .apply_authority_mutation(
                snapshot.owner_epoch,
                snapshot.revision,
                AuthorityMutation::RevokeGrant(grant.get()),
            )
            .unwrap();
        exchange(
            authenticated,
            &launch_request("request.drift", "key.drift", grant, "gpt-6-sol")
                .encode_json()
                .unwrap(),
        )
    });
    let (server, _) = listener.accept().unwrap();
    serve_authenticated_linux_launch_one(server, &mut authority, &policy).unwrap();
    let response = client.join().unwrap();
    assert_eq!(response["error"]["code"], "stale_guard");
    assert_eq!(response["requestId"], "request.drift");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(
        PodBayStore::open(&fixture.database)
            .unwrap()
            .scope_snapshot("scope.server.launch")
            .unwrap()
            .receipts
            .is_empty()
    );
}
