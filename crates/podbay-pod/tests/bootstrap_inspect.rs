#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use podbay_core::{
    ActorId, Attempt, AttemptId, CommandId, Epoch, LaunchBinding, Pod, PodId, Resource, ResourceId,
    ResourceKind, Role, Run, RunId, ScopeId, Session, SessionId, WorkKind,
};
use podbay_pod::{
    BootstrapControlStage, BootstrapSettlementStage, CodexCommandJournal, CodexJournalIdentity,
    CodexJournalStage, LinuxBackend, LinuxPeerEvidence, NativeEventKind, NativeEventStatus,
    PodError, PodPeerBootstrap, codex_private_slot_directory,
    launch_bound_codex_v2,
};
use podbay_store::{
    Admission, AuthorityActorRecord, AuthorityMutation, BootstrapSendSelector,
    BoundLaunchAdmission, BoundRootLaunchProposalV2, BoundRootLaunchRequestV2, EffectClaim,
    LaunchPortResult, PodBayStore, TrustedBootstrapSendRequest, TrustedNativeWriterLeaseRequest,
    VerifiedPrincipal,
};
use podbay_wire::{
    CodexAppServerPolicyV2, CommandBody, CommandEnvelope, ContentBlock, DecimalString,
    EffectiveLaunchContract, EffectiveLaunchContractV2, Guard, ImmutableLaunchDescriptorV2,
    ResourceDriver, ReviewedNativePolicy, ReviewedResource, SendPolicy, SessionSendBody,
    Target as WireTarget, TargetOs,
};
use sha2::{Digest, Sha256};

const ARGUMENTS: [&str; 3] = ["app-server", "--listen", "stdio://"];

#[test]
fn native_events_same_uid_sibling_is_refused() {
    let Some(path) = std::env::var_os("PODBAY_NATIVE_SIBLING_MANIFEST") else {
        return;
    };
    let manifest: podbay_pod::PodManifest = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let binding = manifest.peer_binding.as_ref().unwrap();
    let launch = &manifest.descriptor;
    let identity = serde_json::json!({
        "store_lineage": binding.store_lineage,
        "scope_id": launch.scope_id,
        "session_id": launch.session_id,
        "run_id": launch.run_id,
        "attempt_id": launch.attempt_id,
        "pod_id": launch.pod_id,
        "pod_incarnation": launch.incarnation,
        "resource_id": launch.resource_id,
        "resource_epoch": binding.resource_epoch,
    });
    let request = serde_json::json!({
        "protocol": "podbay.codex-events.read/1",
        "operation": "codex.events.read",
        "token": manifest.token,
        "identity": identity,
        "cursor": null,
        "limit": 16,
    });
    let mut socket = UnixStream::connect(manifest.socket_path).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    socket.write_all(&serde_json::to_vec(&request).unwrap()).unwrap();
    socket.shutdown(std::net::Shutdown::Write).unwrap();
    let mut reply = Vec::new();
    socket.read_to_end(&mut reply).unwrap();
    let reply: serde_json::Value = serde_json::from_slice(&reply).unwrap();
    assert_eq!(reply["refused"], true);
    assert!(reply["read"].is_null());
}

struct Fixture {
    root: PathBuf,
    database: PathBuf,
    workspace: PathBuf,
    executable: PathBuf,
    credential: PathBuf,
    pod_id: PodId,
    attempt_id: AttemptId,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "podbay-bootstrap-inspect-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let workspace = root.join("workspace");
        fs::create_dir(&workspace).unwrap();
        let executable = root.join("fake-app-server");
        fs::write(&executable, br##"#!/bin/sh
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
printf '{"id":2,"result":{"thread":{"id":"thread.fixture","sessionId":"native.session.fixture","cwd":"%s","status":{"type":"idle"},"turns":[]},"model":"codex.fixture","reasoningEffort":"medium","approvalPolicy":"never","sandbox":{"type":"dangerFullAccess"},"cwd":"%s"}}\n' "$(pwd)" "$(pwd)"
read -r inspect
printf '%s\n' "$inspect" >> "$CODEX_HOME/frames.log"
printf '{"id":3,"result":{"thread":{"id":"thread.fixture","sessionId":"native.session.fixture","cwd":"%s","status":{"type":"idle"},"turns":[]}}}\n' "$(pwd)"
read -r turn
printf '%s\n' "$turn" >> "$CODEX_HOME/frames.log"
printf '{"id":4,"result":{"turn":{"id":"turn.fixture","status":"inProgress"}}}\n'
printf '{"method":"item/agentMessage/delta","params":{"threadId":"thread.fixture","delta":"private fixture output"}}\n'
sleep 2
printf '{"method":"turn/completed","params":{"threadId":"thread.fixture","turn":{"id":"turn.fixture","status":"completed"}}}\n'
printf '{"method":"thread/status/changed","params":{"threadId":"thread.fixture","status":{"type":"idle"}}}\n'
read -r final_read
printf '%s\n' "$final_read" >> "$CODEX_HOME/frames.log"
sleep 2
printf '{"id":5,"result":{"thread":{"id":"thread.fixture","sessionId":"native.session.fixture","cwd":"%s","status":{"type":"idle"},"turns":[]}}}\n' "$(pwd)"
sleep 30
"##).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let credential = root.join("dummy-auth.json");
        fs::write(&credential, b"disposable credential fixture only\n").unwrap();
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).unwrap();
        let suffix = format!("{:x}", nonce & 0xffff_ffff_ffff);
        Self {
            database: root.join("store.sqlite"),
            workspace,
            executable,
            credential,
            pod_id: PodId::try_from(format!("pod.inspect.{suffix}")).unwrap(),
            attempt_id: AttemptId::try_from(format!("attempt.inspect.{suffix}")).unwrap(),
            root,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Ok(entries) = fs::read_dir(&self.root) {
            for path in entries.flatten().map(|entry| entry.path()) {
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
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn text(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn list(bytes: &mut Vec<u8>, values: &[&str]) {
    bytes.extend_from_slice(&(values.len() as u32).to_be_bytes());
    for value in values {
        text(bytes, value)
    }
}

fn sha256_file(path: &Path) -> String {
    Sha256::digest(fs::read(path).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn effective_bytes(fixture: &Fixture, generation: &str) -> Vec<u8> {
    let mut bytes = b"podbay.effective-launch/1\0".to_vec();
    text(&mut bytes, fixture.pod_id.as_str());
    text(&mut bytes, "worker");
    bytes.push(0);
    text(&mut bytes, "podbay.codex.fixture");
    bytes.extend_from_slice(&1_u64.to_be_bytes());
    text(&mut bytes, fixture.executable.to_str().unwrap());
    text(&mut bytes, generation);
    list(&mut bytes, &ARGUMENTS);
    text(&mut bytes, "codex.fixture");
    text(&mut bytes, "medium");
    bytes.push(0);
    text(&mut bytes, "scope.fixture");
    text(&mut bytes, "basis.fixture");
    text(&mut bytes, ".");
    bytes.push(1);
    list(&mut bytes, &[]);
    bytes.extend_from_slice(&1_u64.to_be_bytes());
    bytes.extend_from_slice(&60_u64.to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    list(&mut bytes, &[]);
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    text(&mut bytes, "scope.fixture");
    text(&mut bytes, "auth.json");
    EffectiveLaunchContract::decode(&bytes).unwrap();
    bytes
}

fn actor() -> AuthorityActorRecord {
    AuthorityActorRecord {
        scope_id: "scope.fixture".into(),
        actor_id: "actor.fixture".into(),
        role: "worker".into(),
        origin: "owner_cli".into(),
        parent_actor_id: None,
        pod_id: None,
        pod_incarnation: None,
        credential_generation: 1,
        platform: "linux".into(),
        os_identity: "linux.uid.1000".into(),
        process_identity: "linux.pid.123".into(),
        start_identity: 456,
        containment_identity: "/user.slice/fixture.scope".into(),
    }
}

#[test]
#[ignore = "requires disposable user systemd and PODBAY_TEST_POD_BINARY"]
fn inspect_claimed_bootstrap_is_read_only_and_recovers_submitted_reply() {
    let binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let fixture = Fixture::new();
    let sha = sha256_file(&fixture.executable);
    let generation = format!("sha256:{sha}");
    let scope = ScopeId::try_from("scope.fixture").unwrap();
    let actor_id = ActorId::try_from("actor.fixture").unwrap();
    let session_id = SessionId::try_from("session.fixture").unwrap();
    let run_id = RunId::try_from("run.fixture").unwrap();
    let resource_id = ResourceId::try_from("resource.fixture").unwrap();
    let mut session = Session::new(session_id.clone(), actor_id.clone(), scope.clone());
    let run = Run::new(run_id.clone(), &session, Role::Worker, WorkKind::Task, None);
    session.bind_run(session.revision(), &run).unwrap();
    let mut attempt = Attempt::new(
        fixture.attempt_id.clone(),
        run_id.clone(),
        1,
        Epoch::new(1).unwrap(),
    )
    .unwrap();
    let mut pod = Pod::new(
        fixture.pod_id.clone(),
        attempt.id().clone(),
        Epoch::new(1).unwrap(),
    );
    attempt.attach_pod(attempt.revision(), &pod).unwrap();
    let resource = Resource::new(
        resource_id.clone(),
        pod.id().clone(),
        ResourceKind::StructuredProvider,
        Epoch::new(1).unwrap(),
    );
    pod.attach_resource(pod.revision(), &resource).unwrap();
    let planned =
        LaunchBinding::plan_first_root(&session, &run, &attempt, &pod, &[resource]).unwrap();
    let policy = CodexAppServerPolicyV2::new(
        &scope,
        "auth.json".into(),
        "codex.app-server".into(),
        "codex.app-server/1".into(),
    )
    .unwrap();
    let base = EffectiveLaunchContract::decode(&effective_bytes(&fixture, &generation)).unwrap();
    let effective = EffectiveLaunchContractV2::from_v1(base, policy.clone()).unwrap();
    let descriptor = ImmutableLaunchDescriptorV2::from_planned_root(
        &planned,
        ReviewedNativePolicy {
            target_os: TargetOs::Linux,
            host_id: "host.fixture".into(),
            profile_ref: "podbay.codex.fixture".into(),
            profile_generation: 1,
            model_id: "codex.fixture".into(),
            reasoning_effort: "medium".into(),
            executable_generation: generation,
            effective_spec_digest: effective.digest().into(),
            workspace_basis_ref: "basis.fixture".into(),
            executable: fixture.executable.to_str().unwrap().into(),
            cwd: fixture.workspace.to_str().unwrap().into(),
            arguments: ARGUMENTS.into_iter().map(str::to_owned).collect(),
            environment_refs: vec![],
            credential_refs: vec!["auth.json".into()],
            wall_seconds: 60,
            max_children: 0,
            resources: vec![ReviewedResource {
                resource_id: resource_id.clone(),
                kind: ResourceKind::StructuredProvider,
                epoch: Epoch::new(1).unwrap(),
                driver: ResourceDriver::Structured {
                    driver_ref: "codex.app-server".into(),
                    protocol_ref: "codex.app-server/1".into(),
                },
            }],
        },
        policy,
    )
    .unwrap();
    effective.compare_with_descriptor(&descriptor).unwrap();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let replay = store.begin_authority_replay(0, 1).unwrap();
    let revision = store
        .apply_authority_mutation(1, replay.revision, AuthorityMutation::PutActor(actor()))
        .unwrap();
    let manager = LinuxPeerEvidence::for_current_process().unwrap();
    let claim = store.current_manager_credential_claim(1).unwrap();
    store
        .register_current_manager_peer(&claim, manager.attested_peer())
        .unwrap();
    let record = match store
        .admit_bound_root_launch_v2(BoundRootLaunchRequestV2 {
            principal: VerifiedPrincipal::from_authenticated_boundary("actor.fixture").unwrap(),
            command_key: "launch.inspect",
            canonical_intent: b"inspect launch",
            scope_id: scope.as_str(),
            pod_id: fixture.pod_id.as_str(),
            proposal: Some(BoundRootLaunchProposalV2 {
                session: &session,
                run: &run,
                binding: &planned,
                effective_spec: &effective,
                descriptor: &descriptor,
                expected_owner_epoch: 1,
                expected_authority_revision: revision,
            }),
        })
        .unwrap()
    {
        BoundLaunchAdmission::Committed(record) => record,
        other => panic!("expected V2 commit: {other:?}"),
    };
    let current = store
        .current_bound_pod_snapshot(scope.as_str(), fixture.pod_id.as_str())
        .unwrap();
    let authority_revision = current.authority_revision();
    let lineage = current.store_lineage().as_str().to_owned();
    assert_eq!(
        store
            .claim_effect(
                record.receipt.outbox_id,
                scope.as_str(),
                fixture.pod_id.as_str(),
                1,
                1,
                authority_revision,
                &format!("claim.{}", record.receipt.command_id)
            )
            .unwrap(),
        EffectClaim::NewClaim
    );
    let database_metadata = fs::symlink_metadata(&fixture.database).unwrap();
    let credential_metadata = fs::symlink_metadata(&fixture.credential).unwrap();
    let client = launch_bound_codex_v2(
        record.clone(),
        PodPeerBootstrap {
            store_path: fixture.database.clone(),
            store_lineage: lineage,
            owner_epoch: 1,
            credential_epoch: claim.credential_epoch(),
            resource_input_epochs: BTreeMap::from([(resource_id.as_str().into(), 1)]),
            canonical_executable: fixture.executable.clone(),
            executable_sha256: sha,
            expected_manager_peer: manager.attested_peer().clone(),
        },
        authority_revision,
        (database_metadata.dev(), database_metadata.ino()),
        &fixture.root,
        &binary,
        &fixture.credential,
        (credential_metadata.dev(), credential_metadata.ino()),
    )
    .unwrap();
    let stem = client.manifest_path().unwrap().file_stem().and_then(|value| value.to_str()).unwrap();
    let private_slot = codex_private_slot_directory(
        &fixture.root, &format!("podbay-pod-{stem}.service"), false,
    ).unwrap();
    store
        .record_launch_port_result(
            record.receipt.outbox_id,
            scope.as_str(),
            fixture.pod_id.as_str(),
            1,
            &format!("claim.{}", record.receipt.command_id),
            LaunchPortResult::HostAccepted {
                receipt_ref: Some("receipt.inspect.launch".into()),
            },
        )
        .unwrap();
    let (target, session_revision) = store
        .current_native_writer_target_for_session(&scope, &session_id)
        .unwrap();
    let lease = store
        .acquire_native_writer_lease_from_trusted_host(&TrustedNativeWriterLeaseRequest {
            target: target.clone(),
            holder_actor_id: actor_id.clone(),
            holder_credential_generation: 1,
            expected_owner_epoch: 1,
            expected_manager_credential_epoch: claim.credential_epoch(),
            expected_authority_revision: authority_revision,
            expected_writer_epoch: None,
            ttl_seconds: 60,
        })
        .unwrap();
    let envelope = CommandEnvelope::new(
        "request.inspect.bootstrap",
        "key.inspect.bootstrap",
        WireTarget::Session {
            session_id: session_id.as_str().into(),
        },
        Some(Guard {
            manager_epoch: Some(DecimalString::new(1)),
            pod_epoch: Some(DecimalString::new(1)),
            resource_epoch: Some(DecimalString::new(1)),
            writer_epoch: Some(DecimalString::new(lease.writer_epoch())),
            lease_epoch: None,
            target_revision: Some(DecimalString::new(session_revision)),
        }),
        None,
        CommandBody::SessionSend(SessionSendBody {
            content: vec![ContentBlock::Text {
                text: "fixture prompt".into(),
            }],
            policy: SendPolicy::WhenIdle,
        }),
    )
    .unwrap();
    let admitted = match store
        .admit_bootstrap_send(&TrustedBootstrapSendRequest {
            principal: VerifiedPrincipal::from_authenticated_boundary("actor.fixture").unwrap(),
            scope_id: scope.clone(),
            envelope: &envelope,
            native_target: target.clone(),
            holder_actor_id: actor_id,
            holder_credential_generation: 1,
            expected_owner_epoch: 1,
            expected_manager_credential_epoch: claim.credential_epoch(),
            expected_authority_revision: authority_revision,
        })
        .unwrap()
    {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected bootstrap commit: {other:?}"),
    };
    let selector = BootstrapSendSelector {
        scope_id: scope.clone(),
        command_id: CommandId::try_from(admitted.command_id.as_str()).unwrap(),
        native_target: target.clone(),
    };
    assert_eq!(
        store.claim_bootstrap_send(&selector).unwrap(),
        EffectClaim::NewClaim
    );
    let initial_events = client.read_codex_native_events(None, 16).unwrap();
    assert_eq!(initial_events.snapshot.watermark, 0);
    assert!(initial_events.events.is_empty());
    let sibling = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "native_events_same_uid_sibling_is_refused"])
        .env("PODBAY_NATIVE_SIBLING_MANIFEST", client.manifest_path().unwrap())
        .stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
    assert!(sibling.success(), "same-UID sibling obtained native event read");
    let frames = private_slot.join("home/codex/frames.log");
    assert!(matches!(
        client
            .inspect_claimed_codex_bootstrap(&selector.command_id, &target, lease.writer_epoch())
            .unwrap()
            .stage,
        BootstrapControlStage::ClaimedUnobserved,
    ));
    assert_eq!(fs::read_to_string(&frames).unwrap().lines().count(), 2);
    // The first IPC reply is deliberately discarded as if the manager lost it.
    let _ = client
        .submit_claimed_codex_bootstrap(&selector.command_id, &target, lease.writer_epoch())
        .unwrap();
    let control_start = Instant::now();
    assert!(client.attested_status().unwrap().child_running);
    assert!(
        control_start.elapsed() < Duration::from_secs(1),
        "native wait blocked pod control"
    );
    let recovered = client
        .inspect_claimed_codex_bootstrap(&selector.command_id, &target, lease.writer_epoch())
        .unwrap();
    assert_eq!(
        recovered.request_digest.as_deref(),
        Some(admitted.request_digest.as_str())
    );
    assert!(matches!(recovered.stage,
        BootstrapControlStage::Submitted { ref native_thread_id, ref native_session_id, ref native_turn_id }
            if native_thread_id == "thread.fixture"
                && native_session_id == "native.session.fixture"
                && native_turn_id == "turn.fixture"));
    assert_eq!(fs::read_to_string(&frames).unwrap().lines().count(), 5);
    let deadline = Instant::now() + Duration::from_secs(5);
    let observed = loop {
        let observed = client
            .inspect_claimed_codex_bootstrap(&selector.command_id, &target, lease.writer_epoch())
            .unwrap();
        if observed.settlement == Some(BootstrapSettlementStage::CompletionObservedPendingIdleProof)
        {
            break observed;
        }
        assert!(
            Instant::now() < deadline,
            "matching completion notification was not journaled"
        );
        std::thread::sleep(Duration::from_millis(25));
    };
    assert!(matches!(
        observed.stage,
        BootstrapControlStage::Submitted { .. }
    ));
    // The child has accepted the read-only RPC but withholds its reply for two
    // seconds. Pod control remains responsive and completion stays pending.
    let read_deadline = Instant::now() + Duration::from_secs(3);
    while fs::read_to_string(&frames).unwrap().lines().count() != 6 {
        assert!(Instant::now() < read_deadline, "asynchronous thread/read was not sent");
        std::thread::sleep(Duration::from_millis(10));
    }
    let control_start = Instant::now();
    assert!(client.attested_status().unwrap().child_running);
    assert!(control_start.elapsed() < Duration::from_secs(1), "thread/read blocked pod control");
    assert_eq!(
        client
            .inspect_claimed_codex_bootstrap(&selector.command_id, &target, lease.writer_epoch())
            .unwrap()
            .settlement,
        Some(BootstrapSettlementStage::CompletionObservedPendingIdleProof)
    );
    let completion_deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let observed = client
            .inspect_claimed_codex_bootstrap(&selector.command_id, &target, lease.writer_epoch())
            .unwrap();
        if observed.settlement == Some(BootstrapSettlementStage::Completed) {
            assert!(matches!(observed.stage, BootstrapControlStage::Submitted { .. }));
            break;
        }
        assert!(Instant::now() < completion_deadline, "fresh idle thread/read was not journaled");
        std::thread::sleep(Duration::from_millis(25));
    }
    let journal_identity = CodexJournalIdentity::from_resource(
        &target.store_lineage, &target.scope_id, &target.session_id, &target.run_id,
        &target.attempt_id, &target.pod_id, Epoch::new(target.pod_incarnation).unwrap(),
        &target.resource_id, Epoch::new(target.resource_epoch).unwrap(),
    );
    let reopened = CodexCommandJournal::open(
        &LinuxBackend, &private_slot.join("codex.commands.log"), journal_identity,
    ).unwrap();
    assert_eq!(reopened.view().stage, CodexJournalStage::BootstrapCompleted);
    let native = client.read_codex_native_events(Some(&initial_events.next_cursor), 64).unwrap();
    assert!(native.snapshot.watermark >= 3);
    assert!(native.gap.is_none());
    assert!(native.events.iter().any(|event| event.kind == NativeEventKind::Output));
    assert!(native.events.iter().any(|event| event.status == Some(NativeEventStatus::Completed)));
    assert!(native.events.iter().any(|event| event.status == Some(NativeEventStatus::Idle)));
    assert_eq!(native.next_cursor.sequence, native.snapshot.watermark);
    let public = serde_json::to_string(&native).unwrap();
    assert!(!public.contains("private fixture output"));
    assert!(!public.contains("fixture prompt"));
    assert!(String::from_utf8_lossy(&fs::read(private_slot.join("codex.native-events.log")).unwrap())
        .contains("private fixture output"));
    let methods: Vec<_> = fs::read_to_string(&frames).unwrap().lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["method"]
            .as_str().unwrap().to_owned())
        .collect();
    assert_eq!(methods, ["initialize", "initialized", "thread/start", "thread/read", "turn/start", "thread/read"]);
    let changed = store
        .acquire_native_writer_lease_from_trusted_host(&TrustedNativeWriterLeaseRequest {
            target: target.clone(),
            holder_actor_id: ActorId::try_from("actor.fixture").unwrap(),
            holder_credential_generation: 1,
            expected_owner_epoch: 1,
            expected_manager_credential_epoch: claim.credential_epoch(),
            expected_authority_revision: authority_revision,
            expected_writer_epoch: Some(1),
            ttl_seconds: 60,
        })
        .unwrap();
    assert_eq!(changed.writer_epoch(), 2);
    assert!(matches!(
        client.inspect_claimed_codex_bootstrap(&selector.command_id, &target, lease.writer_epoch()),
        Err(PodError::Refused(_)),
    ));
    assert_eq!(fs::read_to_string(&frames).unwrap().lines().count(), 6);
    assert!(!client.stop().unwrap().child_running);
}
