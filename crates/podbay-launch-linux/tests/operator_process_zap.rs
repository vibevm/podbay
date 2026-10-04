#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use podbay_core::{
    ActorId, Attempt, AttemptId, CommandAdmission, CommandId, Epoch, LaunchBinding, Pod, PodId,
    Resource, ResourceId, ResourceKind, Role, Run, RunCommandKind, RunId, ScopeId, Session,
    SessionId, WorkKind,
};
use podbay_host::{
    ActorRegistration, AuthenticatedPeer, AuthenticatedProcessSubject, AuthenticatedTransport,
    BoundHostLaunchProposal, BoundLaunchPodRequest, CredentialGeneration, DurableAuthority,
    ExecutionMode, GrantMode, GrantSpec, GuardSet, HostAction, HostError, HostRequest,
    LaunchSelection, ManagerEpoch, Operation, PodIncarnation, RegisteredLaunchProfile, Right,
    Target, TrustedDriverTemplate, TrustedLaunchProfileInput, TrustedNativeHostConfig,
    WorkspaceAccess, WorkspaceSelection,
};
use podbay_launch_linux::{
    LinuxLaunchPort, TrustedLinuxLaunchConfig, TrustedOperatorProcessProfile,
};
use podbay_pod::{
    OPERATOR_PROCESS_CAPABILITY, OPERATOR_PROCESS_PROFILE_REF, PodClient, PodManifest,
    manifest_path_for_identity,
};
use podbay_store::{CommandLookupSelector, LaunchDispatchStage};
use podbay_wire::ResourceDriver;
use sha2::{Digest, Sha256};

struct Fixture {
    root: PathBuf,
    pod_directory: PathBuf,
    database: PathBuf,
    state: PathBuf,
    unit: Option<String>,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("podbay-zap-process-{}-{nonce}", std::process::id()));
        let pod_directory = root.join("pods");
        let state = root.join("zap-state");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&pod_directory).unwrap();
        fs::create_dir(&state).unwrap();
        for path in [&root, &pod_directory, &state] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self {
            database: root.join("store.sqlite"),
            root,
            pod_directory,
            state,
            unit: None,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(unit) = &self.unit {
            let _ = Command::new("systemctl")
                .args(["--user", "stop", unit])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Clone)]
struct Transport(AuthenticatedPeer);

impl AuthenticatedTransport for Transport {
    fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError> {
        Ok(self.0.clone())
    }
}

// The V1 aggregate fixture predates transaction-local Run admission. The
// actual pod.offer/outbox is still committed by DurableAuthority before the
// Linux port can receive its private ResolvedNativeLaunch capability.
struct FixtureAdmission(CommandId, RunId);
impl CommandAdmission for FixtureAdmission {
    fn admits_run(&self, command: &CommandId, run: &RunId, kind: RunCommandKind) -> bool {
        command == &self.0 && run == &self.1 && kind == RunCommandKind::Launch
    }
}

fn sha256_file(path: &Path) -> String {
    let mut file = fs::File::open(path).unwrap();
    let mut hash = Sha256::new();
    let mut chunk = [0u8; 8192];
    loop {
        let count = file.read(&mut chunk).unwrap();
        if count == 0 {
            break;
        }
        hash.update(&chunk[..count]);
    }
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn node_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("PODBAY_TEST_NODE_BINARY") {
        return fs::canonicalize(path).unwrap();
    }
    let output = Command::new("node")
        .args(["-p", "process.execPath"])
        .output()
        .unwrap();
    assert!(output.status.success());
    fs::canonicalize(String::from_utf8(output.stdout).unwrap().trim()).unwrap()
}

fn wait_for_receipt(path: &Path, client: &PodClient) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let bytes = fs::read_to_string(path).unwrap_or_default();
        if let Some(line) = bytes.lines().next() {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
                if value["protocol"] == "zap-server/1" {
                    return value;
                }
            }
        }
        assert!(
            client.attested_status().unwrap().child_running,
            "Zap exited before its headless receipt; private stderr: {}",
            fs::read_to_string(path.with_extension("process-error")).unwrap_or_default()
        );
        assert!(
            Instant::now() < deadline,
            "Zap headless receipt did not arrive"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn assert_authenticated_empty_setup(node: &Path, zap_root: &Path, url: &str) {
    const SCRIPT: &str = r#"
import { createWorkspaceHttpConnection } from './src/cells/workspace-client/index.ts';
const attach = new URL(process.argv[1]);
const gateway = attach.searchParams.get('workspace-gateway');
const pairing = new URLSearchParams(attach.hash.slice(1)).get('workspace-pair');
if (!gateway || !pairing) process.exit(2);
const connection = createWorkspaceHttpConnection({
  baseUrl: gateway, origin: attach.origin, pairingToken: pairing,
});
if (!connection) process.exit(3);
const setup = await connection.product.request({ operation: 'product.setup.get.v1' });
if (!setup.ok || setup.value.operation !== 'product.setup.get.v1'
    || setup.value.snapshot.projects.length !== 0) process.exit(4);
"#;
    let output = Command::new(node)
        .args([
            "--experimental-strip-types",
            "--input-type=module",
            "-e",
            SCRIPT,
            url,
        ])
        .current_dir(zap_root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "authenticated setup request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn operator_profile_refuses_private_data_directory_drift_before_effect() {
    let fixture = Fixture::new();
    let binary = fs::canonicalize("/bin/true").unwrap();
    let digest = sha256_file(&binary);
    let profile = TrustedOperatorProcessProfile::from_trusted_policy(
        1,
        binary.clone(),
        digest.clone(),
        fixture.root.clone(),
        vec!["--fixed".into()],
        fixture.state.clone(),
        60,
    )
    .unwrap();
    let config = TrustedLinuxLaunchConfig::from_trusted_policy(
        binary,
        digest,
        fixture.pod_directory.clone(),
    )
    .unwrap();
    fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o755)).unwrap();
    let mut port = LinuxLaunchPort::new(config);
    assert!(
        port.register_operator_process_from_trusted_policy(profile)
            .is_err()
    );
    assert!(
        fs::read_dir(&fixture.pod_directory)
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
#[ignore = "requires disposable user systemd, PODBAY_TEST_POD_BINARY and PODBAY_TEST_ZAP_ROOT"]
fn real_zap_server_runs_once_as_attested_pod_child() {
    let pod_binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let zap_root = fs::canonicalize(std::env::var_os("PODBAY_TEST_ZAP_ROOT").unwrap()).unwrap();
    let node = node_binary();
    let mut fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let ui_port = listener.local_addr().unwrap().port();
    drop(listener);
    let settings = serde_json::json!({
        "version":1,"uiPort":ui_port,"proxy":{"mode":"inherit"},
        "coordinatorDefaults":{"modelId":"gpt-5.6-luna","effort":"low"}
    });
    let settings_path = fixture.state.join("settings.json");
    fs::write(&settings_path, serde_json::to_vec(&settings).unwrap()).unwrap();
    fs::set_permissions(&settings_path, fs::Permissions::from_mode(0o600)).unwrap();
    let args = vec![
        "--experimental-strip-types".into(),
        "src/zap-server.ts".into(),
        "--state-dir".into(),
        fixture.state.to_string_lossy().into_owned(),
    ];
    assert_eq!(args[3].as_str(), fixture.state.to_str().unwrap());
    let node_sha = sha256_file(&node);
    let pod_sha = sha256_file(&pod_binary);
    let config = TrustedLinuxLaunchConfig::from_trusted_policy(
        pod_binary,
        pod_sha,
        fixture.pod_directory.clone(),
    )
    .unwrap();
    let mut port = LinuxLaunchPort::new(config);
    port.register_operator_process_from_trusted_policy(
        TrustedOperatorProcessProfile::from_trusted_policy(
            1,
            node.clone(),
            node_sha.clone(),
            zap_root.clone(),
            args.clone(),
            fixture.state.clone(),
            120,
        )
        .unwrap(),
    )
    .unwrap();
    let mut host = DurableAuthority::open(&fixture.database, port).unwrap();
    let scope = ScopeId::try_from("scope.zap.disposable").unwrap();
    let actor = ActorId::try_from("actor.zap.disposable").unwrap();
    let pod_id =
        PodId::try_from(format!("pod.zap.disposable.{}", std::process::id()).as_str()).unwrap();
    let process = AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(
        1000, 4242, 777, "/fixture",
    )
    .unwrap();
    let transport = Transport(AuthenticatedPeer::owner_cli_from_authenticated_transport(
        process.clone(),
        CredentialGeneration::new(1).unwrap(),
    ));
    host.register_actor_from_trusted_policy(ActorRegistration::owner_cli_from_trusted_policy(
        actor.clone(),
        scope.clone(),
        process,
        CredentialGeneration::new(1).unwrap(),
    ))
    .unwrap();
    let grant = host
        .install_grant_from_trusted_policy(
            &actor,
            GrantSpec {
                scope_id: scope.clone(),
                mode: GrantMode::Controller,
                rights: BTreeSet::from([Right::new(
                    Operation::LaunchPod,
                    Target::Pod(pod_id.clone()),
                )]),
                remaining_delegation_depth: 0,
            },
        )
        .unwrap();
    host.register_launch_profile_from_trusted_policy(
        RegisteredLaunchProfile::from_trusted_policy(TrustedLaunchProfileInput {
            profile_ref: OPERATOR_PROCESS_PROFILE_REF.into(),
            profile_generation: 1,
            executable: node.to_string_lossy().into_owned(),
            binary_generation: format!("sha256:{node_sha}"),
            executable_sha256: node_sha,
            workspace_root: zap_root.clone(),
            resource_layout: vec![TrustedDriverTemplate {
                kind: ResourceKind::Auxiliary,
                driver: ResourceDriver::Auxiliary {
                    driver_ref: "process.exec".into(),
                },
            }],
            execution_mode: ExecutionMode::LinuxCooperative,
            fixed_arguments: args,
            permitted_extra_arguments: BTreeSet::new(),
            default_model: "none".into(),
            allowed_models: BTreeSet::from(["none".into()]),
            default_effort: "none".into(),
            allowed_efforts: BTreeSet::from(["none".into()]),
            workspace_scope: scope.clone(),
            workspace_basis_ref: "basis.zap.disposable".into(),
            allowed_cwd_prefix: ".".into(),
            allow_write: true,
            allowed_tool_bundle_refs: BTreeSet::new(),
            environment_refs: vec![],
            credential_refs: vec![],
            max_wall_seconds: 120,
            max_children: 0,
            allow_fallback: false,
        })
        .unwrap(),
    )
    .unwrap();
    host.register_native_host_from_trusted_policy(
        TrustedNativeHostConfig::for_compiled_backend("host.zap.disposable".into())
            .unwrap()
            .with_auxiliary_driver("process.exec".into())
            .unwrap(),
    )
    .unwrap();
    let session_id = SessionId::try_from("session.zap.disposable").unwrap();
    let run_id = RunId::try_from("run.zap.disposable").unwrap();
    let attempt_id = AttemptId::try_from("attempt.zap.disposable").unwrap();
    let resource_id = ResourceId::try_from("resource.zap.disposable").unwrap();
    let mut session = Session::new(session_id, actor, scope.clone());
    let mut run = Run::new(
        run_id.clone(),
        &session,
        Role::Coordinator,
        WorkKind::Service,
        None,
    );
    let command_id = CommandId::try_from("command.zap.disposable").unwrap();
    run.admit(
        run.revision(),
        &command_id,
        &FixtureAdmission(command_id.clone(), run_id),
    )
    .unwrap();
    session.bind_run(session.revision(), &run).unwrap();
    let mut attempt = Attempt::new(
        attempt_id.clone(),
        run.id().clone(),
        1,
        Epoch::new(1).unwrap(),
    )
    .unwrap();
    run.start_attempt(run.revision(), &attempt).unwrap();
    let mut pod = Pod::new(pod_id.clone(), attempt.id().clone(), Epoch::new(1).unwrap());
    attempt.attach_pod(attempt.revision(), &pod).unwrap();
    let resource = Resource::new(
        resource_id.clone(),
        pod_id.clone(),
        ResourceKind::Auxiliary,
        Epoch::new(1).unwrap(),
    );
    pod.attach_resource(pod.revision(), &resource).unwrap();
    let binding =
        LaunchBinding::from_aggregates(&session, &run, &attempt, &pod, &[resource]).unwrap();
    let request = BoundLaunchPodRequest {
        host_request: HostRequest {
            scope_id: scope.clone(),
            grant_id: grant,
            guards: GuardSet {
                manager_epoch: ManagerEpoch::new(1).unwrap(),
                pod_incarnation: PodIncarnation::new(1).unwrap(),
                resource_epoch: None,
                credential_generation: CredentialGeneration::new(1).unwrap(),
            },
            command_key: "launch.zap.disposable".into(),
            correlation_id: "correlation.zap.disposable".into(),
            deadline: Instant::now() + Duration::from_secs(45),
            action: HostAction::LaunchPod {
                pod_id: pod_id.clone(),
                role: Role::Coordinator,
                credential: None,
            },
        },
        canonical_request: b"disposable operator process launch".to_vec(),
        proposal: Some(BoundHostLaunchProposal {
            session,
            run,
            binding,
            selection: LaunchSelection {
                profile_ref: OPERATOR_PROCESS_PROFILE_REF.into(),
                profile_generation: 1,
                model_id: None,
                reasoning_effort: None,
                fallback_approved: false,
                workspace: WorkspaceSelection {
                    scope_id: scope.clone(),
                    basis_ref: "basis.zap.disposable".into(),
                    relative_cwd: ".".into(),
                    access: WorkspaceAccess::ReadWrite,
                },
                arguments: vec![],
                tool_bundle_refs: vec![],
                authority_ref: format!("grant.{}", grant.get()),
                wall_seconds: 120,
                max_children: 0,
                parent_run_id: None,
            },
        }),
    };
    let manifest_path = manifest_path_for_identity(
        &fixture.pod_directory,
        &pod_id,
        &attempt_id,
        Epoch::new(1).unwrap(),
    );
    let stem = manifest_path.file_stem().unwrap().to_string_lossy();
    fixture.unit = Some(format!("podbay-pod-{stem}.service"));
    let first = host.launch_bound_pod(&transport, request.clone()).unwrap();
    assert_eq!(first.status.stage, LaunchDispatchStage::HostAccepted);
    assert!(first.port_called && !first.duplicate);
    let inspected = host
        .lookup_command(
            &transport,
            &scope,
            &CommandLookupSelector::Id {
                command_id: first.receipt.command_id.clone(),
            },
        )
        .unwrap();
    assert_eq!(inspected.receipt, first.receipt);
    assert_eq!(
        inspected.launch_dispatch_status.unwrap().stage,
        LaunchDispatchStage::HostAccepted
    );
    let manifest: PodManifest = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    let client = PodClient::connect(&manifest_path).unwrap();
    let before = client.attested_status().unwrap();
    assert!(before.child_running);
    assert_eq!(before.pod_id, pod_id.as_str());
    assert_eq!(
        before.bound.as_ref().unwrap().capability,
        OPERATOR_PROCESS_CAPABILITY
    );
    assert_eq!(
        before.bound.as_ref().unwrap().resource_id,
        resource_id.as_str()
    );
    assert!(before.child_pid > 1 && before.child_start_ticks > 0);
    let duplicate = host.launch_bound_pod(&transport, request).unwrap();
    assert!(duplicate.duplicate && !duplicate.port_called);
    assert_eq!(duplicate.receipt, first.receipt);
    let after = client.attested_status().unwrap();
    assert_eq!(
        (
            after.supervisor_pid,
            after.supervisor_start_ticks,
            after.child_pid,
            after.child_start_ticks
        ),
        (
            before.supervisor_pid,
            before.supervisor_start_ticks,
            before.child_pid,
            before.child_start_ticks
        )
    );
    let output_path = manifest_path.with_extension("process-output");
    let receipt = wait_for_receipt(&output_path, &client);
    assert_eq!(receipt["headless"], true);
    assert_eq!(receipt["viewerOpened"], false);
    assert_eq!(receipt["reusedOwner"], false);
    let url = receipt["url"].as_str().unwrap();
    assert_authenticated_empty_setup(&node, &zap_root, url);
    assert!(client.attested_status().unwrap().child_running);
    assert!(!client.stop().unwrap().child_running);
    let deadline = Instant::now() + Duration::from_secs(5);
    while manifest.socket_path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        !manifest.socket_path.exists(),
        "pod socket remained after stop"
    );
    loop {
        let unit = Command::new("systemctl")
            .args([
                "--user",
                "show",
                "--property=LoadState",
                "--value",
                fixture.unit.as_deref().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(unit.status.success());
        if String::from_utf8_lossy(&unit.stdout).trim() == "not-found" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "disposable PodBay unit remained loaded"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}
