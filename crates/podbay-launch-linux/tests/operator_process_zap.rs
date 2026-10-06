#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use podbay_core::{
    ActorId, Attempt, AttemptId, Epoch, LaunchBinding, Pod, PodId,
    Resource, ResourceId, ResourceKind, Role, Run, RunId, ScopeId, Session,
    SessionId, WorkKind,
};
use podbay_host::{
    ActorRegistration, AuthenticatedPeer, AuthenticatedProcessSubject, AuthenticatedTransport,
    BoundHostLaunchProposal, BoundLaunchPodRequest, CredentialGeneration, DurableAuthority,
    ExecutionMode, GrantMode, GrantSpec, GuardSet, HostAction, HostDispatchPort, HostError,
    HostRequest, LaunchSelection, ManagerEpoch, Operation, PodIncarnation, RegisteredLaunchProfile,
    Right, Target, TrustedDriverTemplate, TrustedLaunchProfileInput, TrustedNativeHostConfig,
    WorkspaceAccess, WorkspaceSelection,
};
use podbay_launch_linux::{
    LinuxLaunchPort, TrustedLinuxLaunchConfig, TrustedOperatorArtifact,
    TrustedOperatorProcessProfile,
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

struct KillOnDrop(Child);

impl KillOnDrop {
    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.0.try_wait()
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
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

    fn from_shared(root: PathBuf) -> Self {
        let root = fs::canonicalize(root).unwrap();
        Self {
            database: root.join("store.sqlite"),
            pod_directory: root.join("pods"),
            state: root.join("zap-state"),
            root,
            unit: None,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let mut units = self.unit.clone().into_iter().collect::<Vec<_>>();
        if let Ok(entries) = fs::read_dir(&self.pod_directory) {
            for path in entries.filter_map(Result::ok).map(|entry| entry.path()) {
                if path
                    .extension()
                    .is_some_and(|extension| extension == "json")
                    && let Some(stem) = path.file_stem().and_then(|stem| stem.to_str())
                    && stem.len() == 32
                    && stem.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    let unit = format!("podbay-pod-{stem}.service");
                    if !units.contains(&unit) {
                        units.push(unit);
                    }
                }
            }
        }
        for unit in units {
            let _ = Command::new("systemctl")
                .args(["--user", "stop", &unit])
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

/// One pairing and one cookie persist across both manager processes. A
/// second pairing would test Zap's one-use token rather than PodBay recovery.
fn spawn_authenticated_rebind_probe(
    node: &Path,
    zap_root: &Path,
    output_path: &Path,
    ready: &Path,
    resume: &Path,
) -> Child {
    const SCRIPT: &str = r#"
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';
import { createWorkspaceHttpConnection } from './src/cells/workspace-client/index.ts';
const receipt = JSON.parse(readFileSync(process.argv[1], 'utf8').split('\n')[0]);
const attach = new URL(receipt.url);
const gateway = attach.searchParams.get('workspace-gateway');
const pairing = new URLSearchParams(attach.hash.slice(1)).get('workspace-pair');
if (!gateway || !pairing) process.exit(2);
const connection = createWorkspaceHttpConnection({
  baseUrl: gateway, origin: attach.origin, pairingToken: pairing,
});
if (!connection) process.exit(3);
async function check() {
  const setup = await connection.product.request({operation:'product.setup.get.v1'});
  return setup.ok && setup.value.operation === 'product.setup.get.v1'
      && setup.value.snapshot.projects.length === 0;
}
if (!(await check())) process.exit(4);
writeFileSync(process.argv[2], 'paired', {mode:0o600});
let released = false;
for (let i=0; i<1200; i++) {
  if (existsSync(process.argv[3])) { released=true; break; }
  await sleep(25);
}
if (!released || !(await check())) process.exit(5);
"#;
    Command::new(node)
        .args([
            "--experimental-strip-types",
            "--input-type=module",
            "-e",
            SCRIPT,
        ])
        .arg(output_path)
        .arg(ready)
        .arg(resume)
        .current_dir(zap_root)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap()
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
fn operator_artifact_digest_refuses_changed_import_before_port_effect() {
    let fixture = Fixture::new();
    let source = fixture.root.join("src");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("zap-server.ts"), b"import './module.ts';\n").unwrap();
    fs::write(source.join("module.ts"), b"export const value = 1;\n").unwrap();
    let binary = fs::canonicalize("/bin/true").unwrap();
    let digest = sha256_file(&binary);
    let proof = TrustedOperatorArtifact::inspect_tree(&fixture.root).unwrap();
    assert!(proof.entries >= 5);
    let artifact = TrustedOperatorArtifact::from_trusted_policy(
        fixture.root.clone(), proof.sha256,
    ).unwrap();
    let profile = TrustedOperatorProcessProfile::from_trusted_policy(
        1, binary.clone(), digest.clone(), fixture.root.clone(),
        vec!["src/zap-server.ts".into()], fixture.state.clone(), 60,
    ).unwrap().with_verified_artifact(artifact).unwrap();
    fs::write(source.join("module.ts"), b"export const value = 2;\n").unwrap();
    let config = TrustedLinuxLaunchConfig::from_trusted_policy(
        binary, digest, fixture.pod_directory.clone(),
    ).unwrap();
    assert!(LinuxLaunchPort::new(config)
        .register_operator_process_from_trusted_policy(profile).is_err());
}

#[test]
fn operator_artifact_digest_refuses_symlink_outside_installed_tree() {
    let fixture = Fixture::new();
    symlink("/etc/hosts", fixture.root.join("escaped-import.ts")).unwrap();
    assert!(TrustedOperatorArtifact::inspect_tree(&fixture.root).is_err());
}

// This fixture has no Pod/Store paths and its teardown never calls a service.
struct ArtifactTreeFixture(PathBuf);
impl ArtifactTreeFixture {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "podbay-artifact-vector-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
}
impl Drop for ArtifactTreeFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// Independent legacy stream oracle for these tiny stable fixtures only. Its
// ordering/framing follows the pre-bounds implementation at base 70f0164;
// it shares no walker, budget, metadata or framing helper with production.
fn legacy_artifact_digest_for_fixture(root: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    fn field(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(bytes);
    }
    fn directory(root: &Path, dir: &Path, out: &mut Vec<u8>) {
        let mut children = fs::read_dir(dir)
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        children.sort_by_key(|entry| entry.file_name());
        for entry in children {
            let path = entry.path();
            field(out, path.strip_prefix(root).unwrap().as_os_str().as_bytes());
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.file_type().is_symlink() {
                assert!(fs::canonicalize(&path).unwrap().starts_with(root));
                out.push(b'L');
                field(out, fs::read_link(&path).unwrap().as_os_str().as_bytes());
            } else if meta.is_dir() {
                out.push(b'D');
                directory(root, &path, out);
            } else {
                assert!(meta.is_file());
                out.push(b'F');
                out.extend_from_slice(&meta.len().to_be_bytes());
                out.extend_from_slice(&fs::read(path).unwrap());
            }
        }
    }
    let mut bytes = b"podbay.operator-artifact-tree/1\0".to_vec();
    directory(root, root, &mut bytes);
    Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn artifact_mixed_fixture(root: &Path) {
    use std::os::unix::ffi::OsStringExt;
    fs::create_dir(root.join("a")).unwrap();
    fs::create_dir(root.join("d")).unwrap();
    fs::write(root.join("a/z"), [0, 255, b'x']).unwrap();
    fs::write(root.join("a-"), b"a").unwrap();
    symlink("a/z", root.join("l")).unwrap();
    fs::write(root.join(std::ffi::OsString::from_vec(vec![255])), b"raw\n").unwrap();
}

#[test]
fn operator_artifact_v1_golden_bytes_and_legacy_compatibility() {
    let tree = ArtifactTreeFixture::new();
    let empty = TrustedOperatorArtifact::inspect_tree(&tree.0).unwrap();
    assert_eq!(
        empty.sha256,
        "875b435a528c840cf06f06760c921b76a6d20d623ecb8e6ab3ce96b63c942163"
    );
    assert_eq!((empty.entries, empty.bytes), (0, 0));
    assert_eq!(empty.sha256, legacy_artifact_digest_for_fixture(&tree.0));
    artifact_mixed_fixture(&tree.0);
    let mixed = TrustedOperatorArtifact::inspect_tree(&tree.0).unwrap();
    // Frozen independently from the explicit 138-byte v1 stream: DFS visits
    // a/z before a-; raw 0xff is the last filename; the literal link is a/z.
    assert_eq!(
        mixed.sha256,
        "bafcc7fa340678219060888a9bdd9af95a6516df243b1f77737e8b6b5e06dd5d"
    );
    assert_eq!((mixed.entries, mixed.bytes), (6, 8));
    assert_eq!(mixed.sha256, legacy_artifact_digest_for_fixture(&tree.0));
    fs::set_permissions(tree.0.join("a-"), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        TrustedOperatorArtifact::inspect_tree(&tree.0)
            .unwrap()
            .sha256,
        mixed.sha256,
        "mode is checked for changes during a scan but is not a v1 hash field"
    );
    fs::remove_file(tree.0.join("l")).unwrap();
    symlink(tree.0.join("a/z"), tree.0.join("l")).unwrap();
    let absolute = TrustedOperatorArtifact::inspect_tree(&tree.0).unwrap();
    assert_ne!(absolute.sha256, mixed.sha256);
    assert_eq!(absolute.sha256, legacy_artifact_digest_for_fixture(&tree.0));
}

#[test]
fn operator_artifact_v1_names_types_content_and_literal_targets_are_committed() {
    let tree = ArtifactTreeFixture::new();
    artifact_mixed_fixture(&tree.0);
    let original = TrustedOperatorArtifact::inspect_tree(&tree.0)
        .unwrap()
        .sha256;
    fs::write(tree.0.join("a/z"), [0, 254, b'x']).unwrap();
    assert_ne!(
        TrustedOperatorArtifact::inspect_tree(&tree.0)
            .unwrap()
            .sha256,
        original
    );
    fs::write(tree.0.join("a/z"), [0, 255, b'x']).unwrap();
    fs::rename(tree.0.join("a-"), tree.0.join("b")).unwrap();
    assert_ne!(
        TrustedOperatorArtifact::inspect_tree(&tree.0)
            .unwrap()
            .sha256,
        original
    );
    fs::rename(tree.0.join("b"), tree.0.join("a-")).unwrap();
    fs::remove_dir(tree.0.join("d")).unwrap();
    fs::write(tree.0.join("d"), b"").unwrap();
    assert_ne!(
        TrustedOperatorArtifact::inspect_tree(&tree.0)
            .unwrap()
            .sha256,
        original
    );
    fs::remove_file(tree.0.join("d")).unwrap();
    fs::create_dir(tree.0.join("d")).unwrap();
    fs::remove_file(tree.0.join("l")).unwrap();
    symlink("./a/z", tree.0.join("l")).unwrap();
    let changed = TrustedOperatorArtifact::inspect_tree(&tree.0).unwrap();
    assert_ne!(
        changed.sha256, original,
        "same resolved file, different literal link bytes"
    );
    assert_eq!(changed.sha256, legacy_artifact_digest_for_fixture(&tree.0));
}

#[test]
fn operator_artifact_v1_refuses_dangling_cycles_and_special_files() {
    let tree = ArtifactTreeFixture::new();
    let link = tree.0.join("link");
    symlink("missing", &link).unwrap();
    assert!(TrustedOperatorArtifact::inspect_tree(&tree.0).is_err());
    fs::remove_file(&link).unwrap();
    symlink("link", &link).unwrap();
    assert!(TrustedOperatorArtifact::inspect_tree(&tree.0).is_err());
    fs::remove_file(&link).unwrap();
    let socket = std::os::unix::net::UnixListener::bind(tree.0.join("socket")).unwrap();
    assert!(TrustedOperatorArtifact::inspect_tree(&tree.0).is_err());
    drop(socket);
}

#[test]
#[ignore = "requires PODBAY_TEST_ZAP_ROOT; hashes the installed Zap import tree"]
fn installed_zap_artifact_tree_fits_bounded_hash_budget() {
    let root = fs::canonicalize(std::env::var_os("PODBAY_TEST_ZAP_ROOT").unwrap()).unwrap();
    let fixture = Fixture::new();
    let installed = fixture.root.join("installed-zap");
    let reflink = Command::new("cp").args(["-a", "--reflink=always"])
        .arg(&root).arg(&installed).stdout(Stdio::null()).stderr(Stdio::null())
        .status().unwrap().success();
    if !reflink {
        let _ = fs::remove_dir_all(&installed);
        assert!(Command::new("cp").args(["-a", "--reflink=auto"])
            .arg(&root).arg(&installed).status().unwrap().success());
    }
    fs::set_permissions(&installed, fs::Permissions::from_mode(0o700)).unwrap();
    let proof = TrustedOperatorArtifact::inspect_tree(&installed).unwrap();
    eprintln!(
        "Zap artifact digest: entries={} bytes={} elapsed_ms={}",
        proof.entries, proof.bytes, proof.elapsed.as_millis(),
    );
    assert!(proof.entries > 100);
    assert!(proof.bytes > 1_000_000);
    assert_eq!(proof.sha256.len(), 64);
}

#[test]
#[ignore = "requires disposable user systemd, PODBAY_TEST_POD_BINARY and PODBAY_TEST_ZAP_ROOT"]
fn real_zap_server_runs_once_as_attested_pod_child() {
    let pod_binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let zap_root = fs::canonicalize(std::env::var_os("PODBAY_TEST_ZAP_ROOT").unwrap()).unwrap();
    let node = node_binary();
    let shared = std::env::var_os("PODBAY_REBIND_FIXTURE_ROOT");
    let mut fixture = shared
        .as_ref()
        .map(|root| Fixture::from_shared(root.into()))
        .unwrap_or_else(Fixture::new);
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
    let run = Run::new(
        run_id.clone(),
        &session,
        Role::Coordinator,
        WorkKind::Service,
        None,
    );
    session.bind_run(session.revision(), &run).unwrap();
    let mut attempt = Attempt::new(
        attempt_id.clone(),
        run.id().clone(),
        1,
        Epoch::new(1).unwrap(),
    )
    .unwrap();
    let mut pod = Pod::new(pod_id.clone(), attempt.id().clone(), Epoch::new(1).unwrap());
    attempt.attach_pod(attempt.revision(), &pod).unwrap();
    let resource = Resource::new(
        resource_id.clone(),
        pod_id.clone(),
        ResourceKind::Auxiliary,
        Epoch::new(1).unwrap(),
    );
    pod.attach_resource(pod.revision(), &resource).unwrap();
    let binding = LaunchBinding::plan_first_root(&session, &run, &attempt, &pod, &[resource])
        .unwrap()
        .identity()
        .clone();
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
    let first = host.launch_bound_operator_process(&transport, request.clone()).unwrap();
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
    let duplicate = host.launch_bound_operator_process(&transport, request).unwrap();
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
    if shared.is_none() {
        assert_authenticated_empty_setup(&node, &zap_root, url);
    }
    assert!(client.attested_status().unwrap().child_running);
    if shared.is_some() {
        fs::write(
            fixture.root.join("manager-a.json"),
            serde_json::to_vec(&serde_json::json!({
                "scope_id": scope.as_str(), "pod_id": pod_id.as_str(),
                "attempt_id": attempt_id.as_str(), "resource_id": resource_id.as_str(),
                "manifest_path": manifest_path, "unit": fixture.unit.as_deref(),
                "supervisor_pid": before.supervisor_pid,
                "supervisor_start_ticks": before.supervisor_start_ticks,
                "child_pid": before.child_pid,
                "child_start_ticks": before.child_start_ticks,
            }))
            .unwrap(),
        )
        .unwrap();
        let release = fixture.root.join("manager-a-exit");
        let deadline = Instant::now() + Duration::from_secs(30);
        while !release.exists() {
            assert!(
                Instant::now() < deadline,
                "manager A exit barrier timed out"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
        std::mem::forget(fixture);
        return;
    }
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

#[test]
#[ignore = "helper for disposable two-manager operator process fixture"]
fn operator_sibling_status_helper() {
    let manifest = PathBuf::from(std::env::var_os("PODBAY_REBIND_MANIFEST").unwrap());
    assert!(
        PodClient::connect(&manifest).is_err(),
        "same-UID sibling may not inherit the current manager's control"
    );
}

fn proc_start_ticks(pid: u32) -> u64 {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    stat.rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
#[ignore = "requires disposable user systemd, PODBAY_TEST_POD_BINARY and PODBAY_TEST_ZAP_ROOT"]
fn real_zap_child_survives_manager_a_and_rebinds_to_b() {
    let pod_binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let zap_root = fs::canonicalize(std::env::var_os("PODBAY_TEST_ZAP_ROOT").unwrap()).unwrap();
    let node = node_binary();
    let mut fixture = Fixture::new();
    let mut manager_a = KillOnDrop(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "real_zap_server_runs_once_as_attested_pod_child",
                "--nocapture",
            ])
            .env("PODBAY_TEST_POD_BINARY", &pod_binary)
            .env("PODBAY_TEST_ZAP_ROOT", &zap_root)
            .env("PODBAY_REBIND_FIXTURE_ROOT", &fixture.root)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let marker_path = fixture.root.join("manager-a.json");
    let wait_deadline = Instant::now() + Duration::from_secs(30);
    while !marker_path.exists() {
        assert!(
            manager_a.try_wait().unwrap().is_none(),
            "manager A exited before launch proof"
        );
        assert!(
            Instant::now() < wait_deadline,
            "manager A launch proof timed out"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    let marker: serde_json::Value =
        serde_json::from_slice(&fs::read(&marker_path).unwrap()).unwrap();
    let field = |name: &str| marker[name].as_str().unwrap().to_owned();
    let scope = ScopeId::try_from(field("scope_id").as_str()).unwrap();
    let pod = PodId::try_from(field("pod_id").as_str()).unwrap();
    let manifest_path = PathBuf::from(field("manifest_path"));
    fixture.unit = Some(field("unit"));
    let a_supervisor = marker["supervisor_pid"].as_u64().unwrap() as u32;
    let a_supervisor_birth = marker["supervisor_start_ticks"].as_u64().unwrap();
    let a_child = marker["child_pid"].as_u64().unwrap() as u32;
    let a_child_birth = marker["child_start_ticks"].as_u64().unwrap();
    assert_eq!(proc_start_ticks(a_supervisor), a_supervisor_birth);
    assert_eq!(proc_start_ticks(a_child), a_child_birth);
    let output_path = manifest_path.with_extension("process-output");
    let output = fs::read_to_string(&output_path).unwrap();
    let receipt: serde_json::Value = serde_json::from_str(output.lines().next().unwrap()).unwrap();
    assert_eq!(receipt["protocol"], "zap-server/1");
    let ready = fixture.root.join("http-before-rebind");
    let resume = fixture.root.join("http-after-rebind");
    let mut probe = KillOnDrop(spawn_authenticated_rebind_probe(
        &node,
        &zap_root,
        &output_path,
        &ready,
        &resume,
    ));
    while !ready.exists() {
        assert!(
            probe.try_wait().unwrap().is_none(),
            "HTTP pairing/setup failed before A exit"
        );
        assert!(
            Instant::now() < wait_deadline,
            "HTTP setup before A exit timed out"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    fs::write(fixture.root.join("manager-a-exit"), b"release").unwrap();
    let exit_deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = manager_a.try_wait().unwrap() {
            assert!(status.success(), "manager A failed while exiting");
            break;
        }
        assert!(Instant::now() < exit_deadline, "manager A did not exit");
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(proc_start_ticks(a_child), a_child_birth);

    let node_sha = sha256_file(&node);
    let config = TrustedLinuxLaunchConfig::from_trusted_policy(
        pod_binary.clone(),
        sha256_file(&pod_binary),
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
            vec![
                "--experimental-strip-types".into(),
                "src/zap-server.ts".into(),
                "--state-dir".into(),
                fixture.state.to_string_lossy().into_owned(),
            ],
            fixture.state.clone(),
            120,
        )
        .unwrap(),
    )
    .unwrap();
    let mut host = DurableAuthority::open(&fixture.database, port).unwrap();
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
            fixed_arguments: vec![
                "--experimental-strip-types".into(),
                "src/zap-server.ts".into(),
                "--state-dir".into(),
                fixture.state.to_string_lossy().into_owned(),
            ],
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
    let key = "rebind.zap.operator.a-to-b";
    let reviewed = host
        .inspect_committed_operator_process(&scope, &pod)
        .unwrap();
    let observed = <LinuxLaunchPort as HostDispatchPort>::inspect_existing_operator_process_rebind(
        host.port(),
        &reviewed,
    );
    assert!(
        observed.is_ok(),
        "operator read-only port inspect failed: {:?}",
        observed.err()
    );
    let prepared = host
        .prepare_current_operator_process_rebind(&scope, &pod, key)
        .unwrap();
    assert_eq!(prepared.phase, podbay_store::DurableRebindPhase::Pending);
    let active = host
        .complete_current_operator_process_rebind(&scope, &pod, key)
        .unwrap();
    assert_eq!(active.stage, podbay_host::RebindCompletionStage::PodActive);
    assert_eq!(
        active.durable.phase,
        podbay_store::DurableRebindPhase::Activated
    );
    let repeat = host
        .complete_current_operator_process_rebind(&scope, &pod, key)
        .unwrap();
    assert_eq!(repeat.durable, active.durable);
    assert_eq!(repeat.stage, podbay_host::RebindCompletionStage::PodActive);
    let client = PodClient::connect(&manifest_path).unwrap();
    let status = client.attested_status().unwrap();
    assert!(status.child_running);
    assert_eq!(status.pod_id, pod.as_str());
    assert_eq!(status.supervisor_pid, a_supervisor);
    assert_eq!(status.supervisor_start_ticks, a_supervisor_birth);
    assert_eq!(status.child_pid, a_child);
    assert_eq!(status.child_start_ticks, a_child_birth);
    assert_eq!(
        status.bound.as_ref().unwrap().capability,
        OPERATOR_PROCESS_CAPABILITY
    );
    assert_eq!(status.bound.as_ref().unwrap().owner_epoch, 2);
    fs::write(&resume, b"continue").unwrap();
    let probe_deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = probe.try_wait().unwrap() {
            assert!(
                status.success(),
                "authenticated HTTP setup failed after rebind"
            );
            break;
        }
        assert!(
            Instant::now() < probe_deadline,
            "HTTP setup after rebind timed out"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    let sibling = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "operator_sibling_status_helper"])
        .env("PODBAY_REBIND_MANIFEST", &manifest_path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .unwrap();
    assert!(sibling.success(), "sibling transport was not refused");
    assert_eq!(proc_start_ticks(a_child), a_child_birth);
    assert!(!client.stop().unwrap().child_running);
    let manifest: PodManifest = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let loaded = Command::new("systemctl")
            .args([
                "--user",
                "show",
                "--property=LoadState",
                "--value",
                fixture.unit.as_deref().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(loaded.status.success());
        if !manifest.socket_path.exists()
            && String::from_utf8_lossy(&loaded.stdout).trim() == "not-found"
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "rebound Zap unit or socket remained"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}
