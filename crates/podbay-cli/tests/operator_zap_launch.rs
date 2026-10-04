#![cfg(target_os = "linux")]

use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use podbay_core::{AttemptId, Epoch, PodId};
use podbay_launch_linux::TrustedOperatorArtifact;
use podbay_pod::{PodManifest, manifest_path_for_identity};
use sha2::{Digest, Sha256};

struct Fixture {
    root: PathBuf,
    outer: PathBuf,
    zap_state: PathBuf,
    installed_zap: PathBuf,
    unit: Option<String>,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("pz-{}-{nonce:x}", std::process::id()));
        let outer = root.join("o");
        let zap_state = root.join("s");
        for path in [&root, &outer, &zap_state] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self {
            installed_zap: root.join("app"),
            root,
            outer,
            zap_state,
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
        if std::thread::panicking() {
            eprintln!("retained failed operator fixture: {}", self.root.display());
            return;
        }
        let _ = fs::remove_dir_all(&self.root);
    }
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

fn sha256_file(path: &Path) -> String {
    let mut file = fs::File::open(path).unwrap();
    let mut hash = Sha256::new();
    let mut chunk = [0u8; 16_384];
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

fn install_private_zap(source: &Path, destination: &Path) -> (bool, Duration) {
    let started = Instant::now();
    let reflink = Command::new("cp")
        .args(["-a", "--reflink=always"])
        .arg(source)
        .arg(destination)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success();
    if !reflink {
        let _ = fs::remove_dir_all(destination);
        assert!(
            Command::new("cp")
                .args(["-a", "--reflink=auto"])
                .arg(source)
                .arg(destination)
                .status()
                .unwrap()
                .success()
        );
    }
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).unwrap();
    (reflink, started.elapsed())
}

fn run_operator(policy: &Path) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_podbay"))
        .args(["operator", "zap", "launch", "--policy"])
        .arg(policy)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "operator CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn wait_for_zap_receipt(path: &Path) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(bytes) = fs::read_to_string(path) {
            if let Some(line) = bytes.lines().next() {
                if let Ok(receipt) = serde_json::from_str::<serde_json::Value>(line) {
                    if receipt["protocol"] == "zap-server/1" {
                        return receipt;
                    }
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "headless Zap receipt did not arrive"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn spawn_http_probe(
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
#[ignore = "requires disposable user systemd, PODBAY_TEST_POD_BINARY and PODBAY_TEST_ZAP_ROOT"]
fn installed_operator_cli_launches_one_zap_and_rebinds_same_http_child_across_processes() {
    let pod_binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let source_zap = fs::canonicalize(std::env::var_os("PODBAY_TEST_ZAP_ROOT").unwrap()).unwrap();
    let node = node_binary();
    let mut fixture = Fixture::new();
    let (reflink, copy_elapsed) = install_private_zap(&source_zap, &fixture.installed_zap);
    let artifact = TrustedOperatorArtifact::inspect_tree(&fixture.installed_zap).unwrap();
    let hash_output = Command::new(env!("CARGO_BIN_EXE_podbay"))
        .args(["operator", "zap", "hash", "--root"])
        .arg(&fixture.installed_zap)
        .output()
        .unwrap();
    assert!(
        hash_output.status.success(),
        "installed hash CLI failed: {}",
        String::from_utf8_lossy(&hash_output.stderr)
    );
    let hash_receipt: serde_json::Value = serde_json::from_slice(&hash_output.stdout).unwrap();
    assert_eq!(hash_receipt["sha256"], artifact.sha256);
    eprintln!(
        "private Zap copy: reflink={} elapsed_ms={}; artifact entries={} bytes={} hash_ms={}",
        reflink,
        copy_elapsed.as_millis(),
        artifact.entries,
        artifact.bytes,
        artifact.elapsed.as_millis()
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let ui_port = listener.local_addr().unwrap().port();
    drop(listener);
    let settings = serde_json::json!({
        "version":1,"uiPort":ui_port,"proxy":{"mode":"inherit"},
        "coordinatorDefaults":{"modelId":"gpt-5.6-luna","effort":"low"}
    });
    let settings_path = fixture.zap_state.join("settings.json");
    fs::write(&settings_path, serde_json::to_vec(&settings).unwrap()).unwrap();
    fs::set_permissions(&settings_path, fs::Permissions::from_mode(0o600)).unwrap();
    let pod_id = PodId::try_from("pod.zap.installed.one").unwrap();
    let attempt_id = AttemptId::try_from("attempt.zap.installed.one").unwrap();
    let policy = serde_json::json!({
        "schema":"podbay.operator-zap-policy/1",
        "stateDirectory":fixture.outer,
        "podExecutable":pod_binary,
        "podExecutableSha256":sha256_file(&pod_binary),
        "nodeExecutable":node,
        "nodeExecutableSha256":sha256_file(&node),
        "zapRoot":fixture.installed_zap,
        "zapArtifactSha256":artifact.sha256,
        "zapStateDirectory":fixture.zap_state,
        "actorId":"actor.zap.installed.one",
        "scopeId":"scope.zap.installed.one",
        "podId":pod_id.as_str(),
        "sessionId":"session.zap.installed.one",
        "runId":"run.zap.installed.one",
        "attemptId":attempt_id.as_str(),
        "resourceId":"resource.zap.installed.one",
        "workspaceBasisRef":"basis.zap.installed.one",
        "hostId":"host.zap.installed.one",
        "commandKey":"launch.zap.installed.one",
        "wallSeconds":120
    });
    let policy_path = fixture.outer.join("operator-zap-policy.json");
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o600)).unwrap();
    let first = run_operator(&policy_path);
    assert_eq!(first["protocol"], "podbay.operator-zap/1");
    assert_eq!(first["duplicate"], false);
    assert_eq!(first["podId"], pod_id.as_str());
    let manifest_path = manifest_path_for_identity(
        &fixture.outer.join("pods"),
        &pod_id,
        &attempt_id,
        Epoch::new(1).unwrap(),
    );
    let stem = manifest_path.file_stem().unwrap().to_string_lossy();
    fixture.unit = Some(format!("podbay-pod-{stem}.service"));
    let manifest: PodManifest = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    let output_path = manifest_path.with_extension("process-output");
    let zap = wait_for_zap_receipt(&output_path);
    assert_eq!(zap["headless"], true);
    assert_eq!(zap["viewerOpened"], false);
    let ready = fixture.root.join("http-before-rebind");
    let resume = fixture.root.join("http-after-rebind");
    let mut probe = KillOnDrop(spawn_http_probe(
        &node,
        &fixture.installed_zap,
        &output_path,
        &ready,
        &resume,
    ));
    let deadline = Instant::now() + Duration::from_secs(30);
    while !ready.exists() {
        assert!(
            probe.try_wait().unwrap().is_none(),
            "HTTP pairing/setup failed before B"
        );
        assert!(Instant::now() < deadline, "HTTP setup before B timed out");
        std::thread::sleep(Duration::from_millis(25));
    }
    let second = run_operator(&policy_path);
    assert_eq!(second["duplicate"], true);
    assert_eq!(second["commandId"], first["commandId"]);
    for generation in [1, 2] {
        let custody = fixture.outer.join(format!("owner-key.{generation}.json"));
        let metadata = fs::symlink_metadata(custody).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    }
    for field in [
        "podId",
        "supervisorPid",
        "supervisorStartTicks",
        "childPid",
        "childStartTicks",
    ] {
        assert_eq!(second[field], first[field], "{field} changed across A to B");
    }
    fs::write(&resume, b"continue").unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = probe.try_wait().unwrap() {
            assert!(
                status.success(),
                "same paired HTTP session failed after B rebind"
            );
            break;
        }
        assert!(Instant::now() < deadline, "HTTP setup after B timed out");
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        std::path::Path::new(&format!(
            "/proc/{}/stat",
            first["childPid"].as_u64().unwrap()
        ))
        .exists()
    );
    assert!(
        Command::new("systemctl")
            .args(["--user", "stop", fixture.unit.as_deref().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let state = Command::new("systemctl")
            .args([
                "--user",
                "show",
                "--property=LoadState",
                "--value",
                fixture.unit.as_deref().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(state.status.success());
        if String::from_utf8_lossy(&state.stdout).trim() == "not-found" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "installed Zap unit remained: load={}",
            String::from_utf8_lossy(&state.stdout).trim()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    // systemctl stop kills the managerless disposable unit; unlike a PodClient
    // Stop, it may leave the private socket pathname after the unit is gone.
    if manifest.socket_path.exists() {
        assert!(
            fs::symlink_metadata(&manifest.socket_path)
                .unwrap()
                .file_type()
                .is_socket()
        );
        fs::remove_file(&manifest.socket_path).unwrap();
    }
    assert!(!manifest.socket_path.exists());
}
