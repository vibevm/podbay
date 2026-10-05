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
    inner_unit: Option<String>,
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
            inner_unit: None,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(unit) = &self.inner_unit {
            let _ = Command::new("systemctl")
                .args(["--user", "stop", unit])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
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

fn install_current_podbay_binding(installed_zap: &Path) {
    let source =
        fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bindings/typescript"))
            .unwrap();
    let destination = installed_zap.join("vendor/podbay/0.1.0/bindings/typescript");
    fs::create_dir_all(&destination).unwrap();
    fs::copy(
        source.join("package.json"),
        destination.join("package.json"),
    )
    .unwrap();
    assert!(
        Command::new("cp")
            .args(["-a"])
            .arg(source.join("src"))
            .arg(&destination)
            .status()
            .unwrap()
            .success()
    );
    assert!(destination.join("src/owner-setup.ts").is_file());
    assert!(destination.join("src/owner-recovery.ts").is_file());
}

fn fake_codex_source(node: &Path) -> String {
    let body = r#"
const fs = require('node:fs');
const readline = require('node:readline');
const home = process.env.CODEX_HOME;
const cwd = process.cwd();
const log = home + '/frames.log';
const send = (value) => process.stdout.write(JSON.stringify(value) + '\n');
let turns = 0;
readline.createInterface({ input: process.stdin }).on('line', (line) => {
  fs.appendFileSync(log, line + '\n');
  const request = JSON.parse(line);
  if (request.method === 'initialize') {
    send({ id: request.id, result: { codexHome: home, platformFamily: 'unix',
      platformOs: 'linux', userAgent: 'fixture' } }); return;
  }
  if (request.method === 'initialized') return;
  if (request.method === 'thread/start') {
    send({ id: request.id, result: { thread: { id: 'thread.fixture',
      sessionId: 'native.session.fixture', cwd, status: { type: 'idle' }, turns: [] },
      model: 'gpt-6-sol', reasoningEffort: 'medium', approvalPolicy: 'never',
      sandbox: { type: 'dangerFullAccess' }, cwd } }); return;
  }
  if (request.method === 'thread/read') {
    send({ id: request.id, result: { thread: { id: 'thread.fixture',
      sessionId: 'native.session.fixture', cwd, status: { type: 'idle' }, turns: [] } } });
    return;
  }
  if (request.method === 'turn/start') {
    turns += 1;
    const id = 'turn.fixture.' + String(turns);
    send({ id: request.id, result: { turn: { id, status: 'inProgress', items: [] } } });
    send({ method: 'item/agentMessage/delta', params: { threadId: 'thread.fixture',
      delta: 'PODBAY_NATIVE_OUTPUT_OK' } });
    setTimeout(() => {
      send({ method: 'turn/completed', params: { threadId: 'thread.fixture',
        turn: { id, status: 'completed', items: [] } } });
      send({ method: 'thread/status/changed', params: { threadId: 'thread.fixture',
        status: { type: 'idle' } } });
    }, 30);
  }
});
"#;
    format!("#!{}\n{body}", node.display())
}

fn write_inner_headless_config(
    fixture: &Fixture,
    node: &Path,
    manager: &Path,
    pod: &Path,
) -> PathBuf {
    let codex = fixture.zap_state.join("fake-codex");
    let auth = fixture.zap_state.join("auth");
    let workspace = fixture.zap_state.join("workspace");
    fs::create_dir(&auth).unwrap();
    fs::create_dir(&workspace).unwrap();
    for directory in [&auth, &workspace] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(&codex, fake_codex_source(node)).unwrap();
    fs::set_permissions(&codex, fs::Permissions::from_mode(0o700)).unwrap();
    let auth_source = auth.join("auth.json");
    fs::write(&auth_source, b"disposable fake credential").unwrap();
    fs::set_permissions(&auth_source, fs::Permissions::from_mode(0o600)).unwrap();
    let profile = "profile.podbay.headless";
    let config = serde_json::json!({
        "version":1,
        "manager":{
            "stateDirectory":fixture.zap_state.join("podbay"),
            "managerExecutable":manager,
            "managerExecutableSha256":sha256_file(manager),
            "podExecutable":pod,
            "podExecutableSha256":sha256_file(pod),
            "codexExecutable":codex,
            "codexExecutableSha256":sha256_file(&codex),
            "codexAuthSource":auth_source,
            "workspaceRoot":workspace,
            "actorId":"actor.podbay.headless",
            "scopeId":"scope.podbay.headless",
            "credentialRef":"vault.podbay.headless",
            "profileRef":profile,
            "profileGeneration":1,
            "workspaceBasisRef":"basis.podbay.headless",
            "hostId":"host.podbay.headless",
            "driverRef":"driver.podbay.headless",
            "protocolRef":"protocol.podbay.headless",
            "resultContractRef":"result.none",
            "wallSeconds":120,
            "maxChildren":2,
            "launchDeadlineSeconds":60,
            "sendDeadlineSeconds":180,
            "writerLeaseSeconds":120
        },
        "project":{
            "registrationId":"request.project.podbay.headless",
            "projectId":"project.podbay.headless",
            "displayName":"PodBay headless fixture",
            "repositoryRootRefs":["repository.podbay.headless"],
            "actions":{"startCoordinator":{"state":"available"}},
            "context":{
                "contextId":"context.podbay.headless",
                "displayName":"PodBay context",
                "workspaceRef":"workspace.podbay.headless",
                "branchLabel":"main",
                "revisionBinding":"fixture",
                "planning":{"state":"unavailable","reason":"no plan"},
                "coordinatorConversationId":"conversation.podbay.headless"
            },
            "coordinatorLaunchOptions":[{
                "profileId":profile,
                "label":"PodBay Codex",
                "interactionKind":"structured",
                "availability":{"state":"available"}
            }],
            "protected":{"cwd":workspace,"launchProfileRef":profile}
        }
    });
    let path = fixture.zap_state.join("podbay-headless.json");
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
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

fn spawn_nested_coordinator_probe(
    node: &Path,
    zap_root: &Path,
    output_path: &Path,
    zap_state: &Path,
    ready: &Path,
    resume: &Path,
) -> Child {
    const SCRIPT: &str = r#"
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';
import { DatabaseSync } from 'node:sqlite';
import { createWorkspaceHttpConnection } from './src/cells/workspace-client/index.ts';
const receipt = JSON.parse(readFileSync(process.argv[1], 'utf8').split('\n')[0]);
const state = process.argv[2];
const ready = process.argv[3];
const resume = process.argv[4];
const attach = new URL(receipt.url);
const gateway = attach.searchParams.get('workspace-gateway');
const pairing = new URLSearchParams(attach.hash.slice(1)).get('workspace-pair');
if (!gateway || !pairing) process.exit(2);
const connection = createWorkspaceHttpConnection({
  baseUrl: gateway, origin: attach.origin, pairingToken: pairing,
});
if (!connection) process.exit(3);
const projects = await connection.workspace.read({operation:'project.list.v1'});
if (!projects.ok || projects.value.projects.length !== 1) process.exit(4);
const started = await connection.workspace.command({
  operation:'session.start.v1',
  clientRequestId:'request.podbay.headless.nested.start',
  projectId:'project.podbay.headless', contextId:'context.podbay.headless',
  profileId:'profile.podbay.headless', interactionKind:'structured',
});
if (!started.ok) { process.stderr.write(JSON.stringify(started)+'\n'); process.exit(5); }
const mapPath = state + '/podbay/zap-coordinator-map.sqlite';
let actorId;
for (let i=0; i<300 && !actorId; i++) {
  if (existsSync(mapPath)) {
    const db = new DatabaseSync(mapPath, {readOnly:true});
    try {
      const row = db.prepare('SELECT payload FROM coordinator_mapping').get();
      if (row) actorId = JSON.parse(row.payload).coordinatorActorId;
    } finally { db.close(); }
  }
  if (!actorId) await sleep(50);
}
if (!actorId) process.exit(6);
async function outputOnce() {
  for (let i=0; i<150; i++) {
    const result = await connection.workspace.read({
      operation:'agent.output.page.v1', projectId:'project.podbay.headless',
      contextId:'context.podbay.headless', actorId, afterSequence:'0', limit:10,
    });
    if (!result.ok) { process.stderr.write(JSON.stringify(result)+'\n'); process.exit(7); }
    const bodies = result.value.page.items.map((item) => item.bodyMarkdown);
    if (bodies.includes('PODBAY_NATIVE_OUTPUT_OK')) return bodies;
    await sleep(100);
  }
  process.exit(8);
}
const first = await outputOnce();
let ack = 0n;
for (let i=0; i<100 && ack < 1n; i++) {
  const db = new DatabaseSync(mapPath, {readOnly:true});
  try {
    const row = db.prepare('SELECT payload FROM coordinator_native_cursor').get();
    if (row) ack = BigInt(JSON.parse(row.payload).sourceSequence);
  } finally { db.close(); }
  if (ack < 1n) await sleep(50);
}
if (ack < 1n) process.exit(9);
writeFileSync(ready, JSON.stringify({actorId, ack:String(ack), bodies:first}), {mode:0o600});
let released = false;
for (let i=0; i<1200; i++) {
  if (existsSync(resume)) { released=true; break; }
  await sleep(25);
}
if (!released) process.exit(10);
const second = await outputOnce();
if (second.filter((value) => value === 'PODBAY_NATIVE_OUTPUT_OK').length !== 1) process.exit(11);
"#;
    Command::new(node)
        .args([
            "--experimental-strip-types",
            "--input-type=module",
            "-e",
            SCRIPT,
        ])
        .arg(output_path)
        .arg(zap_state)
        .arg(ready)
        .arg(resume)
        .current_dir(zap_root)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InnerEvidence {
    unit: String,
    pod_id: String,
    supervisor_pid: u32,
    supervisor_birth: u64,
    child_pid: u32,
    child_birth: u64,
    turn_starts: usize,
    socket: PathBuf,
}

fn process_birth(pid: u32) -> u64 {
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

fn inner_evidence(zap_state: &Path) -> InnerEvidence {
    let directory = zap_state.join("podbay/pods");
    let manifests = fs::read_dir(&directory)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
                && path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .is_some_and(|stem| {
                        stem.len() == 32 && stem.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        manifests.len(),
        1,
        "exactly one inner Codex Pod is required"
    );
    let manifest: PodManifest = serde_json::from_slice(&fs::read(&manifests[0]).unwrap()).unwrap();
    let stem = manifests[0].file_stem().unwrap().to_string_lossy();
    let unit = format!("podbay-pod-{stem}.service");
    let shown = Command::new("systemctl")
        .args(["--user", "show", "--property=MainPID", "--value", &unit])
        .output()
        .unwrap();
    assert!(shown.status.success());
    let supervisor_pid: u32 = String::from_utf8(shown.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(supervisor_pid > 0);
    let children = fs::read_to_string(format!(
        "/proc/{supervisor_pid}/task/{supervisor_pid}/children"
    ))
    .unwrap();
    let children = children.split_whitespace().collect::<Vec<_>>();
    assert_eq!(children.len(), 1, "inner Codex must be a direct Pod child");
    let child_pid: u32 = children[0].parse().unwrap();
    let frames =
        fs::read_to_string(directory.join(format!("{stem}.private/home/codex/frames.log")))
            .unwrap();
    InnerEvidence {
        unit,
        pod_id: manifest.descriptor.pod_id,
        supervisor_pid,
        supervisor_birth: process_birth(supervisor_pid),
        child_pid,
        child_birth: process_birth(child_pid),
        turn_starts: frames
            .lines()
            .filter(|line| line.contains("\"method\":\"turn/start\""))
            .count(),
        socket: manifest.socket_path,
    }
}

fn stop_and_unload_unit(unit: &str) {
    assert!(
        Command::new("systemctl")
            .args(["--user", "stop", unit])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let shown = Command::new("systemctl")
            .args(["--user", "show", "--property=LoadState", "--value", unit])
            .output()
            .unwrap();
        assert!(shown.status.success());
        if String::from_utf8_lossy(&shown.stdout).trim() == "not-found" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "disposable unit remained loaded: {unit}"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn remove_stale_socket_after_unload(path: &Path) {
    if path.exists() {
        assert!(fs::symlink_metadata(path).unwrap().file_type().is_socket());
        fs::remove_file(path).unwrap();
    }
    assert!(!path.exists());
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
        "lifetime":{"kind":"untilStopped"}
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

#[test]
#[ignore = "requires disposable user systemd, PODBAY_TEST_POD_BINARY and PODBAY_TEST_ZAP_ROOT"]
fn installed_outer_zap_pod_nests_one_fake_codex_coordinator_without_resend() {
    let pod_binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let source_zap = fs::canonicalize(std::env::var_os("PODBAY_TEST_ZAP_ROOT").unwrap()).unwrap();
    let manager = fs::canonicalize(env!("CARGO_BIN_EXE_podbay")).unwrap();
    let node = node_binary();
    let mut fixture = Fixture::new();
    let (reflink, copy_elapsed) = install_private_zap(&source_zap, &fixture.installed_zap);
    install_current_podbay_binding(&fixture.installed_zap);
    let artifact = TrustedOperatorArtifact::inspect_tree(&fixture.installed_zap).unwrap();
    eprintln!(
        "nested Zap copy: reflink={} copy_ms={} artifact_entries={} artifact_bytes={} hash_ms={}",
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
    let config_path = write_inner_headless_config(&fixture, &node, &manager, &pod_binary);
    let outer_pod = PodId::try_from("pod.zap.nested.one").unwrap();
    let outer_attempt = AttemptId::try_from("attempt.zap.nested.one").unwrap();
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
        "headlessConfig":config_path,
        "headlessConfigSha256":sha256_file(&config_path),
        "actorId":"actor.zap.nested.one",
        "scopeId":"scope.zap.nested.one",
        "podId":outer_pod.as_str(),
        "sessionId":"session.zap.nested.one",
        "runId":"run.zap.nested.one",
        "attemptId":outer_attempt.as_str(),
        "resourceId":"resource.zap.nested.one",
        "workspaceBasisRef":"basis.zap.nested.one",
        "hostId":"host.zap.nested.one",
        "commandKey":"launch.zap.nested.one",
        "lifetime":{"kind":"untilStopped"}
    });
    let policy_path = fixture.outer.join("operator-zap-policy.json");
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o600)).unwrap();
    let first = run_operator(&policy_path);
    assert_eq!(first["duplicate"], false);
    assert_eq!(first["podId"], outer_pod.as_str());
    let outer_manifest_path = manifest_path_for_identity(
        &fixture.outer.join("pods"),
        &outer_pod,
        &outer_attempt,
        Epoch::new(1).unwrap(),
    );
    let outer_stem = outer_manifest_path.file_stem().unwrap().to_string_lossy();
    fixture.unit = Some(format!("podbay-pod-{outer_stem}.service"));
    let outer_manifest: PodManifest =
        serde_json::from_slice(&fs::read(&outer_manifest_path).unwrap()).unwrap();
    let output_path = outer_manifest_path.with_extension("process-output");
    let zap = wait_for_zap_receipt(&output_path);
    assert_eq!(zap["headless"], true);
    assert!(fixture.zap_state.join("podbay/manager.sock").exists());
    let ready = fixture.root.join("nested-ready");
    let resume = fixture.root.join("nested-resume");
    let mut probe = KillOnDrop(spawn_nested_coordinator_probe(
        &node,
        &fixture.installed_zap,
        &output_path,
        &fixture.zap_state,
        &ready,
        &resume,
    ));
    let deadline = Instant::now() + Duration::from_secs(60);
    while !ready.exists() {
        assert!(
            probe.try_wait().unwrap().is_none(),
            "nested HTTP coordinator probe exited"
        );
        assert!(
            Instant::now() < deadline,
            "nested coordinator did not produce output and ACK"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    let ready_value: serde_json::Value =
        serde_json::from_slice(&fs::read(&ready).unwrap()).unwrap();
    assert!(
        ready_value["bodies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|body| body == "PODBAY_NATIVE_OUTPUT_OK")
    );
    assert!(ready_value["ack"].as_str().unwrap().parse::<u64>().unwrap() >= 1);
    let inner_before = inner_evidence(&fixture.zap_state);
    assert_eq!(inner_before.turn_starts, 1);
    fixture.inner_unit = Some(inner_before.unit.clone());
    let second = run_operator(&policy_path);
    assert_eq!(second["duplicate"], true);
    assert_eq!(second["commandId"], first["commandId"]);
    for field in [
        "podId",
        "supervisorPid",
        "supervisorStartTicks",
        "childPid",
        "childStartTicks",
    ] {
        assert_eq!(
            second[field], first[field],
            "outer {field} changed across A to B"
        );
    }
    let inner_after = inner_evidence(&fixture.zap_state);
    assert_eq!(inner_after, inner_before);
    assert_eq!(
        inner_after.turn_starts, 1,
        "outer rebind resent native input"
    );
    fs::write(&resume, b"continue").unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = probe.try_wait().unwrap() {
            assert!(
                status.success(),
                "same paired nested HTTP session failed after outer rebind"
            );
            break;
        }
        assert!(Instant::now() < deadline, "nested HTTP recheck timed out");
        std::thread::sleep(Duration::from_millis(25));
    }
    stop_and_unload_unit(&inner_after.unit);
    remove_stale_socket_after_unload(&inner_after.socket);
    stop_and_unload_unit(fixture.unit.as_deref().unwrap());
    remove_stale_socket_after_unload(&outer_manifest.socket_path);
    let manager_socket = fixture.zap_state.join("podbay/manager.sock");
    let deadline = Instant::now() + Duration::from_secs(15);
    while manager_socket.exists() {
        assert!(
            Instant::now() < deadline,
            "inner manager socket survived outer Zap stop"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(!Path::new(&format!("/proc/{}/stat", inner_after.child_pid)).exists());
    assert!(
        !Path::new(&format!(
            "/proc/{}/stat",
            first["childPid"].as_u64().unwrap()
        ))
        .exists()
    );
}

fn setup_disposable_stop() -> (Fixture, PathBuf, serde_json::Value, PodManifest) {
    let pod_binary = fs::canonicalize(std::env::var_os("PODBAY_TEST_POD_BINARY").unwrap()).unwrap();
    let source_zap = fs::canonicalize(std::env::var_os("PODBAY_TEST_ZAP_ROOT").unwrap()).unwrap();
    let node = node_binary();
    let mut fixture = Fixture::new();
    install_private_zap(&source_zap, &fixture.installed_zap);
    let artifact = TrustedOperatorArtifact::inspect_tree(&fixture.installed_zap).unwrap();
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
    let pod_id = PodId::try_from("pod.zap.stop.one").unwrap();
    let attempt = AttemptId::try_from("attempt.zap.stop.one").unwrap();
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
        "actorId":"actor.zap.stop.one",
        "scopeId":"scope.zap.stop.one",
        "podId":pod_id.as_str(),
        "sessionId":"session.zap.stop.one",
        "runId":"run.zap.stop.one",
        "attemptId":attempt.as_str(),
        "resourceId":"resource.zap.stop.one",
        "workspaceBasisRef":"basis.zap.stop.one",
        "hostId":"host.zap.stop.one",
        "commandKey":"launch.zap.stop.one",
        "lifetime":{"kind":"untilStopped"}
    });
    let policy_path = fixture.outer.join("operator-zap-policy.json");
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    fs::set_permissions(&policy_path, fs::Permissions::from_mode(0o600)).unwrap();
    // A crash before final key publication cannot have signed enrollment.
    let key_temp = fixture.outer.join(".owner-key.1.json.pending");
    fs::write(&key_temp, b"partial prepublication key").unwrap();
    fs::set_permissions(&key_temp, fs::Permissions::from_mode(0o600)).unwrap();
    let first = run_operator(&policy_path);
    assert_eq!(first["duplicate"], false);
    assert!(!key_temp.exists());
    let manifest_path = manifest_path_for_identity(
        &fixture.outer.join("pods"),
        &pod_id,
        &attempt,
        Epoch::new(1).unwrap(),
    );
    let stem = manifest_path.file_stem().unwrap().to_string_lossy();
    fixture.unit = Some(format!("podbay-pod-{stem}.service"));
    let manifest: PodManifest = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    let zap = wait_for_zap_receipt(
        &fixture
            .outer
            .join("pods")
            .join(format!("{stem}.process-output")),
    );
    assert_eq!(zap["headless"], true);
    (fixture, policy_path, first, manifest)
}

fn operator_stop_output(policy: &Path, lose_reply: bool) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_podbay"));
    command
        .args(["operator", "zap", "stop", "--policy"])
        .arg(policy);
    if lose_reply {
        command.env("PODBAY_TEST_OPERATOR_STOP_DROP_REPLY", "1");
    }
    command.output().unwrap()
}

fn successful_operator_stop(policy: &Path) -> serde_json::Value {
    let output = operator_stop_output(policy, false);
    assert!(
        output.status.success(),
        "operator stop failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn assert_unit_unloaded(unit: &str) {
    let shown = Command::new("systemctl")
        .args(["--user", "show", "--property=LoadState", "--value", unit])
        .output()
        .unwrap();
    assert!(shown.status.success());
    assert_eq!(String::from_utf8_lossy(&shown.stdout).trim(), "not-found");
}

fn unit_runtime_limit(unit: &str) -> String {
    let shown = Command::new("systemctl")
        .args(["--user", "show", "--property=RuntimeMaxUSec", "--value", unit])
        .output().unwrap();
    assert!(shown.status.success());
    String::from_utf8(shown.stdout).unwrap().trim().to_owned()
}

#[test]
#[ignore = "requires disposable user systemd, PODBAY_TEST_POD_BINARY and PODBAY_TEST_ZAP_ROOT"]
fn installed_operator_until_stopped_service_has_unlimited_unit_and_exact_stop() {
    let (fixture, policy_path, first, manifest) = setup_disposable_stop();
    assert_eq!(first["lifetime"]["kind"], "untilStopped");
    let unit = fixture.unit.as_deref().unwrap();
    assert_eq!(unit_runtime_limit(unit), "infinity");
    let pid = first["childPid"].as_u64().unwrap() as u32;
    let birth = first["childStartTicks"].as_u64().unwrap();
    // This deliberately exceeds a short finite comparison budget while the
    // actual unit has no RuntimeMaxSec deadline; it does not wait an hour.
    std::thread::sleep(Duration::from_millis(2_500));
    assert_eq!(process_birth(pid), birth);
    assert_eq!(unit_runtime_limit(unit), "infinity");
    let second = run_operator(&policy_path);
    assert_eq!(second["duplicate"], true);
    assert_eq!(second["commandId"], first["commandId"]);
    for field in ["podId", "supervisorPid", "supervisorStartTicks", "childPid", "childStartTicks"] {
        assert_eq!(second[field], first[field], "{field} changed on reattach");
    }
    let stopped = successful_operator_stop(&policy_path);
    assert_eq!(stopped["terminal"], true);
    assert_eq!(stopped["duplicate"], false);
    assert_unit_unloaded(unit);
    assert!(!manifest.socket_path.exists());
    assert!(!Path::new(&format!("/proc/{pid}/stat")).exists());
    let repeated = successful_operator_stop(&policy_path);
    assert_eq!(repeated["duplicate"], true);
    assert_eq!(repeated["intentDigest"], stopped["intentDigest"]);
}

#[test]
#[ignore = "requires disposable user systemd, PODBAY_TEST_POD_BINARY and PODBAY_TEST_ZAP_ROOT"]
fn exited_child_leaves_outer_unit_but_signed_stop_cannot_rebind() {
    let (fixture, policy_path, first, _manifest) = setup_disposable_stop();
    let unit = fixture.unit.as_deref().unwrap();
    let child_pid = first["childPid"].as_u64().unwrap() as u32;
    let child_birth = first["childStartTicks"].as_u64().unwrap();
    assert_eq!(process_birth(child_pid), child_birth);
    assert!(Command::new("kill")
        .args(["-KILL", &child_pid.to_string()])
        .status().unwrap().success());
    let deadline = Instant::now() + Duration::from_secs(5);
    let child_stat = format!("/proc/{child_pid}/stat");
    while Path::new(&child_stat).exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(!Path::new(&child_stat).exists());
    let shown = Command::new("systemctl")
        .args(["--user", "show", "--property=ActiveState", "--value", unit])
        .output().unwrap();
    assert!(shown.status.success());
    assert_eq!(String::from_utf8_lossy(&shown.stdout).trim(), "active");
    let refused = operator_stop_output(&policy_path, false);
    assert!(!refused.status.success(), "unexpected signed stop: {}",
        String::from_utf8_lossy(&refused.stdout));
    assert!(String::from_utf8_lossy(&refused.stderr)
        .contains("operator stop rebind preparation failed: Host(StaleGuard)"));
    assert!(!fixture.outer.join("operator-zap-stop-intent.json").exists());
    // Disposal only: this bypass is intentionally outside the operator API.
    assert!(Command::new("systemctl")
        .args(["--user", "stop", unit])
        .status().unwrap().success());
    assert_unit_unloaded(unit);
}

#[test]
#[ignore = "requires disposable user systemd, PODBAY_TEST_POD_BINARY and PODBAY_TEST_ZAP_ROOT"]
fn installed_operator_stop_refuses_wrong_actor_pod_then_settles_once_and_reads_duplicate() {
    let (fixture, policy_path, first, manifest) = setup_disposable_stop();
    let original = fs::read(&policy_path).unwrap();
    for (field, changed) in [
        ("actorId", "actor.zap.stop.foreign"),
        ("podId", "pod.zap.stop.foreign"),
    ] {
        let mut wrong: serde_json::Value = serde_json::from_slice(&original).unwrap();
        wrong[field] = changed.into();
        fs::write(&policy_path, serde_json::to_vec(&wrong).unwrap()).unwrap();
        let refused = operator_stop_output(&policy_path, false);
        assert!(
            !refused.status.success(),
            "wrong {field} acquired stop authority"
        );
        assert!(!fixture.outer.join("operator-zap-stop-intent.json").exists());
        assert!(
            Path::new(&format!(
                "/proc/{}/stat",
                first["childPid"].as_u64().unwrap()
            ))
            .exists()
        );
        fs::write(&policy_path, &original).unwrap();
    }
    let intent_temp = fixture.outer.join(".operator-zap-stop-intent.json.pending");
    fs::write(&intent_temp, b"partial prepublication stop intent").unwrap();
    fs::set_permissions(&intent_temp, fs::Permissions::from_mode(0o600)).unwrap();
    let stopped = successful_operator_stop(&policy_path);
    assert!(!intent_temp.exists());
    assert_eq!(stopped["terminal"], true);
    assert_eq!(stopped["duplicate"], false);
    assert_eq!(stopped["launchCommandId"], first["commandId"]);
    assert!(!manifest.socket_path.exists());
    assert!(
        !Path::new(&format!(
            "/proc/{}/stat",
            first["childPid"].as_u64().unwrap()
        ))
        .exists()
    );
    assert_unit_unloaded(fixture.unit.as_deref().unwrap());
    let intent_before = fs::read(fixture.outer.join("operator-zap-stop-intent.json")).unwrap();
    let terminal = fixture.outer.join("operator-zap-stop-terminal.json");
    let terminal_temp = fixture
        .outer
        .join(".operator-zap-stop-terminal.json.pending");
    fs::hard_link(&terminal, &terminal_temp).unwrap();
    let duplicate = successful_operator_stop(&policy_path);
    assert!(!terminal_temp.exists());
    assert_eq!(duplicate["terminal"], true);
    assert_eq!(duplicate["duplicate"], true);
    assert_eq!(duplicate["intentDigest"], stopped["intentDigest"]);
    assert_eq!(
        fs::read(fixture.outer.join("operator-zap-stop-intent.json")).unwrap(),
        intent_before
    );
    assert!(!manifest.socket_path.exists());
}

#[test]
#[ignore = "requires disposable user systemd, PODBAY_TEST_POD_BINARY and PODBAY_TEST_ZAP_ROOT"]
fn installed_operator_stop_lost_reply_is_settled_by_readback_without_second_stop() {
    let (fixture, policy_path, first, manifest) = setup_disposable_stop();
    let lost = operator_stop_output(&policy_path, true);
    assert!(!lost.status.success());
    assert!(String::from_utf8_lossy(&lost.stderr).contains("test-only lost stop reply"));
    assert!(
        fixture
            .outer
            .join("operator-zap-stop-intent.json")
            .is_file()
    );
    assert!(
        !fixture
            .outer
            .join("operator-zap-stop-terminal.json")
            .exists()
    );
    let terminal_temp = fixture
        .outer
        .join(".operator-zap-stop-terminal.json.pending");
    fs::write(&terminal_temp, b"partial prepublication terminal receipt").unwrap();
    fs::set_permissions(&terminal_temp, fs::Permissions::from_mode(0o600)).unwrap();
    let settled = successful_operator_stop(&policy_path);
    assert!(!terminal_temp.exists());
    assert_eq!(settled["terminal"], true);
    assert_eq!(settled["duplicate"], true);
    assert_eq!(settled["launchCommandId"], first["commandId"]);
    assert!(
        fixture
            .outer
            .join("operator-zap-stop-terminal.json")
            .is_file()
    );
    assert_unit_unloaded(fixture.unit.as_deref().unwrap());
    assert!(!manifest.socket_path.exists());
    assert!(
        !Path::new(&format!(
            "/proc/{}/stat",
            first["childPid"].as_u64().unwrap()
        ))
        .exists()
    );
}
