#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_core::{
    ActorId, Attempt, AttemptId, CommandAdmission, CommandId, Epoch, LaunchBinding, Pod, PodId,
    Resource, ResourceId, ResourceKind, Role, Run, RunCommandKind, RunId, ScopeId, Session,
    SessionId, WorkKind,
};
use podbay_pod::{
    BoundPeerManifest, CODEX_AUTH_CREDENTIAL_NAME, LaunchDescriptor, LinuxPeerEvidence,
    PodCodexResource, PodError, PodRole, ValidatedCodexResourceLaunch,
    prepare_codex_home_from_systemd_credential,
};
use podbay_wire::{
    CodexAppServerPolicyV2, EffectiveLaunchContract, EffectiveLaunchContractV2,
    ImmutableLaunchDescriptorV2, ResourceDriver, ReviewedNativePolicy, ReviewedResource, TargetOs,
};
use sha2::{Digest, Sha256};

const ARGS: [&str; 3] = ["app-server", "--listen", "stdio://"];
const CREDENTIAL: &str = "auth.json";
const DRIVER: &str = "codex.app-server";
const PROTOCOL: &str = "codex.app-server/1";
const DUMMY: &[u8] = b"disposable credential fixture only\n";

struct Fixture {
    root: PathBuf,
    workspace: PathBuf,
    executable: PathBuf,
    pod_id: String,
    attempt_id: String,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "podbay-codex-resource-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let workspace = root.join("workspace");
        fs::create_dir(&workspace).unwrap();
        let executable = root.join("fake-app-server");
        fs::write(
            &executable,
            b"#!/bin/sh\nset -eu\n[ \"$1\" = app-server ]\n[ \"$2\" = --listen ]\n[ \"$3\" = stdio:// ]\n[ -r \"$CODEX_HOME/auth.json\" ]\n[ -z \"${UNREVIEWED_SECRET+x}\" ]\nread -r initialize\nprintf '%s\\n' \"$initialize\" > \"$CODEX_HOME/frames.log\"\nprintf '{\"id\":1,\"result\":{\"codexHome\":\"%s\",\"platformFamily\":\"unix\",\"platformOs\":\"linux\",\"userAgent\":\"fixture\"}}\\n' \"$CODEX_HOME\"\nread -r initialized\nprintf '%s\\n' \"$initialized\" >> \"$CODEX_HOME/frames.log\"\nsleep 15\n",
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let suffix = format!("{:x}", nonce & 0xffff_ffff_ffff);
        Self {
            root,
            workspace,
            executable,
            pod_id: format!("pod.fixture.{suffix}"),
            attempt_id: format!("attempt.fixture.{suffix}"),
        }
    }

    fn credential_directory(&self, unit: &str) -> PathBuf {
        let parent = self.root.join("credentials");
        fs::create_dir_all(&parent).unwrap();
        let directory = parent.join(unit);
        fs::create_dir(&directory).unwrap();
        let file = directory.join(CODEX_AUTH_CREDENTIAL_NAME);
        fs::write(&file, DUMMY).unwrap();
        fs::set_permissions(file, fs::Permissions::from_mode(0o400)).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
        directory
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Ok(entries) = fs::read_dir(self.root.join("credentials")) {
            for directory in entries.flatten().map(|entry| entry.path()) {
                let _ = fs::set_permissions(directory, fs::Permissions::from_mode(0o700));
            }
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct Admitted;
impl CommandAdmission for Admitted {
    fn admits_run(&self, _: &CommandId, _: &RunId, kind: RunCommandKind) -> bool {
        kind == RunCommandKind::Launch
    }
}

fn text(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn list(bytes: &mut Vec<u8>, values: &[&str]) {
    bytes.extend_from_slice(&(values.len() as u32).to_be_bytes());
    for value in values {
        text(bytes, value);
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
    text(&mut bytes, &fixture.pod_id);
    text(&mut bytes, "worker");
    bytes.push(0);
    text(&mut bytes, "podbay.codex.fixture");
    bytes.extend_from_slice(&1_u64.to_be_bytes());
    text(&mut bytes, fixture.executable.to_str().unwrap());
    text(&mut bytes, generation);
    list(&mut bytes, &ARGS);
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
    text(&mut bytes, CREDENTIAL);
    EffectiveLaunchContract::decode(&bytes).unwrap();
    bytes
}

fn launch_binding(fixture: &Fixture) -> LaunchBinding {
    let mut session = Session::new(
        SessionId::try_from("session.fixture").unwrap(),
        ActorId::try_from("actor.fixture").unwrap(),
        ScopeId::try_from("scope.fixture").unwrap(),
    );
    let mut run = Run::new(
        RunId::try_from("run.fixture").unwrap(),
        &session,
        Role::Worker,
        WorkKind::Task,
        None,
    );
    run.admit(
        run.revision(),
        &CommandId::try_from("command.fixture").unwrap(),
        &Admitted,
    )
    .unwrap();
    session.bind_run(session.revision(), &run).unwrap();
    let mut attempt = Attempt::new(
        AttemptId::try_from(fixture.attempt_id.as_str()).unwrap(),
        run.id().clone(),
        1,
        Epoch::new(1).unwrap(),
    )
    .unwrap();
    run.start_attempt(run.revision(), &attempt).unwrap();
    let mut pod = Pod::new(
        PodId::try_from(fixture.pod_id.as_str()).unwrap(),
        attempt.id().clone(),
        Epoch::new(1).unwrap(),
    );
    attempt.attach_pod(attempt.revision(), &pod).unwrap();
    let resource = Resource::new(
        ResourceId::try_from("resource.fixture").unwrap(),
        pod.id().clone(),
        ResourceKind::StructuredProvider,
        Epoch::new(1).unwrap(),
    );
    pod.attach_resource(pod.revision(), &resource).unwrap();
    LaunchBinding::from_aggregates(&session, &run, &attempt, &pod, &[resource]).unwrap()
}

fn binding(fixture: &Fixture) -> (LaunchDescriptor, BoundPeerManifest) {
    let binding = launch_binding(fixture);
    let sha = sha256_file(&fixture.executable);
    let generation = format!("sha256:{sha}");
    let scope = ScopeId::try_from("scope.fixture").unwrap();
    let policy =
        CodexAppServerPolicyV2::new(&scope, CREDENTIAL.into(), DRIVER.into(), PROTOCOL.into())
            .unwrap();
    let v1 = EffectiveLaunchContract::decode(&effective_bytes(fixture, &generation)).unwrap();
    let effective = EffectiveLaunchContractV2::from_v1(v1, policy.clone()).unwrap();
    let descriptor = ImmutableLaunchDescriptorV2::from_binding(
        &binding,
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
            arguments: ARGS.into_iter().map(str::to_owned).collect(),
            environment_refs: vec![],
            credential_refs: vec![CREDENTIAL.into()],
            wall_seconds: 60,
            max_children: 0,
            resources: vec![ReviewedResource {
                resource_id: ResourceId::try_from("resource.fixture").unwrap(),
                kind: ResourceKind::StructuredProvider,
                epoch: Epoch::new(1).unwrap(),
                driver: ResourceDriver::Structured {
                    driver_ref: DRIVER.into(),
                    protocol_ref: PROTOCOL.into(),
                },
            }],
        },
        policy,
    )
    .unwrap();
    let launch = LaunchDescriptor {
        protocol: "podbay-pod/1".into(),
        pod_id: fixture.pod_id.clone(),
        attempt_id: fixture.attempt_id.clone(),
        session_id: "session.fixture".into(),
        run_id: "run.fixture".into(),
        scope_id: "scope.fixture".into(),
        role: PodRole::Worker,
        incarnation: 1,
        resource_id: "resource.fixture".into(),
        executable: fixture.executable.clone(),
        args: ARGS.into_iter().map(str::to_owned).collect(),
        cwd: fixture.workspace.clone(),
        pty: None,
    };
    let manager = LinuxPeerEvidence::for_current_process().unwrap();
    let manager = manager.attested_peer();
    let mut peer = BoundPeerManifest {
        protocol: "podbay.peer-binding/2".into(),
        capability: "codex_app_server_v2".into(),
        wire_descriptor: descriptor.encode_json().unwrap(),
        effective_spec: effective.canonical_bytes().to_vec(),
        descriptor_digest: descriptor.digest().into(),
        effective_digest: effective.digest().into(),
        resource_epoch: 1,
        store_path: fixture.root.join("store.sqlite"),
        store_lineage: "lineage.fixture".into(),
        owner_epoch: 1,
        credential_epoch: 1,
        resource_input_epochs: BTreeMap::from([("resource.fixture".into(), 1)]),
        manager_os_identity: manager.os_identity().into(),
        manager_process_id: manager.native_process_id().into(),
        manager_boot_identity: manager.boot_identity().into(),
        manager_birth_identity: manager.birth_identity().into(),
        manager_containment: manager.containment_identity().into(),
        canonical_executable: fixture.executable.clone(),
        executable_sha256: sha,
        binding_digest: String::new(),
    };
    peer.binding_digest = peer.digest().unwrap();
    (launch, peer)
}

#[test]
fn outside_pod_unit_refuses_before_spawning_fake_app_server() {
    let fixture = Fixture::new();
    let (launch, peer) = binding(&fixture);
    let reviewed =
        ValidatedCodexResourceLaunch::from_peer_binding(&peer, &launch, &fixture.root).unwrap();
    let credentials = fixture.credential_directory(reviewed.expected_unit());
    let home = prepare_codex_home_from_systemd_credential(
        reviewed.expected_unit(),
        &fixture.root,
        &credentials,
    )
    .unwrap();
    let codex_home = home.codex_home().to_path_buf();
    assert!(matches!(
        PodCodexResource::spawn_initialized(reviewed, home),
        Err(PodError::Refused(
            "Codex child constructor is outside its pod unit"
        ))
    ));
    assert!(!codex_home.join("frames.log").exists());
}

/// Invoked only by the opt-in disposable transient-service fixture below.
#[test]
fn native_systemd_child_helper() {
    let Some(root) = std::env::var_os("PODBAY_CODEX_RESOURCE_FIXTURE") else {
        return;
    };
    let root = PathBuf::from(root);
    let launch: LaunchDescriptor =
        serde_json::from_slice(&fs::read(root.join("launch.json")).unwrap()).unwrap();
    let peer: BoundPeerManifest =
        serde_json::from_slice(&fs::read(root.join("peer.json")).unwrap()).unwrap();
    let reviewed = ValidatedCodexResourceLaunch::from_peer_binding(&peer, &launch, &root).unwrap();
    let expected_unit = reviewed.expected_unit().to_owned();
    let credentials = PathBuf::from(std::env::var_os("CREDENTIALS_DIRECTORY").unwrap());
    let home =
        prepare_codex_home_from_systemd_credential(reviewed.expected_unit(), &root, &credentials)
            .unwrap();
    let codex_home = home.codex_home().to_path_buf();
    let mut resource = PodCodexResource::spawn_initialized(reviewed, home).unwrap();
    let birth = resource.recheck_child().unwrap();
    assert_eq!(&birth, resource.child_birth());
    assert_eq!(resource.pid(), birth.pid);
    assert_eq!(resource.try_wait().unwrap(), None);
    assert!(birth.pid > 0 && birth.start_ticks > 0);
    assert_eq!(
        birth.cgroup_path.rsplit('/').next(),
        Some(expected_unit.as_str())
    );
    assert_eq!(
        birth.boot_id,
        fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .unwrap()
            .trim()
    );
    assert_eq!(resource.identity().resource_id.as_str(), "resource.fixture");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let frames = loop {
        let frames = fs::read_to_string(codex_home.join("frames.log")).unwrap_or_default();
        if frames.lines().count() == 2 {
            break frames;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "fake child did not record initialize frames"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    let lines = frames.lines().collect::<Vec<_>>();
    assert!(lines[0].contains("\"method\":\"initialize\""));
    assert!(lines[1].contains("\"method\":\"initialized\""));
    assert!(!frames.contains("turn/start"));
    resource.stop().unwrap();
    assert_eq!(resource.try_wait().unwrap(), Some(None));
    assert!(resource.recheck_child().is_err());
    resource.stop().unwrap();
}

/// Optional native proof: no Codex executable, account, model input or turn.
/// The unique user-systemd unit and dummy credential are disposable.
#[test]
#[ignore = "requires a running disposable user-systemd manager"]
fn native_systemd_fake_app_server_initializes_without_turn() {
    let fixture = Fixture::new();
    let (launch, peer) = binding(&fixture);
    let reviewed =
        ValidatedCodexResourceLaunch::from_peer_binding(&peer, &launch, &fixture.root).unwrap();
    let unit = reviewed.expected_unit().to_owned();
    let dummy = fixture.root.join("dummy-auth.json");
    fs::write(&dummy, DUMMY).unwrap();
    fs::set_permissions(&dummy, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(
        fixture.root.join("launch.json"),
        serde_json::to_vec(&launch).unwrap(),
    )
    .unwrap();
    fs::write(
        fixture.root.join("peer.json"),
        serde_json::to_vec(&peer).unwrap(),
    )
    .unwrap();
    let output = Command::new("systemd-run")
        .args([
            "--user",
            "--no-ask-password",
            "--wait",
            "--collect",
            "--service-type=exec",
        ])
        .arg(format!("--unit={unit}"))
        .arg(format!(
            "--property=LoadCredential=auth.json:{}",
            dummy.display()
        ))
        .arg("--property=RuntimeMaxSec=30s")
        .arg(format!(
            "--setenv=PODBAY_CODEX_RESOURCE_FIXTURE={}",
            fixture.root.display()
        ))
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "native_systemd_child_helper", "--nocapture"])
        .output()
        .unwrap();
    let _ = Command::new("systemctl")
        .args(["--user", "stop", &unit])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    assert!(
        output.status.success(),
        "disposable unit failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(fixture.root.join("home/codex/frames.log"))
            .unwrap()
            .lines()
            .count(),
        2
    );
}

#[test]
fn changed_credential_reference_refuses_before_child_spawn() {
    let fixture = Fixture::new();
    let (launch, peer) = binding(&fixture);
    let reviewed =
        ValidatedCodexResourceLaunch::from_peer_binding(&peer, &launch, &fixture.root).unwrap();
    let credentials = fixture.credential_directory(reviewed.expected_unit());
    let home = prepare_codex_home_from_systemd_credential(
        reviewed.expected_unit(),
        &fixture.root,
        &credentials,
    )
    .unwrap();
    fs::remove_file(home.credential_reference()).unwrap();
    symlink(
        fixture.root.join("wrong-auth.json"),
        home.credential_reference(),
    )
    .unwrap();
    let codex_home = home.codex_home().to_path_buf();
    assert!(matches!(
        PodCodexResource::spawn_initialized(reviewed, home),
        Err(PodError::Refused("Codex credential reference is stale"))
    ));
    assert!(!codex_home.join("frames.log").exists());
}
