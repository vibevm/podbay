#![cfg(target_os = "linux")]
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use podbay_core::{
    ActorId, Attempt, AttemptId, CommandAdmission, CommandId, Epoch, LaunchBinding, Pod, PodId,
    Resource, ResourceId, ResourceKind, Role, Run, RunCommandKind, RunId, ScopeId, Session,
    SessionId, WorkKind,
};
use podbay_pod::{
    LaunchDescriptor, LinuxPeerEvidence, PodError, PodManifest, PodPeerBootstrap, PodRole, launch,
    launch_bound,
};
use podbay_store::{
    BoundLaunchAdmission, BoundLaunchProposal, BoundLaunchRequest, PodBayStore, VerifiedPrincipal,
};
use podbay_wire::{
    EffectiveLaunchContract, ImmutableLaunchDescriptor, ResourceDriver, ReviewedNativePolicy,
    ReviewedResource, TargetOs,
};
use sha2::{Digest, Sha256};

struct Fixture {
    directory: PathBuf,
    database: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("podbay-bound-peer-{}-{stamp}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            database: directory.join("store.sqlite"),
            directory,
        }
    }
    fn sleep_path_and_sha(&self) -> (PathBuf, String) {
        let output = Command::new("sh")
            .args(["-c", "command -v sleep"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        let canonical = fs::canonicalize(text.trim()).unwrap();
        let mut file = File::open(&canonical).unwrap();
        let mut hash = Sha256::new();
        let mut bytes = [0u8; 8192];
        loop {
            let count = file.read(&mut bytes).unwrap();
            if count == 0 {
                break;
            }
            hash.update(&bytes[..count]);
        }
        let sha = hash
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        (canonical, sha)
    }
    fn manifest_path(&self) -> PathBuf {
        let manifests = fs::read_dir(&self.directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .collect::<Vec<_>>();
        assert_eq!(manifests.len(), 1);
        manifests[0].clone()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Ok(entries) = fs::read_dir(&self.directory) {
            for path in entries.flatten().map(|entry| entry.path()) {
                if path.extension().is_some_and(|ext| ext == "json") {
                    if let Ok(bytes) = fs::read(&path) {
                        if let Ok(manifest) = serde_json::from_slice::<PodManifest>(&bytes) {
                            let _ = Command::new("systemctl")
                                .args(["--user", "stop", &manifest.unit_name])
                                .stdout(Stdio::null())
                                .stderr(Stdio::null())
                                .status();
                        }
                    }
                }
            }
        }
        let _ = fs::remove_dir_all(&self.directory);
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
fn effective_bytes(executable: &str, generation: &str) -> Vec<u8> {
    let mut bytes = b"podbay.effective-launch/1\0".to_vec();
    text(&mut bytes, "pod.fixture");
    text(&mut bytes, "worker");
    bytes.push(0);
    text(&mut bytes, "podbay.fixture.process.exec");
    bytes.extend_from_slice(&1u64.to_be_bytes());
    text(&mut bytes, executable);
    text(&mut bytes, generation);
    list(&mut bytes, &["60"]);
    text(&mut bytes, "none");
    text(&mut bytes, "none");
    bytes.push(0);
    text(&mut bytes, "scope.fixture");
    text(&mut bytes, "basis.fixture");
    text(&mut bytes, ".");
    bytes.push(1);
    list(&mut bytes, &[]);
    bytes.extend_from_slice(&1u64.to_be_bytes());
    bytes.extend_from_slice(&60u64.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    list(&mut bytes, &[]);
    bytes.extend_from_slice(&0u32.to_be_bytes());
    EffectiveLaunchContract::decode(&bytes).unwrap();
    bytes
}
fn bound_record(fixture: &Fixture) -> (podbay_store::BoundLaunchRecord, PodPeerBootstrap) {
    let (sleep, sha) = fixture.sleep_path_and_sha();
    let executable = sleep.to_str().unwrap();
    let generation = format!("sha256:{sha}");
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
        AttemptId::try_from("attempt.fixture").unwrap(),
        run.id().clone(),
        1,
        Epoch::new(1).unwrap(),
    )
    .unwrap();
    run.start_attempt(run.revision(), &attempt).unwrap();
    let mut pod = Pod::new(
        PodId::try_from("pod.fixture").unwrap(),
        attempt.id().clone(),
        Epoch::new(1).unwrap(),
    );
    attempt.attach_pod(attempt.revision(), &pod).unwrap();
    let resource = Resource::new(
        ResourceId::try_from("resource.fixture").unwrap(),
        pod.id().clone(),
        ResourceKind::Auxiliary,
        Epoch::new(1).unwrap(),
    );
    pod.attach_resource(pod.revision(), &resource).unwrap();
    let binding =
        LaunchBinding::from_aggregates(&session, &run, &attempt, &pod, &[resource.clone()])
            .unwrap();
    let effective = effective_bytes(executable, &generation);
    let digest = EffectiveLaunchContract::decode(&effective)
        .unwrap()
        .digest()
        .to_owned();
    let descriptor = ImmutableLaunchDescriptor::from_binding(
        &binding,
        ReviewedNativePolicy {
            target_os: TargetOs::Linux,
            host_id: "host.fixture".into(),
            profile_ref: "podbay.fixture.process.exec".into(),
            profile_generation: 1,
            model_id: "none".into(),
            reasoning_effort: "none".into(),
            executable_generation: generation,
            effective_spec_digest: digest,
            workspace_basis_ref: "basis.fixture".into(),
            executable: executable.into(),
            cwd: fixture.directory.to_str().unwrap().into(),
            arguments: vec!["60".into()],
            environment_refs: vec![],
            credential_refs: vec![],
            wall_seconds: 60,
            max_children: 0,
            resources: vec![ReviewedResource {
                resource_id: resource.id().clone(),
                kind: ResourceKind::Auxiliary,
                epoch: resource.epoch(),
                driver: ResourceDriver::Auxiliary {
                    driver_ref: "process.exec".into(),
                },
            }],
        },
    )
    .unwrap();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    store.advance_owner_epoch(0, 1).unwrap();
    let record = match store
        .admit_bound_launch(BoundLaunchRequest {
            principal: VerifiedPrincipal::from_authenticated_boundary("principal.fixture").unwrap(),
            command_key: "key.fixture",
            canonical_intent: b"caller.intent",
            scope_id: "scope.fixture",
            pod_id: "pod.fixture",
            proposal: Some(BoundLaunchProposal {
                session: &session,
                run: &run,
                binding: &binding,
                effective_spec: &effective,
                descriptor: &descriptor,
                expected_owner_epoch: 1,
                expected_authority_revision: 0,
            }),
        })
        .unwrap()
    {
        BoundLaunchAdmission::Committed(record) => record,
        other => panic!("{other:?}"),
    };
    let lineage = store.initial_cursor("scope.fixture").unwrap().store_lineage;
    let bootstrap = PodPeerBootstrap {
        store_path: fixture.database.clone(),
        store_lineage: lineage,
        owner_epoch: 1,
        credential_epoch: 1,
        resource_input_epochs: BTreeMap::from([("resource.fixture".into(), 1)]),
        canonical_executable: sleep,
        executable_sha256: sha,
        expected_manager_peer: LinuxPeerEvidence::for_current_process()
            .unwrap()
            .attested_peer()
            .clone(),
    };
    (record, bootstrap)
}

#[test]
fn unbound_legacy_launch_refuses_before_manifest_or_child() {
    let fixture = Fixture::new();
    let descriptor = LaunchDescriptor {
        protocol: "podbay-pod/1".into(),
        pod_id: "pod.fixture".into(),
        attempt_id: "attempt.fixture".into(),
        session_id: "session.fixture".into(),
        run_id: "run.fixture".into(),
        scope_id: "scope.fixture".into(),
        role: PodRole::Worker,
        incarnation: 1,
        resource_id: "resource.fixture".into(),
        executable: "/bin/sleep".into(),
        args: vec!["60".into()],
        cwd: fixture.directory.clone(),
        pty: None,
    };
    assert!(matches!(
        launch(descriptor, &fixture.directory, Path::new("/bin/false")),
        Err(PodError::Unsupported("unbound pod launch is retired"))
    ));
    assert!(fs::read_dir(&fixture.directory).unwrap().next().is_none());
}

#[test]
#[ignore = "requires disposable user systemd and Linux peer evidence"]
fn bound_synthetic_unit_pins_peer_and_refuses_copied_sibling_bearer() {
    assert_eq!(std::env::var("PODBAY_TEST_SYSTEMD").as_deref(), Ok("1"));
    let fixture = Fixture::new();
    let (record, bootstrap) = bound_record(&fixture);
    let expected_descriptor = ImmutableLaunchDescriptor::decode_json(&record.descriptor).unwrap();
    let client = launch_bound(
        record,
        bootstrap,
        &fixture.directory,
        PathBuf::from(env!("CARGO_BIN_EXE_podbay-pod")),
    )
    .unwrap();
    let bound = client.bound_status().unwrap();
    assert_eq!(bound.capability, "synthetic_fixture_only");
    assert_eq!(bound.descriptor_digest, expected_descriptor.digest());
    assert_eq!(
        bound.effective_digest,
        expected_descriptor.effective_spec_digest()
    );
    assert_eq!(bound.resource_epoch, 1);
    let status = client.status().unwrap();
    assert!(status.child_running && status.child.start_identity.is_some());
    let manifest: PodManifest =
        serde_json::from_slice(&fs::read(fixture.manifest_path()).unwrap()).unwrap();
    let task_limit = Command::new("systemctl")
        .args([
            "--user",
            "show",
            &manifest.unit_name,
            "-p",
            "TasksMax",
            "--value",
        ])
        .output()
        .unwrap();
    assert!(task_limit.status.success());
    assert_eq!(String::from_utf8_lossy(&task_limit.stdout).trim(), "2");
    let runtime_limit = Command::new("systemctl")
        .args([
            "--user",
            "show",
            &manifest.unit_name,
            "-p",
            "RuntimeMaxUSec",
            "--value",
        ])
        .output()
        .unwrap();
    assert!(runtime_limit.status.success());
    assert!(matches!(
        String::from_utf8_lossy(&runtime_limit.stdout).trim(),
        "1min" | "60000000"
    ));
    let script = fixture.directory.join("sibling_probe.py");
    fs::write(
        &script,
        r#"import json,socket,struct,sys,time
manifest=json.load(open(sys.argv[1]))
result=sys.argv[2]
endpoint=manifest['socket_path']
base={'protocol':manifest['descriptor']['protocol'],
      'pod_id':manifest['descriptor']['pod_id'],
      'attempt_id':manifest['descriptor']['attempt_id'],
      'incarnation':manifest['descriptor']['incarnation'],
      'token':manifest['token']}
def connect():
    sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    sock.settimeout(4)
    sock.connect(endpoint)
    return sock
stall=connect()
time.sleep(2.5)
stall.close()
reset=connect()
reset.sendall(json.dumps(dict(base,operation='status')).encode())
reset.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0))
reset.close()
responses=[]
for operation in ('status','stop','terminal'):
    command=None
    if operation=='terminal':
        command={'kind':'write','command_id':'sibling.write',
                 'resource_id':manifest['descriptor']['resource_id'],
                 'incarnation':manifest['descriptor']['incarnation'],
                 'actor_id':'actor.sibling','lease_id':'lease.sibling',
                 'epoch':1,'bytes':[65]}
    request=dict(base,operation=operation,terminal=command)
    sock=connect()
    sock.sendall(json.dumps(request).encode())
    sock.shutdown(socket.SHUT_WR)
    chunks=[]
    while True:
        chunk=sock.recv(65536)
        if not chunk: break
        chunks.append(chunk)
    sock.close()
    response=json.loads(b''.join(chunks))
    responses.append({'ok':response.get('ok'),'status':response.get('status')})
json.dump(responses,open(result,'w'))
"#,
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o600)).unwrap();
    let python = Command::new("sh")
        .args(["-c", "command -v python3"])
        .output()
        .unwrap();
    assert!(python.status.success());
    let python = fs::canonicalize(String::from_utf8(python.stdout).unwrap().trim()).unwrap();
    let response_path = fixture.directory.join("sibling-results.json");
    let sibling_unit = format!(
        "podbay-sibling-{}-{}.service",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let sibling = Command::new("systemd-run")
        .args([
            "--user",
            "--no-ask-password",
            "--wait",
            "--collect",
            "--service-type=exec",
        ])
        .arg(format!("--unit={sibling_unit}"))
        .arg(python)
        .arg(script)
        .arg(fixture.manifest_path())
        .arg(&response_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(sibling.success(), "separate sibling unit failed");
    let responses: serde_json::Value =
        serde_json::from_slice(&fs::read(response_path).unwrap()).unwrap();
    let responses = responses.as_array().unwrap();
    assert_eq!(responses.len(), 3);
    assert!(
        responses
            .iter()
            .all(|response| response["ok"] == false && response["status"].is_null())
    );
    let after_sibling = client.status().unwrap();
    assert_eq!(after_sibling.child.native_id, status.child.native_id);
    assert_eq!(
        after_sibling.child.start_identity,
        status.child.start_identity
    );
    assert!(after_sibling.child_running);
    PodBayStore::open(&fixture.database)
        .unwrap()
        .begin_authority_replay(1, 2)
        .unwrap();
    assert!(matches!(client.status(), Err(PodError::Refused(_))));
    assert!(
        fs::metadata(format!("/proc/{}", status.child.native_id)).is_ok(),
        "owner replay must hold controls without killing the child"
    );
    drop(client);
    std::thread::sleep(Duration::from_millis(100));
    assert!(fs::metadata(format!("/proc/{}", status.child.native_id)).is_ok());
}
