#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_core::{
    ActorId, Attempt, AttemptId, CommandAdmission, CommandId, Epoch, LaunchBinding, Pod, PodId,
    Resource, ResourceId, ResourceKind, Role, Run, RunCommandKind, RunId, ScopeId, Session,
    SessionId, WorkKind,
};
use podbay_pod::{BoundPeerManifest, LaunchDescriptor, LinuxPeerEvidence, PodRole};
use podbay_wire::{
    CodexAppServerPolicyV2, EffectiveLaunchContract, EffectiveLaunchContractV2,
    ImmutableLaunchDescriptorV2, ResourceDriver, ReviewedNativePolicy, ReviewedResource, TargetOs,
};
use sha2::{Digest, Sha256};

const ARGS: [&str; 3] = ["app-server", "--listen", "stdio://"];
const CREDENTIAL: &str = "credential.fixture";
const DRIVER: &str = "codex.app-server";
const PROTOCOL: &str = "codex.app-server/1";

struct Fixture {
    root: PathBuf,
    workspace: PathBuf,
    executable: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("podbay-manifest-v2-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let workspace = root.join("workspace");
        fs::create_dir(&workspace).unwrap();
        let executable = root.join("codex-fixture");
        fs::write(&executable, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(fs::canonicalize(&executable).unwrap(), executable);
        assert_eq!(fs::canonicalize(&workspace).unwrap(), workspace);
        Self {
            root,
            workspace,
            executable,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
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
    let bytes = fs::read(path).unwrap();
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn v1_effective_bytes(executable: &Path, generation: &str) -> Vec<u8> {
    let mut bytes = b"podbay.effective-launch/1\0".to_vec();
    text(&mut bytes, "pod.fixture");
    text(&mut bytes, "worker");
    bytes.push(0); // no parent run
    text(&mut bytes, "podbay.codex.fixture");
    bytes.extend_from_slice(&1_u64.to_be_bytes());
    text(&mut bytes, executable.to_str().unwrap());
    text(&mut bytes, generation);
    list(&mut bytes, &ARGS);
    text(&mut bytes, "codex.fixture");
    text(&mut bytes, "medium");
    bytes.push(0); // no fallback
    text(&mut bytes, "scope.fixture");
    text(&mut bytes, "basis.fixture");
    text(&mut bytes, ".");
    bytes.push(1); // read-write workspace
    list(&mut bytes, &[]); // no tool bundles
    bytes.extend_from_slice(&1_u64.to_be_bytes()); // reviewed authority grant
    bytes.extend_from_slice(&60_u64.to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes()); // no child pods
    list(&mut bytes, &[]); // no environment references
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    text(&mut bytes, "scope.fixture");
    text(&mut bytes, CREDENTIAL); // locator only, never a credential value
    EffectiveLaunchContract::decode(&bytes).unwrap();
    bytes
}

fn launch_binding() -> LaunchBinding {
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
        ResourceKind::StructuredProvider,
        Epoch::new(1).unwrap(),
    );
    pod.attach_resource(pod.revision(), &resource).unwrap();
    LaunchBinding::from_aggregates(&session, &run, &attempt, &pod, &[resource]).unwrap()
}

#[derive(Clone)]
struct Case {
    launch: LaunchDescriptor,
    peer: BoundPeerManifest,
    binding: LaunchBinding,
    reviewed: ReviewedNativePolicy,
    policy: CodexAppServerPolicyV2,
}

fn case(fixture: &Fixture, executable: &Path, workspace: &Path) -> Case {
    let binding = launch_binding();
    let sha = sha256_file(executable);
    let generation = format!("sha256:{sha}");
    let scope = ScopeId::try_from("scope.fixture").unwrap();
    let policy =
        CodexAppServerPolicyV2::new(&scope, CREDENTIAL.into(), DRIVER.into(), PROTOCOL.into())
            .unwrap();
    let v1 = EffectiveLaunchContract::decode(&v1_effective_bytes(executable, &generation)).unwrap();
    let effective = EffectiveLaunchContractV2::from_v1(v1, policy.clone()).unwrap();
    let reviewed = ReviewedNativePolicy {
        target_os: TargetOs::Linux,
        host_id: "host.fixture".into(),
        profile_ref: "podbay.codex.fixture".into(),
        profile_generation: 1,
        model_id: "codex.fixture".into(),
        reasoning_effort: "medium".into(),
        executable_generation: generation,
        effective_spec_digest: effective.digest().into(),
        workspace_basis_ref: "basis.fixture".into(),
        executable: executable.to_str().unwrap().into(),
        cwd: workspace.to_str().unwrap().into(),
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
    };
    let descriptor =
        ImmutableLaunchDescriptorV2::from_binding(&binding, reviewed.clone(), policy.clone())
            .unwrap();
    let launch = LaunchDescriptor {
        protocol: "podbay-pod/1".into(),
        pod_id: "pod.fixture".into(),
        attempt_id: "attempt.fixture".into(),
        session_id: "session.fixture".into(),
        run_id: "run.fixture".into(),
        scope_id: "scope.fixture".into(),
        role: PodRole::Worker,
        incarnation: 1,
        resource_id: "resource.fixture".into(),
        executable: executable.into(),
        args: ARGS.into_iter().map(str::to_owned).collect(),
        cwd: workspace.into(),
        pty: None,
    };
    launch.validate().unwrap();
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
        authority_revision: Some(1),
        resource_input_epochs: BTreeMap::from([("resource.fixture".into(), 1)]),
        manager_os_identity: manager.os_identity().into(),
        manager_process_id: manager.native_process_id().into(),
        manager_boot_identity: manager.boot_identity().into(),
        manager_birth_identity: manager.birth_identity().into(),
        manager_containment: manager.containment_identity().into(),
        canonical_executable: executable.into(),
        executable_sha256: sha,
        binding_digest: String::new(),
    };
    peer.binding_digest = peer.digest().unwrap();
    Case {
        launch,
        peer,
        binding,
        reviewed,
        policy,
    }
}

fn set_descriptor(case: &mut Case, descriptor: ImmutableLaunchDescriptorV2) {
    case.peer.wire_descriptor = descriptor.encode_json().unwrap();
    case.peer.descriptor_digest = descriptor.digest().into();
    case.peer.binding_digest = case.peer.digest().unwrap();
}

#[test]
fn codex_v2_manifest_accepts_exact_typed_binding_without_launching() {
    let fixture = Fixture::new();
    let case = case(&fixture, &fixture.executable, &fixture.workspace);
    case.peer.validate(&case.launch, &fixture.root).unwrap();
    assert_eq!(
        fs::read(&fixture.executable).unwrap(),
        b"#!/bin/sh\nexit 0\n"
    );
    assert!(!fixture.root.join("store.sqlite").exists());
}

#[test]
fn codex_v2_manifest_requires_positive_revision_and_legacy_omits_field() {
    let fixture = Fixture::new();
    let baseline = case(&fixture, &fixture.executable, &fixture.workspace);
    assert_eq!(baseline.peer.authority_revision, Some(1));
    for revision in [None, Some(0)] {
        let mut changed = baseline.clone();
        changed.peer.authority_revision = revision;
        changed.peer.binding_digest = changed.peer.digest().unwrap();
        assert!(
            changed
                .peer
                .validate(&changed.launch, &fixture.root)
                .is_err()
        );
    }
    let mut legacy_shape = baseline.peer;
    legacy_shape.protocol = "podbay.peer-binding/1".into();
    legacy_shape.capability = "synthetic_fixture_only".into();
    legacy_shape.authority_revision = None;
    let json = serde_json::to_vec(&legacy_shape).unwrap();
    assert!(
        !json
            .windows(b"authority_revision".len())
            .any(|window| { window == b"authority_revision" })
    );
}

#[test]
fn codex_v2_manifest_refuses_capability_digest_role_driver_and_credential_changes() {
    let fixture = Fixture::new();
    let baseline = case(&fixture, &fixture.executable, &fixture.workspace);

    let mut changed = baseline.clone();
    changed.peer.capability = "synthetic_fixture_only".into();
    changed.peer.binding_digest = changed.peer.digest().unwrap();
    assert!(
        changed
            .peer
            .validate(&changed.launch, &fixture.root)
            .is_err()
    );

    for digest in ["descriptor", "effective"] {
        let mut changed = baseline.clone();
        if digest == "descriptor" {
            changed.peer.descriptor_digest = "0".repeat(64);
        } else {
            changed.peer.effective_digest = "0".repeat(64);
        }
        changed.peer.binding_digest = changed.peer.digest().unwrap();
        assert!(
            changed
                .peer
                .validate(&changed.launch, &fixture.root)
                .is_err()
        );
    }

    let mut changed = baseline.clone();
    changed.launch.role = PodRole::Coordinator;
    assert!(
        changed
            .peer
            .validate(&changed.launch, &fixture.root)
            .is_err()
    );

    let mut changed = baseline.clone();
    let scope = ScopeId::try_from("scope.fixture").unwrap();
    changed.policy = CodexAppServerPolicyV2::new(
        &scope,
        CREDENTIAL.into(),
        "codex.other-driver".into(),
        PROTOCOL.into(),
    )
    .unwrap();
    changed.reviewed.resources[0].driver = ResourceDriver::Structured {
        driver_ref: "codex.other-driver".into(),
        protocol_ref: PROTOCOL.into(),
    };
    let descriptor = ImmutableLaunchDescriptorV2::from_binding(
        &changed.binding,
        changed.reviewed.clone(),
        changed.policy.clone(),
    )
    .unwrap();
    set_descriptor(&mut changed, descriptor);
    assert!(
        changed
            .peer
            .validate(&changed.launch, &fixture.root)
            .is_err()
    );

    let mut changed = baseline.clone();
    changed.policy = CodexAppServerPolicyV2::new(
        &scope,
        "credential.other".into(),
        DRIVER.into(),
        PROTOCOL.into(),
    )
    .unwrap();
    changed.reviewed.credential_refs = vec!["credential.other".into()];
    let descriptor = ImmutableLaunchDescriptorV2::from_binding(
        &changed.binding,
        changed.reviewed.clone(),
        changed.policy.clone(),
    )
    .unwrap();
    set_descriptor(&mut changed, descriptor);
    assert!(
        changed
            .peer
            .validate(&changed.launch, &fixture.root)
            .is_err()
    );
}

#[test]
fn codex_v2_manifest_refuses_symlink_workspace_and_executable_paths() {
    let fixture = Fixture::new();
    let baseline = case(&fixture, &fixture.executable, &fixture.workspace);
    let workspace_alias = fixture.root.join("workspace-alias");
    symlink(&fixture.workspace, &workspace_alias).unwrap();
    let mut changed = baseline.clone();
    changed.launch.cwd = workspace_alias.clone();
    changed.reviewed.cwd = workspace_alias.to_str().unwrap().into();
    let descriptor = ImmutableLaunchDescriptorV2::from_binding(
        &changed.binding,
        changed.reviewed.clone(),
        changed.policy.clone(),
    )
    .unwrap();
    set_descriptor(&mut changed, descriptor);
    assert!(
        changed
            .peer
            .validate(&changed.launch, &fixture.root)
            .is_err()
    );

    let executable_alias = fixture.root.join("codex-alias");
    symlink(&fixture.executable, &executable_alias).unwrap();
    let changed = case(&fixture, &executable_alias, &fixture.workspace);
    assert!(
        changed
            .peer
            .validate(&changed.launch, &fixture.root)
            .is_err()
    );
}
