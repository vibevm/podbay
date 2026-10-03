use podbay_core::{
    ActorId, Attempt, AttemptId, CommandAdmission, CommandId, Epoch, LaunchBinding, Pod, PodId,
    Resource, ResourceId, ResourceKind, Role, Run, RunCommandKind, RunId, ScopeId, Session,
    SessionId, WorkKind,
};
use podbay_wire::{
    ImmutableLaunchDescriptor, LaunchDescriptorError, ResourceDriver, ReviewedNativePolicy,
    ReviewedResource, TargetOs,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

struct Admitted;
impl CommandAdmission for Admitted {
    fn admits_run(&self, _: &CommandId, _: &RunId, kind: RunCommandKind) -> bool {
        kind == RunCommandKind::Launch
    }
}

fn binding(role: Role, work: WorkKind) -> LaunchBinding {
    let mut session = Session::new(
        SessionId::try_from("session.descriptor.fixture").unwrap(),
        ActorId::try_from("actor.descriptor.fixture").unwrap(),
        ScopeId::try_from("scope.descriptor.fixture").unwrap(),
    );
    let mut run = Run::new(
        RunId::try_from("run.descriptor.fixture").unwrap(),
        &session,
        role,
        work,
        Some(RunId::try_from("run.parent.fixture").unwrap()),
    );
    run.admit(
        run.revision(),
        &CommandId::try_from("command.fixture").unwrap(),
        &Admitted,
    )
    .unwrap();
    session.bind_run(session.revision(), &run).unwrap();
    let mut attempt = Attempt::new(
        AttemptId::try_from("attempt.descriptor.fixture").unwrap(),
        run.id().clone(),
        1,
        Epoch::new(5).unwrap(),
    )
    .unwrap();
    run.start_attempt(run.revision(), &attempt).unwrap();
    let mut pod = Pod::new(
        PodId::try_from("pod.descriptor.fixture").unwrap(),
        attempt.id().clone(),
        Epoch::new(7).unwrap(),
    );
    attempt.attach_pod(attempt.revision(), &pod).unwrap();
    let resources = vec![
        Resource::new(
            ResourceId::try_from("resource.pty.fixture").unwrap(),
            pod.id().clone(),
            ResourceKind::Pty,
            Epoch::new(11).unwrap(),
        ),
        Resource::new(
            ResourceId::try_from("resource.structured.fixture").unwrap(),
            pod.id().clone(),
            ResourceKind::StructuredProvider,
            Epoch::new(9_007_199_254_740_993).unwrap(),
        ),
    ];
    for resource in &resources {
        pod.attach_resource(pod.revision(), resource).unwrap();
    }
    LaunchBinding::from_aggregates(&session, &run, &attempt, &pod, &resources).unwrap()
}

fn policy(binding: &LaunchBinding, os: TargetOs) -> ReviewedNativePolicy {
    let (executable, cwd) = match os {
        TargetOs::Linux => ("/opt/podbay/bin/agent", "/work/tree"),
        TargetOs::Macos => ("/Applications/PodBay/agent", "/Users/dev/work"),
        TargetOs::Windows => (r"C:\work\agent.exe", r"C:\work"),
    };
    ReviewedNativePolicy {
        target_os: os,
        host_id: "host.fixture".into(),
        profile_ref: "profile.fixture".into(),
        profile_generation: 4,
        model_id: "model.fixture".into(),
        reasoning_effort: "effort.high".into(),
        executable_generation: "binary.gen.4".into(),
        effective_spec_digest: "a".repeat(64),
        workspace_basis_ref: "basis.fixture".into(),
        executable: executable.into(),
        cwd: cwd.into(),
        arguments: vec!["--profile".into(), "review".into()],
        environment_refs: vec!["env.profile".into()],
        credential_refs: vec!["vault.credential".into()],
        wall_seconds: 3600,
        max_children: 2,
        resources: binding
            .resources()
            .iter()
            .map(|resource| ReviewedResource {
                resource_id: resource.id().clone(),
                kind: resource.kind(),
                epoch: resource.epoch(),
                driver: match resource.kind() {
                    ResourceKind::Pty => ResourceDriver::Pty {
                        rows: 32,
                        columns: 120,
                        retention_events: 2000,
                    },
                    ResourceKind::StructuredProvider => ResourceDriver::Structured {
                        driver_ref: "driver.native.fixture".into(),
                        protocol_ref: "protocol.native.fixture".into(),
                    },
                    ResourceKind::Auxiliary => ResourceDriver::Auxiliary {
                        driver_ref: "driver.aux.fixture".into(),
                    },
                },
            })
            .collect(),
    }
}

fn forged_with_new_digest(encoded: &[u8], original_digest: &str, old: &str, new: &str) -> Vec<u8> {
    let text = String::from_utf8(encoded.to_vec()).unwrap();
    let changed = text.replacen(old, new, 1);
    assert_ne!(changed, text, "forge target absent");
    let marker = "\"descriptor\":";
    let body_start = changed.find(marker).unwrap() + marker.len();
    let body = &changed.as_bytes()[body_start..changed.len() - 1];
    let mut hash = Sha256::new();
    hash.update(b"podbay.launch-descriptor/1\0");
    hash.update(body);
    let digest: String = hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    changed.replacen(original_digest, &digest, 1).into_bytes()
}

#[test]
fn coordinator_and_worker_share_the_constructor_and_round_trip_two_resources() {
    for (role, work) in [
        (Role::Coordinator, WorkKind::Service),
        (Role::Worker, WorkKind::Task),
    ] {
        let binding = binding(role, work);
        let descriptor =
            ImmutableLaunchDescriptor::from_binding(&binding, policy(&binding, TargetOs::Linux))
                .unwrap();
        assert_eq!(descriptor.resources_len(), 2);
        assert_eq!(
            descriptor.resource_id(1),
            Some("resource.structured.fixture")
        );
        assert_eq!(descriptor.resource(1).unwrap().epoch, 9_007_199_254_740_993);
        assert_eq!(descriptor.attempt_epoch(), 5);
        assert_eq!(descriptor.pod_incarnation(), 7);
        assert_eq!(descriptor.effective_spec_digest(), "a".repeat(64));
        let encoded = descriptor.encode_json().unwrap();
        let decoded =
            ImmutableLaunchDescriptor::decode_for_binding(&encoded, &binding, &"a".repeat(64))
                .unwrap();
        assert_eq!(decoded, descriptor);
        assert_eq!(decoded.encode_json().unwrap(), encoded);
        assert_eq!(decoded.digest(), descriptor.digest());
        let raw: Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(
            raw["descriptor"]["resources"][1]["epoch"],
            "9007199254740993"
        );
        assert_eq!(
            raw["descriptor"]["role"],
            if role == Role::Coordinator {
                "coordinator"
            } else {
                "worker"
            }
        );
        assert_eq!(raw["descriptor"]["parentRunId"], "run.parent.fixture");
    }
}

#[test]
fn missing_reordered_or_wrong_epoch_resource_policy_refuses_before_encoding() {
    let binding = binding(Role::Worker, WorkKind::Task);
    let mut missing = policy(&binding, TargetOs::Linux);
    missing.resources.pop();
    assert_eq!(
        ImmutableLaunchDescriptor::from_binding(&binding, missing),
        Err(LaunchDescriptorError::ResourceMismatch)
    );
    let mut reordered = policy(&binding, TargetOs::Linux);
    reordered.resources.swap(0, 1);
    assert_eq!(
        ImmutableLaunchDescriptor::from_binding(&binding, reordered),
        Err(LaunchDescriptorError::ResourceMismatch)
    );
    let mut stale = policy(&binding, TargetOs::Linux);
    stale.resources[1].epoch = Epoch::new(12).unwrap();
    assert_eq!(
        ImmutableLaunchDescriptor::from_binding(&binding, stale),
        Err(LaunchDescriptorError::ResourceMismatch)
    );
}

#[test]
fn canonical_forgery_cannot_bypass_binding_or_inventory() {
    let binding = binding(Role::Coordinator, WorkKind::Service);
    let descriptor =
        ImmutableLaunchDescriptor::from_binding(&binding, policy(&binding, TargetOs::Linux))
            .unwrap();
    let encoded = descriptor.encode_json().unwrap();
    let duplicate = forged_with_new_digest(
        &encoded,
        descriptor.digest(),
        "resource.structured.fixture",
        "resource.pty.fixture",
    );
    assert_eq!(
        ImmutableLaunchDescriptor::decode_json(&duplicate),
        Err(LaunchDescriptorError::InvalidField("duplicate resourceId"))
    );
    let wrong_epoch = forged_with_new_digest(
        &encoded,
        descriptor.digest(),
        "9007199254740993",
        "9007199254740994",
    );
    let decoded = ImmutableLaunchDescriptor::decode_json(&wrong_epoch).unwrap();
    assert_eq!(
        decoded.validate_against_binding(&binding),
        Err(LaunchDescriptorError::ResourceMismatch)
    );
    assert_eq!(
        ImmutableLaunchDescriptor::decode_for_binding(&wrong_epoch, &binding, &"a".repeat(64)),
        Err(LaunchDescriptorError::ResourceMismatch)
    );
    let wrong_pod = forged_with_new_digest(
        &encoded,
        descriptor.digest(),
        "pod.descriptor.fixture",
        "pod.other.fixture",
    );
    let decoded = ImmutableLaunchDescriptor::decode_json(&wrong_pod).unwrap();
    assert_eq!(
        decoded.validate_against_binding(&binding),
        Err(LaunchDescriptorError::BindingMismatch)
    );
    assert_eq!(
        ImmutableLaunchDescriptor::decode_for_binding(&encoded, &binding, &"b".repeat(64)),
        Err(LaunchDescriptorError::DigestMismatch)
    );
}

#[test]
fn reviewed_policy_changes_digest_and_malformed_unknown_or_noncanonical_input_refuses() {
    let binding = binding(Role::Worker, WorkKind::Task);
    let original =
        ImmutableLaunchDescriptor::from_binding(&binding, policy(&binding, TargetOs::Linux))
            .unwrap();
    let mut changed = policy(&binding, TargetOs::Linux);
    changed.model_id = "model.other".into();
    let changed = ImmutableLaunchDescriptor::from_binding(&binding, changed).unwrap();
    assert_ne!(original.digest(), changed.digest());
    let encoded = String::from_utf8(original.encode_json().unwrap()).unwrap();
    assert_eq!(
        ImmutableLaunchDescriptor::decode_json(format!("{encoded} ").as_bytes()),
        Err(LaunchDescriptorError::NonCanonical)
    );
    assert_eq!(
        ImmutableLaunchDescriptor::decode_json(
            encoded
                .replacen("\"targetOs\"", "\"unknown\":1,\"targetOs\"", 1)
                .as_bytes()
        ),
        Err(LaunchDescriptorError::Malformed)
    );
    let unknown_driver = encoded.replacen(
        "\"retentionEvents\":2000}",
        "\"retentionEvents\":2000,\"future\":1}",
        1,
    );
    assert_ne!(unknown_driver, encoded);
    assert_eq!(
        ImmutableLaunchDescriptor::decode_json(unknown_driver.as_bytes()),
        Err(LaunchDescriptorError::Malformed)
    );
    assert_eq!(
        ImmutableLaunchDescriptor::decode_json(
            encoded
                .replacen("\"attemptEpoch\":\"5\"", "\"attemptEpoch\":5", 1)
                .as_bytes()
        ),
        Err(LaunchDescriptorError::Malformed)
    );
    assert_eq!(
        ImmutableLaunchDescriptor::decode_json(
            encoded
                .replacen(
                    "podbay.launch-descriptor/1",
                    "podbay.launch-descriptor/2",
                    1
                )
                .as_bytes()
        ),
        Err(LaunchDescriptorError::UnsupportedVersion)
    );
}

#[test]
fn target_os_paths_are_checked_without_host_path_semantics() {
    let binding = binding(Role::Worker, WorkKind::Task);
    let windows = policy(&binding, TargetOs::Windows);
    assert!(ImmutableLaunchDescriptor::from_binding(&binding, windows.clone()).is_ok());
    let mut unc = windows.clone();
    unc.executable = r"\\server\share\agent.exe".into();
    unc.cwd = r"\\server\share\work".into();
    assert!(ImmutableLaunchDescriptor::from_binding(&binding, unc).is_ok());
    for wrong in [
        r"C:relative",
        r"\work",
        "C:\\bad\0name",
        r"c:\work\agent.exe",
    ] {
        let mut input = windows.clone();
        input.executable = wrong.into();
        assert_eq!(
            ImmutableLaunchDescriptor::from_binding(&binding, input),
            Err(LaunchDescriptorError::InvalidField("native path"))
        );
    }
    let mut posix = policy(&binding, TargetOs::Linux);
    assert!(ImmutableLaunchDescriptor::from_binding(&binding, posix.clone()).is_ok());
    posix.executable = "opt/podbay/agent".into();
    assert_eq!(
        ImmutableLaunchDescriptor::from_binding(&binding, posix),
        Err(LaunchDescriptorError::InvalidField("native path"))
    );
    let mac = policy(&binding, TargetOs::Macos);
    assert!(ImmutableLaunchDescriptor::from_binding(&binding, mac).is_ok());
}
