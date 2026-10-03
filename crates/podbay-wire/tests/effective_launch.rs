use podbay_core::{
    ActorId, Attempt, AttemptId, CommandAdmission, CommandId, Epoch, LaunchBinding, Pod, PodId,
    Resource, ResourceId, ResourceKind, Role, Run, RunCommandKind, RunId, ScopeId, Session,
    SessionId, WorkKind,
};
use podbay_wire::{
    EffectiveLaunchContract, EffectiveLaunchError, EffectiveWorkspaceAccess,
    ImmutableLaunchDescriptor, ResourceDriver, ReviewedNativePolicy, ReviewedResource, TargetOs,
};

/// Exact PB09b field order and fixture values from host launch_pod.rs, with
/// one selected vault locator. No secret value is present in these bytes.
fn golden() -> Vec<u8> {
    let hex = include_str!("effective_launch_v1.hex")
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    hex.chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

struct Admitted;
impl CommandAdmission for Admitted {
    fn admits_run(&self, _: &CommandId, _: &RunId, kind: RunCommandKind) -> bool {
        kind == RunCommandKind::Launch
    }
}
fn binding() -> LaunchBinding {
    let mut session = Session::new(
        SessionId::try_from("session.fixture").unwrap(),
        ActorId::try_from("actor.fixture").unwrap(),
        ScopeId::try_from("scope.launch").unwrap(),
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
        PodId::try_from("pod.launch").unwrap(),
        attempt.id().clone(),
        Epoch::new(1).unwrap(),
    );
    attempt.attach_pod(attempt.revision(), &pod).unwrap();
    let resource = Resource::new(
        ResourceId::try_from("resource.fixture").unwrap(),
        pod.id().clone(),
        ResourceKind::Pty,
        Epoch::new(1).unwrap(),
    );
    pod.attach_resource(pod.revision(), &resource).unwrap();
    LaunchBinding::from_aggregates(&session, &run, &attempt, &pod, &[resource]).unwrap()
}
fn policy(binding: &LaunchBinding, digest: &str) -> ReviewedNativePolicy {
    ReviewedNativePolicy {
        target_os: TargetOs::Linux,
        host_id: "host.fixture".into(),
        profile_ref: "profile.fixture".into(),
        profile_generation: 1,
        model_id: "model.alpha".into(),
        reasoning_effort: "medium".into(),
        executable_generation: "sha256.fakegeneration1".into(),
        effective_spec_digest: digest.into(),
        workspace_basis_ref: "basis.commit.one".into(),
        executable: "/opt/podbay/bin/fake-agent".into(),
        cwd: "/work/src".into(),
        arguments: vec!["--managed".into(), "--safe".into()],
        environment_refs: vec!["env.clean".into()],
        credential_refs: vec!["vault.allowed.one".into()],
        wall_seconds: 60,
        max_children: 2,
        resources: vec![ReviewedResource {
            resource_id: binding.resources()[0].id().clone(),
            kind: ResourceKind::Pty,
            epoch: binding.resources()[0].epoch(),
            driver: ResourceDriver::Pty {
                rows: 24,
                columns: 80,
                retention_events: 100,
            },
        }],
    }
}

#[test]
fn exact_golden_decodes_and_reencodes_with_typed_fields() {
    let bytes = golden();
    let decoded = EffectiveLaunchContract::decode(&bytes).unwrap();
    assert_eq!(decoded.canonical_bytes(), bytes);
    assert_eq!(decoded.reencode(), bytes);
    assert_eq!(decoded.pod_id().as_str(), "pod.launch");
    assert_eq!(decoded.profile_generation(), 1);
    assert_eq!(decoded.arguments(), &["--managed", "--safe"]);
    assert_eq!(decoded.workspace_scope().as_str(), "scope.launch");
    assert_eq!(decoded.relative_cwd(), "src");
    assert_eq!(
        decoded.workspace_access(),
        EffectiveWorkspaceAccess::ReadWrite
    );
    assert_eq!(decoded.tool_bundle_refs(), &["tools.base"]);
    assert_eq!(decoded.environment_refs(), &["env.clean"]);
    assert_eq!(
        decoded.credential_refs()[0].scope_id().as_str(),
        "scope.launch"
    );
    assert_eq!(
        decoded.credential_refs()[0].reference(),
        "vault.allowed.one"
    );
    let binding = binding();
    let descriptor =
        ImmutableLaunchDescriptor::from_binding(&binding, policy(&binding, decoded.digest()))
            .unwrap();
    decoded.compare_with_descriptor(&descriptor).unwrap();
}

#[test]
fn descriptor_rehash_does_not_hide_semantic_model_executable_or_credential_drift() {
    let decoded = EffectiveLaunchContract::decode(&golden()).unwrap();
    let binding = binding();
    let mut reviewed = policy(&binding, decoded.digest());
    reviewed.model_id = "model.beta".into();
    let changed = ImmutableLaunchDescriptor::from_binding(&binding, reviewed).unwrap();
    assert_eq!(
        decoded.compare_with_descriptor(&changed),
        Err(EffectiveLaunchError::DescriptorMismatch("modelId"))
    );
    let mut reviewed = policy(&binding, decoded.digest());
    reviewed.executable = "/opt/podbay/bin/other-agent".into();
    let changed = ImmutableLaunchDescriptor::from_binding(&binding, reviewed).unwrap();
    assert_eq!(
        decoded.compare_with_descriptor(&changed),
        Err(EffectiveLaunchError::DescriptorMismatch("executable"))
    );
    let mut reviewed = policy(&binding, decoded.digest());
    reviewed.credential_refs = vec!["vault.allowed.two".into()];
    let changed = ImmutableLaunchDescriptor::from_binding(&binding, reviewed).unwrap();
    assert_eq!(
        decoded.compare_with_descriptor(&changed),
        Err(EffectiveLaunchError::DescriptorMismatch("credentialRefs"))
    );
    let reviewed = policy(&binding, &"a".repeat(64));
    let changed = ImmutableLaunchDescriptor::from_binding(&binding, reviewed).unwrap();
    assert_eq!(
        decoded.compare_with_descriptor(&changed),
        Err(EffectiveLaunchError::DescriptorMismatch(
            "effectiveSpecDigest"
        ))
    );
}

#[test]
fn malformed_truncated_trailing_and_noncanonical_bytes_refuse() {
    let bytes = golden();
    assert_eq!(
        EffectiveLaunchContract::decode(&bytes[..bytes.len() - 1]),
        Err(EffectiveLaunchError::Truncated)
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        EffectiveLaunchContract::decode(&trailing),
        Err(EffectiveLaunchError::TrailingBytes)
    );
    let mut wrong_version = bytes.clone();
    wrong_version[0] = b'X';
    assert_eq!(
        EffectiveLaunchContract::decode(&wrong_version),
        Err(EffectiveLaunchError::InvalidField("version"))
    );
    let mut invalid_utf8 = bytes.clone();
    let model = invalid_utf8
        .windows("model.alpha".len())
        .position(|window| window == b"model.alpha")
        .unwrap();
    invalid_utf8[model] = 0xff;
    assert_eq!(
        EffectiveLaunchContract::decode(&invalid_utf8),
        Err(EffectiveLaunchError::InvalidField("UTF-8"))
    );
    let mut invalid_credential_scope = bytes.clone();
    let last_scope = invalid_credential_scope
        .windows("scope.launch".len())
        .rposition(|window| window == b"scope.launch")
        .unwrap();
    invalid_credential_scope[last_scope + "scope.launch".len() - 1] = b'X';
    assert_eq!(
        EffectiveLaunchContract::decode(&invalid_credential_scope),
        Err(EffectiveLaunchError::InvalidField("credential scope"))
    );
    let mut zero_profile_generation = bytes;
    let profile = zero_profile_generation
        .windows("profile.fixture".len())
        .position(|window| window == b"profile.fixture")
        .unwrap();
    let generation = profile + "profile.fixture".len();
    zero_profile_generation[generation..generation + 8].fill(0);
    assert_eq!(
        EffectiveLaunchContract::decode(&zero_profile_generation),
        Err(EffectiveLaunchError::InvalidField("profileGeneration"))
    );
}

#[test]
fn unsorted_reviewed_references_refuse() {
    let mut bytes = golden();
    let mut pattern = vec![0, 0, 0, 1, 0, 0, 0, 10];
    pattern.extend_from_slice(b"tools.base");
    let at = bytes
        .windows(pattern.len())
        .position(|window| window == pattern)
        .unwrap();
    bytes[at + 3] = 2;
    let mut extra = vec![0, 0, 0, 9];
    extra.extend_from_slice(b"tools.aaa");
    bytes.splice(at + pattern.len()..at + pattern.len(), extra);
    assert_eq!(
        EffectiveLaunchContract::decode(&bytes),
        Err(EffectiveLaunchError::InvalidField("toolBundleRefs order"))
    );
}
