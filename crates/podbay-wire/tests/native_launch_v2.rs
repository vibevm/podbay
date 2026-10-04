use podbay_core::{
    ActorId, Attempt, AttemptId, CommandAdmission, CommandId, Epoch, LaunchBinding, Pod, PodId,
    Resource, ResourceId, ResourceKind, Role, Run, RunCommandKind, RunId, ScopeId, Session,
    SessionId, WorkKind,
};
use podbay_wire::{
    CodexAppServerPolicyV2, EffectiveLaunchContract, EffectiveLaunchContractV2,
    EffectiveLaunchError, ImmutableLaunchDescriptor, ImmutableLaunchDescriptorV2,
    LaunchDescriptorError, ResourceDriver, ReviewedNativePolicy, ReviewedResource, TargetOs,
};
use serde_json::Value;

struct Admitted;
impl CommandAdmission for Admitted {
    fn admits_run(&self, _: &CommandId, _: &RunId, kind: RunCommandKind) -> bool {
        kind == RunCommandKind::Launch
    }
}

fn decode_hex(text: &str) -> Vec<u8> {
    let digits = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    digits
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn v1_effective() -> EffectiveLaunchContract {
    let mut bytes = decode_hex(include_str!("effective_launch_v1.hex"));
    replace_string(&mut bytes, "worker", "coordinator");
    replace_string(&mut bytes, "model.alpha", "gpt-6-sol");
    EffectiveLaunchContract::decode(&bytes).unwrap()
}

fn v1_worker_effective() -> EffectiveLaunchContract {
    let mut bytes = decode_hex(include_str!("effective_launch_v1.hex"));
    replace_string(&mut bytes, "model.alpha", "gpt-6-sol");
    EffectiveLaunchContract::decode(&bytes).unwrap()
}

fn replace_string(bytes: &mut Vec<u8>, from: &str, to: &str) {
    let mut old = (from.len() as u32).to_be_bytes().to_vec();
    old.extend_from_slice(from.as_bytes());
    let at = bytes
        .windows(old.len())
        .position(|window| window == old)
        .unwrap();
    let mut replacement = (to.len() as u32).to_be_bytes().to_vec();
    replacement.extend_from_slice(to.as_bytes());
    bytes.splice(at..at + old.len(), replacement);
}

fn make_binding(extra_pty: bool) -> LaunchBinding {
    make_binding_for(Role::Coordinator, WorkKind::Service, extra_pty)
}

fn make_binding_for(role: Role, work: WorkKind, extra_pty: bool) -> LaunchBinding {
    let mut session = Session::new(
        SessionId::try_from("session.codex.fixture").unwrap(),
        ActorId::try_from("actor.codex.fixture").unwrap(),
        ScopeId::try_from("scope.launch").unwrap(),
    );
    let mut run = Run::new(
        RunId::try_from("run.codex.fixture").unwrap(),
        &session,
        role,
        work,
        None,
    );
    run.admit(
        run.revision(),
        &CommandId::try_from("command.codex.fixture").unwrap(),
        &Admitted,
    )
    .unwrap();
    session.bind_run(session.revision(), &run).unwrap();
    let mut attempt = Attempt::new(
        AttemptId::try_from("attempt.codex.fixture").unwrap(),
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
    let mut resources = vec![Resource::new(
        ResourceId::try_from("resource.codex.fixture").unwrap(),
        pod.id().clone(),
        ResourceKind::StructuredProvider,
        Epoch::new(1).unwrap(),
    )];
    if extra_pty {
        resources.push(Resource::new(
            ResourceId::try_from("resource.pty.fixture").unwrap(),
            pod.id().clone(),
            ResourceKind::Pty,
            Epoch::new(1).unwrap(),
        ));
    }
    for resource in &resources {
        pod.attach_resource(pod.revision(), resource).unwrap();
    }
    LaunchBinding::from_aggregates(&session, &run, &attempt, &pod, &resources).unwrap()
}

fn codex_policy() -> CodexAppServerPolicyV2 {
    CodexAppServerPolicyV2::new(
        &ScopeId::try_from("scope.launch").unwrap(),
        "vault.allowed.one".into(),
        "driver.codex.app-server".into(),
        "protocol.codex.app-server".into(),
    )
    .unwrap()
}

fn reviewed_policy(binding: &LaunchBinding, effective_digest: &str) -> ReviewedNativePolicy {
    ReviewedNativePolicy {
        target_os: TargetOs::Linux,
        host_id: "host.codex.fixture".into(),
        profile_ref: "profile.fixture".into(),
        profile_generation: 1,
        model_id: "gpt-6-sol".into(),
        reasoning_effort: "medium".into(),
        executable_generation: "sha256.fakegeneration1".into(),
        effective_spec_digest: effective_digest.into(),
        workspace_basis_ref: "basis.commit.one".into(),
        executable: "/opt/podbay/bin/fake-agent".into(),
        cwd: "/work/src".into(),
        arguments: vec!["--managed".into(), "--safe".into()],
        environment_refs: vec!["env.clean".into()],
        credential_refs: vec!["vault.allowed.one".into()],
        wall_seconds: 60,
        max_children: 2,
        resources: binding
            .resources()
            .iter()
            .map(|resource| ReviewedResource {
                resource_id: resource.id().clone(),
                kind: resource.kind(),
                epoch: resource.epoch(),
                driver: match resource.kind() {
                    ResourceKind::StructuredProvider => ResourceDriver::Structured {
                        driver_ref: "driver.codex.app-server".into(),
                        protocol_ref: "protocol.codex.app-server".into(),
                    },
                    ResourceKind::Pty => ResourceDriver::Pty {
                        rows: 24,
                        columns: 80,
                        retention_events: 100,
                    },
                    ResourceKind::Auxiliary => unreachable!(),
                },
            })
            .collect(),
    }
}

#[test]
fn codex_v2_round_trips_one_structured_coordinator_and_has_distinct_digest() {
    let base = v1_effective();
    let effective = EffectiveLaunchContractV2::from_v1(base.clone(), codex_policy()).unwrap();
    let binding = make_binding(false);
    let descriptor = ImmutableLaunchDescriptorV2::from_binding(
        &binding,
        reviewed_policy(&binding, effective.digest()),
        codex_policy(),
    )
    .unwrap();
    effective.compare_with_descriptor(&descriptor).unwrap();
    assert_eq!(descriptor.resources_len(), 1);
    assert_eq!(descriptor.role(), podbay_wire::NativeRole::Coordinator);
    assert_eq!(descriptor.work_kind(), podbay_wire::NativeWorkKind::Service);
    assert_eq!(descriptor.model_id(), "gpt-6-sol");
    assert_eq!(descriptor.reasoning_effort(), "medium");
    assert_eq!(descriptor.credential_refs(), &["vault.allowed.one"]);
    assert_ne!(effective.digest(), base.digest());
    assert_eq!(
        effective.digest(),
        "d511a181ceb413ed8c871060cec7f5e980ae544cab8bab764b2f67da7e4fabbb"
    );
    assert_eq!(
        descriptor.digest(),
        "53deae9eb850149312bc11de33c84a39518375476fb6ee781f2823b930b7558c"
    );
    assert_eq!(
        effective.canonical_bytes(),
        decode_hex(include_str!("effective_launch_v2.hex"))
    );
    assert_eq!(
        descriptor.encode_json().unwrap(),
        include_str!("launch_descriptor_v2.json")
            .trim_end()
            .as_bytes()
    );
    assert_eq!(
        EffectiveLaunchContractV2::decode(effective.canonical_bytes()).unwrap(),
        effective
    );
    assert_eq!(
        ImmutableLaunchDescriptorV2::decode_for_binding(
            &descriptor.encode_json().unwrap(),
            &binding,
            effective.digest(),
        )
        .unwrap(),
        descriptor
    );
}

#[test]
fn codex_v2_round_trips_one_structured_worker_task() {
    let effective =
        EffectiveLaunchContractV2::from_v1(v1_worker_effective(), codex_policy()).unwrap();
    let binding = make_binding_for(Role::Worker, WorkKind::Task, false);
    let descriptor = ImmutableLaunchDescriptorV2::from_binding(
        &binding,
        reviewed_policy(&binding, effective.digest()),
        codex_policy(),
    )
    .unwrap();
    effective.compare_with_descriptor(&descriptor).unwrap();
    assert_eq!(descriptor.role(), podbay_wire::NativeRole::Worker);
    assert_eq!(descriptor.work_kind(), podbay_wire::NativeWorkKind::Task);
    assert_eq!(descriptor.resources_len(), 1);
    assert_eq!(descriptor.credential_refs(), &["vault.allowed.one"]);
    assert_eq!(
        EffectiveLaunchContractV2::decode(effective.canonical_bytes()).unwrap(),
        effective
    );
    assert_eq!(
        ImmutableLaunchDescriptorV2::decode_for_binding(
            &descriptor.encode_json().unwrap(),
            &binding,
            effective.digest(),
        )
        .unwrap(),
        descriptor
    );
}

#[test]
fn codex_v2_refuses_mismatched_role_and_work_kind() {
    for (role, work) in [
        (Role::Coordinator, WorkKind::Task),
        (Role::Worker, WorkKind::Service),
    ] {
        let base = if role == Role::Coordinator {
            v1_effective()
        } else {
            v1_worker_effective()
        };
        let effective = EffectiveLaunchContractV2::from_v1(base, codex_policy()).unwrap();
        let binding = make_binding_for(role, work, false);
        assert_eq!(
            ImmutableLaunchDescriptorV2::from_binding(
                &binding,
                reviewed_policy(&binding, effective.digest()),
                codex_policy(),
            ),
            Err(LaunchDescriptorError::InvalidField("codexPolicy binding"))
        );
    }
}

#[test]
fn v1_bytes_never_decode_as_codex_v2() {
    let base = v1_effective();
    assert_eq!(
        EffectiveLaunchContractV2::decode(base.canonical_bytes()),
        Err(EffectiveLaunchError::InvalidField("version"))
    );
    let binding = make_binding(false);
    let legacy =
        ImmutableLaunchDescriptor::from_binding(&binding, reviewed_policy(&binding, base.digest()))
            .unwrap();
    assert!(ImmutableLaunchDescriptorV2::decode_json(&legacy.encode_json().unwrap()).is_err());
    let effective = EffectiveLaunchContractV2::from_v1(base, codex_policy()).unwrap();
    assert!(EffectiveLaunchContract::decode(effective.canonical_bytes()).is_err());
    let native = ImmutableLaunchDescriptorV2::from_binding(
        &binding,
        reviewed_policy(&binding, effective.digest()),
        codex_policy(),
    )
    .unwrap();
    assert!(ImmutableLaunchDescriptor::decode_json(&native.encode_json().unwrap()).is_err());
}

#[test]
fn missing_or_changed_codex_policy_credential_and_resource_refuse() {
    let effective = EffectiveLaunchContractV2::from_v1(v1_effective(), codex_policy()).unwrap();
    let binding = make_binding(false);
    let descriptor = ImmutableLaunchDescriptorV2::from_binding(
        &binding,
        reviewed_policy(&binding, effective.digest()),
        codex_policy(),
    )
    .unwrap();
    let encoded = descriptor.encode_json().unwrap();
    let mut raw: Value = serde_json::from_slice(&encoded).unwrap();
    raw["descriptor"]
        .as_object_mut()
        .unwrap()
        .remove("codexPolicy");
    assert_eq!(
        ImmutableLaunchDescriptorV2::decode_json(&serde_json::to_vec(&raw).unwrap()),
        Err(LaunchDescriptorError::Malformed)
    );
    let mut raw: Value = serde_json::from_slice(&encoded).unwrap();
    raw["descriptor"]["codexPolicy"]
        .as_object_mut()
        .unwrap()
        .remove("requiredCredential");
    assert_eq!(
        ImmutableLaunchDescriptorV2::decode_json(&serde_json::to_vec(&raw).unwrap()),
        Err(LaunchDescriptorError::Malformed)
    );
    for (field, value) in [
        ("sandbox", "workspace_write"),
        ("approvalPolicy", "on_request"),
    ] {
        let mut raw: Value = serde_json::from_slice(&encoded).unwrap();
        raw["descriptor"]["codexPolicy"][field] = value.into();
        assert_eq!(
            ImmutableLaunchDescriptorV2::decode_json(&serde_json::to_vec(&raw).unwrap()),
            Err(LaunchDescriptorError::Malformed)
        );
    }
    let mut reviewed = reviewed_policy(&binding, effective.digest());
    reviewed.credential_refs.clear();
    assert_eq!(
        ImmutableLaunchDescriptorV2::from_binding(&binding, reviewed, codex_policy()),
        Err(LaunchDescriptorError::InvalidField("codexPolicy binding"))
    );
    let mut raw: Value = serde_json::from_slice(&encoded).unwrap();
    raw["descriptor"]["codexPolicy"]["requiredCredential"]["reference"] =
        "vault.allowed.two".into();
    assert_eq!(
        ImmutableLaunchDescriptorV2::decode_json(&serde_json::to_vec(&raw).unwrap()),
        Err(LaunchDescriptorError::InvalidField("codexPolicy binding"))
    );
    let mut reviewed = reviewed_policy(&binding, effective.digest());
    reviewed.resources[0].driver = ResourceDriver::Structured {
        driver_ref: "driver.other".into(),
        protocol_ref: "protocol.codex.app-server".into(),
    };
    assert_eq!(
        ImmutableLaunchDescriptorV2::from_binding(&binding, reviewed, codex_policy()),
        Err(LaunchDescriptorError::InvalidField("codex resource driver"))
    );
    let extra = make_binding(true);
    assert_eq!(
        ImmutableLaunchDescriptorV2::from_binding(
            &extra,
            reviewed_policy(&extra, effective.digest()),
            codex_policy(),
        ),
        Err(LaunchDescriptorError::InvalidField("codexPolicy binding"))
    );
    let mut other = CodexAppServerPolicyV2::new(
        &ScopeId::try_from("scope.launch").unwrap(),
        "vault.allowed.two".into(),
        "driver.codex.app-server".into(),
        "protocol.codex.app-server".into(),
    )
    .unwrap();
    assert!(EffectiveLaunchContractV2::from_v1(v1_effective(), other.clone()).is_err());
    other = CodexAppServerPolicyV2::new(
        &ScopeId::try_from("scope.other").unwrap(),
        "vault.allowed.one".into(),
        "driver.codex.app-server".into(),
        "protocol.codex.app-server".into(),
    )
    .unwrap();
    assert!(EffectiveLaunchContractV2::from_v1(v1_effective(), other).is_err());
}

#[test]
fn v2_rebind_detects_model_profile_workspace_and_resource_identity_drift() {
    let effective = EffectiveLaunchContractV2::from_v1(v1_effective(), codex_policy()).unwrap();
    let binding = make_binding(false);
    for (field, change) in [
        ("modelId", "model"),
        ("profileGeneration", "profile"),
        ("workspace.basisRef", "workspace"),
    ] {
        let mut native = reviewed_policy(&binding, effective.digest());
        match change {
            "model" => native.model_id = "gpt-other".into(),
            "profile" => native.profile_generation = 2,
            "workspace" => native.workspace_basis_ref = "basis.other".into(),
            _ => unreachable!(),
        }
        let descriptor =
            ImmutableLaunchDescriptorV2::from_binding(&binding, native, codex_policy()).unwrap();
        assert_eq!(
            effective.compare_with_descriptor(&descriptor),
            Err(EffectiveLaunchError::DescriptorMismatch(field))
        );
    }
    let mut changed_base = v1_effective().canonical_bytes().to_vec();
    replace_string(&mut changed_base, "gpt-6-sol", "gpt-6-foo");
    let changed = EffectiveLaunchContractV2::from_v1(
        EffectiveLaunchContract::decode(&changed_base).unwrap(),
        codex_policy(),
    )
    .unwrap();
    let original_descriptor = ImmutableLaunchDescriptorV2::from_binding(
        &binding,
        reviewed_policy(&binding, effective.digest()),
        codex_policy(),
    )
    .unwrap();
    assert_ne!(changed.digest(), effective.digest());
    assert_eq!(
        changed.compare_with_descriptor(&original_descriptor),
        Err(EffectiveLaunchError::DescriptorMismatch("modelId"))
    );
    let other_binding = make_binding(true);
    let other_descriptor = ImmutableLaunchDescriptorV2::from_binding(
        &other_binding,
        reviewed_policy(&other_binding, effective.digest()),
        codex_policy(),
    );
    assert_eq!(
        other_descriptor,
        Err(LaunchDescriptorError::InvalidField("codexPolicy binding"))
    );
}
