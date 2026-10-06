use super::*;
use podbay_core::{
    ActorId, Attempt, AttemptId, Epoch, Pod, Resource, ResourceId, Run, RunId, Session, SessionId,
};
use podbay_wire::{
    OperatorArtifactTreePinV1, OperatorConfigurationPinV1, OperatorFd3ObservePolicyInputV1,
    OperatorWorkspaceExpectationV1,
};

const ROOT: &str = "/podbay-fd3-host-fixture/unopened/lens";
const EXE: &str = "/podbay-fd3-host-fixture/unopened/node";

fn policy(digit: char) -> OperatorFd3ObservePolicyV1 {
    OperatorFd3ObservePolicyV1::new(OperatorFd3ObservePolicyInputV1 {
        supervisor: OperatorFilePinV1 {
            path: "/podbay-fd3-host-fixture/unopened/podbay-pod".into(),
            sha256: "a".repeat(64),
        },
        artifact: OperatorArtifactTreePinV1 {
            root: ROOT.into(),
            sha256: "b".repeat(64),
        },
        configuration: OperatorConfigurationPinV1::Absent,
        public_composition_digest: "c".repeat(64),
        registry_digest: digit.to_string().repeat(64),
        workspace: OperatorWorkspaceExpectationV1 {
            logical_store_id: "00000000-0000-4000-8000-000000000001".into(),
            main_path: "/podbay-fd3-host-fixture/unopened/state/workspace.sqlite".into(),
        },
    })
    .unwrap()
}
fn input() -> TrustedLaunchProfileInput {
    TrustedLaunchProfileInput {
        profile_ref: OPERATOR_FD3_OBSERVE_PROFILE_REF.into(),
        profile_generation: 1,
        executable: EXE.into(),
        binary_generation: format!("sha256:{}", "d".repeat(64)),
        executable_sha256: "d".repeat(64),
        workspace_root: ROOT.into(),
        resource_layout: vec![TrustedDriverTemplate {
            kind: ResourceKind::Auxiliary,
            driver: ResourceDriver::Auxiliary {
                driver_ref: OPERATOR_FD3_OBSERVE_DRIVER_REF.into(),
            },
        }],
        execution_mode: ExecutionMode::LinuxCooperative,
        fixed_arguments: vec![
            "src/zap-server.ts".into(),
            "--state-dir".into(),
            "/podbay-fd3-host-fixture/unopened/state".into(),
        ],
        permitted_extra_arguments: BTreeSet::new(),
        default_model: "none".into(),
        allowed_models: BTreeSet::from(["none".into()]),
        default_effort: "none".into(),
        allowed_efforts: BTreeSet::from(["none".into()]),
        workspace_scope: ScopeId::try_from("scope.fd3.host").unwrap(),
        workspace_basis_ref: "basis.fd3.host".into(),
        allowed_cwd_prefix: ".".into(),
        allow_write: true,
        allowed_tool_bundle_refs: BTreeSet::new(),
        environment_refs: vec![],
        credential_refs: vec![],
        max_wall_seconds: 60,
        max_children: 0,
        allow_fallback: false,
    }
}
fn registered(lifetime: LifetimeLimit) -> RegisteredLaunchProfile {
    RegisteredLaunchProfile::from_trusted_operator_fd3_observe_policy(
        input(),
        policy('e'),
        lifetime,
    )
    .unwrap()
}
fn host() -> TrustedNativeHostConfig {
    TrustedNativeHostConfig::for_compiled_backend("host.fd3.fixture".into())
        .unwrap()
        .with_auxiliary_driver(OPERATOR_FD3_OBSERVE_DRIVER_REF.into())
        .unwrap()
}
fn selection() -> LaunchSelection {
    LaunchSelection {
        profile_ref: OPERATOR_FD3_OBSERVE_PROFILE_REF.into(),
        profile_generation: 1,
        model_id: None,
        reasoning_effort: None,
        fallback_approved: false,
        workspace: WorkspaceSelection {
            scope_id: ScopeId::try_from("scope.fd3.host").unwrap(),
            basis_ref: "basis.fd3.host".into(),
            relative_cwd: ".".into(),
            access: WorkspaceAccess::ReadWrite,
        },
        arguments: vec![],
        tool_bundle_refs: vec![],
        authority_ref: "grant.7".into(),
        wall_seconds: 60,
        max_children: 0,
        parent_run_id: None,
    }
}
fn planned(scope: &str) -> PlannedRootBinding {
    let mut session = Session::new(
        SessionId::try_from("session.fd3.host").unwrap(),
        ActorId::try_from("actor.fd3.host").unwrap(),
        ScopeId::try_from(scope).unwrap(),
    );
    let run = Run::new(
        RunId::try_from("run.fd3.host").unwrap(),
        &session,
        Role::Coordinator,
        WorkKind::Service,
        None,
    );
    session.bind_run(session.revision(), &run).unwrap();
    let mut attempt = Attempt::new(
        AttemptId::try_from("attempt.fd3.host").unwrap(),
        run.id().clone(),
        1,
        Epoch::new(1).unwrap(),
    )
    .unwrap();
    let mut pod = Pod::new(
        PodId::try_from("pod.fd3.host").unwrap(),
        attempt.id().clone(),
        Epoch::new(1).unwrap(),
    );
    attempt.attach_pod(attempt.revision(), &pod).unwrap();
    let resource = Resource::new(
        ResourceId::try_from("resource.fd3.host").unwrap(),
        pod.id().clone(),
        ResourceKind::Auxiliary,
        Epoch::new(1).unwrap(),
    );
    pod.attach_resource(pod.revision(), &resource).unwrap();
    LaunchBinding::plan_first_root(&session, &run, &attempt, &pod, &[resource]).unwrap()
}

#[test]
fn resolves_exact_registered_policy_for_finite_and_until_stopped_without_io() {
    for lifetime in [
        LifetimeLimit::Finite { seconds: 60 },
        LifetimeLimit::UntilStopped,
    ] {
        let profile = registered(lifetime);
        let binding = planned("scope.fd3.host");
        let resolved = profile
            .resolve_operator_fd3_observe_data(&host(), &binding, 7, &selection())
            .unwrap();
        assert_eq!(resolved.effective().policy(), policy('e'));
        assert_eq!(resolved.effective().lifetime(), lifetime);
        resolved
            .effective()
            .compare_with_descriptor(resolved.descriptor())
            .unwrap();
        resolved
            .descriptor()
            .validate_against_planned_root(&binding)
            .unwrap();
        assert_eq!(
            resolved,
            profile
                .resolve_operator_fd3_observe_data(&host(), &binding, 7, &selection())
                .unwrap()
        );
        assert!(EffectiveLaunchContract::decode(resolved.effective().canonical_bytes()).is_err());
        assert!(
            ImmutableLaunchDescriptor::decode_json(&resolved.descriptor().encode_json().unwrap())
                .is_err()
        );
        assert!(EffectiveLaunchContractV2::decode(resolved.effective().canonical_bytes()).is_err());
        assert!(
            ImmutableLaunchDescriptorV2::decode_json(&resolved.descriptor().encode_json().unwrap())
                .is_err()
        );
    }
}

#[test]
fn registry_requires_exact_complete_policy_and_monotonic_generation() {
    let mut profiles = HashMap::new();
    let first = registered(LifetimeLimit::Finite { seconds: 60 });
    register_launch_profile(&mut profiles, first.clone()).unwrap();
    register_launch_profile(&mut profiles, first.clone()).unwrap();
    assert_eq!(profiles.len(), 1);
    for changed in [
        RegisteredLaunchProfile::from_trusted_operator_fd3_observe_policy(
            input(),
            policy('f'),
            LifetimeLimit::Finite { seconds: 60 },
        )
        .unwrap(),
        registered(LifetimeLimit::UntilStopped),
    ] {
        assert_eq!(
            register_launch_profile(&mut profiles, changed),
            Err(HostError::StaleGuard)
        );
        assert_eq!(profiles.get(OPERATOR_FD3_OBSERVE_PROFILE_REF), Some(&first));
    }
    let mut next_input = input();
    next_input.profile_generation = 2;
    let next = RegisteredLaunchProfile::from_trusted_operator_fd3_observe_policy(
        next_input,
        policy('f'),
        LifetimeLimit::UntilStopped,
    )
    .unwrap();
    register_launch_profile(&mut profiles, next.clone()).unwrap();
    assert_eq!(
        register_launch_profile(&mut profiles, first),
        Err(HostError::StaleGuard)
    );
    assert_eq!(profiles.get(OPERATOR_FD3_OBSERVE_PROFILE_REF), Some(&next));
    let mut stripped = next.clone();
    stripped.operator_fd3_observe = None;
    assert_eq!(
        register_launch_profile(&mut profiles, stripped),
        Err(HostError::Unsupported)
    );
    assert_eq!(profiles.get(OPERATOR_FD3_OBSERVE_PROFILE_REF), Some(&next));
}

#[test]
fn trusted_constructor_refuses_bare_names_mixed_capabilities_and_mutable_choices() {
    assert_eq!(
        RegisteredLaunchProfile::from_trusted_policy(input()),
        Err(HostError::Unsupported)
    );
    let mut old_name = input();
    old_name.profile_ref = OPERATOR_PROCESS_PROFILE_REF.into();
    assert_eq!(
        RegisteredLaunchProfile::from_trusted_policy(old_name.clone()),
        Err(HostError::Unsupported)
    );
    assert!(
        RegisteredLaunchProfile::from_trusted_operator_fd3_observe_policy(
            old_name,
            policy('e'),
            LifetimeLimit::UntilStopped
        )
        .is_err()
    );
    for field in 0..12 {
        let mut changed = input();
        match field {
            0 => changed
                .permitted_extra_arguments
                .insert("--override".into()),
            1 => changed.allowed_models.insert("other-model".into()),
            2 => changed.allowed_efforts.insert("other-effort".into()),
            3 => changed
                .allowed_tool_bundle_refs
                .insert("tools.override".into()),
            4 => {
                changed.environment_refs.push("env.override".into());
                true
            }
            5 => {
                changed.allow_fallback = true;
                true
            }
            6 => {
                changed.max_children = 1;
                true
            }
            7 => {
                changed.workspace_root = "/foreign/root".into();
                true
            }
            8 => {
                changed.allowed_cwd_prefix = "subdir".into();
                true
            }
            9 => {
                changed.allow_write = false;
                true
            }
            10 => {
                changed.fixed_arguments.clear();
                true
            }
            11 => {
                changed.executable = "/fixture/../node".into();
                true
            }
            _ => unreachable!(),
        };
        assert!(
            RegisteredLaunchProfile::from_trusted_operator_fd3_observe_policy(
                changed,
                policy('e'),
                LifetimeLimit::UntilStopped
            )
            .is_err(),
            "field {field}"
        );
    }
    assert!(
        RegisteredLaunchProfile::from_trusted_operator_fd3_observe_policy(
            input(),
            policy('e'),
            LifetimeLimit::Finite { seconds: 59 }
        )
        .is_err()
    );
    assert!(
        registered(LifetimeLimit::UntilStopped)
            .with_until_stopped_operator_service()
            .is_err()
    );
    assert!(
        registered(LifetimeLimit::UntilStopped)
            .with_until_stopped_codex_service()
            .is_err()
    );
}

#[test]
fn caller_selections_cannot_override_registered_inputs_or_lifetime() {
    let profile = registered(LifetimeLimit::UntilStopped);
    let original = profile.clone();
    let binding = planned("scope.fd3.host");
    for field in 0..14 {
        let mut request = selection();
        match field {
            0 => request.arguments.push("src/foreign.ts".into()),
            1 => request.tool_bundle_refs.push("tools.foreign".into()),
            2 => request.workspace.relative_cwd = "subdir".into(),
            3 => request.workspace.access = WorkspaceAccess::ReadOnly,
            4 => request.workspace.scope_id = ScopeId::try_from("scope.foreign").unwrap(),
            5 => request.workspace.basis_ref = "basis.foreign".into(),
            6 => request.profile_ref = OPERATOR_PROCESS_PROFILE_REF.into(),
            7 => request.profile_generation = 2,
            8 => request.model_id = Some("other-model".into()),
            9 => request.reasoning_effort = Some("other-effort".into()),
            10 => request.fallback_approved = true,
            11 => request.max_children = 1,
            12 => request.parent_run_id = Some("run.foreign".into()),
            13 => request.wall_seconds = 59,
            _ => unreachable!(),
        }
        assert!(
            profile
                .resolve_operator_fd3_observe_data(&host(), &binding, 7, &request)
                .is_err(),
            "field {field}"
        );
        assert_eq!(profile, original);
    }
    assert!(
        profile
            .resolve_operator_fd3_observe_data(&host(), &binding, 0, &selection())
            .is_err()
    );
    assert!(
        profile
            .resolve_operator_fd3_observe_data(&host(), &binding, 8, &selection())
            .is_err()
    );
    assert!(
        profile
            .resolve_operator_fd3_observe_data(&host(), &planned("scope.foreign"), 7, &selection())
            .is_err()
    );
    let absent_driver =
        TrustedNativeHostConfig::for_compiled_backend("host.fd3.fixture".into()).unwrap();
    assert_eq!(
        profile.resolve_operator_fd3_observe_data(&absent_driver, &binding, 7, &selection()),
        Err(HostError::Unsupported)
    );
}

fn old_contracts(
    until_stopped: bool,
) -> (
    RegisteredLaunchProfile,
    EffectiveLaunchContract,
    ImmutableLaunchDescriptor,
) {
    let mut old = input();
    old.profile_ref = OPERATOR_PROCESS_PROFILE_REF.into();
    old.resource_layout[0].driver = ResourceDriver::Auxiliary {
        driver_ref: "process.exec".into(),
    };
    let mut profile = RegisteredLaunchProfile::from_trusted_policy(old.clone()).unwrap();
    if until_stopped {
        profile = profile.with_until_stopped_operator_service().unwrap();
    }
    let mut request = selection();
    request.profile_ref = OPERATOR_PROCESS_PROFILE_REF.into();
    let plan = planned("scope.fd3.host");
    let spec = profile
        .resolve(
            plan.identity().pod_id().clone(),
            Role::Coordinator,
            7,
            None,
            &request,
        )
        .unwrap();
    let effective = EffectiveLaunchContract::decode(&spec.canonical_bytes().unwrap()).unwrap();
    let native = ReviewedNativePolicy {
        target_os: TargetOs::Linux,
        host_id: "host.fd3.fixture".into(),
        profile_ref: old.profile_ref,
        profile_generation: 1,
        model_id: "none".into(),
        reasoning_effort: "none".into(),
        executable_generation: old.binary_generation,
        effective_spec_digest: effective.digest().into(),
        workspace_basis_ref: old.workspace_basis_ref,
        executable: old.executable,
        cwd: ROOT.into(),
        arguments: old.fixed_arguments,
        environment_refs: vec![],
        credential_refs: vec![],
        wall_seconds: 60,
        max_children: 0,
        resources: vec![ReviewedResource {
            resource_id: plan.identity().resources()[0].id().clone(),
            kind: ResourceKind::Auxiliary,
            epoch: Epoch::new(1).unwrap(),
            driver: ResourceDriver::Auxiliary {
                driver_ref: "process.exec".into(),
            },
        }],
    };
    let descriptor = if until_stopped {
        ImmutableLaunchDescriptor::from_planned_operator_root_until_stopped(&plan, native)
    } else {
        ImmutableLaunchDescriptor::from_planned_root(&plan, native)
    }
    .unwrap();
    effective.compare_with_descriptor(&descriptor).unwrap();
    (profile, effective, descriptor)
}

#[test]
fn generic_resolution_and_revalidation_refuse_marked_and_stripped_fd3_profiles() {
    let profile = registered(LifetimeLimit::UntilStopped);
    let plan = planned("scope.fd3.host");
    // Internal test-only construction confirms serialization itself is closed.
    let spec = profile
        .resolve_selection(
            plan.identity().pod_id().clone(),
            Role::Coordinator,
            7,
            None,
            &selection(),
        )
        .unwrap();
    assert_eq!(spec.canonical_bytes(), Err(HostError::Unsupported));
    let (_, old_effective, old_descriptor) = old_contracts(false);
    let mut stripped = profile.clone();
    stripped.operator_fd3_observe = None;
    for candidate in [profile, stripped] {
        assert!(matches!(
            candidate.resolve(
                plan.identity().pod_id().clone(),
                Role::Coordinator,
                7,
                None,
                &selection()
            ),
            Err(HostError::Unsupported)
        ));
        assert!(matches!(
            candidate.resolve_native_policy(&host(), &spec, plan.identity(), "unused"),
            Err(HostError::Unsupported)
        ));
        assert!(matches!(
            candidate.resolve_native_policy_codex_v2(&host(), &spec, plan.identity(), "unused"),
            Err(HostError::Unsupported)
        ));
        assert!(matches!(
            candidate.revalidate_committed_native(&host(), &old_effective, &old_descriptor),
            Err(HostError::Unsupported)
        ));
        assert!(matches!(
            candidate.resolve_codex_v2(
                plan.identity().pod_id().clone(),
                Role::Coordinator,
                7,
                None,
                &selection()
            ),
            Err(HostError::Unsupported)
        ));
    }
}

#[test]
fn legacy_operator_profiles_keep_finite_until_stopped_and_registry_behavior() {
    let mut profiles = HashMap::new();
    for until_stopped in [false, true] {
        let (profile, effective, descriptor) = old_contracts(until_stopped);
        assert!(!profile.requires_fd3_observe());
        assert_eq!(profile.operator_fd3_observe_policy(), None);
        assert_eq!(
            effective.lifetime(),
            if until_stopped {
                LifetimeLimit::UntilStopped
            } else {
                LifetimeLimit::Finite { seconds: 60 }
            }
        );
        assert_eq!(
            EffectiveLaunchContract::decode(&effective.reencode()).unwrap(),
            effective
        );
        assert_eq!(
            ImmutableLaunchDescriptor::decode_json(&descriptor.encode_json().unwrap()).unwrap(),
            descriptor
        );
        profiles.clear();
        register_launch_profile(&mut profiles, profile.clone()).unwrap();
        register_launch_profile(&mut profiles, profile.clone()).unwrap();
        assert_eq!(profiles.get(OPERATOR_PROCESS_PROFILE_REF), Some(&profile));
    }
}

#[test]
fn dedicated_resolution_enforces_the_complete_wire_byte_bound() {
    let mut large = input();
    large.fixed_arguments = vec!["x".repeat(1024); 64];
    let profile = RegisteredLaunchProfile::from_trusted_operator_fd3_observe_policy(
        large,
        policy('e'),
        LifetimeLimit::UntilStopped,
    )
    .unwrap();
    assert_eq!(
        profile.resolve_operator_fd3_observe_data(
            &host(),
            &planned("scope.fd3.host"),
            7,
            &selection()
        ),
        Err(HostError::InvalidInput)
    );
}
