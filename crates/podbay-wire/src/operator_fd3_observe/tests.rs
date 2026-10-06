use super::*;
use crate::{
    EffectiveLaunchContract, EffectiveLaunchContractV2, ImmutableLaunchDescriptor,
    ImmutableLaunchDescriptorV2, OPERATOR_PROCESS_PROFILE_REF, ReviewedNativePolicy,
    ReviewedResource,
};
use podbay_core::{
    ActorId, Attempt, AttemptId, Epoch, LaunchBinding, Pod, Resource, ResourceId, Run, RunId,
    Session, SessionId,
};

fn pin(path: &str, byte: char) -> OperatorFilePinV1 {
    OperatorFilePinV1 {
        path: path.into(),
        sha256: byte.to_string().repeat(64),
    }
}
fn policy_input() -> OperatorFd3ObservePolicyInputV1 {
    OperatorFd3ObservePolicyInputV1 {
        supervisor: pin("/fixture/podbay-pod", 'a'),
        artifact: OperatorArtifactTreePinV1 {
            root: "/fixture/lens".into(),
            sha256: "b".repeat(64),
        },
        configuration: OperatorConfigurationPinV1::File {
            pin: pin("/fixture/state/config.json", 'c'),
        },
        public_composition_digest: "d".repeat(64),
        registry_digest: "e".repeat(64),
        workspace: OperatorWorkspaceExpectationV1 {
            logical_store_id: "00000000-0000-4000-8000-000000000001".into(),
            main_path: "/fixture/state/workspace.sqlite".into(),
        },
    }
}
fn planned(suffix: &str) -> PlannedRootBinding {
    let actor = ActorId::try_from("actor.fd3.fixture").unwrap();
    let scope = ScopeId::try_from("scope.fd3.fixture").unwrap();
    let mut session = Session::new(
        SessionId::try_from(format!("session.fd3.{suffix}").as_str()).unwrap(),
        actor,
        scope,
    );
    let run = Run::new(
        RunId::try_from(format!("run.fd3.{suffix}").as_str()).unwrap(),
        &session,
        Role::Coordinator,
        WorkKind::Service,
        None,
    );
    session.bind_run(session.revision(), &run).unwrap();
    let mut attempt = Attempt::new(
        AttemptId::try_from(format!("attempt.fd3.{suffix}").as_str()).unwrap(),
        run.id().clone(),
        1,
        Epoch::new(1).unwrap(),
    )
    .unwrap();
    let mut pod = Pod::new(
        PodId::try_from(format!("pod.fd3.{suffix}").as_str()).unwrap(),
        attempt.id().clone(),
        Epoch::new(1).unwrap(),
    );
    attempt.attach_pod(attempt.revision(), &pod).unwrap();
    let resource = Resource::new(
        ResourceId::try_from(format!("resource.fd3.{suffix}").as_str()).unwrap(),
        pod.id().clone(),
        ResourceKind::Auxiliary,
        Epoch::new(1).unwrap(),
    );
    pod.attach_resource(pod.revision(), &resource).unwrap();
    LaunchBinding::plan_first_root(&session, &run, &attempt, &pod, &[resource]).unwrap()
}
fn input(lifetime: LifetimeLimit) -> OperatorFd3ObserveEffectiveInputV1 {
    OperatorFd3ObserveEffectiveInputV1 {
        pod_id: PodId::try_from("pod.fd3.fixture").unwrap(),
        scope_id: ScopeId::try_from("scope.fd3.fixture").unwrap(),
        host_id: "host.fd3.fixture".into(),
        profile_generation: 1,
        executable: pin("/fixture/node", 'f'),
        cwd: "/fixture/lens".into(),
        arguments: vec![
            "src/zap-server.ts".into(),
            "--state-dir".into(),
            "/fixture/state".into(),
        ],
        workspace_basis_ref: "basis.fd3.fixture".into(),
        authority_grant_id: 7,
        lifetime,
    }
}
fn effective(lifetime: LifetimeLimit) -> EffectiveOperatorFd3ObserveContractV1 {
    EffectiveOperatorFd3ObserveContractV1::new(
        input(lifetime),
        OperatorFd3ObservePolicyV1::new(policy_input()).unwrap(),
    )
    .unwrap()
}
fn descriptor(lifetime: LifetimeLimit) -> ImmutableOperatorFd3ObserveDescriptorV1 {
    ImmutableOperatorFd3ObserveDescriptorV1::from_planned_root(
        &planned("fixture"),
        &effective(lifetime),
    )
    .unwrap()
}
fn unchecked_effective(body: &EffectiveBody) -> Vec<u8> {
    framed_json(&json(body).unwrap())
}
fn framed_json(payload: &[u8]) -> Vec<u8> {
    let mut bytes = EFFECTIVE_DOMAIN.to_vec();
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
fn unchecked_descriptor(body: DescriptorBody) -> Vec<u8> {
    json(&DescriptorEnvelope {
        protocol: ProtocolVersion::V1,
        schema: LAUNCH_DESCRIPTOR_OPERATOR_FD3_OBSERVE_SCHEMA.into(),
        digest: hash(DESCRIPTOR_DOMAIN, &json(&body).unwrap()),
        descriptor: body,
    })
    .unwrap()
}
fn rehash_policy(envelope: &mut PolicyEnvelope) {
    envelope.digest = hash(POLICY_DOMAIN, &json(&envelope.policy).unwrap());
}

#[test]
fn finite_and_until_stopped_round_trip_and_duplicate_bytes() {
    for lifetime in [
        LifetimeLimit::Finite { seconds: 30 },
        LifetimeLimit::Finite { seconds: 3600 },
        LifetimeLimit::UntilStopped,
    ] {
        let policy = OperatorFd3ObservePolicyV1::new(policy_input()).unwrap();
        let policy_bytes = policy.encode_json().unwrap();
        assert_eq!(
            OperatorFd3ObservePolicyV1::decode_json(&policy_bytes).unwrap(),
            policy
        );
        let effective = effective(lifetime);
        assert_eq!(
            EffectiveOperatorFd3ObserveContractV1::decode(effective.canonical_bytes()).unwrap(),
            effective
        );
        assert_eq!(
            effective.canonical_bytes(),
            effective.clone().canonical_bytes()
        );
        let first = ImmutableOperatorFd3ObserveDescriptorV1::from_planned_root(
            &planned("fixture"),
            &effective,
        )
        .unwrap();
        let second = ImmutableOperatorFd3ObserveDescriptorV1::from_planned_root(
            &planned("fixture"),
            &effective,
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.encode_json().unwrap(), second.encode_json().unwrap());
        assert_eq!(first.lifetime(), lifetime);
        assert_eq!(first.effective(), effective);
        first
            .validate_against_planned_root(&planned("fixture"))
            .unwrap();
        effective.compare_with_descriptor(&first).unwrap();
        let decoded =
            ImmutableOperatorFd3ObserveDescriptorV1::decode_json(&first.encode_json().unwrap())
                .unwrap();
        assert_eq!(decoded, first);
        assert_eq!(decoded.effective_spec_digest(), effective.digest());
        assert!(
            !String::from_utf8(first.encode_json().unwrap())
                .unwrap()
                .contains("wallSeconds")
        );
    }
    let mut absent = policy_input();
    absent.configuration = OperatorConfigurationPinV1::Absent;
    let policy = OperatorFd3ObservePolicyV1::new(absent).unwrap();
    assert_eq!(
        OperatorFd3ObservePolicyV1::decode_json(&policy.encode_json().unwrap()).unwrap(),
        policy
    );
}

#[test]
fn every_policy_pin_changes_effective_and_descriptor_digest() {
    let original_policy = OperatorFd3ObservePolicyV1::new(policy_input()).unwrap();
    let original_effective = effective(LifetimeLimit::UntilStopped);
    let original_descriptor = descriptor(LifetimeLimit::UntilStopped);
    for field in 0..11 {
        let mut next_policy = policy_input();
        match field {
            0 => next_policy.supervisor.sha256 = "0".repeat(64),
            1 => next_policy.supervisor.path.push_str("-new"),
            2 => next_policy.artifact.sha256 = "0".repeat(64),
            3 => next_policy.configuration = OperatorConfigurationPinV1::Absent,
            4 => {
                next_policy.configuration = OperatorConfigurationPinV1::File {
                    pin: pin("/fixture/state/config.json", '0'),
                }
            }
            5 => {
                next_policy.configuration = OperatorConfigurationPinV1::File {
                    pin: pin("/fixture/state/other.json", 'c'),
                }
            }
            6 => next_policy.public_composition_digest = "0".repeat(64),
            7 => next_policy.registry_digest = "0".repeat(64),
            8 => {
                next_policy.workspace.logical_store_id =
                    "00000000-0000-4000-8000-000000000002".into()
            }
            9 => next_policy.workspace.main_path.push_str("-new"),
            10 => next_policy.artifact.root.push_str("-new"),
            _ => unreachable!(),
        }
        let changed = OperatorFd3ObservePolicyV1::new(next_policy).unwrap();
        assert_ne!(changed.digest(), original_policy.digest());
        let mut next_input = input(LifetimeLimit::UntilStopped);
        next_input.cwd = changed.artifact().root.clone();
        let next = EffectiveOperatorFd3ObserveContractV1::new(next_input, changed.clone()).unwrap();
        assert_ne!(next.digest(), original_effective.digest());
        let next_descriptor =
            ImmutableOperatorFd3ObserveDescriptorV1::from_planned_root(&planned("fixture"), &next)
                .unwrap();
        assert_ne!(next_descriptor.digest(), original_descriptor.digest());
        assert_eq!(
            original_effective.compare_with_descriptor(&next_descriptor),
            Err(OperatorFd3ContractError::BindingMismatch)
        );
        let mut stale = changed.envelope.clone();
        stale.digest = original_policy.digest().into();
        assert_eq!(
            OperatorFd3ObservePolicyV1::decode_json(&json(&stale).unwrap()),
            Err(OperatorFd3ContractError::DigestMismatch)
        );
    }
    let mut stale = original_descriptor.body.clone();
    stale.effective.observation_policy.policy.artifact.sha256 = "0".repeat(64);
    assert_eq!(
        ImmutableOperatorFd3ObserveDescriptorV1::decode_json(&unchecked_descriptor(stale)),
        Err(OperatorFd3ContractError::DigestMismatch)
    );
}

#[test]
fn rehashed_invalid_policy_fields_still_refuse() {
    let original = OperatorFd3ObservePolicyV1::new(policy_input()).unwrap();
    for field in 0..10 {
        let mut envelope = original.envelope.clone();
        match field {
            0 => envelope.policy.fd = 4,
            1 => envelope.policy.transport = "namedSocket".into(),
            2 => envelope.policy.child_protocol = "unregistered.protocol/1".into(),
            3 => envelope.policy.max_frame_bytes += 1,
            4 => envelope.policy.exchange_timeout_ms += 1,
            5 => envelope.policy.supervisor.sha256 = "A".repeat(64),
            6 => envelope.policy.artifact.root = "relative/root".into(),
            7 => envelope.policy.workspace.main_path = "/fixture/../foreign/db".into(),
            8 => {
                envelope.policy.workspace.logical_store_id =
                    "00000000-0000-4000-8000-00000000000A".into()
            }
            9 => envelope.policy.registry_digest.pop().map(|_| ()).unwrap(),
            _ => unreachable!(),
        }
        rehash_policy(&mut envelope);
        assert!(
            matches!(
                OperatorFd3ObservePolicyV1::decode_json(&json(&envelope).unwrap()),
                Err(OperatorFd3ContractError::InvalidField(_))
            ),
            "field {field}"
        );
    }
    let mut unknown: serde_json::Value =
        serde_json::from_slice(&original.encode_json().unwrap()).unwrap();
    unknown["policy"]["configuration"]["unexpected"] = true.into();
    assert_eq!(
        OperatorFd3ObservePolicyV1::decode_json(&json(&unknown).unwrap()),
        Err(OperatorFd3ContractError::Malformed)
    );
}

#[test]
fn effective_limits_framing_and_canonical_json_refuse() {
    let original = effective(LifetimeLimit::UntilStopped);
    let bytes = original.canonical_bytes();
    for cut in 0..bytes.len() {
        assert!(EffectiveOperatorFd3ObserveContractV1::decode(&bytes[..cut]).is_err());
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert_eq!(
        EffectiveOperatorFd3ObserveContractV1::decode(&trailing),
        Err(OperatorFd3ContractError::TrailingBytes)
    );
    let mut oversized = bytes.to_vec();
    oversized[EFFECTIVE_DOMAIN.len()..EFFECTIVE_DOMAIN.len() + 4]
        .copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        EffectiveOperatorFd3ObserveContractV1::decode(&oversized),
        Err(OperatorFd3ContractError::TooLarge)
    );
    let mut spaced = b" ".to_vec();
    spaced.extend(json(&original.body).unwrap());
    assert_eq!(
        EffectiveOperatorFd3ObserveContractV1::decode(&framed_json(&spaced)),
        Err(OperatorFd3ContractError::NonCanonical)
    );
    let mut unknown = serde_json::to_value(&original.body).unwrap();
    unknown["nonce"] = "not-part-of-this-contract".into();
    assert_eq!(
        EffectiveOperatorFd3ObserveContractV1::decode(&framed_json(&json(&unknown).unwrap())),
        Err(OperatorFd3ContractError::Malformed)
    );
    let body = String::from_utf8(json(&original.body).unwrap()).unwrap();
    let duplicate = body.replacen(
        "{",
        "{\"capability\":\"operator_process_fd3_observe_v1\",",
        1,
    );
    assert_eq!(
        EffectiveOperatorFd3ObserveContractV1::decode(&framed_json(duplicate.as_bytes())),
        Err(OperatorFd3ContractError::Malformed)
    );
    for field in 0..8 {
        let mut body = original.body.clone();
        match field {
            0 => body.profile_ref = OPERATOR_PROCESS_PROFILE_REF.into(),
            1 => body.parent_run_id = Some("run.foreign".into()),
            2 => body.lifetime = LifetimeLimit::Finite { seconds: 0 },
            3 => body.arguments.push("\n".into()),
            4 => body.credential_refs.push("credential.foreign".into()),
            5 => body.target_os = TargetOs::Macos,
            6 => body.cwd = "/other/artifact".into(),
            7 => body.authority_grant_id = Counter(0),
            _ => unreachable!(),
        }
        assert!(
            matches!(
                EffectiveOperatorFd3ObserveContractV1::decode(&unchecked_effective(&body)),
                Err(OperatorFd3ContractError::InvalidField(_))
            ),
            "field {field}"
        );
    }
}

#[test]
fn descriptor_requires_exact_first_root_and_effective_binding() {
    let original = descriptor(LifetimeLimit::UntilStopped);
    assert_eq!(
        original.validate_against_planned_root(&planned("foreign")),
        Err(OperatorFd3ContractError::BindingMismatch)
    );
    assert_eq!(
        ImmutableOperatorFd3ObserveDescriptorV1::from_planned_root(
            &planned("foreign"),
            &effective(LifetimeLimit::UntilStopped)
        ),
        Err(OperatorFd3ContractError::BindingMismatch)
    );
    for field in 0..5 {
        let mut body = original.body.clone();
        match field {
            0 => body.identity.resource.epoch = Counter(2),
            1 => body.identity.role = NativeRole::Worker,
            2 => body.identity.attempt_ordinal = Counter(2),
            3 => body.identity.parent_run_id = Some("run.parent".into()),
            4 => {
                body.identity.resource.driver = ResourceDriver::Auxiliary {
                    driver_ref: "process.exec".into(),
                }
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            ImmutableOperatorFd3ObserveDescriptorV1::decode_json(&unchecked_descriptor(body)),
            Err(OperatorFd3ContractError::InvalidField(_))
        ));
    }
    let mut body = original.body.clone();
    body.identity.scope_id = "scope.foreign".into();
    assert_eq!(
        ImmutableOperatorFd3ObserveDescriptorV1::decode_json(&unchecked_descriptor(body)),
        Err(OperatorFd3ContractError::BindingMismatch)
    );
    let mut body = original.body.clone();
    body.effective_spec_digest = "0".repeat(64);
    assert_eq!(
        ImmutableOperatorFd3ObserveDescriptorV1::decode_json(&unchecked_descriptor(body)),
        Err(OperatorFd3ContractError::BindingMismatch)
    );
    let mut unknown: serde_json::Value =
        serde_json::from_slice(&original.encode_json().unwrap()).unwrap();
    unknown["descriptor"]["identity"]["childPid"] = 123.into();
    assert_eq!(
        ImmutableOperatorFd3ObserveDescriptorV1::decode_json(&json(&unknown).unwrap()),
        Err(OperatorFd3ContractError::Malformed)
    );
}

#[test]
fn bounds_are_checked_before_or_during_construction_and_decode() {
    assert_eq!(
        OperatorFd3ObservePolicyV1::decode_json(&vec![
            0;
            OPERATOR_FD3_OBSERVE_MAX_POLICY_BYTES + 1
        ]),
        Err(OperatorFd3ContractError::TooLarge)
    );
    assert_eq!(
        EffectiveOperatorFd3ObserveContractV1::decode(&vec![
            0;
            OPERATOR_FD3_OBSERVE_MAX_CONTRACT_BYTES
                + 1
        ]),
        Err(OperatorFd3ContractError::TooLarge)
    );
    assert_eq!(
        ImmutableOperatorFd3ObserveDescriptorV1::decode_json(&vec![
            0;
            OPERATOR_FD3_OBSERVE_MAX_CONTRACT_BYTES
                + 1
        ]),
        Err(OperatorFd3ContractError::TooLarge)
    );
    let mut large = input(LifetimeLimit::UntilStopped);
    large.arguments = vec!["x".repeat(1024); 64];
    assert_eq!(
        EffectiveOperatorFd3ObserveContractV1::new(
            large,
            OperatorFd3ObservePolicyV1::new(policy_input()).unwrap()
        ),
        Err(OperatorFd3ContractError::TooLarge)
    );
    let mut large = policy_input();
    let path = format!("/{}", "x".repeat(4095));
    large.supervisor.path = path.clone();
    large.artifact.root = path.clone();
    large.configuration = OperatorConfigurationPinV1::File {
        pin: OperatorFilePinV1 {
            path: path.clone(),
            sha256: "c".repeat(64),
        },
    };
    large.workspace.main_path = path;
    assert_eq!(
        OperatorFd3ObservePolicyV1::new(large),
        Err(OperatorFd3ContractError::TooLarge)
    );
    let mut large_counter = input(LifetimeLimit::UntilStopped);
    large_counter.profile_generation = u64::MAX;
    large_counter.authority_grant_id = u64::MAX;
    let large_counter = EffectiveOperatorFd3ObserveContractV1::new(
        large_counter,
        OperatorFd3ObservePolicyV1::new(policy_input()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        EffectiveOperatorFd3ObserveContractV1::decode(large_counter.canonical_bytes()).unwrap(),
        large_counter
    );
}

// Independent legacy byte recipe matches the unchanged V1 effective encoder.
fn legacy_effective(lifetime: LifetimeLimit, profile: &str) -> Vec<u8> {
    fn string(bytes: &mut Vec<u8>, text: &str) {
        bytes.extend_from_slice(&(text.len() as u32).to_be_bytes());
        bytes.extend_from_slice(text.as_bytes());
    }
    fn list(bytes: &mut Vec<u8>, values: &[String]) {
        bytes.extend_from_slice(&(values.len() as u32).to_be_bytes());
        for value in values {
            string(bytes, value);
        }
    }
    let input = input(lifetime);
    let mut bytes = if lifetime == LifetimeLimit::UntilStopped {
        b"podbay.effective-launch/operator-until-stopped/1\0".to_vec()
    } else {
        b"podbay.effective-launch/1\0".to_vec()
    };
    string(&mut bytes, input.pod_id.as_str());
    string(&mut bytes, "coordinator");
    bytes.push(0);
    string(&mut bytes, profile);
    bytes.extend_from_slice(&1u64.to_be_bytes());
    string(&mut bytes, &input.executable.path);
    string(&mut bytes, &format!("sha256:{}", input.executable.sha256));
    list(&mut bytes, &input.arguments);
    string(&mut bytes, "none");
    string(&mut bytes, "none");
    bytes.push(0);
    string(&mut bytes, input.scope_id.as_str());
    string(&mut bytes, &input.workspace_basis_ref);
    string(&mut bytes, ".");
    bytes.push(1);
    list(&mut bytes, &[]);
    bytes.extend_from_slice(&7u64.to_be_bytes());
    if let LifetimeLimit::Finite { seconds } = lifetime {
        bytes.extend_from_slice(&seconds.to_be_bytes());
    }
    bytes.extend_from_slice(&0u32.to_be_bytes());
    list(&mut bytes, &[]);
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes
}
fn legacy_descriptor(
    lifetime: LifetimeLimit,
    profile: &str,
    driver: &str,
) -> std::result::Result<ImmutableLaunchDescriptor, crate::LaunchDescriptorError> {
    let plan = planned("fixture");
    let input = input(lifetime);
    let policy = ReviewedNativePolicy {
        target_os: TargetOs::Linux,
        host_id: input.host_id,
        profile_ref: profile.into(),
        profile_generation: 1,
        model_id: "none".into(),
        reasoning_effort: "none".into(),
        executable_generation: format!("sha256:{}", input.executable.sha256),
        effective_spec_digest: hash(&[], &legacy_effective(lifetime, profile)),
        workspace_basis_ref: input.workspace_basis_ref,
        executable: input.executable.path,
        cwd: input.cwd,
        arguments: input.arguments,
        environment_refs: vec![],
        credential_refs: vec![],
        wall_seconds: match lifetime {
            LifetimeLimit::Finite { seconds } => seconds,
            LifetimeLimit::UntilStopped => 30,
        },
        max_children: 0,
        resources: vec![ReviewedResource {
            resource_id: plan.identity().resources()[0].id().clone(),
            kind: ResourceKind::Auxiliary,
            epoch: Epoch::new(1).unwrap(),
            driver: ResourceDriver::Auxiliary {
                driver_ref: driver.into(),
            },
        }],
    };
    if lifetime == LifetimeLimit::UntilStopped {
        ImmutableLaunchDescriptor::from_planned_operator_root_until_stopped(&plan, policy)
    } else {
        ImmutableLaunchDescriptor::from_planned_root(&plan, policy)
    }
}

#[test]
fn cross_format_and_stripped_policy_downgrades_refuse() {
    for lifetime in [
        LifetimeLimit::Finite { seconds: 30 },
        LifetimeLimit::UntilStopped,
    ] {
        let new_descriptor = descriptor(lifetime).encode_json().unwrap();
        let new_effective = effective(lifetime);
        assert!(ImmutableLaunchDescriptor::decode_json(&new_descriptor).is_err());
        assert!(ImmutableLaunchDescriptorV2::decode_json(&new_descriptor).is_err());
        assert!(EffectiveLaunchContract::decode(new_effective.canonical_bytes()).is_err());
        assert!(EffectiveLaunchContractV2::decode(new_effective.canonical_bytes()).is_err());
        let old_descriptor =
            legacy_descriptor(lifetime, OPERATOR_PROCESS_PROFILE_REF, "process.exec").unwrap();
        let old_bytes = old_descriptor.encode_json().unwrap();
        assert!(ImmutableOperatorFd3ObserveDescriptorV1::decode_json(&old_bytes).is_err());
        let old_effective_bytes = legacy_effective(lifetime, OPERATOR_PROCESS_PROFILE_REF);
        let old_effective = EffectiveLaunchContract::decode(&old_effective_bytes).unwrap();
        old_effective
            .compare_with_descriptor(&old_descriptor)
            .unwrap();
        assert_eq!(old_effective.reencode(), old_effective_bytes);
        assert_eq!(
            ImmutableLaunchDescriptor::decode_json(&old_bytes).unwrap(),
            old_descriptor
        );
        assert!(EffectiveOperatorFd3ObserveContractV1::decode(&old_effective_bytes).is_err());
    }
    assert_eq!(
        legacy_descriptor(
            LifetimeLimit::Finite { seconds: 30 },
            OPERATOR_FD3_OBSERVE_PROFILE_REF,
            "process.exec"
        ),
        Err(crate::LaunchDescriptorError::UnsupportedVersion)
    );
    assert_eq!(
        legacy_descriptor(
            LifetimeLimit::Finite { seconds: 30 },
            OPERATOR_PROCESS_PROFILE_REF,
            OPERATOR_FD3_OBSERVE_DRIVER_REF
        ),
        Err(crate::LaunchDescriptorError::UnsupportedVersion)
    );
    assert!(
        EffectiveLaunchContract::decode(&legacy_effective(
            LifetimeLimit::Finite { seconds: 30 },
            OPERATOR_FD3_OBSERVE_PROFILE_REF
        ))
        .is_err()
    );
}

#[test]
fn legacy_operator_finite_and_until_stopped_digest_vectors_are_unchanged() {
    // Independently encoded from the pre-change V1 field order and domains.
    for (lifetime, effective_hash, descriptor_hash) in [
        (
            LifetimeLimit::Finite { seconds: 30 },
            "0476956d596c0a67acbc3b826188a7d1561adbc79e6add479ee25cf24c806feb",
            "2945650bc656d83e234b7cd3d82f536047f399e3e57b4b94946d58f3804a2cdd",
        ),
        (
            LifetimeLimit::UntilStopped,
            "6213dd5c756a18241841c85ffe018606811dfbb0e3930658005f67d18d3f0962",
            "17187ec572c29ce1206e322fec62e0229efa144c110b7a3140b562abec4868c5",
        ),
    ] {
        let bytes = legacy_effective(lifetime, OPERATOR_PROCESS_PROFILE_REF);
        let effective = EffectiveLaunchContract::decode(&bytes).unwrap();
        assert_eq!(effective.digest(), effective_hash);
        assert_eq!(effective.reencode(), bytes);
        let descriptor =
            legacy_descriptor(lifetime, OPERATOR_PROCESS_PROFILE_REF, "process.exec").unwrap();
        assert_eq!(descriptor.digest(), descriptor_hash);
        effective.compare_with_descriptor(&descriptor).unwrap();
    }
}

#[test]
fn json_envelopes_refuse_trailing_duplicate_and_relabelled_schema() {
    let policy = OperatorFd3ObservePolicyV1::new(policy_input()).unwrap();
    let descriptor = descriptor(LifetimeLimit::UntilStopped);
    let policy_bytes = policy.encode_json().unwrap();
    let descriptor_bytes = descriptor.encode_json().unwrap();
    let mut trailing = policy_bytes.clone();
    trailing.push(b' ');
    assert_eq!(
        OperatorFd3ObservePolicyV1::decode_json(&trailing),
        Err(OperatorFd3ContractError::NonCanonical)
    );
    trailing.push(0);
    assert_eq!(
        OperatorFd3ObservePolicyV1::decode_json(&trailing),
        Err(OperatorFd3ContractError::Malformed)
    );
    let mut trailing = descriptor_bytes.clone();
    trailing.push(b' ');
    assert_eq!(
        ImmutableOperatorFd3ObserveDescriptorV1::decode_json(&trailing),
        Err(OperatorFd3ContractError::NonCanonical)
    );
    trailing.push(0);
    assert_eq!(
        ImmutableOperatorFd3ObserveDescriptorV1::decode_json(&trailing),
        Err(OperatorFd3ContractError::Malformed)
    );
    let duplicate_policy = String::from_utf8(policy_bytes).unwrap().replacen(
        "{",
        "{\"schema\":\"podbay.operator-fd3-observe-policy/1\",",
        1,
    );
    assert_eq!(
        OperatorFd3ObservePolicyV1::decode_json(duplicate_policy.as_bytes()),
        Err(OperatorFd3ContractError::Malformed)
    );
    let duplicate_descriptor =
        String::from_utf8(descriptor_bytes)
            .unwrap()
            .replacen("{", "{\"digest\":\"duplicate\",", 1);
    assert_eq!(
        ImmutableOperatorFd3ObserveDescriptorV1::decode_json(duplicate_descriptor.as_bytes()),
        Err(OperatorFd3ContractError::Malformed)
    );
    let mut relabelled = policy.envelope;
    relabelled.schema = crate::LAUNCH_DESCRIPTOR_SCHEMA.into();
    assert_eq!(
        OperatorFd3ObservePolicyV1::decode_json(&json(&relabelled).unwrap()),
        Err(OperatorFd3ContractError::UnsupportedVersion)
    );
    let relabelled = DescriptorEnvelope {
        protocol: ProtocolVersion::V1,
        schema: crate::LAUNCH_DESCRIPTOR_SCHEMA.into(),
        digest: descriptor.digest.clone(),
        descriptor: descriptor.body,
    };
    assert_eq!(
        ImmutableOperatorFd3ObserveDescriptorV1::decode_json(&json(&relabelled).unwrap()),
        Err(OperatorFd3ContractError::UnsupportedVersion)
    );
}
