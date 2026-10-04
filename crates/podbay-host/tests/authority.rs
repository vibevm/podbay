use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use podbay_core::{ActorId, PodId, ResourceId, Role, ScopeId};
use podbay_host::{
    ActorRegistration, AuthenticatedPeer, AuthenticatedProcessSubject, AuthenticatedTransport,
    AuthorisedBoundLaunch, AuthorisedDispatch, CredentialGeneration, CredentialRef, GrantId,
    GrantMode, GrantSpec, GuardSet, HostAction, HostAuthority, HostDispatchPort, HostError,
    HostPlatform, HostRequest, InputEpoch, ManagerEpoch, Operation, PodIncarnation,
    PodRegistration, PortDispatchError, PortDispatchOutcome, PortReceiptRef, ResourceEpoch,
    ResourceRegistration, Right, Target,
};

#[derive(Clone)]
struct FakeTransport(AuthenticatedPeer);

impl AuthenticatedTransport for FakeTransport {
    fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError> {
        Ok(self.0.clone())
    }
}

#[derive(Clone, Copy, Default)]
enum FakePortMode {
    #[default]
    Accepted,
    Settled,
    Refused,
    LostReply,
}

#[derive(Default)]
struct FakePort {
    calls: Vec<AuthorisedDispatch>,
    mode: FakePortMode,
}

impl HostDispatchPort for FakePort {
    type Receipt = usize;

    fn dispatch(
        &mut self,
        action: AuthorisedDispatch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        if matches!(self.mode, FakePortMode::Refused) {
            return Err(PortDispatchError::RefusedBeforeEffect);
        }
        self.calls.push(action);
        match self.mode {
            FakePortMode::Accepted => Ok(PortDispatchOutcome::Accepted(self.calls.len())),
            FakePortMode::Settled => Ok(PortDispatchOutcome::Settled(self.calls.len())),
            FakePortMode::LostReply => Err(PortDispatchError::UncertainAfterPossibleEffect {
                receipt_ref: Some(PortReceiptRef::from_port("receipt.fixture").unwrap()),
            }),
            FakePortMode::Refused => unreachable!(),
        }
    }

    fn launch_bound(
        &mut self,
        _launch: AuthorisedBoundLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        Err(PortDispatchError::RefusedBeforeEffect)
    }
}

fn manager(value: u64) -> ManagerEpoch {
    ManagerEpoch::new(value).unwrap()
}
fn pod_epoch(value: u64) -> PodIncarnation {
    PodIncarnation::new(value).unwrap()
}
fn resource_epoch(value: u64) -> ResourceEpoch {
    ResourceEpoch::new(value).unwrap()
}
fn credential_epoch(value: u64) -> CredentialGeneration {
    CredentialGeneration::new(value).unwrap()
}
fn input_epoch(value: u64) -> InputEpoch {
    InputEpoch::new(value).unwrap()
}

fn subject(pid: u32, start: u64, cgroup: &str) -> AuthenticatedProcessSubject {
    AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(1000, pid, start, cgroup)
        .unwrap()
}

fn rights(entries: impl IntoIterator<Item = (Operation, Target)>) -> BTreeSet<Right> {
    entries
        .into_iter()
        .map(|(op, target)| Right::new(op, target))
        .collect()
}

fn guards(owner: u64, pod: u64, resource: Option<u64>, credential: u64) -> GuardSet {
    GuardSet {
        manager_epoch: manager(owner),
        pod_incarnation: pod_epoch(pod),
        resource_epoch: resource.map(resource_epoch),
        credential_generation: credential_epoch(credential),
    }
}

fn request(
    scope: &ScopeId,
    grant_id: GrantId,
    guards: GuardSet,
    action: HostAction,
) -> HostRequest {
    HostRequest {
        scope_id: scope.clone(),
        grant_id,
        guards,
        command_key: "command.fixture".into(),
        correlation_id: "correlation.fixture".into(),
        deadline: Instant::now() + Duration::from_secs(30),
        action,
    }
}

struct Fixture {
    host: HostAuthority<FakePort>,
    owner: FakeTransport,
    coordinator: FakeTransport,
    sibling: FakeTransport,
    child: FakeTransport,
    scope: ScopeId,
    sibling_scope: ScopeId,
    pod: PodId,
    child_pod: PodId,
    resource: ResourceId,
    sibling_resource: ResourceId,
    owner_actor: ActorId,
    coordinator_actor: ActorId,
    child_actor: ActorId,
    owner_grant: GrantId,
    coordinator_grant: GrantId,
    sibling_grant: GrantId,
}

fn fixture() -> Fixture {
    let scope = ScopeId::try_from("scope.main").unwrap();
    let sibling_scope = ScopeId::try_from("scope.sibling").unwrap();
    let pod = PodId::try_from("pod.coordinator").unwrap();
    let child_pod = PodId::try_from("pod.child").unwrap();
    let sibling_pod = PodId::try_from("pod.sibling").unwrap();
    let resource = ResourceId::try_from("resource.main").unwrap();
    let sibling_resource = ResourceId::try_from("resource.sibling").unwrap();
    let owner_actor = ActorId::try_from("actor.owner").unwrap();
    let coordinator_actor = ActorId::try_from("actor.coordinator").unwrap();
    let child_actor = ActorId::try_from("actor.child").unwrap();
    let sibling_actor = ActorId::try_from("actor.sibling").unwrap();
    let owner_process = subject(101, 1001, "/user.slice/user-1000.slice/session-2.scope");
    let coordinator_process = subject(
        201,
        2001,
        "/user.slice/user-1000.slice/user@1000.service/app.slice/pod-coordinator.scope",
    );
    let child_process = subject(
        202,
        2002,
        "/user.slice/user-1000.slice/user@1000.service/app.slice/pod-child.scope",
    );
    let sibling_process = subject(
        203,
        2003,
        "/user.slice/user-1000.slice/user@1000.service/app.slice/pod-sibling.scope",
    );
    let mut host = HostAuthority::new(FakePort::default(), manager(1));
    for (scope_id, pod_id) in [
        (scope.clone(), pod.clone()),
        (scope.clone(), child_pod.clone()),
        (sibling_scope.clone(), sibling_pod.clone()),
    ] {
        host.register_pod_from_trusted_policy(PodRegistration {
            scope_id,
            pod_id,
            incarnation: pod_epoch(1),
        })
        .unwrap();
    }
    for (scope_id, resource_id, pod_id) in [
        (scope.clone(), resource.clone(), pod.clone()),
        (
            sibling_scope.clone(),
            sibling_resource.clone(),
            sibling_pod.clone(),
        ),
    ] {
        host.register_resource_from_trusted_policy(ResourceRegistration {
            scope_id,
            resource_id,
            pod_id,
            pod_incarnation: pod_epoch(1),
            resource_epoch: resource_epoch(1),
            input_epoch: input_epoch(1),
        })
        .unwrap();
    }
    host.register_actor_from_trusted_policy(ActorRegistration::owner_cli_from_trusted_policy(
        owner_actor.clone(),
        scope.clone(),
        owner_process.clone(),
        credential_epoch(1),
    ))
    .unwrap();
    for (actor_id, scope_id, role, pod_id, parent_actor_id, process) in [
        (
            coordinator_actor.clone(),
            scope.clone(),
            Role::Coordinator,
            pod.clone(),
            None,
            coordinator_process.clone(),
        ),
        (
            child_actor.clone(),
            scope.clone(),
            Role::Worker,
            child_pod.clone(),
            Some(coordinator_actor.clone()),
            child_process.clone(),
        ),
        (
            sibling_actor.clone(),
            sibling_scope.clone(),
            Role::Worker,
            sibling_pod.clone(),
            None,
            sibling_process.clone(),
        ),
    ] {
        host.register_actor_from_trusted_policy(ActorRegistration::pod_from_trusted_policy(
            actor_id,
            scope_id,
            role,
            pod_id,
            pod_epoch(1),
            parent_actor_id,
            process,
            credential_epoch(1),
        ))
        .unwrap();
    }
    let owner = FakeTransport(AuthenticatedPeer::owner_cli_from_authenticated_transport(
        owner_process,
        credential_epoch(1),
    ));
    let coordinator = FakeTransport(AuthenticatedPeer::pod_from_authenticated_transport(
        coordinator_actor.clone(),
        pod.clone(),
        pod_epoch(1),
        coordinator_process,
        credential_epoch(1),
    ));
    let child = FakeTransport(AuthenticatedPeer::pod_from_authenticated_transport(
        child_actor.clone(),
        child_pod.clone(),
        pod_epoch(1),
        child_process,
        credential_epoch(1),
    ));
    let sibling = FakeTransport(AuthenticatedPeer::pod_from_authenticated_transport(
        sibling_actor.clone(),
        sibling_pod,
        pod_epoch(1),
        sibling_process,
        credential_epoch(1),
    ));
    let owner_grant = host
        .install_grant_from_trusted_policy(
            &owner_actor,
            GrantSpec {
                scope_id: scope.clone(),
                mode: GrantMode::Controller,
                rights: rights([
                    (
                        Operation::ObserveResource,
                        Target::Resource(resource.clone()),
                    ),
                    (Operation::AcquireInput, Target::Resource(resource.clone())),
                    (Operation::TakeoverInput, Target::Resource(resource.clone())),
                    (Operation::WriteInput, Target::Resource(resource.clone())),
                    (
                        Operation::ResizeResource,
                        Target::Resource(resource.clone()),
                    ),
                    (Operation::LaunchPod, Target::Pod(child_pod.clone())),
                ]),
                remaining_delegation_depth: 2,
            },
        )
        .unwrap();
    let coordinator_grant = host
        .install_grant_from_trusted_policy(
            &coordinator_actor,
            GrantSpec {
                scope_id: scope.clone(),
                mode: GrantMode::Controller,
                rights: rights([
                    (
                        Operation::ObserveResource,
                        Target::Resource(resource.clone()),
                    ),
                    (Operation::AcquireInput, Target::Resource(resource.clone())),
                    (Operation::WriteInput, Target::Resource(resource.clone())),
                    (Operation::LaunchPod, Target::Pod(child_pod.clone())),
                ]),
                remaining_delegation_depth: 1,
            },
        )
        .unwrap();
    let sibling_grant = host
        .install_grant_from_trusted_policy(
            &sibling_actor,
            GrantSpec {
                scope_id: sibling_scope.clone(),
                mode: GrantMode::Viewer,
                rights: rights([(
                    Operation::ObserveResource,
                    Target::Resource(sibling_resource.clone()),
                )]),
                remaining_delegation_depth: 0,
            },
        )
        .unwrap();
    Fixture {
        host,
        owner,
        coordinator,
        sibling,
        child,
        scope,
        sibling_scope,
        pod,
        child_pod,
        resource,
        sibling_resource,
        owner_actor,
        coordinator_actor,
        child_actor,
        owner_grant,
        coordinator_grant,
        sibling_grant,
    }
}

#[test]
fn same_uid_sibling_and_spoofed_process_cannot_use_another_grant() {
    let mut f = fixture();
    assert_eq!(
        f.host.dispatch(
            &f.owner,
            request(
                &f.scope,
                f.owner_grant,
                guards(1, 1, Some(1), 1),
                HostAction::ObserveResource {
                    resource_id: f.resource.clone()
                },
            )
        ),
        Ok(PortDispatchOutcome::Accepted(1))
    );
    assert_eq!(
        f.host.dispatch(
            &f.coordinator,
            request(
                &f.scope,
                f.owner_grant,
                guards(1, 1, Some(1), 1),
                HostAction::ObserveResource {
                    resource_id: f.resource.clone()
                },
            )
        ),
        Err(HostError::Unauthorised)
    );
    assert_eq!(
        f.host.dispatch(
            &f.sibling,
            request(
                &f.scope,
                f.coordinator_grant,
                guards(1, 1, Some(1), 1),
                HostAction::ObserveResource {
                    resource_id: f.resource.clone()
                },
            )
        ),
        Err(HostError::Unauthorised)
    );
    let forged = FakeTransport(AuthenticatedPeer::pod_from_authenticated_transport(
        f.coordinator_actor.clone(),
        f.pod.clone(),
        pod_epoch(1),
        subject(
            203,
            2003,
            "/user.slice/user-1000.slice/user@1000.service/app.slice/pod-sibling.scope",
        ),
        credential_epoch(1),
    ));
    assert_eq!(
        f.host.dispatch(
            &forged,
            request(
                &f.scope,
                f.coordinator_grant,
                guards(1, 1, Some(1), 1),
                HostAction::ObserveResource {
                    resource_id: f.resource.clone()
                },
            )
        ),
        Err(HostError::Unauthenticated)
    );
    assert_eq!(f.host.port().calls.len(), 1);
}

#[test]
fn viewer_and_coordinator_role_do_not_grant_control() {
    let mut f = fixture();
    let viewer = f
        .host
        .install_grant_from_trusted_policy(
            &f.coordinator_actor,
            GrantSpec {
                scope_id: f.scope.clone(),
                mode: GrantMode::Viewer,
                rights: rights([(
                    Operation::ObserveResource,
                    Target::Resource(f.resource.clone()),
                )]),
                remaining_delegation_depth: 0,
            },
        )
        .unwrap();
    assert_eq!(
        f.host.dispatch(
            &f.coordinator,
            request(
                &f.scope,
                viewer,
                guards(1, 1, Some(1), 1),
                HostAction::ObserveResource {
                    resource_id: f.resource.clone()
                },
            )
        ),
        Ok(PortDispatchOutcome::Accepted(1))
    );
    assert_eq!(
        f.host.dispatch(
            &f.coordinator,
            request(
                &f.scope,
                viewer,
                guards(1, 1, None, 1),
                HostAction::LaunchPod {
                    pod_id: f.child_pod.clone(),
                    role: Role::Coordinator,
                    credential: None
                },
            )
        ),
        Err(HostError::Unauthorised)
    );
    assert_eq!(
        f.host.install_grant_from_trusted_policy(
            &f.coordinator_actor,
            GrantSpec {
                scope_id: f.scope.clone(),
                mode: GrantMode::Viewer,
                rights: rights([(Operation::WriteInput, Target::Resource(f.resource.clone()))]),
                remaining_delegation_depth: 0,
            }
        ),
        Err(HostError::Unauthorised)
    );
    assert_eq!(
        f.host.dispatch(
            &f.sibling,
            request(
                &f.sibling_scope,
                f.sibling_grant,
                guards(1, 1, Some(1), 1),
                HostAction::ObserveResource {
                    resource_id: f.sibling_resource.clone()
                },
            )
        ),
        Ok(PortDispatchOutcome::Accepted(2))
    );
    assert_eq!(f.host.port().calls.len(), 2);
}

#[test]
fn child_grant_must_reduce_scope_rights_mode_and_depth() {
    let mut f = fixture();
    let unrelated_pod = PodId::try_from("pod.unrelated").unwrap();
    let unrelated_actor = ActorId::try_from("actor.unrelated").unwrap();
    f.host
        .register_pod_from_trusted_policy(PodRegistration {
            scope_id: f.scope.clone(),
            pod_id: unrelated_pod.clone(),
            incarnation: pod_epoch(1),
        })
        .unwrap();
    f.host
        .register_actor_from_trusted_policy(ActorRegistration::pod_from_trusted_policy(
            unrelated_actor.clone(),
            f.scope.clone(),
            Role::Worker,
            unrelated_pod,
            pod_epoch(1),
            Some(f.owner_actor.clone()),
            subject(
                204,
                2004,
                "/user.slice/user-1000.slice/user@1000.service/app.slice/pod-unrelated.scope",
            ),
            credential_epoch(1),
        ))
        .unwrap();
    assert_eq!(
        f.host.delegate_child(
            &f.coordinator,
            f.coordinator_grant,
            &unrelated_actor,
            GrantSpec {
                scope_id: f.scope.clone(),
                mode: GrantMode::Viewer,
                rights: rights([(
                    Operation::ObserveResource,
                    Target::Resource(f.resource.clone()),
                )]),
                remaining_delegation_depth: 0,
            },
        ),
        Err(HostError::Unauthorised)
    );
    assert_eq!(
        f.host.delegate_child(
            &f.coordinator,
            f.coordinator_grant,
            &f.child_actor,
            GrantSpec {
                scope_id: f.scope.clone(),
                mode: GrantMode::Controller,
                rights: rights([(
                    Operation::TakeoverInput,
                    Target::Resource(f.resource.clone()),
                )]),
                remaining_delegation_depth: 0,
            },
        ),
        Err(HostError::Unauthorised)
    );
    let child_grant = f
        .host
        .delegate_child(
            &f.coordinator,
            f.coordinator_grant,
            &f.child_actor,
            GrantSpec {
                scope_id: f.scope.clone(),
                mode: GrantMode::Viewer,
                rights: rights([(
                    Operation::ObserveResource,
                    Target::Resource(f.resource.clone()),
                )]),
                remaining_delegation_depth: 0,
            },
        )
        .unwrap();
    assert_eq!(
        f.host.dispatch(
            &f.child,
            request(
                &f.scope,
                child_grant,
                guards(1, 1, Some(1), 1),
                HostAction::ObserveResource {
                    resource_id: f.resource.clone()
                },
            )
        ),
        Ok(PortDispatchOutcome::Accepted(1))
    );
    assert_eq!(
        f.host.dispatch(
            &f.child,
            request(
                &f.scope,
                child_grant,
                guards(1, 1, None, 1),
                HostAction::LaunchPod {
                    pod_id: f.child_pod.clone(),
                    role: Role::Worker,
                    credential: None
                },
            )
        ),
        Err(HostError::Unauthorised)
    );
    assert_eq!(
        f.host.delegate_child(
            &f.coordinator,
            f.coordinator_grant,
            &f.child_actor,
            GrantSpec {
                scope_id: f.sibling_scope.clone(),
                mode: GrantMode::Viewer,
                rights: rights([(
                    Operation::ObserveResource,
                    Target::Resource(f.sibling_resource.clone())
                )]),
                remaining_delegation_depth: 0,
            }
        ),
        Err(HostError::Unauthorised)
    );
    assert_eq!(
        f.host.delegate_child(
            &f.coordinator,
            f.coordinator_grant,
            &f.child_actor,
            GrantSpec {
                scope_id: f.scope.clone(),
                mode: GrantMode::Controller,
                rights: rights([(
                    Operation::ObserveResource,
                    Target::Resource(f.resource.clone())
                )]),
                remaining_delegation_depth: 1,
            }
        ),
        Err(HostError::Unauthorised)
    );
    assert_eq!(f.host.port().calls.len(), 1);
}

#[test]
fn stale_manager_pod_resource_and_credential_guards_refuse() {
    let mut f = fixture();
    let view = || HostAction::ObserveResource {
        resource_id: f.resource.clone(),
    };
    f.host
        .advance_manager_epoch_from_trusted_policy(manager(1), manager(2))
        .unwrap();
    assert_eq!(
        f.host.dispatch(
            &f.owner,
            request(&f.scope, f.owner_grant, guards(1, 1, Some(1), 1), view())
        ),
        Err(HostError::StaleGuard)
    );
    assert_eq!(
        f.host.dispatch(
            &f.owner,
            request(&f.scope, f.owner_grant, guards(2, 1, Some(1), 1), view())
        ),
        Ok(PortDispatchOutcome::Accepted(1))
    );
    f.host
        .advance_resource_epoch_from_trusted_policy(
            &f.resource,
            resource_epoch(1),
            resource_epoch(2),
        )
        .unwrap();
    assert_eq!(
        f.host.dispatch(
            &f.owner,
            request(&f.scope, f.owner_grant, guards(2, 1, Some(1), 1), view())
        ),
        Err(HostError::StaleGuard)
    );
    assert_eq!(
        f.host.dispatch(
            &f.owner,
            request(&f.scope, f.owner_grant, guards(2, 1, Some(2), 1), view())
        ),
        Ok(PortDispatchOutcome::Accepted(2))
    );
    f.host
        .advance_pod_incarnation_from_trusted_policy(&f.pod, pod_epoch(1), pod_epoch(2))
        .unwrap();
    assert_eq!(
        f.host.dispatch(
            &f.owner,
            request(&f.scope, f.owner_grant, guards(2, 1, Some(2), 1), view())
        ),
        Err(HostError::StaleGuard)
    );
    f.host
        .advance_credential_generation_from_trusted_policy(
            &f.owner_actor,
            credential_epoch(1),
            credential_epoch(2),
        )
        .unwrap();
    assert_eq!(
        f.host.dispatch(
            &f.owner,
            request(&f.scope, f.owner_grant, guards(2, 2, Some(2), 1), view())
        ),
        Err(HostError::Unauthenticated)
    );
    let renewed_owner = FakeTransport(AuthenticatedPeer::owner_cli_from_authenticated_transport(
        subject(101, 1001, "/user.slice/user-1000.slice/session-2.scope"),
        credential_epoch(2),
    ));
    assert_eq!(
        f.host.dispatch(
            &renewed_owner,
            request(&f.scope, f.owner_grant, guards(2, 2, Some(2), 2), view(),),
        ),
        Err(HostError::Unauthorised)
    );
    assert_eq!(f.host.port().calls.len(), 2);
}

#[test]
fn human_takeover_fences_old_input_lease_before_port_call() {
    let mut f = fixture();
    let first = f
        .host
        .acquire_input_lease(
            &f.coordinator,
            f.coordinator_grant,
            &f.scope,
            &f.resource,
            guards(1, 1, Some(1), 1),
            input_epoch(1),
            Duration::from_secs(30),
        )
        .unwrap();
    assert_eq!(first.input_epoch(), input_epoch(2));
    let old_write = || HostAction::WriteInput {
        resource_id: f.resource.clone(),
        lease: first.clone(),
        bytes: b"hello".to_vec(),
    };
    assert_eq!(
        f.host.dispatch(
            &f.coordinator,
            request(
                &f.scope,
                f.coordinator_grant,
                guards(1, 1, Some(1), 1),
                old_write()
            )
        ),
        Ok(PortDispatchOutcome::Accepted(1))
    );
    let owner_lease = f
        .host
        .human_takeover_input_lease(
            &f.owner,
            f.owner_grant,
            &f.scope,
            &f.resource,
            guards(1, 1, Some(1), 1),
            input_epoch(2),
            Duration::from_secs(30),
        )
        .unwrap();
    assert_eq!(owner_lease.input_epoch(), input_epoch(3));
    assert_eq!(
        f.host.dispatch(
            &f.coordinator,
            request(
                &f.scope,
                f.coordinator_grant,
                guards(1, 1, Some(1), 1),
                old_write()
            )
        ),
        Err(HostError::StaleGuard)
    );
    assert_eq!(
        f.host.dispatch(
            &f.owner,
            request(
                &f.scope,
                f.owner_grant,
                guards(1, 1, Some(1), 1),
                HostAction::WriteInput {
                    resource_id: f.resource.clone(),
                    lease: owner_lease,
                    bytes: b"owner".to_vec(),
                }
            )
        ),
        Ok(PortDispatchOutcome::Accepted(2))
    );
    assert_eq!(f.host.port().calls.len(), 2);
}

#[test]
fn trusted_resource_rebind_recovers_new_pod_and_revokes_old_lease() {
    let mut f = fixture();
    let old_lease = f
        .host
        .acquire_input_lease(
            &f.owner,
            f.owner_grant,
            &f.scope,
            &f.resource,
            guards(1, 1, Some(1), 1),
            input_epoch(1),
            Duration::from_secs(30),
        )
        .unwrap();
    f.host
        .advance_pod_incarnation_from_trusted_policy(&f.pod, pod_epoch(1), pod_epoch(2))
        .unwrap();
    assert_eq!(
        f.host.dispatch(
            &f.owner,
            request(
                &f.scope,
                f.owner_grant,
                guards(1, 2, Some(1), 1),
                HostAction::ObserveResource {
                    resource_id: f.resource.clone(),
                },
            ),
        ),
        Err(HostError::StaleGuard)
    );
    f.host
        .rebind_resource_from_trusted_policy(
            ResourceRegistration {
                scope_id: f.scope.clone(),
                resource_id: f.resource.clone(),
                pod_id: f.pod.clone(),
                pod_incarnation: pod_epoch(2),
                resource_epoch: resource_epoch(2),
                input_epoch: input_epoch(3),
            },
            pod_epoch(1),
            resource_epoch(1),
            input_epoch(2),
        )
        .unwrap();
    assert_eq!(
        f.host.dispatch(
            &f.owner,
            request(
                &f.scope,
                f.owner_grant,
                guards(1, 2, Some(2), 1),
                HostAction::WriteInput {
                    resource_id: f.resource.clone(),
                    lease: old_lease,
                    bytes: b"stale".to_vec(),
                },
            ),
        ),
        Err(HostError::StaleGuard)
    );
    assert_eq!(
        f.host.dispatch(
            &f.owner,
            request(
                &f.scope,
                f.owner_grant,
                guards(1, 2, Some(2), 1),
                HostAction::ObserveResource {
                    resource_id: f.resource.clone(),
                },
            ),
        ),
        Ok(PortDispatchOutcome::Accepted(1))
    );
    let new_lease = f
        .host
        .acquire_input_lease(
            &f.owner,
            f.owner_grant,
            &f.scope,
            &f.resource,
            guards(1, 2, Some(2), 1),
            input_epoch(3),
            Duration::from_secs(30),
        )
        .unwrap();
    assert_eq!(new_lease.input_epoch(), input_epoch(4));
    assert_eq!(f.host.port().calls.len(), 1);
}

#[test]
fn credential_reference_needs_exact_grant_and_fresh_host_fails_closed() {
    let mut f = fixture();
    let reference = CredentialRef::from_trusted_vault(f.scope.clone(), "vault.ref.one").unwrap();
    assert!(!format!("{reference:?}").contains("vault.ref.one"));
    let launch = || HostAction::LaunchPod {
        pod_id: f.child_pod.clone(),
        role: Role::Coordinator,
        credential: Some(reference.clone()),
    };
    assert_eq!(
        f.host.dispatch(
            &f.owner,
            request(&f.scope, f.owner_grant, guards(1, 1, None, 1), launch())
        ),
        Err(HostError::Unauthorised)
    );
    let sibling_reference =
        CredentialRef::from_trusted_vault(f.sibling_scope.clone(), "vault.ref.sibling").unwrap();
    assert_eq!(
        f.host.install_grant_from_trusted_policy(
            &f.owner_actor,
            GrantSpec {
                scope_id: f.scope.clone(),
                mode: GrantMode::Controller,
                rights: rights([
                    (Operation::LaunchPod, Target::Pod(f.child_pod.clone())),
                    (
                        Operation::UseCredential,
                        Target::Credential(sibling_reference),
                    ),
                ]),
                remaining_delegation_depth: 0,
            },
        ),
        Err(HostError::Unauthorised)
    );
    let exact = f
        .host
        .install_grant_from_trusted_policy(
            &f.owner_actor,
            GrantSpec {
                scope_id: f.scope.clone(),
                mode: GrantMode::Controller,
                rights: rights([
                    (Operation::LaunchPod, Target::Pod(f.child_pod.clone())),
                    (
                        Operation::UseCredential,
                        Target::Credential(reference.clone()),
                    ),
                ]),
                remaining_delegation_depth: 0,
            },
        )
        .unwrap();
    assert_eq!(
        f.host.dispatch(
            &f.owner,
            request(&f.scope, exact, guards(1, 1, None, 1), launch())
        ),
        Ok(PortDispatchOutcome::Accepted(1))
    );
    let mut fresh = HostAuthority::new(FakePort::default(), manager(1));
    assert_eq!(
        fresh.dispatch(
            &f.owner,
            request(&f.scope, exact, guards(1, 1, None, 1), launch())
        ),
        Err(HostError::Unauthenticated)
    );
    assert_eq!(fresh.port().calls.len(), 0);
}

#[test]
fn scope_launch_right_never_grants_stop_or_credential_use() {
    let mut f = fixture();
    let grant = f
        .host
        .install_grant_from_trusted_policy(
            &f.owner_actor,
            GrantSpec {
                scope_id: f.scope.clone(),
                mode: GrantMode::Controller,
                rights: rights([(Operation::LaunchPod, Target::Scope(f.scope.clone()))]),
                remaining_delegation_depth: 0,
            },
        )
        .unwrap();
    let launch = HostAction::LaunchPod {
        pod_id: f.child_pod.clone(),
        role: Role::Worker,
        credential: None,
    };
    assert_eq!(
        f.host.dispatch(
            &f.owner,
            request(&f.scope, grant, guards(1, 1, None, 1), launch)
        ),
        Err(HostError::Unauthorised)
    );
    assert_eq!(
        f.host.dispatch(
            &f.owner,
            request(
                &f.scope,
                grant,
                guards(1, 1, None, 1),
                HostAction::StopPod {
                    pod_id: f.child_pod.clone()
                }
            )
        ),
        Err(HostError::Unauthorised)
    );
    let reference = CredentialRef::from_trusted_vault(f.scope.clone(), "vault.scope.only").unwrap();
    assert_eq!(
        f.host.dispatch(
            &f.owner,
            request(
                &f.scope,
                grant,
                guards(1, 1, None, 1),
                HostAction::LaunchPod {
                    pod_id: f.child_pod.clone(),
                    role: Role::Worker,
                    credential: Some(reference),
                }
            )
        ),
        Err(HostError::Unauthorised)
    );
    for right in [
        Right::new(Operation::LaunchPod, Target::Scope(f.sibling_scope.clone())),
        Right::new(Operation::StopPod, Target::Scope(f.scope.clone())),
    ] {
        assert_eq!(
            f.host.install_grant_from_trusted_policy(
                &f.owner_actor,
                GrantSpec {
                    scope_id: f.scope.clone(),
                    mode: GrantMode::Controller,
                    rights: BTreeSet::from([right]),
                    remaining_delegation_depth: 0,
                }
            ),
            Err(HostError::Unauthorised)
        );
    }
    assert_eq!(f.host.port().calls.len(), 0);
}

#[test]
fn scope_send_right_is_same_scope_controller_only_and_grants_no_other_action() {
    let mut f = fixture();
    let send = f
        .host
        .install_grant_from_trusted_policy(
            &f.owner_actor,
            GrantSpec {
                scope_id: f.scope.clone(),
                mode: GrantMode::Controller,
                rights: rights([(Operation::SendSession, Target::Scope(f.scope.clone()))]),
                remaining_delegation_depth: 0,
            },
        )
        .unwrap();
    for right in [
        Right::new(
            Operation::SendSession,
            Target::Scope(f.sibling_scope.clone()),
        ),
        Right::new(Operation::SendSession, Target::Resource(f.resource.clone())),
    ] {
        assert_eq!(
            f.host.install_grant_from_trusted_policy(
                &f.owner_actor,
                GrantSpec {
                    scope_id: f.scope.clone(),
                    mode: GrantMode::Controller,
                    rights: BTreeSet::from([right]),
                    remaining_delegation_depth: 0,
                }
            ),
            Err(HostError::Unauthorised)
        );
    }
    assert_eq!(
        f.host.install_grant_from_trusted_policy(
            &f.owner_actor,
            GrantSpec {
                scope_id: f.scope.clone(),
                mode: GrantMode::Viewer,
                rights: rights([(Operation::SendSession, Target::Scope(f.scope.clone()))]),
                remaining_delegation_depth: 0,
            }
        ),
        Err(HostError::Unauthorised)
    );
    for action in [
        HostAction::LaunchPod {
            pod_id: f.child_pod.clone(),
            role: Role::Worker,
            credential: None,
        },
        HostAction::StopPod {
            pod_id: f.child_pod.clone(),
        },
        HostAction::ObserveResource {
            resource_id: f.resource.clone(),
        },
    ] {
        assert_eq!(
            f.host.dispatch(
                &f.owner,
                request(&f.scope, send, guards(1, 1, None, 1), action)
            ),
            Err(HostError::Unauthorised)
        );
    }
    let lease = f
        .host
        .acquire_input_lease(
            &f.owner,
            f.owner_grant,
            &f.scope,
            &f.resource,
            guards(1, 1, Some(1), 1),
            input_epoch(1),
            Duration::from_secs(30),
        )
        .unwrap();
    assert_eq!(
        f.host.dispatch(
            &f.owner,
            request(
                &f.scope,
                send,
                guards(1, 1, Some(1), 1),
                HostAction::WriteInput {
                    resource_id: f.resource.clone(),
                    lease,
                    bytes: b"hello".to_vec(),
                },
            )
        ),
        Err(HostError::Unauthorised)
    );
    assert_eq!(f.host.port().calls.len(), 0);
}

#[test]
fn linux_subject_accepts_realistic_cgroup_but_rejects_relative_identity() {
    let real = AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(
        1000,
        4242,
        987654,
        "/user.slice/user-1000.slice/user@1000.service/app.slice/pod-42.scope",
    );
    assert!(real.is_ok());
    assert_eq!(
        AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(
            1000,
            4242,
            987654,
            "user.slice/pod-42.scope",
        ),
        Err(HostError::InvalidInput)
    );
    assert!(matches!(
        HostAuthority::for_platform(FakePort::default(), manager(1), HostPlatform::MacOs),
        Err(HostError::Unsupported)
    ));
    assert!(matches!(
        HostAuthority::for_platform(FakePort::default(), manager(1), HostPlatform::Windows),
        Err(HostError::Unsupported)
    ));
}

#[test]
fn port_reply_loss_remains_uncertain_after_possible_effect() {
    let mut f = fixture();
    let launch = || HostAction::LaunchPod {
        pod_id: f.child_pod.clone(),
        role: Role::Worker,
        credential: None,
    };
    f.host.port_mut().mode = FakePortMode::Refused;
    assert_eq!(
        f.host.dispatch(
            &f.owner,
            request(&f.scope, f.owner_grant, guards(1, 1, None, 1), launch()),
        ),
        Err(HostError::RefusedBeforeEffect)
    );
    assert_eq!(f.host.port().calls.len(), 0);

    f.host.port_mut().mode = FakePortMode::LostReply;
    assert_eq!(
        f.host.dispatch(
            &f.owner,
            request(&f.scope, f.owner_grant, guards(1, 1, None, 1), launch()),
        ),
        Err(HostError::UncertainAfterPossibleEffect {
            command_key: "command.fixture".into(),
            receipt_ref: Some(PortReceiptRef::from_port("receipt.fixture").unwrap()),
        })
    );
    assert_eq!(f.host.port().calls.len(), 1);

    f.host.port_mut().mode = FakePortMode::Settled;
    let mut view = request(
        &f.scope,
        f.owner_grant,
        guards(1, 1, Some(1), 1),
        HostAction::ObserveResource {
            resource_id: f.resource.clone(),
        },
    );
    view.command_key = "command.view".into();
    assert_eq!(
        f.host.dispatch(&f.owner, view),
        Ok(PortDispatchOutcome::Settled(2))
    );
    assert_eq!(f.host.port().calls.len(), 2);
}
