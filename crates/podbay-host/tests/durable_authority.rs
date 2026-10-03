use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use podbay_core::{ActorId, PodId, ResourceId, Role, ScopeId};
use podbay_host::{
    ActorRegistration, AuthenticatedPeer, AuthenticatedProcessSubject, AuthenticatedTransport,
    AuthorisedDispatch, AuthorisedLaunch, CredentialGeneration, DurableAuthority,
    DurableAuthorityError, GrantMode, GrantSpec, GuardSet, HostAction, HostDispatchPort, HostError,
    HostRequest, InputEpoch, ManagerEpoch, Operation, PodIncarnation, PodRegistration,
    PortDispatchError, PortDispatchOutcome, ResourceEpoch, ResourceRegistration, Right, Target,
};
use podbay_store::PodBayStore;

struct Fixture {
    directory: PathBuf,
    database: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "podbay-host-authority-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        Self {
            database: directory.join("podbay.sqlite"),
            directory,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[derive(Default)]
struct FakePort {
    calls: Vec<AuthorisedDispatch>,
}

impl HostDispatchPort for FakePort {
    type Receipt = usize;

    fn dispatch(
        &mut self,
        action: AuthorisedDispatch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        self.calls.push(action);
        Ok(PortDispatchOutcome::Accepted(self.calls.len()))
    }

    fn launch(
        &mut self,
        _launch: AuthorisedLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        Err(PortDispatchError::RefusedBeforeEffect)
    }
}

#[derive(Clone)]
struct FakeTransport(AuthenticatedPeer);

impl AuthenticatedTransport for FakeTransport {
    fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError> {
        Ok(self.0.clone())
    }
}

fn subject(pid: u32, start: u64, cgroup: &str) -> AuthenticatedProcessSubject {
    AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(1000, pid, start, cgroup)
        .unwrap()
}

fn actor(
    scope: &ScopeId,
    actor_id: &ActorId,
    pod: &PodId,
    process: &AuthenticatedProcessSubject,
) -> ActorRegistration {
    ActorRegistration::pod_from_trusted_policy(
        actor_id.clone(),
        scope.clone(),
        Role::Coordinator,
        pod.clone(),
        PodIncarnation::new(1).unwrap(),
        None,
        process.clone(),
        CredentialGeneration::new(1).unwrap(),
    )
}

fn peer(actor_id: &ActorId, pod: &PodId, process: &AuthenticatedProcessSubject) -> FakeTransport {
    FakeTransport(AuthenticatedPeer::pod_from_authenticated_transport(
        actor_id.clone(),
        pod.clone(),
        PodIncarnation::new(1).unwrap(),
        process.clone(),
        CredentialGeneration::new(1).unwrap(),
    ))
}

fn guards(owner: u64) -> GuardSet {
    GuardSet {
        manager_epoch: ManagerEpoch::new(owner).unwrap(),
        pod_incarnation: PodIncarnation::new(1).unwrap(),
        resource_epoch: Some(ResourceEpoch::new(1).unwrap()),
        credential_generation: CredentialGeneration::new(1).unwrap(),
    }
}

fn request(
    scope: &ScopeId,
    grant_id: podbay_host::GrantId,
    owner: u64,
    action: HostAction,
) -> HostRequest {
    HostRequest {
        scope_id: scope.clone(),
        grant_id,
        guards: guards(owner),
        command_key: "command.durable".into(),
        correlation_id: "correlation.durable".into(),
        deadline: Instant::now() + Duration::from_secs(30),
        action,
    }
}

fn grant(scope: &ScopeId, resource: &ResourceId) -> GrantSpec {
    GrantSpec {
        scope_id: scope.clone(),
        mode: GrantMode::Controller,
        rights: [
            Right::new(
                Operation::ObserveResource,
                Target::Resource(resource.clone()),
            ),
            Right::new(Operation::AcquireInput, Target::Resource(resource.clone())),
            Right::new(Operation::WriteInput, Target::Resource(resource.clone())),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>(),
        remaining_delegation_depth: 0,
    }
}

#[test]
fn restart_requires_reattest_and_fences_old_input_lease() {
    let fixture = Fixture::new();
    let scope = ScopeId::try_from("scope.main").unwrap();
    let pod = PodId::try_from("pod.main").unwrap();
    let resource = ResourceId::try_from("resource.main").unwrap();
    let actor_id = ActorId::try_from("actor.main").unwrap();
    let process = subject(200, 300, "/user.slice/pod-main.scope");
    let transport = peer(&actor_id, &pod, &process);
    let registration = actor(&scope, &actor_id, &pod, &process);

    let mut first = DurableAuthority::open(&fixture.database, FakePort::default()).unwrap();
    assert_eq!(first.owner_epoch().get(), 1);
    first
        .register_pod_from_trusted_policy(PodRegistration {
            scope_id: scope.clone(),
            pod_id: pod.clone(),
            incarnation: PodIncarnation::new(1).unwrap(),
        })
        .unwrap();
    first
        .register_resource_from_trusted_policy(ResourceRegistration {
            scope_id: scope.clone(),
            resource_id: resource.clone(),
            pod_id: pod.clone(),
            pod_incarnation: PodIncarnation::new(1).unwrap(),
            resource_epoch: ResourceEpoch::new(1).unwrap(),
            input_epoch: InputEpoch::new(1).unwrap(),
        })
        .unwrap();
    first
        .register_actor_from_trusted_policy(registration.clone())
        .unwrap();
    let grant_id = first
        .install_grant_from_trusted_policy(&actor_id, grant(&scope, &resource))
        .unwrap();
    let old_lease = first
        .acquire_input_lease(
            &transport,
            grant_id,
            &scope,
            &resource,
            guards(1),
            InputEpoch::new(1).unwrap(),
            Duration::from_secs(30),
        )
        .unwrap();
    assert_eq!(old_lease.input_epoch().get(), 2);
    drop(first);

    let mut reopened = DurableAuthority::open(&fixture.database, FakePort::default()).unwrap();
    assert_eq!(reopened.owner_epoch().get(), 2);
    assert_eq!(reopened.recorded_snapshot().resources[0].input_epoch, 3);
    let old_action = || HostAction::WriteInput {
        resource_id: resource.clone(),
        lease: old_lease.clone(),
        bytes: b"old".to_vec(),
    };
    assert!(matches!(
        reopened.dispatch(&transport, request(&scope, grant_id, 2, old_action())),
        Err(HostError::Unauthenticated)
    ));
    assert_eq!(reopened.port().calls.len(), 0);
    let wrong_process = subject(200, 301, "/user.slice/pod-main.scope");
    assert!(reopened
        .reattest_actor_from_trusted_replay(
            &peer(&actor_id, &pod, &wrong_process),
            registration.clone()
        )
        .is_err());
    reopened
        .reattest_actor_from_trusted_replay(&transport, registration)
        .unwrap();
    reopened
        .activate_grant_from_trusted_replay(grant_id)
        .unwrap();
    assert_eq!(
        reopened.dispatch(
            &transport,
            request(
                &scope,
                grant_id,
                2,
                HostAction::ObserveResource {
                    resource_id: resource.clone(),
                },
            ),
        ),
        Ok(PortDispatchOutcome::Accepted(1))
    );
    assert_eq!(
        reopened.dispatch(&transport, request(&scope, grant_id, 2, old_action())),
        Err(HostError::StaleGuard)
    );
    assert_eq!(reopened.port().calls.len(), 1);
    let new_lease = reopened
        .acquire_input_lease(
            &transport,
            grant_id,
            &scope,
            &resource,
            guards(2),
            InputEpoch::new(3).unwrap(),
            Duration::from_secs(30),
        )
        .unwrap();
    assert_eq!(new_lease.input_epoch().get(), 4);
    assert_eq!(
        reopened.dispatch(
            &transport,
            request(
                &scope,
                grant_id,
                2,
                HostAction::WriteInput {
                    resource_id: resource,
                    lease: new_lease,
                    bytes: b"new".to_vec(),
                },
            ),
        ),
        Ok(PortDispatchOutcome::Accepted(2))
    );
}

#[test]
fn same_uid_sibling_scope_stays_isolated_after_replay() {
    let fixture = Fixture::new();
    let scope_a = ScopeId::try_from("scope.alpha").unwrap();
    let scope_b = ScopeId::try_from("scope.beta").unwrap();
    let pod_a = PodId::try_from("pod.alpha").unwrap();
    let pod_b = PodId::try_from("pod.beta").unwrap();
    let resource_a = ResourceId::try_from("resource.alpha").unwrap();
    let resource_b = ResourceId::try_from("resource.beta").unwrap();
    let actor_a = ActorId::try_from("actor.alpha").unwrap();
    let actor_b = ActorId::try_from("actor.beta").unwrap();
    let process_a = subject(301, 401, "/user.slice/pod-alpha.scope");
    let process_b = subject(302, 402, "/user.slice/pod-beta.scope");
    let transport_a = peer(&actor_a, &pod_a, &process_a);
    let transport_b = peer(&actor_b, &pod_b, &process_b);
    let registration_a = actor(&scope_a, &actor_a, &pod_a, &process_a);
    let registration_b = actor(&scope_b, &actor_b, &pod_b, &process_b);
    let mut first = DurableAuthority::open(&fixture.database, FakePort::default()).unwrap();
    for (scope, pod, resource, registration) in [
        (&scope_a, &pod_a, &resource_a, registration_a.clone()),
        (&scope_b, &pod_b, &resource_b, registration_b.clone()),
    ] {
        first
            .register_pod_from_trusted_policy(PodRegistration {
                scope_id: scope.clone(),
                pod_id: pod.clone(),
                incarnation: PodIncarnation::new(1).unwrap(),
            })
            .unwrap();
        first
            .register_resource_from_trusted_policy(ResourceRegistration {
                scope_id: scope.clone(),
                resource_id: resource.clone(),
                pod_id: pod.clone(),
                pod_incarnation: PodIncarnation::new(1).unwrap(),
                resource_epoch: ResourceEpoch::new(1).unwrap(),
                input_epoch: InputEpoch::new(1).unwrap(),
            })
            .unwrap();
        first
            .register_actor_from_trusted_policy(registration)
            .unwrap();
    }
    let grant_a = first
        .install_grant_from_trusted_policy(&actor_a, grant(&scope_a, &resource_a))
        .unwrap();
    let grant_b = first
        .install_grant_from_trusted_policy(&actor_b, grant(&scope_b, &resource_b))
        .unwrap();
    drop(first);

    let mut reopened = DurableAuthority::open(&fixture.database, FakePort::default()).unwrap();
    assert_eq!(reopened.recorded_snapshot().actors.len(), 2);
    reopened
        .reattest_actor_from_trusted_replay(&transport_b, registration_b)
        .unwrap();
    reopened
        .activate_grant_from_trusted_replay(grant_b)
        .unwrap();
    assert_eq!(
        reopened.dispatch(
            &transport_b,
            request(
                &scope_a,
                grant_a,
                2,
                HostAction::ObserveResource {
                    resource_id: resource_a.clone(),
                },
            ),
        ),
        Err(HostError::Unauthorised)
    );
    assert_eq!(
        reopened.dispatch(
            &transport_b,
            request(
                &scope_a,
                grant_b,
                2,
                HostAction::ObserveResource {
                    resource_id: resource_a.clone(),
                },
            ),
        ),
        Err(HostError::Unauthorised)
    );
    assert_eq!(reopened.port().calls.len(), 0);
    assert_eq!(
        reopened.dispatch(
            &transport_b,
            request(
                &scope_b,
                grant_b,
                2,
                HostAction::ObserveResource {
                    resource_id: resource_b,
                },
            ),
        ),
        Ok(PortDispatchOutcome::Accepted(1))
    );
    reopened
        .reattest_actor_from_trusted_replay(&transport_a, registration_a)
        .unwrap();
    reopened
        .activate_grant_from_trusted_replay(grant_a)
        .unwrap();
    assert_eq!(
        reopened.dispatch(
            &transport_a,
            request(
                &scope_a,
                grant_a,
                2,
                HostAction::ObserveResource {
                    resource_id: resource_a,
                },
            ),
        ),
        Ok(PortDispatchOutcome::Accepted(2))
    );
}

#[test]
fn manager_lifetime_lock_prevents_dual_effect_owners() {
    let fixture = Fixture::new();
    let scope = ScopeId::try_from("scope.locked").unwrap();
    let pod = PodId::try_from("pod.locked").unwrap();
    let resource = ResourceId::try_from("resource.locked").unwrap();
    let actor_id = ActorId::try_from("actor.locked").unwrap();
    let process = subject(501, 601, "/user.slice/pod-locked.scope");
    let transport = peer(&actor_id, &pod, &process);
    let mut first = DurableAuthority::open(&fixture.database, FakePort::default()).unwrap();
    first
        .register_pod_from_trusted_policy(PodRegistration {
            scope_id: scope.clone(),
            pod_id: pod.clone(),
            incarnation: PodIncarnation::new(1).unwrap(),
        })
        .unwrap();
    first
        .register_resource_from_trusted_policy(ResourceRegistration {
            scope_id: scope.clone(),
            resource_id: resource.clone(),
            pod_id: pod.clone(),
            pod_incarnation: PodIncarnation::new(1).unwrap(),
            resource_epoch: ResourceEpoch::new(1).unwrap(),
            input_epoch: InputEpoch::new(1).unwrap(),
        })
        .unwrap();
    first
        .register_actor_from_trusted_policy(actor(&scope, &actor_id, &pod, &process))
        .unwrap();
    let grant_id = first
        .install_grant_from_trusted_policy(&actor_id, grant(&scope, &resource))
        .unwrap();

    assert!(matches!(
        DurableAuthority::open(&fixture.database, FakePort::default()),
        Err(DurableAuthorityError::Busy)
    ));
    #[cfg(unix)]
    {
        let alias = fixture.directory.join("alias.sqlite");
        std::os::unix::fs::symlink(&fixture.database, &alias).unwrap();
        assert!(matches!(
            DurableAuthority::open(alias, FakePort::default()),
            Err(DurableAuthorityError::Busy)
        ));
    }
    let probe = PodBayStore::open(&fixture.database).unwrap();
    assert_eq!(probe.owner_epoch().unwrap(), 1);
    drop(probe);
    assert_eq!(
        first.dispatch(
            &transport,
            request(
                &scope,
                grant_id,
                1,
                HostAction::ObserveResource {
                    resource_id: resource.clone(),
                },
            ),
        ),
        Ok(PortDispatchOutcome::Accepted(1))
    );
    assert_eq!(first.port().calls.len(), 1);
    let mut bypass = PodBayStore::open(&fixture.database).unwrap();
    bypass.advance_owner_epoch(1, 2).unwrap();
    assert_eq!(
        bypass.authority_snapshot().unwrap().resources[0].input_epoch,
        1
    );
    drop(bypass);
    assert_eq!(
        first.dispatch(
            &transport,
            request(
                &scope,
                grant_id,
                1,
                HostAction::ObserveResource {
                    resource_id: resource.clone(),
                },
            ),
        ),
        Err(HostError::StaleGuard)
    );
    assert!(matches!(
        first.acquire_input_lease(
            &transport,
            grant_id,
            &scope,
            &resource,
            guards(1),
            InputEpoch::new(1).unwrap(),
            Duration::from_secs(30),
        ),
        Err(DurableAuthorityError::Host(HostError::StaleGuard))
    ));
    assert_eq!(first.port().calls.len(), 1);
    drop(first);

    let reopened = DurableAuthority::open(&fixture.database, FakePort::default()).unwrap();
    assert_eq!(reopened.owner_epoch().get(), 3);
    assert_eq!(reopened.port().calls.len(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn manager_lockfile_symlink_refuses_before_owner_epoch_changes() {
    let fixture = Fixture::new();
    let target = fixture.directory.join("unrelated-file");
    std::fs::write(&target, b"unrelated").unwrap();
    let lock_path = fixture.directory.join("podbay.sqlite.manager.lock");
    std::os::unix::fs::symlink(&target, &lock_path).unwrap();
    assert!(matches!(
        DurableAuthority::open(&fixture.database, FakePort::default()),
        Err(DurableAuthorityError::Io(_))
    ));
    let probe = PodBayStore::open(&fixture.database).unwrap();
    assert_eq!(probe.owner_epoch().unwrap(), 0);
}
