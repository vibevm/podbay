use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::time::{Duration, Instant};

use podbay_core::{ActorId, PodId, ResourceId, Role, ScopeId};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostError {
    InvalidInput,
    Unauthenticated,
    Unauthorised,
    StaleGuard,
    LeaseHeld,
    LeaseExpired,
    DeadlineExpired,
    Unsupported,
    RefusedBeforeEffect,
    UncertainAfterPossibleEffect {
        command_key: String,
        receipt_ref: Option<PortReceiptRef>,
    },
}

macro_rules! positive_epoch {
    ($($name:ident),+ $(,)?) => {
        $(
            #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
            pub struct $name(u64);

            impl $name {
                pub fn new(value: u64) -> Result<Self, HostError> {
                    if value == 0 { Err(HostError::InvalidInput) } else { Ok(Self(value)) }
                }

                pub const fn get(self) -> u64 { self.0 }

                fn next(self) -> Result<Self, HostError> {
                    self.0.checked_add(1).map(Self).ok_or(HostError::InvalidInput)
                }
            }
        )+
    };
}

positive_epoch!(
    ManagerEpoch,
    PodIncarnation,
    ResourceEpoch,
    CredentialGeneration,
    InputEpoch
);

/// A vault locator, never a credential value. Debug output deliberately hides the locator.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CredentialRef {
    scope_id: ScopeId,
    reference: Box<str>,
}

impl CredentialRef {
    pub fn from_trusted_vault(scope_id: ScopeId, reference: &str) -> Result<Self, HostError> {
        if !valid_token(reference) {
            return Err(HostError::InvalidInput);
        }
        Ok(Self {
            scope_id,
            reference: reference.into(),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.reference
    }
}

impl fmt::Debug for CredentialRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialRef([redacted])")
    }
}

fn valid_token(value: &str) -> bool {
    (3..=160).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn valid_cgroup_identity(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 4096
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostPlatform {
    Linux,
    MacOs,
    Windows,
}

/// Platform-neutral subject asserted by a verified OS transport adapter.
/// Linux supplies peer credentials and cgroup evidence; other adapters are not yet enabled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedProcessSubject {
    platform: HostPlatform,
    os_identity: Box<str>,
    process_identity: Box<str>,
    start_identity: u64,
    containment_identity: Box<str>,
}

impl AuthenticatedProcessSubject {
    pub fn linux_from_verified_peercred_cgroup(
        uid: u32,
        pid: u32,
        pid_start_ticks: u64,
        cgroup_identity: &str,
    ) -> Result<Self, HostError> {
        if pid == 0 || pid_start_ticks == 0 || !valid_cgroup_identity(cgroup_identity) {
            return Err(HostError::InvalidInput);
        }
        Ok(Self {
            platform: HostPlatform::Linux,
            os_identity: format!("linux.uid.{uid}").into(),
            process_identity: format!("linux.pid.{pid}").into(),
            start_identity: pid_start_ticks,
            containment_identity: cgroup_identity.into(),
        })
    }

    pub fn platform(&self) -> HostPlatform {
        self.platform
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PeerOrigin {
    OwnerCli,
    Pod {
        actor_id: ActorId,
        pod_id: PodId,
        incarnation: PodIncarnation,
    },
}

/// This value may be produced only by a server-side transport that verified the peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPeer {
    origin: PeerOrigin,
    process: AuthenticatedProcessSubject,
    credential_generation: CredentialGeneration,
}

impl AuthenticatedPeer {
    pub fn owner_cli_from_authenticated_transport(
        process: AuthenticatedProcessSubject,
        credential_generation: CredentialGeneration,
    ) -> Self {
        Self {
            origin: PeerOrigin::OwnerCli,
            process,
            credential_generation,
        }
    }

    pub fn pod_from_authenticated_transport(
        actor_id: ActorId,
        pod_id: PodId,
        incarnation: PodIncarnation,
        process: AuthenticatedProcessSubject,
        credential_generation: CredentialGeneration,
    ) -> Self {
        Self {
            origin: PeerOrigin::Pod {
                actor_id,
                pod_id,
                incarnation,
            },
            process,
            credential_generation,
        }
    }
}

pub trait AuthenticatedTransport {
    fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError>;
}

/// Trusted local policy registers exact process evidence before any grant can be used.
#[derive(Clone, Debug)]
pub struct ActorRegistration {
    actor_id: ActorId,
    scope_id: ScopeId,
    role: Role,
    origin: PeerOrigin,
    parent_actor_id: Option<ActorId>,
    process: AuthenticatedProcessSubject,
    credential_generation: CredentialGeneration,
}

impl ActorRegistration {
    pub fn owner_cli_from_trusted_policy(
        actor_id: ActorId,
        scope_id: ScopeId,
        process: AuthenticatedProcessSubject,
        credential_generation: CredentialGeneration,
    ) -> Self {
        Self {
            actor_id,
            scope_id,
            role: Role::Coordinator,
            origin: PeerOrigin::OwnerCli,
            parent_actor_id: None,
            process,
            credential_generation,
        }
    }

    pub fn pod_from_trusted_policy(
        actor_id: ActorId,
        scope_id: ScopeId,
        role: Role,
        pod_id: PodId,
        incarnation: PodIncarnation,
        parent_actor_id: Option<ActorId>,
        process: AuthenticatedProcessSubject,
        credential_generation: CredentialGeneration,
    ) -> Self {
        Self {
            origin: PeerOrigin::Pod {
                actor_id: actor_id.clone(),
                pod_id,
                incarnation,
            },
            actor_id,
            scope_id,
            role,
            parent_actor_id,
            process,
            credential_generation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Operation {
    LaunchPod,
    StopPod,
    ObserveResource,
    AcquireInput,
    TakeoverInput,
    WriteInput,
    ResizeResource,
    UseCredential,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Target {
    Pod(PodId),
    Resource(ResourceId),
    Credential(CredentialRef),
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Right {
    pub operation: Operation,
    pub target: Target,
}

impl Right {
    pub fn new(operation: Operation, target: Target) -> Self {
        Self { operation, target }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantMode {
    Viewer,
    Controller,
}

#[derive(Clone, Debug)]
pub struct GrantSpec {
    pub scope_id: ScopeId,
    pub mode: GrantMode,
    pub rights: BTreeSet<Right>,
    pub remaining_delegation_depth: u8,
}

impl GrantSpec {
    fn valid(&self) -> bool {
        !self.rights.is_empty()
            && (self.mode == GrantMode::Controller
                || self
                    .rights
                    .iter()
                    .all(|right| right.operation == Operation::ObserveResource))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct GrantId(u64);

#[derive(Clone, Debug)]
struct Grant {
    actor_id: ActorId,
    scope_id: ScopeId,
    credential_generation: CredentialGeneration,
    spec: GrantSpec,
}

#[derive(Clone, Debug)]
pub struct PodRegistration {
    pub scope_id: ScopeId,
    pub pod_id: PodId,
    pub incarnation: PodIncarnation,
}

#[derive(Clone, Debug)]
pub struct ResourceRegistration {
    pub scope_id: ScopeId,
    pub resource_id: ResourceId,
    pub pod_id: PodId,
    pub pod_incarnation: PodIncarnation,
    pub resource_epoch: ResourceEpoch,
    pub input_epoch: InputEpoch,
}

#[derive(Clone, Debug)]
struct ResourceState {
    registration: ResourceRegistration,
    lease: Option<InputLease>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputLease {
    actor_id: ActorId,
    scope_id: ScopeId,
    resource_id: ResourceId,
    pod_incarnation: PodIncarnation,
    resource_epoch: ResourceEpoch,
    input_epoch: InputEpoch,
    expires_at: Instant,
}

impl InputLease {
    pub fn input_epoch(&self) -> InputEpoch {
        self.input_epoch
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuardSet {
    pub manager_epoch: ManagerEpoch,
    pub pod_incarnation: PodIncarnation,
    pub resource_epoch: Option<ResourceEpoch>,
    pub credential_generation: CredentialGeneration,
}

/// Each variant has one exact operation and one exact target.
#[derive(Clone, Debug)]
pub enum HostAction {
    LaunchPod {
        pod_id: PodId,
        role: Role,
        credential: Option<CredentialRef>,
    },
    StopPod {
        pod_id: PodId,
    },
    ObserveResource {
        resource_id: ResourceId,
    },
    WriteInput {
        resource_id: ResourceId,
        lease: InputLease,
        bytes: Vec<u8>,
    },
    ResizeResource {
        resource_id: ResourceId,
        lease: InputLease,
        columns: u16,
        rows: u16,
    },
}

impl HostAction {
    fn right(&self) -> Right {
        match self {
            Self::LaunchPod { pod_id, .. } => {
                Right::new(Operation::LaunchPod, Target::Pod(pod_id.clone()))
            }
            Self::StopPod { pod_id } => Right::new(Operation::StopPod, Target::Pod(pod_id.clone())),
            Self::ObserveResource { resource_id } => Right::new(
                Operation::ObserveResource,
                Target::Resource(resource_id.clone()),
            ),
            Self::WriteInput { resource_id, .. } => {
                Right::new(Operation::WriteInput, Target::Resource(resource_id.clone()))
            }
            Self::ResizeResource { resource_id, .. } => Right::new(
                Operation::ResizeResource,
                Target::Resource(resource_id.clone()),
            ),
        }
    }

    fn resource_id(&self) -> Option<&ResourceId> {
        match self {
            Self::ObserveResource { resource_id }
            | Self::WriteInput { resource_id, .. }
            | Self::ResizeResource { resource_id, .. } => Some(resource_id),
            Self::LaunchPod { .. } | Self::StopPod { .. } => None,
        }
    }

    fn lease(&self) -> Option<&InputLease> {
        match self {
            Self::WriteInput { lease, .. } | Self::ResizeResource { lease, .. } => Some(lease),
            _ => None,
        }
    }

    fn validate(&self) -> Result<(), HostError> {
        match self {
            Self::WriteInput { bytes, .. } if bytes.is_empty() || bytes.len() > 65_536 => {
                Err(HostError::InvalidInput)
            }
            Self::ResizeResource { columns, rows, .. } if *columns == 0 || *rows == 0 => {
                Err(HostError::InvalidInput)
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct HostRequest {
    pub scope_id: ScopeId,
    pub grant_id: GrantId,
    pub guards: GuardSet,
    pub command_key: String,
    pub correlation_id: String,
    pub deadline: Instant,
    pub action: HostAction,
}

/// The port receives only a fully checked request. It is independent of pod factories.
#[derive(Clone, Debug)]
pub struct AuthorisedDispatch {
    pub actor_id: ActorId,
    pub role: Role,
    pub scope_id: ScopeId,
    pub command_key: String,
    pub correlation_id: String,
    pub action: HostAction,
}

/// An opaque handle returned by the transport port after possible external input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortReceiptRef(Box<str>);

impl PortReceiptRef {
    pub fn from_port(value: &str) -> Result<Self, HostError> {
        if !valid_token(value) {
            return Err(HostError::InvalidInput);
        }
        Ok(Self(value.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Accepted means this port accepted the request; settled requires its own evidence.
/// Neither variant by itself proves provider consumption or application completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PortDispatchOutcome<R> {
    Accepted(R),
    Settled(R),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PortDispatchError {
    RefusedBeforeEffect,
    UncertainAfterPossibleEffect { receipt_ref: Option<PortReceiptRef> },
}

pub trait HostDispatchPort {
    type Receipt;

    fn dispatch(
        &mut self,
        action: AuthorisedDispatch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError>;
}

/// Host-local authority. A fresh instance has no recovered grants and fails closed.
pub struct HostAuthority<P: HostDispatchPort> {
    port: P,
    manager_epoch: ManagerEpoch,
    actors: HashMap<ActorId, ActorRegistration>,
    pods: HashMap<PodId, PodRegistration>,
    resources: HashMap<ResourceId, ResourceState>,
    grants: HashMap<GrantId, Grant>,
    next_grant_id: u64,
}

impl<P: HostDispatchPort> HostAuthority<P> {
    pub fn for_platform(
        port: P,
        manager_epoch: ManagerEpoch,
        platform: HostPlatform,
    ) -> Result<Self, HostError> {
        if platform != HostPlatform::Linux {
            return Err(HostError::Unsupported);
        }
        Ok(Self::new(port, manager_epoch))
    }

    pub fn new(port: P, manager_epoch: ManagerEpoch) -> Self {
        Self {
            port,
            manager_epoch,
            actors: HashMap::new(),
            pods: HashMap::new(),
            resources: HashMap::new(),
            grants: HashMap::new(),
            next_grant_id: 1,
        }
    }

    pub fn port(&self) -> &P {
        &self.port
    }

    pub fn port_mut(&mut self) -> &mut P {
        &mut self.port
    }

    pub fn register_pod_from_trusted_policy(
        &mut self,
        registration: PodRegistration,
    ) -> Result<(), HostError> {
        if self.pods.contains_key(&registration.pod_id) {
            return Err(HostError::InvalidInput);
        }
        self.pods.insert(registration.pod_id.clone(), registration);
        Ok(())
    }

    pub fn register_resource_from_trusted_policy(
        &mut self,
        registration: ResourceRegistration,
    ) -> Result<(), HostError> {
        let pod = self
            .pods
            .get(&registration.pod_id)
            .ok_or(HostError::InvalidInput)?;
        if pod.scope_id != registration.scope_id
            || pod.incarnation != registration.pod_incarnation
            || self.resources.contains_key(&registration.resource_id)
        {
            return Err(HostError::InvalidInput);
        }
        self.resources.insert(
            registration.resource_id.clone(),
            ResourceState {
                registration,
                lease: None,
            },
        );
        Ok(())
    }

    /// Rebinds a stable ResourceId to a verified replacement process incarnation.
    /// Both resource and input epochs advance and any old lease is revoked.
    pub fn rebind_resource_from_trusted_policy(
        &mut self,
        replacement: ResourceRegistration,
        expected_old_pod: PodIncarnation,
        expected_old_resource: ResourceEpoch,
        expected_old_input: InputEpoch,
    ) -> Result<(), HostError> {
        let pod = self
            .pods
            .get(&replacement.pod_id)
            .ok_or(HostError::Unauthorised)?;
        let current = self
            .resources
            .get_mut(&replacement.resource_id)
            .ok_or(HostError::Unauthorised)?;
        if pod.scope_id != replacement.scope_id
            || pod.incarnation != replacement.pod_incarnation
            || current.registration.scope_id != replacement.scope_id
            || current.registration.pod_id != replacement.pod_id
            || current.registration.pod_incarnation != expected_old_pod
            || current.registration.resource_epoch != expected_old_resource
            || current.registration.input_epoch != expected_old_input
            || expected_old_pod.next()? != replacement.pod_incarnation
            || expected_old_resource.next()? != replacement.resource_epoch
            || expected_old_input.next()? != replacement.input_epoch
        {
            return Err(HostError::StaleGuard);
        }
        current.registration = replacement;
        current.lease = None;
        Ok(())
    }

    pub fn register_actor_from_trusted_policy(
        &mut self,
        registration: ActorRegistration,
    ) -> Result<(), HostError> {
        if registration.process.platform() != HostPlatform::Linux {
            return Err(HostError::Unsupported);
        }
        if self.actors.contains_key(&registration.actor_id)
            || self
                .actors
                .values()
                .any(|existing| existing.process == registration.process)
        {
            return Err(HostError::InvalidInput);
        }
        if let PeerOrigin::Pod {
            pod_id,
            incarnation,
            ..
        } = &registration.origin
        {
            let pod = self.pods.get(pod_id).ok_or(HostError::InvalidInput)?;
            if pod.scope_id != registration.scope_id || pod.incarnation != *incarnation {
                return Err(HostError::InvalidInput);
            }
        }
        if let Some(parent_actor_id) = &registration.parent_actor_id {
            let parent = self
                .actors
                .get(parent_actor_id)
                .ok_or(HostError::InvalidInput)?;
            if parent.scope_id != registration.scope_id {
                return Err(HostError::InvalidInput);
            }
        }
        self.actors
            .insert(registration.actor_id.clone(), registration);
        Ok(())
    }

    pub fn install_grant_from_trusted_policy(
        &mut self,
        actor_id: &ActorId,
        spec: GrantSpec,
    ) -> Result<GrantId, HostError> {
        let actor = self
            .actors
            .get(actor_id)
            .ok_or(HostError::Unauthenticated)?;
        if actor.scope_id != spec.scope_id || !spec.valid() || !self.rights_match_scope(&spec) {
            return Err(HostError::Unauthorised);
        }
        self.insert_grant(actor_id.clone(), actor.credential_generation, spec)
    }

    pub fn delegate_child<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        parent_grant_id: GrantId,
        child_actor_id: &ActorId,
        child_spec: GrantSpec,
    ) -> Result<GrantId, HostError> {
        let parent_actor = self.authenticate(transport)?;
        let parent_grant = self
            .grants
            .get(&parent_grant_id)
            .ok_or(HostError::Unauthorised)?;
        let child = self
            .actors
            .get(child_actor_id)
            .ok_or(HostError::Unauthenticated)?;
        if parent_grant.actor_id != parent_actor.actor_id
            || parent_grant.credential_generation != parent_actor.credential_generation
            || parent_grant.scope_id != parent_actor.scope_id
            || child.scope_id != parent_grant.scope_id
            || child.parent_actor_id.as_ref() != Some(&parent_actor.actor_id)
            || child_spec.scope_id != parent_grant.scope_id
            || !child_spec.valid()
            || !self.rights_match_scope(&child_spec)
            || !child_spec.rights.is_subset(&parent_grant.spec.rights)
            || parent_grant.spec.remaining_delegation_depth == 0
            || child_spec.remaining_delegation_depth >= parent_grant.spec.remaining_delegation_depth
            || (parent_grant.spec.mode == GrantMode::Viewer && child_spec.mode != GrantMode::Viewer)
        {
            return Err(HostError::Unauthorised);
        }
        let generation = child.credential_generation;
        self.insert_grant(child_actor_id.clone(), generation, child_spec)
    }

    pub fn revoke_grant_from_trusted_policy(&mut self, grant_id: GrantId) {
        self.grants.remove(&grant_id);
    }

    pub fn advance_manager_epoch_from_trusted_policy(
        &mut self,
        expected: ManagerEpoch,
        next: ManagerEpoch,
    ) -> Result<(), HostError> {
        if self.manager_epoch != expected || expected.next()? != next {
            return Err(HostError::StaleGuard);
        }
        let renewed = self
            .resources
            .iter()
            .map(|(id, resource)| Ok((id.clone(), resource.registration.input_epoch.next()?)))
            .collect::<Result<Vec<_>, HostError>>()?;
        self.manager_epoch = next;
        for (id, epoch) in renewed {
            let resource = self.resources.get_mut(&id).ok_or(HostError::InvalidInput)?;
            resource.registration.input_epoch = epoch;
            resource.lease = None;
        }
        Ok(())
    }

    pub fn advance_pod_incarnation_from_trusted_policy(
        &mut self,
        pod_id: &PodId,
        expected: PodIncarnation,
        next: PodIncarnation,
    ) -> Result<(), HostError> {
        let pod = self.pods.get_mut(pod_id).ok_or(HostError::Unauthorised)?;
        if pod.incarnation != expected || expected.next()? != next {
            return Err(HostError::StaleGuard);
        }
        pod.incarnation = next;
        Ok(())
    }

    pub fn advance_resource_epoch_from_trusted_policy(
        &mut self,
        resource_id: &ResourceId,
        expected: ResourceEpoch,
        next: ResourceEpoch,
    ) -> Result<(), HostError> {
        let resource = self
            .resources
            .get_mut(resource_id)
            .ok_or(HostError::Unauthorised)?;
        if resource.registration.resource_epoch != expected || expected.next()? != next {
            return Err(HostError::StaleGuard);
        }
        let next_input_epoch = resource.registration.input_epoch.next()?;
        resource.registration.resource_epoch = next;
        resource.registration.input_epoch = next_input_epoch;
        resource.lease = None;
        Ok(())
    }

    pub fn advance_credential_generation_from_trusted_policy(
        &mut self,
        actor_id: &ActorId,
        expected: CredentialGeneration,
        next: CredentialGeneration,
    ) -> Result<(), HostError> {
        let actor = self
            .actors
            .get_mut(actor_id)
            .ok_or(HostError::Unauthenticated)?;
        if actor.credential_generation != expected || expected.next()? != next {
            return Err(HostError::StaleGuard);
        }
        actor.credential_generation = next;
        Ok(())
    }

    fn insert_grant(
        &mut self,
        actor_id: ActorId,
        credential_generation: CredentialGeneration,
        spec: GrantSpec,
    ) -> Result<GrantId, HostError> {
        let id = GrantId(self.next_grant_id);
        self.next_grant_id = self
            .next_grant_id
            .checked_add(1)
            .ok_or(HostError::InvalidInput)?;
        self.grants.insert(
            id,
            Grant {
                actor_id,
                scope_id: spec.scope_id.clone(),
                credential_generation,
                spec,
            },
        );
        Ok(id)
    }

    fn rights_match_scope(&self, spec: &GrantSpec) -> bool {
        spec.rights.iter().all(|right| match &right.target {
            Target::Pod(id) => {
                matches!(right.operation, Operation::LaunchPod | Operation::StopPod)
                    && self
                        .pods
                        .get(id)
                        .is_some_and(|pod| pod.scope_id == spec.scope_id)
            }
            Target::Resource(id) => {
                matches!(
                    right.operation,
                    Operation::ObserveResource
                        | Operation::AcquireInput
                        | Operation::TakeoverInput
                        | Operation::WriteInput
                        | Operation::ResizeResource
                ) && self
                    .resources
                    .get(id)
                    .is_some_and(|resource| resource.registration.scope_id == spec.scope_id)
            }
            Target::Credential(reference) => {
                right.operation == Operation::UseCredential && reference.scope_id == spec.scope_id
            }
        })
    }

    fn authenticate<T: AuthenticatedTransport>(
        &self,
        transport: &T,
    ) -> Result<&ActorRegistration, HostError> {
        let peer = transport.verified_peer()?;
        if peer.process.platform() != HostPlatform::Linux {
            return Err(HostError::Unsupported);
        }
        let actor = match &peer.origin {
            PeerOrigin::OwnerCli => self
                .actors
                .values()
                .find(|actor| actor.origin == PeerOrigin::OwnerCli && actor.process == peer.process)
                .ok_or(HostError::Unauthenticated)?,
            PeerOrigin::Pod {
                actor_id,
                pod_id,
                incarnation,
            } => {
                let actor = self
                    .actors
                    .get(actor_id)
                    .ok_or(HostError::Unauthenticated)?;
                let pod = self.pods.get(pod_id).ok_or(HostError::Unauthenticated)?;
                if pod.scope_id != actor.scope_id || pod.incarnation != *incarnation {
                    return Err(HostError::Unauthenticated);
                }
                actor
            }
        };
        if actor.origin != peer.origin
            || actor.process != peer.process
            || actor.credential_generation != peer.credential_generation
        {
            return Err(HostError::Unauthenticated);
        }
        Ok(actor)
    }

    fn check_grant(
        &self,
        actor: &ActorRegistration,
        grant_id: GrantId,
        scope_id: &ScopeId,
        right: &Right,
    ) -> Result<(), HostError> {
        let grant = self.grants.get(&grant_id).ok_or(HostError::Unauthorised)?;
        if grant.actor_id != actor.actor_id
            || grant.scope_id != *scope_id
            || grant.scope_id != actor.scope_id
            || grant.credential_generation != actor.credential_generation
            || !grant.spec.rights.contains(right)
            || (grant.spec.mode == GrantMode::Viewer
                && right.operation != Operation::ObserveResource)
        {
            return Err(HostError::Unauthorised);
        }
        Ok(())
    }

    fn check_target_guards(
        &self,
        scope_id: &ScopeId,
        action: &HostAction,
        guards: GuardSet,
    ) -> Result<(), HostError> {
        if guards.manager_epoch != self.manager_epoch {
            return Err(HostError::StaleGuard);
        }
        if let Some(resource_id) = action.resource_id() {
            let resource = self
                .resources
                .get(resource_id)
                .ok_or(HostError::Unauthorised)?;
            let registration = &resource.registration;
            let pod = self
                .pods
                .get(&registration.pod_id)
                .ok_or(HostError::Unauthorised)?;
            if registration.scope_id != *scope_id
                || pod.scope_id != *scope_id
                || guards.pod_incarnation != pod.incarnation
                || registration.pod_incarnation != pod.incarnation
                || guards.resource_epoch != Some(registration.resource_epoch)
            {
                return Err(HostError::StaleGuard);
            }
        } else {
            let pod_id = match action {
                HostAction::LaunchPod { pod_id, .. } | HostAction::StopPod { pod_id } => pod_id,
                _ => return Err(HostError::InvalidInput),
            };
            let pod = self.pods.get(pod_id).ok_or(HostError::Unauthorised)?;
            if pod.scope_id != *scope_id
                || guards.pod_incarnation != pod.incarnation
                || guards.resource_epoch.is_some()
            {
                return Err(HostError::StaleGuard);
            }
        }
        Ok(())
    }

    fn check_lease(
        &self,
        actor_id: &ActorId,
        scope_id: &ScopeId,
        resource_id: &ResourceId,
        lease: &InputLease,
    ) -> Result<(), HostError> {
        let resource = self
            .resources
            .get(resource_id)
            .ok_or(HostError::Unauthorised)?;
        if lease.expires_at <= Instant::now() {
            return Err(HostError::LeaseExpired);
        }
        if lease.actor_id != *actor_id
            || lease.scope_id != *scope_id
            || lease.resource_id != *resource_id
            || lease.pod_incarnation != resource.registration.pod_incarnation
            || lease.resource_epoch != resource.registration.resource_epoch
            || lease.input_epoch != resource.registration.input_epoch
            || resource.lease.as_ref() != Some(lease)
        {
            return Err(HostError::StaleGuard);
        }
        Ok(())
    }

    pub fn dispatch<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        request: HostRequest,
    ) -> Result<PortDispatchOutcome<P::Receipt>, HostError> {
        request.action.validate()?;
        if !valid_token(&request.command_key) || !valid_token(&request.correlation_id) {
            return Err(HostError::InvalidInput);
        }
        if request.deadline <= Instant::now() {
            return Err(HostError::DeadlineExpired);
        }
        let actor = self.authenticate(transport)?;
        self.check_grant(
            actor,
            request.grant_id,
            &request.scope_id,
            &request.action.right(),
        )?;
        if request.guards.credential_generation != actor.credential_generation {
            return Err(HostError::StaleGuard);
        }
        self.check_target_guards(&request.scope_id, &request.action, request.guards)?;
        if let HostAction::LaunchPod {
            credential: Some(reference),
            ..
        } = &request.action
        {
            self.check_grant(
                actor,
                request.grant_id,
                &request.scope_id,
                &Right::new(
                    Operation::UseCredential,
                    Target::Credential(reference.clone()),
                ),
            )?;
        }
        if let (Some(resource_id), Some(lease)) =
            (request.action.resource_id(), request.action.lease())
        {
            self.check_lease(&actor.actor_id, &request.scope_id, resource_id, lease)?;
        }
        let authorised = AuthorisedDispatch {
            actor_id: actor.actor_id.clone(),
            role: actor.role,
            scope_id: request.scope_id,
            command_key: request.command_key,
            correlation_id: request.correlation_id,
            action: request.action,
        };
        let command_key = authorised.command_key.clone();
        match self.port.dispatch(authorised) {
            Ok(outcome) => Ok(outcome),
            Err(PortDispatchError::RefusedBeforeEffect) => Err(HostError::RefusedBeforeEffect),
            Err(PortDispatchError::UncertainAfterPossibleEffect { receipt_ref }) => {
                Err(HostError::UncertainAfterPossibleEffect {
                    command_key,
                    receipt_ref,
                })
            }
        }
    }

    pub fn acquire_input_lease<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        grant_id: GrantId,
        scope_id: &ScopeId,
        resource_id: &ResourceId,
        guards: GuardSet,
        expected_input_epoch: InputEpoch,
        lifetime: Duration,
    ) -> Result<InputLease, HostError> {
        self.set_input_lease(
            transport,
            grant_id,
            scope_id,
            resource_id,
            guards,
            expected_input_epoch,
            lifetime,
            Operation::AcquireInput,
        )
    }

    pub fn human_takeover_input_lease<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        grant_id: GrantId,
        scope_id: &ScopeId,
        resource_id: &ResourceId,
        guards: GuardSet,
        expected_input_epoch: InputEpoch,
        lifetime: Duration,
    ) -> Result<InputLease, HostError> {
        self.set_input_lease(
            transport,
            grant_id,
            scope_id,
            resource_id,
            guards,
            expected_input_epoch,
            lifetime,
            Operation::TakeoverInput,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn set_input_lease<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        grant_id: GrantId,
        scope_id: &ScopeId,
        resource_id: &ResourceId,
        guards: GuardSet,
        expected_input_epoch: InputEpoch,
        lifetime: Duration,
        operation: Operation,
    ) -> Result<InputLease, HostError> {
        if lifetime.is_zero() || lifetime > Duration::from_secs(3600) {
            return Err(HostError::InvalidInput);
        }
        let actor = self.authenticate(transport)?;
        self.check_grant(
            actor,
            grant_id,
            scope_id,
            &Right::new(operation, Target::Resource(resource_id.clone())),
        )?;
        if guards.credential_generation != actor.credential_generation {
            return Err(HostError::StaleGuard);
        }
        self.check_target_guards(
            scope_id,
            &HostAction::ObserveResource {
                resource_id: resource_id.clone(),
            },
            guards,
        )?;
        let actor_id = actor.actor_id.clone();
        let resource = self
            .resources
            .get_mut(resource_id)
            .ok_or(HostError::Unauthorised)?;
        if resource.registration.input_epoch != expected_input_epoch {
            return Err(HostError::StaleGuard);
        }
        if operation == Operation::AcquireInput
            && resource
                .lease
                .as_ref()
                .is_some_and(|lease| lease.expires_at > Instant::now())
        {
            return Err(HostError::LeaseHeld);
        }
        let expires_at = Instant::now()
            .checked_add(lifetime)
            .ok_or(HostError::InvalidInput)?;
        let next_epoch = resource.registration.input_epoch.next()?;
        let lease = InputLease {
            actor_id,
            scope_id: scope_id.clone(),
            resource_id: resource_id.clone(),
            pod_incarnation: resource.registration.pod_incarnation,
            resource_epoch: resource.registration.resource_epoch,
            input_epoch: next_epoch,
            expires_at,
        };
        resource.registration.input_epoch = next_epoch;
        resource.lease = Some(lease.clone());
        Ok(lease)
    }
}
