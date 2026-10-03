use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use podbay_core::{ActorId, PodId, ResourceId, Role, ScopeId};
use podbay_store::{
    Admission, AuthorityActorRecord, AuthorityGrantRecord, AuthorityMutation, AuthorityPodRecord,
    AuthorityResourceRecord, AuthorityRightRecord, AuthoritySnapshot, CommandRequest, EffectClaim,
    LaunchDispatchStatus, LaunchPortResult, PodBayStore, Receipt, StoreError, VerifiedPrincipal,
};

use crate::launch_spec::{EffectiveLaunchSpec, LaunchSelection, RegisteredLaunchProfile};

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
    AuthorityStoreUnavailable,
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

    pub fn scope_id(&self) -> &ScopeId {
        &self.scope_id
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

impl GrantId {
    pub const fn get(self) -> u64 {
        self.0
    }
}

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

/// The launch port receives only the profile-resolved immutable descriptor.
#[derive(Clone, Debug)]
pub struct AuthorisedLaunch {
    actor_id: ActorId,
    scope_id: ScopeId,
    command_key: String,
    correlation_id: String,
    spec: EffectiveLaunchSpec,
    spec_digest: String,
}

impl AuthorisedLaunch {
    pub fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    pub fn scope_id(&self) -> &ScopeId {
        &self.scope_id
    }

    pub fn command_key(&self) -> &str {
        &self.command_key
    }

    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    pub fn spec(&self) -> &EffectiveLaunchSpec {
        &self.spec
    }

    pub fn spec_digest(&self) -> &str {
        &self.spec_digest
    }
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

    fn launch(
        &mut self,
        launch: AuthorisedLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError>;
}

pub trait StablePortReceipt {
    fn stable_reference(&self) -> &str;
}

impl StablePortReceipt for PortReceiptRef {
    fn stable_reference(&self) -> &str {
        self.as_str()
    }
}

#[derive(Clone, Debug)]
pub struct LaunchPodRequest {
    pub host_request: HostRequest,
    /// Exact normalised request bytes from the typed protocol boundary.
    pub canonical_request: Vec<u8>,
    pub selection: LaunchSelection,
    /// Admission epochs stay fixed across retries; host_request.guards are current.
    pub admission_owner_epoch: ManagerEpoch,
    pub admission_pod_incarnation: PodIncarnation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchPodReceipt {
    pub receipt: Receipt,
    pub status: LaunchDispatchStatus,
    pub duplicate: bool,
    pub port_called: bool,
}

#[derive(Debug)]
pub enum LaunchPodError {
    Host(HostError),
    Store(StoreError),
    WrongOperation,
    /// The port returned, but the durable stage write failed; query the original receipt.
    OutcomeNotRecorded {
        receipt: Receipt,
        observed: LaunchPortResult,
        source: StoreError,
    },
}

impl From<HostError> for LaunchPodError {
    fn from(value: HostError) -> Self {
        Self::Host(value)
    }
}

impl From<StoreError> for LaunchPodError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
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

    fn authorise_request<T: AuthenticatedTransport>(
        &self,
        transport: &T,
        request: &HostRequest,
    ) -> Result<AuthorisedDispatch, HostError> {
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
        Ok(AuthorisedDispatch {
            actor_id: actor.actor_id.clone(),
            role: actor.role,
            scope_id: request.scope_id.clone(),
            command_key: request.command_key.clone(),
            correlation_id: request.correlation_id.clone(),
            action: request.action.clone(),
        })
    }

    pub fn dispatch<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        request: HostRequest,
    ) -> Result<PortDispatchOutcome<P::Receipt>, HostError> {
        let authorised = self.authorise_request(transport, &request)?;
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

#[derive(Debug)]
pub enum DurableAuthorityError {
    Host(HostError),
    Store(StoreError),
    Io(std::io::Error),
    Busy,
    Corrupt(&'static str),
}

impl From<HostError> for DurableAuthorityError {
    fn from(value: HostError) -> Self {
        Self::Host(value)
    }
}

impl From<StoreError> for DurableAuthorityError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<std::io::Error> for DurableAuthorityError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Clone)]
struct HostCheckpoint {
    manager_epoch: ManagerEpoch,
    actors: HashMap<ActorId, ActorRegistration>,
    pods: HashMap<PodId, PodRegistration>,
    resources: HashMap<ResourceId, ResourceState>,
    grants: HashMap<GrantId, Grant>,
    next_grant_id: u64,
}

impl<P: HostDispatchPort> HostAuthority<P> {
    fn checkpoint(&self) -> HostCheckpoint {
        HostCheckpoint {
            manager_epoch: self.manager_epoch,
            actors: self.actors.clone(),
            pods: self.pods.clone(),
            resources: self.resources.clone(),
            grants: self.grants.clone(),
            next_grant_id: self.next_grant_id,
        }
    }

    fn restore(&mut self, checkpoint: HostCheckpoint) {
        self.manager_epoch = checkpoint.manager_epoch;
        self.actors = checkpoint.actors;
        self.pods = checkpoint.pods;
        self.resources = checkpoint.resources;
        self.grants = checkpoint.grants;
        self.next_grant_id = checkpoint.next_grant_id;
    }
}

/// SQLite-backed authority. Recorded actors and grants are inert after reopen
/// until trusted replay. Dispatch here is an authority gate, not durable command
/// admission; PB09 must issue the durable receipt before production effects.
pub struct DurableAuthority<P: HostDispatchPort> {
    _manager_lock: File,
    host: HostAuthority<P>,
    store: PodBayStore,
    recorded: AuthoritySnapshot,
    launch_profiles: HashMap<String, RegisteredLaunchProfile>,
}

impl<P: HostDispatchPort> DurableAuthority<P> {
    pub fn open(path: impl AsRef<Path>, port: P) -> Result<Self, DurableAuthorityError> {
        if !cfg!(target_os = "linux") {
            return Err(DurableAuthorityError::Host(HostError::Unsupported));
        }
        let path = path.as_ref();
        let (manager_lock, canonical_database) = acquire_manager_lock(path)?;
        let mut store = PodBayStore::open(&canonical_database)?;
        if std::fs::canonicalize(&canonical_database)? != canonical_database {
            return Err(DurableAuthorityError::Corrupt(
                "authority database path changed while acquiring lease",
            ));
        }
        let old_epoch = store.owner_epoch()?;
        let new_epoch = old_epoch
            .checked_add(1)
            .ok_or(DurableAuthorityError::Corrupt("manager epoch exhausted"))?;
        let recorded = store.begin_authority_replay(old_epoch, new_epoch)?;
        let mut host = HostAuthority::new(port, ManagerEpoch::new(new_epoch)?);
        for record in &recorded.pods {
            let pod_id = PodId::try_from(record.pod_id.as_str())
                .map_err(|_| DurableAuthorityError::Corrupt("invalid durable pod id"))?;
            let scope_id = ScopeId::try_from(record.scope_id.as_str())
                .map_err(|_| DurableAuthorityError::Corrupt("invalid durable pod scope"))?;
            let incarnation = PodIncarnation::new(record.incarnation)?;
            host.register_pod_from_trusted_policy(PodRegistration {
                scope_id,
                pod_id,
                incarnation,
            })?;
        }
        for record in &recorded.resources {
            let resource_id = ResourceId::try_from(record.resource_id.as_str())
                .map_err(|_| DurableAuthorityError::Corrupt("invalid durable resource id"))?;
            let scope_id = ScopeId::try_from(record.scope_id.as_str())
                .map_err(|_| DurableAuthorityError::Corrupt("invalid durable resource scope"))?;
            let pod_id = PodId::try_from(record.pod_id.as_str())
                .map_err(|_| DurableAuthorityError::Corrupt("invalid durable resource pod"))?;
            host.resources.insert(
                resource_id.clone(),
                ResourceState {
                    registration: ResourceRegistration {
                        scope_id,
                        resource_id,
                        pod_id,
                        pod_incarnation: PodIncarnation::new(record.pod_incarnation)?,
                        resource_epoch: ResourceEpoch::new(record.resource_epoch)?,
                        input_epoch: InputEpoch::new(record.input_epoch)?,
                    },
                    lease: None,
                },
            );
        }
        host.next_grant_id = recorded
            .grants
            .iter()
            .map(|grant| grant.grant_id)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(DurableAuthorityError::Corrupt("grant id exhausted"))?;
        Ok(Self {
            _manager_lock: manager_lock,
            host,
            store,
            recorded,
            launch_profiles: HashMap::new(),
        })
    }

    pub fn port(&self) -> &P {
        self.host.port()
    }

    pub fn owner_epoch(&self) -> ManagerEpoch {
        self.host.manager_epoch
    }

    pub fn recorded_snapshot(&self) -> &AuthoritySnapshot {
        &self.recorded
    }

    /// Trusted policy must register the effective profile on every manager
    /// incarnation; an old outbox effect alone cannot reactivate a changed policy.
    pub fn register_launch_profile_from_trusted_policy(
        &mut self,
        profile: RegisteredLaunchProfile,
    ) -> Result<(), HostError> {
        let key = profile.profile_ref().to_owned();
        if let Some(existing) = self.launch_profiles.get(&key) {
            if existing.generation() > profile.generation()
                || (existing.generation() == profile.generation() && existing != &profile)
            {
                return Err(HostError::StaleGuard);
            }
        }
        self.launch_profiles.insert(key, profile);
        Ok(())
    }

    pub fn dispatch<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        request: HostRequest,
    ) -> Result<PortDispatchOutcome<P::Receipt>, HostError> {
        if matches!(request.action, HostAction::LaunchPod { .. }) {
            return Err(HostError::Unsupported);
        }
        self.ensure_current_owner_epoch()?;
        self.host.dispatch(transport, request)
    }

    /// One durable LaunchPod path. A persisted intent precedes the claim, and
    /// the port call occurs only after the claim transaction has committed.
    /// HostAccepted and PortSettled describe the launch port only: neither is
    /// provider insertion or run/task completion. A proven refusal remains
    /// non-dispatchable under this claim; retry needs a new command and policy.
    pub fn launch_pod<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        request: LaunchPodRequest,
    ) -> Result<LaunchPodReceipt, LaunchPodError>
    where
        P::Receipt: StablePortReceipt,
    {
        let (authorised, receipt, duplicate) = self.admit_launch_intent(transport, &request)?;
        let pod_id = authorised.spec.pod_id();
        let claim_key = format!("claim.{}", receipt.command_id);
        let claim = self.store.claim_effect(
            receipt.outbox_id,
            authorised.scope_id.as_str(),
            pod_id.as_str(),
            self.host.manager_epoch.get(),
            request.host_request.guards.pod_incarnation.get(),
            &claim_key,
        )?;
        if claim != EffectClaim::NewClaim {
            return Ok(LaunchPodReceipt {
                status: self.store.launch_dispatch_status(
                    receipt.outbox_id,
                    authorised.scope_id.as_str(),
                    pod_id.as_str(),
                )?,
                receipt,
                duplicate,
                port_called: false,
            });
        }
        // A noncooperative owner-epoch write between claim and port call still
        // fences this instance. The claim remains uncertain and is not replayed.
        self.ensure_current_owner_epoch()?;
        let port_result = match self.host.port.launch(authorised.clone()) {
            Ok(PortDispatchOutcome::Accepted(port_receipt)) => LaunchPortResult::HostAccepted {
                receipt_ref: Some(port_receipt.stable_reference().to_owned()),
            },
            Ok(PortDispatchOutcome::Settled(port_receipt)) => LaunchPortResult::PortSettled {
                receipt_ref: Some(port_receipt.stable_reference().to_owned()),
            },
            Err(PortDispatchError::RefusedBeforeEffect) => LaunchPortResult::RefusedBeforeEffect,
            Err(PortDispatchError::UncertainAfterPossibleEffect { receipt_ref }) => {
                LaunchPortResult::UncertainAfterPossibleEffect {
                    receipt_ref: receipt_ref.map(|reference| reference.as_str().to_owned()),
                }
            }
        };
        let status = self
            .store
            .record_launch_port_result(
                receipt.outbox_id,
                authorised.scope_id.as_str(),
                pod_id.as_str(),
                self.host.manager_epoch.get(),
                &claim_key,
                port_result.clone(),
            )
            .map_err(|source| LaunchPodError::OutcomeNotRecorded {
                receipt: receipt.clone(),
                observed: port_result,
                source,
            })?;
        Ok(LaunchPodReceipt {
            receipt,
            status,
            duplicate,
            port_called: true,
        })
    }

    /// Commits intent only. Its receipt proves persistence, not a port call.
    pub fn admit_launch_pod<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        request: LaunchPodRequest,
    ) -> Result<LaunchPodReceipt, LaunchPodError> {
        let (authorised, receipt, duplicate) = self.admit_launch_intent(transport, &request)?;
        let pod_id = authorised.spec.pod_id();
        let status = self.store.launch_dispatch_status(
            receipt.outbox_id,
            authorised.scope_id.as_str(),
            pod_id.as_str(),
        )?;
        Ok(LaunchPodReceipt {
            receipt,
            status,
            duplicate,
            port_called: false,
        })
    }

    fn admit_launch_intent<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        request: &LaunchPodRequest,
    ) -> Result<(AuthorisedLaunch, Receipt, bool), LaunchPodError> {
        self.ensure_current_owner_epoch()?;
        let authorised = self
            .host
            .authorise_request(transport, &request.host_request)?;
        let HostAction::LaunchPod { pod_id, .. } = &authorised.action else {
            return Err(LaunchPodError::WrongOperation);
        };
        let spec = self.resolve_effective_launch(
            &authorised,
            request.host_request.grant_id,
            &request.selection,
        )?;
        let effect_payload = spec.canonical_bytes()?;
        let command = CommandRequest {
            principal: VerifiedPrincipal::from_authenticated_boundary(
                authorised.actor_id.as_str(),
            )?,
            namespace: "podbay.launch".to_owned(),
            command_key: authorised.command_key.clone(),
            scope_id: authorised.scope_id.as_str().to_owned(),
            target_id: pod_id.as_str().to_owned(),
            expected_owner_epoch: request.admission_owner_epoch.get(),
            expected_target_epoch: request.admission_pod_incarnation.get(),
            canonical_request: request.canonical_request.clone(),
            event_kind: "command.admitted".to_owned(),
            event_payload: br#"{"kind":"command_admitted"}"#.to_vec(),
            effect_kind: "pod.offer".to_owned(),
            effect_payload: effect_payload.clone(),
        };
        let (receipt, duplicate) = match self.store.admit(&command)? {
            Admission::Committed(receipt) => (receipt, false),
            Admission::Duplicate(receipt) => (receipt, true),
        };
        let effect = self.store.load_effect(
            receipt.outbox_id,
            authorised.scope_id.as_str(),
            pod_id.as_str(),
        )?;
        if effect.kind != "pod.offer" || effect.payload != effect_payload {
            return Err(LaunchPodError::Store(StoreError::Conflict(
                "durable launch spec differs from reviewed effective spec",
            )));
        }
        let launch = AuthorisedLaunch {
            actor_id: authorised.actor_id,
            scope_id: authorised.scope_id,
            command_key: authorised.command_key,
            correlation_id: authorised.correlation_id,
            spec,
            spec_digest: effect.effect_digest,
        };
        Ok((launch, receipt, duplicate))
    }

    fn resolve_effective_launch(
        &self,
        authorised: &AuthorisedDispatch,
        grant_id: GrantId,
        selection: &LaunchSelection,
    ) -> Result<EffectiveLaunchSpec, HostError> {
        let HostAction::LaunchPod {
            pod_id,
            role,
            credential,
        } = &authorised.action
        else {
            return Err(HostError::InvalidInput);
        };
        let profile = self
            .launch_profiles
            .get(&selection.profile_ref)
            .ok_or(HostError::Unsupported)?;
        if profile.workspace_scope() != &authorised.scope_id {
            return Err(HostError::Unauthorised);
        }
        let spec = profile.resolve(
            pod_id.clone(),
            *role,
            grant_id.get(),
            credential.as_ref(),
            selection,
        )?;
        let actor = self
            .host
            .actors
            .get(&authorised.actor_id)
            .ok_or(HostError::Unauthenticated)?;
        for reference in spec.credential_refs() {
            self.host.check_grant(
                actor,
                grant_id,
                &authorised.scope_id,
                &Right::new(
                    Operation::UseCredential,
                    Target::Credential(reference.clone()),
                ),
            )?;
        }
        Ok(spec)
    }

    fn ensure_current_owner_epoch(&self) -> Result<(), HostError> {
        match self.store.owner_epoch() {
            Ok(epoch) if epoch == self.host.manager_epoch.get() => Ok(()),
            Ok(_) => Err(HostError::StaleGuard),
            Err(_) => Err(HostError::AuthorityStoreUnavailable),
        }
    }

    fn persist<R>(
        &mut self,
        checkpoint: HostCheckpoint,
        mutation: AuthorityMutation,
        result: R,
    ) -> Result<R, DurableAuthorityError> {
        match self.store.apply_authority_mutation(
            self.recorded.owner_epoch,
            self.recorded.revision,
            mutation.clone(),
        ) {
            Ok(revision) => {
                self.recorded.revision = revision;
                apply_recorded_mutation(&mut self.recorded, mutation);
                Ok(result)
            }
            Err(error) => {
                self.host.restore(checkpoint);
                Err(DurableAuthorityError::Store(error))
            }
        }
    }
}

/// Cooperative manager ownership is held for the complete host lifetime.
/// The lockfile is separate from SQLite so no database transaction spans a port call.
fn acquire_manager_lock(database: &Path) -> Result<(File, PathBuf), DurableAuthorityError> {
    if database.as_os_str().is_empty() {
        return Err(DurableAuthorityError::Corrupt(
            "empty authority database path",
        ));
    }
    let parent = database
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let canonical_database = if database.exists() {
        std::fs::canonicalize(database)?
    } else {
        let file_name = database.file_name().ok_or(DurableAuthorityError::Corrupt(
            "database filename is missing",
        ))?;
        std::fs::canonicalize(parent)?.join(file_name)
    };
    let mut lock_name = canonical_database
        .file_name()
        .ok_or(DurableAuthorityError::Corrupt(
            "database filename is missing",
        ))?
        .to_os_string();
    lock_name.push(".manager.lock");
    let lock_path: PathBuf = canonical_database.with_file_name(lock_name);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    #[cfg(target_os = "linux")]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(lock_path)?;
    #[cfg(unix)]
    {
        let metadata = file.metadata()?;
        let owner = if canonical_database.exists() {
            std::fs::metadata(&canonical_database)?.uid()
        } else {
            std::fs::metadata(parent)?.uid()
        };
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != owner
            || metadata.nlink() != 1
        {
            return Err(DurableAuthorityError::Corrupt(
                "manager lockfile is not private and singly owned",
            ));
        }
    }
    match file.try_lock() {
        Ok(()) => Ok((file, canonical_database)),
        Err(error) => {
            let error: std::io::Error = error.into();
            if error.kind() == ErrorKind::WouldBlock {
                Err(DurableAuthorityError::Busy)
            } else {
                Err(DurableAuthorityError::Io(error))
            }
        }
    }
}

fn apply_recorded_mutation(snapshot: &mut AuthoritySnapshot, mutation: AuthorityMutation) {
    match mutation {
        AuthorityMutation::PutPod(record) => {
            snapshot.pods.retain(|old| old.pod_id != record.pod_id);
            snapshot.pods.push(record);
        }
        AuthorityMutation::PutResource(record) => {
            snapshot
                .resources
                .retain(|old| old.resource_id != record.resource_id);
            snapshot.resources.push(record);
        }
        AuthorityMutation::PutActor(record) => {
            snapshot
                .actors
                .retain(|old| old.actor_id != record.actor_id);
            snapshot.actors.push(record);
        }
        AuthorityMutation::PutGrant(record) => {
            snapshot
                .grants
                .retain(|old| old.grant_id != record.grant_id);
            snapshot.grants.push(record);
        }
        AuthorityMutation::RevokeGrant(id) => {
            snapshot.grants.retain(|old| old.grant_id != id);
        }
    }
}

fn durable_pod(record: &PodRegistration) -> AuthorityPodRecord {
    AuthorityPodRecord {
        scope_id: record.scope_id.as_str().to_owned(),
        pod_id: record.pod_id.as_str().to_owned(),
        incarnation: record.incarnation.get(),
    }
}

fn durable_resource(record: &ResourceRegistration) -> AuthorityResourceRecord {
    AuthorityResourceRecord {
        scope_id: record.scope_id.as_str().to_owned(),
        resource_id: record.resource_id.as_str().to_owned(),
        pod_id: record.pod_id.as_str().to_owned(),
        pod_incarnation: record.pod_incarnation.get(),
        resource_epoch: record.resource_epoch.get(),
        input_epoch: record.input_epoch.get(),
    }
}

fn durable_actor(record: &ActorRegistration) -> AuthorityActorRecord {
    let (origin, pod_id, pod_incarnation) = match &record.origin {
        PeerOrigin::OwnerCli => ("owner_cli", None, None),
        PeerOrigin::Pod {
            pod_id,
            incarnation,
            ..
        } => (
            "pod",
            Some(pod_id.as_str().to_owned()),
            Some(incarnation.get()),
        ),
    };
    let role = match record.role {
        Role::Coordinator => "coordinator",
        Role::Worker => "worker",
        Role::Advisor => "advisor",
    };
    let platform = match record.process.platform {
        HostPlatform::Linux => "linux",
        HostPlatform::MacOs => "macos",
        HostPlatform::Windows => "windows",
    };
    AuthorityActorRecord {
        scope_id: record.scope_id.as_str().to_owned(),
        actor_id: record.actor_id.as_str().to_owned(),
        role: role.to_owned(),
        origin: origin.to_owned(),
        parent_actor_id: record
            .parent_actor_id
            .as_ref()
            .map(|id| id.as_str().to_owned()),
        pod_id,
        pod_incarnation,
        credential_generation: record.credential_generation.get(),
        platform: platform.to_owned(),
        os_identity: record.process.os_identity.to_string(),
        process_identity: record.process.process_identity.to_string(),
        start_identity: record.process.start_identity,
        containment_identity: record.process.containment_identity.to_string(),
    }
}

fn durable_grant(id: GrantId, grant: &Grant) -> AuthorityGrantRecord {
    let mode = match grant.spec.mode {
        GrantMode::Viewer => "viewer",
        GrantMode::Controller => "controller",
    };
    AuthorityGrantRecord {
        grant_id: id.0,
        scope_id: grant.scope_id.as_str().to_owned(),
        actor_id: grant.actor_id.as_str().to_owned(),
        credential_generation: grant.credential_generation.get(),
        mode: mode.to_owned(),
        remaining_delegation_depth: grant.spec.remaining_delegation_depth,
        rights: grant
            .spec
            .rights
            .iter()
            .map(|right| {
                let operation = match right.operation {
                    Operation::LaunchPod => "launch_pod",
                    Operation::StopPod => "stop_pod",
                    Operation::ObserveResource => "observe_resource",
                    Operation::AcquireInput => "acquire_input",
                    Operation::TakeoverInput => "takeover_input",
                    Operation::WriteInput => "write_input",
                    Operation::ResizeResource => "resize_resource",
                    Operation::UseCredential => "use_credential",
                };
                let (kind, id) = match &right.target {
                    Target::Pod(id) => ("pod", id.as_str()),
                    Target::Resource(id) => ("resource", id.as_str()),
                    Target::Credential(reference) => ("credential", reference.as_str()),
                };
                AuthorityRightRecord {
                    operation: operation.to_owned(),
                    target_kind: kind.to_owned(),
                    target_id: id.to_owned(),
                }
            })
            .collect(),
    }
}

fn replay_grant_spec(record: &AuthorityGrantRecord) -> Result<GrantSpec, DurableAuthorityError> {
    let scope = ScopeId::try_from(record.scope_id.as_str())
        .map_err(|_| DurableAuthorityError::Corrupt("invalid durable grant scope"))?;
    let mode = match record.mode.as_str() {
        "viewer" => GrantMode::Viewer,
        "controller" => GrantMode::Controller,
        _ => return Err(DurableAuthorityError::Corrupt("unknown durable grant mode")),
    };
    let mut rights = BTreeSet::new();
    for right in &record.rights {
        let operation = match right.operation.as_str() {
            "launch_pod" => Operation::LaunchPod,
            "stop_pod" => Operation::StopPod,
            "observe_resource" => Operation::ObserveResource,
            "acquire_input" => Operation::AcquireInput,
            "takeover_input" => Operation::TakeoverInput,
            "write_input" => Operation::WriteInput,
            "resize_resource" => Operation::ResizeResource,
            "use_credential" => Operation::UseCredential,
            _ => {
                return Err(DurableAuthorityError::Corrupt(
                    "unknown durable grant operation",
                ))
            }
        };
        let target = match right.target_kind.as_str() {
            "pod" => Target::Pod(
                PodId::try_from(right.target_id.as_str())
                    .map_err(|_| DurableAuthorityError::Corrupt("invalid durable pod target"))?,
            ),
            "resource" => {
                Target::Resource(ResourceId::try_from(right.target_id.as_str()).map_err(|_| {
                    DurableAuthorityError::Corrupt("invalid durable resource target")
                })?)
            }
            "credential" => Target::Credential(CredentialRef::from_trusted_vault(
                scope.clone(),
                &right.target_id,
            )?),
            _ => {
                return Err(DurableAuthorityError::Corrupt(
                    "unknown durable grant target",
                ))
            }
        };
        rights.insert(Right::new(operation, target));
    }
    Ok(GrantSpec {
        scope_id: scope,
        mode,
        rights,
        remaining_delegation_depth: record.remaining_delegation_depth,
    })
}

impl<P: HostDispatchPort> DurableAuthority<P> {
    /// Recorded identity alone never authenticates a restarted process.
    pub fn reattest_actor_from_trusted_replay<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        registration: ActorRegistration,
    ) -> Result<(), DurableAuthorityError> {
        let recorded = self
            .recorded
            .actors
            .iter()
            .find(|actor| actor.actor_id == registration.actor_id.as_str())
            .ok_or(DurableAuthorityError::Host(HostError::Unauthenticated))?;
        if *recorded != durable_actor(&registration) {
            return Err(DurableAuthorityError::Host(HostError::Unauthenticated));
        }
        let peer = transport.verified_peer()?;
        if peer.origin != registration.origin
            || peer.process != registration.process
            || peer.credential_generation != registration.credential_generation
        {
            return Err(DurableAuthorityError::Host(HostError::Unauthenticated));
        }
        if let Some(active) = self.host.actors.get(&registration.actor_id) {
            return if durable_actor(active) == *recorded {
                Ok(())
            } else {
                Err(DurableAuthorityError::Host(HostError::Unauthenticated))
            };
        }
        self.host.register_actor_from_trusted_policy(registration)?;
        Ok(())
    }

    pub fn activate_grant_from_trusted_replay(
        &mut self,
        grant_id: GrantId,
    ) -> Result<GrantId, DurableAuthorityError> {
        let record = self
            .recorded
            .grants
            .iter()
            .find(|grant| grant.grant_id == grant_id.0)
            .ok_or(DurableAuthorityError::Host(HostError::Unauthorised))?;
        let actor_id = ActorId::try_from(record.actor_id.as_str())
            .map_err(|_| DurableAuthorityError::Corrupt("invalid durable grant actor"))?;
        let actor = self
            .host
            .actors
            .get(&actor_id)
            .ok_or(DurableAuthorityError::Host(HostError::Unauthenticated))?;
        let spec = replay_grant_spec(record)?;
        if actor.scope_id != spec.scope_id
            || actor.credential_generation.get() != record.credential_generation
            || !spec.valid()
            || !self.host.rights_match_scope(&spec)
        {
            return Err(DurableAuthorityError::Host(HostError::Unauthorised));
        }
        let id = grant_id;
        if let Some(active) = self.host.grants.get(&id) {
            return if durable_grant(id, active) == *record {
                Ok(id)
            } else {
                Err(DurableAuthorityError::Host(HostError::Unauthorised))
            };
        }
        self.host.grants.insert(
            id,
            Grant {
                actor_id,
                scope_id: spec.scope_id.clone(),
                credential_generation: actor.credential_generation,
                spec,
            },
        );
        Ok(id)
    }

    pub fn register_pod_from_trusted_policy(
        &mut self,
        registration: PodRegistration,
    ) -> Result<(), DurableAuthorityError> {
        let checkpoint = self.host.checkpoint();
        self.host
            .register_pod_from_trusted_policy(registration.clone())?;
        self.persist(
            checkpoint,
            AuthorityMutation::PutPod(durable_pod(&registration)),
            (),
        )
    }

    pub fn register_resource_from_trusted_policy(
        &mut self,
        registration: ResourceRegistration,
    ) -> Result<(), DurableAuthorityError> {
        let checkpoint = self.host.checkpoint();
        self.host
            .register_resource_from_trusted_policy(registration.clone())?;
        self.persist(
            checkpoint,
            AuthorityMutation::PutResource(durable_resource(&registration)),
            (),
        )
    }

    pub fn register_actor_from_trusted_policy(
        &mut self,
        registration: ActorRegistration,
    ) -> Result<(), DurableAuthorityError> {
        let checkpoint = self.host.checkpoint();
        self.host
            .register_actor_from_trusted_policy(registration.clone())?;
        self.persist(
            checkpoint,
            AuthorityMutation::PutActor(durable_actor(&registration)),
            (),
        )
    }

    pub fn install_grant_from_trusted_policy(
        &mut self,
        actor_id: &ActorId,
        spec: GrantSpec,
    ) -> Result<GrantId, DurableAuthorityError> {
        let checkpoint = self.host.checkpoint();
        let id = self
            .host
            .install_grant_from_trusted_policy(actor_id, spec)?;
        let grant = self
            .host
            .grants
            .get(&id)
            .ok_or(DurableAuthorityError::Corrupt("new grant missing"))?;
        self.persist(
            checkpoint,
            AuthorityMutation::PutGrant(durable_grant(id, grant)),
            id,
        )
    }

    pub fn delegate_child<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        parent_grant_id: GrantId,
        child_actor_id: &ActorId,
        child_spec: GrantSpec,
    ) -> Result<GrantId, DurableAuthorityError> {
        let checkpoint = self.host.checkpoint();
        let id =
            self.host
                .delegate_child(transport, parent_grant_id, child_actor_id, child_spec)?;
        let grant = self
            .host
            .grants
            .get(&id)
            .ok_or(DurableAuthorityError::Corrupt("delegated grant missing"))?;
        self.persist(
            checkpoint,
            AuthorityMutation::PutGrant(durable_grant(id, grant)),
            id,
        )
    }

    pub fn revoke_grant_from_trusted_policy(
        &mut self,
        grant_id: GrantId,
    ) -> Result<(), DurableAuthorityError> {
        let checkpoint = self.host.checkpoint();
        self.host.revoke_grant_from_trusted_policy(grant_id);
        self.persist(checkpoint, AuthorityMutation::RevokeGrant(grant_id.0), ())
    }

    pub fn advance_pod_incarnation_from_trusted_policy(
        &mut self,
        pod_id: &PodId,
        expected: PodIncarnation,
        next: PodIncarnation,
    ) -> Result<(), DurableAuthorityError> {
        let checkpoint = self.host.checkpoint();
        self.host
            .advance_pod_incarnation_from_trusted_policy(pod_id, expected, next)?;
        let pod = self
            .host
            .pods
            .get(pod_id)
            .ok_or(DurableAuthorityError::Corrupt("advanced pod missing"))?;
        self.persist(checkpoint, AuthorityMutation::PutPod(durable_pod(pod)), ())
    }

    pub fn advance_resource_epoch_from_trusted_policy(
        &mut self,
        resource_id: &ResourceId,
        expected: ResourceEpoch,
        next: ResourceEpoch,
    ) -> Result<(), DurableAuthorityError> {
        let checkpoint = self.host.checkpoint();
        self.host
            .advance_resource_epoch_from_trusted_policy(resource_id, expected, next)?;
        self.persist_current_resource(checkpoint, resource_id, ())
    }

    pub fn rebind_resource_from_trusted_policy(
        &mut self,
        replacement: ResourceRegistration,
        expected_old_pod: PodIncarnation,
        expected_old_resource: ResourceEpoch,
        expected_old_input: InputEpoch,
    ) -> Result<(), DurableAuthorityError> {
        let checkpoint = self.host.checkpoint();
        self.host.rebind_resource_from_trusted_policy(
            replacement.clone(),
            expected_old_pod,
            expected_old_resource,
            expected_old_input,
        )?;
        self.persist(
            checkpoint,
            AuthorityMutation::PutResource(durable_resource(&replacement)),
            (),
        )
    }

    pub fn advance_credential_generation_from_trusted_policy(
        &mut self,
        actor_id: &ActorId,
        expected: CredentialGeneration,
        next: CredentialGeneration,
    ) -> Result<(), DurableAuthorityError> {
        let checkpoint = self.host.checkpoint();
        self.host
            .advance_credential_generation_from_trusted_policy(actor_id, expected, next)?;
        let actor = self
            .host
            .actors
            .get(actor_id)
            .ok_or(DurableAuthorityError::Corrupt("advanced actor missing"))?;
        self.persist(
            checkpoint,
            AuthorityMutation::PutActor(durable_actor(actor)),
            (),
        )
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
    ) -> Result<InputLease, DurableAuthorityError> {
        self.ensure_current_owner_epoch()?;
        let checkpoint = self.host.checkpoint();
        let lease = self.host.acquire_input_lease(
            transport,
            grant_id,
            scope_id,
            resource_id,
            guards,
            expected_input_epoch,
            lifetime,
        )?;
        self.persist_current_resource(checkpoint, resource_id, lease)
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
    ) -> Result<InputLease, DurableAuthorityError> {
        self.ensure_current_owner_epoch()?;
        let checkpoint = self.host.checkpoint();
        let lease = self.host.human_takeover_input_lease(
            transport,
            grant_id,
            scope_id,
            resource_id,
            guards,
            expected_input_epoch,
            lifetime,
        )?;
        self.persist_current_resource(checkpoint, resource_id, lease)
    }

    fn persist_current_resource<R>(
        &mut self,
        checkpoint: HostCheckpoint,
        resource_id: &ResourceId,
        result: R,
    ) -> Result<R, DurableAuthorityError> {
        let resource = self
            .host
            .resources
            .get(resource_id)
            .ok_or(DurableAuthorityError::Corrupt("changed resource missing"))?;
        self.persist(
            checkpoint,
            AuthorityMutation::PutResource(durable_resource(&resource.registration)),
            result,
        )
    }
}
