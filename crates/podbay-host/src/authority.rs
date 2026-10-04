use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use podbay_core::{
    ActorId, Attempt, AttestedPeer, Epoch, LaunchBinding, PlannedRootBinding, Pod, PodId, Resource,
    ResourceId, ResourceKind, Role, Run, ScopeId, Session, StoreLineageId, WorkKind,
};
use podbay_store::{
    AuthorityActorRecord, AuthorityGrantRecord, AuthorityMutation, AuthorityPodRecord,
    AuthorityResourceRecord, AuthorityRightRecord, AuthoritySnapshot, BoundLaunchAdmission,
    BoundLaunchFormat, BoundLaunchProposal, BoundLaunchRecord, BoundLaunchRequest,
    BoundRootLaunchProposalV2, BoundRootLaunchRequestV2, CommandInspection, CommandLookupSelector,
    EffectClaim, LaunchDispatchStatus, LaunchKeyLookupRequest, LaunchLookupRequest,
    LaunchPortResult, ManagerCredentialClaim, PodBayStore, Receipt, SqliteActorVerifierWitness,
    StoreError, VerifiedPrincipal,
};
use podbay_wire::{
    CommandBody, CommandEnvelope, EffectiveLaunchContract, EffectiveLaunchContractV2,
    FallbackPolicy, ImmutableLaunchDescriptor, ImmutableLaunchDescriptorV2, LaunchRole,
    SessionChoice, Target as WireTarget, WorkKind as WireWorkKind,
    WorkspaceAccess as WireWorkspaceAccess,
};

#[cfg(target_os = "linux")]
use crate::linux_manager_peer::LinuxManagerPeer;

use crate::id_mint::{RootIdMintError, RootLaunchIds};
use crate::launch_spec::{
    EffectiveLaunchSpec, LaunchSelection, RegisteredLaunchProfile, ResolvedNativePaths,
    TrustedNativeHostConfig,
};
use crate::{ActorChallenge, ActorChallengeOrigin, ActorCredentialError, verify_actor_challenge};

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
    NativeResolutionUnverified,
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

    pub fn os_identity(&self) -> &str {
        &self.os_identity
    }

    pub fn process_identity(&self) -> &str {
        &self.process_identity
    }

    pub fn start_identity(&self) -> u64 {
        self.start_identity
    }

    pub fn containment_identity(&self) -> &str {
        &self.containment_identity
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

/// A read-only, owned challenge candidate minted from the current manager's
/// active actor map and durable public verifier. Merely holding it authenticates
/// nobody. It cannot be cloned or reused for a second challenge.
pub struct ActorAuthCandidate {
    actor_id: ActorId,
    scope_id: ScopeId,
    generation: CredentialGeneration,
    process: AuthenticatedProcessSubject,
    origin: PeerOrigin,
    store_lineage: StoreLineageId,
    public_key: [u8; 32],
    verifier_witness: SqliteActorVerifierWitness,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActorAuthProofError {
    StaleVerifier,
    ProcessChanged,
    Credential(ActorCredentialError),
}

/// One pending server nonce and one candidate. The caller must generate the
/// nonce with a CSPRNG and send these exact transcript bytes to the actor.
pub struct PendingActorChallenge {
    candidate: ActorAuthCandidate,
    nonce: [u8; 32],
}

/// A proof-backed peer plus a read-only verifier fence. The caller must supply
/// a freshly kernel-attested process on every check; this is not a socket or a
/// manager-liveness witness, and it grants no rights by itself.
pub struct ProvenActorSession {
    peer: AuthenticatedPeer,
    process: AuthenticatedProcessSubject,
    verifier_witness: SqliteActorVerifierWitness,
}

impl ActorAuthCandidate {
    fn challenge(&self, nonce: [u8; 32]) -> Result<ActorChallenge<'_>, ActorAuthProofError> {
        let origin = match &self.origin {
            PeerOrigin::OwnerCli => ActorChallengeOrigin::OwnerCli,
            PeerOrigin::Pod {
                pod_id,
                incarnation,
                ..
            } => ActorChallengeOrigin::Pod {
                pod_id,
                incarnation: *incarnation,
            },
        };
        ActorChallenge::from_trusted_context(
            nonce,
            &self.store_lineage,
            &self.actor_id,
            &self.scope_id,
            self.generation,
            &self.process,
            origin,
        )
        .map_err(ActorAuthProofError::Credential)
    }

    pub fn begin_challenge(
        self,
        nonce: [u8; 32],
    ) -> Result<PendingActorChallenge, ActorAuthProofError> {
        self.challenge(nonce)?;
        if !self.verifier_witness.is_current() {
            return Err(ActorAuthProofError::StaleVerifier);
        }
        Ok(PendingActorChallenge {
            candidate: self,
            nonce,
        })
    }
}

impl PendingActorChallenge {
    pub fn transcript_bytes(&self) -> Result<Vec<u8>, ActorAuthProofError> {
        if !self.candidate.verifier_witness.is_current() {
            return Err(ActorAuthProofError::StaleVerifier);
        }
        self.candidate
            .challenge(self.nonce)?
            .transcript_bytes()
            .map_err(ActorAuthProofError::Credential)
    }

    pub fn verify(
        self,
        freshly_observed_process: &AuthenticatedProcessSubject,
        signature: &[u8],
    ) -> Result<ProvenActorSession, ActorAuthProofError> {
        let candidate = self.candidate;
        if freshly_observed_process != &candidate.process {
            return Err(ActorAuthProofError::ProcessChanged);
        }
        {
            let challenge = candidate.challenge(self.nonce)?;
            verify_actor_challenge(&challenge, &candidate.public_key, signature)
                .map_err(ActorAuthProofError::Credential)?;
        }
        if !candidate.verifier_witness.is_current() {
            return Err(ActorAuthProofError::StaleVerifier);
        }
        let peer = AuthenticatedPeer {
            origin: candidate.origin,
            process: candidate.process.clone(),
            credential_generation: candidate.generation,
        };
        Ok(ProvenActorSession {
            peer,
            process: candidate.process,
            verifier_witness: candidate.verifier_witness,
        })
    }
}

impl ProvenActorSession {
    pub fn verified_peer(
        &self,
        freshly_observed_process: &AuthenticatedProcessSubject,
    ) -> Result<AuthenticatedPeer, ActorAuthProofError> {
        if freshly_observed_process != &self.process {
            return Err(ActorAuthProofError::ProcessChanged);
        }
        if !self.verifier_witness.is_current() {
            return Err(ActorAuthProofError::StaleVerifier);
        }
        Ok(self.peer.clone())
    }
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
    Scope(ScopeId),
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

/// The port sees only bytes read back from a committed bound admission. The
/// current profile cannot rewrite the logical launch after a lost reply.
/// Native cwd, host and driver locality are still unverified in PB09j; only
/// a preproduction fixture port may opt in to receiving this value.
pub struct AuthorisedBoundLaunch {
    actor_id: ActorId,
    scope_id: ScopeId,
    command_key: String,
    correlation_id: String,
    record: BoundLaunchRecord,
    effective: EffectiveLaunchContract,
    descriptor: ImmutableLaunchDescriptor,
    native_resolution: NativeResolutionState,
}

/// Host-created capability for a committed descriptor whose native fields
/// were rechecked against trusted Linux configuration immediately preclaim.
/// Its private constructor keeps decoded/request data from creating one.
/// This cooperative pathname proof does not pin the dynamic loader/libraries
/// or prevent a later same-UID rename/write before an OS port uses the path.
pub struct ResolvedNativeLaunch {
    committed: AuthorisedBoundLaunch,
    paths: ResolvedNativePaths,
    store_path: PathBuf,
    store_lineage: String,
    owner_epoch: u64,
    credential_epoch: u64,
    manager_peer: AttestedPeer,
    resource_input_epochs: BTreeMap<String, u64>,
}

/// Read-only, host-created proof for the exact current committed Codex V2
/// root launch. It neither claims the outbox effect nor authorises a port call.
/// A future port must recheck the manager and path evidence at effect time.
pub struct ResolvedNativeCodexLaunch {
    record: BoundLaunchRecord,
    effective: EffectiveLaunchContractV2,
    descriptor: ImmutableLaunchDescriptorV2,
    paths: ResolvedNativePaths,
    store_path: PathBuf,
    #[cfg(target_os = "linux")]
    store_file_identity: (u64, u64),
    store_lineage: String,
    owner_epoch: u64,
    credential_epoch: u64,
    authority_revision: u64,
    manager_peer: AttestedPeer,
    resource_input_epochs: BTreeMap<String, u64>,
}

impl ResolvedNativeCodexLaunch {
    pub fn committed_record(&self) -> &BoundLaunchRecord {
        &self.record
    }
    pub fn effective(&self) -> &EffectiveLaunchContractV2 {
        &self.effective
    }
    pub fn descriptor(&self) -> &ImmutableLaunchDescriptorV2 {
        &self.descriptor
    }
    pub fn effective_spec_bytes(&self) -> &[u8] {
        &self.record.effective_spec
    }
    pub fn descriptor_bytes(&self) -> &[u8] {
        &self.record.descriptor
    }
    pub fn outbox_id(&self) -> i64 {
        self.record.receipt.outbox_id
    }
    pub fn store_path(&self) -> &Path {
        &self.store_path
    }
    #[cfg(target_os = "linux")]
    pub fn store_file_identity(&self) -> (u64, u64) {
        self.store_file_identity
    }
    pub fn store_lineage(&self) -> &str {
        &self.store_lineage
    }
    pub fn owner_epoch(&self) -> u64 {
        self.owner_epoch
    }
    pub fn credential_epoch(&self) -> u64 {
        self.credential_epoch
    }
    pub fn authority_revision(&self) -> u64 {
        self.authority_revision
    }
    pub fn manager_peer(&self) -> &AttestedPeer {
        &self.manager_peer
    }
    pub fn resource_input_epochs(&self) -> &BTreeMap<String, u64> {
        &self.resource_input_epochs
    }
    pub fn cwd(&self) -> &Path {
        &self.paths.cwd
    }
    pub fn executable(&self) -> &Path {
        &self.paths.executable
    }
    pub fn executable_sha256(&self) -> &str {
        &self.paths.executable_sha256
    }
}

impl ResolvedNativeLaunch {
    pub fn store_path(&self) -> &Path {
        &self.store_path
    }
    pub fn store_lineage(&self) -> &str {
        &self.store_lineage
    }
    pub fn owner_epoch(&self) -> u64 {
        self.owner_epoch
    }
    pub fn credential_epoch(&self) -> u64 {
        self.credential_epoch
    }
    pub fn manager_peer(&self) -> &AttestedPeer {
        &self.manager_peer
    }
    pub fn resource_input_epochs(&self) -> &BTreeMap<String, u64> {
        &self.resource_input_epochs
    }
    pub fn outbox_id(&self) -> i64 {
        self.committed.record.receipt.outbox_id
    }
    pub fn descriptor_bytes(&self) -> &[u8] {
        &self.committed.record.descriptor
    }
    pub fn effective_spec_bytes(&self) -> &[u8] {
        &self.committed.record.effective_spec
    }
    pub fn committed(&self) -> &AuthorisedBoundLaunch {
        &self.committed
    }
    pub fn cwd(&self) -> &Path {
        &self.paths.cwd
    }
    pub fn executable(&self) -> &Path {
        &self.paths.executable
    }
    pub fn executable_sha256(&self) -> &str {
        &self.paths.executable_sha256
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NativeResolutionState {
    Unverified,
}

impl AuthorisedBoundLaunch {
    /// Validates a readback record against the already authenticated host
    /// action. This check alone does not authorize any native effect.
    pub fn from_committed(
        authorised: &AuthorisedDispatch,
        record: BoundLaunchRecord,
    ) -> Result<Self, HostError> {
        let effective = EffectiveLaunchContract::decode(&record.effective_spec)
            .map_err(|_| HostError::StaleGuard)?;
        let descriptor = ImmutableLaunchDescriptor::decode_json(&record.descriptor)
            .map_err(|_| HostError::StaleGuard)?;
        effective
            .compare_with_descriptor(&descriptor)
            .map_err(|_| HostError::StaleGuard)?;
        let HostAction::LaunchPod { pod_id, role, .. } = &authorised.action else {
            return Err(HostError::InvalidInput);
        };
        if record.scope_id != authorised.scope_id.as_str()
            || record.pod_id != pod_id.as_str()
            || effective.role() != (*role).into()
            || descriptor.session_id() != record.session_id
            || descriptor.run_id() != record.run_id
            || descriptor.attempt_id() != record.attempt_id
            || descriptor.pod_incarnation() != record.pod_incarnation
        {
            return Err(HostError::StaleGuard);
        }
        Ok(Self {
            actor_id: authorised.actor_id.clone(),
            scope_id: authorised.scope_id.clone(),
            command_key: authorised.command_key.clone(),
            correlation_id: authorised.correlation_id.clone(),
            record,
            effective,
            descriptor,
            native_resolution: NativeResolutionState::Unverified,
        })
    }
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
    pub fn record(&self) -> &BoundLaunchRecord {
        &self.record
    }
    pub fn effective(&self) -> &EffectiveLaunchContract {
        &self.effective
    }
    pub fn descriptor(&self) -> &ImmutableLaunchDescriptor {
        &self.descriptor
    }
    pub fn descriptor_bytes(&self) -> &[u8] {
        &self.record.descriptor
    }
    pub fn native_resolution(&self) -> NativeResolutionState {
        self.native_resolution
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

    fn launch_bound(
        &mut self,
        launch: AuthorisedBoundLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError>;

    /// Production ports consume only the private host-created resolved value.
    fn launch_resolved(
        &mut self,
        _launch: ResolvedNativeLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        Err(PortDispatchError::RefusedBeforeEffect)
    }

    /// Distinct committed Codex V2 root launch. No V1 descriptor or fixture
    /// capability can enter this path.
    fn launch_resolved_codex_v2(
        &mut self,
        _launch: ResolvedNativeCodexLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        Err(PortDispatchError::RefusedBeforeEffect)
    }

    /// The host checks this before claiming a V2 effect. A default-deny port
    /// leaves the durable outbox Prepared and calls no external effect.
    fn accepts_resolved_codex_v2(&self) -> bool {
        false
    }

    fn accepts_resolved_native_launch(&self) -> bool {
        false
    }

    /// Default-deny until a trusted host-owned native resolver supplies a
    /// private verified capability. Only fake test ports may opt in here.
    fn allow_unverified_native_launch_for_fixture(&self) -> bool {
        false
    }
}

/// Aggregate snapshots and logical selection for a new initial root launch.
/// Native cwd, host, executable identity and drivers come only from registered
/// host/profile configuration. A duplicate may omit this entire proposal.
#[derive(Clone, Debug)]
pub struct BoundHostLaunchProposal {
    pub session: Session,
    pub run: Run,
    pub binding: LaunchBinding,
    pub selection: LaunchSelection,
}

#[derive(Clone, Debug)]
pub struct BoundLaunchPodRequest {
    pub host_request: HostRequest,
    pub canonical_request: Vec<u8>,
    pub proposal: Option<BoundHostLaunchProposal>,
}

/// Host-owned context for the first high-level wire root. The GrantId comes
/// from trusted grant installation or replay; wire `grantRef` is only compared
/// with it. The caller supplies a monotonic deadline from its own policy.
#[derive(Clone, Debug)]
pub struct TrustedWireRootLaunchPolicy {
    grant_id: GrantId,
    deadline: Instant,
    result_contract_ref: Box<str>,
}

impl TrustedWireRootLaunchPolicy {
    pub fn from_trusted_policy(
        grant_id: GrantId,
        deadline: Instant,
        result_contract_ref: &str,
    ) -> Result<Self, HostError> {
        if deadline <= Instant::now() || !valid_token(result_contract_ref) {
            return Err(HostError::InvalidInput);
        }
        Ok(Self {
            grant_id,
            deadline,
            result_contract_ref: result_contract_ref.into(),
        })
    }
}

pub trait StablePortReceipt {
    fn stable_reference(&self) -> &str;
}

impl StablePortReceipt for PortReceiptRef {
    fn stable_reference(&self) -> &str {
        self.as_str()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchPodReceipt {
    pub receipt: Receipt,
    pub status: LaunchDispatchStatus,
    pub duplicate: bool,
    /// False also covers a committed Prepared admission held by the native
    /// resolution gate; it is not evidence of an OS launch.
    pub port_called: bool,
}

#[derive(Debug)]
pub enum LaunchPodError {
    Host(HostError),
    Store(StoreError),
    IdMint(RootIdMintError),
    WrongOperation,
    /// Admission committed, but dispatch/readback did not produce a complete
    /// reply. The original CommandId remains queryable and must not be retried
    /// under a new key or with newly minted root IDs.
    CommittedDispatchUnavailable {
        receipt: Receipt,
        source: Box<LaunchPodError>,
    },
    /// A port outcome or pre-port refusal could not be durably recorded.
    /// Query the original receipt; a committed claim must never be resent.
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
impl From<RootIdMintError> for LaunchPodError {
    fn from(value: RootIdMintError) -> Self {
        Self::IdMint(value)
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
            Target::Scope(scope) => {
                right.operation == Operation::LaunchPod && scope == &spec.scope_id
            }
            Target::Pod(id) => {
                matches!(right.operation, Operation::LaunchPod | Operation::StopPod)
                    && match right.operation {
                        // A precise LaunchPod right may be issued before the
                        // initial Pod row is atomically admitted. Existing
                        // identities may never cross scope.
                        Operation::LaunchPod => self
                            .pods
                            .get(id)
                            .is_none_or(|pod| pod.scope_id == spec.scope_id),
                        Operation::StopPod => self
                            .pods
                            .get(id)
                            .is_some_and(|pod| pod.scope_id == spec.scope_id),
                        _ => false,
                    }
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

    /// Initial launch authorisation for an exact proposed PodId. It checks
    /// actor/grant/credential and initial fences without installing a Pod in
    /// memory. The store transaction is the first authority registration.
    fn authorise_proposed_launch<T: AuthenticatedTransport>(
        &self,
        transport: &T,
        request: &HostRequest,
    ) -> Result<AuthorisedDispatch, HostError> {
        let HostAction::LaunchPod {
            pod_id, credential, ..
        } = &request.action
        else {
            return Err(HostError::InvalidInput);
        };
        request.action.validate()?;
        if !valid_token(&request.command_key) || !valid_token(&request.correlation_id) {
            return Err(HostError::InvalidInput);
        }
        if request.deadline <= Instant::now() {
            return Err(HostError::DeadlineExpired);
        }
        let actor = self.authenticate(transport)?;
        let exact = Right::new(Operation::LaunchPod, Target::Pod(pod_id.clone()));
        if self
            .check_grant(actor, request.grant_id, &request.scope_id, &exact)
            .is_err()
        {
            self.check_grant(
                actor,
                request.grant_id,
                &request.scope_id,
                &Right::new(
                    Operation::LaunchPod,
                    Target::Scope(request.scope_id.clone()),
                ),
            )?;
        }
        if request.guards.manager_epoch != self.manager_epoch
            || request.guards.pod_incarnation.get() != 1
            || request.guards.resource_epoch.is_some()
            || request.guards.credential_generation != actor.credential_generation
        {
            return Err(HostError::StaleGuard);
        }
        if self
            .pods
            .get(pod_id)
            .is_some_and(|pod| pod.scope_id != request.scope_id || pod.incarnation.get() != 1)
        {
            return Err(HostError::StaleGuard);
        }
        if let Some(reference) = credential {
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

/// A read-only current-pod context borrowed from the manager that still
/// holds its lifetime lock. It is not pod inspection evidence or a rebind
/// admission. Recheck immediately before external inspection or preparation.
///
/// A context cannot escape the authority that owns its manager lock:
/// ```compile_fail
/// use podbay_core::{ScopeId, PodId};
/// use podbay_host::{DurableAuthority, HostDispatchPort, ManagerRebindContext};
/// fn escape<P: HostDispatchPort>(mut host: DurableAuthority<P>, scope: ScopeId,
///     pod: PodId) -> ManagerRebindContext<'static> {
///     host.rebind_context(&scope, &pod).unwrap()
/// }
/// ```
pub struct ManagerRebindContext<'a> {
    _manager_lock: &'a File,
    database: &'a Path,
    #[cfg(target_os = "linux")]
    database_identity: (u64, u64),
    #[cfg(target_os = "linux")]
    manager_peer: &'a LinuxManagerPeer,
    manager_claim: &'a ManagerCredentialClaim,
    store: &'a mut PodBayStore,
    snapshot: podbay_store::CurrentBoundPodSnapshot,
    identity: podbay_core::PodFenceIdentity,
    input_epochs: BTreeMap<ResourceId, podbay_core::InputEpoch>,
    peer: AttestedPeer,
}

#[derive(Debug)]
pub enum RebindContextError {
    Host(HostError),
    Store(StoreError),
}
impl From<HostError> for RebindContextError {
    fn from(value: HostError) -> Self {
        Self::Host(value)
    }
}
impl From<StoreError> for RebindContextError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}
impl From<RebindContextError> for LaunchPodError {
    fn from(value: RebindContextError) -> Self {
        match value {
            RebindContextError::Host(error) => Self::Host(error),
            RebindContextError::Store(error) => Self::Store(error),
        }
    }
}

impl ManagerRebindContext<'_> {
    pub fn store_path(&self) -> &Path {
        self.database
    }
    pub fn store_lineage(&self) -> &str {
        self.manager_claim.store_lineage()
    }
    pub fn owner_epoch(&self) -> u64 {
        self.manager_claim.owner_epoch()
    }
    pub fn credential_epoch(&self) -> u64 {
        self.manager_claim.credential_epoch()
    }
    pub fn manager_peer(&self) -> &AttestedPeer {
        // The snapshot is only minted after the Linux-only manager check.
        &self.peer
    }
    pub fn identity(&self) -> &podbay_core::PodFenceIdentity {
        &self.identity
    }
    pub fn launch(&self) -> &BoundLaunchRecord {
        self.snapshot.launch()
    }
    pub fn resource_input_epochs(&self) -> &BTreeMap<ResourceId, podbay_core::InputEpoch> {
        &self.input_epochs
    }
    pub fn authority_revision(&self) -> u64 {
        self.snapshot.authority_revision()
    }

    pub fn recheck_current(&mut self) -> Result<(), RebindContextError> {
        #[cfg(not(target_os = "linux"))]
        return Err(HostError::Unsupported.into());
        #[cfg(target_os = "linux")]
        {
            recheck_current_manager(
                self.store,
                self.database,
                self.database_identity,
                self.manager_peer,
                self.manager_claim,
            )?;
            let fresh = self.store.current_bound_pod_snapshot(
                self.identity.scope_id.as_str(),
                self.identity.pod_id.as_str(),
            )?;
            let inputs = fresh
                .resources()
                .iter()
                .map(|resource| (resource.id().clone(), resource.input_epoch()))
                .collect::<BTreeMap<_, _>>();
            if fresh.store_lineage() != self.snapshot.store_lineage()
                || fresh.owner_epoch() != self.snapshot.owner_epoch()
                || fresh.authority_revision() != self.snapshot.authority_revision()
                || fresh.attempt_id() != self.snapshot.attempt_id()
                || fresh.pod_incarnation() != self.snapshot.pod_incarnation()
                || fresh.launch() != self.snapshot.launch()
                || inputs != self.input_epochs
            {
                return Err(HostError::StaleGuard.into());
            }
            recheck_current_manager(
                self.store,
                self.database,
                self.database_identity,
                self.manager_peer,
                self.manager_claim,
            )?;
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
fn recheck_current_manager(
    store: &mut PodBayStore,
    database: &Path,
    database_identity: (u64, u64),
    peer: &LinuxManagerPeer,
    claim: &ManagerCredentialClaim,
) -> Result<AttestedPeer, RebindContextError> {
    peer.recheck().map_err(|_| HostError::StaleGuard)?;
    let metadata =
        std::fs::symlink_metadata(database).map_err(|_| HostError::AuthorityStoreUnavailable)?;
    if !metadata.is_file() || (metadata.dev(), metadata.ino()) != database_identity {
        return Err(HostError::StaleGuard.into());
    }
    if std::fs::canonicalize(database).map_err(|_| HostError::AuthorityStoreUnavailable)?
        != database
        || store.current_manager_credential_claim(claim.owner_epoch())? != *claim
        || !store.current_manager_peer_matches(claim, peer.peer())?
    {
        return Err(HostError::StaleGuard.into());
    }
    Ok(peer.peer().clone())
}

/// SQLite-backed authority. Recorded actors and grants are inert after reopen
/// until trusted replay. Dispatch here is an authority gate, not durable command
/// admission; PB09 must issue the durable receipt before production effects.
pub struct DurableAuthority<P: HostDispatchPort> {
    _manager_lock: File,
    canonical_database: PathBuf,
    #[cfg(target_os = "linux")]
    database_identity: (u64, u64),
    #[cfg(target_os = "linux")]
    manager_peer: LinuxManagerPeer,
    manager_claim: ManagerCredentialClaim,
    host: HostAuthority<P>,
    store: PodBayStore,
    recorded: AuthoritySnapshot,
    launch_profiles: HashMap<String, RegisteredLaunchProfile>,
    native_host: Option<TrustedNativeHostConfig>,
}

impl<P: HostDispatchPort> DurableAuthority<P> {
    pub fn open(path: impl AsRef<Path>, port: P) -> Result<Self, DurableAuthorityError> {
        if !cfg!(target_os = "linux") {
            return Err(DurableAuthorityError::Host(HostError::Unsupported));
        }
        let path = path.as_ref();
        let (manager_lock, canonical_database) = acquire_manager_lock(path)?;
        #[cfg(target_os = "linux")]
        let manager_peer = LinuxManagerPeer::capture()?;
        let mut store = PodBayStore::open(&canonical_database)?;
        if std::fs::canonicalize(&canonical_database)? != canonical_database {
            return Err(DurableAuthorityError::Corrupt(
                "authority database path changed while acquiring lease",
            ));
        }
        #[cfg(target_os = "linux")]
        let database_identity = {
            let metadata = std::fs::metadata(&canonical_database)?;
            (metadata.dev(), metadata.ino())
        };
        let old_epoch = store.owner_epoch()?;
        let new_epoch = old_epoch
            .checked_add(1)
            .ok_or(DurableAuthorityError::Corrupt("manager epoch exhausted"))?;
        let recorded = store.begin_authority_replay(old_epoch, new_epoch)?;
        let manager_claim = store.current_manager_credential_claim(new_epoch)?;
        if recorded.owner_epoch != new_epoch {
            return Err(DurableAuthorityError::Corrupt(
                "owner changed during manager replay",
            ));
        }
        #[cfg(target_os = "linux")]
        manager_peer.recheck()?;
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
        // Register only after replay/hydration succeeds, while the lifetime
        // lock still belongs to this opening manager. Request/actor identity
        // never supplies the OS peer stored for this credential generation.
        #[cfg(target_os = "linux")]
        {
            manager_peer.recheck()?;
            store.register_current_manager_peer(&manager_claim, manager_peer.peer())?;
            manager_peer.recheck()?;
            if store.current_manager_credential_claim(new_epoch)? != manager_claim
                || !store.current_manager_peer_matches(&manager_claim, manager_peer.peer())?
            {
                return Err(DurableAuthorityError::Corrupt(
                    "manager binding changed during registration",
                ));
            }
        }
        Ok(Self {
            _manager_lock: manager_lock,
            canonical_database,
            #[cfg(target_os = "linux")]
            database_identity,
            #[cfg(target_os = "linux")]
            manager_peer,
            manager_claim,
            host,
            store,
            recorded,
            launch_profiles: HashMap::new(),
            native_host: None,
        })
    }

    /// Scope and PodId are selectors only. Attempt, incarnation, launch bytes
    /// and complete resource inputs are derived from one current store view.
    pub fn rebind_context(
        &mut self,
        scope: &ScopeId,
        pod: &PodId,
    ) -> Result<ManagerRebindContext<'_>, RebindContextError> {
        #[cfg(not(target_os = "linux"))]
        return Err(HostError::Unsupported.into());
        #[cfg(target_os = "linux")]
        {
            let peer = recheck_current_manager(
                &mut self.store,
                &self.canonical_database,
                self.database_identity,
                &self.manager_peer,
                &self.manager_claim,
            )?;
            let snapshot = self
                .store
                .current_bound_pod_snapshot(scope.as_str(), pod.as_str())?;
            if snapshot.store_lineage().as_str() != self.manager_claim.store_lineage()
                || snapshot.owner_epoch().get() != self.manager_claim.owner_epoch()
                || snapshot.authority_revision() != self.recorded.revision
            {
                return Err(HostError::StaleGuard.into());
            }
            let identity = podbay_core::PodFenceIdentity {
                scope_id: snapshot.scope_id().clone(),
                pod_id: snapshot.pod_id().clone(),
                attempt_id: snapshot.attempt_id().clone(),
                incarnation: snapshot.pod_incarnation(),
                store_lineage: snapshot.store_lineage().clone(),
            };
            let input_epochs = snapshot
                .resources()
                .iter()
                .map(|resource| (resource.id().clone(), resource.input_epoch()))
                .collect();
            recheck_current_manager(
                &mut self.store,
                &self.canonical_database,
                self.database_identity,
                &self.manager_peer,
                &self.manager_claim,
            )?;
            Ok(ManagerRebindContext {
                _manager_lock: &self._manager_lock,
                database: &self.canonical_database,
                database_identity: self.database_identity,
                manager_peer: &self.manager_peer,
                manager_claim: &self.manager_claim,
                store: &mut self.store,
                snapshot,
                identity,
                input_epochs,
                peer,
            })
        }
    }

    /// Inspects only the current committed root launch selected by scope and
    /// PodId. The store supplies the exact bytes; today's opted-in profile and
    /// native host must still reproduce their complete effective meaning.
    /// This method does not claim, dispatch, or advance any effect.
    pub fn inspect_committed_root_codex_v2(
        &mut self,
        scope: &ScopeId,
        pod: &PodId,
    ) -> Result<ResolvedNativeCodexLaunch, RebindContextError> {
        let initial = self.rebind_context(scope, pod)?;
        let record = initial.launch().clone();
        drop(initial);
        if record.format != BoundLaunchFormat::CodexV2 {
            return Err(HostError::Unsupported.into());
        }
        let effective = EffectiveLaunchContractV2::decode(&record.effective_spec)
            .map_err(|_| HostError::StaleGuard)?;
        let descriptor = ImmutableLaunchDescriptorV2::decode_json(&record.descriptor)
            .map_err(|_| HostError::StaleGuard)?;
        effective
            .compare_with_descriptor(&descriptor)
            .map_err(|_| HostError::StaleGuard)?;
        if descriptor.scope_id() != record.scope_id
            || descriptor.session_id() != record.session_id
            || descriptor.run_id() != record.run_id
            || descriptor.attempt_id() != record.attempt_id
            || descriptor.pod_id() != record.pod_id
            || descriptor.pod_incarnation() != record.pod_incarnation
            || descriptor.parent_run_id().is_some()
            || descriptor.resources_len() != record.resources.len()
        {
            return Err(HostError::StaleGuard.into());
        }
        for (index, bound) in record.resources.iter().enumerate() {
            let native = descriptor.resource(index).ok_or(HostError::StaleGuard)?;
            if native.resource_id != bound.id || native.epoch != bound.epoch {
                return Err(HostError::StaleGuard.into());
            }
        }
        let profile = self
            .launch_profiles
            .get(effective.base().profile_ref())
            .cloned()
            .ok_or(HostError::StaleGuard)?;
        let host = self.native_host.clone().ok_or(HostError::StaleGuard)?;
        #[cfg(target_os = "linux")]
        let store_file_identity = self.database_identity;
        let mut current = self.rebind_context(scope, pod)?;
        if current.launch() != &record {
            return Err(HostError::StaleGuard.into());
        }
        let paths = profile
            .revalidate_committed_codex_v2(&host, &effective, &descriptor)
            .map_err(RebindContextError::Host)?;
        let resource_input_epochs = current
            .resource_input_epochs()
            .iter()
            .map(|(id, epoch)| (id.as_str().to_owned(), epoch.get()))
            .collect();
        current.recheck_current()?;
        Ok(ResolvedNativeCodexLaunch {
            record,
            effective,
            descriptor,
            paths,
            store_path: current.store_path().to_path_buf(),
            #[cfg(target_os = "linux")]
            store_file_identity,
            store_lineage: current.store_lineage().to_owned(),
            owner_epoch: current.owner_epoch(),
            credential_epoch: current.credential_epoch(),
            authority_revision: current.authority_revision(),
            manager_peer: current.manager_peer().clone(),
            resource_input_epochs,
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

    /// Treats `actor_selector` only as a lookup hint. The process must come
    /// from a fresh kernel-attested transport, never from request JSON. This
    /// returns owned, read-only proof inputs; it does not authenticate the
    /// caller, activate replayed actors, grant rights, or invoke a host port.
    pub fn challenge_candidate_for_observed_process(
        &mut self,
        actor_selector: &ActorId,
        observed_process: &AuthenticatedProcessSubject,
    ) -> Result<ActorAuthCandidate, DurableAuthorityError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (actor_selector, observed_process);
            return Err(HostError::Unsupported.into());
        }
        #[cfg(target_os = "linux")]
        {
            if observed_process.platform() != HostPlatform::Linux {
                return Err(HostError::Unsupported.into());
            }
            self.recheck_actor_resolution_manager()?;
            let current = self.store.authority_snapshot()?;
            if current.owner_epoch != self.manager_claim.owner_epoch()
                || current.owner_epoch != self.host.manager_epoch.get()
                || current.revision != self.recorded.revision
            {
                return Err(HostError::StaleGuard.into());
            }

            let mut active = self
                .host
                .actors
                .values()
                .filter(|actor| actor.process == *observed_process);
            let actor = active.next().ok_or(HostError::Unauthenticated)?.clone();
            if active.next().is_some() || actor.actor_id != *actor_selector {
                return Err(HostError::Unauthenticated.into());
            }
            let expected = durable_actor(&actor);
            for snapshot in [&current, &self.recorded] {
                let mut matching = snapshot
                    .actors
                    .iter()
                    .filter(|record| actor_record_matches_process(record, observed_process));
                if matching.next() != Some(&expected) || matching.next().is_some() {
                    return Err(HostError::Unauthenticated.into());
                }
            }
            if let PeerOrigin::Pod {
                actor_id,
                pod_id,
                incarnation,
            } = &actor.origin
            {
                if actor_id != &actor.actor_id {
                    return Err(HostError::Unauthenticated.into());
                }
                let pod = self
                    .host
                    .pods
                    .get(pod_id)
                    .ok_or(HostError::Unauthenticated)?;
                if pod.scope_id != actor.scope_id || pod.incarnation != *incarnation {
                    return Err(HostError::Unauthenticated.into());
                }
                let expected_pod = durable_pod(pod);
                for snapshot in [&current, &self.recorded] {
                    let mut matching = snapshot
                        .pods
                        .iter()
                        .filter(|record| record.pod_id == pod_id.as_str());
                    if matching.next() != Some(&expected_pod) || matching.next().is_some() {
                        return Err(HostError::Unauthenticated.into());
                    }
                }
            }

            let public_key = self.store.current_actor_verifier(
                current.owner_epoch,
                current.revision,
                &expected,
            )?;
            let store_lineage = StoreLineageId::try_from(self.manager_claim.store_lineage())
                .map_err(|_| DurableAuthorityError::Corrupt("invalid store lineage"))?;
            let verifier_witness = SqliteActorVerifierWitness::for_actor(
                &self.canonical_database,
                self.manager_claim.store_lineage(),
                current.owner_epoch,
                current.revision,
                expected,
                public_key,
            )?;
            self.recheck_actor_resolution_manager()?;
            let final_snapshot = self.store.authority_snapshot()?;
            if final_snapshot.owner_epoch != current.owner_epoch
                || final_snapshot.revision != current.revision
                || !verifier_witness.is_current()
            {
                return Err(HostError::StaleGuard.into());
            }
            Ok(ActorAuthCandidate {
                actor_id: actor.actor_id,
                scope_id: actor.scope_id,
                generation: actor.credential_generation,
                process: actor.process,
                origin: actor.origin,
                store_lineage,
                public_key,
                verifier_witness,
            })
        }
    }

    /// Resolves a live local transport observation to one active actor. The
    /// caller must have independently attested the process with the kernel and
    /// the credential generation with the local credential protocol; neither
    /// value may come from a request envelope. This method grants no rights.
    /// Recorded actors remain inert after manager reopen until trusted replay
    /// has explicitly reattested them into this manager's active actor map.
    pub fn resolve_observed_actor_from_trusted_transport(
        &mut self,
        observed_process: &AuthenticatedProcessSubject,
        observed_generation: CredentialGeneration,
    ) -> Result<AuthenticatedPeer, DurableAuthorityError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (observed_process, observed_generation);
            return Err(HostError::Unsupported.into());
        }
        #[cfg(target_os = "linux")]
        {
            if observed_process.platform() != HostPlatform::Linux {
                return Err(HostError::Unsupported.into());
            }
            self.recheck_actor_resolution_manager()?;
            let current = self.store.authority_snapshot()?;
            if current.owner_epoch != self.manager_claim.owner_epoch()
                || current.owner_epoch != self.host.manager_epoch.get()
                || current.revision != self.recorded.revision
            {
                return Err(HostError::StaleGuard.into());
            }

            let mut active = self
                .host
                .actors
                .values()
                .filter(|actor| actor.process == *observed_process);
            let actor = active.next().ok_or(HostError::Unauthenticated)?.clone();
            if active.next().is_some() || actor.credential_generation != observed_generation {
                return Err(HostError::Unauthenticated.into());
            }
            let expected = durable_actor(&actor);
            for snapshot in [&current, &self.recorded] {
                let mut matching = snapshot
                    .actors
                    .iter()
                    .filter(|record| actor_record_matches_process(record, observed_process));
                if matching.next() != Some(&expected) || matching.next().is_some() {
                    return Err(HostError::Unauthenticated.into());
                }
            }

            if let PeerOrigin::Pod {
                actor_id,
                pod_id,
                incarnation,
            } = &actor.origin
            {
                if actor_id != &actor.actor_id {
                    return Err(HostError::Unauthenticated.into());
                }
                let pod = self
                    .host
                    .pods
                    .get(pod_id)
                    .ok_or(HostError::Unauthenticated)?;
                if pod.scope_id != actor.scope_id || pod.incarnation != *incarnation {
                    return Err(HostError::Unauthenticated.into());
                }
                let expected = durable_pod(pod);
                for snapshot in [&current, &self.recorded] {
                    let mut matching = snapshot
                        .pods
                        .iter()
                        .filter(|record| record.pod_id == pod_id.as_str());
                    if matching.next() != Some(&expected) || matching.next().is_some() {
                        return Err(HostError::Unauthenticated.into());
                    }
                }
            }

            self.recheck_actor_resolution_manager()?;
            let final_snapshot = self.store.authority_snapshot()?;
            if final_snapshot.owner_epoch != current.owner_epoch
                || final_snapshot.revision != current.revision
            {
                return Err(HostError::StaleGuard.into());
            }
            Ok(AuthenticatedPeer {
                origin: actor.origin,
                process: actor.process,
                credential_generation: actor.credential_generation,
            })
        }
    }

    #[cfg(target_os = "linux")]
    fn recheck_actor_resolution_manager(&mut self) -> Result<(), DurableAuthorityError> {
        recheck_current_manager(
            &mut self.store,
            &self.canonical_database,
            self.database_identity,
            &self.manager_peer,
            &self.manager_claim,
        )
        .map(|_| ())
        .map_err(|error| match error {
            RebindContextError::Host(error) => DurableAuthorityError::Host(error),
            RebindContextError::Store(StoreError::StaleEpoch) => {
                DurableAuthorityError::Host(HostError::StaleGuard)
            }
            RebindContextError::Store(error) => DurableAuthorityError::Store(error),
        })
    }

    /// Read only this live actor's own durable command receipt and outbox
    /// status. The transport, never the request, supplies the actor principal
    /// and credential generation. Historical receipt lookup remains available
    /// after a grant changes, but grants no host or provider effect.
    pub fn lookup_command<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        scope: &ScopeId,
        selector: &CommandLookupSelector,
    ) -> Result<CommandInspection, DurableAuthorityError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (transport, scope, selector);
            return Err(HostError::Unsupported.into());
        }
        #[cfg(target_os = "linux")]
        {
            self.recheck_actor_resolution_manager()?;
            let actor = self.host.authenticate(transport)?.clone();
            if actor.scope_id != *scope {
                return Err(StoreError::NotFound.into());
            }
            let expected = durable_actor(&actor);
            let current = self.store.authority_snapshot()?;
            if current.owner_epoch != self.manager_claim.owner_epoch()
                || current.owner_epoch != self.host.manager_epoch.get()
                || current.revision != self.recorded.revision
            {
                return Err(HostError::StaleGuard.into());
            }
            for snapshot in [&current, &self.recorded] {
                let mut matching = snapshot
                    .actors
                    .iter()
                    .filter(|record| record.actor_id == actor.actor_id.as_str());
                if matching.next() != Some(&expected) || matching.next().is_some() {
                    return Err(HostError::Unauthenticated.into());
                }
            }
            let principal =
                VerifiedPrincipal::from_authenticated_boundary(actor.actor_id.as_str())?;
            let found = self
                .store
                .lookup_command(scope.as_str(), &principal, selector);
            self.recheck_actor_resolution_manager()?;
            let fresh = self.store.authority_snapshot()?;
            if fresh.owner_epoch != current.owner_epoch || fresh.revision != current.revision {
                return Err(HostError::StaleGuard.into());
            }
            let mut matching = fresh
                .actors
                .iter()
                .filter(|record| record.actor_id == actor.actor_id.as_str());
            if matching.next() != Some(&expected) || matching.next().is_some() {
                return Err(HostError::Unauthenticated.into());
            }
            let live = self.host.authenticate(transport)?;
            if durable_actor(live) != expected {
                return Err(HostError::Unauthenticated.into());
            }
            self.recheck_actor_resolution_manager()?;
            found.map_err(Into::into)
        }
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

    pub fn register_native_host_from_trusted_policy(
        &mut self,
        config: TrustedNativeHostConfig,
    ) -> Result<(), HostError> {
        if config.target_os() != podbay_wire::TargetOs::Linux {
            return Err(HostError::Unsupported);
        }
        self.native_host = Some(config);
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

    /// New bound initial launch. A duplicate is inspection-only here: it
    /// returns original bytes/receipt before today's profile is resolved and
    /// never replays an external port call. Prepared recovery is explicit.
    pub fn launch_bound_pod<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        request: BoundLaunchPodRequest,
    ) -> Result<LaunchPodReceipt, LaunchPodError>
    where
        P::Receipt: StablePortReceipt,
    {
        let (authorised, record, duplicate) = self.lookup_or_admit_bound(transport, &request)?;
        if duplicate {
            return self.bound_receipt(record, true);
        }
        self.dispatch_committed_bound(authorised.ok_or(HostError::InvalidInput)?, record, false)
    }

    /// Commits the complete bound launch transaction without an OS port call.
    pub fn admit_bound_pod<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        request: BoundLaunchPodRequest,
    ) -> Result<LaunchPodReceipt, LaunchPodError> {
        let (_, record, duplicate) = self.lookup_or_admit_bound(transport, &request)?;
        self.bound_receipt(record, duplicate)
    }

    /// Reviews and commits one first root Codex V2 launch. This records the
    /// typed effective policy and native descriptor but makes no OS port call.
    /// A delegated child Worker needs a distinct parent-authorised admission.
    pub fn admit_bound_root_codex_v2<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        request: BoundLaunchPodRequest,
    ) -> Result<LaunchPodReceipt, LaunchPodError> {
        self.ensure_current_owner_epoch()?;
        self.recheck_manager_binding()?;
        let HostAction::LaunchPod { pod_id, .. } = &request.host_request.action else {
            return Err(LaunchPodError::WrongOperation);
        };
        let actor = self.host.authenticate(transport)?;
        if actor.scope_id != request.host_request.scope_id {
            return Err(HostError::Unauthorised.into());
        }
        let principal = VerifiedPrincipal::from_authenticated_boundary(actor.actor_id.as_str())?;
        let lookup = self.bound_lookup(&request, principal.clone());
        if let Some(record) = self.store.lookup_bound_launch(&lookup)? {
            if record.format != BoundLaunchFormat::CodexV2 {
                return Err(HostError::Unauthorised.into());
            }
            return self.bound_receipt(record, true);
        }
        let authorised = self
            .host
            .authorise_proposed_launch(transport, &request.host_request)?;
        let proposal = request.proposal.as_ref().ok_or(HostError::InvalidInput)?;
        let planned = PlannedRootBinding::from_queued_snapshot(
            &proposal.session,
            &proposal.run,
            &proposal.binding,
        )
        .map_err(|_| HostError::Unauthorised)?;
        let (effective, descriptor) =
            self.review_bound_root_codex_v2(&authorised, request.host_request.grant_id, proposal)?;
        let admission = self
            .store
            .admit_bound_root_launch_v2(BoundRootLaunchRequestV2 {
                principal,
                command_key: &request.host_request.command_key,
                canonical_intent: &request.canonical_request,
                scope_id: authorised.scope_id.as_str(),
                pod_id: pod_id.as_str(),
                proposal: Some(BoundRootLaunchProposalV2 {
                    session: &proposal.session,
                    run: &proposal.run,
                    binding: &planned,
                    effective_spec: &effective,
                    descriptor: &descriptor,
                    expected_owner_epoch: self.host.manager_epoch.get(),
                    expected_authority_revision: self.recorded.revision,
                }),
            })?;
        let (record, duplicate) = match admission {
            BoundLaunchAdmission::Committed(record) => (record, false),
            BoundLaunchAdmission::Duplicate(record) => (record, true),
        };
        if record.format != BoundLaunchFormat::CodexV2 {
            return Err(HostError::StaleGuard.into());
        }
        if !duplicate {
            if record.effective_spec != effective.canonical_bytes()
                || record.descriptor
                    != descriptor
                        .encode_json()
                        .map_err(|_| HostError::InvalidInput)?
            {
                return Err(HostError::StaleGuard.into());
            }
            self.hydrate_new_bound(&record)?;
        }
        self.bound_receipt(record, duplicate)
    }

    /// Authenticate a high-level caller and inspect an existing Codex V2
    /// root before allocating any new IDs. This returns the original bound
    /// record, not a current-pod or dispatch proof. A changed key payload
    /// conflicts; absence alone permits a separate reviewed planning step.
    pub fn lookup_bound_root_codex_v2_by_key<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        scope_id: &ScopeId,
        command_key: &str,
        canonical_intent: &[u8],
    ) -> Result<Option<BoundLaunchRecord>, LaunchPodError> {
        self.ensure_current_owner_epoch()?;
        self.recheck_manager_binding()?;
        let actor = self.host.authenticate(transport)?;
        if &actor.scope_id != scope_id {
            return Err(HostError::Unauthorised.into());
        }
        let principal = VerifiedPrincipal::from_authenticated_boundary(actor.actor_id.as_str())?;
        let record = self
            .store
            .lookup_bound_launch_by_key(&LaunchKeyLookupRequest {
                principal,
                command_key: command_key.to_owned(),
                scope_id: scope_id.as_str().to_owned(),
                canonical_intent: canonical_intent.to_vec(),
            })?;
        if record
            .as_ref()
            .is_some_and(|record| record.format != BoundLaunchFormat::CodexV2)
        {
            return Err(HostError::Unauthorised.into());
        }
        Ok(record)
    }

    /// Plan one new Coordinator/Service root from an authenticated `launch`
    /// envelope. The key and verified semantic digest are looked up before any
    /// IDs are minted. Only trusted host state supplies actor, profile
    /// generation, credential, manager generation, and a preinstalled grant.
    /// An explicit deadline comes from the calling manager policy; this first
    /// slice refuses a wire `deadlineAt` until wall-to-monotonic conversion is
    /// implemented. No server mutation endpoint calls this method yet.
    pub fn launch_new_root_codex_v2_from_wire<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        request: CommandEnvelope,
        policy: &TrustedWireRootLaunchPolicy,
    ) -> Result<LaunchPodReceipt, LaunchPodError>
    where
        P::Receipt: StablePortReceipt,
    {
        request.encode_json().map_err(|_| HostError::InvalidInput)?;
        let WireTarget::Scope { scope_id } = &request.target else {
            return Err(HostError::Unsupported.into());
        };
        let scope = ScopeId::try_from(scope_id.as_str()).map_err(|_| HostError::InvalidInput)?;
        let CommandBody::Launch(body) = &request.body else {
            return Err(HostError::Unsupported.into());
        };
        if !valid_token(&request.key) || !valid_token(&request.request_id) {
            return Err(HostError::InvalidInput.into());
        }
        let mut canonical_intent = b"podbay.wire-launch/1\0".to_vec();
        canonical_intent.extend_from_slice(request.payload_digest.as_bytes());
        if let Some(record) = self.lookup_bound_root_codex_v2_by_key(
            transport,
            &scope,
            &request.key,
            &canonical_intent,
        )? {
            return self.bound_receipt(record, true);
        }
        if !matches!(body.session, SessionChoice::New)
            || body.role != LaunchRole::Coordinator
            || body.work.kind != WireWorkKind::Service
            || body.parent_run_id.is_some()
            || body.work.input.is_some()
            || body.work.task_ref.is_some()
            || !body.tool_bundle_refs.is_empty()
            || body.selection.fallback != FallbackPolicy::None
            || body.workspace.access != WireWorkspaceAccess::ReadWrite
            || request.deadline_at.is_some()
        {
            return Err(HostError::Unsupported.into());
        }
        if policy.deadline <= Instant::now() {
            return Err(HostError::DeadlineExpired.into());
        }
        if body.work.result_contract_ref != policy.result_contract_ref.as_ref()
            || body.authority.grant_ref != format!("grant.{}", policy.grant_id.get())
            || body.workspace.scope_id != scope.as_str()
        {
            return Err(HostError::Unauthorised.into());
        }
        let basis_ref = body
            .workspace
            .basis_ref
            .clone()
            .ok_or(HostError::InvalidInput)?;
        let model_id = body
            .selection
            .model_id
            .clone()
            .ok_or(HostError::InvalidInput)?;
        let reasoning_effort = body
            .selection
            .reasoning_effort
            .clone()
            .ok_or(HostError::InvalidInput)?;
        let max_children =
            u32::try_from(body.limits.max_children.get()).map_err(|_| HostError::InvalidInput)?;
        let actor = self.host.authenticate(transport)?;
        if actor.scope_id != scope {
            return Err(HostError::Unauthorised.into());
        }
        let actor_id = actor.actor_id.clone();
        let generation = actor.credential_generation;
        let profile = self
            .launch_profiles
            .get(&body.profile_ref)
            .ok_or(HostError::Unsupported)?;
        if profile.workspace_scope() != &scope {
            return Err(HostError::Unauthorised.into());
        }
        let codex_policy = profile.codex_policy().ok_or(HostError::Unsupported)?;
        let credential =
            CredentialRef::from_trusted_vault(scope.clone(), codex_policy.credential_ref())?;
        let profile_generation = profile.generation();
        self.host.check_grant(
            actor,
            policy.grant_id,
            &scope,
            &Right::new(Operation::LaunchPod, Target::Scope(scope.clone())),
        )?;
        self.host.check_grant(
            actor,
            policy.grant_id,
            &scope,
            &Right::new(
                Operation::UseCredential,
                Target::Credential(credential.clone()),
            ),
        )?;
        if let Some(guard) = &request.guard {
            let matches = guard
                .manager_epoch
                .is_none_or(|epoch| epoch.get() == self.host.manager_epoch.get())
                && guard.pod_epoch.is_none_or(|epoch| epoch.get() == 1)
                && guard.resource_epoch.is_none()
                && guard.writer_epoch.is_none()
                && guard.lease_epoch.is_none()
                && guard.target_revision.is_none();
            if !matches {
                return Err(HostError::StaleGuard.into());
            }
        }

        let ids = RootLaunchIds::mint()?;
        let first_epoch = Epoch::new(1).map_err(|_| HostError::InvalidInput)?;
        let mut session = Session::new(ids.session_id, actor_id, scope.clone());
        let run = Run::new(
            ids.run_id,
            &session,
            Role::Coordinator,
            WorkKind::Service,
            None,
        );
        session
            .bind_run(session.revision(), &run)
            .map_err(|_| HostError::InvalidInput)?;
        let mut attempt = Attempt::new(ids.attempt_id, run.id().clone(), 1, first_epoch)
            .map_err(|_| HostError::InvalidInput)?;
        let mut pod = Pod::new(ids.pod_id, attempt.id().clone(), first_epoch);
        attempt
            .attach_pod(attempt.revision(), &pod)
            .map_err(|_| HostError::InvalidInput)?;
        let resource = Resource::new(
            ids.resource_id,
            pod.id().clone(),
            ResourceKind::StructuredProvider,
            first_epoch,
        );
        pod.attach_resource(pod.revision(), &resource)
            .map_err(|_| HostError::InvalidInput)?;
        let binding = LaunchBinding::plan_first_root(&session, &run, &attempt, &pod, &[resource])
            .map_err(|_| HostError::InvalidInput)?
            .identity()
            .clone();
        let planned_request = BoundLaunchPodRequest {
            host_request: HostRequest {
                scope_id: scope.clone(),
                grant_id: policy.grant_id,
                guards: GuardSet {
                    manager_epoch: self.host.manager_epoch,
                    pod_incarnation: PodIncarnation::new(1)?,
                    resource_epoch: None,
                    credential_generation: generation,
                },
                command_key: request.key,
                correlation_id: request.request_id,
                deadline: policy.deadline,
                action: HostAction::LaunchPod {
                    pod_id: pod.id().clone(),
                    role: Role::Coordinator,
                    credential: Some(credential),
                },
            },
            canonical_request: canonical_intent,
            proposal: Some(BoundHostLaunchProposal {
                session,
                run,
                binding,
                selection: LaunchSelection {
                    profile_ref: body.profile_ref.clone(),
                    profile_generation,
                    model_id: Some(model_id),
                    reasoning_effort: Some(reasoning_effort),
                    fallback_approved: false,
                    workspace: crate::launch_spec::WorkspaceSelection {
                        scope_id: scope,
                        basis_ref,
                        relative_cwd: body.workspace.relative_cwd.clone(),
                        access: crate::launch_spec::WorkspaceAccess::ReadWrite,
                    },
                    arguments: Vec::new(),
                    tool_bundle_refs: Vec::new(),
                    authority_ref: format!("grant.{}", policy.grant_id.get()),
                    wall_seconds: body.limits.wall_seconds.get(),
                    max_children,
                    parent_run_id: None,
                },
            }),
        };
        let admitted = self.admit_bound_root_codex_v2(transport, planned_request.clone())?;
        if admitted.duplicate {
            return Ok(admitted);
        }
        let admitted_receipt = admitted.receipt.clone();
        let key = planned_request.host_request.command_key.clone();
        let intent = planned_request.canonical_request.clone();
        let scope = planned_request.host_request.scope_id.clone();
        match self.dispatch_prepared_bound_root_codex_v2(transport, planned_request) {
            Ok(dispatched) => Ok(dispatched),
            Err(source) => {
                if let Ok(Some(record)) =
                    self.lookup_bound_root_codex_v2_by_key(transport, &scope, &key, &intent)
                {
                    if let Ok(current) = self.bound_receipt(record, true) {
                        return Ok(current);
                    }
                }
                Err(LaunchPodError::CommittedDispatchUnavailable {
                    receipt: admitted_receipt,
                    source: Box::new(source),
                })
            }
        }
    }

    /// Dispatches only an already committed, still-Prepared Codex V2 root.
    /// The caller's key and canonical bytes select the original record; a
    /// fresh actor/grant review and today's trusted profile must agree with
    /// the stored typed bytes before effect.
    /// A repeated or ambiguous claim returns its durable receipt without a
    /// second port call.
    pub fn dispatch_prepared_bound_root_codex_v2<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        request: BoundLaunchPodRequest,
    ) -> Result<LaunchPodReceipt, LaunchPodError>
    where
        P::Receipt: StablePortReceipt,
    {
        self.ensure_current_owner_epoch()?;
        self.recheck_manager_binding()?;
        let HostAction::LaunchPod { pod_id, .. } = &request.host_request.action else {
            return Err(LaunchPodError::WrongOperation);
        };
        let actor = self.host.authenticate(transport)?;
        if actor.scope_id != request.host_request.scope_id {
            return Err(HostError::Unauthorised.into());
        }
        let actor_id = actor.actor_id.clone();
        let principal = VerifiedPrincipal::from_authenticated_boundary(actor_id.as_str())?;
        let lookup = self.bound_lookup(&request, principal);
        let record = self
            .store
            .lookup_bound_launch(&lookup)?
            .ok_or(StoreError::NotFound)?;
        if record.format != BoundLaunchFormat::CodexV2 {
            return Err(HostError::Unauthorised.into());
        }
        let status = self.store.launch_dispatch_status(
            record.receipt.outbox_id,
            &record.scope_id,
            &record.pod_id,
        )?;
        if status.stage != podbay_store::LaunchDispatchStage::Prepared {
            return self.bound_receipt(record, true);
        }
        let authorised = self
            .host
            .authorise_proposed_launch(transport, &request.host_request)?;
        if authorised.actor_id != actor_id || authorised.scope_id != request.host_request.scope_id {
            return Err(HostError::Unauthenticated.into());
        }
        let reviewed =
            self.inspect_committed_root_codex_v2(&request.host_request.scope_id, pod_id)?;
        if reviewed.committed_record() != &record {
            return Err(HostError::StaleGuard.into());
        }
        let HostAction::LaunchPod {
            pod_id: authorised_pod,
            role,
            credential,
        } = &authorised.action
        else {
            return Err(HostError::InvalidInput.into());
        };
        let selected_credential = credential.as_ref().ok_or(HostError::Unauthorised)?;
        let effective = reviewed.effective().base();
        let policy = reviewed.effective().codex_policy();
        if authorised.actor_id.as_str() != reviewed.descriptor().actor_id()
            || authorised_pod.as_str() != reviewed.descriptor().pod_id()
            || reviewed.descriptor().role() != (*role).into()
            || request.host_request.grant_id.get() != effective.authority_grant_id()
            || selected_credential.scope_id() != &authorised.scope_id
            || selected_credential.as_str() != policy.credential_ref()
            || policy.credential_scope() != authorised.scope_id.as_str()
            || effective.credential_refs().len() != 1
            || effective.credential_refs()[0].reference() != selected_credential.as_str()
        {
            return Err(HostError::Unauthorised.into());
        }
        if let Some(proposal) = request.proposal.as_ref() {
            let (proposed_effective, proposed_descriptor) = self.review_bound_root_codex_v2(
                &authorised,
                request.host_request.grant_id,
                proposal,
            )?;
            if record.effective_spec != proposed_effective.canonical_bytes()
                || record.descriptor
                    != proposed_descriptor
                        .encode_json()
                        .map_err(|_| HostError::InvalidInput)?
            {
                return Err(HostError::StaleGuard.into());
            }
        }
        if !self.host.port.accepts_resolved_codex_v2() {
            return Err(HostError::NativeResolutionUnverified.into());
        }
        let claim_key = format!("claim.{}", record.receipt.command_id);
        let claim = self.store.claim_effect(
            record.receipt.outbox_id,
            &record.scope_id,
            &record.pod_id,
            self.host.manager_epoch.get(),
            record.pod_incarnation,
            self.recorded.revision,
            &claim_key,
        )?;
        if claim != EffectClaim::NewClaim {
            return self.bound_receipt(record, true);
        }
        let postclaim = (|| -> Result<ResolvedNativeCodexLaunch, LaunchPodError> {
            self.ensure_current_owner_epoch()?;
            if self.recheck_manager_binding()? != *reviewed.manager_peer() {
                return Err(HostError::StaleGuard.into());
            }
            let fresh =
                self.inspect_committed_root_codex_v2(&request.host_request.scope_id, pod_id)?;
            if fresh.committed_record() != &record
                || fresh.store_path() != reviewed.store_path()
                || fresh.store_lineage() != reviewed.store_lineage()
                || fresh.owner_epoch() != reviewed.owner_epoch()
                || fresh.credential_epoch() != reviewed.credential_epoch()
                || fresh.authority_revision() != reviewed.authority_revision()
                || fresh.manager_peer() != reviewed.manager_peer()
                || fresh.resource_input_epochs() != reviewed.resource_input_epochs()
                || fresh.cwd() != reviewed.cwd()
                || fresh.executable() != reviewed.executable()
                || fresh.executable_sha256() != reviewed.executable_sha256()
            {
                return Err(HostError::StaleGuard.into());
            }
            #[cfg(target_os = "linux")]
            if fresh.store_file_identity() != reviewed.store_file_identity() {
                return Err(HostError::StaleGuard.into());
            }
            Ok(fresh)
        })();
        let resolved = match postclaim {
            Ok(resolved) => resolved,
            Err(failure) => {
                return self.refuse_claimed_launch(record, true, &claim_key, failure);
            }
        };
        let port_call = self.host.port.launch_resolved_codex_v2(resolved);
        let observed = match port_call {
            Ok(PortDispatchOutcome::Accepted(receipt)) => LaunchPortResult::HostAccepted {
                receipt_ref: Some(receipt.stable_reference().to_owned()),
            },
            Ok(PortDispatchOutcome::Settled(receipt)) => LaunchPortResult::PortSettled {
                receipt_ref: Some(receipt.stable_reference().to_owned()),
            },
            Err(PortDispatchError::RefusedBeforeEffect) => LaunchPortResult::RefusedBeforeEffect,
            Err(PortDispatchError::UncertainAfterPossibleEffect { receipt_ref }) => {
                LaunchPortResult::UncertainAfterPossibleEffect {
                    receipt_ref: receipt_ref.map(|receipt| receipt.as_str().to_owned()),
                }
            }
        };
        let status = self
            .store
            .record_launch_port_result(
                record.receipt.outbox_id,
                &record.scope_id,
                &record.pod_id,
                self.host.manager_epoch.get(),
                &claim_key,
                observed.clone(),
            )
            .map_err(|source| LaunchPodError::OutcomeNotRecorded {
                receipt: record.receipt.clone(),
                observed,
                source,
            })?;
        Ok(LaunchPodReceipt {
            receipt: record.receipt,
            status,
            duplicate: true,
            port_called: true,
        })
    }

    /// Only a still-prepared original may be dispatched after restart. The
    /// committed descriptor is used at the port, and today's profile/grant
    /// must independently reauthorize its exact reviewed semantics.
    pub fn resume_prepared_bound_pod<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        request: BoundLaunchPodRequest,
    ) -> Result<LaunchPodReceipt, LaunchPodError>
    where
        P::Receipt: StablePortReceipt,
    {
        self.ensure_current_owner_epoch()?;
        if !matches!(request.host_request.action, HostAction::LaunchPod { .. }) {
            return Err(LaunchPodError::WrongOperation);
        }
        let actor = self.host.authenticate(transport)?;
        if actor.scope_id != request.host_request.scope_id {
            return Err(HostError::Unauthorised.into());
        }
        let principal = VerifiedPrincipal::from_authenticated_boundary(actor.actor_id.as_str())?;
        let lookup = self.bound_lookup(&request, principal);
        let record = self
            .store
            .lookup_bound_launch(&lookup)?
            .ok_or(StoreError::NotFound)?;
        if record.format != BoundLaunchFormat::V1 {
            return Err(HostError::Unauthorised.into());
        }
        let status = self.store.launch_dispatch_status(
            record.receipt.outbox_id,
            &record.scope_id,
            &record.pod_id,
        )?;
        if status.stage != podbay_store::LaunchDispatchStage::Prepared {
            return self.bound_receipt(record, true);
        }
        let proposal = request.proposal.as_ref().ok_or(HostError::InvalidInput)?;
        let authorised = self
            .host
            .authorise_proposed_launch(transport, &request.host_request)?;
        let (effective_bytes, descriptor) =
            self.review_bound_proposal(&authorised, request.host_request.grant_id, proposal)?;
        if effective_bytes != record.effective_spec
            || descriptor
                .encode_json()
                .map_err(|_| HostError::InvalidInput)?
                != record.descriptor
        {
            return Err(HostError::StaleGuard.into());
        }
        self.dispatch_committed_bound(authorised, record, true)
    }

    fn bound_lookup(
        &self,
        request: &BoundLaunchPodRequest,
        principal: VerifiedPrincipal,
    ) -> LaunchLookupRequest {
        let pod_id = match &request.host_request.action {
            HostAction::LaunchPod { pod_id, .. } => pod_id.as_str(),
            _ => "invalid.target",
        };
        LaunchLookupRequest {
            principal,
            namespace: "podbay.launch".into(),
            command_key: request.host_request.command_key.clone(),
            scope_id: request.host_request.scope_id.as_str().into(),
            target_id: pod_id.into(),
            canonical_intent: request.canonical_request.clone(),
        }
    }

    fn lookup_or_admit_bound<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        request: &BoundLaunchPodRequest,
    ) -> Result<(Option<AuthorisedDispatch>, BoundLaunchRecord, bool), LaunchPodError> {
        self.ensure_current_owner_epoch()?;
        let HostAction::LaunchPod { pod_id, .. } = &request.host_request.action else {
            return Err(LaunchPodError::WrongOperation);
        };
        let actor = self.host.authenticate(transport)?;
        if actor.scope_id != request.host_request.scope_id {
            return Err(HostError::Unauthorised.into());
        }
        let principal = VerifiedPrincipal::from_authenticated_boundary(actor.actor_id.as_str())?;
        let lookup = self.bound_lookup(request, principal.clone());
        if let Some(record) = self.store.lookup_bound_launch(&lookup)? {
            if record.format != BoundLaunchFormat::V1 {
                return Err(HostError::Unauthorised.into());
            }
            return Ok((None, record, true));
        }
        let authorised = self
            .host
            .authorise_proposed_launch(transport, &request.host_request)?;
        let proposal = request.proposal.as_ref().ok_or(HostError::InvalidInput)?;
        let (effective_bytes, descriptor) =
            self.review_bound_proposal(&authorised, request.host_request.grant_id, proposal)?;
        let store_request = BoundLaunchRequest {
            principal,
            command_key: &request.host_request.command_key,
            canonical_intent: &request.canonical_request,
            scope_id: authorised.scope_id.as_str(),
            pod_id: pod_id.as_str(),
            proposal: Some(BoundLaunchProposal {
                session: &proposal.session,
                run: &proposal.run,
                binding: &proposal.binding,
                effective_spec: &effective_bytes,
                descriptor: &descriptor,
                expected_owner_epoch: self.host.manager_epoch.get(),
                expected_authority_revision: self.recorded.revision,
            }),
        };
        let (record, duplicate) = match self.store.admit_bound_launch(store_request)? {
            BoundLaunchAdmission::Committed(record) => (record, false),
            BoundLaunchAdmission::Duplicate(record) => (record, true),
        };
        if !duplicate {
            if record.effective_spec != effective_bytes
                || record.descriptor
                    != descriptor
                        .encode_json()
                        .map_err(|_| HostError::InvalidInput)?
            {
                return Err(HostError::StaleGuard.into());
            }
            self.hydrate_new_bound(&record)?;
        }
        Ok((Some(authorised), record, duplicate))
    }

    fn hydrate_new_bound(&mut self, record: &BoundLaunchRecord) -> Result<(), LaunchPodError> {
        let scope_id =
            ScopeId::try_from(record.scope_id.as_str()).map_err(|_| HostError::InvalidInput)?;
        let pod_id =
            PodId::try_from(record.pod_id.as_str()).map_err(|_| HostError::InvalidInput)?;
        let pod_incarnation = PodIncarnation::new(record.pod_incarnation)?;
        self.host
            .register_pod_from_trusted_policy(PodRegistration {
                scope_id: scope_id.clone(),
                pod_id: pod_id.clone(),
                incarnation: pod_incarnation,
            })?;
        for resource in &record.resources {
            self.host
                .register_resource_from_trusted_policy(ResourceRegistration {
                    scope_id: scope_id.clone(),
                    resource_id: ResourceId::try_from(resource.id.as_str())
                        .map_err(|_| HostError::InvalidInput)?,
                    pod_id: pod_id.clone(),
                    pod_incarnation,
                    resource_epoch: ResourceEpoch::new(resource.epoch)?,
                    input_epoch: InputEpoch::new(1)?,
                })?;
        }
        self.recorded = self.store.authority_snapshot()?;
        Ok(())
    }

    fn bound_receipt(
        &self,
        record: BoundLaunchRecord,
        duplicate: bool,
    ) -> Result<LaunchPodReceipt, LaunchPodError> {
        let status = self.store.launch_dispatch_status(
            record.receipt.outbox_id,
            &record.scope_id,
            &record.pod_id,
        )?;
        Ok(LaunchPodReceipt {
            receipt: record.receipt,
            status,
            duplicate,
            port_called: false,
        })
    }

    /// The OS process and exact v10 claim must still be the ones captured
    /// under the lifetime lock. Neither is derived from the launch actor.
    fn recheck_manager_binding(&mut self) -> Result<AttestedPeer, LaunchPodError> {
        #[cfg(not(target_os = "linux"))]
        return Err(HostError::Unsupported.into());
        #[cfg(target_os = "linux")]
        {
            recheck_current_manager(
                &mut self.store,
                &self.canonical_database,
                self.database_identity,
                &self.manager_peer,
                &self.manager_claim,
            )
            .map_err(|error| match error {
                RebindContextError::Host(error) => LaunchPodError::Host(error),
                RebindContextError::Store(error) => LaunchPodError::Store(error),
            })
        }
    }

    fn current_launch_inputs(
        &mut self,
        record: &BoundLaunchRecord,
    ) -> Result<BTreeMap<String, u64>, LaunchPodError> {
        let snapshot = self.store.authority_snapshot()?;
        if snapshot.owner_epoch != self.manager_claim.owner_epoch()
            || snapshot.revision != self.recorded.revision
        {
            return Err(HostError::StaleGuard.into());
        }
        let resources = snapshot
            .resources
            .iter()
            .filter(|resource| resource.pod_id == record.pod_id)
            .collect::<Vec<_>>();
        if resources.len() != record.resources.len() {
            return Err(HostError::StaleGuard.into());
        }
        let mut inputs = BTreeMap::new();
        for resource in resources {
            if resource.scope_id != record.scope_id
                || resource.pod_incarnation != record.pod_incarnation
                || resource.input_epoch == 0
                || !record.resources.iter().any(|bound| {
                    bound.id == resource.resource_id && bound.epoch == resource.resource_epoch
                })
                || inputs
                    .insert(resource.resource_id.clone(), resource.input_epoch)
                    .is_some()
            {
                return Err(HostError::StaleGuard.into());
            }
        }
        Ok(inputs)
    }

    /// This manager knows the claimed effect never crossed the OS port.
    /// Record that refusal; if ownership/storage prevents recording, preserve
    /// the original receipt and explicitly report the unrecorded outcome.
    fn refuse_claimed_launch(
        &mut self,
        record: BoundLaunchRecord,
        duplicate: bool,
        claim_key: &str,
        _guard_failure: LaunchPodError,
    ) -> Result<LaunchPodReceipt, LaunchPodError> {
        let observed = LaunchPortResult::RefusedBeforeEffect;
        let status = self
            .store
            .record_launch_port_result(
                record.receipt.outbox_id,
                &record.scope_id,
                &record.pod_id,
                self.host.manager_epoch.get(),
                claim_key,
                observed.clone(),
            )
            .map_err(|source| LaunchPodError::OutcomeNotRecorded {
                receipt: record.receipt.clone(),
                observed,
                source,
            })?;
        Ok(LaunchPodReceipt {
            receipt: record.receipt,
            status,
            duplicate,
            port_called: false,
        })
    }

    fn dispatch_committed_bound(
        &mut self,
        authorised: AuthorisedDispatch,
        record: BoundLaunchRecord,
        duplicate: bool,
    ) -> Result<LaunchPodReceipt, LaunchPodError>
    where
        P::Receipt: StablePortReceipt,
    {
        // Validate exactly the committed bytes before moving the outbox into
        // an uncertain claim state. No current proposal reaches this port.
        let committed = AuthorisedBoundLaunch::from_committed(&authorised, record.clone())?;
        let paths = self.revalidate_committed_native(&committed)?;
        let fixture_port = self.host.port.allow_unverified_native_launch_for_fixture();
        if !fixture_port && !self.host.port.accepts_resolved_native_launch() {
            return Err(HostError::NativeResolutionUnverified.into());
        }
        let resolved_binding = if fixture_port {
            None
        } else {
            let peer = self.recheck_manager_binding()?;
            let inputs = self.current_launch_inputs(&record)?;
            Some((peer, inputs))
        };
        let claim_key = format!("claim.{}", record.receipt.command_id);
        let claim = self.store.claim_effect(
            record.receipt.outbox_id,
            &record.scope_id,
            &record.pod_id,
            self.host.manager_epoch.get(),
            record.pod_incarnation,
            self.recorded.revision,
            &claim_key,
        )?;
        if claim != EffectClaim::NewClaim {
            return self.bound_receipt(record, duplicate);
        }
        let postclaim_guard = (|| -> Result<(), LaunchPodError> {
            self.ensure_current_owner_epoch()?;
            if !fixture_port {
                let (peer, inputs) = resolved_binding
                    .as_ref()
                    .ok_or(HostError::NativeResolutionUnverified)?;
                if &self.recheck_manager_binding()? != peer
                    || &self.current_launch_inputs(&record)? != inputs
                {
                    return Err(HostError::StaleGuard.into());
                }
            }
            Ok(())
        })();
        if let Err(failure) = postclaim_guard {
            return self.refuse_claimed_launch(record, duplicate, &claim_key, failure);
        }
        let port_call = if fixture_port {
            self.host.port.launch_bound(committed)
        } else {
            let Some((manager_peer, resource_input_epochs)) = resolved_binding else {
                return self.refuse_claimed_launch(
                    record,
                    duplicate,
                    &claim_key,
                    HostError::NativeResolutionUnverified.into(),
                );
            };
            self.host.port.launch_resolved(ResolvedNativeLaunch {
                committed,
                paths,
                store_path: self.canonical_database.clone(),
                store_lineage: self.manager_claim.store_lineage().to_owned(),
                owner_epoch: self.manager_claim.owner_epoch(),
                credential_epoch: self.manager_claim.credential_epoch(),
                manager_peer,
                resource_input_epochs,
            })
        };
        let port_result = match port_call {
            Ok(PortDispatchOutcome::Accepted(receipt)) => LaunchPortResult::HostAccepted {
                receipt_ref: Some(receipt.stable_reference().to_owned()),
            },
            Ok(PortDispatchOutcome::Settled(receipt)) => LaunchPortResult::PortSettled {
                receipt_ref: Some(receipt.stable_reference().to_owned()),
            },
            Err(PortDispatchError::RefusedBeforeEffect) => LaunchPortResult::RefusedBeforeEffect,
            Err(PortDispatchError::UncertainAfterPossibleEffect { receipt_ref }) => {
                LaunchPortResult::UncertainAfterPossibleEffect {
                    receipt_ref: receipt_ref.map(|value| value.as_str().to_owned()),
                }
            }
        };
        let status = self
            .store
            .record_launch_port_result(
                record.receipt.outbox_id,
                &record.scope_id,
                &record.pod_id,
                self.host.manager_epoch.get(),
                &claim_key,
                port_result.clone(),
            )
            .map_err(|source| LaunchPodError::OutcomeNotRecorded {
                receipt: record.receipt.clone(),
                observed: port_result,
                source,
            })?;
        Ok(LaunchPodReceipt {
            receipt: record.receipt,
            status,
            duplicate,
            port_called: true,
        })
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

    fn review_bound_proposal(
        &self,
        authorised: &AuthorisedDispatch,
        grant_id: GrantId,
        proposal: &BoundHostLaunchProposal,
    ) -> Result<(Vec<u8>, ImmutableLaunchDescriptor), HostError> {
        let HostAction::LaunchPod { pod_id, role, .. } = &authorised.action else {
            return Err(HostError::InvalidInput);
        };
        if proposal.binding.scope_id() != &authorised.scope_id
            || proposal.binding.actor_id() != &authorised.actor_id
            || proposal.binding.pod_id() != pod_id
            || proposal.binding.role() != *role
        {
            return Err(HostError::Unauthorised);
        }
        let spec = self.resolve_effective_launch(authorised, grant_id, &proposal.selection)?;
        let bytes = spec.canonical_bytes()?;
        let decoded =
            EffectiveLaunchContract::decode(&bytes).map_err(|_| HostError::Unauthorised)?;
        let profile = self
            .launch_profiles
            .get(&proposal.selection.profile_ref)
            .ok_or(HostError::Unsupported)?;
        let host = self.native_host.as_ref().ok_or(HostError::Unsupported)?;
        let (native, _) =
            profile.resolve_native_policy(host, &spec, &proposal.binding, decoded.digest())?;
        let descriptor = ImmutableLaunchDescriptor::from_binding(&proposal.binding, native)
            .map_err(|_| HostError::Unauthorised)?;
        decoded
            .compare_with_descriptor(&descriptor)
            .map_err(|_| HostError::Unauthorised)?;
        Ok((bytes, descriptor))
    }

    fn review_bound_root_codex_v2(
        &self,
        authorised: &AuthorisedDispatch,
        grant_id: GrantId,
        proposal: &BoundHostLaunchProposal,
    ) -> Result<(EffectiveLaunchContractV2, ImmutableLaunchDescriptorV2), HostError> {
        let planned = PlannedRootBinding::from_queued_snapshot(
            &proposal.session,
            &proposal.run,
            &proposal.binding,
        )
        .map_err(|_| HostError::Unauthorised)?;
        let HostAction::LaunchPod {
            pod_id,
            role,
            credential,
        } = &authorised.action
        else {
            return Err(HostError::InvalidInput);
        };
        if proposal.binding.scope_id() != &authorised.scope_id
            || proposal.binding.actor_id() != &authorised.actor_id
            || proposal.binding.pod_id() != pod_id
            || proposal.binding.role() != *role
            || proposal.binding.parent_run_id().is_some()
        {
            return Err(HostError::Unauthorised);
        }
        let profile = self
            .launch_profiles
            .get(&proposal.selection.profile_ref)
            .ok_or(HostError::Unsupported)?;
        if profile.workspace_scope() != &authorised.scope_id {
            return Err(HostError::Unauthorised);
        }
        let policy = profile.codex_policy().ok_or(HostError::Unsupported)?;
        let spec = profile.resolve_codex_v2(
            pod_id.clone(),
            *role,
            grant_id.get(),
            credential.as_ref(),
            &proposal.selection,
        )?;
        let base_bytes = spec.canonical_bytes()?;
        let base =
            EffectiveLaunchContract::decode(&base_bytes).map_err(|_| HostError::Unauthorised)?;
        let effective = EffectiveLaunchContractV2::from_v1(base, policy.clone())
            .map_err(|_| HostError::Unauthorised)?;
        let host = self.native_host.as_ref().ok_or(HostError::Unsupported)?;
        let (native, _) = profile.resolve_native_policy_codex_v2(
            host,
            &spec,
            &proposal.binding,
            effective.digest(),
        )?;
        let descriptor =
            ImmutableLaunchDescriptorV2::from_planned_root(&planned, native, policy.clone())
                .map_err(|_| HostError::Unauthorised)?;
        effective
            .compare_with_descriptor(&descriptor)
            .map_err(|_| HostError::Unauthorised)?;
        Ok((effective, descriptor))
    }

    fn revalidate_committed_native(
        &self,
        committed: &AuthorisedBoundLaunch,
    ) -> Result<ResolvedNativePaths, HostError> {
        let host = self.native_host.as_ref().ok_or(HostError::Unsupported)?;
        let profile = self
            .launch_profiles
            .get(committed.effective().profile_ref())
            .ok_or(HostError::Unsupported)?;
        profile.revalidate_committed_native(host, committed.effective(), committed.descriptor())
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

#[cfg(target_os = "linux")]
fn actor_record_matches_process(
    record: &AuthorityActorRecord,
    process: &AuthenticatedProcessSubject,
) -> bool {
    let platform = match process.platform {
        HostPlatform::Linux => "linux",
        HostPlatform::MacOs => "macos",
        HostPlatform::Windows => "windows",
    };
    record.platform == platform
        && record.os_identity == process.os_identity.as_ref()
        && record.process_identity == process.process_identity.as_ref()
        && record.start_identity == process.start_identity
        && record.containment_identity == process.containment_identity.as_ref()
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
                    Target::Scope(id) => ("scope", id.as_str()),
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
                ));
            }
        };
        let target = match right.target_kind.as_str() {
            "scope" => Target::Scope(
                ScopeId::try_from(right.target_id.as_str())
                    .map_err(|_| DurableAuthorityError::Corrupt("invalid durable scope target"))?,
            ),
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
                ));
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

#[cfg(all(test, target_os = "linux"))]
mod postclaim_refusal_tests {
    use super::*;
    use crate::launch_spec::{
        ExecutionMode, TrustedDriverTemplate, TrustedLaunchProfileInput, WorkspaceAccess,
        WorkspaceSelection,
    };
    use podbay_core::{
        Attempt, AttemptId, CommandAdmission, CommandId, Epoch, Pod, Resource, ResourceKind,
        RunCommandKind, RunId, SessionId, WorkKind,
    };
    use podbay_store::LaunchDispatchStage;
    use podbay_wire::{ResourceDriver, ReviewedNativePolicy, ReviewedResource, TargetOs};
    use std::sync::atomic::{AtomicU64, Ordering};

    struct NoPortCalls(usize);
    impl HostDispatchPort for NoPortCalls {
        type Receipt = PortReceiptRef;
        fn launch_bound(
            &mut self,
            _: AuthorisedBoundLaunch,
        ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
            self.0 += 1;
            panic!("refusal must not invoke an OS port")
        }
        fn dispatch(
            &mut self,
            _: AuthorisedDispatch,
        ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
            self.0 += 1;
            panic!("refusal must not invoke an OS port")
        }
        fn launch_resolved(
            &mut self,
            _: ResolvedNativeLaunch,
        ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
            self.0 += 1;
            panic!("refusal must not invoke an OS port")
        }
    }
    struct Admitted;
    impl CommandAdmission for Admitted {
        fn admits_run(&self, _: &CommandId, _: &RunId, kind: RunCommandKind) -> bool {
            kind == RunCommandKind::Launch
        }
    }
    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn claimed() -> (
        Fixture,
        DurableAuthority<NoPortCalls>,
        BoundLaunchRecord,
        String,
    ) {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "podbay-postclaim-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let mut host =
            DurableAuthority::open(directory.join("store.sqlite"), NoPortCalls(0)).unwrap();
        let scope = ScopeId::try_from("scope.postclaim").unwrap();
        let actor = ActorId::try_from("actor.postclaim").unwrap();
        let mut session = Session::new(
            SessionId::try_from("session.postclaim").unwrap(),
            actor.clone(),
            scope.clone(),
        );
        let mut run = Run::new(
            RunId::try_from("run.postclaim").unwrap(),
            &session,
            Role::Worker,
            WorkKind::Task,
            None,
        );
        run.admit(
            run.revision(),
            &CommandId::try_from("command.postclaim").unwrap(),
            &Admitted,
        )
        .unwrap();
        session.bind_run(session.revision(), &run).unwrap();
        let mut attempt = Attempt::new(
            AttemptId::try_from("attempt.postclaim").unwrap(),
            run.id().clone(),
            1,
            Epoch::new(1).unwrap(),
        )
        .unwrap();
        run.start_attempt(run.revision(), &attempt).unwrap();
        let mut pod = Pod::new(
            PodId::try_from("pod.postclaim").unwrap(),
            attempt.id().clone(),
            Epoch::new(1).unwrap(),
        );
        attempt.attach_pod(attempt.revision(), &pod).unwrap();
        let resource = Resource::new(
            ResourceId::try_from("resource.postclaim").unwrap(),
            pod.id().clone(),
            ResourceKind::Auxiliary,
            Epoch::new(1).unwrap(),
        );
        pod.attach_resource(pod.revision(), &resource).unwrap();
        let binding =
            LaunchBinding::from_aggregates(&session, &run, &attempt, &pod, &[resource]).unwrap();
        let driver = ResourceDriver::Auxiliary {
            driver_ref: "process.exec".into(),
        };
        let generation = format!("sha256:{}", "0".repeat(64));
        let profile = RegisteredLaunchProfile::from_trusted_policy(TrustedLaunchProfileInput {
            profile_ref: "profile.postclaim".into(),
            profile_generation: 1,
            executable: "/bin/true".into(),
            binary_generation: generation.clone(),
            executable_sha256: "0".repeat(64),
            workspace_root: directory.clone(),
            resource_layout: vec![TrustedDriverTemplate {
                kind: ResourceKind::Auxiliary,
                driver: driver.clone(),
            }],
            execution_mode: ExecutionMode::LinuxCooperative,
            fixed_arguments: vec![],
            permitted_extra_arguments: BTreeSet::new(),
            default_model: "none".into(),
            allowed_models: BTreeSet::from(["none".into()]),
            default_effort: "none".into(),
            allowed_efforts: BTreeSet::from(["none".into()]),
            workspace_scope: scope.clone(),
            workspace_basis_ref: "basis.postclaim".into(),
            allowed_cwd_prefix: ".".into(),
            allow_write: true,
            allowed_tool_bundle_refs: BTreeSet::new(),
            environment_refs: vec![],
            credential_refs: vec![],
            max_wall_seconds: 60,
            max_children: 0,
            allow_fallback: false,
        })
        .unwrap();
        let spec = profile
            .resolve(
                pod.id().clone(),
                Role::Worker,
                1,
                None,
                &LaunchSelection {
                    profile_ref: "profile.postclaim".into(),
                    profile_generation: 1,
                    model_id: None,
                    reasoning_effort: None,
                    fallback_approved: false,
                    workspace: WorkspaceSelection {
                        scope_id: scope.clone(),
                        basis_ref: "basis.postclaim".into(),
                        relative_cwd: ".".into(),
                        access: WorkspaceAccess::ReadWrite,
                    },
                    arguments: vec![],
                    tool_bundle_refs: vec![],
                    authority_ref: "grant.1".into(),
                    wall_seconds: 60,
                    max_children: 0,
                    parent_run_id: None,
                },
            )
            .unwrap()
            .canonical_bytes()
            .unwrap();
        let digest = EffectiveLaunchContract::decode(&spec)
            .unwrap()
            .digest()
            .to_owned();
        let descriptor = ImmutableLaunchDescriptor::from_binding(
            &binding,
            ReviewedNativePolicy {
                target_os: TargetOs::Linux,
                host_id: "host.postclaim".into(),
                profile_ref: "profile.postclaim".into(),
                profile_generation: 1,
                model_id: "none".into(),
                reasoning_effort: "none".into(),
                executable_generation: generation,
                effective_spec_digest: digest,
                workspace_basis_ref: "basis.postclaim".into(),
                executable: "/bin/true".into(),
                cwd: directory.to_string_lossy().into_owned(),
                arguments: vec![],
                environment_refs: vec![],
                credential_refs: vec![],
                wall_seconds: 60,
                max_children: 0,
                resources: vec![ReviewedResource {
                    resource_id: binding.resources()[0].id().clone(),
                    kind: ResourceKind::Auxiliary,
                    epoch: Epoch::new(1).unwrap(),
                    driver,
                }],
            },
        )
        .unwrap();
        let admission = host
            .store
            .admit_bound_launch(BoundLaunchRequest {
                principal: VerifiedPrincipal::from_authenticated_boundary(actor.as_str()).unwrap(),
                command_key: "command.postclaim",
                canonical_intent: b"postclaim fixture",
                scope_id: scope.as_str(),
                pod_id: pod.id().as_str(),
                proposal: Some(BoundLaunchProposal {
                    session: &session,
                    run: &run,
                    binding: &binding,
                    effective_spec: &spec,
                    descriptor: &descriptor,
                    expected_owner_epoch: 1,
                    expected_authority_revision: host.recorded.revision,
                }),
            })
            .unwrap();
        let BoundLaunchAdmission::Committed(record) = admission else {
            panic!("new fixture");
        };
        host.recorded = host.store.authority_snapshot().unwrap();
        let key = format!("claim.{}", record.receipt.command_id);
        assert_eq!(
            host.store
                .claim_effect(
                    record.receipt.outbox_id,
                    &record.scope_id,
                    &record.pod_id,
                    1,
                    record.pod_incarnation,
                    host.recorded.revision,
                    &key
                )
                .unwrap(),
            EffectClaim::NewClaim
        );
        (Fixture(directory), host, record, key)
    }

    #[test]
    fn postclaim_resource_drift_records_refusal_without_port_call() {
        let (_fixture, mut host, record, key) = claimed();
        let mut resource = host.recorded.resources[0].clone();
        resource.input_epoch += 1;
        host.store
            .apply_authority_mutation(
                1,
                host.recorded.revision,
                AuthorityMutation::PutResource(resource),
            )
            .unwrap();
        let failure = host.current_launch_inputs(&record).unwrap_err();
        let receipt = record.receipt.clone();
        let result = host
            .refuse_claimed_launch(record.clone(), false, &key, failure)
            .unwrap();
        assert!(!result.port_called);
        assert_eq!(result.receipt, receipt);
        assert_eq!(
            result.status.stage,
            LaunchDispatchStage::RefusedBeforeEffect
        );
        assert_eq!(
            host.store
                .launch_dispatch_status(receipt.outbox_id, &record.scope_id, &record.pod_id)
                .unwrap()
                .stage,
            LaunchDispatchStage::RefusedBeforeEffect
        );
        assert_eq!(host.host.port.0, 0);
    }

    #[test]
    fn postclaim_owner_drift_returns_receipt_with_unrecorded_refusal() {
        let (_fixture, mut host, record, key) = claimed();
        host.store.begin_authority_replay(1, 2).unwrap();
        let failure = host.recheck_manager_binding().unwrap_err();
        let receipt = record.receipt.clone();
        let error = host
            .refuse_claimed_launch(record.clone(), false, &key, failure)
            .unwrap_err();
        match error {
            LaunchPodError::OutcomeNotRecorded {
                receipt: actual,
                observed: LaunchPortResult::RefusedBeforeEffect,
                source: StoreError::StaleEpoch,
            } => {
                assert_eq!(actual, receipt);
            }
            other => panic!("wrong postclaim result: {other:?}"),
        }
        assert_eq!(
            host.store
                .launch_dispatch_status(receipt.outbox_id, &record.scope_id, &record.pod_id)
                .unwrap()
                .stage,
            LaunchDispatchStage::ClaimedUncertain
        );
        assert_eq!(host.host.port.0, 0);
    }
}
