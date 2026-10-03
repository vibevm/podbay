//! Portable pod-side control fence. Ports attest peers and owner epochs; core
//! only compares their evidence and refuses unproven transitions before effect.
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::{
    AttemptId, CommandKey, CredentialEpoch, Epoch, InputEpoch, OwnerEpoch, PeerGrantId, PodId,
    ResourceId, ScopeId, StoreLineageId,
};

const MAX_MANAGER_LEASE_MS: u64 = 30_000;
const MAX_GRANT_LEASE_MS: u64 = 60_000;
const MAX_INPUT_LEASE_MS: u64 = 30_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FenceError {
    InvalidEvidence,
    WrongAssociation,
    WrongPeer,
    WrongContainment,
    StaleEpoch,
    OwnerUnverified,
    LeaseExpired,
    LeaseHeld,
    GrantDenied,
    PendingRebind,
    NotAdmitted,
    IdempotencyConflict,
    CounterOverflow,
}

impl Display for FenceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidEvidence => "peer or timing evidence is invalid",
            Self::WrongAssociation => "pod fence identity or target differs",
            Self::WrongPeer => "attested peer process birth differs",
            Self::WrongContainment => "peer is outside pinned manager containment",
            Self::StaleEpoch => "owner, credential, or input epoch is stale",
            Self::OwnerUnverified => "current owner epoch is unavailable or mismatched",
            Self::LeaseExpired => "manager, grant, or input lease expired",
            Self::LeaseHeld => "an input lease is already held",
            Self::GrantDenied => "peer grant does not authorize this operation",
            Self::PendingRebind => "pod control is held during manager rebind",
            Self::NotAdmitted => "trusted rebind ledger did not prove this transition",
            Self::IdempotencyConflict => "rebind command key was reused with different content",
            Self::CounterOverflow => "peer fence epoch exhausted",
        })
    }
}
impl Error for FenceError {}

fn checked_next<T>(
    value: T,
    next: T,
    step: impl FnOnce(T) -> Result<T, crate::IdError>,
) -> Result<(), FenceError>
where
    T: Copy + Eq,
{
    if step(value).map_err(|_| FenceError::CounterOverflow)? == next {
        Ok(())
    } else {
        Err(FenceError::StaleEpoch)
    }
}

fn valid_piece(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

/// Evidence produced by an OS transport port. Construction here validates
/// shape only; it does not turn caller-supplied strings into OS attestation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestedPeer {
    os_identity: Box<str>,
    native_process_id: Box<str>,
    boot_identity: Box<str>,
    birth_identity: Box<str>,
    containment_identity: Box<str>,
}

impl AttestedPeer {
    pub fn from_port(
        os_identity: &str,
        native_process_id: &str,
        boot_identity: &str,
        birth_identity: &str,
        containment_identity: &str,
    ) -> Result<Self, FenceError> {
        if ![
            os_identity,
            native_process_id,
            boot_identity,
            birth_identity,
        ]
        .iter()
        .all(|value| valid_piece(value, 256))
            || !valid_piece(containment_identity, 4096)
        {
            return Err(FenceError::InvalidEvidence);
        }
        Ok(Self {
            os_identity: os_identity.into(),
            native_process_id: native_process_id.into(),
            boot_identity: boot_identity.into(),
            birth_identity: birth_identity.into(),
            containment_identity: containment_identity.into(),
        })
    }

    pub fn os_identity(&self) -> &str {
        &self.os_identity
    }
    pub fn native_process_id(&self) -> &str {
        &self.native_process_id
    }
    pub fn boot_identity(&self) -> &str {
        &self.boot_identity
    }
    pub fn birth_identity(&self) -> &str {
        &self.birth_identity
    }
    pub fn containment_identity(&self) -> &str {
        &self.containment_identity
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodFenceIdentity {
    pub scope_id: ScopeId,
    pub pod_id: PodId,
    pub attempt_id: AttemptId,
    pub incarnation: Epoch,
    pub store_lineage: StoreLineageId,
}

/// The trusted store lookup must bind lineage and scope, and return the
/// committed owner epoch. `None` holds controls rather than assuming freshness.
pub trait OwnerEpochWitness {
    fn current_owner_epoch(&self, lineage: &StoreLineageId, scope: &ScopeId) -> Option<OwnerEpoch>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestDigest(Box<str>);

impl RequestDigest {
    pub fn parse(value: &str) -> Result<Self, FenceError> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(FenceError::InvalidEvidence);
        }
        Ok(Self(value.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebindProposal {
    pub identity: PodFenceIdentity,
    pub expected_owner_epoch: OwnerEpoch,
    pub next_owner_epoch: OwnerEpoch,
    pub expected_credential_epoch: CredentialEpoch,
    pub next_credential_epoch: CredentialEpoch,
    pub expected_input_epochs: BTreeMap<ResourceId, InputEpoch>,
    pub next_input_epochs: BTreeMap<ResourceId, InputEpoch>,
    pub next_manager: AttestedPeer,
    pub command_key: CommandKey,
    pub digest: RequestDigest,
}

/// Implemented only by the trusted durable rebind ledger. A Boolean from a
/// request body is not an admission or activation proof.
pub trait RebindLedger {
    fn pending(&self, proposal: &RebindProposal) -> bool;
    fn activated(&self, proposal: &RebindProposal) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagerLiveness {
    Alive,
    DeadAttested,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebindPhase {
    Active,
    PendingStore,
    PendingPod,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantKind {
    Viewer,
    Controller,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum FenceTarget {
    Pod,
    Resource(ResourceId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum FenceOperation {
    ObservePod,
    ObserveResource,
    AcquireInput,
    TakeoverInput,
    WriteInput,
    ResizeResource,
    InterruptResource,
    StopPod,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerGrant {
    id: PeerGrantId,
    peer: AttestedPeer,
    kind: GrantKind,
    target: FenceTarget,
    operations: BTreeSet<FenceOperation>,
    owner_epoch: OwnerEpoch,
    credential_epoch: CredentialEpoch,
    expires_at_ms: u64,
}

impl PeerGrant {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: PeerGrantId,
        peer: AttestedPeer,
        kind: GrantKind,
        target: FenceTarget,
        operations: BTreeSet<FenceOperation>,
        owner_epoch: OwnerEpoch,
        credential_epoch: CredentialEpoch,
        expires_at_ms: u64,
    ) -> Result<Self, FenceError> {
        if operations.is_empty() || expires_at_ms == 0 {
            return Err(FenceError::InvalidEvidence);
        }
        if kind == GrantKind::Viewer
            && (target == FenceTarget::Pod
                || operations != BTreeSet::from([FenceOperation::ObserveResource]))
        {
            return Err(FenceError::GrantDenied);
        }
        if operations
            .iter()
            .any(|operation| match (&target, operation) {
                (FenceTarget::Pod, FenceOperation::ObservePod | FenceOperation::StopPod) => false,
                (
                    FenceTarget::Resource(_),
                    FenceOperation::ObserveResource
                    | FenceOperation::AcquireInput
                    | FenceOperation::TakeoverInput
                    | FenceOperation::WriteInput
                    | FenceOperation::ResizeResource
                    | FenceOperation::InterruptResource,
                ) => false,
                _ => true,
            })
        {
            return Err(FenceError::GrantDenied);
        }
        Ok(Self {
            id,
            peer,
            kind,
            target,
            operations,
            owner_epoch,
            credential_epoch,
            expires_at_ms,
        })
    }
    pub fn id(&self) -> &PeerGrantId {
        &self.id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerRequest {
    pub identity: PodFenceIdentity,
    pub grant_id: PeerGrantId,
    pub owner_epoch: OwnerEpoch,
    pub credential_epoch: CredentialEpoch,
    pub target: FenceTarget,
    pub operation: FenceOperation,
    pub input_epoch: Option<InputEpoch>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManagerBinding {
    peer: AttestedPeer,
    owner_epoch: OwnerEpoch,
    credential_epoch: CredentialEpoch,
    lease_until_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InputLease {
    grant_id: PeerGrantId,
    peer: AttestedPeer,
    resource_id: ResourceId,
    epoch: InputEpoch,
    expires_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResourceInputState {
    epoch: InputEpoch,
    lease: Option<InputLease>,
}

pub const POD_FENCE_CHECKPOINT_VERSION: u16 = 1;

/// Portable durable state only. A checkpoint never carries live grants,
/// resource input leases, or a manager lease across pod process recovery.
/// Native peer attestation and a fresh store witness are still required.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodFenceCheckpoint {
    version: u16,
    identity: PodFenceIdentity,
    manager_containment: Box<str>,
    manager_peer: AttestedPeer,
    owner_epoch: OwnerEpoch,
    credential_epoch: CredentialEpoch,
    input_epochs: BTreeMap<ResourceId, InputEpoch>,
    phase: RebindPhase,
    pending_rebind: Option<RebindProposal>,
    last_rebind: Option<RebindProposal>,
}

impl PodFenceCheckpoint {
    pub fn version(&self) -> u16 {
        self.version
    }
    pub fn identity(&self) -> &PodFenceIdentity {
        &self.identity
    }
    pub fn manager_containment(&self) -> &str {
        &self.manager_containment
    }
    pub fn manager_peer(&self) -> &AttestedPeer {
        &self.manager_peer
    }
    pub fn owner_epoch(&self) -> OwnerEpoch {
        self.owner_epoch
    }
    pub fn credential_epoch(&self) -> CredentialEpoch {
        self.credential_epoch
    }
    pub fn input_epochs(&self) -> &BTreeMap<ResourceId, InputEpoch> {
        &self.input_epochs
    }
    pub fn phase(&self) -> RebindPhase {
        self.phase
    }
    pub fn pending_rebind(&self) -> Option<&RebindProposal> {
        self.pending_rebind.as_ref()
    }
    pub fn last_rebind(&self) -> Option<&RebindProposal> {
        self.last_rebind.as_ref()
    }

    fn validate(&self) -> Result<(), FenceError> {
        if self.version != POD_FENCE_CHECKPOINT_VERSION
            || self.input_epochs.is_empty()
            || self.manager_containment.as_ref() != self.manager_peer.containment_identity()
        {
            return Err(FenceError::InvalidEvidence);
        }
        let validate_proposal = |proposal: &RebindProposal,
                                 exact_inputs: bool|
         -> Result<(), FenceError> {
            if proposal.identity != self.identity
                || proposal.next_manager.containment_identity() != self.manager_containment.as_ref()
                || proposal.expected_owner_epoch.checked_next().ok()
                    != Some(proposal.next_owner_epoch)
                || proposal.expected_credential_epoch.checked_next().ok()
                    != Some(proposal.next_credential_epoch)
                || proposal.expected_input_epochs.len() != self.input_epochs.len()
                || proposal.next_input_epochs.len() != self.input_epochs.len()
            {
                return Err(FenceError::WrongAssociation);
            }
            for (id, next) in &proposal.next_input_epochs {
                let old = proposal
                    .expected_input_epochs
                    .get(id)
                    .ok_or(FenceError::WrongAssociation)?;
                let current = self
                    .input_epochs
                    .get(id)
                    .ok_or(FenceError::WrongAssociation)?;
                if old.checked_next().ok() != Some(*next)
                    || (exact_inputs && current != next)
                    || (!exact_inputs && current < next)
                {
                    return Err(FenceError::StaleEpoch);
                }
            }
            Ok(())
        };
        match self.phase {
            RebindPhase::Active => {
                if self.pending_rebind.is_some() {
                    return Err(FenceError::InvalidEvidence);
                }
                if let Some(last) = &self.last_rebind {
                    // Active input epochs may have advanced through legitimate
                    // later human takeover; they cannot move behind rebind.
                    validate_proposal(last, false)?;
                    if self.manager_peer != last.next_manager
                        || self.owner_epoch != last.next_owner_epoch
                        || self.credential_epoch != last.next_credential_epoch
                    {
                        return Err(FenceError::StaleEpoch);
                    }
                }
            }
            RebindPhase::PendingStore | RebindPhase::PendingPod => {
                let pending = self
                    .pending_rebind
                    .as_ref()
                    .ok_or(FenceError::InvalidEvidence)?;
                if self.last_rebind.as_ref() != Some(pending) {
                    return Err(FenceError::IdempotencyConflict);
                }
                validate_proposal(pending, true)?;
                if self.manager_peer == pending.next_manager
                    || self.owner_epoch != pending.expected_owner_epoch
                    || self.credential_epoch != pending.expected_credential_epoch
                {
                    return Err(FenceError::StaleEpoch);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodPeerFence {
    identity: PodFenceIdentity,
    manager_containment: Box<str>,
    manager: ManagerBinding,
    resources: BTreeMap<ResourceId, ResourceInputState>,
    grants: BTreeMap<PeerGrantId, PeerGrant>,
    phase: RebindPhase,
    pending: Option<RebindProposal>,
    last_rebind: Option<RebindProposal>,
}

impl PodPeerFence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: PodFenceIdentity,
        manager_peer: AttestedPeer,
        owner_epoch: OwnerEpoch,
        credential_epoch: CredentialEpoch,
        input_epochs: BTreeMap<ResourceId, InputEpoch>,
        now_ms: u64,
        lease_until_ms: u64,
    ) -> Result<Self, FenceError> {
        short_lease(now_ms, lease_until_ms, MAX_MANAGER_LEASE_MS)?;
        if input_epochs.is_empty() {
            return Err(FenceError::InvalidEvidence);
        }
        let resources = input_epochs
            .into_iter()
            .map(|(id, epoch)| (id, ResourceInputState { epoch, lease: None }))
            .collect();
        Ok(Self {
            identity,
            manager_containment: manager_peer.containment_identity.clone(),
            manager: ManagerBinding {
                peer: manager_peer,
                owner_epoch,
                credential_epoch,
                lease_until_ms,
            },
            resources,
            grants: BTreeMap::new(),
            phase: RebindPhase::Active,
            pending: None,
            last_rebind: None,
        })
    }

    pub fn identity(&self) -> &PodFenceIdentity {
        &self.identity
    }
    pub fn phase(&self) -> RebindPhase {
        self.phase
    }
    pub fn owner_epoch(&self) -> OwnerEpoch {
        self.manager.owner_epoch
    }
    pub fn credential_epoch(&self) -> CredentialEpoch {
        self.manager.credential_epoch
    }
    pub fn input_epoch(&self, resource_id: &ResourceId) -> Option<InputEpoch> {
        self.resources.get(resource_id).map(|state| state.epoch)
    }

    pub fn checkpoint(&self) -> PodFenceCheckpoint {
        PodFenceCheckpoint {
            version: POD_FENCE_CHECKPOINT_VERSION,
            identity: self.identity.clone(),
            manager_containment: self.manager_containment.clone(),
            manager_peer: self.manager.peer.clone(),
            owner_epoch: self.manager.owner_epoch,
            credential_epoch: self.manager.credential_epoch,
            input_epochs: self
                .resources
                .iter()
                .map(|(id, state)| (id.clone(), state.epoch))
                .collect(),
            phase: self.phase,
            pending_rebind: self.pending.clone(),
            last_rebind: self.last_rebind.clone(),
        }
    }

    /// Restores only monotonic durable associations. All controls stay held
    /// until a fresh owner witness, peer attestation, grant and lease renewal.
    pub fn restore_after_crash(checkpoint: PodFenceCheckpoint) -> Result<Self, FenceError> {
        checkpoint.validate()?;
        Ok(Self {
            identity: checkpoint.identity,
            manager_containment: checkpoint.manager_containment,
            manager: ManagerBinding {
                peer: checkpoint.manager_peer,
                owner_epoch: checkpoint.owner_epoch,
                credential_epoch: checkpoint.credential_epoch,
                lease_until_ms: 0,
            },
            resources: checkpoint
                .input_epochs
                .into_iter()
                .map(|(id, epoch)| (id, ResourceInputState { epoch, lease: None }))
                .collect(),
            grants: BTreeMap::new(),
            phase: checkpoint.phase,
            pending: checkpoint.pending_rebind,
            last_rebind: checkpoint.last_rebind,
        })
    }

    /// A cold pod reopen keeps the monotonic fence and pending proposal, but
    /// does not resurrect an old wall-clock/monotonic lease or active grant.
    pub fn recover_after_crash(&mut self) {
        self.manager.lease_until_ms = 0;
        for resource in self.resources.values_mut() {
            resource.lease = None;
        }
        self.grants.clear();
    }

    pub fn renew_manager_lease(
        &mut self,
        peer: &AttestedPeer,
        witness: &impl OwnerEpochWitness,
        now_ms: u64,
        lease_until_ms: u64,
    ) -> Result<(), FenceError> {
        self.require_active(peer, witness, now_ms, false)?;
        short_lease(now_ms, lease_until_ms, MAX_MANAGER_LEASE_MS)?;
        self.manager.lease_until_ms = lease_until_ms;
        Ok(())
    }

    pub fn install_grant(
        &mut self,
        issuer: &AttestedPeer,
        grant: PeerGrant,
        witness: &impl OwnerEpochWitness,
        now_ms: u64,
    ) -> Result<(), FenceError> {
        self.require_active(issuer, witness, now_ms, true)?;
        short_lease(now_ms, grant.expires_at_ms, MAX_GRANT_LEASE_MS)?;
        if grant.owner_epoch != self.manager.owner_epoch
            || grant.credential_epoch != self.manager.credential_epoch
        {
            return Err(FenceError::StaleEpoch);
        }
        if let FenceTarget::Resource(id) = &grant.target
            && !self.resources.contains_key(id)
        {
            return Err(FenceError::WrongAssociation);
        }
        if self.grants.contains_key(&grant.id) {
            return Err(FenceError::IdempotencyConflict);
        }
        self.grants.insert(grant.id.clone(), grant);
        Ok(())
    }

    /// Evaluate immediately before effect, using fresh OS peer evidence and a
    /// fresh committed owner-epoch witness. No bearer-only fallback exists.
    pub fn authorize(
        &self,
        peer: &AttestedPeer,
        request: &PeerRequest,
        witness: &impl OwnerEpochWitness,
        now_ms: u64,
    ) -> Result<(), FenceError> {
        if request.identity != self.identity {
            return Err(FenceError::WrongAssociation);
        }
        self.require_phase_and_owner(witness)?;
        if now_ms == 0 || now_ms >= self.manager.lease_until_ms {
            return Err(FenceError::LeaseExpired);
        }
        if request.owner_epoch != self.manager.owner_epoch
            || request.credential_epoch != self.manager.credential_epoch
        {
            return Err(FenceError::StaleEpoch);
        }
        let grant = self
            .grants
            .get(&request.grant_id)
            .ok_or(FenceError::GrantDenied)?;
        if grant.peer != *peer {
            return Err(FenceError::WrongPeer);
        }
        if grant.owner_epoch != self.manager.owner_epoch
            || grant.credential_epoch != self.manager.credential_epoch
        {
            return Err(FenceError::StaleEpoch);
        }
        if now_ms >= grant.expires_at_ms {
            return Err(FenceError::LeaseExpired);
        }
        if grant.target != request.target || !grant.operations.contains(&request.operation) {
            return Err(FenceError::GrantDenied);
        }
        if grant.kind == GrantKind::Viewer && request.operation != FenceOperation::ObserveResource {
            return Err(FenceError::GrantDenied);
        }
        match request.operation {
            FenceOperation::WriteInput | FenceOperation::ResizeResource => {
                let FenceTarget::Resource(resource_id) = &request.target else {
                    return Err(FenceError::WrongAssociation);
                };
                let resource = self
                    .resources
                    .get(resource_id)
                    .ok_or(FenceError::WrongAssociation)?;
                let lease = resource.lease.as_ref().ok_or(FenceError::LeaseExpired)?;
                if lease.grant_id != request.grant_id
                    || lease.peer != *peer
                    || lease.resource_id != *resource_id
                    || lease.epoch != resource.epoch
                    || request.input_epoch != Some(resource.epoch)
                {
                    return Err(FenceError::StaleEpoch);
                }
                if now_ms >= lease.expires_at_ms {
                    return Err(FenceError::LeaseExpired);
                }
            }
            FenceOperation::AcquireInput | FenceOperation::TakeoverInput => {
                let FenceTarget::Resource(resource_id) = &request.target else {
                    return Err(FenceError::WrongAssociation);
                };
                let resource = self
                    .resources
                    .get(resource_id)
                    .ok_or(FenceError::WrongAssociation)?;
                if request.input_epoch != Some(resource.epoch) {
                    return Err(FenceError::StaleEpoch);
                }
            }
            _ if request.input_epoch.is_some() => return Err(FenceError::StaleEpoch),
            _ => {}
        }
        Ok(())
    }

    pub fn acquire_input_lease(
        &mut self,
        peer: &AttestedPeer,
        grant_id: &PeerGrantId,
        resource_id: &ResourceId,
        expected: InputEpoch,
        witness: &impl OwnerEpochWitness,
        now_ms: u64,
        lease_until_ms: u64,
    ) -> Result<InputEpoch, FenceError> {
        self.set_input_lease(
            peer,
            grant_id,
            resource_id,
            expected,
            witness,
            now_ms,
            lease_until_ms,
            FenceOperation::AcquireInput,
        )
    }

    /// A separately granted takeover advances only this resource's input
    /// epoch. Other resource leases remain live and independently fenced.
    #[allow(clippy::too_many_arguments)]
    pub fn takeover_input_lease(
        &mut self,
        peer: &AttestedPeer,
        grant_id: &PeerGrantId,
        resource_id: &ResourceId,
        expected: InputEpoch,
        witness: &impl OwnerEpochWitness,
        now_ms: u64,
        lease_until_ms: u64,
    ) -> Result<InputEpoch, FenceError> {
        self.set_input_lease(
            peer,
            grant_id,
            resource_id,
            expected,
            witness,
            now_ms,
            lease_until_ms,
            FenceOperation::TakeoverInput,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn set_input_lease(
        &mut self,
        peer: &AttestedPeer,
        grant_id: &PeerGrantId,
        resource_id: &ResourceId,
        expected: InputEpoch,
        witness: &impl OwnerEpochWitness,
        now_ms: u64,
        lease_until_ms: u64,
        operation: FenceOperation,
    ) -> Result<InputEpoch, FenceError> {
        short_lease(now_ms, lease_until_ms, MAX_INPUT_LEASE_MS)?;
        let request = PeerRequest {
            identity: self.identity.clone(),
            grant_id: grant_id.clone(),
            owner_epoch: self.manager.owner_epoch,
            credential_epoch: self.manager.credential_epoch,
            target: FenceTarget::Resource(resource_id.clone()),
            operation,
            input_epoch: Some(expected),
        };
        self.authorize(peer, &request, witness, now_ms)?;
        let resource = self
            .resources
            .get_mut(resource_id)
            .ok_or(FenceError::WrongAssociation)?;
        if operation == FenceOperation::AcquireInput
            && resource
                .lease
                .as_ref()
                .is_some_and(|lease| now_ms < lease.expires_at_ms)
        {
            return Err(FenceError::LeaseHeld);
        }
        let next = resource
            .epoch
            .checked_next()
            .map_err(|_| FenceError::CounterOverflow)?;
        resource.epoch = next;
        resource.lease = Some(InputLease {
            grant_id: grant_id.clone(),
            peer: peer.clone(),
            resource_id: resource_id.clone(),
            epoch: next,
            expires_at_ms: lease_until_ms,
        });
        Ok(next)
    }

    pub fn prepare_rebind(
        &mut self,
        proposal: RebindProposal,
        new_peer: &AttestedPeer,
        old_liveness: ManagerLiveness,
        witness: &impl OwnerEpochWitness,
        ledger: &impl RebindLedger,
        now_ms: u64,
    ) -> Result<RebindPhase, FenceError> {
        if now_ms == 0 {
            return Err(FenceError::InvalidEvidence);
        }
        if proposal.identity != self.identity {
            return Err(FenceError::WrongAssociation);
        }
        self.require_owner(witness, proposal.next_owner_epoch)?;
        if proposal.next_manager != *new_peer {
            return Err(FenceError::WrongPeer);
        }
        if proposal.next_manager.containment_identity != self.manager_containment {
            return Err(FenceError::WrongContainment);
        }
        if self.repeat_phase(&proposal)?.is_some() {
            let still_admitted = match self.phase {
                RebindPhase::Active => ledger.activated(&proposal),
                RebindPhase::PendingStore => ledger.pending(&proposal),
                RebindPhase::PendingPod => ledger.pending(&proposal) || ledger.activated(&proposal),
            };
            return if still_admitted {
                Ok(self.phase)
            } else {
                Err(FenceError::NotAdmitted)
            };
        }
        if self.phase != RebindPhase::Active {
            return Err(FenceError::PendingRebind);
        }
        if proposal.next_manager == self.manager.peer {
            return Err(FenceError::WrongPeer);
        }
        if proposal.expected_owner_epoch != self.manager.owner_epoch
            || proposal.expected_credential_epoch != self.manager.credential_epoch
        {
            return Err(FenceError::StaleEpoch);
        }
        if proposal.expected_input_epochs.len() != self.resources.len()
            || proposal.next_input_epochs.len() != self.resources.len()
        {
            return Err(FenceError::StaleEpoch);
        }
        for (id, resource) in &self.resources {
            let expected = proposal
                .expected_input_epochs
                .get(id)
                .ok_or(FenceError::StaleEpoch)?;
            let next = proposal
                .next_input_epochs
                .get(id)
                .ok_or(FenceError::StaleEpoch)?;
            if *expected != resource.epoch {
                return Err(FenceError::StaleEpoch);
            }
            checked_next(*expected, *next, InputEpoch::checked_next)?;
        }
        checked_next(
            proposal.expected_owner_epoch,
            proposal.next_owner_epoch,
            OwnerEpoch::checked_next,
        )?;
        checked_next(
            proposal.expected_credential_epoch,
            proposal.next_credential_epoch,
            CredentialEpoch::checked_next,
        )?;
        if !ledger.pending(&proposal) {
            return Err(FenceError::NotAdmitted);
        }
        if old_liveness != ManagerLiveness::DeadAttested
            && (now_ms == 0 || now_ms < self.manager.lease_until_ms)
        {
            return Err(FenceError::LeaseHeld);
        }
        self.grants.clear();
        for (id, resource) in &mut self.resources {
            resource.lease = None;
            resource.epoch = *proposal
                .next_input_epochs
                .get(id)
                .ok_or(FenceError::StaleEpoch)?;
        }
        self.last_rebind = Some(proposal.clone());
        self.pending = Some(proposal);
        self.phase = RebindPhase::PendingStore;
        Ok(self.phase)
    }

    /// Caller must durably checkpoint PendingPod before acknowledging rebind.
    pub fn confirm_pod_bound(
        &mut self,
        proposal: &RebindProposal,
        peer: &AttestedPeer,
        witness: &impl OwnerEpochWitness,
        ledger: &impl RebindLedger,
    ) -> Result<RebindPhase, FenceError> {
        self.require_owner(witness, proposal.next_owner_epoch)?;
        self.require_pending_proposal(proposal, peer)?;
        if !ledger.pending(proposal) {
            return Err(FenceError::NotAdmitted);
        }
        if self.phase == RebindPhase::PendingPod {
            return Ok(self.phase);
        }
        if self.phase != RebindPhase::PendingStore {
            return Err(FenceError::PendingRebind);
        }
        self.phase = RebindPhase::PendingPod;
        Ok(self.phase)
    }

    pub fn activate_rebind(
        &mut self,
        proposal: &RebindProposal,
        peer: &AttestedPeer,
        witness: &impl OwnerEpochWitness,
        ledger: &impl RebindLedger,
    ) -> Result<RebindPhase, FenceError> {
        self.require_owner(witness, proposal.next_owner_epoch)?;
        if proposal.next_manager != *peer {
            return Err(FenceError::WrongPeer);
        }
        if !ledger.activated(proposal) {
            return Err(FenceError::NotAdmitted);
        }
        if self.phase == RebindPhase::Active && self.last_rebind.as_ref() == Some(proposal) {
            return Ok(self.phase);
        }
        self.require_pending_proposal(proposal, peer)?;
        if self.phase != RebindPhase::PendingPod {
            return Err(FenceError::PendingRebind);
        }
        self.manager = ManagerBinding {
            peer: peer.clone(),
            owner_epoch: proposal.next_owner_epoch,
            credential_epoch: proposal.next_credential_epoch,
            lease_until_ms: 0,
        };
        self.pending = None;
        self.phase = RebindPhase::Active;
        Ok(self.phase)
    }

    fn repeat_phase(&self, proposal: &RebindProposal) -> Result<Option<RebindPhase>, FenceError> {
        if let Some(last) = &self.last_rebind {
            if last.command_key == proposal.command_key {
                return if last == proposal {
                    Ok(Some(self.phase))
                } else {
                    Err(FenceError::IdempotencyConflict)
                };
            }
        }
        Ok(None)
    }

    fn require_pending_proposal(
        &self,
        proposal: &RebindProposal,
        peer: &AttestedPeer,
    ) -> Result<(), FenceError> {
        if self.pending.as_ref() != Some(proposal) {
            return Err(FenceError::IdempotencyConflict);
        }
        if proposal.next_manager != *peer {
            return Err(FenceError::WrongPeer);
        }
        Ok(())
    }

    fn require_active(
        &self,
        peer: &AttestedPeer,
        witness: &impl OwnerEpochWitness,
        now_ms: u64,
        require_lease: bool,
    ) -> Result<(), FenceError> {
        self.require_phase_and_owner(witness)?;
        if *peer != self.manager.peer {
            return Err(FenceError::WrongPeer);
        }
        if require_lease && (now_ms == 0 || now_ms >= self.manager.lease_until_ms) {
            return Err(FenceError::LeaseExpired);
        }
        Ok(())
    }

    fn require_phase_and_owner(&self, witness: &impl OwnerEpochWitness) -> Result<(), FenceError> {
        if self.phase != RebindPhase::Active {
            return Err(FenceError::PendingRebind);
        }
        self.require_owner(witness, self.manager.owner_epoch)
    }

    fn require_owner(
        &self,
        witness: &impl OwnerEpochWitness,
        expected: OwnerEpoch,
    ) -> Result<(), FenceError> {
        if witness.current_owner_epoch(&self.identity.store_lineage, &self.identity.scope_id)
            != Some(expected)
        {
            return Err(FenceError::OwnerUnverified);
        }
        Ok(())
    }
}

fn short_lease(now_ms: u64, until_ms: u64, maximum_ms: u64) -> Result<(), FenceError> {
    if now_ms == 0 || until_ms <= now_ms || until_ms - now_ms > maximum_ms {
        Err(FenceError::InvalidEvidence)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> PodFenceIdentity {
        PodFenceIdentity {
            scope_id: ScopeId::try_from("scope.peer.fixture").unwrap(),
            pod_id: PodId::try_from("pod.peer.fixture").unwrap(),
            attempt_id: AttemptId::try_from("attempt.peer.fixture").unwrap(),
            incarnation: Epoch::new(7).unwrap(),
            store_lineage: StoreLineageId::try_from("store.peer.fixture").unwrap(),
        }
    }
    fn peer(pid: &str, birth: &str, containment: &str) -> AttestedPeer {
        AttestedPeer::from_port("uid.1000", pid, "boot.fixture", birth, containment).unwrap()
    }
    fn manager() -> AttestedPeer {
        peer("pid.100", "birth.100", "manager.unit")
    }
    fn successor() -> AttestedPeer {
        peer("pid.200", "birth.200", "manager.unit")
    }
    fn sibling() -> AttestedPeer {
        peer("pid.300", "birth.300", "sibling.pod.unit")
    }
    fn resource() -> ResourceId {
        ResourceId::try_from("resource.peer.fixture").unwrap()
    }
    fn resource_two() -> ResourceId {
        ResourceId::try_from("resource.second.fixture").unwrap()
    }
    fn owner(value: u64) -> OwnerEpoch {
        OwnerEpoch::new(value).unwrap()
    }
    fn credential(value: u64) -> CredentialEpoch {
        CredentialEpoch::new(value).unwrap()
    }
    fn input(value: u64) -> InputEpoch {
        InputEpoch::new(value).unwrap()
    }
    fn grant_id(value: &str) -> PeerGrantId {
        PeerGrantId::try_from(value).unwrap()
    }

    struct Witness {
        identity: PodFenceIdentity,
        epoch: Option<OwnerEpoch>,
    }
    impl Witness {
        fn new(epoch: Option<OwnerEpoch>) -> Self {
            Self {
                identity: id(),
                epoch,
            }
        }
    }
    impl OwnerEpochWitness for Witness {
        fn current_owner_epoch(
            &self,
            lineage: &StoreLineageId,
            scope: &ScopeId,
        ) -> Option<OwnerEpoch> {
            (lineage == &self.identity.store_lineage && scope == &self.identity.scope_id)
                .then_some(self.epoch)
                .flatten()
        }
    }
    struct Ledger {
        proposal: RebindProposal,
        pending: bool,
        active: bool,
    }
    impl RebindLedger for Ledger {
        fn pending(&self, proposal: &RebindProposal) -> bool {
            self.pending && proposal == &self.proposal
        }
        fn activated(&self, proposal: &RebindProposal) -> bool {
            self.active && proposal == &self.proposal
        }
    }
    fn fence() -> PodPeerFence {
        PodPeerFence::new(
            id(),
            manager(),
            owner(1),
            credential(1),
            BTreeMap::from([(resource(), input(1)), (resource_two(), input(1))]),
            100,
            800,
        )
        .unwrap()
    }
    fn controller(
        peer: AttestedPeer,
        owner_epoch: OwnerEpoch,
        credential_epoch: CredentialEpoch,
    ) -> PeerGrant {
        PeerGrant::new(
            grant_id("grant.controller"),
            peer,
            GrantKind::Controller,
            FenceTarget::Resource(resource()),
            BTreeSet::from([
                FenceOperation::ObserveResource,
                FenceOperation::AcquireInput,
                FenceOperation::WriteInput,
                FenceOperation::ResizeResource,
            ]),
            owner_epoch,
            credential_epoch,
            700,
        )
        .unwrap()
    }
    fn request(
        grant: &str,
        operation: FenceOperation,
        input_epoch: Option<InputEpoch>,
        owner_epoch: OwnerEpoch,
        credential_epoch: CredentialEpoch,
    ) -> PeerRequest {
        PeerRequest {
            identity: id(),
            grant_id: grant_id(grant),
            owner_epoch,
            credential_epoch,
            target: FenceTarget::Resource(resource()),
            operation,
            input_epoch,
        }
    }
    fn proposal(first: InputEpoch, second: InputEpoch) -> RebindProposal {
        let expected_input_epochs = BTreeMap::from([(resource(), first), (resource_two(), second)]);
        let next_input_epochs = expected_input_epochs
            .iter()
            .map(|(id, epoch)| (id.clone(), epoch.checked_next().unwrap()))
            .collect();
        RebindProposal {
            identity: id(),
            expected_owner_epoch: owner(1),
            next_owner_epoch: owner(2),
            expected_credential_epoch: credential(1),
            next_credential_epoch: credential(2),
            expected_input_epochs,
            next_input_epochs,
            next_manager: successor(),
            command_key: CommandKey::try_from("key.rebind.fixture").unwrap(),
            digest: RequestDigest::parse(&"a".repeat(64)).unwrap(),
        }
    }

    #[test]
    fn copied_bearer_or_viewer_grant_cannot_control_another_peer() {
        let mut fence = fence();
        let witness = Witness::new(Some(owner(1)));
        fence
            .install_grant(
                &manager(),
                controller(manager(), owner(1), credential(1)),
                &witness,
                120,
            )
            .unwrap();
        let acquire = request(
            "grant.controller",
            FenceOperation::AcquireInput,
            Some(input(1)),
            owner(1),
            credential(1),
        );
        assert_eq!(
            fence.authorize(&sibling(), &acquire, &witness, 130),
            Err(FenceError::WrongPeer)
        );
        let epoch = fence
            .acquire_input_lease(
                &manager(),
                &grant_id("grant.controller"),
                &resource(),
                input(1),
                &witness,
                130,
                500,
            )
            .unwrap();
        assert_eq!(epoch, input(2));
        let write = request(
            "grant.controller",
            FenceOperation::WriteInput,
            Some(input(2)),
            owner(1),
            credential(1),
        );
        assert_eq!(fence.authorize(&manager(), &write, &witness, 140), Ok(()));
        assert_eq!(
            fence.authorize(&sibling(), &write, &witness, 140),
            Err(FenceError::WrongPeer)
        );
        let stale = request(
            "grant.controller",
            FenceOperation::WriteInput,
            Some(input(1)),
            owner(1),
            credential(1),
        );
        assert_eq!(
            fence.authorize(&manager(), &stale, &witness, 140),
            Err(FenceError::StaleEpoch)
        );

        let viewer = peer("pid.400", "birth.400", "viewer.gateway");
        let view_grant = PeerGrant::new(
            grant_id("grant.viewer"),
            viewer.clone(),
            GrantKind::Viewer,
            FenceTarget::Resource(resource()),
            BTreeSet::from([FenceOperation::ObserveResource]),
            owner(1),
            credential(1),
            700,
        )
        .unwrap();
        fence
            .install_grant(&manager(), view_grant, &witness, 150)
            .unwrap();
        assert_eq!(
            fence.authorize(
                &viewer,
                &request(
                    "grant.viewer",
                    FenceOperation::ObserveResource,
                    None,
                    owner(1),
                    credential(1)
                ),
                &witness,
                160
            ),
            Ok(())
        );
        assert_eq!(
            fence.authorize(
                &viewer,
                &request(
                    "grant.viewer",
                    FenceOperation::WriteInput,
                    Some(input(2)),
                    owner(1),
                    credential(1)
                ),
                &witness,
                160
            ),
            Err(FenceError::GrantDenied)
        );
        assert_eq!(
            fence.authorize(
                &sibling(),
                &request(
                    "grant.viewer",
                    FenceOperation::ObserveResource,
                    None,
                    owner(1),
                    credential(1)
                ),
                &witness,
                160
            ),
            Err(FenceError::WrongPeer)
        );
        assert_eq!(
            fence.authorize(&manager(), &write, &witness, 800),
            Err(FenceError::LeaseExpired)
        );
    }

    #[test]
    fn independent_resources_keep_their_leases_when_one_is_taken_over() {
        let mut fence = fence();
        let witness = Witness::new(Some(owner(1)));
        fence
            .install_grant(
                &manager(),
                controller(manager(), owner(1), credential(1)),
                &witness,
                120,
            )
            .unwrap();
        fence
            .install_grant(
                &manager(),
                PeerGrant::new(
                    grant_id("grant.second"),
                    manager(),
                    GrantKind::Controller,
                    FenceTarget::Resource(resource_two()),
                    BTreeSet::from([FenceOperation::AcquireInput, FenceOperation::WriteInput]),
                    owner(1),
                    credential(1),
                    700,
                )
                .unwrap(),
                &witness,
                120,
            )
            .unwrap();
        assert_eq!(
            fence.acquire_input_lease(
                &manager(),
                &grant_id("grant.controller"),
                &resource(),
                input(1),
                &witness,
                130,
                500
            ),
            Ok(input(2))
        );
        assert_eq!(
            fence.acquire_input_lease(
                &manager(),
                &grant_id("grant.second"),
                &resource_two(),
                input(1),
                &witness,
                130,
                500
            ),
            Ok(input(2))
        );
        let first_write = request(
            "grant.controller",
            FenceOperation::WriteInput,
            Some(input(2)),
            owner(1),
            credential(1),
        );
        let second_write = PeerRequest {
            identity: id(),
            grant_id: grant_id("grant.second"),
            owner_epoch: owner(1),
            credential_epoch: credential(1),
            target: FenceTarget::Resource(resource_two()),
            operation: FenceOperation::WriteInput,
            input_epoch: Some(input(2)),
        };
        assert_eq!(
            fence.authorize(&manager(), &first_write, &witness, 140),
            Ok(())
        );
        assert_eq!(
            fence.authorize(&manager(), &second_write, &witness, 140),
            Ok(())
        );

        let human = peer("pid.500", "birth.500", "human.gateway");
        fence
            .install_grant(
                &manager(),
                PeerGrant::new(
                    grant_id("grant.human"),
                    human.clone(),
                    GrantKind::Controller,
                    FenceTarget::Resource(resource()),
                    BTreeSet::from([FenceOperation::TakeoverInput, FenceOperation::WriteInput]),
                    owner(1),
                    credential(1),
                    700,
                )
                .unwrap(),
                &witness,
                150,
            )
            .unwrap();
        assert_eq!(
            fence.takeover_input_lease(
                &human,
                &grant_id("grant.human"),
                &resource(),
                input(2),
                &witness,
                160,
                500
            ),
            Ok(input(3))
        );
        assert_eq!(
            fence.authorize(&manager(), &first_write, &witness, 170),
            Err(FenceError::StaleEpoch)
        );
        let human_write = request(
            "grant.human",
            FenceOperation::WriteInput,
            Some(input(3)),
            owner(1),
            credential(1),
        );
        assert_eq!(fence.authorize(&human, &human_write, &witness, 170), Ok(()));
        assert_eq!(
            fence.authorize(&manager(), &second_write, &witness, 170),
            Ok(())
        );
        assert_eq!(fence.input_epoch(&resource()), Some(input(3)));
        assert_eq!(fence.input_epoch(&resource_two()), Some(input(2)));

        let advanced = Witness::new(Some(owner(2)));
        let proposed = proposal(input(3), input(2));
        let ledger = Ledger {
            proposal: proposed.clone(),
            pending: true,
            active: false,
        };
        assert_eq!(
            fence.prepare_rebind(
                proposed,
                &successor(),
                ManagerLiveness::DeadAttested,
                &advanced,
                &ledger,
                180
            ),
            Ok(RebindPhase::PendingStore)
        );
        assert_eq!(fence.input_epoch(&resource()), Some(input(4)));
        assert_eq!(fence.input_epoch(&resource_two()), Some(input(3)));
        assert_eq!(
            fence.authorize(&manager(), &second_write, &advanced, 190),
            Err(FenceError::PendingRebind)
        );
    }

    #[test]
    fn store_epoch_advance_and_both_pending_crash_windows_hold_old_controls() {
        let mut fence = fence();
        let old = Witness::new(Some(owner(1)));
        fence
            .install_grant(
                &manager(),
                controller(manager(), owner(1), credential(1)),
                &old,
                120,
            )
            .unwrap();
        let observe = request(
            "grant.controller",
            FenceOperation::ObserveResource,
            None,
            owner(1),
            credential(1),
        );
        assert_eq!(fence.authorize(&manager(), &observe, &old, 150), Ok(()));
        let advanced = Witness::new(Some(owner(2)));
        // Store committed before the pod saw rebind: old authority is already dead.
        assert_eq!(
            fence.authorize(&manager(), &observe, &advanced, 150),
            Err(FenceError::OwnerUnverified)
        );
        assert_eq!(
            fence.authorize(&manager(), &observe, &Witness::new(None), 150),
            Err(FenceError::OwnerUnverified)
        );
        let proposed = proposal(input(1), input(1));
        let mut ledger = Ledger {
            proposal: proposed.clone(),
            pending: true,
            active: false,
        };
        assert_eq!(
            fence.prepare_rebind(
                proposed.clone(),
                &successor(),
                ManagerLiveness::DeadAttested,
                &advanced,
                &ledger,
                170
            ),
            Ok(RebindPhase::PendingStore)
        );
        assert_eq!(
            fence.authorize(&manager(), &observe, &advanced, 180),
            Err(FenceError::PendingRebind)
        );
        let mut after_prepare_crash = fence.clone();
        after_prepare_crash.recover_after_crash();
        assert_eq!(
            after_prepare_crash.authorize(&manager(), &observe, &advanced, 180),
            Err(FenceError::PendingRebind)
        );
        assert_eq!(
            after_prepare_crash.confirm_pod_bound(&proposed, &successor(), &advanced, &ledger),
            Ok(RebindPhase::PendingPod)
        );
        let mut after_pod_checkpoint_crash = after_prepare_crash.clone();
        after_pod_checkpoint_crash.recover_after_crash();
        assert_eq!(
            after_pod_checkpoint_crash.authorize(&manager(), &observe, &advanced, 190),
            Err(FenceError::PendingRebind)
        );
        assert_eq!(
            after_pod_checkpoint_crash.activate_rebind(&proposed, &successor(), &advanced, &ledger),
            Err(FenceError::NotAdmitted)
        );
        ledger.active = true;
        assert_eq!(
            after_pod_checkpoint_crash.activate_rebind(&proposed, &successor(), &advanced, &ledger),
            Ok(RebindPhase::Active)
        );
        assert_eq!(after_pod_checkpoint_crash.owner_epoch(), owner(2));
        assert_eq!(
            after_pod_checkpoint_crash.input_epoch(&resource()),
            Some(input(2))
        );
        assert_eq!(
            after_pod_checkpoint_crash.input_epoch(&resource_two()),
            Some(input(2))
        );
        assert_eq!(
            after_pod_checkpoint_crash.authorize(&manager(), &observe, &advanced, 200),
            Err(FenceError::LeaseExpired)
        );
        after_pod_checkpoint_crash
            .renew_manager_lease(&successor(), &advanced, 200, 500)
            .unwrap();
        assert_eq!(
            after_pod_checkpoint_crash.authorize(&manager(), &observe, &advanced, 210),
            Err(FenceError::StaleEpoch)
        );
        let fresh_generation_with_old_grant = request(
            "grant.controller",
            FenceOperation::ObserveResource,
            None,
            owner(2),
            credential(2),
        );
        assert_eq!(
            after_pod_checkpoint_crash.authorize(
                &successor(),
                &fresh_generation_with_old_grant,
                &advanced,
                210,
            ),
            Err(FenceError::GrantDenied)
        );
    }

    #[test]
    fn rebind_is_exact_idempotent_and_refuses_sibling_birth_or_changed_digest() {
        let mut fence = fence();
        let advanced = Witness::new(Some(owner(2)));
        let proposed = proposal(input(1), input(1));
        let ledger = Ledger {
            proposal: proposed.clone(),
            pending: true,
            active: true,
        };
        assert_eq!(
            fence.prepare_rebind(
                proposed.clone(),
                &sibling(),
                ManagerLiveness::DeadAttested,
                &advanced,
                &ledger,
                180
            ),
            Err(FenceError::WrongPeer)
        );
        let mut wrong_containment = proposed.clone();
        wrong_containment.next_manager = sibling();
        assert_eq!(
            fence.prepare_rebind(
                wrong_containment,
                &sibling(),
                ManagerLiveness::DeadAttested,
                &advanced,
                &ledger,
                180
            ),
            Err(FenceError::WrongContainment)
        );
        assert_eq!(
            fence.prepare_rebind(
                proposed.clone(),
                &successor(),
                ManagerLiveness::Alive,
                &advanced,
                &ledger,
                180
            ),
            Err(FenceError::LeaseHeld)
        );
        assert_eq!(
            fence.prepare_rebind(
                proposed.clone(),
                &successor(),
                ManagerLiveness::DeadAttested,
                &advanced,
                &ledger,
                180
            ),
            Ok(RebindPhase::PendingStore)
        );
        assert_eq!(
            fence.prepare_rebind(
                proposed.clone(),
                &successor(),
                ManagerLiveness::Unknown,
                &advanced,
                &ledger,
                180
            ),
            Ok(RebindPhase::PendingStore)
        );
        let mut changed = proposed.clone();
        changed.digest = RequestDigest::parse(&"b".repeat(64)).unwrap();
        assert_eq!(
            fence.prepare_rebind(
                changed,
                &successor(),
                ManagerLiveness::Unknown,
                &advanced,
                &ledger,
                180
            ),
            Err(FenceError::IdempotencyConflict)
        );
        fence
            .confirm_pod_bound(&proposed, &successor(), &advanced, &ledger)
            .unwrap();
        assert_eq!(
            fence.confirm_pod_bound(&proposed, &successor(), &advanced, &ledger),
            Ok(RebindPhase::PendingPod)
        );
        assert_eq!(
            fence.activate_rebind(&proposed, &sibling(), &advanced, &ledger),
            Err(FenceError::WrongPeer)
        );
        assert_eq!(
            fence.activate_rebind(&proposed, &successor(), &advanced, &ledger),
            Ok(RebindPhase::Active)
        );
        assert_eq!(
            fence.prepare_rebind(
                proposed.clone(),
                &successor(),
                ManagerLiveness::Unknown,
                &advanced,
                &ledger,
                200
            ),
            Ok(RebindPhase::Active)
        );
        assert_eq!(
            fence.activate_rebind(&proposed, &successor(), &advanced, &ledger),
            Ok(RebindPhase::Active)
        );
    }

    #[test]
    fn stale_identity_epochs_and_expired_lease_fail_before_effect() {
        let mut fence = fence();
        let witness = Witness::new(Some(owner(1)));
        fence
            .install_grant(
                &manager(),
                controller(manager(), owner(1), credential(1)),
                &witness,
                120,
            )
            .unwrap();
        let mut request = request(
            "grant.controller",
            FenceOperation::ObserveResource,
            None,
            owner(1),
            credential(1),
        );
        request.identity.attempt_id = AttemptId::try_from("attempt.other").unwrap();
        assert_eq!(
            fence.authorize(&manager(), &request, &witness, 130),
            Err(FenceError::WrongAssociation)
        );
        request.identity = id();
        request.identity.store_lineage = StoreLineageId::try_from("store.other").unwrap();
        assert_eq!(
            fence.authorize(&manager(), &request, &witness, 130),
            Err(FenceError::WrongAssociation)
        );
        request.identity = id();
        let reused_pid = peer("pid.100", "birth.reused", "manager.unit");
        assert_eq!(
            fence.authorize(&reused_pid, &request, &witness, 130),
            Err(FenceError::WrongPeer)
        );
        request.credential_epoch = credential(2);
        assert_eq!(
            fence.authorize(&manager(), &request, &witness, 130),
            Err(FenceError::StaleEpoch)
        );
        request.credential_epoch = credential(1);
        assert_eq!(
            fence.authorize(&manager(), &request, &witness, 800),
            Err(FenceError::LeaseExpired)
        );
        fence.recover_after_crash();
        assert_eq!(
            fence.authorize(&manager(), &request, &witness, 140),
            Err(FenceError::LeaseExpired)
        );
        assert_eq!(
            fence.renew_manager_lease(&sibling(), &witness, 140, 400),
            Err(FenceError::WrongPeer)
        );
        fence
            .renew_manager_lease(&manager(), &witness, 140, 400)
            .unwrap();
        assert_eq!(
            fence.authorize(&manager(), &request, &witness, 150),
            Err(FenceError::GrantDenied)
        );
    }

    #[test]
    fn initial_checkpoint_restores_epochs_but_no_live_controls() {
        let mut fence = fence();
        let witness = Witness::new(Some(owner(1)));
        fence
            .install_grant(
                &manager(),
                controller(manager(), owner(1), credential(1)),
                &witness,
                120,
            )
            .unwrap();
        assert_eq!(
            fence
                .acquire_input_lease(
                    &manager(),
                    &grant_id("grant.controller"),
                    &resource(),
                    input(1),
                    &witness,
                    130,
                    500
                )
                .unwrap(),
            input(2)
        );
        let checkpoint = fence.checkpoint();
        assert_eq!(checkpoint.version(), POD_FENCE_CHECKPOINT_VERSION);
        assert_eq!(checkpoint.identity(), &id());
        assert_eq!(checkpoint.manager_peer(), &manager());
        assert_eq!(checkpoint.input_epochs().get(&resource()), Some(&input(2)));
        assert_eq!(
            checkpoint.input_epochs().get(&resource_two()),
            Some(&input(1))
        );
        let mut restored = PodPeerFence::restore_after_crash(checkpoint).unwrap();
        assert_eq!(restored.input_epoch(&resource()), Some(input(2)));
        assert_eq!(restored.input_epoch(&resource_two()), Some(input(1)));
        let write = request(
            "grant.controller",
            FenceOperation::WriteInput,
            Some(input(2)),
            owner(1),
            credential(1),
        );
        assert_eq!(
            restored.authorize(&manager(), &write, &witness, 140),
            Err(FenceError::LeaseExpired)
        );
        restored
            .renew_manager_lease(&manager(), &witness, 140, 500)
            .unwrap();
        assert_eq!(
            restored.authorize(&manager(), &write, &witness, 150),
            Err(FenceError::GrantDenied)
        );
    }

    #[test]
    fn checkpoint_across_both_rebind_crash_windows_never_revives_old_controls() {
        let mut fence = fence();
        let advanced = Witness::new(Some(owner(2)));
        let proposed = proposal(input(1), input(1));
        let mut ledger = Ledger {
            proposal: proposed.clone(),
            pending: true,
            active: false,
        };
        // Store epoch can commit before any pod checkpoint. The restored old
        // manager still fails the fresh owner witness and has no live lease.
        let cold = PodPeerFence::restore_after_crash(fence.checkpoint()).unwrap();
        let observe_old = request(
            "grant.controller",
            FenceOperation::ObserveResource,
            None,
            owner(1),
            credential(1),
        );
        assert_eq!(
            cold.authorize(&manager(), &observe_old, &advanced, 170),
            Err(FenceError::OwnerUnverified)
        );
        assert_eq!(
            fence.prepare_rebind(
                proposed.clone(),
                &successor(),
                ManagerLiveness::DeadAttested,
                &advanced,
                &ledger,
                170
            ),
            Ok(RebindPhase::PendingStore)
        );
        let mut pending = PodPeerFence::restore_after_crash(fence.checkpoint()).unwrap();
        assert_eq!(pending.phase(), RebindPhase::PendingStore);
        assert_eq!(pending.input_epoch(&resource()), Some(input(2)));
        assert_eq!(pending.input_epoch(&resource_two()), Some(input(2)));
        assert_eq!(
            pending.authorize(&manager(), &observe_old, &advanced, 180),
            Err(FenceError::PendingRebind)
        );
        assert_eq!(
            pending.confirm_pod_bound(&proposed, &successor(), &advanced, &ledger),
            Ok(RebindPhase::PendingPod)
        );
        let mut after_checkpoint = PodPeerFence::restore_after_crash(pending.checkpoint()).unwrap();
        assert_eq!(after_checkpoint.phase(), RebindPhase::PendingPod);
        assert_eq!(
            after_checkpoint.authorize(&manager(), &observe_old, &advanced, 190),
            Err(FenceError::PendingRebind)
        );
        let mut changed = proposed.clone();
        changed.digest = RequestDigest::parse(&"b".repeat(64)).unwrap();
        assert_eq!(
            after_checkpoint.prepare_rebind(
                changed,
                &successor(),
                ManagerLiveness::Unknown,
                &advanced,
                &ledger,
                195
            ),
            Err(FenceError::IdempotencyConflict)
        );
        ledger.active = true;
        assert_eq!(
            after_checkpoint.activate_rebind(&proposed, &successor(), &advanced, &ledger),
            Ok(RebindPhase::Active)
        );
        let mut active = PodPeerFence::restore_after_crash(after_checkpoint.checkpoint()).unwrap();
        assert_eq!(active.owner_epoch(), owner(2));
        assert_eq!(active.credential_epoch(), credential(2));
        assert_eq!(active.input_epoch(&resource()), Some(input(2)));
        assert_eq!(active.input_epoch(&resource_two()), Some(input(2)));
        assert_eq!(
            active.authorize(&manager(), &observe_old, &advanced, 200),
            Err(FenceError::LeaseExpired)
        );
        let observe_new = request(
            "grant.controller",
            FenceOperation::ObserveResource,
            None,
            owner(2),
            credential(2),
        );
        assert_eq!(
            active.authorize(&successor(), &observe_new, &advanced, 200),
            Err(FenceError::LeaseExpired)
        );
        active
            .renew_manager_lease(&successor(), &advanced, 200, 500)
            .unwrap();
        assert_eq!(
            active.authorize(&manager(), &observe_old, &advanced, 210),
            Err(FenceError::StaleEpoch)
        );
        assert_eq!(
            active.authorize(&manager(), &observe_new, &advanced, 210),
            Err(FenceError::GrantDenied)
        );
        assert_eq!(
            active.authorize(&successor(), &observe_new, &advanced, 210),
            Err(FenceError::GrantDenied)
        );
        assert_eq!(
            active.prepare_rebind(
                proposed.clone(),
                &successor(),
                ManagerLiveness::Unknown,
                &advanced,
                &ledger,
                220
            ),
            Ok(RebindPhase::Active)
        );
        let mut wrong = proposed.clone();
        wrong.digest = RequestDigest::parse(&"c".repeat(64)).unwrap();
        assert_eq!(
            active.prepare_rebind(
                wrong,
                &successor(),
                ManagerLiveness::Unknown,
                &advanced,
                &ledger,
                220
            ),
            Err(FenceError::IdempotencyConflict)
        );
        active
            .install_grant(
                &successor(),
                controller(successor(), owner(2), credential(2)),
                &advanced,
                230,
            )
            .unwrap();
        assert_eq!(
            active
                .acquire_input_lease(
                    &successor(),
                    &grant_id("grant.controller"),
                    &resource(),
                    input(2),
                    &advanced,
                    240,
                    500
                )
                .unwrap(),
            input(3)
        );
        let after_takeover = PodPeerFence::restore_after_crash(active.checkpoint()).unwrap();
        assert_eq!(after_takeover.input_epoch(&resource()), Some(input(3)));
        assert_eq!(after_takeover.input_epoch(&resource_two()), Some(input(2)));
        assert_eq!(
            after_takeover.authorize(&successor(), &observe_new, &advanced, 250),
            Err(FenceError::LeaseExpired)
        );
    }

    #[test]
    fn malformed_checkpoint_association_or_epoch_refuses_restore() {
        let original = fence().checkpoint();
        let mut wrong_version = original.clone();
        wrong_version.version += 1;
        assert_eq!(
            PodPeerFence::restore_after_crash(wrong_version),
            Err(FenceError::InvalidEvidence)
        );
        let mut wrong_containment = original.clone();
        wrong_containment.manager_containment = "sibling.unit".into();
        assert_eq!(
            PodPeerFence::restore_after_crash(wrong_containment),
            Err(FenceError::InvalidEvidence)
        );
        let mut empty = original.clone();
        empty.input_epochs.clear();
        assert_eq!(
            PodPeerFence::restore_after_crash(empty),
            Err(FenceError::InvalidEvidence)
        );
        let mut pending_without_proposal = original.clone();
        pending_without_proposal.phase = RebindPhase::PendingStore;
        assert_eq!(
            PodPeerFence::restore_after_crash(pending_without_proposal),
            Err(FenceError::InvalidEvidence)
        );
    }
}
