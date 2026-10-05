//! Single-writer SQLite journal for PodBay command intent, events, and outbox effects.
#![forbid(unsafe_code)]

mod authority;
mod bootstrap_send;
mod bound_launch;
mod current_snapshot;
mod launch;
mod later_turn;
mod manager_peer;
mod model;
mod native_evidence;
mod peer_witness;
mod rebind;
mod store;
mod supersession;
mod writer_lease;

pub use authority::SqliteActorVerifierWitness;
pub use bootstrap_send::{
    BootstrapSendRecord, BootstrapSendSelector, TrustedBootstrapSendRequest,
};
pub use bound_launch::{
    BoundLaunchAdmission, BoundLaunchFormat, BoundLaunchProposal, BoundLaunchRecord,
    BoundLaunchRequest, BoundLaunchResource, BoundOperatorRootLaunchProposal,
    BoundOperatorRootLaunchRequest, BoundRootLaunchProposalV2, BoundRootLaunchRequestV2,
    CurrentBoundPodSnapshot, CurrentBoundResource, CurrentDelegatingParentSnapshot,
    CurrentLaunchPolicyFence, CurrentV2RebindCursor, CurrentV2RebindPage, RunChildBudget,
};
pub use current_snapshot::CURRENT_SCOPE_ENTITY_LIMIT;
pub use later_turn::{LaterCodexSendRecord, LaterCodexSendSelector, TrustedLaterCodexSendRequest};
pub use manager_peer::SqliteManagerPeerWitness;
pub use model::{
    Admission, AdmittedLaunchInspection, AuthorityActorRecord, AuthorityGrantRecord,
    AuthorityMutation, AuthorityPodRecord, AuthorityResourceRecord, AuthorityRightRecord,
    AuthoritySnapshot, CommandInspection, CommandLookupSelector, CommandRequest, CommittedEvent,
    CurrentAttemptSnapshot, CurrentObservation, CurrentPodSnapshot, CurrentResourceSnapshot,
    CurrentRunSnapshot, CurrentScopeSnapshot, CurrentSessionSnapshot, EffectClaim,
    EffectObservation, EffectState, EventCursor, EventReference, HostAcceptanceProof,
    HostObservedPriorCheckpoint, LaunchDispatchStage, LaunchDispatchStatus, LaunchIntentBinding,
    LaunchKeyLookupRequest, LaunchLookupRequest, LaunchPortResult, ManagerCredentialClaim,
    NativeWriterLease, NativeWriterRenewalReceipt, NativeWriterRenewalRequest, NativeWriterTarget, ObservedStage, OwnerActorRotationReceipt,
    QuarantinedSourceEvent, Receipt, ScopeSnapshot, SourceAnomaly, SourceOrder, StoreError,
    StoredEffect, TrustedNativeWriterLeaseRequest, TrustedOwnerRotationProof, VerifiedPrincipal,
};
pub use native_evidence::{
    NativeEvidenceEvent, NativeEvidenceGap, NativeEvidenceIdentity, NativeEvidencePage,
    NativeEvidenceSnapshot, TrustedNativeEvidenceAdmission,
};
pub use peer_witness::SqliteOwnerEpochWitness;
pub use rebind::{
    DurableRebindPhase, DurableRebindReceipt, PriorObservedRebindInspection,
    SqlitePriorObservedPendingLedger, SqliteRebindLedger, StoreOnlyPendingRebind,
};
pub use supersession::{
    PriorPlannedRecovery, SqliteSupersessionLedger, SupersessionReceipt, SupersessionStage,
};
pub use store::PodBayStore;
