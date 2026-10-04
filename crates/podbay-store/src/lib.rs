//! Single-writer SQLite journal for PodBay command intent, events, and outbox effects.
#![forbid(unsafe_code)]

mod authority;
mod bootstrap_send;
mod bound_launch;
mod launch;
mod manager_peer;
mod model;
mod peer_witness;
mod rebind;
mod store;
mod writer_lease;

pub use authority::SqliteActorVerifierWitness;
pub use bootstrap_send::{
    BootstrapSendRecord, BootstrapSendSelector, TrustedBootstrapSendRequest,
};
pub use bound_launch::{
    BoundLaunchAdmission, BoundLaunchFormat, BoundLaunchProposal, BoundLaunchRecord,
    BoundLaunchRequest, BoundLaunchResource, BoundRootLaunchProposalV2, BoundRootLaunchRequestV2,
    CurrentBoundPodSnapshot, CurrentBoundResource, CurrentDelegatingParentSnapshot, RunChildBudget,
};
pub use manager_peer::SqliteManagerPeerWitness;
pub use model::{
    Admission, AdmittedLaunchInspection, AuthorityActorRecord, AuthorityGrantRecord,
    AuthorityMutation, AuthorityPodRecord, AuthorityResourceRecord, AuthorityRightRecord,
    AuthoritySnapshot, CommandInspection, CommandLookupSelector, CommandRequest, CommittedEvent,
    EffectClaim, EffectObservation, EffectState, EventCursor, EventReference, HostAcceptanceProof,
    HostObservedPriorCheckpoint, LaunchDispatchStage, LaunchDispatchStatus, LaunchIntentBinding,
    LaunchKeyLookupRequest, LaunchLookupRequest, LaunchPortResult, ManagerCredentialClaim,
    NativeWriterLease, NativeWriterTarget, ObservedStage, OwnerActorRotationReceipt,
    QuarantinedSourceEvent, Receipt, ScopeSnapshot, SourceAnomaly, SourceOrder, StoreError,
    StoredEffect, TrustedNativeWriterLeaseRequest, TrustedOwnerRotationProof, VerifiedPrincipal,
};
pub use peer_witness::SqliteOwnerEpochWitness;
pub use rebind::{
    DurableRebindPhase, DurableRebindReceipt, PriorObservedRebindInspection,
    SqlitePriorObservedPendingLedger, SqliteRebindLedger,
};
pub use store::PodBayStore;
