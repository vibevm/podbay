//! Single-writer SQLite journal for PodBay command intent, events, and outbox effects.
#![forbid(unsafe_code)]

mod authority;
mod bound_launch;
mod launch;
mod manager_peer;
mod model;
mod peer_witness;
mod rebind;
mod store;

pub use authority::SqliteActorVerifierWitness;
pub use bound_launch::{
    BoundLaunchAdmission, BoundLaunchProposal, BoundLaunchRecord, BoundLaunchRequest,
    BoundLaunchResource, CurrentBoundPodSnapshot, CurrentBoundResource,
};
pub use manager_peer::SqliteManagerPeerWitness;
pub use model::{
    Admission, AdmittedLaunchInspection, AuthorityActorRecord, AuthorityGrantRecord,
    AuthorityMutation, AuthorityPodRecord, AuthorityResourceRecord, AuthorityRightRecord,
    AuthoritySnapshot, CommandInspection, CommandLookupSelector, CommandRequest, CommittedEvent,
    EffectClaim, EffectObservation, EffectState, EventCursor, EventReference, HostAcceptanceProof,
    HostObservedPriorCheckpoint,
    LaunchDispatchStage, LaunchDispatchStatus, LaunchIntentBinding, LaunchLookupRequest,
    LaunchPortResult, ManagerCredentialClaim, ObservedStage, QuarantinedSourceEvent, Receipt,
    ScopeSnapshot, SourceAnomaly, SourceOrder, StoreError, StoredEffect, VerifiedPrincipal,
};
pub use peer_witness::SqliteOwnerEpochWitness;
pub use rebind::{
    DurableRebindPhase, DurableRebindReceipt, PriorObservedRebindInspection,
    SqlitePriorObservedPendingLedger, SqliteRebindLedger,
};
pub use store::PodBayStore;
