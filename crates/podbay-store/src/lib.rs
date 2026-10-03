//! Single-writer SQLite journal for PodBay command intent, events, and outbox effects.
#![forbid(unsafe_code)]

mod authority;
mod launch;
mod model;
mod peer_witness;
mod store;

pub use model::{
    Admission, AdmittedLaunchInspection, AuthorityActorRecord, AuthorityGrantRecord,
    AuthorityMutation, AuthorityPodRecord, AuthorityResourceRecord, AuthorityRightRecord,
    AuthoritySnapshot, CommandRequest, CommittedEvent, EffectClaim, EffectObservation, EffectState,
    EventCursor, EventReference, HostAcceptanceProof, LaunchDispatchStage, LaunchDispatchStatus,
    LaunchIntentBinding, LaunchLookupRequest, LaunchPortResult, ObservedStage,
    QuarantinedSourceEvent, Receipt, ScopeSnapshot, SourceAnomaly, SourceOrder, StoreError,
    StoredEffect, VerifiedPrincipal,
};
pub use peer_witness::SqliteOwnerEpochWitness;
pub use store::PodBayStore;
