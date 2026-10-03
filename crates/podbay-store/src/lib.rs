//! Single-writer SQLite journal for PodBay command intent, events, and outbox effects.
#![forbid(unsafe_code)]

mod authority;
mod bound_launch;
mod launch;
mod model;
mod peer_witness;
mod rebind;
mod store;

pub use bound_launch::{
    BoundLaunchAdmission, BoundLaunchProposal, BoundLaunchRecord, BoundLaunchRequest,
    BoundLaunchResource,
};
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
pub use rebind::{DurableRebindPhase, DurableRebindReceipt, SqliteRebindLedger};
pub use store::PodBayStore;
