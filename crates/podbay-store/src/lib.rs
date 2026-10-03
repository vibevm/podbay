//! Single-writer SQLite journal for PodBay command intent, events, and outbox effects.
#![forbid(unsafe_code)]

mod authority;
mod model;
mod store;

pub use model::{
    Admission, AuthorityActorRecord, AuthorityGrantRecord, AuthorityMutation, AuthorityPodRecord,
    AuthorityResourceRecord, AuthorityRightRecord, AuthoritySnapshot, CommandRequest,
    CommittedEvent, EffectClaim, EffectObservation, EffectState, EventCursor, EventReference,
    HostAcceptanceProof, ObservedStage, QuarantinedSourceEvent, Receipt, ScopeSnapshot,
    SourceAnomaly, SourceOrder, StoreError, StoredEffect, VerifiedPrincipal,
};
pub use store::PodBayStore;
