//! Single-writer SQLite journal for PodBay command intent, events, and outbox effects.
#![forbid(unsafe_code)]

mod model;
mod store;

pub use model::{
    Admission, CommandRequest, CommittedEvent, EffectClaim, EffectObservation, EffectState,
    EventCursor, Receipt, ScopeSnapshot, StoreError, StoredEffect, VerifiedPrincipal,
};
pub use store::PodBayStore;
