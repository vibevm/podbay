//! Versioned native PodBay wire DTOs and bounded local frames.
#![forbid(unsafe_code)]

mod command;
mod cursor;
mod decimal;
mod error;
mod frame;
mod observation;
mod schema;
mod timestamp;
mod typescript;

pub use command::{
    CommandBody, CommandEnvelope, ContentBlock, Guard, MutationOperation, PausePolicy,
    ResourceAction, ResourceCommandBody, ResumePolicy, RunPauseBody, RunResumeBody, RunStopBody,
    SendPolicy, SessionSendBody, StopScope, Target, command_digest, decode_command_json,
};
pub use cursor::EventCursor;
pub use decimal::DecimalString;
pub use error::WireError;
pub use frame::{MAX_FRAME_BYTES, decode_frame_bytes, encode_frame};
pub use observation::{
    Capability, CapabilityEnvelope, CapabilitySupport, CommandStage, ErrorEnvelope, EventEnvelope,
    ObservationKind, ProtocolVersion, Receipt, RuntimeError, RuntimeErrorCode, SnapshotEnvelope,
    decode_event_json,
};
pub use schema::contract_manifest;
pub use typescript::typescript_source;
