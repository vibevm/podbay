//! Versioned native PodBay wire DTOs and bounded local frames.
#![forbid(unsafe_code)]

mod command;
mod cursor;
mod decimal;
mod error;
mod frame;
mod observation;
mod read;
mod schema;
mod timestamp;
mod typescript;

pub use command::{
    AcknowledgementKind, AnswerItem, AnswerMode, ChildPolicy, CommandBody, CommandEnvelope,
    ContentBlock, ControlAcquireBody, ControlReleaseBody, DeliveryAckBody, DeliveryCancelBody,
    FallbackPolicy, Guard, LaunchBody, LaunchLimits, LaunchRole, LaunchSelection, LaunchWork,
    LeaseHolder, MutationOperation, PausePolicy, PermissionDecideBody, PermissionDecision,
    PermissionRequestBody, QuestionAnswerBody, QuestionAskBody, QuestionCancelBody, QuestionItem,
    QuestionResponse, Recipient, RequestedAuthority, ResourceAction, ResourceCommandBody,
    ResultDeclaration, ResumePolicy, RunFinishBody, RunInterruptBody, RunPauseBody, RunReportBody,
    RunResumeBody, RunStopBody, SendPolicy, SessionChoice, SessionCloseBody, SessionSendBody,
    StopScope, Target, TaskRef, TerminalDetachBody, WorkKind, WorkspaceAccess, WorkspaceBinding,
    command_digest, decode_command_json,
};
pub use cursor::EventCursor;
pub use decimal::DecimalString;
pub use error::WireError;
pub use frame::{MAX_FRAME_BYTES, decode_frame_bytes, encode_frame};
pub use observation::{
    Capability, CapabilityEnvelope, CapabilitySupport, CommandStage, ErrorEnvelope, EventEnvelope,
    ObservationKind, ProtocolVersion, Receipt, RuntimeError, RuntimeErrorCode, SnapshotEnvelope,
    SuccessEnvelope, decode_event_json,
};
pub use read::{
    CommandSelector, CommandsGetBody, EmptyReadBody, EventsSubscribeBody, HistoryReadBody,
    ReadBody, ReadEnvelope, ReadOperation, TerminalAttachBody, TerminalObserveBody,
    decode_read_json,
};
pub use schema::contract_manifest;
pub use typescript::typescript_source;
