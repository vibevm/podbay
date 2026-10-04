//! Role-neutral, fake-transport Codex app-server resource adapter.
//!
//! An explicit pod-side child stdio transport exists, but only fake-child
//! fixtures have exercised it. This crate does not certify a real Codex
//! account/session launch or an exclusive native writer. A durable writer
//! fence and native provider conformance remain required before live use.

mod adapter;
mod codec;
mod host_requests;
mod process_transport;

pub use adapter::{
    AnswerWriteOutcome, ApprovalPolicy, AuthorizedAnswerPermit, AvailableLine, AvailableWrite,
    BlockReason, BootstrapReadPoll, BootstrapState, BootstrapTurnStage, BootstrapTurnSubmission,
    CodexError, CodexResource, InterruptState, JsonlTransport, NativeThread, PinnedCodexConfig,
    ResourceIdentity, Sandbox, StartReceipt, ThreadStatus, TurnControlState, TurnMode,
    TurnSubmission, TurnSubmissionStage, WriterPermit,
};
pub use codec::{CodecError, MAX_FRAME_BYTES, decode, encode};
pub use host_requests::{
    ApprovalDecision, CommandApprovalKind, NativeAnswer, NativeQuestion, NativeQuestionOption,
    NativeRequestKind, NativeRequestStage, NativeRpcId, PendingNativeRequest,
    RedactedNativeObservation,
};
pub use process_transport::{
    ChildBirthObservation, ChildExitObservation, ChildLaunchSpec, KernelChildBirthObservation,
    ProcessJsonlTransport,
};

pub const TESTED_CODEX_CLI_VERSION: &str = "0.159.3";
pub const TESTED_V2_SCHEMA_SHA256: &str =
    "81a88c04ae4984b16d73080f4109d0477682bc76c8adbe483e371175ce54c054";
