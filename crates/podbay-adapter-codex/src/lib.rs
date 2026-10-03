//! Role-neutral, fake-transport Codex app-server resource adapter.
//!
//! This crate does not spawn Codex, open a provider account, grant permissions,
//! or claim that a native session has an exclusive writer. A pod-side transport
//! and durable writer fence must supply those boundaries before live use.

mod adapter;
mod codec;
mod host_requests;

pub use adapter::{
    AnswerWriteOutcome, ApprovalPolicy, AuthorizedAnswerPermit, BlockReason, BootstrapState,
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

pub const TESTED_CODEX_CLI_VERSION: &str = "0.159.3";
pub const TESTED_V2_SCHEMA_SHA256: &str =
    "81a88c04ae4984b16d73080f4109d0477682bc76c8adbe483e371175ce54c054";
