//! Versioned native PodBay wire DTOs and bounded local frames.
#![forbid(unsafe_code)]

mod codex_policy_v2;
mod command;
mod cursor;
mod decimal;
mod effective_launch;
mod error;
mod frame;
mod launch_descriptor;
mod observation;
mod read;
mod schema;
mod timestamp;
mod typescript;

pub use codex_policy_v2::{
    CodexAppServerPolicyV2, CodexApprovalPolicyV2, CodexPolicyV2Error, CodexSandboxV2,
};
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
pub use effective_launch::{
    CredentialLocator, EFFECTIVE_LAUNCH_V2_VERSION, EFFECTIVE_LAUNCH_VERSION,
    EFFECTIVE_OPERATOR_UNTIL_STOPPED_VERSION,
    EffectiveLaunchContract, EffectiveLaunchContractV2, EffectiveLaunchError,
    EffectiveWorkspaceAccess,
};
pub use error::WireError;
pub use frame::{MAX_FRAME_BYTES, decode_frame_bytes, encode_frame};
pub use launch_descriptor::{
    ImmutableLaunchDescriptor, ImmutableLaunchDescriptorV2, LAUNCH_DESCRIPTOR_SCHEMA,
    LAUNCH_DESCRIPTOR_V2_SCHEMA, LAUNCH_DESCRIPTOR_OPERATOR_UNTIL_STOPPED_SCHEMA,
    OPERATOR_PROCESS_PROFILE_REF, LaunchDescriptorError, LifetimeLimit,
    NativeResourceKind, NativeResourceView,
    NativeRole, NativeWorkKind, ResourceDriver, ReviewedNativePolicy, ReviewedResource, TargetOs,
};
pub use observation::{
    Capability, CapabilityEnvelope, CapabilitySupport, CommandStage, ErrorEnvelope, EventEnvelope,
    ObservationKind, ProtocolVersion, Receipt, RuntimeError, RuntimeErrorCode, SnapshotEnvelope,
    SuccessEnvelope, decode_event_json,
};
pub use read::{
    CommandSelector, CommandsGetBody, EmptyReadBody, EventsSubscribeBody, HistoryReadBody,
    NativeEventCursor, NativeEventIdentity, NativeEventsReadBody, ReadBody, ReadEnvelope,
    ReadOperation, TerminalAttachBody, TerminalObserveBody,
    decode_read_json,
};
pub use schema::contract_manifest;
pub use typescript::typescript_source;
