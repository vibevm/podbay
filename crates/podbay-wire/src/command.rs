//! Strict mutation decoding. Unknown operations and resource kinds have no opaque fallback.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::cursor::valid_identity;
use crate::timestamp::valid_utc_timestamp;
use crate::{DecimalString, ProtocolVersion, WireError};

const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MutationOperation {
    #[serde(rename = "launch")]
    Launch,
    #[serde(rename = "session.close")]
    SessionClose,
    #[serde(rename = "session.send")]
    SessionSend,
    #[serde(rename = "session.writerLease.renew")]
    SessionWriterLeaseRenew,
    #[serde(rename = "run.interrupt")]
    RunInterrupt,
    #[serde(rename = "run.pause")]
    RunPause,
    #[serde(rename = "run.resume")]
    RunResume,
    #[serde(rename = "run.stop")]
    RunStop,
    #[serde(rename = "run.report")]
    RunReport,
    #[serde(rename = "run.finish")]
    RunFinish,
    #[serde(rename = "delivery.ack")]
    DeliveryAck,
    #[serde(rename = "delivery.cancel")]
    DeliveryCancel,
    #[serde(rename = "control.acquire")]
    ControlAcquire,
    #[serde(rename = "control.release")]
    ControlRelease,
    #[serde(rename = "terminal.detach")]
    TerminalDetach,
    #[serde(rename = "question.ask")]
    QuestionAsk,
    #[serde(rename = "question.answer")]
    QuestionAnswer,
    #[serde(rename = "question.cancel")]
    QuestionCancel,
    #[serde(rename = "permission.request")]
    PermissionRequest,
    #[serde(rename = "permission.decide")]
    PermissionDecide,
    #[serde(rename = "resource.command")]
    ResourceCommand,
}

impl MutationOperation {
    pub const SUPPORTED: [Self; 21] = [
        Self::Launch,
        Self::SessionClose,
        Self::SessionSend,
        Self::SessionWriterLeaseRenew,
        Self::RunInterrupt,
        Self::RunPause,
        Self::RunResume,
        Self::RunStop,
        Self::RunReport,
        Self::RunFinish,
        Self::DeliveryAck,
        Self::DeliveryCancel,
        Self::ControlAcquire,
        Self::ControlRelease,
        Self::TerminalDetach,
        Self::QuestionAsk,
        Self::QuestionAnswer,
        Self::QuestionCancel,
        Self::PermissionRequest,
        Self::PermissionDecide,
        Self::ResourceCommand,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Launch => "launch",
            Self::SessionClose => "session.close",
            Self::SessionSend => "session.send",
            Self::SessionWriterLeaseRenew => "session.writerLease.renew",
            Self::RunInterrupt => "run.interrupt",
            Self::RunPause => "run.pause",
            Self::RunResume => "run.resume",
            Self::RunStop => "run.stop",
            Self::RunReport => "run.report",
            Self::RunFinish => "run.finish",
            Self::DeliveryAck => "delivery.ack",
            Self::DeliveryCancel => "delivery.cancel",
            Self::ControlAcquire => "control.acquire",
            Self::ControlRelease => "control.release",
            Self::TerminalDetach => "terminal.detach",
            Self::QuestionAsk => "question.ask",
            Self::QuestionAnswer => "question.answer",
            Self::QuestionCancel => "question.cancel",
            Self::PermissionRequest => "permission.request",
            Self::PermissionDecide => "permission.decide",
            Self::ResourceCommand => "resource.command",
        }
    }

    fn from_wire(value: &str) -> Result<Self, WireError> {
        match value {
            "launch" => Ok(Self::Launch),
            "session.close" => Ok(Self::SessionClose),
            "session.send" => Ok(Self::SessionSend),
            "session.writerLease.renew" => Ok(Self::SessionWriterLeaseRenew),
            "run.interrupt" => Ok(Self::RunInterrupt),
            "run.pause" => Ok(Self::RunPause),
            "run.resume" => Ok(Self::RunResume),
            "run.stop" => Ok(Self::RunStop),
            "run.report" => Ok(Self::RunReport),
            "run.finish" => Ok(Self::RunFinish),
            "delivery.ack" => Ok(Self::DeliveryAck),
            "delivery.cancel" => Ok(Self::DeliveryCancel),
            "control.acquire" => Ok(Self::ControlAcquire),
            "control.release" => Ok(Self::ControlRelease),
            "terminal.detach" => Ok(Self::TerminalDetach),
            "question.ask" => Ok(Self::QuestionAsk),
            "question.answer" => Ok(Self::QuestionAnswer),
            "question.cancel" => Ok(Self::QuestionCancel),
            "permission.request" => Ok(Self::PermissionRequest),
            "permission.decide" => Ok(Self::PermissionDecide),
            "resource.command" => Ok(Self::ResourceCommand),
            other => Err(WireError::UnsupportedOperation(other.to_owned())),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    Scope {
        #[serde(rename = "scopeId")]
        scope_id: String,
    },
    Session {
        #[serde(rename = "sessionId")]
        session_id: String,
    },
    Run {
        #[serde(rename = "runId")]
        run_id: String,
    },
    Delivery {
        #[serde(rename = "deliveryId")]
        delivery_id: String,
    },
    Question {
        #[serde(rename = "questionId")]
        question_id: String,
    },
    Permission {
        #[serde(rename = "permissionId")]
        permission_id: String,
    },
    Resource {
        #[serde(rename = "podId")]
        pod_id: String,
        #[serde(rename = "resourceId")]
        resource_id: String,
    },
}

impl Target {
    pub fn validate(&self) -> Result<(), WireError> {
        match self {
            Self::Scope { scope_id } => {
                valid_identity(scope_id).map_err(|_| WireError::InvalidField("target.scopeId"))
            }
            Self::Session { session_id } => {
                valid_identity(session_id).map_err(|_| WireError::InvalidField("target.sessionId"))
            }
            Self::Run { run_id } => {
                valid_identity(run_id).map_err(|_| WireError::InvalidField("target.runId"))
            }
            Self::Delivery { delivery_id } => valid_identity(delivery_id)
                .map_err(|_| WireError::InvalidField("target.deliveryId")),
            Self::Question { question_id } => valid_identity(question_id)
                .map_err(|_| WireError::InvalidField("target.questionId")),
            Self::Permission { permission_id } => valid_identity(permission_id)
                .map_err(|_| WireError::InvalidField("target.permissionId")),
            Self::Resource {
                pod_id,
                resource_id,
            } => {
                valid_identity(pod_id).map_err(|_| WireError::InvalidField("target.podId"))?;
                valid_identity(resource_id)
                    .map_err(|_| WireError::InvalidField("target.resourceId"))
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Guard {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manager_epoch: Option<DecimalString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_epoch: Option<DecimalString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_epoch: Option<DecimalString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writer_epoch: Option<DecimalString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_epoch: Option<DecimalString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_revision: Option<DecimalString>,
}

impl Guard {
    fn validate(&self) -> Result<(), WireError> {
        for value in [
            self.manager_epoch,
            self.pod_epoch,
            self.resource_epoch,
            self.writer_epoch,
            self.lease_epoch,
            self.target_revision,
        ]
        .into_iter()
        .flatten()
        {
            if value.get() == 0 {
                return Err(WireError::InvalidField("guard"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContentBlock {
    Text {
        text: String,
    },
    Artifact {
        #[serde(rename = "artifactRef")]
        artifact_ref: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SendPolicy {
    WhenIdle,
    Steer {
        #[serde(rename = "expectedIntervalId")]
        expected_interval_id: String,
    },
    ProviderQueue,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionSendBody {
    pub content: Vec<ContentBlock>,
    pub policy: SendPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionWriterLeaseRenewBody {
    pub expected_writer_epoch: DecimalString,
    pub expected_lease_expires_at_unix_seconds: DecimalString,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PausePolicy {
    Drain,
    InterruptCurrent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunPauseBody {
    pub policy: PausePolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumePolicy {
    LiveOnly,
    ContinueSavedSession,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunResumeBody {
    pub policy: ResumePolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopScope {
    SelfOnly,
    Subtree,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunStopBody {
    pub scope: StopScope,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceAction {
    Write {
        #[serde(rename = "contentRef")]
        content_ref: String,
    },
    Resize {
        columns: DecimalString,
        rows: DecimalString,
    },
    Interrupt,
    Stop,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceCommandBody {
    pub command: ResourceAction,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionChoice {
    New,
    Existing {
        #[serde(rename = "sessionId")]
        session_id: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchRole {
    Coordinator,
    Worker,
    Advisor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkKind {
    Task,
    Service,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskRef {
    pub namespace: String,
    pub id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaunchWork {
    pub kind: WorkKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Vec<ContentBlock>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_ref: Option<TaskRef>,
    pub result_contract_ref: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackPolicy {
    None,
    Approved,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaunchSelection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
    pub fallback: FallbackPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceBinding {
    pub scope_id: String,
    pub relative_cwd: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis_ref: Option<String>,
    pub access: WorkspaceAccess,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestedAuthority {
    pub grant_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaunchLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_seconds: Option<DecimalString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime: Option<crate::LifetimeLimit>,
    pub max_children: DecimalString,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaunchBody {
    pub session: SessionChoice,
    pub role: LaunchRole,
    pub work: LaunchWork,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_run_id: Option<String>,
    pub profile_ref: String,
    pub selection: LaunchSelection,
    pub workspace: WorkspaceBinding,
    pub tool_bundle_refs: Vec<String>,
    pub authority: RequestedAuthority,
    pub limits: LaunchLimits,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCloseBody {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunInterruptBody {
    pub expected_interval_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultDeclaration {
    Succeeded,
    NeedsFollowUp,
    Blocked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunReportBody {
    pub summary: String,
    pub artifact_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub declaration: ResultDeclaration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChildPolicy {
    Join,
    Cancel,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunFinishBody {
    pub child_policy: ChildPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcknowledgementKind {
    Received,
    Processed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeliveryAckBody {
    pub kind: AcknowledgementKind,
    pub evidence_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeliveryCancelBody {
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseHolder {
    Human,
    Automation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlAcquireBody {
    pub expected_lease_epoch: DecimalString,
    pub holder: LeaseHolder,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlReleaseBody {
    pub lease_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalDetachBody {
    pub viewer_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Recipient {
    Superior,
    Human,
    Actor {
        #[serde(rename = "actorId")]
        actor_id: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnswerMode {
    SingleChoice,
    FreeText,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuestionItem {
    pub item_id: String,
    pub prompt: String,
    pub required: bool,
    pub answer_mode: AnswerMode,
    pub options: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuestionAskBody {
    pub recipient: Recipient,
    pub title: String,
    pub context: String,
    pub items: Vec<QuestionItem>,
    pub independent_work_available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_at: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnswerItem {
    pub item_id: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum QuestionResponse {
    Submit { answers: Vec<AnswerItem> },
    Decline { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuestionAnswerBody {
    pub expected_revision: DecimalString,
    pub response: QuestionResponse,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuestionCancelBody {
    pub expected_revision: DecimalString,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionRequestBody {
    pub action: String,
    pub subject_digest: String,
    pub run_id: String,
    pub attempt_id: String,
    pub request_epoch: DecimalString,
    pub grant_duration_seconds: DecimalString,
    pub expires_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PermissionDecision {
    AllowOnce,
    AllowScoped {
        #[serde(rename = "constraintRef")]
        constraint_ref: String,
    },
    Deny,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionDecideBody {
    pub expected_revision: DecimalString,
    pub request_epoch: DecimalString,
    pub decision: PermissionDecision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandBody {
    Launch(LaunchBody),
    SessionClose(SessionCloseBody),
    SessionSend(SessionSendBody),
    SessionWriterLeaseRenew(SessionWriterLeaseRenewBody),
    RunInterrupt(RunInterruptBody),
    RunPause(RunPauseBody),
    RunResume(RunResumeBody),
    RunStop(RunStopBody),
    RunReport(RunReportBody),
    RunFinish(RunFinishBody),
    DeliveryAck(DeliveryAckBody),
    DeliveryCancel(DeliveryCancelBody),
    ControlAcquire(ControlAcquireBody),
    ControlRelease(ControlReleaseBody),
    TerminalDetach(TerminalDetachBody),
    QuestionAsk(QuestionAskBody),
    QuestionAnswer(QuestionAnswerBody),
    QuestionCancel(QuestionCancelBody),
    PermissionRequest(PermissionRequestBody),
    PermissionDecide(PermissionDecideBody),
    ResourceCommand(ResourceCommandBody),
}

impl CommandBody {
    pub const fn operation(&self) -> MutationOperation {
        match self {
            Self::Launch(_) => MutationOperation::Launch,
            Self::SessionClose(_) => MutationOperation::SessionClose,
            Self::SessionSend(_) => MutationOperation::SessionSend,
            Self::SessionWriterLeaseRenew(_) => MutationOperation::SessionWriterLeaseRenew,
            Self::RunInterrupt(_) => MutationOperation::RunInterrupt,
            Self::RunPause(_) => MutationOperation::RunPause,
            Self::RunResume(_) => MutationOperation::RunResume,
            Self::RunStop(_) => MutationOperation::RunStop,
            Self::RunReport(_) => MutationOperation::RunReport,
            Self::RunFinish(_) => MutationOperation::RunFinish,
            Self::DeliveryAck(_) => MutationOperation::DeliveryAck,
            Self::DeliveryCancel(_) => MutationOperation::DeliveryCancel,
            Self::ControlAcquire(_) => MutationOperation::ControlAcquire,
            Self::ControlRelease(_) => MutationOperation::ControlRelease,
            Self::TerminalDetach(_) => MutationOperation::TerminalDetach,
            Self::QuestionAsk(_) => MutationOperation::QuestionAsk,
            Self::QuestionAnswer(_) => MutationOperation::QuestionAnswer,
            Self::QuestionCancel(_) => MutationOperation::QuestionCancel,
            Self::PermissionRequest(_) => MutationOperation::PermissionRequest,
            Self::PermissionDecide(_) => MutationOperation::PermissionDecide,
            Self::ResourceCommand(_) => MutationOperation::ResourceCommand,
        }
    }

    fn to_value(&self) -> Result<Value, WireError> {
        Ok(match self {
            Self::Launch(value) => serde_json::to_value(value)?,
            Self::SessionClose(value) => serde_json::to_value(value)?,
            Self::SessionSend(value) => serde_json::to_value(value)?,
            Self::SessionWriterLeaseRenew(value) => serde_json::to_value(value)?,
            Self::RunInterrupt(value) => serde_json::to_value(value)?,
            Self::RunPause(value) => serde_json::to_value(value)?,
            Self::RunResume(value) => serde_json::to_value(value)?,
            Self::RunStop(value) => serde_json::to_value(value)?,
            Self::RunReport(value) => serde_json::to_value(value)?,
            Self::RunFinish(value) => serde_json::to_value(value)?,
            Self::DeliveryAck(value) => serde_json::to_value(value)?,
            Self::DeliveryCancel(value) => serde_json::to_value(value)?,
            Self::ControlAcquire(value) => serde_json::to_value(value)?,
            Self::ControlRelease(value) => serde_json::to_value(value)?,
            Self::TerminalDetach(value) => serde_json::to_value(value)?,
            Self::QuestionAsk(value) => serde_json::to_value(value)?,
            Self::QuestionAnswer(value) => serde_json::to_value(value)?,
            Self::QuestionCancel(value) => serde_json::to_value(value)?,
            Self::PermissionRequest(value) => serde_json::to_value(value)?,
            Self::PermissionDecide(value) => serde_json::to_value(value)?,
            Self::ResourceCommand(value) => serde_json::to_value(value)?,
        })
    }

    fn from_value(operation: MutationOperation, value: Value) -> Result<Self, WireError> {
        Ok(match operation {
            MutationOperation::Launch => Self::Launch(serde_json::from_value(value)?),
            MutationOperation::SessionClose => Self::SessionClose(serde_json::from_value(value)?),
            MutationOperation::SessionSend => Self::SessionSend(serde_json::from_value(value)?),
            MutationOperation::SessionWriterLeaseRenew =>
                Self::SessionWriterLeaseRenew(serde_json::from_value(value)?),
            MutationOperation::RunInterrupt => Self::RunInterrupt(serde_json::from_value(value)?),
            MutationOperation::RunPause => Self::RunPause(serde_json::from_value(value)?),
            MutationOperation::RunResume => Self::RunResume(serde_json::from_value(value)?),
            MutationOperation::RunStop => Self::RunStop(serde_json::from_value(value)?),
            MutationOperation::RunReport => Self::RunReport(serde_json::from_value(value)?),
            MutationOperation::RunFinish => Self::RunFinish(serde_json::from_value(value)?),
            MutationOperation::DeliveryAck => Self::DeliveryAck(serde_json::from_value(value)?),
            MutationOperation::DeliveryCancel => {
                Self::DeliveryCancel(serde_json::from_value(value)?)
            }
            MutationOperation::ControlAcquire => {
                Self::ControlAcquire(serde_json::from_value(value)?)
            }
            MutationOperation::ControlRelease => {
                Self::ControlRelease(serde_json::from_value(value)?)
            }
            MutationOperation::TerminalDetach => {
                Self::TerminalDetach(serde_json::from_value(value)?)
            }
            MutationOperation::QuestionAsk => Self::QuestionAsk(serde_json::from_value(value)?),
            MutationOperation::QuestionAnswer => {
                Self::QuestionAnswer(serde_json::from_value(value)?)
            }
            MutationOperation::QuestionCancel => {
                Self::QuestionCancel(serde_json::from_value(value)?)
            }
            MutationOperation::PermissionRequest => {
                Self::PermissionRequest(serde_json::from_value(value)?)
            }
            MutationOperation::PermissionDecide => {
                Self::PermissionDecide(serde_json::from_value(value)?)
            }
            MutationOperation::ResourceCommand => {
                Self::ResourceCommand(serde_json::from_value(value)?)
            }
        })
    }

    fn validate(&self) -> Result<(), WireError> {
        match self {
            Self::Launch(body) => {
                if let SessionChoice::Existing { session_id } = &body.session {
                    valid_identity(session_id)
                        .map_err(|_| WireError::InvalidField("body.session.sessionId"))?;
                }
                if let Some(parent) = &body.parent_run_id {
                    valid_identity(parent)
                        .map_err(|_| WireError::InvalidField("body.parentRunId"))?;
                }
                for value in [
                    &body.profile_ref,
                    &body.work.result_contract_ref,
                    &body.workspace.scope_id,
                    &body.authority.grant_ref,
                ] {
                    valid_identity(value).map_err(|_| WireError::InvalidField("body.launchRef"))?;
                }
                if valid_identity(&body.workspace.relative_cwd).is_err()
                    || body.workspace.relative_cwd.starts_with('/')
                    || body.workspace.relative_cwd.contains('\\')
                    || body.workspace.relative_cwd.contains(':')
                    || body
                        .workspace
                        .relative_cwd
                        .split('/')
                        .any(|part| part == ".." || part.is_empty())
                {
                    return Err(WireError::InvalidField("body.workspace.relativeCwd"));
                }
                if let Some(basis) = &body.workspace.basis_ref {
                    valid_identity(basis)
                        .map_err(|_| WireError::InvalidField("body.workspace.basisRef"))?;
                }
                if let Some(model) = &body.selection.model_id {
                    valid_identity(model)
                        .map_err(|_| WireError::InvalidField("body.selection.modelId"))?;
                }
                if let Some(effort) = &body.selection.reasoning_effort {
                    valid_identity(effort)
                        .map_err(|_| WireError::InvalidField("body.selection.reasoningEffort"))?;
                }
                if let Some(task) = &body.work.task_ref {
                    valid_identity(&task.namespace)
                        .map_err(|_| WireError::InvalidField("body.work.taskRef.namespace"))?;
                    valid_identity(&task.id)
                        .map_err(|_| WireError::InvalidField("body.work.taskRef.id"))?;
                }
                if body.work.kind == WorkKind::Task
                    && body.work.input.as_ref().is_none_or(Vec::is_empty)
                {
                    return Err(WireError::InvalidField("body.work.input"));
                }
                if let Some(input) = &body.work.input {
                    validate_content(input)?;
                }
                if body.tool_bundle_refs.len() > 64 {
                    return Err(WireError::InvalidField("body.toolBundleRefs"));
                }
                for tool in &body.tool_bundle_refs {
                    valid_identity(tool)
                        .map_err(|_| WireError::InvalidField("body.toolBundleRefs"))?;
                }
                let valid_lifetime = match (body.limits.wall_seconds, body.limits.lifetime) {
                    (Some(seconds), None) => (1..=604_800).contains(&seconds.get()),
                    (None, Some(crate::LifetimeLimit::UntilStopped)) =>
                        body.role == LaunchRole::Coordinator
                            && body.work.kind == WorkKind::Service
                            && body.parent_run_id.is_none(),
                    _ => false,
                };
                if !valid_lifetime || body.limits.max_children.get() > 1024 {
                    return Err(WireError::InvalidField("body.limits"));
                }
            }
            Self::SessionSend(body) => {
                validate_content(&body.content)?;
                if let SendPolicy::Steer {
                    expected_interval_id,
                } = &body.policy
                {
                    valid_identity(expected_interval_id)
                        .map_err(|_| WireError::InvalidField("body.policy.expectedIntervalId"))?;
                }
            }
            Self::SessionWriterLeaseRenew(body) => {
                if body.expected_writer_epoch.get() == 0
                    || body.expected_lease_expires_at_unix_seconds.get() == 0
                {
                    return Err(WireError::InvalidField("body.writerLease"));
                }
            }
            Self::RunInterrupt(body) => valid_identity(&body.expected_interval_id)
                .map_err(|_| WireError::InvalidField("body.expectedIntervalId"))?,
            Self::RunReport(body) => {
                if body.summary.is_empty()
                    || body.summary.len() > 64_000
                    || body.artifact_refs.len() > 64
                    || body.evidence_refs.len() > 64
                {
                    return Err(WireError::InvalidField("body.report"));
                }
                for reference in body.artifact_refs.iter().chain(body.evidence_refs.iter()) {
                    valid_identity(reference)
                        .map_err(|_| WireError::InvalidField("body.reportRef"))?;
                }
            }
            Self::DeliveryAck(body) => valid_identity(&body.evidence_ref)
                .map_err(|_| WireError::InvalidField("body.evidenceRef"))?,
            Self::DeliveryCancel(body) if body.reason.is_empty() || body.reason.len() > 8_000 => {
                return Err(WireError::InvalidField("body.reason"));
            }
            Self::ControlRelease(body) => valid_identity(&body.lease_id)
                .map_err(|_| WireError::InvalidField("body.leaseId"))?,
            Self::TerminalDetach(body) => valid_identity(&body.viewer_id)
                .map_err(|_| WireError::InvalidField("body.viewerId"))?,
            Self::QuestionAsk(body) => {
                if body.title.is_empty()
                    || body.title.len() > 256
                    || body.context.len() > 64_000
                    || body.items.is_empty()
                    || body.items.len() > 32
                {
                    return Err(WireError::InvalidField("body.question"));
                }
                if let Recipient::Actor { actor_id } = &body.recipient {
                    valid_identity(actor_id)
                        .map_err(|_| WireError::InvalidField("body.recipient.actorId"))?;
                }
                if body
                    .deadline_at
                    .as_ref()
                    .is_some_and(|value| !valid_utc_timestamp(value))
                {
                    return Err(WireError::InvalidField("body.deadlineAt"));
                }
                for item in &body.items {
                    valid_identity(&item.item_id)
                        .map_err(|_| WireError::InvalidField("body.items.itemId"))?;
                    if item.prompt.is_empty() || item.prompt.len() > 8_000 {
                        return Err(WireError::InvalidField("body.items.prompt"));
                    }
                    if (item.answer_mode == AnswerMode::SingleChoice && item.options.is_empty())
                        || (item.answer_mode == AnswerMode::FreeText && !item.options.is_empty())
                        || item.options.len() > 32
                    {
                        return Err(WireError::InvalidField("body.items.options"));
                    }
                    for option in &item.options {
                        if option.is_empty() || option.len() > 1024 {
                            return Err(WireError::InvalidField("body.items.options"));
                        }
                    }
                }
            }
            Self::QuestionAnswer(body) => {
                if body.expected_revision.get() == 0 {
                    return Err(WireError::InvalidField("body.expectedRevision"));
                }
                match &body.response {
                    QuestionResponse::Submit { answers } => {
                        if answers.is_empty() || answers.len() > 32 {
                            return Err(WireError::InvalidField("body.answers"));
                        }
                        for answer in answers {
                            valid_identity(&answer.item_id)
                                .map_err(|_| WireError::InvalidField("body.answers.itemId"))?;
                            if answer.value.is_empty() || answer.value.len() > 8_000 {
                                return Err(WireError::InvalidField("body.answers.value"));
                            }
                        }
                    }
                    QuestionResponse::Decline { reason }
                        if reason.is_empty() || reason.len() > 8_000 =>
                    {
                        return Err(WireError::InvalidField("body.response.reason"));
                    }
                    _ => {}
                }
            }
            Self::QuestionCancel(body)
                if body.expected_revision.get() == 0
                    || body.reason.is_empty()
                    || body.reason.len() > 8_000 =>
            {
                return Err(WireError::InvalidField("body.questionCancel"));
            }
            Self::PermissionRequest(body) => {
                for value in [&body.action, &body.run_id, &body.attempt_id] {
                    valid_identity(value)
                        .map_err(|_| WireError::InvalidField("body.permissionRequest"))?;
                }
                if !is_lower_hex_digest(&body.subject_digest)
                    || body.request_epoch.get() == 0
                    || body.grant_duration_seconds.get() == 0
                    || !valid_utc_timestamp(&body.expires_at)
                {
                    return Err(WireError::InvalidField("body.permissionRequest"));
                }
            }
            Self::PermissionDecide(body) => {
                if body.expected_revision.get() == 0 || body.request_epoch.get() == 0 {
                    return Err(WireError::InvalidField("body.permissionDecision"));
                }
                if let PermissionDecision::AllowScoped { constraint_ref } = &body.decision {
                    valid_identity(constraint_ref)
                        .map_err(|_| WireError::InvalidField("body.decision.constraintRef"))?;
                }
            }
            Self::ResourceCommand(body) => match &body.command {
                ResourceAction::Write { content_ref } => valid_identity(content_ref)
                    .map_err(|_| WireError::InvalidField("body.command.contentRef"))?,
                ResourceAction::Resize { columns, rows }
                    if !(1..=4096).contains(&columns.get())
                        || !(1..=4096).contains(&rows.get()) =>
                {
                    return Err(WireError::InvalidField("body.command.geometry"));
                }
                _ => {}
            },
            _ => {}
        }
        Ok(())
    }
}

fn validate_content(content: &[ContentBlock]) -> Result<(), WireError> {
    if content.is_empty() || content.len() > 64 {
        return Err(WireError::InvalidField("body.content"));
    }
    for block in content {
        match block {
            ContentBlock::Text { text } if text.is_empty() || text.len() > 64_000 => {
                return Err(WireError::InvalidField("body.content.text"));
            }
            ContentBlock::Artifact { artifact_ref } if valid_identity(artifact_ref).is_err() => {
                return Err(WireError::InvalidField("body.content.artifactRef"));
            }
            _ => {}
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandEnvelope {
    pub request_id: String,
    pub key: String,
    pub target: Target,
    pub guard: Option<Guard>,
    pub deadline_at: Option<String>,
    pub body: CommandBody,
    pub payload_digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawCommandEnvelope {
    protocol: ProtocolVersion,
    operation: MutationOperation,
    request_id: String,
    key: String,
    target: Target,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    guard: Option<Guard>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deadline_at: Option<String>,
    payload_digest: String,
    body: Value,
}

impl CommandEnvelope {
    /// Construct through the same strict typed body parser used for inbound commands.
    pub fn new_json(
        request_id: impl Into<String>,
        key: impl Into<String>,
        target: Target,
        guard: Option<Guard>,
        deadline_at: Option<String>,
        operation: MutationOperation,
        body: Value,
    ) -> Result<Self, WireError> {
        Self::new(
            request_id,
            key,
            target,
            guard,
            deadline_at,
            CommandBody::from_value(operation, body)?,
        )
    }

    pub fn new(
        request_id: impl Into<String>,
        key: impl Into<String>,
        target: Target,
        guard: Option<Guard>,
        deadline_at: Option<String>,
        body: CommandBody,
    ) -> Result<Self, WireError> {
        let mut envelope = Self {
            request_id: request_id.into(),
            key: key.into(),
            target,
            guard,
            deadline_at,
            body,
            payload_digest: String::new(),
        };
        envelope.validate()?;
        envelope.payload_digest = command_digest(&envelope)?;
        Ok(envelope)
    }

    pub fn operation(&self) -> MutationOperation {
        self.body.operation()
    }

    pub fn encode_json(&self) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        if command_digest(self)? != self.payload_digest {
            return Err(WireError::DigestMismatch);
        }
        Ok(serde_json::to_vec(&RawCommandEnvelope {
            protocol: ProtocolVersion::V1,
            operation: self.operation(),
            request_id: self.request_id.clone(),
            key: self.key.clone(),
            target: self.target.clone(),
            guard: self.guard.clone(),
            deadline_at: self.deadline_at.clone(),
            payload_digest: self.payload_digest.clone(),
            body: self.body.to_value()?,
        })?)
    }

    fn validate(&self) -> Result<(), WireError> {
        valid_identity(&self.request_id).map_err(|_| WireError::InvalidField("requestId"))?;
        valid_identity(&self.key).map_err(|_| WireError::InvalidField("key"))?;
        self.target.validate()?;
        if let Some(guard) = &self.guard {
            guard.validate()?;
        }
        if self
            .deadline_at
            .as_ref()
            .is_some_and(|value| !valid_utc_timestamp(value))
        {
            return Err(WireError::InvalidField("deadlineAt"));
        }
        let matching_target = matches!(
            (self.operation(), &self.target),
            (MutationOperation::Launch, Target::Scope { .. })
                | (
                    MutationOperation::SessionClose | MutationOperation::SessionSend
                        | MutationOperation::SessionWriterLeaseRenew,
                    Target::Session { .. }
                )
                | (
                    MutationOperation::RunInterrupt
                        | MutationOperation::RunPause
                        | MutationOperation::RunResume
                        | MutationOperation::RunStop
                        | MutationOperation::RunReport
                        | MutationOperation::RunFinish
                        | MutationOperation::QuestionAsk,
                    Target::Run { .. }
                )
                | (
                    MutationOperation::DeliveryAck | MutationOperation::DeliveryCancel,
                    Target::Delivery { .. }
                )
                | (
                    MutationOperation::QuestionAnswer | MutationOperation::QuestionCancel,
                    Target::Question { .. }
                )
                | (
                    MutationOperation::PermissionDecide,
                    Target::Permission { .. }
                )
                | (
                    MutationOperation::ControlAcquire
                        | MutationOperation::ControlRelease
                        | MutationOperation::TerminalDetach
                        | MutationOperation::PermissionRequest
                        | MutationOperation::ResourceCommand,
                    Target::Resource { .. }
                )
        );
        if !matching_target {
            return Err(WireError::InvalidField("target"));
        }
        self.body.validate()
    }
}

pub fn decode_command_json(bytes: &[u8]) -> Result<CommandEnvelope, WireError> {
    if bytes.len() > crate::MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge);
    }
    let value: Value = serde_json::from_slice(bytes)?;
    if value.get("protocol").and_then(Value::as_str) != Some("podbay/1") {
        return Err(WireError::UnsupportedVersion);
    }
    let operation = value
        .get("operation")
        .and_then(Value::as_str)
        .ok_or(WireError::InvalidField("operation"))?;
    MutationOperation::from_wire(operation)?;
    let raw: RawCommandEnvelope = serde_json::from_value(value)?;
    if raw.protocol != ProtocolVersion::V1 {
        return Err(WireError::UnsupportedVersion);
    }
    let envelope = CommandEnvelope {
        request_id: raw.request_id,
        key: raw.key,
        target: raw.target,
        guard: raw.guard,
        deadline_at: raw.deadline_at,
        body: CommandBody::from_value(raw.operation, raw.body)?,
        payload_digest: raw.payload_digest,
    };
    envelope.validate()?;
    if !is_lower_hex_digest(&envelope.payload_digest)
        || command_digest(&envelope)? != envelope.payload_digest
    {
        return Err(WireError::DigestMismatch);
    }
    Ok(envelope)
}

pub fn command_digest(command: &CommandEnvelope) -> Result<String, WireError> {
    let mut fields = BTreeMap::new();
    fields.insert("body", command.body.to_value()?);
    fields.insert("deadlineAt", serde_json::to_value(&command.deadline_at)?);
    fields.insert("guard", serde_json::to_value(&command.guard)?);
    fields.insert(
        "operation",
        Value::String(command.operation().as_str().to_owned()),
    );
    fields.insert("protocol", Value::String("podbay/1".to_owned()));
    fields.insert("target", serde_json::to_value(&command.target)?);
    let canonical = canonical_json(&serde_json::to_value(fields)?)?;
    let digest = Sha256::digest(&canonical);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn canonical_json(value: &Value) -> Result<Vec<u8>, WireError> {
    fn append(value: &Value, output: &mut Vec<u8>) -> Result<(), WireError> {
        match value {
            Value::Null => output.extend_from_slice(b"null"),
            Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
            Value::String(value) => {
                output.extend_from_slice(serde_json::to_string(value)?.as_bytes())
            }
            Value::Number(value) => {
                let safe = if let Some(number) = value.as_i64() {
                    (-(MAX_SAFE_JSON_INTEGER as i64)..=MAX_SAFE_JSON_INTEGER as i64)
                        .contains(&number)
                } else {
                    value
                        .as_u64()
                        .is_some_and(|number| number <= MAX_SAFE_JSON_INTEGER)
                };
                if !safe {
                    return Err(WireError::InvalidCounter);
                }
                output.extend_from_slice(value.to_string().as_bytes());
            }
            Value::Array(values) => {
                output.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    append(value, output)?;
                }
                output.push(b']');
            }
            Value::Object(fields) => {
                output.push(b'{');
                let sorted: BTreeMap<_, _> = fields.iter().collect();
                for (index, (key, value)) in sorted.into_iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    output.extend_from_slice(serde_json::to_string(key)?.as_bytes());
                    output.push(b':');
                    append(value, output)?;
                }
                output.push(b'}');
            }
        }
        Ok(())
    }
    let mut output = Vec::new();
    append(value, &mut output)?;
    Ok(output)
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
