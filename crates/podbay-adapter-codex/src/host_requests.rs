//! Typed, bounded observations of app-server initiated host requests.
//!
//! The accepted answer subset follows the generated Codex 0.159.3 schema.
//! Policy amendments and positive permission grants require a later authority
//! boundary and are intentionally unsupported here.

use std::collections::{BTreeMap, HashSet};
use std::fmt::{Debug, Formatter};

use podbay_core::Epoch;
use serde_json::{Value, json};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeRpcId {
    Number(i64),
    Text(String),
}

impl NativeRpcId {
    pub(crate) fn from_value(value: &Value) -> Option<Self> {
        if let Some(number) = value.as_i64() {
            return Some(Self::Number(number));
        }
        let text = value.as_str()?;
        bounded_nonempty(text, 512).then(|| Self::Text(text.to_owned()))
    }

    pub(crate) fn key(&self) -> String {
        match self {
            Self::Number(number) => format!("n:{number}"),
            Self::Text(text) => format!("s:{text}"),
        }
    }

    pub(crate) fn wire_value(&self) -> Value {
        match self {
            Self::Number(number) => json!(number),
            Self::Text(text) => json!(text),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandApprovalKind {
    Command,
    WriteStdin,
}

#[derive(Clone, Eq, PartialEq)]
pub struct NativeQuestionOption {
    pub label: String,
    pub description: String,
}

impl Debug for NativeQuestionOption {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeQuestionOption")
            .field("label_bytes", &self.label.len())
            .field("description_bytes", &self.description.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct NativeQuestion {
    pub id: String,
    pub header: String,
    pub question: String,
    pub options: Vec<NativeQuestionOption>,
    pub is_secret: bool,
}

impl Debug for NativeQuestion {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeQuestion")
            .field("id", &self.id)
            .field("header_bytes", &self.header.len())
            .field("question_bytes", &self.question.len())
            .field("option_count", &self.options.len())
            .field("is_secret", &self.is_secret)
            .finish()
    }
}

/// Raw values are withheld; this identifies an unsupported request without
/// echoing command text, paths, or secret question content into diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactedNativeObservation {
    pub method: String,
    pub field_names: Vec<String>,
    pub encoded_bytes: usize,
}

#[derive(Clone, Eq, PartialEq)]
pub enum NativeRequestKind {
    CommandExecution {
        approval_kind: CommandApprovalKind,
        approval_id: Option<String>,
        command: Option<String>,
        network_context_present: bool,
    },
    FileChange {
        grant_root: Option<String>,
        reason: Option<String>,
    },
    Permissions {
        requested_file_system: bool,
        requested_network: Option<bool>,
    },
    UserInput {
        is_blocking: bool,
        questions: Vec<NativeQuestion>,
    },
    Unsupported(RedactedNativeObservation),
}

impl Debug for NativeRequestKind {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommandExecution {
                approval_kind,
                approval_id,
                command,
                network_context_present,
            } => formatter
                .debug_struct("CommandExecution")
                .field("approval_kind", approval_kind)
                .field("approval_id_present", &approval_id.is_some())
                .field("command_present", &command.is_some())
                .field("network_context_present", network_context_present)
                .finish(),
            Self::FileChange { grant_root, reason } => formatter
                .debug_struct("FileChange")
                .field("grant_root_present", &grant_root.is_some())
                .field("reason_present", &reason.is_some())
                .finish(),
            Self::Permissions {
                requested_file_system,
                requested_network,
            } => formatter
                .debug_struct("Permissions")
                .field("requested_file_system", requested_file_system)
                .field("requested_network", requested_network)
                .finish(),
            Self::UserInput {
                is_blocking,
                questions,
            } => formatter
                .debug_struct("UserInput")
                .field("is_blocking", is_blocking)
                .field("question_count", &questions.len())
                .finish(),
            Self::Unsupported(observation) => formatter
                .debug_tuple("Unsupported")
                .field(observation)
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeRequestStage {
    Pending,
    AnswerWritten,
    AnswerWriteUncertain,
    ResolvedAwaitingStatus,
}

#[derive(Clone, Eq, PartialEq)]
pub struct PendingNativeRequest {
    pub request_id: NativeRpcId,
    pub native_thread_id: String,
    pub native_turn_id: String,
    pub native_item_id: String,
    pub resource_epoch: Epoch,
    pub kind: NativeRequestKind,
    pub stage: NativeRequestStage,
    pub redacted: RedactedNativeObservation,
}

impl Debug for PendingNativeRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingNativeRequest")
            .field("request_id", &self.request_id)
            .field("native_thread_id", &self.native_thread_id)
            .field("native_turn_id", &self.native_turn_id)
            .field("native_item_id", &self.native_item_id)
            .field("resource_epoch", &self.resource_epoch)
            .field("kind", &self.kind)
            .field("stage", &self.stage)
            .field("redacted", &self.redacted)
            .finish()
    }
}

impl PendingNativeRequest {
    pub(crate) fn key(&self) -> String {
        self.request_id.key()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDecision {
    Accept,
    AcceptForSession,
    Decline,
    Cancel,
}

impl ApprovalDecision {
    fn wire(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::AcceptForSession => "acceptForSession",
            Self::Decline => "decline",
            Self::Cancel => "cancel",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum NativeAnswer {
    CommandDecision(ApprovalDecision),
    CommandExecPolicyAmendmentUnsupported,
    CommandNetworkPolicyAmendmentUnsupported,
    FileDecision(ApprovalDecision),
    PermissionsDenyAll,
    PermissionsGrantUnsupported,
    UserInputAnswers(BTreeMap<String, Vec<String>>),
}

impl Debug for NativeAnswer {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommandDecision(decision) => formatter
                .debug_tuple("CommandDecision")
                .field(decision)
                .finish(),
            Self::CommandExecPolicyAmendmentUnsupported => {
                formatter.write_str("CommandExecPolicyAmendmentUnsupported")
            }
            Self::CommandNetworkPolicyAmendmentUnsupported => {
                formatter.write_str("CommandNetworkPolicyAmendmentUnsupported")
            }
            Self::FileDecision(decision) => formatter
                .debug_tuple("FileDecision")
                .field(decision)
                .finish(),
            Self::PermissionsDenyAll => formatter.write_str("PermissionsDenyAll"),
            Self::PermissionsGrantUnsupported => formatter.write_str("PermissionsGrantUnsupported"),
            Self::UserInputAnswers(answers) => formatter
                .debug_struct("UserInputAnswers")
                .field("question_count", &answers.len())
                .field(
                    "answer_count",
                    &answers.values().map(Vec::len).sum::<usize>(),
                )
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeAnswerError {
    Unsupported,
    WrongKind,
    InvalidShape,
}

pub(crate) fn answer_value(
    request: &PendingNativeRequest,
    answer: &NativeAnswer,
) -> Result<Value, NativeAnswerError> {
    match (&request.kind, answer) {
        (NativeRequestKind::Unsupported(_), _) => Err(NativeAnswerError::Unsupported),
        (
            NativeRequestKind::CommandExecution { .. },
            NativeAnswer::CommandExecPolicyAmendmentUnsupported
            | NativeAnswer::CommandNetworkPolicyAmendmentUnsupported,
        )
        | (NativeRequestKind::Permissions { .. }, NativeAnswer::PermissionsGrantUnsupported) => {
            Err(NativeAnswerError::Unsupported)
        }
        (NativeRequestKind::CommandExecution { .. }, NativeAnswer::CommandDecision(decision)) => {
            Ok(json!({"decision":decision.wire()}))
        }
        (NativeRequestKind::FileChange { .. }, NativeAnswer::FileDecision(decision)) => {
            Ok(json!({"decision":decision.wire()}))
        }
        (NativeRequestKind::Permissions { .. }, NativeAnswer::PermissionsDenyAll) => {
            Ok(json!({"permissions":{},"scope":"turn"}))
        }
        (
            NativeRequestKind::UserInput { questions, .. },
            NativeAnswer::UserInputAnswers(answers),
        ) => {
            if answers.len() != questions.len() {
                return Err(NativeAnswerError::InvalidShape);
            }
            let mut encoded = serde_json::Map::new();
            for question in questions {
                let Some(values) = answers.get(&question.id) else {
                    return Err(NativeAnswerError::InvalidShape);
                };
                if values.len() > 1000 || values.iter().any(|value| value.len() > 100_000) {
                    return Err(NativeAnswerError::InvalidShape);
                }
                encoded.insert(question.id.clone(), json!({"answers":values}));
            }
            Ok(json!({"answers":encoded}))
        }
        _ => Err(NativeAnswerError::WrongKind),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeRequestParseError {
    MissingIdentity,
    InvalidRequestId,
}

pub(crate) fn parse_pending_request(
    event: &Value,
    resource_epoch: Epoch,
) -> Result<PendingNativeRequest, NativeRequestParseError> {
    let id = event
        .get("id")
        .and_then(NativeRpcId::from_value)
        .ok_or(NativeRequestParseError::InvalidRequestId)?;
    let params = event
        .get("params")
        .and_then(Value::as_object)
        .ok_or(NativeRequestParseError::MissingIdentity)?;
    let thread_id = required_string(params.get("threadId"), 512)
        .ok_or(NativeRequestParseError::MissingIdentity)?;
    let turn_id = required_string(params.get("turnId"), 512)
        .ok_or(NativeRequestParseError::MissingIdentity)?;
    let item_id = required_string(params.get("itemId"), 512)
        .ok_or(NativeRequestParseError::MissingIdentity)?;
    let method = event.get("method").and_then(Value::as_str).unwrap_or("");
    let observation = redacted(method, params);
    let kind = match method {
        "item/commandExecution/requestApproval" => parse_command(params),
        "item/fileChange/requestApproval" => parse_file_change(params),
        "item/permissions/requestApproval" => parse_permissions(params),
        "item/tool/requestUserInput" => parse_user_input(params),
        _ => None,
    }
    .unwrap_or_else(|| NativeRequestKind::Unsupported(observation.clone()));
    Ok(PendingNativeRequest {
        request_id: id,
        native_thread_id: thread_id,
        native_turn_id: turn_id,
        native_item_id: item_id,
        resource_epoch,
        kind,
        stage: NativeRequestStage::Pending,
        redacted: observation,
    })
}

fn parse_command(params: &serde_json::Map<String, Value>) -> Option<NativeRequestKind> {
    params.get("startedAtMs")?.as_i64()?;
    let approval_kind = match params.get("kind") {
        None => CommandApprovalKind::Command,
        Some(Value::String(kind)) if kind == "command" => CommandApprovalKind::Command,
        Some(Value::String(kind)) if kind == "writeStdin" => CommandApprovalKind::WriteStdin,
        _ => return None,
    };
    let approval_id = optional_string(params.get("approvalId"), 512)?;
    let command = optional_string(params.get("command"), 1_000_000)?;
    if approval_kind == CommandApprovalKind::WriteStdin && approval_id.is_none() {
        return None;
    }
    let network_context_present = match params.get("networkApprovalContext") {
        None | Some(Value::Null) => false,
        Some(Value::Object(_)) => true,
        _ => return None,
    };
    Some(NativeRequestKind::CommandExecution {
        approval_kind,
        approval_id,
        command,
        network_context_present,
    })
}

fn parse_file_change(params: &serde_json::Map<String, Value>) -> Option<NativeRequestKind> {
    params.get("startedAtMs")?.as_i64()?;
    Some(NativeRequestKind::FileChange {
        grant_root: optional_string(params.get("grantRoot"), 32_768)?,
        reason: optional_string(params.get("reason"), 100_000)?,
    })
}

fn parse_permissions(params: &serde_json::Map<String, Value>) -> Option<NativeRequestKind> {
    params.get("startedAtMs")?.as_i64()?;
    required_string(params.get("cwd"), 32_768)?;
    let requested = params.get("permissions")?.as_object()?;
    if requested
        .keys()
        .any(|key| key != "fileSystem" && key != "network")
    {
        return None;
    }
    let requested_file_system = match requested.get("fileSystem") {
        None | Some(Value::Null) => false,
        Some(Value::Object(_)) => true,
        _ => return None,
    };
    let requested_network = match requested.get("network") {
        None | Some(Value::Null) => None,
        Some(Value::Object(network)) => match network.get("enabled") {
            None | Some(Value::Null) => None,
            Some(Value::Bool(enabled)) => Some(*enabled),
            _ => return None,
        },
        _ => return None,
    };
    Some(NativeRequestKind::Permissions {
        requested_file_system,
        requested_network,
    })
}

fn parse_user_input(params: &serde_json::Map<String, Value>) -> Option<NativeRequestKind> {
    let is_blocking = params.get("isBlocking")?.as_bool()?;
    let requested = params.get("questions")?.as_array()?;
    if requested.is_empty() || requested.len() > 100 {
        return None;
    }
    let mut ids = HashSet::new();
    let mut questions = Vec::with_capacity(requested.len());
    for value in requested {
        let question = value.as_object()?;
        let id = required_string(question.get("id"), 256)?;
        if !ids.insert(id.clone()) {
            return None;
        }
        let header = required_text(question.get("header"), 256)?;
        let text = required_text(question.get("question"), 100_000)?;
        let options = match question.get("options") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) if items.len() <= 1000 => {
                let mut options = Vec::with_capacity(items.len());
                for item in items {
                    let item = item.as_object()?;
                    options.push(NativeQuestionOption {
                        label: required_text(item.get("label"), 10_000)?,
                        description: required_text(item.get("description"), 100_000)?,
                    });
                }
                options
            }
            _ => return None,
        };
        let is_secret = match question.get("isSecret") {
            None => false,
            Some(value) => value.as_bool()?,
        };
        questions.push(NativeQuestion {
            id,
            header,
            question: text,
            options,
            is_secret,
        });
    }
    Some(NativeRequestKind::UserInput {
        is_blocking,
        questions,
    })
}

fn redacted(method: &str, params: &serde_json::Map<String, Value>) -> RedactedNativeObservation {
    let mut field_names: Vec<_> = params.keys().cloned().collect();
    field_names.sort();
    RedactedNativeObservation {
        method: method.to_owned(),
        field_names,
        encoded_bytes: serde_json::to_vec(params).map_or(0, |bytes| bytes.len()),
    }
}

fn required_string(value: Option<&Value>, max: usize) -> Option<String> {
    let text = value?.as_str()?;
    bounded_nonempty(text, max).then(|| text.to_owned())
}

fn required_text(value: Option<&Value>, max: usize) -> Option<String> {
    let text = value?.as_str()?;
    (!text.is_empty() && text.len() <= max).then(|| text.to_owned())
}

fn optional_string(value: Option<&Value>, max: usize) -> Option<Option<String>> {
    match value {
        None | Some(Value::Null) => Some(None),
        Some(Value::String(text)) if text.len() <= max => Some(Some(text.clone())),
        _ => None,
    }
}

fn bounded_nonempty(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && !text.chars().any(char::is_control)
}
