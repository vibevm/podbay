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
    #[serde(rename = "session.send")]
    SessionSend,
    #[serde(rename = "run.pause")]
    RunPause,
    #[serde(rename = "run.resume")]
    RunResume,
    #[serde(rename = "run.stop")]
    RunStop,
    #[serde(rename = "resource.command")]
    ResourceCommand,
}

impl MutationOperation {
    pub const SUPPORTED: [Self; 5] = [
        Self::SessionSend,
        Self::RunPause,
        Self::RunResume,
        Self::RunStop,
        Self::ResourceCommand,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionSend => "session.send",
            Self::RunPause => "run.pause",
            Self::RunResume => "run.resume",
            Self::RunStop => "run.stop",
            Self::ResourceCommand => "resource.command",
        }
    }

    fn from_wire(value: &str) -> Result<Self, WireError> {
        match value {
            "session.send" => Ok(Self::SessionSend),
            "run.pause" => Ok(Self::RunPause),
            "run.resume" => Ok(Self::RunResume),
            "run.stop" => Ok(Self::RunStop),
            "resource.command" => Ok(Self::ResourceCommand),
            other => Err(WireError::UnsupportedOperation(other.to_owned())),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    Session {
        #[serde(rename = "sessionId")]
        session_id: String,
    },
    Run {
        #[serde(rename = "runId")]
        run_id: String,
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
            Self::Session { session_id } => {
                valid_identity(session_id).map_err(|_| WireError::InvalidField("target.sessionId"))
            }
            Self::Run { run_id } => {
                valid_identity(run_id).map_err(|_| WireError::InvalidField("target.runId"))
            }
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandBody {
    SessionSend(SessionSendBody),
    RunPause(RunPauseBody),
    RunResume(RunResumeBody),
    RunStop(RunStopBody),
    ResourceCommand(ResourceCommandBody),
}

impl CommandBody {
    pub const fn operation(&self) -> MutationOperation {
        match self {
            Self::SessionSend(_) => MutationOperation::SessionSend,
            Self::RunPause(_) => MutationOperation::RunPause,
            Self::RunResume(_) => MutationOperation::RunResume,
            Self::RunStop(_) => MutationOperation::RunStop,
            Self::ResourceCommand(_) => MutationOperation::ResourceCommand,
        }
    }

    fn to_value(&self) -> Result<Value, WireError> {
        Ok(match self {
            Self::SessionSend(value) => serde_json::to_value(value)?,
            Self::RunPause(value) => serde_json::to_value(value)?,
            Self::RunResume(value) => serde_json::to_value(value)?,
            Self::RunStop(value) => serde_json::to_value(value)?,
            Self::ResourceCommand(value) => serde_json::to_value(value)?,
        })
    }

    fn from_value(operation: MutationOperation, value: Value) -> Result<Self, WireError> {
        Ok(match operation {
            MutationOperation::SessionSend => Self::SessionSend(serde_json::from_value(value)?),
            MutationOperation::RunPause => Self::RunPause(serde_json::from_value(value)?),
            MutationOperation::RunResume => Self::RunResume(serde_json::from_value(value)?),
            MutationOperation::RunStop => Self::RunStop(serde_json::from_value(value)?),
            MutationOperation::ResourceCommand => {
                Self::ResourceCommand(serde_json::from_value(value)?)
            }
        })
    }

    fn validate(&self) -> Result<(), WireError> {
        match self {
            Self::SessionSend(body) => {
                if body.content.is_empty() || body.content.len() > 64 {
                    return Err(WireError::InvalidField("body.content"));
                }
                for block in &body.content {
                    match block {
                        ContentBlock::Text { text } if text.is_empty() || text.len() > 64_000 => {
                            return Err(WireError::InvalidField("body.content.text"));
                        }
                        ContentBlock::Artifact { artifact_ref }
                            if valid_identity(artifact_ref).is_err() =>
                        {
                            return Err(WireError::InvalidField("body.content.artifactRef"));
                        }
                        _ => {}
                    }
                }
                if let SendPolicy::Steer {
                    expected_interval_id,
                } = &body.policy
                {
                    valid_identity(expected_interval_id)
                        .map_err(|_| WireError::InvalidField("body.policy.expectedIntervalId"))?;
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
            (MutationOperation::SessionSend, Target::Session { .. })
                | (
                    MutationOperation::RunPause
                        | MutationOperation::RunResume
                        | MutationOperation::RunStop,
                    Target::Run { .. }
                )
                | (MutationOperation::ResourceCommand, Target::Resource { .. })
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
