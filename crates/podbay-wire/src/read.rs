//! Strict read requests. RequestId correlates an exchange; reads carry no mutation key.
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cursor::valid_identity;
use crate::{DecimalString, EventCursor, ProtocolVersion, Target, WireError};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ReadOperation {
    #[serde(rename = "capabilities.get")]
    CapabilitiesGet,
    #[serde(rename = "commands.get")]
    CommandsGet,
    #[serde(rename = "run.get")]
    RunGet,
    #[serde(rename = "session.get")]
    SessionGet,
    #[serde(rename = "delivery.get")]
    DeliveryGet,
    #[serde(rename = "snapshot.get")]
    SnapshotGet,
    #[serde(rename = "event.subscribe")]
    EventsSubscribe,
    #[serde(rename = "history.read")]
    HistoryRead,
    #[serde(rename = "terminal.snapshot")]
    TerminalSnapshot,
    #[serde(rename = "terminal.attach")]
    TerminalAttach,
    #[serde(rename = "terminal.observe")]
    TerminalObserve,
}

impl ReadOperation {
    pub const SUPPORTED: [Self; 11] = [
        Self::CapabilitiesGet,
        Self::CommandsGet,
        Self::RunGet,
        Self::SessionGet,
        Self::DeliveryGet,
        Self::SnapshotGet,
        Self::EventsSubscribe,
        Self::HistoryRead,
        Self::TerminalSnapshot,
        Self::TerminalAttach,
        Self::TerminalObserve,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CapabilitiesGet => "capabilities.get",
            Self::CommandsGet => "commands.get",
            Self::RunGet => "run.get",
            Self::SessionGet => "session.get",
            Self::DeliveryGet => "delivery.get",
            Self::SnapshotGet => "snapshot.get",
            Self::EventsSubscribe => "event.subscribe",
            Self::HistoryRead => "history.read",
            Self::TerminalSnapshot => "terminal.snapshot",
            Self::TerminalAttach => "terminal.attach",
            Self::TerminalObserve => "terminal.observe",
        }
    }

    fn from_wire(value: &str) -> Result<Self, WireError> {
        Self::SUPPORTED
            .iter()
            .copied()
            .find(|item| item.as_str() == value)
            .ok_or_else(|| WireError::UnsupportedOperation(value.to_owned()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyReadBody {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandSelector {
    Id {
        #[serde(rename = "commandId")]
        command_id: String,
    },
    Key {
        key: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandsGetBody {
    pub selector: CommandSelector,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsSubscribeBody {
    pub after: EventCursor,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryReadBody {
    pub after: EventCursor,
    pub limit: DecimalString,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalObserveBody {
    pub after: DecimalString,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalAttachBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<DecimalString>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadBody {
    CapabilitiesGet(EmptyReadBody),
    CommandsGet(CommandsGetBody),
    RunGet(EmptyReadBody),
    SessionGet(EmptyReadBody),
    DeliveryGet(EmptyReadBody),
    SnapshotGet(EmptyReadBody),
    EventsSubscribe(EventsSubscribeBody),
    HistoryRead(HistoryReadBody),
    TerminalSnapshot(EmptyReadBody),
    TerminalAttach(TerminalAttachBody),
    TerminalObserve(TerminalObserveBody),
}

impl ReadBody {
    pub const fn operation(&self) -> ReadOperation {
        match self {
            Self::CapabilitiesGet(_) => ReadOperation::CapabilitiesGet,
            Self::CommandsGet(_) => ReadOperation::CommandsGet,
            Self::RunGet(_) => ReadOperation::RunGet,
            Self::SessionGet(_) => ReadOperation::SessionGet,
            Self::DeliveryGet(_) => ReadOperation::DeliveryGet,
            Self::SnapshotGet(_) => ReadOperation::SnapshotGet,
            Self::EventsSubscribe(_) => ReadOperation::EventsSubscribe,
            Self::HistoryRead(_) => ReadOperation::HistoryRead,
            Self::TerminalSnapshot(_) => ReadOperation::TerminalSnapshot,
            Self::TerminalAttach(_) => ReadOperation::TerminalAttach,
            Self::TerminalObserve(_) => ReadOperation::TerminalObserve,
        }
    }

    fn to_value(&self) -> Result<Value, WireError> {
        Ok(match self {
            Self::CapabilitiesGet(value)
            | Self::RunGet(value)
            | Self::SessionGet(value)
            | Self::DeliveryGet(value)
            | Self::SnapshotGet(value)
            | Self::TerminalSnapshot(value) => serde_json::to_value(value)?,
            Self::CommandsGet(value) => serde_json::to_value(value)?,
            Self::EventsSubscribe(value) => serde_json::to_value(value)?,
            Self::HistoryRead(value) => serde_json::to_value(value)?,
            Self::TerminalAttach(value) => serde_json::to_value(value)?,
            Self::TerminalObserve(value) => serde_json::to_value(value)?,
        })
    }

    fn from_value(operation: ReadOperation, value: Value) -> Result<Self, WireError> {
        Ok(match operation {
            ReadOperation::CapabilitiesGet => Self::CapabilitiesGet(serde_json::from_value(value)?),
            ReadOperation::CommandsGet => Self::CommandsGet(serde_json::from_value(value)?),
            ReadOperation::RunGet => Self::RunGet(serde_json::from_value(value)?),
            ReadOperation::SessionGet => Self::SessionGet(serde_json::from_value(value)?),
            ReadOperation::DeliveryGet => Self::DeliveryGet(serde_json::from_value(value)?),
            ReadOperation::SnapshotGet => Self::SnapshotGet(serde_json::from_value(value)?),
            ReadOperation::EventsSubscribe => Self::EventsSubscribe(serde_json::from_value(value)?),
            ReadOperation::HistoryRead => Self::HistoryRead(serde_json::from_value(value)?),
            ReadOperation::TerminalSnapshot => {
                Self::TerminalSnapshot(serde_json::from_value(value)?)
            }
            ReadOperation::TerminalAttach => Self::TerminalAttach(serde_json::from_value(value)?),
            ReadOperation::TerminalObserve => Self::TerminalObserve(serde_json::from_value(value)?),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadEnvelope {
    pub request_id: String,
    pub target: Target,
    pub body: ReadBody,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawReadEnvelope {
    protocol: ProtocolVersion,
    operation: ReadOperation,
    request_id: String,
    target: Target,
    body: Value,
}

impl ReadEnvelope {
    /// Construct through the strict typed read body parser.
    pub fn new_json(
        request_id: impl Into<String>,
        target: Target,
        operation: ReadOperation,
        body: Value,
    ) -> Result<Self, WireError> {
        Self::new(request_id, target, ReadBody::from_value(operation, body)?)
    }

    pub fn new(
        request_id: impl Into<String>,
        target: Target,
        body: ReadBody,
    ) -> Result<Self, WireError> {
        let request = Self {
            request_id: request_id.into(),
            target,
            body,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn operation(&self) -> ReadOperation {
        self.body.operation()
    }

    pub fn encode_json(&self) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        Ok(serde_json::to_vec(&RawReadEnvelope {
            protocol: ProtocolVersion::V1,
            operation: self.operation(),
            request_id: self.request_id.clone(),
            target: self.target.clone(),
            body: self.body.to_value()?,
        })?)
    }

    fn validate(&self) -> Result<(), WireError> {
        valid_identity(&self.request_id).map_err(|_| WireError::InvalidField("requestId"))?;
        self.target.validate()?;
        let matching_target = matches!(
            (self.operation(), &self.target),
            (
                ReadOperation::CapabilitiesGet
                    | ReadOperation::CommandsGet
                    | ReadOperation::SnapshotGet
                    | ReadOperation::EventsSubscribe
                    | ReadOperation::HistoryRead,
                Target::Scope { .. }
            ) | (ReadOperation::RunGet, Target::Run { .. })
                | (ReadOperation::SessionGet, Target::Session { .. })
                | (ReadOperation::DeliveryGet, Target::Delivery { .. })
                | (
                    ReadOperation::TerminalSnapshot
                        | ReadOperation::TerminalAttach
                        | ReadOperation::TerminalObserve,
                    Target::Resource { .. }
                )
        );
        if !matching_target {
            return Err(WireError::InvalidField("target"));
        }
        match &self.body {
            ReadBody::CommandsGet(body) => match &body.selector {
                CommandSelector::Id { command_id } => valid_identity(command_id)
                    .map_err(|_| WireError::InvalidField("body.selector.commandId"))?,
                CommandSelector::Key { key } => {
                    valid_identity(key).map_err(|_| WireError::InvalidField("body.selector.key"))?
                }
            },
            ReadBody::EventsSubscribe(body) => validate_cursor_scope(&body.after, &self.target)?,
            ReadBody::HistoryRead(body) => {
                validate_cursor_scope(&body.after, &self.target)?;
                if !(1..=1024).contains(&body.limit.get()) {
                    return Err(WireError::InvalidField("body.limit"));
                }
            }
            ReadBody::TerminalObserve(body) => {
                body.after.try_i64()?;
            }
            ReadBody::TerminalAttach(body) => {
                if let Some(after) = body.after {
                    after.try_i64()?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn validate_cursor_scope(cursor: &EventCursor, target: &Target) -> Result<(), WireError> {
    cursor.validate_shape()?;
    if let Target::Scope { scope_id } = target {
        if cursor.scope_id != *scope_id {
            return Err(WireError::ForeignScope);
        }
    }
    Ok(())
}

pub fn decode_read_json(bytes: &[u8]) -> Result<ReadEnvelope, WireError> {
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
    ReadOperation::from_wire(operation)?;
    let raw: RawReadEnvelope = serde_json::from_value(value)?;
    let request = ReadEnvelope {
        request_id: raw.request_id,
        target: raw.target,
        body: ReadBody::from_value(raw.operation, raw.body)?,
    };
    request.validate()?;
    Ok(request)
}
