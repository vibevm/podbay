//! Receipts and observational envelopes. Unknown observations remain raw evidence.
use std::collections::BTreeMap;

use podbay_core::{EventId, SourceId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cursor::valid_identity;
use crate::timestamp::valid_utc_timestamp;
use crate::{DecimalString, EventCursor, Target, WireError};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProtocolVersion {
    #[serde(rename = "podbay/1")]
    V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandStage {
    Persisted,
    Blocked,
    Dispatched,
    HostAccepted,
    ProviderInserted,
    ReplyObserved,
    Acknowledged,
    Settled,
    Rejected,
    Uncertain,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt<T> {
    pub protocol: ProtocolVersion,
    pub command_id: String,
    pub state: CommandStage,
    pub value: T,
    pub revision: DecimalString,
    pub cursor: EventCursor,
}

impl<T> Receipt<T> {
    pub fn validate(&self) -> Result<(), WireError> {
        valid_identity(&self.command_id).map_err(|_| WireError::InvalidField("commandId"))?;
        self.cursor.validate_shape()?;
        if self.revision.get() == 0 {
            return Err(WireError::InvalidField("revision"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceIdentity {
    pub source_id: String,
    pub kind: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventEnvelope {
    pub protocol: ProtocolVersion,
    pub event_id: String,
    pub schema: String,
    pub cursor: EventCursor,
    pub source: SourceIdentity,
    pub source_epoch: DecimalString,
    pub source_sequence: DecimalString,
    pub target: Target,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation: Option<String>,
    pub recorded_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<String>,
    pub provenance: String,
    pub payload: Value,
    /// Additive fields are retained byte-semantically as JSON values, never interpreted as grants.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservationKind {
    RunAdmitted,
    DeliveryChanged,
    ProcessExited,
    ReplayGap,
    Unknown(String),
}

impl EventEnvelope {
    pub fn kind(&self) -> ObservationKind {
        let payload_kind = self.payload.get("kind").and_then(Value::as_str);
        if self.schema != "podbay.event/1" {
            return ObservationKind::Unknown(payload_kind.unwrap_or("<missing>").to_owned());
        }
        match payload_kind {
            Some("run_admitted") => ObservationKind::RunAdmitted,
            Some("delivery_changed") => ObservationKind::DeliveryChanged,
            Some("process_exited") => ObservationKind::ProcessExited,
            Some("replay_gap") => ObservationKind::ReplayGap,
            Some(other) => ObservationKind::Unknown(other.to_owned()),
            None => ObservationKind::Unknown("<missing>".to_owned()),
        }
    }

    pub fn validate(&self) -> Result<(), WireError> {
        EventId::try_from(self.event_id.as_str())
            .map_err(|_| WireError::InvalidField("eventId"))?;
        SourceId::try_from(self.source.source_id.as_str())
            .map_err(|_| WireError::InvalidField("source.sourceId"))?;
        valid_identity(&self.source.kind).map_err(|_| WireError::InvalidField("source.kind"))?;
        self.cursor.validate_shape()?;
        self.target.validate()?;
        valid_identity(&self.schema).map_err(|_| WireError::InvalidField("schema"))?;
        if self.source_epoch.get() == 0 || self.source_sequence.get() == 0 {
            return Err(WireError::InvalidCounter);
        }
        if !valid_utc_timestamp(&self.recorded_at)
            || self
                .occurred_at
                .as_ref()
                .is_some_and(|value| !valid_utc_timestamp(value))
        {
            return Err(WireError::InvalidField("recordedAt/occurredAt"));
        }
        if self.provenance.is_empty() {
            return Err(WireError::InvalidField("provenance"));
        }
        if !self.payload.is_object() {
            return Err(WireError::InvalidField("payload"));
        }
        Ok(())
    }
}

pub fn decode_event_json(bytes: &[u8]) -> Result<EventEnvelope, WireError> {
    if bytes.len() > crate::MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge);
    }
    let value: Value = serde_json::from_slice(bytes)?;
    if value.get("protocol").and_then(Value::as_str) != Some("podbay/1") {
        return Err(WireError::UnsupportedVersion);
    }
    let event: EventEnvelope = serde_json::from_value(value)?;
    event.validate()?;
    Ok(event)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotEnvelope<T> {
    pub protocol: ProtocolVersion,
    pub scope_id: String,
    pub state: T,
    pub revision: DecimalString,
    pub cursor: EventCursor,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl<T> SnapshotEnvelope<T> {
    pub fn validate(&self) -> Result<(), WireError> {
        self.cursor.validate_shape()?;
        if self.scope_id != self.cursor.scope_id {
            return Err(WireError::ForeignScope);
        }
        if self.revision.get() == 0 {
            return Err(WireError::InvalidField("revision"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilitySupport {
    Supported,
    Conditional,
    Unsupported,
    Unverified,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capability {
    pub operation: String,
    /// Raw value is retained. Unrecognized values never confer support.
    pub support: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Capability {
    pub fn effective_support(&self) -> CapabilitySupport {
        match self.support.as_str() {
            "supported" => CapabilitySupport::Supported,
            "conditional" => CapabilitySupport::Conditional,
            "unsupported" => CapabilitySupport::Unsupported,
            _ => CapabilitySupport::Unverified,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityEnvelope {
    pub protocol: ProtocolVersion,
    pub implementation_id: String,
    pub scope_id: String,
    pub revision: DecimalString,
    pub capabilities: Vec<Capability>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl CapabilityEnvelope {
    pub fn validate(&self) -> Result<(), WireError> {
        valid_identity(&self.implementation_id)
            .map_err(|_| WireError::InvalidField("implementationId"))?;
        valid_identity(&self.scope_id).map_err(|_| WireError::InvalidField("scopeId"))?;
        if self.revision.get() == 0 {
            return Err(WireError::InvalidField("revision"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeErrorCode {
    InvalidInput,
    Unsupported,
    Forbidden,
    Conflict,
    StaleGuard,
    Busy,
    ExternalWriter,
    Unavailable,
    Uncertain,
    StorageFailure,
    DeadlineExceeded,
    LimitExceeded,
    ReplayGap,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeError {
    pub code: RuntimeErrorCode,
    pub message: String,
    pub retry: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ErrorEnvelope {
    pub protocol: ProtocolVersion,
    pub request_id: String,
    pub error: RuntimeError,
}

/// Successful exchange wrapper. RequestId belongs to this transport exchange;
/// a contained receipt's CommandId belongs to the durable logical mutation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SuccessEnvelope<T> {
    pub protocol: ProtocolVersion,
    pub request_id: String,
    pub ok: T,
}

impl<T> SuccessEnvelope<T> {
    pub fn validate(&self) -> Result<(), WireError> {
        valid_identity(&self.request_id).map_err(|_| WireError::InvalidField("requestId"))
    }
}

impl ErrorEnvelope {
    pub fn validate(&self) -> Result<(), WireError> {
        valid_identity(&self.request_id).map_err(|_| WireError::InvalidField("requestId"))?;
        if self.error.message.is_empty() || self.error.message.len() > 1024 {
            return Err(WireError::InvalidField("error.message"));
        }
        if let Some(command_id) = &self.error.command_id {
            valid_identity(command_id).map_err(|_| WireError::InvalidField("error.commandId"))?;
        }
        Ok(())
    }
}
