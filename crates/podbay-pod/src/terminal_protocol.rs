//! Portable terminal command and observation contract. No OS process handles.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreenFidelity {
    Partial { reason: String },
    Unknown { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScreenCheckpoint {
    pub parser_version: String,
    pub revision: u64,
    pub through: u64,
    pub source_byte_position: u64,
    pub rows: u16,
    pub cols: u16,
    pub cursor_row: u16,
    pub cursor_col: u16,
    pub alternate_screen: bool,
    pub plain_text: String,
    pub formatted_bytes: Vec<u8>,
    pub fidelity: ScreenFidelity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TerminalView {
    pub resource_id: String,
    pub incarnation: u64,
    pub screen: ScreenCheckpoint,
    pub through: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TerminalEventKind {
    Output {
        bytes: Vec<u8>,
        source_byte_position: u64,
    },
    Resize {
        rows: u16,
        cols: u16,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TerminalEvent {
    pub sequence: u64,
    pub resource_id: String,
    pub incarnation: u64,
    pub value: TerminalEventKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TerminalEventPage {
    pub events: Vec<TerminalEvent>,
    pub through: u64,
    pub next_cursor: u64,
    pub has_more: bool,
    pub gap: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TerminalCommand {
    Attach {
        resource_id: String,
        incarnation: u64,
    },
    Events {
        resource_id: String,
        incarnation: u64,
        after: u64,
        limit: usize,
    },
    Acquire {
        resource_id: String,
        incarnation: u64,
        actor_id: String,
        holder: LeaseKind,
        expected_epoch: u64,
        ttl_ms: u64,
    },
    Write {
        #[serde(default)]
        command_id: Option<String>,
        resource_id: String,
        incarnation: u64,
        actor_id: String,
        lease_id: String,
        epoch: u64,
        bytes: Vec<u8>,
    },
    Resize {
        #[serde(default)]
        command_id: Option<String>,
        resource_id: String,
        incarnation: u64,
        actor_id: String,
        lease_id: String,
        epoch: u64,
        rows: u16,
        cols: u16,
    },
    Release {
        resource_id: String,
        incarnation: u64,
        actor_id: String,
        lease_id: String,
        epoch: u64,
    },
}

impl TerminalCommand {
    pub fn resource(&self) -> (&str, u64) {
        match self {
            Self::Attach {
                resource_id,
                incarnation,
            }
            | Self::Events {
                resource_id,
                incarnation,
                ..
            }
            | Self::Acquire {
                resource_id,
                incarnation,
                ..
            }
            | Self::Write {
                resource_id,
                incarnation,
                ..
            }
            | Self::Resize {
                resource_id,
                incarnation,
                ..
            }
            | Self::Release {
                resource_id,
                incarnation,
                ..
            } => (resource_id, *incarnation),
        }
    }
    pub fn read_only(&self) -> bool {
        matches!(self, Self::Attach { .. } | Self::Events { .. })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TerminalReply {
    View { value: TerminalView },
    Events { value: TerminalEventPage },
    Lease { value: InputLease },
    BytesWritten,
    Resized { through: u64 },
    Released { epoch: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseKind {
    Automation,
    Human,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InputLease {
    pub lease_id: String,
    pub resource_id: String,
    pub incarnation: u64,
    pub actor_id: String,
    pub kind: LeaseKind,
    pub epoch: u64,
    pub expires_at_ms: u64,
}
