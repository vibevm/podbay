use std::error::Error;
use std::fmt;

/// The caller supplies canonical request bytes; this store hashes those exact bytes.
/// Semantic JSON normalization belongs to the PB03 wire layer.
pub const DIGEST_VERSION: &str = "pb04-request-bytes/1";

/// Principal identity supplied only by an authenticated manager boundary.
/// This constructor is deliberately named to make that trust step visible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPrincipal(String);

impl VerifiedPrincipal {
    pub fn from_authenticated_boundary(value: &str) -> Result<Self, StoreError> {
        if value.len() < 3 || value.len() > 160 || value.chars().any(char::is_control) {
            return Err(StoreError::InvalidInput(
                "verified principal identity is invalid",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct CommandRequest {
    pub principal: VerifiedPrincipal,
    pub namespace: String,
    pub command_key: String,
    pub scope_id: String,
    pub target_id: String,
    pub expected_owner_epoch: u64,
    pub expected_target_epoch: u64,
    pub canonical_request: Vec<u8>,
    pub event_kind: String,
    pub event_payload: Vec<u8>,
    pub effect_kind: String,
    pub effect_payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    /// Stable opaque identity; the SQLite command_rowid is never public.
    pub command_id: String,
    pub event_sequence: i64,
    pub outbox_id: i64,
    pub digest_version: &'static str,
    pub request_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Admission {
    Committed(Receipt),
    Duplicate(Receipt),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedEvent {
    pub sequence: i64,
    pub command_id: String,
    pub kind: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeSnapshot {
    /// Global committed event sequence, captured in the same read transaction.
    pub cursor: EventCursor,
    pub receipts: Vec<Receipt>,
}

/// An event position is valid only for the store and scope that produced it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventCursor {
    pub store_lineage: String,
    pub scope_id: String,
    pub sequence: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectState {
    Prepared,
    /// A claim was committed before the external effect; after a crash its outcome is unknown.
    ClaimedUncertain,
    Observed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectClaim {
    NewClaim,
    ExistingUncertain,
    AlreadyObserved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectObservation {
    NewObservation,
    AlreadyObserved,
}

/// Durable dispatch material. Admission epochs remain unchanged after takeover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredEffect {
    pub outbox_id: i64,
    pub command_id: String,
    pub scope_id: String,
    pub target_id: String,
    pub admission_owner_epoch: u64,
    pub admission_target_epoch: u64,
    pub kind: String,
    pub payload: Vec<u8>,
    pub state: EffectState,
    pub claim_key: Option<String>,
    pub claim_owner_epoch: Option<u64>,
    pub observation_key: Option<String>,
    pub observation_payload: Option<Vec<u8>>,
}

#[derive(Debug)]
pub enum StoreError {
    InvalidInput(&'static str),
    Conflict(&'static str),
    StaleEpoch,
    TargetReconciliationRequired,
    WrongScope,
    WrongCursor,
    UnsupportedEffectKind,
    NotFound,
    UnsupportedSchema(i64),
    Storage(rusqlite::Error),
    Io(std::io::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => write!(formatter, "invalid store input: {message}"),
            Self::Conflict(message) => write!(formatter, "store identity conflict: {message}"),
            Self::StaleEpoch => write!(formatter, "owner or target epoch is stale"),
            Self::TargetReconciliationRequired => {
                write!(
                    formatter,
                    "prepared effect targets an older target incarnation"
                )
            }
            Self::WrongScope => write!(formatter, "effect belongs to another scope or target"),
            Self::WrongCursor => {
                write!(formatter, "event cursor belongs to another store or scope")
            }
            Self::UnsupportedEffectKind => write!(formatter, "effect kind is unsupported"),
            Self::NotFound => write!(formatter, "durable record was not found"),
            Self::UnsupportedSchema(version) => {
                write!(formatter, "unsupported store schema {version}")
            }
            Self::Storage(error) => write!(formatter, "SQLite store operation failed: {error}"),
            Self::Io(error) => write!(formatter, "store filesystem operation failed: {error}"),
        }
    }
}

impl Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error)
    }
}

impl From<std::io::Error> for StoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
