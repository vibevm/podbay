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
    pub event_id: String,
    pub cursor: EventCursor,
    pub schema_version: u32,
    pub command_id: String,
    pub target_id: String,
    pub source_id: String,
    pub source_kind: String,
    pub source_epoch: u64,
    pub source_sequence: u64,
    pub source_order: SourceOrder,
    pub recorded_at: String,
    pub occurred_at: Option<String>,
    pub provenance: String,
    pub correlation_id: Option<String>,
    pub causation_id: Option<String>,
    pub kind: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceOrder {
    Contiguous,
    Gap { expected_next: u64 },
    OutOfOrder { highest_seen: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceAnomaly {
    pub event_id: String,
    pub source_id: String,
    pub source_epoch: u64,
    pub source_sequence: u64,
    pub order: SourceOrder,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeSnapshot {
    /// Global committed event sequence, captured in the same read transaction.
    pub cursor: EventCursor,
    pub receipts: Vec<Receipt>,
    pub effects: Vec<StoredEffect>,
    pub source_anomalies: Vec<SourceAnomaly>,
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
    /// Some evidence was recorded; inspect observed_stage before drawing a conclusion.
    Observed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservedStage {
    HostAccepted,
    /// Schema-two evidence did not identify an authenticated source or proof type.
    LegacyUnverified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectClaim {
    NewClaim,
    ExistingUncertain,
    AlreadyObserved,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectObservation {
    NewObservation(EventReference),
    AlreadyObserved(EventReference),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventReference {
    pub event_id: String,
    pub cursor: EventCursor,
}

/// A host acknowledgement, asserted only by the authenticated host boundary.
/// It does not establish provider insertion, a reply, or task completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostAcceptanceProof {
    pub(crate) source_id: String,
    pub(crate) source_epoch: u64,
    pub(crate) source_sequence: u64,
    pub(crate) host_receipt_id: String,
    pub(crate) evidence: Vec<u8>,
    pub(crate) occurred_at: Option<String>,
    pub(crate) correlation_id: String,
    pub(crate) causation_id: Option<String>,
}

impl HostAcceptanceProof {
    #[allow(clippy::too_many_arguments)]
    pub fn from_authenticated_host_boundary(
        source_id: &str,
        source_epoch: u64,
        source_sequence: u64,
        host_receipt_id: &str,
        evidence: &[u8],
        occurred_at: Option<&str>,
        correlation_id: &str,
        causation_id: Option<&str>,
    ) -> Result<Self, StoreError> {
        valid_proof_id(source_id)?;
        valid_proof_id(host_receipt_id)?;
        valid_proof_id(correlation_id)?;
        if let Some(value) = causation_id {
            valid_proof_id(value)?;
        }
        if source_epoch == 0
            || source_sequence == 0
            || source_epoch > i64::MAX as u64
            || source_sequence >= i64::MAX as u64
        {
            return Err(StoreError::InvalidInput(
                "host source epoch or sequence is invalid",
            ));
        }
        if evidence.is_empty() || evidence.len() > 1_048_576 {
            return Err(StoreError::InvalidInput("host evidence size is invalid"));
        }
        if let Some(value) = occurred_at {
            if !valid_utc_timestamp(value) {
                return Err(StoreError::InvalidInput("host occurrence time is invalid"));
            }
        }
        Ok(Self {
            source_id: source_id.to_owned(),
            source_epoch,
            source_sequence,
            host_receipt_id: host_receipt_id.to_owned(),
            evidence: evidence.to_vec(),
            occurred_at: occurred_at.map(str::to_owned),
            correlation_id: correlation_id.to_owned(),
            causation_id: causation_id.map(str::to_owned),
        })
    }
}

fn valid_proof_id(value: &str) -> Result<(), StoreError> {
    if value.len() < 3
        || value.len() > 160
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(StoreError::InvalidInput("host proof identity is invalid"));
    }
    Ok(())
}

fn valid_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20 || bytes.len() > 30 {
        return false;
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[bytes.len() - 1] != b'Z'
    {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || index == bytes.len() - 1 {
            continue;
        }
        if !byte.is_ascii_digit() {
            return false;
        }
    }
    if bytes.len() == 20 {
        if bytes[19] != b'Z' {
            return false;
        }
    } else if bytes[19] != b'.' || bytes.len() < 22 {
        return false;
    }
    let decimal = |slice: &[u8]| {
        slice
            .iter()
            .fold(0_u32, |number, byte| number * 10 + u32::from(byte - b'0'))
    };
    let year = decimal(&bytes[0..4]);
    let month = decimal(&bytes[5..7]);
    let day = decimal(&bytes[8..10]);
    let hour = decimal(&bytes[11..13]);
    let minute = decimal(&bytes[14..16]);
    let second = decimal(&bytes[17..19]);
    if year == 0 || hour > 23 || minute > 59 || second > 60 {
        return false;
    }
    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let last_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => return false,
    };
    (1..=last_day).contains(&day)
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
    pub observed_stage: Option<ObservedStage>,
    pub observation_event_sequence: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantinedSourceEvent {
    pub quarantine_id: i64,
    pub scope_id: String,
    pub source_id: String,
    pub source_epoch: u64,
    pub source_sequence: u64,
    pub existing_event_id: String,
    pub incoming_digest: String,
    pub incoming_payload: Vec<u8>,
    pub incoming_evidence: Vec<u8>,
    pub recorded_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityPodRecord {
    pub scope_id: String,
    pub pod_id: String,
    pub incarnation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityResourceRecord {
    pub scope_id: String,
    pub resource_id: String,
    pub pod_id: String,
    pub pod_incarnation: u64,
    pub resource_epoch: u64,
    pub input_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityActorRecord {
    pub scope_id: String,
    pub actor_id: String,
    pub role: String,
    pub origin: String,
    pub parent_actor_id: Option<String>,
    pub pod_id: Option<String>,
    pub pod_incarnation: Option<u64>,
    pub credential_generation: u64,
    pub platform: String,
    pub os_identity: String,
    pub process_identity: String,
    pub start_identity: u64,
    pub containment_identity: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityRightRecord {
    pub operation: String,
    pub target_kind: String,
    pub target_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityGrantRecord {
    pub grant_id: u64,
    pub scope_id: String,
    pub actor_id: String,
    pub credential_generation: u64,
    pub mode: String,
    pub remaining_delegation_depth: u8,
    pub rights: Vec<AuthorityRightRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthoritySnapshot {
    pub owner_epoch: u64,
    pub revision: u64,
    pub pods: Vec<AuthorityPodRecord>,
    pub resources: Vec<AuthorityResourceRecord>,
    pub actors: Vec<AuthorityActorRecord>,
    pub grants: Vec<AuthorityGrantRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityMutation {
    PutPod(AuthorityPodRecord),
    PutResource(AuthorityResourceRecord),
    PutActor(AuthorityActorRecord),
    PutGrant(AuthorityGrantRecord),
    RevokeGrant(u64),
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
    SourceIdentityQuarantined,
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
            Self::SourceIdentityQuarantined => {
                write!(formatter, "conflicting source event was quarantined")
            }
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
