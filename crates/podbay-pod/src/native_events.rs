//! Private pod-owned native observations. Public reads contain only typed,
//! redacted facts; the exact JSONL evidence remains in a held append log.

use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_core::{AttemptId, Epoch, PodId, ResourceId, RunId, ScopeId, SessionId, StoreLineageId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::manifest::PodError;
#[cfg(target_os = "linux")]
use crate::manifest::PodManifest;
use crate::ports::{DurableAppendLog, DurableFiles};

const FRAME_DOMAIN: &[u8] = b"podbay.native-event-frame/1\0";
const EVENT_DOMAIN: &[u8] = b"podbay.native-event-id/1\0";
const MAX_LOG_BYTES: u64 = 16 * 1_048_576;
pub const MAX_PRIVATE_NATIVE_EVENT_LOG_BYTES: u64 = MAX_LOG_BYTES;
const MAX_FRAME_BYTES: usize = 262_144;
const MAX_RAW_BYTES: usize = 262_144;
const MAX_RECORDS: u64 = 65_536;
const TERMINAL_RESERVE_BYTES: u64 = MAX_FRAME_BYTES as u64 + HEADER_BYTES as u64;
// A long Codex bootstrap can emit hundreds of JSONL observations before its
// owner completes the first read. Keep a bounded multi-page replay window.
const RETAINED_EVENTS: usize = 4096;
const MAX_READ_EVENTS: usize = 64;
const HEADER_BYTES: usize = 4 + 32;
pub const CODEX_NATIVE_EVENTS_READ_PROTOCOL: &str = "podbay.codex-events.read/1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeEventIdentity {
    pub store_lineage: String,
    pub scope_id: String,
    pub session_id: String,
    pub run_id: String,
    pub attempt_id: String,
    pub pod_id: String,
    pub pod_incarnation: u64,
    pub resource_id: String,
    pub resource_epoch: u64,
}

impl NativeEventIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn from_resource(
        lineage: &StoreLineageId,
        scope: &ScopeId,
        session: &SessionId,
        run: &RunId,
        attempt: &AttemptId,
        pod: &PodId,
        incarnation: Epoch,
        resource: &ResourceId,
        resource_epoch: Epoch,
    ) -> Self {
        Self {
            store_lineage: lineage.as_str().into(),
            scope_id: scope.as_str().into(),
            session_id: session.as_str().into(),
            run_id: run.as_str().into(),
            attempt_id: attempt.as_str().into(),
            pod_id: pod.as_str().into(),
            pod_incarnation: incarnation.get(),
            resource_id: resource.as_str().into(),
            resource_epoch: resource_epoch.get(),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), PodError> {
        if StoreLineageId::try_from(self.store_lineage.as_str()).is_err()
            || ScopeId::try_from(self.scope_id.as_str()).is_err()
            || SessionId::try_from(self.session_id.as_str()).is_err()
            || RunId::try_from(self.run_id.as_str()).is_err()
            || AttemptId::try_from(self.attempt_id.as_str()).is_err()
            || PodId::try_from(self.pod_id.as_str()).is_err()
            || ResourceId::try_from(self.resource_id.as_str()).is_err()
            || self.pod_incarnation == 0
            || self.resource_epoch == 0
        {
            return Err(PodError::Invalid("native event resource identity"));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn identity_from_manifest(
    manifest: &PodManifest,
) -> Result<NativeEventIdentity, PodError> {
    let binding = manifest
        .peer_binding
        .as_ref()
        .ok_or(PodError::Refused("native event binding is unavailable"))?;
    let launch = &manifest.descriptor;
    Ok(NativeEventIdentity::from_resource(
        &StoreLineageId::try_from(binding.store_lineage.as_str())
            .map_err(|_| PodError::Invalid("native event lineage"))?,
        &ScopeId::try_from(launch.scope_id.as_str())
            .map_err(|_| PodError::Invalid("native event scope"))?,
        &SessionId::try_from(launch.session_id.as_str())
            .map_err(|_| PodError::Invalid("native event Session"))?,
        &RunId::try_from(launch.run_id.as_str())
            .map_err(|_| PodError::Invalid("native event Run"))?,
        &AttemptId::try_from(launch.attempt_id.as_str())
            .map_err(|_| PodError::Invalid("native event Attempt"))?,
        &PodId::try_from(launch.pod_id.as_str())
            .map_err(|_| PodError::Invalid("native event Pod"))?,
        Epoch::new(launch.incarnation)
            .map_err(|_| PodError::Invalid("native event incarnation"))?,
        &ResourceId::try_from(launch.resource_id.as_str())
            .map_err(|_| PodError::Invalid("native event Resource"))?,
        Epoch::new(binding.resource_epoch)
            .map_err(|_| PodError::Invalid("native event Resource epoch"))?,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeEventKind {
    Status,
    Output,
    /// Native question request observed; no answer has been authorised.
    Question,
    /// Native permission request observed; no grant has been created.
    Permission,
    Opaque,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// A reported native status only. `Completed` is not PodBay Run, delivery,
/// bootstrap, or review settlement; those require separate durable proof.
pub enum NativeEventStatus {
    Idle,
    Active,
    Waiting,
    Completed,
    Failed,
    Interrupted,
    SystemError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeEventFidelity {
    Exact,
    Partial,
    Unknown,
}

/// No prompt, answer, command, path, or native free text is serialized here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicNativeEvent {
    pub event_id: String,
    pub schema_version: u8,
    pub identity: NativeEventIdentity,
    pub committed_cursor: u64,
    /// Monotonic pod observation order, not provider causal sequence.
    pub source_sequence: u64,
    pub recorded_at_unix_millis: u64,
    pub occurred_at_unix_millis: Option<u64>,
    pub provenance: String,
    pub correlation_id: Option<String>,
    pub causation_id: Option<String>,
    pub kind: NativeEventKind,
    pub status: Option<NativeEventStatus>,
    pub external_conflict: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeEventSnapshot {
    pub identity: NativeEventIdentity,
    pub watermark: u64,
    pub earliest_retained: u64,
    pub last_status: Option<NativeEventStatus>,
    pub output_events: u64,
    pub question_events: u64,
    pub permission_events: u64,
    pub opaque_events: u64,
    pub external_conflict: bool,
    pub fidelity: NativeEventFidelity,
    pub quarantined: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeEventCursor {
    pub identity: NativeEventIdentity,
    pub sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeEventGap {
    pub missing_from: u64,
    pub missing_through: u64,
    pub earliest_available: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeEventRead {
    pub snapshot: NativeEventSnapshot,
    pub events: Vec<PublicNativeEvent>,
    pub next_cursor: NativeEventCursor,
    pub gap: Option<NativeEventGap>,
}

/// Privileged point-in-time evidence for an internal manager bridge only.
/// This type deliberately does not implement Serialize, and Debug redacts
/// the exact private JSONL bytes.
pub struct PrivateNativeEvidence {
    source_sequence: u64,
    event_id: String,
    private_jsonl: Vec<u8>,
}

impl std::fmt::Debug for PrivateNativeEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrivateNativeEvidence")
            .field("source_sequence", &self.source_sequence)
            .field("event_id", &self.event_id)
            .field("private_bytes", &self.private_jsonl.len())
            .finish()
    }
}

impl PrivateNativeEvidence {
    pub(crate) fn from_verified_segment(
        source_sequence: u64,
        event_id: String,
        private_jsonl: Vec<u8>,
    ) -> Self {
        Self { source_sequence, event_id, private_jsonl }
    }
    pub fn source_sequence(&self) -> u64 {
        self.source_sequence
    }
    pub fn event_id(&self) -> &str {
        &self.event_id
    }
    pub fn private_jsonl(&self) -> &[u8] {
        &self.private_jsonl
    }
}

/// A trusted manager reader supplies only EventIds from an attested pod
/// snapshot. Parse the entire bounded held-file copy once to reject a torn
/// or conflicting tail, then return exact selected private frames. This is
/// not the normal public snapshot path and must not be exposed by a server.
pub fn decode_private_native_evidence_for_trusted_reader(
    raw: &[u8],
    identity: &NativeEventIdentity,
    selected: &[PublicNativeEvent],
) -> Result<Vec<PrivateNativeEvidence>, PodError> {
    if raw.len() as u64 > MAX_LOG_BYTES || selected.len() > MAX_READ_EVENTS {
        return Err(PodError::Invalid(
            "private native evidence read exceeds bound",
        ));
    }
    identity.validate()?;
    let _ = replay(raw, identity)?;
    let mut wanted = BTreeMap::new();
    for event in selected {
        if event.identity != *identity
            || wanted
                .insert(event.source_sequence, event.event_id.as_str())
                .is_some()
        {
            return Err(PodError::Refused("private evidence selector differs"));
        }
    }
    let mut found = BTreeMap::new();
    let mut at = 0usize;
    while at < raw.len() {
        let len = u32::from_be_bytes(raw[at..at + 4].try_into().expect("validated frame")) as usize;
        let end = at + HEADER_BYTES + len;
        let record: PrivateRecord = serde_json::from_slice(&raw[at + HEADER_BYTES..end])
            .map_err(|_| PodError::Uncertain("validated native event changed"))?;
        if let PrivateBody::Event {
            source_sequence,
            event_id,
            private_jsonl,
            ..
        } = record.body
            && let Some(expected) = wanted.get(&source_sequence)
        {
            if *expected != event_id {
                return Err(PodError::Conflict("private evidence EventId differs"));
            }
            found.insert(
                source_sequence,
                PrivateNativeEvidence {
                    source_sequence,
                    event_id,
                    private_jsonl: private_jsonl.into_bytes(),
                },
            );
        }
        at = end;
    }
    if found.len() != wanted.len() {
        return Err(PodError::Uncertain(
            "private evidence is absent from held log",
        ));
    }
    Ok(found.into_values().collect())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeEventsReadRequest {
    pub protocol: String,
    pub operation: String,
    pub token: String,
    pub identity: NativeEventIdentity,
    pub cursor: Option<NativeEventCursor>,
    pub limit: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeEventsReadReply {
    pub protocol: String,
    pub read: Option<NativeEventRead>,
    pub refused: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeEventAppend {
    Committed(PublicNativeEvent),
    Duplicate {
        event_id: String,
        source_sequence: u64,
    },
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum PrivateBody {
    Event {
        source_sequence: u64,
        event_id: String,
        recorded_at_unix_millis: u64,
        payload_digest: String,
        private_jsonl: String,
        summary_kind: NativeEventKind,
        status: Option<NativeEventStatus>,
        external_conflict: bool,
    },
    Quarantine {
        source_sequence: u64,
        existing_digest: String,
        conflicting_digest: String,
        private_jsonl: String,
    },
    ContinuityLost,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateRecord {
    version: u8,
    record_index: u64,
    identity: NativeEventIdentity,
    body: PrivateBody,
}

/// Historical v1 held-log source for already-running pods. Reads are
/// O(retained events); reopen replays its bounded private log. New Linux V2
/// slots use the segmented source. Private JSONL never enters this public
/// snapshot.
pub struct NativeEventSpool {
    log: Box<dyn DurableAppendLog>,
    identity: NativeEventIdentity,
    snapshot: NativeEventSnapshot,
    retained: VecDeque<PublicNativeEvent>,
    digests: BTreeMap<u64, String>,
    records: u64,
    poisoned: bool,
}

impl NativeEventSpool {
    pub fn open(
        files: &impl DurableFiles,
        path: &Path,
        identity: NativeEventIdentity,
    ) -> Result<Self, PodError> {
        identity.validate()?;
        let mut log = files.open_private_append_log(path, MAX_LOG_BYTES)?;
        let raw = log.read_all_bounded()?;
        let (snapshot, retained, digests, records) = replay(&raw, &identity)?;
        Ok(Self {
            log,
            identity,
            snapshot,
            retained,
            digests,
            records,
            poisoned: false,
        })
    }

    pub fn identity(&self) -> &NativeEventIdentity {
        &self.identity
    }
    pub fn next_source_sequence(&self) -> Result<u64, PodError> {
        self.snapshot
            .watermark
            .checked_add(1)
            .filter(|value| *value > 0)
            .ok_or(PodError::Invalid("native source sequence exhausted"))
    }
    pub fn snapshot(&self) -> &NativeEventSnapshot {
        &self.snapshot
    }

    /// A consumed native frame that cannot be validated or appended ends the
    /// contiguous source. Keep the fact durable and visible to readers rather
    /// than continuing with an apparently exact watermark.
    pub(crate) fn mark_continuity_unknown(&mut self) -> Result<(), PodError> {
        if self.snapshot.quarantined {
            return Ok(());
        }
        if self.poisoned {
            return Err(PodError::Uncertain("native event log append is uncertain"));
        }
        self.append_record(PrivateBody::ContinuityLost)?;
        self.snapshot.fidelity = NativeEventFidelity::Unknown;
        self.snapshot.quarantined = true;
        Ok(())
    }

    /// Caller is the pod's state-applied adapter boundary. Raw JSONL is
    /// private and never appears in PublicNativeEvent, snapshot, or Debug.
    pub(crate) fn append_applied(
        &mut self,
        source_sequence: u64,
        private_jsonl: &[u8],
        kind: NativeEventKind,
        status: Option<NativeEventStatus>,
        external_conflict: bool,
    ) -> Result<NativeEventAppend, PodError> {
        let result = self.append_applied_inner(
            source_sequence,
            private_jsonl,
            kind,
            status,
            external_conflict,
        );
        if result.is_err() && !self.snapshot.quarantined {
            if self.mark_continuity_unknown().is_err() {
                self.poisoned = true;
                self.snapshot.fidelity = NativeEventFidelity::Unknown;
            }
        }
        result
    }

    fn append_applied_inner(
        &mut self,
        source_sequence: u64,
        private_jsonl: &[u8],
        kind: NativeEventKind,
        status: Option<NativeEventStatus>,
        external_conflict: bool,
    ) -> Result<NativeEventAppend, PodError> {
        if self.poisoned || self.snapshot.quarantined {
            return Err(PodError::Uncertain(
                "native event source is quarantined or uncertain",
            ));
        }
        validate_private_jsonl(private_jsonl)?;
        let digest = hex(Sha256::digest(private_jsonl).as_slice());
        if let Some(prior) = self.digests.get(&source_sequence) {
            if prior == &digest {
                return Ok(NativeEventAppend::Duplicate {
                    event_id: public_event(
                        &self.identity,
                        source_sequence,
                        0,
                        kind,
                        status,
                        external_conflict,
                    )
                    .event_id,
                    source_sequence,
                });
            }
            let body = PrivateBody::Quarantine {
                source_sequence,
                existing_digest: prior.clone(),
                conflicting_digest: digest,
                private_jsonl: String::from_utf8(private_jsonl.to_vec())
                    .map_err(|_| PodError::Invalid("native event JSONL is not UTF-8"))?,
            };
            self.append_record(body)?;
            self.snapshot.quarantined = true;
            self.snapshot.fidelity = NativeEventFidelity::Unknown;
            return Err(PodError::Conflict(
                "native source sequence payload conflicts",
            ));
        }
        if source_sequence == 0 || source_sequence <= self.snapshot.watermark {
            return Err(PodError::Conflict("native source sequence is stale"));
        }
        let recorded_at_unix_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PodError::Invalid("native event clock unavailable"))?
            .as_millis()
            .try_into()
            .map_err(|_| PodError::Invalid("native event clock overflow"))?;
        let event = public_event(
            &self.identity,
            source_sequence,
            recorded_at_unix_millis,
            kind,
            status,
            external_conflict,
        );
        let body = PrivateBody::Event {
            source_sequence,
            event_id: event.event_id.clone(),
            recorded_at_unix_millis,
            payload_digest: digest.clone(),
            private_jsonl: String::from_utf8(private_jsonl.to_vec())
                .map_err(|_| PodError::Invalid("native event JSONL is not UTF-8"))?,
            summary_kind: kind,
            status,
            external_conflict,
        };
        self.append_record(body)?;
        apply_public(&mut self.snapshot, &mut self.retained, event.clone())?;
        self.digests.insert(source_sequence, digest);
        Ok(NativeEventAppend::Committed(event))
    }

    fn append_record(&mut self, body: PrivateBody) -> Result<(), PodError> {
        let ordinary_event = matches!(&body, PrivateBody::Event { .. });
        let next = self
            .records
            .checked_add(1)
            .filter(|value| *value <= MAX_RECORDS)
            .ok_or(PodError::Refused("native event record bound reached"))?;
        let record = PrivateRecord {
            version: 1,
            record_index: next,
            identity: self.identity.clone(),
            body,
        };
        let frame = encode_frame(&record)?;
        if ordinary_event
            && (next >= MAX_RECORDS
                || self.log.len().saturating_add(frame.len() as u64)
                    > MAX_LOG_BYTES.saturating_sub(TERMINAL_RESERVE_BYTES))
        {
            return Err(PodError::Refused("native event retention bound reached"));
        }
        if self.log.append_synced(&frame).is_err() {
            self.poisoned = true;
            return Err(PodError::Uncertain("native event append or sync unknown"));
        }
        self.records = next;
        Ok(())
    }

    /// Cursor identity is exact. A slow reader receives one snapshot/watermark
    /// and an explicit gap; it never induces an unbounded in-memory backlog.
    pub fn read_after(
        &self,
        cursor: Option<&NativeEventCursor>,
        limit: usize,
    ) -> Result<NativeEventRead, PodError> {
        if self.poisoned || limit == 0 || limit > MAX_READ_EVENTS {
            return Err(PodError::Refused(
                "native event read unavailable or unbounded",
            ));
        }
        let snapshot = self.snapshot.clone();
        let after = if let Some(cursor) = cursor {
            if cursor.identity != self.identity || cursor.sequence > snapshot.watermark {
                return Err(PodError::Refused(
                    "native event cursor is foreign or future",
                ));
            }
            if cursor.sequence > 0 && !self.digests.contains_key(&cursor.sequence) {
                return Err(PodError::Refused(
                    "native event cursor has no committed source sequence",
                ));
            }
            cursor.sequence
        } else {
            snapshot.watermark
        };
        let mut events = Vec::new();
        let mut gap = None;
        let mut expected = after.saturating_add(1);
        for event in self
            .retained
            .iter()
            .filter(|event| event.source_sequence > after)
        {
            if event.source_sequence > expected {
                if gap.is_none() {
                    gap = Some(NativeEventGap {
                        missing_from: expected,
                        missing_through: event.source_sequence - 1,
                        earliest_available: event.source_sequence,
                    });
                } else {
                    // One reply never conceals a second source gap. The next
                    // cursor read will expose it before that later event.
                    break;
                }
            }
            events.push(event.clone());
            expected = event.source_sequence.saturating_add(1);
            if events.len() == limit {
                break;
            }
        }
        let next_sequence = events
            .last()
            .map(|event| event.source_sequence)
            .unwrap_or(after);
        Ok(NativeEventRead {
            snapshot,
            events,
            next_cursor: NativeEventCursor {
                identity: self.identity.clone(),
                sequence: next_sequence,
            },
            gap,
        })
    }
}

pub(crate) fn validate_private_jsonl(bytes: &[u8]) -> Result<(), PodError> {
    if bytes.is_empty()
        || bytes.len() > MAX_RAW_BYTES
        || bytes.last() != Some(&b'\n')
        || bytes[..bytes.len() - 1].contains(&b'\n')
    {
        return Err(PodError::Invalid(
            "native event private frame is malformed or too large",
        ));
    }
    let value = serde_json::from_slice::<serde_json::Value>(bytes)
        .map_err(|_| PodError::Invalid("native event private frame is malformed"))?;
    if !value
        .get("method")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|method| !method.is_empty() && method.len() <= 512)
    {
        return Err(PodError::Invalid("native event method is invalid"));
    }
    Ok(())
}

pub(crate) fn public_event(
    identity: &NativeEventIdentity,
    sequence: u64,
    recorded_at: u64,
    kind: NativeEventKind,
    status: Option<NativeEventStatus>,
    external_conflict: bool,
) -> PublicNativeEvent {
    // Public IDs bind the resource source and sequence, never a digest of
    // private text that could expose low-entropy prompt/answer candidates.
    PublicNativeEvent {
        event_id: native_event_id(identity, sequence),
        schema_version: 1,
        identity: identity.clone(),
        committed_cursor: sequence,
        source_sequence: sequence,
        recorded_at_unix_millis: recorded_at,
        occurred_at_unix_millis: None,
        provenance: "codex.app-server.pod-observed/1".into(),
        correlation_id: None,
        causation_id: None,
        kind,
        status,
        external_conflict,
    }
}

pub(crate) fn native_event_id(identity: &NativeEventIdentity, sequence: u64) -> String {
    let mut hash = Sha256::new();
    hash.update(EVENT_DOMAIN);
    hash.update(serde_json::to_vec(identity).expect("validated identity encodes"));
    hash.update(sequence.to_be_bytes());
    format!("native.{}", hex(hash.finalize().as_slice()))
}

pub(crate) fn apply_public(
    snapshot: &mut NativeEventSnapshot,
    retained: &mut VecDeque<PublicNativeEvent>,
    event: PublicNativeEvent,
) -> Result<(), PodError> {
    let expected = snapshot
        .watermark
        .checked_add(1)
        .ok_or(PodError::Invalid("native event watermark exhausted"))?;
    if event.source_sequence != expected {
        snapshot.fidelity = NativeEventFidelity::Partial;
    }
    snapshot.watermark = event.source_sequence;
    if let Some(status) = event.status {
        snapshot.last_status = Some(status);
    }
    match event.kind {
        NativeEventKind::Output => {
            snapshot.output_events = snapshot.output_events.saturating_add(1)
        }
        NativeEventKind::Question => {
            snapshot.question_events = snapshot.question_events.saturating_add(1)
        }
        NativeEventKind::Permission => {
            snapshot.permission_events = snapshot.permission_events.saturating_add(1)
        }
        NativeEventKind::Opaque => {
            snapshot.opaque_events = snapshot.opaque_events.saturating_add(1);
            snapshot.fidelity = NativeEventFidelity::Partial;
        }
        NativeEventKind::Status => {}
    }
    snapshot.external_conflict |= event.external_conflict;
    retained.push_back(event);
    while retained.len() > RETAINED_EVENTS {
        retained.pop_front();
    }
    snapshot.earliest_retained = retained
        .front()
        .map(|event| event.source_sequence)
        .unwrap_or(snapshot.watermark.saturating_add(1));
    Ok(())
}

fn encode_frame(record: &PrivateRecord) -> Result<Vec<u8>, PodError> {
    let payload = serde_json::to_vec(record)?;
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(PodError::Invalid("native event frame bound"));
    }
    let mut hash = Sha256::new();
    hash.update(FRAME_DOMAIN);
    hash.update(&payload);
    let mut frame = Vec::with_capacity(HEADER_BYTES + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&hash.finalize());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn replay(
    raw: &[u8],
    identity: &NativeEventIdentity,
) -> Result<
    (
        NativeEventSnapshot,
        VecDeque<PublicNativeEvent>,
        BTreeMap<u64, String>,
        u64,
    ),
    PodError,
> {
    let mut snapshot = NativeEventSnapshot {
        identity: identity.clone(),
        watermark: 0,
        earliest_retained: 1,
        last_status: None,
        output_events: 0,
        question_events: 0,
        permission_events: 0,
        opaque_events: 0,
        external_conflict: false,
        fidelity: NativeEventFidelity::Exact,
        quarantined: false,
    };
    let mut retained = VecDeque::new();
    let mut digests = BTreeMap::new();
    let mut records = 0u64;
    let mut at = 0usize;
    while at < raw.len() {
        if raw.len() - at < HEADER_BYTES {
            return Err(PodError::Uncertain("native event log tail is torn"));
        }
        let len = u32::from_be_bytes(raw[at..at + 4].try_into().expect("four bytes")) as usize;
        if len == 0 || len > MAX_FRAME_BYTES {
            return Err(PodError::Uncertain("native event frame length is corrupt"));
        }
        let end = at
            .checked_add(HEADER_BYTES)
            .and_then(|value| value.checked_add(len))
            .ok_or(PodError::Uncertain("native event frame length overflows"))?;
        if end > raw.len() {
            return Err(PodError::Uncertain("native event log tail is torn"));
        }
        let payload = &raw[at + HEADER_BYTES..end];
        let mut hash = Sha256::new();
        hash.update(FRAME_DOMAIN);
        hash.update(payload);
        if hash.finalize().as_slice() != &raw[at + 4..at + HEADER_BYTES] {
            return Err(PodError::Uncertain("native event frame checksum differs"));
        }
        let record: PrivateRecord = serde_json::from_slice(payload)
            .map_err(|_| PodError::Uncertain("native event frame is malformed"))?;
        if serde_json::to_vec(&record)? != payload {
            return Err(PodError::Uncertain("native event frame is not canonical"));
        }
        records = records
            .checked_add(1)
            .filter(|value| *value <= MAX_RECORDS)
            .ok_or(PodError::Uncertain(
                "native event record count exceeds bound",
            ))?;
        if record.version != 1
            || record.record_index != records
            || record.identity != *identity
            || snapshot.quarantined
        {
            return Err(PodError::Conflict(
                "native event record identity or transition differs",
            ));
        }
        match record.body {
            PrivateBody::Event {
                source_sequence,
                event_id,
                recorded_at_unix_millis,
                payload_digest,
                private_jsonl,
                summary_kind,
                status,
                external_conflict,
            } => {
                validate_private_jsonl(private_jsonl.as_bytes())?;
                if source_sequence == 0
                    || source_sequence <= snapshot.watermark
                    || hex(Sha256::digest(private_jsonl.as_bytes()).as_slice()) != payload_digest
                {
                    return Err(PodError::Conflict(
                        "native event sequence or payload changed",
                    ));
                }
                let event = public_event(
                    identity,
                    source_sequence,
                    recorded_at_unix_millis,
                    summary_kind,
                    status,
                    external_conflict,
                );
                if event.event_id != event_id {
                    return Err(PodError::Conflict("native event ID changed"));
                }
                apply_public(&mut snapshot, &mut retained, event)?;
                digests.insert(source_sequence, payload_digest);
            }
            PrivateBody::Quarantine {
                source_sequence,
                existing_digest,
                conflicting_digest,
                private_jsonl,
            } => {
                validate_private_jsonl(private_jsonl.as_bytes())?;
                if digests.get(&source_sequence) != Some(&existing_digest)
                    || hex(Sha256::digest(private_jsonl.as_bytes()).as_slice())
                        != conflicting_digest
                    || existing_digest == conflicting_digest
                {
                    return Err(PodError::Conflict(
                        "native event quarantine evidence differs",
                    ));
                }
                snapshot.quarantined = true;
                snapshot.fidelity = NativeEventFidelity::Unknown;
            }
            PrivateBody::ContinuityLost => {
                snapshot.quarantined = true;
                snapshot.fidelity = NativeEventFidelity::Unknown;
            }
        }
        at = end;
    }
    Ok((snapshot, retained, digests, records))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::ports::DurableFileIdentity;

    #[derive(Default)]
    struct MemoryState {
        bytes: Vec<u8>,
        append_calls: usize,
        read_calls: usize,
        partial_next: bool,
    }

    #[derive(Clone)]
    struct MemoryFiles(Arc<Mutex<MemoryState>>);

    struct MemoryHandle {
        state: Arc<Mutex<MemoryState>>,
        identity: DurableFileIdentity,
        max_bytes: u64,
    }

    impl DurableAppendLog for MemoryHandle {
        fn identity(&self) -> &DurableFileIdentity {
            &self.identity
        }
        fn len(&self) -> u64 {
            self.state.lock().unwrap().bytes.len() as u64
        }
        fn read_all_bounded(&mut self) -> Result<Vec<u8>, PodError> {
            let mut state = self.state.lock().unwrap();
            state.read_calls += 1;
            if state.bytes.len() as u64 > self.max_bytes {
                return Err(PodError::Refused("fake log bound"));
            }
            Ok(state.bytes.clone())
        }
        fn append_synced(&mut self, bytes: &[u8]) -> Result<(), PodError> {
            let mut state = self.state.lock().unwrap();
            if state.bytes.len() as u64 + bytes.len() as u64 > self.max_bytes {
                return Err(PodError::Refused("fake log bound"));
            }
            state.append_calls += 1;
            if std::mem::take(&mut state.partial_next) {
                state
                    .bytes
                    .extend_from_slice(&bytes[..bytes.len().div_ceil(2)]);
                return Err(PodError::Uncertain("fake partial native append"));
            }
            state.bytes.extend_from_slice(bytes);
            Ok(())
        }
    }

    impl DurableFiles for MemoryFiles {
        fn create_private(&self, _: &Path, _: &[u8]) -> Result<(), PodError> {
            Err(PodError::Unsupported("fake legacy file operation"))
        }
        fn append_durable(&self, _: &Path, _: &[u8]) -> Result<(), PodError> {
            Err(PodError::Unsupported("fake legacy file operation"))
        }
        fn replace_durable(&self, _: &Path, _: &[u8]) -> Result<(), PodError> {
            Err(PodError::Unsupported("fake legacy file operation"))
        }
        fn open_private_append_log(
            &self,
            _: &Path,
            max_bytes: u64,
        ) -> Result<Box<dyn DurableAppendLog>, PodError> {
            Ok(Box::new(MemoryHandle {
                state: self.0.clone(),
                identity: DurableFileIdentity::from_backend("fake/1", vec![1, 2, 3]).unwrap(),
                max_bytes,
            }))
        }
    }

    fn files() -> MemoryFiles {
        MemoryFiles(Arc::new(Mutex::new(MemoryState::default())))
    }
    fn identity() -> NativeEventIdentity {
        NativeEventIdentity::from_resource(
            &StoreLineageId::try_from("lineage.fixture").unwrap(),
            &ScopeId::try_from("scope.fixture").unwrap(),
            &SessionId::try_from("session.fixture").unwrap(),
            &RunId::try_from("run.fixture").unwrap(),
            &AttemptId::try_from("attempt.fixture").unwrap(),
            &PodId::try_from("pod.fixture").unwrap(),
            Epoch::new(1).unwrap(),
            &ResourceId::try_from("resource.fixture").unwrap(),
            Epoch::new(1).unwrap(),
        )
    }
    fn raw(value: &str) -> Vec<u8> {
        format!("{{\"method\":\"item/agentMessage/delta\",\"params\":{{\"delta\":\"{value}\"}}}}\n")
            .into_bytes()
    }

    #[test]
    fn snapshot_then_events_after_is_consistent_and_redacts_private_payload() {
        let files = files();
        let mut spool =
            NativeEventSpool::open(&files, Path::new("/private/events"), identity()).unwrap();
        let secret = raw("private prompt and answer");
        assert!(matches!(
            spool
                .append_applied(1, &secret, NativeEventKind::Output, None, false)
                .unwrap(),
            NativeEventAppend::Committed(_)
        ));
        let first = spool.read_after(None, 16).unwrap();
        assert_eq!(first.snapshot.watermark, 1);
        assert!(first.events.is_empty());
        assert_eq!(first.next_cursor.sequence, 1);
        assert!(
            !serde_json::to_string(&first)
                .unwrap()
                .contains("private prompt")
        );
        spool
            .append_applied(2, &raw("second"), NativeEventKind::Output, None, false)
            .unwrap();
        let after = spool.read_after(Some(&first.next_cursor), 16).unwrap();
        assert_eq!(after.snapshot.watermark, 2);
        assert_eq!(after.events.len(), 1);
        assert_eq!(after.events[0].source_sequence, 2);
        assert_eq!(after.next_cursor.sequence, 2);
        assert_eq!(
            files.0.lock().unwrap().read_calls,
            1,
            "readback replayed lifetime log"
        );
        assert!(String::from_utf8_lossy(&files.0.lock().unwrap().bytes).contains("private prompt"));
        let evidence = decode_private_native_evidence_for_trusted_reader(
            &files.0.lock().unwrap().bytes,
            &identity(),
            &after.events,
        )
        .unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].private_jsonl(), raw("second"));
        assert!(!format!("{:?}", evidence[0]).contains("second"));
        let mut wrong = after.events.clone();
        wrong[0].event_id = "native.changed".into();
        assert!(matches!(
            decode_private_native_evidence_for_trusted_reader(
                &files.0.lock().unwrap().bytes,
                &identity(),
                &wrong,
            ),
            Err(PodError::Conflict(_))
        ));
    }

    #[test]
    fn duplicate_conflict_and_missing_source_sequence_are_explicit() {
        let files = files();
        let mut spool =
            NativeEventSpool::open(&files, Path::new("/private/events"), identity()).unwrap();
        let first = raw("first");
        spool
            .append_applied(1, &first, NativeEventKind::Output, None, false)
            .unwrap();
        let cursor = spool.read_after(None, 1).unwrap().next_cursor;
        assert!(matches!(
            spool
                .append_applied(1, &first, NativeEventKind::Output, None, false)
                .unwrap(),
            NativeEventAppend::Duplicate {
                source_sequence: 1,
                ..
            }
        ));
        assert_eq!(files.0.lock().unwrap().append_calls, 1);
        spool
            .append_applied(3, &raw("third"), NativeEventKind::Output, None, false)
            .unwrap();
        assert_eq!(spool.snapshot().fidelity, NativeEventFidelity::Partial);
        let read = spool.read_after(Some(&cursor), 16).unwrap();
        assert_eq!(
            read.gap
                .as_ref()
                .map(|gap| (gap.missing_from, gap.missing_through)),
            Some((2, 2))
        );
        let invented = NativeEventCursor {
            identity: identity(),
            sequence: 2,
        };
        assert!(matches!(
            spool.read_after(Some(&invented), 1),
            Err(PodError::Refused(_))
        ));
        spool
            .append_applied(5, &raw("fifth"), NativeEventKind::Output, None, false)
            .unwrap();
        let first_page = spool.read_after(Some(&cursor), 16).unwrap();
        assert_eq!(
            first_page
                .events
                .iter()
                .map(|event| event.source_sequence)
                .collect::<Vec<_>>(),
            [3]
        );
        assert_eq!(first_page.gap.as_ref().map(|gap| gap.missing_from), Some(2));
        let second_page = spool.read_after(Some(&first_page.next_cursor), 16).unwrap();
        assert_eq!(
            second_page
                .events
                .iter()
                .map(|event| event.source_sequence)
                .collect::<Vec<_>>(),
            [5]
        );
        assert_eq!(
            second_page.gap.as_ref().map(|gap| gap.missing_from),
            Some(4)
        );
        assert!(matches!(
            spool.append_applied(1, &raw("conflict"), NativeEventKind::Output, None, false),
            Err(PodError::Conflict(_))
        ));
        assert!(spool.snapshot().quarantined);
        drop(spool);
        let reopened =
            NativeEventSpool::open(&files, Path::new("/private/events"), identity()).unwrap();
        assert!(reopened.snapshot().quarantined);
        assert_eq!(reopened.snapshot().fidelity, NativeEventFidelity::Unknown);
    }

    #[test]
    fn torn_append_refuses_reopen_and_slow_reader_gets_retention_gap() {
        let files = files();
        let mut spool =
            NativeEventSpool::open(&files, Path::new("/private/events"), identity()).unwrap();
        spool
            .append_applied(1, &raw("first"), NativeEventKind::Output, None, false)
            .unwrap();
        let old = spool.read_after(None, 1).unwrap().next_cursor;
        let final_sequence = RETAINED_EVENTS as u64 + 6;
        for sequence in 2..=final_sequence {
            spool
                .append_applied(
                    sequence,
                    &raw(&format!("line{sequence}")),
                    NativeEventKind::Output,
                    None,
                    false,
                )
                .unwrap();
        }
        let slow = spool.read_after(Some(&old), 64).unwrap();
        assert_eq!(slow.snapshot.watermark, final_sequence);
        assert_eq!(slow.events.len(), 64);
        assert_eq!(slow.events[0].source_sequence, 7);
        assert_eq!(
            slow.gap
                .as_ref()
                .map(|gap| (gap.missing_from, gap.missing_through)),
            Some((2, 6))
        );
        assert_eq!(files.0.lock().unwrap().read_calls, 1);
        files.0.lock().unwrap().partial_next = true;
        assert!(matches!(
            spool.append_applied(71, &raw("torn"), NativeEventKind::Output, None, false),
            Err(PodError::Uncertain(_))
        ));
        assert_eq!(spool.snapshot().fidelity, NativeEventFidelity::Unknown);
        assert!(matches!(
            spool.read_after(Some(&old), 1),
            Err(PodError::Refused(_))
        ));
        drop(spool);
        assert!(matches!(
            NativeEventSpool::open(&files, Path::new("/private/events"), identity()),
            Err(PodError::Uncertain(_))
        ));
    }

    #[test]
    fn consumed_unvalidated_frame_seals_unknown_continuity_durably() {
        let files = files();
        let mut spool =
            NativeEventSpool::open(&files, Path::new("/private/events"), identity()).unwrap();
        spool
            .append_applied(1, &raw("first"), NativeEventKind::Output, None, false)
            .unwrap();
        spool.mark_continuity_unknown().unwrap();
        assert_eq!(spool.snapshot().fidelity, NativeEventFidelity::Unknown);
        assert!(spool.snapshot().quarantined);
        assert!(matches!(
            spool.append_applied(2, &raw("later"), NativeEventKind::Output, None, false),
            Err(PodError::Uncertain(_))
        ));
        drop(spool);
        let reopened =
            NativeEventSpool::open(&files, Path::new("/private/events"), identity()).unwrap();
        assert!(reopened.snapshot().quarantined);
        assert_eq!(reopened.snapshot().watermark, 1);
        assert_eq!(reopened.snapshot().fidelity, NativeEventFidelity::Unknown);

        let files = self::files();
        let mut spool =
            NativeEventSpool::open(&files, Path::new("/private/events"), identity()).unwrap();
        let oversized = raw(&"x".repeat(MAX_RAW_BYTES));
        assert!(matches!(
            spool.append_applied(1, &oversized, NativeEventKind::Output, None, false),
            Err(PodError::Invalid(_))
        ));
        assert_eq!(spool.snapshot().fidelity, NativeEventFidelity::Unknown);
        drop(spool);
        let reopened =
            NativeEventSpool::open(&files, Path::new("/private/events"), identity()).unwrap();
        assert!(reopened.snapshot().quarantined);
        assert_eq!(reopened.snapshot().watermark, 0);
    }
}
