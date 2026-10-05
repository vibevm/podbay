//! Versioned private segment/checkpoint backend for new Linux Codex V2 slots.
//! Historical held logs retain their v1 decoder. A pod writer fsyncs each
//! frame and checkpoint; a manager reader verifies one bounded attachment,
//! then only new suffixes and requested indexed frames.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::manifest::{PodError, private_directory};
use crate::native_events::{
    NativeEventCursor, NativeEventFidelity, NativeEventGap, NativeEventIdentity, NativeEventKind,
    NativeEventRead, NativeEventSnapshot, NativeEventStatus, PrivateNativeEvidence,
    PublicNativeEvent, apply_public, native_event_id, public_event, validate_private_jsonl,
};

const CHECKPOINT_DOMAIN: &[u8] = b"podbay.native-segment-checkpoint/2\0";
const FRAME_DOMAIN: &[u8] = b"podbay.native-segment-frame/1\0";
const CHAIN_DOMAIN: &[u8] = b"podbay.native-segment-chain/1\0";
const MAX_SEGMENTS: usize = 4;
const MAX_SEGMENT_BYTES: u64 = 1_048_576;
const MAX_FRAME_PAYLOAD: usize = 65_536;
pub(crate) const MAX_SEGMENT_FRAME_BYTES: u64 = (MAX_FRAME_PAYLOAD + 4 + 32) as u64;
// Codex's first bootstrap may burst well past one 64-event read page before
// Zap can acknowledge it. Retain several pages in the durable index.
const MAX_OFFSETS: usize = 512;
const MAX_CHECKPOINT_BYTES: usize = 524_288;
const FRAME_HEADER: usize = 4 + 32;
const CHECKPOINT_HEADER: usize = 4 + 32;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSegmentMeta {
    pub id: u64,
    pub start_sequence: u64,
    pub end_sequence: u64,
    pub byte_len: u64,
    pub prior_segment_digest: String,
    pub chain_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSegmentOffset {
    pub source_sequence: u64,
    pub event_id: String,
    pub segment_id: u64,
    pub offset: u64,
    pub frame_len: u32,
    pub frame_digest: String,
}

/// Exact public event facts without repeating seven potentially long scope
/// identifiers in every retained entry. Identity, EventId and provenance are
/// reconstructed from the checkpoint's checked resource identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSegmentEventProjection {
    pub source_sequence: u64,
    pub recorded_at_unix_millis: u64,
    pub kind: NativeEventKind,
    pub status: Option<NativeEventStatus>,
    pub external_conflict: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSegmentCheckpoint {
    pub version: u8,
    pub identity: NativeEventIdentity,
    pub generation: u64,
    pub watermark: u64,
    pub pruned_through: u64,
    /// Fsynced before taking one native notification. Reopen with this marker
    /// quarantines rather than silently skipping a possibly consumed frame.
    pub pending_source_sequence: Option<u64>,
    pub segments: Vec<NativeSegmentMeta>,
    pub retained_offsets: Vec<NativeSegmentOffset>,
    pub redacted_events: Vec<NativeSegmentEventProjection>,
    /// Typed public projection; native JSONL cannot be placed here.
    pub redacted_snapshot: NativeEventSnapshot,
}

pub struct SegmentAppendReceipt {
    segment_id: u64,
    offset: u64,
    frame_len: u32,
    frame_digest: String,
}

pub struct SegmentRolloverPlan {
    pub checkpoint: NativeSegmentCheckpoint,
    pub prune: Option<NativeSegmentMeta>,
}

/// Raw bytes are private and never Serialize or Debug output.
pub struct IndexedPrivateFrame {
    source_sequence: u64,
    event_id: String,
    private_payload: Vec<u8>,
}

impl std::fmt::Debug for IndexedPrivateFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IndexedPrivateFrame")
            .field("source_sequence", &self.source_sequence)
            .field("event_id", &self.event_id)
            .field("private_bytes", &self.private_payload.len())
            .finish()
    }
}

impl IndexedPrivateFrame {
    pub fn source_sequence(&self) -> u64 {
        self.source_sequence
    }
    pub fn event_id(&self) -> &str {
        &self.event_id
    }
    pub fn private_payload(&self) -> &[u8] {
        &self.private_payload
    }
    pub fn into_private_evidence(self) -> Result<PrivateNativeEvidence, PodError> {
        validate_private_jsonl(&self.private_payload)
            .map_err(|_| PodError::Uncertain("indexed native JSONL is malformed"))?;
        Ok(PrivateNativeEvidence::from_verified_segment(
            self.source_sequence,
            self.event_id,
            self.private_payload,
        ))
    }
}

impl NativeSegmentCheckpoint {
    pub fn initial(identity: NativeEventIdentity) -> Result<Self, PodError> {
        identity.validate()?;
        Ok(Self {
            version: 2,
            identity: identity.clone(),
            generation: 1,
            watermark: 0,
            pruned_through: 0,
            pending_source_sequence: None,
            segments: vec![new_segment(1, 1, &"0".repeat(64))],
            retained_offsets: Vec::new(),
            redacted_events: Vec::new(),
            redacted_snapshot: NativeEventSnapshot {
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
            },
        })
    }

    pub fn active(&self) -> &NativeSegmentMeta {
        self.segments.last().expect("validated checkpoint")
    }

    pub fn can_hold_max_frame(&self) -> bool {
        self.active()
            .byte_len
            .saturating_add(MAX_SEGMENT_FRAME_BYTES)
            <= MAX_SEGMENT_BYTES
    }

    pub fn redacted_read_after(
        &self,
        cursor: Option<&NativeEventCursor>,
        limit: usize,
    ) -> Result<NativeEventRead, PodError> {
        self.validate()?;
        if self.pending_source_sequence.is_some() || !(1..=MAX_OFFSETS).contains(&limit) {
            return Err(PodError::Uncertain(
                "native segment snapshot is pending or unbounded",
            ));
        }
        let snapshot = self.redacted_snapshot.clone();
        let after = match cursor {
            Some(cursor)
                if cursor.identity == self.identity && cursor.sequence <= snapshot.watermark =>
            {
                cursor.sequence
            }
            Some(_) => {
                return Err(PodError::Refused(
                    "native event cursor is foreign or future",
                ));
            }
            None => snapshot.watermark,
        };
        let first = self
            .redacted_events
            .first()
            .map_or(snapshot.watermark.saturating_add(1), |event| {
                event.source_sequence
            });
        let gap = (after.saturating_add(1) < first).then(|| NativeEventGap {
            missing_from: after + 1,
            missing_through: first - 1,
            earliest_available: first,
        });
        let events: Vec<_> = self
            .redacted_events
            .iter()
            .filter(|event| event.source_sequence > after)
            .take(limit)
            .map(|event| {
                public_event(
                    &self.identity,
                    event.source_sequence,
                    event.recorded_at_unix_millis,
                    event.kind,
                    event.status,
                    event.external_conflict,
                )
            })
            .collect();
        let next_cursor = NativeEventCursor {
            identity: self.identity.clone(),
            sequence: events.last().map_or(after, |event| event.source_sequence),
        };
        Ok(NativeEventRead {
            snapshot,
            events,
            next_cursor,
            gap,
        })
    }

    pub fn reserve_native_take(&self) -> Result<Self, PodError> {
        self.validate()?;
        if self.pending_source_sequence.is_some() || self.redacted_snapshot.quarantined {
            return Err(PodError::Refused(
                "native event source is pending or quarantined",
            ));
        }
        let mut next = self.clone();
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or(PodError::Invalid("checkpoint generation exhausted"))?;
        next.pending_source_sequence = Some(
            self.watermark
                .checked_add(1)
                .ok_or(PodError::Invalid("native source sequence exhausted"))?,
        );
        next.validate()?;
        Ok(next)
    }

    pub fn mark_continuity_unknown(&self) -> Result<Self, PodError> {
        self.validate()?;
        let mut next = self.clone();
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or(PodError::Invalid("checkpoint generation exhausted"))?;
        next.pending_source_sequence = None;
        next.redacted_snapshot.fidelity = NativeEventFidelity::Unknown;
        next.redacted_snapshot.quarantined = true;
        next.validate()?;
        Ok(next)
    }

    /// A caller may advance the index only after the exact frame append has
    /// returned from fsync. The new checkpoint must then be durably replaced;
    /// a crash between those steps is detected as an unmatched segment tail.
    pub fn after_synced_append(
        &self,
        source_sequence: u64,
        event: PublicNativeEvent,
        receipt: &SegmentAppendReceipt,
    ) -> Result<Self, PodError> {
        self.validate()?;
        if source_sequence == 0
            || source_sequence
                != self
                    .watermark
                    .checked_add(1)
                    .ok_or(PodError::Invalid("segment watermark exhausted"))?
            || self.pending_source_sequence != Some(source_sequence)
            || event.identity != self.identity
            || event.source_sequence != source_sequence
            || event.committed_cursor != source_sequence
            || event.event_id != native_event_id(&self.identity, source_sequence)
            || event.schema_version != 1
            || event.provenance != "codex.app-server.pod-observed/1"
            || event.occurred_at_unix_millis.is_some()
            || event.correlation_id.is_some()
            || event.causation_id.is_some()
            || receipt.segment_id != self.active().id
            || receipt.offset != self.active().byte_len
            || receipt.frame_len == 0
            || receipt.offset.saturating_add(receipt.frame_len as u64) > MAX_SEGMENT_BYTES
        {
            return Err(PodError::Invalid(
                "synced native frame differs from checkpoint",
            ));
        }
        let mut next = self.clone();
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or(PodError::Invalid("segment checkpoint generation exhausted"))?;
        next.watermark = source_sequence;
        next.pending_source_sequence = None;
        let active = next.segments.last_mut().expect("validated checkpoint");
        active.end_sequence = source_sequence;
        active.byte_len += receipt.frame_len as u64;
        active.chain_digest = chain_digest(&active.chain_digest, &receipt.frame_digest);
        next.retained_offsets.push(NativeSegmentOffset {
            source_sequence,
            event_id: event.event_id.clone(),
            segment_id: receipt.segment_id,
            offset: receipt.offset,
            frame_len: receipt.frame_len,
            frame_digest: receipt.frame_digest.clone(),
        });
        if next.retained_offsets.len() > MAX_OFFSETS {
            next.retained_offsets.remove(0);
        }
        next.redacted_events.push(NativeSegmentEventProjection {
            source_sequence,
            recorded_at_unix_millis: event.recorded_at_unix_millis,
            kind: event.kind,
            status: event.status,
            external_conflict: event.external_conflict,
        });
        if next.redacted_events.len() > MAX_OFFSETS {
            next.redacted_events.remove(0);
        }
        let mut snapshot = self.redacted_snapshot.clone();
        let mut retained: VecDeque<_> = self
            .redacted_events
            .iter()
            .map(|item| {
                public_event(
                    &self.identity,
                    item.source_sequence,
                    item.recorded_at_unix_millis,
                    item.kind,
                    item.status,
                    item.external_conflict,
                )
            })
            .collect();
        apply_public(&mut snapshot, &mut retained, event)?;
        next.redacted_snapshot = snapshot;
        next.redacted_snapshot.earliest_retained = next
            .retained_offsets
            .first()
            .map_or(source_sequence.saturating_add(1), |offset| {
                offset.source_sequence
            });
        next.validate()?;
        Ok(next)
    }

    /// Called only after the successor's empty file and its directory entry
    /// are durable. Pruning is permitted only after this checkpoint is fsynced.
    pub fn rollover_plan(&self) -> Result<SegmentRolloverPlan, PodError> {
        self.validate()?;
        let active = self.active();
        if active.byte_len == 0 || self.pending_source_sequence.is_some() {
            return Err(PodError::Invalid("empty segment cannot roll over"));
        }
        let id = active
            .id
            .checked_add(1)
            .ok_or(PodError::Invalid("segment ID exhausted"))?;
        let start = self
            .watermark
            .checked_add(1)
            .ok_or(PodError::Invalid("source sequence exhausted"))?;
        let mut next = self.clone();
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or(PodError::Invalid("checkpoint generation exhausted"))?;
        next.segments
            .push(new_segment(id, start, &active.chain_digest));
        let prune = if next.segments.len() > MAX_SEGMENTS {
            let removed = next.segments.remove(0);
            next.pruned_through = removed.end_sequence;
            next.retained_offsets
                .retain(|offset| offset.segment_id != removed.id);
            let first = next
                .retained_offsets
                .first()
                .map(|offset| offset.source_sequence);
            next.redacted_events
                .retain(|event| first.is_some_and(|first| event.source_sequence >= first));
            Some(removed)
        } else {
            None
        };
        next.redacted_snapshot.earliest_retained = next
            .retained_offsets
            .first()
            .map_or(next.watermark.saturating_add(1), |offset| {
                offset.source_sequence
            });
        next.validate()?;
        Ok(SegmentRolloverPlan {
            checkpoint: next,
            prune,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, PodError> {
        self.validate()?;
        let payload = serde_json::to_vec(self)?;
        if payload.is_empty() || payload.len() > MAX_CHECKPOINT_BYTES {
            return Err(PodError::Invalid("native segment checkpoint bound"));
        }
        let digest = hash(CHECKPOINT_DOMAIN, &payload);
        let mut bytes = Vec::with_capacity(CHECKPOINT_HEADER + payload.len());
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&digest);
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8], expected: &NativeEventIdentity) -> Result<Self, PodError> {
        if bytes.len() < CHECKPOINT_HEADER || bytes.len() > CHECKPOINT_HEADER + MAX_CHECKPOINT_BYTES
        {
            return Err(PodError::Uncertain(
                "native segment checkpoint is torn or oversized",
            ));
        }
        let len = u32::from_be_bytes(bytes[..4].try_into().expect("four bytes")) as usize;
        if len != bytes.len() - CHECKPOINT_HEADER || len == 0 {
            return Err(PodError::Uncertain(
                "native segment checkpoint length differs",
            ));
        }
        let payload = &bytes[CHECKPOINT_HEADER..];
        if hash(CHECKPOINT_DOMAIN, payload).as_slice() != &bytes[4..CHECKPOINT_HEADER] {
            return Err(PodError::Uncertain(
                "native segment checkpoint checksum differs",
            ));
        }
        let value: Self = serde_json::from_slice(payload)
            .map_err(|_| PodError::Uncertain("native segment checkpoint is malformed"))?;
        if serde_json::to_vec(&value)? != payload || value.identity != *expected {
            return Err(PodError::Conflict(
                "native segment checkpoint identity differs",
            ));
        }
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), PodError> {
        self.identity.validate()?;
        if self.version != 2
            || self.generation == 0
            || self.segments.is_empty()
            || self.segments.len() > MAX_SEGMENTS
            || self.retained_offsets.len() > MAX_OFFSETS
            || self.redacted_events.len() != self.retained_offsets.len()
            || self.pending_source_sequence.is_some_and(|sequence| {
                self.watermark.checked_add(1) != Some(sequence)
                    || self.redacted_snapshot.quarantined
            })
            || self.redacted_snapshot.identity != self.identity
            || self.redacted_snapshot.watermark != self.watermark
            || self.redacted_snapshot.earliest_retained
                != self
                    .retained_offsets
                    .first()
                    .map_or(self.watermark.saturating_add(1), |offset| {
                        offset.source_sequence
                    })
        {
            return Err(PodError::Invalid("native segment checkpoint shape"));
        }
        let mut prior: Option<String> = None;
        let mut prior_id: Option<u64> = None;
        let mut next_sequence = self
            .pruned_through
            .checked_add(1)
            .ok_or(PodError::Invalid("pruned source sequence exhausted"))?;
        for segment in &self.segments {
            if segment.id == 0
                || prior_id.is_some_and(|previous| previous.checked_add(1) != Some(segment.id))
                || segment.start_sequence != next_sequence
                || !hex_digest(&segment.prior_segment_digest)
                || !hex_digest(&segment.chain_digest)
                || segment.byte_len > MAX_SEGMENT_BYTES
                || prior
                    .as_ref()
                    .is_some_and(|prior| segment.prior_segment_digest != *prior)
                || (segment.byte_len == 0 && segment.end_sequence != segment.start_sequence - 1)
                || (segment.byte_len > 0 && segment.end_sequence < segment.start_sequence)
            {
                return Err(PodError::Invalid("native segment chain differs"));
            }
            prior = Some(segment.chain_digest.clone());
            prior_id = Some(segment.id);
            next_sequence = segment
                .end_sequence
                .checked_add(1)
                .ok_or(PodError::Invalid("segment source sequence exhausted"))?;
        }
        if (self.pruned_through == 0 && self.segments[0].id != 1)
            || (self.segments[0].id == 1 && self.segments[0].prior_segment_digest != "0".repeat(64))
        {
            return Err(PodError::Invalid("initial segment has nonzero predecessor"));
        }
        if self.active().end_sequence != self.watermark || self.pruned_through > self.watermark {
            return Err(PodError::Invalid("native segment watermark differs"));
        }
        if self
            .retained_offsets
            .last()
            .is_some_and(|last| last.source_sequence != self.watermark)
        {
            return Err(PodError::Invalid("native segment indexed tail differs"));
        }
        let mut prior_offset_sequence = 0;
        for (offset, event) in self.retained_offsets.iter().zip(&self.redacted_events) {
            let segment = self
                .segments
                .iter()
                .find(|segment| segment.id == offset.segment_id)
                .ok_or(PodError::Invalid("native segment offset is pruned"))?;
            if offset.source_sequence == 0
                || offset.source_sequence > self.watermark
                || offset.source_sequence <= prior_offset_sequence
                || offset.source_sequence < segment.start_sequence
                || offset.source_sequence > segment.end_sequence
                || offset.event_id != native_event_id(&self.identity, offset.source_sequence)
                || event.source_sequence != offset.source_sequence
                || !hex_digest(&offset.frame_digest)
                || offset.frame_len < FRAME_HEADER as u32
                || offset.offset.saturating_add(offset.frame_len as u64) > segment.byte_len
            {
                return Err(PodError::Invalid("native segment offset differs"));
            }
            prior_offset_sequence = offset.source_sequence;
        }
        Ok(())
    }
}

fn new_segment(id: u64, start_sequence: u64, prior: &str) -> NativeSegmentMeta {
    NativeSegmentMeta {
        id,
        start_sequence,
        end_sequence: start_sequence - 1,
        byte_len: 0,
        prior_segment_digest: prior.into(),
        chain_digest: initial_chain_digest(id, prior),
    }
}

fn initial_chain_digest(id: u64, prior: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(CHAIN_DOMAIN);
    hash.update(id.to_be_bytes());
    hash.update(prior.as_bytes());
    hex(&hash.finalize())
}

fn chain_digest(previous: &str, frame_digest: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(CHAIN_DOMAIN);
    hash.update(previous.as_bytes());
    hash.update(frame_digest.as_bytes());
    hex(&hash.finalize())
}

fn hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Linux file port for the active segmented Codex event source. Every open is
/// no-follow, owner/mode/link checked, and parent inode-pinned.
pub struct LinuxNativeSegmentDirectory {
    root: PathBuf,
    held_root: File,
    owner_uid: u32,
    identity: (u64, u64),
}

impl LinuxNativeSegmentDirectory {
    pub fn from_private_slot(root: PathBuf) -> Result<Self, PodError> {
        private_directory(&root)?;
        let metadata = fs::symlink_metadata(&root)?;
        if metadata.mode() & 0o7777 != 0o700 {
            return Err(PodError::Refused("segment parent mode differs"));
        }
        let held_root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&root)?;
        let held = held_root.metadata()?;
        if (held.dev(), held.ino()) != (metadata.dev(), metadata.ino()) {
            return Err(PodError::Refused("held segment parent identity differs"));
        }
        Ok(Self {
            root,
            held_root,
            owner_uid: metadata.uid(),
            identity: (metadata.dev(), metadata.ino()),
        })
    }

    fn recheck(&self) -> Result<(), PodError> {
        private_directory(&self.root)?;
        let metadata = fs::symlink_metadata(&self.root)?;
        if (metadata.dev(), metadata.ino()) != self.identity
            || metadata.uid() != self.owner_uid
            || metadata.mode() & 0o7777 != 0o700
            || (
                self.held_root.metadata()?.dev(),
                self.held_root.metadata()?.ino(),
            ) != self.identity
        {
            return Err(PodError::Refused("segment parent identity changed"));
        }
        Ok(())
    }

    fn segment_path(&self, id: u64) -> Result<PathBuf, PodError> {
        if id == 0 {
            return Err(PodError::Invalid("zero native segment ID"));
        }
        Ok(self
            .held_root_path()
            .join(format!("native-events-{id:016x}.segment")))
    }

    fn held_root_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.held_root.as_raw_fd()))
    }

    fn checkpoint_path(&self) -> PathBuf {
        self.held_root_path().join("native-events.checkpoint")
    }

    /// The pod writer is the only caller. A checkpoint-less empty first
    /// segment is the harmless crash window after durable creation; any
    /// nonempty first segment without a checkpoint is ambiguous.
    pub fn open_or_initialize_writer(
        &self,
        identity: &NativeEventIdentity,
    ) -> Result<NativeSegmentCheckpoint, PodError> {
        self.recheck()?;
        self.recover_fsynced_temporary_checkpoint(identity)?;
        match fs::symlink_metadata(self.checkpoint_path()) {
            Ok(_) => self.read_checkpoint(identity),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let first = self.segment_path(1)?;
                match fs::symlink_metadata(&first) {
                    Ok(metadata) if self.safe_file(&first, &metadata) && metadata.len() == 0 => {}
                    Ok(_) => return Err(PodError::Uncertain("checkpoint-less segment differs")),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        self.create_empty_segment(1)?;
                    }
                    Err(error) => return Err(error.into()),
                }
                let initial = NativeSegmentCheckpoint::initial(identity.clone())?;
                self.commit_checkpoint(&initial)?;
                self.read_checkpoint(identity)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Complete a verified fsynced checkpoint that crashed before rename.
    /// An incomplete or conflicting temporary file remains uncertain.
    fn recover_fsynced_temporary_checkpoint(
        &self,
        identity: &NativeEventIdentity,
    ) -> Result<(), PodError> {
        let path = self.checkpoint_path();
        let temporary = path.with_extension("checkpoint-new");
        match fs::symlink_metadata(&temporary) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let candidate = self.read_checkpoint_payload_at(&temporary, identity)?;
        let previous = match fs::symlink_metadata(&path) {
            Ok(_) => Some(self.read_checkpoint_payload(identity)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        if !matches!(&previous, Some(old) if old.generation.checked_add(1) == Some(candidate.generation))
            && !(previous.is_none()
                && candidate == NativeSegmentCheckpoint::initial(identity.clone())?)
        {
            return Err(PodError::Uncertain(
                "temporary checkpoint generation differs",
            ));
        }
        self.verify_retained_segments(&candidate)?;
        self.verify_segment_inventory(&candidate)?;
        fs::rename(&temporary, &path)
            .map_err(|_| PodError::Uncertain("temporary checkpoint recovery rename unknown"))?;
        self.held_root
            .sync_all()
            .map_err(|_| PodError::Uncertain("temporary checkpoint recovery sync unknown"))?;
        self.recheck()
            .map_err(|_| PodError::Uncertain("checkpoint parent changed after recovery"))?;
        Ok(())
    }

    /// Durable creation occurs before a rollover checkpoint may name the new
    /// segment. A crash here leaves an empty orphan, never an unindexed event.
    pub fn create_empty_segment(&self, id: u64) -> Result<(), PodError> {
        self.recheck()?;
        let path = self.segment_path(id)?;
        let file = OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        file.sync_all()
            .map_err(|_| PodError::Uncertain("new segment sync unknown"))?;
        self.held_root
            .sync_all()
            .map_err(|_| PodError::Uncertain("new segment directory sync unknown"))?;
        self.recheck()
            .map_err(|_| PodError::Uncertain("new segment parent changed after creation"))?;
        Ok(())
    }

    pub fn append_frame_synced(
        &self,
        segment: &NativeSegmentMeta,
        private_payload: &[u8],
    ) -> Result<SegmentAppendReceipt, PodError> {
        self.recheck()?;
        if private_payload.is_empty() || private_payload.len() > MAX_FRAME_PAYLOAD {
            return Err(PodError::Invalid("private segment frame bound"));
        }
        let path = self.segment_path(segment.id)?;
        let mut file = self.open_checked(&path, true)?;
        let metadata = file.metadata()?;
        if metadata.len() != segment.byte_len {
            return Err(PodError::Uncertain("segment length differs before append"));
        }
        let digest = hash(FRAME_DOMAIN, private_payload);
        let mut frame = Vec::with_capacity(FRAME_HEADER + private_payload.len());
        frame.extend_from_slice(&(private_payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&digest);
        frame.extend_from_slice(private_payload);
        if segment.byte_len.saturating_add(frame.len() as u64) > MAX_SEGMENT_BYTES {
            return Err(PodError::Refused("segment requires rollover"));
        }
        file.write_all(&frame)
            .map_err(|_| PodError::Uncertain("segment append unknown"))?;
        file.sync_data()
            .map_err(|_| PodError::Uncertain("segment append sync unknown"))?;
        if file
            .metadata()
            .map_err(|_| PodError::Uncertain("segment length after append unknown"))?
            .len()
            != segment.byte_len + frame.len() as u64
        {
            return Err(PodError::Uncertain("segment append length unknown"));
        }
        self.recheck()
            .map_err(|_| PodError::Uncertain("segment parent changed after append"))?;
        Ok(SegmentAppendReceipt {
            segment_id: segment.id,
            offset: segment.byte_len,
            frame_len: frame.len() as u32,
            frame_digest: hex(&digest),
        })
    }

    /// Checkpoint replace is fsynced before any old-segment prune may occur.
    pub fn commit_checkpoint(&self, checkpoint: &NativeSegmentCheckpoint) -> Result<(), PodError> {
        self.recheck()?;
        let path = self.checkpoint_path();
        let temporary = path.with_extension("checkpoint-new");
        let bytes = checkpoint.encode()?;
        let previous = match fs::symlink_metadata(&path) {
            Ok(_) => Some(self.read_checkpoint_payload(&checkpoint.identity)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        if !matches!(&previous, Some(value) if value.generation.checked_add(1) == Some(checkpoint.generation))
            && !(previous.is_none()
                && *checkpoint == NativeSegmentCheckpoint::initial(checkpoint.identity.clone())?)
        {
            return Err(PodError::Refused(
                "native checkpoint generation is stale or skipped",
            ));
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        file.write_all(&bytes)
            .map_err(|_| PodError::Uncertain("checkpoint write unknown"))?;
        file.sync_all()
            .map_err(|_| PodError::Uncertain("checkpoint sync unknown"))?;
        fs::rename(&temporary, &path)
            .map_err(|_| PodError::Uncertain("checkpoint replace unknown"))?;
        self.held_root
            .sync_all()
            .map_err(|_| PodError::Uncertain("checkpoint directory sync unknown"))?;
        self.recheck()
            .map_err(|_| PodError::Uncertain("checkpoint parent changed after replace"))?;
        Ok(())
    }

    pub fn read_checkpoint(
        &self,
        expected: &NativeEventIdentity,
    ) -> Result<NativeSegmentCheckpoint, PodError> {
        self.recheck()?;
        if fs::symlink_metadata(self.checkpoint_path().with_extension("checkpoint-new")).is_ok() {
            return Err(PodError::Uncertain(
                "native checkpoint temporary file remains",
            ));
        }
        let checkpoint = self.read_checkpoint_payload(expected)?;
        self.verify_retained_segments(&checkpoint)?;
        self.verify_segment_inventory(&checkpoint)?;
        Ok(checkpoint)
    }

    /// A retained reader first performs the bounded full attach above. Later
    /// checkpoints verify only newly appended frames and metadata for the
    /// unchanged prefix. Falling behind all retained segments performs one
    /// bounded reattach; the checkpoint's indexed gap remains explicit.
    pub fn read_checkpoint_incremental(
        &self,
        previous: &NativeSegmentCheckpoint,
    ) -> Result<NativeSegmentCheckpoint, PodError> {
        self.recheck()?;
        previous.validate()?;
        if fs::symlink_metadata(self.checkpoint_path().with_extension("checkpoint-new")).is_ok() {
            return Err(PodError::Uncertain(
                "native checkpoint temporary file remains",
            ));
        }
        let current = self.read_checkpoint_payload(&previous.identity)?;
        if current == *previous {
            for segment in &current.segments {
                self.checked_segment_length(segment)?;
            }
            self.verify_segment_inventory(&current)?;
            return Ok(current);
        }
        if current.generation <= previous.generation
            || current.watermark < previous.watermark
            || current.pruned_through < previous.pruned_through
        {
            return Err(PodError::Uncertain("native checkpoint moved backward"));
        }
        let overlap = current
            .segments
            .iter()
            .any(|segment| previous.segments.iter().any(|old| old.id == segment.id));
        if !overlap {
            self.verify_retained_segments(&current)?;
        } else {
            for segment in &current.segments {
                let old = previous.segments.iter().find(|old| old.id == segment.id);
                if let Some(old) = old {
                    if segment.start_sequence != old.start_sequence
                        || segment.prior_segment_digest != old.prior_segment_digest
                        || segment.end_sequence < old.end_sequence
                        || segment.byte_len < old.byte_len
                    {
                        return Err(PodError::Uncertain(
                            "retained native segment moved backward",
                        ));
                    }
                }
                self.verify_segment_suffix(segment, old)?;
            }
        }
        self.verify_segment_inventory(&current)?;
        self.recheck()?;
        Ok(current)
    }

    fn checked_segment_length(&self, segment: &NativeSegmentMeta) -> Result<(), PodError> {
        let path = self.segment_path(segment.id)?;
        let file = self.open_checked(&path, false)?;
        if file.metadata()?.len() != segment.byte_len {
            return Err(PodError::Uncertain("native segment length changed"));
        }
        Ok(())
    }

    fn verify_segment_suffix(
        &self,
        segment: &NativeSegmentMeta,
        previous: Option<&NativeSegmentMeta>,
    ) -> Result<(), PodError> {
        let path = self.segment_path(segment.id)?;
        let mut file = self.open_checked(&path, false)?;
        if file.metadata()?.len() != segment.byte_len {
            return Err(PodError::Uncertain("native segment length changed"));
        }
        let from = previous.map_or(0, |old| old.byte_len);
        let mut chain = previous.map_or_else(
            || initial_chain_digest(segment.id, &segment.prior_segment_digest),
            |old| old.chain_digest.clone(),
        );
        file.seek(SeekFrom::Start(from))?;
        let mut bytes = vec![0; (segment.byte_len - from) as usize];
        file.read_exact(&mut bytes)?;
        let mut at = 0usize;
        let mut frames = 0u64;
        while at < bytes.len() {
            let (_, frame_len, digest) = checked_frame(&bytes[at..])?;
            chain = chain_digest(&chain, &digest);
            at += frame_len;
            frames += 1;
        }
        let old_end = previous.map_or(segment.start_sequence - 1, |old| old.end_sequence);
        if chain != segment.chain_digest || frames != segment.end_sequence - old_end {
            return Err(PodError::Uncertain("native segment suffix chain differs"));
        }
        Ok(())
    }

    fn verify_segment_inventory(
        &self,
        checkpoint: &NativeSegmentCheckpoint,
    ) -> Result<(), PodError> {
        let predecessor = checkpoint.segments[0].id.checked_sub(1);
        let successor = checkpoint.active().id.checked_add(1);
        let mut extras = 0;
        for entry in fs::read_dir(self.held_root_path())? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or(PodError::Uncertain("native segment filename is invalid"))?;
            if !name.starts_with("native-events-") || !name.ends_with(".segment") {
                continue;
            }
            let middle = &name[14..name.len() - 8];
            let id = (middle.len() == 16)
                .then(|| u64::from_str_radix(middle, 16).ok())
                .flatten()
                .ok_or(PodError::Uncertain("native segment filename differs"))?;
            if checkpoint.segments.iter().any(|segment| segment.id == id) {
                continue;
            }
            extras += 1;
            if extras > 2 {
                return Err(PodError::Uncertain("native segment orphan bound exceeded"));
            }
            let path = self.segment_path(id)?;
            let metadata = fs::symlink_metadata(&path)?;
            if !self.safe_file(&path, &metadata) || metadata.len() > MAX_SEGMENT_BYTES {
                return Err(PodError::Uncertain(
                    "native segment orphan identity differs",
                ));
            }
            let durable_prune_pending = Some(id) == predecessor && checkpoint.pruned_through > 0;
            let empty_successor = Some(id) == successor && metadata.len() == 0;
            if !durable_prune_pending && !empty_successor {
                return Err(PodError::Uncertain("uncheckpointed native segment exists"));
            }
        }
        Ok(())
    }

    /// A crash between empty successor creation and checkpoint rename leaves
    /// exactly this harmless orphan. Only a verified current checkpoint may
    /// authorise its removal; a nonempty successor remains uncertain.
    pub fn discard_empty_successor_after_reopen(
        &self,
        expected: &NativeEventIdentity,
    ) -> Result<bool, PodError> {
        let checkpoint = self.read_checkpoint(expected)?;
        let id = checkpoint
            .active()
            .id
            .checked_add(1)
            .ok_or(PodError::Invalid("native segment ID exhausted"))?;
        let path = self.segment_path(id)?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        if !self.safe_file(&path, &metadata) || metadata.len() != 0 {
            return Err(PodError::Uncertain(
                "native successor is not an empty private file",
            ));
        }
        fs::remove_file(&path)
            .map_err(|_| PodError::Uncertain("empty successor removal unknown"))?;
        self.held_root
            .sync_all()
            .map_err(|_| PodError::Uncertain("empty successor directory sync unknown"))?;
        self.recheck()
            .map_err(|_| PodError::Uncertain("segment parent changed after orphan recovery"))?;
        Ok(true)
    }

    /// The checkpoint may be durable while the old segment's unlink was lost
    /// to a crash. Its predecessor is outside the retained range and can be
    /// pruned only after rereading that exact current checkpoint.
    pub fn prune_durable_predecessor_after_reopen(
        &self,
        expected: &NativeEventIdentity,
    ) -> Result<bool, PodError> {
        let checkpoint = self.read_checkpoint(expected)?;
        if checkpoint.pruned_through == 0 {
            return Ok(false);
        }
        let id = checkpoint.segments[0]
            .id
            .checked_sub(1)
            .ok_or(PodError::Invalid("native predecessor ID underflow"))?;
        let path = self.segment_path(id)?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        if !self.safe_file(&path, &metadata) || metadata.len() > MAX_SEGMENT_BYTES {
            return Err(PodError::Uncertain("native predecessor identity differs"));
        }
        fs::remove_file(&path)
            .map_err(|_| PodError::Uncertain("native predecessor prune unknown"))?;
        self.held_root
            .sync_all()
            .map_err(|_| PodError::Uncertain("native predecessor prune sync unknown"))?;
        self.recheck()
            .map_err(|_| PodError::Uncertain("segment parent changed after predecessor prune"))?;
        Ok(true)
    }

    fn read_checkpoint_payload(
        &self,
        expected: &NativeEventIdentity,
    ) -> Result<NativeSegmentCheckpoint, PodError> {
        self.read_checkpoint_payload_at(&self.checkpoint_path(), expected)
    }

    fn read_checkpoint_payload_at(
        &self,
        path: &Path,
        expected: &NativeEventIdentity,
    ) -> Result<NativeSegmentCheckpoint, PodError> {
        let mut file = self.open_checked(path, false)?;
        if file.metadata()?.len() as usize > MAX_CHECKPOINT_BYTES + CHECKPOINT_HEADER {
            return Err(PodError::Uncertain("checkpoint file exceeds bound"));
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take((MAX_CHECKPOINT_BYTES + CHECKPOINT_HEADER + 1) as u64)
            .read_to_end(&mut bytes)?;
        let checkpoint = NativeSegmentCheckpoint::decode(&bytes, expected)?;
        Ok(checkpoint)
    }

    /// Bounded reopen verification scans at most four 1 MiB segments, never
    /// a lifetime chain. An uncheckpointed partial tail refuses rather than
    /// assuming the attempted event was absent.
    pub fn verify_retained_segments(
        &self,
        checkpoint: &NativeSegmentCheckpoint,
    ) -> Result<(), PodError> {
        self.recheck()?;
        checkpoint.validate()?;
        for segment in &checkpoint.segments {
            let path = self.segment_path(segment.id)?;
            let mut file = self.open_checked(&path, false)?;
            if file.metadata()?.len() != segment.byte_len {
                return Err(PodError::Uncertain(
                    "segment tail differs from durable checkpoint",
                ));
            }
            let mut bytes = Vec::new();
            (&mut file)
                .take(MAX_SEGMENT_BYTES + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 != segment.byte_len {
                return Err(PodError::Uncertain("segment changed during read"));
            }
            let mut chain = initial_chain_digest(segment.id, &segment.prior_segment_digest);
            let mut at = 0usize;
            let mut frames = 0u64;
            while at < bytes.len() {
                let (payload, frame_len, digest) = checked_frame(&bytes[at..])?;
                let _ = payload;
                chain = chain_digest(&chain, &digest);
                at += frame_len;
                frames += 1;
            }
            if chain != segment.chain_digest
                || (segment.byte_len == 0 && frames != 0)
                || (segment.byte_len > 0
                    && frames != segment.end_sequence - segment.start_sequence + 1)
            {
                return Err(PodError::Uncertain("segment chain digest or count differs"));
            }
        }
        self.recheck()?;
        Ok(())
    }

    /// Offset-indexed private page read: seek and verify only requested frames.
    pub fn read_indexed_page(
        &self,
        checkpoint: &NativeSegmentCheckpoint,
        after_sequence: u64,
        limit: usize,
    ) -> Result<(Vec<IndexedPrivateFrame>, Option<(u64, u64)>), PodError> {
        self.recheck()?;
        checkpoint.validate()?;
        if limit == 0 || limit > MAX_OFFSETS || after_sequence > checkpoint.watermark {
            return Err(PodError::Invalid("private segment cursor or limit"));
        }
        let first = checkpoint
            .retained_offsets
            .first()
            .map(|offset| offset.source_sequence)
            .unwrap_or(checkpoint.watermark.saturating_add(1));
        let gap =
            (after_sequence.saturating_add(1) < first).then(|| (after_sequence + 1, first - 1));
        let mut result = Vec::new();
        for offset in checkpoint
            .retained_offsets
            .iter()
            .filter(|value| value.source_sequence > after_sequence)
            .take(limit)
        {
            let path = self.segment_path(offset.segment_id)?;
            let mut file = self.open_checked(&path, false)?;
            file.seek(SeekFrom::Start(offset.offset))?;
            let mut frame = vec![0; offset.frame_len as usize];
            file.read_exact(&mut frame)?;
            let (payload, frame_len, digest) = checked_frame(&frame)?;
            if frame_len != frame.len() || digest != offset.frame_digest {
                return Err(PodError::Uncertain("indexed private frame differs"));
            }
            result.push(IndexedPrivateFrame {
                source_sequence: offset.source_sequence,
                event_id: offset.event_id.clone(),
                private_payload: payload.to_vec(),
            });
        }
        self.recheck()?;
        Ok((result, gap))
    }

    /// Must be called only after a checkpoint that no longer names this exact
    /// segment has returned from fsync. A failed removal leaves an extra file
    /// and reports uncertainty; it never rewrites the checkpoint backwards.
    pub fn prune_after_checkpoint(
        &self,
        removed: &NativeSegmentMeta,
        successor: &NativeSegmentCheckpoint,
    ) -> Result<(), PodError> {
        self.recheck()?;
        if successor
            .segments
            .iter()
            .any(|segment| segment.id == removed.id)
            || removed.id.checked_add(1) != Some(successor.segments[0].id)
            || successor.pruned_through != removed.end_sequence
            || successor.segments[0].prior_segment_digest != removed.chain_digest
            || self.read_checkpoint(&successor.identity)? != *successor
        {
            return Err(PodError::Refused(
                "segment prune lacks durable successor checkpoint",
            ));
        }
        let path = self.segment_path(removed.id)?;
        let metadata = fs::symlink_metadata(&path)?;
        if !self.safe_file(&path, &metadata) || metadata.len() != removed.byte_len {
            return Err(PodError::Refused("segment prune identity changed"));
        }
        fs::remove_file(&path).map_err(|_| PodError::Uncertain("segment remove unknown"))?;
        self.held_root
            .sync_all()
            .map_err(|_| PodError::Uncertain("segment prune directory sync unknown"))?;
        Ok(())
    }

    fn open_checked(&self, path: &Path, writable: bool) -> Result<File, PodError> {
        let metadata = fs::symlink_metadata(path)?;
        if !self.safe_file(path, &metadata) {
            return Err(PodError::Refused("private segment file identity differs"));
        }
        let file = OpenOptions::new()
            .read(true)
            .append(writable)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let held = file.metadata()?;
        if !self.safe_file(path, &held)
            || (held.dev(), held.ino()) != (metadata.dev(), metadata.ino())
        {
            return Err(PodError::Refused("held private segment inode differs"));
        }
        Ok(file)
    }

    fn safe_file(&self, path: &Path, metadata: &fs::Metadata) -> bool {
        path.parent() == Some(self.held_root_path().as_path())
            && metadata.is_file()
            && metadata.mode() & 0o7777 == 0o600
            && metadata.uid() == self.owner_uid
            && metadata.dev() == self.identity.0
            && metadata.nlink() == 1
    }
}

fn checked_frame(bytes: &[u8]) -> Result<(&[u8], usize, String), PodError> {
    if bytes.len() < FRAME_HEADER {
        return Err(PodError::Uncertain("segment frame tail is torn"));
    }
    let len = u32::from_be_bytes(bytes[..4].try_into().expect("four bytes")) as usize;
    let frame_len = FRAME_HEADER
        .checked_add(len)
        .filter(|value| len > 0 && len <= MAX_FRAME_PAYLOAD && *value <= bytes.len())
        .ok_or(PodError::Uncertain("segment frame length is invalid"))?;
    let payload = &bytes[FRAME_HEADER..frame_len];
    let digest = hash(FRAME_DOMAIN, payload);
    if digest.as_slice() != &bytes[4..FRAME_HEADER] {
        return Err(PodError::Uncertain("segment frame checksum differs"));
    }
    Ok((payload, frame_len, hex(&digest)))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    use podbay_core::{
        AttemptId, Epoch, PodId, ResourceId, RunId, ScopeId, SessionId, StoreLineageId,
    };

    use super::*;

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        files: LinuxNativeSegmentDirectory,
        checkpoint: NativeSegmentCheckpoint,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "podbay-native-segments-{}-{}",
                std::process::id(),
                NEXT_DIR.fetch_add(1, Ordering::Relaxed),
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let files = LinuxNativeSegmentDirectory::from_private_slot(root.clone()).unwrap();
            let checkpoint = NativeSegmentCheckpoint::initial(identity()).unwrap();
            files.create_empty_segment(1).unwrap();
            files.commit_checkpoint(&checkpoint).unwrap();
            Self {
                root,
                files,
                checkpoint,
            }
        }

        fn append(&mut self, private_payload: &[u8]) {
            let sequence = self.checkpoint.watermark + 1;
            self.checkpoint = self.checkpoint.reserve_native_take().unwrap();
            self.files.commit_checkpoint(&self.checkpoint).unwrap();
            let receipt = self
                .files
                .append_frame_synced(self.checkpoint.active(), private_payload)
                .unwrap();
            let event = PublicNativeEvent {
                event_id: native_event_id(&self.checkpoint.identity, sequence),
                schema_version: 1,
                identity: self.checkpoint.identity.clone(),
                committed_cursor: sequence,
                source_sequence: sequence,
                recorded_at_unix_millis: 1,
                occurred_at_unix_millis: None,
                provenance: "codex.app-server.pod-observed/1".into(),
                correlation_id: None,
                causation_id: None,
                kind: crate::native_events::NativeEventKind::Output,
                status: None,
                external_conflict: false,
            };
            self.checkpoint = self
                .checkpoint
                .after_synced_append(sequence, event, &receipt)
                .unwrap();
            self.files.commit_checkpoint(&self.checkpoint).unwrap();
        }

        fn rollover(&mut self) {
            let next_id = self.checkpoint.active().id + 1;
            self.files.create_empty_segment(next_id).unwrap();
            let plan = self.checkpoint.rollover_plan().unwrap();
            self.files.commit_checkpoint(&plan.checkpoint).unwrap();
            if let Some(removed) = &plan.prune {
                self.files
                    .prune_after_checkpoint(removed, &plan.checkpoint)
                    .unwrap();
            }
            self.checkpoint = plan.checkpoint;
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
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

    #[test]
    fn checkpoint_reopens_and_indexed_read_keeps_private_bytes_out_of_debug() {
        let mut fixture = Fixture::new();
        fixture.append(b"private native prompt contents");
        let reopened =
            LinuxNativeSegmentDirectory::from_private_slot(fixture.root.clone()).unwrap();
        let checkpoint = reopened.read_checkpoint(&identity()).unwrap();
        let (page, gap) = reopened.read_indexed_page(&checkpoint, 0, 4).unwrap();
        assert_eq!(gap, None);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].source_sequence(), 1);
        assert_eq!(page[0].private_payload(), b"private native prompt contents");
        assert!(!format!("{:?}", page[0]).contains("prompt"));
        assert!(
            !String::from_utf8(checkpoint.encode().unwrap())
                .unwrap_or_default()
                .contains("prompt")
        );
    }

    #[test]
    fn rollover_prunes_only_after_durable_successor_and_reports_slow_reader_gap() {
        let mut fixture = Fixture::new();
        for sequence in 1..=5 {
            fixture.append(format!("private-{sequence}").as_bytes());
            if sequence < 5 {
                fixture.rollover();
            }
        }
        assert_eq!(fixture.checkpoint.segments.len(), MAX_SEGMENTS);
        assert_eq!(fixture.checkpoint.pruned_through, 1);
        assert!(!fixture.files.segment_path(1).unwrap().exists());
        let reopened = fixture.files.read_checkpoint(&identity()).unwrap();
        let (page, gap) = fixture.files.read_indexed_page(&reopened, 0, 8).unwrap();
        assert_eq!(gap, Some((1, 1)));
        assert_eq!(page.len(), 4);
        assert_eq!(page[0].source_sequence(), 2);
        assert_eq!(page[3].private_payload(), b"private-5");
    }

    #[test]
    fn unsnapshotted_append_is_uncertain_on_reopen_and_cannot_be_blindly_repeated() {
        let fixture = Fixture::new();
        fixture
            .files
            .append_frame_synced(fixture.checkpoint.active(), b"possibly applied")
            .unwrap();
        let reopened =
            LinuxNativeSegmentDirectory::from_private_slot(fixture.root.clone()).unwrap();
        assert!(matches!(
            reopened.read_checkpoint(&identity()),
            Err(PodError::Uncertain(_))
        ));
        assert!(matches!(
            reopened.append_frame_synced(fixture.checkpoint.active(), b"possibly applied"),
            Err(PodError::Uncertain(_)),
        ));
    }

    #[test]
    fn torn_tail_and_nonempty_orphan_refuse_reopen() {
        let fixture = Fixture::new();
        let mut segment = OpenOptions::new()
            .append(true)
            .open(fixture.files.segment_path(1).unwrap())
            .unwrap();
        segment.write_all(&[0, 0, 0, 4, 1]).unwrap();
        segment.sync_data().unwrap();
        assert!(matches!(
            fixture.files.read_checkpoint(&identity()),
            Err(PodError::Uncertain(_))
        ));

        // A distinct fixture isolates the orphan case from the torn tail.
        let second = Fixture::new();
        second.files.create_empty_segment(2).unwrap();
        assert!(second.files.read_checkpoint(&identity()).is_ok());
        fs::write(second.files.segment_path(2).unwrap(), b"unindexed").unwrap();
        assert!(matches!(
            second.files.read_checkpoint(&identity()),
            Err(PodError::Uncertain(_))
        ));
    }

    #[test]
    fn empty_rollover_orphan_can_be_discarded_after_verified_reopen() {
        let fixture = Fixture::new();
        fixture.files.create_empty_segment(2).unwrap();
        let reopened =
            LinuxNativeSegmentDirectory::from_private_slot(fixture.root.clone()).unwrap();
        assert!(
            reopened
                .discard_empty_successor_after_reopen(&identity())
                .unwrap()
        );
        assert!(!reopened.segment_path(2).unwrap().exists());
        assert!(
            !reopened
                .discard_empty_successor_after_reopen(&identity())
                .unwrap()
        );
    }

    #[test]
    fn bounded_offset_index_reports_explicit_gap_without_lifetime_replay() {
        let mut fixture = Fixture::new();
        for _ in 0..(MAX_OFFSETS + 7) {
            fixture.append(b"private notification");
        }
        let checkpoint = fixture.files.read_checkpoint(&identity()).unwrap();
        assert_eq!(checkpoint.retained_offsets.len(), MAX_OFFSETS);
        assert_eq!(checkpoint.redacted_snapshot.earliest_retained, 8);
        let (page, gap) = fixture.files.read_indexed_page(&checkpoint, 0, 4).unwrap();
        assert_eq!(gap, Some((1, 7)));
        assert_eq!(page.len(), 4);
        assert_eq!(page[0].source_sequence(), 8);
        let (next, no_gap) = fixture.files.read_indexed_page(&checkpoint, 11, 4).unwrap();
        assert_eq!(no_gap, None);
        assert_eq!(next[0].source_sequence(), 12);
    }

    #[test]
    fn long_bootstrap_replays_all_indexed_pages_without_gap() {
        let mut fixture = Fixture::new();
        for _ in 0..160 {
            fixture.append(b"private bootstrap notification");
        }
        let checkpoint = fixture.files.read_checkpoint(&identity()).unwrap();
        assert_eq!(checkpoint.redacted_snapshot.earliest_retained, 1);
        let mut after = 0;
        let mut count = 0;
        loop {
            let (page, gap) = fixture
                .files
                .read_indexed_page(&checkpoint, after, 64)
                .unwrap();
            assert_eq!(gap, None);
            if page.is_empty() {
                break;
            }
            count += page.len();
            after = page.last().unwrap().source_sequence();
        }
        assert_eq!(count, 160);
        assert_eq!(after, 160);
    }

    #[test]
    fn compact_checkpoint_accepts_maximal_escaped_valid_identity() {
        let field = "\"".repeat(256);
        let identity = NativeEventIdentity {
            store_lineage: field.clone(),
            scope_id: field.clone(),
            session_id: field.clone(),
            run_id: field.clone(),
            attempt_id: field.clone(),
            pod_id: field.clone(),
            pod_incarnation: 1,
            resource_id: field,
            resource_epoch: 1,
        };
        let mut checkpoint = NativeSegmentCheckpoint::initial(identity.clone()).unwrap();
        for sequence in 1..=64 {
            checkpoint = checkpoint.reserve_native_take().unwrap();
            let receipt = SegmentAppendReceipt {
                segment_id: checkpoint.active().id,
                offset: checkpoint.active().byte_len,
                frame_len: 37,
                frame_digest: "0".repeat(64),
            };
            let event = public_event(&identity, sequence, 1, NativeEventKind::Output, None, false);
            checkpoint = checkpoint
                .after_synced_append(sequence, event, &receipt)
                .unwrap();
        }
        assert!(checkpoint.encode().unwrap().len() <= MAX_CHECKPOINT_BYTES + CHECKPOINT_HEADER);
    }

    #[test]
    fn incremental_reader_verifies_new_suffix_and_refuses_corruption() {
        let mut fixture = Fixture::new();
        let initial = fixture.checkpoint.clone();
        fixture.append(b"private first frame");
        assert_eq!(
            fixture.files.read_checkpoint_incremental(&initial).unwrap(),
            fixture.checkpoint,
        );
        let previous = fixture.checkpoint.clone();
        fixture.append(b"private second frame");
        assert_eq!(
            fixture
                .files
                .read_checkpoint_incremental(&previous)
                .unwrap(),
            fixture.checkpoint,
        );
        let path = fixture
            .files
            .segment_path(fixture.checkpoint.active().id)
            .unwrap();
        let mut file = OpenOptions::new().write(true).open(path).unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(b"!").unwrap();
        file.sync_data().unwrap();
        assert!(matches!(
            fixture.files.read_checkpoint_incremental(&previous),
            Err(PodError::Uncertain(_)),
        ));
    }

    #[test]
    fn incremental_reader_tracks_durable_rollover_and_pruned_prefix() {
        let mut fixture = Fixture::new();
        for sequence in 1..=4 {
            fixture.append(format!("private-{sequence}").as_bytes());
            if sequence < 4 {
                fixture.rollover();
            }
        }
        let prior = fixture.checkpoint.clone();
        fixture.rollover();
        fixture.append(b"private after rollover");
        assert_eq!(fixture.checkpoint.pruned_through, 1);
        assert_eq!(
            fixture.files.read_checkpoint_incremental(&prior).unwrap(),
            fixture.checkpoint
        );
    }

    #[test]
    fn stale_generation_cannot_replace_current_checkpoint() {
        let mut fixture = Fixture::new();
        let original = fixture.checkpoint.clone();
        fixture.append(b"private notification");
        assert!(matches!(
            fixture.files.commit_checkpoint(&original),
            Err(PodError::Refused(_)),
        ));
        assert_eq!(
            fixture.files.read_checkpoint(&identity()).unwrap(),
            fixture.checkpoint
        );
    }

    #[test]
    fn failed_successor_checkpoint_cannot_authorise_prune() {
        let mut fixture = Fixture::new();
        for sequence in 1..=4 {
            fixture.append(format!("private-{sequence}").as_bytes());
            if sequence < 4 {
                fixture.rollover();
            }
        }
        fixture.files.create_empty_segment(5).unwrap();
        let plan = fixture.checkpoint.rollover_plan().unwrap();
        let removed = plan.prune.unwrap();
        assert!(matches!(
            fixture
                .files
                .prune_after_checkpoint(&removed, &plan.checkpoint),
            Err(PodError::Refused(_)),
        ));
        assert!(fixture.files.segment_path(1).unwrap().exists());
    }

    #[test]
    fn durable_successor_reopen_prunes_crash_left_predecessor() {
        let mut fixture = Fixture::new();
        for sequence in 1..=4 {
            fixture.append(format!("private-{sequence}").as_bytes());
            if sequence < 4 {
                fixture.rollover();
            }
        }
        fixture.files.create_empty_segment(5).unwrap();
        let plan = fixture.checkpoint.rollover_plan().unwrap();
        fixture.files.commit_checkpoint(&plan.checkpoint).unwrap();
        assert!(fixture.files.segment_path(1).unwrap().exists());
        let reopened =
            LinuxNativeSegmentDirectory::from_private_slot(fixture.root.clone()).unwrap();
        assert!(
            reopened
                .prune_durable_predecessor_after_reopen(&identity())
                .unwrap()
        );
        assert!(!reopened.segment_path(1).unwrap().exists());
        assert!(
            !reopened
                .prune_durable_predecessor_after_reopen(&identity())
                .unwrap()
        );
        assert_eq!(
            reopened.read_checkpoint(&identity()).unwrap(),
            plan.checkpoint
        );
    }

    #[test]
    fn symlink_and_parent_replacement_refuse() {
        let fixture = Fixture::new();
        let path = fixture.files.segment_path(1).unwrap();
        let other = fixture.root.join("other");
        fs::write(&other, b"not an event").unwrap();
        fs::set_permissions(&other, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&path).unwrap();
        symlink(&other, &path).unwrap();
        assert!(matches!(
            fixture.files.read_checkpoint(&identity()),
            Err(PodError::Refused(_)),
        ));
        let moved = fixture.root.with_extension("moved");
        fs::rename(&fixture.root, &moved).unwrap();
        assert!(matches!(
            fixture.files.create_empty_segment(2),
            Err(PodError::Io(_)) | Err(PodError::Refused(_)) | Err(PodError::Invalid(_))
        ));
        fs::rename(&moved, &fixture.root).unwrap();
    }
}
