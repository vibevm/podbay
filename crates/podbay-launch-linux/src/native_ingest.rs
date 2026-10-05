//! Read-only manager bridge for one current committed Codex V2 Resource.
//! Native JSONL never enters the public server response or a command effect.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use podbay_core::{AttemptId, Epoch, PodId, ResourceId, RunId, ScopeId, SessionId, StoreLineageId};
use podbay_host::ResolvedNativeCodexLaunch;
use podbay_store::{
    NativeEvidenceEvent, NativeEvidenceGap, NativeEvidenceIdentity, NativeEvidencePage,
    NativeEvidenceSnapshot,
};
use podbay_pod::{
    CODEX_V2_CAPABILITY, LinuxNativeSegmentDirectory, LinuxPeerEvidence,
    NativeEventCursor, NativeEventFidelity, NativeEventIdentity, NativeEventKind,
    NativeEventRead, NativeEventStatus, NativeSegmentCheckpoint, PodClient,
    PodError, PrivateNativeEvidence, codex_private_slot_directory,
    manifest_path_for_identity,
};
use sha2::{Digest, Sha256};

use crate::codex_v2::{
    ExecutableDigestWitness, TrustedCodexCredentialSource,
    preflight_committed_codex_v2_cached_read_only,
};

const MAX_PRIVATE_JSONL_BYTES: usize = 4 * 1_048_576;

/// A bounded private diagnostic for a native read refusal. PodError's dynamic
/// I/O and JSON messages can contain paths or source text, so only its static
/// variants may be recorded by the manager.
pub(crate) fn native_read_diagnostic_reason(error: &PodError) -> &'static str {
    match error {
        PodError::Invalid(reason)
        | PodError::Conflict(reason)
        | PodError::Uncertain(reason)
        | PodError::Refused(reason)
        | PodError::Unsupported(reason) => reason,
        PodError::Io(_) => "native evidence I/O",
        PodError::Json(_) => "native evidence JSON",
    }
}

pub struct TrustedNativeEventDirectory {
    path: PathBuf,
    identity: (u64, u64),
    segment_readers: Mutex<Vec<CachedSegmentReader>>,
    executable_witness: Mutex<ExecutableDigestWitness>,
}

struct CachedSegmentReader {
    path: PathBuf,
    identity: NativeEventIdentity,
    files: LinuxNativeSegmentDirectory,
    checkpoint: NativeSegmentCheckpoint,
}

impl TrustedNativeEventDirectory {
    pub fn from_trusted_policy(path: PathBuf) -> Result<Self, PodError> {
        let peer = LinuxPeerEvidence::for_current_process()
            .map_err(|_| PodError::Refused("manager OS identity unavailable"))?;
        let identity = checked_private_directory(&path, peer.uid())?;
        Ok(Self {
            path,
            identity,
            segment_readers: Mutex::new(Vec::new()),
            executable_witness: Mutex::new(ExecutableDigestWitness::default()),
        })
    }

    fn recheck(&self, uid: u32) -> Result<(), PodError> {
        if checked_private_directory(&self.path, uid)? != self.identity {
            return Err(PodError::Refused("trusted native event directory changed"));
        }
        Ok(())
    }

    fn preflight_cached(
        &self,
        launch: &ResolvedNativeCodexLaunch,
        credential: &TrustedCodexCredentialSource,
    ) -> Result<(), PodError> {
        let mut witness = self
            .executable_witness
            .lock()
            .map_err(|_| PodError::Uncertain("executable witness lock is poisoned"))?;
        preflight_committed_codex_v2_cached_read_only(launch, credential, &mut witness)?;
        Ok(())
    }
}

/// The raw evidence is deliberately non-serializable; Debug redacts it.
/// This point-in-time result is neither a durable manager event admission nor
/// proof of Run/Delivery settlement. Its public half retains pod watermark
/// and explicit gaps.
pub struct ManagerNativeEvidenceRead {
    redacted: NativeEventRead,
    private: Vec<PrivateNativeEvidence>,
}

impl std::fmt::Debug for ManagerNativeEvidenceRead {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagerNativeEvidenceRead")
            .field("redacted", &self.redacted)
            .field("private_event_count", &self.private.len())
            .finish()
    }
}

impl ManagerNativeEvidenceRead {
    pub fn redacted(&self) -> &NativeEventRead {
        &self.redacted
    }
    pub fn private_evidence(&self) -> &[PrivateNativeEvidence] {
        &self.private
    }
}

/// Convert an attested private page into the command-independent store DTO.
/// The store validates/deduplicates it again inside the current owner CAS.
pub(crate) fn read_committed_codex_native_page(
    launch: &ResolvedNativeCodexLaunch,
    credential: &TrustedCodexCredentialSource,
    directory: &TrustedNativeEventDirectory,
    identity: &NativeEvidenceIdentity,
    after: Option<u64>,
    limit: usize,
) -> Result<NativeEvidencePage, PodError> {
    let expected = NativeEventIdentity {
        store_lineage: identity.store_lineage.clone(),
        scope_id: identity.scope_id.clone(),
        session_id: identity.session_id.clone(),
        run_id: identity.run_id.clone(),
        attempt_id: identity.attempt_id.clone(),
        pod_id: identity.pod_id.clone(),
        pod_incarnation: identity.pod_incarnation,
        resource_id: identity.resource_id.clone(),
        resource_epoch: identity.resource_epoch,
    };
    // The first owner read starts at source sequence zero. A pod's None
    // cursor means snapshot-only, so the manager must pass the exact saved
    // source identity even for the initial page.
    let cursor = NativeEventCursor {
        identity: expected.clone(), sequence: after.unwrap_or(0),
    };
    let page = read_committed_codex_native_evidence(
        launch, credential, directory, Some(&cursor), limit,
    )?;
    let read = page.redacted();
    if read.snapshot.identity != expected || read.events.len() != page.private_evidence().len() {
        return Err(PodError::Refused("native evidence identity or private count differs"));
    }
    let events = read.events.iter().zip(page.private_evidence()).map(|(event, private)| {
        if event.source_sequence != private.source_sequence()
            || event.event_id != private.event_id()
        {
            return Err(PodError::Refused("private native EventId differs"));
        }
        let raw = private.private_jsonl();
        if !valid_private_jsonl_bytes(raw) {
            return Err(PodError::Refused("private native JSONL is malformed"));
        }
        let content_digest: String = Sha256::digest(raw)
            .iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(NativeEvidenceEvent {
            event_id: event.event_id.clone(), source_sequence: event.source_sequence,
            kind: kind_name(event.kind).into(),
            status: event.status.map(|status| status_name(status).into()),
            recorded_at_unix_millis: event.recorded_at_unix_millis,
            provenance: event.provenance.clone(),
            external_conflict: event.external_conflict,
            content_digest, raw_jsonl: raw.to_vec(),
        })
    }).collect::<Result<Vec<_>, _>>()?;
    let source = &read.snapshot;
    Ok(NativeEvidencePage {
        snapshot: NativeEvidenceSnapshot {
            identity: identity.clone(), watermark: source.watermark,
            earliest_retained: source.earliest_retained,
            last_status: source.last_status.map(|status| status_name(status).into()),
            output_events: source.output_events,
            question_events: source.question_events,
            permission_events: source.permission_events,
            opaque_events: source.opaque_events,
            external_conflict: source.external_conflict,
            fidelity: fidelity_name(source.fidelity).into(),
            quarantined: source.quarantined,
        },
        events,
        // The pod's snapshot-only empty gap keeps its cursor at `after`.
        // The manager advances across the explicitly declared missing range
        // so a client never loops forever on the same retained empty page.
        next_source_sequence: if read.events.is_empty() {
            read.gap.as_ref().map_or(read.next_cursor.sequence, |gap| gap.missing_through)
        } else {
            read.next_cursor.sequence
        },
        gap: read.gap.as_ref().map(|gap| NativeEvidenceGap {
            missing_from: gap.missing_from,
            missing_through: gap.missing_through,
            earliest_available: gap.earliest_available,
        }),
    })
}

fn valid_private_jsonl_bytes(raw: &[u8]) -> bool {
    !raw.is_empty()
        && raw.len() <= MAX_PRIVATE_JSONL_BYTES
        && std::str::from_utf8(raw).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_jsonl_ingest_bound_is_inclusive() {
        assert!(valid_private_jsonl_bytes(&vec![b'x'; MAX_PRIVATE_JSONL_BYTES]));
        assert!(!valid_private_jsonl_bytes(&vec![b'x'; MAX_PRIVATE_JSONL_BYTES + 1]));
        assert!(!valid_private_jsonl_bytes(&[]));
        assert!(!valid_private_jsonl_bytes(&[0xff]));
    }

    #[test]
    fn native_read_diagnostic_hides_dynamic_error_text() {
        let io = PodError::Io(std::io::Error::other("private path and content"));
        assert_eq!(native_read_diagnostic_reason(&io), "native evidence I/O");
        let json = PodError::Json(serde_json::from_str::<serde_json::Value>("{").unwrap_err());
        assert_eq!(native_read_diagnostic_reason(&json), "native evidence JSON");
        assert_eq!(native_read_diagnostic_reason(&PodError::Uncertain("checkpoint race")),
            "checkpoint race");
    }
}

fn kind_name(value: NativeEventKind) -> &'static str {
    match value {
        NativeEventKind::Status => "status", NativeEventKind::Output => "output",
        NativeEventKind::Question => "question", NativeEventKind::Permission => "permission",
        NativeEventKind::Opaque => "opaque",
    }
}

fn status_name(value: NativeEventStatus) -> &'static str {
    match value {
        NativeEventStatus::Idle => "idle", NativeEventStatus::Active => "active",
        NativeEventStatus::Waiting => "waiting", NativeEventStatus::Completed => "completed",
        NativeEventStatus::Failed => "failed", NativeEventStatus::Interrupted => "interrupted",
        NativeEventStatus::SystemError => "system_error",
    }
}

fn fidelity_name(value: NativeEventFidelity) -> &'static str {
    match value {
        NativeEventFidelity::Exact => "exact", NativeEventFidelity::Partial => "partial",
        NativeEventFidelity::Unknown => "unknown",
    }
}

/// Requires a host-minted committed proof, today's trusted credential source,
/// the same manager OS process, exact store inode/revision and an attested pod
/// socket around private evidence readback. Current slots use an indexed,
/// incrementally verified segment reader. A concurrent change refuses for a
/// read-only retry; the former single-file format is unsupported.
pub fn read_committed_codex_native_evidence(
    launch: &ResolvedNativeCodexLaunch,
    credential: &TrustedCodexCredentialSource,
    directory: &TrustedNativeEventDirectory,
    cursor: Option<&NativeEventCursor>,
    limit: usize,
) -> Result<ManagerNativeEvidenceRead, PodError> {
    if !(1..=64).contains(&limit) {
        return Err(PodError::Invalid("native evidence page limit"));
    }
    let peer = LinuxPeerEvidence::for_current_process()
        .map_err(|_| PodError::Refused("manager OS identity unavailable"))?;
    if peer.attested_peer() != launch.manager_peer() {
        return Err(PodError::Refused("manager process changed"));
    }
    directory.recheck(peer.uid())?;
    directory.preflight_cached(launch, credential)?;
    let store_identity = checked_store_file(launch.store_path(), peer.uid())?;
    if store_identity != launch.store_file_identity() {
        return Err(PodError::Refused("current store file changed"));
    }
    let wire = launch.descriptor();
    let resource = wire
        .resource(0)
        .ok_or(PodError::Invalid("Codex Resource absent"))?;
    let expected = NativeEventIdentity::from_resource(
        &StoreLineageId::try_from(launch.store_lineage())
            .map_err(|_| PodError::Invalid("native event lineage"))?,
        &ScopeId::try_from(wire.scope_id()).map_err(|_| PodError::Invalid("native event scope"))?,
        &SessionId::try_from(wire.session_id())
            .map_err(|_| PodError::Invalid("native event Session"))?,
        &RunId::try_from(wire.run_id()).map_err(|_| PodError::Invalid("native event Run"))?,
        &AttemptId::try_from(wire.attempt_id())
            .map_err(|_| PodError::Invalid("native event Attempt"))?,
        &PodId::try_from(wire.pod_id()).map_err(|_| PodError::Invalid("native event Pod"))?,
        Epoch::new(wire.pod_incarnation())
            .map_err(|_| PodError::Invalid("native event Pod incarnation"))?,
        &ResourceId::try_from(resource.resource_id)
            .map_err(|_| PodError::Invalid("native event Resource"))?,
        Epoch::new(resource.epoch).map_err(|_| PodError::Invalid("native event Resource epoch"))?,
    );
    if cursor.is_some_and(|cursor| cursor.identity != expected) {
        return Err(PodError::Refused(
            "native event cursor belongs to another Resource",
        ));
    }
    let path = manifest_path_for_identity(
        &directory.path,
        &PodId::try_from(wire.pod_id()).map_err(|_| PodError::Invalid("Codex Pod ID"))?,
        &AttemptId::try_from(wire.attempt_id())
            .map_err(|_| PodError::Invalid("Codex Attempt ID"))?,
        Epoch::new(wire.pod_incarnation()).map_err(|_| PodError::Invalid("Codex incarnation"))?,
    );
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or(PodError::Invalid("Codex manifest slot stem"))?;
    let private_slot = codex_private_slot_directory(
        &directory.path,
        &format!("podbay-pod-{stem}.service"),
        false,
    )?;
    let client = PodClient::connect(&path)?;
    let before = client.attested_status()?;
    if !status_matches(&before, launch, &expected, resource.epoch) {
        return Err(PodError::Refused("current Codex pod status differs"));
    }
    let checkpoint = private_slot.join("native-events.checkpoint");
    let old_format = private_slot.join("codex.native-events.log");
    if path_entry_exists(&old_format)? {
        return Err(PodError::Unsupported("old native event format"));
    }
    if !path_entry_exists(&checkpoint)? {
        return Err(PodError::Refused("native event checkpoint is missing"));
    }
    let mut snapshot_race_attempts = 0;
    let (redacted, private) = loop {
        let redacted = client.read_codex_native_events(cursor, limit)?;
        if redacted.snapshot.identity != expected {
            return Err(PodError::Refused(
                "native event snapshot belongs to another Resource",
            ));
        }
        let private = match directory.read_segmented_page(
            &private_slot,
            &expected,
            &redacted,
            cursor,
            limit,
        )? {
            Some(private) => private,
            None if snapshot_race_attempts < 2 => {
                snapshot_race_attempts += 1;
                continue;
            }
            None => {
                return Err(PodError::Uncertain(
                    "pod snapshot kept moving during bounded private read",
                ));
            }
        };
        break (redacted, private);
    };
    let after = client.attested_status()?;
    directory.recheck(peer.uid())?;
    directory.preflight_cached(launch, credential)?;
    if checked_store_file(launch.store_path(), peer.uid())? != store_identity
        || !path_entry_exists(&checkpoint)?
        || path_entry_exists(&old_format)?
        || !LinuxPeerEvidence::for_current_process()
            .is_ok_and(|current| current.attested_peer() == peer.attested_peer())
        || !status_matches(&after, launch, &expected, resource.epoch)
        || before.supervisor_pid != after.supervisor_pid
        || before.supervisor_start_ticks != after.supervisor_start_ticks
        || before.child_pid != after.child_pid
        || before.child_start_ticks != after.child_start_ticks
        || before.boot_id != after.boot_id
        || before.cgroup_path != after.cgroup_path
        || before.unit_name != after.unit_name
    {
        return Err(PodError::Refused(
            "manager, store or pod changed during native evidence read",
        ));
    }
    Ok(ManagerNativeEvidenceRead { redacted, private })
}

impl TrustedNativeEventDirectory {
    fn read_segmented_page(
        &self,
        private_slot: &Path,
        expected: &NativeEventIdentity,
        redacted: &NativeEventRead,
        cursor: Option<&NativeEventCursor>,
        limit: usize,
    ) -> Result<Option<Vec<PrivateNativeEvidence>>, PodError> {
        let mut readers = self
            .segment_readers
            .lock()
            .map_err(|_| PodError::Uncertain("native reader cache lock is poisoned"))?;
        let index = readers
            .iter()
            .position(|reader| reader.path == private_slot && reader.identity == *expected);
        let mut reader = if let Some(index) = index {
            readers.remove(index)
        } else {
            let files = LinuxNativeSegmentDirectory::from_private_slot(private_slot.to_path_buf())?;
            let checkpoint = files.read_checkpoint_live(expected)?;
            CachedSegmentReader {
                path: private_slot.to_path_buf(),
                identity: expected.clone(),
                files,
                checkpoint,
            }
        };
        reader.checkpoint = reader
            .files
            .read_checkpoint_incremental_live(&reader.checkpoint)?;
        if !reader
            .checkpoint
            .contains_redacted_prefix(redacted, cursor, limit)?
        {
            readers.push(reader);
            if readers.len() > 64 {
                readers.remove(0);
            }
            return Ok(None);
        }
        let after = cursor.map_or(reader.checkpoint.watermark, |cursor| cursor.sequence);
        let frames = if redacted.events.is_empty() {
            Vec::new()
        } else {
            reader
                .files
                .read_indexed_page(&reader.checkpoint, after, redacted.events.len())?
                .0
        };
        if frames.len() != redacted.events.len() {
            return Err(PodError::Uncertain(
                "indexed private page differs from pod reply",
            ));
        }
        let mut evidence = Vec::with_capacity(frames.len());
        for (frame, event) in frames.into_iter().zip(&redacted.events) {
            if frame.source_sequence() != event.source_sequence
                || frame.event_id() != event.event_id
            {
                return Err(PodError::Uncertain(
                    "private segment EventId differs from pod reply",
                ));
            }
            evidence.push(frame.into_private_evidence()?);
        }
        readers.push(reader);
        if readers.len() > 64 {
            readers.remove(0);
        }
        Ok(Some(evidence))
    }
}

fn path_entry_exists(path: &Path) -> Result<bool, PodError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn status_matches(
    status: &podbay_pod::PodStatus,
    launch: &ResolvedNativeCodexLaunch,
    expected: &NativeEventIdentity,
    resource_epoch: u64,
) -> bool {
    let Some(bound) = status.bound.as_ref() else {
        return false;
    };
    let peer = launch.manager_peer();
    status.pod_id == expected.pod_id
        && status.attempt_id == expected.attempt_id
        && status.incarnation == expected.pod_incarnation
        && bound.capability == CODEX_V2_CAPABILITY
        && bound.descriptor_digest == launch.descriptor().digest()
        && bound.effective_digest == launch.effective().digest()
        && bound.scope_id == expected.scope_id
        && bound.resource_id == expected.resource_id
        && bound.resource_epoch == resource_epoch
        && bound.store_lineage == expected.store_lineage
        && bound.owner_epoch == launch.owner_epoch()
        && bound.credential_epoch == launch.credential_epoch()
        && bound.manager_os_identity == peer.os_identity()
        && bound.manager_process_id == peer.native_process_id()
        && bound.manager_boot_identity == peer.boot_identity()
        && bound.manager_birth_identity == peer.birth_identity()
        && bound.manager_containment == peer.containment_identity()
}

fn checked_private_directory(path: &Path, uid: u32) -> Result<(u64, u64), PodError> {
    let metadata = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.mode() & 0o077 != 0
        || fs::canonicalize(path)? != path
    {
        return Err(PodError::Refused("private native event directory differs"));
    }
    Ok((metadata.dev(), metadata.ino()))
}

fn checked_store_file(path: &Path, uid: u32) -> Result<(u64, u64), PodError> {
    let metadata = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != uid
        || fs::canonicalize(path)? != path
    {
        return Err(PodError::Refused("native evidence store file differs"));
    }
    Ok((metadata.dev(), metadata.ino()))
}
