//! Read-only manager bridge for one current committed Codex V2 Resource.
//! Native JSONL never enters the public server response or a command effect.

use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use podbay_core::{AttemptId, Epoch, PodId, ResourceId, RunId, ScopeId, SessionId, StoreLineageId};
use podbay_host::ResolvedNativeCodexLaunch;
use podbay_pod::{
    CODEX_V2_CAPABILITY, LinuxNativeSegmentDirectory, LinuxPeerEvidence,
    MAX_PRIVATE_NATIVE_EVENT_LOG_BYTES, NativeEventCursor, NativeEventIdentity, NativeEventRead,
    NativeSegmentCheckpoint, PodClient, PodError, PrivateNativeEvidence,
    codex_private_slot_directory, decode_private_native_evidence_for_trusted_reader,
    manifest_path_for_identity,
};

use crate::codex_v2::{
    ExecutableDigestWitness, TrustedCodexCredentialSource,
    preflight_committed_codex_v2_cached_read_only,
};

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

/// Requires a host-minted committed proof, today's trusted credential source,
/// the same manager OS process, exact store inode/revision and an attested pod
/// socket around private evidence readback. New V2 slots use an indexed,
/// incrementally verified segment reader; historical v1 slots retain one
/// bounded full-copy diagnostic read. A concurrent change refuses for a
/// read-only retry.
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
    let historical = private_slot.join("codex.native-events.log");
    let segmented_present = path_entry_exists(&checkpoint)?;
    let historical_present = path_entry_exists(&historical)?;
    if historical_present && segment_file_present(&private_slot)? {
        return Err(PodError::Refused(
            "historical and segmented native evidence coexist",
        ));
    }
    if !matches!(
        (segmented_present, historical_present),
        (true, false) | (false, true)
    ) {
        return Err(PodError::Refused(
            "native evidence format is missing or ambiguous",
        ));
    }
    let mut snapshot_race_attempts = 0;
    let (redacted, private) = loop {
        let redacted = client.read_codex_native_events(cursor, limit)?;
        if redacted.snapshot.identity != expected {
            return Err(PodError::Refused(
                "native event snapshot belongs to another Resource",
            ));
        }
        let private = if segmented_present {
            match directory.read_segmented_page(
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
            }
        } else if redacted.events.is_empty() {
            Vec::new()
        } else {
            let raw = read_private_log_copy(&historical, peer.uid())?;
            decode_private_native_evidence_for_trusted_reader(&raw, &expected, &redacted.events)?
        };
        break (redacted, private);
    };
    let after = client.attested_status()?;
    directory.recheck(peer.uid())?;
    directory.preflight_cached(launch, credential)?;
    if checked_store_file(launch.store_path(), peer.uid())? != store_identity
        || path_entry_exists(&checkpoint)? != segmented_present
        || path_entry_exists(&historical)? != historical_present
        || (historical_present && segment_file_present(&private_slot)?)
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
            let checkpoint = files.read_checkpoint(expected)?;
            CachedSegmentReader {
                path: private_slot.to_path_buf(),
                identity: expected.clone(),
                files,
                checkpoint,
            }
        };
        reader.checkpoint = reader
            .files
            .read_checkpoint_incremental(&reader.checkpoint)?;
        if reader.checkpoint.redacted_read_after(cursor, limit)? != *redacted {
            readers.push(reader);
            if readers.len() > 64 {
                readers.remove(0);
            }
            return Ok(None);
        }
        let after = cursor.map_or(reader.checkpoint.watermark, |cursor| cursor.sequence);
        let (frames, _) = reader
            .files
            .read_indexed_page(&reader.checkpoint, after, limit)?;
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

fn segment_file_present(slot: &Path) -> Result<bool, PodError> {
    let mut found = false;
    for entry in fs::read_dir(slot)? {
        let name = entry?.file_name();
        let name = name
            .to_str()
            .ok_or(PodError::Refused("native slot filename is invalid"))?;
        found |= name.starts_with("native-events-") && name.ends_with(".segment");
    }
    Ok(found)
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

fn read_private_log_copy(path: &Path, uid: u32) -> Result<Vec<u8>, PodError> {
    let before = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || !before.is_file()
        || before.nlink() != 1
        || before.uid() != uid
        || before.mode() & 0o7777 != 0o600
        || before.len() > MAX_PRIVATE_NATIVE_EVENT_LOG_BYTES
        || fs::canonicalize(path)? != path
    {
        return Err(PodError::Refused("private native event log changed"));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let held = file.metadata()?;
    if (held.dev(), held.ino()) != (before.dev(), before.ino()) {
        return Err(PodError::Refused("private native event log inode changed"));
    }
    let mut raw = Vec::new();
    (&mut file)
        .take(MAX_PRIVATE_NATIVE_EVENT_LOG_BYTES + 1)
        .read_to_end(&mut raw)?;
    let after = fs::symlink_metadata(path)?;
    let held_after = file.metadata()?;
    if raw.len() as u64 > MAX_PRIVATE_NATIVE_EVENT_LOG_BYTES
        || before.len() != raw.len() as u64
        || after.len() != before.len()
        || held_after.len() != before.len()
        || (after.dev(), after.ino()) != (before.dev(), before.ino())
        || (held_after.dev(), held_after.ino()) != (before.dev(), before.ino())
        || after.uid() != uid
        || after.mode() & 0o7777 != 0o600
        || after.nlink() != 1
        || fs::canonicalize(path)? != path
    {
        return Err(PodError::Refused(
            "private native event log changed during read",
        ));
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn held_private_evidence_read_refuses_symlink_and_insecure_mode() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "podbay-native-reader-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("codex.native-events.log");
        fs::write(&path, b"private fixture evidence").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = LinuxPeerEvidence::for_current_process().unwrap().uid();
        assert_eq!(
            read_private_log_copy(&path, uid).unwrap(),
            b"private fixture evidence"
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            read_private_log_copy(&path, uid),
            Err(PodError::Refused(_))
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let real = root.join("real.log");
        fs::rename(&path, &real).unwrap();
        symlink(&real, &path).unwrap();
        assert!(matches!(
            read_private_log_copy(&path, uid),
            Err(PodError::Refused(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }
}
