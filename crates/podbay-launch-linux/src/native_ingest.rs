//! Read-only manager bridge for one current committed Codex V2 Resource.
//! Native JSONL never enters the public server response or a command effect.

use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use podbay_core::{AttemptId, Epoch, PodId, ResourceId, RunId, ScopeId, SessionId, StoreLineageId};
use podbay_host::ResolvedNativeCodexLaunch;
use podbay_pod::{
    CODEX_V2_CAPABILITY, LinuxPeerEvidence, MAX_PRIVATE_NATIVE_EVENT_LOG_BYTES, NativeEventCursor,
    NativeEventIdentity, NativeEventRead, PodClient, PodError, PrivateNativeEvidence,
    codex_private_slot_directory, decode_private_native_evidence_for_trusted_reader,
    manifest_path_for_identity,
};

use crate::codex_v2::{TrustedCodexCredentialSource, preflight_committed_codex_v2};

pub struct TrustedNativeEventDirectory {
    path: PathBuf,
    identity: (u64, u64),
}

impl TrustedNativeEventDirectory {
    pub fn from_trusted_policy(path: PathBuf) -> Result<Self, PodError> {
        let peer = LinuxPeerEvidence::for_current_process()
            .map_err(|_| PodError::Refused("manager OS identity unavailable"))?;
        let identity = checked_private_directory(&path, peer.uid())?;
        Ok(Self { path, identity })
    }

    fn recheck(&self, uid: u32) -> Result<(), PodError> {
        if checked_private_directory(&self.path, uid)? != self.identity {
            return Err(PodError::Refused("trusted native event directory changed"));
        }
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
/// socket before and after reading a no-follow private log copy. A concurrent
/// append with a torn copy refuses; the caller may retry this read-only path.
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
    preflight_committed_codex_v2(launch, credential)?;
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
    let stem = path.file_stem().and_then(|value| value.to_str())
        .ok_or(PodError::Invalid("Codex manifest slot stem"))?;
    let private_slot = codex_private_slot_directory(
        &directory.path, &format!("podbay-pod-{stem}.service"), false,
    )?;
    let client = PodClient::connect(&path)?;
    let before = client.attested_status()?;
    if !status_matches(&before, launch, &expected, resource.epoch) {
        return Err(PodError::Refused("current Codex pod status differs"));
    }
    let redacted = client.read_codex_native_events(cursor, limit)?;
    if redacted.snapshot.identity != expected {
        return Err(PodError::Refused(
            "native event snapshot belongs to another Resource",
        ));
    }
    let private = if redacted.events.is_empty() {
        Vec::new()
    } else {
        let raw = read_private_log_copy(&private_slot.join("codex.native-events.log"), peer.uid())?;
        decode_private_native_evidence_for_trusted_reader(&raw, &expected, &redacted.events)?
    };
    let after = client.attested_status()?;
    directory.recheck(peer.uid())?;
    preflight_committed_codex_v2(launch, credential)?;
    if checked_store_file(launch.store_path(), peer.uid())? != store_identity
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
