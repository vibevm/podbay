//! Portable canonical peer-fence checkpoint bytes and a Linux private-file
//! backend. This persists no live grant, input lease, or manager lease.
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::Path;

use podbay_core::{
    AttemptId, AttestedPeer, CommandKey, CredentialEpoch, Epoch, FenceError, InputEpoch,
    OwnerEpoch, POD_FENCE_CHECKPOINT_VERSION, PodFenceCheckpoint, PodFenceIdentity, PodId,
    PodPeerFence, RebindPhase, RebindProposal, RequestDigest, ResourceId, ScopeId, StoreLineageId,
};
use sha2::{Digest, Sha256};

const MAGIC: &[u8] = b"podbay.peer-fence-checkpoint/1\0";
const MAX_CHECKPOINT_BYTES: usize = 65_536;
const MAX_RESOURCES: usize = 64;
const DIGEST_BYTES: usize = 32;
const OBSERVATION_DOMAIN: &[u8] = b"podbay.peer-checkpoint-observation/1\0";

/// Read-only observation of one validated private checkpoint file. The digest
/// names the exact bytes read, not a reconstructed logical summary.
pub(crate) struct PeerCheckpointObservation {
    checkpoint: PodFenceCheckpoint,
    digest: String,
}
impl PeerCheckpointObservation {
    pub(crate) fn checkpoint(&self) -> &PodFenceCheckpoint {
        &self.checkpoint
    }
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Debug)]
pub enum PeerCheckpointError {
    Invalid(&'static str),
    UnsupportedVersion,
    TooLarge,
    DigestMismatch,
    ForeignIdentity,
    Fence(FenceError),
    Io(std::io::Error),
    Uncertain(&'static str),
}

impl Display for PeerCheckpointError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "invalid peer checkpoint: {reason}"),
            Self::UnsupportedVersion => f.write_str("unsupported peer checkpoint version"),
            Self::TooLarge => f.write_str("peer checkpoint exceeds the size bound"),
            Self::DigestMismatch => f.write_str("peer checkpoint digest differs"),
            Self::ForeignIdentity => f.write_str("peer checkpoint belongs to another pod"),
            Self::Fence(error) => write!(f, "peer checkpoint violates fence: {error}"),
            Self::Io(error) => write!(f, "peer checkpoint I/O: {error}"),
            Self::Uncertain(reason) => write!(f, "peer checkpoint durability uncertain: {reason}"),
        }
    }
}
impl Error for PeerCheckpointError {}
impl From<std::io::Error> for PeerCheckpointError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<FenceError> for PeerCheckpointError {
    fn from(error: FenceError) -> Self {
        Self::Fence(error)
    }
}

fn put_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_be_bytes());
}
fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}
fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}
fn put_text(bytes: &mut Vec<u8>, value: &str) -> Result<(), PeerCheckpointError> {
    let length = u32::try_from(value.len()).map_err(|_| PeerCheckpointError::TooLarge)?;
    put_u32(bytes, length);
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}
fn put_identity(bytes: &mut Vec<u8>, id: &PodFenceIdentity) -> Result<(), PeerCheckpointError> {
    for value in [
        id.scope_id.as_str(),
        id.pod_id.as_str(),
        id.attempt_id.as_str(),
        id.store_lineage.as_str(),
    ] {
        put_text(bytes, value)?;
    }
    put_u64(bytes, id.incarnation.get());
    Ok(())
}
fn put_peer(bytes: &mut Vec<u8>, peer: &AttestedPeer) -> Result<(), PeerCheckpointError> {
    for value in [
        peer.os_identity(),
        peer.native_process_id(),
        peer.boot_identity(),
        peer.birth_identity(),
        peer.containment_identity(),
    ] {
        put_text(bytes, value)?;
    }
    Ok(())
}
fn put_inputs(
    bytes: &mut Vec<u8>,
    values: &BTreeMap<ResourceId, InputEpoch>,
) -> Result<(), PeerCheckpointError> {
    if values.is_empty() || values.len() > MAX_RESOURCES {
        return Err(PeerCheckpointError::Invalid("resource count"));
    }
    put_u16(bytes, values.len() as u16);
    for (id, epoch) in values {
        put_text(bytes, id.as_str())?;
        put_u64(bytes, epoch.get());
    }
    Ok(())
}
fn put_proposal(bytes: &mut Vec<u8>, proposal: &RebindProposal) -> Result<(), PeerCheckpointError> {
    put_identity(bytes, &proposal.identity)?;
    put_u64(bytes, proposal.expected_owner_epoch.get());
    put_u64(bytes, proposal.next_owner_epoch.get());
    put_u64(bytes, proposal.expected_credential_epoch.get());
    put_u64(bytes, proposal.next_credential_epoch.get());
    put_inputs(bytes, &proposal.expected_input_epochs)?;
    put_inputs(bytes, &proposal.next_input_epochs)?;
    put_peer(bytes, &proposal.next_manager)?;
    put_text(bytes, proposal.command_key.as_str())?;
    put_text(bytes, proposal.digest.as_str())?;
    Ok(())
}
fn put_optional_proposal(
    bytes: &mut Vec<u8>,
    value: Option<&RebindProposal>,
) -> Result<(), PeerCheckpointError> {
    match value {
        None => bytes.push(0),
        Some(proposal) => {
            bytes.push(1);
            put_proposal(bytes, proposal)?;
        }
    }
    Ok(())
}

/// Canonical portable bytes: fixed-order bounded fields followed by SHA-256
/// of every preceding byte, including the magic and version.
pub fn encode_peer_checkpoint(
    checkpoint: &PodFenceCheckpoint,
) -> Result<Vec<u8>, PeerCheckpointError> {
    if checkpoint.version() != POD_FENCE_CHECKPOINT_VERSION {
        return Err(PeerCheckpointError::UnsupportedVersion);
    }
    let mut bytes = MAGIC.to_vec();
    put_u16(&mut bytes, checkpoint.version());
    put_identity(&mut bytes, checkpoint.identity())?;
    put_text(&mut bytes, checkpoint.manager_containment())?;
    put_peer(&mut bytes, checkpoint.manager_peer())?;
    put_u64(&mut bytes, checkpoint.owner_epoch().get());
    put_u64(&mut bytes, checkpoint.credential_epoch().get());
    put_inputs(&mut bytes, checkpoint.input_epochs())?;
    bytes.push(match checkpoint.phase() {
        RebindPhase::Active => 0,
        RebindPhase::PendingStore => 1,
        RebindPhase::PendingPod => 2,
    });
    put_optional_proposal(&mut bytes, checkpoint.pending_rebind())?;
    put_optional_proposal(&mut bytes, checkpoint.last_rebind())?;
    if bytes
        .len()
        .checked_add(DIGEST_BYTES)
        .is_none_or(|size| size > MAX_CHECKPOINT_BYTES)
    {
        return Err(PeerCheckpointError::TooLarge);
    }
    let digest = Sha256::digest(&bytes);
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], PeerCheckpointError> {
        let end = self
            .at
            .checked_add(count)
            .ok_or(PeerCheckpointError::TooLarge)?;
        let value = self
            .bytes
            .get(self.at..end)
            .ok_or(PeerCheckpointError::Invalid("truncated field"))?;
        self.at = end;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8, PeerCheckpointError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, PeerCheckpointError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, PeerCheckpointError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, PeerCheckpointError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn text(&mut self, max: usize) -> Result<String, PeerCheckpointError> {
        let length = self.u32()? as usize;
        if length == 0 || length > max {
            return Err(PeerCheckpointError::Invalid("text length"));
        }
        let value = std::str::from_utf8(self.take(length)?)
            .map_err(|_| PeerCheckpointError::Invalid("UTF-8"))?;
        Ok(value.into())
    }
}
fn parse_id<T>(value: String) -> Result<T, PeerCheckpointError>
where
    T: TryFrom<String>,
{
    T::try_from(value).map_err(|_| PeerCheckpointError::Invalid("identity"))
}
fn read_identity(reader: &mut Reader<'_>) -> Result<PodFenceIdentity, PeerCheckpointError> {
    let scope_id = parse_id::<ScopeId>(reader.text(256)?)?;
    let pod_id = parse_id::<PodId>(reader.text(256)?)?;
    let attempt_id = parse_id::<AttemptId>(reader.text(256)?)?;
    let store_lineage = parse_id::<StoreLineageId>(reader.text(256)?)?;
    let incarnation =
        Epoch::new(reader.u64()?).map_err(|_| PeerCheckpointError::Invalid("incarnation"))?;
    Ok(PodFenceIdentity {
        scope_id,
        pod_id,
        attempt_id,
        incarnation,
        store_lineage,
    })
}
fn read_peer(reader: &mut Reader<'_>) -> Result<AttestedPeer, PeerCheckpointError> {
    let os = reader.text(256)?;
    let pid = reader.text(256)?;
    let boot = reader.text(256)?;
    let birth = reader.text(256)?;
    let containment = reader.text(4096)?;
    AttestedPeer::from_port(&os, &pid, &boot, &birth, &containment).map_err(Into::into)
}
fn read_inputs(
    reader: &mut Reader<'_>,
) -> Result<BTreeMap<ResourceId, InputEpoch>, PeerCheckpointError> {
    let count = reader.u16()? as usize;
    if count == 0 || count > MAX_RESOURCES {
        return Err(PeerCheckpointError::Invalid("resource count"));
    }
    let mut result = BTreeMap::new();
    let mut previous: Option<ResourceId> = None;
    for _ in 0..count {
        let id = parse_id::<ResourceId>(reader.text(256)?)?;
        if previous.as_ref().is_some_and(|before| before >= &id) {
            return Err(PeerCheckpointError::Invalid("resource order"));
        }
        let epoch = InputEpoch::new(reader.u64()?)
            .map_err(|_| PeerCheckpointError::Invalid("input epoch"))?;
        result.insert(id.clone(), epoch);
        previous = Some(id);
    }
    Ok(result)
}
fn read_proposal(reader: &mut Reader<'_>) -> Result<RebindProposal, PeerCheckpointError> {
    let identity = read_identity(reader)?;
    let expected_owner_epoch =
        OwnerEpoch::new(reader.u64()?).map_err(|_| PeerCheckpointError::Invalid("owner epoch"))?;
    let next_owner_epoch =
        OwnerEpoch::new(reader.u64()?).map_err(|_| PeerCheckpointError::Invalid("owner epoch"))?;
    let expected_credential_epoch = CredentialEpoch::new(reader.u64()?)
        .map_err(|_| PeerCheckpointError::Invalid("credential epoch"))?;
    let next_credential_epoch = CredentialEpoch::new(reader.u64()?)
        .map_err(|_| PeerCheckpointError::Invalid("credential epoch"))?;
    let expected_input_epochs = read_inputs(reader)?;
    let next_input_epochs = read_inputs(reader)?;
    let next_manager = read_peer(reader)?;
    let command_key = parse_id::<CommandKey>(reader.text(256)?)?;
    let digest = RequestDigest::parse(&reader.text(64)?)?;
    Ok(RebindProposal {
        identity,
        expected_owner_epoch,
        next_owner_epoch,
        expected_credential_epoch,
        next_credential_epoch,
        expected_input_epochs,
        next_input_epochs,
        next_manager,
        command_key,
        digest,
    })
}
fn read_optional_proposal(
    reader: &mut Reader<'_>,
) -> Result<Option<RebindProposal>, PeerCheckpointError> {
    match reader.byte()? {
        0 => Ok(None),
        1 => Ok(Some(read_proposal(reader)?)),
        _ => Err(PeerCheckpointError::Invalid("proposal marker")),
    }
}

pub fn decode_peer_checkpoint(bytes: &[u8]) -> Result<PodFenceCheckpoint, PeerCheckpointError> {
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(PeerCheckpointError::TooLarge);
    }
    if bytes.len() < MAGIC.len() + 2 + DIGEST_BYTES {
        return Err(PeerCheckpointError::Invalid("truncated checkpoint"));
    }
    let (body, claimed_digest) = bytes.split_at(bytes.len() - DIGEST_BYTES);
    if Sha256::digest(body).as_slice() != claimed_digest {
        return Err(PeerCheckpointError::DigestMismatch);
    }
    let mut reader = Reader { bytes: body, at: 0 };
    if reader.take(MAGIC.len())? != MAGIC {
        return Err(PeerCheckpointError::UnsupportedVersion);
    }
    let version = reader.u16()?;
    if version != POD_FENCE_CHECKPOINT_VERSION {
        return Err(PeerCheckpointError::UnsupportedVersion);
    }
    let identity = read_identity(&mut reader)?;
    let containment = reader.text(4096)?;
    let manager_peer = read_peer(&mut reader)?;
    let owner_epoch =
        OwnerEpoch::new(reader.u64()?).map_err(|_| PeerCheckpointError::Invalid("owner epoch"))?;
    let credential_epoch = CredentialEpoch::new(reader.u64()?)
        .map_err(|_| PeerCheckpointError::Invalid("credential epoch"))?;
    let input_epochs = read_inputs(&mut reader)?;
    let phase = match reader.byte()? {
        0 => RebindPhase::Active,
        1 => RebindPhase::PendingStore,
        2 => RebindPhase::PendingPod,
        _ => return Err(PeerCheckpointError::Invalid("rebind phase")),
    };
    let pending = read_optional_proposal(&mut reader)?;
    let last = read_optional_proposal(&mut reader)?;
    if reader.at != body.len() {
        return Err(PeerCheckpointError::Invalid("trailing bytes"));
    }
    let checkpoint = PodFenceCheckpoint::from_durable_parts(
        version,
        identity,
        containment,
        manager_peer,
        owner_epoch,
        credential_epoch,
        input_epochs,
        phase,
        pending,
        last,
    )?;
    if encode_peer_checkpoint(&checkpoint)? != bytes {
        return Err(PeerCheckpointError::Invalid("noncanonical encoding"));
    }
    Ok(checkpoint)
}

#[cfg(target_os = "linux")]
mod linux_file {
    use super::*;
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::manifest::private_directory;

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn checkpoint_path(directory: &Path, identity: &PodFenceIdentity) -> std::path::PathBuf {
        let mut hash = Sha256::new();
        hash.update(b"podbay.peer-fence-checkpoint-path/1\0");
        for value in [
            identity.scope_id.as_str(),
            identity.pod_id.as_str(),
            identity.attempt_id.as_str(),
            identity.store_lineage.as_str(),
        ] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
        hash.update(identity.incarnation.get().to_be_bytes());
        let digest = hash
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        directory.join(format!("peer-{digest}.chk"))
    }

    fn parent(path: &Path) -> Result<&Path, PeerCheckpointError> {
        let parent = path
            .parent()
            .ok_or(PeerCheckpointError::Invalid("checkpoint parent"))?;
        private_directory(parent)
            .map_err(|_| PeerCheckpointError::Invalid("checkpoint directory is not private"))?;
        if path.file_name().is_none() {
            return Err(PeerCheckpointError::Invalid("checkpoint name"));
        }
        Ok(parent)
    }
    fn existing_final_is_safe(path: &Path, owner: u32) -> Result<(), PeerCheckpointError> {
        match fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.file_type().is_file()
                    && metadata.uid() == owner
                    && metadata.mode() & 0o077 == 0 =>
            {
                Ok(())
            }
            Ok(_) => Err(PeerCheckpointError::Invalid(
                "checkpoint path is not private regular file",
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(PeerCheckpointError::Io(error)),
        }
    }
    fn temporary_path(path: &Path) -> Result<std::path::PathBuf, PeerCheckpointError> {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PeerCheckpointError::Invalid("system clock"))?
            .as_nanos();
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = path
            .file_name()
            .ok_or(PeerCheckpointError::Invalid("checkpoint name"))?
            .to_string_lossy();
        Ok(path.with_file_name(format!(
            "{name}.tmp.{}.{}.{sequence}",
            std::process::id(),
            stamp
        )))
    }

    /// New private temp → file fsync → atomic rename → directory fsync.
    /// A stale temp after a crash is never interpreted as a committed state.
    fn write_at_path(
        path: &Path,
        checkpoint: &PodFenceCheckpoint,
    ) -> Result<(), PeerCheckpointError> {
        let bytes = encode_peer_checkpoint(checkpoint)?;
        let directory = parent(path)?;
        let owner = fs::metadata(directory)?.uid();
        existing_final_is_safe(path, owner)?;
        let temporary = temporary_path(path)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        // Recheck the destination immediately before rename; rename replaces
        // the final component and never traverses it as a symlink.
        existing_final_is_safe(path, owner)?;
        fs::rename(&temporary, path)
            .map_err(|_| PeerCheckpointError::Uncertain("checkpoint rename outcome"))?;
        File::open(directory)?
            .sync_all()
            .map_err(|_| PeerCheckpointError::Uncertain("checkpoint directory sync outcome"))?;
        Ok(())
    }

    /// The trusted identity comes from the launcher, never checkpoint bytes.
    fn read_at_path(
        path: &Path,
        expected: &PodFenceIdentity,
    ) -> Result<(PodFenceCheckpoint, Vec<u8>), PeerCheckpointError> {
        let directory = parent(path)?;
        let owner = fs::metadata(directory)?.uid();
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != owner
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() > MAX_CHECKPOINT_BYTES as u64
        {
            return Err(PeerCheckpointError::Invalid(
                "checkpoint file is not private and bounded",
            ));
        }
        let mut bytes = Vec::new();
        file.take((MAX_CHECKPOINT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(PeerCheckpointError::TooLarge);
        }
        let checkpoint = decode_peer_checkpoint(&bytes)?;
        if checkpoint.identity() != expected {
            return Err(PeerCheckpointError::ForeignIdentity);
        }
        Ok((checkpoint, bytes))
    }

    /// The trusted identity, rather than a caller-selected filename, chooses
    /// the sole checkpoint slot for this scope/pod/attempt/incarnation/lineage.
    pub fn write_peer_checkpoint(
        directory: &Path,
        expected: &PodFenceIdentity,
        checkpoint: &PodFenceCheckpoint,
    ) -> Result<(), PeerCheckpointError> {
        if checkpoint.identity() != expected {
            return Err(PeerCheckpointError::ForeignIdentity);
        }
        write_at_path(&checkpoint_path(directory, expected), checkpoint)
    }

    pub fn read_peer_checkpoint(
        directory: &Path,
        expected: &PodFenceIdentity,
    ) -> Result<PodPeerFence, PeerCheckpointError> {
        let (checkpoint, _bytes) = read_at_path(&checkpoint_path(directory, expected), expected)?;
        PodPeerFence::restore_after_crash(checkpoint).map_err(Into::into)
    }

    pub(crate) fn read_peer_checkpoint_observation(
        directory: &Path,
        expected: &PodFenceIdentity,
    ) -> Result<PeerCheckpointObservation, PeerCheckpointError> {
        let (checkpoint, bytes) = read_at_path(&checkpoint_path(directory, expected), expected)?;
        let mut hash = Sha256::new();
        hash.update(OBSERVATION_DOMAIN);
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(&bytes);
        let digest = hash
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Ok(PeerCheckpointObservation { checkpoint, digest })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::collections::BTreeMap;

        use podbay_core::{
            AttemptId, AttestedPeer, CredentialEpoch, Epoch, InputEpoch, OwnerEpoch, PodId,
            PodPeerFence, ResourceId, ScopeId, StoreLineageId,
        };

        fn private_fixture() -> std::path::PathBuf {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory = std::env::temp_dir()
                .join(format!("podbay-observation-{}-{stamp}", std::process::id()));
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            directory
        }
        fn identity(pod: &str) -> PodFenceIdentity {
            PodFenceIdentity {
                scope_id: ScopeId::try_from("scope.fixture").unwrap(),
                pod_id: PodId::try_from(pod).unwrap(),
                attempt_id: AttemptId::try_from("attempt.fixture").unwrap(),
                incarnation: Epoch::new(1).unwrap(),
                store_lineage: StoreLineageId::try_from("store.fixture").unwrap(),
            }
        }
        fn checkpoint(id: PodFenceIdentity, epoch: u64) -> PodFenceCheckpoint {
            PodPeerFence::new(
                id,
                AttestedPeer::from_port(
                    "uid.1000",
                    "pid.100",
                    "boot.fixture",
                    "birth.100",
                    "manager.unit",
                )
                .unwrap(),
                OwnerEpoch::new(epoch).unwrap(),
                CredentialEpoch::new(epoch).unwrap(),
                BTreeMap::from([(
                    ResourceId::try_from("resource.fixture").unwrap(),
                    InputEpoch::new(epoch).unwrap(),
                )]),
                100,
                800,
            )
            .unwrap()
            .checkpoint()
        }

        #[test]
        fn observation_hashes_exact_private_file_bytes_and_changes_after_update() {
            let directory = private_fixture();
            let id = identity("pod.fixture");
            let first = checkpoint(id.clone(), 1);
            write_peer_checkpoint(&directory, &id, &first).unwrap();
            let path = checkpoint_path(&directory, &id);
            let original = fs::read(&path).unwrap();
            let observed = read_peer_checkpoint_observation(&directory, &id).unwrap();
            assert_eq!(observed.checkpoint(), &first);
            let mut expected = Sha256::new();
            expected.update(OBSERVATION_DOMAIN);
            expected.update((original.len() as u64).to_be_bytes());
            expected.update(&original);
            let expected = expected
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(observed.digest(), expected);
            assert_eq!(
                fs::read(&path).unwrap(),
                original,
                "observation is read-only"
            );
            assert_eq!(
                read_peer_checkpoint_observation(&directory, &id)
                    .unwrap()
                    .digest(),
                expected
            );
            let second = checkpoint(id.clone(), 2);
            write_peer_checkpoint(&directory, &id, &second).unwrap();
            let updated = read_peer_checkpoint_observation(&directory, &id).unwrap();
            assert_eq!(updated.checkpoint(), &second);
            assert_ne!(updated.digest(), observed.digest());
            assert_ne!(fs::read(&path).unwrap(), original);
            fs::remove_dir_all(directory).unwrap();
        }

        #[test]
        fn observation_refuses_missing_corrupt_or_foreign_checkpoint() {
            let directory = private_fixture();
            let id = identity("pod.fixture");
            assert!(matches!(
                read_peer_checkpoint_observation(&directory, &id),
                Err(PeerCheckpointError::Io(_))
            ));
            let first = checkpoint(id.clone(), 1);
            write_peer_checkpoint(&directory, &id, &first).unwrap();
            let path = checkpoint_path(&directory, &id);
            let mut corrupt = fs::read(&path).unwrap();
            corrupt[10] ^= 1;
            fs::write(&path, &corrupt).unwrap();
            assert!(matches!(
                read_peer_checkpoint_observation(&directory, &id),
                Err(PeerCheckpointError::DigestMismatch)
            ));
            let foreign = checkpoint(identity("pod.foreign"), 1);
            fs::write(&path, encode_peer_checkpoint(&foreign).unwrap()).unwrap();
            assert!(matches!(
                read_peer_checkpoint_observation(&directory, &id),
                Err(PeerCheckpointError::ForeignIdentity)
            ));
            fs::remove_dir_all(directory).unwrap();
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux_file::read_peer_checkpoint_observation;
#[cfg(target_os = "linux")]
pub use linux_file::{read_peer_checkpoint, write_peer_checkpoint};
