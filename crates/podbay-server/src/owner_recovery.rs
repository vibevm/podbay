//! One-use Linux owner recovery before the ordinary manager socket opens.
//! The socket receives only two public keys and their signatures. Actor,
//! scope, epochs and current verifier come from the manager's durable store.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use podbay_host::{
    DurableAuthority, DurableAuthorityError, GrantId, HostDispatchPort, HostError,
    TrustedInitialOwnerPolicy,
};
use podbay_pod::{LinuxPeerError, LinuxPeerEvidence};
use podbay_store::OwnerActorRotationReceipt;
use serde_json::{Value, json};

use crate::LinuxAcceptedPeerEvidence;

pub const OWNER_RECOVERY_SOCKET_NAME: &str = "owner-recovery.sock";
const TOTAL_LIMIT: Duration = Duration::from_secs(20);
const IO_LIMIT: Duration = Duration::from_secs(5);
const MAX_KEY_FILE: u64 = 8_192;

#[derive(Debug)]
pub enum OwnerRecoveryError {
    Io(io::Error),
    Peer(LinuxPeerError),
    Authority(DurableAuthorityError),
    Proof(HostError),
    Invalid(&'static str),
    IdentityChanged,
    Stopped,
    Timeout,
    ReplyUnconfirmed,
}
impl Display for OwnerRecoveryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "owner recovery I/O failed: {error}"),
            Self::Peer(error) => write!(f, "owner recovery peer refused: {error}"),
            Self::Authority(error) => write!(f, "owner recovery authority refused: {error:?}"),
            Self::Proof(error) => write!(f, "owner recovery proof refused: {error:?}"),
            Self::Invalid(reason) => write!(f, "owner recovery input refused: {reason}"),
            Self::IdentityChanged => {
                f.write_str("owner recovery socket or launcher parent changed")
            }
            Self::Stopped => f.write_str("owner recovery stopped"),
            Self::Timeout => f.write_str("owner recovery deadline elapsed"),
            Self::ReplyUnconfirmed => {
                f.write_str("owner recovery committed but receipt ACK was not confirmed")
            }
        }
    }
}
impl Error for OwnerRecoveryError {}
impl From<io::Error> for OwnerRecoveryError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<LinuxPeerError> for OwnerRecoveryError {
    fn from(value: LinuxPeerError) -> Self {
        Self::Peer(value)
    }
}
impl From<DurableAuthorityError> for OwnerRecoveryError {
    fn from(value: DurableAuthorityError) -> Self {
        Self::Authority(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerRecoveryReceipt {
    pub rotation: OwnerActorRotationReceipt,
    pub grant_id: GrantId,
}

pub struct LinuxOwnerRecoveryListener {
    listener: UnixListener,
    directory: PathBuf,
    directory_identity: (u64, u64),
    path: PathBuf,
    socket_identity: (u64, u64),
    uid: u32,
    parent: LinuxPeerEvidence,
}

impl LinuxOwnerRecoveryListener {
    pub fn bind(
        directory: impl AsRef<Path>,
        parent: LinuxPeerEvidence,
    ) -> Result<Self, OwnerRecoveryError> {
        parent.recheck_launcher_parent()?;
        let directory = directory.as_ref();
        let current = LinuxPeerEvidence::for_current_process()?;
        let metadata = fs::symlink_metadata(directory)?;
        if !directory.is_absolute()
            || !metadata.is_dir()
            || metadata.uid() != current.uid()
            || metadata.mode() & 0o7777 != 0o700
            || fs::canonicalize(directory)? != directory
            || parent.uid() != current.uid()
        {
            return Err(OwnerRecoveryError::Invalid(
                "private recovery directory or parent UID",
            ));
        }
        let path = directory.join(OWNER_RECOVERY_SOCKET_NAME);
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let socket = fs::symlink_metadata(&path)?;
        if !socket.file_type().is_socket()
            || socket.uid() != current.uid()
            || socket.mode() & 0o7777 != 0o600
        {
            return Err(OwnerRecoveryError::IdentityChanged);
        }
        Ok(Self {
            listener,
            directory: directory.to_path_buf(),
            directory_identity: (metadata.dev(), metadata.ino()),
            path,
            socket_identity: (socket.dev(), socket.ino()),
            uid: current.uid(),
            parent,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn serve<P: HostDispatchPort>(
        &mut self,
        authority: &mut DurableAuthority<P>,
        policy: &TrustedInitialOwnerPolicy,
        stop: &AtomicBool,
    ) -> Result<OwnerRecoveryReceipt, OwnerRecoveryError> {
        let deadline = Instant::now() + TOTAL_LIMIT;
        let mut first = self.accept_parent(stop, deadline)?;
        let peer = LinuxAcceptedPeerEvidence::from_accepted(&first)
            .map_err(|_| OwnerRecoveryError::IdentityChanged)?;
        if peer.kernel_evidence() != &self.parent {
            return Err(OwnerRecoveryError::IdentityChanged);
        }
        self.parent.recheck_launcher_parent()?;
        let keys = read_frame_exact(&mut first, 64, deadline)?;
        let old_key: [u8; 32] = keys[..32]
            .try_into()
            .map_err(|_| OwnerRecoveryError::Invalid("old key"))?;
        let next_key: [u8; 32] = keys[32..]
            .try_into()
            .map_err(|_| OwnerRecoveryError::Invalid("new key"))?;
        let pending =
            authority.begin_owner_recovery(policy, peer.subject().clone(), old_key, next_key)?;
        verify_staged_key(&self.directory, self.uid, &pending)?;
        write_frame(&mut first, pending.challenge_bytes(), deadline)?;
        let signatures = read_frame_exact(&mut first, 128, deadline)?;
        verify_staged_key(&self.directory, self.uid, &pending)?;
        let proof = pending
            .verify(&signatures[..64], &signatures[64..])
            .map_err(OwnerRecoveryError::Proof)?;
        self.parent.recheck_launcher_parent()?;
        let fresh = peer
            .recheck_before_dispatch(&first)
            .map_err(|_| OwnerRecoveryError::IdentityChanged)?;
        let rotation = authority.commit_owner_recovery(proof, fresh)?;
        let grant_id = authority.current_owner_grant_from_trusted_policy(policy)?;
        let receipt = OwnerRecoveryReceipt { rotation, grant_id };
        let confirmed = write_receipt(&mut first, &receipt, false, deadline).is_ok()
            && read_frame_exact(&mut first, 3, deadline).is_ok_and(|ack| ack == b"ack");
        if confirmed {
            return Ok(receipt);
        }

        // One read-only lost-ACK reconciliation. No second actor rotation.
        let mut retry = self.accept_parent(stop, deadline)?;
        let retry_peer = LinuxAcceptedPeerEvidence::from_accepted(&retry)
            .map_err(|_| OwnerRecoveryError::IdentityChanged)?;
        if retry_peer.kernel_evidence() != &self.parent || retry_peer.subject() != peer.subject() {
            return Err(OwnerRecoveryError::IdentityChanged);
        }
        let repeated = read_frame_exact(&mut retry, 64, deadline)?;
        if repeated != keys {
            return Err(OwnerRecoveryError::Invalid("recovery key pair changed"));
        }
        let actor = podbay_core::ActorId::try_from(receipt.rotation.actor_id.as_str())
            .map_err(|_| OwnerRecoveryError::Invalid("recovered actor id"))?;
        let candidate =
            authority.challenge_candidate_for_observed_process(&actor, retry_peer.subject())?;
        let nonce = getrandom_nonce()?;
        let challenge = candidate
            .begin_challenge(nonce)
            .map_err(|_| OwnerRecoveryError::IdentityChanged)?;
        let transcript = challenge
            .transcript_bytes()
            .map_err(|_| OwnerRecoveryError::IdentityChanged)?;
        write_frame(&mut retry, &transcript, deadline)?;
        let signature = read_frame_exact(&mut retry, 64, deadline)?;
        retry_peer
            .recheck_before_dispatch(&retry)
            .map_err(|_| OwnerRecoveryError::IdentityChanged)?;
        challenge
            .verify(retry_peer.subject(), &signature)
            .map_err(|_| OwnerRecoveryError::IdentityChanged)?;
        let confirmed = write_receipt(&mut retry, &receipt, true, deadline).is_ok()
            && read_frame_exact(&mut retry, 3, deadline).is_ok_and(|ack| ack == b"ack");
        if confirmed {
            Ok(receipt)
        } else {
            Err(OwnerRecoveryError::ReplyUnconfirmed)
        }
    }

    pub fn shutdown(self) -> Result<(), OwnerRecoveryError> {
        self.recheck_socket()?;
        fs::remove_file(&self.path)?;
        fs::File::open(&self.directory)?.sync_all()?;
        Ok(())
    }

    fn accept_parent(
        &self,
        stop: &AtomicBool,
        deadline: Instant,
    ) -> Result<UnixStream, OwnerRecoveryError> {
        loop {
            if stop.load(Ordering::Acquire) {
                return Err(OwnerRecoveryError::Stopped);
            }
            if Instant::now() >= deadline {
                return Err(OwnerRecoveryError::Timeout);
            }
            self.recheck_socket()?;
            self.parent.recheck_launcher_parent()?;
            match self.listener.accept() {
                Ok((stream, _)) => return Ok(stream),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20))
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn recheck_socket(&self) -> Result<(), OwnerRecoveryError> {
        let directory = fs::symlink_metadata(&self.directory)?;
        let socket = fs::symlink_metadata(&self.path)?;
        if !directory.is_dir()
            || (directory.dev(), directory.ino()) != self.directory_identity
            || directory.uid() != self.uid
            || directory.mode() & 0o7777 != 0o700
            || fs::canonicalize(&self.directory)? != self.directory
            || !socket.file_type().is_socket()
            || (socket.dev(), socket.ino()) != self.socket_identity
            || socket.uid() != self.uid
            || socket.mode() & 0o7777 != 0o600
        {
            return Err(OwnerRecoveryError::IdentityChanged);
        }
        Ok(())
    }
}

fn verify_staged_key(
    state: &Path,
    uid: u32,
    pending: &podbay_host::PendingOwnerRecovery,
) -> Result<(), OwnerRecoveryError> {
    let generation = pending.next_generation();
    let directory = state.join(format!("owner-generation-{generation}"));
    let folder = fs::symlink_metadata(&directory)?;
    if !folder.is_dir()
        || folder.uid() != uid
        || folder.mode() & 0o7777 != 0o700
        || fs::canonicalize(&directory)? != directory
    {
        return Err(OwnerRecoveryError::Invalid(
            "next owner key directory is not private",
        ));
    }
    let key_directory = directory.join(format!("key-{}", hex(pending.next_public_key())));
    let key_folder = fs::symlink_metadata(&key_directory)?;
    if !key_folder.is_dir()
        || key_folder.uid() != uid
        || key_folder.mode() & 0o7777 != 0o700
        || fs::canonicalize(&key_directory)? != key_directory
    {
        return Err(OwnerRecoveryError::Invalid(
            "next owner verifier directory is not private",
        ));
    }
    let private_path = key_directory.join("owner-key-custody.json");
    let private_path_stat = fs::symlink_metadata(&private_path)?;
    let private_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&private_path)?;
    let private_stat = private_file.metadata()?;
    if !private_path_stat.is_file()
        || !private_stat.is_file()
        || (private_path_stat.dev(), private_path_stat.ino())
            != (private_stat.dev(), private_stat.ino())
        || private_stat.uid() != uid
        || private_stat.mode() & 0o7777 != 0o600
        || private_stat.nlink() != 1
        || private_stat.len() == 0
        || private_stat.len() > MAX_KEY_FILE
        || fs::canonicalize(&private_path)? != private_path
    {
        return Err(OwnerRecoveryError::Invalid(
            "next private key file is not canonical",
        ));
    }
    // Never read PKCS8 bytes. The separate public receipt is the only file
    // parsed here; the dual signature proves possession of the staged key.
    let path = key_directory.join("owner-next-public.json");
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != uid
        || before.mode() & 0o7777 != 0o600
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > MAX_KEY_FILE
        || fs::canonicalize(&path)? != path
    {
        return Err(OwnerRecoveryError::Invalid(
            "next public receipt is not private",
        ));
    }
    let value: Value = serde_json::from_reader(&file)
        .map_err(|_| OwnerRecoveryError::Invalid("next owner public receipt is invalid"))?;
    let after = file.metadata()?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
    ) {
        return Err(OwnerRecoveryError::IdentityChanged);
    }
    let private_after = private_file.metadata()?;
    if (
        private_stat.dev(),
        private_stat.ino(),
        private_stat.len(),
        private_stat.mtime(),
        private_stat.mtime_nsec(),
    ) != (
        private_after.dev(),
        private_after.ino(),
        private_after.len(),
        private_after.mtime(),
        private_after.mtime_nsec(),
    ) {
        return Err(OwnerRecoveryError::IdentityChanged);
    }
    let item = value
        .as_object()
        .ok_or(OwnerRecoveryError::Invalid("next owner public receipt"))?;
    if item.len() != 12 {
        return Err(OwnerRecoveryError::Invalid(
            "next owner public receipt fields differ",
        ));
    }
    let text = |name: &str| item.get(name).and_then(Value::as_str);
    if text("schema") != Some("podbay.owner-next-public/1")
        || text("actorId") != Some(pending.actor_id())
        || text("scopeId") != Some(pending.scope_id())
        || text("storeLineage") != Some(pending.store_lineage())
        || text("credentialGeneration") != Some(&generation.to_string())
        || text("ownerEpoch") != Some(&pending.owner_epoch().to_string())
        || text("authorityRevision") != Some(&pending.authority_revision().to_string())
        || text("osIdentity") != Some(pending.next_process().os_identity())
        || text("processIdentity") != Some(pending.next_process().process_identity())
        || text("startIdentity") != Some(&pending.next_process().start_identity().to_string())
        || text("containmentIdentity") != Some(pending.next_process().containment_identity())
        || text("publicKey") != Some(&base64url(pending.next_public_key()))
    {
        return Err(OwnerRecoveryError::Invalid(
            "next owner key binding differs",
        ));
    }
    Ok(())
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        out.push(ALPHABET[(a >> 2) as usize] as char);
        out.push(ALPHABET[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(((b & 15) << 2) | (c >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(c & 63) as usize] as char);
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn getrandom_nonce() -> Result<[u8; 32], OwnerRecoveryError> {
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce)
        .map_err(|_| OwnerRecoveryError::Invalid("recovery entropy unavailable"))?;
    if nonce == [0; 32] {
        return Err(OwnerRecoveryError::Invalid("recovery nonce is empty"));
    }
    Ok(nonce)
}

fn write_receipt(
    stream: &mut UnixStream,
    receipt: &OwnerRecoveryReceipt,
    duplicate: bool,
    deadline: Instant,
) -> Result<(), OwnerRecoveryError> {
    let bytes = serde_json::to_vec(&json!({
        "actorId": receipt.rotation.actor_id,
        "scopeId": receipt.rotation.scope_id,
        "grantRef": format!("grant.{}", receipt.grant_id.get()),
        "ownerEpoch": receipt.rotation.owner_epoch.to_string(),
        "authorityRevision": receipt.rotation.authority_revision.to_string(),
        "credentialGeneration": receipt.rotation.next_generation.to_string(),
        "rotationKey": receipt.rotation.rotation_key,
        "protocol": "podbay.owner-recovery/1",
        "duplicate": duplicate,
    }))
    .map_err(|_| OwnerRecoveryError::Invalid("receipt encoding"))?;
    if bytes.len() > 2048 {
        return Err(OwnerRecoveryError::Invalid("receipt bound"));
    }
    write_frame(stream, &bytes, deadline)
}

fn remaining(deadline: Instant) -> Result<Duration, OwnerRecoveryError> {
    let value = deadline
        .saturating_duration_since(Instant::now())
        .min(IO_LIMIT);
    if value.is_zero() {
        Err(OwnerRecoveryError::Timeout)
    } else {
        Ok(value)
    }
}
fn read_frame_exact(
    stream: &mut UnixStream,
    size: usize,
    deadline: Instant,
) -> Result<Vec<u8>, OwnerRecoveryError> {
    let mut prefix = [0; 4];
    stream.set_read_timeout(Some(remaining(deadline)?))?;
    stream.read_exact(&mut prefix)?;
    if u32::from_be_bytes(prefix) as usize != size {
        return Err(OwnerRecoveryError::Invalid("frame size differs"));
    }
    let mut bytes = vec![0; size];
    stream.set_read_timeout(Some(remaining(deadline)?))?;
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn write_frame(
    stream: &mut UnixStream,
    value: &[u8],
    deadline: Instant,
) -> Result<(), OwnerRecoveryError> {
    let size = u32::try_from(value.len())
        .map_err(|_| OwnerRecoveryError::Invalid("frame exceeds bound"))?;
    stream.set_write_timeout(Some(remaining(deadline)?))?;
    stream.write_all(&size.to_be_bytes())?;
    stream.set_write_timeout(Some(remaining(deadline)?))?;
    stream.write_all(value)?;
    Ok(())
}
