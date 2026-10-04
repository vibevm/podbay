//! One trusted launcher-parent enrollment before the normal manager socket is
//! exposed. The only peer-supplied identity material is an Ed25519 public key.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use podbay_host::{
    DurableAuthority, DurableAuthorityError, HostDispatchPort, HostError,
    InitialOwnerEnrollmentReceipt, TrustedInitialOwnerPolicy,
};
use podbay_pod::{LinuxPeerError, LinuxPeerEvidence};
use serde_json::json;

use crate::LinuxAcceptedPeerEvidence;

pub const OWNER_SETUP_SOCKET_NAME: &str = "owner-setup.sock";
const TOTAL_LIMIT: Duration = Duration::from_secs(20);
const IO_LIMIT: Duration = Duration::from_secs(5);
const ACCEPT_POLL: Duration = Duration::from_millis(20);
const MAX_CHALLENGE: usize = 8192;
const MAX_RECEIPT: usize = 2048;

#[derive(Debug)]
pub enum InitialOwnerSetupError {
    Io(io::Error),
    Peer(LinuxPeerError),
    Authority(DurableAuthorityError),
    Proof(HostError),
    Invalid(&'static str),
    Stopped,
    Timeout,
    IdentityChanged,
    ReplyUnconfirmed,
}

impl Display for InitialOwnerSetupError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "owner setup I/O failed: {error}"),
            Self::Peer(error) => write!(f, "launcher parent evidence refused: {error}"),
            Self::Authority(error) => write!(f, "owner enrollment refused: {error:?}"),
            Self::Proof(error) => write!(f, "owner key proof refused: {error:?}"),
            Self::Invalid(reason) => write!(f, "owner setup input refused: {reason}"),
            Self::Stopped => f.write_str("owner setup stopped"),
            Self::Timeout => f.write_str("owner setup deadline elapsed"),
            Self::IdentityChanged => f.write_str("owner setup socket or launcher parent changed"),
            Self::ReplyUnconfirmed => {
                f.write_str("owner enrollment may have committed; receipt ACK was not confirmed")
            }
        }
    }
}
impl Error for InitialOwnerSetupError {}
impl From<io::Error> for InitialOwnerSetupError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<LinuxPeerError> for InitialOwnerSetupError {
    fn from(value: LinuxPeerError) -> Self {
        Self::Peer(value)
    }
}
impl From<DurableAuthorityError> for InitialOwnerSetupError {
    fn from(value: DurableAuthorityError) -> Self {
        Self::Authority(value)
    }
}

/// The caller pins its actual parent before bind. A second connection is
/// permitted only to reconcile an unacknowledged receipt for the same exact
/// parent/key; no second enrollment or policy choice is exposed.
pub struct LinuxInitialOwnerSetupListener {
    listener: UnixListener,
    directory: PathBuf,
    directory_identity: (u64, u64),
    path: PathBuf,
    socket_identity: (u64, u64),
    uid: u32,
    parent: LinuxPeerEvidence,
}

impl LinuxInitialOwnerSetupListener {
    pub fn bind(
        directory: impl AsRef<Path>,
        parent: LinuxPeerEvidence,
    ) -> Result<Self, InitialOwnerSetupError> {
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
            return Err(InitialOwnerSetupError::Invalid(
                "private setup directory or parent UID",
            ));
        }
        let path = directory.join(OWNER_SETUP_SOCKET_NAME);
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let socket = fs::symlink_metadata(&path)?;
        if !socket.file_type().is_socket()
            || socket.uid() != current.uid()
            || socket.mode() & 0o7777 != 0o600
        {
            return Err(InitialOwnerSetupError::IdentityChanged);
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

    /// Bounded two-attempt setup. The second attempt exists solely for a lost
    /// final receipt/ACK; each attempt requires a new challenge signature.
    pub fn serve<P: HostDispatchPort>(
        &mut self,
        authority: &mut DurableAuthority<P>,
        policy: TrustedInitialOwnerPolicy,
        stop: &AtomicBool,
    ) -> Result<InitialOwnerEnrollmentReceipt, InitialOwnerSetupError> {
        let deadline = Instant::now() + TOTAL_LIMIT;
        let mut prior: Option<([u8; 32], InitialOwnerEnrollmentReceipt)> = None;
        for attempt in 0..2 {
            let mut stream = self.accept_parent(stop, deadline)?;
            let peer = LinuxAcceptedPeerEvidence::from_accepted(&stream)
                .map_err(|_| InitialOwnerSetupError::IdentityChanged)?;
            if peer.kernel_evidence() != &self.parent {
                return Err(InitialOwnerSetupError::IdentityChanged);
            }
            self.parent.recheck_launcher_parent()?;
            let key = read_frame_exact(&mut stream, 32, deadline)?;
            let public_key: [u8; 32] = key
                .try_into()
                .map_err(|_| InitialOwnerSetupError::Invalid("public key length"))?;
            if let Some((previous_key, _)) = &prior {
                if *previous_key != public_key {
                    return Err(InitialOwnerSetupError::Invalid("retry changed owner key"));
                }
            }
            let pending = authority.begin_initial_owner_enrollment(
                policy.clone(),
                peer.subject().clone(),
                public_key,
            )?;
            if pending.challenge_bytes().len() > MAX_CHALLENGE {
                return Err(InitialOwnerSetupError::Invalid("challenge exceeds bound"));
            }
            write_frame(&mut stream, pending.challenge_bytes(), deadline)?;
            let signature = read_frame_exact(&mut stream, 64, deadline)?;
            let proof = pending
                .verify(&signature)
                .map_err(InitialOwnerSetupError::Proof)?;
            self.parent.recheck_launcher_parent()?;
            let fresh = peer
                .recheck_before_dispatch(&stream)
                .map_err(|_| InitialOwnerSetupError::IdentityChanged)?;
            let receipt = authority.commit_initial_owner_enrollment(proof, fresh)?;
            if attempt == 1
                && (!receipt.duplicate
                    || prior.as_ref().is_none_or(|(_, previous)| {
                        previous.actor_id != receipt.actor_id
                            || previous.scope_id != receipt.scope_id
                            || previous.grant_id != receipt.grant_id
                            || previous.authority_revision != receipt.authority_revision
                    }))
            {
                return Err(InitialOwnerSetupError::IdentityChanged);
            }
            let response = serde_json::to_vec(&json!({
                "protocol": "podbay.owner-initial-enrollment/1",
                "actorId": receipt.actor_id.as_str(),
                "scopeId": receipt.scope_id.as_str(),
                "grantRef": format!("grant.{}", receipt.grant_id.get()),
                "ownerEpoch": receipt.owner_epoch.to_string(),
                "authorityRevision": receipt.authority_revision.to_string(),
                "duplicate": receipt.duplicate,
            }))
            .map_err(|_| InitialOwnerSetupError::Invalid("receipt encoding"))?;
            if response.len() > MAX_RECEIPT {
                return Err(InitialOwnerSetupError::Invalid("receipt exceeds bound"));
            }
            let confirmed = write_frame(&mut stream, &response, deadline).is_ok()
                && read_frame_exact(&mut stream, 3, deadline).is_ok_and(|ack| ack == b"ack");
            if confirmed {
                self.parent.recheck_launcher_parent()?;
                peer.recheck_before_dispatch(&stream)
                    .map_err(|_| InitialOwnerSetupError::IdentityChanged)?;
                return Ok(receipt);
            }
            prior = Some((public_key, receipt));
        }
        Err(InitialOwnerSetupError::ReplyUnconfirmed)
    }

    pub fn shutdown(self) -> Result<(), InitialOwnerSetupError> {
        self.recheck_owned_socket()?;
        fs::remove_file(&self.path)?;
        fs::File::open(&self.directory)?.sync_all()?;
        Ok(())
    }

    fn accept_parent(
        &self,
        stop: &AtomicBool,
        deadline: Instant,
    ) -> Result<UnixStream, InitialOwnerSetupError> {
        loop {
            if stop.load(Ordering::Acquire) {
                return Err(InitialOwnerSetupError::Stopped);
            }
            if Instant::now() >= deadline {
                return Err(InitialOwnerSetupError::Timeout);
            }
            self.recheck_owned_socket()?;
            self.parent.recheck_launcher_parent()?;
            match self.listener.accept() {
                Ok((stream, _)) => return Ok(stream),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(ACCEPT_POLL);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn recheck_owned_socket(&self) -> Result<(), InitialOwnerSetupError> {
        let directory = fs::symlink_metadata(&self.directory)
            .map_err(|_| InitialOwnerSetupError::IdentityChanged)?;
        let socket = fs::symlink_metadata(&self.path)
            .map_err(|_| InitialOwnerSetupError::IdentityChanged)?;
        if !directory.is_dir()
            || (directory.dev(), directory.ino()) != self.directory_identity
            || directory.uid() != self.uid
            || directory.mode() & 0o7777 != 0o700
            || fs::canonicalize(&self.directory)
                .map_err(|_| InitialOwnerSetupError::IdentityChanged)?
                != self.directory
            || !socket.file_type().is_socket()
            || (socket.dev(), socket.ino()) != self.socket_identity
            || socket.uid() != self.uid
            || socket.mode() & 0o7777 != 0o600
        {
            return Err(InitialOwnerSetupError::IdentityChanged);
        }
        Ok(())
    }
}

fn remaining(deadline: Instant) -> Result<Duration, InitialOwnerSetupError> {
    let limit = deadline
        .saturating_duration_since(Instant::now())
        .min(IO_LIMIT);
    if limit.is_zero() {
        Err(InitialOwnerSetupError::Timeout)
    } else {
        Ok(limit)
    }
}

fn read_exact_until(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), InitialOwnerSetupError> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(bytes) {
            Ok(0) => return Err(InitialOwnerSetupError::Invalid("setup frame ended early")),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn write_all_until(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<(), InitialOwnerSetupError> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(bytes) {
            Ok(0) => return Err(InitialOwnerSetupError::Invalid("setup write returned zero")),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn read_frame_exact(
    stream: &mut UnixStream,
    expected: usize,
    deadline: Instant,
) -> Result<Vec<u8>, InitialOwnerSetupError> {
    let mut prefix = [0_u8; 4];
    read_exact_until(stream, &mut prefix, deadline)?;
    if u32::from_be_bytes(prefix) as usize != expected {
        return Err(InitialOwnerSetupError::Invalid(
            "setup frame length differs",
        ));
    }
    let mut payload = vec![0_u8; expected];
    read_exact_until(stream, &mut payload, deadline)?;
    Ok(payload)
}

fn write_frame(
    stream: &mut UnixStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), InitialOwnerSetupError> {
    let size = u32::try_from(bytes.len())
        .map_err(|_| InitialOwnerSetupError::Invalid("setup frame exceeds bound"))?;
    write_all_until(stream, &size.to_be_bytes(), deadline)?;
    write_all_until(stream, bytes, deadline)
}
