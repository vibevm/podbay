//! One bounded actor proof on an already accepted Linux Unix stream.
//! The selector is only a lookup hint. No listener or command effect lives here.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use podbay_core::ActorId;
use podbay_host::{
    ActorAuthProofError, AuthenticatedPeer, AuthenticatedTransport, DurableAuthority,
    DurableAuthorityError, HostDispatchPort, HostError, ProvenActorSession,
};
use serde::Deserialize;

use crate::{LinuxAcceptedPeerError, LinuxAcceptedPeerEvidence};

pub const AUTH_PRELUDE_PROTOCOL: &str = "podbay.auth/1";
const MAX_SELECTOR_BYTES: usize = 512;
const MAX_CHALLENGE_BYTES: usize = 8_192;
const SIGNATURE_BYTES: usize = 64;
const ACK_BYTES: &[u8] = b"{\"protocol\":\"podbay.auth/1\",\"ok\":true}";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Selector {
    protocol: String,
    actor_id: String,
}

#[derive(Clone, Copy, Debug)]
pub struct LinuxAuthPreludeLimits {
    pub handshake: Duration,
    pub exchange: Duration,
}

impl LinuxAuthPreludeLimits {
    pub fn new(handshake: Duration, exchange: Duration) -> Result<Self, LinuxAuthPreludeError> {
        if handshake.is_zero()
            || exchange.is_zero()
            || handshake > Duration::from_secs(60)
            || exchange > Duration::from_secs(300)
        {
            return Err(LinuxAuthPreludeError::InvalidLimits);
        }
        Ok(Self {
            handshake,
            exchange,
        })
    }
}

impl Default for LinuxAuthPreludeLimits {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(5),
            exchange: Duration::from_secs(30),
        }
    }
}

#[derive(Debug)]
pub enum LinuxAuthPreludeError {
    InvalidLimits,
    InvalidSelector,
    InvalidSignatureFrame,
    Peer(LinuxAcceptedPeerError),
    Authority(DurableAuthorityError),
    Proof(ActorAuthProofError),
    Io(io::Error),
}

impl Display for LinuxAuthPreludeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("authentication deadlines are invalid"),
            Self::InvalidSelector => formatter.write_str("authentication selector is invalid"),
            Self::InvalidSignatureFrame => {
                formatter.write_str("authentication signature frame is invalid")
            }
            Self::Peer(error) => write!(formatter, "authentication peer refused: {error}"),
            Self::Authority(error) => {
                write!(formatter, "authentication candidate refused: {error:?}")
            }
            Self::Proof(error) => write!(formatter, "authentication proof refused: {error:?}"),
            Self::Io(error) => write!(formatter, "authentication transport failed: {error}"),
        }
    }
}
impl Error for LinuxAuthPreludeError {}
impl From<LinuxAcceptedPeerError> for LinuxAuthPreludeError {
    fn from(value: LinuxAcceptedPeerError) -> Self {
        Self::Peer(value)
    }
}
impl From<DurableAuthorityError> for LinuxAuthPreludeError {
    fn from(value: DurableAuthorityError) -> Self {
        Self::Authority(value)
    }
}
impl From<ActorAuthProofError> for LinuxAuthPreludeError {
    fn from(value: ActorAuthProofError) -> Self {
        Self::Proof(value)
    }
}
impl From<io::Error> for LinuxAuthPreludeError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// A single post-proof connection. Every peer check reattests the accepted
/// socket and rereads the public-verifier witness without mutable authority.
pub struct LinuxAuthenticatedStream {
    socket: UnixStream,
    os_peer: LinuxAcceptedPeerEvidence,
    proof: ProvenActorSession,
    deadline: Instant,
}

impl AuthenticatedTransport for LinuxAuthenticatedStream {
    fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError> {
        if Instant::now() >= self.deadline {
            return Err(HostError::Unauthenticated);
        }
        let process = self
            .os_peer
            .recheck_before_dispatch(&self.socket)
            .map_err(|_| HostError::Unauthenticated)?;
        self.proof
            .verified_peer(process)
            .map_err(|_| HostError::Unauthenticated)
    }
}

impl Read for LinuxAuthenticatedStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.socket
            .set_read_timeout(Some(time_left(self.deadline)?))?;
        let read = self.socket.read(bytes)?;
        time_left(self.deadline)?;
        Ok(read)
    }
}

impl Write for LinuxAuthenticatedStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.socket
            .set_write_timeout(Some(time_left(self.deadline)?))?;
        let written = self.socket.write(bytes)?;
        time_left(self.deadline)?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket
            .set_write_timeout(Some(time_left(self.deadline)?))?;
        self.socket.flush()?;
        time_left(self.deadline)?;
        Ok(())
    }
}

pub fn authenticate_accepted_linux_stream<P: HostDispatchPort>(
    socket: UnixStream,
    authority: &mut DurableAuthority<P>,
) -> Result<LinuxAuthenticatedStream, LinuxAuthPreludeError> {
    authenticate_accepted_linux_stream_with_limits(
        socket,
        authority,
        LinuxAuthPreludeLimits::default(),
    )
}

/// The server receives only a bounded actor selector before proof. A fresh
/// kernel process, active authority candidate and current public verifier are
/// required; neither UID nor a request field enrolls an actor implicitly.
pub fn authenticate_accepted_linux_stream_with_limits<P: HostDispatchPort>(
    mut socket: UnixStream,
    authority: &mut DurableAuthority<P>,
    limits: LinuxAuthPreludeLimits,
) -> Result<LinuxAuthenticatedStream, LinuxAuthPreludeError> {
    let limits = LinuxAuthPreludeLimits::new(limits.handshake, limits.exchange)?;
    let deadline = Instant::now() + limits.handshake;
    let os_peer = LinuxAcceptedPeerEvidence::from_accepted(&socket)?;
    let selector = read_selector(&mut socket, deadline)?;
    let process = os_peer.recheck_before_dispatch(&socket)?;
    let candidate = authority.challenge_candidate_for_observed_process(&selector, process)?;

    let mut nonce = [0_u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    let pending = candidate.begin_challenge(nonce)?;
    let challenge = pending.transcript_bytes()?;
    if challenge.is_empty() || challenge.len() > MAX_CHALLENGE_BYTES {
        return Err(LinuxAuthPreludeError::Proof(
            ActorAuthProofError::Credential(podbay_host::ActorCredentialError::InvalidTranscript),
        ));
    }
    write_frame(&mut socket, &challenge, deadline)?;

    let signature = read_signature(&mut socket, deadline)?;
    let process = os_peer.recheck_before_dispatch(&socket)?;
    let proof = pending.verify(process, &signature)?;
    proof.verified_peer(process)?;
    write_frame(&mut socket, ACK_BYTES, deadline)?;
    let process = os_peer.recheck_before_dispatch(&socket)?;
    proof.verified_peer(process)?;
    time_left(deadline)?;

    Ok(LinuxAuthenticatedStream {
        socket,
        os_peer,
        proof,
        deadline: Instant::now() + limits.exchange,
    })
}

fn read_selector(
    socket: &mut UnixStream,
    deadline: Instant,
) -> Result<ActorId, LinuxAuthPreludeError> {
    let bytes = read_frame(socket, MAX_SELECTOR_BYTES, deadline)?;
    let selector: Selector =
        serde_json::from_slice(&bytes).map_err(|_| LinuxAuthPreludeError::InvalidSelector)?;
    if selector.protocol != AUTH_PRELUDE_PROTOCOL {
        return Err(LinuxAuthPreludeError::InvalidSelector);
    }
    ActorId::try_from(selector.actor_id.as_str())
        .map_err(|_| LinuxAuthPreludeError::InvalidSelector)
}

fn read_signature(
    socket: &mut UnixStream,
    deadline: Instant,
) -> Result<[u8; SIGNATURE_BYTES], LinuxAuthPreludeError> {
    let mut prefix = [0_u8; 4];
    read_exact_until(socket, &mut prefix, deadline)?;
    if u32::from_be_bytes(prefix) as usize != SIGNATURE_BYTES {
        return Err(LinuxAuthPreludeError::InvalidSignatureFrame);
    }
    let mut signature = [0_u8; SIGNATURE_BYTES];
    read_exact_until(socket, &mut signature, deadline)?;
    Ok(signature)
}

fn read_frame(
    socket: &mut UnixStream,
    maximum: usize,
    deadline: Instant,
) -> Result<Vec<u8>, LinuxAuthPreludeError> {
    let mut prefix = [0_u8; 4];
    read_exact_until(socket, &mut prefix, deadline)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > maximum {
        return Err(LinuxAuthPreludeError::InvalidSelector);
    }
    let mut bytes = vec![0_u8; length];
    read_exact_until(socket, &mut bytes, deadline)?;
    Ok(bytes)
}

fn write_frame(socket: &mut UnixStream, bytes: &[u8], deadline: Instant) -> io::Result<()> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "auth frame exceeds bound"))?;
    write_all_until(socket, &length.to_be_bytes(), deadline)?;
    write_all_until(socket, bytes, deadline)
}

fn read_exact_until(
    socket: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        socket.set_read_timeout(Some(time_left(deadline)?))?;
        match socket.read(bytes) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if time_left(deadline).is_err() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "auth/1 read deadline elapsed",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }
    time_left(deadline)?;
    Ok(())
}

fn write_all_until(socket: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        socket.set_write_timeout(Some(time_left(deadline)?))?;
        match socket.write(bytes) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if time_left(deadline).is_err() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "auth/1 write deadline elapsed",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }
    time_left(deadline)?;
    Ok(())
}

fn time_left(deadline: Instant) -> io::Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "auth/1 deadline elapsed",
        ))
    } else {
        Ok(remaining)
    }
}
