//! One bounded auth/1 proof over a caller-owned, already connected Unix socket.
//! The caller must validate host/lineage/scope/process expectations before signing.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const AUTH_PROTOCOL: &str = "podbay.auth/1";
const CHALLENGE_DOMAIN: &[u8] = b"podbay.actor-credential.challenge\0";
const CHALLENGE_VERSION: u8 = 1;
const MAX_SELECTOR_BYTES: usize = 512;
const MAX_CHALLENGE_BYTES: usize = 8_192;
const SIGNATURE_BYTES: usize = 64;
const ACK_BYTES: &[u8] = b"{\"protocol\":\"podbay.auth/1\",\"ok\":true}";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientAuthStage {
    BeforeWrite,
    SelectorPossiblyWritten,
    SignaturePossiblyWritten,
}

#[derive(Debug)]
pub enum ClientAuthFailureKind {
    InvalidInput,
    InvalidLimits,
    MalformedChallenge,
    MalformedAcknowledgement,
    SignerRejected,
    Io(io::Error),
}

#[derive(Debug)]
pub struct ClientAuthFailure {
    pub stage: ClientAuthStage,
    pub kind: ClientAuthFailureKind,
}

fn failure(stage: ClientAuthStage, kind: ClientAuthFailureKind) -> ClientAuthFailure {
    ClientAuthFailure { stage, kind }
}

impl Display for ClientAuthFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "PodBay auth/1 failed at {:?}: {:?}",
            self.stage, self.kind
        )
    }
}
impl Error for ClientAuthFailure {}

#[derive(Clone, Copy, Debug)]
pub struct LinuxClientAuthLimits {
    /// Absolute deadline for the complete selector/challenge/signature/ACK.
    pub handshake: Duration,
    /// Per-read/write idle timeout on the returned UnixStream, not a command deadline.
    pub post_auth_idle: Duration,
}
impl LinuxClientAuthLimits {
    pub fn new(handshake: Duration, post_auth_idle: Duration) -> Result<Self, ClientAuthFailure> {
        if handshake.is_zero()
            || post_auth_idle.is_zero()
            || handshake > Duration::from_secs(60)
            || post_auth_idle > Duration::from_secs(300)
        {
            return Err(failure(
                ClientAuthStage::BeforeWrite,
                ClientAuthFailureKind::InvalidLimits,
            ));
        }
        Ok(Self {
            handshake,
            post_auth_idle,
        })
    }
}
impl Default for LinuxClientAuthLimits {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(5),
            post_auth_idle: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActorChallengeOrigin<'a> {
    OwnerCli,
    Pod { pod_id: &'a str, incarnation: u64 },
}

/// Strictly decoded host transcript. `bytes` are the exact bytes to sign.
/// The signer must compare actor, lineage, scope, generation, process binding,
/// and origin with trusted local expectations. It must separately establish
/// that the connected server is the expected host; the transcript alone does
/// not attest the server endpoint.
#[derive(Clone, Copy, Debug)]
pub struct CanonicalActorChallenge<'a> {
    pub bytes: &'a [u8],
    pub nonce: [u8; 32],
    pub store_lineage: &'a str,
    pub actor_id: &'a str,
    pub scope_id: &'a str,
    pub credential_generation: u64,
    pub os_identity: &'a str,
    pub process_identity: &'a str,
    pub start_identity: u64,
    pub containment_identity: &'a str,
    pub origin: ActorChallengeOrigin<'a>,
}

/// The callback is a validation-and-sign boundary, not a generic signing
/// oracle. It must refuse any unexpected store lineage, scope, generation,
/// process evidence or origin and return `None` without signing. The caller
/// must also verify its expected host connection out of band. The client
/// checks canonical structure and the selected actor before calling it. The
/// returned raw stream has only a per-I/O idle timeout; its PodBay/1 caller
/// must enforce any absolute command or exchange deadline separately.
pub fn authenticate_existing_linux_stream<F>(
    socket: UnixStream,
    actor_id: &str,
    validate_and_sign: F,
) -> Result<UnixStream, ClientAuthFailure>
where
    F: FnOnce(&CanonicalActorChallenge<'_>) -> Option<[u8; SIGNATURE_BYTES]>,
{
    authenticate_existing_linux_stream_with_limits(
        socket,
        actor_id,
        LinuxClientAuthLimits::default(),
        validate_and_sign,
    )
}

pub fn authenticate_existing_linux_stream_with_limits<F>(
    mut socket: UnixStream,
    actor_id: &str,
    limits: LinuxClientAuthLimits,
    validate_and_sign: F,
) -> Result<UnixStream, ClientAuthFailure>
where
    F: FnOnce(&CanonicalActorChallenge<'_>) -> Option<[u8; SIGNATURE_BYTES]>,
{
    let limits = LinuxClientAuthLimits::new(limits.handshake, limits.post_auth_idle)?;
    if !valid_actor_id(actor_id) {
        return Err(failure(
            ClientAuthStage::BeforeWrite,
            ClientAuthFailureKind::InvalidInput,
        ));
    }
    let selector = format!("{{\"protocol\":\"{AUTH_PROTOCOL}\",\"actorId\":\"{actor_id}\"}}");
    if selector.len() > MAX_SELECTOR_BYTES {
        return Err(failure(
            ClientAuthStage::BeforeWrite,
            ClientAuthFailureKind::InvalidInput,
        ));
    }
    let deadline = Instant::now() + limits.handshake;
    let mut stage = ClientAuthStage::BeforeWrite;
    write_frame(
        &mut socket,
        selector.as_bytes(),
        deadline,
        &mut stage,
        ClientAuthStage::SelectorPossiblyWritten,
    )?;
    let challenge_bytes = read_frame(
        &mut socket,
        MAX_CHALLENGE_BYTES,
        deadline,
        stage,
        ClientAuthFailureKind::MalformedChallenge,
    )?;
    let challenge = parse_challenge(&challenge_bytes, actor_id)
        .ok_or_else(|| failure(stage, ClientAuthFailureKind::MalformedChallenge))?;
    let signature = validate_and_sign(&challenge)
        .ok_or_else(|| failure(stage, ClientAuthFailureKind::SignerRejected))?;
    write_frame(
        &mut socket,
        &signature,
        deadline,
        &mut stage,
        ClientAuthStage::SignaturePossiblyWritten,
    )?;
    let acknowledgement = read_frame(
        &mut socket,
        ACK_BYTES.len(),
        deadline,
        stage,
        ClientAuthFailureKind::MalformedAcknowledgement,
    )?;
    if acknowledgement != ACK_BYTES {
        return Err(failure(
            stage,
            ClientAuthFailureKind::MalformedAcknowledgement,
        ));
    }
    time_left(deadline).map_err(|error| failure(stage, ClientAuthFailureKind::Io(error)))?;
    socket
        .set_read_timeout(Some(limits.post_auth_idle))
        .map_err(|error| failure(stage, ClientAuthFailureKind::Io(error)))?;
    socket
        .set_write_timeout(Some(limits.post_auth_idle))
        .map_err(|error| failure(stage, ClientAuthFailureKind::Io(error)))?;
    Ok(socket)
}

fn valid_actor_id(actor: &str) -> bool {
    (3..=256).contains(&actor.len())
        && actor
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn parse_challenge<'a>(
    bytes: &'a [u8],
    selected_actor: &str,
) -> Option<CanonicalActorChallenge<'a>> {
    if bytes.len() > MAX_CHALLENGE_BYTES || !bytes.starts_with(CHALLENGE_DOMAIN) {
        return None;
    }
    let mut at = CHALLENGE_DOMAIN.len();
    if *bytes.get(at)? != CHALLENGE_VERSION {
        return None;
    }
    at += 1;
    let nonce_bytes = field(bytes, &mut at, 1, 32)?;
    if nonce_bytes.len() != 32 || nonce_bytes.iter().all(|byte| *byte == 0) {
        return None;
    }
    let nonce: [u8; 32] = nonce_bytes.try_into().ok()?;
    let store_lineage = text(field(bytes, &mut at, 2, 256)?)?;
    let actor_id = text(field(bytes, &mut at, 3, 256)?)?;
    if actor_id != selected_actor {
        return None;
    }
    let scope_id = text(field(bytes, &mut at, 4, 256)?)?;
    let credential_generation = counter(field(bytes, &mut at, 5, 8)?)?;
    let platform = field(bytes, &mut at, 6, 1)?;
    if platform != [1] {
        return None;
    }
    let os_identity = text(field(bytes, &mut at, 7, 256)?)?;
    let process_identity = text(field(bytes, &mut at, 8, 256)?)?;
    let start_identity = counter(field(bytes, &mut at, 9, 8)?)?;
    let containment_identity = text(field(bytes, &mut at, 10, 4096)?)?;
    let origin = match field(bytes, &mut at, 11, 1)? {
        [1] => ActorChallengeOrigin::OwnerCli,
        [2] => {
            let pod_id = text(field(bytes, &mut at, 12, 256)?)?;
            let incarnation = counter(field(bytes, &mut at, 13, 8)?)?;
            ActorChallengeOrigin::Pod {
                pod_id,
                incarnation,
            }
        }
        _ => return None,
    };
    (at == bytes.len()).then_some(CanonicalActorChallenge {
        bytes,
        nonce,
        store_lineage,
        actor_id,
        scope_id,
        credential_generation,
        os_identity,
        process_identity,
        start_identity,
        containment_identity,
        origin,
    })
}

fn field<'a>(bytes: &'a [u8], at: &mut usize, tag: u8, maximum: usize) -> Option<&'a [u8]> {
    let header_end = at.checked_add(3)?;
    let header = bytes.get(*at..header_end)?;
    if header[0] != tag {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([header[1], header[2]]));
    if length == 0 || length > maximum {
        return None;
    }
    let end = header_end.checked_add(length)?;
    let value = bytes.get(header_end..end)?;
    *at = end;
    Some(value)
}

fn text(bytes: &[u8]) -> Option<&str> {
    if !bytes.iter().all(|byte| byte.is_ascii_graphic()) {
        return None;
    }
    std::str::from_utf8(bytes).ok()
}

fn counter(bytes: &[u8]) -> Option<u64> {
    let value = u64::from_be_bytes(bytes.try_into().ok()?);
    (value > 0).then_some(value)
}

fn read_frame(
    socket: &mut UnixStream,
    maximum: usize,
    deadline: Instant,
    stage: ClientAuthStage,
    invalid: ClientAuthFailureKind,
) -> Result<Vec<u8>, ClientAuthFailure> {
    let mut prefix = [0_u8; 4];
    read_exact_until(socket, &mut prefix, deadline)
        .map_err(|error| failure(stage, ClientAuthFailureKind::Io(error)))?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > maximum {
        return Err(failure(stage, invalid));
    }
    let mut bytes = vec![0_u8; length];
    read_exact_until(socket, &mut bytes, deadline)
        .map_err(|error| failure(stage, ClientAuthFailureKind::Io(error)))?;
    Ok(bytes)
}

fn write_frame(
    socket: &mut UnixStream,
    bytes: &[u8],
    deadline: Instant,
    stage: &mut ClientAuthStage,
    after_attempt: ClientAuthStage,
) -> Result<(), ClientAuthFailure> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| failure(*stage, ClientAuthFailureKind::InvalidInput))?;
    write_all_until(
        socket,
        &length.to_be_bytes(),
        deadline,
        stage,
        after_attempt,
    )
    .and_then(|()| write_all_until(socket, bytes, deadline, stage, after_attempt))
    .map_err(|error| failure(*stage, ClientAuthFailureKind::Io(error)))
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

fn write_all_until(
    socket: &mut UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
    stage: &mut ClientAuthStage,
    after_attempt: ClientAuthStage,
) -> io::Result<()> {
    while !bytes.is_empty() {
        socket.set_write_timeout(Some(time_left(deadline)?))?;
        *stage = after_attempt;
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
