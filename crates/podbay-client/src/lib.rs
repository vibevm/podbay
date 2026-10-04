//! Synchronous, OS-neutral PodBay transport over an authenticated caller stream.
//! This crate never chooses credentials, reconnects, or retries a logical command.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod linux_auth;

use std::fmt::{Display, Formatter};
use std::io::{self, Read, Write};

use podbay_wire::{
    CommandEnvelope, ErrorEnvelope, MAX_FRAME_BYTES, ReadEnvelope, Receipt, SuccessEnvelope,
    WireError,
};
use serde::de::DeserializeOwned;
use serde_json::Value;

#[cfg(target_os = "linux")]
pub use linux_auth::{
    ActorChallengeOrigin, CanonicalActorChallenge, ClientAuthFailure, ClientAuthFailureKind,
    ClientAuthStage, LinuxClientAuthLimits, authenticate_existing_linux_stream,
    authenticate_existing_linux_stream_with_limits,
};

#[derive(Debug)]
pub enum ClientFault {
    Io(io::Error),
    Wire(WireError),
    Json(serde_json::Error),
    ResponseShape,
    RequestCorrelation,
    Poisoned,
}

impl Display for ClientFault {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "PodBay transport I/O failed: {error}"),
            Self::Wire(error) => write!(f, "PodBay wire failed: {error}"),
            Self::Json(error) => write!(f, "PodBay response JSON failed: {error}"),
            Self::ResponseShape => {
                f.write_str("PodBay response must have exactly one success or error")
            }
            Self::RequestCorrelation => f.write_str("PodBay response requestId differs"),
            Self::Poisoned => {
                f.write_str("PodBay transport alignment is unknown; reconnect required")
            }
        }
    }
}
impl std::error::Error for ClientFault {}

#[derive(Debug)]
pub enum MutationError {
    /// Local validation and frame construction failed before any transport write.
    BeforeEffect(WireError),
    /// The previous exchange lost frame alignment; this request was not sent.
    NotSent(ClientFault),
    /// A complete correlated server error with no explicit admitted uncertainty.
    Server {
        key: String,
        envelope: ErrorEnvelope,
    },
    /// The server explicitly reported an uncertain outcome (or a deadline
    /// after admission). The original key and CommandId remain available.
    ServerUncertain {
        key: String,
        envelope: ErrorEnvelope,
    },
    /// Bytes may have reached the manager. Preserve the key for commands.get
    /// or an explicit caller-directed retry through a new connection.
    Uncertain {
        key: String,
        request_id: String,
        cause: ClientFault,
    },
}

impl Display for MutationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BeforeEffect(error) => write!(f, "PodBay mutation not sent: {error}"),
            Self::NotSent(error) => write!(f, "PodBay mutation not sent: {error}"),
            Self::Server { key, envelope } => write!(
                f,
                "PodBay mutation {key} failed: {}",
                envelope.error.message
            ),
            Self::ServerUncertain { key, envelope } => write!(
                f,
                "PodBay mutation {key} uncertain: {}",
                envelope.error.message
            ),
            Self::Uncertain { key, cause, .. } => {
                write!(f, "PodBay mutation {key} uncertain: {cause}")
            }
        }
    }
}
impl std::error::Error for MutationError {}

#[derive(Debug)]
pub enum ReadError {
    BeforeEffect(WireError),
    Server(ErrorEnvelope),
    Unavailable(ClientFault),
}

impl Display for ReadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BeforeEffect(error) => write!(f, "PodBay read not sent: {error}"),
            Self::Server(envelope) => write!(f, "PodBay read failed: {}", envelope.error.message),
            Self::Unavailable(error) => write!(f, "PodBay read unavailable: {error}"),
        }
    }
}
impl std::error::Error for ReadError {}

enum Reply<T> {
    Ok(T),
    Error(ErrorEnvelope),
}

/// One in-order framed exchange at a time. The supplied stream must already
/// be authenticated and scoped by its caller. A protocol fault poisons it.
pub struct PodBayClient<S> {
    stream: S,
    poisoned: bool,
}

impl<S: Read + Write> PodBayClient<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            poisoned: false,
        }
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// A mutation uses exactly the caller's key and performs no automatic retry.
    pub fn command<T: DeserializeOwned>(
        &mut self,
        command: &CommandEnvelope,
    ) -> Result<Receipt<T>, MutationError> {
        let payload = command.encode_json().map_err(MutationError::BeforeEffect)?;
        let frame = frame(&payload).map_err(MutationError::BeforeEffect)?;
        if self.poisoned {
            return Err(MutationError::NotSent(ClientFault::Poisoned));
        }
        let key = command.key.clone();
        let request_id = command.request_id.clone();
        match self.exchange::<Receipt<T>>(&frame, &request_id) {
            Ok(Reply::Ok(receipt)) => {
                receipt.validate().map_err(|error| {
                    self.poisoned = true;
                    MutationError::Uncertain {
                        key,
                        request_id,
                        cause: ClientFault::Wire(error),
                    }
                })?;
                Ok(receipt)
            }
            Ok(Reply::Error(envelope))
                if envelope.error.code == podbay_wire::RuntimeErrorCode::Uncertain
                    || (envelope.error.code == podbay_wire::RuntimeErrorCode::DeadlineExceeded
                        && envelope.error.command_id.is_some()) =>
            {
                Err(MutationError::ServerUncertain { key, envelope })
            }
            Ok(Reply::Error(envelope)) => Err(MutationError::Server { key, envelope }),
            Err(cause) => Err(MutationError::Uncertain {
                key,
                request_id,
                cause,
            }),
        }
    }

    /// Read failures never imply a mutation. Reconnect before another exchange
    /// if frame alignment is unknown.
    pub fn read<T: DeserializeOwned>(&mut self, request: &ReadEnvelope) -> Result<T, ReadError> {
        let payload = request.encode_json().map_err(ReadError::BeforeEffect)?;
        let frame = frame(&payload).map_err(ReadError::BeforeEffect)?;
        if self.poisoned {
            return Err(ReadError::Unavailable(ClientFault::Poisoned));
        }
        match self.exchange::<T>(&frame, &request.request_id) {
            Ok(Reply::Ok(value)) => Ok(value),
            Ok(Reply::Error(envelope)) => Err(ReadError::Server(envelope)),
            Err(cause) => Err(ReadError::Unavailable(cause)),
        }
    }

    fn exchange<T: DeserializeOwned>(
        &mut self,
        frame: &[u8],
        request_id: &str,
    ) -> Result<Reply<T>, ClientFault> {
        let result = (|| {
            self.stream.write_all(frame).map_err(ClientFault::Io)?;
            self.stream.flush().map_err(ClientFault::Io)?;
            let response = read_frame(&mut self.stream)?;
            parse_reply::<T>(&response, request_id)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

fn frame(payload: &[u8]) -> Result<Vec<u8>, WireError> {
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge);
    }
    let length = u32::try_from(payload.len()).map_err(|_| WireError::FrameTooLarge)?;
    let mut result = Vec::with_capacity(payload.len() + 4);
    result.extend_from_slice(&length.to_be_bytes());
    result.extend_from_slice(payload);
    Ok(result)
}

fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>, ClientFault> {
    let mut prefix = [0u8; 4];
    stream.read_exact(&mut prefix).map_err(ClientFault::Io)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(ClientFault::Wire(WireError::FrameTooLarge));
    }
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).map_err(ClientFault::Io)?;
    Ok(payload)
}

fn parse_reply<T: DeserializeOwned>(
    payload: &[u8],
    request_id: &str,
) -> Result<Reply<T>, ClientFault> {
    let value: Value = serde_json::from_slice(payload).map_err(ClientFault::Json)?;
    let object = value.as_object().ok_or(ClientFault::ResponseShape)?;
    if object.get("protocol").and_then(Value::as_str) != Some("podbay/1") {
        return Err(ClientFault::Wire(WireError::UnsupportedVersion));
    }
    if object.contains_key("ok") == object.contains_key("error") {
        return Err(ClientFault::ResponseShape);
    }
    if object.contains_key("error") {
        let envelope: ErrorEnvelope = serde_json::from_value(value).map_err(ClientFault::Json)?;
        envelope.validate().map_err(ClientFault::Wire)?;
        if envelope.request_id != request_id {
            return Err(ClientFault::RequestCorrelation);
        }
        return Ok(Reply::Error(envelope));
    }
    let envelope: SuccessEnvelope<T> = serde_json::from_value(value).map_err(ClientFault::Json)?;
    envelope.validate().map_err(ClientFault::Wire)?;
    if envelope.request_id != request_id {
        return Err(ClientFault::RequestCorrelation);
    }
    Ok(Reply::Ok(envelope.ok))
}
