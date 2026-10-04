//! Authenticated PodBay/1 exchanges over an owned Linux socket. The default
//! listener is read-only; explicit trusted policies enable root launch and
//! the first claimed Codex session send. No automatic retry lives here.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod auth_prelude;
#[cfg(target_os = "linux")]
mod host_launch_handler;
#[cfg(target_os = "linux")]
mod host_read_handler;
#[cfg(target_os = "linux")]
mod initial_owner_setup;
#[cfg(target_os = "linux")]
mod owner_recovery;
#[cfg(target_os = "linux")]
mod linux_listener;
#[cfg(target_os = "linux")]
mod linux_peer;

use std::fmt;
use std::io::{self, Read, Write};

use podbay_host::{AuthenticatedPeer, AuthenticatedTransport, HostError};
use podbay_wire::{
    CommandEnvelope, ErrorEnvelope, MAX_FRAME_BYTES, ProtocolVersion, ReadEnvelope, ReadOperation,
    Receipt, RuntimeError, RuntimeErrorCode, SuccessEnvelope, WireError, decode_command_json,
    decode_read_json, encode_frame,
};
use serde_json::Value;

#[cfg(target_os = "linux")]
pub use auth_prelude::{
    AUTH_PRELUDE_PROTOCOL, LinuxAuthPreludeError, LinuxAuthPreludeLimits, LinuxAuthenticatedStream,
    authenticate_accepted_linux_stream, authenticate_accepted_linux_stream_with_limits,
};
#[cfg(target_os = "linux")]
pub use initial_owner_setup::{
    InitialOwnerSetupError, LinuxInitialOwnerSetupListener, OWNER_SETUP_SOCKET_NAME,
};
#[cfg(target_os = "linux")]
pub use owner_recovery::{
    LinuxOwnerRecoveryListener, OwnerRecoveryError, OwnerRecoveryReceipt,
    OWNER_RECOVERY_SOCKET_NAME,
};
#[cfg(target_os = "linux")]
pub use linux_listener::{
    LinuxListenerError, LinuxListenerReport, LinuxManagerCommandsGetListener, MANAGER_SOCKET_NAME,
    TrustedBootstrapSendTemplate, TrustedWireRootLaunchTemplate,
};
#[cfg(target_os = "linux")]
pub use linux_peer::{LinuxAcceptedPeerError, LinuxAcceptedPeerEvidence};

/// Authenticate the accepted Linux socket before reading any PodBay/1 request,
/// then perform exactly one exchange. Authentication grants no command rights;
/// `serve_one` and its handler retain their own authority checks. In particular,
/// a lost response keeps the original `ServerFault::ResponseLost` key/CommandId.
#[cfg(target_os = "linux")]
pub fn serve_authenticated_linux_one<P: podbay_host::HostDispatchPort, H: Handler>(
    socket: std::os::unix::net::UnixStream,
    authority: &mut podbay_host::DurableAuthority<P>,
    handler: &mut H,
) -> Result<(), LinuxServeOneFault> {
    let mut authenticated = authenticate_accepted_linux_stream(socket, authority)
        .map_err(LinuxServeOneFault::Authentication)?;
    serve_one(&mut authenticated, handler).map_err(LinuxServeOneFault::Exchange)
}

/// Authenticate and perform one `commands.get` or `snapshot.get` using the same manager owner
/// for proof and read authority. Other reads and every mutation are refused
/// by the handler without calling a host port. No listener loop lives here.
#[cfg(target_os = "linux")]
pub fn serve_authenticated_linux_commands_get_one<P: podbay_host::HostDispatchPort>(
    socket: std::os::unix::net::UnixStream,
    authority: &mut podbay_host::DurableAuthority<P>,
) -> Result<(), LinuxServeOneFault> {
    let mut authenticated = authenticate_accepted_linux_stream(socket, authority)
        .map_err(LinuxServeOneFault::Authentication)?;
    let mut handler = host_read_handler::HostReadHandler::new(authority);
    serve_one(&mut authenticated, &mut handler).map_err(LinuxServeOneFault::Exchange)
}

/// Opt-in one-exchange manager surface. The policy must be constructed from
/// trusted manager configuration for this exchange; the wire request cannot
/// create a grant or credential. Reads still use the same authenticated owner.
#[cfg(target_os = "linux")]
pub fn serve_authenticated_linux_launch_one<P>(
    socket: std::os::unix::net::UnixStream,
    authority: &mut podbay_host::DurableAuthority<P>,
    policy: &podbay_host::TrustedWireRootLaunchPolicy,
) -> Result<(), LinuxServeOneFault>
where
    P: podbay_host::HostDispatchPort,
    P::Receipt: podbay_host::StablePortReceipt,
{
    let mut authenticated = authenticate_accepted_linux_stream(socket, authority)
        .map_err(LinuxServeOneFault::Authentication)?;
    let mut handler = host_launch_handler::HostLaunchHandler::new(authority, policy);
    serve_one(&mut authenticated, &mut handler).map_err(LinuxServeOneFault::Exchange)
}

/// Opt in to root launch and the first Codex bootstrap send on one authenticated
/// manager socket. The send policy maps to a preinstalled scope grant; the
/// request cannot install one or supply native input directly to the pod.
#[cfg(target_os = "linux")]
pub fn serve_authenticated_linux_launch_and_first_send_one<P>(
    socket: std::os::unix::net::UnixStream,
    authority: &mut podbay_host::DurableAuthority<P>,
    launch_policy: &podbay_host::TrustedWireRootLaunchPolicy,
    send_policy: &podbay_host::TrustedBootstrapSendPolicy,
) -> Result<(), LinuxServeOneFault>
where
    P: podbay_host::HostDispatchPort,
    P::Receipt: podbay_host::StablePortReceipt,
{
    serve_authenticated_linux_launch_and_first_send_one_with_limits(
        socket,
        authority,
        launch_policy,
        send_policy,
        LinuxAuthPreludeLimits::default(),
    )
}

/// The listener supplies a bounded post-auth exchange budget from trusted
/// manager policy. The challenge and acknowledgement retain their separate
/// short handshake deadline; neither wire JSON nor a port reply extends it.
#[cfg(target_os = "linux")]
pub fn serve_authenticated_linux_launch_and_first_send_one_with_limits<P>(
    socket: std::os::unix::net::UnixStream,
    authority: &mut podbay_host::DurableAuthority<P>,
    launch_policy: &podbay_host::TrustedWireRootLaunchPolicy,
    send_policy: &podbay_host::TrustedBootstrapSendPolicy,
    limits: LinuxAuthPreludeLimits,
) -> Result<(), LinuxServeOneFault>
where
    P: podbay_host::HostDispatchPort,
    P::Receipt: podbay_host::StablePortReceipt,
{
    let mut authenticated =
        authenticate_accepted_linux_stream_with_limits(socket, authority, limits)
            .map_err(LinuxServeOneFault::Authentication)?;
    let mut handler = host_launch_handler::HostLaunchHandler::with_first_send(
        authority,
        launch_policy,
        send_policy,
    );
    serve_one(&mut authenticated, &mut handler).map_err(LinuxServeOneFault::Exchange)
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub enum LinuxServeOneFault {
    Authentication(LinuxAuthPreludeError),
    Exchange(ServerFault),
}

#[cfg(target_os = "linux")]
impl fmt::Display for LinuxServeOneFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentication(error) => write!(formatter, "Linux actor proof failed: {error}"),
            Self::Exchange(error) => write!(formatter, "authenticated exchange failed: {error}"),
        }
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for LinuxServeOneFault {}

#[derive(Debug)]
pub enum ServerFault {
    Unauthenticated,
    Transport(io::Error),
    /// The handler may have admitted a command, but its correlated reply was
    /// not delivered. The caller must query the original key/CommandId.
    ResponseLost {
        key: Option<String>,
        command_id: Option<String>,
        cause: io::Error,
    },
    Internal(WireError),
}
impl fmt::Display for ServerFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthenticated => f.write_str("PodBay transport peer was not verified"),
            Self::Transport(error) => write!(f, "PodBay request transport failed: {error}"),
            Self::ResponseLost {
                key,
                command_id,
                cause,
            } => write!(
                f,
                "PodBay response lost for key {key:?}, command {command_id:?}: {cause}"
            ),
            Self::Internal(error) => write!(f, "PodBay server wire construction failed: {error}"),
        }
    }
}
impl std::error::Error for ServerFault {}

/// A handler supplies domain reads and durable mutation admission. It must
/// use the supplied authenticated transport for its own live authority check
/// immediately before admission/effect. If an effect may have occurred, it
/// returns `Uncertain` (or an admitted deadline) and the known CommandId.
/// This router never invokes it twice.
pub trait Handler {
    fn command<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        request: CommandEnvelope,
    ) -> Result<Receipt<Value>, RuntimeError>;
    fn read<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        request: ReadEnvelope,
    ) -> Result<Value, RuntimeError>;
}

/// A handler-side authority check can reattest the *same* initially bound
/// process/generation at its own durable admission boundary. No cloned peer
/// value is supplied as a substitute for a live transport witness.
struct BoundTransport<'a, T> {
    inner: &'a T,
    initial: AuthenticatedPeer,
}
impl<T: AuthenticatedTransport> AuthenticatedTransport for BoundTransport<'_, T> {
    fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError> {
        let current = self.inner.verified_peer()?;
        if current == self.initial {
            Ok(current)
        } else {
            Err(HostError::Unauthenticated)
        }
    }
}

/// Process exactly one exchange. The transport adapter must enforce finite
/// read/write deadlines and live reattestation on each `verified_peer` call;
/// generic `Read + Write` alone cannot bound a partial frame wait. Authentication
/// runs before the prefix and again before dispatch. An invalid request receives
/// an error when framing permits; none reaches `Handler`.
pub fn serve_one<S: Read + Write + AuthenticatedTransport, H: Handler>(
    stream: &mut S,
    handler: &mut H,
) -> Result<(), ServerFault> {
    let peer = stream
        .verified_peer()
        .map_err(|_| ServerFault::Unauthenticated)?;
    let payload = match read_frame(stream) {
        Ok(payload) => payload,
        Err(ReadFrameFault::Io(error)) => return Err(ServerFault::Transport(error)),
        Err(ReadFrameFault::Bound) => {
            return send_error(
                stream,
                "request.invalid",
                RuntimeErrorCode::InvalidInput,
                "request frame exceeded bound",
                None,
                None,
            );
        }
    };
    let request_id = request_id_hint(&payload).unwrap_or_else(|| "request.invalid".to_owned());
    let value: Value = match serde_json::from_slice(&payload) {
        Ok(value) => value,
        Err(_) => {
            return send_error(
                stream,
                &request_id,
                RuntimeErrorCode::InvalidInput,
                "request JSON is malformed",
                None,
                None,
            );
        }
    };
    let operation = value.get("operation").and_then(Value::as_str).unwrap_or("");
    let is_read = ReadOperation::SUPPORTED
        .iter()
        .any(|item| item.as_str() == operation);
    if is_read {
        let request = match decode_read_json(&payload) {
            Ok(request) => request,
            Err(error) => return wire_refusal(stream, &request_id, error),
        };
        let bound = BoundTransport {
            inner: stream,
            initial: peer.clone(),
        };
        bound
            .verified_peer()
            .map_err(|_| ServerFault::Unauthenticated)?;
        let request_id = request.request_id.clone();
        match handler.read(&bound, request) {
            Ok(value) => {
                let response = SuccessEnvelope {
                    protocol: ProtocolVersion::V1,
                    request_id: request_id.clone(),
                    ok: value,
                };
                match encode_frame(&response) {
                    Ok(frame) => write_response(stream, &frame, None, None),
                    Err(_) => send_error(
                        stream,
                        &request_id,
                        RuntimeErrorCode::Unavailable,
                        "read response exceeded frame bound",
                        None,
                        None,
                    ),
                }
            }
            Err(error) => send_runtime_error(stream, &request_id, error, None),
        }
    } else {
        let request = match decode_command_json(&payload) {
            Ok(request) => request,
            Err(error) => return wire_refusal(stream, &request_id, error),
        };
        let bound = BoundTransport {
            inner: stream,
            initial: peer.clone(),
        };
        bound
            .verified_peer()
            .map_err(|_| ServerFault::Unauthenticated)?;
        let request_id = request.request_id.clone();
        let key = request.key.clone();
        match handler.command(&bound, request) {
            Ok(receipt) => {
                let command_id = receipt.command_id.clone();
                if receipt.validate().is_err() {
                    return send_error(
                        stream,
                        &request_id,
                        RuntimeErrorCode::Uncertain,
                        "admitted command receipt is invalid",
                        Some(command_id),
                        Some(key),
                    );
                }
                let response = SuccessEnvelope {
                    protocol: ProtocolVersion::V1,
                    request_id: request_id.clone(),
                    ok: receipt,
                };
                match encode_frame(&response) {
                    Ok(frame) => write_response(stream, &frame, Some(key), Some(command_id)),
                    Err(_) => send_error(
                        stream,
                        &request_id,
                        RuntimeErrorCode::Uncertain,
                        "admitted command response exceeded frame bound",
                        Some(command_id),
                        Some(key),
                    ),
                }
            }
            Err(error) => send_runtime_error(stream, &request_id, error, Some(key)),
        }
    }
}

enum ReadFrameFault {
    Io(io::Error),
    Bound,
}
fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>, ReadFrameFault> {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).map_err(ReadFrameFault::Io)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(ReadFrameFault::Bound);
    }
    let mut payload = vec![0_u8; length];
    stream
        .read_exact(&mut payload)
        .map_err(ReadFrameFault::Io)?;
    Ok(payload)
}
fn request_id_hint(bytes: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let id = value.get("requestId")?.as_str()?;
    valid_identity(id).then(|| id.to_owned())
}
fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn wire_refusal(
    stream: &mut impl Write,
    request_id: &str,
    error: WireError,
) -> Result<(), ServerFault> {
    let code = match error {
        WireError::UnsupportedVersion | WireError::UnsupportedOperation(_) => {
            RuntimeErrorCode::Unsupported
        }
        _ => RuntimeErrorCode::InvalidInput,
    };
    send_error(
        stream,
        request_id,
        code,
        "request envelope refused by podbay-wire",
        None,
        None,
    )
}
fn send_runtime_error(
    stream: &mut impl Write,
    request_id: &str,
    mut error: RuntimeError,
    key: Option<String>,
) -> Result<(), ServerFault> {
    if key.is_none() {
        error.command_id = None;
    }
    if error
        .command_id
        .as_deref()
        .is_some_and(|id| !valid_identity(id))
    {
        error.command_id = None;
        error.code = RuntimeErrorCode::Uncertain;
    }
    if error.command_id.is_some()
        && error.code != RuntimeErrorCode::Uncertain
        && error.code != RuntimeErrorCode::DeadlineExceeded
    {
        error.code = RuntimeErrorCode::Uncertain;
    }
    if error.message.is_empty() || error.message.len() > 1024 {
        error.message = "handler error message invalid".into();
    }
    if error.retry.is_empty()
        || error.retry.len() > 64
        || !error.retry.bytes().all(|byte| byte.is_ascii_graphic())
    {
        error.retry = if error.command_id.is_some() {
            "query_command"
        } else {
            "never"
        }
        .into();
    }
    let command_id = error.command_id.clone();
    let envelope = ErrorEnvelope {
        protocol: ProtocolVersion::V1,
        request_id: request_id.to_owned(),
        error,
    };
    envelope.validate().map_err(ServerFault::Internal)?;
    let frame = encode_frame(&envelope).map_err(ServerFault::Internal)?;
    write_response(stream, &frame, key, command_id)
}
fn send_error(
    stream: &mut impl Write,
    request_id: &str,
    code: RuntimeErrorCode,
    message: &str,
    command_id: Option<String>,
    key: Option<String>,
) -> Result<(), ServerFault> {
    let error = RuntimeError {
        code,
        message: message.to_owned(),
        retry: if command_id.is_some() {
            "query_command"
        } else {
            "never"
        }
        .into(),
        command_id,
    };
    send_runtime_error(stream, request_id, error, key)
}
fn write_response(
    stream: &mut impl Write,
    frame: &[u8],
    key: Option<String>,
    command_id: Option<String>,
) -> Result<(), ServerFault> {
    stream
        .write_all(frame)
        .and_then(|()| stream.flush())
        .map_err(|cause| ServerFault::ResponseLost {
            key,
            command_id,
            cause,
        })
}
