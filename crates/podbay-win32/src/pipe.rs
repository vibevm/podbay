//! PB27c one-shot local pipe transport. OS birth and scoped capability gate
//! every request before it can reach a PodBay effect dispatcher.
use std::io;
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    FILE_READ_DATA, FILE_WRITE_DATA, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, SYNCHRONIZE,
};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::GetCurrentProcessId;

use crate::overlapped::{IoKind, operate};
use crate::pipe_model::{MAX_FRAME, PeerGrant, PipeRequest};
use crate::security::pipe_descriptor;
use crate::windows::{OwnedHandle, RunningProcess, open_exact_process};
use crate::{ProcessIdentity, Win32Error};

pub struct PipeServer {
    pipe: Option<OwnedHandle>,
    pod: RunningProcess,
}
pub struct PipeClient {
    pipe: Option<OwnedHandle>,
    server: RunningProcess,
}
pub struct AcceptedPipe {
    pipe: Option<OwnedHandle>,
    peer: RunningProcess,
    request: PipeRequest,
}

impl PipeServer {
    /// `slot` is a 32-character lowercase hex digest bound to a persisted
    /// PodId/attempt/incarnation. No generic pipe name is accepted.
    pub fn bind(slot: &str, expected_pod: ProcessIdentity) -> Result<Self, Win32Error> {
        let name = pipe_name(slot)?;
        // SAFETY: this is an observation-only pseudo-handle/ID query.
        if unsafe { GetCurrentProcessId() } != expected_pod.pid {
            return Err(Win32Error::Unsupported(
                "pipe server is not the recorded pod",
            ));
        }
        let pod = open_exact_process(expected_pod)?;
        let descriptor = pipe_descriptor()?;
        let mut attrs = SECURITY_ATTRIBUTES::default();
        attrs.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
        attrs.lpSecurityDescriptor = descriptor.raw();
        attrs.bInheritHandle = 0;
        // SAFETY: name, explicit protected DACL, and attributes remain alive
        // during CreateNamedPipeW. A first-instance collision is a refusal.
        let raw = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                MAX_FRAME as u32,
                MAX_FRAME as u32,
                2_000,
                &attrs,
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            // SAFETY: capture the failure before any other Win32 call.
            let code = unsafe { GetLastError() };
            return Err(if code == ERROR_ACCESS_DENIED {
                Win32Error::Unsupported("pipe first instance or access was refused")
            } else {
                Win32Error::Os(io::Error::from_raw_os_error(code as i32))
            });
        }
        Ok(Self {
            pipe: Some(OwnedHandle::new(raw)?),
            pod,
        })
    }

    /// One-shot accept. Timeout consumes this pipe instance; a pending
    /// cancellation retains its exact OS allocations in a bounded quarantine.
    pub fn accept_once(
        mut self,
        grant: PeerGrant,
        timeout: Duration,
    ) -> Result<AcceptedPipe, Win32Error> {
        grant.validate()?;
        bounded_timeout(timeout)?;
        let pipe = self
            .pipe
            .take()
            .ok_or(Win32Error::Uncertain("pipe instance consumed"))?;
        let _pod = self.pod; // pins the recorded server process through accept
        accept_and_authenticate(pipe, grant, Instant::now() + timeout)
    }
}

impl PipeClient {
    pub fn connect(slot: &str, expected_server: ProcessIdentity) -> Result<Self, Win32Error> {
        let name = pipe_name(slot)?;
        if expected_server.pid == 0 || expected_server.creation_100ns == 0 {
            return Err(Win32Error::Invalid("pipe server identity incomplete"));
        }
        // Request exact data rights. GENERIC_WRITE would also grant
        // FILE_CREATE_PIPE_INSTANCE, which our protected DACL excludes.
        let rights = FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE;
        // SAFETY: name is NUL-terminated; no inherited handle or template.
        let raw = unsafe {
            CreateFileW(
                name.as_ptr(),
                rights,
                0,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(Win32Error::Os(io::Error::last_os_error()));
        }
        let pipe = OwnedHandle::new(raw)?;
        let mut pid = 0_u32;
        // SAFETY: this owned connected pipe and PID output are valid.
        if unsafe { GetNamedPipeServerProcessId(pipe.raw(), &mut pid) } == 0 {
            return Err(Win32Error::Os(io::Error::last_os_error()));
        }
        if pid != expected_server.pid {
            return Err(Win32Error::Unsupported("pipe server PID mismatch"));
        }
        let server = open_exact_process(expected_server)?;
        Ok(Self {
            pipe: Some(pipe),
            server,
        })
    }

    /// One logical exchange; transport loss after a possible write is always
    /// Uncertain and must be reconciled by CommandId, never retried blindly.
    pub fn exchange(
        mut self,
        request: PipeRequest,
        timeout: Duration,
    ) -> Result<Vec<u8>, Win32Error> {
        bounded_timeout(timeout)?;
        let body = request.encode()?;
        let pipe = self
            .pipe
            .take()
            .ok_or(Win32Error::Uncertain("pipe client consumed"))?;
        let _server = self.server;
        let deadline = Instant::now() + timeout;
        let pipe = write_frame(pipe, &body, deadline)?;
        let (_, response) = read_frame(pipe, deadline)?;
        Ok(response)
    }
}

impl AcceptedPipe {
    pub fn request(&self) -> &PipeRequest {
        &self.request
    }
    pub fn peer_identity(&self) -> ProcessIdentity {
        self.peer.identity()
    }
    pub fn respond(mut self, payload: &[u8], timeout: Duration) -> Result<(), Win32Error> {
        bounded_timeout(timeout)?;
        if payload.len() > MAX_FRAME {
            return Err(Win32Error::Invalid("pipe response bound"));
        }
        let pipe = self
            .pipe
            .take()
            .ok_or(Win32Error::Uncertain("pipe response consumed"))?;
        let _peer = self.peer;
        write_frame(pipe, payload, Instant::now() + timeout).map(|_| ())
    }
}

fn accept_and_authenticate(
    pipe: OwnedHandle,
    grant: PeerGrant,
    deadline: Instant,
) -> Result<AcceptedPipe, Win32Error> {
    let (pipe, _, _) = operate(pipe, IoKind::Connect, deadline)?;
    let mut pid = 0_u32;
    // SAFETY: connected server pipe and writable PID output are valid.
    if unsafe { GetNamedPipeClientProcessId(pipe.raw(), &mut pid) } == 0 {
        return Err(Win32Error::Os(io::Error::last_os_error()));
    }
    if pid != grant.expected_process.pid {
        return Err(Win32Error::Unsupported("unregistered pipe client PID"));
    }
    let peer = open_exact_process(grant.expected_process)?;
    let (pipe, body) = read_frame(pipe, deadline)?;
    let request = PipeRequest::decode(&body)?;
    grant.authorize(peer.identity(), &request)?;
    Ok(AcceptedPipe {
        pipe: Some(pipe),
        peer,
        request,
    })
}

fn pipe_name(slot: &str) -> Result<Vec<u16>, Win32Error> {
    if slot.len() != 32
        || !slot
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Win32Error::Invalid(
            "pipe slot must be 32 lowercase hex characters",
        ));
    }
    Ok(format!(r"\\.\pipe\podbay-{slot}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect())
}
fn bounded_timeout(value: Duration) -> Result<(), Win32Error> {
    if value.is_zero() || value > Duration::from_secs(5) {
        Err(Win32Error::Invalid("pipe deadline bound"))
    } else {
        Ok(())
    }
}

fn read_frame(pipe: OwnedHandle, deadline: Instant) -> Result<(OwnedHandle, Vec<u8>), Win32Error> {
    let (pipe, size) = read_exact(pipe, 4, deadline)?;
    let length = u32::from_be_bytes(size.try_into().unwrap()) as usize;
    if length > MAX_FRAME {
        return Err(Win32Error::Invalid("pipe frame exceeded bound"));
    }
    read_exact(pipe, length, deadline)
}
fn read_exact(
    mut pipe: OwnedHandle,
    length: usize,
    deadline: Instant,
) -> Result<(OwnedHandle, Vec<u8>), Win32Error> {
    let mut collected = Vec::with_capacity(length);
    while collected.len() < length {
        let (next, bytes, read) = operate(pipe, IoKind::Read(length - collected.len()), deadline)?;
        if read == 0 || read > bytes.len() {
            return Err(Win32Error::Uncertain("pipe frame read incomplete"));
        }
        collected.extend_from_slice(&bytes[..read]);
        pipe = next;
    }
    Ok((pipe, collected))
}
fn write_frame(
    mut pipe: OwnedHandle,
    bytes: &[u8],
    deadline: Instant,
) -> Result<OwnedHandle, Win32Error> {
    if bytes.len() > MAX_FRAME {
        return Err(Win32Error::Invalid("pipe frame exceeded bound"));
    }
    let mut frame = Vec::with_capacity(bytes.len() + 4);
    frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    frame.extend_from_slice(bytes);
    let mut offset = 0_usize;
    while offset < frame.len() {
        let (next, _, written) = operate(pipe, IoKind::Write(frame[offset..].to_vec()), deadline)?;
        if written == 0 || written > frame.len() - offset {
            return Err(Win32Error::Uncertain("pipe frame may be partially written"));
        }
        offset += written;
        pipe = next;
    }
    Ok(pipe)
}

#[cfg(test)]
mod compile_tests {
    use super::*;
    #[test]
    fn exact_peer_pipe_surface_compiles_on_windows() {
        let _bind: fn(&str, ProcessIdentity) -> Result<PipeServer, Win32Error> = PipeServer::bind;
        let _connect: fn(&str, ProcessIdentity) -> Result<PipeClient, Win32Error> =
            PipeClient::connect;
        let _accept: fn(PipeServer, PeerGrant, Duration) -> Result<AcceptedPipe, Win32Error> =
            PipeServer::accept_once;
        let _respond: fn(AcceptedPipe, &[u8], Duration) -> Result<(), Win32Error> =
            AcceptedPipe::respond;
    }
}
