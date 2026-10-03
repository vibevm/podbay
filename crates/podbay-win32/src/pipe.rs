//! PB27c one-shot local pipe transport. OS birth and scoped capability gate
//! every request before it can reach a PodBay effect dispatcher.
use std::io;
use std::ptr::{null, null_mut};
use std::sync::mpsc;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_PIPE_CONNECTED, GetLastError, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_READ_DATA,
    FILE_WRITE_DATA, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile, SYNCHRONIZE, WriteFile,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::GetCurrentProcessId;

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
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
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

    /// One-shot accept. Timeout consumes this pipe instance; a late worker may
    /// finish authentication, but cannot dispatch because its receiver is gone.
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
        let pod = self.pod; // pins the recorded server process through accept
        let (sender, receiver) = mpsc::channel();
        std::thread::Builder::new()
            .name("podbay-pipe-accept".into())
            .spawn(move || {
                let result = accept_and_authenticate(pipe, grant);
                let _ = sender.send(result);
                drop(pod);
            })
            .map_err(Win32Error::Os)?;
        receiver.recv_timeout(timeout).map_err(|_| {
            Win32Error::Uncertain("pipe accept/read timed out; no effect dispatched")
        })?
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
                FILE_ATTRIBUTE_NORMAL,
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
        let server = self.server;
        let (sender, receiver) = mpsc::channel();
        std::thread::Builder::new()
            .name("podbay-pipe-exchange".into())
            .spawn(move || {
                let result = write_frame(&pipe, &body).and_then(|()| read_frame(&pipe));
                let _ = sender.send(result);
                drop(server);
            })
            .map_err(Win32Error::Os)?;
        receiver
            .recv_timeout(timeout)
            .map_err(|_| Win32Error::Uncertain("pipe response after possible request is unknown"))?
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
        let bytes = payload.to_vec();
        let peer = self.peer;
        let (sender, receiver) = mpsc::channel();
        std::thread::Builder::new()
            .name("podbay-pipe-response".into())
            .spawn(move || {
                let result = write_frame(&pipe, &bytes);
                let _ = sender.send(result);
                drop(peer);
            })
            .map_err(Win32Error::Os)?;
        receiver
            .recv_timeout(timeout)
            .map_err(|_| Win32Error::Uncertain("pipe response write outcome unknown"))?
    }
}

fn accept_and_authenticate(
    pipe: OwnedHandle,
    grant: PeerGrant,
) -> Result<AcceptedPipe, Win32Error> {
    // SAFETY: the worker exclusively owns this pipe instance during connect.
    let connected = unsafe { ConnectNamedPipe(pipe.raw(), null_mut()) };
    if connected == 0 {
        // SAFETY: capture the failure immediately; an already-connected client
        // is a documented successful race for a one-instance server.
        let code = unsafe { GetLastError() };
        if code != ERROR_PIPE_CONNECTED {
            return Err(Win32Error::Os(io::Error::from_raw_os_error(code as i32)));
        }
    }
    let mut pid = 0_u32;
    // SAFETY: connected server pipe and writable PID output are valid.
    if unsafe { GetNamedPipeClientProcessId(pipe.raw(), &mut pid) } == 0 {
        return Err(Win32Error::Os(io::Error::last_os_error()));
    }
    if pid != grant.expected_process.pid {
        return Err(Win32Error::Unsupported("unregistered pipe client PID"));
    }
    let peer = open_exact_process(grant.expected_process)?;
    let body = read_frame(&pipe)?;
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

fn read_frame(pipe: &OwnedHandle) -> Result<Vec<u8>, Win32Error> {
    let mut size = [0_u8; 4];
    read_exact(pipe, &mut size)?;
    let length = u32::from_be_bytes(size) as usize;
    if length > MAX_FRAME {
        return Err(Win32Error::Invalid("pipe frame exceeded bound"));
    }
    let mut bytes = vec![0_u8; length];
    read_exact(pipe, &mut bytes)?;
    Ok(bytes)
}
fn read_exact(pipe: &OwnedHandle, mut bytes: &mut [u8]) -> Result<(), Win32Error> {
    while !bytes.is_empty() {
        let mut read = 0_u32;
        // SAFETY: owned pipe and writable slice are live; synchronous I/O only.
        let okay = unsafe {
            ReadFile(
                pipe.raw(),
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                &mut read,
                null_mut(),
            )
        };
        if okay == 0 || read == 0 {
            return Err(Win32Error::Uncertain("pipe frame read incomplete"));
        }
        bytes = &mut bytes[read as usize..];
    }
    Ok(())
}
fn write_frame(pipe: &OwnedHandle, bytes: &[u8]) -> Result<(), Win32Error> {
    if bytes.len() > MAX_FRAME {
        return Err(Win32Error::Invalid("pipe frame exceeded bound"));
    }
    let mut frame = Vec::with_capacity(bytes.len() + 4);
    frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    frame.extend_from_slice(bytes);
    while !frame.is_empty() {
        let mut written = 0_u32;
        // SAFETY: owned pipe and immutable slice are live; synchronous I/O only.
        let okay = unsafe {
            WriteFile(
                pipe.raw(),
                frame.as_ptr(),
                frame.len() as u32,
                &mut written,
                null_mut(),
            )
        };
        if okay == 0 || written == 0 {
            return Err(Win32Error::Uncertain("pipe frame may be partially written"));
        }
        frame.drain(..written as usize);
    }
    Ok(())
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
