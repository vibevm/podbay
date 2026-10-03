//! Cancellable one-operation-at-a-time named-pipe I/O. A pending OS request
//! always retains its handle, buffer, event, and OVERLAPPED allocation.
use std::io;
use std::ptr::null;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use windows_sys::Win32::Foundation::{
    ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, ERROR_OPERATION_ABORTED, ERROR_PIPE_CONNECTED,
    GetLastError, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::ConnectNamedPipe;
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

use crate::Win32Error;
use crate::overlapped_model::{TimeoutCompletion, confirmed_completion_before_deadline};
use crate::windows::OwnedHandle;

const MAX_PENDING: usize = 32;
const CANCEL_GRACE_MS: u32 = 250;
static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
static QUARANTINE: OnceLock<Mutex<Vec<PendingIo>>> = OnceLock::new();

pub(crate) enum IoKind {
    Connect,
    Read(usize),
    Write(Vec<u8>),
}
#[derive(Clone, Copy)]
enum KindTag {
    Connect,
    Read,
    Write,
}
struct Permit;
impl Permit {
    fn acquire() -> Result<Self, Win32Error> {
        reap();
        loop {
            let value = IN_FLIGHT.load(Ordering::Acquire);
            if value >= MAX_PENDING {
                return Err(Win32Error::Unsupported(
                    "pipe cancellation quarantine capacity reached",
                ));
            }
            if IN_FLIGHT
                .compare_exchange(value, value + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(Self);
            }
        }
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        IN_FLIGHT.fetch_sub(1, Ordering::AcqRel);
    }
}

struct PendingIo {
    kind: KindTag,
    handle: Option<OwnedHandle>,
    event: Option<OwnedHandle>,
    overlapped: Option<Box<OVERLAPPED>>,
    buffer: Option<Vec<u8>>,
    permit: Option<Permit>,
    pending: bool,
}
// SAFETY: the sole Rust owner moves under a Mutex only after issuance. The
// Box allocation and buffer address stay stable while Windows may complete
// the request. Rust reads OVERLAPPED only after GetOverlappedResult completes.
unsafe impl Send for PendingIo {}
impl PendingIo {
    fn new(handle: OwnedHandle, kind: IoKind) -> Result<Self, Win32Error> {
        let permit = Permit::acquire()?;
        // SAFETY: an unnamed manual-reset event is private to this request.
        let event = OwnedHandle::new(unsafe { CreateEventW(null(), 1, 0, null()) })?;
        let mut overlapped = Box::new(OVERLAPPED::default());
        overlapped.hEvent = event.raw();
        let tag = match &kind {
            IoKind::Connect => KindTag::Connect,
            IoKind::Read(_) => KindTag::Read,
            IoKind::Write(_) => KindTag::Write,
        };
        let buffer = match kind {
            IoKind::Connect => Vec::new(),
            IoKind::Read(size) => vec![0; size],
            IoKind::Write(bytes) => bytes,
        };
        Ok(Self {
            kind: tag,
            handle: Some(handle),
            event: Some(event),
            overlapped: Some(overlapped),
            buffer: Some(buffer),
            permit: Some(permit),
            pending: false,
        })
    }
    fn handle(&self) -> &OwnedHandle {
        self.handle.as_ref().expect("owned pipe")
    }
    fn overlap(&mut self) -> *mut OVERLAPPED {
        &mut **self.overlapped.as_mut().expect("overlap")
    }
    fn event(&self) -> &OwnedHandle {
        self.event.as_ref().expect("event")
    }
    fn poll(&mut self) -> Poll {
        let mut count = 0_u32;
        // SAFETY: handle, event, Box<OVERLAPPED>, and I/O buffer are still
        // owned here; FALSE never blocks and reports exact completion state.
        let okay = unsafe {
            GetOverlappedResult(
                self.handle().raw(),
                self.overlapped.as_ref().unwrap().as_ref(),
                &mut count,
                0,
            )
        };
        if okay != 0 {
            self.pending = false;
            return Poll::Done(count as usize);
        }
        // SAFETY: capture last error before any other Win32 operation.
        let code = unsafe { GetLastError() };
        if code == ERROR_IO_INCOMPLETE {
            Poll::Pending
        } else {
            self.pending = false;
            if code == ERROR_OPERATION_ABORTED {
                Poll::Canceled
            } else {
                Poll::Failed(code)
            }
        }
    }
    fn finish(mut self, count: usize) -> (OwnedHandle, Vec<u8>, usize) {
        self.pending = false;
        (
            self.handle.take().unwrap(),
            self.buffer.take().unwrap(),
            count,
        )
    }
}
impl Drop for PendingIo {
    fn drop(&mut self) {
        if self.pending {
            // A panic must not free memory that the kernel may still write.
            // The normal timeout path moves this whole value to QUARANTINE.
            if let Some(value) = self.handle.take() {
                std::mem::forget(value);
            }
            if let Some(value) = self.event.take() {
                std::mem::forget(value);
            }
            if let Some(value) = self.overlapped.take() {
                std::mem::forget(value);
            }
            if let Some(value) = self.buffer.take() {
                std::mem::forget(value);
            }
            if let Some(value) = self.permit.take() {
                std::mem::forget(value);
            }
        }
    }
}
enum Poll {
    Pending,
    Done(usize),
    Canceled,
    Failed(u32),
}

/// On success returns the same owned pipe plus bytes transferred. On an
/// unobserved cancellation the entire operation is quarantined; no worker
/// thread is left blocked and no dangling OVERLAPPED pointer is freed.
pub(crate) fn operate(
    handle: OwnedHandle,
    kind: IoKind,
    deadline: Instant,
) -> Result<(OwnedHandle, Vec<u8>, usize), Win32Error> {
    if Instant::now() >= deadline {
        return Err(Win32Error::Uncertain("pipe deadline elapsed before I/O"));
    }
    let mut op = PendingIo::new(handle, kind)?;
    let mut immediate = 0_u32;
    let (okay, start_error) = match op.kind {
        KindTag::Connect => {
            // SAFETY: pipe and stable OVERLAPPED are owned for the full request.
            let handle = op.handle().raw();
            let overlap = op.overlap();
            let okay = unsafe { ConnectNamedPipe(handle, overlap) };
            let code = if okay == 0 {
                unsafe { GetLastError() }
            } else {
                0
            };
            (okay, code)
        }
        KindTag::Read | KindTag::Write => {
            let write = matches!(op.kind, KindTag::Write);
            let pointer = op.buffer.as_mut().unwrap().as_mut_ptr();
            let len = op.buffer.as_ref().unwrap().len() as u32;
            let handle = op.handle().raw();
            let overlap = op.overlap();
            // SAFETY: buffer and OVERLAPPED allocations remain owned by op
            // until completion is observed or op is quarantined.
            let okay = unsafe {
                if write {
                    WriteFile(handle, pointer, len, &mut immediate, overlap)
                } else {
                    ReadFile(handle, pointer, len, &mut immediate, overlap)
                }
            };
            let code = if okay == 0 {
                unsafe { GetLastError() }
            } else {
                0
            };
            (okay, code)
        }
    };
    if okay != 0 || (matches!(op.kind, KindTag::Connect) && start_error == ERROR_PIPE_CONNECTED) {
        return completed_before_deadline(op, immediate as usize, deadline);
    }
    if start_error != ERROR_IO_PENDING {
        return Err(failed_before_pending(op.kind, start_error));
    }
    op.pending = true;
    let remaining = deadline.saturating_duration_since(Instant::now());
    let millis = remaining.as_millis().min(u32::MAX as u128) as u32;
    // SAFETY: event remains owned and referenced by this pending OVERLAPPED.
    let wait = unsafe { WaitForSingleObject(op.event().raw(), millis) };
    if wait == WAIT_OBJECT_0 {
        match op.poll() {
            Poll::Done(count) => return completed_before_deadline(op, count, deadline),
            Poll::Canceled => {
                return Err(Win32Error::Uncertain("pipe I/O canceled before completion"));
            }
            Poll::Failed(code) => return Err(failed_before_pending(op.kind, code)),
            Poll::Pending => {}
        }
    }
    // Deadline or anomalous wait: request targeted cancellation, then inspect
    // completion. CancelIoEx success is not completion evidence.
    // SAFETY: pointer is to the same stable OVERLAPPED used for issuance.
    let handle = op.handle().raw();
    let overlap = op.overlap();
    unsafe {
        CancelIoEx(handle, overlap);
    }
    // SAFETY: event and request allocations stay alive during the grace wait.
    unsafe {
        WaitForSingleObject(op.event().raw(), CANCEL_GRACE_MS);
    }
    let classified = match op.poll() {
        Poll::Done(_) => TimeoutCompletion::CompletedAfterDeadline,
        Poll::Failed(_) => TimeoutCompletion::FailedAfterDeadline,
        Poll::Canceled => TimeoutCompletion::Canceled,
        Poll::Pending => TimeoutCompletion::PendingQuarantined,
    };
    debug_assert!(!classified.dispatch_allowed());
    if classified == TimeoutCompletion::PendingQuarantined {
        quarantine(op);
    }
    Err(Win32Error::Uncertain(
        if wait == WAIT_OBJECT_0 || wait == windows_sys::Win32::Foundation::WAIT_TIMEOUT {
            classified.diagnostic()
        } else {
            "pipe wait failed; cancellation outcome uncertain"
        },
    ))
}

fn completed_before_deadline(
    op: PendingIo,
    count: usize,
    deadline: Instant,
) -> Result<(OwnedHandle, Vec<u8>, usize), Win32Error> {
    // Completion is attested, so all kernel-owned allocations can be freed
    // even when the caller's deadline has elapsed. A late completion may
    // already have affected the peer and must never authorize dispatch.
    let result = op.finish(count);
    confirmed_completion_before_deadline(Instant::now() >= deadline)
        .map_err(|status| Win32Error::Uncertain(status.diagnostic()))?;
    Ok(result)
}

fn failed_before_pending(kind: KindTag, code: u32) -> Win32Error {
    if matches!(kind, KindTag::Write) {
        Win32Error::Uncertain("pipe write may have partially affected peer")
    } else {
        Win32Error::Os(io::Error::from_raw_os_error(code as i32))
    }
}

fn quarantine(op: PendingIo) {
    QUARANTINE
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(op);
}
fn reap() {
    if let Some(list) = QUARANTINE.get() {
        list.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain_mut(|op| matches!(op.poll(), Poll::Pending));
    }
}
