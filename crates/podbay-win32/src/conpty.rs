//! PB27b ConPTY transport. Raw bytes are transport evidence, not TUI success.
use std::ffi::{OsStr, c_void};
use std::io;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, GetLastError, HANDLE, HMODULE,
};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::Console::{COORD, HPCON};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, STARTUPINFOEXW, UpdateProcThreadAttribute,
};

use crate::Win32Error;
use crate::conpty_model::{OutputPage, OutputState, geometry, validate_timeout};
use crate::windows::{OwnedHandle, PodJob, RunningProcess};

type CreateFn = unsafe extern "system" fn(COORD, HANDLE, HANDLE, u32, *mut HPCON) -> i32;
type ResizeFn = unsafe extern "system" fn(HPCON, COORD) -> i32;
type CloseFn = unsafe extern "system" fn(HPCON);

#[derive(Clone, Copy)]
struct ConPtyApi {
    create: CreateFn,
    resize: ResizeFn,
    close: CloseFn,
}
impl ConPtyApi {
    fn load() -> Result<Self, Win32Error> {
        let kernel = "kernel32.dll\0".encode_utf16().collect::<Vec<_>>();
        // SAFETY: GetModuleHandleW borrows a loaded system DLL; no ownership is transferred.
        let module: HMODULE = unsafe { GetModuleHandleW(kernel.as_ptr()) };
        if module.is_null() {
            return Err(Win32Error::Unsupported("kernel32 is unavailable"));
        }
        let create = symbol(module, b"CreatePseudoConsole\0")?;
        let resize = symbol(module, b"ResizePseudoConsole\0")?;
        let close = symbol(module, b"ClosePseudoConsole\0")?;
        // SAFETY: each checked symbol is a kernel32 export with the exact
        // documented WINAPI signature above. No DLL can be substituted here.
        Ok(Self {
            create: unsafe { std::mem::transmute(create) },
            resize: unsafe { std::mem::transmute(resize) },
            close: unsafe { std::mem::transmute(close) },
        })
    }
}
fn symbol(
    module: HMODULE,
    name: &[u8],
) -> Result<unsafe extern "system" fn() -> isize, Win32Error> {
    // SAFETY: name is a constant NUL-terminated ASCII export name and module
    // is the already-loaded kernel32 handle.
    unsafe { GetProcAddress(module, name.as_ptr()) }
        .ok_or(Win32Error::Unsupported("ConPTY API is unavailable"))
}

struct PseudoConsole {
    api: ConPtyApi,
    handle: HPCON,
}
impl Drop for PseudoConsole {
    fn drop(&mut self) {
        let api = self.api;
        let handle = self.handle;
        // The output reader is independent, so closing cannot block the caller.
        let closing = std::thread::Builder::new()
            .name("podbay-conpty-close".into())
            .spawn(move || {
                // SAFETY: this thread takes the sole ConPTY close responsibility.
                unsafe {
                    (api.close)(handle);
                }
            });
        if closing.is_err() {
            // No worker was created. Closing here may block, but cannot leak
            // the sole HPCON; normal operation always has a separate reader.
            unsafe {
                (api.close)(handle);
            }
        }
    }
}

enum ControlRequest {
    Resize {
        rows: u16,
        cols: u16,
        reply: mpsc::Sender<Result<(), Win32Error>>,
    },
    Close {
        reply: mpsc::Sender<()>,
    },
}
struct WriteRequest {
    bytes: Vec<u8>,
    reply: mpsc::Sender<Result<(), Win32Error>>,
}

pub struct ConPtyProcess {
    child: RunningProcess,
    input: mpsc::SyncSender<WriteRequest>,
    control: mpsc::SyncSender<ControlRequest>,
    output: Arc<Mutex<OutputState>>,
    input_unknown: bool,
    control_unknown: bool,
    closed: bool,
}
impl ConPtyProcess {
    pub fn identity(&self) -> crate::ProcessIdentity {
        self.child.identity()
    }
    pub fn child_exited(&self) -> Result<bool, Win32Error> {
        self.child.has_exited()
    }
    pub fn output_after(&self, after: u64, limit: usize) -> Result<OutputPage, Win32Error> {
        self.output
            .lock()
            .map_err(|_| Win32Error::Uncertain("output state poisoned"))?
            .page(after, limit)
    }
    /// This proves only that bytes reached the ConPTY input pipe. The caller
    /// must have durably recorded a PodBay command Intent before invoking it.
    pub fn write_input(&mut self, bytes: &[u8], timeout: Duration) -> Result<(), Win32Error> {
        if self.closed {
            return Err(Win32Error::Unsupported("ConPTY close was requested"));
        }
        if self.input_unknown {
            return Err(Win32Error::Uncertain("prior input outcome unknown"));
        }
        if bytes.is_empty() || bytes.len() > 4_096 {
            return Err(Win32Error::Invalid("ConPTY input bound"));
        }
        validate_timeout(timeout)?;
        let (reply, answer) = mpsc::channel();
        if self
            .input
            .try_send(WriteRequest {
                bytes: bytes.to_vec(),
                reply,
            })
            .is_err()
        {
            self.input_unknown = true;
            return Err(Win32Error::Uncertain(
                "input writer unavailable after possible request",
            ));
        }
        match answer.recv_timeout(timeout) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                self.input_unknown = true;
                Err(error)
            }
            Err(_) => {
                self.input_unknown = true;
                Err(Win32Error::Uncertain(
                    "ConPTY input completion unknown; do not retry",
                ))
            }
        }
    }
    pub fn resize(&mut self, rows: u16, cols: u16, timeout: Duration) -> Result<(), Win32Error> {
        if self.closed {
            return Err(Win32Error::Unsupported("ConPTY close was requested"));
        }
        if self.control_unknown {
            return Err(Win32Error::Uncertain(
                "prior ConPTY control outcome unknown",
            ));
        }
        geometry(rows, cols)?;
        validate_timeout(timeout)?;
        let (reply, answer) = mpsc::channel();
        if self
            .control
            .try_send(ControlRequest::Resize { rows, cols, reply })
            .is_err()
        {
            self.control_unknown = true;
            return Err(Win32Error::Uncertain(
                "ConPTY control unavailable after possible request",
            ));
        }
        match answer.recv_timeout(timeout) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                self.control_unknown = true;
                Err(error)
            }
            Err(_) => {
                self.control_unknown = true;
                Err(Win32Error::Uncertain("ConPTY resize completion unknown"))
            }
        }
    }
    pub fn close(&mut self, timeout: Duration) -> Result<(), Win32Error> {
        validate_timeout(timeout)?;
        if self.closed {
            return Err(Win32Error::Uncertain("ConPTY close was already requested"));
        }
        self.closed = true;
        let (reply, answer) = mpsc::channel();
        self.control
            .try_send(ControlRequest::Close { reply })
            .map_err(|_| Win32Error::Uncertain("ConPTY close was not accepted"))?;
        // A reply means ClosePseudoConsole returned; it does not prove the
        // hosted child exited or that its application completed work.
        answer
            .recv_timeout(timeout)
            .map_err(|_| Win32Error::Uncertain("ConPTY close completion unknown"))?;
        Ok(())
    }
}

impl PodJob {
    /// Bind ConPTY before child creation; job assignment still precedes resume.
    pub fn spawn_conpty_child(
        &self,
        application: &Path,
        exact_command_line: &OsStr,
        cwd: &Path,
        rows: u16,
        cols: u16,
    ) -> Result<ConPtyProcess, Win32Error> {
        geometry(rows, cols)?;
        let api = ConPtyApi::load()?; // Unsupported before any pipe or child effect.
        let (input_read, input_write) = pipe()?;
        let (output_read, output_write) = pipe()?;
        let mut handle = 0_isize;
        // SAFETY: both valid pipe ends and writable HPCON output live through
        // this synchronous call; default flags avoid cursor-inherit handshake.
        let result = unsafe {
            (api.create)(
                coord(rows, cols),
                input_read.raw(),
                output_write.raw(),
                0,
                &mut handle,
            )
        };
        if result < 0 || handle == 0 {
            return Err(Win32Error::Unsupported("ConPTY creation unavailable"));
        }
        let console = PseudoConsole { api, handle };
        let output = Arc::new(Mutex::new(OutputState::new()));
        let feed = output.clone();
        std::thread::Builder::new()
            .name("podbay-conpty-output".into())
            .spawn(move || drain_output(output_read, feed))
            .map_err(|_| Win32Error::Uncertain("ConPTY output reader could not start"))?;
        let (control_tx, control_rx) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("podbay-conpty-control".into())
            .spawn(move || control_loop(console, control_rx))
            .map_err(|_| Win32Error::Uncertain("ConPTY control worker could not start"))?;
        let (input_tx, input_rx) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("podbay-conpty-input".into())
            .spawn(move || input_loop(input_write, input_rx))
            .map_err(|_| Win32Error::Uncertain("ConPTY input worker could not start"))?;
        let attrs = AttributeList::new(handle)?;
        let child = self.spawn_child_with_startup(
            application,
            exact_command_line,
            cwd,
            Some(&attrs.startup),
        )?;
        // Microsoft requires the host's duplicate ConPTY ends to close after
        // CreateProcess, so broken-channel detection works during teardown.
        drop(input_read);
        drop(output_write);
        Ok(ConPtyProcess {
            child,
            input: input_tx,
            control: control_tx,
            output,
            input_unknown: false,
            control_unknown: false,
            closed: false,
        })
    }
}

fn coord(rows: u16, cols: u16) -> COORD {
    COORD {
        X: cols as i16,
        Y: rows as i16,
    }
}

fn pipe() -> Result<(OwnedHandle, OwnedHandle), Win32Error> {
    let mut read = null_mut();
    let mut write = null_mut();
    // SAFETY: output pointers are writable; null attributes make pipe handles
    // non-inheritable and CreateProcessW independently sets inherit=false.
    if unsafe { CreatePipe(&mut read, &mut write, null(), 0) } == 0 {
        return Err(Win32Error::Os(io::Error::last_os_error()));
    }
    let read = OwnedHandle::new(read)?;
    let write = OwnedHandle::new(write)?;
    Ok((read, write))
}

struct AttributeList {
    _storage: Vec<usize>,
    startup: STARTUPINFOEXW,
}
impl AttributeList {
    fn new(console: HPCON) -> Result<Self, Win32Error> {
        let mut bytes = 0_usize;
        // SAFETY: null first call requests the required byte count only.
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut bytes);
        }
        if bytes == 0 || bytes > 1_048_576 {
            return Err(Win32Error::Unsupported("ConPTY attribute list unavailable"));
        }
        let mut storage = vec![0_usize; bytes.div_ceil(std::mem::size_of::<usize>())];
        let list = storage.as_mut_ptr().cast();
        // SAFETY: usize-aligned storage has at least `bytes` bytes and remains
        // owned by AttributeList until after CreateProcessW returns.
        if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut bytes) } == 0 {
            return Err(Win32Error::Os(io::Error::last_os_error()));
        }
        // SAFETY: Microsoft specifies lpValue as the HPCON handle value, not a
        // pointer to a temporary handle variable. List is initialized.
        let updated = unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                console as *const c_void,
                std::mem::size_of::<HPCON>(),
                null_mut(),
                null(),
            )
        };
        if updated == 0 {
            let error = io::Error::last_os_error();
            // SAFETY: initialized list must be released once on failure.
            unsafe {
                DeleteProcThreadAttributeList(list);
            }
            return Err(Win32Error::Os(error));
        }
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = list;
        Ok(Self {
            _storage: storage,
            startup,
        })
    }
}
impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: list was initialized exactly once and storage still lives.
        unsafe {
            DeleteProcThreadAttributeList(self.startup.lpAttributeList);
        }
    }
}

fn input_loop(handle: OwnedHandle, requests: mpsc::Receiver<WriteRequest>) {
    while let Ok(request) = requests.recv() {
        let mut written_total = 0_usize;
        let outcome = loop {
            let mut written = 0_u32;
            // SAFETY: owned pipe handle and input slice remain live during this
            // synchronous call; no OVERLAPPED I/O is requested.
            let okay = unsafe {
                WriteFile(
                    handle.raw(),
                    request.bytes[written_total..].as_ptr(),
                    (request.bytes.len() - written_total) as u32,
                    &mut written,
                    null_mut(),
                )
            };
            if okay == 0 || written == 0 {
                break Err(Win32Error::Uncertain(
                    "ConPTY input may have been partially written",
                ));
            }
            written_total += written as usize;
            if written_total == request.bytes.len() {
                break Ok(());
            }
        };
        let _ = request.reply.send(outcome);
    }
}
fn drain_output(handle: OwnedHandle, state: Arc<Mutex<OutputState>>) {
    let mut buffer = [0_u8; 4_096];
    loop {
        let mut read = 0_u32;
        // SAFETY: owned output pipe and writable buffer live through ReadFile.
        let okay = unsafe {
            ReadFile(
                handle.raw(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &mut read,
                null_mut(),
            )
        };
        if okay == 0 || read == 0 {
            if okay == 0 {
                // SAFETY: inspect the failure before another FFI call can
                // overwrite this thread's last-error value.
                let code = unsafe { GetLastError() };
                if code != ERROR_BROKEN_PIPE
                    && code != ERROR_HANDLE_EOF
                    && let Ok(mut state) = state.lock()
                {
                    state.mark_unknown();
                }
            }
            break;
        }
        if let Ok(mut state) = state.lock() {
            state.push(&buffer[..read as usize]);
        } else {
            break;
        }
    }
}
fn control_loop(console: PseudoConsole, requests: mpsc::Receiver<ControlRequest>) {
    while let Ok(request) = requests.recv() {
        match request {
            ControlRequest::Resize { rows, cols, reply } => {
                // SAFETY: control thread solely owns HPCON; geometry was bounded.
                let result = unsafe { (console.api.resize)(console.handle, coord(rows, cols)) };
                let _ = reply.send(if result < 0 {
                    Err(Win32Error::Uncertain("ConPTY resize outcome unknown"))
                } else {
                    Ok(())
                });
            }
            ControlRequest::Close { reply } => {
                // The output reader is independent and keeps draining while
                // this potentially blocking close runs. The caller waits only
                // for its bounded deadline; timeout remains uncertain.
                let console = std::mem::ManuallyDrop::new(console);
                // SAFETY: control thread owns the sole HPCON close call; the
                // ManuallyDrop guard prevents the fallback Drop closing twice.
                unsafe {
                    (console.api.close)(console.handle);
                }
                let _ = reply.send(());
                return;
            }
        }
    }
}

#[cfg(test)]
mod compile_tests {
    use super::*;
    #[test]
    fn job_bound_conpty_surface_compiles_for_windows() {
        let _spawn: fn(
            &PodJob,
            &Path,
            &OsStr,
            &Path,
            u16,
            u16,
        ) -> Result<ConPtyProcess, Win32Error> = PodJob::spawn_conpty_child;
        let _write: fn(&mut ConPtyProcess, &[u8], Duration) -> Result<(), Win32Error> =
            ConPtyProcess::write_input;
        let _resize: fn(&mut ConPtyProcess, u16, u16, Duration) -> Result<(), Win32Error> =
            ConPtyProcess::resize;
        let _close: fn(&mut ConPtyProcess, Duration) -> Result<(), Win32Error> =
            ConPtyProcess::close;
    }
}
