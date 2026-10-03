//! Win32 calls are confined here. No manager owns the pod's child Job handle.
use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, FILETIME, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetCurrentProcessId, GetProcessTimes,
    OpenProcess, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    ResumeThread, STARTUPINFOEXW, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};

use crate::{PossibleProcess, ProcessIdentity, ResumeFence, Win32Error};

pub(super) struct OwnedHandle(HANDLE);
// SAFETY: OwnedHandle uniquely owns a real kernel HANDLE. Moving that sole
// owner to a worker thread does not invalidate the handle; the worker closes
// it exactly once on Drop. We deliberately do not implement Sync.
unsafe impl Send for OwnedHandle {}
impl OwnedHandle {
    pub(super) fn new(raw: HANDLE) -> Result<Self, Win32Error> {
        if raw.is_null() {
            Err(Win32Error::Os(io::Error::last_os_error()))
        } else {
            Ok(Self(raw))
        }
    }
    pub(super) fn raw(&self) -> HANDLE {
        self.0
    }
}
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper is the sole owner of a non-null real handle;
        // pseudo handles are never placed in OwnedHandle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

pub struct SuspendedProcess {
    process: Option<OwnedHandle>,
    thread: Option<OwnedHandle>,
    identity: ProcessIdentity,
    fence: ResumeFence,
    resumed: bool,
    terminated: bool,
}
impl SuspendedProcess {
    pub fn identity(&self) -> ProcessIdentity {
        self.identity
    }

    /// Only an independently contained pod may start executing user code.
    pub fn resume_independent(mut self) -> Result<RunningProcess, Win32Error> {
        self.resume(ResumeFence::IndependentPod)
    }
    fn resume(&mut self, expected: ResumeFence) -> Result<RunningProcess, Win32Error> {
        self.fence.permits(expected)?;
        let thread = self
            .thread
            .as_ref()
            .ok_or(Win32Error::UncertainAfterCreate {
                message: "thread handle absent",
                process: self.possible_identity(),
            })?;
        // SAFETY: thread is a live owned primary-thread handle from CreateProcessW.
        let prior = unsafe { ResumeThread(thread.raw()) };
        if prior != 1 {
            return Err(Win32Error::UncertainAfterCreate {
                message: "suspended thread did not resume exactly once",
                process: self.possible_identity(),
            });
        }
        self.resumed = true;
        self.thread.take(); // close primary-thread handle; process remains alive.
        Ok(RunningProcess {
            process: self.process.take().expect("owned process"),
            identity: self.identity,
        })
    }
    fn possible_identity(&self) -> PossibleProcess {
        PossibleProcess {
            pid: self.identity.pid,
            creation_100ns: (self.identity.creation_100ns != 0)
                .then_some(self.identity.creation_100ns),
        }
    }
    fn abort_suspended(&mut self) -> Result<(), Win32Error> {
        let process = self
            .process
            .as_ref()
            .ok_or(Win32Error::UncertainAfterCreate {
                message: "process handle absent after creation",
                process: self.possible_identity(),
            })?;
        // SAFETY: the owned process handle stays live throughout both waits.
        if unsafe { WaitForSingleObject(process.raw(), 0) } == WAIT_OBJECT_0 {
            self.terminated = true;
            return Ok(());
        }
        // SAFETY: the primary thread has not been resumed by this facade.
        if unsafe { TerminateProcess(process.raw(), 2) } == 0 {
            return Err(Win32Error::UncertainAfterCreate {
                message: "suspended process termination failed",
                process: self.possible_identity(),
            });
        }
        // SAFETY: wait pins the same owned process handle after termination.
        if unsafe { WaitForSingleObject(process.raw(), 5_000) } != WAIT_OBJECT_0 {
            return Err(Win32Error::UncertainAfterCreate {
                message: "suspended process exit not observed",
                process: self.possible_identity(),
            });
        }
        self.terminated = true;
        Ok(())
    }
}
impl Drop for SuspendedProcess {
    fn drop(&mut self) {
        if !self.resumed && !self.terminated {
            let _ = self.abort_suspended();
        }
    }
}

pub struct RunningProcess {
    process: OwnedHandle,
    identity: ProcessIdentity,
}
impl RunningProcess {
    pub fn identity(&self) -> ProcessIdentity {
        self.identity
    }
    pub fn has_exited(&self) -> Result<bool, Win32Error> {
        // SAFETY: process is an owned live handle; zero timeout only observes.
        match unsafe { WaitForSingleObject(self.process.raw(), 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(Win32Error::Os(io::Error::last_os_error())),
        }
    }
}

pub struct PodJob {
    job: OwnedHandle,
    owner: ProcessIdentity,
}
impl PodJob {
    /// This constructor must run inside the recorded pod, never the manager.
    pub fn new_in_pod(expected_pod: ProcessIdentity) -> Result<Self, Win32Error> {
        // SAFETY: these pseudo-handle/ID queries do not transfer ownership.
        let current_pid = unsafe { GetCurrentProcessId() };
        let current = identity_of(unsafe { GetCurrentProcess() }, current_pid)?;
        if current != expected_pod {
            return Err(Win32Error::Unsupported(
                "Job Object owner is not the attested pod",
            ));
        }
        // SAFETY: null security attributes and name create an unnamed job;
        // the returned handle is owned only by this pod process.
        let job = OwnedHandle::new(unsafe { CreateJobObjectW(null(), null()) })?;
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: limits is initialized and lives through the call; size matches
        // the requested JobObjectExtendedLimitInformation class.
        let set = unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if set == 0 {
            return Err(Win32Error::Os(io::Error::last_os_error()));
        }
        Ok(Self {
            job,
            owner: expected_pod,
        })
    }

    pub fn owner(&self) -> ProcessIdentity {
        self.owner
    }

    /// Create suspended, assign to the pod-owned job, verify, then resume.
    pub fn spawn_child(
        &self,
        application: &Path,
        exact_command_line: &OsStr,
        cwd: &Path,
    ) -> Result<RunningProcess, Win32Error> {
        self.spawn_child_with_startup(application, exact_command_line, cwd, None)
    }

    pub(super) fn spawn_child_with_startup(
        &self,
        application: &Path,
        exact_command_line: &OsStr,
        cwd: &Path,
        startup: Option<&STARTUPINFOEXW>,
    ) -> Result<RunningProcess, Win32Error> {
        let mut child = create_suspended_with_startup(
            application,
            exact_command_line,
            cwd,
            CREATE_SUSPENDED,
            startup,
        )?;
        // SAFETY: both handles are live and owned; child is still suspended.
        let assigned = unsafe {
            AssignProcessToJobObject(self.job.raw(), child.process.as_ref().unwrap().raw())
        };
        if assigned == 0 {
            child.abort_suspended()?;
            return Err(Win32Error::Unsupported("child Job assignment refused"));
        }
        if !matches!(
            in_job(child.process.as_ref().unwrap().raw(), self.job.raw()),
            Ok(true)
        ) {
            child.abort_suspended()?;
            return Err(Win32Error::Uncertain(
                "child Job membership could not be attested",
            ));
        }
        child.fence = ResumeFence::AssignedChild;
        child.resume(ResumeFence::AssignedChild)
    }
}
// PodJob does not expose or duplicate its handle. Dropping it closes the last
// handle held by the pod and invokes KILL_ON_JOB_CLOSE for contained children.

/// Manager-side admission. The caller must have persisted the exact PodBay
/// command/manifest claim before this call; a possible launch is never retried.
pub fn launch_independent_suspended(
    application: &Path,
    exact_command_line: &OsStr,
    cwd: &Path,
) -> Result<SuspendedProcess, Win32Error> {
    // SAFETY: GetCurrentProcess is a borrowed pseudo handle, never closed here.
    let manager_in_job = in_job(unsafe { GetCurrentProcess() }, null_mut())?;
    let mut pod = match create_suspended(
        application,
        exact_command_line,
        cwd,
        CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB,
    ) {
        Ok(value) => value,
        Err(Win32Error::Os(error))
            if manager_in_job && error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) =>
        {
            return Err(Win32Error::Unsupported("manager Job denied pod breakaway"));
        }
        Err(error) => return Err(error),
    };
    match in_job(pod.process.as_ref().unwrap().raw(), null_mut()) {
        Ok(false) => {}
        Ok(true) => {
            pod.abort_suspended()?;
            return Err(Win32Error::Unsupported("pod remains in a parent Job"));
        }
        Err(_) => {
            pod.abort_suspended()?;
            return Err(Win32Error::UncertainAfterCreate {
                message: "pod Job independence could not be attested",
                process: pod.possible_identity(),
            });
        }
    }
    pod.fence = ResumeFence::IndependentPod;
    Ok(pod)
}

/// A PID alone never authorizes reattachment. The caller must additionally
/// authenticate the PodBay manifest, pipe principal, and incarnation.
pub fn open_exact_process(expected: ProcessIdentity) -> Result<RunningProcess, Win32Error> {
    if expected.pid == 0 || expected.creation_100ns == 0 {
        return Err(Win32Error::Invalid("process identity is incomplete"));
    }
    // SAFETY: OpenProcess returns an owned real handle, never a pseudo handle.
    let handle = OwnedHandle::new(unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            expected.pid,
        )
    })?;
    let actual = identity_of(handle.raw(), expected.pid)?;
    if actual != expected {
        return Err(Win32Error::Unsupported("process PID was reused"));
    }
    Ok(RunningProcess {
        process: handle,
        identity: actual,
    })
}

fn create_suspended(
    application: &Path,
    command_line: &OsStr,
    cwd: &Path,
    flags: u32,
) -> Result<SuspendedProcess, Win32Error> {
    create_suspended_with_startup(application, command_line, cwd, flags, None)
}

fn create_suspended_with_startup(
    application: &Path,
    command_line: &OsStr,
    cwd: &Path,
    flags: u32,
    extended: Option<&STARTUPINFOEXW>,
) -> Result<SuspendedProcess, Win32Error> {
    if !application.is_absolute() || !cwd.is_absolute() {
        return Err(Win32Error::Invalid("application and cwd must be absolute"));
    }
    let app = wide(application.as_os_str())?;
    let cwd = wide(cwd.as_os_str())?;
    let mut command = wide(command_line)?;
    if command.len() <= 1 {
        return Err(Win32Error::Invalid("command line is empty"));
    }
    let mut startup = STARTUPINFOW::default();
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let startup_ptr = extended.map_or(&startup as *const STARTUPINFOW, |value| {
        &value.StartupInfo as *const STARTUPINFOW
    });
    let extended_flag = if extended.is_some() {
        EXTENDED_STARTUPINFO_PRESENT
    } else {
        0
    };
    let mut info = PROCESS_INFORMATION::default();
    // PB27a never inherits the manager's ambient credentials. A later PodBay
    // environment policy can supply an explicit, reviewed Unicode block.
    let empty_environment = [0_u16, 0_u16];
    // SAFETY: pointers refer to owned NUL-terminated buffers through the call;
    // no handles are inherited, and CREATE_SUSPENDED prevents user code before
    // the caller proves independence or child Job membership.
    let created = unsafe {
        CreateProcessW(
            app.as_ptr(),
            command.as_mut_ptr(),
            null(),
            null(),
            0,
            flags | CREATE_UNICODE_ENVIRONMENT | extended_flag,
            empty_environment.as_ptr().cast(),
            cwd.as_ptr(),
            startup_ptr,
            &mut info,
        )
    };
    if created == 0 {
        return Err(Win32Error::Os(io::Error::last_os_error()));
    }
    // Every returned handle is immediately wrapped. A successful CreateProcess
    // must supply both; any anomaly is an uncertain post-creation outcome.
    let process = OwnedHandle::new(info.hProcess).map_err(|_| {
        if !info.hThread.is_null() {
            // SAFETY: CreateProcessW returned this thread handle, and no wrapper owns it.
            unsafe {
                CloseHandle(info.hThread);
            }
        }
        Win32Error::UncertainAfterCreate {
            message: "CreateProcess returned no process handle",
            process: PossibleProcess {
                pid: info.dwProcessId,
                creation_100ns: None,
            },
        }
    })?;
    let mut suspended = SuspendedProcess {
        process: Some(process),
        thread: None,
        identity: ProcessIdentity {
            pid: info.dwProcessId,
            creation_100ns: 0,
        },
        fence: ResumeFence::Unverified,
        resumed: false,
        terminated: false,
    };
    suspended.thread = match OwnedHandle::new(info.hThread) {
        Ok(thread) => Some(thread),
        Err(_) => {
            suspended.abort_suspended()?;
            return Err(Win32Error::UncertainAfterCreate {
                message: "CreateProcess returned no primary thread handle",
                process: suspended.possible_identity(),
            });
        }
    };
    suspended.identity =
        match identity_of(suspended.process.as_ref().unwrap().raw(), info.dwProcessId) {
            Ok(identity) => identity,
            Err(_) => {
                suspended.abort_suspended()?;
                return Err(Win32Error::UncertainAfterCreate {
                    message: "birth identity failed after process creation",
                    process: suspended.possible_identity(),
                });
            }
        };
    Ok(suspended)
}

fn in_job(process: HANDLE, job: HANDLE) -> Result<bool, Win32Error> {
    let mut result = 0;
    // SAFETY: process and optional job are valid handles for the call; result
    // is a writable BOOL initialized by IsProcessInJob on success.
    let okay = unsafe { IsProcessInJob(process, job, &mut result) };
    if okay == 0 {
        Err(Win32Error::Os(io::Error::last_os_error()))
    } else {
        Ok(result != 0)
    }
}

fn identity_of(process: HANDLE, pid: u32) -> Result<ProcessIdentity, Win32Error> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: four initialized FILETIME outputs live through GetProcessTimes.
    let okay =
        unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) };
    if okay == 0 {
        return Err(Win32Error::Os(io::Error::last_os_error()));
    }
    let value = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    if pid == 0 || value == 0 {
        return Err(Win32Error::Invalid("process birth identity absent"));
    }
    Ok(ProcessIdentity {
        pid,
        creation_100ns: value,
    })
}

fn wide(value: &OsStr) -> Result<Vec<u16>, Win32Error> {
    let mut result = value.encode_wide().collect::<Vec<_>>();
    if result.contains(&0) {
        return Err(Win32Error::Invalid("embedded NUL"));
    }
    result.push(0);
    Ok(result)
}

#[cfg(test)]
mod compile_tests {
    use super::*;
    #[test]
    fn windows_handle_ownership_api_compiles() {
        let _launch: fn(&Path, &OsStr, &Path) -> Result<SuspendedProcess, Win32Error> =
            launch_independent_suspended;
        let _reattach: fn(ProcessIdentity) -> Result<RunningProcess, Win32Error> =
            open_exact_process;
        let _job: fn(ProcessIdentity) -> Result<PodJob, Win32Error> = PodJob::new_in_pod;
    }
}
