//! Private pre-source lifetime boundary, compiled outside cfg(test).
//! Requests are inert caller input. Nothing here observes or establishes CLOSED.
//! There is no OS launcher implementation and no successful acquisition value.

use core::convert::Infallible;

const MAX_BOUNDARY_PATH_BYTES: usize = 4096;

/// An intended boundary location, not an observed directory or store identity.
/// Historical bytes are borrowed only so they can be explicitly refused;
/// neither their contents nor an asserted record state can establish custody.
pub(super) struct BootstrapRequest<'a> {
    pub(super) boundary_path: &'a str,
    pub(super) historical_checkpoint: Option<&'a [u8]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BootstrapRefusal {
    UnsupportedTarget,
    MalformedRequest,
    HistoricalInputCannotAcquire,
    LauncherEnforcementUnavailable,
}

/// Diagnostic categories for a deferred I/O boundary, not available effects or
/// evidence. The current acquisition path never invokes the borrowed observer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DeferredIo {
    OpenSource,
    ReadCheckpoint,
    AcquireManagerLock,
    CreateStateDirectory,
    ContactCustodian,
    LaunchCustodian,
}

/// Owns one attempted lifetime of borrowed input, with a sticky first refusal.
/// Construction performs no inspection and confers no authority. This type has
/// no Clone, serialization, Drop callback, handle export, admit or release API.
pub(super) struct PreSourceAttempt<'a> {
    request: BootstrapRequest<'a>,
    refused: Option<BootstrapRefusal>,
}

impl<'a> PreSourceAttempt<'a> {
    pub(super) fn new(request: BootstrapRequest<'a>) -> Self {
        Self {
            request,
            refused: None,
        }
    }

    /// Always refuses before any deferred source/checkpoint/lock/launcher I/O.
    /// `Infallible` makes a successful value unconstructible in safe Rust; no
    /// caller assertion or test-only origin handle supplies a missing witness.
    /// The observer is borrowed, so refusal cannot run a caller-owned Drop.
    pub(super) fn acquire(
        &mut self,
        _deferred_io: &mut dyn FnMut(DeferredIo),
    ) -> Result<Infallible, BootstrapRefusal> {
        let reason = if let Some(refused) = self.refused {
            refused
        } else if !cfg!(target_os = "linux") {
            BootstrapRefusal::UnsupportedTarget
        } else if !valid_boundary_path(self.request.boundary_path) {
            BootstrapRefusal::MalformedRequest
        } else if self.request.historical_checkpoint.is_some() {
            // Do not decode, hash, copy or inspect historical bytes here.
            BootstrapRefusal::HistoricalInputCannotAcquire
        } else {
            // PID/UID, current/old boot, digest and CLOSED/NeverStarted flags
            // are deliberately not request fields or substitutes for a launcher.
            BootstrapRefusal::LauncherEnforcementUnavailable
        };
        self.refused = Some(reason);
        Err(reason)
    }
}

fn valid_boundary_path(path: &str) -> bool {
    path.len() > 1
        && path.len() <= MAX_BOUNDARY_PATH_BYTES
        && path.starts_with('/')
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && path[1..]
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

#[cfg(test)]
mod tests;
