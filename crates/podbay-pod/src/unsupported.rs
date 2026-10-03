//! No native pod backend is admitted on this target yet.
use std::path::Path;

use crate::manifest::{LaunchDescriptor, PodError};
use crate::ports::{
    DurableFiles, LocalControlTransport, PodControlPort, PodObservation, SupervisorBackend,
    TerminalBackend, TerminalResource, TerminalViewerPort,
};
use crate::terminal_protocol::{TerminalCommand, TerminalEventPage, TerminalReply, TerminalView};

const MISSING: &str = "native pod supervision, local control, terminal, and durable files are not implemented on this platform";

pub struct PodClient {
    _private: (),
}
pub struct TerminalViewer {
    _private: (),
}
pub struct UnsupportedBackend;

impl PodClient {
    pub fn connect(_path: impl AsRef<Path>) -> Result<Self, PodError> {
        Err(PodError::Unsupported(MISSING))
    }
    pub fn manifest_path(&self) -> Result<&Path, PodError> {
        Err(PodError::Unsupported(MISSING))
    }
    pub fn status(&self) -> Result<PodObservation, PodError> {
        Err(PodError::Unsupported(MISSING))
    }
    pub fn stop(&self) -> Result<PodObservation, PodError> {
        Err(PodError::Unsupported(MISSING))
    }
    pub fn viewer(&self) -> Result<TerminalViewer, PodError> {
        Err(PodError::Unsupported(MISSING))
    }
    pub fn terminal_control(&self, _command: TerminalCommand) -> Result<TerminalReply, PodError> {
        Err(PodError::Unsupported(MISSING))
    }
}
impl TerminalViewer {
    pub fn attach(&self) -> Result<TerminalView, PodError> {
        Err(PodError::Unsupported(MISSING))
    }
    pub fn events_after(&self, _after: u64, _limit: usize) -> Result<TerminalEventPage, PodError> {
        Err(PodError::Unsupported(MISSING))
    }
}
impl TerminalViewerPort for TerminalViewer {
    fn attach(&self) -> Result<TerminalView, PodError> {
        Self::attach(self)
    }
    fn events_after(&self, after: u64, limit: usize) -> Result<TerminalEventPage, PodError> {
        Self::events_after(self, after, limit)
    }
}
impl PodControlPort for PodClient {
    fn status(&self) -> Result<PodObservation, PodError> {
        Self::status(self)
    }
    fn stop(&self) -> Result<PodObservation, PodError> {
        Self::stop(self)
    }
    fn terminal_control(&self, command: TerminalCommand) -> Result<TerminalReply, PodError> {
        Self::terminal_control(self, command)
    }
    fn viewer(&self) -> Result<Box<dyn TerminalViewerPort>, PodError> {
        Err(PodError::Unsupported(MISSING))
    }
}
impl SupervisorBackend for UnsupportedBackend {
    fn launch(
        &self,
        _descriptor: LaunchDescriptor,
        _private_directory: &Path,
        _pod_binary: &Path,
    ) -> Result<Box<dyn PodControlPort>, PodError> {
        Err(PodError::Unsupported(MISSING))
    }
    fn connect(&self, _manifest_path: &Path) -> Result<Box<dyn PodControlPort>, PodError> {
        Err(PodError::Unsupported(MISSING))
    }
}
impl TerminalBackend for UnsupportedBackend {
    fn spawn(
        &self,
        _: &LaunchDescriptor,
        _: crate::manifest::PtySpec,
        _: &Path,
    ) -> Result<Box<dyn TerminalResource>, PodError> {
        Err(PodError::Unsupported(MISSING))
    }
}
impl LocalControlTransport for UnsupportedBackend {
    fn exchange(&self, _: &Path, _: &[u8]) -> Result<Vec<u8>, PodError> {
        Err(PodError::Unsupported(MISSING))
    }
}
impl DurableFiles for UnsupportedBackend {
    fn create_private(&self, _: &Path, _: &[u8]) -> Result<(), PodError> {
        Err(PodError::Unsupported(MISSING))
    }
    fn append_durable(&self, _: &Path, _: &[u8]) -> Result<(), PodError> {
        Err(PodError::Unsupported(MISSING))
    }
    fn replace_durable(&self, _: &Path, _: &[u8]) -> Result<(), PodError> {
        Err(PodError::Unsupported(MISSING))
    }
}
pub fn launch(
    _descriptor: LaunchDescriptor,
    _directory: impl AsRef<Path>,
    _pod_binary: impl AsRef<Path>,
) -> Result<PodClient, PodError> {
    Err(PodError::Unsupported(MISSING))
}
pub fn serve(_manifest_path: impl AsRef<Path>) -> Result<(), PodError> {
    Err(PodError::Unsupported(MISSING))
}
