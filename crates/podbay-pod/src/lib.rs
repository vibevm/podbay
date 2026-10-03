//! PB05 Linux pod process boundary. No provider turns or PTY semantics are inferred here.
#![forbid(unsafe_code)]

mod manifest;
mod ports;
#[cfg(target_os = "linux")]
mod runtime;
#[cfg(target_os = "linux")]
mod spool;
#[cfg(target_os = "linux")]
mod terminal;
mod terminal_protocol;
#[cfg(not(target_os = "linux"))]
mod unsupported;

pub use manifest::{LaunchDescriptor, PodError, PodRole, PtySpec, manifest_path};
#[cfg(target_os = "linux")]
pub use manifest::{PodManifest, PodStatus};
pub use ports::{
    DurableFiles, LocalConnection, LocalControlTransport, PodControlPort, PodObservation,
    ProcessIdentity, SupervisorBackend, SupervisorEvidence, TerminalBackend, TerminalResource,
    TerminalViewerPort,
};
#[cfg(target_os = "linux")]
pub use runtime::{LinuxBackend, PodClient, TerminalViewer, launch, serve};
pub use terminal_protocol::{
    InputLease, LeaseKind, ScreenCheckpoint, ScreenFidelity, TerminalCommand, TerminalEvent,
    TerminalEventKind, TerminalEventPage, TerminalReply, TerminalView,
};
#[cfg(not(target_os = "linux"))]
pub use unsupported::{PodClient, TerminalViewer, UnsupportedBackend, launch, serve};
