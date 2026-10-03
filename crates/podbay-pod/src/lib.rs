//! PB05 Linux pod process boundary. No provider turns or PTY semantics are inferred here.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod linux_peer;
mod manifest;
mod peer_checkpoint;
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

#[cfg(target_os = "linux")]
pub use linux_peer::{LinuxPeerError, LinuxPeerEvidence};
pub use manifest::{LaunchDescriptor, PodError, PodRole, PtySpec, manifest_path};
#[cfg(target_os = "linux")]
pub use manifest::{PodManifest, PodStatus};
pub use peer_checkpoint::{PeerCheckpointError, decode_peer_checkpoint, encode_peer_checkpoint};
#[cfg(target_os = "linux")]
pub use peer_checkpoint::{read_peer_checkpoint, write_peer_checkpoint};
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
