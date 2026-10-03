//! PB05 Linux pod process boundary. No provider turns or PTY semantics are inferred here.
#![forbid(unsafe_code)]

mod manifest;
mod runtime;
mod spool;
mod terminal;

pub use manifest::{
    LaunchDescriptor, PodError, PodManifest, PodRole, PodStatus, PtySpec, manifest_path,
};
pub use runtime::{PodClient, TerminalViewer, launch, serve};
pub use terminal::{
    InputLease, LeaseKind, ScreenCheckpoint, ScreenFidelity, TerminalCommand, TerminalEvent,
    TerminalEventKind, TerminalEventPage, TerminalReply, TerminalView,
};
