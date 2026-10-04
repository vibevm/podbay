//! PB05 Linux pod process boundary. No provider turns or PTY semantics are inferred here.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod codex_bootstrap;
#[cfg(target_os = "linux")]
mod codex_credential;
mod codex_journal;
#[cfg(target_os = "linux")]
mod codex_launch;
#[cfg(target_os = "linux")]
mod codex_resource;
#[cfg(target_os = "linux")]
mod linux_peer;
mod manifest;
mod native_events;
mod peer_checkpoint;
mod ports;
#[cfg(all(target_os = "linux", test))]
mod rebind_protocol;
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
pub use codex_bootstrap::{
    BootstrapControlReceipt, BootstrapControlStage, BootstrapSettlementStage,
    CODEX_BOOTSTRAP_INSPECT_PROTOCOL, CODEX_BOOTSTRAP_PROTOCOL,
};
#[cfg(target_os = "linux")]
pub use codex_credential::{
    CODEX_AUTH_CREDENTIAL_NAME, PreparedCodexHome, codex_private_slot_directory,
    prepare_codex_home_from_systemd_credential,
};
pub use codex_journal::{
    CodexCommandJournal, CodexJournalIdentity, CodexJournalIntentResult, CodexJournalStage,
    CodexJournalView,
};
#[cfg(target_os = "linux")]
pub use codex_launch::launch_bound_codex_v2;
#[cfg(target_os = "linux")]
pub use codex_resource::{PodCodexResource, ValidatedCodexResourceLaunch};
#[cfg(target_os = "linux")]
pub use linux_peer::{LinuxPeerError, LinuxPeerEvidence};
#[cfg(target_os = "linux")]
pub use manifest::{
    BoundPeerManifest, BoundPodStatus, CODEX_V2_CAPABILITY, PodManifest, PodPeerBootstrap,
    PodStatus,
};
pub use manifest::{
    LaunchDescriptor, PodError, PodRole, PtySpec, manifest_path, manifest_path_for_identity,
};
pub use native_events::{
    CODEX_NATIVE_EVENTS_READ_PROTOCOL, MAX_PRIVATE_NATIVE_EVENT_LOG_BYTES,
    NativeEventCursor, NativeEventFidelity, NativeEventGap, NativeEventIdentity, NativeEventKind,
    NativeEventRead, NativeEventSnapshot, NativeEventSpool, NativeEventStatus, PrivateNativeEvidence,
    PublicNativeEvent, decode_private_native_evidence_for_trusted_reader,
};
pub use peer_checkpoint::{PeerCheckpointError, decode_peer_checkpoint, encode_peer_checkpoint};
#[cfg(target_os = "linux")]
pub use peer_checkpoint::{read_peer_checkpoint, write_peer_checkpoint};
pub use ports::{
    DurableAppendLog, DurableFileIdentity, DurableFiles, LocalConnection, LocalControlTransport,
    PodControlPort, PodObservation, ProcessIdentity, SupervisorBackend, SupervisorEvidence,
    TerminalBackend, TerminalResource, TerminalViewerPort,
};
#[cfg(target_os = "linux")]
pub use runtime::{
    LinuxBackend, PodClient, RebindInspection, TerminalViewer, launch, launch_bound, serve,
};
pub use terminal_protocol::{
    InputLease, LeaseKind, ScreenCheckpoint, ScreenFidelity, TerminalCommand, TerminalEvent,
    TerminalEventKind, TerminalEventPage, TerminalReply, TerminalView,
};
#[cfg(not(target_os = "linux"))]
pub use unsupported::{PodClient, TerminalViewer, UnsupportedBackend, launch, serve};
