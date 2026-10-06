//! PB05 Linux pod process boundary. No provider turns or PTY semantics are inferred here.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod codex_bootstrap;
#[cfg(target_os = "linux")]
mod codex_credential;
mod codex_journal;
mod codex_later_turn;
#[cfg(target_os = "linux")]
mod codex_launch;
#[cfg(target_os = "linux")]
mod codex_resource;
mod codex_turn_journal;
#[cfg(target_os = "linux")]
mod codex_turn_control;
#[cfg(target_os = "linux")]
mod linux_peer;
mod manifest;
mod native_events;
#[cfg(target_os = "linux")]
mod native_segment_checkpoint;
mod peer_checkpoint;
mod ports;
#[cfg(target_os = "linux")]
mod rebind_protocol;
#[cfg(target_os = "linux")]
mod rebind_recovery_protocol;
#[cfg(target_os = "linux")]
mod runtime;
#[cfg(target_os = "linux")]
mod segmented_native_events;
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
pub use codex_launch::{launch_bound_codex_v2, launch_bound_codex_v3};
#[cfg(target_os = "linux")]
pub use codex_resource::{PodCodexResource, ValidatedCodexResourceLaunch};
pub use codex_turn_journal::{
    CodexLaterTurnJournal, LaterTurnIntentResult, LaterTurnStage, LaterTurnTerminal, LaterTurnView,
};
#[cfg(target_os = "linux")]
pub use codex_turn_control::{CodexAnchorInspectReceipt, LaterTurnControlReceipt, LaterTurnControlStage};
#[cfg(target_os = "linux")]
pub use linux_peer::{LinuxPeerError, LinuxPeerEvidence};
#[cfg(target_os = "linux")]
pub use manifest::{
    BoundPeerManifest, BoundPodStatus, BoundPolicyFenceV3, CODEX_V2_CAPABILITY,
    CODEX_V3_CAPABILITY, OPERATOR_PROCESS_CAPABILITY, OPERATOR_PROCESS_PROFILE_REF,
    PEER_BINDING_V3_PROTOCOL, PodManifest, PodPeerBootstrap, PodStatus,
};
pub use manifest::{
    LaunchDescriptor, PodError, PodRole, PtySpec, manifest_path, manifest_path_for_identity,
};
pub use native_events::{
    CODEX_NATIVE_EVENTS_READ_PROTOCOL, MAX_PRIVATE_NATIVE_EVENT_LOG_BYTES, NativeEventCursor,
    NativeEventFidelity, NativeEventGap, NativeEventIdentity, NativeEventKind, NativeEventRead,
    NativeEventSnapshot, NativeEventSpool, NativeEventStatus, PrivateNativeEvidence,
    PublicNativeEvent, decode_private_native_evidence_for_trusted_reader,
};
#[cfg(target_os = "linux")]
pub use native_segment_checkpoint::{
    IndexedPrivateFrame, LinuxNativeSegmentDirectory, NativeSegmentCheckpoint, NativeSegmentMeta,
    NativeSegmentOffset,
};
pub use peer_checkpoint::{
    PeerCheckpointError, decode_peer_checkpoint, encode_peer_checkpoint,
    peer_checkpoint_observation_digest,
};
pub use peer_checkpoint::{read_peer_checkpoint, write_peer_checkpoint};
pub use ports::{
    DurableAppendLog, DurableFileIdentity, DurableFiles, LocalConnection, LocalControlTransport,
    PodControlPort, PodObservation, ProcessIdentity, SupervisorBackend, SupervisorEvidence,
    TerminalBackend, TerminalResource, TerminalViewerPort,
};
#[cfg(target_os = "linux")]
pub use runtime::{
    AttestedStopError, AttestedStopReply, PreparedAttestedStop, PreparedStopIdentity,
    LinuxBackend, PodClient, RebindInspection, TerminalViewer, current_bound_peer_binding, launch,
    launch_bound, serve,
};
#[cfg(target_os = "linux")]
pub use rebind_recovery_protocol::{PendingRecoveryInspection, RECOVER_INSPECT_PROTOCOL};
pub use terminal_protocol::{
    InputLease, LeaseKind, ScreenCheckpoint, ScreenFidelity, TerminalCommand, TerminalEvent,
    TerminalEventKind, TerminalEventPage, TerminalReply, TerminalView,
};
#[cfg(not(target_os = "linux"))]
pub use unsupported::{PodClient, TerminalViewer, UnsupportedBackend, launch, serve};
