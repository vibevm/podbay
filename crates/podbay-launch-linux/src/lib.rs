//! Linux native launch boundaries for bound process resources and Codex V2.
//! Process and transport evidence does not establish provider readiness.
#![forbid(unsafe_code)]
#[cfg(target_os = "linux")]
mod codex_v2;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod native_ingest;
#[cfg(target_os = "linux")]
pub use codex_v2::{
    CodexV2Preflight, CodexV3Preflight, TrustedCodexCredentialSource,
    preflight_committed_codex_v2, preflight_committed_codex_v2_read_only,
    preflight_committed_codex_v3,
};
#[cfg(target_os = "linux")]
pub use linux::{
    LinuxLaunchPort, OperatorArtifactDigest, TrustedLinuxLaunchConfig,
    TrustedOperatorArtifact, TrustedOperatorProcessProfile,
    VerifiedRebindInspection,
};
#[cfg(target_os = "linux")]
pub use native_ingest::{
    ManagerNativeEvidenceRead, TrustedNativeEventDirectory, read_committed_codex_native_evidence,
};
