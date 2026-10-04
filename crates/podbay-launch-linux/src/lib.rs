//! Linux native launch boundaries. Codex V2 is preflight-only here;
//! neither path infers provider readiness from process transport.
#![forbid(unsafe_code)]
#[cfg(target_os = "linux")]
mod codex_v2;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use codex_v2::{CodexV2Preflight, TrustedCodexCredentialSource, preflight_committed_codex_v2};
#[cfg(target_os = "linux")]
pub use linux::{LinuxLaunchPort, TrustedLinuxLaunchConfig, VerifiedRebindInspection};
