//! Linux native launch boundaries for synthetic V1 and committed Codex V2.
//! Process and transport evidence does not establish provider readiness.
#![forbid(unsafe_code)]
#[cfg(target_os = "linux")]
mod codex_v2;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use codex_v2::{CodexV2Preflight, TrustedCodexCredentialSource, preflight_committed_codex_v2};
#[cfg(target_os = "linux")]
pub use linux::{LinuxLaunchPort, TrustedLinuxLaunchConfig, VerifiedRebindInspection};
