//! Linux synthetic process.exec launch adapter. No provider-readiness claim.
#![forbid(unsafe_code)]
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{LinuxLaunchPort, TrustedLinuxLaunchConfig, VerifiedRebindInspection};
