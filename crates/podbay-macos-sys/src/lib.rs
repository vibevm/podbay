//! Audited macOS-only OS calls behind safe interfaces for podbay-pod.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "macos")]
pub use darwin::*;
