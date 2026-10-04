//! Authenticated host admission and transport-independent dispatch guards.
#![forbid(unsafe_code)]

mod actor_credential;
mod authority;
mod launch_spec;
#[cfg(target_os = "linux")]
mod linux_manager_peer;

pub use actor_credential::*;
pub use authority::*;
pub use launch_spec::*;
