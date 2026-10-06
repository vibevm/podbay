//! Authenticated host admission and transport-independent dispatch guards.
#![forbid(unsafe_code)]

mod actor_credential;
// Inert recovery calculus only; no production admission/acquisition hook.
mod access_barrier_gate;
mod authority;
mod id_mint;
mod launch_spec;
mod owner_recovery;
#[cfg(target_os = "linux")]
mod linux_manager_peer;

pub use actor_credential::*;
pub use authority::*;
pub use id_mint::*;
pub use launch_spec::*;
pub use owner_recovery::*;
