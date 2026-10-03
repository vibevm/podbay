//! Authenticated host admission and transport-independent dispatch guards.
#![forbid(unsafe_code)]

mod authority;
mod launch_spec;

pub use authority::*;
pub use launch_spec::*;
