//! PB05 Linux pod process boundary. No provider turns or PTY semantics are inferred here.
#![forbid(unsafe_code)]

mod manifest;
mod runtime;

pub use manifest::{LaunchDescriptor, PodError, PodManifest, PodRole, PodStatus, manifest_path};
pub use runtime::{PodClient, launch, serve};
