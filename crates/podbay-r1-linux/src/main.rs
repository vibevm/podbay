#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

mod contract;
mod entry;
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
#[allow(
    dead_code,
    reason = "Private native primitives compile before any positive origin entry exists"
)]
mod sys;
#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "Metadata checks cannot acquire the uninhabited cold permit"
)]
mod vault;

fn main() -> std::process::ExitCode {
    // Bound argument collection. No environment, manifest, FD or path is read.
    let args: Vec<_> = std::env::args_os().skip(1).take(5).collect();
    let code = match entry::arguments(&args) {
        Err(reason) => reason.code(),
        Ok(role) => {
            #[cfg(target_os = "linux")]
            {
                let (real, effective) = sys::uids();
                entry::acquisition(role, real, effective).code()
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = role;
                "UNSUPPORTED_TARGET"
            }
        }
    };
    let manifest_schema = contract::MANIFEST_SCHEMA;
    println!(
        "{{\"schema\":\"podbay.r1.refusal/1\",\"manifest_schema\":\"{manifest_schema}\",\"code\":\"{code}\",\"gate\":\"UNESTABLISHED\",\"admission\":\"UNAVAILABLE\"}}"
    );
    std::process::ExitCode::from(2)
}
