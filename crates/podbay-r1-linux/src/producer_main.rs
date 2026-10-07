#![forbid(unsafe_code)]

#[allow(
    dead_code,
    reason = "Pure protocol scaffold has no live transport or producer"
)]
mod producer_lifecycle;

fn main() -> std::process::ExitCode {
    // Zero arguments is the only syntax. Do not inspect environment, stdin,
    // inherited descriptors, candidate files or systemd notify endpoints.
    let refusal = producer_lifecycle::entry(std::env::args_os().skip(1).next().is_some());
    println!(
        "{{\"schema\":\"podbay.r1.producer-refusal/2\",\"lifecycle_schema\":\"podbay.r1.producer-lifecycle/2\",\"code\":\"{}\",\"production_origin\":\"UNAVAILABLE\",\"admission\":\"UNAVAILABLE\",\"ready\":false,\"retry\":false}}",
        refusal.code()
    );
    std::process::ExitCode::from(2)
}
