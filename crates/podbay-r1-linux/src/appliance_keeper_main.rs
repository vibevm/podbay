#![deny(unsafe_code)]
#[allow(dead_code)]
mod appliance;
#[allow(dead_code)]
mod appliance_protocol;
#[allow(unsafe_code, dead_code)]
mod appliance_sys;
fn main() -> std::process::ExitCode {
    if std::env::args_os().skip(1).next().is_some() {
        return std::process::ExitCode::from(2);
    }
    match appliance::keeper() {
        Ok(()) => std::process::ExitCode::from(2),
        Err(_) => {
            eprintln!("APPLIANCE_KEEPER_REFUSED_OR_LOST");
            std::process::ExitCode::from(2)
        }
    }
}
