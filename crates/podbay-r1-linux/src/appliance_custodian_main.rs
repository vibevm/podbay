#![deny(unsafe_code)]
#[allow(dead_code)]
mod appliance;
#[allow(dead_code)]
mod appliance_protocol;
#[allow(unsafe_code, dead_code)]
mod appliance_sys;
fn main() {
    if std::env::args_os().skip(1).next().is_some() {
        appliance_sys::finish(125);
    }
    let code = if appliance::custodian().is_ok() {
        0
    } else {
        125
    };
    appliance_sys::finish(code);
}
