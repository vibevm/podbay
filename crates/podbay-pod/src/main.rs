//! Pod supervisor entry point; intentionally unavailable during bootstrap.
#![forbid(unsafe_code)]

fn main() {
    eprintln!("podbay-pod 0.1.0 bootstrap has no operational supervisor");
    std::process::exit(2);
}
