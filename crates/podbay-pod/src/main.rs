//! Private pod supervisor entry point. Provider turns and PTY controls are later atoms.
#![forbid(unsafe_code)]

fn main() {
    let mut arguments = std::env::args().skip(1);
    match (
        arguments.next().as_deref(),
        arguments.next().as_deref(),
        arguments.next(),
    ) {
        (Some("serve"), Some("--manifest"), Some(path)) if arguments.next().is_none() => {
            if let Err(error) = podbay_pod::serve(path) {
                eprintln!("podbay-pod refused startup: {error}");
                std::process::exit(2);
            }
        }
        _ => {
            eprintln!("podbay-pod accepts only the private serve --manifest entry point");
            std::process::exit(2);
        }
    }
}
