#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "linux")]
#[path = "../sys.rs"]
#[allow(unsafe_code, dead_code)]
mod sys;

fn main() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let mut args = std::env::args_os().skip(1);
        if let Some(path) = args.next() {
            let option = args.next();
            if args.next().is_none()
                && (option.is_none()
                    || option.as_deref() == Some(std::ffi::OsStr::new("--mutant-allow-sendmsg")))
            {
                sys::native_probe(std::path::Path::new(&path), option.is_some());
            }
        }
    }
    std::process::exit(2);
}
