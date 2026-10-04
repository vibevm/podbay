//! Foreground, read-only Linux manager ownership. Actor enrollment and
//! mutation policy are separate trusted setup steps, not CLI flags.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::env;
    use std::ffi::{OsStr, OsString};
    use std::fs::{self, OpenOptions};
    use std::io;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use podbay_host::{DurableAuthority, DurableAuthorityError};
    use podbay_launch_linux::{LinuxLaunchPort, TrustedLinuxLaunchConfig};
    use podbay_pod::LinuxPeerEvidence;
    use podbay_server::{LinuxListenerError, LinuxManagerCommandsGetListener, MANAGER_SOCKET_NAME};
    use signal_hook::{
        consts::signal::{SIGINT, SIGTERM},
        flag,
    };

    const USAGE: &str = "usage: podbay manager serve --state-dir DIR --database FILE --pod-dir DIR --pod-binary FILE --pod-sha256 HEX\nThis command serves authenticated reads only at DIR/manager.sock.";

    struct ServeConfig {
        state_dir: PathBuf,
        database: PathBuf,
        pod_dir: PathBuf,
        pod_binary: PathBuf,
        pod_sha256: String,
    }

    pub fn main() -> ExitCode {
        match run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("podbay manager serve: {error}");
                ExitCode::from(2)
            }
        }
    }

    fn run() -> Result<(), String> {
        let config = parse_args(env::args_os())?;
        let self_peer = LinuxPeerEvidence::for_current_process()
            .map_err(|error| format!("manager process evidence unavailable: {error}"))?;
        validate_private_directory(&config.state_dir, self_peer.uid())?;
        validate_private_directory(&config.pod_dir, self_peer.uid())?;
        validate_database_path(&config.database, &config.state_dir, self_peer.uid())?;
        let port_config = TrustedLinuxLaunchConfig::from_trusted_policy(
            config.pod_binary,
            config.pod_sha256,
            config.pod_dir,
        )
        .map_err(|error| format!("trusted pod configuration refused: {error}"))?;

        // Register before exposing the socket. A signal handler only sets a
        // flag; unlink and SQLite teardown run on the normal thread.
        let stop = Arc::new(AtomicBool::new(false));
        flag::register(SIGINT, stop.clone())
            .map_err(|error| format!("cannot register SIGINT handler: {error}"))?;
        flag::register(SIGTERM, stop.clone())
            .map_err(|error| format!("cannot register SIGTERM handler: {error}"))?;
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        let socket_path = config.state_dir.join(MANAGER_SOCKET_NAME);
        // A stale pathname must not advance the durable owner epoch. Probe it
        // before opening the manager; the later check still catches races.
        check_manager_socket_path(&socket_path)?;
        ensure_private_database(&config.database, &config.state_dir, self_peer.uid())?;
        // One lock and manager OS identity live for this entire serve loop.
        let mut authority = DurableAuthority::open(
            &config.database,
            LinuxLaunchPort::new(port_config),
        )
        .map_err(|error| match error {
            DurableAuthorityError::Busy => "manager owner busy for this database".to_owned(),
            other => format!("durable manager open failed: {other:?}"),
        })?;
        check_manager_socket_path(&socket_path)?;
        let mut listener = LinuxManagerCommandsGetListener::bind(&config.state_dir).map_err(
            |error| match error {
                LinuxListenerError::Io(ref io_error)
                    if matches!(io_error.kind(), io::ErrorKind::AddrInUse | io::ErrorKind::AlreadyExists) =>
                {
                    format!(
                        "existing manager socket path {}; inspect the prior owner and reconcile it manually",
                        socket_path.display()
                    )
                }
                other => format!("manager socket bind failed: {other}"),
            },
        )?;
        eprintln!(
            "podbay manager read-only socket: {}",
            listener.path().display()
        );
        let served = listener.serve_until(&mut authority, &stop);
        let shutdown = listener.shutdown();
        match (served, shutdown) {
            (Ok(report), Ok(())) => {
                eprintln!(
                    "podbay manager stopped: accepted={} completed={} auth_failures={} exchange_failures={}",
                    report.accepted,
                    report.completed,
                    report.authentication_failures,
                    report.exchange_failures
                );
                Ok(())
            }
            (Err(serve_error), Ok(())) => Err(format!("manager listener failed: {serve_error}")),
            (Ok(_), Err(shutdown_error)) => {
                Err(format!("manager socket shutdown failed: {shutdown_error}"))
            }
            (Err(serve_error), Err(shutdown_error)) => Err(format!(
                "manager listener failed: {serve_error}; socket shutdown failed: {shutdown_error}"
            )),
        }
    }

    fn parse_args(mut args: impl Iterator<Item = OsString>) -> Result<ServeConfig, String> {
        let _binary = args.next();
        if args.next().as_deref() != Some(OsStr::new("manager"))
            || args.next().as_deref() != Some(OsStr::new("serve"))
        {
            return Err(USAGE.into());
        }
        let mut flags = HashMap::<String, OsString>::new();
        while let Some(flag) = args.next() {
            let flag = flag
                .into_string()
                .map_err(|_| format!("flag names must be UTF-8; {USAGE}"))?;
            if !matches!(
                flag.as_str(),
                "--state-dir" | "--database" | "--pod-dir" | "--pod-binary" | "--pod-sha256"
            ) {
                return Err(format!("unknown flag {flag}; {USAGE}"));
            }
            let value = args
                .next()
                .ok_or_else(|| format!("missing value for {flag}; {USAGE}"))?;
            if flags.insert(flag.clone(), value).is_some() {
                return Err(format!("duplicate flag {flag}; {USAGE}"));
            }
        }
        let mut take = |name: &str| {
            flags
                .remove(name)
                .ok_or_else(|| format!("missing {name}; {USAGE}"))
        };
        Ok(ServeConfig {
            state_dir: take("--state-dir")?.into(),
            database: take("--database")?.into(),
            pod_dir: take("--pod-dir")?.into(),
            pod_binary: take("--pod-binary")?.into(),
            pod_sha256: take("--pod-sha256")?
                .into_string()
                .map_err(|_| "pod SHA-256 must be ASCII hex".to_owned())?,
        })
    }

    fn validate_private_directory(path: &Path, uid: u32) -> Result<(), String> {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            format!("private directory {} unavailable: {error}", path.display())
        })?;
        if !path.is_absolute()
            || !metadata.is_dir()
            || metadata.uid() != uid
            || metadata.mode() & 0o7777 != 0o700
            || fs::canonicalize(path).map_err(|error| error.to_string())? != path
        {
            return Err(format!(
                "directory {} must be canonical, owned by this process and mode 0700",
                path.display()
            ));
        }
        Ok(())
    }

    fn check_manager_socket_path(path: &Path) -> Result<(), String> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_socket() && UnixStream::connect(path).is_ok() {
                    return Err("manager owner busy for this database".into());
                }
                Err(format!(
                    "existing manager socket path {}; inspect the prior owner and reconcile it manually",
                    path.display()
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("manager socket path inspection failed: {error}")),
        }
    }

    fn validate_database_path(database: &Path, state_dir: &Path, uid: u32) -> Result<(), String> {
        if !database.is_absolute()
            || database.parent() != Some(state_dir)
            || database.file_name().is_none()
        {
            return Err("database must be an absolute filename directly inside --state-dir".into());
        }
        match fs::symlink_metadata(database) {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.uid() != uid
                    || metadata.mode() & 0o777 != 0o600
                    || metadata.nlink() != 1
                    || fs::canonicalize(database).map_err(|error| error.to_string())? != database
                {
                    return Err("existing database is not a canonical private regular file".into());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("database path inspection failed: {error}")),
        }
        Ok(())
    }

    fn ensure_private_database(database: &Path, state_dir: &Path, uid: u32) -> Result<(), String> {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(database)
        {
            Ok(file) => file
                .sync_all()
                .map_err(|error| format!("database creation failed: {error}"))?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("database creation failed: {error}")),
        }
        validate_database_path(database, state_dir, uid)
    }
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::main()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("podbay manager serve is available on Linux only");
    std::process::ExitCode::from(2)
}
