//! Foreground, read-only Linux manager ownership. Actor enrollment and
//! mutation policy are separate trusted setup steps, not CLI flags.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod manager_policy;

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

    use crate::manager_policy::PreparedManagerPolicy;
    use podbay_core::{ActorId, ScopeId};
    use podbay_host::{
        CredentialRef, DurableAuthority, DurableAuthorityError, TrustedInitialOwnerPolicy,
    };
    use podbay_launch_linux::{LinuxLaunchPort, TrustedLinuxLaunchConfig};
    use podbay_pod::LinuxPeerEvidence;
    use podbay_server::{
        InitialOwnerSetupError, LinuxInitialOwnerSetupListener, LinuxListenerError,
        LinuxManagerCommandsGetListener, MANAGER_SOCKET_NAME, OWNER_SETUP_SOCKET_NAME,
        TrustedBootstrapSendTemplate, TrustedWireRootLaunchTemplate,
    };
    use signal_hook::{
        consts::signal::{SIGINT, SIGTERM},
        flag,
    };

    const USAGE: &str = "usage: podbay manager serve --state-dir DIR --database FILE --pod-dir DIR --pod-binary FILE --pod-sha256 HEX [--trusted-policy FILE | --initial-owner-actor ID --initial-owner-scope ID --initial-owner-credential REF]\nA fresh initial owner setup uses DIR/owner-setup.sock before DIR/manager.sock. A trusted policy file explicitly enables one V2 root launch and first send.";

    struct InitialOwnerConfig {
        actor_id: String,
        scope_id: String,
        credential_ref: String,
    }

    struct ServeConfig {
        state_dir: PathBuf,
        database: PathBuf,
        pod_dir: PathBuf,
        pod_binary: PathBuf,
        pod_sha256: String,
        initial_owner: Option<InitialOwnerConfig>,
        trusted_policy: Option<PathBuf>,
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
        let parent = if config.initial_owner.is_some() || config.trusted_policy.is_some() {
            Some(
                LinuxPeerEvidence::for_launcher_parent()
                    .map_err(|error| format!("launcher parent evidence unavailable: {error}"))?,
            )
        } else {
            None
        };
        let self_peer = LinuxPeerEvidence::for_current_process()
            .map_err(|error| format!("manager process evidence unavailable: {error}"))?;
        if parent.as_ref().is_some_and(|parent| {
            parent.uid() != self_peer.uid() || parent.gid() != self_peer.gid()
        }) {
            return Err("launcher parent effective UID/GID differs from manager".into());
        }
        validate_private_directory(&config.state_dir, self_peer.uid())?;
        validate_private_directory(&config.pod_dir, self_peer.uid())?;
        validate_database_path(&config.database, &config.state_dir, self_peer.uid())?;
        let mut prepared = config
            .trusted_policy
            .as_ref()
            .map(|path| PreparedManagerPolicy::load(path, &config.state_dir, self_peer.uid()))
            .transpose()?;
        let owner_policy = if let Some(ref policy) = prepared {
            Some(policy.owner.clone())
        } else if let Some(ref initial) = config.initial_owner {
            let actor_id = ActorId::try_from(initial.actor_id.as_str())
                .map_err(|_| "initial owner actor ID is invalid".to_owned())?;
            let scope_id = ScopeId::try_from(initial.scope_id.as_str())
                .map_err(|_| "initial owner scope ID is invalid".to_owned())?;
            let credential =
                CredentialRef::from_trusted_vault(scope_id.clone(), &initial.credential_ref)
                    .map_err(|_| "initial owner credential reference is invalid".to_owned())?;
            Some(
                TrustedInitialOwnerPolicy::from_trusted_manager_policy(
                    actor_id, scope_id, credential,
                )
                .map_err(|_| "initial owner policy is invalid".to_owned())?,
            )
        } else {
            None
        };
        let port_config = TrustedLinuxLaunchConfig::from_trusted_policy(
            config.pod_binary,
            config.pod_sha256,
            config.pod_dir,
        )
        .map_err(|error| format!("trusted pod configuration refused: {error}"))?;
        let mut port = LinuxLaunchPort::new(port_config);
        if let Some(ref mut policy) = prepared {
            let source = policy
                .credential_source
                .take()
                .ok_or_else(|| "trusted credential source is missing".to_owned())?;
            port.register_codex_credential_source_from_trusted_policy(source)
                .map_err(|error| format!("trusted credential registration refused: {error}"))?;
        }

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
        let setup_path = config.state_dir.join(OWNER_SETUP_SOCKET_NAME);
        // A stale pathname must not advance the durable owner epoch. Probe it
        // before opening the manager; the later check still catches races.
        check_manager_socket_path(&socket_path)?;
        if owner_policy.is_some() {
            check_owner_setup_socket_path(&setup_path)?;
        }
        ensure_private_database(&config.database, &config.state_dir, self_peer.uid())?;
        // One lock and manager OS identity live for this entire serve loop.
        let mut authority =
            DurableAuthority::open(&config.database, port).map_err(|error| match error {
                DurableAuthorityError::Busy => "manager owner busy for this database".to_owned(),
                other => format!("durable manager open failed: {other:?}"),
            })?;
        check_manager_socket_path(&socket_path)?;
        let mut enrolled_grant = None;
        if let Some(policy) = owner_policy {
            check_owner_setup_socket_path(&setup_path)?;
            let mut setup = LinuxInitialOwnerSetupListener::bind(
                &config.state_dir,
                parent.expect("setup requires captured launcher parent"),
            )
            .map_err(|error| format!("owner setup bind failed: {error}"))?;
            eprintln!("podbay owner setup socket: {}", setup.path().display());
            let enrolled = setup.serve(&mut authority, policy, &stop);
            let cleanup = setup.shutdown();
            match (enrolled, cleanup) {
                (Ok(receipt), Ok(())) => {
                    eprintln!(
                        "podbay initial owner enrolled: actor={} scope={} grant=grant.{} ownerEpoch={}",
                        receipt.actor_id.as_str(),
                        receipt.scope_id.as_str(),
                        receipt.grant_id.get(),
                        receipt.owner_epoch,
                    );
                    enrolled_grant = Some(receipt.grant_id);
                }
                (Err(InitialOwnerSetupError::Stopped), Ok(())) => return Ok(()),
                (Err(error), Ok(())) => return Err(format!("owner setup failed: {error}")),
                (Ok(_), Err(error)) => return Err(format!("owner setup cleanup failed: {error}")),
                (Err(setup_error), Err(cleanup_error)) => {
                    return Err(format!(
                        "owner setup failed: {setup_error}; cleanup failed: {cleanup_error}"
                    ));
                }
            }
        }
        let templates = if let Some(policy) = prepared {
            let grant = enrolled_grant
                .ok_or_else(|| "trusted policy lacks an enrolled owner grant".to_owned())?;
            authority
                .register_native_host_from_trusted_policy(policy.native_host)
                .map_err(|error| format!("trusted native host registration refused: {error:?}"))?;
            authority
                .register_launch_profile_from_trusted_policy(policy.profile)
                .map_err(|error| {
                    format!("trusted launch profile registration refused: {error:?}")
                })?;
            let launch = TrustedWireRootLaunchTemplate::from_trusted_policy(
                grant,
                policy.launch_deadline,
                &policy.result_contract_ref,
            )
            .map_err(|error| format!("trusted launch template refused: {error:?}"))?;
            let send =
                TrustedBootstrapSendTemplate::from_trusted_policy(grant, policy.send_deadline)
                    .and_then(|template| {
                        template.with_initial_writer_lease_seconds(policy.writer_lease_seconds)
                    })
                    .map_err(|error| format!("trusted send template refused: {error:?}"))?;
            Some((launch, send))
        } else {
            None
        };
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
            "podbay manager socket: {} mode={}",
            listener.path().display(),
            if templates.is_some() {
                "trusted-v2-root"
            } else {
                "read-only"
            }
        );
        let served = if let Some((launch, send)) = templates.as_ref() {
            listener.serve_until_with_launch_and_first_send(&mut authority, &stop, launch, send)
        } else {
            listener.serve_until(&mut authority, &stop)
        };
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
                "--state-dir"
                    | "--database"
                    | "--pod-dir"
                    | "--pod-binary"
                    | "--pod-sha256"
                    | "--initial-owner-actor"
                    | "--initial-owner-scope"
                    | "--initial-owner-credential"
                    | "--trusted-policy"
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
        let actor = flags.remove("--initial-owner-actor");
        let scope = flags.remove("--initial-owner-scope");
        let credential = flags.remove("--initial-owner-credential");
        let trusted_policy = flags.remove("--trusted-policy").map(PathBuf::from);
        if trusted_policy.is_some() && (actor.is_some() || scope.is_some() || credential.is_some())
        {
            return Err("--trusted-policy and individual initial-owner flags are exclusive".into());
        }
        let initial_owner = match (actor, scope, credential) {
            (None, None, None) => None,
            (Some(actor), Some(scope), Some(credential)) => Some(InitialOwnerConfig {
                actor_id: actor
                    .into_string()
                    .map_err(|_| "initial owner actor ID is not UTF-8")?,
                scope_id: scope
                    .into_string()
                    .map_err(|_| "initial owner scope ID is not UTF-8")?,
                credential_ref: credential
                    .into_string()
                    .map_err(|_| "initial owner credential ref is not UTF-8")?,
            }),
            _ => {
                return Err(format!(
                    "all three initial owner policy flags are required; {USAGE}"
                ));
            }
        };
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
            initial_owner,
            trusted_policy,
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

    fn check_owner_setup_socket_path(path: &Path) -> Result<(), String> {
        match fs::symlink_metadata(path) {
            Ok(_) => Err(format!(
                "existing owner setup socket path {}; inspect the prior owner and reconcile it manually",
                path.display()
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "owner setup socket path inspection failed: {error}"
            )),
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
