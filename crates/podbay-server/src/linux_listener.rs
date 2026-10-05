//! Single-threaded Linux manager socket ownership for authenticated reads.
//! A caller supplies the private directory and retains the durable authority.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use podbay_host::{
    DurableAuthority, GrantId, HostDispatchPort, HostError, StablePortReceipt,
    TrustedBootstrapSendPolicy, TrustedWireRootLaunchPolicy,
};
use podbay_pod::LinuxPeerEvidence;

use crate::{
    LinuxAuthPreludeLimits, LinuxServeOneFault, serve_authenticated_linux_commands_get_one,
    serve_authenticated_linux_launch_and_first_send_one_with_limits,
    serve_authenticated_linux_launch_one,
};

pub const MANAGER_SOCKET_NAME: &str = "manager.sock";
const ACCEPT_POLL: Duration = Duration::from_millis(20);

#[derive(Debug)]
pub enum LinuxListenerError {
    Io(io::Error),
    Configuration(HostError),
    PrivateDirectoryRequired,
    SocketIdentityChanged,
    OwnerProcessChanged,
}

impl Display for LinuxListenerError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "manager socket I/O failed: {error}"),
            Self::Configuration(error) => {
                write!(formatter, "manager launch policy failed: {error:?}")
            }
            Self::PrivateDirectoryRequired => {
                formatter.write_str("manager socket directory is not canonical, owned and private")
            }
            Self::SocketIdentityChanged => {
                formatter.write_str("manager socket path or directory changed")
            }
            Self::OwnerProcessChanged => {
                formatter.write_str("manager launcher process changed or exited")
            }
        }
    }
}
impl Error for LinuxListenerError {}
impl From<io::Error> for LinuxListenerError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// A trusted grant mapping and relative per-connection budget. The listener
/// derives a fresh monotonic deadline for each accepted connection, so a
/// long-lived manager never reuses an expired absolute Instant.
pub struct TrustedWireRootLaunchTemplate {
    grant_id: GrantId,
    exchange_budget: Duration,
    result_contract_ref: String,
}

impl TrustedWireRootLaunchTemplate {
    pub fn from_trusted_policy(
        grant_id: GrantId,
        exchange_budget: Duration,
        result_contract_ref: &str,
    ) -> Result<Self, HostError> {
        if exchange_budget.is_zero() || exchange_budget > Duration::from_secs(300) {
            return Err(HostError::InvalidInput);
        }
        let deadline = Instant::now()
            .checked_add(exchange_budget)
            .ok_or(HostError::InvalidInput)?;
        TrustedWireRootLaunchPolicy::from_trusted_policy(grant_id, deadline, result_contract_ref)?;
        Ok(Self {
            grant_id,
            exchange_budget,
            result_contract_ref: result_contract_ref.into(),
        })
    }

    fn fresh(&self) -> Result<TrustedWireRootLaunchPolicy, HostError> {
        let deadline = Instant::now()
            .checked_add(self.exchange_budget)
            .ok_or(HostError::InvalidInput)?;
        TrustedWireRootLaunchPolicy::from_trusted_policy(
            self.grant_id,
            deadline,
            &self.result_contract_ref,
        )
    }
}

/// Trusted scope SendSession grant and a fresh budget for each accepted
/// exchange. This does not itself create a writer lease or permit native input.
pub struct TrustedBootstrapSendTemplate {
    grant_id: GrantId,
    exchange_budget: Duration,
    initial_writer_lease_seconds: Option<u64>,
}

impl TrustedBootstrapSendTemplate {
    pub fn from_trusted_policy(
        grant_id: GrantId,
        exchange_budget: Duration,
    ) -> Result<Self, HostError> {
        if exchange_budget.is_zero() || exchange_budget > Duration::from_secs(300) {
            return Err(HostError::InvalidInput);
        }
        Instant::now()
            .checked_add(exchange_budget)
            .ok_or(HostError::InvalidInput)?;
        Ok(Self {
            grant_id,
            exchange_budget,
            initial_writer_lease_seconds: None,
        })
    }

    pub fn with_initial_writer_lease_seconds(mut self, seconds: u64) -> Result<Self, HostError> {
        if !(1..=3_600).contains(&seconds) {
            return Err(HostError::InvalidInput);
        }
        self.initial_writer_lease_seconds = Some(seconds);
        Ok(self)
    }

    fn fresh(&self) -> Result<TrustedBootstrapSendPolicy, HostError> {
        let deadline = Instant::now()
            .checked_add(self.exchange_budget)
            .ok_or(HostError::InvalidInput)?;
        let policy = TrustedBootstrapSendPolicy::from_trusted_policy(self.grant_id, deadline)?;
        match self.initial_writer_lease_seconds {
            Some(seconds) => policy.with_initial_writer_lease_seconds(seconds),
            None => Ok(policy),
        }
    }
}

/// Bounded-memory observation of one serial listener run. A failed connection
/// is never retried; the last exact fault is retained for operator diagnosis.
#[derive(Debug, Default)]
pub struct LinuxListenerReport {
    pub accepted: u64,
    pub completed: u64,
    pub authentication_failures: u64,
    pub exchange_failures: u64,
    pub last_failure: Option<LinuxServeOneFault>,
}

/// Owns one filesystem socket path. Drop closes the listener but deliberately
/// leaves the pathname for explicit reconciliation after an unclean stop.
/// `shutdown` removes only the same socket inode this value created.
pub struct LinuxManagerCommandsGetListener {
    listener: UnixListener,
    directory: PathBuf,
    directory_identity: (u64, u64),
    path: PathBuf,
    socket_identity: (u64, u64),
    uid: u32,
}

impl LinuxManagerCommandsGetListener {
    pub fn bind(directory: impl AsRef<Path>) -> Result<Self, LinuxListenerError> {
        let directory = directory.as_ref();
        let peer = LinuxPeerEvidence::for_current_process()
            .map_err(|_| LinuxListenerError::PrivateDirectoryRequired)?;
        let metadata = fs::symlink_metadata(directory)?;
        if !directory.is_absolute()
            || !metadata.file_type().is_dir()
            || metadata.uid() != peer.uid()
            || metadata.mode() & 0o7777 != 0o700
            || fs::canonicalize(directory)? != directory
        {
            return Err(LinuxListenerError::PrivateDirectoryRequired);
        }
        let path = directory.join(MANAGER_SOCKET_NAME);
        // UnixListener::bind refuses an existing path. A stale socket is
        // reconciled explicitly; bind never unlinks or adopts it.
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let socket = fs::symlink_metadata(&path)?;
        if !socket.file_type().is_socket()
            || socket.uid() != peer.uid()
            || socket.mode() & 0o7777 != 0o600
        {
            return Err(LinuxListenerError::SocketIdentityChanged);
        }
        Ok(Self {
            listener,
            directory: directory.to_path_buf(),
            directory_identity: (metadata.dev(), metadata.ino()),
            path,
            socket_identity: (socket.dev(), socket.ino()),
            uid: peer.uid(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Process one connection at a time. The stop flag is checked between
    /// connections and every idle poll; an in-flight handshake/exchange uses
    /// the existing finite socket deadlines and is never retried. The caller
    /// must budget for its durable read before a graceful stop can finish.
    pub fn serve_until<P: HostDispatchPort>(
        &mut self,
        authority: &mut DurableAuthority<P>,
        stop: &AtomicBool,
    ) -> Result<LinuxListenerReport, LinuxListenerError> {
        self.serve_until_checked(authority, stop, || Ok(()))
    }

    /// An opt-in launcher process fence, checked on the accepted connection
    /// before dispatch. A separate pidfd watcher sets `stop` while idle. It
    /// grants no actor or command authority.
    pub fn serve_until_checked<P: HostDispatchPort>(
        &mut self,
        authority: &mut DurableAuthority<P>,
        stop: &AtomicBool,
        owner_check: impl FnMut() -> Result<(), LinuxListenerError>,
    ) -> Result<LinuxListenerReport, LinuxListenerError> {
        self.serve_serial(authority, stop, owner_check, |stream, authority| {
            Ok(serve_authenticated_linux_commands_get_one(
                stream, authority,
            ))
        })
    }

    /// Opt in to one narrow `launch` command on this same auth/1 socket while
    /// retaining `commands.get`. Each accepted connection gets a fresh trusted
    /// deadline and is handled serially; no command is retried by the loop.
    pub fn serve_until_with_launch<P: HostDispatchPort>(
        &mut self,
        authority: &mut DurableAuthority<P>,
        stop: &AtomicBool,
        template: &TrustedWireRootLaunchTemplate,
    ) -> Result<LinuxListenerReport, LinuxListenerError>
    where
        P::Receipt: StablePortReceipt,
    {
        self.serve_serial(
            authority,
            stop,
            || Ok(()),
            |stream, authority| {
                let policy = template
                    .fresh()
                    .map_err(LinuxListenerError::Configuration)?;
                Ok(serve_authenticated_linux_launch_one(
                    stream, authority, &policy,
                ))
            },
        )
    }

    /// Opt in to root launch and claimed Codex `session.send` on the same socket.
    /// An exchange is dispatched once; duplicate reconciliation belongs to
    /// the durable authority and the pod journal, never this listener loop.
    pub fn serve_until_with_launch_and_first_send<P: HostDispatchPort>(
        &mut self,
        authority: &mut DurableAuthority<P>,
        stop: &AtomicBool,
        launch_template: &TrustedWireRootLaunchTemplate,
        send_template: &TrustedBootstrapSendTemplate,
    ) -> Result<LinuxListenerReport, LinuxListenerError>
    where
        P::Receipt: StablePortReceipt,
    {
        self.serve_until_with_launch_and_first_send_checked(
            authority,
            stop,
            launch_template,
            send_template,
            None,
            || Ok(()),
        )
    }

    pub fn serve_until_with_launch_and_first_send_checked<P: HostDispatchPort>(
        &mut self,
        authority: &mut DurableAuthority<P>,
        stop: &AtomicBool,
        launch_template: &TrustedWireRootLaunchTemplate,
        send_template: &TrustedBootstrapSendTemplate,
        pod_directory: Option<&std::path::Path>,
        owner_check: impl FnMut() -> Result<(), LinuxListenerError>,
    ) -> Result<LinuxListenerReport, LinuxListenerError>
    where
        P::Receipt: StablePortReceipt,
    {
        // Pod bootstrap can wait up to 75s on its attested socket. The
        // authenticated manager exchange stays bounded but must outlive that
        // call. This limit is created from trusted templates, never wire JSON.
        let exchange = launch_template
            .exchange_budget
            .max(send_template.exchange_budget)
            .max(Duration::from_secs(90))
            .min(Duration::from_secs(300));
        let limits = LinuxAuthPreludeLimits::new(Duration::from_secs(5), exchange)
            .map_err(|_| LinuxListenerError::Configuration(HostError::InvalidInput))?;
        self.serve_serial(authority, stop, owner_check, |stream, authority| {
            let launch_policy = launch_template
                .fresh()
                .map_err(LinuxListenerError::Configuration)?;
            let send_policy = send_template
                .fresh()
                .map_err(LinuxListenerError::Configuration)?;
            Ok(
                serve_authenticated_linux_launch_and_first_send_one_with_limits(
                    stream,
                    authority,
                    &launch_policy,
                    &send_policy,
                    limits,
                    pod_directory,
                ),
            )
        })
    }

    fn serve_serial<P: HostDispatchPort>(
        &mut self,
        authority: &mut DurableAuthority<P>,
        stop: &AtomicBool,
        mut owner_check: impl FnMut() -> Result<(), LinuxListenerError>,
        mut serve: impl FnMut(
            UnixStream,
            &mut DurableAuthority<P>,
        ) -> Result<Result<(), LinuxServeOneFault>, LinuxListenerError>,
    ) -> Result<LinuxListenerReport, LinuxListenerError> {
        let mut report = LinuxListenerReport::default();
        while !stop.load(Ordering::Acquire) {
            self.recheck_owned_socket()?;
            let (stream, _) = match self.listener.accept() {
                Ok(accepted) => accepted,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(ACCEPT_POLL);
                    continue;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            if stop.load(Ordering::Acquire) {
                break;
            }
            owner_check()?;
            self.recheck_owned_socket()?;
            report.accepted = report.accepted.saturating_add(1);
            match serve(stream, authority)? {
                Ok(()) => report.completed = report.completed.saturating_add(1),
                Err(error) => {
                    match &error {
                        LinuxServeOneFault::Authentication(_) => {
                            report.authentication_failures =
                                report.authentication_failures.saturating_add(1);
                        }
                        LinuxServeOneFault::Exchange(_) => {
                            report.exchange_failures = report.exchange_failures.saturating_add(1);
                        }
                    }
                    report.last_failure = Some(error);
                }
            }
        }
        Ok(report)
    }

    /// Close the owned endpoint and remove only the exact path we created.
    /// A missing or replaced path fails closed and is preserved for inspection.
    pub fn shutdown(self) -> Result<(), LinuxListenerError> {
        self.recheck_owned_socket()?;
        fs::remove_file(&self.path)?;
        fs::File::open(&self.directory)?.sync_all()?;
        Ok(())
    }

    fn recheck_owned_socket(&self) -> Result<(), LinuxListenerError> {
        let directory = fs::symlink_metadata(&self.directory)
            .map_err(|_| LinuxListenerError::SocketIdentityChanged)?;
        let socket = fs::symlink_metadata(&self.path)
            .map_err(|_| LinuxListenerError::SocketIdentityChanged)?;
        if !directory.file_type().is_dir()
            || (directory.dev(), directory.ino()) != self.directory_identity
            || directory.uid() != self.uid
            || directory.mode() & 0o7777 != 0o700
            || fs::canonicalize(&self.directory)
                .map_err(|_| LinuxListenerError::SocketIdentityChanged)?
                != self.directory
            || !socket.file_type().is_socket()
            || (socket.dev(), socket.ino()) != self.socket_identity
            || socket.uid() != self.uid
            || socket.mode() & 0o7777 != 0o600
        {
            return Err(LinuxListenerError::SocketIdentityChanged);
        }
        Ok(())
    }
}
