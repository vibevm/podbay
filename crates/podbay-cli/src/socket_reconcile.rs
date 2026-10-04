//! Reconcile only abandoned, private Unix socket names while the manager
//! lifetime lock is held. No store open or owner replay has happened yet.

use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use nix::fcntl::AtFlags;
use nix::sys::stat::fstatat;
use nix::unistd::{UnlinkatFlags, unlinkat};

const PROBE_LIMIT: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
}

/// The caller must invoke this only from DurableAuthority's locked preflight.
/// `canonical_database` is returned by the same lock acquisition.
pub(crate) fn reconcile_abandoned_sockets(
    state_dir: &Path,
    canonical_database: &Path,
    uid: u32,
    names: &[&str],
) -> io::Result<()> {
    reconcile_with_probe(state_dir, canonical_database, uid, names, probe_abandoned)
}

fn reconcile_with_probe(
    state_dir: &Path,
    canonical_database: &Path,
    uid: u32,
    names: &[&str],
    mut probe: impl FnMut(PathBuf) -> io::Result<()>,
) -> io::Result<()> {
    if !state_dir.is_absolute() || canonical_database.parent() != Some(state_dir) {
        return Err(refused("socket directory does not own the locked database"));
    }
    let before = fs::symlink_metadata(state_dir)?;
    if !before.is_dir()
        || before.uid() != uid
        || before.mode() & 0o7777 != 0o700
        || fs::canonicalize(state_dir)? != state_dir
    {
        return Err(refused(
            "socket parent is not canonical, owned and mode 0700",
        ));
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(state_dir)?;
    let pinned = directory.metadata()?;
    let parent = Identity {
        device: pinned.dev(),
        inode: pinned.ino(),
    };
    if parent
        != (Identity {
            device: before.dev(),
            inode: before.ino(),
        })
    {
        return Err(refused("socket parent changed during pin"));
    }

    // Validate and probe every entry before unlinking any of them.
    let mut stale = Vec::new();
    for &name in names {
        if name.is_empty() || name.contains('/') || name.contains('\0') {
            return Err(refused("socket name is invalid"));
        }
        let Some(identity) = inspect_socket(&directory, name, uid)? else {
            continue;
        };
        probe(state_dir.join(name))?;
        recheck_parent(state_dir, &directory, parent, uid)?;
        if inspect_socket(&directory, name, uid)? != Some(identity) {
            return Err(refused("socket inode changed during live probe"));
        }
        stale.push((name, identity));
    }
    for (name, identity) in stale {
        recheck_parent(state_dir, &directory, parent, uid)?;
        if inspect_socket(&directory, name, uid)? != Some(identity) {
            return Err(refused("socket inode changed before unlink"));
        }
        unlinkat(
            Some(directory.as_raw_fd()),
            name,
            UnlinkatFlags::NoRemoveDir,
        )
        .map_err(nix_error)?;
        directory.sync_all()?;
    }
    Ok(())
}

fn recheck_parent(
    state_dir: &Path,
    directory: &File,
    expected: Identity,
    uid: u32,
) -> io::Result<()> {
    let path = fs::symlink_metadata(state_dir)?;
    let fd = directory.metadata()?;
    if !path.is_dir()
        || !fd.is_dir()
        || path.uid() != uid
        || fd.uid() != uid
        || path.mode() & 0o7777 != 0o700
        || fd.mode() & 0o7777 != 0o700
        || fs::canonicalize(state_dir)? != state_dir
        || (Identity {
            device: path.dev(),
            inode: path.ino(),
        }) != expected
        || (Identity {
            device: fd.dev(),
            inode: fd.ino(),
        }) != expected
    {
        return Err(refused("socket parent changed before unlink"));
    }
    Ok(())
}

fn inspect_socket(directory: &File, name: &str, uid: u32) -> io::Result<Option<Identity>> {
    let entry = match fstatat(
        Some(directory.as_raw_fd()),
        name,
        AtFlags::AT_SYMLINK_NOFOLLOW,
    ) {
        Ok(entry) => entry,
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(error) => return Err(nix_error(error)),
    };
    if entry.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || entry.st_uid != uid
        || entry.st_mode & 0o7777 != 0o600
        || entry.st_nlink != 1
    {
        return Err(refused(
            "socket path is non-socket, foreign or not mode 0600",
        ));
    }
    Ok(Some(Identity {
        device: entry.st_dev,
        inode: entry.st_ino,
    }))
}

fn probe_abandoned(path: PathBuf) -> io::Result<()> {
    let (send, receive) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = UnixStream::connect(path).map(|_| ());
        let _ = send.send(result);
    });
    match receive.recv_timeout(PROBE_LIMIT) {
        Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => Ok(()),
        Ok(Ok(())) => Err(refused("socket has a live listener")),
        Ok(Err(error)) => Err(io::Error::new(
            error.kind(),
            format!("socket live probe refused: {error}"),
        )),
        Err(_) => Err(refused("socket live probe timed out")),
    }
}

fn refused(reason: &'static str) -> io::Error {
    io::Error::new(ErrorKind::PermissionDenied, reason)
}

fn nix_error(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn socket_inode_substitution_is_refused_before_unlink() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let state =
            std::env::temp_dir().join(format!("podbay-socket-swap-{}-{nonce}", std::process::id()));
        fs::create_dir(&state).unwrap();
        let state = fs::canonicalize(state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = state.join("manager.sock");
        let other = state.join("other.sock");
        let original = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let substitute = UnixListener::bind(&other).unwrap();
        fs::set_permissions(&other, fs::Permissions::from_mode(0o600)).unwrap();
        let replacement = fs::symlink_metadata(&other).unwrap();
        drop(original);
        drop(substitute);
        let result = reconcile_with_probe(
            &state,
            &state.join("podbay.sqlite"),
            fs::metadata(&state).unwrap().uid(),
            &["manager.sock"],
            |_| fs::rename(&other, &socket),
        );
        assert!(result.is_err());
        let preserved = fs::symlink_metadata(&socket).unwrap();
        assert_eq!(
            (preserved.dev(), preserved.ino()),
            (replacement.dev(), replacement.ino())
        );
        fs::remove_dir_all(state).unwrap();
    }
}
