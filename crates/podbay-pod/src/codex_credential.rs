//! Linux pod-owned Codex credential path preparation. This never reads or
//! copies credential bytes and does not claim hostile same-UID isolation.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, symlink};
use std::path::{Path, PathBuf};

use crate::manifest::{PodError, private_directory};

/// The reviewed `LoadCredential=auth.json:<trusted-source>` unit property
/// supplies exactly this name to the pod's credential directory.
pub const CODEX_AUTH_CREDENTIAL_NAME: &str = "auth.json";
const MAX_CREDENTIAL_BYTES: u64 = 1_048_576;

/// One private directory for the exact immutable manifest slot. The unit
/// name is derived from that manifest's 32-hex stem, never request JSON.
/// `create` is used only by the pod before child spawn; manager reads pass
/// false and cannot create or change the slot directory.
pub fn codex_private_slot_directory(
    shared_manifest_directory: &Path,
    expected_unit: &str,
    create: bool,
) -> Result<PathBuf, PodError> {
    let stem = expected_unit.strip_prefix("podbay-pod-")
        .and_then(|value| value.strip_suffix(".service"))
        .filter(|_| valid_pod_unit(expected_unit))
        .ok_or(PodError::Invalid("Codex manifest slot identity"))?;
    private_directory(shared_manifest_directory)?;
    let parent = fs::symlink_metadata(shared_manifest_directory)?;
    if parent.mode() & 0o7777 != 0o700 {
        return Err(PodError::Refused("Codex shared manifest directory mode changed"));
    }
    let slot = shared_manifest_directory.join(format!("{stem}.private"));
    if create {
        ensure_private_child(&slot)?;
    } else {
        private_directory(&slot)?;
    }
    let child = fs::symlink_metadata(&slot)?;
    if child.mode() & 0o7777 != 0o700
        || child.uid() != parent.uid()
        || child.dev() != parent.dev()
    {
        return Err(PodError::Refused("Codex private slot directory changed"));
    }
    Ok(slot)
}

/// Paths for `ChildLaunchSpec` after the pod has verified a systemd credential.
/// The reference is a symlink, not another stored copy of the credential.
pub struct PreparedCodexHome {
    isolated_home: PathBuf,
    codex_home: PathBuf,
    credential_reference: PathBuf,
}

impl PreparedCodexHome {
    pub fn isolated_home(&self) -> &Path {
        &self.isolated_home
    }

    pub fn codex_home(&self) -> &Path {
        &self.codex_home
    }

    pub fn credential_reference(&self) -> &Path {
        &self.credential_reference
    }
}

/// Prepare a private `HOME/CODEX_HOME` for one Linux pod before child spawn.
/// `expected_unit` and `private_pod_directory` must come from the checked
/// launch binding, never a request field.
/// `credentials_directory` must be captured from systemd's own
/// `$CREDENTIALS_DIRECTORY` at service startup, not a manifest, request, or
/// inherited child environment value. This function checks path shape and
/// ownership but cannot authenticate that environment provenance against a
/// malicious process sharing the same UID.
///
/// The symlink becomes dangling when systemd deactivates the unit and removes
/// its credential directory. No private credential bytes are persisted here.
pub fn prepare_codex_home_from_systemd_credential(
    expected_unit: &str,
    private_pod_directory: &Path,
    credentials_directory: &Path,
) -> Result<PreparedCodexHome, PodError> {
    if !valid_pod_unit(expected_unit) {
        return Err(PodError::Invalid("Codex credential unit name"));
    }
    private_directory(private_pod_directory)?;
    let pod = fs::symlink_metadata(private_pod_directory)?;
    if pod.mode() & 0o7777 != 0o700 {
        return Err(PodError::Refused("Codex pod directory mode changed"));
    }
    if !credentials_directory.is_absolute()
        || credentials_directory
            .file_name()
            .is_none_or(|name| name != expected_unit)
    {
        return Err(PodError::Refused("Codex credential unit path differs"));
    }
    private_directory(credentials_directory)?;
    let directory = fs::symlink_metadata(credentials_directory)?;
    if directory.mode() & 0o7777 != 0o500 || directory.uid() != pod.uid() {
        return Err(PodError::Refused(
            "Codex credential directory mode or owner changed",
        ));
    }

    let mut entries = fs::read_dir(credentials_directory)?;
    let one = entries
        .next()
        .ok_or(PodError::Refused("Codex credential is absent"))??;
    if one.file_name() != CODEX_AUTH_CREDENTIAL_NAME || entries.next().is_some() {
        return Err(PodError::Refused("Codex credential inventory differs"));
    }
    let credential = credentials_directory.join(CODEX_AUTH_CREDENTIAL_NAME);
    let link_metadata = fs::symlink_metadata(&credential)?;
    if !credential_file_is_safe(&link_metadata, directory.uid(), directory.dev()) {
        return Err(PodError::Refused(
            "Codex credential file is not private and regular",
        ));
    }
    let opened = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&credential)?;
    let handle_metadata = opened.metadata()?;
    if !credential_file_is_safe(&handle_metadata, directory.uid(), directory.dev())
        || (link_metadata.dev(), link_metadata.ino())
            != (handle_metadata.dev(), handle_metadata.ino())
    {
        return Err(PodError::Refused(
            "Codex credential file changed during inspection",
        ));
    }

    let private_slot = codex_private_slot_directory(
        private_pod_directory, expected_unit, true,
    )?;
    let isolated_home = private_slot.join("home");
    let codex_home = isolated_home.join("codex");
    ensure_private_child(&isolated_home)?;
    ensure_private_child(&codex_home)?;
    let credential_reference = codex_home.join(CODEX_AUTH_CREDENTIAL_NAME);
    match fs::symlink_metadata(&credential_reference) {
        Ok(metadata) => {
            if !metadata.file_type().is_symlink()
                || fs::read_link(&credential_reference)? != credential
            {
                return Err(PodError::Conflict("Codex credential reference changed"));
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            symlink(&credential, &credential_reference)?;
        }
        Err(error) => return Err(error.into()),
    }
    if fs::read_link(&credential_reference)? != credential {
        return Err(PodError::Refused("Codex credential reference changed"));
    }
    Ok(PreparedCodexHome {
        isolated_home,
        codex_home,
        credential_reference,
    })
}

fn valid_pod_unit(value: &str) -> bool {
    value
        .strip_prefix("podbay-pod-")
        .and_then(|suffix| suffix.strip_suffix(".service"))
        .is_some_and(|stem| {
            stem.len() == 32
                && stem
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn credential_file_is_safe(metadata: &fs::Metadata, uid: u32, dev: u64) -> bool {
    metadata.file_type().is_file()
        && metadata.mode() & 0o7777 == 0o400
        && metadata.uid() == uid
        && metadata.dev() == dev
        && metadata.nlink() == 1
        && (1..=MAX_CREDENTIAL_BYTES).contains(&metadata.len())
}

fn ensure_private_child(path: &Path) -> Result<(), PodError> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    private_directory(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.mode() & 0o7777 != 0o700 {
        return Err(PodError::Refused("Codex home directory mode changed"));
    }
    Ok(())
}
