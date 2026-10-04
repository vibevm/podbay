use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::manifest::{LaunchDescriptor, PodError, hex, manifest_path};
use crate::ports::DurableFiles;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MacManifest {
    pub descriptor: LaunchDescriptor,
    pub pod_binary: PathBuf,
    pub digest: String,
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub viewer_token: Option<String>,
    pub socket_path: PathBuf,
    pub plist_path: PathBuf,
    pub label: String,
    pub bootstrap_domain: String,
    pub plist_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MacStatus {
    pub protocol: String,
    pub pod_id: String,
    pub attempt_id: String,
    pub incarnation: u64,
    pub manifest_digest: String,
    pub supervisor_pid: u32,
    pub supervisor_start: String,
    pub child_pid: u32,
    pub child_start: String,
    pub label: String,
    pub bootstrap_domain: String,
    pub plist_digest: String,
    pub child_running: bool,
    pub exit_code: Option<i32>,
}

pub(super) fn private_directory(directory: &Path) -> Result<(), PodError> {
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.file_type().is_dir()
        || !directory.is_absolute()
        || fs::canonicalize(directory)? != directory
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != podbay_macos_sys::effective_uid()
    {
        return Err(PodError::Invalid(
            "macOS pod directory is not owned, private, absolute, and symlink-free",
        ));
    }
    Ok(())
}

pub(super) fn slot_label(path: &Path) -> Result<String, PodError> {
    let stem = path
        .file_stem()
        .and_then(|v| v.to_str())
        .ok_or(PodError::Invalid("manifest filename"))?;
    if stem.len() != 32 || !stem.bytes().all(|v| v.is_ascii_hexdigit()) {
        return Err(PodError::Invalid("manifest filename"));
    }
    Ok(format!("org.vibevm.podbay.pod.{stem}"))
}

pub(super) fn bootstrap_domain() -> String {
    format!("gui/{}", podbay_macos_sys::effective_uid())
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub(super) fn plist_bytes(
    label: &str,
    binary: &Path,
    manifest: &Path,
) -> Result<Vec<u8>, PodError> {
    let binary = binary
        .to_str()
        .ok_or(PodError::Invalid("pod binary path is not UTF-8"))?;
    let manifest = manifest
        .to_str()
        .ok_or(PodError::Invalid("manifest path is not UTF-8"))?;
    if !binary.starts_with('/') || !manifest.starts_with('/') {
        return Err(PodError::Invalid("launchd paths must be absolute"));
    }
    // KeepAlive=false forbids a hidden replacement execution after a crash.
    // This user agent is confined to the current login session.
    Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{}</string>\n<key>ProgramArguments</key><array><string>{}</string><string>serve</string><string>--manifest</string><string>{}</string></array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><false/>\n<key>AbandonProcessGroup</key><false/>\n</dict></plist>\n", xml_escape(label), xml_escape(binary), xml_escape(manifest)).into_bytes())
}

pub(super) fn plist_digest(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"podbay-macos-plist/1\0");
    hash.update(bytes);
    hex(&hash.finalize())
}

pub(super) fn read_manifest(path: &Path) -> Result<MacManifest, PodError> {
    private_directory(path.parent().ok_or(PodError::Invalid("manifest parent"))?)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != podbay_macos_sys::effective_uid()
        || metadata.len() > 65_536
    {
        return Err(PodError::Invalid(
            "manifest is not owned, private, regular, and bounded",
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let manifest: MacManifest = serde_json::from_slice(&bytes)?;
    manifest.descriptor.validate()?;
    let expected_plist = plist_bytes(&manifest.label, &manifest.pod_binary, path)?;
    if manifest.digest != manifest.descriptor.digest()?
        || !manifest.pod_binary.is_absolute()
        || !valid_token(&manifest.token)
        || (manifest.descriptor.pty.is_some() != manifest.viewer_token.is_some())
        || manifest
            .viewer_token
            .as_deref()
            .is_some_and(|v| !valid_token(v))
        || manifest.socket_path != path.with_extension("sock")
        || manifest.plist_path != path.with_extension("plist")
        || manifest.label != slot_label(path)?
        || manifest.bootstrap_domain != bootstrap_domain()
        || manifest_path(
            path.parent().ok_or(PodError::Invalid("manifest parent"))?,
            &manifest.descriptor,
        )? != path
    {
        return Err(PodError::Invalid(
            "macOS manifest identity or digest changed",
        ));
    }
    let mut plist = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&manifest.plist_path)?;
    let metadata = plist.metadata()?;
    if !metadata.is_file()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != podbay_macos_sys::effective_uid()
        || metadata.len() > 65_536
    {
        return Err(PodError::Invalid(
            "launchd plist is not owned, private, regular, and bounded",
        ));
    }
    let mut plist_bytes = Vec::new();
    plist.read_to_end(&mut plist_bytes)?;
    if plist_bytes != expected_plist || plist_digest(&plist_bytes) != manifest.plist_digest {
        return Err(PodError::Invalid("launchd plist digest changed"));
    }
    Ok(manifest)
}

fn valid_token(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|v| v.is_ascii_hexdigit())
}

pub(super) struct MacDurableFiles;

impl DurableFiles for MacDurableFiles {
    fn create_private(&self, path: &Path, bytes: &[u8]) -> Result<(), PodError> {
        let parent = path
            .parent()
            .ok_or(PodError::Invalid("durable file parent"))?;
        private_directory(parent)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        file.write_all(bytes)
            .map_err(|_| PodError::Uncertain("private file write outcome unknown"))?;
        podbay_macos_sys::full_sync(&file)
            .map_err(|_| PodError::Uncertain("private file full sync outcome unknown"))?;
        sync_parent(parent)?;
        Ok(())
    }
    fn append_durable(&self, path: &Path, bytes: &[u8]) -> Result<(), PodError> {
        let parent = path
            .parent()
            .ok_or(PodError::Invalid("durable file parent"))?;
        private_directory(parent)?;
        let mut file = OpenOptions::new()
            .append(true)
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != podbay_macos_sys::effective_uid()
        {
            return Err(PodError::Invalid(
                "durable file is not owned, private, and regular",
            ));
        }
        file.write_all(bytes)
            .map_err(|_| PodError::Uncertain("durable append outcome unknown"))?;
        podbay_macos_sys::full_sync(&file)
            .map_err(|_| PodError::Uncertain("durable append full sync outcome unknown"))?;
        Ok(())
    }
    fn replace_durable(&self, path: &Path, bytes: &[u8]) -> Result<(), PodError> {
        let temporary = path.with_extension("podbay-new");
        self.create_private(&temporary, bytes)?;
        fs::rename(&temporary, path)
            .map_err(|_| PodError::Uncertain("durable replace outcome unknown"))?;
        sync_parent(
            path.parent()
                .ok_or(PodError::Invalid("durable file parent"))?,
        )?;
        Ok(())
    }
}

fn sync_parent(parent: &Path) -> Result<(), PodError> {
    let directory = File::open(parent)?;
    podbay_macos_sys::full_sync(&directory)
        .map_err(|_| PodError::Uncertain("directory full sync outcome unknown"))
}
