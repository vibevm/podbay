//! PB27d NTFS-only append and immutable checkpoint facade. No rename is an
//! authority step, and any ambiguous write/flush fences this instance.
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_BEGIN, FILE_END,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_DATA, FileAttributeTagInfo, FlushFileBuffers,
    GetFileInformationByHandle, GetFileInformationByHandleEx, GetFileSizeEx,
    GetVolumeInformationByHandleW, OPEN_EXISTING, ReadFile, SYNCHRONIZE, SetFilePointerEx,
    WriteFile,
};
use windows_sys::Win32::System::SystemServices::FILE_PERSISTENT_ACLS;

use crate::Win32Error;
use crate::durable_model::{
    self, CheckpointRecovery, DurabilityEvidence, FlushReceipt, MAX_LOG, Record, RecordKind,
    Unknown, WriteFence,
};
use crate::security::directory_descriptor;
use crate::windows::OwnedHandle;

pub struct DurableDirectory {
    root: PathBuf,
    directory: OwnedHandle,
    volume_serial: u32,
    event_log: OwnedHandle,
    commit_log: OwnedHandle,
    last_event: u64,
    last_commit: u64,
    write_fence: WriteFence,
}
impl DurableDirectory {
    /// Creates one new private NTFS directory and two append-only logs.
    /// Existing/partially created slots are never silently adopted.
    pub fn create(root: &Path) -> Result<Self, Win32Error> {
        validate_root(root, false)?;
        let parent = root
            .parent()
            .ok_or(Win32Error::Invalid("durable parent absent"))?;
        let (_, parent_volume) = open_directory(parent)?;
        let descriptor = directory_descriptor()?;
        let attrs = security_attributes(descriptor.raw());
        let wide = wide(root)?;
        // SAFETY: root path and explicit protected DACL live through the call.
        if unsafe { CreateDirectoryW(wide.as_ptr(), &attrs) } == 0 {
            return Err(Win32Error::Os(io::Error::last_os_error()));
        }
        let (directory, volume_serial) = open_directory(root)
            .map_err(|_| Win32Error::Uncertain("created directory could not be attested"))?;
        if volume_serial != parent_volume {
            return Err(Win32Error::Uncertain(
                "created directory crossed parent volume",
            ));
        }
        let mut event_log = create_file(&root.join("event.wal"), volume_serial)
            .map_err(|_| Win32Error::Uncertain("event log creation outcome unknown"))?;
        write_and_flush(&mut event_log, &[])?;
        let mut commit_log = create_file(&root.join("commit.wal"), volume_serial)
            .map_err(|_| Win32Error::Uncertain("commit log creation outcome unknown"))?;
        write_and_flush(&mut commit_log, &[])?;
        Ok(Self {
            root: root.to_path_buf(),
            directory,
            volume_serial,
            event_log,
            commit_log,
            last_event: 0,
            last_commit: 0,
            write_fence: WriteFence::default(),
        })
    }

    /// Reopen after a manager/pod restart. Corrupt logs refuse mutation; the
    /// caller can still inspect raw files through a separate forensic path.
    pub fn reopen(root: &Path) -> Result<Self, Win32Error> {
        validate_root(root, true)?;
        let (directory, volume_serial) = open_directory(root)?;
        let mut event_log = open_file(&root.join("event.wal"), volume_serial)?;
        let mut commit_log = open_file(&root.join("commit.wal"), volume_serial)?;
        let events = read_all(&mut event_log)?;
        let commits = read_all(&mut commit_log)?;
        let event_rows = durable_model::decode_log(&events, RecordKind::Event, Some(1))
            .map_err(|_| Win32Error::Uncertain("event log gap or corruption"))?;
        let commit_rows = durable_model::decode_log(&commits, RecordKind::Commit, None)
            .map_err(|_| Win32Error::Uncertain("checkpoint commit log corrupt"))?;
        Ok(Self {
            root: root.to_path_buf(),
            directory,
            volume_serial,
            event_log,
            commit_log,
            last_event: event_rows.last().map_or(0, |record| record.sequence),
            last_commit: commit_rows.last().map_or(0, |record| record.sequence),
            write_fence: WriteFence::default(),
        })
    }

    /// Return provisional flush evidence only after FlushFileBuffers succeeds.
    /// This is not a production power-loss receipt or input acceptance.
    pub fn append_event(
        &mut self,
        sequence: u64,
        bytes: &[u8],
    ) -> Result<FlushReceipt, Win32Error> {
        self.healthy()?;
        if sequence != self.last_event.saturating_add(1) {
            return Err(Win32Error::Invalid("event sequence is not contiguous"));
        }
        let frame = Record {
            kind: RecordKind::Event,
            sequence,
            payload: bytes.to_vec(),
        }
        .encode()
        .map_err(Win32Error::Invalid)?;
        if let Err(error) = append_and_flush(&mut self.event_log, &frame) {
            self.write_fence.mark_uncertain();
            return Err(error);
        }
        self.last_event = sequence;
        Ok(FlushReceipt {
            sequence,
            evidence: DurabilityEvidence::ProvisionalNtfsFlush,
        })
    }

    /// Immutable generation is flushed first. Only a separately flushed
    /// checksum commit record makes it eligible for recovery.
    pub fn checkpoint(&mut self, sequence: u64, screen: &[u8]) -> Result<FlushReceipt, Win32Error> {
        self.healthy()?;
        if sequence <= self.last_commit || sequence > self.last_event {
            return Err(Win32Error::Invalid(
                "checkpoint watermark outside committed events",
            ));
        }
        let generation = Record {
            kind: RecordKind::Snapshot,
            sequence,
            payload: screen.to_vec(),
        }
        .encode()
        .map_err(Win32Error::Invalid)?;
        let path = self.generation_path(sequence);
        let mut file = match create_file(&path, self.volume_serial) {
            Ok(file) => file,
            Err(_) => {
                self.write_fence.mark_uncertain();
                return Err(Win32Error::Uncertain(
                    "checkpoint generation creation outcome unknown",
                ));
            }
        };
        if let Err(error) = write_and_flush(&mut file, &generation) {
            self.write_fence.mark_uncertain();
            return Err(error);
        }
        drop(file);
        let commit = Record {
            kind: RecordKind::Commit,
            sequence,
            payload: durable_model::digest(&generation).to_vec(),
        }
        .encode()
        .map_err(Win32Error::Invalid)?;
        if let Err(error) = append_and_flush(&mut self.commit_log, &commit) {
            self.write_fence.mark_uncertain();
            return Err(error);
        }
        self.last_commit = sequence;
        Ok(FlushReceipt {
            sequence,
            evidence: DurabilityEvidence::ProvisionalNtfsFlush,
        })
    }

    /// A corrupt/torn commit or referenced generation is Unknown, never the
    /// previous checkpoint silently promoted as current.
    pub fn recover_checkpoint(&mut self) -> CheckpointRecovery {
        if self.write_fence.is_uncertain() {
            return CheckpointRecovery::Unknown(Unknown {
                last_valid_sequence: Some(self.last_commit).filter(|value| *value > 0),
                gap_at: None,
                reason: "prior file effect or flush uncertain",
            });
        }
        let commits = match read_all(&mut self.commit_log) {
            Ok(bytes) => bytes,
            Err(_) => {
                return CheckpointRecovery::Unknown(Unknown {
                    last_valid_sequence: None,
                    gap_at: None,
                    reason: "commit log read failed",
                });
            }
        };
        durable_model::recover_checkpoint(&commits, |sequence| {
            let mut file = open_file(&self.generation_path(sequence), self.volume_serial).ok()?;
            read_all(&mut file).ok()
        })
    }

    pub fn read_events(&mut self, expected_start: u64) -> Result<Vec<Record>, Unknown> {
        if self.write_fence.is_uncertain() {
            return Err(Unknown {
                last_valid_sequence: None,
                gap_at: Some(expected_start),
                reason: "prior file effect or flush uncertain",
            });
        }
        let bytes = read_all(&mut self.event_log).map_err(|_| Unknown {
            last_valid_sequence: None,
            gap_at: Some(expected_start),
            reason: "event log read failed",
        })?;
        durable_model::decode_log(&bytes, RecordKind::Event, Some(expected_start))
    }

    fn generation_path(&self, sequence: u64) -> PathBuf {
        self.root.join(format!("checkpoint-{sequence:016x}.bin"))
    }
    fn healthy(&self) -> Result<(), Win32Error> {
        if !self.write_fence.permits_ack() {
            return Err(Win32Error::Uncertain(
                "prior file effect or flush uncertain",
            ));
        }
        verify_handle(&self.directory, Some(self.volume_serial))?;
        Ok(())
    }
    pub fn volume_serial(&self) -> u32 {
        self.volume_serial
    }
}

fn security_attributes(descriptor: *mut std::ffi::c_void) -> SECURITY_ATTRIBUTES {
    let mut attrs = SECURITY_ATTRIBUTES::default();
    attrs.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
    attrs.lpSecurityDescriptor = descriptor;
    attrs.bInheritHandle = 0;
    attrs
}
fn validate_root(root: &Path, existing: bool) -> Result<(), Win32Error> {
    if !root.is_absolute() || root.to_string_lossy().starts_with(r"\\") {
        return Err(Win32Error::Unsupported(
            "durable directory must be local absolute path",
        ));
    }
    if !existing && root.exists() {
        return Err(Win32Error::Unsupported("durable directory already exists"));
    }
    let ancestors = if existing {
        root.ancestors()
    } else {
        root.parent()
            .ok_or(Win32Error::Invalid("durable parent absent"))?
            .ancestors()
    };
    for path in ancestors {
        let meta = std::fs::symlink_metadata(path).map_err(Win32Error::Os)?;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Win32Error::Unsupported(
                "durable path has a reparse ancestor",
            ));
        }
    }
    Ok(())
}
fn wide(path: &Path) -> Result<Vec<u16>, Win32Error> {
    let mut value = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if value.contains(&0) {
        return Err(Win32Error::Invalid("durable path has NUL"));
    }
    value.push(0);
    Ok(value)
}
fn open_directory(root: &Path) -> Result<(OwnedHandle, u32), Win32Error> {
    let path = wide(root)?;
    // SAFETY: exact path is NUL-terminated. OPEN_REPARSE_POINT prevents final
    // junction/symlink traversal, and BACKUP_SEMANTICS opens a directory.
    let raw = unsafe {
        CreateFileW(
            path.as_ptr(),
            FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            0,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(Win32Error::Os(io::Error::last_os_error()));
    }
    let handle = OwnedHandle::new(raw)?;
    let serial = verify_handle(&handle, None)?;
    let mut fs_name = [0_u16; 32];
    let mut flags = 0_u32;
    // SAFETY: owned directory handle and writable buffers live through call.
    let okay = unsafe {
        GetVolumeInformationByHandleW(
            handle.raw(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &mut flags,
            fs_name.as_mut_ptr(),
            fs_name.len() as u32,
        )
    };
    if okay == 0 {
        return Err(Win32Error::Os(io::Error::last_os_error()));
    }
    let length = fs_name
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(fs_name.len());
    if String::from_utf16_lossy(&fs_name[..length]) != "NTFS" || flags & FILE_PERSISTENT_ACLS == 0 {
        return Err(Win32Error::Unsupported(
            "durable backend requires NTFS persistent ACLs",
        ));
    }
    Ok((handle, serial))
}
fn verify_handle(handle: &OwnedHandle, expected_volume: Option<u32>) -> Result<u32, Win32Error> {
    let mut tag = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: initialized attribute-tag output lives through call.
    let okay = unsafe {
        GetFileInformationByHandleEx(
            handle.raw(),
            FileAttributeTagInfo,
            (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if okay == 0 {
        return Err(Win32Error::Os(io::Error::last_os_error()));
    }
    if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(Win32Error::Unsupported("durable file is a reparse point"));
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: initialized file-info output lives through call.
    if unsafe { GetFileInformationByHandle(handle.raw(), &mut info) } == 0 {
        return Err(Win32Error::Os(io::Error::last_os_error()));
    }
    if expected_volume.is_some_and(|volume| volume != info.dwVolumeSerialNumber) {
        return Err(Win32Error::Unsupported(
            "durable file crossed volume boundary",
        ));
    }
    Ok(info.dwVolumeSerialNumber)
}
fn create_file(path: &Path, volume: u32) -> Result<OwnedHandle, Win32Error> {
    let descriptor = directory_descriptor()?;
    let attrs = security_attributes(descriptor.raw());
    let wide = wide(path)?;
    // SAFETY: CREATE_NEW refuses an existing/reparse final path; explicit DACL
    // and no-inherit attributes live through the call.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
            0,
            &attrs,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(Win32Error::Os(io::Error::last_os_error()));
    }
    let handle = OwnedHandle::new(raw)?;
    verify_handle(&handle, Some(volume))?;
    Ok(handle)
}
fn open_file(path: &Path, volume: u32) -> Result<OwnedHandle, Win32Error> {
    let wide = wide(path)?;
    // SAFETY: final reparse point is opened as itself, never followed.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
            0,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(Win32Error::Os(io::Error::last_os_error()));
    }
    let handle = OwnedHandle::new(raw)?;
    verify_handle(&handle, Some(volume))?;
    Ok(handle)
}
fn write_and_flush(handle: &mut OwnedHandle, bytes: &[u8]) -> Result<(), Win32Error> {
    let mut remaining = bytes;
    while !remaining.is_empty() {
        let mut written = 0_u32;
        // SAFETY: owned file handle and byte slice live through synchronous write.
        let okay = unsafe {
            WriteFile(
                handle.raw(),
                remaining.as_ptr(),
                remaining.len() as u32,
                &mut written,
                null_mut(),
            )
        };
        if okay == 0 || written == 0 {
            return Err(Win32Error::Uncertain(
                "durable file may be partially written",
            ));
        }
        remaining = &remaining[written as usize..];
    }
    // SAFETY: FlushFileBuffers acts on the same owned file handle, before ack.
    if unsafe { FlushFileBuffers(handle.raw()) } == 0 {
        return Err(Win32Error::Uncertain("durable file flush outcome unknown"));
    }
    Ok(())
}
fn append_and_flush(handle: &mut OwnedHandle, bytes: &[u8]) -> Result<(), Win32Error> {
    let mut size = 0_i64;
    // SAFETY: owned file handle and writable size output live through call.
    if unsafe { GetFileSizeEx(handle.raw(), &mut size) } == 0 {
        return Err(Win32Error::Uncertain("durable append size unknown"));
    }
    if size < 0 || (size as usize).saturating_add(bytes.len()) > MAX_LOG {
        return Err(Win32Error::Unsupported("durable log byte bound reached"));
    }
    // SAFETY: single-writer handle with no sharing; position moves to current end.
    if unsafe { SetFilePointerEx(handle.raw(), 0, null_mut(), FILE_END) } == 0 {
        return Err(Win32Error::Uncertain("durable append position unknown"));
    }
    write_and_flush(handle, bytes)
}
fn read_all(handle: &mut OwnedHandle) -> Result<Vec<u8>, Win32Error> {
    let mut size = 0_i64;
    // SAFETY: owned file handle and writable size output live through call.
    if unsafe { GetFileSizeEx(handle.raw(), &mut size) } == 0 {
        return Err(Win32Error::Os(io::Error::last_os_error()));
    }
    if size < 0 || size as usize > MAX_LOG {
        return Err(Win32Error::Unsupported("durable log byte bound"));
    }
    // SAFETY: single-writer handle is repositioned for bounded observation.
    if unsafe { SetFilePointerEx(handle.raw(), 0, null_mut(), FILE_BEGIN) } == 0 {
        return Err(Win32Error::Os(io::Error::last_os_error()));
    }
    let mut bytes = vec![0_u8; size as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        let mut read = 0_u32;
        // SAFETY: owned file handle and writable slice live through sync read.
        let okay = unsafe {
            ReadFile(
                handle.raw(),
                bytes[offset..].as_mut_ptr(),
                (bytes.len() - offset) as u32,
                &mut read,
                null_mut(),
            )
        };
        if okay == 0 || read == 0 {
            return Err(Win32Error::Uncertain("durable file read truncated"));
        }
        offset += read as usize;
    }
    Ok(bytes)
}
