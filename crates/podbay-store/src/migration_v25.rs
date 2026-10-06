use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::backup::Backup;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{PodBayStore, StoreError};

const SOURCE_SCHEMA_VERSION: i64 = 24;
const STAGING_SCHEMA_VERSION: i64 = 25;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V25PreservedTable {
    pub name: String,
    pub row_count: u64,
    pub max_rowid: i64,
    pub content_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V25SequenceHighWater {
    pub table: String,
    pub sequence: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V25StagingResult {
    pub source_path: PathBuf,
    pub staging_path: PathBuf,
    pub store_lineage: String,
    pub source_schema_version: i64,
    pub staging_schema_version: i64,
    pub preserved_tables: Vec<V25PreservedTable>,
    pub sequence_high_water: Vec<V25SequenceHighWater>,
    #[cfg(unix)]
    exchange: ExchangeAttestation,
}

/// Verified orientation of the exact staged pair, not a durable migration receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V25ExchangeOrientation {
    Unpublished,
    Published,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeAttestation {
    source_path: PathBuf,
    staging_path: PathBuf,
    parent_identity: FileIdentity,
    source_identity: FileIdentity,
    staging_identity: FileIdentity,
    source: StoreSnapshot,
    staging: StoreSnapshot,
}

impl V25StagingResult {
    /// Reject staging at canonical-source metadata or SQLite companion entries.
    /// This read-only namespace check also applies to older/recovered attestations.
    pub fn verify_exchange_namespace(&self) -> Result<(), V25StagingError> {
        reject_reserved_staging_path(&self.source_path, &self.staging_path)
    }

    /// Revalidate a sidecar-free, non-WAL pair under an externally maintained
    /// manager lock and reader/writer exclusion. This method only reads files;
    /// it does not acquire exclusion or authorize publication.
    pub fn verify_exchange_orientation(&self) -> Result<V25ExchangeOrientation, V25StagingError> {
        #[cfg(not(unix))]
        return Err(V25StagingError::Safety(
            "exchange verification requires Unix",
        ));
        #[cfg(unix)]
        {
            self.verify_exchange_namespace()?;
            refuse_activation_direction(&self.source_path)?;
            let proof = &self.exchange;
            verify_parent_identity(&proof.source_path, proof.parent_identity)?;
            if self.source_path != proof.source_path || self.staging_path != proof.staging_path {
                return Err(V25StagingError::Safety("staged pair paths were changed"));
            }
            reject_exchange_sidecars(&proof.source_path)?;
            reject_exchange_sidecars(&proof.staging_path)?;
            let source_identity = private_file_identity(&proof.source_path, false)?;
            let staging_identity = private_file_identity(&proof.staging_path, false)?;
            let (orientation, expected_source, expected_staging) = if source_identity
                == proof.source_identity
                && staging_identity == proof.staging_identity
            {
                (
                    V25ExchangeOrientation::Unpublished,
                    &proof.source,
                    &proof.staging,
                )
            } else if source_identity == proof.staging_identity
                && staging_identity == proof.source_identity
            {
                (
                    V25ExchangeOrientation::Published,
                    &proof.staging,
                    &proof.source,
                )
            } else {
                return Err(V25StagingError::Safety(
                    "staged pair inode orientation changed",
                ));
            };
            for (path, expected) in [
                (&proof.source_path, expected_source),
                (&proof.staging_path, expected_staging),
            ] {
                let connection = open_exchange_read_only(path)?;
                let journal_mode: String =
                    connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
                if journal_mode != "delete" {
                    return Err(V25StagingError::Safety(
                        "exchange requires DELETE journal mode",
                    ));
                }
                verify_integrity(&connection)?;
                verify_foreign_keys(&connection)?;
                verify_current_v2_bindings(&connection)?;
                if expected.version == STAGING_SCHEMA_VERSION {
                    verify_recovery_tables_empty(&connection)?;
                }
                if &snapshot(&connection)? != expected {
                    return Err(V25StagingError::Safety(
                        "staged pair exact snapshot changed",
                    ));
                }
            }
            reject_exchange_sidecars(&proof.source_path)?;
            reject_exchange_sidecars(&proof.staging_path)?;
            if private_file_identity(&proof.source_path, false)? != source_identity
                || private_file_identity(&proof.staging_path, false)? != staging_identity
            {
                return Err(V25StagingError::Safety(
                    "staged pair inode changed during verification",
                ));
            }
            verify_parent_identity(&proof.source_path, proof.parent_identity)?;
            Ok(orientation)
        }
    }
}

const INTENT_FORMAT: &str = "podbay.disposable-v25-exchange-intent/1";
const INTENT_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// A reopened intent proves pair orientation only. It is not a terminal receipt,
/// a reader-exclusion capability, or permission to open schema 25 normally.
#[cfg(unix)]
#[derive(Debug)]
pub struct V25RecoveredIntent {
    pub intent_path: PathBuf,
    pub orientation: V25ExchangeOrientation,
    staged: V25StagingResult,
}

#[cfg(unix)]
impl V25RecoveredIntent {
    pub fn staged(&self) -> &V25StagingResult {
        &self.staged
    }
}

#[cfg(unix)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableIntent {
    format: String,
    key: String,
    attestation: ExchangeAttestation,
    attestation_digest: String,
}

#[cfg(unix)]
fn intent_paths(source: &Path, key: &str) -> Result<(PathBuf, PathBuf), V25StagingError> {
    if key.is_empty() || key.len() > 256 || key.chars().any(char::is_control) {
        return Err(V25StagingError::InvalidInput(
            "migration key is empty, oversized or contains control characters",
        ));
    }
    let mut name = source
        .file_name()
        .ok_or(V25StagingError::InvalidInput("source filename missing"))?
        .to_os_string();
    name.push(".v25-intent.json");
    let intent = source.with_file_name(name);
    let mut writing = intent.as_os_str().to_os_string();
    writing.push(".writing");
    Ok((intent, PathBuf::from(writing)))
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(unix)]
fn attestation_digest(
    key: &str,
    attestation: &ExchangeAttestation,
) -> Result<String, V25StagingError> {
    // Bind the format, key, both exact paths/identities and complete snapshots.
    let bytes = serde_json::to_vec(&(INTENT_FORMAT, key, attestation))?;
    Ok(hex_digest(&bytes))
}

#[cfg(unix)]
fn refuse_occupied(path: &Path) -> Result<(), V25StagingError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(V25StagingError::Safety(
            "partial or foreign migration intent companion exists",
        )),
    }
}

#[cfg(unix)]
fn private_parent_identity(path: &Path) -> Result<FileIdentity, V25StagingError> {
    let parent = path
        .parent()
        .ok_or(V25StagingError::InvalidInput("private path has no parent"))?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700
        || fs::canonicalize(parent)? != parent
    {
        return Err(V25StagingError::Safety(
            "migration parent is not private and canonical",
        ));
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn verify_parent_identity(path: &Path, expected: FileIdentity) -> Result<(), V25StagingError> {
    if private_parent_identity(path)? != expected {
        return Err(V25StagingError::Safety("migration parent identity changed"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntentSyncPoint {
    WritingFile,
    PublishedFile,
    ParentDirectory,
}

#[cfg(target_os = "linux")]
fn pinned_parent_directory(path: &Path, expected: FileIdentity) -> Result<File, V25StagingError> {
    verify_parent_identity(path, expected)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc_no_follow() | nix::libc::O_DIRECTORY)
        .open(path.parent().expect("verified source parent"))?;
    let metadata = directory.metadata()?;
    if (metadata.dev(), metadata.ino()) != (expected.device, expected.inode) {
        return Err(V25StagingError::Safety(
            "opened migration parent identity changed",
        ));
    }
    Ok(directory)
}

impl V25StagingResult {
    /// Persist a complete reviewed pair attestation before the caller's exchange.
    /// Requires the same externally held manager lock and maintained exclusion
    /// as orientation verification. Failed/partial writes are retained and refused;
    /// this helper neither exchanges nor rebuilds staging.
    #[cfg(target_os = "linux")]
    pub fn persist_exchange_intent(&self, key: &str) -> Result<PathBuf, V25StagingError> {
        self.persist_exchange_intent_with_sync(key, |file, _point| file.sync_all())
    }

    #[cfg(target_os = "linux")]
    fn persist_exchange_intent_with_sync(
        &self,
        key: &str,
        mut sync: impl FnMut(&File, IntentSyncPoint) -> std::io::Result<()>,
    ) -> Result<PathBuf, V25StagingError> {
        use std::io::Write;
        let (intent_path, writing_path) = intent_paths(&self.source_path, key)?;
        refuse_occupied(&writing_path)?;
        if self.staging_path == intent_path || self.staging_path == writing_path {
            return Err(V25StagingError::Safety(
                "staging aliases a migration intent pathname",
            ));
        }
        match fs::symlink_metadata(&intent_path) {
            Ok(_) => {
                let recovered =
                    recover_schema_v25_intent(&self.source_path, &self.staging_path, key)?;
                if recovered.staged.exchange != self.exchange {
                    return Err(V25StagingError::Safety(
                        "migration key already binds a different attestation",
                    ));
                }
                // A visible rename may precede its directory fsync. Repair both
                // durability barriers on exact-key retry before reporting success.
                let identity = private_file_identity(&intent_path, false)?;
                let file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc_no_follow())
                    .open(&intent_path)?;
                let metadata = file.metadata()?;
                if (metadata.dev(), metadata.ino()) != (identity.device, identity.inode) {
                    return Err(V25StagingError::Safety(
                        "opened migration intent identity changed",
                    ));
                }
                let directory =
                    pinned_parent_directory(&self.source_path, self.exchange.parent_identity)?;
                sync(&file, IntentSyncPoint::PublishedFile)?;
                sync(&directory, IntentSyncPoint::ParentDirectory)?;
                let reverified =
                    recover_schema_v25_intent(&self.source_path, &self.staging_path, key)?;
                if reverified.staged.exchange != self.exchange
                    || private_file_identity(&intent_path, false)? != identity
                {
                    return Err(V25StagingError::Safety(
                        "migration intent changed during durability repair",
                    ));
                }
                return Ok(intent_path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if self.verify_exchange_orientation()? != V25ExchangeOrientation::Unpublished {
            return Err(V25StagingError::Safety(
                "cannot originate an intent after publication",
            ));
        }
        let record = DurableIntent {
            format: INTENT_FORMAT.to_owned(),
            key: key.to_owned(),
            attestation: self.exchange.clone(),
            attestation_digest: attestation_digest(key, &self.exchange)?,
        };
        let bytes = serde_json::to_vec(&record)?;
        if bytes.len() as u64 > INTENT_MAX_BYTES {
            return Err(V25StagingError::Safety(
                "migration intent exceeds bounded encoding",
            ));
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc_no_follow())
            .open(&writing_path)?;
        file.write_all(&bytes)?;
        sync(&file, IntentSyncPoint::WritingFile)?;
        drop(file);
        private_file_identity(&writing_path, false)?;
        verify_parent_identity(&self.source_path, self.exchange.parent_identity)?;
        let directory = pinned_parent_directory(&self.source_path, self.exchange.parent_identity)?;
        rustix::fs::renameat_with(
            &directory,
            writing_path.file_name().expect("writing filename"),
            &directory,
            intent_path.file_name().expect("intent filename"),
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(std::io::Error::from)?;
        sync(&directory, IntentSyncPoint::ParentDirectory)?;
        // Reopen exactly what was published; a successful return proves both
        // the durable intent and a currently unchanged reviewed pair.
        recover_schema_v25_intent(&self.source_path, &self.staging_path, key)?;
        Ok(intent_path)
    }
}

/// Fresh-open reconstruction, with no reliance on a caller's old in-memory
/// staging result or last phase flag. The caller must hold the original manager
/// lock and maintained reader/writer exclusion. This function never exchanges,
/// writes SQLite, creates a terminal receipt or authorizes ordinary v25 open.
#[cfg(unix)]
pub fn recover_schema_v25_intent(
    source_path: impl AsRef<Path>,
    staging_path: impl AsRef<Path>,
    key: &str,
) -> Result<V25RecoveredIntent, V25StagingError> {
    use std::io::Read;
    let source_path = source_path.as_ref();
    let staging_path = staging_path.as_ref();
    let (intent_path, writing_path) = intent_paths(source_path, key)?;
    refuse_occupied(&writing_path)?;
    let identity = private_file_identity(&intent_path, false)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc_no_follow())
        .open(&intent_path)?;
    let metadata = file.metadata()?;
    if (metadata.dev(), metadata.ino()) != (identity.device, identity.inode)
        || metadata.len() > INTENT_MAX_BYTES
    {
        return Err(V25StagingError::Safety(
            "migration intent changed or exceeds bounded encoding",
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(INTENT_MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > INTENT_MAX_BYTES {
        return Err(V25StagingError::Safety(
            "migration intent exceeds bounded encoding",
        ));
    }
    let record: DurableIntent = serde_json::from_slice(&bytes)?;
    let proof = record.attestation;
    if record.format != INTENT_FORMAT
        || record.key != key
        || proof.source_path != source_path
        || proof.staging_path != staging_path
        || source_path == staging_path
        || source_path.parent() != staging_path.parent()
        || proof.source.version != SOURCE_SCHEMA_VERSION
        || proof.staging.version != STAGING_SCHEMA_VERSION
        || proof.source.schema != canonical_schema(false)?
        || proof.staging.schema != canonical_schema(true)?
        || record.attestation_digest != attestation_digest(key, &proof)?
    {
        return Err(V25StagingError::Safety(
            "migration intent format, key, paths or attestation mismatch",
        ));
    }
    verify_preserved_snapshot(&proof.source, &proof.staging)?;
    verify_parent_identity(&intent_path, proof.parent_identity)?;
    let staged = V25StagingResult {
        source_path: proof.source_path.clone(),
        staging_path: proof.staging_path.clone(),
        store_lineage: proof.source.lineage.clone(),
        source_schema_version: proof.source.version,
        staging_schema_version: proof.staging.version,
        preserved_tables: proof.source.tables.clone(),
        sequence_high_water: proof.source.sequences.clone(),
        exchange: proof,
    };
    let orientation = staged.verify_exchange_orientation()?;
    if private_file_identity(&intent_path, false)? != identity {
        return Err(V25StagingError::Safety(
            "migration intent inode changed during recovery",
        ));
    }
    Ok(V25RecoveredIntent {
        intent_path,
        orientation,
        staged,
    })
}

const RECEIPT_FORMAT: &str = "podbay.disposable-v25-publication-receipt/1";
const RECEIPT_DISPOSITION: &str = "published_unactivated";

/// A verified publication receipt for a disposable unchanged pair. It certifies
/// neither ordinary v25 activation nor settlement of any historical Pod effect.
#[cfg(unix)]
#[derive(Debug)]
pub struct V25PublicationReceipt {
    pub receipt_path: PathBuf,
    pub intent_digest: String,
    recovered: V25RecoveredIntent,
}

#[cfg(unix)]
impl V25PublicationReceipt {
    pub fn intent(&self) -> &V25RecoveredIntent {
        &self.recovered
    }
}

#[cfg(unix)]
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PublicationReceiptPayload {
    key: String,
    disposition: String,
    intent_digest: String,
    attestation: ExchangeAttestation,
}

#[cfg(unix)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurablePublicationReceipt {
    format: String,
    payload: PublicationReceiptPayload,
    receipt_digest: String,
}

#[cfg(unix)]
fn receipt_paths(source: &Path, key: &str) -> Result<(PathBuf, PathBuf), V25StagingError> {
    // Reuse the checked key contract, with one receipt slot per canonical source.
    intent_paths(source, key)?;
    let mut name = source
        .file_name()
        .ok_or(V25StagingError::InvalidInput("source filename missing"))?
        .to_os_string();
    name.push(".v25-publication-receipt.json");
    let receipt = source.with_file_name(name);
    let mut writing = receipt.as_os_str().to_os_string();
    writing.push(".writing");
    Ok((receipt, PathBuf::from(writing)))
}

#[cfg(unix)]
fn receipt_digest(payload: &PublicationReceiptPayload) -> Result<String, V25StagingError> {
    Ok(hex_digest(&serde_json::to_vec(&(RECEIPT_FORMAT, payload))?))
}

#[cfg(unix)]
fn open_exact_private_file(path: &Path, identity: FileIdentity) -> Result<File, V25StagingError> {
    if private_file_identity(path, false)? != identity {
        return Err(V25StagingError::Safety(
            "private migration file identity changed",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc_no_follow())
        .open(path)?;
    let metadata = file.metadata()?;
    if (metadata.dev(), metadata.ino()) != (identity.device, identity.inode) {
        return Err(V25StagingError::Safety(
            "opened private migration file identity changed",
        ));
    }
    Ok(file)
}

#[cfg(unix)]
fn bounded_private_bytes(path: &Path) -> Result<Vec<u8>, V25StagingError> {
    use std::io::Read;
    let identity = private_file_identity(path, false)?;
    let file = open_exact_private_file(path, identity)?;
    if file.metadata()?.len() > INTENT_MAX_BYTES {
        return Err(V25StagingError::Safety(
            "migration record exceeds bounded encoding",
        ));
    }
    let mut bytes = Vec::new();
    file.take(INTENT_MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > INTENT_MAX_BYTES || private_file_identity(path, false)? != identity {
        return Err(V25StagingError::Safety(
            "migration record changed or exceeds bounded encoding",
        ));
    }
    Ok(bytes)
}

/// Fresh-process verification of receipt, exact intent bytes and current
/// Published pair. The same manager lock and exclusion must be maintained.
/// This function never exchanges, writes, activates v25 or resolves old effects.
#[cfg(unix)]
pub fn recover_schema_v25_receipt(
    source_path: impl AsRef<Path>,
    staging_path: impl AsRef<Path>,
    key: &str,
) -> Result<V25PublicationReceipt, V25StagingError> {
    let source_path = source_path.as_ref();
    let staging_path = staging_path.as_ref();
    let recovered = recover_schema_v25_intent(source_path, staging_path, key)?;
    if recovered.orientation != V25ExchangeOrientation::Published {
        return Err(V25StagingError::Safety(
            "publication receipt requires exact Published orientation",
        ));
    }
    let (receipt_path, writing_path) = receipt_paths(source_path, key)?;
    refuse_occupied(&writing_path)?;
    if staging_path == receipt_path || staging_path == writing_path {
        return Err(V25StagingError::Safety(
            "staging aliases a publication receipt pathname",
        ));
    }
    let identity = private_file_identity(&receipt_path, false)?;
    let bytes = bounded_private_bytes(&receipt_path)?;
    let record: DurablePublicationReceipt = serde_json::from_slice(&bytes)?;
    let intent_digest = hex_digest(&bounded_private_bytes(&recovered.intent_path)?);
    if record.format != RECEIPT_FORMAT
        || record.payload.key != key
        || record.payload.disposition != RECEIPT_DISPOSITION
        || record.payload.intent_digest != intent_digest
        || record.payload.attestation != recovered.staged.exchange
        || record.receipt_digest != receipt_digest(&record.payload)?
    {
        return Err(V25StagingError::Safety(
            "publication receipt format, key, intent or payload mismatch",
        ));
    }
    let reverified = recover_schema_v25_intent(source_path, staging_path, key)?;
    if reverified.orientation != V25ExchangeOrientation::Published
        || reverified.staged.exchange != recovered.staged.exchange
        || hex_digest(&bounded_private_bytes(&reverified.intent_path)?) != intent_digest
        || private_file_identity(&receipt_path, false)? != identity
    {
        return Err(V25StagingError::Safety(
            "publication receipt pair or intent changed during verification",
        ));
    }
    Ok(V25PublicationReceipt {
        receipt_path,
        intent_digest,
        recovered: reverified,
    })
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiptSyncPoint {
    CanonicalFile,
    StagedOldFile,
    PairDirectory,
    WritingReceipt,
    PublishedReceipt,
    ReceiptDirectory,
}

/// Persist a terminal *publication-only* receipt after repairing intent/pair
/// durability. Requires the exact manager lock and maintained reader exclusion.
/// A failure may leave a visible receipt, so only verified fsynced retry succeeds.
#[cfg(target_os = "linux")]
pub fn persist_schema_v25_receipt(
    source_path: impl AsRef<Path>,
    staging_path: impl AsRef<Path>,
    key: &str,
) -> Result<V25PublicationReceipt, V25StagingError> {
    persist_schema_v25_receipt_with_sync(
        source_path.as_ref(),
        staging_path.as_ref(),
        key,
        |file, _| file.sync_all(),
    )
}

#[cfg(target_os = "linux")]
fn persist_schema_v25_receipt_with_sync(
    source_path: &Path,
    staging_path: &Path,
    key: &str,
    mut sync: impl FnMut(&File, ReceiptSyncPoint) -> std::io::Result<()>,
) -> Result<V25PublicationReceipt, V25StagingError> {
    use std::io::Write;
    let recovered = recover_schema_v25_intent(source_path, staging_path, key)?;
    if recovered.orientation != V25ExchangeOrientation::Published {
        return Err(V25StagingError::Safety(
            "publication receipt requires exact Published orientation",
        ));
    }
    let (receipt_path, writing_path) = receipt_paths(source_path, key)?;
    refuse_occupied(&writing_path)?;
    if staging_path == receipt_path || staging_path == writing_path {
        return Err(V25StagingError::Safety(
            "staging aliases a publication receipt pathname",
        ));
    }
    // Repair even a visible intent whose publication directory fsync was lost.
    recovered.staged.persist_exchange_intent(key)?;
    let proof = &recovered.staged.exchange;
    let directory = pinned_parent_directory(source_path, proof.parent_identity)?;
    let canonical = open_exact_private_file(source_path, proof.staging_identity)?;
    let old = open_exact_private_file(staging_path, proof.source_identity)?;
    sync(&canonical, ReceiptSyncPoint::CanonicalFile)?;
    sync(&old, ReceiptSyncPoint::StagedOldFile)?;
    sync(&directory, ReceiptSyncPoint::PairDirectory)?;
    let reverified = recover_schema_v25_intent(source_path, staging_path, key)?;
    if reverified.orientation != V25ExchangeOrientation::Published
        || reverified.staged.exchange != *proof
    {
        return Err(V25StagingError::Safety(
            "Published pair changed during receipt preparation",
        ));
    }
    let payload = PublicationReceiptPayload {
        key: key.to_owned(),
        disposition: RECEIPT_DISPOSITION.to_owned(),
        intent_digest: hex_digest(&bounded_private_bytes(&reverified.intent_path)?),
        attestation: proof.clone(),
    };
    match fs::symlink_metadata(&receipt_path) {
        Ok(_) => {
            let prior = recover_schema_v25_receipt(source_path, staging_path, key)?;
            if prior.intent_digest != payload.intent_digest
                || prior.recovered.staged.exchange != payload.attestation
            {
                return Err(V25StagingError::Safety(
                    "publication receipt already binds different payload",
                ));
            }
            let identity = private_file_identity(&receipt_path, false)?;
            let file = open_exact_private_file(&receipt_path, identity)?;
            sync(&file, ReceiptSyncPoint::PublishedReceipt)?;
            sync(&directory, ReceiptSyncPoint::ReceiptDirectory)?;
            let result = recover_schema_v25_receipt(source_path, staging_path, key)?;
            if result.intent_digest != payload.intent_digest
                || private_file_identity(&receipt_path, false)? != identity
            {
                return Err(V25StagingError::Safety(
                    "publication receipt changed during durability repair",
                ));
            }
            return Ok(result);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let record = DurablePublicationReceipt {
        format: RECEIPT_FORMAT.to_owned(),
        receipt_digest: receipt_digest(&payload)?,
        payload,
    };
    let bytes = serde_json::to_vec(&record)?;
    if bytes.len() as u64 > INTENT_MAX_BYTES {
        return Err(V25StagingError::Safety(
            "publication receipt exceeds bounded encoding",
        ));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc_no_follow())
        .open(&writing_path)?;
    file.write_all(&bytes)?;
    sync(&file, ReceiptSyncPoint::WritingReceipt)?;
    drop(file);
    private_file_identity(&writing_path, false)?;
    verify_parent_identity(source_path, proof.parent_identity)?;
    rustix::fs::renameat_with(
        &directory,
        writing_path.file_name().expect("writing filename"),
        &directory,
        receipt_path.file_name().expect("receipt filename"),
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)?;
    sync(&directory, ReceiptSyncPoint::ReceiptDirectory)?;
    recover_schema_v25_receipt(source_path, staging_path, key)
}

const ACTIVATION_FORMAT: &str = "podbay.disposable-v25-forward-activation/1";
const ACTIVATION_DIRECTION: &str = "forward_only_metadata_readback";

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V25ActivationMetadata {
    pub store_lineage: String,
    pub owner_epoch: u64,
    pub authority_revision: u64,
}

/// Restricted metadata/readback handle, not PodBayStore or a runtime grant.
/// Decoder version 1 allows only monotone authority_revision drift; it forbids
/// new pending/final rows and every other authority mutation. A later versioned
/// current-state decoder is required before exposing any pending or runtime API.
#[cfg(unix)]
#[derive(Debug)]
pub struct DisposableV25ActivatedStore {
    source_path: PathBuf,
    staging_path: PathBuf,
    migration_key: String,
    activation_key: String,
    proof: V25StagingResult,
}

#[cfg(unix)]
impl DisposableV25ActivatedStore {
    pub fn metadata(&self) -> Result<V25ActivationMetadata, V25StagingError> {
        let (_, metadata, _) = read_activation(
            &self.source_path,
            &self.staging_path,
            &self.migration_key,
            &self.activation_key,
        )?;
        Ok(metadata)
    }
    /// Historical pair identities for the host's exact manager-lock namespace
    /// check only. Calling its frozen migration verifier after activation refuses.
    pub fn attested_pair(&self) -> &V25StagingResult {
        &self.proof
    }
}

#[cfg(unix)]
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ActivationMetadataRow {
    rowid: i64,
    key: String,
    value: i64,
}

#[cfg(unix)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationPayload {
    migration_key: String,
    activation_key: String,
    direction: String,
    receipt_path: PathBuf,
    receipt_identity: FileIdentity,
    receipt_bytes_digest: String,
    intent_path: PathBuf,
    intent_identity: FileIdentity,
    intent_bytes_digest: String,
    attestation: ExchangeAttestation,
    initial_metadata: Vec<ActivationMetadataRow>,
}

#[cfg(unix)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableActivation {
    format: String,
    payload: ActivationPayload,
    payload_digest: String,
}

#[cfg(unix)]
fn activation_paths(source: &Path) -> Result<(PathBuf, PathBuf), V25StagingError> {
    let mut name = source
        .file_name()
        .ok_or(V25StagingError::InvalidInput("source filename missing"))?
        .to_os_string();
    name.push(".v25-activation.json");
    let marker = source.with_file_name(name);
    let mut writing = marker.as_os_str().to_os_string();
    writing.push(".writing");
    Ok((marker, PathBuf::from(writing)))
}

#[cfg(unix)]
fn refuse_activation_direction(source: &Path) -> Result<(), V25StagingError> {
    let (marker, writing) = activation_paths(source)?;
    for path in [marker, writing] {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(V25StagingError::Safety(
                    "forward activation exists or is partial; frozen migration exchange is forbidden",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn activation_digest(payload: &ActivationPayload) -> Result<String, V25StagingError> {
    Ok(hex_digest(&serde_json::to_vec(&(
        ACTIVATION_FORMAT,
        payload,
    ))?))
}

#[cfg(unix)]
fn activation_metadata_rows(
    connection: &Connection,
) -> Result<Vec<ActivationMetadataRow>, V25StagingError> {
    let mut statement = connection.prepare("SELECT rowid,key,value FROM metadata ORDER BY key")?;
    Ok(statement
        .query_map([], |row| {
            Ok(ActivationMetadataRow {
                rowid: row.get(0)?,
                key: row.get(1)?,
                value: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?)
}

#[cfg(unix)]
fn activation_proof_result(proof: ExchangeAttestation) -> V25StagingResult {
    V25StagingResult {
        source_path: proof.source_path.clone(),
        staging_path: proof.staging_path.clone(),
        store_lineage: proof.source.lineage.clone(),
        source_schema_version: proof.source.version,
        staging_schema_version: proof.staging.version,
        preserved_tables: proof.source.tables.clone(),
        sequence_high_water: proof.source.sequences.clone(),
        exchange: proof,
    }
}

#[cfg(unix)]
fn decode_activated_current_state(
    payload: &ActivationPayload,
) -> Result<V25ActivationMetadata, V25StagingError> {
    let proof = &payload.attestation;
    verify_parent_identity(&proof.source_path, proof.parent_identity)?;
    reject_reserved_staging_path(&proof.source_path, &proof.staging_path)?;
    for path in [&proof.source_path, &proof.staging_path] {
        reject_exchange_sidecars(path)?;
    }
    open_exact_private_file(&proof.source_path, proof.staging_identity)?;
    open_exact_private_file(&proof.staging_path, proof.source_identity)?;
    let old = open_exchange_read_only(&proof.staging_path)?;
    verify_integrity(&old)?;
    verify_foreign_keys(&old)?;
    verify_current_v2_bindings(&old)?;
    if snapshot(&old)? != proof.source {
        return Err(V25StagingError::Safety(
            "activated old v24 snapshot changed",
        ));
    }
    if activation_metadata_rows(&old)? != payload.initial_metadata {
        return Err(V25StagingError::Safety(
            "activation initial metadata differs from preserved v24",
        ));
    }
    drop(old);
    let current = open_exchange_read_only(&proof.source_path)?;
    verify_integrity(&current)?;
    verify_foreign_keys(&current)?;
    verify_current_v2_bindings(&current)?;
    verify_recovery_tables_empty(&current)?;
    let state = snapshot(&current)?;
    if state.version != STAGING_SCHEMA_VERSION
        || state.lineage != proof.staging.lineage
        || state.schema != canonical_schema(true)?
        || state.schema != proof.staging.schema
        || state.sequences != proof.staging.sequences
        || state
            .tables
            .iter()
            .filter(|table| table.name != "metadata")
            .collect::<Vec<_>>()
            != proof
                .staging
                .tables
                .iter()
                .filter(|table| table.name != "metadata")
                .collect::<Vec<_>>()
    {
        return Err(V25StagingError::Safety(
            "restricted activated v25 schema, lineage or authority state changed",
        ));
    }
    let rows = activation_metadata_rows(&current)?;
    if rows.len() != payload.initial_metadata.len() {
        return Err(V25StagingError::Safety("activated metadata set changed"));
    }
    let mut authority_revision = None;
    let mut owner_epoch = None;
    for (row, initial) in rows.iter().zip(&payload.initial_metadata) {
        if row.rowid != initial.rowid
            || row.key != initial.key
            || (if row.key == "authority_revision" {
                initial.value < 0 || row.value < initial.value
            } else {
                row.value != initial.value
            })
        {
            return Err(V25StagingError::Safety(
                "activated metadata rollback or unsupported mutation",
            ));
        }
        if row.key == "authority_revision" {
            authority_revision = Some(row.value as u64);
        }
        if row.key == "owner_epoch" {
            owner_epoch =
                Some(u64::try_from(row.value).map_err(|_| {
                    V25StagingError::Safety("activated owner metadata is negative")
                })?);
        }
    }
    drop(current);
    verify_parent_identity(&proof.source_path, proof.parent_identity)?;
    for path in [&proof.source_path, &proof.staging_path] {
        reject_exchange_sidecars(path)?;
    }
    open_exact_private_file(&proof.source_path, proof.staging_identity)?;
    open_exact_private_file(&proof.staging_path, proof.source_identity)?;
    Ok(V25ActivationMetadata {
        store_lineage: state.lineage,
        owner_epoch: owner_epoch
            .ok_or(V25StagingError::Safety("activated owner metadata missing"))?,
        authority_revision: authority_revision.ok_or(V25StagingError::Safety(
            "activated revision metadata missing",
        ))?,
    })
}

#[cfg(unix)]
fn read_activation(
    source: &Path,
    staging: &Path,
    migration_key: &str,
    activation_key: &str,
) -> Result<(ActivationPayload, V25ActivationMetadata, FileIdentity), V25StagingError> {
    read_activation_with_decoder(
        source,
        staging,
        migration_key,
        activation_key,
        decode_activated_current_state,
    )
}

#[cfg(unix)]
fn read_activation_with_decoder(
    source: &Path,
    staging: &Path,
    migration_key: &str,
    activation_key: &str,
    decoder: impl FnOnce(&ActivationPayload) -> Result<V25ActivationMetadata, V25StagingError>,
) -> Result<(ActivationPayload, V25ActivationMetadata, FileIdentity), V25StagingError> {
    intent_paths(source, migration_key)?;
    intent_paths(source, activation_key)?;
    let (marker, writing) = activation_paths(source)?;
    refuse_occupied(&writing)?;
    let marker_identity = private_file_identity(&marker, false)?;
    let record: DurableActivation = serde_json::from_slice(&bounded_private_bytes(&marker)?)?;
    let p = record.payload;
    let (receipt_path, receipt_writing) = receipt_paths(source, migration_key)?;
    let (intent_path, intent_writing) = intent_paths(source, migration_key)?;
    if record.format != ACTIVATION_FORMAT
        || p.direction != ACTIVATION_DIRECTION
        || p.migration_key != migration_key
        || p.activation_key != activation_key
        || p.attestation.source_path != source
        || p.attestation.staging_path != staging
        || p.receipt_path != receipt_path
        || p.intent_path != intent_path
        || record.payload_digest != activation_digest(&p)?
    {
        return Err(V25StagingError::Safety(
            "activation format, keys, paths or payload mismatch",
        ));
    }
    refuse_occupied(&receipt_writing)?;
    refuse_occupied(&intent_writing)?;
    open_exact_private_file(&receipt_path, p.receipt_identity)?;
    open_exact_private_file(&intent_path, p.intent_identity)?;
    let receipt_bytes = bounded_private_bytes(&receipt_path)?;
    let intent_bytes = bounded_private_bytes(&intent_path)?;
    if hex_digest(&receipt_bytes) != p.receipt_bytes_digest
        || hex_digest(&intent_bytes) != p.intent_bytes_digest
    {
        return Err(V25StagingError::Safety(
            "activation historical receipt or intent bytes changed",
        ));
    }
    let receipt: DurablePublicationReceipt = serde_json::from_slice(&receipt_bytes)?;
    let intent: DurableIntent = serde_json::from_slice(&intent_bytes)?;
    if receipt.format != RECEIPT_FORMAT
        || receipt.payload.key != migration_key
        || receipt.payload.disposition != RECEIPT_DISPOSITION
        || receipt.payload.attestation != p.attestation
        || receipt.payload.intent_digest != p.intent_bytes_digest
        || receipt.receipt_digest != receipt_digest(&receipt.payload)?
        || intent.format != INTENT_FORMAT
        || intent.key != migration_key
        || intent.attestation != p.attestation
        || intent.attestation_digest != attestation_digest(migration_key, &p.attestation)?
        || p.attestation.source.version != SOURCE_SCHEMA_VERSION
        || p.attestation.staging.version != STAGING_SCHEMA_VERSION
        || p.attestation.source.schema != canonical_schema(false)?
        || p.attestation.staging.schema != canonical_schema(true)?
    {
        return Err(V25StagingError::Safety(
            "activation historical publication binding differs",
        ));
    }
    verify_preserved_snapshot(&p.attestation.source, &p.attestation.staging)?;
    let metadata = decoder(&p)?;
    if private_file_identity(&marker, false)? != marker_identity
        || hex_digest(&bounded_private_bytes(&receipt_path)?) != p.receipt_bytes_digest
        || hex_digest(&bounded_private_bytes(&intent_path)?) != p.intent_bytes_digest
        || private_file_identity(&receipt_path, false)? != p.receipt_identity
        || private_file_identity(&intent_path, false)? != p.intent_identity
    {
        return Err(V25StagingError::Safety(
            "activation identities changed during recovery",
        ));
    }
    Ok((p, metadata, marker_identity))
}

/// Read-only exact-key restart decoder. It uses the marker's historical receipt
/// and its restricted current-state protocol, never the frozen v25 snapshot.
#[cfg(unix)]
pub fn recover_disposable_v25_activation(
    source: impl AsRef<Path>,
    staging: impl AsRef<Path>,
    migration_key: &str,
    activation_key: &str,
) -> Result<V25ActivationMetadata, V25StagingError> {
    Ok(read_activation(
        source.as_ref(),
        staging.as_ref(),
        migration_key,
        activation_key,
    )?
    .1)
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActivationSyncPoint {
    WritingMarker,
    ExistingMarker,
    ParentDirectory,
}

/// Durable forward-only disposable boundary; callers must hold the exact manager
/// lock and exclusion through the handle's lifetime. No runtime/writer methods exist.
#[cfg(target_os = "linux")]
pub fn activate_disposable_schema_v25(
    source: impl AsRef<Path>,
    staging: impl AsRef<Path>,
    migration_key: &str,
    activation_key: &str,
) -> Result<DisposableV25ActivatedStore, V25StagingError> {
    activate_disposable_schema_v25_with_sync(
        source.as_ref(),
        staging.as_ref(),
        migration_key,
        activation_key,
        |file, _| file.sync_all(),
    )
}

#[cfg(target_os = "linux")]
fn activate_disposable_schema_v25_with_sync(
    source: &Path,
    staging: &Path,
    migration_key: &str,
    activation_key: &str,
    mut sync: impl FnMut(&File, ActivationSyncPoint) -> std::io::Result<()>,
) -> Result<DisposableV25ActivatedStore, V25StagingError> {
    use std::io::Write;
    intent_paths(source, activation_key)?;
    let (marker, writing) = activation_paths(source)?;
    refuse_occupied(&writing)?;
    let payload = match fs::symlink_metadata(&marker) {
        Ok(_) => {
            let (payload, _, identity) =
                read_activation(source, staging, migration_key, activation_key)?;
            let file = open_exact_private_file(&marker, identity)?;
            let directory = pinned_parent_directory(source, payload.attestation.parent_identity)?;
            sync(&file, ActivationSyncPoint::ExistingMarker)?;
            sync(&directory, ActivationSyncPoint::ParentDirectory)?;
            let (rechecked, _, after_identity) =
                read_activation(source, staging, migration_key, activation_key)?;
            if activation_digest(&payload)? != activation_digest(&rechecked)?
                || identity != after_identity
            {
                return Err(V25StagingError::Safety(
                    "activation marker changed during durability repair",
                ));
            }
            rechecked
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let receipt = persist_schema_v25_receipt(source, staging, migration_key)?;
            let proof = receipt.recovered.staged.exchange.clone();
            let current = open_exchange_read_only(source)?;
            let initial_metadata = activation_metadata_rows(&current)?;
            drop(current);
            let payload = ActivationPayload {
                migration_key: migration_key.to_owned(),
                activation_key: activation_key.to_owned(),
                direction: ACTIVATION_DIRECTION.to_owned(),
                receipt_path: receipt.receipt_path.clone(),
                receipt_identity: private_file_identity(&receipt.receipt_path, false)?,
                receipt_bytes_digest: hex_digest(&bounded_private_bytes(&receipt.receipt_path)?),
                intent_path: receipt.recovered.intent_path.clone(),
                intent_identity: private_file_identity(&receipt.recovered.intent_path, false)?,
                intent_bytes_digest: receipt.intent_digest,
                attestation: proof,
                initial_metadata,
            };
            // The restricted decoder checks the full admitted state before marker publication.
            decode_activated_current_state(&payload)?;
            let record = DurableActivation {
                format: ACTIVATION_FORMAT.to_owned(),
                payload_digest: activation_digest(&payload)?,
                payload,
            };
            let bytes = serde_json::to_vec(&record)?;
            if bytes.len() as u64 > INTENT_MAX_BYTES {
                return Err(V25StagingError::Safety(
                    "activation marker exceeds bounded encoding",
                ));
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc_no_follow())
                .open(&writing)?;
            file.write_all(&bytes)?;
            sync(&file, ActivationSyncPoint::WritingMarker)?;
            drop(file);
            private_file_identity(&writing, false)?;
            let directory =
                pinned_parent_directory(source, record.payload.attestation.parent_identity)?;
            rustix::fs::renameat_with(
                &directory,
                writing.file_name().expect("writing filename"),
                &directory,
                marker.file_name().expect("marker filename"),
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(std::io::Error::from)?;
            sync(&directory, ActivationSyncPoint::ParentDirectory)?;
            read_activation(source, staging, migration_key, activation_key)?.0
        }
        Err(error) => return Err(error.into()),
    };
    Ok(DisposableV25ActivatedStore {
        source_path: source.to_path_buf(),
        staging_path: staging.to_path_buf(),
        migration_key: migration_key.to_owned(),
        activation_key: activation_key.to_owned(),
        proof: activation_proof_result(payload.attestation),
    })
}

fn reject_exchange_sidecars(path: &Path) -> Result<(), V25StagingError> {
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut name = OsString::from(path.as_os_str());
        name.push(suffix);
        match fs::symlink_metadata(Path::new(&name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(V25StagingError::Safety(
                    "exchange refuses every SQLite sidecar",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn open_exchange_read_only(path: &Path) -> Result<Connection, V25StagingError> {
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    // immutable=1 prevents SQLite from creating WAL/SHM or recovering journals.
    // It is sound here only with the maintained exclusion and sidecar refusal.
    let mut header = [0u8; 20];
    OpenOptions::new()
        .read(true)
        .custom_flags(libc_no_follow())
        .open(path)?
        .read_exact(&mut header)?;
    if &header[..16] != b"SQLite format 3\0" || header[18] != 1 || header[19] != 1 {
        return Err(V25StagingError::Safety(
            "exchange refuses WAL-format main files",
        ));
    }
    let mut uri = String::from("file:");
    for byte in path.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || b"/-_.".contains(byte) {
            uri.push(char::from(*byte));
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    uri.push_str("?immutable=1");
    Ok(Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )?)
}

#[cfg(unix)]
fn libc_no_follow() -> i32 {
    nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC
}

#[derive(Debug)]
pub enum V25StagingError {
    InvalidInput(&'static str),
    Safety(&'static str),
    UnsupportedSourceVersion(i64),
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
    SourceStore(StoreError),
    Encoding(serde_json::Error),
}

impl fmt::Display for V25StagingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) | Self::Safety(message) => formatter.write_str(message),
            Self::UnsupportedSourceVersion(version) => {
                write!(formatter, "source schema version {version} is not 24")
            }
            Self::Io(error) => write!(formatter, "staging I/O failed: {error}"),
            Self::Sqlite(error) => write!(formatter, "staging SQLite operation failed: {error}"),
            Self::Encoding(error) => write!(formatter, "migration intent encoding failed: {error}"),
            Self::SourceStore(error) => {
                write!(formatter, "source store validation failed: {error}")
            }
        }
    }
}

impl std::error::Error for V25StagingError {}

impl From<std::io::Error> for V25StagingError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for V25StagingError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<serde_json::Error> for V25StagingError {
    fn from(error: serde_json::Error) -> Self {
        Self::Encoding(error)
    }
}

impl From<StoreError> for V25StagingError {
    fn from(error: StoreError) -> Self {
        Self::SourceStore(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaObject {
    kind: String,
    name: String,
    sql: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreSnapshot {
    version: i64,
    lineage: String,
    schema: Vec<SchemaObject>,
    tables: Vec<V25PreservedTable>,
    sequences: Vec<V25SequenceHighWater>,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

/// Create and fully verify an unpublished schema-25 copy of a private v24 store.
///
/// The caller must provide an absent staging pathname in the source directory.
/// The source is opened read-only and the staging file is never renamed or
/// exchanged. A failed attempt intentionally leaves its staging pathname
/// occupied so a retry cannot mistake partial output for a fresh destination.
/// This offline helper does not acquire the manager lifetime lock: its caller
/// must maintain exclusive control of the private directory and exclude every
/// concurrent path replacement or source writer for the entire call. It must
/// not be used as a live cutover or as proof that old Pod readers are gone.
pub fn stage_schema_v25(
    source_path: impl AsRef<Path>,
    staging_path: impl AsRef<Path>,
) -> Result<V25StagingResult, V25StagingError> {
    let source_path = source_path.as_ref();
    let staging_path = staging_path.as_ref();
    validate_path_pair(source_path, staging_path)?;
    #[cfg(unix)]
    refuse_activation_direction(source_path)?;
    #[cfg(not(unix))]
    validate_private_file(source_path, false)?;

    #[cfg(unix)]
    let source_identity = private_file_identity(source_path, false)?;
    #[cfg(unix)]
    let parent_identity = private_parent_identity(source_path)?;

    let source_version = read_version(source_path)?;
    if source_version != SOURCE_SCHEMA_VERSION {
        return Err(V25StagingError::UnsupportedSourceVersion(source_version));
    }
    drop(PodBayStore::open_existing_read_only(source_path)?);

    let expected_v24_schema = canonical_schema(false)?;
    let source = open_read_only(source_path)?;
    verify_integrity(&source)?;
    verify_foreign_keys(&source)?;
    verify_current_v2_bindings(&source)?;
    let source_before = snapshot(&source)?;
    if source_before.schema != expected_v24_schema {
        return Err(V25StagingError::Safety(
            "source does not have the exact canonical schema-24 objects",
        ));
    }

    create_private_file(staging_path)?;
    #[cfg(unix)]
    let staging_identity = private_file_identity(staging_path, true)?;
    let mut staging = Connection::open_with_flags(
        staging_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    staging.busy_timeout(Duration::from_secs(5))?;
    {
        let backup = Backup::new(&source, &mut staging)?;
        backup.run_to_completion(32, Duration::from_millis(10), None)?;
    }

    verify_integrity(&staging)?;
    verify_foreign_keys(&staging)?;
    let copied_v24 = snapshot(&staging)?;
    if copied_v24 != source_before {
        return Err(V25StagingError::Safety(
            "SQLite backup does not exactly preserve the source snapshot",
        ));
    }

    staging.execute_batch(
        "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
    )?;
    let transaction = staging.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let copied_version: i64 = transaction.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if copied_version != SOURCE_SCHEMA_VERSION {
        return Err(V25StagingError::UnsupportedSourceVersion(copied_version));
    }
    transaction.execute_batch(include_str!("schema_v25_delta.sql"))?;
    transaction.pragma_update(None, "user_version", STAGING_SCHEMA_VERSION)?;
    transaction.commit()?;

    verify_integrity(&staging)?;
    verify_foreign_keys(&staging)?;
    verify_recovery_tables_empty(&staging)?;
    let staged_v25 = snapshot(&staging)?;
    let expected_v25_schema = canonical_schema(true)?;
    if staged_v25.schema != expected_v25_schema {
        return Err(V25StagingError::Safety(
            "staging does not have the exact canonical schema-25 objects",
        ));
    }
    verify_preserved_snapshot(&source_before, &staged_v25)?;
    drop(staging);
    drop(source);

    #[cfg(unix)]
    if private_file_identity(staging_path, false)? != staging_identity {
        return Err(V25StagingError::Safety(
            "staging file identity changed while building the copy",
        ));
    }

    File::open(staging_path)?.sync_all()?;
    File::open(
        staging_path
            .parent()
            .ok_or(V25StagingError::InvalidInput("staging path has no parent"))?,
    )?
    .sync_all()?;

    #[cfg(unix)]
    if private_file_identity(source_path, false)? != source_identity {
        return Err(V25StagingError::Safety(
            "source file identity changed while staging",
        ));
    }
    let source_after_connection = open_read_only(source_path)?;
    verify_integrity(&source_after_connection)?;
    verify_foreign_keys(&source_after_connection)?;
    let source_after = snapshot(&source_after_connection)?;
    if source_after != source_before {
        return Err(V25StagingError::Safety(
            "source logical content changed while staging",
        ));
    }
    drop(source_after_connection);

    #[cfg(unix)]
    verify_parent_identity(source_path, parent_identity)?;
    #[cfg(unix)]
    let exchange = ExchangeAttestation {
        source_path: source_path.to_path_buf(),
        staging_path: staging_path.to_path_buf(),
        parent_identity,
        source_identity,
        staging_identity,
        source: source_before.clone(),
        staging: staged_v25.clone(),
    };

    Ok(V25StagingResult {
        source_path: source_path.to_path_buf(),
        staging_path: staging_path.to_path_buf(),
        store_lineage: source_before.lineage,
        source_schema_version: source_before.version,
        staging_schema_version: staged_v25.version,
        preserved_tables: source_before.tables,
        sequence_high_water: source_before.sequences,
        #[cfg(unix)]
        exchange,
    })
}

fn reject_reserved_staging_path(
    source_path: &Path,
    staging_path: &Path,
) -> Result<(), V25StagingError> {
    let canonical_source = fs::canonicalize(source_path)?;
    let parent = staging_path
        .parent()
        .ok_or(V25StagingError::InvalidInput("staging path has no parent"))?;
    let normalized_staging = fs::canonicalize(parent)?.join(
        staging_path
            .file_name()
            .ok_or(V25StagingError::InvalidInput("staging filename is missing"))?,
    );
    // Reserve only these exact canonical-source names, not arbitrary suffixes.
    for suffix in [
        ".v25-intent.json",
        ".v25-intent.json.writing",
        ".v25-publication-receipt.json",
        ".v25-publication-receipt.json.writing",
        ".v25-activation.json",
        ".v25-activation.json.writing",
        ".v25-pending-state.json",
        ".v25-pending-state.json.writing",
        "-wal",
        "-shm",
        "-journal",
    ] {
        let mut name = canonical_source
            .file_name()
            .ok_or(V25StagingError::InvalidInput("source filename is missing"))?
            .to_os_string();
        name.push(suffix);
        if normalized_staging == canonical_source.with_file_name(name) {
            return Err(V25StagingError::Safety(
                "staging path is reserved for canonical migration metadata or SQLite companions",
            ));
        }
    }
    Ok(())
}

fn validate_path_pair(source_path: &Path, staging_path: &Path) -> Result<(), V25StagingError> {
    if !source_path.is_absolute() || !staging_path.is_absolute() {
        return Err(V25StagingError::InvalidInput(
            "source and staging paths must be absolute",
        ));
    }
    if source_path == staging_path {
        return Err(V25StagingError::InvalidInput(
            "staging path must be distinct from source",
        ));
    }
    if staging_path
        .file_name()
        .is_some_and(|name| name.to_string_lossy().ends_with(".manager.lock"))
    {
        return Err(V25StagingError::Safety(
            "staging basename uses the reserved manager lock suffix",
        ));
    }
    let source_parent = source_path
        .parent()
        .ok_or(V25StagingError::InvalidInput("source path has no parent"))?;
    let staging_parent = staging_path
        .parent()
        .ok_or(V25StagingError::InvalidInput("staging path has no parent"))?;
    if fs::canonicalize(source_parent)? != fs::canonicalize(staging_parent)? {
        return Err(V25StagingError::Safety(
            "staging path must be in the source directory",
        ));
    }
    // The manager lock belongs to the canonical database filename, independent
    // of whether it exists yet. Never create staging at that reserved entry.
    let canonical_source = fs::canonicalize(source_path)?;
    let mut lock_name = canonical_source
        .file_name()
        .ok_or(V25StagingError::InvalidInput("source filename is missing"))?
        .to_os_string();
    lock_name.push(".manager.lock");
    let reserved_lock = canonical_source.with_file_name(lock_name);
    let normalized_staging = fs::canonicalize(staging_parent)?.join(
        staging_path
            .file_name()
            .ok_or(V25StagingError::InvalidInput("staging filename is missing"))?,
    );
    if normalized_staging == reserved_lock {
        return Err(V25StagingError::Safety(
            "staging path is the reserved manager lock pathname",
        ));
    }
    reject_reserved_staging_path(source_path, staging_path)?;
    match fs::symlink_metadata(staging_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(V25StagingError::Safety("staging path is already occupied")),
        Err(error) => Err(error.into()),
    }?;
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut name = OsString::from(staging_path.as_os_str());
        name.push(suffix);
        match fs::symlink_metadata(Path::new(&name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(V25StagingError::Safety(
                    "staging SQLite sidecar is already occupied",
                ));
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn private_file_identity(path: &Path, allow_empty: bool) -> Result<FileIdentity, V25StagingError> {
    let metadata = fs::symlink_metadata(path)?;
    let parent = path
        .parent()
        .ok_or(V25StagingError::InvalidInput("private file has no parent"))?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    let uid = nix::unistd::geteuid().as_raw();
    if !metadata.is_file()
        || (!allow_empty && metadata.len() == 0)
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != uid
        || parent_metadata.mode() & 0o7777 != 0o700
        || fs::canonicalize(path)? != path
    {
        return Err(V25StagingError::Safety(
            "database file or parent directory is not private and stable",
        ));
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn validate_private_file(_path: &Path, _allow_empty: bool) -> Result<(), V25StagingError> {
    Err(V25StagingError::Safety(
        "private schema-25 staging is supported only on Unix",
    ))
}

fn create_private_file(path: &Path) -> Result<(), V25StagingError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path)?;
    file.sync_all()?;
    Ok(())
}

fn open_read_only(path: &Path) -> Result<Connection, V25StagingError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(Duration::from_secs(5))?;
    Ok(connection)
}

fn read_version(path: &Path) -> Result<i64, V25StagingError> {
    let connection = open_read_only(path)?;
    Ok(connection.query_row("PRAGMA user_version", [], |row| row.get(0))?)
}

fn canonical_schema(with_v25_delta: bool) -> Result<Vec<SchemaObject>, V25StagingError> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(include_str!("schema_v24.sql"))?;
    if with_v25_delta {
        connection.execute_batch(include_str!("schema_v25_delta.sql"))?;
    }
    schema_objects(&connection)
}

fn snapshot(connection: &Connection) -> Result<StoreSnapshot, V25StagingError> {
    let version = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let lineage = connection.query_row(
        "SELECT lineage FROM store_identity WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let schema = schema_objects(connection)?;
    let mut table_statement = connection.prepare(
        "SELECT name FROM sqlite_schema
         WHERE type='table' AND name NOT GLOB 'sqlite_*' ORDER BY name",
    )?;
    let table_names = table_statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut tables = Vec::with_capacity(table_names.len());
    for name in table_names {
        tables.push(table_snapshot(connection, &name)?);
    }
    let mut sequence_statement =
        connection.prepare("SELECT name,seq FROM sqlite_sequence ORDER BY name")?;
    let sequences = sequence_statement
        .query_map([], |row| {
            Ok(V25SequenceHighWater {
                table: row.get(0)?,
                sequence: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(StoreSnapshot {
        version,
        lineage,
        schema,
        tables,
        sequences,
    })
}

fn schema_objects(connection: &Connection) -> Result<Vec<SchemaObject>, V25StagingError> {
    let mut statement = connection.prepare(
        "SELECT type,name,sql FROM sqlite_schema
         WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name",
    )?;
    Ok(statement
        .query_map([], |row| {
            Ok(SchemaObject {
                kind: row.get(0)?,
                name: row.get(1)?,
                sql: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?)
}

fn quoted_identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn table_snapshot(
    connection: &Connection,
    name: &str,
) -> Result<V25PreservedTable, V25StagingError> {
    let quoted = quoted_identifier(name);
    let (row_count, max_rowid): (i64, i64) = connection.query_row(
        &format!("SELECT count(*),coalesce(max(rowid),0) FROM {quoted}"),
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let mut statement =
        connection.prepare(&format!("SELECT rowid,* FROM {quoted} ORDER BY rowid"))?;
    let column_count = statement.column_count();
    let mut rows = statement.query([])?;
    let mut digest = Sha256::new();
    while let Some(row) = rows.next()? {
        digest.update([0xff]);
        for index in 0..column_count {
            match row.get_ref(index)? {
                ValueRef::Null => digest.update([0]),
                ValueRef::Integer(value) => {
                    digest.update([1]);
                    digest.update(value.to_be_bytes());
                }
                ValueRef::Real(value) => {
                    digest.update([2]);
                    digest.update(value.to_bits().to_be_bytes());
                }
                ValueRef::Text(value) => {
                    digest.update([3]);
                    digest.update((value.len() as u64).to_be_bytes());
                    digest.update(value);
                }
                ValueRef::Blob(value) => {
                    digest.update([4]);
                    digest.update((value.len() as u64).to_be_bytes());
                    digest.update(value);
                }
            }
        }
    }
    Ok(V25PreservedTable {
        name: name.to_owned(),
        row_count: row_count
            .try_into()
            .map_err(|_| V25StagingError::Safety("table row count is negative"))?,
        max_rowid,
        content_digest: digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    })
}

fn verify_integrity(connection: &Connection) -> Result<(), V25StagingError> {
    let mut statement = connection.prepare("PRAGMA integrity_check")?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if rows != ["ok"] {
        return Err(V25StagingError::Safety("SQLite integrity_check failed"));
    }
    Ok(())
}

fn verify_foreign_keys(connection: &Connection) -> Result<(), V25StagingError> {
    let violation: Option<String> = connection
        .query_row(
            "SELECT \"table\" FROM pragma_foreign_key_check LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if violation.is_some() {
        return Err(V25StagingError::Safety("SQLite foreign_key_check failed"));
    }
    Ok(())
}

fn verify_current_v2_bindings(connection: &Connection) -> Result<(), V25StagingError> {
    let inconsistent_launch: bool = connection.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM launch_bindings lb
           LEFT JOIN commands c ON c.command_rowid=lb.command_rowid
           WHERE c.command_rowid IS NULL OR c.scope_id<>lb.scope_id OR c.target_id<>lb.pod_id
             OR c.target_epoch<>lb.pod_incarnation
         )",
        [],
        |row| row.get(0),
    )?;
    let lineage: String = connection.query_row(
        "SELECT lineage FROM store_identity WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let inconsistent_rebind: bool = connection.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM manager_rebinds mr
           LEFT JOIN launch_bindings lb
             ON lb.scope_id=mr.scope_id AND lb.pod_id=mr.pod_id
            AND lb.pod_incarnation=mr.pod_incarnation AND lb.attempt_id=mr.attempt_id
           LEFT JOIN manager_rebind_prior_observations prior
             ON prior.rebind_rowid=mr.rebind_rowid
           WHERE mr.phase='activated'
             AND (mr.store_lineage<>?1 OR lb.command_rowid IS NULL
               OR prior.rebind_rowid IS NULL)
         )",
        [&lineage],
        |row| row.get(0),
    )?;
    if inconsistent_launch || inconsistent_rebind {
        return Err(V25StagingError::Safety(
            "current V2 launch or activated rebind binding is inconsistent",
        ));
    }
    Ok(())
}

fn verify_recovery_tables_empty(connection: &Connection) -> Result<(), V25StagingError> {
    let count: i64 = connection.query_row(
        "SELECT
           (SELECT count(*) FROM external_death_pending)
           + (SELECT count(*) FROM external_death_final)",
        [],
        |row| row.get(0),
    )?;
    if count != 0 {
        return Err(V25StagingError::Safety(
            "schema-25 recovery tables are not empty after staging",
        ));
    }
    Ok(())
}

fn verify_preserved_snapshot(
    source: &StoreSnapshot,
    staging: &StoreSnapshot,
) -> Result<(), V25StagingError> {
    if source.version != SOURCE_SCHEMA_VERSION
        || staging.version != STAGING_SCHEMA_VERSION
        || source.lineage != staging.lineage
        || source.sequences != staging.sequences
    {
        return Err(V25StagingError::Safety(
            "schema version, lineage, or sequence high-water verification failed",
        ));
    }
    let preserved = staging
        .tables
        .iter()
        .filter(|table| {
            table.name != "external_death_pending" && table.name != "external_death_final"
        })
        .cloned()
        .collect::<Vec<_>>();
    if preserved != source.tables {
        return Err(V25StagingError::Safety(
            "row count, rowid high-water, or table content verification failed",
        ));
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod durable_intent_sync_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn same_key_retry_repairs_post_rename_durability_and_refuses_sync_failures() {
        let directory = std::env::temp_dir().join(format!(
            "podbay-intent-sync-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let source = directory.join("podbay.sqlite");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&source)
            .unwrap();
        drop(PodBayStore::open(&source).unwrap());
        let connection = Connection::open(&source).unwrap();
        connection
            .execute_batch("PRAGMA journal_mode=DELETE;")
            .unwrap();
        drop(connection);
        let staged = stage_schema_v25(&source, directory.join("staged.sqlite")).unwrap();
        let key = "key.post-rename";
        let (intent, writing) = intent_paths(&source, key).unwrap();
        let first = staged.persist_exchange_intent_with_sync(key, |file, point| {
            if point == IntentSyncPoint::ParentDirectory {
                assert!(intent.exists(), "injection must occur after atomic rename");
                assert!(!writing.exists());
                return Err(std::io::Error::other(
                    "injected post-rename directory sync failure",
                ));
            }
            file.sync_all()
        });
        assert!(matches!(first, Err(V25StagingError::Io(_))));
        assert!(intent.exists());
        for failing_point in [
            IntentSyncPoint::PublishedFile,
            IntentSyncPoint::ParentDirectory,
        ] {
            let mut observed = Vec::new();
            let retry = staged.persist_exchange_intent_with_sync(key, |file, point| {
                observed.push(point);
                if point == failing_point {
                    return Err(std::io::Error::other(
                        "injected retry durability repair failure",
                    ));
                }
                file.sync_all()
            });
            assert!(matches!(retry, Err(V25StagingError::Io(_))));
            assert_eq!(observed.first(), Some(&IntentSyncPoint::PublishedFile));
            assert_eq!(observed.last(), Some(&failing_point));
        }
        let mut repaired = Vec::new();
        let path = staged
            .persist_exchange_intent_with_sync(key, |file, point| {
                repaired.push(point);
                file.sync_all()
            })
            .unwrap();
        assert_eq!(path, intent);
        assert_eq!(
            repaired,
            [
                IntentSyncPoint::PublishedFile,
                IntentSyncPoint::ParentDirectory
            ]
        );
        assert_eq!(
            recover_schema_v25_intent(&source, &staged.staging_path, key)
                .unwrap()
                .orientation,
            V25ExchangeOrientation::Unpublished
        );
        fs::remove_dir_all(directory).unwrap();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod durable_receipt_sync_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn recovered_older_intent_refuses_reserved_receipt_and_sqlite_staging_names() {
        for suffix in [
            ".v25-publication-receipt.json",
            ".v25-publication-receipt.json.writing",
            "-wal",
            "-shm",
            "-journal",
        ] {
            let directory = std::env::temp_dir().join(format!(
                "podbay-reserved-recovery-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            let source = directory.join("podbay.sqlite");
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&source)
                .unwrap();
            drop(PodBayStore::open(&source).unwrap());
            let connection = Connection::open(&source).unwrap();
            connection
                .execute_batch("PRAGMA journal_mode=DELETE;")
                .unwrap();
            drop(connection);
            let staged = stage_schema_v25(&source, directory.join("staged.sqlite")).unwrap();
            let intent = staged.persist_exchange_intent("key.older").unwrap();
            let mut name = source.as_os_str().to_os_string();
            name.push(suffix);
            let reserved = PathBuf::from(name);
            fs::rename(&staged.staging_path, &reserved).unwrap();
            // Reconstruct a checksum-valid legacy intent with exact unchanged inodes/content.
            let mut record: DurableIntent =
                serde_json::from_slice(&fs::read(&intent).unwrap()).unwrap();
            record.attestation.staging_path = reserved.clone();
            record.attestation_digest =
                attestation_digest("key.older", &record.attestation).unwrap();
            fs::write(&intent, serde_json::to_vec(&record).unwrap()).unwrap();
            drop(staged);
            let source_before = fs::read(&source).unwrap();
            let foreign_before = fs::read(&reserved).unwrap();
            let refused = recover_schema_v25_intent(&source, &reserved, "key.older");
            assert!(
                matches!(
                    refused,
                    Err(V25StagingError::Safety(
                        "staging path is reserved for canonical migration metadata or SQLite companions"
                    ))
                ),
                "{suffix}: {refused:?}"
            );
            assert_eq!(fs::read(&source).unwrap(), source_before);
            assert_eq!(fs::read(&reserved).unwrap(), foreign_before);
            fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn receipt_post_rename_retry_repairs_fsync_and_refuses_every_repair_failure() {
        let directory = std::env::temp_dir().join(format!(
            "podbay-receipt-sync-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let source = directory.join("podbay.sqlite");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&source)
            .unwrap();
        drop(PodBayStore::open(&source).unwrap());
        let c = Connection::open(&source).unwrap();
        c.execute_batch("PRAGMA journal_mode=DELETE;").unwrap();
        drop(c);
        let stage = directory.join("staged.sqlite");
        let staged = stage_schema_v25(&source, &stage).unwrap();
        staged.persist_exchange_intent("key.receipt").unwrap();
        let dir = File::open(&directory).unwrap();
        rustix::fs::renameat_with(
            &dir,
            source.file_name().unwrap(),
            &dir,
            stage.file_name().unwrap(),
            rustix::fs::RenameFlags::EXCHANGE,
        )
        .unwrap();
        drop(staged);
        let (receipt, writing) = receipt_paths(&source, "key.receipt").unwrap();
        let first =
            persist_schema_v25_receipt_with_sync(&source, &stage, "key.receipt", |file, point| {
                if point == ReceiptSyncPoint::ReceiptDirectory {
                    assert!(receipt.exists());
                    assert!(!writing.exists());
                    return Err(std::io::Error::other(
                        "injected after receipt rename before dir fsync",
                    ));
                }
                file.sync_all()
            });
        assert!(matches!(first, Err(V25StagingError::Io(_))));
        assert!(receipt.exists());
        for fail in [
            ReceiptSyncPoint::CanonicalFile,
            ReceiptSyncPoint::StagedOldFile,
            ReceiptSyncPoint::PairDirectory,
            ReceiptSyncPoint::PublishedReceipt,
            ReceiptSyncPoint::ReceiptDirectory,
        ] {
            let mut calls = Vec::new();
            let retry = persist_schema_v25_receipt_with_sync(
                &source,
                &stage,
                "key.receipt",
                |file, point| {
                    calls.push(point);
                    if point == fail {
                        return Err(std::io::Error::other("injected receipt retry sync failure"));
                    }
                    file.sync_all()
                },
            );
            assert!(matches!(retry, Err(V25StagingError::Io(_))));
            assert_eq!(calls.last(), Some(&fail));
        }
        let mut repaired = Vec::new();
        let terminal =
            persist_schema_v25_receipt_with_sync(&source, &stage, "key.receipt", |file, point| {
                repaired.push(point);
                file.sync_all()
            })
            .unwrap();
        assert_eq!(terminal.receipt_path, receipt);
        assert_eq!(
            repaired,
            [
                ReceiptSyncPoint::CanonicalFile,
                ReceiptSyncPoint::StagedOldFile,
                ReceiptSyncPoint::PairDirectory,
                ReceiptSyncPoint::PublishedReceipt,
                ReceiptSyncPoint::ReceiptDirectory
            ]
        );
        assert_eq!(
            recover_schema_v25_receipt(&source, &stage, "key.receipt")
                .unwrap()
                .intent()
                .orientation,
            V25ExchangeOrientation::Published
        );
        fs::remove_dir_all(directory).unwrap();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod disposable_activation_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    struct Fixture {
        directory: PathBuf,
        source: PathBuf,
        staging: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            Self::with_revision(0)
        }
        fn with_revision(revision: i64) -> Self {
            let directory = std::env::temp_dir().join(format!(
                "podbay-activate-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            let source = directory.join("podbay.sqlite");
            let staging = directory.join("old.sqlite");
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&source)
                .unwrap();
            drop(PodBayStore::open(&source).unwrap());
            let c = Connection::open(&source).unwrap();
            c.execute_batch("PRAGMA journal_mode=DELETE;").unwrap();
            c.execute(
                "UPDATE metadata SET value=?1 WHERE key='authority_revision'",
                [revision],
            )
            .unwrap();
            drop(c);
            let staged = stage_schema_v25(&source, &staging).unwrap();
            staged.persist_exchange_intent("migration.one").unwrap();
            let dir = File::open(&directory).unwrap();
            rustix::fs::renameat_with(
                &dir,
                source.file_name().unwrap(),
                &dir,
                staging.file_name().unwrap(),
                rustix::fs::RenameFlags::EXCHANGE,
            )
            .unwrap();
            persist_schema_v25_receipt(&source, &staging, "migration.one").unwrap();
            drop(staged);
            Self {
                directory,
                source,
                staging,
            }
        }
        fn activate(&self) -> DisposableV25ActivatedStore {
            activate_disposable_schema_v25(
                &self.source,
                &self.staging,
                "migration.one",
                "activation.one",
            )
            .unwrap()
        }
        fn recover(&self) -> Result<V25ActivationMetadata, V25StagingError> {
            recover_disposable_v25_activation(
                &self.source,
                &self.staging,
                "migration.one",
                "activation.one",
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    // No production write method exists. This private oracle proves that the
    // persisted boundary precedes a disposable monotone revision transaction.
    fn advance_revision_for_test(store: &DisposableV25ActivatedStore) -> u64 {
        let before = store.metadata().unwrap();
        let mut connection =
            Connection::open_with_flags(&store.source_path, OpenFlags::SQLITE_OPEN_READ_WRITE)
                .unwrap();
        connection
            .execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")
            .unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let next = before.authority_revision.checked_add(1).unwrap();
        assert_eq!(
            transaction
                .execute(
                    "UPDATE metadata SET value=?1 WHERE key='authority_revision' AND value=?2",
                    rusqlite::params![
                        i64::try_from(next).unwrap(),
                        i64::try_from(before.authority_revision).unwrap()
                    ]
                )
                .unwrap(),
            1
        );
        transaction.commit().unwrap();
        drop(connection);
        File::open(&store.source_path).unwrap().sync_all().unwrap();
        File::open(store.source_path.parent().unwrap())
            .unwrap()
            .sync_all()
            .unwrap();
        next
    }

    #[test]
    fn activation_marker_precedes_write_and_decoder_reopens_changed_v25_state() {
        let f = Fixture::new();
        let old_bytes = fs::read(&f.staging).unwrap();
        let handle = f.activate();
        let initial = handle.metadata().unwrap();
        let (marker, _) = activation_paths(&f.source).unwrap();
        assert_eq!(fs::metadata(&marker).unwrap().mode() & 0o7777, 0o600);
        let next = advance_revision_for_test(&handle);
        assert_eq!(next, initial.authority_revision + 1);
        assert_eq!(handle.metadata().unwrap().authority_revision, next);
        let current = open_exchange_read_only(&f.source).unwrap();
        assert_ne!(snapshot(&current).unwrap(), handle.proof.exchange.staging);
        drop(current);
        assert!(recover_schema_v25_receipt(&f.source, &f.staging, "migration.one").is_err());
        assert_eq!(fs::read(&f.staging).unwrap(), old_bytes);
        assert!(PodBayStore::open(&f.source).is_err());
        assert!(PodBayStore::open_existing_read_only(&f.source).is_err());
        drop(handle);
        assert_eq!(f.activate().metadata().unwrap().authority_revision, next);
    }

    #[test]
    fn checksum_valid_marker_cannot_rebase_metadata_away_from_preserved_v24() {
        for field in ["authority_revision", "owner_epoch"] {
            let f = Fixture::with_revision(5);
            let handle = f.activate();
            assert_eq!(advance_revision_for_test(&handle), 6);
            drop(handle);
            let old_bytes = fs::read(&f.staging).unwrap();
            let (marker, _) = activation_paths(&f.source).unwrap();
            let mut record: DurableActivation =
                serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap();
            let baseline = record
                .payload
                .initial_metadata
                .iter_mut()
                .find(|row| row.key == field)
                .unwrap();
            let current_value = if field == "authority_revision" {
                assert_eq!(baseline.value, 5);
                baseline.value = 0;
                4
            } else {
                baseline.value += 1;
                baseline.value
            };
            record.payload_digest = activation_digest(&record.payload).unwrap();
            fs::write(&marker, serde_json::to_vec(&record).unwrap()).unwrap();
            // SQL-valid current values match the forged marker but not the preserved v24 origin.
            let current = Connection::open(&f.source).unwrap();
            assert_eq!(
                current
                    .execute(
                        "UPDATE metadata SET value=?1 WHERE key=?2",
                        rusqlite::params![current_value, field]
                    )
                    .unwrap(),
                1
            );
            let observed: i64 = current
                .query_row("SELECT value FROM metadata WHERE key=?1", [field], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(observed, current_value);
            drop(current);
            assert!(
                matches!(
                    f.recover(),
                    Err(V25StagingError::Safety(
                        "activation initial metadata differs from preserved v24"
                    ))
                ),
                "{field}"
            );
            assert!(
                matches!(
                    activate_disposable_schema_v25(
                        &f.source,
                        &f.staging,
                        "migration.one",
                        "activation.one"
                    ),
                    Err(V25StagingError::Safety(
                        "activation initial metadata differs from preserved v24"
                    ))
                ),
                "{field}"
            );
            assert_eq!(fs::read(&f.staging).unwrap(), old_bytes);
        }
    }

    #[test]
    fn activation_restart_child() {
        let Some(source) = std::env::var_os("PODBAY_ACTIVATE_PROBE_SOURCE") else {
            return;
        };
        let staging = std::env::var_os("PODBAY_ACTIVATE_PROBE_STAGING").unwrap();
        let expected = std::env::var("PODBAY_ACTIVATE_PROBE_REVISION")
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let handle = activate_disposable_schema_v25(
            PathBuf::from(source),
            PathBuf::from(staging),
            "migration.one",
            "activation.one",
        )
        .unwrap();
        assert_eq!(handle.metadata().unwrap().authority_revision, expected);
        println!("fresh-process activated metadata revision={expected}");
    }

    #[test]
    fn activation_fresh_process_recovers_after_private_revision_write() {
        let f = Fixture::new();
        let handle = f.activate();
        let next = advance_revision_for_test(&handle);
        drop(handle);
        let source_inode = fs::metadata(&f.source).unwrap().ino();
        let old_bytes = fs::read(&f.staging).unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "migration_v25::disposable_activation_tests::activation_restart_child",
                "--nocapture",
            ])
            .env("PODBAY_ACTIVATE_PROBE_SOURCE", &f.source)
            .env("PODBAY_ACTIVATE_PROBE_STAGING", &f.staging)
            .env("PODBAY_ACTIVATE_PROBE_REVISION", next.to_string())
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "{} {}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
        println!("{}", String::from_utf8_lossy(&child.stdout));
        assert_eq!(fs::metadata(&f.source).unwrap().ino(), source_inode);
        assert_eq!(fs::read(&f.staging).unwrap(), old_bytes);
    }

    #[test]
    fn activation_retry_repairs_post_rename_sync_and_never_demands_frozen_state() {
        let f = Fixture::with_revision(5);
        let (marker, writing) = activation_paths(&f.source).unwrap();
        let first = activate_disposable_schema_v25_with_sync(
            &f.source,
            &f.staging,
            "migration.one",
            "activation.one",
            |file, point| {
                if point == ActivationSyncPoint::ParentDirectory {
                    assert!(marker.exists());
                    assert!(!writing.exists());
                    return Err(std::io::Error::other(
                        "injected after marker rename before dir sync",
                    ));
                }
                file.sync_all()
            },
        );
        assert!(matches!(first, Err(V25StagingError::Io(_))));
        for fail in [
            ActivationSyncPoint::ExistingMarker,
            ActivationSyncPoint::ParentDirectory,
        ] {
            let mut calls = Vec::new();
            let attempt = activate_disposable_schema_v25_with_sync(
                &f.source,
                &f.staging,
                "migration.one",
                "activation.one",
                |file, point| {
                    calls.push(point);
                    if point == fail {
                        return Err(std::io::Error::other(
                            "injected activation retry repair error",
                        ));
                    }
                    file.sync_all()
                },
            );
            assert!(matches!(attempt, Err(V25StagingError::Io(_))));
            assert_eq!(calls.first(), Some(&ActivationSyncPoint::ExistingMarker));
            assert_eq!(calls.last(), Some(&fail));
        }
        let mut calls = Vec::new();
        let handle = activate_disposable_schema_v25_with_sync(
            &f.source,
            &f.staging,
            "migration.one",
            "activation.one",
            |file, point| {
                calls.push(point);
                file.sync_all()
            },
        )
        .unwrap();
        assert_eq!(
            calls,
            [
                ActivationSyncPoint::ExistingMarker,
                ActivationSyncPoint::ParentDirectory
            ]
        );
        let next = advance_revision_for_test(&handle);
        drop(handle);
        assert_eq!(f.activate().metadata().unwrap().authority_revision, next);
        let c = Connection::open(&f.source).unwrap();
        c.execute(
            "UPDATE metadata SET value=4 WHERE key='authority_revision'",
            [],
        )
        .unwrap();
        drop(c);
        assert!(
            activate_disposable_schema_v25(
                &f.source,
                &f.staging,
                "migration.one",
                "activation.one"
            )
            .is_err()
        );
    }

    #[test]
    fn partial_activation_refuses_and_preserves_forward_only_direction() {
        let f = Fixture::new();
        let source_before = fs::read(&f.source).unwrap();
        let result = activate_disposable_schema_v25_with_sync(
            &f.source,
            &f.staging,
            "migration.one",
            "activation.one",
            |_, point| {
                if point == ActivationSyncPoint::WritingMarker {
                    return Err(std::io::Error::other("injected writing marker failure"));
                }
                Ok(())
            },
        );
        assert!(matches!(result, Err(V25StagingError::Io(_))));
        assert!(f.recover().is_err());
        assert!(
            activate_disposable_schema_v25(
                &f.source,
                &f.staging,
                "migration.one",
                "activation.one"
            )
            .is_err()
        );
        assert!(recover_schema_v25_receipt(&f.source, &f.staging, "migration.one").is_err());
        assert_eq!(fs::read(&f.source).unwrap(), source_before);
    }

    #[test]
    fn activation_refuses_wrong_keys_corrupt_foreign_marker_and_historical_artifacts() {
        for change in [
            "format",
            "direction",
            "checksum",
            "unknown",
            "partial",
            "receipt_bytes",
            "intent_inode",
            "marker_link",
            "marker_symlink",
            "marker_mode",
            "receipt_inode",
        ] {
            let f = Fixture::new();
            drop(f.activate());
            let (marker, writing) = activation_paths(&f.source).unwrap();
            assert!(
                activate_disposable_schema_v25(
                    &f.source,
                    &f.staging,
                    "migration.other",
                    "activation.one"
                )
                .is_err()
            );
            assert!(
                activate_disposable_schema_v25(
                    &f.source,
                    &f.staging,
                    "migration.one",
                    "activation.other"
                )
                .is_err()
            );
            assert!(
                recover_disposable_v25_activation(
                    &f.source,
                    f.directory.join("foreign-stage.sqlite"),
                    "migration.one",
                    "activation.one"
                )
                .is_err()
            );
            match change {
                "format" | "direction" | "checksum" | "unknown" => {
                    let mut v: serde_json::Value =
                        serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap();
                    match change {
                        "format" => v["format"] = "future/2".into(),
                        "direction" => v["payload"]["direction"] = "rollback".into(),
                        "checksum" => v["payload_digest"] = "0".repeat(64).into(),
                        "unknown" => v["caller_activated"] = true.into(),
                        _ => unreachable!(),
                    }
                    fs::write(&marker, serde_json::to_vec(&v).unwrap()).unwrap();
                }
                "partial" => fs::write(writing, b"partial foreign").unwrap(),
                "receipt_bytes" => {
                    let (path, _) = receipt_paths(&f.source, "migration.one").unwrap();
                    let mut bytes = fs::read(&path).unwrap();
                    bytes.push(b' ');
                    fs::write(path, bytes).unwrap();
                }
                "intent_inode" => {
                    let (path, _) = intent_paths(&f.source, "migration.one").unwrap();
                    let replacement = f.directory.join("replacement");
                    fs::copy(&path, &replacement).unwrap();
                    fs::rename(replacement, path).unwrap();
                }
                "marker_link" => fs::hard_link(&marker, f.directory.join("marker.link")).unwrap(),
                "marker_symlink" => {
                    let old = f.directory.join("marker.old");
                    fs::rename(&marker, &old).unwrap();
                    std::os::unix::fs::symlink(old, &marker).unwrap();
                }
                "marker_mode" => {
                    fs::set_permissions(&marker, fs::Permissions::from_mode(0o640)).unwrap()
                }
                "receipt_inode" => {
                    let (path, _) = receipt_paths(&f.source, "migration.one").unwrap();
                    let replacement = f.directory.join("receipt.replacement");
                    fs::copy(&path, &replacement).unwrap();
                    fs::rename(replacement, path).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(f.recover().is_err(), "{change}");
            assert!(
                activate_disposable_schema_v25(
                    &f.source,
                    &f.staging,
                    "migration.one",
                    "activation.one"
                )
                .is_err(),
                "{change}"
            );
        }
    }

    #[test]
    fn activation_decoder_refuses_schema_lineage_authority_changes_old_companions_and_orientation()
    {
        for change in [
            "schema",
            "version",
            "lineage",
            "owner",
            "old_sidecar",
            "source_inode",
            "orientation",
            "new_pending",
        ] {
            let f = Fixture::new();
            drop(f.activate());
            match change {
                "schema" | "version" | "lineage" | "owner" | "new_pending" => {
                    let c = Connection::open(&f.source).unwrap();
                    c.execute_batch(match change {
                        "schema"=>"CREATE TABLE unsupported_activation(value INTEGER) STRICT",
                        "version"=>"PRAGMA user_version=24",
                        "lineage"=>"UPDATE store_identity SET lineage='foreign' WHERE singleton=1",
                        "owner"=>"UPDATE metadata SET value=value+1 WHERE key='owner_epoch'",
                        "new_pending"=>"PRAGMA foreign_keys=OFF; INSERT INTO external_death_pending(recovery_key,store_lineage,scope_id,pod_id,pod_incarnation,launch_command_rowid,activated_rebind_rowid,preparing_owner_epoch,preparing_authority_revision,authenticated_author,request_version,canonical_request,request_digest) SELECT 'new',lineage,'scope','pod',1,1,1,1,1,'fixture.owner','podbay.external-death-pending-request/1',X'01','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' FROM store_identity",
                        _=>unreachable!()
                    }).unwrap();
                }
                "old_sidecar" => fs::write(
                    format!("{}-wal", f.staging.display()),
                    b"foreign old v24 sidecar",
                )
                .unwrap(),
                "source_inode" => {
                    let replacement = f.directory.join("replacement.sqlite");
                    fs::copy(&f.source, &replacement).unwrap();
                    fs::rename(replacement, &f.source).unwrap();
                }
                "orientation" => {
                    let dir = File::open(&f.directory).unwrap();
                    rustix::fs::renameat_with(
                        &dir,
                        f.source.file_name().unwrap(),
                        &dir,
                        f.staging.file_name().unwrap(),
                        rustix::fs::RenameFlags::EXCHANGE,
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(f.recover().is_err(), "{change}");
            assert!(
                activate_disposable_schema_v25(
                    &f.source,
                    &f.staging,
                    "migration.one",
                    "activation.one"
                )
                .is_err(),
                "{change}"
            );
        }
    }

    #[test]
    fn activation_metadata_filenames_are_reserved_before_staging_creation() {
        for suffix in [".v25-activation.json", ".v25-activation.json.writing"] {
            let f = Fixture::new();
            let alternate = f.directory.join("another-source.sqlite");
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&alternate)
                .unwrap();
            drop(PodBayStore::open(&alternate).unwrap());
            let mut name = alternate.as_os_str().to_os_string();
            name.push(suffix);
            let reserved = PathBuf::from(name);
            assert!(matches!(
                stage_schema_v25(&alternate, &reserved),
                Err(V25StagingError::Safety(
                    "staging path is reserved for canonical migration metadata or SQLite companions"
                ))
            ));
            assert!(!reserved.exists());
        }
    }
}

#[cfg(target_os = "linux")]
#[path = "external_death_v25.rs"]
mod external_death_v25;
#[cfg(target_os = "linux")]
pub use external_death_v25::{
    DisposablePendingAuthor, DisposableV25PendingStore, ExternalDeathPendingReceipt,
    ExternalDeathPendingRequest, PendingResourceBinding, open_disposable_v25_pending,
};
