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
use sha2::{Digest, Sha256};

use crate::{PodBayStore, StoreError};

const SOURCE_SCHEMA_VERSION: i64 = 24;
const STAGING_SCHEMA_VERSION: i64 = 25;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V25PreservedTable {
    pub name: String,
    pub row_count: u64,
    pub max_rowid: i64,
    pub content_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
struct ExchangeAttestation {
    source_path: PathBuf,
    staging_path: PathBuf,
    source_identity: FileIdentity,
    staging_identity: FileIdentity,
    source: StoreSnapshot,
    staging: StoreSnapshot,
}

impl V25StagingResult {
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
            let proof = &self.exchange;
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
            Ok(orientation)
        }
    }
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

impl From<StoreError> for V25StagingError {
    fn from(error: StoreError) -> Self {
        Self::SourceStore(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SchemaObject {
    kind: String,
    name: String,
    sql: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoreSnapshot {
    version: i64,
    lineage: String,
    schema: Vec<SchemaObject>,
    tables: Vec<V25PreservedTable>,
    sequences: Vec<V25SequenceHighWater>,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    #[cfg(not(unix))]
    validate_private_file(source_path, false)?;

    #[cfg(unix)]
    let source_identity = private_file_identity(source_path, false)?;

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
    let exchange = ExchangeAttestation {
        source_path: source_path.to_path_buf(),
        staging_path: staging_path.to_path_buf(),
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
