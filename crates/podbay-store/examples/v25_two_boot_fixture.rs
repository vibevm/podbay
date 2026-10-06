//! Disposable two-phase fixture. No production barrier, admission or service.
use podbay_store::{
    PodBayStore, StoreError, V25StagingError, activate_disposable_schema_v25,
    persist_schema_v25_receipt, recover_disposable_v25_activation, recover_schema_v25_intent,
    stage_schema_v25,
};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const SCHEMA: &str = "podbay.disposable-v25-two-boot-fixture/1";
const MIGRATION: &str = "migration.fixture";
const ACTIVATION: &str = "activation.fixture";
const PARTIAL: &[u8] = b"{\"fixture_partial_activation\":";
const FROZEN: &str =
    "forward activation exists or is partial; frozen migration exchange is forbidden";

fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.to_owned().into())
    }
}
fn digest(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
fn private_dir(path: &Path) -> Result<()> {
    DirBuilder::new().mode(0o700).create(path)?;
    File::open(path)?.sync_all()?;
    File::open(path.parent().ok_or("missing parent")?)?.sync_all()?;
    Ok(())
}
fn new_file(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?)
}
fn lock_case(case: &Path, create: bool) -> Result<File> {
    let path = case.join("podbay.sqlite.manager.lock");
    let file = if create {
        new_file(&path)?
    } else {
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path)?
    };
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
    if create {
        file.sync_all()?;
        File::open(case)?.sync_all()?;
    }
    Ok(file)
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Pin {
    relative: String,
    directory: bool,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    bytes: u64,
    sha256: String,
}
fn pin(root: &Path, path: &Path) -> Result<Pin> {
    let m = fs::symlink_metadata(path)?;
    require(m.is_dir() || m.is_file(), "foreign filesystem entry")?;
    require(
        m.uid() == nix::unistd::geteuid().as_raw(),
        "foreign fixture UID",
    )?;
    require(
        m.mode() & 0o7777 == if m.is_dir() { 0o700 } else { 0o600 },
        "unsafe fixture mode",
    )?;
    require(m.is_dir() || m.nlink() == 1, "linked fixture file")?;
    Ok(Pin {
        relative: path
            .strip_prefix(root)?
            .to_str()
            .ok_or("non-UTF8 path")?
            .into(),
        directory: m.is_dir(),
        device: m.dev(),
        inode: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode() & 0o7777,
        links: m.nlink(),
        bytes: if m.is_dir() { 0 } else { m.len() },
        sha256: if m.is_dir() {
            String::new()
        } else {
            digest(path)?
        },
    })
}
fn snapshot(root: &Path) -> Result<Vec<Pin>> {
    fn visit(root: &Path, path: &Path, out: &mut Vec<Pin>) -> Result<()> {
        require(out.len() < 64, "fixture entry bound")?;
        let value = pin(root, path)?;
        let directory = value.directory;
        out.push(value);
        if directory {
            let mut paths = fs::read_dir(path)?
                .map(|e| e.map(|e| e.path()))
                .collect::<std::io::Result<Vec<_>>>()?;
            paths.sort();
            for child in paths {
                if child == root.join("manifest.json") {
                    continue;
                }
                visit(root, &child, out)?;
            }
        }
        Ok(())
    }
    let mut result = Vec::new();
    visit(root, root, &mut result)?;
    Ok(result)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    nonce: String,
    domain: String,
    boot_a: String,
    executable_sha256: String,
    root: String,
    lineage: String,
    owner_epoch: u64,
    authority_revision: u64,
    pins: Vec<Pin>,
}
struct Context {
    root: PathBuf,
    nonce: String,
    domain: String,
    boot: String,
    executable: String,
    sequence: u64,
}
impl Context {
    fn event(&mut self, event: &str, details: serde_json::Value) -> Result<()> {
        self.sequence += 1;
        println!(
            "PODBAY_V25_FIXTURE {}",
            serde_json::json!({"schema":SCHEMA,"event":event,
            "gate":"CLOSED","admission":"UNIMPLEMENTED","domain":self.domain,
            "nonce":self.nonce,"boot_id":self.boot,"sequence":self.sequence,
            "executable_sha256":self.executable,"details":details})
        );
        std::io::stdout().flush()?;
        Ok(())
    }
}

fn published_case(case: &Path) -> Result<(PathBuf, PathBuf, File)> {
    private_dir(case)?;
    let lock = lock_case(case, true)?;
    let source = case.join("podbay.sqlite");
    let staging = case.join("old.sqlite");
    new_file(&source)?.sync_all()?;
    drop(PodBayStore::open(&source)?);
    let connection = Connection::open(&source)?;
    connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;")?;
    require(
        connection.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))? == 24,
        "fresh store was not v24",
    )?;
    drop(connection);
    let staged = stage_schema_v25(&source, &staging)?;
    staged.persist_exchange_intent(MIGRATION)?;
    let directory = File::open(case)?;
    rustix::fs::renameat_with(
        &directory,
        source.file_name().ok_or("source name")?,
        &directory,
        staging.file_name().ok_or("staging name")?,
        rustix::fs::RenameFlags::EXCHANGE,
    )?;
    persist_schema_v25_receipt(&source, &staging, MIGRATION)?;
    Ok((source, staging, lock))
}

fn boot_a(context: &mut Context) -> Result<()> {
    require(!context.root.exists(), "boot A never reuses a fixture root")?;
    private_dir(&context.root)?;
    context.event("BOOT_A_STARTED", serde_json::json!({"root":context.root}))?;
    let clean = context.root.join("clean");
    let (source, staging, _clean_lock) = published_case(&clean)?;
    let old_hash = digest(&staging)?;
    let active = activate_disposable_schema_v25(&source, &staging, MIGRATION, ACTIVATION)?;
    let before = active.metadata()?;
    let next = before
        .authority_revision
        .checked_add(1)
        .ok_or("revision overflow")?;
    let mut connection = Connection::open_with_flags(&source, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    connection.execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require(
        tx.execute(
            "UPDATE metadata SET value=?1 WHERE key='authority_revision' AND value=?2",
            params![
                i64::try_from(next)?,
                i64::try_from(before.authority_revision)?
            ],
        )? == 1,
        "revision compare-and-update failed",
    )?;
    tx.commit()?;
    drop(connection);
    File::open(&source)?.sync_all()?;
    File::open(&clean)?.sync_all()?;
    let after = active.metadata()?;
    require(
        after.authority_revision == next
            && after.owner_epoch == before.owner_epoch
            && after.store_lineage == before.store_lineage,
        "activated revision readback mismatch",
    )?;
    require(digest(&staging)? == old_hash, "preserved v24 changed")?;
    drop(active);
    context.event(
        "ACTIVATED_REVISION_SYNCED",
        serde_json::json!({"authority_revision":next}),
    )?;

    let partial = context.root.join("partial");
    let (partial_source, _, _partial_lock) = published_case(&partial)?;
    let writing = partial_source.with_file_name("podbay.sqlite.v25-activation.json.writing");
    let mut f = new_file(&writing)?;
    f.write_all(PARTIAL)?;
    f.sync_all()?;
    drop(f);
    File::open(&partial)?.sync_all()?;
    context.event(
        "PARTIAL_CONTROL_SYNCED",
        serde_json::json!({"constructed_control":true}),
    )?;

    let manifest = Manifest {
        schema: SCHEMA.into(),
        nonce: context.nonce.clone(),
        domain: context.domain.clone(),
        boot_a: context.boot.clone(),
        executable_sha256: context.executable.clone(),
        root: context.root.to_str().ok_or("root UTF8")?.into(),
        lineage: after.store_lineage,
        owner_epoch: after.owner_epoch,
        authority_revision: next,
        pins: snapshot(&context.root)?,
    };
    let manifest_path = context.root.join("manifest.json");
    let bytes = serde_json::to_vec(&manifest)?;
    let mut file = new_file(&manifest_path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    File::open(&context.root)?.sync_all()?;
    context.event("BOOT_A_DURABLE", serde_json::json!({"manifest_sha256":digest(&manifest_path)?,
        "authority_revision":next,"files":manifest.pins.len(),"next":"host may kill and reap exact QEMU"}))
}

fn boot_b(context: &mut Context) -> Result<()> {
    require(
        pin(&context.root, &context.root)?.directory,
        "fixture root is not a private directory",
    )?;
    let manifest_path = context.root.join("manifest.json");
    let manifest_pin = pin(&context.root, &manifest_path)?;
    require(manifest_pin.bytes <= 65536, "manifest bound")?;
    let raw = fs::read(&manifest_path)?;
    let manifest: Manifest = serde_json::from_slice(&raw)?;
    require(
        serde_json::to_vec(&manifest)? == raw,
        "noncanonical manifest",
    )?;
    require(
        manifest.schema == SCHEMA
            && manifest.nonce == context.nonce
            && manifest.domain == context.domain
            && manifest.executable_sha256 == context.executable
            && Path::new(&manifest.root) == context.root,
        "foreign manifest",
    )?;
    let cold = manifest.boot_a != context.boot;
    require(
        context.domain == "host-process-control" || cold,
        "COLD_BOOT_REQUIRED: guest boot ID did not change",
    )?;
    require(
        snapshot(&context.root)? == manifest.pins,
        "persisted bytes or identity changed",
    )?;
    context.event(
        "BOOT_B_PINNED",
        serde_json::json!({"cold_boot_verified":cold,"boot_a":manifest.boot_a,
        "manifest_sha256":manifest_pin.sha256}),
    )?;
    let clean = context.root.join("clean");
    let _clean_lock = lock_case(&clean, false)?;
    let source = clean.join("podbay.sqlite");
    let staging = clean.join("old.sqlite");
    let recovered = recover_disposable_v25_activation(&source, &staging, MIGRATION, ACTIVATION)?;
    require(
        recovered.authority_revision == manifest.authority_revision
            && recovered.owner_epoch == manifest.owner_epoch
            && recovered.store_lineage == manifest.lineage,
        "cold activation metadata mismatch",
    )?;
    require(
        matches!(
            PodBayStore::open(&source),
            Err(StoreError::UnsupportedSchema(25))
        ),
        "ordinary writer did not refuse exactly UnsupportedSchema(25)",
    )?;
    require(
        matches!(
            PodBayStore::open_existing_read_only(&source),
            Err(StoreError::UnsupportedSchema(25))
        ),
        "ordinary reader did not refuse exactly UnsupportedSchema(25)",
    )?;
    require(
        matches!(
            recover_schema_v25_intent(&source, &staging, MIGRATION),
            Err(V25StagingError::Safety(FROZEN))
        ),
        "frozen migration helper did not refuse activation",
    )?;
    require(
        matches!(
            recover_disposable_v25_activation(&source, &staging, MIGRATION, "activation.foreign"),
            Err(V25StagingError::Safety(_))
        ),
        "foreign activation key was not refused",
    )?;
    context.event("CLEAN_RECOVERY_AND_REFUSALS", serde_json::json!({"authority_revision":recovered.authority_revision,
        "ordinary_write":"UnsupportedSchema(25)","ordinary_read":"UnsupportedSchema(25)","frozen_exchange":"refused","foreign_key":"refused"}))?;
    let partial = context.root.join("partial");
    let _partial_lock = lock_case(&partial, false)?;
    let psource = partial.join("podbay.sqlite");
    let pstage = partial.join("old.sqlite");
    require(
        matches!(
            recover_disposable_v25_activation(&psource, &pstage, MIGRATION, ACTIVATION),
            Err(V25StagingError::Safety(_))
        ),
        "partial activation was not refused",
    )?;
    require(
        !psource
            .with_file_name("podbay.sqlite.v25-activation.json")
            .exists(),
        "partial control unexpectedly activated",
    )?;
    require(
        snapshot(&context.root)? == manifest.pins
            && pin(&context.root, &manifest_path)? == manifest_pin,
        "readback/refusal modified fixture bytes or identities",
    )?;
    context.event("BOOT_B_VERIFIED", serde_json::json!({"cold_boot_verified":cold,
        "manifest_sha256":manifest_pin.sha256,"authority_revision":recovered.authority_revision,
        "partial_control":"refused_and_unchanged","scope":"disposable persistence and refusal only"}))
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    require(
        args.len() == 5,
        "usage: v25_two_boot_fixture boot-a|boot-b ABSOLUTE_ROOT NONCE guest|host-process-control",
    )?;
    let phase = &args[1];
    let root = PathBuf::from(&args[2]);
    let nonce = &args[3];
    let domain = &args[4];
    require(
        matches!(phase.as_str(), "boot-a" | "boot-b"),
        "unknown phase",
    )?;
    require(
        matches!(domain.as_str(), "guest" | "host-process-control"),
        "unknown execution domain",
    )?;
    require(
        nonce.len() == 32
            && nonce
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            && nonce.bytes().any(|b| b != b'0'),
        "nonce must be nonzero lowercase hexadecimal length32",
    )?;
    require(
        root.is_absolute()
            && root
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
        "unsafe root path",
    )?;
    require(
        root.file_name().and_then(|n| n.to_str()) == Some(&format!("podbay-v25-fixture-{nonce}")),
        "fixture root must bind nonce",
    )?;
    let parent = root.parent().ok_or("missing parent")?;
    require(fs::canonicalize(parent)? == parent, "symlinked parent")?;
    let parent_meta = fs::metadata(parent)?;
    require(
        parent_meta.is_dir()
            && parent_meta.mode() & 0o022 == 0
            && (parent_meta.uid() == 0 || parent_meta.uid() == nix::unistd::geteuid().as_raw()),
        "unsafe fixture parent",
    )?;
    if domain == "guest" {
        require(
            nix::unistd::geteuid().is_root(),
            "guest fixture requires trusted root PID1 domain",
        )?;
    }
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    require(
        boot.len() == 36 && boot.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
        "invalid kernel boot ID",
    )?;
    let mut context = Context {
        root,
        nonce: nonce.clone(),
        domain: domain.clone(),
        boot,
        executable: digest(Path::new("/proc/self/exe"))?,
        sequence: 0,
    };
    if phase == "boot-a" {
        boot_a(&mut context)
    } else {
        boot_b(&mut context)
    }
}
fn main() {
    if let Err(error) = run() {
        eprintln!(
            "PODBAY_V25_FIXTURE {}",
            serde_json::json!({"schema":SCHEMA,"event":"FIXTURE_FAILED",
            "gate":"CLOSED","admission":"UNIMPLEMENTED","error":error.to_string()})
        );
        std::process::exit(2);
    }
}
