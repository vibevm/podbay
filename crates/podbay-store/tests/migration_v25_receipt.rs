#![cfg(target_os = "linux")]

use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_store::{
    PodBayStore, V25ExchangeOrientation, persist_schema_v25_receipt, recover_schema_v25_intent,
    recover_schema_v25_receipt, stage_schema_v25,
};
use rusqlite::Connection;

struct Fixture {
    directory: PathBuf,
    source: PathBuf,
    staging: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "podbay-publication-receipt-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let source = directory.join("podbay.sqlite");
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&source)
            .unwrap();
        drop(PodBayStore::open(&source).unwrap());
        let connection = Connection::open(&source).unwrap();
        connection
            .execute_batch(
                "PRAGMA journal_mode=DELETE; UPDATE metadata SET value=3 WHERE key='owner_epoch';",
            )
            .unwrap();
        connection.execute(
            "INSERT INTO commands(command_rowid,command_id,principal,namespace,command_key,scope_id,target_id,digest_version,request_digest,canonical_request,owner_epoch,target_epoch)
             VALUES(1,'command.receipt.stop','fixture.principal','fixture.stop','stop.key','scope.alpha','pod.alpha','sha256-v1',?1,X'02',3,1)",
            ["a".repeat(64)],
        ).unwrap();
        connection.execute(
            "INSERT INTO outbox(outbox_id,command_rowid,scope_id,target_id,owner_epoch,target_epoch,kind,payload,state,claim_key,claim_owner_epoch,effect_digest)
             VALUES(1,1,'scope.alpha','pod.alpha',3,1,'pod.stop',X'03','claimed_uncertain','claim.stop',3,?1)",
            ["b".repeat(64)],
        ).unwrap();
        drop(connection);
        let staging = directory.join("podbay.sqlite.staged");
        Self {
            directory,
            source,
            staging,
        }
    }

    fn persist(&self) -> PathBuf {
        let staged = stage_schema_v25(&self.source, &self.staging).unwrap();
        let path = staged.persist_exchange_intent("key.intent").unwrap();
        drop(staged);
        path
    }

    fn swap(&self) {
        let directory = File::open(&self.directory).unwrap();
        rustix::fs::renameat_with(
            &directory,
            self.source.file_name().unwrap(),
            &directory,
            self.staging.file_name().unwrap(),
            rustix::fs::RenameFlags::EXCHANGE,
        )
        .unwrap();
        // Intentionally omit directory fsync to exercise the post-exchange seam.
    }

    fn recover(&self) -> V25ExchangeOrientation {
        recover_schema_v25_intent(&self.source, &self.staging, "key.intent")
            .unwrap()
            .orientation
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn receipt_requires_published_pair_and_preserves_old_effect_state() {
    let fixture = Fixture::new();
    fixture.persist();
    assert!(persist_schema_v25_receipt(&fixture.source, &fixture.staging, "key.intent").is_err());
    fixture.swap();
    let inode = fs::metadata(&fixture.source).unwrap().ino();
    let receipt =
        persist_schema_v25_receipt(&fixture.source, &fixture.staging, "key.intent").unwrap();
    let bytes = fs::read(&receipt.receipt_path).unwrap();
    let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(record["payload"]["disposition"], "published_unactivated");
    assert_eq!(
        fs::metadata(&receipt.receipt_path).unwrap().mode() & 0o7777,
        0o600
    );
    assert_eq!(
        receipt.intent().orientation,
        V25ExchangeOrientation::Published
    );
    assert_eq!(fixture.recover(), V25ExchangeOrientation::Published);
    let retry =
        persist_schema_v25_receipt(&fixture.source, &fixture.staging, "key.intent").unwrap();
    assert_eq!(retry.intent_digest, receipt.intent_digest);
    assert_eq!(fs::read(&retry.receipt_path).unwrap(), bytes);
    assert_eq!(fs::metadata(&fixture.source).unwrap().ino(), inode);
    let verified =
        Connection::open_with_flags(&fixture.source, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let state: String = verified
        .query_row("SELECT state FROM outbox WHERE outbox_id=1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        state, "claimed_uncertain",
        "publication cannot settle the old Pod effect"
    );
    drop(verified);
    assert!(PodBayStore::open_existing_read_only(&fixture.source).is_err());
}

#[test]
fn receipt_rejects_conflicting_key_payload_corruption_and_partial_companion() {
    for change in [
        "key",
        "format",
        "digest",
        "intent_digest",
        "disposition",
        "path",
        "truncated",
        "partial",
    ] {
        let fixture = Fixture::new();
        fixture.persist();
        fixture.swap();
        let receipt =
            persist_schema_v25_receipt(&fixture.source, &fixture.staging, "key.intent").unwrap();
        let bytes = fs::read(&receipt.receipt_path).unwrap();
        assert!(
            persist_schema_v25_receipt(&fixture.source, &fixture.staging, "key.foreign").is_err()
        );
        assert!(
            recover_schema_v25_receipt(&fixture.source, &fixture.staging, "key.foreign").is_err()
        );
        if change == "partial" {
            fs::write(
                format!("{}.writing", receipt.receipt_path.display()),
                b"partial",
            )
            .unwrap();
        } else if change == "truncated" {
            fs::write(&receipt.receipt_path, &bytes[..bytes.len() / 2]).unwrap();
        } else {
            let mut record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            match change {
                "key" => record["payload"]["key"] = "foreign.key".into(),
                "format" => record["format"] = "future/2".into(),
                "digest" => record["receipt_digest"] = "0".repeat(64).into(),
                "intent_digest" => record["payload"]["intent_digest"] = "0".repeat(64).into(),
                "disposition" => record["payload"]["disposition"] = "activated".into(),
                "path" => {
                    record["payload"]["attestation"]["source_path"] =
                        "/foreign/source.sqlite".into()
                }
                _ => unreachable!(),
            }
            fs::write(&receipt.receipt_path, serde_json::to_vec(&record).unwrap()).unwrap();
        }
        assert!(
            recover_schema_v25_receipt(&fixture.source, &fixture.staging, "key.intent").is_err(),
            "{change}"
        );
        assert!(
            persist_schema_v25_receipt(&fixture.source, &fixture.staging, "key.intent").is_err(),
            "{change}"
        );
    }
}

#[test]
fn receipt_binds_exact_intent_bytes_and_current_published_content() {
    for change in [
        "intent_bytes",
        "intent_missing",
        "content",
        "schema",
        "lineage",
        "highwater",
        "inode",
        "sidecar",
        "unpublished",
    ] {
        let fixture = Fixture::new();
        let intent = fixture.persist();
        fixture.swap();
        persist_schema_v25_receipt(&fixture.source, &fixture.staging, "key.intent").unwrap();
        match change {
            "intent_bytes" => {
                let mut bytes = fs::read(&intent).unwrap();
                bytes.push(b' ');
                fs::write(intent, bytes).unwrap();
                // Semantic intent remains valid, but its exact bytes no longer match receipt.
                assert_eq!(fixture.recover(), V25ExchangeOrientation::Published);
            }
            "intent_missing" => fs::remove_file(intent).unwrap(),
            "content" | "schema" | "lineage" | "highwater" => {
                let c = Connection::open(&fixture.source).unwrap();
                c.execute_batch(match change {
                    "content" => "UPDATE metadata SET value=99 WHERE key='owner_epoch'",
                    "schema" => "CREATE TABLE foreign_receipt(value INTEGER) STRICT",
                    "lineage" => {
                        "UPDATE store_identity SET lineage='foreign.lineage' WHERE singleton=1"
                    }
                    "highwater" => "INSERT INTO sqlite_sequence(name,seq) VALUES('commands',99)",
                    _ => unreachable!(),
                })
                .unwrap();
            }
            "inode" => {
                let replacement = fixture.directory.join("replacement");
                fs::copy(&fixture.source, &replacement).unwrap();
                fs::rename(replacement, &fixture.source).unwrap();
            }
            "sidecar" => {
                fs::write(format!("{}-wal", fixture.source.display()), b"foreign").unwrap()
            }
            "unpublished" => fixture.swap(),
            _ => unreachable!(),
        }
        assert!(
            recover_schema_v25_receipt(&fixture.source, &fixture.staging, "key.intent").is_err(),
            "{change}"
        );
        assert!(
            persist_schema_v25_receipt(&fixture.source, &fixture.staging, "key.intent").is_err(),
            "{change}"
        );
    }
}

#[test]
fn receipt_refuses_nonprivate_links_and_foreign_path() {
    for change in ["mode", "symlink", "hardlink", "foreign_path"] {
        let fixture = Fixture::new();
        fixture.persist();
        fixture.swap();
        let receipt =
            persist_schema_v25_receipt(&fixture.source, &fixture.staging, "key.intent").unwrap();
        match change {
            "mode" => fs::set_permissions(&receipt.receipt_path, fs::Permissions::from_mode(0o640))
                .unwrap(),
            "symlink" => {
                let old = fixture.directory.join("receipt.old");
                fs::rename(&receipt.receipt_path, &old).unwrap();
                std::os::unix::fs::symlink(old, &receipt.receipt_path).unwrap();
            }
            "hardlink" => fs::hard_link(
                &receipt.receipt_path,
                fixture.directory.join("receipt.link"),
            )
            .unwrap(),
            "foreign_path" => {
                assert!(
                    recover_schema_v25_receipt(
                        &fixture.source,
                        fixture.directory.join("foreign.sqlite"),
                        "key.intent"
                    )
                    .is_err()
                );
                continue;
            }
            _ => unreachable!(),
        }
        assert!(
            recover_schema_v25_receipt(&fixture.source, &fixture.staging, "key.intent").is_err(),
            "{change}"
        );
        assert!(
            persist_schema_v25_receipt(&fixture.source, &fixture.staging, "key.intent").is_err(),
            "{change}"
        );
    }
}

#[test]
fn receipt_restart_reader_child() {
    let Some(source) = std::env::var_os("PODBAY_RECEIPT_PROBE_SOURCE") else {
        return;
    };
    let stage = std::env::var_os("PODBAY_RECEIPT_PROBE_STAGE").unwrap();
    let result =
        recover_schema_v25_receipt(PathBuf::from(source), PathBuf::from(stage), "key.intent")
            .unwrap();
    assert_eq!(
        result.intent().orientation,
        V25ExchangeOrientation::Published
    );
    println!("fresh-process receipt Published verified");
}

#[test]
fn receipt_fresh_process_reopens_intent_and_pair_without_reexchange() {
    let fixture = Fixture::new();
    fixture.persist();
    fixture.swap();
    drop(persist_schema_v25_receipt(&fixture.source, &fixture.staging, "key.intent").unwrap());
    let inode = fs::metadata(&fixture.source).unwrap().ino();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "receipt_restart_reader_child", "--nocapture"])
        .env("PODBAY_RECEIPT_PROBE_SOURCE", &fixture.source)
        .env("PODBAY_RECEIPT_PROBE_STAGE", &fixture.staging)
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{} {}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    println!("{}", String::from_utf8_lossy(&child.stdout));
    assert_eq!(fs::metadata(&fixture.source).unwrap().ino(), inode);
}

#[test]
fn staging_reserves_exact_canonical_metadata_and_sqlite_companions_before_creation() {
    for suffix in [
        ".v25-intent.json",
        ".v25-intent.json.writing",
        ".v25-publication-receipt.json",
        ".v25-publication-receipt.json.writing",
        "-wal",
        "-shm",
        "-journal",
    ] {
        for occupied in [false, true] {
            let fixture = Fixture::new();
            let before = fs::read(&fixture.source).unwrap();
            let inode = fs::metadata(&fixture.source).unwrap().ino();
            let mut name = fixture.source.as_os_str().to_os_string();
            name.push(suffix);
            let reserved = PathBuf::from(name);
            let foreign = b"foreign namespace sentinel";
            if occupied {
                fs::write(&reserved, foreign).unwrap();
            }
            let refused = stage_schema_v25(&fixture.source, &reserved);
            assert!(
                matches!(
                    refused,
                    Err(podbay_store::V25StagingError::Safety(
                        "staging path is reserved for canonical migration metadata or SQLite companions"
                    ))
                ),
                "{suffix}: {refused:?}"
            );
            let after = fs::read(&fixture.source).unwrap();
            assert_eq!(after, before);
            assert_eq!(u32::from_be_bytes(after[60..64].try_into().unwrap()), 24);
            assert_eq!(fs::metadata(&fixture.source).unwrap().ino(), inode);
            if occupied {
                assert_eq!(fs::read(&reserved).unwrap(), foreign);
            } else {
                assert!(!reserved.exists());
            }
        }
    }
}
