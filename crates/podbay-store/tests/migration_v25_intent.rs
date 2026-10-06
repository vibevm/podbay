#![cfg(target_os = "linux")]

use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_store::{
    PodBayStore, V25ExchangeOrientation, recover_schema_v25_intent, stage_schema_v25,
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
            "podbay-durable-intent-{}-{nonce}",
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
fn intent_fresh_open_reconstructs_both_orientations_without_exchange() {
    let fixture = Fixture::new();
    let intent = fixture.persist();
    assert_eq!(fs::metadata(&intent).unwrap().mode() & 0o7777, 0o600);
    assert_eq!(fixture.recover(), V25ExchangeOrientation::Unpublished);
    fixture.swap();
    let inode = fs::metadata(&fixture.source).unwrap().ino();
    assert_eq!(fixture.recover(), V25ExchangeOrientation::Published);
    assert_eq!(fixture.recover(), V25ExchangeOrientation::Published);
    assert_eq!(fs::metadata(&fixture.source).unwrap().ino(), inode);
    assert!(PodBayStore::open_existing_read_only(&fixture.source).is_err());
}

#[test]
fn intent_key_retry_is_exact_and_missing_published_intent_cannot_be_invented() {
    let fixture = Fixture::new();
    let staged = stage_schema_v25(&fixture.source, &fixture.staging).unwrap();
    let path = staged.persist_exchange_intent("key.intent").unwrap();
    assert_eq!(staged.persist_exchange_intent("key.intent").unwrap(), path);
    assert!(recover_schema_v25_intent(&fixture.source, &fixture.staging, "key.foreign").is_err());
    fixture.swap();
    assert_eq!(staged.persist_exchange_intent("key.intent").unwrap(), path);
    assert!(
        staged
            .persist_exchange_intent("key.new-after-publication")
            .is_err()
    );
    assert_eq!(fixture.recover(), V25ExchangeOrientation::Published);
}

#[test]
fn intent_refuses_corrupt_encoding_digest_unknown_fields_and_foreign_paths() {
    for change in ["truncated", "digest", "unknown", "key", "path", "format"] {
        let fixture = Fixture::new();
        let intent = fixture.persist();
        let bytes = fs::read(&intent).unwrap();
        let altered = if change == "truncated" {
            bytes[..bytes.len() / 2].to_vec()
        } else {
            let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            match change {
                "digest" => value["attestation_digest"] = "0".repeat(64).into(),
                "unknown" => value["last_phase"] = "unpublished".into(),
                "key" => value["key"] = "foreign.key".into(),
                "path" => {
                    value["attestation"]["staging_path"] = fixture
                        .directory
                        .join("foreign.sqlite")
                        .to_str()
                        .unwrap()
                        .into()
                }
                "format" => value["format"] = "future/2".into(),
                _ => unreachable!(),
            }
            serde_json::to_vec(&value).unwrap()
        };
        fs::write(&intent, altered).unwrap();
        assert!(
            recover_schema_v25_intent(&fixture.source, &fixture.staging, "key.intent").is_err(),
            "{change}"
        );
        assert!(
            recover_schema_v25_intent(
                &fixture.source,
                fixture.directory.join("foreign.sqlite"),
                "key.intent"
            )
            .is_err()
        );
    }
}

#[test]
fn intent_refuses_changed_content_schema_lineage_highwater_inode_and_companions() {
    for change in [
        "content",
        "schema",
        "lineage",
        "highwater",
        "inode",
        "sidecar",
        "writing",
    ] {
        let fixture = Fixture::new();
        let intent = fixture.persist();
        match change {
            "content" | "schema" | "lineage" | "highwater" => {
                let connection = Connection::open(&fixture.staging).unwrap();
                let sql = match change {
                    "content" => "UPDATE metadata SET value=99 WHERE key='owner_epoch'",
                    "schema" => "CREATE TABLE foreign_table(value INTEGER) STRICT",
                    "lineage" => {
                        "UPDATE store_identity SET lineage='foreign.lineage' WHERE singleton=1"
                    }
                    "highwater" => "INSERT INTO sqlite_sequence(name,seq) VALUES('commands',99)",
                    _ => unreachable!(),
                };
                connection.execute_batch(sql).unwrap();
            }
            "inode" => {
                let replacement = fixture.directory.join("replacement");
                fs::copy(&fixture.staging, &replacement).unwrap();
                fs::rename(replacement, &fixture.staging).unwrap();
            }
            "sidecar" => {
                fs::write(format!("{}-wal", fixture.staging.display()), b"foreign").unwrap()
            }
            "writing" => fs::write(format!("{}.writing", intent.display()), b"partial").unwrap(),
            _ => unreachable!(),
        }
        assert!(
            recover_schema_v25_intent(&fixture.source, &fixture.staging, "key.intent").is_err(),
            "{change}"
        );
    }
}

#[test]
fn intent_refuses_nonprivate_links_and_replaced_parent_identity() {
    for change in ["mode", "symlink", "hardlink", "parent"] {
        let fixture = Fixture::new();
        let intent = fixture.persist();
        match change {
            "mode" => fs::set_permissions(&intent, fs::Permissions::from_mode(0o640)).unwrap(),
            "symlink" => {
                let old = fixture.directory.join("old-intent");
                fs::rename(&intent, &old).unwrap();
                std::os::unix::fs::symlink(old, &intent).unwrap();
            }
            "hardlink" => fs::hard_link(&intent, fixture.directory.join("linked-intent")).unwrap(),
            "parent" => {
                let old = fixture.directory.with_extension("old");
                fs::rename(&fixture.directory, &old).unwrap();
                fs::create_dir(&fixture.directory).unwrap();
                fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o700)).unwrap();
                for name in [
                    fixture.source.file_name().unwrap(),
                    fixture.staging.file_name().unwrap(),
                    intent.file_name().unwrap(),
                ] {
                    fs::rename(old.join(name), fixture.directory.join(name)).unwrap();
                }
                fs::remove_dir(old).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            recover_schema_v25_intent(&fixture.source, &fixture.staging, "key.intent").is_err(),
            "{change}"
        );
    }
}

#[test]
fn restart_reader_child() {
    let Some(source) = std::env::var_os("PODBAY_INTENT_PROBE_SOURCE") else {
        return;
    };
    let staging = std::env::var_os("PODBAY_INTENT_PROBE_STAGING").unwrap();
    let expected = std::env::var("PODBAY_INTENT_PROBE_ORIENTATION").unwrap();
    let recovered =
        recover_schema_v25_intent(PathBuf::from(source), PathBuf::from(staging), "key.intent")
            .unwrap();
    assert_eq!(format!("{:?}", recovered.orientation), expected);
    println!("fresh-process orientation={:?}", recovered.orientation);
}

#[test]
fn intent_recovers_in_fresh_process_after_original_attestation_is_dropped() {
    let fixture = Fixture::new();
    fixture.persist();
    for orientation in ["Unpublished", "Published"] {
        if orientation == "Published" {
            fixture.swap();
        }
        let inode = fs::metadata(&fixture.source).unwrap().ino();
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "restart_reader_child", "--nocapture"])
            .env("PODBAY_INTENT_PROBE_SOURCE", &fixture.source)
            .env("PODBAY_INTENT_PROBE_STAGING", &fixture.staging)
            .env("PODBAY_INTENT_PROBE_ORIENTATION", orientation)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "child status={} stdout={} stderr={}",
            child.status,
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
        println!("{}", String::from_utf8_lossy(&child.stdout));
        assert_eq!(fs::metadata(&fixture.source).unwrap().ino(), inode);
    }
}
