#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    directory: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "podbay-restart-closed-{}-{nonce}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        for (name, bytes) in [
            (
                "operator-zap-policy.json",
                b"policy must not be parsed".as_slice(),
            ),
            ("podbay.sqlite", b"authority must not be opened".as_slice()),
            (
                "owner-key.1.json",
                b"key custody must not be loaded".as_slice(),
            ),
            (
                "operator-zap-stop-terminal.json",
                br#"{"terminal":true,"childExited":true,"stage":"ready"}"#.as_slice(),
            ),
        ] {
            let path = directory.join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        Self { directory }
    }

    fn policy(&self) -> PathBuf {
        self.directory.join("operator-zap-policy.json")
    }

    fn args(&self, policy: &Path, key: impl Into<OsString>) -> Vec<OsString> {
        vec![
            "operator".into(),
            "zap".into(),
            "restart".into(),
            "--policy".into(),
            policy.as_os_str().into(),
            "--request-key".into(),
            key.into(),
        ]
    }

    fn run(&self, args: &[OsString]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_podbay"))
            .args(args)
            .current_dir(&self.directory)
            // An accidental external-tool call cannot reach the user's services.
            .env("PATH", &self.directory)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if child.try_wait().unwrap().is_some() {
                return child.wait_with_output().unwrap();
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("closed restart did not return within five seconds");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    device: u64,
    inode: u64,
    mode: u32,
    modified_seconds: i64,
    modified_nanos: i64,
    contents: Option<Vec<u8>>,
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Entry>) {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(metadata.is_file() || metadata.is_dir());
        result.insert(
            path.strip_prefix(root).unwrap().to_owned(),
            Entry {
                device: metadata.dev(),
                inode: metadata.ino(),
                mode: metadata.mode(),
                modified_seconds: metadata.mtime(),
                modified_nanos: metadata.mtime_nsec(),
                contents: metadata.is_file().then(|| fs::read(path).unwrap()),
            },
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                visit(root, &entry.unwrap().path(), result);
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}

fn assert_closed(output: &Output, key: &str) {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value,
        json!({
            "protocol": "podbay.operator-zap-restart/1",
            "requestKey": key,
            "disposition": "unsupported",
            "code": "production_restart_closed",
            "allocatedGeneration": null,
            "acceptedLaunch": null,
            "missingCapabilities": [
                "trusted_terminal_acquisition",
                "trusted_historical_signer_snapshot",
                "durable_generation_publication",
                "authenticated_child_readiness",
            ],
        }),
    );
}

#[test]
fn restart_default_closed_refuses_before_policy_or_authority_io() {
    let fixture = Fixture::new();
    let before = snapshot(&fixture.directory);
    let output = fixture.run(&fixture.args(&fixture.policy(), "restart.closed"));
    assert_closed(&output, "restart.closed");
    assert_eq!(snapshot(&fixture.directory), before);

    let absent = fixture.directory.join("absent/operator-zap-policy.json");
    let output = fixture.run(&fixture.args(&absent, "restart.absent"));
    assert_closed(&output, "restart.absent");
    assert_eq!(snapshot(&fixture.directory), before);
}

#[test]
fn restart_repeated_request_is_an_identical_side_effect_free_refusal() {
    let fixture = Fixture::new();
    let before = snapshot(&fixture.directory);
    let args = fixture.args(&fixture.policy(), "restart.same-key");
    let first = fixture.run(&args);
    let second = fixture.run(&args);
    assert_closed(&first, "restart.same-key");
    assert_closed(&second, "restart.same-key");
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(snapshot(&fixture.directory), before);
}

#[test]
fn restart_parser_rejects_invalid_flags_paths_and_keys_without_effects() {
    let fixture = Fixture::new();
    let before = snapshot(&fixture.directory);
    let correct = fixture.args(&fixture.policy(), "restart.valid");
    let mut missing = correct.clone();
    missing.truncate(5);
    let mut duplicate = correct.clone();
    duplicate.extend([
        OsString::from("--request-key"),
        OsString::from("restart.other"),
    ]);
    let mut reordered = correct.clone();
    reordered[3..].rotate_left(2);
    let mut unknown = correct.clone();
    unknown[5] = "--enable".into();
    let mut foreign_command = correct.clone();
    foreign_command[1] = "other".into();
    let mut cases = vec![missing, duplicate, reordered, unknown, foreign_command];
    cases.push(fixture.args(Path::new("operator-zap-policy.json"), "restart.valid"));
    cases.push(fixture.args(&fixture.directory.join("policy.json"), "restart.valid"));
    for key in ["".into(), "ab".into(), "bad key".into(), "x".repeat(161)] {
        cases.push(fixture.args(&fixture.policy(), key));
    }
    cases.push(fixture.args(
        &fixture.policy(),
        OsString::from_vec(vec![b'x', 0xff, b'x']),
    ));
    for args in cases {
        let output = fixture.run(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .starts_with("podbay operator zap: "),
            "{args:?}",
        );
    }
    assert_eq!(snapshot(&fixture.directory), before);
}
