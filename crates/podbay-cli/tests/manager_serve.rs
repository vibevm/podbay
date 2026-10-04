#![cfg(target_os = "linux")]

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_compact::{KeyPair, Seed};
use podbay_client::authenticate_existing_linux_stream;
use podbay_store::PodBayStore;
use podbay_wire::{CommandEnvelope, MutationOperation, ReadEnvelope, ReadOperation, Target};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

struct Fixture {
    root: PathBuf,
    state: PathBuf,
    pods: PathBuf,
    database: PathBuf,
    binary: PathBuf,
    digest: String,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("podbay-cli-manager-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let state = root.join("state");
        let pods = root.join("pods");
        for directory in [&state, &pods] {
            fs::create_dir(directory).unwrap();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let binary = root.join("pod-binary");
        let contents = b"#!/bin/sh\nexit 0\n";
        fs::write(&binary, contents).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let digest = Sha256::digest(contents)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Self {
            database: state.join("podbay.sqlite"),
            root,
            state,
            pods,
            binary,
            digest,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_podbay"));
        command
            .arg("manager")
            .arg("serve")
            .arg("--state-dir")
            .arg(&self.state)
            .arg("--database")
            .arg(&self.database)
            .arg("--pod-dir")
            .arg(&self.pods)
            .arg("--pod-binary")
            .arg(&self.binary)
            .arg("--pod-sha256")
            .arg(&self.digest)
            .stdin(Stdio::null());
        command
    }

    fn setup_command(&self) -> Command {
        let mut command = self.command();
        command
            .arg("--initial-owner-actor")
            .arg("actor.zap.test")
            .arg("--initial-owner-scope")
            .arg("scope.zap.test")
            .arg("--initial-owner-credential")
            .arg("vault.zap.test");
        command
    }

    fn trusted_policy_file(&self) -> PathBuf {
        let credentials = self.root.join("credentials");
        fs::create_dir(&credentials).unwrap();
        fs::set_permissions(&credentials, fs::Permissions::from_mode(0o700)).unwrap();
        let source = credentials.join("dummy-auth.json");
        fs::write(&source, b"dummy credential fixture").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        let workspace = self.root.join("workspace");
        fs::create_dir(&workspace).unwrap();
        let path = self.state.join("trusted-policy.json");
        let value = json!({
            "schema": "podbay.trusted-manager-policy/1",
            "actorId": "actor.zap.test",
            "scopeId": "scope.zap.test",
            "credentialRef": "vault.zap.test",
            "credentialSource": source,
            "profileRef": "profile.codex.test",
            "profileGeneration": 1,
            "executable": self.binary,
            "executableSha256": self.digest,
            "workspaceRoot": workspace,
            "workspaceBasisRef": "basis.test",
            "hostId": "host.test",
            "driverRef": "driver.codex.test",
            "protocolRef": "protocol.codex.test",
            "modelId": "gpt-6-sol",
            "reasoningEffort": "medium",
            "approvalPolicy": "never",
            "sandbox": "danger_full_access",
            "wallSeconds": 60,
            "maxChildren": 2,
            "resultContractRef": "result.none",
            "launchDeadlineSeconds": 30,
            "sendDeadlineSeconds": 30,
            "writerLeaseSeconds": 120,
        });
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn policy_command(&self, path: &PathBuf) -> Command {
        let mut command = self.command();
        command.arg("--trusted-policy").arg(path);
        command
    }

    fn socket(&self) -> PathBuf {
        self.state.join("manager.sock")
    }

    fn setup_socket(&self) -> PathBuf {
        self.state.join("owner-setup.sock")
    }

    fn recovery_socket(&self) -> PathBuf {
        self.state.join("owner-recovery.sock")
    }

    fn owner_epoch(&self) -> u64 {
        PodBayStore::open(&self.database)
            .unwrap()
            .owner_epoch()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct Running(Child);

impl Running {
    fn spawn(fixture: &Fixture) -> Self {
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(fixture.root.join("manager.log"))
            .unwrap();
        let child = fixture
            .command()
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        Self(child)
    }

    fn wait_ready(&mut self, fixture: &Fixture) {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                let log = fs::read_to_string(fixture.root.join("manager.log")).unwrap_or_default();
                panic!("manager exited before readiness: {status}; {log}");
            }
            if fs::symlink_metadata(fixture.socket())
                .is_ok_and(|metadata| metadata.file_type().is_socket())
                && UnixStream::connect(fixture.socket()).is_ok()
            {
                return;
            }
            assert!(Instant::now() < until, "manager socket did not appear");
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_setup_ready(&mut self, fixture: &Fixture) {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                let log = fs::read_to_string(fixture.root.join("manager.log")).unwrap_or_default();
                panic!("manager exited before setup socket: {status}; {log}");
            }
            if fs::symlink_metadata(fixture.setup_socket()).is_ok_and(|metadata| {
                metadata.file_type().is_socket() && metadata.mode() & 0o7777 == 0o600
            }) {
                return;
            }
            assert!(Instant::now() < until, "owner setup socket did not appear");
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_recovery_ready(&mut self, fixture: &Fixture) {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                let log = fs::read_to_string(fixture.root.join("manager.log")).unwrap_or_default();
                panic!("manager exited before recovery socket: {status}; {log}");
            }
            if fs::symlink_metadata(fixture.recovery_socket()).is_ok_and(|metadata| {
                metadata.file_type().is_socket() && metadata.mode() & 0o7777 == 0o600
            }) {
                return;
            }
            assert!(
                Instant::now() < until,
                "owner recovery socket did not appear"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_exit(&mut self) -> ExitStatus {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < until,
                "manager did not exit after setup refusal"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn stop_with(&mut self, signal: &str) -> ExitStatus {
        let sent = Command::new("kill")
            .arg(format!("-{signal}"))
            .arg(self.0.id().to_string())
            .status()
            .unwrap();
        assert!(sent.success(), "failed to signal manager");
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < until, "manager did not stop after signal");
            thread::sleep(Duration::from_millis(20));
        }
    }
}

fn spawn_setup(fixture: &Fixture) -> Running {
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(fixture.root.join("manager.log"))
        .unwrap();
    Running(
        fixture
            .setup_command()
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    )
}

fn spawn_policy(fixture: &Fixture, path: &PathBuf) -> Running {
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(fixture.root.join("manager.log"))
        .unwrap();
    Running(
        fixture
            .policy_command(path)
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    )
}

fn write_frame(stream: &mut UnixStream, bytes: &[u8]) {
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(bytes).unwrap();
}

fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).unwrap();
    let len = u32::from_be_bytes(prefix) as usize;
    assert!(len <= 8192);
    let mut bytes = vec![0_u8; len];
    stream.read_exact(&mut bytes).unwrap();
    bytes
}

fn setup_attempt(
    fixture: &Fixture,
    key: &KeyPair,
    signer: &KeyPair,
    acknowledge: bool,
) -> Option<Value> {
    let mut socket = UnixStream::connect(fixture.setup_socket()).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write_frame(&mut socket, key.pk.as_ref());
    let challenge = read_frame(&mut socket);
    assert!(challenge.starts_with(b"podbay.owner-initial-enrollment/1\0"));
    let signature = signer.sk.sign(&challenge, None);
    write_frame(&mut socket, signature.as_ref());
    if !acknowledge {
        socket.shutdown(std::net::Shutdown::Read).unwrap();
        return None;
    }
    let receipt: Value = serde_json::from_slice(&read_frame(&mut socket)).unwrap();
    write_frame(&mut socket, b"ack");
    Some(receipt)
}

fn authenticated_missing_read(fixture: &Fixture, signer: &KeyPair) -> Value {
    let socket = UnixStream::connect(fixture.socket()).unwrap();
    let mut stream = authenticate_existing_linux_stream(socket, "actor.zap.test", |challenge| {
        let signature = signer.sk.sign(challenge.bytes, None);
        let mut bytes = [0_u8; 64];
        bytes.copy_from_slice(signature.as_ref());
        Some(bytes)
    })
    .unwrap();
    let request = ReadEnvelope::new_json(
        "request.setup.read",
        Target::Scope {
            scope_id: "scope.zap.test".into(),
        },
        ReadOperation::CommandsGet,
        json!({"selector":{"kind":"key","key":"key.missing"}}),
    )
    .unwrap();
    write_frame(&mut stream, &request.encode_json().unwrap());
    serde_json::from_slice(&read_frame(&mut stream)).unwrap()
}

impl Drop for Running {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn run_short_command(mut command: Command) -> (ExitStatus, String) {
    let mut child = Running(
        command
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            let mut stderr = String::new();
            child
                .0
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            return (status, stderr);
        }
        assert!(
            Instant::now() < until,
            "second manager did not refuse promptly"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn run_short(fixture: &Fixture) -> (ExitStatus, String) {
    run_short_command(fixture.command())
}

fn authenticated_wrong_model_launch(fixture: &Fixture, signer: &KeyPair) -> Value {
    let socket = UnixStream::connect(fixture.socket()).unwrap();
    let mut stream = authenticate_existing_linux_stream(socket, "actor.zap.test", |challenge| {
        let signature = signer.sk.sign(challenge.bytes, None);
        let mut bytes = [0_u8; 64];
        bytes.copy_from_slice(signature.as_ref());
        Some(bytes)
    })
    .unwrap();
    let request = CommandEnvelope::new_json(
        "request.policy.launch",
        "key.policy.launch",
        Target::Scope {
            scope_id: "scope.zap.test".into(),
        },
        None,
        None,
        MutationOperation::Launch,
        json!({
            "session":{"kind":"new"},
            "role":"coordinator",
            "work":{"kind":"service","resultContractRef":"result.none"},
            "profileRef":"profile.codex.test",
            "selection":{"modelId":"model.other","reasoningEffort":"medium","fallback":"none"},
            "workspace":{"scopeId":"scope.zap.test","relativeCwd":".",
                "basisRef":"basis.test","access":"read_write"},
            "toolBundleRefs":[],
            "authority":{"grantRef":"grant.1"},
            "limits":{"wallSeconds":"30","maxChildren":"1"}
        }),
    )
    .unwrap();
    write_frame(&mut stream, &request.encode_json().unwrap());
    serde_json::from_slice(&read_frame(&mut stream)).unwrap()
}

#[test]
fn exclusive_manager_stops_cleanly_and_restarts_over_private_stale_socket() {
    let fixture = Fixture::new();
    let mut first = Running::spawn(&fixture);
    first.wait_ready(&fixture);
    let owner = fixture.owner_epoch();
    assert!(owner > 0);
    let (second_status, second_error) = run_short(&fixture);
    assert!(!second_status.success());
    assert!(second_error.contains("manager owner busy"));
    assert_eq!(fixture.owner_epoch(), owner);
    assert!(first.0.try_wait().unwrap().is_none());

    assert!(first.stop_with("TERM").success());
    assert!(!fixture.socket().exists());
    let mut restarted = Running::spawn(&fixture);
    restarted.wait_ready(&fixture);
    assert_eq!(fixture.owner_epoch(), owner + 1);
    assert!(restarted.stop_with("INT").success());
    assert!(!fixture.socket().exists());
    let epoch_before_stale_socket = fixture.owner_epoch();

    let stale = UnixListener::bind(fixture.socket()).unwrap();
    fs::set_permissions(fixture.socket(), fs::Permissions::from_mode(0o600)).unwrap();
    drop(stale);
    let mut recovered = Running::spawn(&fixture);
    recovered.wait_ready(&fixture);
    assert_eq!(fixture.owner_epoch(), epoch_before_stale_socket + 1);
    assert!(recovered.stop_with("TERM").success());
}

#[test]
fn sigkill_leaves_manager_socket_and_next_process_reconciles_it_under_lock() {
    let fixture = Fixture::new();
    let mut first = Running::spawn(&fixture);
    first.wait_ready(&fixture);
    let epoch = fixture.owner_epoch();
    assert!(!first.stop_with("KILL").success());
    assert!(fixture.socket().exists());
    let mut second = Running::spawn(&fixture);
    second.wait_ready(&fixture);
    assert_eq!(fixture.owner_epoch(), epoch + 1);
    assert!(second.stop_with("TERM").success());
}

#[test]
fn live_or_substituted_socket_refuses_before_owner_epoch_change() {
    let fixture = Fixture::new();
    let mut initial = Running::spawn(&fixture);
    initial.wait_ready(&fixture);
    assert!(initial.stop_with("TERM").success());
    let epoch = fixture.owner_epoch();
    let live = UnixListener::bind(fixture.socket()).unwrap();
    fs::set_permissions(fixture.socket(), fs::Permissions::from_mode(0o600)).unwrap();
    let live_identity = fs::symlink_metadata(fixture.socket()).unwrap();
    let (status, error) = run_short(&fixture);
    assert!(!status.success());
    assert!(error.contains("live listener"), "{error}");
    assert_eq!(fixture.owner_epoch(), epoch);
    let preserved = fs::symlink_metadata(fixture.socket()).unwrap();
    assert_eq!(
        (preserved.dev(), preserved.ino()),
        (live_identity.dev(), live_identity.ino())
    );
    drop(live);
    fs::remove_file(fixture.socket()).unwrap();

    fs::write(fixture.socket(), b"substituted").unwrap();
    fs::set_permissions(fixture.socket(), fs::Permissions::from_mode(0o600)).unwrap();
    let (status, error) = run_short(&fixture);
    assert!(!status.success());
    assert!(error.contains("non-socket"), "{error}");
    assert_eq!(fs::read(fixture.socket()).unwrap(), b"substituted");
    assert_eq!(fixture.owner_epoch(), epoch);
    fs::remove_file(fixture.socket()).unwrap();

    let marker = fixture.root.join("marker");
    fs::write(&marker, b"marker").unwrap();
    std::os::unix::fs::symlink(&marker, fixture.socket()).unwrap();
    let (status, error) = run_short(&fixture);
    assert!(!status.success());
    assert!(error.contains("non-socket"), "{error}");
    assert!(
        fs::symlink_metadata(fixture.socket())
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&marker).unwrap(), b"marker");
    assert_eq!(fixture.owner_epoch(), epoch);
    fs::remove_file(fixture.socket()).unwrap();

    let stale = UnixListener::bind(fixture.socket()).unwrap();
    fs::set_permissions(fixture.socket(), fs::Permissions::from_mode(0o644)).unwrap();
    drop(stale);
    let (status, error) = run_short(&fixture);
    assert!(!status.success());
    assert!(error.contains("mode 0600"), "{error}");
    assert_eq!(fixture.owner_epoch(), epoch);
}

#[test]
fn nonprivate_state_directory_refuses_before_database_creation() {
    let fixture = Fixture::new();
    fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o755)).unwrap();
    let (status, error) = run_short(&fixture);
    assert!(!status.success());
    assert!(error.contains("mode 0700"));
    assert!(!fixture.database.exists());
    fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn launcher_parent_enrolls_once_then_authenticates_on_normal_manager_socket() {
    let fixture = Fixture::new();
    let mut manager = spawn_setup(&fixture);
    manager.wait_setup_ready(&fixture);
    assert!(!fixture.socket().exists());
    let signer = KeyPair::from_seed(Seed::new([7; 32]));
    let receipt = setup_attempt(&fixture, &signer, &signer, true).unwrap();
    assert_eq!(receipt["protocol"], "podbay.owner-initial-enrollment/1");
    assert_eq!(receipt["actorId"], "actor.zap.test");
    assert_eq!(receipt["scopeId"], "scope.zap.test");
    assert_eq!(receipt["grantRef"], "grant.1");
    assert_eq!(receipt["duplicate"], false);
    manager.wait_ready(&fixture);
    assert!(!fixture.setup_socket().exists());
    let read = authenticated_missing_read(&fixture, &signer);
    assert_eq!(read["requestId"], "request.setup.read");
    assert_eq!(read["error"]["code"], "forbidden");
    assert!(manager.stop_with("TERM").success());
    assert!(!fixture.socket().exists());
    assert!(!fixture.setup_socket().exists());
}

#[test]
fn helper_sibling_connects() {
    let Ok(path) = std::env::var("PODAY_TEST_OWNER_SETUP_SOCKET") else {
        return;
    };
    let _socket = UnixStream::connect(path).unwrap();
    thread::sleep(Duration::from_millis(500));
}

#[test]
fn same_uid_sibling_cannot_take_launcher_parent_setup_socket() {
    let fixture = Fixture::new();
    let mut manager = spawn_setup(&fixture);
    manager.wait_setup_ready(&fixture);
    let helper = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("helper_sibling_connects")
        .env("PODAY_TEST_OWNER_SETUP_SOCKET", fixture.setup_socket())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(helper.success());
    assert!(!manager.wait_exit().success());
    assert!(!fixture.socket().exists());
    assert!(!fixture.setup_socket().exists());
    assert!(
        PodBayStore::open(&fixture.database)
            .unwrap()
            .authority_snapshot()
            .unwrap()
            .actors
            .is_empty()
    );
}

#[test]
fn wrong_key_and_partial_frame_refuse_before_enrollment() {
    let fixture = Fixture::new();
    let mut manager = spawn_setup(&fixture);
    manager.wait_setup_ready(&fixture);
    let key = KeyPair::from_seed(Seed::new([7; 32]));
    let wrong_signer = KeyPair::from_seed(Seed::new([8; 32]));
    setup_attempt(&fixture, &key, &wrong_signer, false);
    assert!(!manager.wait_exit().success());
    assert!(!fixture.socket().exists());
    assert!(!fixture.setup_socket().exists());
    assert!(
        PodBayStore::open(&fixture.database)
            .unwrap()
            .authority_snapshot()
            .unwrap()
            .actors
            .is_empty()
    );

    let fixture = Fixture::new();
    let mut manager = spawn_setup(&fixture);
    manager.wait_setup_ready(&fixture);
    let mut socket = UnixStream::connect(fixture.setup_socket()).unwrap();
    socket.write_all(&32_u32.to_be_bytes()).unwrap();
    socket.write_all(&[1_u8; 4]).unwrap();
    drop(socket);
    assert!(!manager.wait_exit().success());
    assert!(!fixture.socket().exists());
    assert!(!fixture.setup_socket().exists());
    assert!(
        PodBayStore::open(&fixture.database)
            .unwrap()
            .authority_snapshot()
            .unwrap()
            .actors
            .is_empty()
    );
}

#[test]
fn lost_receipt_reconciles_same_parent_key_without_second_enrollment() {
    let fixture = Fixture::new();
    let mut manager = spawn_setup(&fixture);
    manager.wait_setup_ready(&fixture);
    let key = KeyPair::from_seed(Seed::new([9; 32]));
    setup_attempt(&fixture, &key, &key, false);
    assert!(!fixture.socket().exists());
    let receipt = setup_attempt(&fixture, &key, &key, true).unwrap();
    assert_eq!(receipt["duplicate"], true);
    manager.wait_ready(&fixture);
    let snapshot = PodBayStore::open(&fixture.database)
        .unwrap()
        .authority_snapshot()
        .unwrap();
    assert_eq!(snapshot.actors.len(), 1);
    assert_eq!(snapshot.grants.len(), 1);
    assert_eq!(snapshot.revision.to_string(), receipt["authorityRevision"]);
    assert_eq!(
        authenticated_missing_read(&fixture, &key)["error"]["code"],
        "forbidden"
    );
    assert!(manager.stop_with("TERM").success());
}

#[test]
fn stale_owner_setup_path_is_reconciled_before_new_setup() {
    let fixture = Fixture::new();
    let path = fixture.setup_socket();
    let stale = UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let identity = fs::symlink_metadata(&path).unwrap();
    drop(stale);
    let mut child = spawn_setup(&fixture);
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        if child.0.try_wait().unwrap().is_some() {
            panic!("replacement setup manager exited");
        }
        if fixture.database.exists()
            && fixture.owner_epoch() > 0
            && fs::read_to_string(fixture.root.join("manager.log"))
                .unwrap_or_default()
                .contains("podbay owner setup socket:")
        {
            break;
        }
        assert!(
            Instant::now() < until,
            "replacement setup owner epoch did not advance"
        );
        thread::sleep(Duration::from_millis(20));
    }
    assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
    assert_eq!(identity.mode() & 0o7777, 0o600);
    assert!(child.stop_with("TERM").success());
    assert!(!path.exists());
}

#[test]
fn sigkill_recovery_socket_is_reconciled_before_next_owner_challenge() {
    let fixture = Fixture::new();
    let policy = fixture.trusted_policy_file();
    let mut enrolled = spawn_policy(&fixture, &policy);
    enrolled.wait_setup_ready(&fixture);
    let signer = KeyPair::from_seed(Seed::new([18; 32]));
    let _receipt = setup_attempt(&fixture, &signer, &signer, true).unwrap();
    enrolled.wait_ready(&fixture);
    assert!(enrolled.stop_with("TERM").success());
    let before = fixture.owner_epoch();

    let mut interrupted = spawn_policy(&fixture, &policy);
    interrupted.wait_recovery_ready(&fixture);
    assert_eq!(fixture.owner_epoch(), before + 1);
    assert!(!interrupted.stop_with("KILL").success());
    assert!(fixture.recovery_socket().exists());

    let mut next = spawn_policy(&fixture, &policy);
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        if next.0.try_wait().unwrap().is_some() {
            panic!("replacement recovery manager exited");
        }
        let log = fs::read_to_string(fixture.root.join("manager.log")).unwrap_or_default();
        if fixture.owner_epoch() == before + 2
            && log.matches("podbay owner recovery socket:").count() == 2
        {
            break;
        }
        assert!(
            Instant::now() < until,
            "replacement owner recovery socket did not bind"
        );
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        fs::symlink_metadata(fixture.recovery_socket())
            .unwrap()
            .file_type()
            .is_socket()
    );
    let _ = next.stop_with("TERM");
    assert!(!fixture.recovery_socket().exists());
}

#[test]
fn private_trusted_policy_enables_reviewed_route_after_parent_enrollment() {
    let fixture = Fixture::new();
    let policy = fixture.trusted_policy_file();
    let mut manager = spawn_policy(&fixture, &policy);
    manager.wait_setup_ready(&fixture);
    let signer = KeyPair::from_seed(Seed::new([11; 32]));
    let receipt = setup_attempt(&fixture, &signer, &signer, true).unwrap();
    assert_eq!(receipt["grantRef"], "grant.1");
    manager.wait_ready(&fixture);
    let reply = authenticated_wrong_model_launch(&fixture, &signer);
    assert_eq!(reply["requestId"], "request.policy.launch");
    assert_ne!(reply["error"]["code"], "unsupported");
    assert_eq!(
        PodBayStore::open(&fixture.database)
            .unwrap()
            .scope_snapshot("scope.zap.test")
            .unwrap()
            .receipts
            .len(),
        0
    );
    assert!(manager.stop_with("TERM").success());

    // A new manager owner epoch cannot silently turn an old process-bound
    // enrollment into a new first enrollment. Invalid recovery proof refuses.
    let before = PodBayStore::open(&fixture.database)
        .unwrap()
        .authority_snapshot()
        .unwrap();
    let mut restarted = spawn_policy(&fixture, &policy);
    restarted.wait_recovery_ready(&fixture);
    let mut socket = UnixStream::connect(fixture.recovery_socket()).unwrap();
    write_frame(&mut socket, &[0; 64]);
    drop(socket);
    assert!(!restarted.wait_exit().success());
    assert!(!fixture.socket().exists());
    let after = PodBayStore::open(&fixture.database)
        .unwrap()
        .authority_snapshot()
        .unwrap();
    assert_eq!(after.actors, before.actors);
    assert_eq!(after.grants, before.grants);
    assert_eq!(after.owner_epoch, before.owner_epoch + 1);
}

#[test]
fn policy_file_must_be_private_canonical_and_fixed() {
    let fixture = Fixture::new();
    let policy = fixture.trusted_policy_file();
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o644)).unwrap();
    let (status, error) = run_short_command(fixture.policy_command(&policy));
    assert!(!status.success());
    assert!(error.contains("canonical owned 0600"));
    assert!(!fixture.database.exists());

    fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
    let mut value: Value = serde_json::from_slice(&fs::read(&policy).unwrap()).unwrap();
    value["approvalPolicy"] = json!("ask");
    fs::write(&policy, serde_json::to_vec(&value).unwrap()).unwrap();
    let (status, error) = run_short_command(fixture.policy_command(&policy));
    assert!(!status.success());
    assert!(error.contains("fixed Codex fields"));
    assert!(!fixture.database.exists());
}
