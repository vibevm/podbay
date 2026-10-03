use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use podbay_adapter_codex::{
    ChildLaunchSpec, CodecError, JsonlTransport, ProcessJsonlTransport, decode, encode,
};
use serde_json::json;

static NEXT_DIR: AtomicU64 = AtomicU64::new(1);

struct PrivateDirs {
    root: PathBuf,
    home: PathBuf,
    codex_home: PathBuf,
}

impl PrivateDirs {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "podbay-fake-codex-{}-{nonce}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let home = root.join("home");
        let codex_home = home.join("codex");
        fs::create_dir_all(&codex_home).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&root, &home, &codex_home] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        Self {
            root,
            home,
            codex_home,
        }
    }

    fn spec(&self, mode: &str, read: Duration, write: Duration) -> ChildLaunchSpec {
        ChildLaunchSpec::new(
            PathBuf::from(env!("CARGO_BIN_EXE_podbay_fake_codex_child")),
            vec![OsString::from(mode)],
            self.root.clone(),
            self.home.clone(),
            self.codex_home.clone(),
            read,
            write,
        )
        .unwrap()
    }
}

impl Drop for PrivateDirs {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn fake_child_handshake_frames_and_direct_child_exit_are_observed() {
    let dirs = PrivateDirs::new();
    let mut transport = ProcessJsonlTransport::spawn(dirs.spec(
        "handshake",
        Duration::from_secs(2),
        Duration::from_secs(2),
    ))
    .unwrap();
    let pid = transport.birth().pid;
    assert!(pid > 0);
    assert!(transport.observe_exit().unwrap().is_none());
    transport
        .write_line(&encode(&json!({"id":1,"method":"initialize","params":{"clientInfo":{"name":"fake","version":"1"}}})).unwrap())
        .unwrap();
    let initialized = decode(&transport.read_line().unwrap().unwrap()).unwrap();
    assert_eq!(initialized["id"], 1);
    assert_eq!(initialized["result"]["platformFamily"], "unix");
    transport
        .write_line(&encode(&json!({"method":"initialized","params":{}})).unwrap())
        .unwrap();
    transport
        .write_line(&encode(&json!({"id":2,"method":"model/list","params":{}})).unwrap())
        .unwrap();
    let models = decode(&transport.read_line().unwrap().unwrap()).unwrap();
    assert_eq!(models["id"], 2);
    assert!(models["result"]["data"].is_array());
    assert!(models["result"]["nextCursor"].is_null());
    let exit = transport.dispose().unwrap();
    assert_eq!(exit.pid, pid);
    assert!(transport.observe_exit().unwrap().is_some());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn malformed_and_oversize_child_output_fail_closed_and_reap() {
    let dirs = PrivateDirs::new();
    let mut malformed = ProcessJsonlTransport::spawn(dirs.spec(
        "malformed",
        Duration::from_secs(2),
        Duration::from_secs(2),
    ))
    .unwrap();
    let line = malformed.read_line().unwrap().unwrap();
    assert_eq!(decode(&line), Err(CodecError::InvalidJson));
    malformed.dispose().unwrap();
    assert!(malformed.observe_exit().unwrap().is_some());

    let mut oversize = ProcessJsonlTransport::spawn(dirs.spec(
        "oversize",
        Duration::from_secs(8),
        Duration::from_secs(2),
    ))
    .unwrap();
    assert_eq!(
        oversize.read_line().unwrap_err().kind(),
        ErrorKind::InvalidData
    );
    assert!(oversize.observe_exit().unwrap().is_some());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn fragmented_jsonl_frame_is_reassembled_once() {
    let dirs = PrivateDirs::new();
    let mut transport = ProcessJsonlTransport::spawn(dirs.spec(
        "fragmented",
        Duration::from_secs(2),
        Duration::from_secs(2),
    ))
    .unwrap();
    let frame = transport.read_line().unwrap().unwrap();
    assert_eq!(decode(&frame).unwrap()["result"]["ok"], true);
    transport.dispose().unwrap();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn blocked_child_read_and_partial_write_deadlines_kill_and_reap() {
    let dirs = PrivateDirs::new();
    let short = Duration::from_millis(150);
    let mut reader = ProcessJsonlTransport::spawn(dirs.spec("blocked", short, short)).unwrap();
    let started = Instant::now();
    assert_eq!(reader.read_line().unwrap_err().kind(), ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(reader.observe_exit().unwrap().is_some());

    let mut writer = ProcessJsonlTransport::spawn(dirs.spec("blocked", short, short)).unwrap();
    let mut line = vec![b'x'; 1024 * 1024];
    line.push(b'\n');
    let started = Instant::now();
    assert_eq!(
        writer.write_line(&line).unwrap_err().kind(),
        ErrorKind::TimedOut
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(writer.observe_exit().unwrap().is_some());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn absent_executable_and_disallowed_environment_fail_before_launch() {
    let dirs = PrivateDirs::new();
    let missing = ChildLaunchSpec::new(
        dirs.root.join("missing-executable"),
        vec![OsString::from("ignored")],
        dirs.root.clone(),
        dirs.home.clone(),
        dirs.codex_home.clone(),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(
        ProcessJsonlTransport::spawn(missing).err().unwrap().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        dirs.spec(
            "environment",
            Duration::from_secs(1),
            Duration::from_secs(1)
        )
        .with_allowed_env("OPENAI_API_KEY", OsString::from("never-copy"))
        .err()
        .unwrap()
        .kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        dirs.spec(
            "environment",
            Duration::from_secs(1),
            Duration::from_secs(1)
        )
        .with_allowed_env("HOME", OsString::from("never-override"))
        .err()
        .unwrap()
        .kind(),
        ErrorKind::InvalidInput
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn env_clear_keeps_only_explicit_isolated_home_and_allowlisted_values() {
    let dirs = PrivateDirs::new();
    let spec = dirs
        .spec(
            "environment",
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .with_allowed_env("LANG", OsString::from("C"))
        .unwrap();
    let mut transport = ProcessJsonlTransport::spawn(spec).unwrap();
    let frame = decode(&transport.read_line().unwrap().unwrap()).unwrap();
    assert_eq!(frame["homeSet"], true);
    assert_eq!(frame["codexHomeSet"], true);
    assert_eq!(frame["pathSet"], false);
    assert_eq!(frame["openaiKeySet"], false);
    assert_eq!(frame["awsKeySet"], false);
    assert_eq!(frame["lang"], "C");
    transport.dispose().unwrap();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn already_exited_fake_child_is_reaped_by_dispose() {
    let dirs = PrivateDirs::new();
    let mut transport = ProcessJsonlTransport::spawn(dirs.spec(
        "environment",
        Duration::from_secs(2),
        Duration::from_secs(2),
    ))
    .unwrap();
    let pid = transport.birth().pid;
    let _ = transport.read_line().unwrap().unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let exit = transport.dispose().unwrap();
    assert_eq!(exit.pid, pid);
    assert!(exit.status.success());
    assert_eq!(
        transport.observe_exit().unwrap().unwrap().status,
        exit.status
    );
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn unsupported_platform_refuses_before_child_spawn() {
    let dirs = PrivateDirs::new();
    assert_eq!(
        ProcessJsonlTransport::spawn(dirs.spec(
            "handshake",
            Duration::from_secs(1),
            Duration::from_secs(1),
        ))
        .err()
        .unwrap()
        .kind(),
        ErrorKind::Unsupported
    );
}
