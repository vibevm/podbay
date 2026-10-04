use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use podbay_adapter_codex::{
    AvailableLine, AvailableWrite, ChildLaunchSpec, CodecError, JsonlTransport,
    ProcessJsonlTransport, TESTED_CODEX_CLI_VERSION, decode, encode,
};
use serde_json::{Value, json};

static NEXT_DIR: AtomicU64 = AtomicU64::new(1);

struct PrivateDirs {
    root: PathBuf,
    home: PathBuf,
    codex_home: PathBuf,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn nonblocking_child_poll_keeps_partial_frame_and_returns_before_read_deadline() {
    let dirs = PrivateDirs::new();
    let mut transport = ProcessJsonlTransport::spawn(dirs.spec(
        "fragmented",
        Duration::from_secs(2),
        Duration::from_secs(2),
    ))
    .unwrap();
    let start = Instant::now();
    let mut saw_pending = false;
    let frame = loop {
        let tick = Instant::now();
        match transport.try_read_line().unwrap() {
            AvailableLine::Pending | AvailableLine::IncompleteFrame => saw_pending = true,
            AvailableLine::Frame(frame) => break frame,
            AvailableLine::EndOfStream => panic!("fake child closed before its frame"),
        }
        assert!(
            tick.elapsed() < Duration::from_millis(250),
            "one poll blocked control"
        );
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "fragmented frame did not finish"
        );
        std::thread::sleep(Duration::from_millis(2));
    };
    assert!(saw_pending);
    assert_eq!(decode(&frame).unwrap()["result"]["ok"], true);
    assert_eq!(transport.try_read_line().unwrap(), AvailableLine::Pending);
    transport.dispose().unwrap();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn atomic_probe_write_reports_pending_without_blocking_when_child_pipe_is_full() {
    let dirs = PrivateDirs::new();
    let mut transport = ProcessJsonlTransport::spawn(dirs.spec(
        "blocked",
        Duration::from_secs(2),
        Duration::from_secs(2),
    ))
    .unwrap();
    let mut frame = vec![b'x'; 511];
    frame.push(b'\n');
    let mut pending = false;
    for _ in 0..8192 {
        let tick = Instant::now();
        let outcome = transport.try_write_line(&frame).unwrap();
        assert!(
            tick.elapsed() < Duration::from_millis(250),
            "atomic write stalled control"
        );
        if outcome == AvailableWrite::Pending {
            pending = true;
            break;
        }
    }
    assert!(pending, "blocked child pipe never reported Pending");
    assert_eq!(
        transport
            .try_write_line(&vec![b'x'; 513])
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidInput,
    );
    transport.dispose().unwrap();
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

#[cfg(target_os = "linux")]
#[test]
fn long_lived_fake_child_has_exact_rechecked_kernel_birth_without_a_native_session() {
    let dirs = PrivateDirs::new();
    // This child only sleeps. No Codex coordinator, thread, turn, or account is used.
    let mut transport = ProcessJsonlTransport::spawn(dirs.spec(
        "blocked",
        Duration::from_secs(2),
        Duration::from_secs(2),
    ))
    .unwrap();
    let first = transport.attest_kernel_birth().unwrap();
    assert_eq!(first.pid, transport.birth().pid);
    assert!(first.start_ticks > 0);
    assert_eq!(
        first.boot_id,
        fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .unwrap()
            .trim()
    );
    let stat = fs::read_to_string(format!("/proc/{}/stat", first.pid)).unwrap();
    let start_ticks: u64 = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(first.start_ticks, start_ticks);
    let cgroups = fs::read_to_string(format!("/proc/{}/cgroup", first.pid)).unwrap();
    assert!(
        cgroups
            .lines()
            .any(|line| line == format!("0::{}", first.cgroup_path))
    );
    assert_eq!(transport.attest_kernel_birth().unwrap(), first);
    transport.dispose().unwrap();
    assert_eq!(
        transport.attest_kernel_birth().unwrap_err().kind(),
        ErrorKind::NotFound
    );
}

#[cfg(target_os = "macos")]
#[test]
fn mac_child_spawn_remains_usable_but_linux_birth_is_unsupported() {
    let dirs = PrivateDirs::new();
    let mut transport = ProcessJsonlTransport::spawn(dirs.spec(
        "blocked",
        Duration::from_secs(2),
        Duration::from_secs(2),
    ))
    .unwrap();
    assert_eq!(
        transport.attest_kernel_birth().unwrap_err().kind(),
        ErrorKind::Unsupported
    );
    transport.dispose().unwrap();
}

/// Manual native conformance fixture. It exercises only the real app-server
/// handshake and read-only model catalog through PodBay's bounded child pipes.
/// Run with an absolute, reviewed Codex executable at the pinned CLI version:
/// PODBAY_CODEX_APP_SERVER_EXE=/absolute/path/to/codex cargo test \
///   -p podbay-adapter-codex --test process_transport \
///   isolated_real_app_server_handshake -- --ignored
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[ignore = "requires an explicit reviewed Codex 0.159.3 executable"]
fn isolated_real_app_server_handshake() {
    let executable = PathBuf::from(
        std::env::var_os("PODBAY_CODEX_APP_SERVER_EXE")
            .expect("PODBAY_CODEX_APP_SERVER_EXE must name a reviewed executable"),
    );
    assert!(
        executable.is_absolute(),
        "Codex executable must be absolute"
    );
    let dirs = PrivateDirs::new();

    let version_spec = ChildLaunchSpec::new(
        executable.clone(),
        vec!["--version".into()],
        dirs.root.clone(),
        dirs.home.clone(),
        dirs.codex_home.clone(),
        Duration::from_secs(10),
        Duration::from_secs(2),
    )
    .unwrap();
    let mut version_child = ProcessJsonlTransport::spawn(version_spec).unwrap();
    let version = version_child
        .read_line()
        .unwrap()
        .expect("Codex version command closed without a response");
    assert_eq!(
        String::from_utf8_lossy(&version).trim(),
        format!("codex-cli {TESTED_CODEX_CLI_VERSION}"),
        "Codex CLI version differs from the pinned schema receipt"
    );
    version_child.dispose().unwrap();

    let spec = ChildLaunchSpec::new(
        executable,
        vec!["app-server".into(), "--listen".into(), "stdio://".into()],
        dirs.root.clone(),
        dirs.home.clone(),
        dirs.codex_home.clone(),
        Duration::from_secs(10),
        Duration::from_secs(2),
    )
    .unwrap();
    let mut transport = ProcessJsonlTransport::spawn(spec).unwrap();
    let pid = transport.birth().pid;
    transport
        .write_line(
            &encode(&json!({
                "id": 1,
                "method": "initialize",
                "params": {"clientInfo": {"name": "podbay-conformance", "version": "0.1.0"}}
            }))
            .unwrap(),
        )
        .unwrap();
    let initialized = read_real_result(&mut transport, 1);
    for field in ["codexHome", "platformFamily", "platformOs", "userAgent"] {
        assert!(
            initialized
                .get(field)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty()),
            "initialize omitted a required identity field"
        );
    }
    assert_eq!(
        fs::canonicalize(initialized["codexHome"].as_str().unwrap()).unwrap(),
        fs::canonicalize(&dirs.codex_home).unwrap(),
        "app-server used a different CODEX_HOME"
    );
    transport
        .write_line(&encode(&json!({"method":"initialized","params":{}})).unwrap())
        .unwrap();
    transport
        .write_line(
            &encode(&json!({
                "id": 2,
                "method": "model/list",
                "params": {"limit": 5, "includeHidden": false}
            }))
            .unwrap(),
        )
        .unwrap();
    let models = read_real_result(&mut transport, 2);
    assert!(models["data"].is_array(), "model catalog omitted data");
    assert!(
        models.get("nextCursor").is_some(),
        "model catalog omitted cursor"
    );
    let exit = transport.dispose().unwrap();
    assert_eq!(exit.pid, pid);
    assert!(transport.observe_exit().unwrap().is_some());
}

/// Opt-in native shape probe. This creates a thread in an empty private home
/// but never submits `turn/start`, invokes a model, or uses account credentials.
/// PODBAY_CODEX_APP_SERVER_EXE=/absolute/path/to/codex cargo test \
///   -p podbay-adapter-codex --test process_transport \
///   isolated_real_app_server_thread_start_without_turn -- --ignored
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[ignore = "requires an explicit reviewed Codex 0.159.3 executable"]
fn isolated_real_app_server_thread_start_without_turn() {
    let executable = PathBuf::from(
        std::env::var_os("PODBAY_CODEX_APP_SERVER_EXE")
            .expect("PODBAY_CODEX_APP_SERVER_EXE must name a reviewed executable"),
    );
    assert!(
        executable.is_absolute(),
        "Codex executable must be absolute"
    );
    let dirs = PrivateDirs::new();
    let version_spec = ChildLaunchSpec::new(
        executable.clone(),
        vec!["--version".into()],
        dirs.root.clone(),
        dirs.home.clone(),
        dirs.codex_home.clone(),
        Duration::from_secs(10),
        Duration::from_secs(2),
    )
    .unwrap();
    let mut version_child = ProcessJsonlTransport::spawn(version_spec).unwrap();
    let version = version_child
        .read_line()
        .unwrap()
        .expect("Codex version closed early");
    let version_exit = version_child.dispose().unwrap();
    assert_eq!(version_exit.pid, version_child.birth().pid);
    assert_eq!(
        String::from_utf8_lossy(&version).trim(),
        format!("codex-cli {TESTED_CODEX_CLI_VERSION}"),
        "Codex CLI version differs from the pinned schema receipt"
    );

    let spec = ChildLaunchSpec::new(
        executable,
        vec!["app-server".into(), "--listen".into(), "stdio://".into()],
        dirs.root.clone(),
        dirs.home.clone(),
        dirs.codex_home.clone(),
        Duration::from_secs(10),
        Duration::from_secs(2),
    )
    .unwrap();
    let mut transport = ProcessJsonlTransport::spawn(spec).unwrap();
    let pid = transport.birth().pid;
    let result = probe_thread_start_without_turn(&mut transport, &dirs);
    let exit = transport
        .dispose()
        .expect("real app-server direct child was not reaped");
    assert_eq!(exit.pid, pid);
    assert!(transport.observe_exit().unwrap().is_some());
    if let Err(detail) = result {
        panic!("isolated thread/start probe failed: {detail}");
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn probe_thread_start_without_turn(
    transport: &mut ProcessJsonlTransport,
    dirs: &PrivateDirs,
) -> Result<String, String> {
    let initialize = raw_real_rpc(
        transport,
        1,
        "initialize",
        json!({"clientInfo":{"name":"podbay-thread-shape","version":"0.1.0"}}),
    )?;
    let home = initialize
        .get("codexHome")
        .and_then(Value::as_str)
        .ok_or("initialize omitted codexHome")?;
    if fs::canonicalize(home).map_err(|error| error.to_string())?
        != fs::canonicalize(&dirs.codex_home).map_err(|error| error.to_string())?
    {
        return Err("app-server used a different CODEX_HOME".into());
    }
    transport
        .write_line(
            &encode(&json!({"method":"initialized","params":{}}))
                .map_err(|error| format!("initialized encode: {error:?}"))?,
        )
        .map_err(|error| format!("initialized write: {error}"))?;

    let start = raw_real_rpc(
        transport,
        2,
        "thread/start",
        json!({
            "model":"gpt-6-sol",
            "cwd":dirs.root,
            "approvalPolicy":"never",
            "sandbox":"danger-full-access",
            "ephemeral":false,
            "serviceName":"podbay-thread-shape",
            "config":{"model_reasoning_effort":"medium"}
        }),
    )?;
    let thread = start.get("thread").ok_or("thread/start omitted thread")?;
    let thread_id = thread
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or("thread/start omitted thread id")?;
    if thread.get("sessionId").and_then(Value::as_str).is_none()
        || thread
            .get("turns")
            .and_then(Value::as_array)
            .is_none_or(|turns| !turns.is_empty())
        || thread.pointer("/status/type").and_then(Value::as_str) != Some("idle")
        || start.get("model").and_then(Value::as_str) != Some("gpt-6-sol")
        || start.get("reasoningEffort").and_then(Value::as_str) != Some("medium")
        || start.get("approvalPolicy").and_then(Value::as_str) != Some("never")
        || start.pointer("/sandbox/type").and_then(Value::as_str) != Some("dangerFullAccess")
        || start.get("cwd").and_then(Value::as_str) != dirs.root.to_str()
    {
        return Err("thread/start effective response differed or a turn was created".into());
    }
    // The 0.159.3 app-server may refuse thread/read's list_turns path even
    // though thread/start returned a complete idle thread with no turns.
    Ok(thread_id.to_owned())
}

/// Read-only method compatibility probe for the same fresh thread. It never
/// sends turn/start, a user message, or a model request.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[ignore = "requires an explicit reviewed Codex 0.159.3 executable"]
fn isolated_real_app_server_reconciliation_methods_without_turn() {
    let executable = PathBuf::from(
        std::env::var_os("PODBAY_CODEX_APP_SERVER_EXE")
            .expect("PODBAY_CODEX_APP_SERVER_EXE must name a reviewed executable"),
    );
    assert!(
        executable.is_absolute(),
        "Codex executable must be absolute"
    );
    let dirs = PrivateDirs::new();
    let version_spec = ChildLaunchSpec::new(
        executable.clone(),
        vec!["--version".into()],
        dirs.root.clone(),
        dirs.home.clone(),
        dirs.codex_home.clone(),
        Duration::from_secs(10),
        Duration::from_secs(2),
    )
    .unwrap();
    let mut version_child = ProcessJsonlTransport::spawn(version_spec).unwrap();
    let version = version_child
        .read_line()
        .unwrap()
        .expect("Codex version closed early");
    version_child.dispose().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&version).trim(),
        format!("codex-cli {TESTED_CODEX_CLI_VERSION}"),
    );
    let spec = ChildLaunchSpec::new(
        executable,
        vec!["app-server".into(), "--listen".into(), "stdio://".into()],
        dirs.root.clone(),
        dirs.home.clone(),
        dirs.codex_home.clone(),
        Duration::from_secs(10),
        Duration::from_secs(2),
    )
    .unwrap();
    let mut transport = ProcessJsonlTransport::spawn(spec).unwrap();
    let pid = transport.birth().pid;
    let observed = (|| -> Result<(), String> {
        let id = probe_thread_start_without_turn(&mut transport, &dirs)?;
        let metadata = raw_real_rpc(&mut transport, 3, "thread/read", json!({"threadId":id}))?;
        let thread = metadata
            .get("thread")
            .ok_or("metadata read omitted thread")?;
        if thread.get("id").and_then(Value::as_str) != Some(id.as_str())
            || thread.pointer("/status/type").and_then(Value::as_str) != Some("idle")
            || thread
                .get("turns")
                .and_then(Value::as_array)
                .is_none_or(|turns| !turns.is_empty())
        {
            return Err("metadata read did not prove the empty thread idle".into());
        }
        eprintln!("thread/read metadata: idle, turns=0");
        let turns = raw_real_rpc(
            &mut transport,
            4,
            "thread/turns/list",
            json!({"threadId":id,"limit":1,"sortDirection":"desc"}),
        )
        .err()
        .ok_or("unmaterialized thread unexpectedly returned a turn list")?;
        if !turns.contains("code=Some(-32600)")
            || !turns.contains("unavailable before first user message")
        {
            return Err(format!("unexpected no-turn list result: {turns}"));
        }
        eprintln!("thread/turns/list: unmaterialized before first user message (-32600)");
        let resumed = raw_real_rpc(
            &mut transport,
            5,
            "thread/resume",
            json!({
                "threadId":id,
                "excludeTurns":true,
                "cwd":dirs.root,
                "model":"gpt-6-sol",
                "approvalPolicy":"never",
                "sandbox":"danger-full-access",
                "config":{"model_reasoning_effort":"medium"}
            }),
        )
        .err()
        .ok_or("unmaterialized thread unexpectedly resumed")?;
        if !resumed.contains("code=Some(-32600)") || !resumed.contains("no rollout found") {
            return Err(format!("unexpected no-turn resume result: {resumed}"));
        }
        eprintln!("thread/resume excludeTurns: no rollout found (-32600)");
        Ok(())
    })();
    let exit = transport
        .dispose()
        .expect("real app-server direct child was not reaped");
    assert_eq!(exit.pid, pid);
    if let Err(detail) = observed {
        panic!("isolated reconciliation probe failed: {detail}");
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn raw_real_rpc(
    transport: &mut ProcessJsonlTransport,
    id: u64,
    method: &str,
    params: Value,
) -> Result<Value, String> {
    let frame = encode(&json!({"id":id,"method":method,"params":params}))
        .map_err(|error| format!("{method} encode: {error:?}"))?;
    transport
        .write_line(&frame)
        .map_err(|error| format!("{method} write: {error}"))?;
    let deadline = Instant::now() + Duration::from_secs(15);
    for _ in 0..64 {
        if Instant::now() >= deadline {
            return Err(format!("{method} response deadline elapsed"));
        }
        let frame = transport
            .read_line()
            .map_err(|error| format!("{method} read: {error}"))?
            .ok_or_else(|| format!("{method} closed before response"))?;
        let value = decode(&frame).map_err(|error| format!("{method} decode: {error:?}"))?;
        if value.get("id").and_then(Value::as_u64) == Some(id) {
            if let Some(error) = value.get("error") {
                let code = error.get("code").and_then(Value::as_i64);
                let message: String = error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("native RPC error without message")
                    .chars()
                    .filter(|ch| !ch.is_control())
                    .take(256)
                    .collect();
                return Err(format!(
                    "{method} RPC error code={code:?} message={message}"
                ));
            }
            return value
                .get("result")
                .cloned()
                .ok_or_else(|| format!("{method} omitted result"));
        }
        if value.get("method").and_then(Value::as_str).is_none() {
            return Err(format!("{method} observed unrelated RPC response"));
        }
    }
    Err(format!("{method} notification limit exceeded"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn read_real_result(transport: &mut ProcessJsonlTransport, expected_id: u64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(15);
    for _ in 0..64 {
        assert!(
            Instant::now() < deadline,
            "app-server response deadline elapsed"
        );
        let frame = transport
            .read_line()
            .unwrap()
            .expect("app-server closed before its response");
        let value = decode(&frame).unwrap();
        if value.get("id").and_then(Value::as_u64) == Some(expected_id) {
            assert!(
                value.get("error").is_none(),
                "app-server returned an RPC error"
            );
            return value
                .get("result")
                .cloned()
                .expect("app-server response omitted result");
        }
        assert!(
            value.get("method").and_then(Value::as_str).is_some(),
            "app-server returned an unexpected RPC response"
        );
    }
    panic!("app-server notification limit exceeded before response");
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
