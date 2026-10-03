use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use podbay_pod::{
    LaunchDescriptor, LeaseKind, PodRole, PtySpec, ScreenFidelity, TerminalCommand,
    TerminalEventKind, TerminalReply, launch, manifest_path,
};

struct Fixture {
    directory: PathBuf,
    unit: String,
    parent_unit: Option<String>,
}
impl Fixture {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("podbay-pty-{}-{unique}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let unit = String::new();
        Self {
            directory,
            unit,
            parent_unit: None,
        }
    }
    fn descriptor(&self) -> LaunchDescriptor {
        LaunchDescriptor {
            protocol: "podbay-pod/1".into(),
            pod_id: "pod.pty.fixture".into(),
            attempt_id: "attempt.pty.fixture".into(),
            session_id: "session.pty.fixture".into(),
            run_id: "run.pty.fixture".into(),
            scope_id: "scope.pty.fixture".into(),
            role: PodRole::Worker,
            incarnation: 1,
            resource_id: "resource.pty.fixture".into(),
            executable: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "printf 'READY\\n'; while read line; do printf 'ECHO:%s\\n' \"$line\"; done".into(),
            ],
            cwd: self.directory.clone(),
            pty: Some(PtySpec {
                rows: 24,
                cols: 80,
                retention_events: 4,
            }),
        }
    }
    fn set_unit(&mut self, descriptor: &LaunchDescriptor) {
        let path = manifest_path(&self.directory, descriptor).unwrap();
        self.unit = format!(
            "podbay-pod-{}.service",
            path.file_stem().unwrap().to_string_lossy()
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if !self.unit.is_empty() {
            let _ = Command::new("systemctl")
                .args(["--user", "stop", &self.unit])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        if let Some(unit) = &self.parent_unit {
            let _ = Command::new("systemctl")
                .args(["--user", "stop", unit])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
#[ignore = "requires isolated user systemd and a private PTY fixture"]
fn two_viewers_replay_and_takeover_fence_one_real_pty() {
    assert_eq!(std::env::var("PODBAY_TEST_SYSTEMD").as_deref(), Ok("1"));
    let mut fixture = Fixture::new();
    let descriptor = fixture.descriptor();
    fixture.set_unit(&descriptor);
    let client = launch(
        descriptor.clone(),
        &fixture.directory,
        PathBuf::from(env!("CARGO_BIN_EXE_podbay-pod")),
    )
    .unwrap();
    let status = client.status().unwrap();
    assert!(status.child_running && status.child_start_ticks > 0);
    let parent_unit = format!("podbay-parent-pty-{}.service", std::process::id());
    fixture.parent_unit = Some(parent_unit.clone());
    assert!(
        Command::new("systemd-run")
            .args([
                "--user",
                "--no-ask-password",
                "--collect",
                "--service-type=exec"
            ])
            .arg(format!("--unit={parent_unit}"))
            .args(["/bin/sleep", "60"])
            .status()
            .unwrap()
            .success()
    );
    let viewer_a = client.viewer().unwrap();
    let viewer_b = client.viewer().unwrap();
    let ready = wait_until(|| {
        let view = viewer_a.attach().unwrap();
        view.screen.plain_text.contains("READY").then_some(view)
    });
    assert_eq!(ready.resource_id, descriptor.resource_id);
    assert_eq!(ready.incarnation, descriptor.incarnation);
    assert!(matches!(
        ready.screen.fidelity,
        ScreenFidelity::Partial { .. }
    ));
    assert_eq!(ready.screen.through, ready.through);
    let other = viewer_b.attach().unwrap();
    let cursor_a = ready.through;
    let cursor_b = other.through;

    let lease = match client
        .terminal_control(TerminalCommand::Acquire {
            resource_id: descriptor.resource_id.clone(),
            incarnation: descriptor.incarnation,
            actor_id: "actor.automation".into(),
            holder: LeaseKind::Automation,
            expected_epoch: 0,
            ttl_ms: 5_000,
        })
        .unwrap()
    {
        TerminalReply::Lease { value } => value,
        _ => panic!("lease reply"),
    };
    assert!(matches!(
        client
            .terminal_control(TerminalCommand::Write {
                command_id: Some("command.write.hello".into()),
                resource_id: descriptor.resource_id.clone(),
                incarnation: descriptor.incarnation,
                actor_id: lease.actor_id.clone(),
                lease_id: lease.lease_id.clone(),
                epoch: lease.epoch,
                bytes: b"hello\n".to_vec(),
            })
            .unwrap(),
        TerminalReply::BytesWritten
    ));
    // A new manager connection can replay the same command ID after losing
    // its reply. The pod ledger returns the prior receipt without input again.
    assert!(
        Command::new("systemctl")
            .args(["--user", "restart", &parent_unit])
            .status()
            .unwrap()
            .success()
    );
    let reattached = podbay_pod::PodClient::connect(client.manifest_path()).unwrap();
    let after_restart = reattached.status().unwrap();
    assert_eq!(
        (
            after_restart.supervisor_pid,
            after_restart.child_pid,
            after_restart.child_start_ticks
        ),
        (
            status.supervisor_pid,
            status.child_pid,
            status.child_start_ticks
        )
    );
    assert!(matches!(
        reattached
            .terminal_control(TerminalCommand::Write {
                command_id: Some("command.write.hello".into()),
                resource_id: descriptor.resource_id.clone(),
                incarnation: descriptor.incarnation,
                actor_id: lease.actor_id.clone(),
                lease_id: lease.lease_id.clone(),
                epoch: lease.epoch,
                bytes: b"hello\n".to_vec(),
            })
            .unwrap(),
        TerminalReply::BytesWritten
    ));
    let output = wait_until(|| {
        let page = viewer_a.events_after(cursor_a, 256).unwrap();
        let raw = page
            .events
            .iter()
            .filter_map(|event| match &event.value {
                TerminalEventKind::Output { bytes, .. } => Some(bytes.as_slice()),
                TerminalEventKind::Resize { .. } => None,
            })
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        String::from_utf8_lossy(&raw)
            .contains("ECHO:hello")
            .then_some(page)
    });
    std::thread::sleep(Duration::from_millis(80));
    let dedup_page = viewer_b.events_after(cursor_b, 256).unwrap();
    let dedup_bytes = dedup_page
        .events
        .iter()
        .filter_map(|event| match &event.value {
            TerminalEventKind::Output { bytes, .. } => Some(bytes.as_slice()),
            TerminalEventKind::Resize { .. } => None,
        })
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(
        String::from_utf8_lossy(&dedup_bytes)
            .matches("ECHO:hello")
            .count(),
        1
    );
    assert!(
        output
            .events
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence)
    );
    let independent = viewer_b.events_after(cursor_b, 256).unwrap();
    assert!(!independent.events.is_empty());
    drop(viewer_a);
    assert!(
        client.status().unwrap().child_running,
        "viewer detach cannot stop the child"
    );

    let human = match client
        .terminal_control(TerminalCommand::Acquire {
            resource_id: descriptor.resource_id.clone(),
            incarnation: descriptor.incarnation,
            actor_id: "actor.human".into(),
            holder: LeaseKind::Human,
            expected_epoch: lease.epoch,
            ttl_ms: 5_000,
        })
        .unwrap()
    {
        TerminalReply::Lease { value } => value,
        _ => panic!("human lease"),
    };
    assert!(human.epoch > lease.epoch);
    assert!(
        client
            .terminal_control(TerminalCommand::Resize {
                command_id: Some("command.resize.stale-incarnation".into()),
                resource_id: descriptor.resource_id.clone(),
                incarnation: descriptor.incarnation + 1,
                actor_id: human.actor_id.clone(),
                lease_id: human.lease_id.clone(),
                epoch: human.epoch,
                rows: 30,
                cols: 90,
            })
            .is_err(),
        "stale resource incarnation cannot resize the live PTY"
    );
    assert!(
        client
            .terminal_control(TerminalCommand::Write {
                command_id: Some("command.write.stale-lease".into()),
                resource_id: descriptor.resource_id.clone(),
                incarnation: descriptor.incarnation,
                actor_id: lease.actor_id.clone(),
                lease_id: lease.lease_id.clone(),
                epoch: lease.epoch,
                bytes: b"stale\n".to_vec(),
            })
            .is_err()
    );
    let resized = client
        .terminal_control(TerminalCommand::Resize {
            command_id: Some("command.resize.first".into()),
            resource_id: descriptor.resource_id.clone(),
            incarnation: descriptor.incarnation,
            actor_id: human.actor_id.clone(),
            lease_id: human.lease_id.clone(),
            epoch: human.epoch,
            rows: 30,
            cols: 90,
        })
        .unwrap();
    assert!(matches!(resized, TerminalReply::Resized { .. }));
    let screen = viewer_b.attach().unwrap();
    assert_eq!((screen.screen.rows, screen.screen.cols), (30, 90));
    for cols in 91..=96 {
        client
            .terminal_control(TerminalCommand::Resize {
                command_id: Some(format!("command.resize.{cols}")),
                resource_id: descriptor.resource_id.clone(),
                incarnation: descriptor.incarnation,
                actor_id: human.actor_id.clone(),
                lease_id: human.lease_id.clone(),
                epoch: human.epoch,
                rows: 30,
                cols,
            })
            .unwrap();
    }
    let gap = viewer_b.events_after(0, 256).unwrap();
    assert!(
        gap.gap.is_some(),
        "bounded event retention must declare a gap"
    );
    assert!(
        gap.events
            .iter()
            .any(|event| matches!(event.value, TerminalEventKind::Resize { .. }))
    );
    assert!(viewer_b.events_after(gap.through + 1, 1).is_err());
    client.stop().unwrap();
}

#[test]
#[ignore = "requires isolated user systemd and a private PTY fixture"]
fn a_viewer_token_cannot_authorize_a_raw_input_command() {
    assert_eq!(std::env::var("PODBAY_TEST_SYSTEMD").as_deref(), Ok("1"));
    let mut fixture = Fixture::new();
    let descriptor = fixture.descriptor();
    fixture.set_unit(&descriptor);
    let client = launch(
        descriptor.clone(),
        &fixture.directory,
        PathBuf::from(env!("CARGO_BIN_EXE_podbay-pod")),
    )
    .unwrap();
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(client.manifest_path()).unwrap()).unwrap();
    let mut socket = UnixStream::connect(manifest["socket_path"].as_str().unwrap()).unwrap();
    let forged = serde_json::json!({
        "protocol":"podbay-pod/1", "pod_id": descriptor.pod_id,
        "attempt_id": descriptor.attempt_id, "incarnation":descriptor.incarnation,
        "token":manifest["viewer_token"], "operation":"terminal",
        "terminal":{"kind":"write", "resource_id":descriptor.resource_id,
            "incarnation":descriptor.incarnation, "actor_id":"actor.forged",
            "lease_id":"lease.forged", "epoch":1, "bytes":[65]}
    });
    socket
        .write_all(&serde_json::to_vec(&forged).unwrap())
        .unwrap();
    socket.shutdown(std::net::Shutdown::Write).unwrap();
    let mut response = Vec::new();
    socket.read_to_end(&mut response).unwrap();
    let result: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(result["ok"], false);
    client.stop().unwrap();
}

fn wait_until<T>(mut check: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if let Some(value) = check() {
            return value;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("fixture observation timed out");
}
