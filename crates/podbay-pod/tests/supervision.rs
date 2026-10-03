use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use podbay_pod::{LaunchDescriptor, PodClient, PodError, PodRole, launch, manifest_path};

struct Fixture {
    directory: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("podbay-pb05-{}-{unique}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        Self { directory }
    }
    fn descriptor(&self) -> LaunchDescriptor {
        let probe = self.directory.join("child-saw-socket");
        let socket = manifest_path(&self.directory, &self.base_descriptor())
            .unwrap()
            .with_extension("sock");
        LaunchDescriptor {
            args: vec![
                "-c".into(),
                format!(
                    "test -S '{}' && printf ready > '{}'; exec /bin/sleep 60",
                    socket.display(),
                    probe.display()
                ),
            ],
            ..self.base_descriptor()
        }
    }
    fn base_descriptor(&self) -> LaunchDescriptor {
        LaunchDescriptor {
            protocol: "podbay-pod/1".into(),
            pod_id: "pod.pb05.fixture".into(),
            attempt_id: "attempt.pb05.fixture".into(),
            session_id: "session.pb05.fixture".into(),
            run_id: "run.pb05.fixture".into(),
            scope_id: "scope.pb05.fixture".into(),
            role: PodRole::Worker,
            incarnation: 1,
            resource_id: "resource.pb05.fixture".into(),
            executable: "/bin/sh".into(),
            args: vec!["-c".into(), "exec /bin/sleep 60".into()],
            cwd: self.directory.clone(),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

struct UnitGuard {
    units: Vec<String>,
}
impl Drop for UnitGuard {
    fn drop(&mut self) {
        for unit in &self.units {
            let _ = Command::new("systemctl")
                .args(["--user", "stop", unit])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
}

#[test]
fn versioned_manifest_digest_and_private_paths_reject_drift() {
    let fixture = Fixture::new();
    let descriptor = fixture.descriptor();
    assert_eq!(descriptor.digest().unwrap().len(), 64);
    let mut changed = descriptor.clone();
    changed.args.push("changed".into());
    assert_ne!(descriptor.digest().unwrap(), changed.digest().unwrap());
    assert_eq!(
        manifest_path(&fixture.directory, &descriptor).unwrap(),
        manifest_path(&fixture.directory, &changed).unwrap(),
        "same pod/attempt slot must detect changed content rather than mint a replacement"
    );
}

#[test]
#[ignore = "requires isolated user systemd"]
fn pod_and_child_survive_restart_of_a_separate_user_manager_unit() {
    assert_eq!(std::env::var("PODBAY_TEST_SYSTEMD").as_deref(), Ok("1"));
    let fixture = Fixture::new();
    let descriptor = fixture.descriptor();
    let manifest = manifest_path(&fixture.directory, &descriptor).unwrap();
    let pod_binary = PathBuf::from(env!("CARGO_BIN_EXE_podbay-pod"));
    let suffix = manifest.file_stem().unwrap().to_string_lossy();
    let parent_unit = format!("podbay-parent-{}.service", &suffix[..16]);
    let _units = UnitGuard {
        units: vec![
            parent_unit.clone(),
            format!("podbay-pod-{}.service", suffix),
        ],
    };
    let parent = Command::new("systemd-run")
        .args([
            "--user",
            "--no-ask-password",
            "--collect",
            "--service-type=exec",
        ])
        .arg(format!("--unit={parent_unit}"))
        .args(["/bin/sleep", "60"])
        .status()
        .unwrap();
    assert!(parent.success());
    let mut client: Option<PodClient> = None;
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let launched = launch(descriptor.clone(), &fixture.directory, &pod_binary)?;
        let first = launched.status()?;
        assert!(first.child_running && first.child_start_ticks > 0);
        assert!(first.cgroup_path.contains(&first.unit_name));
        let marker = fixture.directory.join("child-saw-socket");
        let deadline = Instant::now() + Duration::from_secs(1);
        while !marker.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            marker.exists(),
            "child must observe the bound authenticated socket"
        );
        let wrong = LaunchDescriptor {
            args: vec!["changed".into()],
            ..descriptor.clone()
        };
        assert!(matches!(
            launch(wrong, &fixture.directory, &pod_binary),
            Err(PodError::Conflict(_))
        ));
        client = Some(launched);
        assert!(
            Command::new("systemctl")
                .args(["--user", "restart", &parent_unit])
                .status()?
                .success()
        );
        let attached = PodClient::connect(&manifest)?;
        let after = attached.status()?;
        assert_eq!(
            (
                after.supervisor_pid,
                after.child_pid,
                after.child_start_ticks
            ),
            (
                first.supervisor_pid,
                first.child_pid,
                first.child_start_ticks
            )
        );
        assert_eq!(after.manifest_digest, first.manifest_digest);
        assert_eq!(after.boot_id, first.boot_id);
        let stopped = attached.stop()?;
        assert!(!stopped.child_running);
        Ok(())
    })();
    if let Some(client) = client {
        let _ = client.stop();
    }
    result.unwrap();
}

#[test]
fn stale_or_symlinked_manifest_never_authorizes_a_replacement() {
    let fixture = Fixture::new();
    let descriptor = fixture.descriptor();
    let path = manifest_path(&fixture.directory, &descriptor).unwrap();
    fs::write(&path, b"not a manifest").unwrap();
    assert!(PodClient::connect(&path).is_err());
    fs::remove_file(&path).unwrap();
    let target = fixture.directory.join("target");
    fs::write(&target, b"not a manifest").unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(PodClient::connect(&path).is_err());
}
