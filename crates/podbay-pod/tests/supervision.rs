#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_core::{AttemptId, Epoch, PodId};
use podbay_pod::{
    LaunchDescriptor, PodClient, PodError, PodRole, launch, manifest_path,
    manifest_path_for_identity,
};

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
            pty: None,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
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
    assert_eq!(
        manifest_path(&fixture.directory, &descriptor).unwrap(),
        manifest_path_for_identity(
            &fixture.directory,
            &PodId::try_from(descriptor.pod_id.as_str()).unwrap(),
            &AttemptId::try_from(descriptor.attempt_id.as_str()).unwrap(),
            Epoch::new(descriptor.incarnation).unwrap(),
        ),
        "recovery must address the same immutable slot without caller bytes"
    );
}

#[test]
fn pb05_manifest_without_pty_keeps_its_canonical_digest() {
    const OLD: &str = "{\"protocol\":\"podbay-pod/1\",\"pod_id\":\"pod.old.fixture\",\"attempt_id\":\"attempt.old.fixture\",\"session_id\":\"session.old.fixture\",\"run_id\":\"run.old.fixture\",\"scope_id\":\"scope.old.fixture\",\"role\":\"worker\",\"incarnation\":1,\"resource_id\":\"resource.old.fixture\",\"executable\":\"/bin/sh\",\"args\":[],\"cwd\":\"/tmp\"}";
    let descriptor: LaunchDescriptor = serde_json::from_str(OLD).unwrap();
    assert!(descriptor.pty.is_none());
    assert_eq!(serde_json::to_string(&descriptor).unwrap(), OLD);
    assert_eq!(
        descriptor.digest().unwrap(),
        "38173a488ee108bb5336535a11f90271004babd72e3da7bdf3e397dff5cd4160"
    );
}

#[test]
fn retired_pb05_launch_refuses_before_manifest_or_child() {
    let fixture = Fixture::new();
    let descriptor = fixture.descriptor();
    let manifest = manifest_path(&fixture.directory, &descriptor).unwrap();
    assert!(matches!(
        launch(
            descriptor,
            &fixture.directory,
            PathBuf::from(env!("CARGO_BIN_EXE_podbay-pod"))
        ),
        Err(PodError::Unsupported("unbound pod launch is retired"))
    ));
    assert!(!manifest.exists());
    assert!(!fixture.directory.join("child-saw-socket").exists());
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
