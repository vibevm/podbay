#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_pod::{
    CODEX_AUTH_CREDENTIAL_NAME, PodError, prepare_codex_home_from_systemd_credential,
};

const UNIT: &str = "podbay-pod-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.service";
const DUMMY: &[u8] = b"disposable dummy credential only\n";

struct Fixture {
    root: PathBuf,
    pod: PathBuf,
    credentials: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "podbay-codex-credential-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let pod = root.join("pod");
        fs::create_dir(&pod).unwrap();
        fs::set_permissions(&pod, fs::Permissions::from_mode(0o700)).unwrap();
        let parent = root.join("systemd-credentials");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let credentials = parent.join(UNIT);
        fs::create_dir(&credentials).unwrap();
        fs::write(credentials.join(CODEX_AUTH_CREDENTIAL_NAME), DUMMY).unwrap();
        fs::set_permissions(
            credentials.join(CODEX_AUTH_CREDENTIAL_NAME),
            fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        fs::set_permissions(&credentials, fs::Permissions::from_mode(0o500)).unwrap();
        Self {
            root,
            pod,
            credentials,
        }
    }

    fn credential(&self) -> PathBuf {
        self.credentials.join(CODEX_AUTH_CREDENTIAL_NAME)
    }

    fn prepare(&self) -> Result<podbay_pod::PreparedCodexHome, PodError> {
        prepare_codex_home_from_systemd_credential(UNIT, &self.pod, &self.credentials)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.credentials.exists() {
            let _ = fs::set_permissions(&self.credentials, fs::Permissions::from_mode(0o700));
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn private_codex_home_links_one_dummy_credential_without_copying_bytes() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare().unwrap();
    assert_eq!(prepared.isolated_home(), fixture.pod.join("home"));
    assert_eq!(prepared.codex_home(), fixture.pod.join("home/codex"));
    assert_eq!(
        prepared.credential_reference(),
        fixture.pod.join("home/codex/auth.json")
    );
    for path in [prepared.isolated_home(), prepared.codex_home()] {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.mode() & 0o7777, 0o700);
    }
    let reference = fs::symlink_metadata(prepared.credential_reference()).unwrap();
    assert!(reference.file_type().is_symlink());
    assert_eq!(
        fs::read_link(prepared.credential_reference()).unwrap(),
        fixture.credential()
    );
    assert_eq!(
        fs::metadata(prepared.credential_reference()).unwrap().len(),
        DUMMY.len() as u64
    );
    assert_eq!(
        fixture.prepare().unwrap().credential_reference(),
        prepared.credential_reference()
    );

    // systemd removes the target on unit deactivation; the path reference
    // then becomes dangling and contains no copied credential bytes.
    fs::set_permissions(&fixture.credentials, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_file(fixture.credential()).unwrap();
    fs::remove_dir(&fixture.credentials).unwrap();
    assert!(
        fs::symlink_metadata(prepared.credential_reference())
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(!prepared.credential_reference().exists());
}

#[test]
fn missing_wrong_unit_or_noncanonical_directory_refuses_before_home_creation() {
    let fixture = Fixture::new();
    let other_unit = "podbay-pod-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.service";
    assert!(
        prepare_codex_home_from_systemd_credential(other_unit, &fixture.pod, &fixture.credentials)
            .is_err()
    );
    assert!(
        prepare_codex_home_from_systemd_credential(
            UNIT,
            &fixture.pod,
            &fixture.root.join("missing")
        )
        .is_err()
    );
    let alias_parent = fixture.root.join("alias-parent");
    fs::create_dir(&alias_parent).unwrap();
    symlink(&fixture.credentials, alias_parent.join(UNIT)).unwrap();
    assert!(
        prepare_codex_home_from_systemd_credential(UNIT, &fixture.pod, &alias_parent.join(UNIT))
            .is_err()
    );
    assert!(!fixture.pod.join("home").exists());
}

#[test]
fn unsafe_directory_and_credential_modes_refuse() {
    let fixture = Fixture::new();
    fs::set_permissions(&fixture.pod, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(fixture.prepare().is_err());
    fs::set_permissions(&fixture.pod, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&fixture.credentials, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(fixture.prepare().is_err());
    fs::set_permissions(&fixture.credentials, fs::Permissions::from_mode(0o500)).unwrap();
    fs::set_permissions(fixture.credential(), fs::Permissions::from_mode(0o600)).unwrap();
    assert!(fixture.prepare().is_err());
    assert!(!fixture.pod.join("home").exists());
}

#[test]
fn symlink_extra_file_or_existing_reference_cannot_substitute_credential() {
    let fixture = Fixture::new();
    fs::set_permissions(&fixture.credentials, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(fixture.credentials.join("extra"), b"dummy extra").unwrap();
    fs::set_permissions(&fixture.credentials, fs::Permissions::from_mode(0o500)).unwrap();
    assert!(fixture.prepare().is_err());
    assert!(!fixture.pod.join("home").exists());
    fs::set_permissions(&fixture.credentials, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_file(fixture.credentials.join("extra")).unwrap();
    fs::remove_file(fixture.credential()).unwrap();
    let dummy_target = fixture.root.join("dummy-source");
    fs::write(&dummy_target, DUMMY).unwrap();
    symlink(&dummy_target, fixture.credential()).unwrap();
    fs::set_permissions(&fixture.credentials, fs::Permissions::from_mode(0o500)).unwrap();
    assert!(fixture.prepare().is_err());
    assert!(!fixture.pod.join("home").exists());

    fs::set_permissions(&fixture.credentials, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_file(fixture.credential()).unwrap();
    fs::write(fixture.credential(), DUMMY).unwrap();
    fs::set_permissions(fixture.credential(), fs::Permissions::from_mode(0o400)).unwrap();
    fs::set_permissions(&fixture.credentials, fs::Permissions::from_mode(0o500)).unwrap();
    let codex_home = fixture.pod.join("home/codex");
    fs::create_dir(fixture.pod.join("home")).unwrap();
    fs::create_dir(&codex_home).unwrap();
    fs::set_permissions(fixture.pod.join("home"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&codex_home, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        codex_home.join(CODEX_AUTH_CREDENTIAL_NAME),
        b"unrelated dummy",
    )
    .unwrap();
    assert!(matches!(fixture.prepare(), Err(PodError::Conflict(_))));
    assert!(
        fs::symlink_metadata(codex_home.join(CODEX_AUTH_CREDENTIAL_NAME))
            .unwrap()
            .is_file()
    );
}
