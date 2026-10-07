#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "podbay-r1-native-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn bounded(command: &mut Command) -> (std::process::ExitStatus, Vec<u8>, Vec<u8>) {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("native child exceeded deadline; killed and reaped");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .take(4097)
        .read_to_end(&mut stdout)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .take(4097)
        .read_to_end(&mut stderr)
        .unwrap();
    assert!(stdout.len() <= 4096 && stderr.len() <= 4096);
    (status, stdout, stderr)
}

#[test]
fn installed_argv_refuses_and_ignores_ambient_manifests() {
    let fixture = Fixture::new();
    let body =
        b"{\"schema\":\"podbay.r1.install-manifest/1\",\"gate\":\"CLOSED\",\"claimed_pid\":1}";
    fs::write(fixture.0.join("manifest.json"), body).unwrap();
    fs::write(fixture.0.join("db.sqlite"), b"untouched").unwrap();
    fs::write(fixture.0.join("db.sqlite.manager.lock"), b"untouched-lock").unwrap();
    for mode in ["bootstrap", "custodian"] {
        let (status, stdout, stderr) = bounded(
            Command::new(env!("CARGO_BIN_EXE_podbay-r1-linux"))
                .args([mode, "--manifest", "/etc/podbay/r1-install-manifest.json"])
                .current_dir(&fixture.0)
                .env("HOME", &fixture.0)
                .env("PODBAY_R1_MANIFEST", fixture.0.join("manifest.json"))
                .env("PODBAY_R1_COLD", "1")
                .env("INVOCATION_ID", "pretend-pid1"),
        );
        assert_eq!(status.code(), Some(2));
        assert!(stderr.is_empty());
        assert!(
            std::str::from_utf8(&stdout)
                .unwrap()
                .contains("\"code\":\"ROOT_REQUIRED\"")
        );
        assert!(
            !std::str::from_utf8(&stdout)
                .unwrap()
                .contains("\"gate\":\"CLOSED\"")
        );
        assert_eq!(fs::read(fixture.0.join("manifest.json")).unwrap(), body);
        assert_eq!(fs::read(fixture.0.join("db.sqlite")).unwrap(), b"untouched");
        assert_eq!(
            fs::read(fixture.0.join("db.sqlite.manager.lock")).unwrap(),
            b"untouched-lock"
        );
        assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 3);
    }
}

#[cfg(all(feature = "native-test-probe", target_arch = "x86_64"))]
#[test]
fn actual_native_filter_keeps_only_issued_fd_and_denies_new_capabilities() {
    let fixture = Fixture::new();
    let source = fixture.0.join("source");
    fs::write(&source, b"podbay-r1-private-probe\n").unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
    let (status, stdout, stderr) =
        bounded(Command::new(env!("CARGO_BIN_EXE_podbay-r1-native-test-probe")).arg(&source));
    assert_eq!(status.code(), Some(0), "native probe failed: {:?}", stderr);
    assert_eq!(stdout, b"FD_ONLY_FILTER_OBSERVED_NOT_COLD_ORIGIN\n");
    assert!(stderr.is_empty());
    assert_eq!(fs::read(&source).unwrap(), b"podbay-r1-private-probe\n");
}

#[cfg(all(feature = "native-test-probe", target_arch = "x86_64"))]
#[test]
fn allowing_sendmsg_mutant_is_detected_by_exact_errno_oracle() {
    let fixture = Fixture::new();
    let source = fixture.0.join("source");
    fs::write(&source, b"podbay-r1-private-probe\n").unwrap();
    let (status, stdout, stderr) = bounded(
        Command::new(env!("CARGO_BIN_EXE_podbay-r1-native-test-probe"))
            .arg(&source)
            .arg("--mutant-allow-sendmsg"),
    );
    assert_eq!(
        status.code(),
        Some(98),
        "mutant must fail EPERM check on allowed sendmsg(-1): {:?}",
        stderr
    );
    assert!(stdout.is_empty() && stderr.is_empty());
    assert_eq!(fs::read(&source).unwrap(), b"podbay-r1-private-probe\n");
}
