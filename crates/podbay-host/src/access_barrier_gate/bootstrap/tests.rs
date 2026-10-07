use super::*;
use std::cell::Cell;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const OPERATIONS: [DeferredIo; 6] = [
    DeferredIo::OpenSource,
    DeferredIo::ReadCheckpoint,
    DeferredIo::AcquireManagerLock,
    DeferredIo::CreateStateDirectory,
    DeferredIo::ContactCustodian,
    DeferredIo::LaunchCustodian,
];

fn expected(reason: BootstrapRefusal) -> BootstrapRefusal {
    if cfg!(target_os = "linux") {
        reason
    } else {
        BootstrapRefusal::UnsupportedTarget
    }
}

fn refusal(result: Result<Infallible, BootstrapRefusal>) -> BootstrapRefusal {
    match result {
        Err(reason) => reason,
        Ok(impossible) => match impossible {},
    }
}

fn request(path: &str) -> BootstrapRequest<'_> {
    BootstrapRequest {
        boundary_path: path,
        historical_checkpoint: None,
    }
}

#[test]
fn well_formed_requests_refuse_before_any_deferred_io() {
    for path in [
        "/fixture/vault",
        "/root/pid1/closed/never-started",
        "/nonexistent/store-root",
    ] {
        let mut attempt = PreSourceAttempt::new(request(path));
        let mut calls = Vec::new();
        for _ in 0..8 {
            assert_eq!(
                refusal(attempt.acquire(&mut |op| calls.push(op))),
                expected(BootstrapRefusal::LauncherEnforcementUnavailable),
            );
        }
        assert!(calls.is_empty());
    }
}

#[test]
fn malformed_paths_refuse_without_io_or_path_normalization() {
    let oversized = format!("/{}", "é".repeat(2048));
    for path in [
        "",
        "/",
        ".",
        "relative",
        "//vault",
        "/vault/",
        "/vault//store",
        "/vault/../store",
        "/vault/./store",
        "/vault\\store",
        "/vault\0store",
        "/vault\nstore",
        "/vault\u{0085}store",
        &oversized,
    ] {
        let mut attempt = PreSourceAttempt::new(request(path));
        assert_eq!(
            refusal(attempt.acquire(&mut |_| panic!("malformed request attempted I/O"))),
            expected(BootstrapRefusal::MalformedRequest),
        );
    }
}

#[test]
fn any_historical_bytes_refuse_without_decoding_or_inspection() {
    let oversized = vec![0x80; 65537];
    for bytes in [
        &b""[..],
        b"PBGATE01",
        b"PBORIG01",
        b"CLOSED PID=1 UID=0 NeverStarted generation=1",
        &oversized,
    ] {
        let mut attempt = PreSourceAttempt::new(BootstrapRequest {
            boundary_path: "/fixture/vault",
            historical_checkpoint: Some(bytes),
        });
        assert_eq!(
            refusal(attempt.acquire(&mut |_| panic!("history attempted I/O"))),
            expected(BootstrapRefusal::HistoricalInputCannotAcquire),
        );
    }
}

#[test]
fn first_refusal_is_sticky_even_if_test_changes_the_private_request() {
    for (path, bytes, reason) in [
        ("relative", None, BootstrapRefusal::MalformedRequest),
        (
            "/fixture/vault",
            Some(&b"historical"[..]),
            BootstrapRefusal::HistoricalInputCannotAcquire,
        ),
        (
            "/fixture/vault",
            None,
            BootstrapRefusal::LauncherEnforcementUnavailable,
        ),
    ] {
        let mut attempt = PreSourceAttempt::new(BootstrapRequest {
            boundary_path: path,
            historical_checkpoint: bytes,
        });
        let mut trap = |_| panic!("a refused lifetime attempted I/O");
        assert_eq!(refusal(attempt.acquire(&mut trap)), expected(reason));
        // No production mutator exists. Deliberate child-module access tests
        // that the latched result takes precedence even over changed input.
        attempt.request = request("/replacement/valid-root");
        assert_eq!(refusal(attempt.acquire(&mut trap)), expected(reason));
        attempt.request.historical_checkpoint = Some(b"different-history");
        assert_eq!(refusal(attempt.acquire(&mut trap)), expected(reason));
    }
}

#[test]
fn retry_new_lifetime_and_drop_do_not_restore_or_release_anything() {
    let calls = Cell::new(0);
    let mut observer = |_| calls.set(calls.get() + 1);
    for _ in 0..16 {
        let mut attempt = PreSourceAttempt::new(request("/fixture/vault"));
        assert_eq!(
            refusal(attempt.acquire(&mut observer)),
            expected(BootstrapRefusal::LauncherEnforcementUnavailable),
        );
        drop(attempt);
    }
    assert_eq!(calls.get(), 0);
    assert!(!core::mem::needs_drop::<BootstrapRequest<'_>>());
    assert!(!core::mem::needs_drop::<PreSourceAttempt<'_>>());
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir();
        for _ in 0..32 {
            let path = base.join(format!(
                "podbay-pre-source-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed),
            ));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            match builder.create(&path) {
                Ok(()) => return Self(path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("private fixture creation: {e}"),
            }
        }
        panic!("private fixture names exhausted");
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove exact test-owned fixture");
    }
}

#[test]
fn zero_call_observer_has_a_real_disposable_side_effect_positive_control() {
    let fixture = Fixture::new();
    let marker = fixture.0.join("observer-called");
    let mut seen = Vec::new();
    let mut observer = |operation| {
        seen.push(operation);
        fs::write(&marker, format!("{operation:?}")).unwrap();
    };
    let absent_boundary = fixture.0.join("not-created");
    let mut attempt = PreSourceAttempt::new(request(absent_boundary.to_str().unwrap()));
    for _ in 0..8 {
        assert_eq!(
            refusal(attempt.acquire(&mut observer)),
            expected(BootstrapRefusal::LauncherEnforcementUnavailable),
        );
    }
    assert!(!marker.exists());
    assert!(!absent_boundary.exists());
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 0);
    // Independent sensitivity control: the supplied observer is callable and
    // records every category; acquisition above simply never called it.
    for operation in OPERATIONS {
        observer(operation);
    }
    assert_eq!(seen, OPERATIONS);
    assert_eq!(fs::read_to_string(&marker).unwrap(), "LaunchCustodian");
}

#[test]
fn existing_disposable_source_checkpoint_and_lock_bytes_remain_unchanged() {
    let fixture = Fixture::new();
    let members = ["source.sqlite", "checkpoint", "manager.lock"];
    let bytes = [
        b"inert source fixture".as_slice(),
        b"inert historical bytes",
        b"unheld lock specimen",
    ];
    for (name, content) in members.iter().zip(bytes) {
        fs::write(fixture.0.join(name), content).unwrap();
    }
    let path = fixture.0.to_str().unwrap();
    for checkpoint in [None, Some(bytes[1])] {
        let mut attempt = PreSourceAttempt::new(BootstrapRequest {
            boundary_path: path,
            historical_checkpoint: checkpoint,
        });
        let reason = if checkpoint.is_some() {
            BootstrapRefusal::HistoricalInputCannotAcquire
        } else {
            BootstrapRefusal::LauncherEnforcementUnavailable
        };
        for _ in 0..8 {
            assert_eq!(
                refusal(attempt.acquire(&mut |_| panic!("specimen inspection attempted"))),
                expected(reason),
            );
        }
    }
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 3);
    for (name, content) in members.iter().zip(bytes) {
        assert_eq!(fs::read(fixture.0.join(name)).unwrap(), content);
    }
}
