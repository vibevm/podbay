use super::*;
use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::process::{Child, Command, Stdio};

const ENTRY: &str = "access_barrier_gate::codec::closed_origin::tests::custodian_process_entry";
struct Process {
    child: Child,
    reaped: bool,
}
impl Process {
    fn reap(&mut self) {
        if self.reaped {
            return;
        }
        let _ = self.child.kill();
        self.child.wait().expect("exact child reap");
        self.reaped = true;
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        self.reap();
    }
}
struct Fixture {
    root: PathBuf,
    record: RecordV1,
    nonce: [u8; 32],
    socket_pin: Option<FileIdentity>,
}
fn file(path: &Path, bytes: &[u8]) {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}
impl Fixture {
    fn new() -> Self {
        assert_ne!(
            rustix::process::geteuid().as_raw(),
            0,
            "root tests are not authorized"
        );
        let base = PathBuf::from(
            std::env::var_os("PODBAY_CLOSED_ORIGIN_CASES").expect("explicit private test root"),
        );
        assert_eq!(fs::canonicalize(&base).unwrap(), base);
        assert_eq!(base.metadata().unwrap().mode() & 0o7777, 0o700);
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).unwrap();
        let name: String = nonce[..8].iter().map(|v| format!("{v:02x}")).collect();
        let root = base.join(name);
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        let source = root.join("db.sqlite");
        let staging = root.join("stage.sqlite");
        file(&source, &[]);
        file(&root.join("db.sqlite.manager.lock"), &[]);
        let initial_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join("db.sqlite.manager.lock"))
            .unwrap();
        flock(&initial_lock, FlockOperation::NonBlockingLockExclusive).unwrap();
        drop(podbay_store::PodBayStore::open(&source).unwrap());
        let c = rusqlite::Connection::open(&source).unwrap();
        c.execute_batch("PRAGMA journal_mode=DELETE;").unwrap();
        drop(c);
        let staged = podbay_store::stage_schema_v25(&source, &staging).unwrap();
        drop(initial_lock);
        let policy = b"closed-origin-prototype/1; admission=UNIMPLEMENTED";
        file(&root.join("policy.bin"), policy);
        let mut record = super::super::tests::initial();
        record.parent = identity(&root.metadata().unwrap());
        let s = &mut record.durable.subject;
        s.canonical_name = "db.sqlite".into();
        s.staging_name = "stage.sqlite".into();
        s.source = identity(&source.metadata().unwrap());
        s.staging = identity(&staging.metadata().unwrap());
        s.manager_lock = identity(&root.join("db.sqlite.manager.lock").metadata().unwrap());
        s.lineage = staged.store_lineage;
        s.current_boot = boot_id().unwrap();
        // Explicit synthetic predecessor. This is not cold-boot evidence.
        s.previous_boot = "disposable-unobserved-prior-boot".into();
        s.policy_digest = Sha256::digest(policy).into();
        s.artifact_digest = hash_file(&File::open("/proc/self/exe").unwrap()).unwrap();
        Self {
            root,
            record,
            nonce,
            socket_pin: None,
        }
    }
    fn spawn(&mut self, domain: Domain) -> Result<(Process, UnixStream, Peer)> {
        let socket_path = self.root.join("channel.sock");
        if let Some(expected) = &self.socket_pin {
            let m = fs::symlink_metadata(&socket_path)?;
            require(
                m.file_type().is_socket() && identity(&m) == *expected,
                "foreign test socket",
            )?;
            fs::remove_file(&socket_path)?;
        }
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        self.socket_pin = Some(identity(&socket_path.symlink_metadata()?));
        listener.set_nonblocking(true)?;
        let parent = self_peer()?;
        let mut bootstrap = vec![domain as u8];
        for n in [parent.pid, parent.uid, parent.gid] {
            bootstrap.extend_from_slice(&n.to_be_bytes());
        }
        bootstrap.extend_from_slice(&parent.birth.to_be_bytes());
        bootstrap.extend_from_slice(&self.nonce);
        bootstrap.extend_from_slice(
            &encode(&self.record).map_err(|_| Error::Refused("test bootstrap codec"))?,
        );
        // This is trusted test-bootstrap input, never an authority record.
        let input = self.root.join("bootstrap.bin");
        if input.exists() {
            fs::remove_file(&input)?;
        }
        file(&input, &bootstrap);
        let output = OpenOptions::new()
            .write(true)
            .create(true)
            .append(true)
            .mode(0o600)
            .open(self.root.join("child.log"))?;
        let child = Command::new(std::env::current_exe()?)
            .args(["--exact", ENTRY, "--ignored", "--nocapture"])
            .env("PODBAY_ORIGIN_CHILD_ROOT", &self.root)
            .stdin(Stdio::null())
            .stdout(Stdio::from(output.try_clone()?))
            .stderr(Stdio::from(output))
            .spawn()?;
        let mut owner = Process {
            child,
            reaped: false,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    let peer = Peer {
                        pid: owner.child.id(),
                        uid: parent.uid,
                        gid: parent.gid,
                        birth: birth(owner.child.id())?,
                    };
                    return Ok((owner, stream, peer));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
            if owner.child.try_wait()?.is_some() {
                owner.reaped = true;
                return Err(Error::Refused("custodian exited before acquisition"));
            }
            require(Instant::now() < deadline, "custodian connect deadline")?;
            // Polling only waits for the actual accepted authenticated channel.
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn acquire(&mut self) -> (Process, ClosedOrigin) {
        let (owner, stream, peer) = self.spawn(Domain::DisposableChild).unwrap();
        let handle = ClosedOrigin::acquire(
            stream,
            peer,
            Domain::DisposableChild,
            self.nonce,
            self.record.clone(),
        )
        .unwrap();
        (owner, handle)
    }
}

#[test]
#[ignore = "private child entry, invoked only by exact fixture subprocess"]
fn custodian_process_entry() {
    let result = (|| -> Result<()> {
        let root = PathBuf::from(
            std::env::var_os("PODBAY_ORIGIN_CHILD_ROOT")
                .ok_or(Error::Refused("no private bootstrap"))?,
        );
        let input = open_member(&open_directory(&root)?, "bootstrap.bin", false)?;
        require(
            input.metadata()?.len() <= (MAX_BYTES + 53) as u64,
            "bootstrap cap",
        )?;
        let mut bytes = Vec::new();
        input
            .take((MAX_BYTES + 54) as u64)
            .read_to_end(&mut bytes)?;
        require(
            bytes.len() >= 53 && bytes.len() <= MAX_BYTES + 53,
            "bootstrap size",
        )?;
        let n = |at| u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
        let parent = Peer {
            pid: n(1),
            uid: n(5),
            gid: n(9),
            birth: u64::from_be_bytes(bytes[13..21].try_into().unwrap()),
        };
        let record = decode(&bytes[53..]).map_err(|_| Error::Refused("bootstrap record"))?;
        serve(
            &root,
            parent,
            Domain::parse(bytes[0])?,
            bytes[21..53].try_into().unwrap(),
            record,
        )
    })();
    if let Err(error) = result {
        eprintln!("CLOSED_ORIGIN_PROTOTYPE_REFUSED {error:?}");
        std::process::exit(2);
    }
    std::process::exit(0);
}

#[test]
fn codec_is_closed_bounded_and_preserves_full_subject() {
    let mut record = super::super::tests::initial();
    record.durable.subject.request_digest = [9; 32];
    let message = Message {
        tag: 0,
        domain: Domain::DisposableChild,
        sequence: u64::MAX,
        nonce: [7; 32],
        record,
    };
    let bytes = encode_message(&message).unwrap();
    let decoded = decode_message(&bytes).unwrap();
    assert_eq!(decoded.record, message.record);
    assert_eq!(decoded.sequence, u64::MAX);
    for n in 0..bytes.len() {
        assert!(decode_message(&bytes[..n]).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(decode_message(&extra).is_err());
    let mut foreign = bytes;
    foreign[9] = 99;
    assert!(decode_message(&foreign).is_err());
    assert!(decode_message(&vec![0; CHANNEL_CAP + 1]).is_err());
}

#[test]
fn authenticated_child_retains_exact_lock_and_read_only_pair() {
    let mut f = Fixture::new();
    let source_before = fs::read(f.root.join("db.sqlite")).unwrap();
    let stage_before = fs::read(f.root.join("stage.sqlite")).unwrap();
    let (mut owner, mut handle) = f.acquire();
    handle.verify_closed().unwrap();
    let competing = OpenOptions::new()
        .read(true)
        .write(true)
        .open(f.root.join("db.sqlite.manager.lock"))
        .unwrap();
    assert!(flock(&competing, FlockOperation::NonBlockingLockExclusive).is_err());
    assert_eq!(handle.domain, Domain::DisposableChild);
    assert_eq!(
        handle.record.durable.subject.lineage,
        f.record.durable.subject.lineage
    );
    assert_eq!(fs::read(f.root.join("db.sqlite")).unwrap(), source_before);
    assert_eq!(fs::read(f.root.join("stage.sqlite")).unwrap(), stage_before);
    owner.reap();
    assert!(handle.verify_closed().is_err());
    assert!(handle.stream.is_none());
    assert!(handle.verify_closed().is_err());
    flock(&competing, FlockOperation::NonBlockingLockExclusive).unwrap();
}

#[test]
fn root_pid1_domain_cannot_be_claimed_by_an_ordinary_child() {
    let mut f = Fixture::new();
    assert!(f.spawn(Domain::RootPid1).is_err());
    assert!(!f.root.join(CLOSED_RECORD).exists());
}

#[test]
fn late_engagement_and_custodian_restart_remain_closed() {
    let mut f = Fixture::new();
    let (mut owner, mut handle) = f.acquire();
    assert!(matches!(
        handle.exchange(Operation::MarkLateForTest),
        Err(Error::Refused("late engagement"))
    ));
    assert!(matches!(
        handle.verify_closed(),
        Err(Error::Refused("origin failure latched closed"))
    ));
    owner.reap();
    // Matching-looking bytes never restore origin authority after process loss.
    assert!(f.spawn(Domain::DisposableChild).is_err());
    assert!(f.root.join(CLOSED_RECORD).exists());
}

#[test]
fn partial_or_foreign_origin_record_is_preserved_and_never_adopted() {
    for bytes in [&b""[..], &b"PBGATE01"[..], &b"foreign origin"[..]] {
        let mut f = Fixture::new();
        let path = f.root.join(CLOSED_RECORD);
        file(&path, bytes);
        let before = identity(&path.metadata().unwrap());
        assert!(f.spawn(Domain::DisposableChild).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(identity(&path.metadata().unwrap()), before);
    }
}

#[test]
fn nonce_peer_and_complete_subject_mismatch_never_construct_a_handle() {
    for case in [
        "nonce",
        "peer",
        "lineage",
        "policy",
        "artifact",
        "generation",
    ] {
        let mut f = Fixture::new();
        let (_owner, stream, mut peer) = f.spawn(Domain::DisposableChild).unwrap();
        let mut nonce = f.nonce;
        let mut record = f.record.clone();
        match case {
            "nonce" => nonce[0] ^= 1,
            "peer" => peer.birth += 1,
            "lineage" => record.durable.subject.lineage.push_str(".foreign"),
            "policy" => record.durable.subject.policy_digest = [5; 32],
            "artifact" => record.durable.subject.artifact_digest = [6; 32],
            _ => {
                record = super::super::tests::next(&record, Kind::ForwardProgress);
            }
        }
        assert!(
            ClosedOrigin::acquire(stream, peer, Domain::DisposableChild, nonce, record).is_err(),
            "{case}"
        );
    }
}

#[test]
fn actual_boot_lineage_policy_and_inode_inputs_are_checked_before_publication() {
    for case in [
        "boot", "lineage", "policy", "artifact", "source", "staging", "lock", "parent",
    ] {
        let mut f = Fixture::new();
        match case {
            "boot" => f.record.durable.subject.current_boot = "foreign.current.boot".into(),
            "lineage" => f.record.durable.subject.lineage.push_str(".foreign"),
            "policy" => f.record.durable.subject.policy_digest = [5; 32],
            "artifact" => f.record.durable.subject.artifact_digest = [6; 32],
            "source" => f.record.durable.subject.source.inode += 99999,
            "staging" => f.record.durable.subject.staging.inode += 99999,
            "lock" => f.record.durable.subject.manager_lock.inode += 99999,
            _ => f.record.parent.inode += 99999,
        }
        assert!(f.spawn(Domain::DisposableChild).is_err(), "{case}");
        assert!(!f.root.join(CLOSED_RECORD).exists(), "{case}");
    }
}

#[test]
fn lock_content_and_namespace_changes_poison_existing_handle() {
    for name in [
        "db.sqlite",
        "stage.sqlite",
        "db.sqlite.manager.lock",
        "policy.bin",
        CLOSED_RECORD,
    ] {
        let mut f = Fixture::new();
        let (_owner, mut handle) = f.acquire();
        let path = f.root.join(name);
        let saved = f.root.join(format!("{name}.retained"));
        let bytes = fs::read(&path).unwrap();
        fs::rename(&path, &saved).unwrap();
        file(&path, &bytes);
        assert!(handle.verify_closed().is_err(), "{name}");
        assert!(handle.stream.is_none(), "{name}");
    }
    let mut f = Fixture::new();
    let (_owner, mut handle) = f.acquire();
    fs::write(f.root.join("policy.bin"), b"changed same-inode policy").unwrap();
    assert!(handle.verify_closed().is_err());
    assert!(handle.stream.is_none());
}

#[test]
fn replay_and_oversized_frame_refuse_without_reacquisition() {
    let mut f = Fixture::new();
    let (_owner, mut handle) = f.acquire();
    send(
        handle.stream.as_mut().unwrap(),
        &Message {
            tag: Operation::Check as u8,
            domain: handle.domain,
            sequence: 1,
            nonce: handle.nonce,
            record: handle.record.clone(),
        },
    )
    .unwrap();
    assert!(receive(handle.stream.as_mut().unwrap()).is_err());
    assert!(handle.verify_closed().is_err());
    assert!(handle.stream.is_none());
    let (mut left, mut right) = UnixStream::pair().unwrap();
    left.write_all(&u32::MAX.to_be_bytes()).unwrap();
    assert!(matches!(
        receive(&mut right),
        Err(Error::Refused("channel cap before allocation"))
    ));
}

#[test]
fn authenticated_but_foreign_or_replayed_reply_does_not_construct_handle() {
    for changed in ["nonce", "sequence", "subject", "domain", "outcome"] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let peer = self_peer().unwrap();
        let record = super::super::tests::initial();
        let responder = std::thread::spawn(move || {
            let mut response = receive(&mut server).unwrap();
            response.tag = Outcome::Closed as u8;
            match changed {
                "nonce" => response.nonce[0] ^= 1,
                "sequence" => response.sequence += 1,
                "subject" => response.record.durable.subject.request_digest = [99; 32],
                "domain" => response.domain = Domain::RootPid1,
                _ => response.tag = Outcome::Refused as u8,
            }
            send(&mut server, &response).unwrap();
        });
        assert!(
            ClosedOrigin::acquire(client, peer, Domain::DisposableChild, [3; 32], record).is_err(),
            "{changed}"
        );
        responder.join().unwrap();
    }
}
