//! NONCANONICAL TEST FIXTURE ONLY. This module is cfg(test) at its parent.
//! It exercises existing authority/rotation transaction ordering. It does not
//! authenticate an OS observer, bind production store origin, or issue grants.
use super::*;
use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DOMAIN: &[u8] = b"podbay.fixture-current-signer-admission/1\0";
const REQUEST_DOMAIN: &[u8] = b"podbay.fixture-signer-admission-request/1\0";
const TABLE: &str = "CREATE TABLE fixture_signer_admissions_v1 (
  scope_id TEXT NOT NULL, actor_id TEXT NOT NULL, admission_key TEXT NOT NULL,
  store_lineage TEXT NOT NULL, signer_generation INTEGER NOT NULL CHECK(signer_generation>=1),
  binding_digest BLOB NOT NULL CHECK(length(binding_digest)=32),
  verifier_key BLOB NOT NULL CHECK(length(verifier_key)=32),
  signed_bytes BLOB NOT NULL CHECK(length(signed_bytes) BETWEEN 1 AND 8192),
  signature BLOB NOT NULL CHECK(length(signature)=64),
  request_digest BLOB NOT NULL CHECK(length(request_digest)=32),
  owner_epoch INTEGER NOT NULL CHECK(owner_epoch>=1),
  prior_revision INTEGER NOT NULL CHECK(prior_revision>=1),
  committed_revision INTEGER NOT NULL CHECK(committed_revision=prior_revision+1),
  PRIMARY KEY(scope_id,actor_id,admission_key)
) STRICT";

#[derive(Clone)]
struct Request {
    key: String,
    lineage: String,
    actor: AuthorityActorRecord,
    owner_epoch: u64,
    expected_revision: u64,
    subject: Vec<u8>,
    signature: [u8; 64],
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Receipt {
    lineage: String,
    generation: u64,
    binding: Vec<u8>,
    key: Vec<u8>,
    signed_bytes: Vec<u8>,
    signature: Vec<u8>,
    request_digest: Vec<u8>,
    owner_epoch: u64,
    prior_revision: u64,
    committed_revision: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    Admitted(Receipt),
    ExactReplay(Receipt),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Point {
    SignerVerified,
    BeforeCommit,
    AfterCommit,
}

fn signed_bytes(request: &Request) -> Result<Vec<u8>, StoreError> {
    if request.subject.is_empty()
        || request.subject.len() > 4096
        || request.owner_epoch == 0
        || request.expected_revision == 0
        || request.actor.credential_generation == 0
        || request.actor.origin != "owner_cli"
        || request.actor.role != "coordinator"
        || request.actor.platform != "linux"
        || request.actor.parent_actor_id.is_some()
        || request.actor.pod_id.is_some()
        || request.actor.pod_incarnation.is_some()
    {
        return Err(StoreError::InvalidInput("fixture admission shape"));
    }
    let mut bytes = DOMAIN.to_vec();
    for value in [
        &request.key,
        &request.lineage,
        &request.actor.scope_id,
        &request.actor.actor_id,
    ] {
        if value.is_empty() || value.len() > 256 || !value.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(StoreError::InvalidInput("fixture admission identity"));
        }
        bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes.extend_from_slice(&actor_binding_digest(&request.actor));
    for n in [
        request.actor.credential_generation,
        request.owner_epoch,
        request.expected_revision,
    ] {
        bytes.extend_from_slice(&n.to_be_bytes());
    }
    bytes.extend_from_slice(&(request.subject.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&request.subject);
    if bytes.len() > 8192 {
        return Err(StoreError::InvalidInput("fixture transcript bound"));
    }
    Ok(bytes)
}
fn request_digest(bytes: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(REQUEST_DOMAIN);
    h.update(bytes);
    h.update(signature);
    h.finalize().to_vec()
}
fn verify_signature(key: &[u8], bytes: &[u8], signature: &[u8]) -> Result<(), StoreError> {
    let key = PublicKey::from_slice(key)
        .and_then(|k| k.validate().map(|_| k))
        .map_err(|_| StoreError::Conflict("fixture invalid verifier"))?;
    let sig = Signature::from_slice(signature)
        .map_err(|_| StoreError::Conflict("fixture signature shape"))?;
    key.verify(bytes, &sig)
        .map_err(|_| StoreError::Conflict("fixture invalid signature"))
}
fn lookup(tx: &rusqlite::Transaction<'_>, r: &Request) -> Result<Option<Receipt>, StoreError> {
    tx.query_row("SELECT store_lineage,signer_generation,binding_digest,verifier_key,signed_bytes,
        signature,request_digest,owner_epoch,prior_revision,committed_revision FROM fixture_signer_admissions_v1
        WHERE scope_id=?1 AND actor_id=?2 AND admission_key=?3",
        params![r.actor.scope_id,r.actor.actor_id,r.key],|row|Ok(Receipt {
            lineage:row.get(0)?,generation:row.get::<_,i64>(1)? as u64,binding:row.get(2)?,key:row.get(3)?,
            signed_bytes:row.get(4)?,signature:row.get(5)?,request_digest:row.get(6)?,
            owner_epoch:row.get::<_,i64>(7)? as u64,prior_revision:row.get::<_,i64>(8)? as u64,
            committed_revision:row.get::<_,i64>(9)? as u64,
        })).optional().map_err(StoreError::from)
}
fn admit(
    store: &mut PodBayStore,
    r: &Request,
    mut hook: impl FnMut(Point) -> Result<(), StoreError>,
) -> Result<Outcome, StoreError> {
    let bytes = signed_bytes(r)?;
    let digest = request_digest(&bytes, &r.signature);
    let expected_commit = r
        .expected_revision
        .checked_add(1)
        .ok_or(StoreError::InvalidInput("fixture revision exhaustion"))?;
    if r.lineage != store.store_lineage {
        return Err(StoreError::WrongScope);
    }
    let tx = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let actual_lineage: String = tx.query_row(
        "SELECT lineage FROM store_identity WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if actual_lineage != r.lineage {
        return Err(StoreError::WrongScope);
    }
    // Exact committed replay is historical readback, never a new admission.
    if let Some(saved) = lookup(&tx, r)? {
        if saved.lineage != r.lineage
            || saved.generation != r.actor.credential_generation
            || saved.binding != actor_binding_digest(&r.actor)
            || saved.signed_bytes != bytes
            || saved.signature != r.signature
            || saved.request_digest != digest
            || saved.owner_epoch != r.owner_epoch
            || saved.prior_revision != r.expected_revision
            || saved.committed_revision != expected_commit
        {
            return Err(StoreError::Conflict(
                "fixture admission key changed exact request",
            ));
        }
        verify_signature(&saved.key, &saved.signed_bytes, &saved.signature)?;
        tx.commit()?;
        return Ok(Outcome::ExactReplay(saved));
    }
    require_current_actor(&tx, r.owner_epoch, r.expected_revision, &r.actor)?;
    let verifier = require_matching_verifier(&tx, &r.actor)?;
    if verifier.revoked {
        return Err(StoreError::Conflict("fixture current verifier revoked"));
    }
    verify_signature(&verifier.public_key, &bytes, &r.signature)?;
    hook(Point::SignerVerified)?;
    let committed = advance_authority_revision(&tx, r.expected_revision)?;
    let receipt = Receipt {
        lineage: actual_lineage,
        generation: r.actor.credential_generation,
        binding: verifier.binding_digest,
        key: verifier.public_key,
        signed_bytes: bytes,
        signature: r.signature.to_vec(),
        request_digest: digest,
        owner_epoch: r.owner_epoch,
        prior_revision: r.expected_revision,
        committed_revision: committed,
    };
    tx.execute("INSERT INTO fixture_signer_admissions_v1(scope_id,actor_id,admission_key,store_lineage,
        signer_generation,binding_digest,verifier_key,signed_bytes,signature,request_digest,owner_epoch,
        prior_revision,committed_revision) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![r.actor.scope_id,r.actor.actor_id,r.key,receipt.lineage,sqlite_integer(receipt.generation)?,
            receipt.binding,receipt.key,receipt.signed_bytes,receipt.signature,receipt.request_digest,
            sqlite_integer(receipt.owner_epoch)?,sqlite_integer(receipt.prior_revision)?,sqlite_integer(committed)?])?;
    hook(Point::BeforeCommit)?;
    tx.commit()?;
    hook(Point::AfterCommit)?;
    Ok(Outcome::Admitted(receipt))
}

struct Fixture {
    root: PathBuf,
    path: PathBuf,
    lineage: String,
    actor: AuthorityActorRecord,
    revision: u64,
    retain: bool,
}
fn actor() -> AuthorityActorRecord {
    AuthorityActorRecord {
        actor_id: "owner.fixture".into(),
        scope_id: "scope.fixture".into(),
        role: "coordinator".into(),
        origin: "owner_cli".into(),
        parent_actor_id: None,
        pod_id: None,
        pod_incarnation: None,
        credential_generation: 1,
        platform: "linux".into(),
        os_identity: "linux.uid.1000".into(),
        process_identity: "linux.pid.123".into(),
        start_identity: 456,
        containment_identity: "/fixture.scope".into(),
    }
}
fn key(seed: u8) -> KeyPair {
    KeyPair::from_seed(Seed::new([seed; 32]))
}
fn sign(mut request: Request, seed: u8) -> Request {
    request.signature = *key(seed).sk.sign(signed_bytes(&request).unwrap(), None);
    request
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "podbay-admission-fixture-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("fixture.sqlite");
        let mut store = PodBayStore::open(&path).unwrap();
        let actor = actor();
        let s = store.begin_authority_replay(0, 1).unwrap();
        let revision = store
            .apply_authority_mutation(1, s.revision, AuthorityMutation::PutActor(actor.clone()))
            .unwrap();
        let revision = store
            .register_actor_verifier_from_trusted_host(1, revision, &actor, *key(7).pk)
            .unwrap();
        store.connection.execute_batch(TABLE).unwrap();
        let lineage = store.store_lineage.clone();
        drop(store);
        Self {
            root,
            path,
            lineage,
            actor,
            revision,
            retain: false,
        }
    }
    fn open(&self) -> PodBayStore {
        PodBayStore::open(&self.path).unwrap()
    }
    fn request(&self, name: &str) -> Request {
        sign(
            Request {
                key: name.into(),
                lineage: self.lineage.clone(),
                actor: self.actor.clone(),
                owner_epoch: 1,
                expected_revision: self.revision,
                subject: b"exact opaque fixture terminal subject".to_vec(),
                signature: [0; 64],
            },
            7,
        )
    }
    fn rotate(
        &self,
        store: &mut PodBayStore,
        revision: u64,
    ) -> Result<OwnerActorRotationReceipt, StoreError> {
        let mut next = self.actor.clone();
        next.credential_generation = 2;
        next.process_identity = "linux.pid.124".into();
        next.start_identity = 457;
        store.rotate_owner_actor_from_trusted_host(&TrustedOwnerRotationProof {
            store_lineage: self.lineage.clone(),
            expected_owner_epoch: 1,
            expected_revision: revision,
            rotation_key: "rotation.fixture.2".into(),
            expected_actor: self.actor.clone(),
            expected_public_key: *key(7).pk,
            next_actor: next,
            next_public_key: *key(8).pk,
        })
    }
    fn rows(&self) -> i64 {
        self.open()
            .connection
            .query_row(
                "SELECT count(*) FROM fixture_signer_admissions_v1",
                [],
                |r| r.get(0),
            )
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if !self.retain {
            std::fs::remove_dir_all(&self.root).unwrap();
        }
    }
}

#[test]
fn admission_before_rotation_and_exact_replay_afterwards() {
    let f = Fixture::new();
    let request = f.request("admission.one");
    let mut store = f.open();
    let Outcome::Admitted(receipt) = admit(&mut store, &request, |_| Ok(())).unwrap() else {
        panic!("not admitted")
    };
    assert_eq!(receipt.committed_revision, f.revision + 1);
    let rotation = f.rotate(&mut store, receipt.committed_revision).unwrap();
    assert_eq!(rotation.authority_revision, receipt.committed_revision + 1);
    drop(store);
    let mut reopened = f.open();
    let revision = reopened.authority_snapshot().unwrap().revision;
    assert_eq!(
        admit(&mut reopened, &request, |_| panic!(
            "replay must not enter commit hooks"
        ))
        .unwrap(),
        Outcome::ExactReplay(receipt)
    );
    assert_eq!(reopened.authority_snapshot().unwrap().revision, revision);
    assert_eq!(f.rows(), 1);
}
#[test]
fn rotation_first_refuses_old_signature_even_when_signed_after_rotation() {
    let f = Fixture::new();
    let mut store = f.open();
    let rotation = f.rotate(&mut store, f.revision).unwrap();
    let mut request = f.request("late.old.key");
    request.expected_revision = rotation.authority_revision;
    request = sign(request, 7); // Deliberately sign with retained old secret AFTER rotation.
    verify_signature(
        key(7).pk.as_ref(),
        &signed_bytes(&request).unwrap(),
        &request.signature,
    )
    .unwrap();
    assert!(matches!(
        admit(&mut store, &request, |_| Ok(())),
        Err(StoreError::StaleEpoch)
    ));
    assert_eq!(
        store.authority_snapshot().unwrap().revision,
        rotation.authority_revision
    );
    assert_eq!(f.rows(), 0);
}
#[test]
fn changed_same_key_cas_and_invalid_signatures_do_not_write() {
    let f = Fixture::new();
    let request = f.request("admission.one");
    let mut store = f.open();
    let mut bad = request.clone();
    bad.signature[0] ^= 1;
    assert!(matches!(
        admit(&mut store, &bad, |_| Ok(())),
        Err(StoreError::Conflict("fixture invalid signature"))
    ));
    assert_eq!(f.rows(), 0);
    assert_eq!(store.authority_snapshot().unwrap().revision, f.revision);
    admit(&mut store, &request, |_| Ok(())).unwrap();
    let mut changed = request.clone();
    changed.subject.push(1);
    changed = sign(changed, 7);
    assert!(matches!(
        admit(&mut store, &changed, |_| Ok(())),
        Err(StoreError::Conflict(
            "fixture admission key changed exact request"
        ))
    ));
    let stale = f.request("admission.two");
    assert!(matches!(
        admit(&mut store, &stale, |_| Ok(())),
        Err(StoreError::StaleEpoch)
    ));
    assert_eq!(f.rows(), 1);
    assert_eq!(store.authority_snapshot().unwrap().revision, f.revision + 1);
}
#[test]
fn actual_rotation_connection_is_busy_until_admission_commits() {
    let f = Fixture::new();
    let mut admitting = f.open();
    let mut rotating = f.open();
    rotating.connection.busy_timeout(Duration::ZERO).unwrap();
    let request = f.request("contended");
    let mut checked = Vec::new();
    let outcome = admit(&mut admitting, &request, |point| {
        if matches!(point, Point::SignerVerified | Point::BeforeCommit) {
            let result = f.rotate(&mut rotating, f.revision);
            assert!(
                matches!(result,Err(StoreError::Storage(rusqlite::Error::SqliteFailure(ref e,_)))
                if e.code==rusqlite::ErrorCode::DatabaseBusy)
            );
            checked.push(point);
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(checked, vec![Point::SignerVerified, Point::BeforeCommit]);
    let Outcome::Admitted(receipt) = outcome else {
        panic!("not admitted")
    };
    f.rotate(&mut rotating, receipt.committed_revision).unwrap();
}
#[test]
fn precommit_error_rolls_back_receipt_and_revision() {
    let f = Fixture::new();
    let mut store = f.open();
    let request = f.request("rollback");
    assert!(
        admit(&mut store, &request, |p| if p == Point::BeforeCommit {
            Err(StoreError::Conflict("fixture stop"))
        } else {
            Ok(())
        })
        .is_err()
    );
    drop(store);
    assert_eq!(f.rows(), 0);
    assert_eq!(f.open().authority_snapshot().unwrap().revision, f.revision);
}

#[test]
#[ignore = "child process entry; invoked only with exact fixture environment"]
fn crash_child() {
    let path = PathBuf::from(
        std::env::var_os("PODBAY_SIGN_FIXTURE_DB").expect("child fixture DB missing"),
    );
    let revision = std::env::var("PODBAY_SIGN_FIXTURE_REVISION")
        .unwrap()
        .parse()
        .unwrap();
    let phase = std::env::var("PODBAY_SIGN_FIXTURE_PHASE").unwrap();
    assert!(matches!(phase.as_str(), "before" | "after"));
    let token = std::env::var("PODBAY_SIGN_FIXTURE_TOKEN").unwrap();
    let mut store = PodBayStore::open(path).unwrap();
    let request = sign(
        Request {
            key: "crash.fixture".into(),
            lineage: store.store_lineage.clone(),
            actor: actor(),
            owner_epoch: 1,
            expected_revision: revision,
            subject: b"exact opaque fixture terminal subject".to_vec(),
            signature: [0; 64],
        },
        7,
    );
    admit(&mut store, &request, |point| {
        if (phase == "before" && point == Point::BeforeCommit)
            || (phase == "after" && point == Point::AfterCommit)
        {
            println!("SIGN_ADMISSION_CHECKPOINT {token} {phase}");
            std::io::stdout().flush().unwrap();
            let mut byte = [0u8; 1];
            std::io::stdin().read_exact(&mut byte).unwrap();
            panic!("parent must kill this exact child, not resume it");
        }
        Ok(())
    })
    .unwrap();
    panic!("child checkpoint missed");
}
#[test]
fn child_death_before_and_after_commit_has_exact_recovery() {
    for phase in ["before", "after"] {
        let mut f = Fixture::new();
        f.retain = true;
        let token = f.root.file_name().unwrap().to_str().unwrap().to_owned();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "authority::signer_admission_fixture::crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env("PODBAY_SIGN_FIXTURE_DB", &f.path)
            .env("PODBAY_SIGN_FIXTURE_REVISION", f.revision.to_string())
            .env("PODBAY_SIGN_FIXTURE_PHASE", phase)
            .env("PODBAY_SIGN_FIXTURE_TOKEN", &token)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let child_pid = child.id();
        let stdout = child.stdout.take().unwrap();
        let expected = format!("SIGN_ADMISSION_CHECKPOINT {token} {phase}");
        let (send, recv) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if line.unwrap() == expected {
                    let _ = send.send(());
                    break;
                }
            }
        });
        let reached = recv.recv_timeout(Duration::from_secs(10));
        child.kill().unwrap();
        let status = child.wait().unwrap();
        reader.join().unwrap();
        assert!(reached.is_ok(), "child did not reach exact checkpoint");
        assert!(!status.success());
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9), "exact child must die by SIGKILL");
        let mut reopened = f.open();
        let request = f.request("crash.fixture");
        if phase == "before" {
            assert_eq!(f.rows(), 0);
            assert_eq!(reopened.authority_snapshot().unwrap().revision, f.revision);
            f.rotate(&mut reopened, f.revision).unwrap();
            assert!(matches!(
                admit(&mut reopened, &request, |_| Ok(())),
                Err(StoreError::StaleEpoch)
            ));
        } else {
            assert_eq!(f.rows(), 1);
            assert_eq!(
                reopened.authority_snapshot().unwrap().revision,
                f.revision + 1
            );
            f.rotate(&mut reopened, f.revision + 1).unwrap();
            assert!(matches!(
                admit(&mut reopened, &request, |_| panic!("replay only")).unwrap(),
                Outcome::ExactReplay(_)
            ));
            assert_eq!(f.rows(), 1);
        }
        let final_revision = reopened.authority_snapshot().unwrap().revision;
        drop(reopened);
        let evidence = serde_json::json!({
            "schema":"podbay.fixture-signer-child-death/1", "phase":phase,
            "fixture_root":f.root, "database":f.path, "lineage":f.lineage,
            "checkpoint_token":token, "child_pid":child_pid, "signal":status.signal(),
            "exact_child_reaped":true, "initial_revision":f.revision,
            "final_revision_after_recovery_and_rotation":final_revision,
            "admission_rows":f.rows(), "power_loss_proof":false,
            "scope":"fresh disposable fixture only; no trusted-origin or terminal-truth claim"
        });
        std::fs::write(
            f.root.join("child-death-evidence.json"),
            serde_json::to_vec_pretty(&evidence).unwrap(),
        )
        .unwrap();
        println!("SIGN_ADMISSION_RECOVERY {evidence}");
    }
}
