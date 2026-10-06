//! NONCANONICAL cfg(test)-only sequencing prototype. Fixture authority is
//! explicitly injected; no production origin/grant/credential is acquired.
//! Only the real Store admission and claim transactions are under test.
//! Outcomes use a separate fixture database, never pod.stopped/outbox observed.
use super::*;
use podbay_store::{
    Admission, CommandRequest, EffectClaim, EffectState, PodBayStore, Receipt, StoreError,
    VerifiedPrincipal,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Point {
    AfterAdmissionCommit,
    AfterClaimCommit,
    BeforeFakeSend,
    AfterFakeSend,
    BeforeOutcomeCommit,
    AfterOutcomeCommit,
}
#[derive(Debug)]
enum Error {
    Store(StoreError),
    Sql(rusqlite::Error),
    Codec(CodecError),
    Unknown(Point),
    FixtureAuthorityMismatch,
    JournalConflict,
    ClaimMismatch,
}
impl From<StoreError> for Error {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}
impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sql(e)
    }
}
impl From<CodecError> for Error {
    fn from(e: CodecError) -> Self {
        Self::Codec(e)
    }
}
type Result<T> = std::result::Result<T, Error>;
fn clear(_: Point, _: &Receipt) -> Result<()> {
    Ok(())
}

/// A test assumption, deliberately not named or exported as trusted authority.
#[derive(Clone)]
struct FixtureAuthority {
    lineage: String,
    actor: String,
    scope: String,
    owner: u64,
    revision: u64,
    actor_generation: u64,
}
impl FixtureAuthority {
    fn check(&self, intent: &IntentRecord) -> Result<()> {
        let c = &intent.context;
        if c.lineage != self.lineage
            || c.actor != self.actor
            || c.scope != self.scope
            || c.owner_epoch != self.owner
            || c.authority_revision != self.revision
            || c.actor_credential_generation != self.actor_generation
        {
            return Err(Error::FixtureAuthorityMismatch);
        }
        Ok(())
    }
}

struct Driver {
    store: PodBayStore,
    journal: Journal,
    authority: FixtureAuthority,
}
#[derive(Debug)]
enum Begin {
    Permit(SendPermit),
    NoPermit {
        receipt: Receipt,
        state: EffectState,
    },
}
/// No Clone/Deserialize/data constructor. One actual Committed+NewClaim path
/// constructs this value. Consuming it never calls a production Pod transport.
#[must_use]
#[derive(Debug)]
struct SendPermit {
    receipt: Receipt,
    intent: IntentRecord,
}

impl Driver {
    fn begin(
        &mut self,
        intent: &IntentRecord,
        mut hook: impl FnMut(Point, &Receipt) -> Result<()>,
    ) -> Result<Begin> {
        self.authority.check(intent)?;
        let bytes = intent.encode()?;
        let request = CommandRequest {
            principal: VerifiedPrincipal::from_authenticated_boundary(&self.authority.actor)?,
            namespace: "fixture.operator.stop".into(),
            command_key: intent.context.stop_key.clone(),
            scope_id: intent.context.scope.clone(),
            target_id: intent.prepared.status.pod_id.clone(),
            expected_owner_epoch: intent.context.owner_epoch,
            expected_target_epoch: intent.prepared.status.incarnation,
            canonical_request: bytes.clone(),
            event_kind: "fixture.operator.stop.intent".into(),
            event_payload: bytes.clone(),
            effect_kind: "pod.stop".into(),
            effect_payload: bytes,
        };
        let receipt = match self.store.admit(&request)? {
            Admission::Duplicate(receipt) => {
                let state = self.store.effect_state(receipt.outbox_id)?;
                return Ok(Begin::NoPermit { receipt, state });
            }
            Admission::Committed(receipt) => receipt,
        };
        hook(Point::AfterAdmissionCommit, &receipt)?;
        let claim = self.store.claim_effect(
            receipt.outbox_id,
            &intent.context.scope,
            &intent.prepared.status.pod_id,
            intent.context.owner_epoch,
            intent.prepared.status.incarnation,
            intent.context.authority_revision,
            &receipt.command_id,
        )?;
        if claim != EffectClaim::NewClaim {
            let state = self.store.effect_state(receipt.outbox_id)?;
            return Ok(Begin::NoPermit { receipt, state });
        }
        hook(Point::AfterClaimCommit, &receipt)?;
        // This is the only send-permit construction site.
        Ok(Begin::Permit(SendPermit {
            receipt,
            intent: intent.clone(),
        }))
    }
    fn check_claim(&self, permit: &SendPermit) -> Result<()> {
        self.authority.check(&permit.intent)?;
        let effect = self.store.load_effect(
            permit.receipt.outbox_id,
            &permit.intent.context.scope,
            &permit.intent.prepared.status.pod_id,
        )?;
        if effect.state != EffectState::ClaimedUncertain
            || effect.kind != "pod.stop"
            || effect.command_id != permit.receipt.command_id
            || effect.claim_key.as_deref() != Some(permit.receipt.command_id.as_str())
            || effect.payload != permit.intent.encode()?
            || hex(&Sha256::digest(&effect.payload)) != effect.effect_digest
        {
            return Err(Error::ClaimMismatch);
        }
        Ok(())
    }
}
impl SendPermit {
    fn consume(
        self,
        driver: &mut Driver,
        sender: &FakeSender,
        mut hook: impl FnMut(Point, &Receipt) -> Result<()>,
    ) -> Result<OutcomeRecord> {
        driver.check_claim(&self)?;
        hook(Point::BeforeFakeSend, &self.receipt)?;
        let outcome = sender.exchange(&self.intent)?;
        hook(Point::AfterFakeSend, &self.receipt)?;
        driver
            .journal
            .save(&self.receipt, &self.intent, &outcome, &mut hook)?;
        Ok(outcome)
    }
}

#[derive(Clone, Copy)]
enum Mode {
    RefusedBeforeWrite,
    UncertainAfterWrite,
    ReplyRunning,
    ReplyStopped,
}
struct FakeSender {
    invocations: Arc<AtomicUsize>,
    emulated_writes: Arc<AtomicUsize>,
    mode: Mode,
}
impl FakeSender {
    fn new(mode: Mode) -> Self {
        Self {
            invocations: Arc::new(AtomicUsize::new(0)),
            emulated_writes: Arc::new(AtomicUsize::new(0)),
            mode,
        }
    }
    fn exchange(&self, intent: &IntentRecord) -> Result<OutcomeRecord> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        let outcome = match self.mode {
            Mode::RefusedBeforeWrite => {
                OutcomeRecord::from_error(intent, AttestedStopError::RefusedBeforeWrite("fixture"))?
            }
            Mode::UncertainAfterWrite => {
                self.emulated_writes.fetch_add(1, Ordering::SeqCst);
                OutcomeRecord::from_error(
                    intent,
                    AttestedStopError::UncertainAfterWrite("fixture"),
                )?
            }
            Mode::ReplyRunning | Mode::ReplyStopped => {
                self.emulated_writes.fetch_add(1, Ordering::SeqCst);
                super::tests::reply_record(intent, matches!(self.mode, Mode::ReplyRunning))
            }
        };
        Ok(outcome)
    }
    fn counts(&self) -> (usize, usize) {
        (
            self.invocations.load(Ordering::SeqCst),
            self.emulated_writes.load(Ordering::SeqCst),
        )
    }
}

// Deliberately separate from the actual PodBay schema. No atomicity with the
// Store transaction is implied. A missing outcome never restores a permit.
const JOURNAL_SCHEMA: &str = "CREATE TABLE fixture_exchange_outcomes (
 store_lineage TEXT NOT NULL, command_id TEXT NOT NULL, outbox_id INTEGER NOT NULL CHECK(outbox_id>0),
 request_digest TEXT NOT NULL, intent_digest TEXT NOT NULL, outcome_digest TEXT NOT NULL,
 outcome BLOB NOT NULL CHECK(length(outcome) BETWEEN 1 AND 196608),
 PRIMARY KEY(store_lineage,command_id), UNIQUE(store_lineage,outbox_id)
) STRICT";
struct Journal {
    connection: Connection,
}
impl Journal {
    fn open(path: &Path) -> Result<Self> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(std::time::Duration::from_secs(3))?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        let schema: Option<String> = connection.query_row("SELECT sql FROM sqlite_master WHERE type='table' AND name='fixture_exchange_outcomes'", [], |r| r.get(0)).optional()?;
        match schema {
            None => connection.execute_batch(JOURNAL_SCHEMA)?,
            Some(value) if value == JOURNAL_SCHEMA => {}
            _ => return Err(Error::JournalConflict),
        }
        Ok(Self { connection })
    }
    fn save(
        &mut self,
        receipt: &Receipt,
        intent: &IntentRecord,
        outcome: &OutcomeRecord,
        hook: &mut impl FnMut(Point, &Receipt) -> Result<()>,
    ) -> Result<()> {
        outcome.verify_intent(intent)?;
        let bytes = outcome.encode()?;
        let digest = outcome.digest()?;
        let intent_digest = intent.digest()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let saved: Option<(i64,String,String,String,Vec<u8>)> = tx.query_row(
            "SELECT outbox_id,request_digest,intent_digest,outcome_digest,outcome FROM fixture_exchange_outcomes WHERE store_lineage=?1 AND command_id=?2",
            params![intent.context.lineage,receipt.command_id], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
        if let Some(row) = saved {
            if row
                != (
                    receipt.outbox_id,
                    receipt.request_digest.clone(),
                    intent_digest,
                    digest,
                    bytes,
                )
            {
                return Err(Error::JournalConflict);
            }
            tx.commit()?;
            return Ok(());
        }
        tx.execute(
            "INSERT INTO fixture_exchange_outcomes VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                intent.context.lineage,
                receipt.command_id,
                receipt.outbox_id,
                receipt.request_digest,
                intent_digest,
                digest,
                bytes
            ],
        )?;
        hook(Point::BeforeOutcomeCommit, receipt)?;
        tx.commit()?;
        hook(Point::AfterOutcomeCommit, receipt)?;
        Ok(())
    }
    fn read(&self, receipt: &Receipt, intent: &IntentRecord) -> Result<Option<OutcomeRecord>> {
        let saved: Option<(i64,String,String,String,Vec<u8>)> = self.connection.query_row(
            "SELECT outbox_id,request_digest,intent_digest,outcome_digest,outcome FROM fixture_exchange_outcomes WHERE store_lineage=?1 AND command_id=?2",
            params![intent.context.lineage,receipt.command_id], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
        let Some((outbox, request_digest, intent_digest, outcome_digest, bytes)) = saved else {
            return Ok(None);
        };
        let outcome = OutcomeRecord::decode(&bytes)?;
        outcome.verify_intent(intent)?;
        if outbox != receipt.outbox_id
            || request_digest != receipt.request_digest
            || intent_digest != intent.digest()?
            || outcome_digest != outcome.digest()?
        {
            return Err(Error::JournalConflict);
        }
        Ok(Some(outcome))
    }
    fn count(&self) -> i64 {
        self.connection
            .query_row("SELECT count(*) FROM fixture_exchange_outcomes", [], |r| {
                r.get(0)
            })
            .unwrap()
    }
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    directory: PathBuf,
    database: PathBuf,
    journal: PathBuf,
    intent: IntentRecord,
    authority: FixtureAuthority,
}
impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "one-send-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let database = directory.join("podbay.sqlite");
        let journal = directory.join("noncanonical-outcomes.sqlite");
        let mut store = PodBayStore::open(&database).unwrap();
        let owner = store.owner_epoch().unwrap();
        store.advance_owner_epoch(owner, owner + 1).unwrap();
        let seed = Connection::open(&database).unwrap();
        // Explicit fixture injection. There is no enrolled actor or StopPod
        // grant here; Store's low-level admission/claim do not verify those.
        seed.execute(
            "UPDATE metadata SET value=19 WHERE key='authority_revision'",
            [],
        )
        .unwrap();
        let lineage: String = seed
            .query_row(
                "SELECT lineage FROM store_identity WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let mut intent = super::tests::fixture();
        intent.context.lineage = lineage.clone();
        intent.context.owner_epoch = owner + 1;
        intent.context.actor_credential_generation = 11;
        intent.context.authority_revision = 19;
        let bound = intent.prepared.status.bound.as_mut().unwrap();
        bound.store_lineage = lineage.clone();
        bound.owner_epoch = owner + 1;
        assert_eq!(bound.credential_epoch, 3);
        store
            .advance_target_epoch(&intent.context.scope, &intent.prepared.status.pod_id, 0, 1)
            .unwrap();
        store
            .advance_target_epoch(
                &intent.context.scope,
                &intent.prepared.status.pod_id,
                1,
                intent.prepared.status.incarnation,
            )
            .unwrap();
        intent.encode().unwrap();
        let authority = FixtureAuthority {
            lineage,
            actor: intent.context.actor.clone(),
            scope: intent.context.scope.clone(),
            owner: owner + 1,
            revision: 19,
            actor_generation: 11,
        };
        drop(seed);
        drop(store);
        Self {
            directory,
            database,
            journal,
            intent,
            authority,
        }
    }
    fn open(&self) -> Driver {
        Driver {
            store: PodBayStore::open(&self.database).unwrap(),
            journal: Journal::open(&self.journal).unwrap(),
            authority: self.authority.clone(),
        }
    }
    fn counts(&self) -> (i64, i64, i64, i64) {
        let c = Connection::open(&self.database).unwrap();
        let count = |sql| c.query_row(sql, [], |r| r.get(0)).unwrap();
        (
            count("SELECT count(*) FROM commands"),
            count("SELECT count(*) FROM outbox"),
            count("SELECT count(*) FROM events"),
            count("SELECT count(*) FROM events WHERE kind='pod.stopped'"),
        )
    }
    fn assert_unobserved(&self, receipt: &Receipt) {
        let d = self.open();
        let effect = d
            .store
            .load_effect(
                receipt.outbox_id,
                &self.intent.context.scope,
                &self.intent.prepared.status.pod_id,
            )
            .unwrap();
        assert_eq!(effect.state, EffectState::ClaimedUncertain);
        assert!(effect.observation_payload.is_none());
        assert!(effect.observed_stage.is_none());
        assert_eq!(self.counts(), (1, 1, 1, 0));
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
fn permit(begin: Begin) -> SendPermit {
    match begin {
        Begin::Permit(p) => p,
        other => panic!("expected fresh permit, got {other:?}"),
    }
}
fn no_permit(begin: Begin, expected: EffectState) -> Receipt {
    match begin {
        Begin::NoPermit { receipt, state } => {
            assert_eq!(state, expected);
            receipt
        }
        Begin::Permit(_) => panic!("duplicate manufactured another permit"),
    }
}

#[test]
fn one_send_fresh_actual_admission_claim_consumption_and_immutable_outcome() {
    for mode in [
        Mode::RefusedBeforeWrite,
        Mode::UncertainAfterWrite,
        Mode::ReplyRunning,
        Mode::ReplyStopped,
    ] {
        let f = Fixture::new();
        let mut d = f.open();
        let sender = FakeSender::new(mode);
        let p = permit(d.begin(&f.intent, clear).unwrap());
        let receipt = p.receipt.clone();
        let outcome = p.consume(&mut d, &sender, clear).unwrap();
        assert_eq!(
            sender.counts(),
            (1, usize::from(!matches!(mode, Mode::RefusedBeforeWrite)))
        );
        assert_eq!(
            d.journal.read(&receipt, &f.intent).unwrap(),
            Some(outcome.clone())
        );
        d.journal
            .save(&receipt, &f.intent, &outcome, &mut |_, _| {
                panic!("exact repetition should not recommit")
            })
            .unwrap();
        let changed = if matches!(mode, Mode::RefusedBeforeWrite) {
            OutcomeRecord::from_error(&f.intent, AttestedStopError::UncertainAfterWrite("fixture"))
                .unwrap()
        } else {
            OutcomeRecord::from_error(&f.intent, AttestedStopError::RefusedBeforeWrite("fixture"))
                .unwrap()
        };
        assert!(matches!(
            d.journal.save(&receipt, &f.intent, &changed, &mut clear),
            Err(Error::JournalConflict)
        ));
        assert_eq!(d.journal.count(), 1);
        drop(d);
        let mut reopened = f.open();
        no_permit(
            reopened
                .begin(&f.intent, |_, _| panic!("duplicate ran commit hook"))
                .unwrap(),
            EffectState::ClaimedUncertain,
        );
        assert_eq!(
            reopened.journal.read(&receipt, &f.intent).unwrap(),
            Some(outcome)
        );
        assert_eq!(sender.invocations.load(Ordering::SeqCst), 1);
        f.assert_unobserved(&receipt);
    }
}

#[test]
fn one_send_unknown_admission_and_claim_acknowledgements_never_resend_after_reopen() {
    for point in [Point::AfterAdmissionCommit, Point::AfterClaimCommit] {
        let f = Fixture::new();
        let mut d = f.open();
        let sender = FakeSender::new(Mode::ReplyRunning);
        assert!(
            matches!(d.begin(&f.intent,|at,_|if at==point {Err(Error::Unknown(at))}else{Ok(())}),Err(Error::Unknown(at)) if at==point)
        );
        assert_eq!(sender.counts(), (0, 0));
        drop(d);
        let mut reopened = f.open();
        let expected = if point == Point::AfterAdmissionCommit {
            EffectState::Prepared
        } else {
            EffectState::ClaimedUncertain
        };
        let receipt = no_permit(
            reopened
                .begin(&f.intent, |_, _| panic!("reopen retried commit"))
                .unwrap(),
            expected,
        );
        assert!(
            reopened
                .journal
                .read(&receipt, &f.intent)
                .unwrap()
                .is_none()
        );
        assert_eq!(f.counts(), (1, 1, 1, 0));
        assert_eq!(sender.counts(), (0, 0));
    }
}

#[test]
fn one_send_lost_outcome_windows_leave_claimed_uncertainty_without_second_send() {
    for point in [
        Point::BeforeFakeSend,
        Point::AfterFakeSend,
        Point::BeforeOutcomeCommit,
        Point::AfterOutcomeCommit,
    ] {
        let f = Fixture::new();
        let mut d = f.open();
        let sender = FakeSender::new(Mode::ReplyStopped);
        let p = permit(d.begin(&f.intent, clear).unwrap());
        let receipt = p.receipt.clone();
        assert!(
            matches!(p.consume(&mut d,&sender,|at,_|if at==point {Err(Error::Unknown(at))}else{Ok(())}),Err(Error::Unknown(at)) if at==point)
        );
        let count = usize::from(point != Point::BeforeFakeSend);
        assert_eq!(sender.counts(), (count, count));
        drop(d);
        let mut reopened = f.open();
        no_permit(
            reopened.begin(&f.intent, clear).unwrap(),
            EffectState::ClaimedUncertain,
        );
        assert_eq!(
            reopened
                .journal
                .read(&receipt, &f.intent)
                .unwrap()
                .is_some(),
            point == Point::AfterOutcomeCommit
        );
        assert_eq!(sender.counts(), (count, count));
        f.assert_unobserved(&receipt);
    }
}

#[test]
fn one_send_changed_same_key_and_competing_key_for_same_pod_refuse() {
    let f = Fixture::new();
    let mut d = f.open();
    let sender = FakeSender::new(Mode::ReplyRunning);
    let p = permit(d.begin(&f.intent, clear).unwrap());
    let receipt = p.receipt.clone();
    drop(p);
    let mut changed = f.intent.clone();
    changed.context.policy_digest = "9".repeat(64);
    assert!(matches!(
        d.begin(&changed, clear),
        Err(Error::Store(StoreError::Conflict(_)))
    ));
    let mut competing = f.intent.clone();
    competing.context.stop_key.push_str(".other");
    assert!(matches!(
        d.begin(&competing, clear),
        Err(Error::Store(StoreError::Conflict(_)))
    ));
    assert_eq!(sender.counts(), (0, 0));
    f.assert_unobserved(&receipt);
}

#[test]
fn one_send_actual_revision_cas_refusal_and_existing_claim_cannot_make_permit() {
    for steal in [false, true] {
        let f = Fixture::new();
        let mut d = f.open();
        let mut other = PodBayStore::open(&f.database).unwrap();
        let result = d.begin(&f.intent, |at, r| {
            if at == Point::AfterAdmissionCommit {
                if steal {
                    assert_eq!(
                        other.claim_effect(
                            r.outbox_id,
                            &f.intent.context.scope,
                            &f.intent.prepared.status.pod_id,
                            f.intent.context.owner_epoch,
                            f.intent.prepared.status.incarnation,
                            f.intent.context.authority_revision,
                            &r.command_id
                        )?,
                        EffectClaim::NewClaim
                    );
                } else {
                    Connection::open(&f.database)?.execute(
                        "UPDATE metadata SET value=value+1 WHERE key='authority_revision'",
                        [],
                    )?;
                }
            }
            Ok(())
        });
        if steal {
            no_permit(result.unwrap(), EffectState::ClaimedUncertain);
        } else {
            assert!(matches!(result, Err(Error::Store(StoreError::StaleEpoch))));
        }
        drop(d);
        let mut reopened = f.open();
        no_permit(
            reopened.begin(&f.intent, clear).unwrap(),
            if steal {
                EffectState::ClaimedUncertain
            } else {
                EffectState::Prepared
            },
        );
        assert_eq!(f.counts(), (1, 1, 1, 0));
    }
}

#[test]
fn one_send_two_connections_race_yields_only_one_actual_fresh_claim_permit() {
    let f = Fixture::new();
    let first = f.open();
    let second = f.open();
    let gate = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for mut d in [first, second] {
        let barrier = gate.clone();
        let intent = f.intent.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            d.begin(&intent, clear).unwrap()
        }));
    }
    let results = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Begin::Permit(_)))
            .count(),
        1
    );
    let sender = FakeSender::new(Mode::ReplyRunning);
    let mut d = f.open();
    for result in results {
        if let Begin::Permit(p) = result {
            p.consume(&mut d, &sender, clear).unwrap();
        }
    }
    assert_eq!(sender.counts(), (1, 1));
    assert_eq!(d.journal.count(), 1);
    assert_eq!(f.counts(), (1, 1, 1, 0));
}

#[test]
fn one_send_injected_authority_mismatch_refuses_before_any_store_admission() {
    let f = Fixture::new();
    let mut d = f.open();
    let mut wrong = f.intent.clone();
    wrong.context.actor_credential_generation += 1;
    assert!(matches!(
        d.begin(&wrong, clear),
        Err(Error::FixtureAuthorityMismatch)
    ));
    assert_eq!(f.counts(), (0, 0, 0, 0));
    // Independent Pod manager epoch is not equated with the fixture actor signer.
    assert_eq!(f.intent.context.actor_credential_generation, 11);
    assert_eq!(
        f.intent
            .prepared
            .status
            .bound
            .as_ref()
            .unwrap()
            .credential_epoch,
        3
    );
}
