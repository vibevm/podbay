use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_store::{
    Admission, CommandRequest, EffectClaim, EffectState, PodBayStore, StoreError, VerifiedPrincipal,
};

struct Fixture {
    directory: PathBuf,
    database: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("podbay-store-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let database = directory.join("podbay.sqlite");
        Self {
            directory,
            database,
        }
    }
    fn open(&self) -> PodBayStore {
        PodBayStore::open(&self.database).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn request(scope: &str, key: &str, body: &[u8]) -> CommandRequest {
    CommandRequest {
        principal: VerifiedPrincipal::from_authenticated_boundary("principal.fixture").unwrap(),
        namespace: "project.fixture".into(),
        command_key: key.into(),
        scope_id: scope.into(),
        target_id: "target.fixture".into(),
        expected_owner_epoch: 1,
        expected_target_epoch: 1,
        canonical_request: body.to_vec(),
        event_kind: "command.admitted".into(),
        event_payload: b"event.fixture".to_vec(),
        effect_kind: "pod.offer".into(),
        effect_payload: b"effect.fixture".to_vec(),
    }
}
fn ready(store: &mut PodBayStore) {
    store.advance_owner_epoch(0, 1).unwrap();
    store
        .advance_target_epoch("scope.fixture", "target.fixture", 0, 1)
        .unwrap();
}

#[test]
fn duplicate_key_returns_original_opaque_id_and_changed_digest_conflicts() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    ready(&mut store);
    let input = request("scope.fixture", "request.one", b"canonical-one");
    let first = match store.admit(&input).unwrap() {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected commit: {other:?}"),
    };
    assert!(first.command_id.starts_with("command.pb04."));
    assert_eq!(first.request_digest.len(), 64);
    assert_eq!(
        store.admit(&input).unwrap(),
        Admission::Duplicate(first.clone())
    );
    assert!(matches!(
        store.admit(&request("scope.fixture", "request.one", b"changed")),
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(
        store.scope_snapshot("scope.fixture").unwrap().receipts,
        vec![first]
    );
}

#[test]
fn claim_survives_reopen_as_uncertain_and_never_replays_as_new() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    ready(&mut store);
    let input = request("scope.fixture", "request.reopen", b"canonical-reopen");
    let receipt = match store.admit(&input).unwrap() {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected commit: {other:?}"),
    };
    assert_eq!(
        store.effect_state(receipt.outbox_id).unwrap(),
        EffectState::Prepared
    );
    assert_eq!(
        store
            .claim_effect(
                receipt.outbox_id,
                "scope.fixture",
                "target.fixture",
                1,
                1,
                "claim.fixture"
            )
            .unwrap(),
        EffectClaim::NewClaim
    );
    drop(store);
    let mut reopened = fixture.open();
    assert_eq!(
        reopened.effect_state(receipt.outbox_id).unwrap(),
        EffectState::ClaimedUncertain
    );
    assert_eq!(
        reopened.admit(&input).unwrap(),
        Admission::Duplicate(receipt.clone())
    );
    assert_eq!(
        reopened
            .claim_effect(
                receipt.outbox_id,
                "scope.fixture",
                "target.fixture",
                1,
                1,
                "claim.fixture"
            )
            .unwrap(),
        EffectClaim::ExistingUncertain
    );
    assert!(matches!(
        reopened.claim_effect(
            receipt.outbox_id,
            "scope.fixture",
            "target.fixture",
            1,
            1,
            "claim.other"
        ),
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(
        reopened.effect_state(receipt.outbox_id).unwrap(),
        EffectState::ClaimedUncertain
    );
}

#[test]
fn stale_epochs_and_wrong_scope_refuse_without_extra_rows() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    ready(&mut store);
    let receipt = match store
        .admit(&request("scope.fixture", "request.scope", b"scope"))
        .unwrap()
    {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected commit: {other:?}"),
    };
    assert!(matches!(
        store.admit(&request("scope.other", "request.scope", b"scope")),
        Err(StoreError::WrongScope)
    ));
    assert!(matches!(
        store.claim_effect(
            receipt.outbox_id,
            "scope.other",
            "target.fixture",
            1,
            1,
            "claim.scope"
        ),
        Err(StoreError::WrongScope)
    ));
    store.advance_owner_epoch(1, 2).unwrap();
    assert!(matches!(
        store.admit(&request("scope.fixture", "request.stale", b"new")),
        Err(StoreError::StaleEpoch)
    ));
    assert!(matches!(
        store.advance_target_epoch("scope.fixture", "target.fixture", 0, 1),
        Err(StoreError::StaleEpoch)
    ));
    assert_eq!(
        store
            .scope_snapshot("scope.fixture")
            .unwrap()
            .receipts
            .len(),
        1
    );
}

#[test]
fn snapshot_cursor_and_following_event_have_no_gap_or_cross_scope_leak() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    ready(&mut store);
    store
        .admit(&request("scope.fixture", "request.before", b"before"))
        .unwrap();
    let snapshot = store.scope_snapshot("scope.fixture").unwrap();
    assert_eq!(snapshot.receipts.len(), 1);
    store
        .admit(&request("scope.fixture", "request.after", b"after"))
        .unwrap();
    let following = store
        .events_after("scope.fixture", snapshot.cursor, 32)
        .unwrap();
    assert_eq!(following.len(), 1);
    assert_eq!(following[0].sequence, snapshot.cursor + 1);
    assert_eq!(following[0].kind, "command.admitted");
    assert!(store.events_after("scope.other", 0, 32).unwrap().is_empty());
}

#[test]
fn outbox_insert_refusal_rolls_back_command_and_admission_event() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    ready(&mut store);
    let injector = rusqlite::Connection::open(&fixture.database).unwrap();
    injector
        .execute_batch(
            "CREATE TRIGGER refuse_outbox BEFORE INSERT ON outbox
        BEGIN SELECT RAISE(ABORT, 'synthetic outbox refusal'); END;",
        )
        .unwrap();
    assert!(matches!(
        store.admit(&request("scope.fixture", "request.atomic", b"atomic")),
        Err(StoreError::Storage(_))
    ));
    assert!(
        store
            .scope_snapshot("scope.fixture")
            .unwrap()
            .receipts
            .is_empty()
    );
    assert!(
        store
            .events_after("scope.fixture", 0, 32)
            .unwrap()
            .is_empty()
    );
    injector
        .execute_batch("DROP TRIGGER refuse_outbox")
        .unwrap();
    assert!(matches!(
        store.admit(&request("scope.fixture", "request.atomic", b"atomic")),
        Ok(Admission::Committed(_))
    ));
}

#[test]
fn first_slice_allows_only_one_admission_event_per_command() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    ready(&mut store);
    let receipt = match store
        .admit(&request("scope.fixture", "request.one-event", b"one"))
        .unwrap()
    {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected commit: {other:?}"),
    };
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    let rowid: i64 = connection
        .query_row(
            "SELECT command_rowid FROM commands WHERE command_id=?1",
            [&receipt.command_id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        connection
            .execute(
                "INSERT INTO events(command_rowid,scope_id,owner_epoch,
        target_epoch,kind,payload) VALUES(?1,'scope.fixture',1,1,'provider.observed',X'01')",
                [rowid]
            )
            .is_err()
    );
    assert_eq!(store.events_after("scope.fixture", 0, 32).unwrap().len(), 1);
}
