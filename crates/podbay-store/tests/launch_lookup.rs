use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_store::{
    Admission, CommandRequest, EffectState, LaunchDispatchStage, LaunchIntentBinding,
    LaunchLookupRequest, PodBayStore, StoreError, VerifiedPrincipal,
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
        let directory = std::env::temp_dir().join(format!(
            "podbay-launch-lookup-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
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
fn command() -> CommandRequest {
    CommandRequest {
        principal: VerifiedPrincipal::from_authenticated_boundary("principal.fixture").unwrap(),
        namespace: "podbay.launch".into(),
        command_key: "key.launch".into(),
        scope_id: "scope.fixture".into(),
        target_id: "pod.fixture".into(),
        expected_owner_epoch: 1,
        expected_target_epoch: 1,
        canonical_request: br#"{"profileRef":"profile.old","model":"gpt-6-sol"}"#.to_vec(),
        event_kind: "command.admitted".into(),
        event_payload: b"event.fixture".to_vec(),
        effect_kind: "pod.offer".into(),
        effect_payload: b"effective.profile.old".to_vec(),
    }
}
fn lookup(input: &CommandRequest) -> LaunchLookupRequest {
    LaunchLookupRequest {
        principal: input.principal.clone(),
        namespace: input.namespace.clone(),
        command_key: input.command_key.clone(),
        scope_id: input.scope_id.clone(),
        target_id: input.target_id.clone(),
        canonical_intent: input.canonical_request.clone(),
    }
}
fn admitted(fixture: &Fixture) -> (PodBayStore, CommandRequest, podbay_store::Receipt) {
    let mut store = fixture.open();
    store.advance_owner_epoch(0, 1).unwrap();
    store
        .advance_target_epoch("scope.fixture", "pod.fixture", 0, 1)
        .unwrap();
    let input = command();
    let receipt = match store.admit(&input).unwrap() {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected committed launch: {other:?}"),
    };
    (store, input, receipt)
}

#[test]
fn original_receipt_effect_and_status_survive_reopen_without_current_profile() {
    let fixture = Fixture::new();
    let (store, input, receipt) = admitted(&fixture);
    drop(store);
    // No profile registry or resolver is supplied to this inspection method.
    // A later change to profile.old cannot change these stored bytes.
    let mut reopened = fixture.open();
    let value = reopened.lookup_admitted_launch(&lookup(&input)).unwrap();
    assert_eq!(value.receipt, receipt);
    assert_eq!(value.effect.payload, b"effective.profile.old");
    assert_eq!(value.status.stage, LaunchDispatchStage::Prepared);
    assert_eq!(value.binding, LaunchIntentBinding::HistoricalUnbound);
    assert_eq!(
        reopened.effect_state(receipt.outbox_id).unwrap(),
        EffectState::Prepared
    );
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    let claim: Option<String> = connection
        .query_row(
            "SELECT claim_key FROM outbox WHERE outbox_id=?1",
            [receipt.outbox_id],
            |row| row.get(0),
        )
        .unwrap();
    let dispatch_rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM launch_dispatch_outcomes WHERE outbox_id=?1",
            [receipt.outbox_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(claim, None);
    assert_eq!(dispatch_rows, 0);
}

#[test]
fn changed_canonical_intent_conflicts_but_wrong_identity_does_not_leak() {
    let fixture = Fixture::new();
    let (mut store, input, _) = admitted(&fixture);
    let mut changed = lookup(&input);
    changed.canonical_intent = b"different caller intent".to_vec();
    assert!(matches!(
        store.lookup_admitted_launch(&changed),
        Err(StoreError::Conflict(_))
    ));
    let mut wrong = lookup(&input);
    wrong.principal = VerifiedPrincipal::from_authenticated_boundary("principal.other").unwrap();
    assert!(matches!(
        store.lookup_admitted_launch(&wrong),
        Err(StoreError::NotFound)
    ));
    let mut wrong = lookup(&input);
    wrong.scope_id = "scope.other".into();
    assert!(matches!(
        store.lookup_admitted_launch(&wrong),
        Err(StoreError::NotFound)
    ));
    let mut wrong = lookup(&input);
    wrong.target_id = "pod.other".into();
    assert!(matches!(
        store.lookup_admitted_launch(&wrong),
        Err(StoreError::NotFound)
    ));
    let mut wrong = lookup(&input);
    wrong.namespace = "other.namespace".into();
    assert!(matches!(
        store.lookup_admitted_launch(&wrong),
        Err(StoreError::NotFound)
    ));
}

#[test]
fn tampered_effect_fails_before_returning_inspection() {
    let fixture = Fixture::new();
    let (mut store, input, receipt) = admitted(&fixture);
    rusqlite::Connection::open(&fixture.database)
        .unwrap()
        .execute(
            "UPDATE outbox SET payload=X'74616d7065726564' WHERE outbox_id=?1",
            [receipt.outbox_id],
        )
        .unwrap();
    assert!(matches!(
        store.lookup_admitted_launch(&lookup(&input)),
        Err(StoreError::Conflict("outbox effect digest changed"))
    ));
    assert_eq!(
        store.effect_state(receipt.outbox_id).unwrap(),
        EffectState::Prepared
    );
}

#[test]
fn historical_v7_status_is_observed_but_never_a_fresh_dispatch_binding() {
    let fixture = Fixture::new();
    let (store, input, receipt) = admitted(&fixture);
    drop(store);
    // Represent a receipt settled before the v8 bound-only claim gate. A new
    // unbound offer is now refused before any claim or host call.
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute(
            "UPDATE outbox SET state='claimed_uncertain',claim_key='claim.fixture',
         claim_owner_epoch=1 WHERE outbox_id=?1",
            [receipt.outbox_id],
        )
        .unwrap();
    connection.execute(
        "INSERT INTO launch_dispatch_outcomes(outbox_id,claim_key,stage,receipt_ref,recorded_at)
         VALUES(?1,'claim.fixture','host_accepted','port.fixture','2026-10-03T12:00:00Z')",
        [receipt.outbox_id],
    ).unwrap();
    drop(connection);
    let mut store = fixture.open();
    let inspected = store.lookup_admitted_launch(&lookup(&input)).unwrap();
    assert_eq!(inspected.status.stage, LaunchDispatchStage::HostAccepted);
    assert_eq!(
        inspected.status.receipt_ref.as_deref(),
        Some("port.fixture")
    );
    assert_eq!(inspected.binding, LaunchIntentBinding::HistoricalUnbound);
}
