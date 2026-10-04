use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_store::{
    Admission, CommandLookupSelector, CommandRequest, EffectObservation, EffectState,
    HostAcceptanceProof, ObservedStage, PodBayStore, StoreError, VerifiedPrincipal,
};

struct Fixture {
    directory: PathBuf,
    database: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "podbay-command-lookup-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        Self {
            database: directory.join("podbay.sqlite"),
            directory,
        }
    }

    fn open(&self) -> PodBayStore {
        PodBayStore::open(&self.database).unwrap()
    }

    fn counts(&self) -> (i64, i64) {
        let connection = rusqlite::Connection::open(&self.database).unwrap();
        let events = connection
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();
        let effects = connection
            .query_row("SELECT COUNT(*) FROM outbox", [], |row| row.get(0))
            .unwrap();
        (events, effects)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn principal(value: &str) -> VerifiedPrincipal {
    VerifiedPrincipal::from_authenticated_boundary(value).unwrap()
}

fn request(namespace: &str, key: &str, target: &str) -> CommandRequest {
    CommandRequest {
        principal: principal("actor.fixture"),
        namespace: namespace.into(),
        command_key: key.into(),
        scope_id: "scope.fixture".into(),
        target_id: target.into(),
        expected_owner_epoch: 1,
        expected_target_epoch: 1,
        canonical_request: b"canonical fixture".to_vec(),
        event_kind: "command.admitted".into(),
        event_payload: b"event fixture".to_vec(),
        effect_kind: "pod.offer".into(),
        effect_payload: b"effect fixture".to_vec(),
    }
}

fn ready(store: &mut PodBayStore, targets: &[&str]) {
    store.advance_owner_epoch(0, 1).unwrap();
    for target in targets {
        store
            .advance_target_epoch("scope.fixture", target, 0, 1)
            .unwrap();
    }
}

fn admitted(store: &mut PodBayStore, request: &CommandRequest) -> podbay_store::Receipt {
    match store.admit(request).unwrap() {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected committed receipt: {other:?}"),
    }
}

fn by_id(id: &str) -> CommandLookupSelector {
    CommandLookupSelector::Id {
        command_id: id.into(),
    }
}

fn by_key(key: &str) -> CommandLookupSelector {
    CommandLookupSelector::Key { key: key.into() }
}

#[test]
fn id_and_key_agree_without_mutating_events_or_outbox() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    ready(&mut store, &["target.fixture"]);
    let input = request("namespace.one", "command.key.one", "target.fixture");
    let receipt = admitted(&mut store, &input);
    let counts = fixture.counts();
    let actor = principal("actor.fixture");

    let id = store
        .lookup_command("scope.fixture", &actor, &by_id(&receipt.command_id))
        .unwrap();
    let key = store
        .lookup_command("scope.fixture", &actor, &by_key("command.key.one"))
        .unwrap();
    assert_eq!(id, key);
    assert_eq!(id.receipt, receipt);
    assert_eq!(id.effect_state, EffectState::Prepared);
    assert_eq!(id.observed_stage, None);
    assert_eq!(fixture.counts(), counts);

    for selector in [by_id(&receipt.command_id), by_key("command.key.one")] {
        assert!(matches!(
            store.lookup_command("scope.fixture", &principal("actor.foreign"), &selector),
            Err(StoreError::NotFound)
        ));
        assert!(matches!(
            store.lookup_command("scope.foreign", &actor, &selector),
            Err(StoreError::NotFound)
        ));
    }
    assert!(matches!(
        store.lookup_command("scope.fixture", &actor, &by_id("x")),
        Err(StoreError::InvalidInput(_))
    ));
    assert_eq!(fixture.counts(), counts);
}

#[test]
fn key_shared_across_namespaces_refuses_ambiguous_read() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    ready(&mut store, &["target.one", "target.two"]);
    let first = admitted(
        &mut store,
        &request("namespace.one", "shared.key", "target.one"),
    );
    let second = admitted(
        &mut store,
        &request("namespace.two", "shared.key", "target.two"),
    );
    let actor = principal("actor.fixture");
    let counts = fixture.counts();
    assert!(matches!(
        store.lookup_command("scope.fixture", &actor, &by_key("shared.key")),
        Err(StoreError::Conflict(
            "command key is ambiguous across namespaces"
        ))
    ));
    assert_eq!(
        store
            .lookup_command("scope.fixture", &actor, &by_id(&first.command_id))
            .unwrap()
            .receipt,
        first
    );
    assert_eq!(
        store
            .lookup_command("scope.fixture", &actor, &by_id(&second.command_id))
            .unwrap()
            .receipt,
        second
    );
    assert_eq!(fixture.counts(), counts);
}

#[test]
fn observed_state_and_receipt_survive_reopen_without_replay() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    ready(&mut store, &["target.fixture"]);
    let input = request("namespace.one", "observed.key", "target.fixture");
    let receipt = admitted(&mut store, &input);
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute(
            "UPDATE outbox SET state='claimed_uncertain',claim_key='claim.fixture',
               claim_owner_epoch=1 WHERE outbox_id=?1 AND state='prepared'",
            [receipt.outbox_id],
        )
        .unwrap();
    drop(connection);
    let uncertain = store
        .lookup_command(
            "scope.fixture",
            &principal("actor.fixture"),
            &by_key("observed.key"),
        )
        .unwrap();
    assert_eq!(uncertain.receipt, receipt);
    assert_eq!(uncertain.effect_state, EffectState::ClaimedUncertain);
    let proof = HostAcceptanceProof::from_authenticated_host_boundary(
        "host.fixture",
        1,
        1,
        "host-receipt.fixture",
        b"host evidence",
        Some("2026-10-03T12:00:00Z"),
        "correlation.fixture",
        None,
    )
    .unwrap();
    let reference = match store
        .observe_effect(
            receipt.outbox_id,
            "scope.fixture",
            "target.fixture",
            1,
            1,
            "claim.fixture",
            &proof,
        )
        .unwrap()
    {
        EffectObservation::NewObservation(reference) => reference,
        other => panic!("expected observation: {other:?}"),
    };
    drop(store);

    let mut reopened = fixture.open();
    let counts = fixture.counts();
    let found = reopened
        .lookup_command(
            "scope.fixture",
            &principal("actor.fixture"),
            &by_key("observed.key"),
        )
        .unwrap();
    assert_eq!(found.receipt, receipt);
    assert_eq!(found.effect_state, EffectState::Observed);
    assert_eq!(found.observed_stage, Some(ObservedStage::HostAccepted));
    assert_eq!(
        found.observation_event_sequence,
        Some(reference.cursor.sequence)
    );
    assert_eq!(fixture.counts(), counts);

    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute(
            "UPDATE outbox SET observation_event_sequence=?1 WHERE outbox_id=?2",
            rusqlite::params![receipt.event_sequence, receipt.outbox_id],
        )
        .unwrap();
    assert!(matches!(
        reopened.lookup_command(
            "scope.fixture",
            &principal("actor.fixture"),
            &by_id(&receipt.command_id),
        ),
        Err(StoreError::Conflict("observation event lineage differs"))
    ));
}

#[test]
fn incomplete_receipt_linkage_refuses_instead_of_looking_absent() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    ready(&mut store, &["target.fixture"]);
    let receipt = admitted(
        &mut store,
        &request("namespace.one", "broken.key", "target.fixture"),
    );
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute(
            "UPDATE commands SET outbox_id=NULL WHERE command_id=?1",
            [&receipt.command_id],
        )
        .unwrap();
    assert!(matches!(
        store.lookup_command(
            "scope.fixture",
            &principal("actor.fixture"),
            &by_id(&receipt.command_id),
        ),
        Err(StoreError::Conflict("incomplete committed outbox"))
    ));
    connection
        .execute(
            "UPDATE commands SET outbox_id=?1 WHERE command_id=?2",
            rusqlite::params![receipt.outbox_id, receipt.command_id],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE outbox SET state='claimed_uncertain' WHERE outbox_id=?1",
            [receipt.outbox_id],
        )
        .unwrap();
    assert!(matches!(
        store.lookup_command(
            "scope.fixture",
            &principal("actor.fixture"),
            &by_key("broken.key"),
        ),
        Err(StoreError::Conflict(
            "claimed effect evidence is incomplete"
        ))
    ));
}
