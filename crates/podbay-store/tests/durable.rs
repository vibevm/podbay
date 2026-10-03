use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_store::{
    Admission, CommandRequest, EffectClaim, EffectObservation, EffectState, HostAcceptanceProof,
    ObservedStage, PodBayStore, SourceOrder, StoreError, VerifiedPrincipal,
};
use sha2::{Digest, Sha256};

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

fn fixture_request_digest(request: &CommandRequest) -> String {
    let mut digest = Sha256::new();
    for field in [
        b"pb04-request-bytes/1".as_slice(),
        request.principal.as_str().as_bytes(),
        request.namespace.as_bytes(),
        request.command_key.as_bytes(),
        request.scope_id.as_bytes(),
        request.target_id.as_bytes(),
        request.canonical_request.as_slice(),
        request.event_kind.as_bytes(),
        request.event_payload.as_slice(),
        request.effect_kind.as_bytes(),
        request.effect_payload.as_slice(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    digest.update(request.expected_owner_epoch.to_be_bytes());
    digest.update(request.expected_target_epoch.to_be_bytes());
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn host_proof(sequence: u64, receipt_id: &str, evidence: &[u8]) -> HostAcceptanceProof {
    HostAcceptanceProof::from_authenticated_host_boundary(
        "host.fixture",
        1,
        sequence,
        receipt_id,
        evidence,
        Some("2026-10-03T12:00:00Z"),
        "correlation.fixture",
        Some("causation.fixture"),
    )
    .unwrap()
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
        .events_after("scope.fixture", &snapshot.cursor, 32)
        .unwrap();
    assert_eq!(following.len(), 1);
    assert_eq!(following[0].sequence, snapshot.cursor.sequence + 1);
    assert_eq!(following[0].kind, "command.admitted");
    assert!(store
        .events_after(
            "scope.other",
            &store.initial_cursor("scope.other").unwrap(),
            32
        )
        .unwrap()
        .is_empty());
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
    assert!(store
        .scope_snapshot("scope.fixture")
        .unwrap()
        .receipts
        .is_empty());
    assert!(store
        .events_after(
            "scope.fixture",
            &store.initial_cursor("scope.fixture").unwrap(),
            32,
        )
        .unwrap()
        .is_empty());
    injector
        .execute_batch("DROP TRIGGER refuse_outbox")
        .unwrap();
    assert!(matches!(
        store.admit(&request("scope.fixture", "request.atomic", b"atomic")),
        Ok(Admission::Committed(_))
    ));
}

#[test]
fn host_acceptance_adds_event_without_changing_admission_receipt() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    ready(&mut store);
    let input = request("scope.fixture", "request.two-events", b"two");
    let receipt = match store.admit(&input).unwrap() {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected commit: {other:?}"),
    };
    let before = store.scope_snapshot("scope.fixture").unwrap();
    assert_eq!(before.cursor.sequence, receipt.event_sequence);
    store
        .claim_effect(
            receipt.outbox_id,
            "scope.fixture",
            "target.fixture",
            1,
            1,
            "claim.two-events",
        )
        .unwrap();
    let observation = store
        .observe_effect(
            receipt.outbox_id,
            "scope.fixture",
            "target.fixture",
            1,
            1,
            "claim.two-events",
            &host_proof(1, "host-receipt.two", b"host-ack"),
        )
        .unwrap();
    let event_ref = match observation {
        EffectObservation::NewObservation(reference) => reference,
        other => panic!("expected new observation: {other:?}"),
    };
    assert!(event_ref.cursor.sequence > receipt.event_sequence);
    assert_eq!(
        store.admit(&input).unwrap(),
        Admission::Duplicate(receipt.clone())
    );
    assert_eq!(
        store
            .events_after(
                "scope.fixture",
                &store.initial_cursor("scope.fixture").unwrap(),
                32,
            )
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        store.scope_snapshot("scope.fixture").unwrap().receipts,
        vec![receipt]
    );
}

#[test]
fn observation_event_insert_failure_keeps_claim_uncertain() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    ready(&mut store);
    let receipt = match store
        .admit(&request("scope.fixture", "request.obs-atomic", b"atomic"))
        .unwrap()
    {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected commit: {other:?}"),
    };
    store
        .claim_effect(
            receipt.outbox_id,
            "scope.fixture",
            "target.fixture",
            1,
            1,
            "claim.obs-atomic",
        )
        .unwrap();
    let before = store.scope_snapshot("scope.fixture").unwrap().cursor;
    let injector = rusqlite::Connection::open(&fixture.database).unwrap();
    injector
        .execute_batch(
            "CREATE TRIGGER refuse_host_event BEFORE INSERT ON events
             WHEN NEW.kind='effect.host_accepted'
             BEGIN SELECT RAISE(ABORT, 'synthetic host event refusal'); END;",
        )
        .unwrap();
    let proof = host_proof(1, "host-receipt.atomic", b"host-ack");
    assert!(matches!(
        store.observe_effect(
            receipt.outbox_id,
            "scope.fixture",
            "target.fixture",
            1,
            1,
            "claim.obs-atomic",
            &proof,
        ),
        Err(StoreError::Storage(_))
    ));
    assert_eq!(
        store.effect_state(receipt.outbox_id).unwrap(),
        EffectState::ClaimedUncertain
    );
    assert_eq!(
        store.scope_snapshot("scope.fixture").unwrap().cursor,
        before
    );
    assert!(store
        .events_after("scope.fixture", &before, 10)
        .unwrap()
        .is_empty());
    injector
        .execute_batch("DROP TRIGGER refuse_host_event")
        .unwrap();
    assert!(matches!(
        store.observe_effect(
            receipt.outbox_id,
            "scope.fixture",
            "target.fixture",
            1,
            1,
            "claim.obs-atomic",
            &proof,
        ),
        Ok(EffectObservation::NewObservation(_))
    ));
}

#[test]
fn owner_takeover_claims_prepared_work_and_fences_old_owner() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    ready(&mut store);
    let receipt = match store
        .admit(&request("scope.fixture", "request.takeover", b"takeover"))
        .unwrap()
    {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected commit: {other:?}"),
    };
    store.advance_owner_epoch(1, 2).unwrap();
    assert!(matches!(
        store.claim_effect(
            receipt.outbox_id,
            "scope.fixture",
            "target.fixture",
            1,
            1,
            "claim.takeover"
        ),
        Err(StoreError::StaleEpoch)
    ));
    assert_eq!(
        store
            .claim_effect(
                receipt.outbox_id,
                "scope.fixture",
                "target.fixture",
                2,
                1,
                "claim.takeover"
            )
            .unwrap(),
        EffectClaim::NewClaim
    );
    let effect = store
        .load_effect(receipt.outbox_id, "scope.fixture", "target.fixture")
        .unwrap();
    assert_eq!(effect.admission_owner_epoch, 1);
    assert_eq!(effect.claim_owner_epoch, Some(2));
    assert_eq!(effect.state, EffectState::ClaimedUncertain);
    drop(store);

    let mut reopened = fixture.open();
    assert_eq!(
        reopened
            .claim_effect(
                receipt.outbox_id,
                "scope.fixture",
                "target.fixture",
                2,
                1,
                "claim.takeover"
            )
            .unwrap(),
        EffectClaim::ExistingUncertain
    );
    reopened
        .advance_target_epoch("scope.fixture", "target.fixture", 1, 2)
        .unwrap();
    assert_eq!(
        reopened
            .claim_effect(
                receipt.outbox_id,
                "scope.fixture",
                "target.fixture",
                2,
                2,
                "claim.takeover"
            )
            .unwrap(),
        EffectClaim::ExistingUncertain
    );
    assert!(matches!(
        reopened.claim_effect(
            receipt.outbox_id,
            "scope.fixture",
            "target.fixture",
            2,
            2,
            "claim.other"
        ),
        Err(StoreError::Conflict(_))
    ));
}

#[test]
fn target_takeover_blocks_prepared_old_incarnation_payload() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    ready(&mut store);
    let receipt = match store
        .admit(&request(
            "scope.fixture",
            "request.old-target",
            b"old-target",
        ))
        .unwrap()
    {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected commit: {other:?}"),
    };
    store
        .advance_target_epoch("scope.fixture", "target.fixture", 1, 2)
        .unwrap();
    assert!(matches!(
        store.claim_effect(
            receipt.outbox_id,
            "scope.fixture",
            "target.fixture",
            1,
            2,
            "claim.new-target"
        ),
        Err(StoreError::TargetReconciliationRequired)
    ));
    assert_eq!(
        store.effect_state(receipt.outbox_id).unwrap(),
        EffectState::Prepared
    );
    assert_eq!(
        store.pending_effects("scope.fixture", 0, 10).unwrap().len(),
        1
    );
}

#[test]
fn restart_recovers_effect_and_observation_requires_exact_evidence() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    ready(&mut store);
    let receipt = match store
        .admit(&request("scope.fixture", "request.observe", b"observe"))
        .unwrap()
    {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected commit: {other:?}"),
    };
    let proof = host_proof(1, "host-receipt.one", b"host-ack");
    drop(store);

    let mut reopened = fixture.open();
    let pending = reopened.pending_effects("scope.fixture", 0, 10).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].outbox_id, receipt.outbox_id);
    assert_eq!(pending[0].kind, "pod.offer");
    assert_eq!(pending[0].payload, b"effect.fixture");
    assert!(matches!(
        reopened.load_effect(receipt.outbox_id, "scope.other", "target.fixture"),
        Err(StoreError::WrongScope)
    ));
    assert!(matches!(
        reopened.observe_effect(
            receipt.outbox_id,
            "scope.fixture",
            "target.fixture",
            1,
            1,
            "claim.observe",
            &proof
        ),
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(
        reopened
            .claim_effect(
                receipt.outbox_id,
                "scope.fixture",
                "target.fixture",
                1,
                1,
                "claim.observe"
            )
            .unwrap(),
        EffectClaim::NewClaim
    );
    drop(reopened);

    let mut recovered = fixture.open();
    let uncertain = recovered.pending_effects("scope.fixture", 0, 10).unwrap();
    assert_eq!(uncertain[0].claim_key.as_deref(), Some("claim.observe"));
    assert_eq!(uncertain[0].state, EffectState::ClaimedUncertain);
    assert!(matches!(
        recovered.observe_effect(
            receipt.outbox_id,
            "scope.fixture",
            "target.fixture",
            1,
            1,
            "claim.other",
            &proof
        ),
        Err(StoreError::Conflict(_))
    ));
    let before = recovered.scope_snapshot("scope.fixture").unwrap();
    let first = recovered
        .observe_effect(
            receipt.outbox_id,
            "scope.fixture",
            "target.fixture",
            1,
            1,
            "claim.observe",
            &proof,
        )
        .unwrap();
    let event_ref = match first {
        EffectObservation::NewObservation(reference) => reference,
        other => panic!("expected new observation: {other:?}"),
    };
    assert_eq!(
        recovered
            .observe_effect(
                receipt.outbox_id,
                "scope.fixture",
                "target.fixture",
                1,
                1,
                "claim.observe",
                &proof,
            )
            .unwrap(),
        EffectObservation::AlreadyObserved(event_ref.clone())
    );
    assert!(matches!(
        recovered.observe_effect(
            receipt.outbox_id,
            "scope.fixture",
            "target.fixture",
            1,
            1,
            "claim.observe",
            &host_proof(1, "host-receipt.one", b"changed-ack")
        ),
        Err(StoreError::SourceIdentityQuarantined)
    ));
    assert!(recovered
        .pending_effects("scope.fixture", 0, 10)
        .unwrap()
        .is_empty());
    let observed = recovered
        .load_effect(receipt.outbox_id, "scope.fixture", "target.fixture")
        .unwrap();
    assert_eq!(observed.state, EffectState::Observed);
    assert_eq!(observed.observed_stage, Some(ObservedStage::HostAccepted));
    assert_eq!(
        observed.observation_event_sequence,
        Some(event_ref.cursor.sequence)
    );
    assert_eq!(
        observed.observation_key.as_deref(),
        Some("host-receipt.one")
    );
    assert_eq!(
        observed.observation_payload.as_deref(),
        Some(b"host-ack".as_slice())
    );
    let replay = recovered
        .events_after("scope.fixture", &before.cursor, 10)
        .unwrap();
    assert_eq!(replay.len(), 1);
    assert_eq!(replay[0].event_id, event_ref.event_id);
    assert_eq!(replay[0].cursor, event_ref.cursor);
    assert_eq!(replay[0].kind, "effect.host_accepted");
    assert_eq!(replay[0].source_kind, "host");
    assert_eq!(replay[0].provenance, "authenticated.host.acceptance");
    assert_eq!(replay[0].source_order, SourceOrder::Contiguous);
    assert!(!String::from_utf8_lossy(&replay[0].payload).contains("host-ack"));
    let snapshot = recovered.scope_snapshot("scope.fixture").unwrap();
    assert_eq!(snapshot.cursor, event_ref.cursor);
    assert_eq!(
        snapshot.effects[0].observed_stage,
        Some(ObservedStage::HostAccepted)
    );
    assert_eq!(
        recovered
            .quarantined_events("scope.fixture", 0, 10)
            .unwrap()
            .len(),
        1
    );
    drop(recovered);
    let mut reopened_again = fixture.open();
    assert_eq!(
        reopened_again
            .observe_effect(
                receipt.outbox_id,
                "scope.fixture",
                "target.fixture",
                1,
                1,
                "claim.observe",
                &proof,
            )
            .unwrap(),
        EffectObservation::AlreadyObserved(event_ref)
    );
}

#[test]
fn source_conflict_quarantines_without_settling_and_gap_is_replayed() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    ready(&mut store);
    let mut receipts = Vec::new();
    for index in 0..3 {
        let receipt = match store
            .admit(&request(
                "scope.fixture",
                &format!("request.source.{index}"),
                b"source",
            ))
            .unwrap()
        {
            Admission::Committed(receipt) => receipt,
            other => panic!("expected commit: {other:?}"),
        };
        store
            .claim_effect(
                receipt.outbox_id,
                "scope.fixture",
                "target.fixture",
                1,
                1,
                &format!("claim.source.{index}"),
            )
            .unwrap();
        receipts.push(receipt);
    }
    let first = store
        .observe_effect(
            receipts[0].outbox_id,
            "scope.fixture",
            "target.fixture",
            1,
            1,
            "claim.source.0",
            &host_proof(1, "host-receipt.source0", b"ack-zero"),
        )
        .unwrap();
    let first_ref = match first {
        EffectObservation::NewObservation(reference) => reference,
        other => panic!("expected new observation: {other:?}"),
    };
    let before_conflict = store.scope_snapshot("scope.fixture").unwrap().cursor;
    assert!(matches!(
        store.observe_effect(
            receipts[1].outbox_id,
            "scope.fixture",
            "target.fixture",
            1,
            1,
            "claim.source.1",
            &host_proof(1, "host-receipt.source1", b"ack-one"),
        ),
        Err(StoreError::SourceIdentityQuarantined)
    ));
    assert_eq!(
        store.effect_state(receipts[1].outbox_id).unwrap(),
        EffectState::ClaimedUncertain
    );
    assert_eq!(
        store.scope_snapshot("scope.fixture").unwrap().cursor,
        before_conflict
    );
    let quarantined = store.quarantined_events("scope.fixture", 0, 10).unwrap();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].existing_event_id, first_ref.event_id);
    assert_eq!(quarantined[0].source_sequence, 1);
    assert_eq!(quarantined[0].incoming_evidence, b"ack-one");

    let gap = store
        .observe_effect(
            receipts[1].outbox_id,
            "scope.fixture",
            "target.fixture",
            1,
            1,
            "claim.source.1",
            &host_proof(3, "host-receipt.source1", b"ack-one"),
        )
        .unwrap();
    let gap_ref = match gap {
        EffectObservation::NewObservation(reference) => reference,
        other => panic!("expected new gap observation: {other:?}"),
    };
    let replay = store
        .events_after("scope.fixture", &before_conflict, 10)
        .unwrap();
    assert_eq!(replay.len(), 1);
    assert_eq!(replay[0].event_id, gap_ref.event_id);
    assert_eq!(replay[0].source_sequence, 3);
    assert_eq!(
        replay[0].source_order,
        SourceOrder::Gap { expected_next: 2 }
    );
    assert_eq!(
        store
            .scope_snapshot("scope.fixture")
            .unwrap()
            .source_anomalies
            .len(),
        1
    );

    store
        .observe_effect(
            receipts[2].outbox_id,
            "scope.fixture",
            "target.fixture",
            1,
            1,
            "claim.source.2",
            &host_proof(2, "host-receipt.source2", b"ack-two"),
        )
        .unwrap();
    let snapshot = store.scope_snapshot("scope.fixture").unwrap();
    assert_eq!(snapshot.source_anomalies.len(), 2);
    assert_eq!(
        snapshot.source_anomalies[1].order,
        SourceOrder::OutOfOrder { highest_seen: 3 }
    );
    drop(store);
    let mut reopened = fixture.open();
    assert_eq!(
        reopened
            .scope_snapshot("scope.fixture")
            .unwrap()
            .source_anomalies,
        snapshot.source_anomalies
    );
}

#[test]
fn host_proof_refuses_unsequenced_or_malformed_evidence() {
    assert!(matches!(
        HostAcceptanceProof::from_authenticated_host_boundary(
            "host.fixture",
            0,
            1,
            "host-receipt.invalid",
            b"ack",
            None,
            "correlation.fixture",
            None,
        ),
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        HostAcceptanceProof::from_authenticated_host_boundary(
            "host.fixture",
            1,
            0,
            "host-receipt.invalid",
            b"ack",
            None,
            "correlation.fixture",
            None,
        ),
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        HostAcceptanceProof::from_authenticated_host_boundary(
            "host.fixture",
            1,
            i64::MAX as u64,
            "host-receipt.invalid",
            b"ack",
            None,
            "correlation.fixture",
            None,
        ),
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        HostAcceptanceProof::from_authenticated_host_boundary(
            "host.fixture",
            1,
            1,
            "host-receipt.invalid",
            b"ack",
            Some("not-a-valid-T-timeZ"),
            "correlation.fixture",
            None,
        ),
        Err(StoreError::InvalidInput(_))
    ));
    for invalid_time in [
        "2026-13-03T12:00:00Z",
        "2026-10-32T12:00:00Z",
        "2026-10-03T25:00:00Z",
        "2026-10-03T12:00:00.Z",
        "2026-10-03T12:00:00.12xZ",
        "2026-10-03T12:00:00.1234567890Z",
        "2025-02-29T12:00:00Z",
        "1900-02-29T12:00:00Z",
    ] {
        assert!(matches!(
            HostAcceptanceProof::from_authenticated_host_boundary(
                "host.fixture",
                1,
                1,
                "host-receipt.invalid",
                b"ack",
                Some(invalid_time),
                "correlation.fixture",
                None,
            ),
            Err(StoreError::InvalidInput(_))
        ));
    }
    for valid_time in ["2024-02-29T12:00:00Z", "2000-02-29T23:59:60.123456789Z"] {
        assert!(HostAcceptanceProof::from_authenticated_host_boundary(
            "host.fixture",
            1,
            1,
            "host-receipt.valid",
            b"ack",
            Some(valid_time),
            "correlation.fixture",
            None,
        )
        .is_ok());
    }
    assert!(matches!(
        HostAcceptanceProof::from_authenticated_host_boundary(
            "host.fixture",
            1,
            1,
            "host-receipt.invalid",
            b"",
            None,
            "correlation.fixture",
            None,
        ),
        Err(StoreError::InvalidInput(_))
    ));
}

#[test]
fn cursor_refuses_foreign_scope_lineage_and_future_position() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    ready(&mut store);
    store
        .admit(&request("scope.fixture", "request.cursor", b"cursor"))
        .unwrap();
    let snapshot = store.scope_snapshot("scope.fixture").unwrap();
    assert!(matches!(
        store.events_after("scope.other", &snapshot.cursor, 10),
        Err(StoreError::WrongCursor)
    ));
    let other_fixture = Fixture::new();
    let other = other_fixture.open();
    assert!(matches!(
        other.events_after("scope.fixture", &snapshot.cursor, 10),
        Err(StoreError::WrongCursor)
    ));
    let mut future = snapshot.cursor.clone();
    future.sequence += 1;
    assert!(matches!(
        store.events_after("scope.fixture", &future, 10),
        Err(StoreError::WrongCursor)
    ));
    let mut negative = snapshot.cursor.clone();
    negative.sequence = -1;
    assert!(matches!(
        store.events_after("scope.fixture", &negative, 10),
        Err(StoreError::InvalidInput(_))
    ));
    drop(store);
    let reopened = fixture.open();
    assert!(reopened
        .events_after("scope.fixture", &snapshot.cursor, 10)
        .unwrap()
        .is_empty());
}

#[test]
fn unknown_effect_refuses_admission_and_cannot_be_claimed_after_downgrade() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    ready(&mut store);
    let mut unsupported = request("scope.fixture", "request.unknown", b"unknown");
    unsupported.effect_kind = "future.effect".into();
    assert!(matches!(
        store.admit(&unsupported),
        Err(StoreError::UnsupportedEffectKind)
    ));
    assert!(store
        .scope_snapshot("scope.fixture")
        .unwrap()
        .receipts
        .is_empty());

    let receipt = match store
        .admit(&request("scope.fixture", "request.known", b"known"))
        .unwrap()
    {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected commit: {other:?}"),
    };
    let injector = rusqlite::Connection::open(&fixture.database).unwrap();
    injector
        .execute(
            "UPDATE outbox SET kind='future.effect' WHERE outbox_id=?1",
            [receipt.outbox_id],
        )
        .unwrap();
    assert!(matches!(
        store.claim_effect(
            receipt.outbox_id,
            "scope.fixture",
            "target.fixture",
            1,
            1,
            "claim.unknown"
        ),
        Err(StoreError::UnsupportedEffectKind)
    ));
    assert_eq!(
        store.effect_state(receipt.outbox_id).unwrap(),
        EffectState::Prepared
    );
    assert_eq!(
        store.pending_effects("scope.fixture", 0, 10).unwrap()[0].kind,
        "future.effect"
    );
}

#[test]
fn downgrade_returns_prior_receipt_for_exact_unknown_effect_retry() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    ready(&mut store);
    let mut input = request("scope.fixture", "request.future-retry", b"future-retry");
    let receipt = match store.admit(&input).unwrap() {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected commit: {other:?}"),
    };
    input.effect_kind = "future.effect".into();
    let future_digest = fixture_request_digest(&input);
    let injector = rusqlite::Connection::open(&fixture.database).unwrap();
    injector
        .execute(
            "UPDATE commands SET request_digest=?1 WHERE command_id=?2",
            rusqlite::params![future_digest, receipt.command_id],
        )
        .unwrap();
    injector
        .execute(
            "UPDATE outbox SET kind='future.effect' WHERE outbox_id=?1",
            [receipt.outbox_id],
        )
        .unwrap();

    let replay = match store.admit(&input).unwrap() {
        Admission::Duplicate(receipt) => receipt,
        other => panic!("expected duplicate: {other:?}"),
    };
    assert_eq!(replay.command_id, receipt.command_id);
    assert_eq!(replay.event_sequence, receipt.event_sequence);
    assert_eq!(replay.outbox_id, receipt.outbox_id);
    assert_eq!(replay.request_digest, future_digest);
    assert!(matches!(
        store.claim_effect(
            receipt.outbox_id,
            "scope.fixture",
            "target.fixture",
            1,
            1,
            "claim.future"
        ),
        Err(StoreError::UnsupportedEffectKind)
    ));
}

#[test]
fn pending_effects_paginates_past_one_full_page() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    ready(&mut store);
    for index in 0..513 {
        store
            .admit(&request(
                "scope.fixture",
                &format!("request.page.{index}"),
                b"page",
            ))
            .unwrap();
    }
    let first = store.pending_effects("scope.fixture", 0, 512).unwrap();
    assert_eq!(first.len(), 512);
    let second = store
        .pending_effects("scope.fixture", first[511].outbox_id, 512)
        .unwrap();
    assert_eq!(second.len(), 1);
    assert!(second[0].outbox_id > first[511].outbox_id);
    assert!(matches!(
        store.pending_effects("scope.fixture", -1, 10),
        Err(StoreError::InvalidInput(_))
    ));
}

#[test]
fn schema_one_open_migrates_without_changing_original_receipt() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    ready(&mut store);
    let input = request("scope.fixture", "request.legacy", b"legacy");
    let receipt = match store.admit(&input).unwrap() {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected commit: {other:?}"),
    };
    drop(store);

    // Reconstruct the schema-one outbox around a committed row. The next open
    // must migrate it without changing command identity or admission lineage.
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys=OFF;
             BEGIN IMMEDIATE;
             CREATE TABLE outbox_legacy (
               outbox_id INTEGER PRIMARY KEY AUTOINCREMENT,
               command_rowid INTEGER NOT NULL UNIQUE REFERENCES commands(command_rowid),
               scope_id TEXT NOT NULL, target_id TEXT NOT NULL,
               owner_epoch INTEGER NOT NULL, target_epoch INTEGER NOT NULL,
               kind TEXT NOT NULL, payload BLOB NOT NULL,
               state TEXT NOT NULL CHECK(state IN ('prepared','claimed_uncertain','observed')),
               claim_key TEXT, claim_owner_epoch INTEGER
             ) STRICT;
             INSERT INTO outbox_legacy(outbox_id,command_rowid,scope_id,target_id,
               owner_epoch,target_epoch,kind,payload,state,claim_key,claim_owner_epoch)
             SELECT outbox_id,command_rowid,scope_id,target_id,owner_epoch,target_epoch,
               kind,payload,state,claim_key,claim_owner_epoch FROM outbox;
             DROP TABLE outbox;
             ALTER TABLE outbox_legacy RENAME TO outbox;
             CREATE TABLE events_legacy (
               sequence INTEGER PRIMARY KEY AUTOINCREMENT,
               command_rowid INTEGER NOT NULL UNIQUE REFERENCES commands(command_rowid),
               scope_id TEXT NOT NULL, owner_epoch INTEGER NOT NULL,
               target_epoch INTEGER NOT NULL, kind TEXT NOT NULL, payload BLOB NOT NULL
             ) STRICT;
             INSERT INTO events_legacy(sequence,command_rowid,scope_id,owner_epoch,
               target_epoch,kind,payload)
             SELECT sequence,command_rowid,scope_id,owner_epoch,target_epoch,kind,payload
               FROM events;
             DROP TABLE events;
             ALTER TABLE events_legacy RENAME TO events;
             CREATE INDEX events_scope_sequence ON events(scope_id,sequence);
             DROP TABLE store_identity;
             PRAGMA user_version=1;
             COMMIT;",
        )
        .unwrap();
    drop(connection);

    let mut migrated = fixture.open();
    assert_eq!(
        migrated.admit(&input).unwrap(),
        Admission::Duplicate(receipt.clone())
    );
    let effect = migrated
        .load_effect(receipt.outbox_id, "scope.fixture", "target.fixture")
        .unwrap();
    assert_eq!(effect.command_id, receipt.command_id);
    assert_eq!(effect.state, EffectState::Prepared);
    assert_eq!(effect.payload, b"effect.fixture");
    assert_eq!(
        migrated.scope_snapshot("scope.fixture").unwrap().receipts,
        vec![receipt]
    );
}

#[test]
fn schema_two_migration_preserves_lineage_cursor_and_legacy_evidence_stage() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    ready(&mut store);
    let input = request("scope.fixture", "request.schema-two", b"schema-two");
    let receipt = match store.admit(&input).unwrap() {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected commit: {other:?}"),
    };
    let original_cursor = store.scope_snapshot("scope.fixture").unwrap().cursor;
    store
        .claim_effect(
            receipt.outbox_id,
            "scope.fixture",
            "target.fixture",
            1,
            1,
            "claim.schema-two",
        )
        .unwrap();
    drop(store);

    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys=OFF;
             BEGIN IMMEDIATE;
             CREATE TABLE outbox_v2 (
               outbox_id INTEGER PRIMARY KEY AUTOINCREMENT,
               command_rowid INTEGER NOT NULL UNIQUE REFERENCES commands(command_rowid),
               scope_id TEXT NOT NULL, target_id TEXT NOT NULL,
               owner_epoch INTEGER NOT NULL, target_epoch INTEGER NOT NULL,
               kind TEXT NOT NULL, payload BLOB NOT NULL,
               state TEXT NOT NULL CHECK(state IN ('prepared','claimed_uncertain','observed')),
               claim_key TEXT, claim_owner_epoch INTEGER,
               observation_key TEXT, observation_payload BLOB
             ) STRICT;
             INSERT INTO outbox_v2(outbox_id,command_rowid,scope_id,target_id,
               owner_epoch,target_epoch,kind,payload,state,claim_key,claim_owner_epoch,
               observation_key,observation_payload)
             SELECT outbox_id,command_rowid,scope_id,target_id,owner_epoch,target_epoch,
               kind,payload,'observed',claim_key,claim_owner_epoch,
               'legacy.evidence',X'01' FROM outbox;
             DROP TABLE outbox;
             ALTER TABLE outbox_v2 RENAME TO outbox;
             CREATE TABLE events_v2 (
               sequence INTEGER PRIMARY KEY AUTOINCREMENT,
               command_rowid INTEGER NOT NULL UNIQUE REFERENCES commands(command_rowid),
               scope_id TEXT NOT NULL, owner_epoch INTEGER NOT NULL,
               target_epoch INTEGER NOT NULL, kind TEXT NOT NULL, payload BLOB NOT NULL
             ) STRICT;
             INSERT INTO events_v2(sequence,command_rowid,scope_id,owner_epoch,
               target_epoch,kind,payload)
             SELECT sequence,command_rowid,scope_id,owner_epoch,target_epoch,kind,payload
               FROM events;
             DROP TABLE events;
             ALTER TABLE events_v2 RENAME TO events;
             CREATE INDEX events_scope_sequence ON events(scope_id,sequence);
             PRAGMA user_version=2;
             COMMIT;",
        )
        .unwrap();
    drop(connection);

    let mut migrated = fixture.open();
    assert_eq!(
        migrated.admit(&input).unwrap(),
        Admission::Duplicate(receipt.clone())
    );
    assert_eq!(
        migrated.scope_snapshot("scope.fixture").unwrap().cursor,
        original_cursor
    );
    assert_eq!(
        migrated
            .events_after("scope.fixture", &original_cursor, 10)
            .unwrap()
            .len(),
        0
    );
    let effect = migrated
        .load_effect(receipt.outbox_id, "scope.fixture", "target.fixture")
        .unwrap();
    assert_eq!(effect.state, EffectState::Observed);
    assert_eq!(effect.observed_stage, Some(ObservedStage::LegacyUnverified));
    assert_eq!(effect.observation_event_sequence, None);
    assert!(matches!(
        migrated.observe_effect(
            receipt.outbox_id,
            "scope.fixture",
            "target.fixture",
            1,
            1,
            "claim.schema-two",
            &host_proof(1, "host-receipt.schema-two", b"host-ack"),
        ),
        Err(StoreError::Conflict(_))
    ));
    let next = match migrated
        .admit(&request(
            "scope.fixture",
            "request.after-schema-two",
            b"after",
        ))
        .unwrap()
    {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected post-migration commit: {other:?}"),
    };
    assert!(next.event_sequence > original_cursor.sequence);
    let replay = migrated
        .events_after("scope.fixture", &original_cursor, 10)
        .unwrap();
    assert_eq!(replay.len(), 1);
    assert_eq!(replay[0].sequence, next.event_sequence);
}
