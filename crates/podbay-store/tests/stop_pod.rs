use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_store::{
    Admission, CommandLookupSelector, CommandRequest, EffectClaim, EffectState, ObservedStage,
    PodBayStore, StoreError, VerifiedPrincipal,
};

struct Fixture {
    root: PathBuf,
    database: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("podbay-stop-store-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        Self {
            database: root.join("podbay.sqlite"),
            root,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn principal() -> VerifiedPrincipal {
    VerifiedPrincipal::from_authenticated_boundary("actor.stop.fixture").unwrap()
}

fn request(key: &str) -> CommandRequest {
    CommandRequest {
        principal: principal(),
        namespace: "podbay.inner.stop".into(),
        command_key: key.into(),
        scope_id: "scope.stop.fixture".into(),
        target_id: "pod.stop.fixture".into(),
        expected_owner_epoch: 1,
        expected_target_epoch: 1,
        canonical_request: b"signed exact stop fixture".to_vec(),
        event_kind: "pod.stop.requested".into(),
        event_payload: b"{\"kind\":\"pod_stop_requested\"}".to_vec(),
        effect_kind: "pod.stop".into(),
        effect_payload: b"exact birth and unit evidence".to_vec(),
    }
}

#[test]
fn exact_stop_intent_claim_survives_owner_change_and_blocks_second_key() {
    let fixture = Fixture::new();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    store.advance_owner_epoch(0, 1).unwrap();
    store
        .advance_target_epoch("scope.stop.fixture", "pod.stop.fixture", 0, 1)
        .unwrap();
    let first = match store.admit(&request("key.stop.first")).unwrap() {
        Admission::Committed(receipt) => receipt,
        other => panic!("unexpected stop admission: {other:?}"),
    };
    assert_eq!(
        store
            .claim_effect(
                first.outbox_id,
                "scope.stop.fixture",
                "pod.stop.fixture",
                1,
                1,
                0,
                &first.command_id
            )
            .unwrap(),
        EffectClaim::NewClaim
    );
    assert!(matches!(
        store.admit(&request("key.stop.second")),
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(
        store.effect_state(first.outbox_id).unwrap(),
        EffectState::ClaimedUncertain
    );
    store.advance_owner_epoch(1, 2).unwrap();
    let (same, effect) = store
        .lookup_pod_stop(
            &principal(),
            "scope.stop.fixture",
            "pod.stop.fixture",
            "key.stop.first",
            b"signed exact stop fixture",
        )
        .unwrap()
        .unwrap();
    assert_eq!(same, first);
    assert_eq!(effect.state, EffectState::ClaimedUncertain);
    assert_eq!(effect.payload, b"exact birth and unit evidence");
    assert_eq!(
        store
            .claim_effect(
                first.outbox_id,
                "scope.stop.fixture",
                "pod.stop.fixture",
                2,
                1,
                0,
                &first.command_id
            )
            .unwrap(),
        EffectClaim::ExistingUncertain
    );
    let terminal = b"{\"kind\":\"pod_stopped\"}";
    let sequence = store
        .observe_pod_stop(
            &first,
            "scope.stop.fixture",
            "pod.stop.fixture",
            2,
            1,
            terminal,
        )
        .unwrap();
    assert_eq!(
        store
            .observe_pod_stop(
                &first,
                "scope.stop.fixture",
                "pod.stop.fixture",
                2,
                1,
                terminal
            )
            .unwrap(),
        sequence
    );
    let inspected = store
        .lookup_command(
            "scope.stop.fixture",
            &principal(),
            &CommandLookupSelector::Key {
                key: "key.stop.first".into(),
            },
        )
        .unwrap();
    assert_eq!(inspected.observed_stage, Some(ObservedStage::PodStopped));
    assert_eq!(inspected.observation_event_sequence, Some(sequence));
    assert!(matches!(
        store.observe_pod_stop(
            &first,
            "scope.stop.fixture",
            "pod.stop.fixture",
            2,
            1,
            b"different"
        ),
        Err(StoreError::Conflict(_))
    ));
}
