use std::collections::BTreeMap;

use podbay_wire::{
    Capability, CapabilityEnvelope, CapabilitySupport, CommandBody, CommandEnvelope, DecimalString,
    ErrorEnvelope, EventCursor, Guard, ObservationKind, ProtocolVersion, Receipt, ResourceAction,
    ResourceCommandBody, SnapshotEnvelope, Target, WireError, contract_manifest,
    decode_command_json, decode_event_json, decode_frame_bytes, encode_frame,
};
use serde_json::{Value, json};

fn resource_command() -> CommandEnvelope {
    CommandEnvelope::new(
        "request.pb03.1",
        "key.pb03.write.1",
        Target::Resource {
            pod_id: "pod.fixture".to_owned(),
            resource_id: "resource.pty".to_owned(),
        },
        Some(Guard {
            manager_epoch: Some(DecimalString::new(42)),
            pod_epoch: Some(DecimalString::new(7)),
            resource_epoch: Some(DecimalString::new(3)),
            lease_epoch: Some(DecimalString::new(19)),
            ..Guard::default()
        }),
        Some("2026-10-03T12:00:00Z".to_owned()),
        CommandBody::ResourceCommand(ResourceCommandBody {
            command: ResourceAction::Write {
                content_ref: "artifact.input.1".to_owned(),
            },
        }),
    )
    .unwrap()
}

#[test]
fn golden_v1_command_has_stable_cross_language_digest() {
    let fixture = include_bytes!("../../../schema/v1/command-resource-write.json");
    let decoded = decode_command_json(fixture).unwrap();
    assert_eq!(decoded, resource_command());
    assert_eq!(
        decoded.payload_digest,
        "df8abdefd49491a11b6312b252922528ed9d558093770df2ee86f07750113b11"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&decoded.encode_json().unwrap()).unwrap(),
        serde_json::from_slice::<Value>(fixture).unwrap(),
    );
}

#[test]
fn all_five_generated_mutation_fixtures_decode_with_exact_operations() {
    for (fixture, operation) in [
        (
            include_str!("../../../schema/v1/command-session-send.json"),
            "session.send",
        ),
        (
            include_str!("../../../schema/v1/command-run-pause.json"),
            "run.pause",
        ),
        (
            include_str!("../../../schema/v1/command-run-resume.json"),
            "run.resume",
        ),
        (
            include_str!("../../../schema/v1/command-run-stop.json"),
            "run.stop",
        ),
        (
            include_str!("../../../schema/v1/command-resource-write.json"),
            "resource.command",
        ),
    ] {
        let decoded = decode_command_json(fixture.as_bytes()).unwrap();
        assert_eq!(decoded.operation().as_str(), operation);
        let encoded: serde_json::Value =
            serde_json::from_slice(&decoded.encode_json().unwrap()).unwrap();
        let checked_in: serde_json::Value = serde_json::from_str(fixture).unwrap();
        assert_eq!(encoded, checked_in);
    }
}

#[test]
fn checked_in_contract_manifest_matches_rust_vocabulary() {
    let checked_in: Value =
        serde_json::from_str(include_str!("../../../schema/v1/contract.json")).unwrap();
    assert_eq!(checked_in, contract_manifest());
}

#[test]
fn generated_typescript_binding_matches_rust_template() {
    assert_eq!(
        podbay_wire::typescript_source(),
        include_str!("../../../bindings/typescript/src/generated.ts"),
    );
}

#[test]
fn golden_receipt_snapshot_capability_and_error_envelopes_decode() {
    let receipt: Receipt<Value> =
        serde_json::from_str(include_str!("../../../schema/v1/receipt-persisted.json")).unwrap();
    receipt.validate().unwrap();
    assert_eq!(receipt.cursor.sequence.get(), 9_007_199_254_740_993);
    assert_eq!(receipt.state, podbay_wire::CommandStage::Persisted);
    assert_eq!(receipt.value["acceptedByProvider"], false);

    let snapshot: SnapshotEnvelope<Value> =
        serde_json::from_str(include_str!("../../../schema/v1/snapshot-current.json")).unwrap();
    snapshot.validate().unwrap();
    assert_eq!(snapshot.state["foreground"], "unknown");
    assert_eq!(snapshot.extra["futureObservation"]["retained"], true);

    let capabilities: CapabilityEnvelope =
        serde_json::from_str(include_str!("../../../schema/v1/capabilities.json")).unwrap();
    capabilities.validate().unwrap();
    assert_eq!(
        capabilities.capabilities[0].effective_support(),
        CapabilitySupport::Conditional
    );
    assert_eq!(
        capabilities.capabilities[1].effective_support(),
        CapabilitySupport::Unverified
    );
    assert_eq!(capabilities.capabilities[1].extra["futureField"], true);

    let error: ErrorEnvelope =
        serde_json::from_str(include_str!("../../../schema/v1/error-stale-guard.json")).unwrap();
    error.validate().unwrap();
    assert_eq!(error.error.code, podbay_wire::RuntimeErrorCode::StaleGuard);
}

#[test]
fn golden_unknown_event_retains_payload_and_additive_fields() {
    let fixture = include_bytes!("../../../schema/v1/event-unknown-observation.json");
    let event = decode_event_json(fixture).unwrap();
    assert_eq!(
        event.kind(),
        ObservationKind::Unknown("future_observation".to_owned())
    );
    assert_eq!(event.cursor.sequence.get(), 9_007_199_254_740_993);
    assert_eq!(event.extra["sourceOrder"]["expectedNext"], "7");
    assert_eq!(
        serde_json::to_value(event).unwrap(),
        serde_json::from_slice::<Value>(fixture).unwrap()
    );
    let future_schema = include_bytes!("../../../schema/v1/event-future-schema.json");
    let event = decode_event_json(future_schema).unwrap();
    assert_eq!(
        event.kind(),
        ObservationKind::Unknown("run_admitted".to_owned())
    );
    assert_eq!(
        serde_json::to_value(event).unwrap(),
        serde_json::from_slice::<Value>(future_schema).unwrap()
    );
    let mut invalid: Value = serde_json::from_slice(future_schema).unwrap();
    invalid["recordedAt"] = json!("2026-02-30T12:00:01Z");
    assert!(decode_event_json(&serde_json::to_vec(&invalid).unwrap()).is_err());
}

#[test]
fn operation_and_inner_resource_kind_cannot_collide() {
    let command = resource_command();
    let encoded = command.encode_json().unwrap();
    assert_eq!(decode_command_json(&encoded).unwrap(), command);
    let mut value: Value = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(value["operation"], "resource.command");
    assert_eq!(value["body"]["command"]["kind"], "write");
    value["operation"] = json!("permission.decide");
    assert!(matches!(
        decode_command_json(&serde_json::to_vec(&value).unwrap()),
        Err(WireError::UnsupportedOperation(_))
    ));
    value["operation"] = json!("resource.command");
    value["body"]["command"]["kind"] = json!("grant_permission");
    assert!(decode_command_json(&serde_json::to_vec(&value).unwrap()).is_err());
    value["body"]["command"]["kind"] = json!("write");
    value["body"]["command"]["operation"] = json!("stop");
    assert!(decode_command_json(&serde_json::to_vec(&value).unwrap()).is_err());
    value["body"]["command"]
        .as_object_mut()
        .unwrap()
        .remove("operation");
    value["action"] = json!("stop");
    assert!(decode_command_json(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn decimal_counters_are_lossless_strings_only() {
    let huge = DecimalString::new(9_007_199_254_740_993);
    assert_eq!(
        serde_json::to_string(&huge).unwrap(),
        "\"9007199254740993\""
    );
    assert_eq!(
        serde_json::from_str::<DecimalString>("\"9007199254740993\"").unwrap(),
        huge
    );
    for invalid in [
        "9007199254740993",
        "\"09007199254740993\"",
        "\"-1\"",
        "\"18446744073709551616\"",
    ] {
        assert!(serde_json::from_str::<DecimalString>(invalid).is_err());
    }
}

#[test]
fn cursor_rejects_foreign_scope_lineage_future_and_retention_gap() {
    let cursor = EventCursor {
        store_lineage: "store.fixture".to_owned(),
        scope_id: "project.fixture".to_owned(),
        sequence: DecimalString::new(9_007_199_254_740_993),
    };
    let head = DecimalString::new(9_007_199_254_741_000);
    assert!(
        cursor
            .validate_for(
                "store.fixture",
                "project.fixture",
                DecimalString::new(1),
                head
            )
            .is_ok()
    );
    assert_eq!(
        cursor.validate_for(
            "store.other",
            "project.fixture",
            DecimalString::new(1),
            head
        ),
        Err(WireError::ForeignLineage)
    );
    assert_eq!(
        cursor.validate_for(
            "store.fixture",
            "project.other",
            DecimalString::new(1),
            head
        ),
        Err(WireError::ForeignScope)
    );
    assert_eq!(
        cursor.validate_for(
            "store.fixture",
            "project.fixture",
            DecimalString::new(1),
            DecimalString::new(5)
        ),
        Err(WireError::FutureCursor)
    );
    assert_eq!(
        cursor.validate_for(
            "store.fixture",
            "project.fixture",
            DecimalString::new(9_007_199_254_741_000),
            head
        ),
        Err(WireError::ReplayGap { earliest: head })
    );
}

#[test]
fn unknown_observations_survive_and_unknown_capability_never_grants_support() {
    let raw = json!({
        "protocol": "podbay/1",
        "eventId": "event.future.1",
        "schema": "podbay.event/1",
        "cursor": {"storeLineage": "store.fixture", "scopeId": "project.fixture", "sequence": "9007199254740993"},
        "source": {"sourceId": "source.future", "kind": "pod"},
        "sourceEpoch": "2",
        "sourceSequence": "8",
        "target": {"kind": "run", "runId": "run.fixture"},
        "recordedAt": "2026-10-03T12:00:00Z",
        "provenance": "pod",
        "payload": {"kind": "future_observation", "newField": {"opaque": true}},
        "futureTopLevel": ["retained"]
    });
    let event = decode_event_json(&serde_json::to_vec(&raw).unwrap()).unwrap();
    assert_eq!(
        event.kind(),
        ObservationKind::Unknown("future_observation".to_owned())
    );
    assert_eq!(serde_json::to_value(&event).unwrap(), raw);
    let capability = Capability {
        operation: "resource.mystery".to_owned(),
        support: "future_grant".to_owned(),
        evidence: None,
        extra: BTreeMap::new(),
    };
    assert_eq!(
        capability.effective_support(),
        CapabilitySupport::Unverified
    );
}

#[test]
fn local_frames_are_bounded_and_exact() {
    let frame = encode_frame(&json!({"protocol": "podbay/1"})).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(decode_frame_bytes(&frame).unwrap()).unwrap()["protocol"],
        "podbay/1"
    );
    let mut trailing = frame.clone();
    trailing.push(0);
    assert_eq!(
        decode_frame_bytes(&trailing),
        Err(WireError::FrameLengthMismatch)
    );
    let oversized = [0, 16, 0, 1];
    assert_eq!(
        decode_frame_bytes(&oversized),
        Err(WireError::FrameTooLarge)
    );
    let _ = ProtocolVersion::V1;
}
