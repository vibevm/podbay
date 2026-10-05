use podbay_wire::{ReadOperation, Target, decode_read_json};
use serde_json::{Value, json};

fn request() -> Value {
    json!({
        "protocol": "podbay/1",
        "operation": "native.events.read",
        "requestId": "request.native.fixture",
        "target": {"kind":"scope","scopeId":"scope.fixture"},
        "body": {
            "sessionId":"session.fixture",
            "resourceId":"resource.fixture",
            "limit":"2",
            "after": {
                "identity": {
                    "storeLineage":"store.fixture",
                    "scopeId":"scope.fixture",
                    "sessionId":"session.fixture",
                    "runId":"run.fixture",
                    "attemptId":"attempt.fixture",
                    "podId":"pod.fixture",
                    "podIncarnation":"1",
                    "resourceId":"resource.fixture",
                    "resourceEpoch":"1"
                },
                "sourceSequence":"7"
            }
        }
    })
}

#[test]
fn native_cursor_is_exact_scoped_and_bounded() {
    let request = request();
    let decoded = decode_read_json(&serde_json::to_vec(&request).unwrap()).unwrap();
    assert_eq!(decoded.operation(), ReadOperation::NativeEventsRead);
    assert!(matches!(decoded.target, Target::Scope { .. }));
    assert_eq!(
        serde_json::from_slice::<Value>(&decoded.encode_json().unwrap()).unwrap(),
        request
    );
    for mut changed in [
        {
            let mut value = request.clone();
            value["body"]["after"]["identity"]["scopeId"] = json!("scope.other");
            value
        },
        {
            let mut value = request.clone();
            value["body"]["after"]["identity"]["sessionId"] = json!("session.other");
            value
        },
        {
            let mut value = request.clone();
            value["body"]["after"]["identity"]["resourceId"] = json!("resource.other");
            value
        },
        {
            let mut value = request.clone();
            value["body"]["limit"] = json!("33");
            value
        },
        {
            let mut value = request.clone();
            value["body"]["after"]["sourceSequence"] = json!("9223372036854775808");
            value
        },
    ] {
        assert!(decode_read_json(&serde_json::to_vec(&changed).unwrap()).is_err());
        changed["body"]["unexpected"] = json!(true);
        assert!(decode_read_json(&serde_json::to_vec(&changed).unwrap()).is_err());
    }
}
