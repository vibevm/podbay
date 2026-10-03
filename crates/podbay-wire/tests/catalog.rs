use podbay_wire::{MutationOperation, ReadOperation, decode_command_json, decode_read_json};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schema/v1")
            .join(name),
    )
    .unwrap()
}

#[test]
fn every_advertised_mutation_and_read_has_a_cross_language_fixture() {
    for operation in MutationOperation::SUPPORTED {
        let name = if operation == MutationOperation::ResourceCommand {
            "command-resource-write.json".to_owned()
        } else {
            format!("command-{}.json", operation.as_str().replace('.', "-"))
        };
        let bytes = fixture(&name);
        let command = decode_command_json(&bytes).unwrap();
        assert_eq!(command.operation(), operation, "{name}");
        let roundtrip: serde_json::Value =
            serde_json::from_slice(&command.encode_json().unwrap()).unwrap();
        let checked_in: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(roundtrip, checked_in, "{name}");
    }
    for operation in ReadOperation::SUPPORTED {
        let name = format!("read-{}.json", operation.as_str().replace('.', "-"));
        let bytes = fixture(&name);
        let request = decode_read_json(&bytes).unwrap();
        assert_eq!(request.operation(), operation, "{name}");
        let roundtrip: serde_json::Value =
            serde_json::from_slice(&request.encode_json().unwrap()).unwrap();
        let checked_in: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(roundtrip, checked_in, "{name}");
    }
}

#[test]
fn launch_choice_and_interaction_boundaries_fail_closed() {
    let fresh = decode_command_json(&fixture("command-launch.json")).unwrap();
    let existing = decode_command_json(&fixture("command-launch-existing.json")).unwrap();
    assert_eq!(fresh.key, existing.key);
    assert_ne!(
        fresh.payload_digest, existing.payload_digest,
        "session choice changes logical content"
    );

    let mut answer: serde_json::Value =
        serde_json::from_slice(&fixture("command-question-answer.json")).unwrap();
    answer["body"]["decision"] = serde_json::json!({"kind":"allow_once"});
    assert!(decode_command_json(&serde_json::to_vec(&answer).unwrap()).is_err());

    let mut permission: serde_json::Value =
        serde_json::from_slice(&fixture("command-permission-decide.json")).unwrap();
    permission["target"] = serde_json::json!({"kind":"question","questionId":"question.fixture"});
    assert!(decode_command_json(&serde_json::to_vec(&permission).unwrap()).is_err());

    let mut report: serde_json::Value =
        serde_json::from_slice(&fixture("command-run-report.json")).unwrap();
    report["body"]["accepted"] = serde_json::json!(true);
    assert!(decode_command_json(&serde_json::to_vec(&report).unwrap()).is_err());

    let mut read: serde_json::Value =
        serde_json::from_slice(&fixture("read-commands-get.json")).unwrap();
    read["key"] = serde_json::json!("must-not-be-a-mutation-key");
    assert!(decode_read_json(&serde_json::to_vec(&read).unwrap()).is_err());
}
