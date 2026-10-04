//! Rust-owned TypeScript artifact. The committed binding is checked against this output.

use crate::{MutationOperation, contract_manifest};

pub fn typescript_source() -> String {
    let generated_body_schemas = [
        "launch",
        "session.close",
        "session.send",
        "run.interrupt",
        "run.pause",
        "run.resume",
        "run.stop",
        "run.report",
        "run.finish",
        "delivery.ack",
        "delivery.cancel",
        "control.acquire",
        "control.release",
        "terminal.detach",
        "question.ask",
        "question.answer",
        "question.cancel",
        "permission.request",
        "permission.decide",
        "resource.command",
    ];
    let advertised = MutationOperation::SUPPORTED.map(MutationOperation::as_str);
    assert_eq!(
        advertised, generated_body_schemas,
        "TypeScript body codecs must be extended before advertising another mutation",
    );
    let generated_read_schemas = [
        "capabilities.get",
        "commands.get",
        "run.get",
        "session.get",
        "delivery.get",
        "snapshot.get",
        "event.subscribe",
        "history.read",
        "native.events.read",
        "terminal.snapshot",
        "terminal.attach",
        "terminal.observe",
    ];
    let advertised_reads = crate::ReadOperation::SUPPORTED.map(crate::ReadOperation::as_str);
    assert_eq!(
        advertised_reads, generated_read_schemas,
        "TypeScript read codecs must be extended before advertising another read",
    );
    let contract = serde_json::to_string(&contract_manifest()).expect("static contract serializes");
    include_str!("../templates/client.ts.in").replace("__PODBAY_CONTRACT_JSON__", &contract)
}
