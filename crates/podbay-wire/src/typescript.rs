//! Rust-owned TypeScript artifact. The committed binding is checked against this output.

use crate::{MutationOperation, contract_manifest};

pub fn typescript_source() -> String {
    let generated_body_schemas = [
        "session.send",
        "run.pause",
        "run.resume",
        "run.stop",
        "resource.command",
    ];
    let advertised = MutationOperation::SUPPORTED.map(MutationOperation::as_str);
    assert_eq!(
        advertised, generated_body_schemas,
        "TypeScript body codecs must be extended before advertising another mutation",
    );
    let contract = serde_json::to_string(&contract_manifest()).expect("static contract serializes");
    include_str!("../templates/client.ts.in").replace("__PODBAY_CONTRACT_JSON__", &contract)
}
