//! Machine-readable v1 manifest generated from the Rust-owned wire vocabulary.
use serde_json::{Value, json};

use crate::{MAX_FRAME_BYTES, MutationOperation};

pub fn contract_manifest() -> Value {
    json!({
        "protocol": "podbay/1",
        "frame": { "prefix": "u32_be", "maxBytes": MAX_FRAME_BYTES },
        "decimalCounter": {
            "encoding": "json_string",
            "grammar": "0|[1-9][0-9]*",
            "maximum": "18446744073709551615"
        },
        "cursorFields": ["storeLineage", "scopeId", "sequence"],
        "supportedMutationSchemas": MutationOperation::SUPPORTED.iter().map(|operation| operation.as_str()).collect::<Vec<_>>(),
        "resourceCommandKinds": ["write", "resize", "interrupt", "stop"],
        "unknownMutation": "reject_before_effect",
        "unknownObservation": "retain_opaque_json",
        "eventSchemaCompatibility": "unknown_schema_is_opaque_under_podbay/1"
    })
}
