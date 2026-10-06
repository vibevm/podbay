//! Closed production restart contract. Parsing does not load policy or evidence.
//! P1-006 remains open until the named production adapters are implemented.

use std::ffi::OsString;
use std::path::Path;

use serde::Serialize;

pub(super) const SYNTAX: &str =
    "podbay operator zap restart --policy ABSOLUTE_PRIVATE_JSON --request-key KEY";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ClosedRestartResult {
    protocol: &'static str,
    request_key: String,
    disposition: Disposition,
    code: RefusalCode,
    allocated_generation: Option<u64>,
    accepted_launch: Option<()>,
    missing_capabilities: [MissingCapability; 4],
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Disposition {
    Unsupported,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum RefusalCode {
    ProductionRestartClosed,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum MissingCapability {
    TrustedTerminalAcquisition,
    TrustedHistoricalSignerSnapshot,
    DurableGenerationPublication,
    AuthenticatedChildReadiness,
}

pub(super) fn parse_closed_request(args: &[OsString]) -> Result<ClosedRestartResult, String> {
    if args.len() != 8
        || args[1] != "operator"
        || args[2] != "zap"
        || args[3] != "restart"
        || args[4] != "--policy"
        || args[6] != "--request-key"
    {
        return Err(format!("usage: {SYNTAX}"));
    }
    let policy_path = Path::new(&args[5]);
    if !policy_path.is_absolute()
        || policy_path
            .file_name()
            .is_none_or(|name| name != "operator-zap-policy.json")
    {
        return Err(
            "restart policy path must be absolute and named operator-zap-policy.json".into(),
        );
    }
    let request_key = args[7]
        .to_str()
        .filter(|key| super::valid_token(key))
        .ok_or("restart request key is invalid")?;
    Ok(ClosedRestartResult {
        protocol: "podbay.operator-zap-restart/1",
        request_key: request_key.into(),
        disposition: Disposition::Unsupported,
        code: RefusalCode::ProductionRestartClosed,
        allocated_generation: None,
        accepted_launch: None,
        missing_capabilities: [
            MissingCapability::TrustedTerminalAcquisition,
            MissingCapability::TrustedHistoricalSignerSnapshot,
            MissingCapability::DurableGenerationPublication,
            MissingCapability::AuthenticatedChildReadiness,
        ],
    })
}
