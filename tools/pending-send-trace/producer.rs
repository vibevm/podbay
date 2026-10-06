// Included only inside external_death_v25::tests in a disposable scratch copy.
use super::*;
use rusqlite::types::ValueRef;

const SNAPSHOT_CAP: usize = 8 * 1024 * 1024;
const ROW_CAP: i64 = 1024;
const CELL_CAP: i64 = 1024 * 1024;
const BASE_FORMAT: &str = "podbay.disposable-pending-send-sql-trace/1";
const FINAL_FORMAT: &str = "podbay.disposable-pending-send-sql-trace/final-recorded/1";
const LATER_FORMAT: &str = "podbay.disposable-pending-send-sql-trace/later-pending/1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum Cell {
    Null,
    Integer { decimal: String },
    Text { hex: String },
    Blob { hex: String },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Table {
    name: String,
    columns: Vec<String>,
    rows: Vec<Vec<Cell>>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema_version: String,
    tables: Vec<Table>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    sequence: String,
    kind: String,
    mode: String,
    fence: String,
    result: String,
    finish: String,
    before: Snapshot,
    after: Snapshot,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureTrace {
    scenario: String,
    subject_request_hex: String,
    command_id: String,
    original_receipt: Vec<String>,
    original_effect_state: String,
    operations: Vec<Operation>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Trace {
    format: String,
    pending_request_cap: String,
    snapshot_cap: String,
    row_cap: String,
    cell_cap: String,
    fixtures: Vec<FixtureTrace>,
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn capture(path: &Path) -> Snapshot {
    let mut c = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let tx = c.transaction_with_behavior(TransactionBehavior::Deferred).unwrap();
    let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
    let (count, name_bytes): (i64, i64) = tx.query_row(
        "SELECT count(*),coalesce(sum(length(CAST(name AS BLOB))),0) FROM sqlite_schema WHERE type='table'", [],
        |r| Ok((r.get(0)?,r.get(1)?))).unwrap();
    assert!(count <= 128 && name_bytes <= 32768, "table metadata budget");
    let names = tx.prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name").unwrap()
        .query_map([], |r| r.get::<_, String>(0)).unwrap().collect::<Result<Vec<_>,_>>().unwrap();
    let mut tables = Vec::new();
    let mut materialized_budget: i64 = 0;
    // sqlite_schema itself is evidence, including exact DDL and schema ordering.
    for name in std::iter::once("sqlite_schema".to_string()).chain(names) {
        let q = quoted_identifier(&name);
        let count: i64 = tx.query_row(&format!("SELECT count(*) FROM {q}"), [], |r| r.get(0)).unwrap();
        assert!(count <= ROW_CAP, "table row budget");
        let mut stmt = tx.prepare(&format!("SELECT rowid,* FROM {q} ORDER BY rowid")).unwrap();
        let columns = stmt.column_names().iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(columns.len() <= 64, "column budget");
        materialized_budget = materialized_budget.checked_add(
            count.checked_mul(columns.len() as i64).unwrap().checked_mul(64).unwrap()
        ).unwrap();
        assert!(materialized_budget <= (SNAPSHOT_CAP / 2) as i64, "row structure budget");
        // Preflight TEXT/BLOB lengths before fetching any cell bytes.
        for column in columns.iter().skip(1) {
            let qc = quoted_identifier(column);
            let (max, sum): (i64,i64) = tx.query_row(&format!(
                "SELECT coalesce(max(length(CAST({qc} AS BLOB))),0),coalesce(sum(length(CAST({qc} AS BLOB))),0) FROM {q}"), [],
                |r| Ok((r.get(0)?,r.get(1)?))).unwrap();
            assert!(max <= CELL_CAP, "cell byte budget");
            materialized_budget = materialized_budget.checked_add(sum.checked_mul(2).unwrap()).unwrap();
            // Reserve JSON structure/name overhead; the final serialized cap is checked too.
            assert!(materialized_budget <= (SNAPSHOT_CAP / 2) as i64, "snapshot preflight budget");
        }
        let mut query = stmt.query([]).unwrap();
        let mut rows = Vec::new();
        while let Some(row) = query.next().unwrap() {
            rows.push((0..columns.len()).map(|i| match row.get_ref(i).unwrap() {
                ValueRef::Null => Cell::Null,
                ValueRef::Integer(n) => Cell::Integer { decimal: n.to_string() },
                ValueRef::Text(b) => Cell::Text { hex: hex(b) },
                ValueRef::Blob(b) => Cell::Blob { hex: hex(b) },
                ValueRef::Real(_) => panic!("unsupported fixture REAL cell"),
            }).collect());
        }
        tables.push(Table { name, columns, rows });
    }
    tx.commit().unwrap();
    let result = Snapshot { schema_version: version.to_string(), tables };
    assert!(serde_json::to_vec(&result).unwrap().len() <= SNAPSHOT_CAP);
    result
}
fn receipt(h: &NativeHarness) -> (Vec<String>, String) {
    // Calls the original-key passive API and its wrong-actor/key/payload controls.
    let (r, state) = h.history();
    (vec![r.command_id, r.event_sequence.to_string(), r.outbox_id.to_string(),
        r.digest_version.to_string(), r.request_digest], format!("{state:?}"))
}
fn op(h: &NativeHarness, sequence: usize, kind: &str) -> Operation {
    let before = capture(&h.f.source);
    let mut fence = "NotReached".to_string();
    let (mode, result, finish) = match kind {
        "PreparePending" => {
            h.f.open().prepare(&h.f.author(), &h.f.request).unwrap();
            ("Immediate", "PendingCommitted".to_string(), "CommitSucceeded")
        }
        "SeedFinalRecorded" => {
            // Explicit private fixture seed only: no authenticated finalization.
            let mut c = Connection::open(&h.f.source).unwrap();
            c.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;").unwrap();
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate).unwrap();
            let pending: i64 = tx.query_row(
                "SELECT pending_rowid FROM external_death_pending WHERE recovery_key=?1 AND store_lineage=?2",
                params![h.f.request.recovery_key, h.f.request.store_lineage], |r| r.get(0)).unwrap();
            tx.execute("INSERT INTO external_death_final(pending_rowid,proof_digest,native_outcome) VALUES(?1,?2,'uncertain')",
                params![pending, "a".repeat(64)]).unwrap();
            tx.commit().unwrap();
            ("Immediate", "FinalRecordedSeeded".to_string(), "CommitSucceeded")
        }
        "PassiveExactReceipt" => {
            let _ = receipt(h);
            ("Deferred", "ExactReceipt".to_string(), "CommitSucceeded")
        }
        _ => {
            let mut c = Connection::open(&h.f.source).unwrap();
            let inspect = kind == "CurrentInspect";
            let tx = c.transaction_with_behavior(if inspect { TransactionBehavior::Deferred } else { TransactionBehavior::Immediate }).unwrap();
            let policy = |t: &Transaction<'_>, target: &crate::NativeWriterTarget, owner, credential, revision| {
                fence = format!("{:?}", native_send_disposition(t, target, owner, credential, revision));
                require_live_native_send(t, target, owner, credential, revision)
            };
            let result = if inspect {
                if let Some(selector) = &h.later {
                    crate::later_turn::inspect_claimed_later_codex_send_in_transaction(
                        &tx, &h.f.request.store_lineage, selector, policy).map(|_| "CurrentRecord".to_string())
                } else {
                    crate::bootstrap_send::inspect_claimed_bootstrap_send_in_transaction(
                        &tx, &h.f.request.store_lineage, &h.bootstrap, policy).map(|_| "CurrentRecord".to_string())
                }
            } else {
                if let Some(selector) = &h.later {
                    crate::later_turn::claim_later_codex_send_in_transaction(
                        &tx, &h.f.request.store_lineage, selector, policy).map(|r| format!("{r:?}"))
                } else {
                    crate::bootstrap_send::claim_bootstrap_send_in_transaction(
                        &tx, &h.f.request.store_lineage, &h.bootstrap, policy).map(|r| format!("{r:?}"))
                }
            };
            let result = match result {
                Ok(s) => s,
                Err(StoreError::Conflict("native send subject pending")) => "DeniedPending".into(),
                Err(StoreError::Conflict("native send subject final recorded")) => "DeniedFinalRecorded".into(),
                Err(e) => panic!("unexpected store outcome: {e:?}"),
            };
            if kind == "RollbackClaim" {
                tx.rollback().unwrap();
                ("Immediate", result, "RollbackSucceeded")
            } else {
                tx.commit().unwrap();
                (if inspect { "Deferred" } else { "Immediate" }, result, "CommitSucceeded")
            }
        }
    };
    let after = capture(&h.f.source);
    Operation { sequence: sequence.to_string(), kind: kind.into(), mode: mode.into(), fence,
        result, finish: finish.into(), before, after }
}
#[test]
fn produce_bootstrap_pending_trace() {
    let profile = std::env::var("PODBAY_PENDING_TRACE_PROFILE").unwrap_or_else(|_| "bootstrap".into());
    assert!(matches!(profile.as_str(), "bootstrap" | "final-recorded" | "later-pending"), "unknown trace profile");
    let mut fixtures = Vec::new();
    let mut scenarios = vec![("PreparedPending", false), ("ClaimedPending", true), ("Rollback", false)];
    if profile != "bootstrap" {
        scenarios.push(("FinalRecorded", true));
    }
    if profile == "later-pending" {
        scenarios.push(("LaterClaimedPending", true));
    }
    for (scenario, claimed) in scenarios {
        let h = NativeHarness::new(scenario == "LaterClaimedPending", claimed);
        let (original_receipt, original_effect_state) = receipt(&h);
        let mut operations = Vec::new();
        if scenario == "Rollback" {
            operations.push(op(&h, 1, "RollbackClaim"));
        } else {
            let kinds = if scenario == "FinalRecorded" {
                vec!["PreparePending", "SeedFinalRecorded", "Claim", "CurrentInspect", "PassiveExactReceipt"]
            } else if scenario == "LaterClaimedPending" {
                vec!["CurrentInspect", "PreparePending", "Claim", "CurrentInspect", "PassiveExactReceipt"]
            } else {
                vec!["PreparePending", "Claim", "CurrentInspect", "PassiveExactReceipt"]
            };
            for (i, kind) in kinds.iter().enumerate() {
                operations.push(op(&h, i + 1, kind));
            }
        }
        assert_eq!(receipt(&h), (original_receipt.clone(), original_effect_state.clone()));
        fixtures.push(FixtureTrace { scenario: scenario.into(),
            subject_request_hex: hex(&canonical(&h.f.author(), &h.f.request).unwrap()),
            command_id: h.later.as_ref().map(|s| s.command_id.as_str()).unwrap_or(h.bootstrap.command_id.as_str()).into(), original_receipt, original_effect_state, operations });
    }
    let format = match profile.as_str() { "later-pending" => LATER_FORMAT, "final-recorded" => FINAL_FORMAT, _ => BASE_FORMAT };
    let trace = Trace { format: format.into(),
        pending_request_cap: MAX_PENDING_BYTES.to_string(), snapshot_cap: SNAPSHOT_CAP.to_string(),
        row_cap: ROW_CAP.to_string(), cell_cap: CELL_CAP.to_string(), fixtures };
    let bytes = serde_json::to_vec(&trace).unwrap();
    assert!(bytes.len() <= 16 * 1024 * 1024, "trace byte budget");
    let _: Trace = serde_json::from_slice(&bytes).unwrap();
    let output = std::env::var_os("PODBAY_PENDING_TRACE_OUTPUT").expect("private trace output path required");
    fs::write(output, bytes).unwrap();
}

#[test]
fn later_current_authority_probe() {
    let h = NativeHarness::new(true, true);
    let before = capture(&h.f.source);
    let history = receipt(&h);
    let mut c = Connection::open(&h.f.source).unwrap();
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate).unwrap();
    tx.execute("UPDATE metadata SET value=value+1 WHERE key='authority_revision'", []).unwrap();
    assert_eq!(native_send_disposition(&tx, &h.bootstrap.native_target,
        h.f.request.expected_owner_epoch, h.f.request.expected_manager_credential_epoch,
        h.f.request.expected_authority_revision), SubjectDisposition::Live);
    assert!(matches!(h.inspect(&tx), Err(StoreError::StaleEpoch)),
        "current authority revision must be rechecked");
    tx.rollback().unwrap();
    assert_eq!(capture(&h.f.source), before);
    assert_eq!(receipt(&h), history);
}
