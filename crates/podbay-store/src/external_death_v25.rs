//! Restricted disposable pending protocol. No production authentication constructor,
//! dispatch, rebind, lease, readiness, Linux proof or finalization API exists here.
use super::*;
use rusqlite::{Transaction, params};

const STATE_FORMAT: &str = "podbay.disposable-v25-pending-state/1";
const MAX_PENDING_ROWS: i64 = 128;
const MAX_PENDING_BYTES: i64 = INTENT_MAX_BYTES as i64;
const REQUEST_VERSION: &str = "podbay.external-death-pending-request/1";
// Bound every fetched byte, including TEXT that SQLite character length would
// undercount. Retain the existing aggregate canonical-request budget.
const MAX_PENDING_ROW_BYTES: i64 =
    MAX_PENDING_BYTES + MAX_PENDING_ROWS * (5 * 256 + REQUEST_VERSION.len() as i64 + 64);
const MAX_FINAL_ROW_BYTES: i64 = MAX_PENDING_ROWS * (64 + 9);

/// Only private tests construct this authenticated Owner boundary in this atom.
/// A serialized actor string or caller digest is not this value.
#[derive(Debug)]
pub struct DisposablePendingAuthor {
    principal: String,
    scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingResourceBinding {
    pub resource_id: String,
    pub resource_epoch: u64,
    pub input_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalDeathPendingRequest {
    pub recovery_key: String,
    pub store_lineage: String,
    pub scope_id: String,
    pub pod_id: String,
    pub pod_incarnation: u64,
    pub session_id: String,
    pub run_id: String,
    pub attempt_id: String,
    pub launch_command_rowid: i64,
    pub activated_rebind_rowid: i64,
    pub checkpoint_digest: String,
    pub resources: Vec<PendingResourceBinding>,
    pub expected_owner_epoch: u64,
    pub expected_manager_credential_epoch: u64,
    pub expected_authority_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalDeathPendingReceipt {
    pub pending_rowid: i64,
    pub recovery_key: String,
    pub authenticated_author: String,
    pub request_digest: String,
    pub preparing_owner_epoch: u64,
    /// Committed POST revision: expected pre revision + 1.
    pub preparing_authority_revision: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalRequest {
    version: String,
    author: String,
    author_scope: String,
    request: ExternalDeathPendingRequest,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateDeclaration {
    format: String,
    state_key: String,
    migration_key: String,
    activation_key: String,
    activation_identity: FileIdentity,
    activation_bytes_digest: String,
    declaration_digest: String,
}

#[derive(Debug)]
pub struct DisposableV25PendingStore {
    source: PathBuf,
    staging: PathBuf,
    migration_key: String,
    activation_key: String,
    state_key: String,
    proof: V25StagingResult,
}

fn paths(source: &Path) -> Result<(PathBuf, PathBuf), V25StagingError> {
    let mut name = source
        .file_name()
        .ok_or(V25StagingError::InvalidInput("source filename missing"))?
        .to_os_string();
    name.push(".v25-pending-state.json");
    let path = source.with_file_name(name);
    let mut writing = path.as_os_str().to_os_string();
    writing.push(".writing");
    Ok((path, PathBuf::from(writing)))
}
fn declaration_digest(value: &StateDeclaration) -> Result<String, V25StagingError> {
    Ok(hex_digest(&serde_json::to_vec(&(
        STATE_FORMAT,
        &value.state_key,
        &value.migration_key,
        &value.activation_key,
        value.activation_identity,
        &value.activation_bytes_digest,
    ))?))
}
fn positive(value: u64) -> Result<i64, V25StagingError> {
    if value == 0 {
        return Err(V25StagingError::InvalidInput("pending counter is zero"));
    }
    i64::try_from(value)
        .map_err(|_| V25StagingError::InvalidInput("pending counter exceeds SQLite range"))
}
fn validate_request(r: &ExternalDeathPendingRequest) -> Result<(), V25StagingError> {
    for text in [
        &r.recovery_key,
        &r.store_lineage,
        &r.scope_id,
        &r.pod_id,
        &r.session_id,
        &r.run_id,
        &r.attempt_id,
    ] {
        if text.is_empty() || text.len() > 256 || text.chars().any(char::is_control) {
            return Err(V25StagingError::InvalidInput("pending identity bounds"));
        }
    }
    for value in [
        r.pod_incarnation,
        r.expected_owner_epoch,
        r.expected_manager_credential_epoch,
        r.expected_authority_revision,
    ] {
        positive(value)?;
    }
    if r.launch_command_rowid <= 0
        || r.activated_rebind_rowid <= 0
        || r.resources.is_empty()
        || r.resources.len() > 64
        || r.resources
            .windows(2)
            .any(|pair| pair[0].resource_id >= pair[1].resource_id)
        || r.checkpoint_digest.len() != 64
        || !r
            .checkpoint_digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(V25StagingError::InvalidInput("pending binding shape"));
    }
    for resource in &r.resources {
        if resource.resource_id.is_empty()
            || resource.resource_id.len() > 256
            || resource.resource_id.chars().any(char::is_control)
        {
            return Err(V25StagingError::InvalidInput(
                "pending resource identity bounds",
            ));
        }
        positive(resource.resource_epoch)?;
        positive(resource.input_epoch)?;
    }
    Ok(())
}
fn canonical(
    author: &DisposablePendingAuthor,
    r: &ExternalDeathPendingRequest,
) -> Result<Vec<u8>, V25StagingError> {
    validate_request(r)?;
    if author.scope != r.scope_id || author.principal.is_empty() {
        return Err(V25StagingError::Safety(
            "pending authenticated author scope differs",
        ));
    }
    Ok(serde_json::to_vec(&CanonicalRequest {
        version: REQUEST_VERSION.into(),
        author: author.principal.clone(),
        author_scope: author.scope.clone(),
        request: r.clone(),
    })?)
}
fn decode_request(bytes: &[u8]) -> Result<CanonicalRequest, V25StagingError> {
    if bytes.is_empty() || bytes.len() > 1_048_576 {
        return Err(V25StagingError::Safety("pending canonical request bounds"));
    }
    let c: CanonicalRequest = serde_json::from_slice(bytes)?;
    validate_request(&c.request)?;
    if c.version != REQUEST_VERSION
        || c.author_scope != c.request.scope_id
        || c.author.is_empty()
        || serde_json::to_vec(&c)? != bytes
    {
        return Err(V25StagingError::Safety(
            "pending request is not exact canonical versioned bytes",
        ));
    }
    Ok(c)
}

fn check_subject(
    tx: &Transaction<'_>,
    r: &ExternalDeathPendingRequest,
) -> Result<(), V25StagingError> {
    let bound = crate::bound_launch::read_bound_record(tx, r.launch_command_rowid)?;
    if bound.format != crate::BoundLaunchFormat::CodexV2
        || bound.scope_id != r.scope_id
        || bound.pod_id != r.pod_id
        || bound.pod_incarnation != r.pod_incarnation
        || bound.session_id != r.session_id
        || bound.run_id != r.run_id
        || bound.attempt_id != r.attempt_id
    {
        return Err(V25StagingError::Safety(
            "pending exact bound V2 launch differs",
        ));
    }
    let pod: Option<(String, i64)> = tx
        .query_row(
            "SELECT scope_id,incarnation FROM authority_pods WHERE pod_id=?1",
            [&r.pod_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let target: Option<i64> = tx
        .query_row(
            "SELECT epoch FROM target_epochs WHERE scope_id=?1 AND target_id=?2",
            params![r.scope_id, r.pod_id],
            |row| row.get(0),
        )
        .optional()?;
    if pod != Some((r.scope_id.clone(), positive(r.pod_incarnation)?))
        || target != Some(positive(r.pod_incarnation)?)
    {
        return Err(V25StagingError::Safety(
            "pending current Pod incarnation differs",
        ));
    }
    let session: Option<(String, String, Option<String>)> = tx
        .query_row(
            "SELECT scope_id,state,current_run_id FROM runtime_sessions WHERE session_id=?1",
            [&r.session_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let run:Option<(String,String,String,String,String,Option<String>,i64)>=tx.query_row("SELECT scope_id,session_id,admission_state,desired_mode,execution_state,current_attempt_id,last_attempt_ordinal FROM runtime_runs WHERE run_id=?1",[&r.run_id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?))).optional()?;
    if session != Some((r.scope_id.clone(), "open".into(), Some(r.run_id.clone())))
        || !run.is_some_and(|x| {
            x.0 == r.scope_id
                && x.1 == r.session_id
                && x.2 == "admitted"
                && x.3 == "run"
                && matches!(x.4.as_str(), "starting" | "running")
                && x.5.as_deref() == Some(&r.attempt_id)
                && x.6 == 1
        })
    {
        return Err(V25StagingError::Safety(
            "pending current Run or Attempt differs",
        ));
    }
    let mut statement = tx.prepare("SELECT scope_id,pod_incarnation,resource_id,resource_epoch,input_epoch FROM authority_resources WHERE pod_id=?1 ORDER BY resource_id LIMIT 65")?;
    let raw_resources = statement
        .query_map([&r.pod_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                PendingResourceBinding {
                    resource_id: row.get(2)?,
                    resource_epoch: row.get::<_, i64>(3)? as u64,
                    input_epoch: row.get::<_, i64>(4)? as u64,
                },
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if raw_resources.iter().any(|(scope, incarnation, _)| {
        scope != &r.scope_id || *incarnation != r.pod_incarnation as i64
    }) {
        return Err(V25StagingError::Safety(
            "pending foreign resource association",
        ));
    }
    let resources = raw_resources
        .into_iter()
        .map(|(_, _, resource)| resource)
        .collect::<Vec<_>>();
    if resources != r.resources
        || bound.resources.len() != r.resources.len()
        || bound.resources.iter().any(|b| {
            !r.resources
                .iter()
                .any(|v| v.resource_id == b.id && v.resource_epoch == b.epoch)
        })
    {
        return Err(V25StagingError::Safety("pending resource vector differs"));
    }
    let rebind:Option<(String,String,String,String,i64,String,i64,String,i64,i64)>=tx.query_row("SELECT store_lineage,scope_id,pod_id,attempt_id,pod_incarnation,phase,resource_count,pod_checkpoint_ref,next_owner_epoch,next_credential_epoch FROM manager_rebinds WHERE rebind_rowid=?1",[r.activated_rebind_rowid],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?))).optional()?;
    let row = rebind.ok_or(V25StagingError::Safety("pending activated rebind missing"))?;
    if row.8 > positive(r.expected_owner_epoch)? {
        return Err(V25StagingError::Safety(
            "pending activated rebind is ahead of admitted Owner",
        ));
    }
    if row.9 > positive(r.expected_manager_credential_epoch)? {
        return Err(V25StagingError::Safety(
            "pending activated rebind is ahead of admitted credential",
        ));
    }
    if row.0 != r.store_lineage
        || row.1 != r.scope_id
        || row.2 != r.pod_id
        || row.3 != r.attempt_id
        || row.4 != positive(r.pod_incarnation)?
        || row.5 != "activated"
        || row.6 != r.resources.len() as i64
        || row.7 != r.checkpoint_digest
    {
        return Err(V25StagingError::Safety(
            "pending rebind phase or subject differs",
        ));
    }
    let prior: Option<String> = tx
        .query_row(
            "SELECT checkpoint_digest FROM manager_rebind_prior_observations WHERE rebind_rowid=?1",
            [r.activated_rebind_rowid],
            |row| row.get(0),
        )
        .optional()?;
    if prior.as_deref() != Some(&r.checkpoint_digest) {
        return Err(V25StagingError::Safety("pending prior observation differs"));
    }
    let mut statement=tx.prepare("SELECT resource_id,next_input_epoch FROM manager_rebind_resources WHERE rebind_rowid=?1 ORDER BY resource_id LIMIT 65")?;
    let next = statement
        .query_map([r.activated_rebind_rowid], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if next
        != r.resources
            .iter()
            .map(|v| (v.resource_id.clone(), v.input_epoch as i64))
            .collect::<Vec<_>>()
    {
        return Err(V25StagingError::Safety(
            "pending rebind resource epochs differ",
        ));
    }
    let conflicts:i64=tx.query_row("SELECT count(*) FROM manager_rebinds WHERE scope_id=?1 AND pod_id=?2 AND pod_incarnation=?3 AND rebind_rowid!=?4 AND (phase!='activated' OR next_owner_epoch>?5 OR rebind_rowid>?4)",params![r.scope_id,r.pod_id,positive(r.pod_incarnation)?,r.activated_rebind_rowid,row.8],|row|row.get(0))?;
    let supersession:i64=tx.query_row("SELECT count(*) FROM rebind_supersession_attempts WHERE scope_id=?1 AND pod_id=?2 AND pod_incarnation=?3",params![r.scope_id,r.pod_id,positive(r.pod_incarnation)?],|row|row.get(0))?;
    if conflicts != 0 || supersession != 0 {
        return Err(V25StagingError::Safety(
            "pending restricted rebind/supersession conflict",
        ));
    }
    Ok(())
}

fn check_owner_author(
    tx: &Transaction<'_>,
    principal: &str,
    scope: &str,
) -> Result<(), V25StagingError> {
    let actor: Option<(String,String,String,Option<String>,Option<String>,Option<i64>,i64)> = tx.query_row(
        "SELECT scope_id,role,origin,parent_actor_id,pod_id,pod_incarnation,credential_generation FROM authority_actors WHERE actor_id=?1", [principal],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?))).optional()?;
    if actor
        != Some((
            scope.into(),
            "coordinator".into(),
            "owner_cli".into(),
            None,
            None,
            None,
            1,
        ))
    {
        return Err(V25StagingError::Safety(
            "pending current authenticated Owner differs",
        ));
    }
    Ok(())
}

fn read_validated_rows(
    tx: &Transaction<'_>,
) -> Result<Vec<(ExternalDeathPendingReceipt, ExternalDeathPendingRequest)>, V25StagingError> {
    // Fetch only numeric lengths before materializing any pending String/Vec.
    let (count, request_bytes, row_bytes, oversized): (i64, i64, i64, i64) = tx.query_row(
        "SELECT count(*),coalesce(sum(length(CAST(canonical_request AS BLOB))),0),
         coalesce(sum(length(CAST(canonical_request AS BLOB))+
           length(CAST(recovery_key AS BLOB))+length(CAST(store_lineage AS BLOB))+
           length(CAST(scope_id AS BLOB))+length(CAST(pod_id AS BLOB))+
           length(CAST(authenticated_author AS BLOB))+length(CAST(request_version AS BLOB))+
           length(CAST(request_digest AS BLOB))),0),
         coalesce(max(length(CAST(canonical_request AS BLOB))>1048576 OR
           length(CAST(recovery_key AS BLOB))>256 OR length(CAST(store_lineage AS BLOB))>256 OR
           length(CAST(scope_id AS BLOB))>256 OR length(CAST(pod_id AS BLOB))>256 OR
           length(CAST(authenticated_author AS BLOB))>256 OR
           length(CAST(request_version AS BLOB))>?1 OR length(CAST(request_digest AS BLOB))>64),0)
         FROM external_death_pending",
        [REQUEST_VERSION.len() as i64],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if count > MAX_PENDING_ROWS
        || request_bytes > MAX_PENDING_BYTES
        || row_bytes > MAX_PENDING_ROW_BYTES
        || oversized != 0
    {
        return Err(V25StagingError::Safety("pending decoder row/byte budget"));
    }
    let mut statement=tx.prepare("SELECT pending_rowid,recovery_key,store_lineage,scope_id,pod_id,pod_incarnation,launch_command_rowid,activated_rebind_rowid,preparing_owner_epoch,preparing_authority_revision,authenticated_author,request_version,canonical_request,request_digest FROM external_death_pending ORDER BY pending_rowid")?;
    let raw = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, Vec<u8>>(12)?,
                row.get::<_, String>(13)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut receipts = Vec::new();
    for row in raw {
        let canonical = decode_request(&row.12)?;
        let r = &canonical.request;
        if row.0 <= 0
            || row.1 != r.recovery_key
            || row.2 != r.store_lineage
            || row.3 != r.scope_id
            || row.4 != r.pod_id
            || row.5 != positive(r.pod_incarnation)?
            || row.6 != r.launch_command_rowid
            || row.7 != r.activated_rebind_rowid
            || row.8 != positive(r.expected_owner_epoch)?
            || row.9
                != positive(
                    r.expected_authority_revision
                        .checked_add(1)
                        .ok_or(V25StagingError::Safety("pending revision overflow"))?,
                )?
            || row.10 != canonical.author
            || row.11 != REQUEST_VERSION
            || row.13 != hex_digest(&row.12)
        {
            return Err(V25StagingError::Safety(
                "pending row differs from canonical author/request",
            ));
        }
        check_owner_author(tx, &canonical.author, &canonical.author_scope)?;
        check_subject(tx, r)?;
        receipts.push((
            ExternalDeathPendingReceipt {
                pending_rowid: row.0,
                recovery_key: row.1,
                authenticated_author: row.10,
                request_digest: row.13,
                preparing_owner_epoch: row.8 as u64,
                preparing_authority_revision: row.9 as u64,
            },
            canonical.request,
        ));
    }
    Ok(receipts)
}

fn read_rows(tx: &Transaction<'_>) -> Result<Vec<ExternalDeathPendingReceipt>, V25StagingError> {
    Ok(read_validated_rows(tx)?
        .into_iter()
        .map(|(receipt, _)| receipt)
        .collect())
}

// Private disposable prototype only: no production claim/readback path calls
// this decoder yet. A disposition is a store fact, never effect authority.
// Restricted to rebound V2 recovery candidates: even Live requires an
// activated rebind and its checkpoint/resource bindings. Ordinary fresh
// native-send subject resolution remains deferred.
// The request supplies a candidate full binding checked against stored rows.
// Future claim integration must resolve it from the selected stored send, not
// take an independently caller-selected Pod subject.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubjectDisposition {
    Live,
    Pending,
    /// A well-shaped blocking record, without any verified death semantics.
    FinalRecorded,
    Unverified,
}

#[allow(dead_code)]
fn subject_disposition(
    tx: &Transaction<'_>,
    subject: &ExternalDeathPendingRequest,
) -> SubjectDisposition {
    decode_subject_disposition(tx, subject).unwrap_or(SubjectDisposition::Unverified)
}

#[allow(dead_code)]
fn decode_subject_disposition(
    tx: &Transaction<'_>,
    subject: &ExternalDeathPendingRequest,
) -> Result<SubjectDisposition, V25StagingError> {
    let version: i64 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let (schema_count, schema_bytes): (i64, i64) = tx.query_row(
        "SELECT count(*),coalesce(sum(length(CAST(sql AS BLOB))),0) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'",
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let expected_schema = canonical_schema(true)?;
    if version != 25
        || schema_count != expected_schema.len() as i64
        || schema_bytes > MAX_PENDING_BYTES
        || schema_objects(tx)? != expected_schema
    {
        return Err(V25StagingError::Safety(
            "subject decoder unsupported schema",
        ));
    }
    validate_request(subject)?;
    let (lineage, owner, revision, claim_lineage, claim_owner, credential): (String, i64, i64, String, i64, i64) = tx.query_row(
        "SELECT (SELECT lineage FROM store_identity WHERE singleton=1),(SELECT value FROM metadata WHERE key='owner_epoch'),(SELECT value FROM metadata WHERE key='authority_revision'),(SELECT store_lineage FROM manager_credential_claims WHERE singleton=1),(SELECT owner_epoch FROM manager_credential_claims WHERE singleton=1),(SELECT credential_epoch FROM manager_credential_claims WHERE singleton=1)",
        [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
    )?;
    if lineage != subject.store_lineage
        || claim_lineage != lineage
        || owner < 1
        || revision < 0
        || claim_owner != owner
        || credential < owner
        || positive(subject.expected_owner_epoch)? > owner
        || positive(subject.expected_authority_revision)? > revision
        || positive(subject.expected_manager_credential_epoch)? > credential
    {
        return Err(V25StagingError::Safety(
            "subject decoder counter/lineage mismatch",
        ));
    }
    // Resolve the full candidate against stored launch/runtime/rebind/resources
    // in this transaction; matching caller Pod fields alone is insufficient.
    check_subject(tx, subject)?;
    let rows = read_validated_rows(tx)?;
    let mut subjects = std::collections::BTreeSet::new();
    let mut selected = None;
    for (receipt, request) in &rows {
        if request.store_lineage != lineage
            || positive(receipt.preparing_owner_epoch)? > owner
            || positive(receipt.preparing_authority_revision)? > revision
            || positive(request.expected_manager_credential_epoch)? > credential
            || !subjects.insert((
                &request.store_lineage,
                &request.scope_id,
                &request.pod_id,
                request.pod_incarnation,
            ))
        {
            return Err(V25StagingError::Safety(
                "subject decoder pending inconsistency",
            ));
        }
        if request.scope_id == subject.scope_id
            && request.pod_id == subject.pod_id
            && request.pod_incarnation == subject.pod_incarnation
        {
            selected = Some(receipt.pending_rowid);
        }
    }
    // Never materialize final TEXT until individual and aggregate byte limits
    // pass; length(TEXT) would miss NUL tails and multibyte characters.
    let (final_count, final_bytes, oversized): (i64, i64, i64) = tx.query_row(
        "SELECT count(*),coalesce(sum(length(CAST(proof_digest AS BLOB))+
          length(CAST(native_outcome AS BLOB))),0),
         coalesce(max(length(CAST(proof_digest AS BLOB))>64 OR
           length(CAST(native_outcome AS BLOB))>9),0) FROM external_death_final",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if final_count > MAX_PENDING_ROWS || final_bytes > MAX_FINAL_ROW_BYTES || oversized != 0 {
        return Err(V25StagingError::Safety(
            "subject decoder final row/byte budget",
        ));
    }
    let mut statement = tx.prepare("SELECT final_rowid,pending_rowid,proof_digest,native_outcome FROM external_death_final ORDER BY final_rowid")?;
    let finals = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut final_subjects = std::collections::BTreeSet::new();
    let mut selected_final = false;
    for (id, pending, digest, outcome) in finals {
        if id <= 0
            || !rows
                .iter()
                .any(|(receipt, _)| receipt.pending_rowid == pending)
            || !final_subjects.insert(pending)
            || outcome != "uncertain"
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(V25StagingError::Safety(
                "subject decoder malformed final linkage",
            ));
        }
        selected_final |= selected == Some(pending);
    }
    Ok(if selected_final {
        SubjectDisposition::FinalRecorded
    } else if selected.is_some() {
        SubjectDisposition::Pending
    } else {
        SubjectDisposition::Live
    })
}

fn decode_pending_state(p: &ActivationPayload) -> Result<V25ActivationMetadata, V25StagingError> {
    let proof = &p.attestation;
    verify_parent_identity(&proof.source_path, proof.parent_identity)?;
    for path in [&proof.source_path, &proof.staging_path] {
        reject_exchange_sidecars(path)?;
    }
    open_exact_private_file(&proof.source_path, proof.staging_identity)?;
    open_exact_private_file(&proof.staging_path, proof.source_identity)?;
    let old = open_exchange_read_only(&proof.staging_path)?;
    verify_integrity(&old)?;
    verify_foreign_keys(&old)?;
    if snapshot(&old)? != proof.source || activation_metadata_rows(&old)? != p.initial_metadata {
        return Err(V25StagingError::Safety(
            "pending decoder preserved v24 baseline differs",
        ));
    }
    let baseline_credential: i64 = old.query_row(
        "SELECT credential_epoch FROM manager_credential_claims WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    drop(old);
    let mut current = open_exchange_read_only(&proof.source_path)?;
    verify_integrity(&current)?;
    verify_foreign_keys(&current)?;
    verify_current_v2_bindings(&current)?;
    let state = snapshot(&current)?;
    if state.version != 25
        || state.lineage != proof.staging.lineage
        || state.schema != canonical_schema(true)?
        || state
            .tables
            .iter()
            .filter(|t| {
                !matches!(
                    t.name.as_str(),
                    "metadata" | "external_death_pending" | "manager_credential_claims"
                )
            })
            .collect::<Vec<_>>()
            != proof
                .staging
                .tables
                .iter()
                .filter(|t| {
                    !matches!(
                        t.name.as_str(),
                        "metadata" | "external_death_pending" | "manager_credential_claims"
                    )
                })
                .collect::<Vec<_>>()
        || state
            .sequences
            .iter()
            .filter(|t| t.table != "external_death_pending")
            .collect::<Vec<_>>()
            != proof
                .staging
                .sequences
                .iter()
                .filter(|t| t.table != "external_death_pending")
                .collect::<Vec<_>>()
    {
        return Err(V25StagingError::Safety(
            "restricted pending decoder authority/schema state differs",
        ));
    }
    let rows = activation_metadata_rows(&current)?;
    if rows.len() != p.initial_metadata.len() {
        return Err(V25StagingError::Safety("pending metadata set differs"));
    }
    let mut owner = 0;
    let mut revision = 0;
    for (row, old) in rows.iter().zip(&p.initial_metadata) {
        if row.rowid != old.rowid
            || row.key != old.key
            || row.value < 0
            || (if matches!(row.key.as_str(), "owner_epoch" | "authority_revision") {
                row.value < old.value
            } else {
                row.value != old.value
            })
        {
            return Err(V25StagingError::Safety(
                "pending metadata rollback/unsupported mutation",
            ));
        }
        if row.key == "owner_epoch" {
            owner = row.value as u64;
        }
        if row.key == "authority_revision" {
            revision = row.value as u64;
        }
    }
    let claim:(String,i64,i64)=current.query_row("SELECT store_lineage,owner_epoch,credential_epoch FROM manager_credential_claims WHERE singleton=1",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
    if owner == 0
        || claim.0 != state.lineage
        || claim.1 != positive(owner)?
        || claim.2 < baseline_credential
        || claim.2 < positive(owner)?
    {
        return Err(V25StagingError::Safety(
            "pending current manager credential claim differs",
        ));
    }
    let tx = current.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let receipts = read_rows(&tx)?;
    if receipts
        .iter()
        .any(|r| r.preparing_owner_epoch > owner || r.preparing_authority_revision > revision)
    {
        return Err(V25StagingError::Safety(
            "pending receipt exceeds current counters",
        ));
    }
    tx.commit()?;
    verify_parent_identity(&proof.source_path, proof.parent_identity)?;
    Ok(V25ActivationMetadata {
        store_lineage: state.lineage,
        owner_epoch: owner,
        authority_revision: revision,
    })
}

fn inspect_state(
    source: &Path,
    staging: &Path,
    migration_key: &str,
    activation_key: &str,
    state_key: &str,
) -> Result<(ActivationPayload, V25ActivationMetadata), V25StagingError> {
    let (path, writing) = paths(source)?;
    refuse_occupied(&writing)?;
    let identity = private_file_identity(&path, false)?;
    let declaration: StateDeclaration = serde_json::from_slice(&bounded_private_bytes(&path)?)?;
    let (activation, _) = activation_paths(source)?;
    if declaration.format != STATE_FORMAT
        || declaration.state_key != state_key
        || declaration.migration_key != migration_key
        || declaration.activation_key != activation_key
        || declaration.declaration_digest != declaration_digest(&declaration)?
        || private_file_identity(&activation, false)? != declaration.activation_identity
        || hex_digest(&bounded_private_bytes(&activation)?) != declaration.activation_bytes_digest
    {
        return Err(V25StagingError::Safety(
            "pending state declaration key/binding differs",
        ));
    }
    let (payload, metadata, _) = read_activation_with_decoder(
        source,
        staging,
        migration_key,
        activation_key,
        decode_pending_state,
    )?;
    if private_file_identity(&path, false)? != identity
        || private_file_identity(&activation, false)? != declaration.activation_identity
        || hex_digest(&bounded_private_bytes(&activation)?) != declaration.activation_bytes_digest
    {
        return Err(V25StagingError::Safety(
            "pending state declaration changed during decode",
        ));
    }
    Ok((payload, metadata))
}

/// Trusted disposable entry only. The host wrapper must maintain the exact lock
/// and closed barrier. The state declaration is fsynced BEFORE prepare is reachable.
pub fn open_disposable_v25_pending(
    source: impl AsRef<Path>,
    staging: impl AsRef<Path>,
    migration_key: &str,
    activation_key: &str,
    state_key: &str,
) -> Result<DisposableV25PendingStore, V25StagingError> {
    use std::io::Write;
    let source = source.as_ref();
    let staging = staging.as_ref();
    intent_paths(source, state_key)?;
    let (path, writing) = paths(source)?;
    refuse_occupied(&writing)?;
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let (p, _) = inspect_state(source, staging, migration_key, activation_key, state_key)?;
            let file = open_exact_private_file(&path, private_file_identity(&path, false)?)?;
            file.sync_all()?;
            pinned_parent_directory(source, p.attestation.parent_identity)?.sync_all()?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let active =
                activate_disposable_schema_v25(source, staging, migration_key, activation_key)?;
            let (proof, _, activation_identity) =
                read_activation(source, staging, migration_key, activation_key)?;
            decode_pending_state(&proof)?;
            let (activation, _) = activation_paths(source)?;
            let mut declaration = StateDeclaration {
                format: STATE_FORMAT.into(),
                state_key: state_key.into(),
                migration_key: migration_key.into(),
                activation_key: activation_key.into(),
                activation_identity,
                activation_bytes_digest: hex_digest(&bounded_private_bytes(&activation)?),
                declaration_digest: String::new(),
            };
            declaration.declaration_digest = declaration_digest(&declaration)?;
            let bytes = serde_json::to_vec(&declaration)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc_no_follow())
                .open(&writing)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            private_file_identity(&writing, false)?;
            let dir = pinned_parent_directory(source, proof.attestation.parent_identity)?;
            rustix::fs::renameat_with(
                &dir,
                writing.file_name().unwrap(),
                &dir,
                path.file_name().unwrap(),
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(std::io::Error::from)?;
            dir.sync_all()?;
            drop(active);
        }
        Err(e) => return Err(e.into()),
    }
    let (p, _) = inspect_state(source, staging, migration_key, activation_key, state_key)?;
    Ok(DisposableV25PendingStore {
        source: source.into(),
        staging: staging.into(),
        migration_key: migration_key.into(),
        activation_key: activation_key.into(),
        state_key: state_key.into(),
        proof: activation_proof_result(p.attestation),
    })
}

impl DisposableV25PendingStore {
    pub fn attested_pair(&self) -> &V25StagingResult {
        &self.proof
    }
    pub fn metadata(&self) -> Result<V25ActivationMetadata, V25StagingError> {
        Ok(inspect_state(
            &self.source,
            &self.staging,
            &self.migration_key,
            &self.activation_key,
            &self.state_key,
        )?
        .1)
    }
    pub fn lookup(
        &self,
        author: &DisposablePendingAuthor,
        r: &ExternalDeathPendingRequest,
    ) -> Result<Option<ExternalDeathPendingReceipt>, V25StagingError> {
        let expected = canonical(author, r)?;
        self.metadata()?;
        let mut c = open_exchange_read_only(&self.source)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let result = lookup(&tx, r, &author.principal, &expected)?;
        tx.commit()?;
        Ok(result)
    }
    pub fn prepare(
        &mut self,
        author: &DisposablePendingAuthor,
        r: &ExternalDeathPendingRequest,
    ) -> Result<ExternalDeathPendingReceipt, V25StagingError> {
        self.prepare_with_hook(author, r, || Ok(()))
    }
    fn prepare_with_hook(
        &mut self,
        author: &DisposablePendingAuthor,
        r: &ExternalDeathPendingRequest,
        after_insert: impl FnOnce() -> Result<(), V25StagingError>,
    ) -> Result<ExternalDeathPendingReceipt, V25StagingError> {
        self.prepare_with_budget(author, r, after_insert, MAX_PENDING_ROWS, MAX_PENDING_BYTES)
    }
    fn prepare_with_budget(
        &mut self,
        author: &DisposablePendingAuthor,
        r: &ExternalDeathPendingRequest,
        after_insert: impl FnOnce() -> Result<(), V25StagingError>,
        max_rows: i64,
        max_bytes: i64,
    ) -> Result<ExternalDeathPendingReceipt, V25StagingError> {
        let bytes = canonical(author, r)?;
        let metadata = self.metadata()?;
        if metadata.store_lineage != r.store_lineage {
            return Err(V25StagingError::Safety("pending lineage differs"));
        }
        let mut connection = Connection::open_with_flags(
            &self.source,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(receipt) = lookup(&tx, r, &author.principal, &bytes)? {
            tx.commit()?;
            return Ok(receipt);
        }
        let actual:(String,i64,i64,String,i64,i64)=tx.query_row("SELECT (SELECT lineage FROM store_identity WHERE singleton=1),(SELECT value FROM metadata WHERE key='owner_epoch'),(SELECT value FROM metadata WHERE key='authority_revision'),(SELECT store_lineage FROM manager_credential_claims WHERE singleton=1),(SELECT owner_epoch FROM manager_credential_claims WHERE singleton=1),(SELECT credential_epoch FROM manager_credential_claims WHERE singleton=1)",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)))?;
        if actual
            != (
                r.store_lineage.clone(),
                positive(r.expected_owner_epoch)?,
                positive(r.expected_authority_revision)?,
                r.store_lineage.clone(),
                positive(r.expected_owner_epoch)?,
                positive(r.expected_manager_credential_epoch)?,
            )
        {
            return Err(V25StagingError::Safety(
                "pending current authority CAS differs",
            ));
        }
        check_owner_author(&tx, &author.principal, &author.scope)?;
        check_subject(&tx, r)?;
        let conflicting:i64=tx.query_row("SELECT count(*) FROM external_death_pending WHERE store_lineage=?1 AND scope_id=?2 AND pod_id=?3 AND pod_incarnation=?4",params![r.store_lineage,r.scope_id,r.pod_id,positive(r.pod_incarnation)?],|row|row.get(0))?;
        let uncertain:i64=tx.query_row("SELECT count(*) FROM outbox o LEFT JOIN events e ON e.sequence=o.observation_event_sequence AND e.command_rowid=o.command_rowid AND e.scope_id=o.scope_id AND e.target_id=o.target_id WHERE o.scope_id=?1 AND o.target_id=?2 AND o.target_epoch=?3 AND o.kind IN ('pod.offer','pod.stop') AND (o.state!='observed' OR o.claim_key IS NULL OR length(o.claim_key)=0 OR o.claim_owner_epoch IS NULL OR o.claim_owner_epoch<=0 OR o.observation_stage IS NULL OR o.observation_key IS NULL OR length(o.observation_key)=0 OR o.observation_payload IS NULL OR length(o.observation_payload)=0 OR e.sequence IS NULL OR e.target_epoch!=o.target_epoch OR e.owner_epoch<=0 OR e.owner_epoch<o.claim_owner_epoch OR e.owner_epoch>?4 OR (o.kind='pod.offer' AND (o.observation_stage!='host_accepted' OR e.kind!='effect.host_accepted' OR e.provenance!='authenticated.host.acceptance')) OR (o.kind='pod.stop' AND (o.observation_stage!='pod_stopped' OR e.kind!='pod.stopped' OR e.provenance!='authenticated.manager.stop')))",params![r.scope_id,r.pod_id,positive(r.pod_incarnation)?,positive(r.expected_owner_epoch)?],|row|row.get(0))?;
        if conflicting != 0 || uncertain != 0 {
            return Err(V25StagingError::Safety(
                "pending conflict or unresolved original launch/stop",
            ));
        }
        let (count, total_bytes): (i64,i64) = tx.query_row("SELECT count(*),coalesce(sum(length(canonical_request)),0) FROM external_death_pending", [], |row| Ok((row.get(0)?,row.get(1)?)))?;
        let prospective_count = count
            .checked_add(1)
            .ok_or(V25StagingError::Safety("pending count arithmetic overflow"))?;
        let new_bytes = i64::try_from(bytes.len())
            .map_err(|_| V25StagingError::Safety("pending request byte arithmetic overflow"))?;
        let prospective_bytes =
            total_bytes
                .checked_add(new_bytes)
                .ok_or(V25StagingError::Safety(
                    "pending total byte arithmetic overflow",
                ))?;
        if prospective_count > max_rows || prospective_bytes > max_bytes {
            return Err(V25StagingError::Safety(
                "pending prospective decoder budget exceeded",
            ));
        }
        let next = r
            .expected_authority_revision
            .checked_add(1)
            .ok_or(V25StagingError::InvalidInput("pending revision exhausted"))?;
        let next_sql = positive(next)?;
        let digest = hex_digest(&bytes);
        tx.execute("INSERT INTO external_death_pending(recovery_key,store_lineage,scope_id,pod_id,pod_incarnation,launch_command_rowid,activated_rebind_rowid,preparing_owner_epoch,preparing_authority_revision,authenticated_author,request_version,canonical_request,request_digest) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",params![r.recovery_key,r.store_lineage,r.scope_id,r.pod_id,positive(r.pod_incarnation)?,r.launch_command_rowid,r.activated_rebind_rowid,positive(r.expected_owner_epoch)?,next_sql,author.principal,REQUEST_VERSION,bytes,digest])?;
        let rowid = tx.last_insert_rowid();
        after_insert()?;
        if tx.execute(
            "UPDATE metadata SET value=?1 WHERE key='authority_revision' AND value=?2",
            params![next_sql, positive(r.expected_authority_revision)?],
        )? != 1
        {
            return Err(V25StagingError::Safety("pending revision compare lost"));
        }
        tx.commit()?;
        Ok(ExternalDeathPendingReceipt {
            pending_rowid: rowid,
            recovery_key: r.recovery_key.clone(),
            authenticated_author: author.principal.clone(),
            request_digest: digest,
            preparing_owner_epoch: r.expected_owner_epoch,
            preparing_authority_revision: next,
        })
    }
}
fn lookup(
    tx: &Transaction<'_>,
    r: &ExternalDeathPendingRequest,
    author: &str,
    bytes: &[u8],
) -> Result<Option<ExternalDeathPendingReceipt>, V25StagingError> {
    // Validate numeric byte budgets in this snapshot before the exact-key
    // lookup materializes its pending TEXT/BLOB fields.
    let receipts = read_rows(tx)?;
    let raw:Option<(String,Vec<u8>,String)>=tx.query_row("SELECT authenticated_author,canonical_request,request_digest FROM external_death_pending WHERE recovery_key=?1",[&r.recovery_key],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.0 != author || raw.1 != bytes || raw.2 != hex_digest(bytes) {
        return Err(V25StagingError::Safety(
            "pending historical key changed author/request",
        ));
    }
    Ok(receipts
        .into_iter()
        .find(|row| row.recovery_key == r.recovery_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use podbay_core::{
        ActorId, Attempt, AttemptId, Epoch, LaunchBinding, Pod, PodId, Resource, ResourceId,
        ResourceKind, Role, Run, RunId, ScopeId, Session, SessionId, WorkKind,
    };
    use podbay_wire::{EffectiveLaunchContractV2, ImmutableLaunchDescriptorV2};
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    struct Fixture {
        directory: PathBuf,
        source: PathBuf,
        staging: PathBuf,
        request: ExternalDeathPendingRequest,
    }
    impl Fixture {
        fn new(variant: &str) -> Self {
            let directory = std::env::temp_dir().join(format!(
                "podbay-v25-pending-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            let source = directory.join("podbay.sqlite");
            let staging = directory.join("old.sqlite");
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&source)
                .unwrap();
            let mut store = PodBayStore::open(&source).unwrap();
            store.advance_owner_epoch(0, 1).unwrap();
            let scope = ScopeId::try_from("scope.launch").unwrap();
            let mut session = Session::new(
                SessionId::try_from("session.codex.fixture").unwrap(),
                ActorId::try_from("actor.codex.fixture").unwrap(),
                scope.clone(),
            );
            let run = Run::new(
                RunId::try_from("run.codex.fixture").unwrap(),
                &session,
                Role::Coordinator,
                WorkKind::Service,
                None,
            );
            session.bind_run(session.revision(), &run).unwrap();
            let mut attempt = Attempt::new(
                AttemptId::try_from("attempt.codex.fixture").unwrap(),
                run.id().clone(),
                1,
                Epoch::new(1).unwrap(),
            )
            .unwrap();
            let mut pod = Pod::new(
                PodId::try_from("pod.launch").unwrap(),
                attempt.id().clone(),
                Epoch::new(1).unwrap(),
            );
            attempt.attach_pod(attempt.revision(), &pod).unwrap();
            let resource = Resource::new(
                ResourceId::try_from("resource.codex.fixture").unwrap(),
                pod.id().clone(),
                ResourceKind::StructuredProvider,
                Epoch::new(1).unwrap(),
            );
            pod.attach_resource(pod.revision(), &resource).unwrap();
            let planned =
                LaunchBinding::plan_first_root(&session, &run, &attempt, &pod, &[resource])
                    .unwrap();
            let hex = include_str!("../../podbay-wire/tests/effective_launch_v2.hex")
                .split_whitespace()
                .collect::<String>();
            let effective = EffectiveLaunchContractV2::decode(
                &(0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            let descriptor = ImmutableLaunchDescriptorV2::decode_json(
                include_str!("../../podbay-wire/tests/launch_descriptor_v2.json")
                    .trim_end()
                    .as_bytes(),
            )
            .unwrap();
            store
                .admit_bound_root_launch_v2(crate::BoundRootLaunchRequestV2 {
                    principal: crate::VerifiedPrincipal::from_authenticated_boundary(
                        "principal.codex.fixture",
                    )
                    .unwrap(),
                    command_key: "launch.fixture",
                    canonical_intent: b"fixture exact launch",
                    scope_id: "scope.launch",
                    pod_id: "pod.launch",
                    proposal: Some(crate::BoundRootLaunchProposalV2 {
                        session: &session,
                        run: &run,
                        binding: &planned,
                        effective_spec: &effective,
                        descriptor: &descriptor,
                        expected_owner_epoch: 1,
                        expected_authority_revision: 0,
                    }),
                })
                .unwrap();
            store.begin_authority_replay(1, 2).unwrap();
            // The private fixture models an authenticated original launch settlement.
            let revision = store.authority_snapshot().unwrap().revision;
            store
                .claim_effect(
                    1,
                    "scope.launch",
                    "pod.launch",
                    2,
                    1,
                    revision,
                    "claim.launch",
                )
                .unwrap();
            let proof = crate::HostAcceptanceProof::from_authenticated_host_boundary(
                "host.fixture",
                2,
                1,
                "receipt.fixture",
                b"disposable trusted host",
                None,
                "correlation.fixture",
                None,
            )
            .unwrap();
            if variant == "late_observation" {
                store.begin_authority_replay(2, 3).unwrap();
            }
            let observing_owner = store.owner_epoch().unwrap();
            store
                .observe_effect(
                    1,
                    "scope.launch",
                    "pod.launch",
                    observing_owner,
                    1,
                    "claim.launch",
                    &proof,
                )
                .unwrap();
            if variant == "raw_witness" {
                let claim = store
                    .current_manager_credential_claim(observing_owner)
                    .unwrap();
                store
                    .register_current_manager_peer(&claim, &raw_witness_peer())
                    .unwrap();
            }
            drop(store);
            let c = Connection::open(&source).unwrap();
            c.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=DELETE; UPDATE metadata SET value=5 WHERE key='authority_revision'; INSERT INTO authority_actors(actor_id,scope_id,role,origin,credential_generation,platform,os_identity,process_identity,start_identity,containment_identity) VALUES('owner.fixture','scope.launch','coordinator','owner_cli',1,'linux','linux.uid.1000','linux.pid.100',100,'/fixture');").unwrap();
            let lineage: String = c
                .query_row(
                    "SELECT lineage FROM store_identity WHERE singleton=1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            c.execute("INSERT INTO manager_rebinds(rebind_rowid,store_lineage,scope_id,pod_id,attempt_id,pod_incarnation,expected_owner_epoch,next_owner_epoch,expected_credential_epoch,next_credential_epoch,manager_os_identity,manager_process_id,manager_boot_identity,manager_birth_identity,manager_containment,command_key,request_digest,resource_count,phase,pod_checkpoint_ref) VALUES(1,?1,'scope.launch','pod.launch','attempt.codex.fixture',1,1,2,1,2,'uid:1000','pid:100','boot.old','birth.100','unit.fixture','rebind.fixture',?2,1,'activated',?3)",params![lineage,"a".repeat(64),"b".repeat(64)]).unwrap();
            c.execute(
                "INSERT INTO manager_rebind_resources VALUES(1,'resource.codex.fixture',1,2)",
                [],
            )
            .unwrap();
            c.execute("INSERT INTO manager_rebind_prior_observations VALUES(1,'podbay.prior-checkpoint/1',?1,100,200,'boot.old','fixture.service','/fixture')",["b".repeat(64)]).unwrap();
            // Independent native uncertainty must remain unknown through pending prepare.
            c.execute("INSERT INTO commands(command_rowid,command_id,principal,namespace,command_key,scope_id,target_id,digest_version,request_digest,canonical_request,owner_epoch,target_epoch) VALUES(2,'native.unknown','fixture','native.fixture','unknown','scope.launch','pod.launch','sha256',?1,X'01',2,1)",["c".repeat(64)]).unwrap();
            c.execute("INSERT INTO outbox(outbox_id,command_rowid,scope_id,target_id,owner_epoch,target_epoch,kind,payload,state,claim_key,claim_owner_epoch,effect_digest) VALUES(2,2,'scope.launch','pod.launch',2,1,'native.send',X'01','claimed_uncertain','native.claim',2,?1)",["d".repeat(64)]).unwrap();
            match variant {
                "target_epoch" => {
                    c.execute("UPDATE events SET target_epoch=2 WHERE sequence=(SELECT observation_event_sequence FROM outbox WHERE outbox_id=1)", []).unwrap();
                }
                "observation_owner_low" => {
                    c.execute("UPDATE events SET owner_epoch=1 WHERE sequence=(SELECT observation_event_sequence FROM outbox WHERE outbox_id=1)", []).unwrap();
                }
                "observation_owner_high" => {
                    c.execute("UPDATE events SET owner_epoch=99 WHERE sequence=(SELECT observation_event_sequence FROM outbox WHERE outbox_id=1)", []).unwrap();
                }
                "empty_claim_key" => {
                    c.execute("UPDATE outbox SET claim_key='' WHERE outbox_id=1", [])
                        .unwrap();
                }
                "empty_observation_key" => {
                    c.execute("UPDATE outbox SET observation_key='' WHERE outbox_id=1", [])
                        .unwrap();
                }
                "credential_ahead" => {
                    c.execute(
                        "UPDATE manager_rebinds SET next_credential_epoch=99 WHERE rebind_rowid=1",
                        [],
                    )
                    .unwrap();
                }
                "late_observation" => {
                    c.execute("UPDATE manager_rebinds SET next_owner_epoch=3,next_credential_epoch=3 WHERE rebind_rowid=1", []).unwrap();
                    c.execute("UPDATE manager_rebind_resources SET next_input_epoch=3 WHERE rebind_rowid=1", []).unwrap();
                }
                "phase" => {
                    c.execute(
                        "UPDATE manager_rebinds SET phase='pod_acknowledged' WHERE rebind_rowid=1",
                        [],
                    )
                    .unwrap();
                }
                "prior" => {
                    c.execute("DELETE FROM manager_rebind_prior_observations", [])
                        .unwrap();
                    c.execute(
                        "UPDATE manager_rebinds SET phase='pod_acknowledged' WHERE rebind_rowid=1",
                        [],
                    )
                    .unwrap();
                }
                "unverified_observed" => {
                    c.execute(
                        "UPDATE outbox SET observation_stage=NULL WHERE outbox_id=1",
                        [],
                    )
                    .unwrap();
                }
                "claimed_launch" => {
                    c.execute("UPDATE outbox SET state='claimed_uncertain',observation_key=NULL,observation_payload=NULL,observation_stage=NULL,observation_event_sequence=NULL WHERE outbox_id=1",[]).unwrap();
                }
                "later" | "later_activated" | "later_lower_epoch" => {
                    c.execute("INSERT INTO manager_rebinds(store_lineage,scope_id,pod_id,attempt_id,pod_incarnation,expected_owner_epoch,next_owner_epoch,expected_credential_epoch,next_credential_epoch,manager_os_identity,manager_process_id,manager_boot_identity,manager_birth_identity,manager_containment,command_key,request_digest,resource_count,phase) SELECT store_lineage,scope_id,pod_id,attempt_id,pod_incarnation,2,3,2,3,manager_os_identity,manager_process_id,manager_boot_identity,manager_birth_identity,manager_containment,'later',request_digest,resource_count,'pending' FROM manager_rebinds WHERE rebind_rowid=1",[]).unwrap();
                    if matches!(variant, "later_activated" | "later_lower_epoch") {
                        c.execute("UPDATE manager_rebinds SET phase='activated',pod_checkpoint_ref=?1 WHERE rebind_rowid=2", ["b".repeat(64)]).unwrap();
                        c.execute("INSERT INTO manager_rebind_prior_observations SELECT 2,schema_version,checkpoint_digest,supervisor_pid,supervisor_start_ticks,boot_id,unit_name,cgroup_path FROM manager_rebind_prior_observations WHERE rebind_rowid=1", []).unwrap();
                    }
                    if variant == "later_lower_epoch" {
                        c.execute(
                            "UPDATE manager_rebinds SET next_owner_epoch=4 WHERE rebind_rowid=2",
                            [],
                        )
                        .unwrap();
                        c.execute("UPDATE manager_rebinds SET expected_owner_epoch=1,next_owner_epoch=3 WHERE rebind_rowid=1", []).unwrap();
                        c.execute("UPDATE manager_rebinds SET expected_owner_epoch=1,next_owner_epoch=2 WHERE rebind_rowid=2", []).unwrap();
                        c.execute_batch("UPDATE metadata SET value=3 WHERE key='owner_epoch'; UPDATE manager_credential_claims SET owner_epoch=3,credential_epoch=3;").unwrap();
                    }
                }
                "baseline_credential" => {
                    c.execute(
                        "UPDATE manager_credential_claims SET credential_epoch=5",
                        [],
                    )
                    .unwrap();
                }
                "extra_resource" => {
                    c.execute("INSERT INTO authority_resources VALUES('foreign.resource','foreign.scope','pod.launch',1,1,2)", []).unwrap();
                }
                "supersession" => {
                    c.execute("INSERT INTO rebind_supersession_attempts(store_lineage,scope_id,pod_id,attempt_id,pod_incarnation,abandoned_rebind_rowid,abandoned_request_digest,abandoned_phase,abandoned_checkpoint_ref,prior_active_checkpoint_digest,observed_phase,observed_checkpoint_digest,supervisor_process_id,supervisor_birth_identity,child_process_id,child_birth_identity,boot_identity,unit_name,cgroup_path,recovering_owner_epoch,recovering_credential_epoch,recovering_os_identity,recovering_process_id,recovering_boot_identity,recovering_birth_identity,recovering_containment,command_key,request_digest,intent_bytes,resource_count,phase) SELECT store_lineage,scope_id,pod_id,attempt_id,pod_incarnation,rebind_rowid,request_digest,phase,pod_checkpoint_ref,pod_checkpoint_ref,'active_prior',pod_checkpoint_ref,'100','200','101','201','boot.old','fixture.service','/fixture',3,3,'uid:1000','pid:200','boot.new','birth.200','/fixture','supersede',request_digest,zeroblob(64),1,'planned' FROM manager_rebinds WHERE rebind_rowid=1", []).unwrap();
                }
                "author_role" => {
                    c.execute(
                        "UPDATE authority_actors SET role='worker' WHERE actor_id='owner.fixture'",
                        [],
                    )
                    .unwrap();
                }
                _ => {}
            }
            let claim_credential: u64 = c
                .query_row(
                    "SELECT credential_epoch FROM manager_credential_claims WHERE singleton=1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap() as u64;
            let current_input: u64 = c.query_row("SELECT input_epoch FROM authority_resources WHERE resource_id='resource.codex.fixture'", [], |row| row.get::<_,i64>(0)).unwrap() as u64;
            let owner_epoch: u64 = c
                .query_row(
                    "SELECT value FROM metadata WHERE key='owner_epoch'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap() as u64;
            let request = ExternalDeathPendingRequest {
                recovery_key: "recover.one".into(),
                store_lineage: lineage,
                scope_id: "scope.launch".into(),
                pod_id: "pod.launch".into(),
                pod_incarnation: 1,
                session_id: "session.codex.fixture".into(),
                run_id: "run.codex.fixture".into(),
                attempt_id: "attempt.codex.fixture".into(),
                launch_command_rowid: 1,
                activated_rebind_rowid: 1,
                checkpoint_digest: "b".repeat(64),
                resources: vec![PendingResourceBinding {
                    resource_id: "resource.codex.fixture".into(),
                    resource_epoch: 1,
                    input_epoch: current_input,
                }],
                expected_owner_epoch: owner_epoch,
                expected_manager_credential_epoch: claim_credential,
                expected_authority_revision: 5,
            };
            drop(c);
            let staged = stage_schema_v25(&source, &staging).unwrap();
            staged.persist_exchange_intent("migration.one").unwrap();
            let dir = File::open(&directory).unwrap();
            rustix::fs::renameat_with(
                &dir,
                source.file_name().unwrap(),
                &dir,
                staging.file_name().unwrap(),
                rustix::fs::RenameFlags::EXCHANGE,
            )
            .unwrap();
            persist_schema_v25_receipt(&source, &staging, "migration.one").unwrap();
            activate_disposable_schema_v25(&source, &staging, "migration.one", "activation.one")
                .unwrap();
            Self {
                directory,
                source,
                staging,
                request,
            }
        }
        fn open(&self) -> DisposableV25PendingStore {
            open_disposable_v25_pending(
                &self.source,
                &self.staging,
                "migration.one",
                "activation.one",
                "pending.state",
            )
            .unwrap()
        }
        fn author(&self) -> DisposablePendingAuthor {
            DisposablePendingAuthor {
                principal: "owner.fixture".into(),
                scope: "scope.launch".into(),
            }
        }
        fn counts(&self) -> (i64, i64) {
            let c = open_exchange_read_only(&self.source).unwrap();
            (
                c.query_row("SELECT count(*) FROM external_death_pending", [], |r| {
                    r.get(0)
                })
                .unwrap(),
                c.query_row(
                    "SELECT value FROM metadata WHERE key='authority_revision'",
                    [],
                    |r| r.get(0),
                )
                .unwrap(),
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
    fn raw_witness_peer() -> podbay_core::AttestedPeer {
        podbay_core::AttestedPeer::from_port(
            "uid:1000",
            "pid:100",
            "boot.old",
            "birth.100",
            "unit.fixture",
        )
        .unwrap()
    }

    fn assert_disposition_unchanged(
        f: &Fixture,
        subject: &ExternalDeathPendingRequest,
        expected: SubjectDisposition,
    ) {
        let mut c = Connection::open(&f.source).unwrap();
        let before = snapshot(&c).unwrap();
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(subject_disposition(&tx, subject), expected);
        assert_eq!(tx.total_changes(), 0, "decoder must execute no mutations");
        tx.commit().unwrap();
        assert_eq!(snapshot(&c).unwrap(), before);
        let uncertainty: (String, String, i64) = c
            .query_row(
                "SELECT state,claim_key,claim_owner_epoch FROM outbox WHERE outbox_id=2",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            uncertainty,
            ("claimed_uncertain".into(), "native.claim".into(), 2)
        );
    }

    #[test]
    fn subject_decoder_live_pending_and_final_are_read_only_store_facts() {
        let f = Fixture::new("");
        assert_disposition_unchanged(&f, &f.request, SubjectDisposition::Live);
        let receipt = f.open().prepare(&f.author(), &f.request).unwrap();
        assert_disposition_unchanged(&f, &f.request, SubjectDisposition::Pending);
        // Passive exact history survives counters advancing; this is no claim.
        let c = Connection::open(&f.source).unwrap();
        c.execute_batch("UPDATE metadata SET value=3 WHERE key='owner_epoch'; UPDATE metadata SET value=7 WHERE key='authority_revision'; UPDATE manager_credential_claims SET owner_epoch=3,credential_epoch=3;").unwrap();
        drop(c);
        assert_eq!(
            f.open().lookup(&f.author(), &f.request).unwrap(),
            Some(receipt.clone())
        );
        assert_disposition_unchanged(&f, &f.request, SubjectDisposition::Pending);
        let c = Connection::open(&f.source).unwrap();
        c.execute("INSERT INTO external_death_final(pending_rowid,proof_digest,native_outcome) VALUES(?1,?2,'uncertain')", params![receipt.pending_rowid, "a".repeat(64)]).unwrap();
        drop(c);
        // This arbitrary shaped digest is deliberately NOT authenticated death.
        assert_disposition_unchanged(&f, &f.request, SubjectDisposition::FinalRecorded);
    }

    #[test]
    fn subject_decoder_exact_stored_binding_never_accepts_caller_fields_alone() {
        let f = Fixture::new("");
        for change in [
            "lineage",
            "scope",
            "pod",
            "incarnation",
            "session",
            "run",
            "attempt",
            "launch",
            "rebind",
            "checkpoint",
            "resource",
            "input",
            "owner",
            "revision",
            "credential",
        ] {
            let mut subject = f.request.clone();
            match change {
                "lineage" => subject.store_lineage = "foreign".into(),
                "scope" => subject.scope_id = "foreign".into(),
                "pod" => subject.pod_id = "foreign".into(),
                "incarnation" => subject.pod_incarnation += 1,
                "session" => subject.session_id = "foreign".into(),
                "run" => subject.run_id = "foreign".into(),
                "attempt" => subject.attempt_id = "foreign".into(),
                "launch" => subject.launch_command_rowid = 2,
                "rebind" => subject.activated_rebind_rowid = 2,
                "checkpoint" => subject.checkpoint_digest = "c".repeat(64),
                "resource" => subject.resources[0].resource_epoch += 1,
                "input" => subject.resources[0].input_epoch += 1,
                "owner" => subject.expected_owner_epoch = 99,
                "revision" => subject.expected_authority_revision = 99,
                "credential" => subject.expected_manager_credential_epoch = 99,
                _ => unreachable!(),
            }
            assert_disposition_unchanged(&f, &subject, SubjectDisposition::Unverified);
        }
    }

    #[test]
    fn subject_decoder_malformed_pending_final_and_schema_default_closed() {
        for change in [
            "author",
            "digest",
            "version",
            "bytes",
            "pending_lineage",
            "pending_counter",
            "resource_binding",
            "ddl",
            "missing_pending",
            "missing_final",
            "user_version",
            "orphan_final",
            "final_digest",
            "final_outcome",
            "pending_rows",
            "pending_bytes",
            "final_rows",
            "final_bytes",
            "author_role",
            "duplicate_subject",
        ] {
            let f = Fixture::new("");
            f.open().prepare(&f.author(), &f.request).unwrap();
            let c = Connection::open(&f.source).unwrap();
            c.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON;")
                .unwrap();
            match change {
                "author_role" => {
                    c.execute(
                        "UPDATE authority_actors SET role='worker' WHERE actor_id='owner.fixture'",
                        [],
                    )
                    .unwrap();
                }
                "final_bytes" => {
                    c.execute("INSERT INTO external_death_final(pending_rowid,proof_digest,native_outcome) VALUES(1,?1,'uncertain')", ["a".repeat(MAX_PENDING_BYTES as usize + 1)]).unwrap();
                }
                "author" => {
                    c.execute(
                        "UPDATE external_death_pending SET authenticated_author='foreign'",
                        [],
                    )
                    .unwrap();
                }
                "digest" => {
                    c.execute(
                        "UPDATE external_death_pending SET request_digest=?1",
                        ["0".repeat(64)],
                    )
                    .unwrap();
                }
                "version" => {
                    c.execute(
                        "UPDATE external_death_pending SET request_version='future/2'",
                        [],
                    )
                    .unwrap();
                }
                "bytes" => {
                    c.execute("UPDATE external_death_pending SET canonical_request=CAST(canonical_request||' ' AS BLOB)", []).unwrap();
                }
                "pending_lineage" => {
                    c.execute(
                        "UPDATE external_death_pending SET store_lineage='foreign'",
                        [],
                    )
                    .unwrap();
                }
                "pending_counter" => {
                    c.execute(
                        "UPDATE metadata SET value=5 WHERE key='authority_revision'",
                        [],
                    )
                    .unwrap();
                }
                "resource_binding" => {
                    c.execute(
                        "UPDATE authority_resources SET input_epoch=input_epoch+1",
                        [],
                    )
                    .unwrap();
                }
                "ddl" => c
                    .execute_batch("CREATE TABLE unexpected(value INTEGER) STRICT")
                    .unwrap(),
                "missing_pending" => c
                    .execute_batch("DROP TABLE external_death_pending")
                    .unwrap(),
                "missing_final" => c.execute_batch("DROP TABLE external_death_final").unwrap(),
                "user_version" => c.execute_batch("PRAGMA user_version=24").unwrap(),
                "orphan_final" => {
                    c.execute("INSERT INTO external_death_final(pending_rowid,proof_digest,native_outcome) VALUES(99,?1,'uncertain')", ["a".repeat(64)]).unwrap();
                }
                "final_digest" => {
                    c.execute("INSERT INTO external_death_final(pending_rowid,proof_digest,native_outcome) VALUES(1,'malformed','uncertain')", []).unwrap();
                }
                "final_outcome" => {
                    c.execute("INSERT INTO external_death_final(pending_rowid,proof_digest,native_outcome) VALUES(1,?1,'settled')", ["a".repeat(64)]).unwrap();
                }
                "pending_rows" | "duplicate_subject" => {
                    let count = if change == "pending_rows" {
                        MAX_PENDING_ROWS
                    } else {
                        1
                    };
                    for n in 0..count {
                        c.execute("INSERT INTO external_death_pending(recovery_key,store_lineage,scope_id,pod_id,pod_incarnation,launch_command_rowid,activated_rebind_rowid,preparing_owner_epoch,preparing_authority_revision,authenticated_author,request_version,canonical_request,request_digest) SELECT ?1,store_lineage,scope_id,pod_id,pod_incarnation,launch_command_rowid,?2,preparing_owner_epoch,preparing_authority_revision,authenticated_author,request_version,canonical_request,request_digest FROM external_death_pending WHERE pending_rowid=1", params![format!("copy.{n}"), n+2]).unwrap();
                    }
                }
                "pending_bytes" => {
                    c.execute(
                        "UPDATE external_death_pending SET canonical_request=zeroblob(?1)",
                        [MAX_PENDING_BYTES + 1],
                    )
                    .unwrap();
                }
                "final_rows" => {
                    for n in 0..=MAX_PENDING_ROWS {
                        c.execute("INSERT INTO external_death_final(pending_rowid,proof_digest,native_outcome) VALUES(?1,?2,'uncertain')", params![n+1, "a".repeat(64)]).unwrap();
                    }
                }
                _ => unreachable!(),
            }
            drop(c);
            assert_disposition_unchanged(&f, &f.request, SubjectDisposition::Unverified);
        }
    }

    #[test]
    fn subject_decoder_text_byte_budgets_refuse_before_materialization() {
        let f = Fixture::new("");
        f.open().prepare(&f.author(), &f.request).unwrap();
        let mut c = Connection::open(&f.source).unwrap();
        c.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON;")
            .unwrap();
        let before = snapshot(&c).unwrap();
        for (column, maximum) in [
            ("recovery_key", 256),
            ("store_lineage", 256),
            ("scope_id", 256),
            ("pod_id", 256),
            ("authenticated_author", 256),
            ("request_version", REQUEST_VERSION.len()),
            ("request_digest", 64),
        ] {
            for nul_tail in [true, false] {
                let value = if nul_tail {
                    format!("a\0{}", "a".repeat(maximum))
                } else {
                    "é".repeat(maximum)
                };
                let tx = c.transaction().unwrap();
                tx.execute(
                    &format!("UPDATE external_death_pending SET {column}=?1"),
                    [&value],
                )
                .unwrap();
                // Demonstrate the old character check would admit this value.
                let (characters, bytes): (i64, i64) = tx.query_row(
                    &format!("SELECT length({column}),length(CAST({column} AS BLOB)) FROM external_death_pending"),
                    [], |row| Ok((row.get(0)?, row.get(1)?)),
                ).unwrap();
                assert!(characters <= maximum as i64 && bytes > maximum as i64);
                let changes = tx.total_changes();
                assert!(
                    matches!(
                        decode_subject_disposition(&tx, &f.request),
                        Err(V25StagingError::Safety("pending decoder row/byte budget"))
                    ),
                    "{column}, NUL tail={nul_tail}: must refuse at numeric preflight before String decoding"
                );
                assert!(
                    matches!(
                        lookup(
                            &tx,
                            &f.request,
                            "owner.fixture",
                            &canonical(&f.author(), &f.request).unwrap()
                        ),
                        Err(V25StagingError::Safety("pending decoder row/byte budget"))
                    ),
                    "exact-key lookup must also preflight before materialization"
                );
                assert_eq!(
                    subject_disposition(&tx, &f.request),
                    SubjectDisposition::Unverified
                );
                assert_eq!(tx.total_changes(), changes);
                tx.rollback().unwrap();
            }
        }
        for (column, maximum) in [("proof_digest", 64), ("native_outcome", 9)] {
            for nul_tail in [true, false] {
                let value = if nul_tail {
                    format!("a\0{}", "a".repeat(maximum))
                } else {
                    "é".repeat(maximum)
                };
                let tx = c.transaction().unwrap();
                tx.execute("INSERT INTO external_death_final(pending_rowid,proof_digest,native_outcome) VALUES(1,?1,'uncertain')", ["a".repeat(64)]).unwrap();
                tx.execute(
                    &format!("UPDATE external_death_final SET {column}=?1"),
                    [&value],
                )
                .unwrap();
                let (characters, bytes): (i64, i64) = tx.query_row(
                    &format!("SELECT length({column}),length(CAST({column} AS BLOB)) FROM external_death_final"),
                    [], |row| Ok((row.get(0)?, row.get(1)?)),
                ).unwrap();
                assert!(characters <= maximum as i64 && bytes > maximum as i64);
                let changes = tx.total_changes();
                assert!(
                    matches!(
                        decode_subject_disposition(&tx, &f.request),
                        Err(V25StagingError::Safety(
                            "subject decoder final row/byte budget"
                        ))
                    ),
                    "{column}, NUL tail={nul_tail}: must refuse at numeric preflight before String decoding"
                );
                assert_eq!(
                    subject_disposition(&tx, &f.request),
                    SubjectDisposition::Unverified
                );
                assert_eq!(tx.total_changes(), changes);
                tx.rollback().unwrap();
            }
        }
        assert_eq!(snapshot(&c).unwrap(), before);
    }

    #[test]
    fn subject_decoder_reads_callers_transaction_and_rollback_preserves_history() {
        let f = Fixture::new("");
        let mut c = Connection::open(&f.source).unwrap();
        let before = snapshot(&c).unwrap();
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            subject_disposition(&tx, &f.request),
            SubjectDisposition::Live
        );
        let bytes = canonical(&f.author(), &f.request).unwrap();
        tx.execute("INSERT INTO external_death_pending(recovery_key,store_lineage,scope_id,pod_id,pod_incarnation,launch_command_rowid,activated_rebind_rowid,preparing_owner_epoch,preparing_authority_revision,authenticated_author,request_version,canonical_request,request_digest) VALUES('recover.one',?1,'scope.launch','pod.launch',1,1,1,2,6,'owner.fixture',?2,?3,?4)", params![f.request.store_lineage, REQUEST_VERSION, &bytes, hex_digest(&bytes)]).unwrap();
        tx.execute(
            "UPDATE metadata SET value=6 WHERE key='authority_revision'",
            [],
        )
        .unwrap();
        assert_eq!(
            subject_disposition(&tx, &f.request),
            SubjectDisposition::Pending,
            "must see uncommitted caller snapshot, not a filesystem reopen"
        );
        let (started, start_rx) = std::sync::mpsc::channel();
        let (finished, finish_rx) = std::sync::mpsc::channel();
        let source = f.source.clone();
        let writer = std::thread::spawn(move || {
            let c = Connection::open(source).unwrap();
            c.busy_timeout(std::time::Duration::ZERO).unwrap();
            started.send(()).unwrap();
            finished
                .send(
                    c.execute(
                        "UPDATE metadata SET value=99 WHERE key='authority_revision'",
                        [],
                    )
                    .unwrap_err(),
                )
                .unwrap();
        });
        start_rx.recv().unwrap();
        let error = finish_rx.recv().unwrap();
        assert!(
            matches!(error, rusqlite::Error::SqliteFailure(ref failure, _) if failure.code == rusqlite::ErrorCode::DatabaseBusy)
        );
        writer.join().unwrap();
        tx.rollback().unwrap();
        assert_eq!(snapshot(&c).unwrap(), before);
        assert_disposition_unchanged(&f, &f.request, SubjectDisposition::Live);
    }

    #[test]
    fn raw_witnesses_refuse_disposable_v25_before_and_after_pending() {
        use crate::{SqliteManagerPeerWitness, SqliteOwnerEpochWitness};
        use podbay_core::{OwnerEpoch, OwnerEpochWitness, PodFenceIdentity, StoreLineageId};

        let f = Fixture::new("raw_witness");
        let identity = PodFenceIdentity {
            store_lineage: StoreLineageId::try_from(f.request.store_lineage.as_str()).unwrap(),
            scope_id: ScopeId::try_from(f.request.scope_id.as_str()).unwrap(),
            pod_id: PodId::try_from(f.request.pod_id.as_str()).unwrap(),
            attempt_id: AttemptId::try_from(f.request.attempt_id.as_str()).unwrap(),
            incarnation: Epoch::new(f.request.pod_incarnation).unwrap(),
        };
        // Exchange preserved the genuine v24 store with the same authority
        // rows. Those rows remain sufficient proof only in the supported store.
        let old_owner = SqliteOwnerEpochWitness::for_pod(&f.staging, identity.clone());
        let old_manager = SqliteManagerPeerWitness::for_pod(&f.staging, identity.clone());
        assert_eq!(
            old_owner.current_owner_epoch(&identity.store_lineage, &identity.scope_id),
            Some(OwnerEpoch::new(f.request.expected_owner_epoch).unwrap())
        );
        assert!(old_manager.matches_current(
            f.request.expected_owner_epoch,
            f.request.expected_manager_credential_epoch,
            &raw_witness_peer()
        ));

        let owner = SqliteOwnerEpochWitness::for_pod(&f.source, identity.clone());
        let manager = SqliteManagerPeerWitness::for_pod(&f.source, identity.clone());
        for pending in [false, true] {
            if pending {
                f.open().prepare(&f.author(), &f.request).unwrap();
            }
            assert_eq!(
                owner.current_owner_epoch(&identity.store_lineage, &identity.scope_id),
                None
            );
            assert!(!manager.matches_current(
                f.request.expected_owner_epoch,
                f.request.expected_manager_credential_epoch,
                &raw_witness_peer()
            ));
            assert_eq!(f.counts(), if pending { (1, 6) } else { (0, 5) });
            let c = open_exchange_read_only(&f.source).unwrap();
            assert_eq!(
                c.query_row("SELECT count(*) FROM external_death_final", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
                0
            );
            assert_eq!(
                c.query_row("SELECT state FROM outbox WHERE outbox_id=2", [], |row| {
                    row.get::<_, String>(0)
                })
                .unwrap(),
                "claimed_uncertain"
            );
        }
    }

    #[test]
    fn pending_commits_atomically_and_exact_readback_survives_epoch_drift() {
        let f = Fixture::new("");
        let mut store = f.open();
        let first = store.prepare(&f.author(), &f.request).unwrap();
        assert_eq!(f.counts(), (1, 6));
        assert_eq!(first.preparing_authority_revision, 6);
        assert_eq!(store.prepare(&f.author(), &f.request).unwrap(), first);
        assert_eq!(f.counts(), (1, 6));
        let c = Connection::open(&f.source).unwrap();
        c.execute_batch("UPDATE metadata SET value=3 WHERE key='owner_epoch'; UPDATE metadata SET value=7 WHERE key='authority_revision'; UPDATE manager_credential_claims SET owner_epoch=3,credential_epoch=3;").unwrap();
        let native: String = c
            .query_row("SELECT state FROM outbox WHERE outbox_id=2", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(native, "claimed_uncertain");
        assert_eq!(
            c.query_row("SELECT count(*) FROM external_death_final", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        drop(c);
        drop(store);
        let mut reopened = f.open();
        assert_eq!(
            reopened.lookup(&f.author(), &f.request).unwrap(),
            Some(first.clone())
        );
        assert_eq!(reopened.prepare(&f.author(), &f.request).unwrap(), first);
        assert_eq!(f.counts(), (1, 7));
        assert!(PodBayStore::open(&f.source).is_err());
        assert!(
            recover_disposable_v25_activation(
                &f.source,
                &f.staging,
                "migration.one",
                "activation.one"
            )
            .is_err()
        );
    }
    #[test]
    fn pending_transaction_failure_rolls_back_row_and_revision() {
        let f = Fixture::new("");
        let mut store = f.open();
        let reached = std::cell::Cell::new(false);
        let failure = store.prepare_with_hook(&f.author(), &f.request, || {
            reached.set(true);
            Err(V25StagingError::Safety("injected after pending insert"))
        });
        assert!(matches!(
            failure,
            Err(V25StagingError::Safety("injected after pending insert"))
        ));
        assert!(reached.get(), "fault must follow INSERT");
        assert_eq!(f.counts(), (0, 5));
        store.prepare(&f.author(), &f.request).unwrap();
        assert_eq!(f.counts(), (1, 6));
    }
    #[test]
    fn pending_refuses_bad_subject_cas_author_and_original_launch() {
        for change in [
            "lineage",
            "pod",
            "attempt",
            "resource",
            "revision",
            "owner",
            "credential",
            "rebind",
            "checkpoint",
        ] {
            let f = Fixture::new("");
            let mut r = f.request.clone();
            match change {
                "lineage" => r.store_lineage = "foreign".into(),
                "pod" => r.pod_id = "foreign.pod".into(),
                "attempt" => r.attempt_id = "foreign.attempt".into(),
                "resource" => r.resources[0].input_epoch = 3,
                "revision" => r.expected_authority_revision = 4,
                "owner" => r.expected_owner_epoch = 3,
                "credential" => r.expected_manager_credential_epoch += 1,
                "rebind" => r.activated_rebind_rowid = 99,
                "checkpoint" => r.checkpoint_digest = "e".repeat(64),
                _ => unreachable!(),
            };
            assert!(f.open().prepare(&f.author(), &r).is_err(), "{change}");
            assert_eq!(f.counts(), (0, 5));
        }
        for variant in [
            "phase",
            "prior",
            "later",
            "later_activated",
            "later_lower_epoch",
            "extra_resource",
            "supersession",
            "claimed_launch",
            "unverified_observed",
            "author_role",
        ] {
            let f = Fixture::new(variant);
            let result = f.open().prepare(&f.author(), &f.request);
            if matches!(
                variant,
                "later" | "later_activated" | "later_lower_epoch" | "supersession"
            ) {
                assert!(
                    matches!(
                        result,
                        Err(V25StagingError::Safety(
                            "pending restricted rebind/supersession conflict"
                        ))
                    ),
                    "{variant}: {result:?}"
                );
            } else {
                assert!(result.is_err(), "{variant}");
            }
            assert_eq!(f.counts(), (0, 5));
        }
        let f = Fixture::new("");
        let mut store = f.open();
        let first = store.prepare(&f.author(), &f.request).unwrap();
        let wrong = DisposablePendingAuthor {
            principal: "foreign.owner".into(),
            scope: "scope.launch".into(),
        };
        assert!(store.lookup(&wrong, &f.request).is_err());
        let mut changed = f.request.clone();
        changed.attempt_id = "foreign".into();
        assert!(store.lookup(&f.author(), &changed).is_err());
        changed = f.request.clone();
        changed.recovery_key = "recover.second".into();
        assert!(store.prepare(&f.author(), &changed).is_err());
        assert_eq!(store.lookup(&f.author(), &f.request).unwrap(), Some(first));
        let c = Connection::open(&f.source).unwrap();
        c.execute(
            "UPDATE external_death_pending SET request_digest=?1",
            ["0".repeat(64)],
        )
        .unwrap();
        drop(c);
        assert!(f.open_result().is_err());
    }
    impl Fixture {
        fn open_result(&self) -> Result<DisposableV25PendingStore, V25StagingError> {
            open_disposable_v25_pending(
                &self.source,
                &self.staging,
                "migration.one",
                "activation.one",
                "pending.state",
            )
        }
    }
    #[test]
    fn pending_decoder_refuses_credential_rollback_below_preserved_baseline() {
        let f = Fixture::new("baseline_credential");
        let before = f.open();
        assert_eq!(f.request.expected_manager_credential_epoch, 5);
        drop(before);
        let c = Connection::open(&f.source).unwrap();
        assert_eq!(
            c.execute(
                "UPDATE manager_credential_claims SET credential_epoch=3",
                []
            )
            .unwrap(),
            1
        );
        assert_eq!(
            c.query_row(
                "SELECT credential_epoch FROM manager_credential_claims WHERE singleton=1",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            3
        );
        drop(c);
        assert!(matches!(
            f.open_result(),
            Err(V25StagingError::Safety(
                "pending current manager credential claim differs"
            ))
        ));
        assert_eq!(f.counts(), (0, 5));
    }
    #[test]
    fn same_epoch_activated_rebind_is_forbidden_by_exact_schema_unique_constraint() {
        let f = Fixture::new("");
        let c = Connection::open(&f.source).unwrap();
        let error = c.execute("INSERT INTO manager_rebinds(store_lineage,scope_id,pod_id,attempt_id,pod_incarnation,expected_owner_epoch,next_owner_epoch,expected_credential_epoch,next_credential_epoch,manager_os_identity,manager_process_id,manager_boot_identity,manager_birth_identity,manager_containment,command_key,request_digest,resource_count,phase,pod_checkpoint_ref) SELECT store_lineage,scope_id,pod_id,attempt_id,pod_incarnation,expected_owner_epoch,next_owner_epoch,expected_credential_epoch,next_credential_epoch,manager_os_identity,manager_process_id,manager_boot_identity,manager_birth_identity,manager_containment,'same.epoch',request_digest,resource_count,phase,pod_checkpoint_ref FROM manager_rebinds WHERE rebind_rowid=1", []).unwrap_err();
        assert!(error.to_string().contains("UNIQUE constraint failed: manager_rebinds.scope_id, manager_rebinds.pod_id, manager_rebinds.pod_incarnation, manager_rebinds.next_owner_epoch"));
        assert_eq!(
            c.query_row("SELECT count(*) FROM manager_rebinds", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn pending_state_declaration_refuses_foreign_key_partial_and_earlier_candidate_schema() {
        let f = Fixture::new("");
        drop(f.open());
        assert!(
            open_disposable_v25_pending(
                &f.source,
                &f.staging,
                "migration.one",
                "activation.one",
                "foreign.state"
            )
            .is_err()
        );
        let (_, writing) = paths(&f.source).unwrap();
        fs::write(&writing, b"foreign partial").unwrap();
        assert!(f.open_result().is_err());
        assert_eq!(f.counts(), (0, 5));
        let old = Fixture::new("");
        let c = Connection::open(&old.source).unwrap();
        c.execute_batch("ALTER TABLE external_death_pending DROP COLUMN authenticated_author; ALTER TABLE external_death_pending DROP COLUMN request_version; ALTER TABLE external_death_pending DROP COLUMN canonical_request;").unwrap();
        assert_eq!(
            c.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            25
        );
        drop(c);
        assert!(
            old.open_result().is_err(),
            "version25 integer alone cannot admit earlier candidate DDL"
        );
        assert_eq!(old.counts(), (0, 5));
    }

    #[test]
    fn pending_prospective_byte_cap_is_atomic_and_historical_retry_at_cap_is_readable() {
        let f = Fixture::new("");
        let author = f.author();
        let bytes = canonical(&author, &f.request).unwrap().len() as i64;
        let mut store = f.open();
        // Scale the private budget to the exact real canonical request size;
        // this executes the same prepare transaction and quota check as production defaults.
        let failed =
            store.prepare_with_budget(&author, &f.request, || Ok(()), MAX_PENDING_ROWS, bytes - 1);
        assert!(matches!(
            failed,
            Err(V25StagingError::Safety(
                "pending prospective decoder budget exceeded"
            ))
        ));
        assert_eq!(f.counts(), (0, 5));
        let first = store
            .prepare_with_budget(&author, &f.request, || Ok(()), MAX_PENDING_ROWS, bytes)
            .unwrap();
        assert_eq!(f.counts(), (1, 6));
        assert_eq!(
            store
                .prepare_with_budget(&author, &f.request, || Ok(()), 1, bytes)
                .unwrap(),
            first
        );
        assert_eq!(store.lookup(&author, &f.request).unwrap(), Some(first));
        assert_eq!(f.counts(), (1, 6));
    }
    #[test]
    fn pending_observation_epochs_and_rebind_credential_are_qualified() {
        for variant in [
            "target_epoch",
            "observation_owner_low",
            "observation_owner_high",
            "empty_claim_key",
            "empty_observation_key",
            "credential_ahead",
        ] {
            let f = Fixture::new(variant);
            let result = f.open().prepare(&f.author(), &f.request);
            let message = if variant == "credential_ahead" {
                "pending activated rebind is ahead of admitted credential"
            } else {
                "pending conflict or unresolved original launch/stop"
            };
            assert!(
                matches!(result, Err(V25StagingError::Safety(m)) if m==message),
                "{variant}: {result:?}"
            );
            assert_eq!(f.counts(), (0, 5));
        }
        let late = Fixture::new("late_observation");
        let c = open_exchange_read_only(&late.source).unwrap();
        let epochs:(i64,i64)=c.query_row("SELECT o.claim_owner_epoch,e.owner_epoch FROM outbox o JOIN events e ON e.sequence=o.observation_event_sequence WHERE o.outbox_id=1",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(epochs, (2, 3));
        drop(c);
        late.open().prepare(&late.author(), &late.request).unwrap();
        assert_eq!(late.counts(), (1, 6));
    }

    #[test]
    fn pending_restart_child() {
        let Some(source) = std::env::var_os("PODBAY_PENDING_PROBE_SOURCE") else {
            return;
        };
        let stage = std::env::var_os("PODBAY_PENDING_PROBE_STAGE").unwrap();
        let bytes = std::env::var("PODBAY_PENDING_PROBE_REQUEST").unwrap();
        let request: ExternalDeathPendingRequest = serde_json::from_str(&bytes).unwrap();
        let store = open_disposable_v25_pending(
            PathBuf::from(source),
            PathBuf::from(stage),
            "migration.one",
            "activation.one",
            "pending.state",
        )
        .unwrap();
        let author = DisposablePendingAuthor {
            principal: "owner.fixture".into(),
            scope: "scope.launch".into(),
        };
        assert_eq!(
            store
                .lookup(&author, &request)
                .unwrap()
                .unwrap()
                .preparing_authority_revision,
            6
        );
        println!("fresh-process pending revision6 verified");
    }
    #[test]
    fn pending_fresh_process_reopens_committed_state() {
        let f = Fixture::new("");
        f.open().prepare(&f.author(), &f.request).unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "migration_v25::external_death_v25::tests::pending_restart_child",
                "--nocapture",
            ])
            .env("PODBAY_PENDING_PROBE_SOURCE", &f.source)
            .env("PODBAY_PENDING_PROBE_STAGE", &f.staging)
            .env(
                "PODBAY_PENDING_PROBE_REQUEST",
                serde_json::to_string(&f.request).unwrap(),
            )
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "{} {}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
        println!("{}", String::from_utf8_lossy(&child.stdout));
    }
}
