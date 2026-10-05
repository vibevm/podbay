//! Private, command-independent Codex evidence. The trusted host supplies
//! authenticated actor and live pod evidence; this store rechecks the current
//! owner, exact launch mapping and digest inside each SQLite transaction.

use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::current_snapshot::check_fence;
use crate::model::{AuthorityActorRecord, StoreError};
use crate::store::{PodBayStore, valid_id};

const MAX_PAGE_EVENTS: usize = 4;
const MAX_RAW_EVENT_BYTES: usize = 4 * 1_048_576;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeEvidenceIdentity {
    pub store_lineage: String,
    pub scope_id: String,
    pub session_id: String,
    pub run_id: String,
    pub attempt_id: String,
    pub pod_id: String,
    pub pod_incarnation: u64,
    pub resource_id: String,
    pub resource_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeEvidenceSnapshot {
    pub identity: NativeEvidenceIdentity,
    pub watermark: u64,
    pub earliest_retained: u64,
    pub last_status: Option<String>,
    pub output_events: u64,
    pub question_events: u64,
    pub permission_events: u64,
    pub opaque_events: u64,
    pub external_conflict: bool,
    pub fidelity: String,
    pub quarantined: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct NativeEvidenceEvent {
    pub event_id: String,
    pub source_sequence: u64,
    pub kind: String,
    pub status: Option<String>,
    pub recorded_at_unix_millis: u64,
    pub provenance: String,
    pub external_conflict: bool,
    pub content_digest: String,
    pub raw_jsonl: Vec<u8>,
}

impl std::fmt::Debug for NativeEvidenceEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeEvidenceEvent")
            .field("event_id", &self.event_id)
            .field("source_sequence", &self.source_sequence)
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("content_digest", &self.content_digest)
            .field("private_bytes", &self.raw_jsonl.len())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeEvidenceGap {
    pub missing_from: u64,
    pub missing_through: u64,
    pub earliest_available: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeEvidencePage {
    pub snapshot: NativeEvidenceSnapshot,
    pub events: Vec<NativeEvidenceEvent>,
    pub next_source_sequence: u64,
    pub gap: Option<NativeEvidenceGap>,
}

/// `actor` and page are trusted-host assertions, never wire DTOs. In
/// particular this method does not authenticate a Unix socket or grant.
pub struct TrustedNativeEvidenceAdmission<'a> {
    pub actor: &'a AuthorityActorRecord,
    pub expected_owner_epoch: u64,
    pub expected_manager_credential_epoch: u64,
    pub expected_authority_revision: u64,
    pub effective_digest: &'a str,
    pub descriptor_digest: &'a str,
    pub after: u64,
    pub limit: usize,
    pub page: &'a NativeEvidencePage,
}

impl PodBayStore {
    /// Replays already admitted private evidence after a fully fenced actor
    /// and exact current launch lookup. None asks the host to fetch the pod.
    #[allow(clippy::too_many_arguments)]
    pub fn native_evidence_after(
        &mut self,
        actor: &AuthorityActorRecord,
        expected_owner_epoch: u64,
        expected_manager_credential_epoch: u64,
        expected_authority_revision: u64,
        identity: &NativeEvidenceIdentity,
        effective_digest: &str,
        descriptor_digest: &str,
        after: u64,
        limit: usize,
    ) -> Result<Option<NativeEvidencePage>, StoreError> {
        if !(1..=MAX_PAGE_EVENTS).contains(&limit) {
            return Err(StoreError::InvalidInput("native evidence page limit"));
        }
        validate_identity(identity)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        check_fence(
            &transaction,
            &self.store_lineage,
            actor,
            expected_owner_epoch,
            expected_manager_credential_epoch,
            expected_authority_revision,
        )?;
        check_current_mapping(
            &transaction,
            actor,
            identity,
            effective_digest,
            descriptor_digest,
        )?;
        let snapshot = read_snapshot(&transaction, identity)?;
        let page = if let Some(snapshot) = snapshot {
            if snapshot.quarantined {
                return Err(StoreError::SourceIdentityQuarantined);
            }
            if after > snapshot.watermark {
                return Err(StoreError::WrongCursor);
            }
            let events = read_events(&transaction, identity, after, limit)?;
            if events.is_empty() {
                None
            } else {
                Some(make_page(snapshot, events, after)?)
            }
        } else if after == 0 {
            None
        } else {
            return Err(StoreError::WrongCursor);
        };
        transaction.commit()?;
        Ok(page)
    }

    /// Atomically stores one verified pod page after the external pod read.
    /// A duplicate source key with different bytes quarantines the source;
    /// no raw bytes enter the generic event or command tables.
    pub fn admit_native_evidence_page(
        &mut self,
        input: TrustedNativeEvidenceAdmission<'_>,
    ) -> Result<NativeEvidencePage, StoreError> {
        if !(1..=MAX_PAGE_EVENTS).contains(&input.limit) || input.page.events.len() > input.limit {
            return Err(StoreError::InvalidInput("native evidence page limit"));
        }
        validate_page(input.page, input.after)?;
        let identity = &input.page.snapshot.identity;
        if identity.store_lineage != self.store_lineage {
            return Err(StoreError::WrongCursor);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_fence(
            &transaction,
            &self.store_lineage,
            input.actor,
            input.expected_owner_epoch,
            input.expected_manager_credential_epoch,
            input.expected_authority_revision,
        )?;
        check_current_mapping(
            &transaction,
            input.actor,
            identity,
            input.effective_digest,
            input.descriptor_digest,
        )?;
        let prior = read_snapshot(&transaction, identity)?;
        if let Some(prior) = &prior {
            if prior.quarantined {
                return Err(StoreError::SourceIdentityQuarantined);
            }
            if input.after > prior.watermark
                || input.page.snapshot.watermark < prior.watermark
                || input.page.snapshot.earliest_retained < prior.earliest_retained
                || input.page.snapshot.output_events < prior.output_events
                || input.page.snapshot.question_events < prior.question_events
                || input.page.snapshot.permission_events < prior.permission_events
                || input.page.snapshot.opaque_events < prior.opaque_events
                || fidelity_rank(&input.page.snapshot.fidelity) > fidelity_rank(&prior.fidelity)
            {
                return Err(StoreError::StaleEpoch);
            }
        } else if input.after != 0 {
            return Err(StoreError::WrongCursor);
        }
        if prior.is_none() {
            insert_source(&transaction, &input.page.snapshot)?;
        }
        let highest: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(source_sequence),0) FROM codex_native_evidence WHERE resource_id=?1",
            [&identity.resource_id], |row| row.get(0),
        )?;
        let mut expected_next =
            u64::try_from(highest).map_err(|_| StoreError::Conflict("native source sequence"))?;
        // An earlier fsynced empty-gap snapshot already proved that all
        // source positions below earliest_retained are unavailable. Its
        // advanced cursor may be followed by the first retained event.
        if let Some(prior) = &prior {
            expected_next = expected_next.max(prior.earliest_retained.saturating_sub(1));
        }
        for event in &input.page.events {
            let existing: Option<NativeEvidenceEvent> = transaction
                .query_row(
                    "SELECT event_id,source_sequence,kind,status,recorded_at_unix_millis,
                        provenance,external_conflict,content_digest,raw_jsonl
                 FROM codex_native_evidence WHERE resource_id=?1 AND source_sequence=?2",
                    params![identity.resource_id, sql_u64(event.source_sequence)?],
                    event_from_row,
                )
                .optional()?;
            if let Some(existing) = existing {
                if existing != *event {
                    transaction.execute(
                        "INSERT OR IGNORE INTO codex_native_conflicts(
                           resource_id,source_sequence,incoming_digest,raw_jsonl)
                         VALUES(?1,?2,?3,?4)",
                        params![
                            identity.resource_id,
                            sql_u64(event.source_sequence)?,
                            event.content_digest,
                            event.raw_jsonl
                        ],
                    )?;
                    transaction.execute(
                        "UPDATE codex_native_sources SET quarantined=1,fidelity='unknown'
                         WHERE resource_id=?1",
                        [&identity.resource_id],
                    )?;
                    transaction.commit()?;
                    return Err(StoreError::SourceIdentityQuarantined);
                }
                continue;
            }
            if event.source_sequence <= expected_next {
                return Err(StoreError::Conflict(
                    "native source sequence moved backward",
                ));
            }
            if event.source_sequence > expected_next + 1
                && input.page.gap.as_ref().is_none_or(|gap| {
                    gap.missing_from > expected_next + 1
                        || gap.missing_through < event.source_sequence - 1
                })
            {
                return Err(StoreError::Conflict("native source gap was not declared"));
            }
            transaction.execute(
                "INSERT INTO codex_native_evidence(
                   resource_id,source_sequence,event_id,kind,status,recorded_at_unix_millis,
                   provenance,external_conflict,content_digest,raw_jsonl)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    identity.resource_id,
                    sql_u64(event.source_sequence)?,
                    event.event_id,
                    event.kind,
                    event.status,
                    sql_u64(event.recorded_at_unix_millis)?,
                    event.provenance,
                    event.external_conflict as i64,
                    event.content_digest,
                    event.raw_jsonl
                ],
            )?;
            expected_next = event.source_sequence;
        }
        update_source(&transaction, &input.page.snapshot)?;
        let events = read_events(&transaction, identity, input.after, input.limit)?;
        let snapshot = read_snapshot(&transaction, identity)?.ok_or(StoreError::Conflict(
            "native snapshot missing after admission",
        ))?;
        let result = make_page(snapshot, events, input.after)?;
        transaction.commit()?;
        Ok(result)
    }
}

fn check_current_mapping(
    transaction: &Transaction<'_>,
    actor: &AuthorityActorRecord,
    id: &NativeEvidenceIdentity,
    effective_digest: &str,
    descriptor_digest: &str,
) -> Result<(), StoreError> {
    if actor.origin != "owner_cli"
        || actor.scope_id != id.scope_id
        || effective_digest.len() != 64
        || descriptor_digest.len() != 64
    {
        return Err(StoreError::NotFound);
    }
    let matching: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM runtime_sessions s
         JOIN runtime_runs r ON r.run_id=s.current_run_id
           AND r.session_id=s.session_id AND r.scope_id=s.scope_id
         JOIN launch_bindings b ON b.run_id=r.run_id AND b.attempt_id=r.current_attempt_id
           AND b.session_id=s.session_id AND b.scope_id=s.scope_id
         JOIN launch_resources lr ON lr.command_rowid=b.command_rowid
         JOIN authority_pods ap ON ap.pod_id=b.pod_id AND ap.scope_id=b.scope_id
           AND ap.incarnation=b.pod_incarnation
         JOIN authority_resources ar ON ar.resource_id=lr.resource_id
           AND ar.scope_id=b.scope_id AND ar.pod_id=b.pod_id
           AND ar.pod_incarnation=b.pod_incarnation
           AND ar.resource_epoch=lr.resource_epoch
         WHERE s.scope_id=?1 AND s.session_id=?2 AND s.actor_id=?3 AND s.state='open'
           AND b.run_id=?4 AND b.attempt_id=?5 AND b.pod_id=?6
           AND b.pod_incarnation=?7 AND lr.resource_id=?8 AND lr.resource_epoch=?9
           AND b.effective_spec_digest=?10 AND b.descriptor_digest=?11",
        params![
            id.scope_id,
            id.session_id,
            actor.actor_id,
            id.run_id,
            id.attempt_id,
            id.pod_id,
            sql_u64(id.pod_incarnation)?,
            id.resource_id,
            sql_u64(id.resource_epoch)?,
            effective_digest,
            descriptor_digest
        ],
        |row| row.get(0),
    )?;
    if matching != 1 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

fn validate_identity(id: &NativeEvidenceIdentity) -> Result<(), StoreError> {
    for value in [
        &id.store_lineage,
        &id.scope_id,
        &id.session_id,
        &id.run_id,
        &id.attempt_id,
        &id.pod_id,
        &id.resource_id,
    ] {
        valid_id(value)?;
    }
    if id.pod_incarnation == 0 || id.resource_epoch == 0 {
        return Err(StoreError::InvalidInput("native evidence epoch is zero"));
    }
    Ok(())
}

fn validate_page(page: &NativeEvidencePage, after: u64) -> Result<(), StoreError> {
    validate_identity(&page.snapshot.identity)?;
    if page.events.len() > MAX_PAGE_EVENTS
        || page.snapshot.quarantined
        || !matches!(
            page.snapshot.fidelity.as_str(),
            "exact" | "partial" | "unknown"
        )
        || page
            .snapshot
            .last_status
            .as_deref()
            .is_some_and(|value| !valid_status(value))
        || page.snapshot.earliest_retained > page.snapshot.watermark.saturating_add(1)
        || page.next_source_sequence
            != page.events.last().map_or_else(
                || page.gap.as_ref().map_or(after, |gap| gap.missing_through),
                |event| event.source_sequence,
            )
    {
        return Err(StoreError::InvalidInput("native evidence page shape"));
    }
    if let Some(gap) = &page.gap {
        if gap.missing_from != after.saturating_add(1)
            || gap.missing_through < gap.missing_from
            || gap.earliest_available != gap.missing_through.saturating_add(1)
            || page.snapshot.fidelity == "exact"
        {
            return Err(StoreError::InvalidInput("native evidence gap shape"));
        }
    }
    let mut last = after;
    for event in &page.events {
        valid_id(&event.event_id)?;
        if event.source_sequence <= last
            || event.source_sequence > page.snapshot.watermark
            || !matches!(
                event.kind.as_str(),
                "status" | "output" | "question" | "permission" | "opaque"
            )
            || event
                .status
                .as_deref()
                .is_some_and(|value| !valid_status(value))
            || event.provenance != "codex.app-server.pod-observed/1"
            || event.raw_jsonl.is_empty()
            || event.raw_jsonl.len() > MAX_RAW_EVENT_BYTES
            || event.raw_jsonl.last() != Some(&b'\n')
            || event.raw_jsonl[..event.raw_jsonl.len() - 1].contains(&b'\n')
            || std::str::from_utf8(&event.raw_jsonl).is_err()
            || event.content_digest != digest(&event.raw_jsonl)
        {
            return Err(StoreError::InvalidInput("native evidence event shape"));
        }
        last = event.source_sequence;
    }
    Ok(())
}

fn fidelity_rank(value: &str) -> u8 {
    match value {
        "exact" => 3,
        "partial" => 2,
        _ => 1,
    }
}

fn valid_status(value: &str) -> bool {
    matches!(
        value,
        "idle" | "active" | "waiting" | "completed" | "failed" | "interrupted" | "system_error"
    )
}

fn digest(raw: &[u8]) -> String {
    Sha256::digest(raw)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn sql_u64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value)
        .map_err(|_| StoreError::InvalidInput("native counter exceeds SQLite range"))
}

fn insert_source(t: &Transaction<'_>, snapshot: &NativeEvidenceSnapshot) -> Result<(), StoreError> {
    let id = &snapshot.identity;
    t.execute(
        "INSERT INTO codex_native_sources(
           resource_id,store_lineage,scope_id,session_id,run_id,attempt_id,pod_id,
           pod_incarnation,resource_epoch,watermark,earliest_retained,last_status,
           output_events,question_events,permission_events,opaque_events,
           external_conflict,fidelity,quarantined)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,0,0,NULL,0,0,0,0,0,'exact',0)",
        params![
            id.resource_id,
            id.store_lineage,
            id.scope_id,
            id.session_id,
            id.run_id,
            id.attempt_id,
            id.pod_id,
            sql_u64(id.pod_incarnation)?,
            sql_u64(id.resource_epoch)?
        ],
    )?;
    Ok(())
}

fn update_source(t: &Transaction<'_>, snapshot: &NativeEvidenceSnapshot) -> Result<(), StoreError> {
    t.execute(
        "UPDATE codex_native_sources SET watermark=?1,earliest_retained=?2,last_status=?3,
           output_events=?4,question_events=?5,permission_events=?6,opaque_events=?7,
           external_conflict=?8,fidelity=?9 WHERE resource_id=?10 AND quarantined=0",
        params![
            sql_u64(snapshot.watermark)?,
            sql_u64(snapshot.earliest_retained)?,
            snapshot.last_status,
            sql_u64(snapshot.output_events)?,
            sql_u64(snapshot.question_events)?,
            sql_u64(snapshot.permission_events)?,
            sql_u64(snapshot.opaque_events)?,
            snapshot.external_conflict as i64,
            snapshot.fidelity,
            snapshot.identity.resource_id
        ],
    )?;
    Ok(())
}

fn read_snapshot(
    t: &Transaction<'_>,
    id: &NativeEvidenceIdentity,
) -> Result<Option<NativeEvidenceSnapshot>, StoreError> {
    let row: Option<(
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
        i64,
        i64,
        i64,
        Option<String>,
        i64,
        i64,
        i64,
        i64,
        i64,
        String,
        i64,
    )> = t
        .query_row(
            "SELECT store_lineage,scope_id,session_id,run_id,attempt_id,pod_id,
                pod_incarnation,resource_epoch,watermark,earliest_retained,last_status,
                output_events,question_events,permission_events,opaque_events,
                external_conflict,fidelity,quarantined
         FROM codex_native_sources WHERE resource_id=?1",
            [&id.resource_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                    row.get(17)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else { return Ok(None) };
    if row.0 != id.store_lineage
        || row.1 != id.scope_id
        || row.2 != id.session_id
        || row.3 != id.run_id
        || row.4 != id.attempt_id
        || row.5 != id.pod_id
        || row.6 != sql_u64(id.pod_incarnation)?
        || row.7 != sql_u64(id.resource_epoch)?
    {
        return Err(StoreError::WrongCursor);
    }
    Ok(Some(NativeEvidenceSnapshot {
        identity: id.clone(),
        watermark: row.8 as u64,
        earliest_retained: row.9 as u64,
        last_status: row.10,
        output_events: row.11 as u64,
        question_events: row.12 as u64,
        permission_events: row.13 as u64,
        opaque_events: row.14 as u64,
        external_conflict: row.15 != 0,
        fidelity: row.16,
        quarantined: row.17 != 0,
    }))
}

fn event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<NativeEvidenceEvent> {
    Ok(NativeEvidenceEvent {
        event_id: row.get(0)?,
        source_sequence: row.get::<_, i64>(1)? as u64,
        kind: row.get(2)?,
        status: row.get(3)?,
        recorded_at_unix_millis: row.get::<_, i64>(4)? as u64,
        provenance: row.get(5)?,
        external_conflict: row.get::<_, i64>(6)? != 0,
        content_digest: row.get(7)?,
        raw_jsonl: row.get(8)?,
    })
}

fn read_events(
    t: &Transaction<'_>,
    id: &NativeEvidenceIdentity,
    after: u64,
    limit: usize,
) -> Result<Vec<NativeEvidenceEvent>, StoreError> {
    let mut statement = t.prepare(
        "SELECT event_id,source_sequence,kind,status,recorded_at_unix_millis,
                provenance,external_conflict,content_digest,raw_jsonl
         FROM codex_native_evidence WHERE resource_id=?1 AND source_sequence>?2
         ORDER BY source_sequence LIMIT ?3",
    )?;
    let events = statement
        .query_map(
            params![id.resource_id, sql_u64(after)?, limit as i64],
            event_from_row,
        )?
        .collect::<Result<Vec<_>, _>>()?;
    for event in &events {
        if event.source_sequence == 0
            || event.raw_jsonl.is_empty()
            || event.raw_jsonl.len() > MAX_RAW_EVENT_BYTES
            || event.content_digest != digest(&event.raw_jsonl)
            || event.provenance != "codex.app-server.pod-observed/1"
        {
            return Err(StoreError::Conflict("private native evidence changed"));
        }
    }
    Ok(events)
}

fn make_page(
    snapshot: NativeEvidenceSnapshot,
    events: Vec<NativeEvidenceEvent>,
    after: u64,
) -> Result<NativeEvidencePage, StoreError> {
    // One page cannot conceal a second gap. Stop before an internal jump;
    // the next cursor read will surface that exact missing range.
    let mut visible = Vec::with_capacity(events.len());
    let mut expected = None;
    for event in events {
        if expected.is_some_and(|sequence| event.source_sequence != sequence) {
            break;
        }
        expected = event.source_sequence.checked_add(1);
        visible.push(event);
    }
    let first_available = visible
        .first()
        .map(|event| event.source_sequence)
        .or_else(|| {
            (snapshot.earliest_retained > after.saturating_add(1))
                .then_some(snapshot.earliest_retained)
        });
    let gap = first_available.and_then(|first| {
        (first > after.saturating_add(1)).then_some(NativeEvidenceGap {
            missing_from: after + 1,
            missing_through: first - 1,
            earliest_available: first,
        })
    });
    let next_source_sequence = visible.last().map_or_else(
        || gap.as_ref().map_or(after, |gap| gap.missing_through),
        |event| event.source_sequence,
    );
    Ok(NativeEvidencePage {
        snapshot,
        events: visible,
        next_source_sequence,
        gap,
    })
}
