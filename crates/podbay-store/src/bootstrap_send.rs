//! First Codex V2 Session send, after a separately accepted Pod launch. Store
//! facts are not actor, grant, socket, or live-child authentication.

use podbay_core::{ActorId, CommandId, ScopeId, SessionId};
use podbay_wire::{CommandBody, CommandEnvelope, ContentBlock, SendPolicy, Target};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use crate::model::CommandRequest;
use crate::model::{
    Admission, DIGEST_VERSION, EffectClaim, EffectState, NativeWriterTarget, Receipt, StoreError,
    VerifiedPrincipal,
};
use crate::store::{
    PodBayStore, digest_request, integer, sha256_hex, stable_command_id, valid_id, validate_request,
};
use crate::writer_lease::checked_native_writer_lease;

const NAMESPACE: &str = "podbay.session.send.bootstrap";
const EFFECT_KIND: &str = "codex.bootstrap";
const EVENT_KIND: &str = "session.send.bootstrap.admitted";
const PAYLOAD_DOMAIN: &[u8] = b"podbay.codex.bootstrap-send/1\0";
const BINDING_DOMAIN: &[u8] = b"podbay.codex.bootstrap-binding/1\0";
const MAX_TEXT_BYTES: usize = 64_000;
const MAX_PAYLOAD_BYTES: usize = 128_000;

/// Supplied only after the host authenticates an actor and current send grant.
/// Public fields are forgeable; this store path validates durable associations
/// and never asserts that a provider write is authorised.
pub struct TrustedBootstrapSendRequest<'a> {
    pub principal: VerifiedPrincipal,
    pub scope_id: ScopeId,
    pub envelope: &'a CommandEnvelope,
    pub native_target: NativeWriterTarget,
    pub holder_actor_id: ActorId,
    pub holder_credential_generation: u64,
    pub expected_owner_epoch: u64,
    pub expected_manager_credential_epoch: u64,
    pub expected_authority_revision: u64,
}

/// CommandId plus exact native target, supplied by a trusted host or pod.
/// This selector does not prove OS identity or permission by itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapSendSelector {
    pub scope_id: ScopeId,
    pub command_id: CommandId,
    pub native_target: NativeWriterTarget,
}

/// Protected committed input. A caller must authenticate and scope access
/// before handing the prompt to a client or a native process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapSendRecord {
    receipt: Receipt,
    scope_id: ScopeId,
    native_target: NativeWriterTarget,
    session_revision: u64,
    holder_actor_id: ActorId,
    holder_credential_generation: u64,
    owner_epoch: u64,
    manager_credential_epoch: u64,
    authority_revision: u64,
    writer_epoch: u64,
    lease_expires_at_unix_seconds: u64,
    wire_payload_digest: String,
    prompt_text: String,
    deadline_at: Option<String>,
    effect_state: EffectState,
    claim_key: Option<String>,
    claim_owner_epoch: Option<u64>,
}

impl BootstrapSendRecord {
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
    pub fn scope_id(&self) -> &ScopeId {
        &self.scope_id
    }
    pub fn native_target(&self) -> &NativeWriterTarget {
        &self.native_target
    }
    pub fn session_revision(&self) -> u64 {
        self.session_revision
    }
    pub fn holder_actor_id(&self) -> &ActorId {
        &self.holder_actor_id
    }
    pub fn holder_credential_generation(&self) -> u64 {
        self.holder_credential_generation
    }
    pub fn owner_epoch(&self) -> u64 {
        self.owner_epoch
    }
    pub fn manager_credential_epoch(&self) -> u64 {
        self.manager_credential_epoch
    }
    pub fn authority_revision(&self) -> u64 {
        self.authority_revision
    }
    pub fn writer_epoch(&self) -> u64 {
        self.writer_epoch
    }
    pub fn lease_expires_at_unix_seconds(&self) -> u64 {
        self.lease_expires_at_unix_seconds
    }
    pub fn wire_payload_digest(&self) -> &str {
        &self.wire_payload_digest
    }
    pub fn prompt_text(&self) -> &str {
        &self.prompt_text
    }
    pub fn deadline_at(&self) -> Option<&str> {
        self.deadline_at.as_deref()
    }
    pub fn effect_state(&self) -> EffectState {
        self.effect_state
    }
}

fn positive(value: i64, reason: &'static str) -> Result<u64, StoreError> {
    if value <= 0 {
        Err(StoreError::Conflict(reason))
    } else {
        Ok(value as u64)
    }
}

fn put_field(out: &mut Vec<u8>, value: &[u8]) -> Result<(), StoreError> {
    let len = u32::try_from(value.len())
        .map_err(|_| StoreError::InvalidInput("bootstrap field exceeds bound"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn canonical_payload(
    digest: &str,
    deadline: Option<&str>,
    text: &str,
) -> Result<Vec<u8>, StoreError> {
    if !valid_digest(digest) || text.is_empty() || text.len() > MAX_TEXT_BYTES {
        return Err(StoreError::InvalidInput(
            "bootstrap text or digest is invalid",
        ));
    }
    let mut out = PAYLOAD_DOMAIN.to_vec();
    put_field(&mut out, digest.as_bytes())?;
    put_field(&mut out, deadline.unwrap_or("").as_bytes())?;
    put_field(&mut out, text.as_bytes())?;
    if out.len() > MAX_PAYLOAD_BYTES {
        return Err(StoreError::InvalidInput("bootstrap payload exceeds bound"));
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn binding_digest(
    target: &NativeWriterTarget,
    session_revision: u64,
    holder_actor_id: &ActorId,
    holder_generation: u64,
    owner_epoch: u64,
    manager_credential_epoch: u64,
    authority_revision: u64,
    writer_epoch: u64,
    lease_expiry: u64,
    wire_digest: &str,
    prompt_digest: &str,
) -> Result<String, StoreError> {
    let mut bytes = BINDING_DOMAIN.to_vec();
    for value in [
        target.store_lineage.as_str(),
        target.scope_id.as_str(),
        target.session_id.as_str(),
        target.run_id.as_str(),
        target.attempt_id.as_str(),
        target.pod_id.as_str(),
        target.resource_id.as_str(),
        holder_actor_id.as_str(),
        wire_digest,
        prompt_digest,
    ] {
        put_field(&mut bytes, value.as_bytes())?;
    }
    for value in [
        session_revision,
        target.pod_incarnation,
        target.resource_epoch,
        target.resource_input_epoch,
        holder_generation,
        owner_epoch,
        manager_credential_epoch,
        authority_revision,
        writer_epoch,
        lease_expiry,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    Ok(sha256_hex(&bytes))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_payload(bytes: &[u8]) -> Result<(String, Option<String>, String), StoreError> {
    if bytes.len() > MAX_PAYLOAD_BYTES || !bytes.starts_with(PAYLOAD_DOMAIN) {
        return Err(StoreError::Conflict("bootstrap payload domain differs"));
    }
    let mut at = PAYLOAD_DOMAIN.len();
    let mut field = || -> Result<String, StoreError> {
        let size = bytes
            .get(at..at + 4)
            .ok_or(StoreError::Conflict("bootstrap payload is truncated"))?;
        let len = u32::from_be_bytes(size.try_into().expect("four bytes")) as usize;
        at += 4;
        let end = at
            .checked_add(len)
            .ok_or(StoreError::Conflict("bootstrap length overflows"))?;
        let raw = bytes
            .get(at..end)
            .ok_or(StoreError::Conflict("bootstrap payload is truncated"))?;
        at = end;
        String::from_utf8(raw.to_vec())
            .map_err(|_| StoreError::Conflict("bootstrap payload is not UTF-8"))
    };
    let digest = field()?;
    let deadline = field()?;
    let text = field()?;
    if at != bytes.len() || !valid_digest(&digest) || text.is_empty() || text.len() > MAX_TEXT_BYTES
    {
        return Err(StoreError::Conflict("bootstrap payload is not canonical"));
    }
    let deadline = (!deadline.is_empty()).then_some(deadline);
    if canonical_payload(&digest, deadline.as_deref(), &text)? != bytes {
        return Err(StoreError::Conflict("bootstrap payload is not canonical"));
    }
    Ok((digest, deadline, text))
}

fn first_text<'a>(
    envelope: &'a CommandEnvelope,
    session_id: &SessionId,
) -> Result<&'a str, StoreError> {
    envelope
        .encode_json()
        .map_err(|_| StoreError::InvalidInput("bootstrap wire envelope is invalid"))?;
    if !matches!(&envelope.target, Target::Session { session_id: id } if id == session_id.as_str())
    {
        return Err(StoreError::WrongScope);
    }
    let CommandBody::SessionSend(body) = &envelope.body else {
        return Err(StoreError::InvalidInput("bootstrap requires session.send"));
    };
    if body.policy != SendPolicy::WhenIdle || body.content.len() != 1 {
        return Err(StoreError::InvalidInput(
            "bootstrap requires one idle text block",
        ));
    }
    let ContentBlock::Text { text } = &body.content[0] else {
        return Err(StoreError::InvalidInput(
            "bootstrap artifacts are unsupported",
        ));
    };
    if text.is_empty() || text.len() > MAX_TEXT_BYTES {
        return Err(StoreError::InvalidInput("bootstrap text exceeds bound"));
    }
    Ok(text)
}

fn session_revision(
    transaction: &Transaction<'_>,
    target: &NativeWriterTarget,
) -> Result<u64, StoreError> {
    let value: Option<i64> = transaction
        .query_row(
            "SELECT revision FROM runtime_sessions WHERE session_id=?1 AND scope_id=?2
           AND state='open' AND current_run_id=?3",
            params![
                target.session_id.as_str(),
                target.scope_id.as_str(),
                target.run_id.as_str()
            ],
            |row| row.get(0),
        )
        .optional()?;
    positive(
        value.ok_or(StoreError::StaleEpoch)?,
        "bootstrap Session revision is invalid",
    )
}

fn check_deadline(transaction: &Transaction<'_>, deadline: Option<&str>) -> Result<(), StoreError> {
    let Some(deadline) = deadline else {
        return Ok(());
    };
    let deadline_second: Option<i64> = transaction.query_row(
        "SELECT CAST(strftime('%s',?1) AS INTEGER)",
        [deadline],
        |row| row.get(0),
    )?;
    let now: i64 =
        transaction.query_row("SELECT CAST(strftime('%s','now') AS INTEGER)", [], |row| {
            row.get(0)
        })?;
    if deadline_second.is_none_or(|value| value <= now) {
        return Err(StoreError::StaleEpoch);
    }
    Ok(())
}

fn check_host_accepted_launch(
    transaction: &Transaction<'_>,
    target: &NativeWriterTarget,
    owner_epoch: u64,
) -> Result<(), StoreError> {
    let evidence: Option<(
        String,
        String,
        Option<i64>,
        Option<String>,
        String,
        String,
        i64,
        String,
        String,
    )> = transaction
        .query_row(
            "SELECT o.kind,o.state,o.claim_owner_epoch,o.claim_key,result.stage,
                    b.session_id,b.resource_count, c.command_id,result.claim_key
             FROM launch_bindings AS b
             JOIN commands AS c ON c.command_rowid=b.command_rowid
             JOIN outbox AS o ON o.command_rowid=b.command_rowid
             JOIN launch_dispatch_outcomes AS result ON result.outbox_id=o.outbox_id
             WHERE b.scope_id=?1 AND b.run_id=?2 AND b.attempt_id=?3
               AND b.pod_id=?4 AND b.pod_incarnation=?5",
            params![
                target.scope_id.as_str(),
                target.run_id.as_str(),
                target.attempt_id.as_str(),
                target.pod_id.as_str(),
                integer(target.pod_incarnation)?
            ],
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
                ))
            },
        )
        .optional()?;
    if !evidence.is_some_and(
        |(
            kind,
            state,
            claim_owner,
            claim_key,
            stage,
            session,
            resources,
            command_id,
            outcome_claim,
        )| {
            kind == "pod.offer"
                && matches!(state.as_str(), "claimed_uncertain" | "observed")
                && claim_owner == i64::try_from(owner_epoch).ok()
                && claim_key.as_deref() == Some(format!("claim.{command_id}").as_str())
                && claim_key.as_deref() == Some(outcome_claim.as_str())
                && matches!(stage.as_str(), "host_accepted" | "port_settled")
                && session == target.session_id.as_str()
                && resources == 1
        },
    ) {
        return Err(StoreError::Conflict("Codex V2 launch is not HostAccepted"));
    }
    Ok(())
}

impl PodBayStore {
    /// Durable first bootstrap intent only. The host must authenticate the
    /// principal, send grant and live pod separately; this method calls no port.
    pub fn admit_bootstrap_send(
        &mut self,
        request: &TrustedBootstrapSendRequest<'_>,
    ) -> Result<Admission, StoreError> {
        valid_id(&request.envelope.key)?;
        if request.principal.as_str() != request.holder_actor_id.as_str()
            || request.scope_id != request.native_target.scope_id
        {
            return Err(StoreError::WrongScope);
        }
        let text = first_text(request.envelope, &request.native_target.session_id)?;
        let canonical = canonical_payload(
            &request.envelope.payload_digest,
            request.envelope.deadline_at.as_deref(),
            text,
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Immutable duplicate lookup is before today's lease, grant, launch,
        // deadline and owner checks. RequestId is intentionally not in canonical.
        let existing: Option<(i64, String, String, Vec<u8>)> = transaction
            .query_row(
                "SELECT command_rowid,scope_id,target_id,canonical_request FROM commands
             WHERE principal=?1 AND namespace=?2 AND command_key=?3",
                params![request.principal.as_str(), NAMESPACE, request.envelope.key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        if let Some((rowid, scope, session, bytes)) = existing {
            if scope != request.scope_id.as_str()
                || session != request.native_target.session_id.as_str()
            {
                return Err(StoreError::WrongScope);
            }
            if bytes != canonical {
                return Err(StoreError::Conflict(
                    "bootstrap key changed canonical payload",
                ));
            }
            let record = read_bootstrap_record(&transaction, rowid)?;
            transaction.commit()?;
            return Ok(Admission::Duplicate(record.receipt));
        }
        let guard = request
            .envelope
            .guard
            .as_ref()
            .ok_or(StoreError::InvalidInput(
                "bootstrap requires exact wire guards",
            ))?;
        let manager_epoch = guard.manager_epoch.map(|value| value.get());
        let pod_epoch = guard.pod_epoch.map(|value| value.get());
        let resource_epoch = guard.resource_epoch.map(|value| value.get());
        let writer_epoch = guard.writer_epoch.map(|value| value.get());
        let target_revision = guard.target_revision.map(|value| value.get());
        if manager_epoch != Some(request.expected_owner_epoch)
            || pod_epoch != Some(request.native_target.pod_incarnation)
            || resource_epoch != Some(request.native_target.resource_epoch)
            || writer_epoch.is_none()
            || target_revision.is_none()
            || guard.lease_epoch.is_some()
        {
            return Err(StoreError::StaleEpoch);
        }
        let writer_epoch = writer_epoch.expect("checked wire writer epoch");
        let lease = checked_native_writer_lease(
            &transaction,
            &self.store_lineage,
            &request.native_target,
            &request.holder_actor_id,
            request.holder_credential_generation,
            request.expected_owner_epoch,
            request.expected_manager_credential_epoch,
            request.expected_authority_revision,
            writer_epoch,
        )?;
        let revision = session_revision(&transaction, &request.native_target)?;
        if target_revision != Some(revision) {
            return Err(StoreError::StaleEpoch);
        }
        check_deadline(&transaction, request.envelope.deadline_at.as_deref())?;
        check_host_accepted_launch(
            &transaction,
            &request.native_target,
            request.expected_owner_epoch,
        )?;
        let occupied: Option<i64> = transaction
            .query_row(
                "SELECT command_rowid FROM codex_bootstrap_sends WHERE session_id=?1",
                [request.native_target.session_id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        if occupied.is_some() {
            return Err(StoreError::Conflict("Session already has a bootstrap send"));
        }
        let prompt_digest = sha256_hex(text.as_bytes());
        let exact_binding_digest = binding_digest(
            &request.native_target,
            revision,
            &request.holder_actor_id,
            request.holder_credential_generation,
            request.expected_owner_epoch,
            request.expected_manager_credential_epoch,
            request.expected_authority_revision,
            writer_epoch,
            lease.expires_at_unix_seconds(),
            &request.envelope.payload_digest,
            &prompt_digest,
        )?;
        let command = CommandRequest {
            principal: request.principal.clone(),
            namespace: NAMESPACE.into(),
            command_key: request.envelope.key.clone(),
            scope_id: request.scope_id.as_str().into(),
            target_id: request.native_target.session_id.as_str().into(),
            expected_owner_epoch: request.expected_owner_epoch,
            expected_target_epoch: revision,
            canonical_request: canonical.clone(),
            event_kind: EVENT_KIND.into(),
            event_payload: exact_binding_digest.as_bytes().to_vec(),
            effect_kind: EFFECT_KIND.into(),
            effect_payload: canonical.clone(),
        };
        validate_request(&command)?;
        let digest = digest_request(&command);
        let command_id = stable_command_id(&command);
        transaction.execute(
            "INSERT INTO commands(command_id,principal,namespace,command_key,scope_id,target_id,
               digest_version,request_digest,canonical_request,owner_epoch,target_epoch)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                command_id,
                command.principal.as_str(),
                NAMESPACE,
                command.command_key,
                command.scope_id,
                command.target_id,
                DIGEST_VERSION,
                digest,
                canonical,
                integer(request.expected_owner_epoch)?,
                integer(revision)?
            ],
        )?;
        let rowid = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO events(event_id,schema_version,command_rowid,scope_id,target_id,
               owner_epoch,target_epoch,source_id,source_kind,source_epoch,source_sequence,
               source_digest,source_order,kind,payload,recorded_at,provenance,causation_id)
             VALUES('event.pb07.' || lower(hex(randomblob(16))),1,?1,?2,?3,?4,?5,?6,
               'manager.admission',?4,1,?7,'contiguous',?8,?9,
               strftime('%Y-%m-%dT%H:%M:%fZ','now'),
               'authenticated.manager.admission',?6)",
            params![
                rowid,
                command.scope_id,
                command.target_id,
                integer(request.expected_owner_epoch)?,
                integer(revision)?,
                command_id,
                digest,
                EVENT_KIND,
                command.event_payload
            ],
        )?;
        let event_sequence = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO outbox(command_rowid,scope_id,target_id,owner_epoch,target_epoch,
               kind,payload,effect_digest,state)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'prepared')",
            params![
                rowid,
                command.scope_id,
                command.target_id,
                integer(request.expected_owner_epoch)?,
                integer(revision)?,
                EFFECT_KIND,
                canonical,
                sha256_hex(&command.effect_payload)
            ],
        )?;
        let outbox_id = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO codex_bootstrap_sends(command_rowid,store_lineage,scope_id,session_id,
               session_revision,run_id,attempt_id,pod_id,pod_incarnation,resource_id,
               resource_epoch,resource_input_epoch,holder_actor_id,
               holder_credential_generation,owner_epoch,manager_credential_epoch,
               authority_revision,writer_epoch,lease_expires_at_unix_seconds,
               wire_payload_digest,prompt_digest,binding_digest)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22)",
            params![
                rowid,
                request.native_target.store_lineage.as_str(),
                request.scope_id.as_str(),
                request.native_target.session_id.as_str(),
                integer(revision)?,
                request.native_target.run_id.as_str(),
                request.native_target.attempt_id.as_str(),
                request.native_target.pod_id.as_str(),
                integer(request.native_target.pod_incarnation)?,
                request.native_target.resource_id.as_str(),
                integer(request.native_target.resource_epoch)?,
                integer(request.native_target.resource_input_epoch)?,
                request.holder_actor_id.as_str(),
                integer(request.holder_credential_generation)?,
                integer(request.expected_owner_epoch)?,
                integer(request.expected_manager_credential_epoch)?,
                integer(request.expected_authority_revision)?,
                integer(writer_epoch)?,
                integer(lease.expires_at_unix_seconds())?,
                request.envelope.payload_digest,
                prompt_digest,
                exact_binding_digest,
            ],
        )?;
        transaction.execute(
            "UPDATE commands SET event_sequence=?1,outbox_id=?2 WHERE command_rowid=?3",
            params![event_sequence, outbox_id, rowid],
        )?;
        let record = read_bootstrap_record(&transaction, rowid)?;
        transaction.commit()?;
        Ok(Admission::Committed(record.receipt))
    }
}

fn read_bootstrap_record(
    transaction: &Transaction<'_>,
    rowid: i64,
) -> Result<BootstrapSendRecord, StoreError> {
    type CommandRow = (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        Vec<u8>,
        i64,
        i64,
        Option<i64>,
        Option<i64>,
    );
    let command: CommandRow = transaction
        .query_row(
            "SELECT command_id,principal,namespace,command_key,scope_id,target_id,
                digest_version,request_digest,canonical_request,owner_epoch,target_epoch,
                event_sequence,outbox_id FROM commands WHERE command_rowid=?1",
            [rowid],
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
                ))
            },
        )
        .optional()?
        .ok_or(StoreError::NotFound)?;
    let (
        command_id,
        principal,
        namespace,
        key,
        scope,
        session,
        version,
        digest,
        canonical,
        owner,
        target_revision,
        event_sequence,
        outbox_id,
    ) = command;
    if namespace != NAMESPACE
        || version != DIGEST_VERSION
        || !valid_digest(&digest)
        || owner <= 0
        || target_revision <= 0
        || event_sequence.is_none_or(|v| v <= 0)
        || outbox_id.is_none_or(|v| v <= 0)
    {
        return Err(StoreError::Conflict("bootstrap command header differs"));
    }
    let event_sequence = event_sequence.expect("checked event sequence");
    let outbox_id = outbox_id.expect("checked outbox id");
    let (wire_digest, deadline_at, text) = decode_payload(&canonical)?;
    type BindingRow = (
        String,
        String,
        String,
        i64,
        String,
        String,
        String,
        i64,
        String,
        i64,
        i64,
        String,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        String,
        String,
        String,
    );
    let binding: BindingRow = transaction
        .query_row(
            "SELECT store_lineage,scope_id,session_id,session_revision,run_id,attempt_id,pod_id,
                pod_incarnation,resource_id,resource_epoch,resource_input_epoch,holder_actor_id,
                holder_credential_generation,owner_epoch,manager_credential_epoch,
                authority_revision,writer_epoch,lease_expires_at_unix_seconds,
                wire_payload_digest,prompt_digest,binding_digest
         FROM codex_bootstrap_sends WHERE command_rowid=?1",
            [rowid],
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
                    row.get(18)?,
                    row.get(19)?,
                    row.get(20)?,
                ))
            },
        )
        .optional()?
        .ok_or(StoreError::Conflict("bootstrap binding is missing"))?;
    if binding.1 != scope
        || binding.2 != session
        || binding.3 != target_revision
        || binding.13 != owner
        || binding.18 != wire_digest
        || binding.19 != sha256_hex(text.as_bytes())
    {
        return Err(StoreError::Conflict(
            "bootstrap binding differs from command",
        ));
    }
    let malformed = || StoreError::Conflict("bootstrap binding identity is malformed");
    let stored_binding_digest = binding.20.clone();
    let target = NativeWriterTarget {
        store_lineage: binding.0.try_into().map_err(|_| malformed())?,
        scope_id: binding.1.try_into().map_err(|_| malformed())?,
        session_id: binding.2.try_into().map_err(|_| malformed())?,
        run_id: binding.4.try_into().map_err(|_| malformed())?,
        attempt_id: binding.5.try_into().map_err(|_| malformed())?,
        pod_id: binding.6.try_into().map_err(|_| malformed())?,
        pod_incarnation: positive(binding.7, "bootstrap Pod incarnation is invalid")?,
        resource_id: binding.8.try_into().map_err(|_| malformed())?,
        resource_epoch: positive(binding.9, "bootstrap Resource epoch is invalid")?,
        resource_input_epoch: positive(binding.10, "bootstrap input epoch is invalid")?,
    };
    let holder_actor_id: ActorId = binding.11.try_into().map_err(|_| malformed())?;
    if principal != holder_actor_id.as_str() {
        return Err(StoreError::Conflict(
            "bootstrap principal differs from writer holder",
        ));
    }
    let session_revision = positive(binding.3, "bootstrap Session revision is invalid")?;
    let holder_generation = positive(binding.12, "bootstrap holder generation is invalid")?;
    let owner_epoch = positive(binding.13, "bootstrap owner epoch is invalid")?;
    let manager_credential_epoch = positive(binding.14, "bootstrap manager credential is invalid")?;
    let authority_revision = positive(binding.15, "bootstrap authority revision is invalid")?;
    let writer_epoch = positive(binding.16, "bootstrap writer epoch is invalid")?;
    let lease_expiry = positive(binding.17, "bootstrap lease expiry is invalid")?;
    let recomputed_binding_digest = binding_digest(
        &target,
        session_revision,
        &holder_actor_id,
        holder_generation,
        owner_epoch,
        manager_credential_epoch,
        authority_revision,
        writer_epoch,
        lease_expiry,
        &wire_digest,
        &sha256_hex(text.as_bytes()),
    )?;
    if stored_binding_digest != recomputed_binding_digest {
        return Err(StoreError::Conflict("bootstrap binding digest differs"));
    }
    let outbox: (
        String,
        String,
        i64,
        i64,
        String,
        Vec<u8>,
        String,
        String,
        Option<String>,
        Option<i64>,
        Option<String>,
        Option<Vec<u8>>,
        Option<String>,
        Option<i64>,
    ) = transaction
        .query_row(
            "SELECT scope_id,target_id,owner_epoch,target_epoch,kind,payload,effect_digest,
                    state,claim_key,claim_owner_epoch,observation_key,observation_payload,
                    observation_stage,observation_event_sequence FROM outbox
             WHERE outbox_id=?1 AND command_rowid=?2",
            params![outbox_id, rowid],
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
                ))
            },
        )
        .optional()?
        .ok_or(StoreError::Conflict("bootstrap outbox is missing"))?;
    if outbox.0 != scope
        || outbox.1 != session
        || outbox.2 != owner
        || outbox.3 != target_revision
        || outbox.4 != EFFECT_KIND
        || outbox.5 != canonical
        || outbox.6 != sha256_hex(&outbox.5)
        || outbox.10.is_some()
        || outbox.11.is_some()
        || outbox.12.is_some()
        || outbox.13.is_some()
    {
        return Err(StoreError::Conflict(
            "bootstrap outbox differs from command",
        ));
    }
    let effect_state = match outbox.7.as_str() {
        "prepared" if outbox.8.is_none() && outbox.9.is_none() => EffectState::Prepared,
        "claimed_uncertain"
            if outbox.8.as_deref() == Some(&format!("claim.{command_id}"))
                && outbox.9 == Some(owner) =>
        {
            EffectState::ClaimedUncertain
        }
        _ => return Err(StoreError::Conflict("bootstrap outbox stage is malformed")),
    };
    let event: (
        String,
        Vec<u8>,
        String,
        String,
        i64,
        i64,
        String,
        String,
        String,
        i64,
        i64,
        String,
    ) = transaction
        .query_row(
            "SELECT kind,payload,scope_id,target_id,owner_epoch,target_epoch,source_id,
                    source_kind,source_digest,source_epoch,source_sequence,provenance
             FROM events WHERE sequence=?1 AND command_rowid=?2",
            params![event_sequence, rowid],
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
                ))
            },
        )
        .optional()?
        .ok_or(StoreError::Conflict("bootstrap admission event is missing"))?;
    if event.0 != EVENT_KIND
        || event.1 != stored_binding_digest.as_bytes()
        || event.2 != scope
        || event.3 != session
        || event.4 != owner
        || event.5 != target_revision
        || event.6 != command_id
        || event.7 != "manager.admission"
        || event.8 != digest
        || event.9 != owner
        || event.10 != 1
        || event.11 != "authenticated.manager.admission"
    {
        return Err(StoreError::Conflict("bootstrap admission event differs"));
    }
    let reconstructed = CommandRequest {
        principal: VerifiedPrincipal::from_authenticated_boundary(&principal)?,
        namespace,
        command_key: key,
        scope_id: scope.clone(),
        target_id: session.clone(),
        expected_owner_epoch: owner_epoch,
        expected_target_epoch: session_revision,
        canonical_request: canonical.clone(),
        event_kind: EVENT_KIND.into(),
        event_payload: stored_binding_digest.as_bytes().to_vec(),
        effect_kind: EFFECT_KIND.into(),
        effect_payload: canonical,
    };
    validate_request(&reconstructed)?;
    if stable_command_id(&reconstructed) != command_id || digest_request(&reconstructed) != digest {
        return Err(StoreError::Conflict(
            "bootstrap command identity or digest differs",
        ));
    }
    Ok(BootstrapSendRecord {
        receipt: Receipt {
            command_id,
            event_sequence,
            outbox_id,
            digest_version: DIGEST_VERSION,
            request_digest: digest,
        },
        scope_id: ScopeId::try_from(scope).map_err(|_| malformed())?,
        native_target: target,
        session_revision,
        holder_actor_id,
        holder_credential_generation: holder_generation,
        owner_epoch,
        manager_credential_epoch,
        authority_revision,
        writer_epoch,
        lease_expires_at_unix_seconds: lease_expiry,
        wire_payload_digest: wire_digest,
        prompt_text: text,
        deadline_at,
        effect_state,
        claim_key: outbox.8,
        claim_owner_epoch: outbox.9.map(|v| v as u64),
    })
}

fn selected_record(
    transaction: &Transaction<'_>,
    selector: &BootstrapSendSelector,
) -> Result<(i64, BootstrapSendRecord), StoreError> {
    let rowid: Option<i64> = transaction
        .query_row(
            "SELECT command_rowid FROM commands WHERE command_id=?1 AND scope_id=?2
           AND namespace=?3",
            params![
                selector.command_id.as_str(),
                selector.scope_id.as_str(),
                NAMESPACE
            ],
            |row| row.get(0),
        )
        .optional()?;
    let rowid = rowid.ok_or(StoreError::NotFound)?;
    let record = read_bootstrap_record(transaction, rowid)?;
    if record.scope_id != selector.scope_id {
        return Err(StoreError::WrongScope);
    }
    if record.native_target != selector.native_target {
        return Err(StoreError::StaleEpoch);
    }
    Ok((rowid, record))
}

fn check_current_record(
    transaction: &Transaction<'_>,
    lineage: &str,
    record: &BootstrapSendRecord,
) -> Result<(), StoreError> {
    let lease = checked_native_writer_lease(
        transaction,
        lineage,
        &record.native_target,
        &record.holder_actor_id,
        record.holder_credential_generation,
        record.owner_epoch,
        record.manager_credential_epoch,
        record.authority_revision,
        record.writer_epoch,
    )?;
    if lease.expires_at_unix_seconds() != record.lease_expires_at_unix_seconds
        || session_revision(transaction, &record.native_target)? != record.session_revision
    {
        return Err(StoreError::StaleEpoch);
    }
    check_deadline(transaction, record.deadline_at.as_deref())?;
    check_host_accepted_launch(transaction, &record.native_target, record.owner_epoch)
}

impl PodBayStore {
    /// CAS-claim one Prepared bootstrap before any pod/native call. An
    /// existing claim is historical uncertainty, never permission to replay.
    /// The trusted host must separately reauthenticate actor and grant.
    pub fn claim_bootstrap_send(
        &mut self,
        selector: &BootstrapSendSelector,
    ) -> Result<EffectClaim, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, record) = selected_record(&transaction, selector)?;
        let claim_key = format!("claim.{}", record.receipt.command_id);
        if record.effect_state != EffectState::Prepared {
            if record.claim_key.as_deref() != Some(claim_key.as_str()) {
                return Err(StoreError::Conflict("bootstrap claim identity differs"));
            }
            return Ok(EffectClaim::ExistingUncertain);
        }
        check_current_record(&transaction, &self.store_lineage, &record)?;
        let changed = transaction.execute(
            "UPDATE outbox SET state='claimed_uncertain',claim_key=?1,claim_owner_epoch=?2
             WHERE outbox_id=?3 AND state='prepared' AND kind=?4",
            params![
                claim_key,
                integer(record.owner_epoch)?,
                record.receipt.outbox_id,
                EFFECT_KIND
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::StaleEpoch);
        }
        transaction.commit()?;
        Ok(EffectClaim::NewClaim)
    }

    /// Read-only exact command and current-lease proof for a pod boundary.
    /// It supplies committed prompt bytes only after the typed outbox claim;
    /// it does not authenticate the connected manager or native child.
    pub fn inspect_claimed_bootstrap_send(
        &mut self,
        selector: &BootstrapSendSelector,
    ) -> Result<BootstrapSendRecord, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let (_, record) = selected_record(&transaction, selector)?;
        if record.effect_state != EffectState::ClaimedUncertain
            || record.claim_key.as_deref()
                != Some(format!("claim.{}", record.receipt.command_id).as_str())
            || record.claim_owner_epoch != Some(record.owner_epoch)
        {
            return Err(StoreError::Conflict(
                "bootstrap has no current claimed effect",
            ));
        }
        check_current_record(&transaction, &self.store_lineage, &record)?;
        transaction.commit()?;
        Ok(record)
    }
}
