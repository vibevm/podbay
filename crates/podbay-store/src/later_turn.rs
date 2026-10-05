//! Durable intent for subsequent Codex turns. This module never calls a
//! provider. A trusted host must prove BootstrapCompleted, native thread
//! identity, actor/grant, and live pod independently before using this path.

use podbay_core::{
    ActorId, AttemptId, CommandId, PodId, ResourceId, RunId, ScopeId, SessionId, StoreLineageId,
};
use podbay_wire::{CommandEnvelope, Target};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};

use crate::bootstrap_send::{
    check_deadline, check_host_accepted_launch, first_text, read_bootstrap_record, session_revision,
};
use crate::model::{
    Admission, CommandRequest, EffectClaim, EffectState, NativeWriterTarget, Receipt, StoreError,
    VerifiedPrincipal, DIGEST_VERSION,
};
use crate::store::{
    digest_request, integer, sha256_hex, stable_command_id, valid_id, validate_request, PodBayStore,
};
use crate::writer_lease::checked_native_writer_lease;

const NAMESPACE: &str = "podbay.session.send.later";
const EFFECT_KIND: &str = "codex.turn";
const EVENT_KIND: &str = "session.send.later.admitted";
const PAYLOAD_DOMAIN: &[u8] = b"podbay.codex.later-send/1\0";
const BINDING_DOMAIN: &[u8] = b"podbay.codex.later-binding/1\0";
const MAX_TEXT_BYTES: usize = 64_000;
const MAX_PAYLOAD_BYTES: usize = 128_000;

/// Forgeable input from a trusted host boundary, never a wire DTO. The host
/// must obtain a fresh authenticated pod-journal BootstrapCompleted and idle
/// proof for `native_thread_id`; the v22 store has no such native evidence.
pub struct TrustedLaterCodexSendRequest<'a> {
    pub principal: VerifiedPrincipal,
    pub scope_id: ScopeId,
    pub envelope: &'a CommandEnvelope,
    pub native_target: NativeWriterTarget,
    pub bootstrap_command_id: CommandId,
    pub native_thread_id: &'a str,
    pub holder_actor_id: ActorId,
    pub holder_credential_generation: u64,
    pub expected_owner_epoch: u64,
    pub expected_manager_credential_epoch: u64,
    pub expected_authority_revision: u64,
}

/// Selector only. The socket request must carry these identities and writer
/// epoch, never prompt bytes or a self-asserted writer permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaterCodexSendSelector {
    pub scope_id: ScopeId,
    pub command_id: CommandId,
    pub native_target: NativeWriterTarget,
}

/// Protected committed input and its original fences. `receipt` acknowledges
/// only fsynced intent; it does not mean a provider accepted or ran a turn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaterCodexSendRecord {
    receipt: Receipt,
    scope_id: ScopeId,
    native_target: NativeWriterTarget,
    bootstrap_command_id: CommandId,
    native_thread_id: String,
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

impl LaterCodexSendRecord {
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
    pub fn scope_id(&self) -> &ScopeId {
        &self.scope_id
    }
    pub fn native_target(&self) -> &NativeWriterTarget {
        &self.native_target
    }
    pub fn bootstrap_command_id(&self) -> &CommandId {
        &self.bootstrap_command_id
    }
    pub fn native_thread_id(&self) -> &str {
        &self.native_thread_id
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

fn valid_thread_id(value: &str) -> bool {
    (1..=256).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn same_resource_anchor(bootstrap: &NativeWriterTarget, current: &NativeWriterTarget) -> bool {
    bootstrap.store_lineage == current.store_lineage
        && bootstrap.scope_id == current.scope_id
        && bootstrap.session_id == current.session_id
        && bootstrap.run_id == current.run_id
        && bootstrap.attempt_id == current.attempt_id
        && bootstrap.pod_id == current.pod_id
        && bootstrap.pod_incarnation == current.pod_incarnation
        && bootstrap.resource_id == current.resource_id
        && bootstrap.resource_epoch == current.resource_epoch
        && bootstrap.resource_input_epoch <= current.resource_input_epoch
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn positive(value: i64, reason: &'static str) -> Result<u64, StoreError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(StoreError::Conflict(reason))
}

fn put_field(out: &mut Vec<u8>, value: &[u8]) -> Result<(), StoreError> {
    let length = u32::try_from(value.len())
        .map_err(|_| StoreError::InvalidInput("later turn field exceeds bound"))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn canonical_payload(
    wire_digest: &str,
    deadline: Option<&str>,
    text: &str,
    bootstrap_command_id: &CommandId,
    native_thread_id: &str,
) -> Result<Vec<u8>, StoreError> {
    if !valid_digest(wire_digest)
        || text.is_empty()
        || text.len() > MAX_TEXT_BYTES
        || !valid_thread_id(native_thread_id)
    {
        return Err(StoreError::InvalidInput(
            "later turn payload or native thread is invalid",
        ));
    }
    let mut bytes = PAYLOAD_DOMAIN.to_vec();
    for field in [
        wire_digest,
        deadline.unwrap_or(""),
        text,
        bootstrap_command_id.as_str(),
        native_thread_id,
    ] {
        put_field(&mut bytes, field.as_bytes())?;
    }
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(StoreError::InvalidInput("later turn payload exceeds bound"));
    }
    Ok(bytes)
}

fn decode_payload(
    bytes: &[u8],
) -> Result<(String, Option<String>, String, CommandId, String), StoreError> {
    if bytes.len() > MAX_PAYLOAD_BYTES || !bytes.starts_with(PAYLOAD_DOMAIN) {
        return Err(StoreError::Conflict("later turn payload domain differs"));
    }
    let mut at = PAYLOAD_DOMAIN.len();
    let mut field = || -> Result<String, StoreError> {
        let size = bytes
            .get(at..at + 4)
            .ok_or(StoreError::Conflict("later turn payload is truncated"))?;
        let length = u32::from_be_bytes(size.try_into().expect("four bytes")) as usize;
        at += 4;
        let end = at
            .checked_add(length)
            .ok_or(StoreError::Conflict("later turn length overflows"))?;
        let raw = bytes
            .get(at..end)
            .ok_or(StoreError::Conflict("later turn payload is truncated"))?;
        at = end;
        String::from_utf8(raw.to_vec())
            .map_err(|_| StoreError::Conflict("later turn payload is not UTF-8"))
    };
    let digest = field()?;
    let deadline = field()?;
    let text = field()?;
    let bootstrap = field()?;
    let thread = field()?;
    let bootstrap = CommandId::try_from(bootstrap.as_str())
        .map_err(|_| StoreError::Conflict("later turn bootstrap ID is malformed"))?;
    if at != bytes.len()
        || !valid_digest(&digest)
        || text.is_empty()
        || text.len() > MAX_TEXT_BYTES
        || !valid_thread_id(&thread)
    {
        return Err(StoreError::Conflict("later turn payload is not canonical"));
    }
    let deadline = (!deadline.is_empty()).then_some(deadline);
    if canonical_payload(&digest, deadline.as_deref(), &text, &bootstrap, &thread)? != bytes {
        return Err(StoreError::Conflict("later turn payload is not canonical"));
    }
    Ok((digest, deadline, text, bootstrap, thread))
}

#[allow(clippy::too_many_arguments)]
fn binding_digest(
    target: &NativeWriterTarget,
    bootstrap: &CommandId,
    native_thread_id: &str,
    revision: u64,
    holder: &ActorId,
    generation: u64,
    owner: u64,
    manager_credential: u64,
    authority_revision: u64,
    writer_epoch: u64,
    lease_expiry: u64,
    wire_digest: &str,
    prompt_digest: &str,
) -> Result<String, StoreError> {
    let mut bytes = BINDING_DOMAIN.to_vec();
    for field in [
        target.store_lineage.as_str(),
        target.scope_id.as_str(),
        target.session_id.as_str(),
        target.run_id.as_str(),
        target.attempt_id.as_str(),
        target.pod_id.as_str(),
        target.resource_id.as_str(),
        bootstrap.as_str(),
        native_thread_id,
        holder.as_str(),
        wire_digest,
        prompt_digest,
    ] {
        put_field(&mut bytes, field.as_bytes())?;
    }
    for value in [
        revision,
        target.pod_incarnation,
        target.resource_epoch,
        target.resource_input_epoch,
        generation,
        owner,
        manager_credential,
        authority_revision,
        writer_epoch,
        lease_expiry,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    Ok(sha256_hex(&bytes))
}

impl PodBayStore {
    /// Historical claimed receipt for read-only native observation after a
    /// manager/writer takeover. Callers must separately verify today's exact
    /// Resource, manager, actor and live writer lease. Never use for send.
    pub fn inspect_historical_claimed_later_codex_send(
        &mut self,
        selector: &LaterCodexSendSelector,
    ) -> Result<LaterCodexSendRecord, StoreError> {
        let transaction = self.connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let rowid: i64 = transaction.query_row(
            "SELECT command_rowid FROM commands WHERE command_id=?1 AND scope_id=?2 AND namespace=?3",
            params![selector.command_id.as_str(), selector.scope_id.as_str(), NAMESPACE],
            |row| row.get(0),
        ).optional()?.ok_or(StoreError::NotFound)?;
        let record = read_later_record(&transaction, rowid)?;
        if record.scope_id != selector.scope_id
            || !same_resource_anchor(&record.native_target, &selector.native_target) {
            return Err(StoreError::StaleEpoch);
        }
        if record.effect_state != EffectState::ClaimedUncertain
            || record.claim_key.as_deref()
                != Some(format!("claim.{}", record.receipt.command_id).as_str())
            || record.claim_owner_epoch != Some(record.owner_epoch)
        {
            return Err(StoreError::Conflict("later turn has no claimed effect"));
        }
        transaction.commit()?;
        Ok(record)
    }

    /// Authenticated caller's exact claimed later-turn selector. This lookup
    /// reads durable history only; the host rechecks today's pod and lease.
    pub fn claimed_later_turn_selector_for_command(
        &mut self,
        principal: &VerifiedPrincipal,
        scope_id: &ScopeId,
        command_id: &CommandId,
    ) -> Result<Option<(LaterCodexSendSelector, u64)>, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let rowid: Option<i64> = transaction
            .query_row(
                "SELECT command_rowid FROM commands WHERE command_id=?1 AND principal=?2
             AND scope_id=?3 AND namespace=?4",
                params![
                    command_id.as_str(),
                    principal.as_str(),
                    scope_id.as_str(),
                    NAMESPACE
                ],
                |row| row.get(0),
            )
            .optional()?;
        let result = if let Some(rowid) = rowid {
            let record = read_later_record(&transaction, rowid)?;
            if record.effect_state() == EffectState::ClaimedUncertain {
                Some((
                    LaterCodexSendSelector {
                        scope_id: scope_id.clone(),
                        command_id: command_id.clone(),
                        native_target: record.native_target().clone(),
                    },
                    record.writer_epoch(),
                ))
            } else {
                None
            }
        } else {
            None
        };
        transaction.commit()?;
        Ok(result)
    }

    /// Principal/scope/key lookup before the current writer exists. Compare
    /// only immutable wire input; return the old native anchor from readback.
    /// The host authenticates `principal` and `scope_id` before calling.
    pub fn lookup_later_codex_send_for_envelope(
        &mut self,
        principal: &VerifiedPrincipal,
        scope_id: &ScopeId,
        envelope: &CommandEnvelope,
    ) -> Result<Option<LaterCodexSendRecord>, StoreError> {
        valid_id(&envelope.key)?;
        let Target::Session { session_id } = &envelope.target else {
            return Err(StoreError::InvalidInput(
                "later turn requires Session target",
            ));
        };
        let session = SessionId::try_from(session_id.as_str())
            .map_err(|_| StoreError::InvalidInput("later turn Session ID is invalid"))?;
        let text = first_text(envelope, &session)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let rowid: Option<i64> = transaction
            .query_row(
                "SELECT command_rowid FROM commands WHERE principal=?1 AND namespace=?2
             AND command_key=?3 AND scope_id=?4 AND target_id=?5",
                params![
                    principal.as_str(),
                    NAMESPACE,
                    envelope.key,
                    scope_id.as_str(),
                    session.as_str()
                ],
                |row| row.get(0),
            )
            .optional()?;
        let Some(rowid) = rowid else {
            transaction.commit()?;
            return Ok(None);
        };
        let record = read_later_record(&transaction, rowid)?;
        if record.wire_payload_digest != envelope.payload_digest
            || record.prompt_text != text
            || record.deadline_at.as_deref() != envelope.deadline_at.as_deref()
        {
            return Err(StoreError::Conflict(
                "later turn key changed canonical payload",
            ));
        }
        transaction.commit()?;
        Ok(Some(record))
    }

    /// Authenticated-principal lookup before today's mutable grant and writer
    /// fences. A miss grants nothing. The returned prompt is protected input.
    pub fn lookup_later_codex_send_by_key(
        &mut self,
        principal: &VerifiedPrincipal,
        scope_id: &ScopeId,
        envelope: &CommandEnvelope,
        bootstrap_command_id: &CommandId,
        native_thread_id: &str,
    ) -> Result<Option<LaterCodexSendRecord>, StoreError> {
        valid_id(&envelope.key)?;
        let Target::Session { session_id } = &envelope.target else {
            return Err(StoreError::InvalidInput(
                "later turn requires Session target",
            ));
        };
        let session = SessionId::try_from(session_id.as_str())
            .map_err(|_| StoreError::InvalidInput("later turn Session ID is invalid"))?;
        let text = first_text(envelope, &session)?;
        let canonical = canonical_payload(
            &envelope.payload_digest,
            envelope.deadline_at.as_deref(),
            text,
            bootstrap_command_id,
            native_thread_id,
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let existing: Option<(i64, String, String, Vec<u8>)> = transaction
            .query_row(
                "SELECT command_rowid,scope_id,target_id,canonical_request FROM commands
             WHERE principal=?1 AND namespace=?2 AND command_key=?3",
                params![principal.as_str(), NAMESPACE, envelope.key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((rowid, scope, target, bytes)) = existing else {
            transaction.commit()?;
            return Ok(None);
        };
        if scope != scope_id.as_str() || target != session.as_str() {
            return Err(StoreError::NotFound);
        }
        if bytes != canonical {
            return Err(StoreError::Conflict(
                "later turn key changed canonical payload",
            ));
        }
        let record = read_later_record(&transaction, rowid)?;
        transaction.commit()?;
        Ok(Some(record))
    }

    /// Exact committed readback for an authenticated principal and scope.
    /// This inspects fsynced intent and original fences, never native outcome.
    pub fn inspect_later_codex_send(
        &mut self,
        principal: &VerifiedPrincipal,
        scope_id: &ScopeId,
        command_id: &CommandId,
    ) -> Result<LaterCodexSendRecord, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let rowid: Option<i64> = transaction
            .query_row(
                "SELECT command_rowid FROM commands WHERE command_id=?1 AND principal=?2
             AND scope_id=?3 AND namespace=?4",
                params![
                    command_id.as_str(),
                    principal.as_str(),
                    scope_id.as_str(),
                    NAMESPACE
                ],
                |row| row.get(0),
            )
            .optional()?;
        let record = read_later_record(&transaction, rowid.ok_or(StoreError::NotFound)?)?;
        transaction.commit()?;
        Ok(record)
    }

    /// One durable later-turn intent. The receipt is **not** provider
    /// insertion, turn/start acceptance, completion, or a native permit.
    pub fn admit_later_codex_send(
        &mut self,
        request: &TrustedLaterCodexSendRequest<'_>,
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
            &request.bootstrap_command_id,
            request.native_thread_id,
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // A scoped, authenticated duplicate is an immutable old receipt, not
        // a new native effect. Check it before current manager/lease/deadline.
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
                return Err(StoreError::NotFound);
            }
            if bytes != canonical {
                return Err(StoreError::Conflict(
                    "later turn key changed canonical payload",
                ));
            }
            let record = read_later_record(&transaction, rowid)?;
            transaction.commit()?;
            return Ok(Admission::Duplicate(record.receipt));
        }
        let current_revision: i64 = transaction.query_row(
            "SELECT value FROM metadata WHERE key='authority_revision'",
            [],
            |row| row.get(0),
        )?;
        if current_revision != integer(request.expected_authority_revision)? {
            return Err(StoreError::StaleEpoch);
        }
        let guard = request
            .envelope
            .guard
            .as_ref()
            .ok_or(StoreError::InvalidInput(
                "later turn requires exact wire guards",
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
            request.expected_manager_credential_epoch,
        )?;
        let bootstrap_rowid: Option<i64> = transaction
            .query_row(
                "SELECT command_rowid FROM commands WHERE command_id=?1",
                [request.bootstrap_command_id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        let bootstrap =
            read_bootstrap_record(&transaction, bootstrap_rowid.ok_or(StoreError::NotFound)?)?;
        if bootstrap.receipt().command_id != request.bootstrap_command_id.as_str()
            || bootstrap.scope_id() != &request.scope_id
            || !same_resource_anchor(bootstrap.native_target(), &request.native_target)
            || bootstrap.holder_actor_id() != &request.holder_actor_id
            || bootstrap.effect_state() != EffectState::ClaimedUncertain
        {
            return Err(StoreError::Conflict("later turn bootstrap anchor differs"));
        }
        let prior_thread: Option<String> = transaction
            .query_row(
                "SELECT native_thread_id FROM codex_later_turns WHERE session_id=?1
             ORDER BY command_rowid LIMIT 1",
                [request.native_target.session_id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        if prior_thread
            .as_deref()
            .is_some_and(|value| value != request.native_thread_id)
        {
            return Err(StoreError::Conflict(
                "later turn native thread anchor differs",
            ));
        }
        let prompt_digest = sha256_hex(text.as_bytes());
        let exact_binding_digest = binding_digest(
            &request.native_target,
            &request.bootstrap_command_id,
            request.native_thread_id,
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
            "INSERT INTO codex_later_turns(command_rowid,bootstrap_command_rowid,store_lineage,
               scope_id,session_id,session_revision,run_id,attempt_id,pod_id,pod_incarnation,
               resource_id,resource_epoch,resource_input_epoch,native_thread_id,holder_actor_id,
               holder_credential_generation,owner_epoch,manager_credential_epoch,
               authority_revision,writer_epoch,lease_expires_at_unix_seconds,
               wire_payload_digest,prompt_digest,binding_digest)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,
                    ?18,?19,?20,?21,?22,?23,?24)",
            params![
                rowid,
                bootstrap_rowid,
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
                request.native_thread_id,
                request.holder_actor_id.as_str(),
                integer(request.holder_credential_generation)?,
                integer(request.expected_owner_epoch)?,
                integer(request.expected_manager_credential_epoch)?,
                integer(request.expected_authority_revision)?,
                integer(writer_epoch)?,
                integer(lease.expires_at_unix_seconds())?,
                request.envelope.payload_digest,
                prompt_digest,
                exact_binding_digest
            ],
        )?;
        transaction.execute(
            "UPDATE commands SET event_sequence=?1,outbox_id=?2 WHERE command_rowid=?3",
            params![event_sequence, outbox_id, rowid],
        )?;
        let record = read_later_record(&transaction, rowid)?;
        transaction.commit()?;
        Ok(Admission::Committed(record.receipt))
    }
}

struct BindingRow {
    bootstrap_rowid: i64,
    lineage: String,
    scope: String,
    session: String,
    session_revision: i64,
    run: String,
    attempt: String,
    pod: String,
    pod_incarnation: i64,
    resource: String,
    resource_epoch: i64,
    resource_input_epoch: i64,
    native_thread_id: String,
    holder: String,
    holder_generation: i64,
    owner_epoch: i64,
    manager_credential_epoch: i64,
    authority_revision: i64,
    writer_epoch: i64,
    lease_expiry: i64,
    wire_digest: String,
    prompt_digest: String,
    binding_digest: String,
}

fn read_later_record(
    transaction: &Transaction<'_>,
    rowid: i64,
) -> Result<LaterCodexSendRecord, StoreError> {
    let header: Option<(
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
    )> = transaction
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
        .optional()?;
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
        command_owner,
        command_revision,
        event_sequence,
        outbox_id,
    ) = header.ok_or(StoreError::NotFound)?;
    if namespace != NAMESPACE
        || version != DIGEST_VERSION
        || !valid_digest(&digest)
        || event_sequence.is_none_or(|value| value <= 0)
        || outbox_id.is_none_or(|value| value <= 0)
    {
        return Err(StoreError::Conflict("later turn command header differs"));
    }
    let event_sequence = event_sequence.expect("checked event sequence");
    let outbox_id = outbox_id.expect("checked outbox id");
    let (wire_digest, deadline, text, bootstrap_id, thread_id) = decode_payload(&canonical)?;
    let binding: Option<BindingRow> = transaction
        .query_row(
            "SELECT bootstrap_command_rowid,store_lineage,scope_id,session_id,session_revision,
                run_id,attempt_id,pod_id,pod_incarnation,resource_id,resource_epoch,
                resource_input_epoch,native_thread_id,holder_actor_id,
                holder_credential_generation,owner_epoch,manager_credential_epoch,
                authority_revision,writer_epoch,lease_expires_at_unix_seconds,
                wire_payload_digest,prompt_digest,binding_digest
         FROM codex_later_turns WHERE command_rowid=?1",
            [rowid],
            |row| {
                Ok(BindingRow {
                    bootstrap_rowid: row.get(0)?,
                    lineage: row.get(1)?,
                    scope: row.get(2)?,
                    session: row.get(3)?,
                    session_revision: row.get(4)?,
                    run: row.get(5)?,
                    attempt: row.get(6)?,
                    pod: row.get(7)?,
                    pod_incarnation: row.get(8)?,
                    resource: row.get(9)?,
                    resource_epoch: row.get(10)?,
                    resource_input_epoch: row.get(11)?,
                    native_thread_id: row.get(12)?,
                    holder: row.get(13)?,
                    holder_generation: row.get(14)?,
                    owner_epoch: row.get(15)?,
                    manager_credential_epoch: row.get(16)?,
                    authority_revision: row.get(17)?,
                    writer_epoch: row.get(18)?,
                    lease_expiry: row.get(19)?,
                    wire_digest: row.get(20)?,
                    prompt_digest: row.get(21)?,
                    binding_digest: row.get(22)?,
                })
            },
        )
        .optional()?;
    let b = binding.ok_or(StoreError::Conflict("later turn binding is missing"))?;
    if b.scope != scope
        || b.session != session
        || b.owner_epoch != command_owner
        || b.session_revision != command_revision
        || b.wire_digest != wire_digest
        || b.prompt_digest != sha256_hex(text.as_bytes())
        || b.native_thread_id != thread_id
        || !valid_digest(&b.binding_digest)
        || !valid_thread_id(&b.native_thread_id)
    {
        return Err(StoreError::Conflict(
            "later turn binding differs from command",
        ));
    }
    let malformed = || StoreError::Conflict("later turn binding identity is malformed");
    let target = NativeWriterTarget {
        store_lineage: StoreLineageId::try_from(b.lineage.as_str()).map_err(|_| malformed())?,
        scope_id: ScopeId::try_from(b.scope.as_str()).map_err(|_| malformed())?,
        session_id: SessionId::try_from(b.session.as_str()).map_err(|_| malformed())?,
        run_id: RunId::try_from(b.run.as_str()).map_err(|_| malformed())?,
        attempt_id: AttemptId::try_from(b.attempt.as_str()).map_err(|_| malformed())?,
        pod_id: PodId::try_from(b.pod.as_str()).map_err(|_| malformed())?,
        pod_incarnation: positive(b.pod_incarnation, "later turn Pod incarnation is invalid")?,
        resource_id: ResourceId::try_from(b.resource.as_str()).map_err(|_| malformed())?,
        resource_epoch: positive(b.resource_epoch, "later turn Resource epoch is invalid")?,
        resource_input_epoch: positive(
            b.resource_input_epoch,
            "later turn input epoch is invalid",
        )?,
    };
    let holder = ActorId::try_from(b.holder.as_str()).map_err(|_| malformed())?;
    if principal != holder.as_str() {
        return Err(StoreError::Conflict(
            "later turn principal differs from writer holder",
        ));
    }
    let revision = positive(b.session_revision, "later turn Session revision is invalid")?;
    let generation = positive(
        b.holder_generation,
        "later turn holder generation is invalid",
    )?;
    let owner_epoch = positive(b.owner_epoch, "later turn owner epoch is invalid")?;
    let manager_credential = positive(
        b.manager_credential_epoch,
        "later turn manager credential is invalid",
    )?;
    let authority_revision = positive(
        b.authority_revision,
        "later turn authority revision is invalid",
    )?;
    let writer_epoch = positive(b.writer_epoch, "later turn writer epoch is invalid")?;
    let lease_expiry = positive(b.lease_expiry, "later turn lease expiry is invalid")?;
    let bootstrap = read_bootstrap_record(transaction, b.bootstrap_rowid)?;
    if bootstrap.receipt().command_id != bootstrap_id.as_str()
        || bootstrap.scope_id() != &target.scope_id
        || !same_resource_anchor(bootstrap.native_target(), &target)
        || bootstrap.holder_actor_id() != &holder
        || bootstrap.effect_state() != EffectState::ClaimedUncertain
    {
        return Err(StoreError::Conflict("later turn bootstrap anchor differs"));
    }
    let computed_binding = binding_digest(
        &target,
        &bootstrap_id,
        &thread_id,
        revision,
        &holder,
        generation,
        owner_epoch,
        manager_credential,
        authority_revision,
        writer_epoch,
        lease_expiry,
        &wire_digest,
        &b.prompt_digest,
    )?;
    if computed_binding != b.binding_digest {
        return Err(StoreError::Conflict("later turn binding digest differs"));
    }
    let outbox: Option<(
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
    )> = transaction
        .query_row(
            "SELECT scope_id,target_id,owner_epoch,target_epoch,kind,payload,effect_digest,
                    state,claim_key,claim_owner_epoch,observation_key,observation_payload,
                    observation_stage,observation_event_sequence
             FROM outbox WHERE outbox_id=?1 AND command_rowid=?2",
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
        .optional()?;
    let outbox = outbox.ok_or(StoreError::Conflict("later turn outbox is missing"))?;
    if outbox.0 != scope
        || outbox.1 != session
        || outbox.2 != command_owner
        || outbox.3 != command_revision
        || outbox.4 != EFFECT_KIND
        || outbox.5 != canonical
        || outbox.6 != sha256_hex(&outbox.5)
        || outbox.10.is_some()
        || outbox.11.is_some()
        || outbox.12.is_some()
        || outbox.13.is_some()
    {
        return Err(StoreError::Conflict(
            "later turn outbox differs from command",
        ));
    }
    let effect_state = match outbox.7.as_str() {
        "prepared" if outbox.8.is_none() && outbox.9.is_none() => EffectState::Prepared,
        "claimed_uncertain"
            if outbox.8.as_deref() == Some(format!("claim.{command_id}").as_str())
                && outbox.9 == Some(command_owner) =>
        {
            EffectState::ClaimedUncertain
        }
        _ => return Err(StoreError::Conflict("later turn outbox stage is malformed")),
    };
    let event: Option<(
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
    )> = transaction
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
        .optional()?;
    let event = event.ok_or(StoreError::Conflict(
        "later turn admission event is missing",
    ))?;
    if event.0 != EVENT_KIND
        || event.1 != b.binding_digest.as_bytes()
        || event.2 != scope
        || event.3 != session
        || event.4 != command_owner
        || event.5 != command_revision
        || event.6 != command_id
        || event.7 != "manager.admission"
        || event.8 != digest
        || event.9 != command_owner
        || event.10 != 1
        || event.11 != "authenticated.manager.admission"
    {
        return Err(StoreError::Conflict("later turn admission event differs"));
    }
    let reconstructed = CommandRequest {
        principal: VerifiedPrincipal::from_authenticated_boundary(&principal)?,
        namespace,
        command_key: key,
        scope_id: scope.clone(),
        target_id: session.clone(),
        expected_owner_epoch: owner_epoch,
        expected_target_epoch: revision,
        canonical_request: canonical.clone(),
        event_kind: EVENT_KIND.into(),
        event_payload: b.binding_digest.as_bytes().to_vec(),
        effect_kind: EFFECT_KIND.into(),
        effect_payload: canonical,
    };
    validate_request(&reconstructed)?;
    if stable_command_id(&reconstructed) != command_id || digest_request(&reconstructed) != digest {
        return Err(StoreError::Conflict(
            "later turn command identity or digest differs",
        ));
    }
    Ok(LaterCodexSendRecord {
        receipt: Receipt {
            command_id,
            event_sequence,
            outbox_id,
            digest_version: DIGEST_VERSION,
            request_digest: digest,
        },
        scope_id: target.scope_id.clone(),
        native_target: target,
        bootstrap_command_id: bootstrap_id,
        native_thread_id: thread_id,
        session_revision: revision,
        holder_actor_id: holder,
        holder_credential_generation: generation,
        owner_epoch,
        manager_credential_epoch: manager_credential,
        authority_revision,
        writer_epoch,
        lease_expires_at_unix_seconds: lease_expiry,
        wire_payload_digest: wire_digest,
        prompt_text: text,
        deadline_at: deadline,
        effect_state,
        claim_key: outbox.8,
        claim_owner_epoch: outbox.9.map(|value| value as u64),
    })
}

fn selected_record(
    transaction: &Transaction<'_>,
    selector: &LaterCodexSendSelector,
) -> Result<(i64, LaterCodexSendRecord), StoreError> {
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
    let record = read_later_record(transaction, rowid)?;
    if record.scope_id != selector.scope_id {
        return Err(StoreError::NotFound);
    }
    if record.native_target != selector.native_target {
        return Err(StoreError::StaleEpoch);
    }
    Ok((rowid, record))
}

fn check_current_record(
    transaction: &Transaction<'_>,
    lineage: &str,
    record: &LaterCodexSendRecord,
) -> Result<(), StoreError> {
    // The command was admitted at one exact authority revision. A changed
    // grant or profile after admission cannot inherit its Prepared claim.
    let current_revision: i64 = transaction.query_row(
        "SELECT value FROM metadata WHERE key='authority_revision'",
        [],
        |row| row.get(0),
    )?;
    if current_revision != integer(record.authority_revision)? {
        return Err(StoreError::StaleEpoch);
    }
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
    check_host_accepted_launch(
        transaction,
        &record.native_target,
        record.owner_epoch,
        record.manager_credential_epoch,
    )
}

impl PodBayStore {
    /// CAS-claim before any pod/native call. A prior claim is uncertainty,
    /// never permission to replay. The host must separately reauthenticate
    /// the actor/grant and attest a live pod plus journal idle proof.
    pub fn claim_later_codex_send(
        &mut self,
        selector: &LaterCodexSendSelector,
    ) -> Result<EffectClaim, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, record) = selected_record(&transaction, selector)?;
        let claim_key = format!("claim.{}", record.receipt.command_id);
        if record.effect_state != EffectState::Prepared {
            if record.claim_key.as_deref() != Some(claim_key.as_str())
                || record.claim_owner_epoch != Some(record.owner_epoch)
            {
                return Err(StoreError::Conflict("later turn claim identity differs"));
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

    /// Exact same-snapshot claimed input for an authenticated pod boundary.
    /// This exposes protected prompt bytes only after a typed claim and fresh
    /// durable fences; it cannot prove the connected manager or native child.
    pub fn inspect_claimed_later_codex_send(
        &mut self,
        selector: &LaterCodexSendSelector,
    ) -> Result<LaterCodexSendRecord, StoreError> {
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
                "later turn has no current claimed effect",
            ));
        }
        check_current_record(&transaction, &self.store_lineage, &record)?;
        transaction.commit()?;
        Ok(record)
    }
}
