//! Durable structured-provider writer exclusion. These rows are store facts,
//! never OS attestations, grants, pod liveness, or native effect permits.

use podbay_core::{
    ActorId, AttemptId, PodId, ResourceId, RunId, ScopeId, SessionId, StoreLineageId,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use crate::bound_launch::{BoundLaunchFormat, read_bound_record};
use crate::model::{
    CommandRequest, NativeWriterLease, NativeWriterRenewalReceipt, NativeWriterRenewalRequest,
    NativeWriterTarget, Receipt, StoreError, TrustedNativeWriterLeaseRequest, DIGEST_VERSION,
};
use crate::store::{PodBayStore, digest_request, stable_command_id, validate_request, sha256_hex};

/// A lease limits the time during which a future host/pod may start native
/// input. An already accepted model turn is not cancelled when this expires.
const MAX_TTL_SECONDS: u64 = 3_600;

impl PodBayStore {
    /// Atomically commit an exact renewal and its keyed, replayable command
    /// receipt. A duplicate key returns its original expiry without touching
    /// the lease, even after another renewal or the original expiry.
    pub fn renew_native_writer_lease_with_receipt(
        &mut self,
        request: &NativeWriterRenewalRequest,
    ) -> Result<NativeWriterRenewalReceipt, StoreError> {
        if !(1..=MAX_TTL_SECONDS).contains(&request.ttl_seconds)
            || request.expected_writer_epoch == 0 || request.expected_expiry == 0
        {
            return Err(StoreError::InvalidInput("native writer renewal bounds"));
        }
        let command = CommandRequest {
            principal: request.principal.clone(),
            namespace: "session.writerLease.renew".into(),
            command_key: request.command_key.clone(),
            scope_id: request.target.scope_id.as_str().into(),
            target_id: request.target.session_id.as_str().into(),
            expected_owner_epoch: request.owner_epoch,
            expected_target_epoch: request.target.resource_epoch,
            canonical_request: request.canonical_request.clone(),
            event_kind: "native_writer_lease.renewed".into(),
            event_payload: request.canonical_request.clone(),
            effect_kind: "native_writer_lease.renew".into(),
            effect_payload: request.canonical_request.clone(),
        };
        validate_request(&command)?;
        let digest = digest_request(&command);
        let command_id = stable_command_id(&command);
        let transaction = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(i64, String, String, Vec<u8>, i64, i64, i64, i64, i64, i64)> = transaction.query_row(
            "SELECT c.command_rowid,c.command_id,c.request_digest,c.canonical_request,
                    c.owner_epoch,c.target_epoch,c.event_sequence,c.outbox_id,
                    r.writer_epoch,r.renewed_expiry
             FROM commands c JOIN native_writer_renewals r ON r.command_rowid=c.command_rowid
             WHERE c.principal=?1 AND c.namespace=?2 AND c.command_key=?3",
            params![request.principal.as_str(), command.namespace, request.command_key],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,
                      row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?)),
        ).optional()?;
        if let Some((rowid, old_id, old_digest, old_bytes, owner, epoch, event, outbox, writer, expiry)) = existing {
            let original: Option<(String,String,String,i64)> = transaction.query_row(
                "SELECT r.scope_id,r.session_id,r.resource_id,r.expected_expiry
                 FROM native_writer_renewals r WHERE r.command_rowid=?1",
                [rowid], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
            ).optional()?;
            if old_id != command_id || old_digest != digest || old_bytes != command.canonical_request
                || owner != sql_integer(request.owner_epoch)?
                || epoch != sql_integer(request.target.resource_epoch)?
                || original != Some((command.scope_id.clone(),command.target_id.clone(),
                    request.target.resource_id.as_str().into(),sql_integer(request.expected_expiry)?))
                || event < 1 || outbox < 1 || writer != sql_integer(request.expected_writer_epoch)?
                || expiry <= sql_integer(request.expected_expiry)?
            {
                return Err(StoreError::Conflict("native writer renewal key changed"));
            }
            let lineage: Option<(String, String, String, String, String, Vec<u8>, i64, String, String, String)> = transaction.query_row(
                "SELECT e.kind,e.provenance,o.kind,o.state,o.observation_stage,
                        o.observation_payload,o.observation_event_sequence,
                        o.effect_digest,observed.kind,observed.provenance
                 FROM events e JOIN outbox o ON o.command_rowid=e.command_rowid
                 JOIN events observed ON observed.sequence=o.observation_event_sequence
                 WHERE e.sequence=?1 AND o.outbox_id=?2 AND e.command_rowid=?3",
                params![event,outbox,rowid],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,
                    row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?)),
            ).optional()?;
            let expected_result = format!("{{\"writerEpoch\":\"{}\",\"leaseExpiresAtUnixSeconds\":\"{}\"}}",
                writer, expiry).into_bytes();
            if !lineage.is_some_and(|(event_kind, provenance, effect_kind, state, stage, payload, observed, effect_digest, observed_kind, observed_provenance)| {
                event_kind == "native_writer_lease.renewed"
                    && provenance == "authenticated.manager.admission"
                    && effect_kind == "native_writer_lease.renew"
                    && state == "observed" && stage == "lease_renewed"
                    && payload == expected_result && observed > event
                    && effect_digest == sha256_hex(&command.effect_payload)
                    && observed_kind == "native_writer_lease.renewed"
                    && observed_provenance == "authenticated.manager.lease"
            }) {
                return Err(StoreError::Conflict("native writer renewal receipt differs"));
            }
            transaction.commit()?;
            return Ok(NativeWriterRenewalReceipt {
                command: Receipt { command_id, event_sequence: event, outbox_id: outbox,
                    digest_version: DIGEST_VERSION, request_digest: digest },
                scope_id: request.target.scope_id.clone(),
                writer_epoch: writer as u64, expires_at_unix_seconds: expiry as u64,
                duplicate: true,
            });
        }
        let format = check_current_target(&transaction, &self.store_lineage, &request.target)?;
        check_manager(&transaction, &self.store_lineage, request.owner_epoch,
            request.manager_credential_epoch, request.authority_revision,
            format != BoundLaunchFormat::CodexV3)?;
        check_actor(&transaction, &request.target.scope_id, &request.holder_actor_id,
            request.holder_credential_generation)?;
        let prior = read_lease(&transaction, &request.target.resource_id)?.ok_or(StoreError::NotFound)?;
        let now = current_unix_seconds(&transaction)?;
        if prior.target != request.target || prior.holder_actor_id != request.holder_actor_id
            || prior.holder_credential_generation != request.holder_credential_generation
            || prior.owner_epoch != request.owner_epoch
            || prior.manager_credential_epoch != request.manager_credential_epoch
            || (if format == BoundLaunchFormat::CodexV3 {
                prior.authority_revision > request.authority_revision
            } else {
                prior.authority_revision != request.authority_revision
            })
            || prior.writer_epoch != request.expected_writer_epoch
            || prior.expires_at_unix_seconds != request.expected_expiry
            || prior.expires_at_unix_seconds <= now
        { return Err(StoreError::StaleEpoch); }
        let expiry = now.checked_add(request.ttl_seconds)
            .filter(|value| *value <= i64::MAX as u64 && *value > request.expected_expiry)
            .ok_or(StoreError::InvalidInput("native writer renewal must extend expiry"))?;
        let changed = transaction.execute(
            "UPDATE native_writer_leases SET expires_at_unix_seconds=?2
             WHERE resource_id=?1 AND writer_epoch=?3 AND expires_at_unix_seconds=?4",
            params![request.target.resource_id.as_str(),sql_integer(expiry)?,
                sql_integer(request.expected_writer_epoch)?,sql_integer(request.expected_expiry)?],
        )?;
        if changed != 1 { return Err(StoreError::StaleEpoch); }
        transaction.execute(
            "INSERT INTO commands(command_id,principal,namespace,command_key,scope_id,target_id,
             digest_version,request_digest,canonical_request,owner_epoch,target_epoch)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![command_id,command.principal.as_str(),command.namespace,command.command_key,
                command.scope_id,command.target_id,DIGEST_VERSION,digest,command.canonical_request,
                sql_integer(command.expected_owner_epoch)?,sql_integer(command.expected_target_epoch)?],
        )?;
        let rowid = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO native_writer_renewals(command_rowid,scope_id,session_id,resource_id,
             writer_epoch,expected_expiry,renewed_expiry) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![rowid,command.scope_id,command.target_id,request.target.resource_id.as_str(),
                sql_integer(request.expected_writer_epoch)?,sql_integer(request.expected_expiry)?,sql_integer(expiry)?],
        )?;
        transaction.execute(
            "INSERT INTO events(event_id,schema_version,command_rowid,scope_id,target_id,
             owner_epoch,target_epoch,source_id,source_kind,source_epoch,source_sequence,
             source_digest,source_order,kind,payload,recorded_at,provenance,causation_id)
             VALUES('event.pb24.' || lower(hex(randomblob(16))),1,?1,?2,?3,?4,?5,?6,
             'manager.admission',?4,1,?7,'contiguous','native_writer_lease.renewed',?8,
             strftime('%Y-%m-%dT%H:%M:%fZ','now'),'authenticated.manager.admission',?6)",
            params![rowid,command.scope_id,command.target_id,sql_integer(request.owner_epoch)?,
                sql_integer(request.target.resource_epoch)?,command_id,digest,command.event_payload],
        )?;
        let event = transaction.last_insert_rowid();
        let result = format!("{{\"writerEpoch\":\"{}\",\"leaseExpiresAtUnixSeconds\":\"{}\"}}",
            request.expected_writer_epoch, expiry).into_bytes();
        transaction.execute(
            "INSERT INTO events(event_id,schema_version,command_rowid,scope_id,target_id,
             owner_epoch,target_epoch,source_id,source_kind,source_epoch,source_sequence,
             source_digest,source_order,kind,payload,recorded_at,provenance,causation_id)
             VALUES('event.pb24.' || lower(hex(randomblob(16))),1,?1,?2,?3,?4,?5,?6,
             'manager.lease',?4,2,?7,'contiguous','native_writer_lease.renewed',?8,
             strftime('%Y-%m-%dT%H:%M:%fZ','now'),'authenticated.manager.lease',?6)",
            params![rowid,command.scope_id,command.target_id,sql_integer(request.owner_epoch)?,
                sql_integer(request.target.resource_epoch)?,command_id,sha256_hex(&result),result],
        )?;
        let observed_event = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO outbox(command_rowid,scope_id,target_id,owner_epoch,target_epoch,
             kind,payload,effect_digest,state,claim_key,claim_owner_epoch,observation_key,
             observation_payload,observation_stage,observation_event_sequence)
             VALUES(?1,?2,?3,?4,?5,'native_writer_lease.renew',?6,?7,'observed',?8,?4,?8,?9,
             'lease_renewed',?10)",
            params![rowid,command.scope_id,command.target_id,sql_integer(request.owner_epoch)?,
                sql_integer(request.target.resource_epoch)?,command.effect_payload,
                sha256_hex(&command.effect_payload),request.command_key,result,observed_event],
        )?;
        let outbox = transaction.last_insert_rowid();
        transaction.execute("UPDATE commands SET event_sequence=?1,outbox_id=?2 WHERE command_rowid=?3",
            params![event,outbox,rowid])?;
        transaction.commit()?;
        Ok(NativeWriterRenewalReceipt {
            command: Receipt { command_id,event_sequence:event,outbox_id:outbox,
                digest_version:DIGEST_VERSION,request_digest:digest },
            scope_id:request.target.scope_id.clone(),
            writer_epoch:request.expected_writer_epoch,expires_at_unix_seconds:expiry,duplicate:false,
        })
    }

    /// Extend only the exact, still-current lease witnessed by the caller.
    /// The expiry is a CAS input, so a replay of an earlier renewal cannot
    /// silently extend the lease again. Renewal never changes writer epoch.
    pub fn renew_native_writer_lease_from_trusted_host(
        &mut self,
        expected: &NativeWriterLease,
        ttl_seconds: u64,
    ) -> Result<NativeWriterLease, StoreError> {
        if !(1..=MAX_TTL_SECONDS).contains(&ttl_seconds) {
            return Err(StoreError::InvalidInput("native writer lease bounds"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let target = expected.target();
        let format = check_current_target(&transaction, &self.store_lineage, target)?;
        check_manager(
            &transaction,
            &self.store_lineage,
            expected.owner_epoch(),
            expected.manager_credential_epoch(),
            expected.authority_revision(),
            format != BoundLaunchFormat::CodexV3,
        )?;
        check_actor(
            &transaction,
            &target.scope_id,
            expected.holder_actor_id(),
            expected.holder_credential_generation(),
        )?;
        let now = current_unix_seconds(&transaction)?;
        if expected.expires_at_unix_seconds() <= now
            || read_lease(&transaction, &target.resource_id)?.as_ref() != Some(expected)
        {
            return Err(StoreError::StaleEpoch);
        }
        let expiry = now
            .checked_add(ttl_seconds)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(StoreError::InvalidInput("native writer expiry overflows"))?;
        if expiry <= expected.expires_at_unix_seconds() {
            return Err(StoreError::InvalidInput("native writer renewal must extend expiry"));
        }
        let changed = transaction.execute(
            "UPDATE native_writer_leases SET expires_at_unix_seconds=?2
             WHERE resource_id=?1 AND writer_epoch=?3 AND expires_at_unix_seconds=?4",
            params![
                target.resource_id.as_str(),
                sql_integer(expiry)?,
                sql_integer(expected.writer_epoch())?,
                sql_integer(expected.expires_at_unix_seconds())?,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::StaleEpoch);
        }
        let renewed = read_lease(&transaction, &target.resource_id)?.ok_or(StoreError::NotFound)?;
        if renewed.writer_epoch() != expected.writer_epoch()
            || renewed.expires_at_unix_seconds() != expiry
            || renewed.target() != target
        {
            return Err(StoreError::Conflict("native writer renewal readback differs"));
        }
        transaction.commit()?;
        Ok(renewed)
    }

    /// Read the fenced prior writer only for a host-proven current rebind.
    /// This is a CAS input, never a usable current lease or a send permit.
    pub fn prior_native_writer_lease_for_rebind(
        &mut self,
        target: &NativeWriterTarget,
        owner_epoch: u64,
        manager_credential_epoch: u64,
        authority_revision: u64,
    ) -> Result<NativeWriterLease, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        check_manager(
            &transaction,
            &self.store_lineage,
            owner_epoch,
            manager_credential_epoch,
            authority_revision,
            true,
        )?;
        check_current_target(&transaction, &self.store_lineage, target)?;
        let prior = read_lease(&transaction, &target.resource_id)?.ok_or(StoreError::NotFound)?;
        let old = prior.target();
        if old.store_lineage != target.store_lineage || old.scope_id != target.scope_id {
            return Err(StoreError::WrongScope);
        }
        if old.session_id != target.session_id
            || old.run_id != target.run_id
            || old.attempt_id != target.attempt_id
            || old.pod_id != target.pod_id
            || old.pod_incarnation != target.pod_incarnation
            || old.resource_id != target.resource_id
            || old.resource_epoch != target.resource_epoch
            || old.resource_input_epoch >= target.resource_input_epoch
            || prior.owner_epoch() >= owner_epoch
            || prior.manager_credential_epoch() >= manager_credential_epoch
        {
            return Err(StoreError::StaleEpoch);
        }
        transaction.commit()?;
        Ok(prior)
    }

    /// Resolve the one current V2 structured child of a Session without
    /// trusting a wire-supplied Run, Pod or Resource ID. This is database
    /// evidence only; actor, grant and live pod checks belong to the host.
    pub fn current_native_writer_target_for_session(
        &mut self,
        scope_id: &ScopeId,
        session_id: &SessionId,
    ) -> Result<(NativeWriterTarget, u64), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let mut statement = transaction.prepare(
            "SELECT binding.command_rowid,resource.resource_id,resource.resource_epoch,
                    registered.input_epoch,session.revision
             FROM runtime_sessions AS session
             JOIN runtime_runs AS run ON run.run_id=session.current_run_id
               AND run.session_id=session.session_id AND run.scope_id=session.scope_id
             JOIN launch_bindings AS binding ON binding.session_id=session.session_id
               AND binding.run_id=run.run_id AND binding.scope_id=session.scope_id
               AND binding.attempt_id=run.current_attempt_id
             JOIN launch_resources AS resource ON resource.command_rowid=binding.command_rowid
               AND resource.resource_ordinal=0
             JOIN authority_resources AS registered ON registered.resource_id=resource.resource_id
             WHERE session.session_id=?1 AND session.scope_id=?2 AND session.state='open'
               AND binding.resource_count=1 AND resource.resource_kind='structured_provider'",
        )?;
        let rows = statement
            .query_map(params![session_id.as_str(), scope_id.as_str()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let [(rowid, resource_id, resource_epoch, input_epoch, session_revision)] = rows.as_slice()
        else {
            return if rows.is_empty() {
                Err(StoreError::NotFound)
            } else {
                Err(StoreError::Conflict(
                    "Session has ambiguous V2 writer target",
                ))
            };
        };
        let launch = read_bound_record(&transaction, *rowid)?;
        if !matches!(launch.format, BoundLaunchFormat::CodexV2 | BoundLaunchFormat::CodexV3)
            || launch.scope_id != scope_id.as_str()
            || launch.session_id != session_id.as_str()
            || launch.resources.len() != 1
            || launch.resources[0].id != *resource_id
            || launch.resources[0].epoch != u64::try_from(*resource_epoch).unwrap_or(0)
            || launch.resources[0].kind != "structured_provider"
        {
            return Err(StoreError::Conflict("Session V2 writer binding differs"));
        }
        let positive = |value: i64| {
            u64::try_from(value)
                .ok()
                .filter(|value| *value > 0)
                .ok_or(StoreError::Conflict("Session writer epoch is invalid"))
        };
        let target = NativeWriterTarget {
            store_lineage: StoreLineageId::try_from(self.store_lineage.as_str())
                .map_err(|_| StoreError::Conflict("store lineage is invalid"))?,
            scope_id: scope_id.clone(),
            session_id: session_id.clone(),
            run_id: RunId::try_from(launch.run_id.as_str())
                .map_err(|_| StoreError::Conflict("Run ID is invalid"))?,
            attempt_id: AttemptId::try_from(launch.attempt_id.as_str())
                .map_err(|_| StoreError::Conflict("Attempt ID is invalid"))?,
            pod_id: PodId::try_from(launch.pod_id.as_str())
                .map_err(|_| StoreError::Conflict("Pod ID is invalid"))?,
            pod_incarnation: launch.pod_incarnation,
            resource_id: ResourceId::try_from(resource_id.as_str())
                .map_err(|_| StoreError::Conflict("Resource ID is invalid"))?,
            resource_epoch: positive(*resource_epoch)?,
            resource_input_epoch: positive(*input_epoch)?,
        };
        check_current_target(&transaction, &self.store_lineage, &target)?;
        transaction.commit()?;
        Ok((target, positive(*session_revision)?))
    }

    /// Initial acquisition (`None`) or explicit takeover (`Some(old_epoch)`).
    /// The request is a forgeable trusted-host DTO: this transaction validates
    /// committed identities and CAS fences but cannot prove OS peer, grant,
    /// pod child liveness, or whether a takeover was authorised by policy.
    pub fn acquire_native_writer_lease_from_trusted_host(
        &mut self,
        request: &TrustedNativeWriterLeaseRequest,
    ) -> Result<NativeWriterLease, StoreError> {
        if !(1..=MAX_TTL_SECONDS).contains(&request.ttl_seconds)
            || request.holder_credential_generation == 0
        {
            return Err(StoreError::InvalidInput("native writer lease bounds"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_manager(
            &transaction,
            &self.store_lineage,
            request.expected_owner_epoch,
            request.expected_manager_credential_epoch,
            request.expected_authority_revision,
            true,
        )?;
        check_current_target(&transaction, &self.store_lineage, &request.target)?;
        check_actor(
            &transaction,
            &request.target.scope_id,
            &request.holder_actor_id,
            request.holder_credential_generation,
        )?;
        let now = current_unix_seconds(&transaction)?;
        let expires = now
            .checked_add(request.ttl_seconds)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(StoreError::InvalidInput("native writer expiry overflows"))?;
        let prior = read_lease(&transaction, &request.target.resource_id)?;
        let next_epoch = match (request.expected_writer_epoch, prior.as_ref()) {
            (None, None) => 1,
            (None, Some(_)) => {
                return Err(StoreError::Conflict("native writer already held"));
            }
            (Some(expected), Some(prior)) if expected > 0 => {
                if prior.target.store_lineage != request.target.store_lineage
                    || prior.target.scope_id != request.target.scope_id
                {
                    return Err(StoreError::WrongScope);
                }
                if prior.writer_epoch != expected {
                    return Err(StoreError::StaleEpoch);
                }
                expected
                    .checked_add(1)
                    .filter(|value| *value <= i64::MAX as u64)
                    .ok_or(StoreError::InvalidInput("native writer epoch exhausted"))?
            }
            (Some(_), None) => return Err(StoreError::NotFound),
            (Some(_), Some(_)) => {
                return Err(StoreError::InvalidInput(
                    "native writer epoch must be positive",
                ));
            }
        };
        let row = NativeWriterLease {
            target: request.target.clone(),
            holder_actor_id: request.holder_actor_id.clone(),
            holder_credential_generation: request.holder_credential_generation,
            owner_epoch: request.expected_owner_epoch,
            manager_credential_epoch: request.expected_manager_credential_epoch,
            authority_revision: request.expected_authority_revision,
            writer_epoch: next_epoch,
            expires_at_unix_seconds: expires,
        };
        if let Some(prior) = prior {
            let mut values = lease_params(&row)?;
            values.push(rusqlite::types::Value::Integer(sql_integer(
                prior.writer_epoch,
            )?));
            let changed = transaction.execute(
                "UPDATE native_writer_leases SET store_lineage=?2,scope_id=?3,session_id=?4,
                   run_id=?5,attempt_id=?6,pod_id=?7,pod_incarnation=?8,resource_epoch=?9,
                   resource_input_epoch=?10,holder_actor_id=?11,holder_credential_generation=?12,
                   owner_epoch=?13,manager_credential_epoch=?14,authority_revision=?15,
                   writer_epoch=?16,expires_at_unix_seconds=?17
                 WHERE resource_id=?1 AND writer_epoch=?18",
                rusqlite::params_from_iter(values.iter()),
            )?;
            if changed != 1 {
                return Err(StoreError::StaleEpoch);
            }
        } else {
            let values = lease_params(&row)?;
            transaction.execute(
                "INSERT INTO native_writer_leases(resource_id,store_lineage,scope_id,session_id,
                   run_id,attempt_id,pod_id,pod_incarnation,resource_epoch,resource_input_epoch,
                   holder_actor_id,holder_credential_generation,owner_epoch,
                   manager_credential_epoch,authority_revision,writer_epoch,expires_at_unix_seconds)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
                rusqlite::params_from_iter(values.iter()),
            )?;
        }
        if read_lease(&transaction, &row.target.resource_id)? != Some(row.clone()) {
            return Err(StoreError::Conflict("native writer lease readback differs"));
        }
        transaction.commit()?;
        Ok(row)
    }

    /// One deferred SQLite snapshot of the exact live resource and lease.
    /// Absence defaults to denial. This does not authenticate a caller or
    /// grant, and the host/pod must recheck it immediately before native input.
    pub fn inspect_native_writer_lease(
        &mut self,
        target: &NativeWriterTarget,
    ) -> Result<NativeWriterLease, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let lease = read_lease(&transaction, &target.resource_id)?.ok_or(StoreError::NotFound)?;
        if lease.target.scope_id != target.scope_id
            || lease.target.store_lineage != target.store_lineage
        {
            return Err(StoreError::WrongScope);
        }
        if &lease.target != target {
            return Err(StoreError::StaleEpoch);
        }
        let format = check_current_target(&transaction, &self.store_lineage, target)?;
        check_manager(
            &transaction,
            &self.store_lineage,
            lease.owner_epoch,
            lease.manager_credential_epoch,
            lease.authority_revision,
            format != BoundLaunchFormat::CodexV3,
        )?;
        check_actor(
            &transaction,
            &target.scope_id,
            &lease.holder_actor_id,
            lease.holder_credential_generation,
        )?;
        if lease.expires_at_unix_seconds <= current_unix_seconds(&transaction)? {
            return Err(StoreError::StaleEpoch);
        }
        transaction.commit()?;
        Ok(lease)
    }
}

/// Same-snapshot durable lease witness for a future typed command. This is
/// only database evidence; a host/pod must still authenticate its transport,
/// grant, live child and fresh process before any native write.
#[allow(clippy::too_many_arguments)]
pub(crate) fn checked_native_writer_lease(
    transaction: &Transaction<'_>,
    cached_lineage: &str,
    target: &NativeWriterTarget,
    holder_actor_id: &ActorId,
    holder_generation: u64,
    owner_epoch: u64,
    manager_credential_epoch: u64,
    authority_revision: u64,
    writer_epoch: u64,
) -> Result<NativeWriterLease, StoreError> {
    let format = check_current_target(transaction, cached_lineage, target)?;
    check_manager(
        transaction,
        cached_lineage,
        owner_epoch,
        manager_credential_epoch,
        authority_revision,
        format != BoundLaunchFormat::CodexV3,
    )?;
    check_actor(
        transaction,
        &target.scope_id,
        holder_actor_id,
        holder_generation,
    )?;
    let lease = read_lease(transaction, &target.resource_id)?.ok_or(StoreError::NotFound)?;
    if lease.target != *target
        || lease.holder_actor_id != *holder_actor_id
        || lease.holder_credential_generation != holder_generation
        || lease.owner_epoch != owner_epoch
        || lease.manager_credential_epoch != manager_credential_epoch
        || (if format == BoundLaunchFormat::CodexV3 {
            lease.authority_revision > authority_revision
        } else {
            lease.authority_revision != authority_revision
        })
        || lease.writer_epoch != writer_epoch
        || lease.expires_at_unix_seconds <= current_unix_seconds(transaction)?
    {
        return Err(StoreError::StaleEpoch);
    }
    Ok(lease)
}

fn positive(value: i64, reason: &'static str) -> Result<u64, StoreError> {
    if value <= 0 {
        Err(StoreError::Conflict(reason))
    } else {
        Ok(value as u64)
    }
}

fn sql_integer(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::InvalidInput("native writer counter overflows"))
}

fn current_unix_seconds(transaction: &Transaction<'_>) -> Result<u64, StoreError> {
    let now: i64 =
        transaction.query_row("SELECT CAST(strftime('%s','now') AS INTEGER)", [], |row| {
            row.get(0)
        })?;
    positive(now, "native writer clock is invalid")
}

fn check_manager(
    transaction: &Transaction<'_>,
    cached_lineage: &str,
    owner_epoch: u64,
    credential_epoch: u64,
    authority_revision: u64,
    exact_revision: bool,
) -> Result<(), StoreError> {
    let (lineage, owner, revision): (String, i64, i64) = transaction.query_row(
        "SELECT (SELECT lineage FROM store_identity WHERE singleton=1),
                (SELECT value FROM metadata WHERE key='owner_epoch'),
                (SELECT value FROM metadata WHERE key='authority_revision')",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let claim: Option<(String, i64, i64)> = transaction
        .query_row(
            "SELECT store_lineage,owner_epoch,credential_epoch
             FROM manager_credential_claims WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if lineage != cached_lineage
        || owner_epoch == 0
        || credential_epoch == 0
        || authority_revision == 0
        || owner != sql_integer(owner_epoch)?
        || (if exact_revision {
            revision != sql_integer(authority_revision)?
        } else {
            revision < sql_integer(authority_revision)?
        })
        || claim
            != Some((
                lineage,
                sql_integer(owner_epoch)?,
                sql_integer(credential_epoch)?,
            ))
    {
        return Err(StoreError::StaleEpoch);
    }
    Ok(())
}

fn check_actor(
    transaction: &Transaction<'_>,
    scope_id: &ScopeId,
    actor_id: &ActorId,
    generation: u64,
) -> Result<(), StoreError> {
    if generation == 0 {
        return Err(StoreError::InvalidInput(
            "native writer credential generation is zero",
        ));
    }
    let actor: Option<(String, i64)> = transaction
        .query_row(
            "SELECT scope_id,credential_generation FROM authority_actors WHERE actor_id=?1",
            [actor_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((scope, current_generation)) = actor else {
        return Err(StoreError::NotFound);
    };
    if scope != scope_id.as_str() {
        return Err(StoreError::WrongScope);
    }
    if current_generation != sql_integer(generation)? {
        return Err(StoreError::StaleEpoch);
    }
    Ok(())
}

fn check_current_target(
    transaction: &Transaction<'_>,
    cached_lineage: &str,
    target: &NativeWriterTarget,
) -> Result<BoundLaunchFormat, StoreError> {
    if target.store_lineage.as_str() != cached_lineage
        || target.pod_incarnation == 0
        || target.resource_epoch == 0
        || target.resource_input_epoch == 0
    {
        return Err(StoreError::StaleEpoch);
    }
    let rowid: Option<i64> = transaction
        .query_row(
            "SELECT b.command_rowid FROM launch_bindings AS b
             JOIN launch_resources AS resource ON resource.command_rowid=b.command_rowid
             WHERE b.scope_id=?1 AND b.session_id=?2 AND b.run_id=?3 AND b.attempt_id=?4
               AND b.pod_id=?5 AND b.pod_incarnation=?6 AND resource.resource_id=?7
               AND resource.resource_epoch=?8 AND resource.resource_kind='structured_provider'
               AND b.resource_count=1 AND resource.resource_ordinal=0",
            params![
                target.scope_id.as_str(),
                target.session_id.as_str(),
                target.run_id.as_str(),
                target.attempt_id.as_str(),
                target.pod_id.as_str(),
                sql_integer(target.pod_incarnation)?,
                target.resource_id.as_str(),
                sql_integer(target.resource_epoch)?,
            ],
            |row| row.get(0),
        )
        .optional()?;
    let record = read_bound_record(transaction, rowid.ok_or(StoreError::NotFound)?)?;
    if !matches!(record.format, BoundLaunchFormat::CodexV2 | BoundLaunchFormat::CodexV3)
        || record.scope_id != target.scope_id.as_str()
        || record.session_id != target.session_id.as_str()
        || record.run_id != target.run_id.as_str()
        || record.attempt_id != target.attempt_id.as_str()
        || record.pod_id != target.pod_id.as_str()
        || record.pod_incarnation != target.pod_incarnation
        || record.resources.len() != 1
        || record.resources[0].id != target.resource_id.as_str()
        || record.resources[0].kind != "structured_provider"
        || record.resources[0].epoch != target.resource_epoch
    {
        return Err(StoreError::Conflict("native writer Codex binding differs"));
    }
    if record.format == BoundLaunchFormat::CodexV3 {
        let policy: Option<(String, i64, i64)> = transaction.query_row(
            "SELECT store_lineage,policy_fence_epoch,admission_authority_revision
             FROM launch_policy_fences WHERE command_rowid=?1",
            [rowid.expect("record rowid was checked")],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional()?;
        let (lineage, epoch, admission_revision) = policy.ok_or(StoreError::StaleEpoch)?;
        let (current_epoch, current_revision): (i64, i64) = transaction.query_row(
            "SELECT (SELECT value FROM metadata WHERE key='policy_fence_epoch'),
                    (SELECT value FROM metadata WHERE key='authority_revision')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if lineage != cached_lineage || epoch < 1 || admission_revision < 1
            || admission_revision > current_revision || epoch != current_epoch {
            return Err(StoreError::StaleEpoch);
        }
    }
    let session: Option<(String, String, Option<String>)> = transaction
        .query_row(
            "SELECT scope_id,state,current_run_id FROM runtime_sessions WHERE session_id=?1",
            [target.session_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if session
        != Some((
            target.scope_id.as_str().into(),
            "open".into(),
            Some(target.run_id.as_str().into()),
        ))
    {
        return Err(StoreError::StaleEpoch);
    }
    let run: Option<(String, String, String, String, String, Option<String>)> = transaction
        .query_row(
            "SELECT session_id,scope_id,admission_state,desired_mode,execution_state,
                    current_attempt_id FROM runtime_runs WHERE run_id=?1",
            [target.run_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    if !run.is_some_and(|(session, scope, admission, desired, execution, attempt)| {
        session == target.session_id.as_str()
            && scope == target.scope_id.as_str()
            && admission == "admitted"
            && desired == "run"
            && matches!(execution.as_str(), "starting" | "running")
            && attempt.as_deref() == Some(target.attempt_id.as_str())
    }) {
        return Err(StoreError::StaleEpoch);
    }
    let pod: Option<(String, i64)> = transaction
        .query_row(
            "SELECT scope_id,incarnation FROM authority_pods WHERE pod_id=?1",
            [target.pod_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let epoch: Option<i64> = transaction
        .query_row(
            "SELECT epoch FROM target_epochs WHERE scope_id=?1 AND target_id=?2",
            params![target.scope_id.as_str(), target.pod_id.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    if pod
        != Some((
            target.scope_id.as_str().into(),
            sql_integer(target.pod_incarnation)?,
        ))
        || epoch != Some(sql_integer(target.pod_incarnation)?)
    {
        return Err(StoreError::StaleEpoch);
    }
    let resource: Option<(String, String, i64, i64, i64)> = transaction
        .query_row(
            "SELECT scope_id,pod_id,pod_incarnation,resource_epoch,input_epoch
             FROM authority_resources WHERE resource_id=?1",
            [target.resource_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    if resource
        != Some((
            target.scope_id.as_str().into(),
            target.pod_id.as_str().into(),
            sql_integer(target.pod_incarnation)?,
            sql_integer(target.resource_epoch)?,
            sql_integer(target.resource_input_epoch)?,
        ))
    {
        return Err(StoreError::StaleEpoch);
    }
    Ok(record.format)
}

fn lease_params(lease: &NativeWriterLease) -> Result<Vec<rusqlite::types::Value>, StoreError> {
    use rusqlite::types::Value;
    let target = &lease.target;
    Ok(vec![
        Value::Text(target.resource_id.as_str().into()),
        Value::Text(target.store_lineage.as_str().into()),
        Value::Text(target.scope_id.as_str().into()),
        Value::Text(target.session_id.as_str().into()),
        Value::Text(target.run_id.as_str().into()),
        Value::Text(target.attempt_id.as_str().into()),
        Value::Text(target.pod_id.as_str().into()),
        Value::Integer(sql_integer(target.pod_incarnation)?),
        Value::Integer(sql_integer(target.resource_epoch)?),
        Value::Integer(sql_integer(target.resource_input_epoch)?),
        Value::Text(lease.holder_actor_id.as_str().into()),
        Value::Integer(sql_integer(lease.holder_credential_generation)?),
        Value::Integer(sql_integer(lease.owner_epoch)?),
        Value::Integer(sql_integer(lease.manager_credential_epoch)?),
        Value::Integer(sql_integer(lease.authority_revision)?),
        Value::Integer(sql_integer(lease.writer_epoch)?),
        Value::Integer(sql_integer(lease.expires_at_unix_seconds)?),
    ])
}

fn read_lease(
    transaction: &Transaction<'_>,
    resource_id: &ResourceId,
) -> Result<Option<NativeWriterLease>, StoreError> {
    type Raw = (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
        i64,
        i64,
        String,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
    );
    let raw: Option<Raw> = transaction
        .query_row(
            "SELECT resource_id,store_lineage,scope_id,session_id,run_id,attempt_id,pod_id,
                    pod_incarnation,resource_epoch,resource_input_epoch,holder_actor_id,
                    holder_credential_generation,owner_epoch,manager_credential_epoch,
                    authority_revision,writer_epoch,expires_at_unix_seconds
             FROM native_writer_leases WHERE resource_id=?1",
            [resource_id.as_str()],
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
                ))
            },
        )
        .optional()?;
    let Some(raw) = raw else { return Ok(None) };
    let malformed = || StoreError::Conflict("native writer identity is malformed");
    Ok(Some(NativeWriterLease {
        target: NativeWriterTarget {
            resource_id: ResourceId::try_from(raw.0).map_err(|_| malformed())?,
            store_lineage: StoreLineageId::try_from(raw.1).map_err(|_| malformed())?,
            scope_id: ScopeId::try_from(raw.2).map_err(|_| malformed())?,
            session_id: SessionId::try_from(raw.3).map_err(|_| malformed())?,
            run_id: RunId::try_from(raw.4).map_err(|_| malformed())?,
            attempt_id: AttemptId::try_from(raw.5).map_err(|_| malformed())?,
            pod_id: PodId::try_from(raw.6).map_err(|_| malformed())?,
            pod_incarnation: positive(raw.7, "native writer Pod incarnation is invalid")?,
            resource_epoch: positive(raw.8, "native writer resource epoch is invalid")?,
            resource_input_epoch: positive(raw.9, "native writer input epoch is invalid")?,
        },
        holder_actor_id: ActorId::try_from(raw.10).map_err(|_| malformed())?,
        holder_credential_generation: positive(
            raw.11,
            "native writer actor generation is invalid",
        )?,
        owner_epoch: positive(raw.12, "native writer owner epoch is invalid")?,
        manager_credential_epoch: positive(raw.13, "native writer manager credential is invalid")?,
        authority_revision: positive(raw.14, "native writer authority revision is invalid")?,
        writer_epoch: positive(raw.15, "native writer epoch is invalid")?,
        expires_at_unix_seconds: positive(raw.16, "native writer expiry is invalid")?,
    }))
}
