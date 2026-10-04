//! Durable structured-provider writer exclusion. These rows are store facts,
//! never OS attestations, grants, pod liveness, or native effect permits.

use podbay_core::{
    ActorId, AttemptId, PodId, ResourceId, RunId, ScopeId, SessionId, StoreLineageId,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use crate::bound_launch::{BoundLaunchFormat, read_bound_record};
use crate::model::{
    NativeWriterLease, NativeWriterTarget, StoreError, TrustedNativeWriterLeaseRequest,
};
use crate::store::PodBayStore;

/// A lease limits the time during which a future host/pod may start native
/// input. An already accepted model turn is not cancelled when this expires.
const MAX_TTL_SECONDS: u64 = 3_600;

impl PodBayStore {
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
        check_manager(
            &transaction,
            &self.store_lineage,
            lease.owner_epoch,
            lease.manager_credential_epoch,
            lease.authority_revision,
        )?;
        check_current_target(&transaction, &self.store_lineage, target)?;
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
        || revision != sql_integer(authority_revision)?
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
) -> Result<(), StoreError> {
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
    if record.format != BoundLaunchFormat::CodexV2
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
        return Err(StoreError::Conflict("native writer V2 binding differs"));
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
    Ok(())
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
