//! Bounded current-state projection. No command, event, or outbox payload is
//! read here; old receipts cannot make this query grow with history.

use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use crate::model::{
    AuthorityActorRecord, CurrentAttemptSnapshot, CurrentObservation, CurrentPodSnapshot,
    CurrentResourceSnapshot, CurrentRunSnapshot, CurrentScopeSnapshot, CurrentSessionSnapshot,
    EventCursor, StoreError,
};
use crate::store::{PodBayStore, valid_id};

/// A fixed response bound, including every nested Session/Run/Attempt/Pod/Resource.
pub const CURRENT_SCOPE_ENTITY_LIMIT: usize = 256;

impl PodBayStore {
    /// One deferred SQLite snapshot of the current runtime graph and event
    /// watermark. `actor` and expected epochs must come from a trusted host;
    /// this low-level store method does not authenticate a socket or signature.
    pub fn current_scope_snapshot(
        &mut self,
        scope_id: &str,
        actor: &AuthorityActorRecord,
        expected_owner_epoch: u64,
        expected_manager_credential_epoch: u64,
        expected_authority_revision: u64,
    ) -> Result<CurrentScopeSnapshot, StoreError> {
        valid_id(scope_id)?;
        if actor.scope_id != scope_id {
            return Err(StoreError::NotFound);
        }
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
        // sequence is the global event head, as in scope_snapshot. The cursor
        // binds it to this store and scope; it is not a provider completion.
        let sequence: i64 =
            transaction.query_row("SELECT COALESCE(MAX(sequence),0) FROM events", [], |row| {
                row.get(0)
            })?;
        let basics = {
            let mut statement = transaction.prepare(
                "SELECT session_id,actor_id,revision,state,current_run_id
                 FROM runtime_sessions INDEXED BY runtime_sessions_open_scope_v19
                 WHERE scope_id=?1 AND state='open' ORDER BY session_id LIMIT ?2",
            )?;
            statement
                .query_map(
                    params![scope_id, (CURRENT_SCOPE_ENTITY_LIMIT + 1) as i64],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, Option<String>>(4)?,
                        ))
                    },
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut count = 0;
        let mut sessions = Vec::with_capacity(basics.len().min(CURRENT_SCOPE_ENTITY_LIMIT));
        for (session_id, actor_id, revision, state, current_run_id) in basics {
            count_entity(&mut count)?;
            valid_stored_id(&session_id)?;
            valid_stored_id(&actor_id)?;
            let run = match current_run_id {
                Some(run_id) => Some(read_run(
                    &transaction,
                    scope_id,
                    &session_id,
                    &run_id,
                    &mut count,
                )?),
                None => None,
            };
            sessions.push(CurrentSessionSnapshot {
                session_id,
                actor_id,
                revision: nonnegative(revision, "current Session revision is invalid")?,
                state,
                run,
            });
        }
        transaction.commit()?;
        Ok(CurrentScopeSnapshot {
            cursor: EventCursor {
                store_lineage: self.store_lineage.clone(),
                scope_id: scope_id.to_owned(),
                sequence,
            },
            owner_epoch: expected_owner_epoch,
            manager_credential_epoch: expected_manager_credential_epoch,
            authority_revision: expected_authority_revision,
            sessions,
        })
    }

    /// Short point lookup after a long read. The host rechecks the live
    /// transport and manager too; a changed actor/epoch never returns a stale
    /// snapshot as current.
    pub fn current_scope_actor_fence(
        &mut self,
        actor: &AuthorityActorRecord,
        expected_owner_epoch: u64,
        expected_manager_credential_epoch: u64,
        expected_authority_revision: u64,
    ) -> Result<(), StoreError> {
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
        transaction.commit()?;
        Ok(())
    }
}

fn check_fence(
    transaction: &Transaction<'_>,
    expected_lineage: &str,
    actor: &AuthorityActorRecord,
    expected_owner_epoch: u64,
    expected_manager_credential_epoch: u64,
    expected_authority_revision: u64,
) -> Result<(), StoreError> {
    let (lineage, owner, revision, claim_lineage, claim_owner, credential): (
        String,
        i64,
        i64,
        Option<String>,
        Option<i64>,
        Option<i64>,
    ) = transaction.query_row(
        "SELECT (SELECT lineage FROM store_identity WHERE singleton=1),
                (SELECT value FROM metadata WHERE key='owner_epoch'),
                (SELECT value FROM metadata WHERE key='authority_revision'),
                (SELECT store_lineage FROM manager_credential_claims WHERE singleton=1),
                (SELECT owner_epoch FROM manager_credential_claims WHERE singleton=1),
                (SELECT credential_epoch FROM manager_credential_claims WHERE singleton=1)",
        [],
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
    )?;
    if lineage != expected_lineage
        || owner != sqlite_u64(expected_owner_epoch)?
        || revision != sqlite_u64(expected_authority_revision)?
        || claim_lineage.as_deref() != Some(expected_lineage)
        || claim_owner != Some(owner)
        || credential != Some(sqlite_u64(expected_manager_credential_epoch)?)
    {
        return Err(StoreError::StaleEpoch);
    }
    let stored: Option<AuthorityActorRecord> = transaction
        .query_row(
            "SELECT scope_id,actor_id,role,origin,parent_actor_id,pod_id,pod_incarnation,
                    credential_generation,platform,os_identity,process_identity,
                    start_identity,containment_identity
             FROM authority_actors WHERE actor_id=?1",
            [&actor.actor_id],
            |row| {
                Ok(AuthorityActorRecord {
                    scope_id: row.get(0)?,
                    actor_id: row.get(1)?,
                    role: row.get(2)?,
                    origin: row.get(3)?,
                    parent_actor_id: row.get(4)?,
                    pod_id: row.get(5)?,
                    pod_incarnation: row.get::<_, Option<i64>>(6)?.map(|value| value as u64),
                    credential_generation: row.get::<_, i64>(7)? as u64,
                    platform: row.get(8)?,
                    os_identity: row.get(9)?,
                    process_identity: row.get(10)?,
                    start_identity: row.get::<_, i64>(11)? as u64,
                    containment_identity: row.get(12)?,
                })
            },
        )
        .optional()?;
    if stored.as_ref() != Some(actor) {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

fn read_run(
    transaction: &Transaction<'_>,
    scope_id: &str,
    session_id: &str,
    run_id: &str,
    count: &mut usize,
) -> Result<CurrentRunSnapshot, StoreError> {
    count_entity(count)?;
    valid_stored_id(run_id)?;
    let row: Option<(
        String,
        String,
        Option<String>,
        i64,
        String,
        String,
        String,
        Option<String>,
        i64,
    )> = transaction
        .query_row(
            "SELECT role,work_kind,parent_run_id,revision,admission_state,
                        desired_mode,execution_state,current_attempt_id,last_attempt_ordinal
                 FROM runtime_runs WHERE run_id=?1 AND session_id=?2 AND scope_id=?3",
            params![run_id, session_id, scope_id],
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
    let (
        role,
        work_kind,
        parent_run_id,
        revision,
        admission_state,
        desired_mode,
        execution_state,
        current_attempt_id,
        last_attempt_ordinal,
    ) = row.ok_or(StoreError::Conflict(
        "current Session references a missing Run",
    ))?;
    if !matches!(role.as_str(), "coordinator" | "worker" | "advisor")
        || !matches!(work_kind.as_str(), "task" | "service")
        || !matches!(admission_state.as_str(), "queued" | "admitted" | "rejected")
        || !matches!(desired_mode.as_str(), "run" | "pause" | "stop")
        || !matches!(
            execution_state.as_str(),
            "queued" | "starting" | "running" | "recovering" | "ended"
        )
    {
        return Err(StoreError::Conflict("current Run state is invalid"));
    }
    if let Some(parent) = &parent_run_id {
        valid_stored_id(parent)?;
    }
    let attempt = match current_attempt_id {
        Some(attempt_id) => {
            let current = read_attempt(
                transaction,
                scope_id,
                session_id,
                run_id,
                &attempt_id,
                count,
            )?;
            if i64::try_from(current.ordinal).ok() != Some(last_attempt_ordinal) {
                return Err(StoreError::Conflict("current Run attempt ordinal differs"));
            }
            Some(current)
        }
        None => None,
    };
    Ok(CurrentRunSnapshot {
        run_id: run_id.to_owned(),
        role,
        work_kind,
        parent_run_id,
        revision: nonnegative(revision, "current Run revision is invalid")?,
        admission_state,
        desired_mode,
        execution_state,
        observation: CurrentObservation::Unavailable,
        attempt,
    })
}

fn read_attempt(
    transaction: &Transaction<'_>,
    scope_id: &str,
    session_id: &str,
    run_id: &str,
    attempt_id: &str,
    count: &mut usize,
) -> Result<CurrentAttemptSnapshot, StoreError> {
    count_entity(count)?;
    valid_stored_id(attempt_id)?;
    let bound: Option<(i64, i64, i64, String, i64, i64)> = transaction
        .query_row(
            "SELECT command_rowid,attempt_ordinal,attempt_epoch,pod_id,pod_incarnation,
                    resource_count
             FROM launch_bindings WHERE attempt_id=?1 AND scope_id=?2 AND session_id=?3
               AND run_id=?4",
            params![attempt_id, scope_id, session_id, run_id],
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
    let (command_rowid, ordinal, epoch, pod_id, incarnation, resource_count) =
        bound.ok_or(StoreError::Conflict("current Attempt lacks a bound launch"))?;
    if resource_count < 1 || resource_count > CURRENT_SCOPE_ENTITY_LIMIT as i64 {
        return Err(StoreError::CurrentSnapshotLimitExceeded {
            limit: CURRENT_SCOPE_ENTITY_LIMIT,
        });
    }
    count_entity(count)?;
    valid_stored_id(&pod_id)?;
    let registered: Option<(String, i64)> = transaction
        .query_row(
            "SELECT scope_id,incarnation FROM authority_pods WHERE pod_id=?1",
            [&pod_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if registered != Some((scope_id.to_owned(), incarnation)) {
        return Err(StoreError::Conflict(
            "current Pod authority differs from bound launch",
        ));
    }
    let target_epoch: Option<i64> = transaction
        .query_row(
            "SELECT epoch FROM target_epochs WHERE scope_id=?1 AND target_id=?2",
            params![scope_id, pod_id],
            |row| row.get(0),
        )
        .optional()?;
    if target_epoch != Some(incarnation) {
        return Err(StoreError::StaleEpoch);
    }
    let resources = {
        let remaining = CURRENT_SCOPE_ENTITY_LIMIT.saturating_sub(*count);
        let mut statement = transaction.prepare(
            "SELECT ar.resource_id,lr.resource_kind,ar.resource_epoch,ar.input_epoch,
                    ar.scope_id,ar.pod_incarnation,lr.resource_epoch
             FROM authority_resources AS ar INDEXED BY authority_resources_pod_v19
             LEFT JOIN launch_resources AS lr
               ON lr.command_rowid=?1 AND lr.resource_id=ar.resource_id
             WHERE ar.pod_id=?2 ORDER BY ar.resource_id LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![command_rowid, pod_id, (remaining + 1) as i64],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                ))
            },
        )?;
        let mut resources = Vec::new();
        for row in rows {
            count_entity(count)?;
            let (
                resource_id,
                kind,
                resource_epoch,
                input_epoch,
                resource_scope,
                resource_incarnation,
                bound_epoch,
            ) = row?;
            valid_stored_id(&resource_id)?;
            if resource_scope != scope_id
                || resource_incarnation != incarnation
                || bound_epoch != Some(resource_epoch)
            {
                return Err(StoreError::Conflict(
                    "current Resource authority differs from bound launch",
                ));
            }
            let kind = kind.ok_or(StoreError::Conflict("current Resource lacks bound kind"))?;
            if !matches!(kind.as_str(), "pty" | "structured_provider" | "auxiliary") {
                return Err(StoreError::Conflict("current Resource kind is invalid"));
            }
            resources.push(CurrentResourceSnapshot {
                resource_id,
                kind,
                epoch: positive(resource_epoch, "current Resource epoch is invalid")?,
                input_epoch: positive(input_epoch, "current Resource input epoch is invalid")?,
                observation: CurrentObservation::Unavailable,
            });
        }
        resources
    };
    if resources.len() != usize::try_from(resource_count).unwrap_or(usize::MAX) {
        return Err(StoreError::Conflict(
            "current Resource inventory differs from bound launch",
        ));
    }
    Ok(CurrentAttemptSnapshot {
        attempt_id: attempt_id.to_owned(),
        ordinal: positive(ordinal, "current Attempt ordinal is invalid")?,
        epoch: positive(epoch, "current Attempt epoch is invalid")?,
        observation: CurrentObservation::Unavailable,
        pod: CurrentPodSnapshot {
            pod_id,
            incarnation: positive(incarnation, "current Pod incarnation is invalid")?,
            observation: CurrentObservation::Unavailable,
            resources,
        },
    })
}

fn count_entity(count: &mut usize) -> Result<(), StoreError> {
    *count += 1;
    if *count > CURRENT_SCOPE_ENTITY_LIMIT {
        return Err(StoreError::CurrentSnapshotLimitExceeded {
            limit: CURRENT_SCOPE_ENTITY_LIMIT,
        });
    }
    Ok(())
}

fn valid_stored_id(value: &str) -> Result<(), StoreError> {
    valid_id(value).map_err(|_| StoreError::Conflict("current runtime identity is invalid"))
}

fn sqlite_u64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::StaleEpoch)
}

fn nonnegative(value: i64, error: &'static str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::Conflict(error))
}

fn positive(value: i64, error: &'static str) -> Result<u64, StoreError> {
    if value < 1 {
        return Err(StoreError::Conflict(error));
    }
    Ok(value as u64)
}
