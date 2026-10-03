//! Durable authority facts. Transport attestations are deliberately not restored as live grants.
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::model::{
    AuthorityActorRecord, AuthorityGrantRecord, AuthorityMutation, AuthorityPodRecord,
    AuthorityResourceRecord, AuthorityRightRecord, AuthoritySnapshot, StoreError,
};
use crate::store::PodBayStore;

impl PodBayStore {
    pub fn authority_snapshot(&mut self) -> Result<AuthoritySnapshot, StoreError> {
        let transaction = self.connection.transaction()?;
        let owner_epoch: i64 = transaction.query_row(
            "SELECT value FROM metadata WHERE key='owner_epoch'",
            [],
            |row| row.get(0),
        )?;
        let revision: i64 = transaction.query_row(
            "SELECT value FROM metadata WHERE key='authority_revision'",
            [],
            |row| row.get(0),
        )?;
        let pods = {
            let mut statement = transaction.prepare(
                "SELECT scope_id,pod_id,incarnation FROM authority_pods ORDER BY pod_id",
            )?;
            statement
                .query_map([], |row| {
                    Ok(AuthorityPodRecord {
                        scope_id: row.get(0)?,
                        pod_id: row.get(1)?,
                        incarnation: row.get::<_, i64>(2)? as u64,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let resources = {
            let mut statement = transaction.prepare(
                "SELECT scope_id,resource_id,pod_id,pod_incarnation,resource_epoch,input_epoch
                 FROM authority_resources ORDER BY resource_id",
            )?;
            statement
                .query_map([], |row| {
                    Ok(AuthorityResourceRecord {
                        scope_id: row.get(0)?,
                        resource_id: row.get(1)?,
                        pod_id: row.get(2)?,
                        pod_incarnation: row.get::<_, i64>(3)? as u64,
                        resource_epoch: row.get::<_, i64>(4)? as u64,
                        input_epoch: row.get::<_, i64>(5)? as u64,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let actors = {
            let mut statement = transaction.prepare(
                "SELECT scope_id,actor_id,role,origin,parent_actor_id,pod_id,pod_incarnation,
                        credential_generation,platform,os_identity,process_identity,
                        start_identity,containment_identity
                 FROM authority_actors ORDER BY actor_id",
            )?;
            statement
                .query_map([], |row| {
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
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let grants = {
            let mut statement = transaction.prepare(
                "SELECT grant_id,scope_id,actor_id,credential_generation,mode,remaining_depth
                 FROM authority_grants ORDER BY grant_id",
            )?;
            let basics = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            let mut grants = Vec::with_capacity(basics.len());
            for (id, scope_id, actor_id, generation, mode, depth) in basics {
                let mut rights_statement = transaction.prepare(
                    "SELECT operation,target_kind,target_id FROM authority_grant_rights
                     WHERE grant_id=?1 ORDER BY operation,target_kind,target_id",
                )?;
                let rights = rights_statement
                    .query_map([id], |row| {
                        Ok(AuthorityRightRecord {
                            operation: row.get(0)?,
                            target_kind: row.get(1)?,
                            target_id: row.get(2)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                grants.push(AuthorityGrantRecord {
                    grant_id: id as u64,
                    scope_id,
                    actor_id,
                    credential_generation: generation as u64,
                    mode,
                    remaining_delegation_depth: u8::try_from(depth).map_err(|_| {
                        StoreError::InvalidInput("persisted grant depth is out of range")
                    })?,
                    rights,
                });
            }
            grants
        };
        transaction.commit()?;
        Ok(AuthoritySnapshot {
            owner_epoch: owner_epoch as u64,
            revision: revision as u64,
            pods,
            resources,
            actors,
            grants,
        })
    }

    /// A new manager fences old command writers and every old input lease atomically.
    pub fn begin_authority_replay(
        &mut self,
        expected_owner_epoch: u64,
        next_owner_epoch: u64,
    ) -> Result<AuthoritySnapshot, StoreError> {
        if expected_owner_epoch.checked_add(1) != Some(next_owner_epoch) {
            return Err(StoreError::InvalidInput("owner epoch must advance once"));
        }
        let expected = sqlite_integer(expected_owner_epoch)?;
        let next = sqlite_integer(next_owner_epoch)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE metadata SET value=?1 WHERE key='owner_epoch' AND value=?2",
            params![next, expected],
        )?;
        if changed != 1 {
            return Err(StoreError::StaleEpoch);
        }
        let exhausted: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM authority_resources WHERE input_epoch>=?1",
            [i64::MAX],
            |row| row.get(0),
        )?;
        if exhausted != 0 {
            return Err(StoreError::InvalidInput("input epoch exhausted"));
        }
        // target_epochs has existed since schema one. Reconcile old PB08b pods
        // before any PB09a outbox claim can use their incarnation fence.
        let newer_target: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM authority_pods p JOIN target_epochs t
             ON t.scope_id=p.scope_id AND t.target_id=p.pod_id
             WHERE t.epoch>p.incarnation",
            [],
            |row| row.get(0),
        )?;
        if newer_target != 0 {
            return Err(StoreError::StaleEpoch);
        }
        transaction.execute_batch(
            "INSERT INTO target_epochs(scope_id,target_id,epoch)
             SELECT scope_id,pod_id,incarnation FROM authority_pods WHERE true
             ON CONFLICT(scope_id,target_id) DO UPDATE SET epoch=excluded.epoch
             WHERE target_epochs.epoch<=excluded.epoch;",
        )?;
        transaction.execute(
            "UPDATE authority_resources SET input_epoch=input_epoch+1",
            [],
        )?;
        transaction.execute(
            "UPDATE metadata SET value=value+1 WHERE key='authority_revision'",
            [],
        )?;
        transaction.commit()?;
        self.authority_snapshot()
    }

    /// Applies one policy fact under the current manager epoch and revision.
    pub fn apply_authority_mutation(
        &mut self,
        expected_owner_epoch: u64,
        expected_revision: u64,
        mutation: AuthorityMutation,
    ) -> Result<u64, StoreError> {
        let owner = sqlite_integer(expected_owner_epoch)?;
        let revision = sqlite_integer(expected_revision)?;
        let next_revision = sqlite_integer(
            expected_revision
                .checked_add(1)
                .ok_or(StoreError::InvalidInput("authority revision exhausted"))?,
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let actual_owner: i64 = transaction.query_row(
            "SELECT value FROM metadata WHERE key='owner_epoch'",
            [],
            |row| row.get(0),
        )?;
        let actual_revision: i64 = transaction.query_row(
            "SELECT value FROM metadata WHERE key='authority_revision'",
            [],
            |row| row.get(0),
        )?;
        if actual_owner != owner || actual_revision != revision {
            return Err(StoreError::StaleEpoch);
        }
        match mutation {
            AuthorityMutation::PutPod(record) => {
                valid_identity(&record.scope_id)?;
                valid_identity(&record.pod_id)?;
                let incarnation = positive(record.incarnation)?;
                let changed = transaction.execute(
                    "INSERT INTO authority_pods(pod_id,scope_id,incarnation) VALUES(?1,?2,?3)
                     ON CONFLICT(pod_id) DO UPDATE SET incarnation=excluded.incarnation
                     WHERE authority_pods.scope_id=excluded.scope_id
                       AND authority_pods.incarnation<=excluded.incarnation",
                    params![record.pod_id, record.scope_id, incarnation],
                )?;
                if changed != 1 {
                    return Err(StoreError::WrongScope);
                }
                // The same transaction advances the PB04 command target fence.
                let existing_target: Option<i64> = transaction
                    .query_row(
                        "SELECT epoch FROM target_epochs WHERE scope_id=?1 AND target_id=?2",
                        params![record.scope_id, record.pod_id],
                        |row| row.get(0),
                    )
                    .optional()?;
                if existing_target.is_some_and(|epoch| epoch > incarnation) {
                    return Err(StoreError::StaleEpoch);
                }
                transaction.execute(
                    "INSERT INTO target_epochs(scope_id,target_id,epoch) VALUES(?1,?2,?3)
                     ON CONFLICT(scope_id,target_id) DO UPDATE SET epoch=excluded.epoch",
                    params![record.scope_id, record.pod_id, incarnation],
                )?;
            }
            AuthorityMutation::PutResource(record) => {
                valid_identity(&record.scope_id)?;
                valid_identity(&record.resource_id)?;
                valid_identity(&record.pod_id)?;
                let pod_incarnation = positive(record.pod_incarnation)?;
                let resource_epoch = positive(record.resource_epoch)?;
                let input_epoch = positive(record.input_epoch)?;
                let pod: Option<(String, i64)> = transaction
                    .query_row(
                        "SELECT scope_id,incarnation FROM authority_pods WHERE pod_id=?1",
                        [&record.pod_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                if pod != Some((record.scope_id.clone(), pod_incarnation)) {
                    return Err(StoreError::StaleEpoch);
                }
                let changed = transaction.execute(
                    "INSERT INTO authority_resources(
                       resource_id,scope_id,pod_id,pod_incarnation,resource_epoch,input_epoch)
                     VALUES(?1,?2,?3,?4,?5,?6)
                     ON CONFLICT(resource_id) DO UPDATE SET
                       pod_incarnation=excluded.pod_incarnation,
                       resource_epoch=excluded.resource_epoch,input_epoch=excluded.input_epoch
                     WHERE authority_resources.scope_id=excluded.scope_id
                       AND authority_resources.pod_id=excluded.pod_id
                       AND authority_resources.pod_incarnation<=excluded.pod_incarnation
                       AND authority_resources.resource_epoch<=excluded.resource_epoch
                       AND authority_resources.input_epoch<=excluded.input_epoch",
                    params![
                        record.resource_id,
                        record.scope_id,
                        record.pod_id,
                        pod_incarnation,
                        resource_epoch,
                        input_epoch
                    ],
                )?;
                if changed != 1 {
                    return Err(StoreError::StaleEpoch);
                }
            }
            AuthorityMutation::PutActor(record) => {
                valid_identity(&record.scope_id)?;
                valid_identity(&record.actor_id)?;
                valid_identity(&record.role)?;
                valid_identity(&record.origin)?;
                valid_identity(&record.platform)?;
                valid_identity(&record.os_identity)?;
                valid_identity(&record.process_identity)?;
                if record.containment_identity.is_empty()
                    || record.containment_identity.len() > 4096
                    || record.containment_identity.chars().any(char::is_control)
                {
                    return Err(StoreError::InvalidInput(
                        "invalid process containment identity",
                    ));
                }
                let generation = positive(record.credential_generation)?;
                let start = positive(record.start_identity)?;
                let pod_incarnation = record.pod_incarnation.map(positive).transpose()?;
                if let Some(pod_id) = &record.pod_id {
                    valid_identity(pod_id)?;
                    let pod: Option<(String, i64)> = transaction
                        .query_row(
                            "SELECT scope_id,incarnation FROM authority_pods WHERE pod_id=?1",
                            [pod_id],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .optional()?;
                    if pod != pod_incarnation.map(|inc| (record.scope_id.clone(), inc)) {
                        return Err(StoreError::StaleEpoch);
                    }
                } else if pod_incarnation.is_some() {
                    return Err(StoreError::InvalidInput(
                        "actor pod incarnation lacks pod id",
                    ));
                }
                let existing: Option<AuthorityActorRecord> = transaction
                    .query_row(
                        "SELECT scope_id,role,origin,parent_actor_id,pod_id,pod_incarnation,
                                credential_generation,platform,os_identity,process_identity,
                                start_identity,containment_identity
                         FROM authority_actors WHERE actor_id=?1",
                        [&record.actor_id],
                        |row| {
                            Ok(AuthorityActorRecord {
                                actor_id: record.actor_id.clone(),
                                scope_id: row.get(0)?,
                                role: row.get(1)?,
                                origin: row.get(2)?,
                                parent_actor_id: row.get(3)?,
                                pod_id: row.get(4)?,
                                pod_incarnation: row
                                    .get::<_, Option<i64>>(5)?
                                    .map(|value| value as u64),
                                credential_generation: row.get::<_, i64>(6)? as u64,
                                platform: row.get(7)?,
                                os_identity: row.get(8)?,
                                process_identity: row.get(9)?,
                                start_identity: row.get::<_, i64>(10)? as u64,
                                containment_identity: row.get(11)?,
                            })
                        },
                    )
                    .optional()?;
                if let Some(prior) = existing {
                    if prior.scope_id != record.scope_id {
                        return Err(StoreError::WrongScope);
                    }
                    if prior.credential_generation > record.credential_generation {
                        return Err(StoreError::StaleEpoch);
                    }
                    if prior.credential_generation == record.credential_generation
                        && prior != record
                    {
                        return Err(StoreError::Conflict(
                            "actor identity changed within credential generation",
                        ));
                    }
                }
                let changed = transaction.execute(
                    "INSERT INTO authority_actors(
                       actor_id,scope_id,role,origin,parent_actor_id,pod_id,pod_incarnation,
                       credential_generation,platform,os_identity,process_identity,
                       start_identity,containment_identity)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
                     ON CONFLICT(actor_id) DO UPDATE SET
                       role=excluded.role,origin=excluded.origin,
                       parent_actor_id=excluded.parent_actor_id,pod_id=excluded.pod_id,
                       pod_incarnation=excluded.pod_incarnation,
                       credential_generation=excluded.credential_generation,
                       platform=excluded.platform,os_identity=excluded.os_identity,
                       process_identity=excluded.process_identity,
                       start_identity=excluded.start_identity,
                       containment_identity=excluded.containment_identity
                     WHERE authority_actors.scope_id=excluded.scope_id
                       AND authority_actors.credential_generation<=excluded.credential_generation",
                    params![
                        record.actor_id,
                        record.scope_id,
                        record.role,
                        record.origin,
                        record.parent_actor_id,
                        record.pod_id,
                        pod_incarnation,
                        generation,
                        record.platform,
                        record.os_identity,
                        record.process_identity,
                        start,
                        record.containment_identity
                    ],
                )?;
                if changed != 1 {
                    return Err(StoreError::StaleEpoch);
                }
            }
            AuthorityMutation::PutGrant(record) => {
                if record.rights.is_empty() {
                    return Err(StoreError::InvalidInput("grant rights are empty"));
                }
                valid_identity(&record.scope_id)?;
                valid_identity(&record.actor_id)?;
                let grant_id = positive(record.grant_id)?;
                let generation = positive(record.credential_generation)?;
                let actor: Option<(String, i64)> = transaction
                    .query_row(
                        "SELECT scope_id,credential_generation FROM authority_actors
                         WHERE actor_id=?1",
                        [&record.actor_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                if actor != Some((record.scope_id.clone(), generation)) {
                    return Err(StoreError::StaleEpoch);
                }
                let existing: Option<i64> = transaction
                    .query_row(
                        "SELECT grant_id FROM authority_grants WHERE grant_id=?1",
                        [grant_id],
                        |row| row.get(0),
                    )
                    .optional()?;
                if existing.is_some() {
                    return Err(StoreError::Conflict("grant id is already committed"));
                }
                transaction.execute(
                    "INSERT INTO authority_grants(
                       grant_id,scope_id,actor_id,credential_generation,mode,remaining_depth)
                     VALUES(?1,?2,?3,?4,?5,?6)",
                    params![
                        grant_id,
                        record.scope_id,
                        record.actor_id,
                        generation,
                        record.mode,
                        i64::from(record.remaining_delegation_depth)
                    ],
                )?;
                for right in record.rights {
                    valid_identity(&right.operation)?;
                    valid_identity(&right.target_kind)?;
                    valid_identity(&right.target_id)?;
                    if right.target_kind == "pod" {
                        let scope: Option<String> = transaction
                            .query_row(
                                "SELECT scope_id FROM authority_pods WHERE pod_id=?1",
                                [&right.target_id],
                                |row| row.get(0),
                            )
                            .optional()?;
                        if scope.as_deref() != Some(&record.scope_id) {
                            return Err(StoreError::WrongScope);
                        }
                    } else if right.target_kind == "resource" {
                        let scope: Option<String> = transaction
                            .query_row(
                                "SELECT scope_id FROM authority_resources WHERE resource_id=?1",
                                [&right.target_id],
                                |row| row.get(0),
                            )
                            .optional()?;
                        if scope.as_deref() != Some(&record.scope_id) {
                            return Err(StoreError::WrongScope);
                        }
                    } else if right.target_kind != "credential" {
                        return Err(StoreError::InvalidInput("unknown grant target kind"));
                    }
                    transaction.execute(
                        "INSERT INTO authority_grant_rights(
                           grant_id,operation,target_kind,target_id) VALUES(?1,?2,?3,?4)",
                        params![
                            grant_id,
                            right.operation,
                            right.target_kind,
                            right.target_id
                        ],
                    )?;
                }
            }
            AuthorityMutation::RevokeGrant(grant_id) => {
                let changed = transaction.execute(
                    "DELETE FROM authority_grants WHERE grant_id=?1",
                    [positive(grant_id)?],
                )?;
                if changed != 1 {
                    return Err(StoreError::NotFound);
                }
            }
        }
        let changed = transaction.execute(
            "UPDATE metadata SET value=?1 WHERE key='authority_revision' AND value=?2",
            params![next_revision, revision],
        )?;
        if changed != 1 {
            return Err(StoreError::StaleEpoch);
        }
        transaction.commit()?;
        Ok(next_revision as u64)
    }
}

fn sqlite_integer(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::InvalidInput("authority counter too large"))
}

fn positive(value: u64) -> Result<i64, StoreError> {
    if value == 0 {
        return Err(StoreError::InvalidInput("authority counter is zero"));
    }
    sqlite_integer(value)
}

fn valid_identity(value: &str) -> Result<(), StoreError> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(StoreError::InvalidInput("invalid authority identity"));
    }
    Ok(())
}
