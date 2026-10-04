//! Durable authority facts. Transport attestations are deliberately not restored as live grants.
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::model::{
    AuthorityActorRecord, AuthorityGrantRecord, AuthorityMutation, AuthorityPodRecord,
    AuthorityResourceRecord, AuthorityRightRecord, AuthoritySnapshot, ManagerCredentialClaim,
    StoreError,
};
use crate::store::PodBayStore;

const ACTOR_VERIFIER_VERSION: &str = "podbay.ed25519/1";

/// Fresh SQLite evidence that one trusted actor binding still names the same
/// public verifier. This is not a peer identity or a signature proof. The
/// caller must derive the actor/process birth from trusted policy and kernel
/// attestation, never from request JSON, and separately verify the challenge.
/// The manager must also bind the database path to its own store/lock; this
/// check does not defend against a same-account copy of the entire database.
pub struct SqliteActorVerifierWitness {
    database: PathBuf,
    store_lineage: String,
    owner_epoch: u64,
    authority_revision: u64,
    actor: AuthorityActorRecord,
    public_key: [u8; 32],
}

impl SqliteActorVerifierWitness {
    /// Capture an expected binding from trusted manager state. All fields are
    /// private so a request envelope cannot itself become a witness value.
    pub fn for_actor(
        database: impl AsRef<Path>,
        store_lineage: &str,
        owner_epoch: u64,
        authority_revision: u64,
        actor: AuthorityActorRecord,
        public_key: [u8; 32],
    ) -> Result<Self, StoreError> {
        let database = database.as_ref();
        if !database.is_absolute()
            || store_lineage.is_empty()
            || owner_epoch == 0
            || actor.credential_generation == 0
            || actor.start_identity == 0
            || public_key == [0; 32]
        {
            return Err(StoreError::InvalidInput(
                "actor witness binding is incomplete",
            ));
        }
        valid_identity(store_lineage)?;
        valid_identity(&actor.actor_id)?;
        valid_identity(&actor.scope_id)?;
        Ok(Self {
            database: database.to_path_buf(),
            store_lineage: store_lineage.to_owned(),
            owner_epoch,
            authority_revision,
            actor,
            public_key,
        })
    }

    /// Opens the existing database read-only on every call. Any missing,
    /// stale, foreign or corrupt state refuses. True only means the trusted
    /// public verifier is still current in this store snapshot.
    pub fn is_current(&self) -> bool {
        self.check_current().unwrap_or(false)
    }

    fn check_current(&self) -> Result<bool, StoreError> {
        let mut connection =
            Connection::open_with_flags(&self.database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let lineage: String = transaction.query_row(
            "SELECT lineage FROM store_identity WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if lineage != self.store_lineage {
            return Ok(false);
        }
        require_current_actor(
            &transaction,
            self.owner_epoch,
            self.authority_revision,
            &self.actor,
        )?;
        let verifier = require_matching_verifier(&transaction, &self.actor)?;
        if verifier.revoked || verifier.public_key != self.public_key {
            return Ok(false);
        }
        transaction.commit()?;
        Ok(true)
    }
}

impl PodBayStore {
    /// Reads only a current v10 manager claim. A migrated v9 owner has no row
    /// until a new owner replay mints one; an actor generation is never used.
    pub fn current_manager_credential_claim(
        &mut self,
        expected_owner_epoch: u64,
    ) -> Result<ManagerCredentialClaim, StoreError> {
        let expected = sqlite_integer(expected_owner_epoch)?;
        let transaction = self.connection.transaction()?;
        let current: i64 = transaction.query_row(
            "SELECT value FROM metadata WHERE key='owner_epoch'",
            [],
            |row| row.get(0),
        )?;
        if current != expected {
            return Err(StoreError::StaleEpoch);
        }
        let claim: Option<(String, i64, i64)> = transaction
            .query_row(
                "SELECT store_lineage,owner_epoch,credential_epoch
             FROM manager_credential_claims WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let (lineage, owner, credential) = claim.ok_or(StoreError::NotFound)?;
        if lineage != self.store_lineage || owner != current || credential < owner {
            return Err(StoreError::StaleEpoch);
        }
        transaction.commit()?;
        Ok(ManagerCredentialClaim {
            store_lineage: lineage,
            owner_epoch: owner as u64,
            credential_epoch: credential as u64,
        })
    }

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

    /// Persist a public verifier supplied by trusted host policy for one
    /// already registered actor and OS process birth. This does not attest a
    /// transport peer or accept a credential from a request body. A repeated
    /// exact registration at the current revision leaves state unchanged.
    pub fn register_actor_verifier_from_trusted_host(
        &mut self,
        expected_owner_epoch: u64,
        expected_revision: u64,
        actor: &AuthorityActorRecord,
        public_key: [u8; 32],
    ) -> Result<u64, StoreError> {
        if public_key == [0; 32] {
            return Err(StoreError::InvalidInput("actor verifier key is empty"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_current_actor(&transaction, expected_owner_epoch, expected_revision, actor)?;
        let binding_digest = actor_binding_digest(actor);
        if let Some(prior) = read_actor_verifier(&transaction, &actor.actor_id)? {
            if prior.scope_id != actor.scope_id {
                return Err(StoreError::WrongScope);
            }
            if prior.credential_generation > actor.credential_generation {
                return Err(StoreError::StaleEpoch);
            }
            if prior.credential_generation == actor.credential_generation {
                if prior.revoked {
                    return Err(StoreError::Conflict("actor verifier was revoked"));
                }
                if prior.version != ACTOR_VERIFIER_VERSION
                    || prior.binding_digest != binding_digest
                    || prior.public_key != public_key
                {
                    return Err(StoreError::Conflict(
                        "actor verifier changed within credential generation",
                    ));
                }
                transaction.commit()?;
                return Ok(expected_revision);
            }
            if prior.public_key == public_key {
                return Err(StoreError::Conflict(
                    "actor verifier key reused across generations",
                ));
            }
            let changed = transaction.execute(
                "UPDATE actor_verifiers SET scope_id=?1,credential_generation=?2,
                   verifier_version=?3,public_key=?4,binding_digest=?5,revoked=0
                 WHERE actor_id=?6 AND credential_generation=?7",
                params![
                    actor.scope_id,
                    sqlite_integer(actor.credential_generation)?,
                    ACTOR_VERIFIER_VERSION,
                    public_key.as_slice(),
                    binding_digest.as_slice(),
                    actor.actor_id,
                    sqlite_integer(prior.credential_generation)?,
                ],
            )?;
            if changed != 1 {
                return Err(StoreError::StaleEpoch);
            }
        } else {
            transaction.execute(
                "INSERT INTO actor_verifiers(actor_id,scope_id,credential_generation,
                   verifier_version,public_key,binding_digest,revoked)
                 VALUES(?1,?2,?3,?4,?5,?6,0)",
                params![
                    actor.actor_id,
                    actor.scope_id,
                    sqlite_integer(actor.credential_generation)?,
                    ACTOR_VERIFIER_VERSION,
                    public_key.as_slice(),
                    binding_digest.as_slice(),
                ],
            )?;
        }
        let next = advance_authority_revision(&transaction, expected_revision)?;
        transaction.commit()?;
        Ok(next)
    }

    /// Revoke the exact current actor verifier. Re-registering the same
    /// generation cannot revive it; trusted policy must advance generation.
    pub fn revoke_actor_verifier_from_trusted_host(
        &mut self,
        expected_owner_epoch: u64,
        expected_revision: u64,
        actor: &AuthorityActorRecord,
    ) -> Result<u64, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_current_actor(&transaction, expected_owner_epoch, expected_revision, actor)?;
        let verifier = require_matching_verifier(&transaction, actor)?;
        if verifier.revoked {
            transaction.commit()?;
            return Ok(expected_revision);
        }
        let changed = transaction.execute(
            "UPDATE actor_verifiers SET revoked=1 WHERE actor_id=?1
               AND credential_generation=?2 AND revoked=0",
            params![actor.actor_id, sqlite_integer(actor.credential_generation)?],
        )?;
        if changed != 1 {
            return Err(StoreError::StaleEpoch);
        }
        let next = advance_authority_revision(&transaction, expected_revision)?;
        transaction.commit()?;
        Ok(next)
    }

    /// Fresh, read-only public-key lookup for a separately OS-attested peer.
    /// The caller must still verify a signature; this row alone authenticates
    /// nobody. Owner, revision, actor birth, scope and generation must match.
    pub fn current_actor_verifier(
        &mut self,
        expected_owner_epoch: u64,
        expected_revision: u64,
        actor: &AuthorityActorRecord,
    ) -> Result<[u8; 32], StoreError> {
        let transaction = self.connection.transaction()?;
        require_current_actor(&transaction, expected_owner_epoch, expected_revision, actor)?;
        let verifier = require_matching_verifier(&transaction, actor)?;
        if verifier.revoked {
            return Err(StoreError::NotFound);
        }
        let public_key: [u8; 32] = verifier
            .public_key
            .try_into()
            .map_err(|_| StoreError::Conflict("actor verifier key size changed"))?;
        if public_key == [0; 32] {
            return Err(StoreError::Conflict("actor verifier key is empty"));
        }
        transaction.commit()?;
        Ok(public_key)
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
        let prior: Option<(String, i64, i64)> = transaction
            .query_row(
                "SELECT store_lineage,owner_epoch,credential_epoch
             FROM manager_credential_claims WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if prior.as_ref().is_some_and(|(lineage, owner, credential)| {
            lineage != &self.store_lineage || *owner != expected || *credential < *owner
        }) {
            return Err(StoreError::StaleEpoch);
        }
        // V9 rebind epochs are pod-local evidence, not a manager credential.
        // Their maximum is only a conservative numeric allocation floor.
        let legacy_highwater: Option<i64> = transaction.query_row(
            "SELECT MAX(next_credential_epoch) FROM manager_rebinds",
            [],
            |row| row.get(0),
        )?;
        let legacy_floor = legacy_highwater
            .map(|value| {
                value.checked_add(1).ok_or(StoreError::InvalidInput(
                    "manager credential epoch exhausted",
                ))
            })
            .transpose()?
            .unwrap_or(1);
        let next_credential = prior
            .as_ref()
            .map(|(_, _, credential)| {
                credential.checked_add(1).ok_or(StoreError::InvalidInput(
                    "manager credential epoch exhausted",
                ))
            })
            .transpose()?
            .unwrap_or(next)
            .max(next)
            .max(legacy_floor);
        if let Some((_, _, credential)) = prior {
            let changed = transaction.execute(
                "UPDATE manager_credential_claims SET owner_epoch=?1,credential_epoch=?2
                 WHERE singleton=1 AND store_lineage=?3 AND owner_epoch=?4 AND credential_epoch=?5",
                params![
                    next,
                    next_credential,
                    self.store_lineage,
                    expected,
                    credential
                ],
            )?;
            if changed != 1 {
                return Err(StoreError::StaleEpoch);
            }
        } else {
            transaction.execute(
                "INSERT INTO manager_credential_claims(singleton,store_lineage,owner_epoch,credential_epoch)
                 VALUES(1,?1,?2,?3)",
                params![self.store_lineage, next, next_credential],
            )?;
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
                        match scope.as_deref() {
                            Some(existing_scope) if existing_scope == record.scope_id => {}
                            // A launch grant can name the exact proposed Pod
                            // before atomic bound admission creates its row.
                            // Absence never authorizes another Pod operation.
                            None if right.operation == "launch_pod" => {}
                            _ => return Err(StoreError::WrongScope),
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

struct StoredActorVerifier {
    scope_id: String,
    credential_generation: u64,
    version: String,
    public_key: Vec<u8>,
    binding_digest: Vec<u8>,
    revoked: bool,
}

fn read_actor_verifier(
    transaction: &rusqlite::Transaction<'_>,
    actor_id: &str,
) -> Result<Option<StoredActorVerifier>, StoreError> {
    transaction
        .query_row(
            "SELECT scope_id,credential_generation,verifier_version,public_key,
                    binding_digest,revoked FROM actor_verifiers WHERE actor_id=?1",
            [actor_id],
            |row| {
                Ok(StoredActorVerifier {
                    scope_id: row.get(0)?,
                    credential_generation: row.get::<_, i64>(1)? as u64,
                    version: row.get(2)?,
                    public_key: row.get(3)?,
                    binding_digest: row.get(4)?,
                    revoked: row.get::<_, i64>(5)? != 0,
                })
            },
        )
        .optional()
        .map_err(StoreError::from)
}

fn require_matching_verifier(
    transaction: &rusqlite::Transaction<'_>,
    actor: &AuthorityActorRecord,
) -> Result<StoredActorVerifier, StoreError> {
    let verifier =
        read_actor_verifier(transaction, &actor.actor_id)?.ok_or(StoreError::NotFound)?;
    if verifier.scope_id != actor.scope_id {
        return Err(StoreError::WrongScope);
    }
    if verifier.credential_generation != actor.credential_generation {
        return Err(StoreError::StaleEpoch);
    }
    if verifier.version != ACTOR_VERIFIER_VERSION
        || verifier.binding_digest != actor_binding_digest(actor)
        || verifier.public_key.len() != 32
    {
        return Err(StoreError::Conflict("actor verifier binding changed"));
    }
    Ok(verifier)
}

fn require_current_actor(
    transaction: &rusqlite::Transaction<'_>,
    expected_owner_epoch: u64,
    expected_revision: u64,
    actor: &AuthorityActorRecord,
) -> Result<(), StoreError> {
    valid_identity(&actor.actor_id)?;
    valid_identity(&actor.scope_id)?;
    let owner: i64 = transaction.query_row(
        "SELECT value FROM metadata WHERE key='owner_epoch'",
        [],
        |row| row.get(0),
    )?;
    let revision: i64 = transaction.query_row(
        "SELECT value FROM metadata WHERE key='authority_revision'",
        [],
        |row| row.get(0),
    )?;
    if owner != sqlite_integer(expected_owner_epoch)?
        || revision != sqlite_integer(expected_revision)?
    {
        return Err(StoreError::StaleEpoch);
    }
    let current: Option<AuthorityActorRecord> = transaction
        .query_row(
            "SELECT scope_id,role,origin,parent_actor_id,pod_id,pod_incarnation,
                    credential_generation,platform,os_identity,process_identity,
                    start_identity,containment_identity
             FROM authority_actors WHERE actor_id=?1",
            [&actor.actor_id],
            |row| {
                Ok(AuthorityActorRecord {
                    actor_id: actor.actor_id.clone(),
                    scope_id: row.get(0)?,
                    role: row.get(1)?,
                    origin: row.get(2)?,
                    parent_actor_id: row.get(3)?,
                    pod_id: row.get(4)?,
                    pod_incarnation: row.get::<_, Option<i64>>(5)?.map(|value| value as u64),
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
    let current = current.ok_or(StoreError::NotFound)?;
    if current.scope_id != actor.scope_id {
        return Err(StoreError::WrongScope);
    }
    if current != *actor {
        return Err(StoreError::StaleEpoch);
    }
    Ok(())
}

fn advance_authority_revision(
    transaction: &rusqlite::Transaction<'_>,
    expected_revision: u64,
) -> Result<u64, StoreError> {
    let next = expected_revision
        .checked_add(1)
        .ok_or(StoreError::InvalidInput("authority revision exhausted"))?;
    let changed = transaction.execute(
        "UPDATE metadata SET value=?1 WHERE key='authority_revision' AND value=?2",
        params![sqlite_integer(next)?, sqlite_integer(expected_revision)?],
    )?;
    if changed != 1 {
        return Err(StoreError::StaleEpoch);
    }
    Ok(next)
}

fn actor_binding_digest(actor: &AuthorityActorRecord) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"podbay.actor-binding/1\0");
    for value in [
        &actor.actor_id,
        &actor.scope_id,
        &actor.role,
        &actor.origin,
        &actor.platform,
        &actor.os_identity,
        &actor.process_identity,
        &actor.containment_identity,
    ] {
        digest_text(&mut hash, value);
    }
    digest_optional_text(&mut hash, actor.parent_actor_id.as_deref());
    digest_optional_text(&mut hash, actor.pod_id.as_deref());
    digest_optional_u64(&mut hash, actor.pod_incarnation);
    hash.update(actor.credential_generation.to_be_bytes());
    hash.update(actor.start_identity.to_be_bytes());
    hash.finalize().into()
}

fn digest_text(hash: &mut Sha256, value: &str) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value.as_bytes());
}

fn digest_optional_text(hash: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hash.update([1]);
            digest_text(hash, value);
        }
        None => hash.update([0]),
    }
}

fn digest_optional_u64(hash: &mut Sha256, value: Option<u64>) {
    match value {
        Some(value) => {
            hash.update([1]);
            hash.update(value.to_be_bytes());
        }
        None => hash.update([0]),
    }
}
