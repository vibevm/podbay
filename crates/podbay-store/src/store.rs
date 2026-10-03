use std::path::Path;
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::model::{
    Admission, CommandRequest, CommittedEvent, EffectClaim, EffectObservation, EffectState,
    EventCursor, Receipt, ScopeSnapshot, StoreError, StoredEffect, DIGEST_VERSION,
};

const SCHEMA_VERSION: i64 = 2;
const MAX_BYTES: usize = 1_048_576;

/// One connection is the one writer. SQLite's IMMEDIATE transaction locks fence other writers.
pub struct PodBayStore {
    connection: Connection,
    store_lineage: String,
}

impl PodBayStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        if path.as_os_str().is_empty() {
            return Err(StoreError::InvalidInput("database path is empty"));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
        )?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: i64 = transaction.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if !(0..=SCHEMA_VERSION).contains(&version) {
            return Err(StoreError::UnsupportedSchema(version));
        }
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS metadata (
               key TEXT PRIMARY KEY, value INTEGER NOT NULL CHECK(value >= 0)
             ) STRICT;
             INSERT OR IGNORE INTO metadata(key,value) VALUES('owner_epoch',0);
             CREATE TABLE IF NOT EXISTS target_epochs (
               scope_id TEXT NOT NULL, target_id TEXT NOT NULL,
               epoch INTEGER NOT NULL CHECK(epoch >= 0),
               PRIMARY KEY(scope_id,target_id)
             ) STRICT;
             CREATE TABLE IF NOT EXISTS commands (
               command_rowid INTEGER PRIMARY KEY AUTOINCREMENT,
               command_id TEXT NOT NULL UNIQUE,
               principal TEXT NOT NULL, namespace TEXT NOT NULL, command_key TEXT NOT NULL,
               scope_id TEXT NOT NULL, target_id TEXT NOT NULL,
               digest_version TEXT NOT NULL, request_digest TEXT NOT NULL,
               canonical_request BLOB NOT NULL,
               owner_epoch INTEGER NOT NULL, target_epoch INTEGER NOT NULL,
               event_sequence INTEGER, outbox_id INTEGER,
               UNIQUE(principal,namespace,command_key)
             ) STRICT;
             -- PB04 has exactly one admission event per command. PB07 will extend
             -- this ledger for independent provider and resource observations.
             CREATE TABLE IF NOT EXISTS events (
               sequence INTEGER PRIMARY KEY AUTOINCREMENT,
               command_rowid INTEGER NOT NULL UNIQUE REFERENCES commands(command_rowid),
               scope_id TEXT NOT NULL, owner_epoch INTEGER NOT NULL,
               target_epoch INTEGER NOT NULL, kind TEXT NOT NULL, payload BLOB NOT NULL
             ) STRICT;
             CREATE INDEX IF NOT EXISTS events_scope_sequence ON events(scope_id,sequence);
             CREATE TABLE IF NOT EXISTS outbox (
               outbox_id INTEGER PRIMARY KEY AUTOINCREMENT,
               command_rowid INTEGER NOT NULL UNIQUE REFERENCES commands(command_rowid),
               scope_id TEXT NOT NULL, target_id TEXT NOT NULL,
               owner_epoch INTEGER NOT NULL, target_epoch INTEGER NOT NULL,
               kind TEXT NOT NULL, payload BLOB NOT NULL,
               state TEXT NOT NULL CHECK(state IN ('prepared','claimed_uncertain','observed')),
               claim_key TEXT,
               claim_owner_epoch INTEGER
             ) STRICT;
             CREATE TABLE IF NOT EXISTS store_identity (
               singleton INTEGER PRIMARY KEY CHECK(singleton=1),
               lineage TEXT NOT NULL UNIQUE
             ) STRICT;
             INSERT OR IGNORE INTO store_identity(singleton,lineage)
               VALUES(1,lower(hex(randomblob(16))));",
        )?;
        if version < 2 {
            transaction.execute_batch(
                "ALTER TABLE outbox ADD COLUMN observation_key TEXT;
                 ALTER TABLE outbox ADD COLUMN observation_payload BLOB;",
            )?;
        }
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.commit()?;
        let store_lineage: String = connection.query_row(
            "SELECT lineage FROM store_identity WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        Ok(Self {
            connection,
            store_lineage,
        })
    }

    pub fn owner_epoch(&self) -> Result<u64, StoreError> {
        let value: i64 = self.connection.query_row(
            "SELECT value FROM metadata WHERE key='owner_epoch'",
            [],
            |row| row.get(0),
        )?;
        Ok(value as u64)
    }

    pub fn advance_owner_epoch(&mut self, expected: u64, next: u64) -> Result<(), StoreError> {
        let (expected, next) = successive_epochs(expected, next)?;
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
        transaction.commit()?;
        Ok(())
    }

    pub fn target_epoch(&self, scope_id: &str, target_id: &str) -> Result<u64, StoreError> {
        valid_id(scope_id)?;
        valid_id(target_id)?;
        let value: Option<i64> = self
            .connection
            .query_row(
                "SELECT epoch FROM target_epochs WHERE scope_id=?1 AND target_id=?2",
                params![scope_id, target_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value.unwrap_or(0) as u64)
    }

    pub fn advance_target_epoch(
        &mut self,
        scope_id: &str,
        target_id: &str,
        expected: u64,
        next: u64,
    ) -> Result<(), StoreError> {
        valid_id(scope_id)?;
        valid_id(target_id)?;
        let (expected, next) = successive_epochs(expected, next)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = if expected == 0 {
            transaction.execute(
                "INSERT OR IGNORE INTO target_epochs(scope_id,target_id,epoch) VALUES(?1,?2,?3)",
                params![scope_id, target_id, next],
            )?
        } else {
            transaction.execute(
                "UPDATE target_epochs SET epoch=?1 WHERE scope_id=?2 AND target_id=?3 AND epoch=?4",
                params![next, scope_id, target_id, expected],
            )?
        };
        if changed != 1 {
            return Err(StoreError::StaleEpoch);
        }
        transaction.commit()?;
        Ok(())
    }

    /// Commits command intent, one event, one outbox row, and their receipt together.
    pub fn admit(&mut self, request: &CommandRequest) -> Result<Admission, StoreError> {
        validate_request(request)?;
        let digest = digest_request(request);
        let command_id = stable_command_id(request);
        let owner_epoch = integer(request.expected_owner_epoch)?;
        let target_epoch = integer(request.expected_target_epoch)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = transaction
            .query_row(
                "SELECT command_id,scope_id,target_id,digest_version,request_digest,
                        canonical_request,owner_epoch,target_epoch,event_sequence,outbox_id
                 FROM commands WHERE principal=?1 AND namespace=?2 AND command_key=?3",
                params![
                    request.principal.as_str(),
                    request.namespace,
                    request.command_key
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, Option<i64>>(8)?,
                        row.get::<_, Option<i64>>(9)?,
                    ))
                },
            )
            .optional()?;
        if let Some((
            id,
            scope,
            target,
            version,
            prior_digest,
            bytes,
            prior_owner,
            prior_target,
            event,
            outbox,
        )) = existing
        {
            if scope != request.scope_id || target != request.target_id {
                return Err(StoreError::WrongScope);
            }
            if version != DIGEST_VERSION
                || prior_digest != digest
                || bytes != request.canonical_request
                || prior_owner != owner_epoch
                || prior_target != target_epoch
            {
                return Err(StoreError::Conflict(
                    "command key changed canonical content",
                ));
            }
            return Ok(Admission::Duplicate(Receipt {
                command_id: id,
                event_sequence: event.ok_or(StoreError::Conflict("incomplete committed event"))?,
                outbox_id: outbox.ok_or(StoreError::Conflict("incomplete committed outbox"))?,
                digest_version: DIGEST_VERSION,
                request_digest: digest,
            }));
        }
        if !supported_effect_kind(&request.effect_kind) {
            return Err(StoreError::UnsupportedEffectKind);
        }
        let actual_owner: i64 = transaction.query_row(
            "SELECT value FROM metadata WHERE key='owner_epoch'",
            [],
            |row| row.get(0),
        )?;
        let actual_target: Option<i64> = transaction
            .query_row(
                "SELECT epoch FROM target_epochs WHERE scope_id=?1 AND target_id=?2",
                params![request.scope_id, request.target_id],
                |row| row.get(0),
            )
            .optional()?;
        if actual_owner != owner_epoch || actual_target.unwrap_or(0) != target_epoch {
            return Err(StoreError::StaleEpoch);
        }
        transaction.execute(
            "INSERT INTO commands(command_id,principal,namespace,command_key,scope_id,target_id,
              digest_version,request_digest,canonical_request,owner_epoch,target_epoch)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                command_id,
                request.principal.as_str(),
                request.namespace,
                request.command_key,
                request.scope_id,
                request.target_id,
                DIGEST_VERSION,
                digest,
                request.canonical_request,
                owner_epoch,
                target_epoch
            ],
        )?;
        let command_rowid = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO events(command_rowid,scope_id,owner_epoch,target_epoch,kind,payload)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                command_rowid,
                request.scope_id,
                owner_epoch,
                target_epoch,
                request.event_kind,
                request.event_payload
            ],
        )?;
        let event_sequence = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO outbox(command_rowid,scope_id,target_id,owner_epoch,target_epoch,
              kind,payload,state) VALUES(?1,?2,?3,?4,?5,?6,?7,'prepared')",
            params![
                command_rowid,
                request.scope_id,
                request.target_id,
                owner_epoch,
                target_epoch,
                request.effect_kind,
                request.effect_payload
            ],
        )?;
        let outbox_id = transaction.last_insert_rowid();
        transaction.execute(
            "UPDATE commands SET event_sequence=?1,outbox_id=?2 WHERE command_rowid=?3",
            params![event_sequence, outbox_id, command_rowid],
        )?;
        transaction.commit()?;
        Ok(Admission::Committed(Receipt {
            command_id,
            event_sequence,
            outbox_id,
            digest_version: DIGEST_VERSION,
            request_digest: digest,
        }))
    }

    /// A claimed effect may already have happened. Reopen must not dispatch it again.
    pub fn claim_effect(
        &mut self,
        outbox_id: i64,
        scope_id: &str,
        target_id: &str,
        expected_owner_epoch: u64,
        expected_target_epoch: u64,
        claim_key: &str,
    ) -> Result<EffectClaim, StoreError> {
        valid_id(scope_id)?;
        valid_id(target_id)?;
        valid_id(claim_key)?;
        let owner_epoch = integer(expected_owner_epoch)?;
        let target_epoch = integer(expected_target_epoch)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = transaction
            .query_row(
                "SELECT scope_id,target_id,target_epoch,state,claim_key,kind
                 FROM outbox WHERE outbox_id=?1",
                [outbox_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        if row.0 != scope_id || row.1 != target_id {
            return Err(StoreError::WrongScope);
        }
        if current_owner(&transaction)? != owner_epoch
            || current_target(&transaction, scope_id, target_id)? != target_epoch
        {
            return Err(StoreError::StaleEpoch);
        }
        if !supported_effect_kind(&row.5) {
            return Err(StoreError::UnsupportedEffectKind);
        }
        let result = match row.3.as_str() {
            "prepared" => {
                if row.2 != target_epoch {
                    return Err(StoreError::TargetReconciliationRequired);
                }
                transaction.execute(
                    "UPDATE outbox SET state='claimed_uncertain',claim_key=?1,
                     claim_owner_epoch=?2 WHERE outbox_id=?3 AND state='prepared'",
                    params![claim_key, owner_epoch, outbox_id],
                )?;
                EffectClaim::NewClaim
            }
            "claimed_uncertain" if row.4.as_deref() == Some(claim_key) => {
                EffectClaim::ExistingUncertain
            }
            "observed" if row.4.as_deref() == Some(claim_key) => EffectClaim::AlreadyObserved,
            _ => return Err(StoreError::Conflict("effect claim identity changed")),
        };
        transaction.commit()?;
        Ok(result)
    }

    pub fn effect_state(&self, outbox_id: i64) -> Result<EffectState, StoreError> {
        let state: Option<String> = self
            .connection
            .query_row(
                "SELECT state FROM outbox WHERE outbox_id=?1",
                [outbox_id],
                |row| row.get(0),
            )
            .optional()?;
        match state.as_deref() {
            Some("prepared") => Ok(EffectState::Prepared),
            Some("claimed_uncertain") => Ok(EffectState::ClaimedUncertain),
            Some("observed") => Ok(EffectState::Observed),
            Some(_) => Err(StoreError::Conflict("unknown outbox state")),
            None => Err(StoreError::NotFound),
        }
    }

    /// Reads durable dispatch material only within the caller's chosen scope and target.
    pub fn load_effect(
        &self,
        outbox_id: i64,
        scope_id: &str,
        target_id: &str,
    ) -> Result<StoredEffect, StoreError> {
        valid_id(scope_id)?;
        valid_id(target_id)?;
        let effect = self
            .connection
            .query_row(
                "SELECT o.outbox_id,c.command_id,o.scope_id,o.target_id,o.owner_epoch,
                        o.target_epoch,o.kind,o.payload,o.state,o.claim_key,
                        o.claim_owner_epoch,o.observation_key,o.observation_payload
                 FROM outbox o JOIN commands c ON c.command_rowid=o.command_rowid
                 WHERE o.outbox_id=?1",
                [outbox_id],
                stored_effect_from_row,
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        if effect.scope_id != scope_id || effect.target_id != target_id {
            return Err(StoreError::WrongScope);
        }
        Ok(effect)
    }

    /// Enumerates unobserved effects for a known authorised scope after restart.
    /// Unknown kinds remain visible for reconciliation, but cannot be claimed.
    pub fn pending_effects(
        &self,
        scope_id: &str,
        after_outbox_id: i64,
        limit: usize,
    ) -> Result<Vec<StoredEffect>, StoreError> {
        valid_id(scope_id)?;
        if after_outbox_id < 0 || !(1..=512).contains(&limit) {
            return Err(StoreError::InvalidInput(
                "effect cursor or page limit is invalid",
            ));
        }
        let mut statement = self.connection.prepare(
            "SELECT o.outbox_id,c.command_id,o.scope_id,o.target_id,o.owner_epoch,
                    o.target_epoch,o.kind,o.payload,o.state,o.claim_key,
                    o.claim_owner_epoch,o.observation_key,o.observation_payload
             FROM outbox o JOIN commands c ON c.command_rowid=o.command_rowid
             WHERE o.scope_id=?1 AND o.outbox_id>?2 AND o.state!='observed'
             ORDER BY o.outbox_id LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![scope_id, after_outbox_id, limit as i64],
            stored_effect_from_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Records an authenticated observation after a previously committed claim.
    /// The manager must verify the external evidence before calling this method.
    pub fn observe_effect(
        &mut self,
        outbox_id: i64,
        scope_id: &str,
        target_id: &str,
        expected_owner_epoch: u64,
        expected_target_epoch: u64,
        claim_key: &str,
        observation_key: &str,
        evidence: &[u8],
    ) -> Result<EffectObservation, StoreError> {
        valid_id(scope_id)?;
        valid_id(target_id)?;
        valid_id(claim_key)?;
        valid_id(observation_key)?;
        if evidence.is_empty() || evidence.len() > MAX_BYTES {
            return Err(StoreError::InvalidInput(
                "observation evidence size is invalid",
            ));
        }
        let owner_epoch = integer(expected_owner_epoch)?;
        let target_epoch = integer(expected_target_epoch)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = transaction
            .query_row(
                "SELECT scope_id,target_id,kind,state,claim_key,
                        observation_key,observation_payload
                 FROM outbox WHERE outbox_id=?1",
                [outbox_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<Vec<u8>>>(6)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        if row.0 != scope_id || row.1 != target_id {
            return Err(StoreError::WrongScope);
        }
        if current_owner(&transaction)? != owner_epoch
            || current_target(&transaction, scope_id, target_id)? != target_epoch
        {
            return Err(StoreError::StaleEpoch);
        }
        if !supported_effect_kind(&row.2) {
            return Err(StoreError::UnsupportedEffectKind);
        }
        if row.4.as_deref() != Some(claim_key) {
            return Err(StoreError::Conflict("effect claim identity changed"));
        }
        let result = match row.3.as_str() {
            "claimed_uncertain" => {
                transaction.execute(
                    "UPDATE outbox SET state='observed',observation_key=?1,
                     observation_payload=?2 WHERE outbox_id=?3 AND state='claimed_uncertain'",
                    params![observation_key, evidence, outbox_id],
                )?;
                EffectObservation::NewObservation
            }
            "observed"
                if row.5.as_deref() == Some(observation_key)
                    && row.6.as_deref() == Some(evidence) =>
            {
                EffectObservation::AlreadyObserved
            }
            _ => return Err(StoreError::Conflict("effect observation identity changed")),
        };
        transaction.commit()?;
        Ok(result)
    }

    /// Snapshot and cursor are read from one SQLite transaction; events after cursor cannot vanish.
    pub fn scope_snapshot(&mut self, scope_id: &str) -> Result<ScopeSnapshot, StoreError> {
        valid_id(scope_id)?;
        let store_lineage = self.store_lineage.clone();
        let transaction = self.connection.transaction()?;
        let cursor: i64 =
            transaction.query_row("SELECT COALESCE(MAX(sequence),0) FROM events", [], |row| {
                row.get(0)
            })?;
        let receipts = {
            let mut statement = transaction.prepare(
                "SELECT command_id,event_sequence,outbox_id,request_digest,digest_version
                 FROM commands WHERE scope_id=?1 ORDER BY command_rowid",
            )?;
            let rows = statement.query_map([scope_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?;
            rows.map(|row| {
                let (command_id, event, outbox, digest, version) = row?;
                if version != DIGEST_VERSION {
                    return Err(StoreError::Conflict("unknown committed digest version"));
                }
                Ok(Receipt {
                    command_id,
                    event_sequence: event.ok_or(StoreError::Conflict("missing event lineage"))?,
                    outbox_id: outbox.ok_or(StoreError::Conflict("missing outbox lineage"))?,
                    request_digest: digest,
                    digest_version: DIGEST_VERSION,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?
        };
        transaction.commit()?;
        Ok(ScopeSnapshot {
            cursor: EventCursor {
                store_lineage,
                scope_id: scope_id.to_owned(),
                sequence: cursor,
            },
            receipts,
        })
    }

    pub fn initial_cursor(&self, scope_id: &str) -> Result<EventCursor, StoreError> {
        valid_id(scope_id)?;
        Ok(EventCursor {
            store_lineage: self.store_lineage.clone(),
            scope_id: scope_id.to_owned(),
            sequence: 0,
        })
    }

    pub fn events_after(
        &self,
        scope_id: &str,
        after: &EventCursor,
        limit: usize,
    ) -> Result<Vec<CommittedEvent>, StoreError> {
        valid_id(scope_id)?;
        if after.store_lineage != self.store_lineage || after.scope_id != scope_id {
            return Err(StoreError::WrongCursor);
        }
        if after.sequence < 0 || !(1..=512).contains(&limit) {
            return Err(StoreError::InvalidInput(
                "event cursor or page limit is invalid",
            ));
        }
        let current_max: i64 = self.connection.query_row(
            "SELECT COALESCE(MAX(sequence),0) FROM events",
            [],
            |row| row.get(0),
        )?;
        if after.sequence > current_max {
            return Err(StoreError::WrongCursor);
        }
        let mut statement = self.connection.prepare(
            "SELECT e.sequence,c.command_id,e.kind,e.payload FROM events e
             JOIN commands c ON c.command_rowid=e.command_rowid
             WHERE e.scope_id=?1 AND e.sequence>?2 ORDER BY e.sequence LIMIT ?3",
        )?;
        let rows = statement.query_map(params![scope_id, after.sequence, limit as i64], |row| {
            Ok(CommittedEvent {
                sequence: row.get(0)?,
                command_id: row.get(1)?,
                kind: row.get(2)?,
                payload: row.get(3)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }
}

fn validate_request(request: &CommandRequest) -> Result<(), StoreError> {
    for value in [
        &request.namespace,
        &request.command_key,
        &request.scope_id,
        &request.target_id,
        &request.event_kind,
        &request.effect_kind,
    ] {
        valid_id(value)?;
    }
    for bytes in [
        &request.canonical_request,
        &request.event_payload,
        &request.effect_payload,
    ] {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(StoreError::InvalidInput(
                "canonical or effect payload size is invalid",
            ));
        }
    }
    integer(request.expected_owner_epoch)?;
    integer(request.expected_target_epoch)?;
    Ok(())
}

fn supported_effect_kind(kind: &str) -> bool {
    matches!(kind, "pod.offer")
}

fn valid_id(value: &str) -> Result<(), StoreError> {
    if value.len() < 3 || value.len() > 160 || value.chars().any(char::is_control) {
        return Err(StoreError::InvalidInput(
            "identity length or content is invalid",
        ));
    }
    Ok(())
}

fn integer(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::InvalidInput("epoch exceeds SQLite range"))
}

fn successive_epochs(expected: u64, next: u64) -> Result<(i64, i64), StoreError> {
    if next
        != expected
            .checked_add(1)
            .ok_or(StoreError::InvalidInput("epoch overflow"))?
    {
        return Err(StoreError::InvalidInput("epoch must advance exactly once"));
    }
    Ok((integer(expected)?, integer(next)?))
}

fn current_owner(transaction: &rusqlite::Transaction<'_>) -> Result<i64, StoreError> {
    transaction
        .query_row(
            "SELECT value FROM metadata WHERE key='owner_epoch'",
            [],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn current_target(
    transaction: &rusqlite::Transaction<'_>,
    scope: &str,
    target: &str,
) -> Result<i64, StoreError> {
    Ok(transaction
        .query_row(
            "SELECT epoch FROM target_epochs WHERE scope_id=?1 AND target_id=?2",
            params![scope, target],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0))
}

fn stored_effect_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredEffect> {
    let state = match row.get::<_, String>(8)?.as_str() {
        "prepared" => EffectState::Prepared,
        "claimed_uncertain" => EffectState::ClaimedUncertain,
        "observed" => EffectState::Observed,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    Ok(StoredEffect {
        outbox_id: row.get(0)?,
        command_id: row.get(1)?,
        scope_id: row.get(2)?,
        target_id: row.get(3)?,
        admission_owner_epoch: row.get::<_, i64>(4)? as u64,
        admission_target_epoch: row.get::<_, i64>(5)? as u64,
        kind: row.get(6)?,
        payload: row.get(7)?,
        state,
        claim_key: row.get(9)?,
        claim_owner_epoch: row.get::<_, Option<i64>>(10)?.map(|value| value as u64),
        observation_key: row.get(11)?,
        observation_payload: row.get(12)?,
    })
}

fn digest_request(request: &CommandRequest) -> String {
    let mut digest = Sha256::new();
    for field in [
        DIGEST_VERSION.as_bytes(),
        request.principal.as_str().as_bytes(),
        request.namespace.as_bytes(),
        request.command_key.as_bytes(),
        request.scope_id.as_bytes(),
        request.target_id.as_bytes(),
        request.canonical_request.as_slice(),
        request.event_kind.as_bytes(),
        request.event_payload.as_slice(),
        request.effect_kind.as_bytes(),
        request.effect_payload.as_slice(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    digest.update(request.expected_owner_epoch.to_be_bytes());
    digest.update(request.expected_target_epoch.to_be_bytes());
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn stable_command_id(request: &CommandRequest) -> String {
    let mut digest = Sha256::new();
    for field in [
        b"podbay-command-id/1".as_slice(),
        request.principal.as_str().as_bytes(),
        request.namespace.as_bytes(),
        request.command_key.as_bytes(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    format!(
        "command.pb04.{}",
        digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}
