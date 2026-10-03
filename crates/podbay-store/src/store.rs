use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::model::{
    Admission, AdmittedLaunchInspection, CommandRequest, CommittedEvent, DIGEST_VERSION,
    EffectClaim, EffectObservation, EffectState, EventCursor, EventReference, HostAcceptanceProof,
    LaunchDispatchStage, LaunchDispatchStatus, LaunchIntentBinding, LaunchLookupRequest,
    ObservedStage, QuarantinedSourceEvent, Receipt, ScopeSnapshot, SourceAnomaly, SourceOrder,
    StoreError, StoredEffect,
};

const SCHEMA_VERSION: i64 = 7;
const MAX_BYTES: usize = 1_048_576;

/// One connection is the one writer. SQLite's IMMEDIATE transaction locks fence other writers.
pub struct PodBayStore {
    pub(crate) connection: Connection,
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
             -- Versions one and two have exactly one admission event per command.
             -- The schema-three migration below expands this journal.
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
        if version < 3 {
            transaction.execute_batch(
                "CREATE TABLE events_v3 (
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   event_id TEXT NOT NULL UNIQUE,
                   schema_version INTEGER NOT NULL CHECK(schema_version >= 1),
                   command_rowid INTEGER NOT NULL REFERENCES commands(command_rowid),
                   scope_id TEXT NOT NULL, target_id TEXT NOT NULL,
                   owner_epoch INTEGER NOT NULL, target_epoch INTEGER NOT NULL,
                   source_id TEXT NOT NULL, source_kind TEXT NOT NULL,
                   source_epoch INTEGER NOT NULL, source_sequence INTEGER NOT NULL,
                   source_digest TEXT NOT NULL,
                   source_order TEXT NOT NULL CHECK(source_order IN
                     ('contiguous','gap','out_of_order')),
                   source_order_reference INTEGER,
                   kind TEXT NOT NULL, payload BLOB NOT NULL,
                   recorded_at TEXT NOT NULL, occurred_at TEXT,
                   provenance TEXT NOT NULL, correlation_id TEXT, causation_id TEXT,
                   UNIQUE(scope_id,source_id,source_epoch,source_sequence)
                 ) STRICT;
                 INSERT INTO events_v3(
                   sequence,event_id,schema_version,command_rowid,scope_id,target_id,
                   owner_epoch,target_epoch,source_id,source_kind,source_epoch,
                   source_sequence,source_digest,source_order,kind,payload,recorded_at,
                   provenance)
                 SELECT e.sequence,
                   'event.pb07.legacy.' || (SELECT lineage FROM store_identity WHERE singleton=1)
                     || '.' || e.sequence,
                   1,e.command_rowid,e.scope_id,c.target_id,e.owner_epoch,e.target_epoch,
                   c.command_id,'manager.admission',e.owner_epoch,1,c.request_digest,
                   'contiguous',e.kind,e.payload,
                   strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                   'legacy.admission.recorded_time_unavailable'
                 FROM events e JOIN commands c ON c.command_rowid=e.command_rowid;
                 DROP TABLE events;
                 ALTER TABLE events_v3 RENAME TO events;
                 CREATE INDEX events_scope_sequence ON events(scope_id,sequence);
                 ALTER TABLE outbox ADD COLUMN observation_stage TEXT;
                 ALTER TABLE outbox ADD COLUMN observation_event_sequence INTEGER
                   REFERENCES events(sequence);
                 UPDATE outbox SET observation_stage='legacy_unverified'
                   WHERE state='observed';",
            )?;
        }
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS event_quarantine (
               quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT,
               scope_id TEXT NOT NULL, source_id TEXT NOT NULL,
               source_epoch INTEGER NOT NULL, source_sequence INTEGER NOT NULL,
               existing_event_id TEXT NOT NULL, incoming_digest TEXT NOT NULL,
               incoming_payload BLOB NOT NULL, incoming_evidence BLOB NOT NULL,
               recorded_at TEXT NOT NULL,
               UNIQUE(scope_id,source_id,source_epoch,source_sequence,incoming_digest)
             ) STRICT;
             CREATE INDEX IF NOT EXISTS quarantine_scope_id
               ON event_quarantine(scope_id,quarantine_id);",
        )?;
        if version < 4 {
            transaction.execute_batch(
                "INSERT OR IGNORE INTO metadata(key,value) VALUES('authority_revision',0);
                 CREATE TABLE IF NOT EXISTS authority_pods (
                   pod_id TEXT PRIMARY KEY, scope_id TEXT NOT NULL,
                   incarnation INTEGER NOT NULL CHECK(incarnation >= 1)
                 ) STRICT;
                 CREATE TABLE IF NOT EXISTS authority_resources (
                   resource_id TEXT PRIMARY KEY, scope_id TEXT NOT NULL,
                   pod_id TEXT NOT NULL REFERENCES authority_pods(pod_id),
                   pod_incarnation INTEGER NOT NULL CHECK(pod_incarnation >= 1),
                   resource_epoch INTEGER NOT NULL CHECK(resource_epoch >= 1),
                   input_epoch INTEGER NOT NULL CHECK(input_epoch >= 1)
                 ) STRICT;
                 CREATE TABLE IF NOT EXISTS authority_actors (
                   actor_id TEXT PRIMARY KEY, scope_id TEXT NOT NULL,
                   role TEXT NOT NULL, origin TEXT NOT NULL,
                   parent_actor_id TEXT, pod_id TEXT REFERENCES authority_pods(pod_id),
                   pod_incarnation INTEGER, credential_generation INTEGER NOT NULL
                     CHECK(credential_generation >= 1),
                   platform TEXT NOT NULL, os_identity TEXT NOT NULL,
                   process_identity TEXT NOT NULL,
                   start_identity INTEGER NOT NULL CHECK(start_identity >= 1),
                   containment_identity TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE IF NOT EXISTS authority_grants (
                   grant_id INTEGER PRIMARY KEY CHECK(grant_id >= 1),
                   scope_id TEXT NOT NULL,
                   actor_id TEXT NOT NULL REFERENCES authority_actors(actor_id),
                   credential_generation INTEGER NOT NULL CHECK(credential_generation >= 1),
                   mode TEXT NOT NULL,
                   remaining_depth INTEGER NOT NULL CHECK(remaining_depth BETWEEN 0 AND 255)
                 ) STRICT;
                 CREATE TABLE IF NOT EXISTS authority_grant_rights (
                   grant_id INTEGER NOT NULL REFERENCES authority_grants(grant_id)
                     ON DELETE CASCADE,
                   operation TEXT NOT NULL, target_kind TEXT NOT NULL,
                   target_id TEXT NOT NULL,
                   PRIMARY KEY(grant_id,operation,target_kind,target_id)
                 ) STRICT;",
            )?;
        }
        if version < 5 {
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS launch_dispatch_outcomes (
                   outbox_id INTEGER PRIMARY KEY REFERENCES outbox(outbox_id),
                   claim_key TEXT NOT NULL,
                   stage TEXT NOT NULL CHECK(stage IN
                     ('refused_before_effect','uncertain_after_possible_effect',
                      'host_accepted','port_settled')),
                   receipt_ref TEXT,
                   recorded_at TEXT NOT NULL
                 ) STRICT;",
            )?;
        }
        let has_effect_digest = {
            let mut statement = transaction.prepare("PRAGMA table_info(outbox)")?;
            statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .any(|name| name == "effect_digest")
        };
        if version < 6 && !has_effect_digest {
            transaction.execute_batch("ALTER TABLE outbox ADD COLUMN effect_digest TEXT;")?;
        } else if version >= 6 && !has_effect_digest {
            return Err(StoreError::Conflict(
                "outbox effect digest column is missing",
            ));
        }
        if version < 6 {
            let prior_effects = {
                let mut statement = transaction.prepare("SELECT outbox_id,payload FROM outbox")?;
                statement
                    .query_map([], |row| {
                        Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?
            };
            for (outbox_id, payload) in prior_effects {
                transaction.execute(
                    "UPDATE outbox SET effect_digest=?1 WHERE outbox_id=?2",
                    params![sha256_hex(&payload), outbox_id],
                )?;
            }
        }
        if version < 7 {
            let nonpositive_launch: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM outbox WHERE kind='pod.offer' AND target_epoch<=0",
                [],
                |row| row.get(0),
            )?;
            if nonpositive_launch != 0 {
                return Err(StoreError::Conflict(
                    "legacy launch has nonpositive pod incarnation",
                ));
            }
            let duplicate_launch_slot: Option<(String, String, i64)> = transaction
                .query_row(
                    "SELECT scope_id,target_id,target_epoch FROM outbox
                     WHERE kind='pod.offer'
                     GROUP BY scope_id,target_id,target_epoch HAVING COUNT(*)>1 LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            if duplicate_launch_slot.is_some() {
                return Err(StoreError::Conflict(
                    "legacy store has multiple launches for one pod incarnation",
                ));
            }
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS launch_slots (
                   scope_id TEXT NOT NULL,pod_id TEXT NOT NULL,
                   pod_incarnation INTEGER NOT NULL CHECK(pod_incarnation>=1),
                   command_rowid INTEGER NOT NULL UNIQUE REFERENCES commands(command_rowid),
                   PRIMARY KEY(scope_id,pod_id,pod_incarnation)
                 ) STRICT;
                 INSERT OR IGNORE INTO launch_slots(scope_id,pod_id,pod_incarnation,command_rowid)
                 SELECT scope_id,target_id,target_epoch,command_rowid
                 FROM outbox WHERE kind='pod.offer';",
            )?;
            let mismatched: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM outbox o LEFT JOIN launch_slots s
                 ON s.scope_id=o.scope_id AND s.pod_id=o.target_id
                   AND s.pod_incarnation=o.target_epoch
                 WHERE o.kind='pod.offer'
                   AND (s.command_rowid IS NULL OR s.command_rowid!=o.command_rowid)",
                [],
                |row| row.get(0),
            )?;
            let extra: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM launch_slots s LEFT JOIN outbox o
                 ON o.command_rowid=s.command_rowid
                 WHERE o.command_rowid IS NULL OR o.kind!='pod.offer'
                   OR o.scope_id!=s.scope_id OR o.target_id!=s.pod_id
                   OR o.target_epoch!=s.pod_incarnation",
                [],
                |row| row.get(0),
            )?;
            if mismatched != 0 || extra != 0 {
                return Err(StoreError::Conflict(
                    "legacy launch reservation does not match committed outbox",
                ));
            }
        }
        verify_authority_schema(&transaction)?;
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
        let effect_digest = sha256_hex(&request.effect_payload);
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
        if request.effect_kind == "pod.offer" {
            let occupied: Option<i64> = transaction
                .query_row(
                    "SELECT command_rowid FROM launch_slots
                     WHERE scope_id=?1 AND pod_id=?2 AND pod_incarnation=?3",
                    params![request.scope_id, request.target_id, target_epoch],
                    |row| row.get(0),
                )
                .optional()?;
            if occupied.is_some() {
                return Err(StoreError::Conflict(
                    "launch slot already admitted for pod incarnation",
                ));
            }
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
        if request.effect_kind == "pod.offer" {
            transaction.execute(
                "INSERT INTO launch_slots(scope_id,pod_id,pod_incarnation,command_rowid)
                 VALUES(?1,?2,?3,?4)",
                params![
                    request.scope_id,
                    request.target_id,
                    target_epoch,
                    command_rowid
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO events(
               event_id,schema_version,command_rowid,scope_id,target_id,
               owner_epoch,target_epoch,source_id,source_kind,source_epoch,
               source_sequence,source_digest,source_order,kind,payload,recorded_at,
               provenance,causation_id)
             VALUES('event.pb07.' || lower(hex(randomblob(16))),1,?1,?2,?3,
                    ?4,?5,?6,'manager.admission',?4,1,?7,'contiguous',?8,?9,
                    strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                    'authenticated.manager.admission',?6)",
            params![
                command_rowid,
                request.scope_id,
                request.target_id,
                owner_epoch,
                target_epoch,
                command_id,
                digest,
                request.event_kind,
                request.event_payload
            ],
        )?;
        let event_sequence = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO outbox(command_rowid,scope_id,target_id,owner_epoch,target_epoch,
              kind,payload,effect_digest,state)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'prepared')",
            params![
                command_rowid,
                request.scope_id,
                request.target_id,
                owner_epoch,
                target_epoch,
                request.effect_kind,
                request.effect_payload,
                effect_digest
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

    /// Inspection-only duplicate lookup. It performs SELECTs in one deferred
    /// snapshot, never resolves today's profile, advances an epoch, claims an
    /// outbox item, or calls a host port. Every schema-v7 result is explicitly
    /// historical/unbound and cannot itself authorize dispatch.
    pub fn lookup_admitted_launch(
        &mut self,
        request: &LaunchLookupRequest,
    ) -> Result<AdmittedLaunchInspection, StoreError> {
        for value in [
            &request.namespace,
            &request.command_key,
            &request.scope_id,
            &request.target_id,
        ] {
            valid_id(value)?;
        }
        if request.namespace != "podbay.launch" {
            return Err(StoreError::NotFound);
        }
        if request.canonical_intent.is_empty() || request.canonical_intent.len() > MAX_BYTES {
            return Err(StoreError::InvalidInput(
                "canonical caller intent size is invalid",
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let row: Option<(
            i64,
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
                "SELECT command_rowid,command_id,digest_version,request_digest,
                        canonical_request,owner_epoch,target_epoch,event_sequence,outbox_id
                 FROM commands WHERE principal=?1 AND namespace=?2 AND command_key=?3
                   AND scope_id=?4 AND target_id=?5",
                params![
                    request.principal.as_str(),
                    request.namespace,
                    request.command_key,
                    request.scope_id,
                    request.target_id
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
        let (
            command_rowid,
            command_id,
            version,
            request_digest,
            canonical,
            owner,
            target_epoch,
            event,
            outbox,
        ) = row.ok_or(StoreError::NotFound)?;
        if canonical != request.canonical_intent {
            return Err(StoreError::Conflict(
                "command key changed canonical caller intent",
            ));
        }
        if version != DIGEST_VERSION || owner < 0 || target_epoch <= 0 {
            return Err(StoreError::Conflict(
                "launch admission lineage is malformed",
            ));
        }
        let event_sequence = event
            .filter(|id| *id > 0)
            .ok_or(StoreError::Conflict("incomplete committed event"))?;
        let outbox_id = outbox
            .filter(|id| *id > 0)
            .ok_or(StoreError::Conflict("incomplete committed outbox"))?;
        let reserved: Option<i64> = transaction
            .query_row(
                "SELECT command_rowid FROM launch_slots
             WHERE scope_id=?1 AND pod_id=?2 AND pod_incarnation=?3",
                params![request.scope_id, request.target_id, target_epoch],
                |row| row.get(0),
            )
            .optional()?;
        if reserved != Some(command_rowid) {
            return Err(StoreError::Conflict(
                "launch slot does not bind admitted command",
            ));
        }
        let admission_event: Option<(String, Vec<u8>, String, String, i64, i64)> = transaction
            .query_row(
                "SELECT kind,payload,scope_id,target_id,owner_epoch,target_epoch
                 FROM events WHERE sequence=?1 AND command_rowid=?2",
                params![event_sequence, command_rowid],
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
        let (event_kind, event_payload, event_scope, event_target, event_owner, event_target_epoch) =
            admission_event.ok_or(StoreError::Conflict("admission event is missing"))?;
        if event_scope != request.scope_id
            || event_target != request.target_id
            || event_owner != owner
            || event_target_epoch != target_epoch
        {
            return Err(StoreError::Conflict("admission event lineage differs"));
        }
        let raw_effect: Option<(Vec<u8>, String)> = transaction
            .query_row(
                "SELECT payload,effect_digest FROM outbox
             WHERE outbox_id=?1 AND command_rowid=?2",
                params![outbox_id, command_rowid],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (effect_payload, effect_digest) =
            raw_effect.ok_or(StoreError::Conflict("admitted outbox effect is missing"))?;
        if sha256_hex(&effect_payload) != effect_digest {
            return Err(StoreError::Conflict("outbox effect digest changed"));
        }
        let effect = transaction.query_row(
            "SELECT o.outbox_id,c.command_id,o.scope_id,o.target_id,o.owner_epoch,
                    o.target_epoch,o.kind,o.payload,o.state,o.claim_key,
                    o.claim_owner_epoch,o.observation_key,o.observation_payload,
                    o.observation_stage,o.observation_event_sequence,o.effect_digest
             FROM outbox o JOIN commands c ON c.command_rowid=o.command_rowid
             WHERE o.outbox_id=?1 AND o.command_rowid=?2",
            params![outbox_id, command_rowid],
            stored_effect_from_row,
        )?;
        if effect.kind != "pod.offer" {
            return Err(StoreError::UnsupportedEffectKind);
        }
        if effect.command_id != command_id
            || effect.scope_id != request.scope_id
            || effect.target_id != request.target_id
            || effect.admission_owner_epoch != owner as u64
            || effect.admission_target_epoch != target_epoch as u64
        {
            return Err(StoreError::Conflict("outbox launch lineage differs"));
        }
        let reconstructed = CommandRequest {
            principal: request.principal.clone(),
            namespace: request.namespace.clone(),
            command_key: request.command_key.clone(),
            scope_id: request.scope_id.clone(),
            target_id: request.target_id.clone(),
            expected_owner_epoch: owner as u64,
            expected_target_epoch: target_epoch as u64,
            canonical_request: canonical,
            event_kind,
            event_payload,
            effect_kind: effect.kind.clone(),
            effect_payload,
        };
        if digest_request(&reconstructed) != request_digest {
            return Err(StoreError::Conflict("stored launch request digest changed"));
        }
        let outcome: (String, Option<String>, Option<String>) = transaction.query_row(
            "SELECT o.state,d.stage,d.receipt_ref FROM outbox o
             LEFT JOIN launch_dispatch_outcomes d ON d.outbox_id=o.outbox_id
             WHERE o.outbox_id=?1",
            [outbox_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let status = match (outcome.0.as_str(), outcome.1.as_deref()) {
            ("prepared", None) => LaunchDispatchStatus {
                stage: LaunchDispatchStage::Prepared,
                receipt_ref: None,
            },
            ("claimed_uncertain" | "observed", None) => LaunchDispatchStatus {
                stage: LaunchDispatchStage::ClaimedUncertain,
                receipt_ref: None,
            },
            ("claimed_uncertain" | "observed", Some(stage)) => LaunchDispatchStatus {
                stage: match stage {
                    "refused_before_effect" => LaunchDispatchStage::RefusedBeforeEffect,
                    "uncertain_after_possible_effect" => {
                        LaunchDispatchStage::UncertainAfterPossibleEffect
                    }
                    "host_accepted" => LaunchDispatchStage::HostAccepted,
                    "port_settled" => LaunchDispatchStage::PortSettled,
                    _ => return Err(StoreError::Conflict("unknown launch dispatch stage")),
                },
                receipt_ref: outcome.2,
            },
            _ => return Err(StoreError::Conflict("launch dispatch state is malformed")),
        };
        transaction.commit()?;
        Ok(AdmittedLaunchInspection {
            receipt: Receipt {
                command_id,
                event_sequence,
                outbox_id,
                digest_version: DIGEST_VERSION,
                request_digest,
            },
            effect,
            status,
            binding: LaunchIntentBinding::HistoricalUnboundV7,
        })
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
                "SELECT scope_id,target_id,target_epoch,state,claim_key,kind,
                        payload,effect_digest
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
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, String>(7)?,
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
        if sha256_hex(&row.6) != row.7 {
            return Err(StoreError::Conflict("outbox effect digest changed"));
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
                        o.claim_owner_epoch,o.observation_key,o.observation_payload,
                        o.observation_stage,o.observation_event_sequence,o.effect_digest
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
                    o.claim_owner_epoch,o.observation_key,o.observation_payload,
                    o.observation_stage,o.observation_event_sequence,o.effect_digest
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

    /// Records host acceptance, never provider insertion or task completion.
    /// The authenticated host boundary must validate the proof before construction.
    pub fn observe_effect(
        &mut self,
        outbox_id: i64,
        scope_id: &str,
        target_id: &str,
        expected_owner_epoch: u64,
        expected_target_epoch: u64,
        claim_key: &str,
        proof: &HostAcceptanceProof,
    ) -> Result<EffectObservation, StoreError> {
        valid_id(scope_id)?;
        valid_id(target_id)?;
        valid_id(claim_key)?;
        let owner_epoch = integer(expected_owner_epoch)?;
        let target_epoch = integer(expected_target_epoch)?;
        let source_epoch = integer(proof.source_epoch)?;
        let source_sequence = integer(proof.source_sequence)?;
        let source_digest = digest_host_proof(outbox_id, scope_id, target_id, claim_key, proof);
        let public_payload = host_event_payload(proof);
        let store_lineage = self.store_lineage.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = transaction
            .query_row(
                "SELECT command_rowid,scope_id,target_id,kind,state,claim_key,
                        observation_key,observation_payload,observation_stage,
                        observation_event_sequence FROM outbox WHERE outbox_id=?1",
                [outbox_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, Option<Vec<u8>>>(7)?,
                        row.get::<_, Option<String>>(8)?,
                        row.get::<_, Option<i64>>(9)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        if row.1 != scope_id || row.2 != target_id {
            return Err(StoreError::WrongScope);
        }
        if current_owner(&transaction)? != owner_epoch
            || current_target(&transaction, scope_id, target_id)? != target_epoch
        {
            return Err(StoreError::StaleEpoch);
        }
        if !supported_effect_kind(&row.3) {
            return Err(StoreError::UnsupportedEffectKind);
        }
        if row.5.as_deref() != Some(claim_key) {
            return Err(StoreError::Conflict("effect claim identity changed"));
        }
        let existing: Option<(String, i64, String)> = transaction
            .query_row(
                "SELECT event_id,sequence,source_digest FROM events
                 WHERE scope_id=?1 AND source_id=?2 AND source_epoch=?3
                   AND source_sequence=?4",
                params![scope_id, proof.source_id, source_epoch, source_sequence],
                |event| Ok((event.get(0)?, event.get(1)?, event.get(2)?)),
            )
            .optional()?;
        if let Some((event_id, event_sequence, prior_digest)) = existing {
            if prior_digest != source_digest {
                transaction.execute(
                    "INSERT OR IGNORE INTO event_quarantine(
                       scope_id,source_id,source_epoch,source_sequence,
                       existing_event_id,incoming_digest,incoming_payload,
                       incoming_evidence,recorded_at)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,
                       strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                    params![
                        scope_id,
                        proof.source_id,
                        source_epoch,
                        source_sequence,
                        event_id,
                        source_digest,
                        public_payload,
                        proof.evidence,
                    ],
                )?;
                transaction.commit()?;
                return Err(StoreError::SourceIdentityQuarantined);
            }
            if row.4 != "observed"
                || row.6.as_deref() != Some(proof.host_receipt_id.as_str())
                || row.7.as_deref() != Some(proof.evidence.as_slice())
                || row.8.as_deref() != Some("host_accepted")
                || row.9 != Some(event_sequence)
            {
                return Err(StoreError::Conflict(
                    "source identity belongs to another effect",
                ));
            }
            transaction.commit()?;
            return Ok(EffectObservation::AlreadyObserved(EventReference {
                event_id,
                cursor: EventCursor {
                    store_lineage,
                    scope_id: scope_id.to_owned(),
                    sequence: event_sequence,
                },
            }));
        }
        if row.4 != "claimed_uncertain" {
            return Err(StoreError::Conflict("effect observation identity changed"));
        }
        let highest_seen: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(source_sequence),0) FROM events
             WHERE scope_id=?1 AND source_id=?2 AND source_epoch=?3",
            params![scope_id, proof.source_id, source_epoch],
            |event| event.get(0),
        )?;
        let (source_order, order_reference) = if source_sequence == highest_seen + 1 {
            ("contiguous", None)
        } else if source_sequence > highest_seen + 1 {
            ("gap", Some(highest_seen + 1))
        } else {
            ("out_of_order", Some(highest_seen))
        };
        transaction.execute(
            "INSERT INTO events(
               event_id,schema_version,command_rowid,scope_id,target_id,
               owner_epoch,target_epoch,source_id,source_kind,source_epoch,
               source_sequence,source_digest,source_order,source_order_reference,
               kind,payload,recorded_at,occurred_at,provenance,correlation_id,
               causation_id)
             VALUES('event.pb07.' || lower(hex(randomblob(16))),1,?1,?2,?3,
                    ?4,?5,?6,'host',?7,?8,?9,?10,?11,
                    'effect.host_accepted',?12,
                    strftime('%Y-%m-%dT%H:%M:%fZ','now'),?13,
                    'authenticated.host.acceptance',?14,?15)",
            params![
                row.0,
                scope_id,
                target_id,
                owner_epoch,
                target_epoch,
                proof.source_id,
                source_epoch,
                source_sequence,
                source_digest,
                source_order,
                order_reference,
                public_payload,
                proof.occurred_at,
                proof.correlation_id,
                proof.causation_id,
            ],
        )?;
        let event_sequence = transaction.last_insert_rowid();
        let event_id: String = transaction.query_row(
            "SELECT event_id FROM events WHERE sequence=?1",
            [event_sequence],
            |event| event.get(0),
        )?;
        let changed = transaction.execute(
            "UPDATE outbox SET state='observed',observation_key=?1,
             observation_payload=?2,observation_stage='host_accepted',
             observation_event_sequence=?3
             WHERE outbox_id=?4 AND state='claimed_uncertain'",
            params![
                proof.host_receipt_id,
                proof.evidence,
                event_sequence,
                outbox_id
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict(
                "effect changed while recording observation",
            ));
        }
        transaction.commit()?;
        Ok(EffectObservation::NewObservation(EventReference {
            event_id,
            cursor: EventCursor {
                store_lineage,
                scope_id: scope_id.to_owned(),
                sequence: event_sequence,
            },
        }))
    }

    pub fn quarantined_events(
        &self,
        scope_id: &str,
        after_quarantine_id: i64,
        limit: usize,
    ) -> Result<Vec<QuarantinedSourceEvent>, StoreError> {
        valid_id(scope_id)?;
        if after_quarantine_id < 0 || !(1..=512).contains(&limit) {
            return Err(StoreError::InvalidInput(
                "quarantine cursor or limit is invalid",
            ));
        }
        let mut statement = self.connection.prepare(
            "SELECT quarantine_id,scope_id,source_id,source_epoch,source_sequence,
                    existing_event_id,incoming_digest,incoming_payload,incoming_evidence,
                    recorded_at
             FROM event_quarantine WHERE scope_id=?1 AND quarantine_id>?2
             ORDER BY quarantine_id LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![scope_id, after_quarantine_id, limit as i64],
            |row| {
                Ok(QuarantinedSourceEvent {
                    quarantine_id: row.get(0)?,
                    scope_id: row.get(1)?,
                    source_id: row.get(2)?,
                    source_epoch: row.get::<_, i64>(3)? as u64,
                    source_sequence: row.get::<_, i64>(4)? as u64,
                    existing_event_id: row.get(5)?,
                    incoming_digest: row.get(6)?,
                    incoming_payload: row.get(7)?,
                    incoming_evidence: row.get(8)?,
                    recorded_at: row.get(9)?,
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
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
        let effects = {
            let mut statement = transaction.prepare(
                "SELECT o.outbox_id,c.command_id,o.scope_id,o.target_id,o.owner_epoch,
                        o.target_epoch,o.kind,o.payload,o.state,o.claim_key,
                        o.claim_owner_epoch,o.observation_key,o.observation_payload,
                        o.observation_stage,o.observation_event_sequence,o.effect_digest
                 FROM outbox o JOIN commands c ON c.command_rowid=o.command_rowid
                 WHERE o.scope_id=?1 ORDER BY o.outbox_id",
            )?;
            statement
                .query_map([scope_id], stored_effect_from_row)?
                .collect::<Result<Vec<_>, _>>()?
        };
        let source_anomalies = {
            let mut statement = transaction.prepare(
                "SELECT event_id,source_id,source_epoch,source_sequence,
                        source_order,source_order_reference
                 FROM events WHERE scope_id=?1 AND source_order!='contiguous'
                 ORDER BY sequence",
            )?;
            statement
                .query_map([scope_id], |row| {
                    let order: String = row.get(4)?;
                    let reference: Option<i64> = row.get(5)?;
                    Ok(SourceAnomaly {
                        event_id: row.get(0)?,
                        source_id: row.get(1)?,
                        source_epoch: row.get::<_, i64>(2)? as u64,
                        source_sequence: row.get::<_, i64>(3)? as u64,
                        order: source_order_from_row(&order, reference)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        transaction.commit()?;
        Ok(ScopeSnapshot {
            cursor: EventCursor {
                store_lineage,
                scope_id: scope_id.to_owned(),
                sequence: cursor,
            },
            receipts,
            effects,
            source_anomalies,
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
            "SELECT e.sequence,e.event_id,e.schema_version,c.command_id,e.target_id,
                    e.source_id,e.source_kind,e.source_epoch,e.source_sequence,
                    e.source_order,e.source_order_reference,e.recorded_at,e.occurred_at,
                    e.provenance,e.correlation_id,e.causation_id,e.kind,e.payload
             FROM events e
             JOIN commands c ON c.command_rowid=e.command_rowid
             WHERE e.scope_id=?1 AND e.sequence>?2 ORDER BY e.sequence LIMIT ?3",
        )?;
        let rows = statement.query_map(params![scope_id, after.sequence, limit as i64], |row| {
            committed_event_from_row(row, &self.store_lineage, scope_id)
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
    if request.effect_kind == "pod.offer" && request.expected_target_epoch == 0 {
        return Err(StoreError::InvalidInput(
            "launch pod incarnation must be positive",
        ));
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
    let observed_stage = match row.get::<_, Option<String>>(13)?.as_deref() {
        Some("host_accepted") => Some(ObservedStage::HostAccepted),
        Some("legacy_unverified") => Some(ObservedStage::LegacyUnverified),
        None => None,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    let payload: Vec<u8> = row.get(7)?;
    let effect_digest: String = row.get(15)?;
    if sha256_hex(&payload) != effect_digest {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(StoredEffect {
        outbox_id: row.get(0)?,
        command_id: row.get(1)?,
        scope_id: row.get(2)?,
        target_id: row.get(3)?,
        admission_owner_epoch: row.get::<_, i64>(4)? as u64,
        admission_target_epoch: row.get::<_, i64>(5)? as u64,
        kind: row.get(6)?,
        payload,
        effect_digest,
        state,
        claim_key: row.get(9)?,
        claim_owner_epoch: row.get::<_, Option<i64>>(10)?.map(|value| value as u64),
        observation_key: row.get(11)?,
        observation_payload: row.get(12)?,
        observed_stage,
        observation_event_sequence: row.get(14)?,
    })
}

fn source_order_from_row(value: &str, reference: Option<i64>) -> rusqlite::Result<SourceOrder> {
    match (value, reference) {
        ("contiguous", None) => Ok(SourceOrder::Contiguous),
        ("gap", Some(expected_next)) if expected_next >= 1 => Ok(SourceOrder::Gap {
            expected_next: expected_next as u64,
        }),
        ("out_of_order", Some(highest_seen)) if highest_seen >= 1 => Ok(SourceOrder::OutOfOrder {
            highest_seen: highest_seen as u64,
        }),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn committed_event_from_row(
    row: &rusqlite::Row<'_>,
    store_lineage: &str,
    scope_id: &str,
) -> rusqlite::Result<CommittedEvent> {
    let sequence: i64 = row.get(0)?;
    let order: String = row.get(9)?;
    let reference: Option<i64> = row.get(10)?;
    Ok(CommittedEvent {
        sequence,
        event_id: row.get(1)?,
        cursor: EventCursor {
            store_lineage: store_lineage.to_owned(),
            scope_id: scope_id.to_owned(),
            sequence,
        },
        schema_version: row.get::<_, i64>(2)? as u32,
        command_id: row.get(3)?,
        target_id: row.get(4)?,
        source_id: row.get(5)?,
        source_kind: row.get(6)?,
        source_epoch: row.get::<_, i64>(7)? as u64,
        source_sequence: row.get::<_, i64>(8)? as u64,
        source_order: source_order_from_row(&order, reference)?,
        recorded_at: row.get(11)?,
        occurred_at: row.get(12)?,
        provenance: row.get(13)?,
        correlation_id: row.get(14)?,
        causation_id: row.get(15)?,
        kind: row.get(16)?,
        payload: row.get(17)?,
    })
}

fn digest_host_proof(
    outbox_id: i64,
    scope_id: &str,
    target_id: &str,
    claim_key: &str,
    proof: &HostAcceptanceProof,
) -> String {
    let mut digest = Sha256::new();
    let outbox_bytes = outbox_id.to_be_bytes();
    let source_epoch_bytes = proof.source_epoch.to_be_bytes();
    let source_sequence_bytes = proof.source_sequence.to_be_bytes();
    for field in [
        b"podbay-host-acceptance/1".as_slice(),
        outbox_bytes.as_slice(),
        scope_id.as_bytes(),
        target_id.as_bytes(),
        claim_key.as_bytes(),
        proof.source_id.as_bytes(),
        source_epoch_bytes.as_slice(),
        source_sequence_bytes.as_slice(),
        proof.host_receipt_id.as_bytes(),
        proof.evidence.as_slice(),
        proof.occurred_at.as_deref().unwrap_or("").as_bytes(),
        proof.correlation_id.as_bytes(),
        proof.causation_id.as_deref().unwrap_or("").as_bytes(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn host_event_payload(proof: &HostAcceptanceProof) -> Vec<u8> {
    let evidence_digest = Sha256::digest(&proof.evidence)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "{{\"kind\":\"delivery_changed\",\"observedStage\":\"host_accepted\",\
         \"hostReceiptId\":\"{}\",\"evidenceDigest\":\"{}\"}}",
        proof.host_receipt_id, evidence_digest
    )
    .into_bytes()
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

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn verify_authority_schema(transaction: &rusqlite::Transaction<'_>) -> Result<(), StoreError> {
    for (table, expected) in [
        ("authority_pods", &["pod_id", "scope_id", "incarnation"][..]),
        (
            "authority_resources",
            &[
                "resource_id",
                "scope_id",
                "pod_id",
                "pod_incarnation",
                "resource_epoch",
                "input_epoch",
            ][..],
        ),
        (
            "authority_actors",
            &[
                "actor_id",
                "scope_id",
                "role",
                "origin",
                "parent_actor_id",
                "pod_id",
                "pod_incarnation",
                "credential_generation",
                "platform",
                "os_identity",
                "process_identity",
                "start_identity",
                "containment_identity",
            ][..],
        ),
        (
            "authority_grants",
            &[
                "grant_id",
                "scope_id",
                "actor_id",
                "credential_generation",
                "mode",
                "remaining_depth",
            ][..],
        ),
        (
            "authority_grant_rights",
            &["grant_id", "operation", "target_kind", "target_id"][..],
        ),
        (
            "launch_dispatch_outcomes",
            &[
                "outbox_id",
                "claim_key",
                "stage",
                "receipt_ref",
                "recorded_at",
            ][..],
        ),
        (
            "launch_slots",
            &["scope_id", "pod_id", "pod_incarnation", "command_rowid"][..],
        ),
    ] {
        let mut statement = transaction.prepare(&format!("PRAGMA table_info({table})"))?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<Vec<_>, _>>()?;
        if columns.iter().map(String::as_str).collect::<Vec<_>>() != expected {
            return Err(StoreError::Conflict(
                "authority schema columns do not match",
            ));
        }
    }
    Ok(())
}
