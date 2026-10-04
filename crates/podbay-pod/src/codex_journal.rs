//! Portable pod-local Codex command facts. This journal performs no native
//! RPC and grants no writer authority; a caller must supply current durable
//! authority and child evidence before using a freshly synced intent.

use std::path::Path;

use podbay_core::{AttemptId, Epoch, PodId, ResourceId, RunId, ScopeId, SessionId, StoreLineageId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::manifest::PodError;
use crate::ports::{DurableAppendLog, DurableFileIdentity, DurableFiles};

const FRAME_DOMAIN: &[u8] = b"podbay.codex-journal-frame/1\0";
const MAX_LOG_BYTES: u64 = 16 * 1_048_576;
const MAX_FRAME_BYTES: usize = 16_384;
const MAX_RECORDS: u64 = 65_536;
const HEADER_BYTES: usize = 4 + 32;

/// The exact durable PodBay resource namespace. No native thread, PID or
/// caller display name substitutes for this identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexJournalIdentity {
    store_lineage: String,
    scope_id: String,
    session_id: String,
    run_id: String,
    attempt_id: String,
    pod_id: String,
    pod_incarnation: u64,
    resource_id: String,
    resource_epoch: u64,
}

impl CodexJournalIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn from_resource(
        store_lineage: &StoreLineageId,
        scope_id: &ScopeId,
        session_id: &SessionId,
        run_id: &RunId,
        attempt_id: &AttemptId,
        pod_id: &PodId,
        pod_incarnation: Epoch,
        resource_id: &ResourceId,
        resource_epoch: Epoch,
    ) -> Self {
        Self {
            store_lineage: store_lineage.as_str().into(),
            scope_id: scope_id.as_str().into(),
            session_id: session_id.as_str().into(),
            run_id: run_id.as_str().into(),
            attempt_id: attempt_id.as_str().into(),
            pod_id: pod_id.as_str().into(),
            pod_incarnation: pod_incarnation.get(),
            resource_id: resource_id.as_str().into(),
            resource_epoch: resource_epoch.get(),
        }
    }

    fn validate(&self) -> Result<(), PodError> {
        let valid = StoreLineageId::try_from(self.store_lineage.as_str()).is_ok()
            && ScopeId::try_from(self.scope_id.as_str()).is_ok()
            && SessionId::try_from(self.session_id.as_str()).is_ok()
            && RunId::try_from(self.run_id.as_str()).is_ok()
            && AttemptId::try_from(self.attempt_id.as_str()).is_ok()
            && PodId::try_from(self.pod_id.as_str()).is_ok()
            && ResourceId::try_from(self.resource_id.as_str()).is_ok()
            && self.pod_incarnation > 0
            && self.resource_epoch > 0;
        if valid {
            Ok(())
        } else {
            Err(PodError::Invalid("Codex journal resource identity"))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodexJournalStage {
    Empty,
    ThreadCreateIntentDurable,
    ThreadCreateUnknownAfterReopen,
    ThreadCreated,
    BootstrapIntentDurable,
    BootstrapUnknownAfterReopen,
    BootstrapUncertain,
    BootstrapSubmitted,
    BootstrapCompletionObservedPendingIdleProof,
    BootstrapFailed,
    BootstrapInterrupted,
    BootstrapCompleted,
    StorageUncertain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexJournalView {
    pub stage: CodexJournalStage,
    pub command_key: Option<String>,
    pub payload_digest: Option<String>,
    pub native_thread_id: Option<String>,
    pub native_session_id: Option<String>,
    pub client_message_id: Option<String>,
    pub native_turn_id: Option<String>,
}

/// Only NewlyDurable follows a completed fsync of this intent. A duplicate
/// never authorizes another native RPC, even within the original process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodexJournalIntentResult {
    NewlyDurable,
    Duplicate(CodexJournalView),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Phase {
    #[default]
    Empty,
    ThreadCreateIntent,
    ThreadCreated,
    BootstrapIntent,
    BootstrapUncertain,
    BootstrapSubmitted,
    BootstrapCompletionObserved,
    BootstrapFailed,
    BootstrapInterrupted,
    BootstrapCompleted,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Snapshot {
    phase: Phase,
    command_key: Option<String>,
    payload_digest: Option<String>,
    native_thread_id: Option<String>,
    native_session_id: Option<String>,
    client_message_id: Option<String>,
    native_turn_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum JournalEvent {
    ThreadCreateIntent,
    ThreadCreated {
        native_thread_id: String,
        native_session_id: String,
    },
    BootstrapIntent {
        client_message_id: String,
    },
    BootstrapUncertain,
    BootstrapSubmitted {
        native_turn_id: String,
    },
    BootstrapCompletionObserved {
        native_turn_id: String,
    },
    BootstrapFailed {
        native_turn_id: String,
    },
    BootstrapInterrupted {
        native_turn_id: String,
    },
    BootstrapCompleted {
        native_turn_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalRecord {
    version: u8,
    sequence: u64,
    identity: CodexJournalIdentity,
    command_key: String,
    payload_digest: String,
    event: JournalEvent,
}

/// A one-bootstrap lifecycle journal. It stores identifiers and a payload
/// digest, never prompt text or credential bytes. Native completion is an
/// externally verified observation supplied by a future pod command bridge.
pub struct CodexCommandJournal {
    log: Box<dyn DurableAppendLog>,
    identity: CodexJournalIdentity,
    snapshot: Snapshot,
    records: u64,
    fresh_thread_intent: bool,
    fresh_bootstrap_intent: bool,
    poisoned: bool,
}

impl CodexCommandJournal {
    /// `path` must be derived from the trusted pod binding, never request JSON.
    /// Reopen parses the complete checksummed tail and never repairs it.
    pub fn open(
        files: &impl DurableFiles,
        path: &Path,
        identity: CodexJournalIdentity,
    ) -> Result<Self, PodError> {
        identity.validate()?;
        let mut log = files.open_private_append_log(path, MAX_LOG_BYTES)?;
        let raw = log.read_all_bounded()?;
        if raw.len() as u64 > MAX_LOG_BYTES {
            return Err(PodError::Refused("Codex journal retention bound"));
        }
        let (snapshot, records) = replay(&raw, &identity)?;
        Ok(Self {
            log,
            identity,
            snapshot,
            records,
            fresh_thread_intent: false,
            fresh_bootstrap_intent: false,
            poisoned: false,
        })
    }

    pub fn file_identity(&self) -> &DurableFileIdentity {
        self.log.identity()
    }

    pub fn matches_identity(&self, expected: &CodexJournalIdentity) -> bool {
        &self.identity == expected
    }

    /// Recheck the held file against its path, privacy and complete durable
    /// tail before a native effect. A changed inode or torn append is never
    /// interpreted as an absent command.
    pub fn recheck_held_file(&mut self) -> Result<(), PodError> {
        self.healthy()?;
        let identity = self.log.identity().clone();
        let raw = self
            .log
            .read_all_bounded()
            .inspect_err(|_| self.poisoned = true)?;
        let (snapshot, records) =
            replay(&raw, &self.identity).inspect_err(|_| self.poisoned = true)?;
        if self.log.identity() != &identity || snapshot != self.snapshot || records != self.records
        {
            self.poisoned = true;
            return Err(PodError::Uncertain("Codex journal changed outside owner"));
        }
        Ok(())
    }

    pub fn view(&self) -> CodexJournalView {
        let stage = if self.poisoned {
            CodexJournalStage::StorageUncertain
        } else {
            match self.snapshot.phase {
                Phase::Empty => CodexJournalStage::Empty,
                Phase::ThreadCreateIntent if self.fresh_thread_intent => {
                    CodexJournalStage::ThreadCreateIntentDurable
                }
                Phase::ThreadCreateIntent => CodexJournalStage::ThreadCreateUnknownAfterReopen,
                Phase::ThreadCreated => CodexJournalStage::ThreadCreated,
                Phase::BootstrapIntent if self.fresh_bootstrap_intent => {
                    CodexJournalStage::BootstrapIntentDurable
                }
                Phase::BootstrapIntent => CodexJournalStage::BootstrapUnknownAfterReopen,
                Phase::BootstrapUncertain => CodexJournalStage::BootstrapUncertain,
                Phase::BootstrapSubmitted => CodexJournalStage::BootstrapSubmitted,
                Phase::BootstrapCompletionObserved => {
                    CodexJournalStage::BootstrapCompletionObservedPendingIdleProof
                }
                Phase::BootstrapFailed => CodexJournalStage::BootstrapFailed,
                Phase::BootstrapInterrupted => CodexJournalStage::BootstrapInterrupted,
                Phase::BootstrapCompleted => CodexJournalStage::BootstrapCompleted,
            }
        };
        CodexJournalView {
            stage,
            command_key: self.snapshot.command_key.clone(),
            payload_digest: self.snapshot.payload_digest.clone(),
            native_thread_id: self.snapshot.native_thread_id.clone(),
            native_session_id: self.snapshot.native_session_id.clone(),
            client_message_id: self.snapshot.client_message_id.clone(),
            native_turn_id: self.snapshot.native_turn_id.clone(),
        }
    }

    /// The caller must have current durable authority. A successful return
    /// only proves the intent was synced before it may call `thread/start`.
    pub fn begin_thread_create(
        &mut self,
        command_key: &str,
        payload_digest: &str,
    ) -> Result<CodexJournalIntentResult, PodError> {
        self.healthy()?;
        validate_command(command_key, payload_digest)?;
        if self.snapshot.phase != Phase::Empty {
            self.same_command(command_key, payload_digest)?;
            return Ok(CodexJournalIntentResult::Duplicate(self.view()));
        }
        self.append(
            command_key,
            payload_digest,
            JournalEvent::ThreadCreateIntent,
        )?;
        self.fresh_thread_intent = true;
        Ok(CodexJournalIntentResult::NewlyDurable)
    }

    /// Checkpoint the exact `thread/start` response before any bootstrap turn.
    pub fn checkpoint_thread_created(
        &mut self,
        command_key: &str,
        payload_digest: &str,
        native_thread_id: &str,
        native_session_id: &str,
    ) -> Result<CodexJournalView, PodError> {
        self.healthy()?;
        self.same_command(command_key, payload_digest)?;
        validate_native_id(native_thread_id)?;
        validate_native_id(native_session_id)?;
        if self.snapshot.phase == Phase::ThreadCreateIntent && self.fresh_thread_intent {
            self.append(
                command_key,
                payload_digest,
                JournalEvent::ThreadCreated {
                    native_thread_id: native_thread_id.into(),
                    native_session_id: native_session_id.into(),
                },
            )?;
            self.fresh_thread_intent = false;
        } else if self.snapshot.phase == Phase::ThreadCreateIntent {
            return Err(PodError::Uncertain(
                "thread create has no durable native receipt",
            ));
        } else if self.snapshot.native_thread_id.as_deref() != Some(native_thread_id)
            || self.snapshot.native_session_id.as_deref() != Some(native_session_id)
        {
            return Err(PodError::Conflict("native thread checkpoint changed"));
        }
        Ok(self.view())
    }

    /// A synced bootstrap intent is still only intent, not native acceptance.
    pub fn begin_bootstrap_intent(
        &mut self,
        command_key: &str,
        payload_digest: &str,
        client_message_id: &str,
    ) -> Result<CodexJournalIntentResult, PodError> {
        self.healthy()?;
        self.same_command(command_key, payload_digest)?;
        validate_client_message_id(client_message_id)?;
        if self.snapshot.phase == Phase::ThreadCreated {
            self.append(
                command_key,
                payload_digest,
                JournalEvent::BootstrapIntent {
                    client_message_id: client_message_id.into(),
                },
            )?;
            self.fresh_bootstrap_intent = true;
            return Ok(CodexJournalIntentResult::NewlyDurable);
        }
        if self.snapshot.client_message_id.as_deref() != Some(client_message_id) {
            return Err(PodError::Conflict("bootstrap client message ID changed"));
        }
        Ok(CodexJournalIntentResult::Duplicate(self.view()))
    }

    /// A lost native reply is recorded distinctly and cannot be resent here.
    pub fn record_bootstrap_uncertain(
        &mut self,
        command_key: &str,
        payload_digest: &str,
    ) -> Result<CodexJournalView, PodError> {
        self.healthy()?;
        self.same_command(command_key, payload_digest)?;
        if self.snapshot.phase == Phase::BootstrapIntent && self.fresh_bootstrap_intent {
            self.append(
                command_key,
                payload_digest,
                JournalEvent::BootstrapUncertain,
            )?;
            self.fresh_bootstrap_intent = false;
        } else if self.snapshot.phase == Phase::BootstrapIntent {
            return Err(PodError::Uncertain(
                "bootstrap intent has no durable native receipt",
            ));
        } else if self.snapshot.phase != Phase::BootstrapUncertain {
            return Err(PodError::Conflict(
                "bootstrap uncertainty transition refused",
            ));
        }
        Ok(self.view())
    }

    /// Store the exact native turn ID from a successful `turn/start` receipt.
    pub fn record_bootstrap_submitted(
        &mut self,
        command_key: &str,
        payload_digest: &str,
        native_turn_id: &str,
    ) -> Result<CodexJournalView, PodError> {
        self.healthy()?;
        self.same_command(command_key, payload_digest)?;
        validate_native_id(native_turn_id)?;
        if self.snapshot.phase == Phase::BootstrapIntent && self.fresh_bootstrap_intent {
            self.append(
                command_key,
                payload_digest,
                JournalEvent::BootstrapSubmitted {
                    native_turn_id: native_turn_id.into(),
                },
            )?;
            self.fresh_bootstrap_intent = false;
        } else if self.snapshot.phase == Phase::BootstrapIntent {
            return Err(PodError::Uncertain(
                "bootstrap intent has no durable native receipt",
            ));
        } else if !matches!(
            self.snapshot.phase,
            Phase::BootstrapSubmitted
                | Phase::BootstrapCompletionObserved
                | Phase::BootstrapFailed
                | Phase::BootstrapInterrupted
                | Phase::BootstrapCompleted
        ) || self.snapshot.native_turn_id.as_deref() != Some(native_turn_id)
        {
            return Err(PodError::Conflict("bootstrap native turn receipt changed"));
        }
        Ok(self.view())
    }

    /// Persist that this exact native turn emitted `turn/completed` with a
    /// completed status. This does not prove a fresh idle `thread/read` and
    /// must never be reported as BootstrapCompleted by itself.
    pub fn record_bootstrap_completion_observed(
        &mut self,
        command_key: &str,
        payload_digest: &str,
        native_turn_id: &str,
    ) -> Result<CodexJournalView, PodError> {
        self.healthy()?;
        self.same_command(command_key, payload_digest)?;
        if self.snapshot.native_turn_id.as_deref() != Some(native_turn_id) {
            return Err(PodError::Conflict("bootstrap completion turn differs"));
        }
        if self.snapshot.phase == Phase::BootstrapSubmitted {
            self.append(
                command_key,
                payload_digest,
                JournalEvent::BootstrapCompletionObserved {
                    native_turn_id: native_turn_id.into(),
                },
            )?;
        } else if !matches!(
            self.snapshot.phase,
            Phase::BootstrapCompletionObserved | Phase::BootstrapCompleted
        ) {
            return Err(PodError::Conflict(
                "bootstrap completion observation transition refused",
            ));
        }
        Ok(self.view())
    }

    /// Preserve a matching native failure separately from successful
    /// completion. A fresh idle read cannot turn this terminal fact into
    /// BootstrapCompleted.
    pub fn record_bootstrap_failed(
        &mut self,
        command_key: &str,
        payload_digest: &str,
        native_turn_id: &str,
    ) -> Result<CodexJournalView, PodError> {
        self.record_noncompletion(
            command_key,
            payload_digest,
            native_turn_id,
            JournalEvent::BootstrapFailed {
                native_turn_id: native_turn_id.into(),
            },
            Phase::BootstrapFailed,
        )
    }

    pub fn record_bootstrap_interrupted(
        &mut self,
        command_key: &str,
        payload_digest: &str,
        native_turn_id: &str,
    ) -> Result<CodexJournalView, PodError> {
        self.record_noncompletion(
            command_key,
            payload_digest,
            native_turn_id,
            JournalEvent::BootstrapInterrupted {
                native_turn_id: native_turn_id.into(),
            },
            Phase::BootstrapInterrupted,
        )
    }

    fn record_noncompletion(
        &mut self,
        command_key: &str,
        payload_digest: &str,
        native_turn_id: &str,
        event: JournalEvent,
        terminal: Phase,
    ) -> Result<CodexJournalView, PodError> {
        self.healthy()?;
        self.same_command(command_key, payload_digest)?;
        if self.snapshot.native_turn_id.as_deref() != Some(native_turn_id) {
            return Err(PodError::Conflict("bootstrap terminal turn differs"));
        }
        if self.snapshot.phase == Phase::BootstrapSubmitted {
            self.append(command_key, payload_digest, event)?;
        } else if self.snapshot.phase != terminal {
            return Err(PodError::Conflict("bootstrap terminal transition refused"));
        }
        Ok(self.view())
    }

    /// A separate bridge must verify a fresh idle/no-waiting/no-pending
    /// `thread/read` after the journaled completion notification before this
    /// final transition. This method is not called by the notification pump.
    pub fn record_bootstrap_completed(
        &mut self,
        command_key: &str,
        payload_digest: &str,
        native_turn_id: &str,
    ) -> Result<CodexJournalView, PodError> {
        self.healthy()?;
        self.same_command(command_key, payload_digest)?;
        if self.snapshot.native_turn_id.as_deref() != Some(native_turn_id) {
            return Err(PodError::Conflict("bootstrap completion turn differs"));
        }
        if self.snapshot.phase == Phase::BootstrapCompletionObserved {
            self.append(
                command_key,
                payload_digest,
                JournalEvent::BootstrapCompleted {
                    native_turn_id: native_turn_id.into(),
                },
            )?;
        } else if self.snapshot.phase != Phase::BootstrapCompleted {
            return Err(PodError::Conflict(
                "bootstrap completion transition refused",
            ));
        }
        Ok(self.view())
    }

    fn healthy(&self) -> Result<(), PodError> {
        if self.poisoned {
            Err(PodError::Uncertain("Codex journal append outcome unknown"))
        } else {
            Ok(())
        }
    }

    fn same_command(&self, key: &str, digest: &str) -> Result<(), PodError> {
        validate_command(key, digest)?;
        if self.snapshot.command_key.as_deref() == Some(key)
            && self.snapshot.payload_digest.as_deref() == Some(digest)
        {
            Ok(())
        } else {
            Err(PodError::Conflict("Codex command key or digest changed"))
        }
    }

    fn append(&mut self, key: &str, digest: &str, event: JournalEvent) -> Result<(), PodError> {
        let sequence = self
            .records
            .checked_add(1)
            .filter(|value| *value <= MAX_RECORDS)
            .ok_or(PodError::Refused("Codex journal record bound"))?;
        let record = JournalRecord {
            version: 1,
            sequence,
            identity: self.identity.clone(),
            command_key: key.into(),
            payload_digest: digest.into(),
            event,
        };
        let mut next = self.snapshot.clone();
        apply_record(&record, &self.identity, sequence, &mut next)?;
        let frame = encode_frame(&record)?;
        if self.log.len().saturating_add(frame.len() as u64) > MAX_LOG_BYTES {
            return Err(PodError::Refused("Codex journal retention bound"));
        }
        if let Err(error) = self.log.append_synced(&frame) {
            self.poisoned = true;
            return Err(error);
        }
        self.snapshot = next;
        self.records = sequence;
        Ok(())
    }
}

fn validate_command(key: &str, digest: &str) -> Result<(), PodError> {
    if !(3..=160).contains(&key.len())
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PodError::Invalid("Codex command key or digest"));
    }
    Ok(())
}

fn validate_native_id(id: &str) -> Result<(), PodError> {
    if id.is_empty() || id.len() > 512 || id.trim() != id || id.chars().any(char::is_control) {
        Err(PodError::Invalid("Codex native identity"))
    } else {
        Ok(())
    }
}

fn validate_client_message_id(id: &str) -> Result<(), PodError> {
    if id.is_empty() || id.len() > 256 || id.trim() != id || id.chars().any(char::is_control) {
        Err(PodError::Invalid("Codex client message ID"))
    } else {
        Ok(())
    }
}

fn apply_record(
    record: &JournalRecord,
    identity: &CodexJournalIdentity,
    expected_sequence: u64,
    state: &mut Snapshot,
) -> Result<(), PodError> {
    if record.version != 1 {
        return Err(PodError::Unsupported("Codex journal version"));
    }
    if record.sequence != expected_sequence || record.identity != *identity {
        return Err(PodError::Conflict(
            "Codex journal sequence or resource differs",
        ));
    }
    record.identity.validate()?;
    validate_command(&record.command_key, &record.payload_digest)?;
    if state.phase == Phase::Empty {
        if record.event != JournalEvent::ThreadCreateIntent {
            return Err(PodError::Conflict(
                "Codex journal initial transition refused",
            ));
        }
        state.command_key = Some(record.command_key.clone());
        state.payload_digest = Some(record.payload_digest.clone());
        state.phase = Phase::ThreadCreateIntent;
        return Ok(());
    }
    if state.command_key.as_deref() != Some(record.command_key.as_str())
        || state.payload_digest.as_deref() != Some(record.payload_digest.as_str())
    {
        return Err(PodError::Conflict("Codex journal command identity changed"));
    }
    match (&state.phase, &record.event) {
        (
            Phase::ThreadCreateIntent,
            JournalEvent::ThreadCreated {
                native_thread_id,
                native_session_id,
            },
        ) => {
            validate_native_id(native_thread_id)?;
            validate_native_id(native_session_id)?;
            state.native_thread_id = Some(native_thread_id.clone());
            state.native_session_id = Some(native_session_id.clone());
            state.phase = Phase::ThreadCreated;
        }
        (Phase::ThreadCreated, JournalEvent::BootstrapIntent { client_message_id }) => {
            validate_client_message_id(client_message_id)?;
            state.client_message_id = Some(client_message_id.clone());
            state.phase = Phase::BootstrapIntent;
        }
        (Phase::BootstrapIntent, JournalEvent::BootstrapUncertain) => {
            state.phase = Phase::BootstrapUncertain;
        }
        (Phase::BootstrapIntent, JournalEvent::BootstrapSubmitted { native_turn_id }) => {
            validate_native_id(native_turn_id)?;
            state.native_turn_id = Some(native_turn_id.clone());
            state.phase = Phase::BootstrapSubmitted;
        }
        (
            Phase::BootstrapSubmitted,
            JournalEvent::BootstrapCompletionObserved { native_turn_id },
        ) if state.native_turn_id.as_deref() == Some(native_turn_id.as_str()) => {
            state.phase = Phase::BootstrapCompletionObserved;
        }
        (Phase::BootstrapSubmitted, JournalEvent::BootstrapFailed { native_turn_id })
            if state.native_turn_id.as_deref() == Some(native_turn_id.as_str()) =>
        {
            state.phase = Phase::BootstrapFailed;
        }
        (Phase::BootstrapSubmitted, JournalEvent::BootstrapInterrupted { native_turn_id })
            if state.native_turn_id.as_deref() == Some(native_turn_id.as_str()) =>
        {
            state.phase = Phase::BootstrapInterrupted;
        }
        (
            Phase::BootstrapCompletionObserved,
            JournalEvent::BootstrapCompleted { native_turn_id },
        ) if state.native_turn_id.as_deref() == Some(native_turn_id.as_str()) => {
            state.phase = Phase::BootstrapCompleted;
        }
        _ => return Err(PodError::Conflict("Codex journal transition refused")),
    }
    Ok(())
}

fn encode_frame(record: &JournalRecord) -> Result<Vec<u8>, PodError> {
    let payload = serde_json::to_vec(record)?;
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(PodError::Invalid("Codex journal frame bound"));
    }
    let mut checksum = Sha256::new();
    checksum.update(FRAME_DOMAIN);
    checksum.update(&payload);
    let mut frame = Vec::with_capacity(HEADER_BYTES + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&checksum.finalize());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn replay(raw: &[u8], identity: &CodexJournalIdentity) -> Result<(Snapshot, u64), PodError> {
    let mut at = 0usize;
    let mut state = Snapshot::default();
    let mut records = 0u64;
    while at < raw.len() {
        if raw.len() - at < HEADER_BYTES {
            return Err(PodError::Uncertain("Codex journal tail is torn"));
        }
        let length = u32::from_be_bytes(raw[at..at + 4].try_into().expect("four bytes")) as usize;
        if length == 0 || length > MAX_FRAME_BYTES {
            return Err(PodError::Uncertain("Codex journal frame length is corrupt"));
        }
        let end = at
            .checked_add(HEADER_BYTES)
            .and_then(|value| value.checked_add(length))
            .ok_or(PodError::Uncertain("Codex journal frame length overflow"))?;
        if end > raw.len() {
            return Err(PodError::Uncertain("Codex journal tail is torn"));
        }
        let checksum = &raw[at + 4..at + HEADER_BYTES];
        let payload = &raw[at + HEADER_BYTES..end];
        let mut hash = Sha256::new();
        hash.update(FRAME_DOMAIN);
        hash.update(payload);
        if checksum != hash.finalize().as_slice() {
            return Err(PodError::Uncertain("Codex journal checksum differs"));
        }
        let record: JournalRecord = serde_json::from_slice(payload)
            .map_err(|_| PodError::Uncertain("Codex journal frame is malformed"))?;
        if serde_json::to_vec(&record)? != payload {
            return Err(PodError::Uncertain("Codex journal frame is not canonical"));
        }
        records = records
            .checked_add(1)
            .filter(|value| *value <= MAX_RECORDS)
            .ok_or(PodError::Refused("Codex journal record bound"))?;
        apply_record(&record, identity, records, &mut state)?;
        at = end;
    }
    Ok((state, records))
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Default)]
    struct MemoryState {
        bytes: Vec<u8>,
        append_calls: usize,
        partial_next: bool,
    }

    #[derive(Clone)]
    struct MemoryFiles {
        state: Arc<Mutex<MemoryState>>,
        identity: DurableFileIdentity,
    }

    impl MemoryFiles {
        fn new() -> Self {
            Self {
                state: Arc::new(Mutex::new(MemoryState::default())),
                identity: DurableFileIdentity::from_backend("fake/1", vec![1, 2, 3]).unwrap(),
            }
        }

        fn append_calls(&self) -> usize {
            self.state.lock().unwrap().append_calls
        }
    }

    struct MemoryHandle {
        state: Arc<Mutex<MemoryState>>,
        identity: DurableFileIdentity,
        max_bytes: u64,
    }

    impl DurableAppendLog for MemoryHandle {
        fn identity(&self) -> &DurableFileIdentity {
            &self.identity
        }

        fn len(&self) -> u64 {
            self.state.lock().unwrap().bytes.len() as u64
        }

        fn read_all_bounded(&mut self) -> Result<Vec<u8>, PodError> {
            let state = self.state.lock().unwrap();
            if state.bytes.len() as u64 > self.max_bytes {
                return Err(PodError::Refused("fake log bound"));
            }
            Ok(state.bytes.clone())
        }

        fn append_synced(&mut self, bytes: &[u8]) -> Result<(), PodError> {
            let mut state = self.state.lock().unwrap();
            if state.bytes.len() as u64 + bytes.len() as u64 > self.max_bytes {
                return Err(PodError::Refused("fake log bound"));
            }
            state.append_calls += 1;
            if std::mem::take(&mut state.partial_next) {
                state
                    .bytes
                    .extend_from_slice(&bytes[..bytes.len().div_ceil(2)]);
                return Err(PodError::Uncertain("fake partial append"));
            }
            state.bytes.extend_from_slice(bytes);
            Ok(())
        }
    }

    impl DurableFiles for MemoryFiles {
        fn create_private(&self, _: &Path, _: &[u8]) -> Result<(), PodError> {
            Err(PodError::Unsupported("fake legacy file operation"))
        }
        fn append_durable(&self, _: &Path, _: &[u8]) -> Result<(), PodError> {
            Err(PodError::Unsupported("fake legacy file operation"))
        }
        fn replace_durable(&self, _: &Path, _: &[u8]) -> Result<(), PodError> {
            Err(PodError::Unsupported("fake legacy file operation"))
        }
        fn open_private_append_log(
            &self,
            _: &Path,
            max_bytes: u64,
        ) -> Result<Box<dyn DurableAppendLog>, PodError> {
            Ok(Box::new(MemoryHandle {
                state: self.state.clone(),
                identity: self.identity.clone(),
                max_bytes,
            }))
        }
    }

    fn identity() -> CodexJournalIdentity {
        CodexJournalIdentity::from_resource(
            &StoreLineageId::try_from("lineage.fixture").unwrap(),
            &ScopeId::try_from("scope.fixture").unwrap(),
            &SessionId::try_from("session.fixture").unwrap(),
            &RunId::try_from("run.fixture").unwrap(),
            &AttemptId::try_from("attempt.fixture").unwrap(),
            &PodId::try_from("pod.fixture").unwrap(),
            Epoch::new(1).unwrap(),
            &ResourceId::try_from("resource.fixture").unwrap(),
            Epoch::new(1).unwrap(),
        )
    }

    const PATH: &str = "unused.fake.log";
    const KEY: &str = "command.fixture";

    #[test]
    fn duplicate_thread_intent_reopens_unknown_and_never_reissues() {
        let files = MemoryFiles::new();
        let digest = "a".repeat(64);
        let mut journal = CodexCommandJournal::open(&files, Path::new(PATH), identity()).unwrap();
        let file_identity = journal.file_identity().clone();
        assert_eq!(journal.view().stage, CodexJournalStage::Empty);
        assert_eq!(
            journal.begin_thread_create(KEY, &digest).unwrap(),
            CodexJournalIntentResult::NewlyDurable
        );
        assert_eq!(
            journal.begin_thread_create(KEY, &digest).unwrap(),
            CodexJournalIntentResult::Duplicate(journal.view())
        );
        assert_eq!(files.append_calls(), 1);
        assert!(matches!(
            journal.begin_thread_create(KEY, &"b".repeat(64)),
            Err(PodError::Conflict(_))
        ));
        drop(journal);
        let mut reopened = CodexCommandJournal::open(&files, Path::new(PATH), identity()).unwrap();
        assert_eq!(reopened.file_identity(), &file_identity);
        assert_eq!(
            reopened.view().stage,
            CodexJournalStage::ThreadCreateUnknownAfterReopen
        );
        assert!(matches!(
            reopened.begin_thread_create(KEY, &digest).unwrap(),
            CodexJournalIntentResult::Duplicate(_)
        ));
        assert!(matches!(
            reopened.checkpoint_thread_created(KEY, &digest, "thread.one", "session.one"),
            Err(PodError::Uncertain(_))
        ));
        assert_eq!(files.append_calls(), 1);
    }

    #[test]
    fn held_file_recheck_refuses_changed_tail_before_native_effect() {
        let files = MemoryFiles::new();
        let digest = "d".repeat(64);
        let mut journal = CodexCommandJournal::open(&files, Path::new(PATH), identity()).unwrap();
        journal.begin_thread_create(KEY, &digest).unwrap();
        journal.recheck_held_file().unwrap();
        files.state.lock().unwrap().bytes.push(0);
        assert!(matches!(
            journal.recheck_held_file(),
            Err(PodError::Uncertain(_))
        ));
        assert!(matches!(
            journal.begin_thread_create(KEY, &digest),
            Err(PodError::Uncertain(_))
        ));
    }

    #[test]
    fn checkpoint_bootstrap_and_completion_replay_distinct_facts() {
        let files = MemoryFiles::new();
        let digest = "b".repeat(64);
        let mut journal = CodexCommandJournal::open(&files, Path::new(PATH), identity()).unwrap();
        journal.begin_thread_create(KEY, &digest).unwrap();
        journal
            .checkpoint_thread_created(KEY, &digest, "thread.one", "session.one")
            .unwrap();
        assert!(matches!(
            journal.checkpoint_thread_created(KEY, &digest, "thread.other", "session.one"),
            Err(PodError::Conflict(_))
        ));
        drop(journal);
        let mut reopened = CodexCommandJournal::open(&files, Path::new(PATH), identity()).unwrap();
        assert_eq!(reopened.view().stage, CodexJournalStage::ThreadCreated);
        assert_eq!(
            reopened.view().native_thread_id.as_deref(),
            Some("thread.one")
        );
        assert_eq!(
            reopened
                .begin_bootstrap_intent(KEY, &digest, "message.one")
                .unwrap(),
            CodexJournalIntentResult::NewlyDurable
        );
        let append_calls = files.append_calls();
        assert!(matches!(
            reopened
                .begin_bootstrap_intent(KEY, &digest, "message.one")
                .unwrap(),
            CodexJournalIntentResult::Duplicate(_)
        ));
        assert_eq!(files.append_calls(), append_calls);
        assert!(matches!(
            reopened.begin_bootstrap_intent(KEY, &digest, "message.changed"),
            Err(PodError::Conflict(_))
        ));
        drop(reopened);
        let mut uncertain = CodexCommandJournal::open(&files, Path::new(PATH), identity()).unwrap();
        assert_eq!(
            uncertain.view().stage,
            CodexJournalStage::BootstrapUnknownAfterReopen
        );
        assert!(matches!(
            uncertain.record_bootstrap_submitted(KEY, &digest, "turn.one"),
            Err(PodError::Uncertain(_))
        ));

        let completed_files = MemoryFiles::new();
        let mut completed =
            CodexCommandJournal::open(&completed_files, Path::new(PATH), identity()).unwrap();
        completed.begin_thread_create(KEY, &digest).unwrap();
        completed
            .checkpoint_thread_created(KEY, &digest, "thread.two", "session.two")
            .unwrap();
        completed
            .begin_bootstrap_intent(KEY, &digest, "message.two")
            .unwrap();
        completed
            .record_bootstrap_submitted(KEY, &digest, "turn.two")
            .unwrap();
        assert!(matches!(
            completed.record_bootstrap_submitted(KEY, &digest, "turn.other"),
            Err(PodError::Conflict(_))
        ));
        drop(completed);
        let mut completed =
            CodexCommandJournal::open(&completed_files, Path::new(PATH), identity()).unwrap();
        assert_eq!(
            completed.view().stage,
            CodexJournalStage::BootstrapSubmitted
        );
        assert_eq!(completed.view().native_turn_id.as_deref(), Some("turn.two"));
        assert!(matches!(
            completed.record_bootstrap_completed(KEY, &digest, "turn.two"),
            Err(PodError::Conflict(_))
        ));
        completed
            .record_bootstrap_completion_observed(KEY, &digest, "turn.two")
            .unwrap();
        drop(completed);
        let mut completed =
            CodexCommandJournal::open(&completed_files, Path::new(PATH), identity()).unwrap();
        assert_eq!(
            completed.view().stage,
            CodexJournalStage::BootstrapCompletionObservedPendingIdleProof
        );
        completed
            .record_bootstrap_completed(KEY, &digest, "turn.two")
            .unwrap();
        drop(completed);
        let mut completed =
            CodexCommandJournal::open(&completed_files, Path::new(PATH), identity()).unwrap();
        assert_eq!(
            completed.view().stage,
            CodexJournalStage::BootstrapCompleted
        );
        assert!(matches!(
            completed.begin_thread_create(KEY, &digest).unwrap(),
            CodexJournalIntentResult::Duplicate(_)
        ));
        assert!(matches!(
            completed.begin_thread_create(KEY, &"c".repeat(64)),
            Err(PodError::Conflict(_))
        ));
        let mut wrong = identity();
        wrong.resource_epoch = 2;
        assert!(matches!(
            CodexCommandJournal::open(&completed_files, Path::new(PATH), wrong),
            Err(PodError::Conflict(_))
        ));

        for (interrupted, expected) in [
            (false, CodexJournalStage::BootstrapFailed),
            (true, CodexJournalStage::BootstrapInterrupted),
        ] {
            let files = MemoryFiles::new();
            let mut journal =
                CodexCommandJournal::open(&files, Path::new(PATH), identity()).unwrap();
            journal.begin_thread_create(KEY, &digest).unwrap();
            journal
                .checkpoint_thread_created(KEY, &digest, "thread.terminal", "session.terminal")
                .unwrap();
            journal
                .begin_bootstrap_intent(KEY, &digest, "message.terminal")
                .unwrap();
            journal
                .record_bootstrap_submitted(KEY, &digest, "turn.terminal")
                .unwrap();
            assert!(matches!(
                journal.record_bootstrap_failed(KEY, &digest, "turn.other"),
                Err(PodError::Conflict(_))
            ));
            if interrupted {
                journal
                    .record_bootstrap_interrupted(KEY, &digest, "turn.terminal")
                    .unwrap();
            } else {
                journal
                    .record_bootstrap_failed(KEY, &digest, "turn.terminal")
                    .unwrap();
            }
            drop(journal);
            let mut reopened =
                CodexCommandJournal::open(&files, Path::new(PATH), identity()).unwrap();
            assert_eq!(reopened.view().stage, expected);
            assert!(matches!(
                reopened.record_bootstrap_completed(KEY, &digest, "turn.terminal"),
                Err(PodError::Conflict(_))
            ));
        }
    }

    #[test]
    fn explicit_uncertain_and_torn_append_never_replay_as_success() {
        let files = MemoryFiles::new();
        let digest = "d".repeat(64);
        let mut journal = CodexCommandJournal::open(&files, Path::new(PATH), identity()).unwrap();
        journal.begin_thread_create(KEY, &digest).unwrap();
        journal
            .checkpoint_thread_created(KEY, &digest, "thread.one", "session.one")
            .unwrap();
        journal
            .begin_bootstrap_intent(KEY, &digest, "message.one")
            .unwrap();
        journal.record_bootstrap_uncertain(KEY, &digest).unwrap();
        drop(journal);
        let mut reopened = CodexCommandJournal::open(&files, Path::new(PATH), identity()).unwrap();
        assert_eq!(reopened.view().stage, CodexJournalStage::BootstrapUncertain);
        assert!(matches!(
            reopened.record_bootstrap_submitted(KEY, &digest, "turn.one"),
            Err(PodError::Conflict(_))
        ));

        let torn = MemoryFiles::new();
        let mut journal = CodexCommandJournal::open(&torn, Path::new(PATH), identity()).unwrap();
        journal.begin_thread_create(KEY, &digest).unwrap();
        torn.state.lock().unwrap().partial_next = true;
        assert!(matches!(
            journal.checkpoint_thread_created(KEY, &digest, "thread.one", "session.one"),
            Err(PodError::Uncertain(_))
        ));
        assert_eq!(journal.view().stage, CodexJournalStage::StorageUncertain);
        assert!(matches!(
            journal.begin_thread_create(KEY, &digest),
            Err(PodError::Uncertain(_))
        ));
        drop(journal);
        assert!(matches!(
            CodexCommandJournal::open(&torn, Path::new(PATH), identity()),
            Err(PodError::Uncertain(_))
        ));
    }

    #[test]
    fn checksum_and_unrecognized_transition_refuse_reopen() {
        let digest = "e".repeat(64);
        let corrupt = MemoryFiles::new();
        let mut journal = CodexCommandJournal::open(&corrupt, Path::new(PATH), identity()).unwrap();
        journal.begin_thread_create(KEY, &digest).unwrap();
        drop(journal);
        *corrupt.state.lock().unwrap().bytes.last_mut().unwrap() ^= 1;
        assert!(matches!(
            CodexCommandJournal::open(&corrupt, Path::new(PATH), identity()),
            Err(PodError::Uncertain(_))
        ));

        let invalid = MemoryFiles::new();
        let mut journal = CodexCommandJournal::open(&invalid, Path::new(PATH), identity()).unwrap();
        journal.begin_thread_create(KEY, &digest).unwrap();
        drop(journal);
        let invalid_record = JournalRecord {
            version: 1,
            sequence: 2,
            identity: identity(),
            command_key: KEY.into(),
            payload_digest: digest,
            event: JournalEvent::BootstrapSubmitted {
                native_turn_id: "turn.unexpected".into(),
            },
        };
        invalid
            .state
            .lock()
            .unwrap()
            .bytes
            .extend(encode_frame(&invalid_record).unwrap());
        assert!(matches!(
            CodexCommandJournal::open(&invalid, Path::new(PATH), identity()),
            Err(PodError::Conflict(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_held_port_reopens_the_same_checkpointed_thread() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "podbay-codex-journal-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("native.commands");
        let digest = "f".repeat(64);
        let mut journal =
            CodexCommandJournal::open(&crate::runtime::LinuxBackend, &path, identity()).unwrap();
        let file_identity = journal.file_identity().clone();
        journal.begin_thread_create(KEY, &digest).unwrap();
        journal
            .checkpoint_thread_created(KEY, &digest, "thread.linux", "session.linux")
            .unwrap();
        drop(journal);
        let reopened =
            CodexCommandJournal::open(&crate::runtime::LinuxBackend, &path, identity()).unwrap();
        assert_eq!(reopened.file_identity(), &file_identity);
        assert_eq!(reopened.view().stage, CodexJournalStage::ThreadCreated);
        assert_eq!(
            reopened.view().native_thread_id.as_deref(),
            Some("thread.linux")
        );
        drop(reopened);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
