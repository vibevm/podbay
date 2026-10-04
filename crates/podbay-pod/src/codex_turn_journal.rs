//! Portable pod-local later-turn facts. This journal never calls a provider or
//! authenticates a writer; the future claimed-command bridge must prove exact
//! manager, writer lease, child and native state before each native effect.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::codex_journal::{CodexCommandJournal, CodexJournalIdentity, CodexJournalStage};
use crate::manifest::PodError;
use crate::ports::{DurableAppendLog, DurableFileIdentity, DurableFiles};

const FRAME_DOMAIN: &[u8] = b"podbay.codex-later-turn-frame/1\0";
const MAX_LOG_BYTES: u64 = 16 * 1_048_576;
const MAX_FRAME_BYTES: usize = 16_384;
const MAX_RECORDS: u64 = 65_536;
const HEADER_BYTES: usize = 4 + 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaterTurnTerminal {
    Completed,
    Failed,
    Interrupted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LaterTurnStage {
    IntentDurable,
    IntentUnknownAfterReopen,
    SubmissionUncertain,
    Submitted,
    CompletionObservedPendingIdleProof(LaterTurnTerminal),
    Settled(LaterTurnTerminal),
    StorageUncertain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaterTurnView {
    pub command_key: String,
    pub payload_digest: String,
    pub client_message_id: String,
    pub writer_epoch: u64,
    pub native_thread_id: String,
    pub native_session_id: String,
    pub native_turn_id: Option<String>,
    pub stage: LaterTurnStage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LaterTurnIntentResult {
    NewlyDurable(LaterTurnView),
    Duplicate(LaterTurnView),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    native_thread_id: String,
    native_session_id: String,
    bootstrap_turn_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    Anchor(Anchor),
    Intent {
        key: String,
        digest: String,
        client_message_id: String,
        writer_epoch: u64,
    },
    SubmissionUncertain {
        key: String,
        digest: String,
    },
    Submitted {
        key: String,
        digest: String,
        native_turn_id: String,
    },
    CompletionObserved {
        key: String,
        digest: String,
        native_turn_id: String,
        terminal: LaterTurnTerminal,
    },
    IdleVerified {
        key: String,
        digest: String,
        native_turn_id: String,
        terminal: LaterTurnTerminal,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    sequence: u64,
    identity: CodexJournalIdentity,
    event: Event,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Intent,
    SubmissionUncertain,
    Submitted,
    CompletionObserved(LaterTurnTerminal),
    Settled(LaterTurnTerminal),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CommandFact {
    digest: String,
    client_message_id: String,
    writer_epoch: u64,
    native_turn_id: Option<String>,
    phase: Phase,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Snapshot {
    anchor: Option<Anchor>,
    commands: BTreeMap<String, CommandFact>,
    active: Option<String>,
    last_writer_epoch: u64,
}

pub struct CodexLaterTurnJournal {
    log: Box<dyn DurableAppendLog>,
    identity: CodexJournalIdentity,
    snapshot: Snapshot,
    records: u64,
    fresh_intent: Option<String>,
    poisoned: bool,
}

impl CodexLaterTurnJournal {
    /// The bootstrap journal is rechecked as a held file. No caller-built
    /// native thread selector can initialise a later-turn log.
    pub fn open_after_completed_bootstrap(
        files: &impl DurableFiles,
        path: &Path,
        identity: CodexJournalIdentity,
        bootstrap: &mut CodexCommandJournal,
    ) -> Result<Self, PodError> {
        identity.validate()?;
        if !bootstrap.matches_identity(&identity) {
            return Err(PodError::Refused(
                "later-turn Resource differs from bootstrap",
            ));
        }
        bootstrap.recheck_held_file()?;
        let view = bootstrap.view();
        if view.stage != CodexJournalStage::BootstrapCompleted {
            return Err(PodError::Refused("bootstrap has no fsynced completion"));
        }
        let anchor = Anchor {
            native_thread_id: view
                .native_thread_id
                .ok_or(PodError::Uncertain("bootstrap thread ID absent"))?,
            native_session_id: view
                .native_session_id
                .ok_or(PodError::Uncertain("bootstrap native Session ID absent"))?,
            bootstrap_turn_id: view
                .native_turn_id
                .ok_or(PodError::Uncertain("bootstrap turn ID absent"))?,
        };
        validate_native_id(&anchor.native_thread_id)?;
        validate_native_id(&anchor.native_session_id)?;
        validate_native_id(&anchor.bootstrap_turn_id)?;
        let mut log = files.open_private_append_log(path, MAX_LOG_BYTES)?;
        let raw = log.read_all_bounded()?;
        let (snapshot, records) = replay(&raw, &identity)?;
        let mut journal = Self {
            log,
            identity,
            snapshot,
            records,
            fresh_intent: None,
            poisoned: false,
        };
        if journal.records == 0 {
            journal.append(Event::Anchor(anchor))?;
        } else if journal.snapshot.anchor.as_ref() != Some(&anchor) {
            return Err(PodError::Conflict("later-turn native anchor changed"));
        }
        Ok(journal)
    }

    pub fn file_identity(&self) -> &DurableFileIdentity {
        self.log.identity()
    }

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
            return Err(PodError::Uncertain(
                "later-turn journal changed outside owner",
            ));
        }
        Ok(())
    }

    pub fn view(&self, key: &str) -> Option<LaterTurnView> {
        let anchor = self.snapshot.anchor.as_ref()?;
        let fact = self.snapshot.commands.get(key)?;
        let stage = if self.poisoned {
            LaterTurnStage::StorageUncertain
        } else {
            match fact.phase {
                Phase::Intent if self.fresh_intent.as_deref() == Some(key) => {
                    LaterTurnStage::IntentDurable
                }
                Phase::Intent => LaterTurnStage::IntentUnknownAfterReopen,
                Phase::SubmissionUncertain => LaterTurnStage::SubmissionUncertain,
                Phase::Submitted => LaterTurnStage::Submitted,
                Phase::CompletionObserved(terminal) => {
                    LaterTurnStage::CompletionObservedPendingIdleProof(terminal)
                }
                Phase::Settled(terminal) => LaterTurnStage::Settled(terminal),
            }
        };
        Some(LaterTurnView {
            command_key: key.into(),
            payload_digest: fact.digest.clone(),
            client_message_id: fact.client_message_id.clone(),
            writer_epoch: fact.writer_epoch,
            native_thread_id: anchor.native_thread_id.clone(),
            native_session_id: anchor.native_session_id.clone(),
            native_turn_id: fact.native_turn_id.clone(),
            stage,
        })
    }

    pub fn begin_turn(
        &mut self,
        key: &str,
        digest: &str,
        client_message_id: &str,
        writer_epoch: u64,
    ) -> Result<LaterTurnIntentResult, PodError> {
        self.healthy()?;
        validate_command(key, digest, client_message_id, writer_epoch)?;
        if let Some(existing) = self.snapshot.commands.get(key) {
            if existing.digest != digest || existing.client_message_id != client_message_id {
                return Err(PodError::Conflict("later-turn same key changed payload"));
            }
            return Ok(LaterTurnIntentResult::Duplicate(
                self.view(key).expect("existing command"),
            ));
        }
        if self.snapshot.active.is_some() {
            return Err(PodError::Refused("prior later turn is not settled"));
        }
        if self
            .snapshot
            .commands
            .values()
            .any(|fact| fact.client_message_id == client_message_id)
        {
            return Err(PodError::Conflict(
                "later-turn native message ID was reused",
            ));
        }
        self.append(Event::Intent {
            key: key.into(),
            digest: digest.into(),
            client_message_id: client_message_id.into(),
            writer_epoch,
        })?;
        self.fresh_intent = Some(key.into());
        Ok(LaterTurnIntentResult::NewlyDurable(
            self.view(key).expect("new command"),
        ))
    }

    /// A lost native reply is terminally uncertain for this command; another
    /// turn cannot be admitted or the same command resent from this journal.
    pub fn record_submission_uncertain(
        &mut self,
        key: &str,
        digest: &str,
    ) -> Result<LaterTurnView, PodError> {
        self.same_command(key, digest)?;
        if self.snapshot.commands[key].phase == Phase::Intent
            && self.fresh_intent.as_deref() == Some(key)
        {
            self.append(Event::SubmissionUncertain {
                key: key.into(),
                digest: digest.into(),
            })?;
            self.fresh_intent = None;
        } else if self.snapshot.commands[key].phase != Phase::SubmissionUncertain {
            return Err(PodError::Uncertain(
                "later-turn intent has no trustworthy native receipt",
            ));
        }
        Ok(self.view(key).expect("known command"))
    }

    pub fn record_submitted(
        &mut self,
        key: &str,
        digest: &str,
        native_turn_id: &str,
    ) -> Result<LaterTurnView, PodError> {
        self.same_command(key, digest)?;
        validate_native_id(native_turn_id)?;
        if self.snapshot.commands[key].phase == Phase::Intent
            && self.fresh_intent.as_deref() == Some(key)
        {
            self.append(Event::Submitted {
                key: key.into(),
                digest: digest.into(),
                native_turn_id: native_turn_id.into(),
            })?;
            self.fresh_intent = None;
        } else if self.snapshot.commands[key].native_turn_id.as_deref() != Some(native_turn_id)
            || !matches!(
                self.snapshot.commands[key].phase,
                Phase::Submitted | Phase::CompletionObserved(_) | Phase::Settled(_)
            )
        {
            return Err(PodError::Conflict("later-turn native receipt changed"));
        }
        Ok(self.view(key).expect("known command"))
    }

    /// Caller must have observed a matching state-applied turn/completed.
    /// This is a provider report, not proof of idle or PodBay Run settlement.
    #[allow(dead_code)] // The future authenticated pod bridge supplies this native observation.
    pub(crate) fn record_completion_observed(
        &mut self,
        key: &str,
        digest: &str,
        native_turn_id: &str,
        terminal: LaterTurnTerminal,
    ) -> Result<LaterTurnView, PodError> {
        self.same_command(key, digest)?;
        if self.snapshot.commands[key].native_turn_id.as_deref() != Some(native_turn_id) {
            return Err(PodError::Conflict("later-turn completion turn differs"));
        }
        if self.snapshot.commands[key].phase == Phase::Submitted {
            self.append(Event::CompletionObserved {
                key: key.into(),
                digest: digest.into(),
                native_turn_id: native_turn_id.into(),
                terminal,
            })?;
        } else if self.snapshot.commands[key].phase != Phase::CompletionObserved(terminal)
            && self.snapshot.commands[key].phase != Phase::Settled(terminal)
        {
            return Err(PodError::Conflict("later-turn completion status changed"));
        }
        Ok(self.view(key).expect("known command"))
    }

    /// Caller must have a fresh idle/no-waiting/no-pending-request native
    /// read for this exact observed turn. The journal does no native RPC.
    #[allow(dead_code)] // The future nonblocking idle-proof bridge supplies this transition.
    pub(crate) fn record_terminal_after_fresh_idle(
        &mut self,
        key: &str,
        digest: &str,
        native_turn_id: &str,
        terminal: LaterTurnTerminal,
    ) -> Result<LaterTurnView, PodError> {
        self.same_command(key, digest)?;
        if self.snapshot.commands[key].native_turn_id.as_deref() != Some(native_turn_id) {
            return Err(PodError::Conflict("later-turn idle proof turn differs"));
        }
        if self.snapshot.commands[key].phase == Phase::CompletionObserved(terminal) {
            self.append(Event::IdleVerified {
                key: key.into(),
                digest: digest.into(),
                native_turn_id: native_turn_id.into(),
                terminal,
            })?;
        } else if self.snapshot.commands[key].phase != Phase::Settled(terminal) {
            return Err(PodError::Conflict(
                "later-turn idle proof transition refused",
            ));
        }
        Ok(self.view(key).expect("known command"))
    }

    fn same_command(&self, key: &str, digest: &str) -> Result<(), PodError> {
        self.healthy()?;
        let fact = self
            .snapshot
            .commands
            .get(key)
            .ok_or(PodError::Refused("later-turn command absent"))?;
        if fact.digest != digest {
            return Err(PodError::Conflict("later-turn command digest changed"));
        }
        Ok(())
    }

    fn healthy(&self) -> Result<(), PodError> {
        if self.poisoned {
            Err(PodError::Uncertain(
                "later-turn journal storage outcome unknown",
            ))
        } else {
            Ok(())
        }
    }

    fn append(&mut self, event: Event) -> Result<(), PodError> {
        self.healthy()?;
        let sequence = self
            .records
            .checked_add(1)
            .filter(|value| *value <= MAX_RECORDS)
            .ok_or(PodError::Refused("later-turn journal record bound"))?;
        let record = Record {
            version: 1,
            sequence,
            identity: self.identity.clone(),
            event,
        };
        let mut next = self.snapshot.clone();
        apply_record(&record, &self.identity, sequence, &mut next)?;
        let frame = encode_frame(&record)?;
        if self.log.len().saturating_add(frame.len() as u64) > MAX_LOG_BYTES {
            return Err(PodError::Refused("later-turn journal byte bound"));
        }
        if self.log.append_synced(&frame).is_err() {
            self.poisoned = true;
            return Err(PodError::Uncertain(
                "later-turn journal append or sync unknown",
            ));
        }
        self.snapshot = next;
        self.records = sequence;
        Ok(())
    }
}

fn validate_native_id(value: &str) -> Result<(), PodError> {
    if value.is_empty()
        || value.len() > 512
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(PodError::Invalid("later-turn native identity"))
    } else {
        Ok(())
    }
}

fn validate_command(key: &str, digest: &str, message: &str, epoch: u64) -> Result<(), PodError> {
    if !(3..=160).contains(&key.len())
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || message.is_empty()
        || message.len() > 256
        || message.trim() != message
        || message.chars().any(char::is_control)
        || epoch == 0
    {
        Err(PodError::Invalid(
            "later-turn command identity or writer epoch",
        ))
    } else {
        Ok(())
    }
}

fn apply_record(
    record: &Record,
    identity: &CodexJournalIdentity,
    expected: u64,
    state: &mut Snapshot,
) -> Result<(), PodError> {
    if record.version != 1 || record.sequence != expected || record.identity != *identity {
        return Err(PodError::Conflict(
            "later-turn journal version or Resource changed",
        ));
    }
    match &record.event {
        Event::Anchor(anchor) if expected == 1 && state.anchor.is_none() => {
            validate_native_id(&anchor.native_thread_id)?;
            validate_native_id(&anchor.native_session_id)?;
            validate_native_id(&anchor.bootstrap_turn_id)?;
            state.anchor = Some(anchor.clone());
        }
        Event::Intent {
            key,
            digest,
            client_message_id,
            writer_epoch,
        } => {
            if state.anchor.is_none()
                || state.active.is_some()
                || state.commands.contains_key(key)
                || *writer_epoch < state.last_writer_epoch
                || state
                    .commands
                    .values()
                    .any(|fact| fact.client_message_id == *client_message_id)
            {
                return Err(PodError::Conflict(
                    "later-turn intent overlaps or reuses identity",
                ));
            }
            validate_command(key, digest, client_message_id, *writer_epoch)?;
            state.commands.insert(
                key.clone(),
                CommandFact {
                    digest: digest.clone(),
                    client_message_id: client_message_id.clone(),
                    writer_epoch: *writer_epoch,
                    native_turn_id: None,
                    phase: Phase::Intent,
                },
            );
            state.active = Some(key.clone());
            state.last_writer_epoch = *writer_epoch;
        }
        Event::SubmissionUncertain { key, digest } => {
            let fact = matching_active(state, key, digest)?;
            if fact.phase != Phase::Intent {
                return Err(PodError::Conflict("later-turn uncertainty transition"));
            }
            fact.phase = Phase::SubmissionUncertain;
        }
        Event::Submitted {
            key,
            digest,
            native_turn_id,
        } => {
            validate_native_id(native_turn_id)?;
            if state
                .anchor
                .as_ref()
                .is_some_and(|anchor| anchor.bootstrap_turn_id == *native_turn_id)
                || state
                    .commands
                    .values()
                    .any(|fact| fact.native_turn_id.as_deref() == Some(native_turn_id))
            {
                return Err(PodError::Conflict("native turn ID reused across commands"));
            }
            let fact = matching_active(state, key, digest)?;
            if fact.phase != Phase::Intent {
                return Err(PodError::Conflict("later-turn submitted transition"));
            }
            fact.native_turn_id = Some(native_turn_id.clone());
            fact.phase = Phase::Submitted;
        }
        Event::CompletionObserved {
            key,
            digest,
            native_turn_id,
            terminal,
        } => {
            let fact = matching_active(state, key, digest)?;
            if fact.phase != Phase::Submitted
                || fact.native_turn_id.as_deref() != Some(native_turn_id)
            {
                return Err(PodError::Conflict(
                    "later-turn completion observation transition",
                ));
            }
            fact.phase = Phase::CompletionObserved(*terminal);
        }
        Event::IdleVerified {
            key,
            digest,
            native_turn_id,
            terminal,
        } => {
            let fact = matching_active(state, key, digest)?;
            if fact.phase != Phase::CompletionObserved(*terminal)
                || fact.native_turn_id.as_deref() != Some(native_turn_id)
            {
                return Err(PodError::Conflict("later-turn fresh idle transition"));
            }
            fact.phase = Phase::Settled(*terminal);
            state.active = None;
        }
        _ => return Err(PodError::Conflict("later-turn journal transition refused")),
    }
    Ok(())
}

fn matching_active<'a>(
    state: &'a mut Snapshot,
    key: &str,
    digest: &str,
) -> Result<&'a mut CommandFact, PodError> {
    if state.active.as_deref() != Some(key) {
        return Err(PodError::Conflict("later-turn active command differs"));
    }
    let fact = state
        .commands
        .get_mut(key)
        .ok_or(PodError::Conflict("later-turn active command absent"))?;
    if fact.digest != digest {
        return Err(PodError::Conflict("later-turn active digest differs"));
    }
    Ok(fact)
}

fn encode_frame(record: &Record) -> Result<Vec<u8>, PodError> {
    let payload = serde_json::to_vec(record)?;
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(PodError::Invalid("later-turn journal frame bound"));
    }
    let mut checksum = Sha256::new();
    checksum.update(FRAME_DOMAIN);
    checksum.update(&payload);
    let mut frame = Vec::with_capacity(HEADER_BYTES + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes().as_slice());
    frame.extend_from_slice(&checksum.finalize());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn replay(raw: &[u8], identity: &CodexJournalIdentity) -> Result<(Snapshot, u64), PodError> {
    if raw.len() as u64 > MAX_LOG_BYTES {
        return Err(PodError::Refused("later-turn journal byte bound"));
    }
    let mut state = Snapshot::default();
    let mut sequence = 0u64;
    let mut at = 0usize;
    while at < raw.len() {
        if raw.len() - at < HEADER_BYTES {
            return Err(PodError::Uncertain("later-turn journal tail is torn"));
        }
        let len = u32::from_be_bytes(raw[at..at + 4].try_into().expect("four bytes")) as usize;
        if len == 0 || len > MAX_FRAME_BYTES {
            return Err(PodError::Uncertain("later-turn frame length differs"));
        }
        let end = at
            .checked_add(HEADER_BYTES)
            .and_then(|value| value.checked_add(len))
            .ok_or(PodError::Uncertain("later-turn frame length overflow"))?;
        if end > raw.len() {
            return Err(PodError::Uncertain("later-turn journal tail is torn"));
        }
        let payload = &raw[at + HEADER_BYTES..end];
        let mut checksum = Sha256::new();
        checksum.update(FRAME_DOMAIN);
        checksum.update(payload);
        if checksum.finalize().as_slice() != &raw[at + 4..at + HEADER_BYTES] {
            return Err(PodError::Uncertain("later-turn journal checksum differs"));
        }
        let record: Record = serde_json::from_slice(payload)
            .map_err(|_| PodError::Uncertain("later-turn journal frame is malformed"))?;
        if serde_json::to_vec(&record)? != payload {
            return Err(PodError::Uncertain(
                "later-turn journal frame is not canonical",
            ));
        }
        sequence = sequence
            .checked_add(1)
            .filter(|value| *value <= MAX_RECORDS)
            .ok_or(PodError::Refused("later-turn journal record bound"))?;
        apply_record(&record, identity, sequence, &mut state)?;
        at = end;
    }
    Ok((state, sequence))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use podbay_core::{
        AttemptId, Epoch, PodId, ResourceId, RunId, ScopeId, SessionId, StoreLineageId,
    };

    use super::*;

    #[derive(Default)]
    struct State {
        files: BTreeMap<PathBuf, Vec<u8>>,
        partial_next: Option<PathBuf>,
        writes: usize,
    }
    #[derive(Clone, Default)]
    struct FakeFiles(Arc<Mutex<State>>);
    struct FakeLog {
        state: Arc<Mutex<State>>,
        path: PathBuf,
        identity: DurableFileIdentity,
        max: u64,
    }

    impl DurableAppendLog for FakeLog {
        fn identity(&self) -> &DurableFileIdentity {
            &self.identity
        }
        fn len(&self) -> u64 {
            self.state.lock().unwrap().files[&self.path].len() as u64
        }
        fn read_all_bounded(&mut self) -> Result<Vec<u8>, PodError> {
            let bytes = self.state.lock().unwrap().files[&self.path].clone();
            if bytes.len() as u64 > self.max {
                return Err(PodError::Refused("fake log bound"));
            }
            Ok(bytes)
        }
        fn append_synced(&mut self, bytes: &[u8]) -> Result<(), PodError> {
            let mut state = self.state.lock().unwrap();
            state.writes += 1;
            let partial = state.partial_next.as_ref() == Some(&self.path);
            if partial {
                state.partial_next = None;
            }
            let file = state.files.get_mut(&self.path).unwrap();
            if file.len() as u64 + bytes.len() as u64 > self.max {
                return Err(PodError::Refused("fake log bound"));
            }
            file.extend_from_slice(if partial {
                &bytes[..bytes.len().div_ceil(2)]
            } else {
                bytes
            });
            if partial {
                Err(PodError::Uncertain("fake partial append"))
            } else {
                Ok(())
            }
        }
    }
    impl DurableFiles for FakeFiles {
        fn create_private(&self, _: &Path, _: &[u8]) -> Result<(), PodError> {
            Err(PodError::Unsupported("fake legacy operation"))
        }
        fn append_durable(&self, _: &Path, _: &[u8]) -> Result<(), PodError> {
            Err(PodError::Unsupported("fake legacy operation"))
        }
        fn replace_durable(&self, _: &Path, _: &[u8]) -> Result<(), PodError> {
            Err(PodError::Unsupported("fake legacy operation"))
        }
        fn open_private_append_log(
            &self,
            path: &Path,
            max: u64,
        ) -> Result<Box<dyn DurableAppendLog>, PodError> {
            self.0.lock().unwrap().files.entry(path.into()).or_default();
            let identity = DurableFileIdentity::from_backend(
                "fake/1",
                path.display().to_string().into_bytes(),
            )
            .unwrap();
            Ok(Box::new(FakeLog {
                state: self.0.clone(),
                path: path.into(),
                identity,
                max,
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

    fn completed_bootstrap(files: &FakeFiles, path: &Path) -> CodexCommandJournal {
        let mut journal = CodexCommandJournal::open(files, path, identity()).unwrap();
        let key = "command.bootstrap";
        let digest = "a".repeat(64);
        journal.begin_thread_create(key, &digest).unwrap();
        journal
            .checkpoint_thread_created(key, &digest, "thread.fixture", "native.session.fixture")
            .unwrap();
        journal
            .begin_bootstrap_intent(key, &digest, "message.bootstrap")
            .unwrap();
        journal
            .record_bootstrap_submitted(key, &digest, "turn.bootstrap")
            .unwrap();
        journal
            .record_bootstrap_completion_observed(key, &digest, "turn.bootstrap")
            .unwrap();
        journal
            .record_bootstrap_completed(key, &digest, "turn.bootstrap")
            .unwrap();
        journal
    }

    #[test]
    fn two_sequential_turns_reopen_and_old_key_replay_never_adds_intent() {
        let files = FakeFiles::default();
        let mut bootstrap = completed_bootstrap(&files, Path::new("/bootstrap"));
        let mut journal = CodexLaterTurnJournal::open_after_completed_bootstrap(
            &files,
            Path::new("/later"),
            identity(),
            &mut bootstrap,
        )
        .unwrap();
        let first = "b".repeat(64);
        let second = "c".repeat(64);
        assert!(matches!(
            journal
                .begin_turn("command.one", &first, "message.one", 1)
                .unwrap(),
            LaterTurnIntentResult::NewlyDurable(_)
        ));
        journal
            .record_submitted("command.one", &first, "turn.one")
            .unwrap();
        journal
            .record_completion_observed(
                "command.one",
                &first,
                "turn.one",
                LaterTurnTerminal::Completed,
            )
            .unwrap();
        assert_eq!(
            journal.view("command.one").unwrap().stage,
            LaterTurnStage::CompletionObservedPendingIdleProof(LaterTurnTerminal::Completed)
        );
        assert!(
            journal
                .begin_turn("command.two", &second, "message.two", 1)
                .is_err()
        );
        journal
            .record_terminal_after_fresh_idle(
                "command.one",
                &first,
                "turn.one",
                LaterTurnTerminal::Completed,
            )
            .unwrap();
        assert!(matches!(
            journal
                .begin_turn("command.two", &second, "message.two", 1)
                .unwrap(),
            LaterTurnIntentResult::NewlyDurable(_)
        ));
        journal
            .record_submitted("command.two", &second, "turn.two")
            .unwrap();
        journal
            .record_completion_observed(
                "command.two",
                &second,
                "turn.two",
                LaterTurnTerminal::Completed,
            )
            .unwrap();
        journal
            .record_terminal_after_fresh_idle(
                "command.two",
                &second,
                "turn.two",
                LaterTurnTerminal::Completed,
            )
            .unwrap();
        let before = files.0.lock().unwrap().writes;
        assert!(
            matches!(journal.begin_turn("command.one", &first, "message.one", 2).unwrap(), LaterTurnIntentResult::Duplicate(view)
            if view.stage == LaterTurnStage::Settled(LaterTurnTerminal::Completed) && view.writer_epoch == 1)
        );
        assert_eq!(files.0.lock().unwrap().writes, before);
        assert!(matches!(
            journal.begin_turn("command.one", &second, "message.one", 2),
            Err(PodError::Conflict(_))
        ));
        drop(journal);
        let reopened = CodexLaterTurnJournal::open_after_completed_bootstrap(
            &files,
            Path::new("/later"),
            identity(),
            &mut bootstrap,
        )
        .unwrap();
        assert_eq!(
            reopened
                .view("command.one")
                .unwrap()
                .native_turn_id
                .as_deref(),
            Some("turn.one")
        );
        assert_eq!(
            reopened
                .view("command.two")
                .unwrap()
                .native_turn_id
                .as_deref(),
            Some("turn.two")
        );
        assert_eq!(
            reopened.view("command.two").unwrap().stage,
            LaterTurnStage::Settled(LaterTurnTerminal::Completed)
        );
    }

    #[test]
    fn lost_reply_or_crash_after_intent_never_allows_a_second_turn() {
        let files = FakeFiles::default();
        let mut bootstrap = completed_bootstrap(&files, Path::new("/bootstrap"));
        let digest = "b".repeat(64);
        let mut journal = CodexLaterTurnJournal::open_after_completed_bootstrap(
            &files,
            Path::new("/later"),
            identity(),
            &mut bootstrap,
        )
        .unwrap();
        journal
            .begin_turn("command.one", &digest, "message.one", 1)
            .unwrap();
        drop(journal);
        let mut reopened = CodexLaterTurnJournal::open_after_completed_bootstrap(
            &files,
            Path::new("/later"),
            identity(),
            &mut bootstrap,
        )
        .unwrap();
        assert_eq!(
            reopened.view("command.one").unwrap().stage,
            LaterTurnStage::IntentUnknownAfterReopen
        );
        assert!(matches!(
            reopened
                .begin_turn("command.one", &digest, "message.one", 1)
                .unwrap(),
            LaterTurnIntentResult::Duplicate(_)
        ));
        assert!(
            reopened
                .record_submitted("command.one", &digest, "turn.one")
                .is_err()
        );
        assert!(
            reopened
                .begin_turn("command.two", &"c".repeat(64), "message.two", 1)
                .is_err()
        );
        drop(reopened);
        let mut bootstrap_two = completed_bootstrap(&files, Path::new("/bootstrap.two"));
        let mut second = CodexLaterTurnJournal::open_after_completed_bootstrap(
            &files,
            Path::new("/later.two"),
            identity(),
            &mut bootstrap_two,
        )
        .unwrap();
        second
            .begin_turn("command.one", &digest, "message.one", 1)
            .unwrap();
        second
            .record_submission_uncertain("command.one", &digest)
            .unwrap();
        assert_eq!(
            second.view("command.one").unwrap().stage,
            LaterTurnStage::SubmissionUncertain
        );
        assert!(
            second
                .begin_turn("command.two", &"c".repeat(64), "message.two", 1)
                .is_err()
        );
    }

    #[test]
    fn partial_append_refuses_reopen_and_storage_is_not_an_absent_command() {
        let files = FakeFiles::default();
        let mut bootstrap = completed_bootstrap(&files, Path::new("/bootstrap"));
        let mut journal = CodexLaterTurnJournal::open_after_completed_bootstrap(
            &files,
            Path::new("/later"),
            identity(),
            &mut bootstrap,
        )
        .unwrap();
        files.0.lock().unwrap().partial_next = Some(PathBuf::from("/later"));
        assert!(matches!(
            journal.begin_turn("command.one", &"b".repeat(64), "message.one", 1),
            Err(PodError::Uncertain(_))
        ));
        assert!(matches!(
            journal.begin_turn("command.two", &"c".repeat(64), "message.two", 1),
            Err(PodError::Uncertain(_))
        ));
        assert!(matches!(
            CodexLaterTurnJournal::open_after_completed_bootstrap(
                &files,
                Path::new("/later"),
                identity(),
                &mut bootstrap,
            ),
            Err(PodError::Uncertain(_))
        ));
    }

    #[test]
    fn incomplete_bootstrap_and_reused_native_turn_id_refuse() {
        let files = FakeFiles::default();
        let mut bootstrap =
            CodexCommandJournal::open(&files, Path::new("/bootstrap"), identity()).unwrap();
        assert!(matches!(
            CodexLaterTurnJournal::open_after_completed_bootstrap(
                &files,
                Path::new("/later"),
                identity(),
                &mut bootstrap,
            ),
            Err(PodError::Refused(_))
        ));
        drop(bootstrap);
        let mut bootstrap = completed_bootstrap(&files, Path::new("/bootstrap.complete"));
        let mut journal = CodexLaterTurnJournal::open_after_completed_bootstrap(
            &files,
            Path::new("/later"),
            identity(),
            &mut bootstrap,
        )
        .unwrap();
        let digest = "b".repeat(64);
        journal
            .begin_turn("command.one", &digest, "message.one", 1)
            .unwrap();
        assert!(matches!(
            journal.record_submitted("command.one", &digest, "turn.bootstrap"),
            Err(PodError::Conflict(_))
        ));
        assert_eq!(
            journal.view("command.one").unwrap().stage,
            LaterTurnStage::IntentDurable
        );
    }

    #[test]
    fn later_intent_cannot_regress_writer_epoch() {
        let files = FakeFiles::default();
        let mut bootstrap = completed_bootstrap(&files, Path::new("/bootstrap"));
        let mut journal = CodexLaterTurnJournal::open_after_completed_bootstrap(
            &files,
            Path::new("/later"),
            identity(),
            &mut bootstrap,
        )
        .unwrap();
        let first = "b".repeat(64);
        journal
            .begin_turn("command.one", &first, "message.one", 2)
            .unwrap();
        journal
            .record_submitted("command.one", &first, "turn.one")
            .unwrap();
        journal
            .record_completion_observed(
                "command.one",
                &first,
                "turn.one",
                LaterTurnTerminal::Completed,
            )
            .unwrap();
        journal
            .record_terminal_after_fresh_idle(
                "command.one",
                &first,
                "turn.one",
                LaterTurnTerminal::Completed,
            )
            .unwrap();
        assert!(matches!(
            journal.begin_turn("command.two", &"c".repeat(64), "message.two", 1),
            Err(PodError::Conflict(_))
        ));
        assert!(
            journal
                .begin_turn("command.two", &"c".repeat(64), "message.two", 2)
                .is_ok()
        );
    }
}
