//! Later-turn controller. Its claimed-command trait is sealed; production
//! construction requires an exact claimed v22 store record.

use podbay_adapter_codex::{
    BlockReason, BootstrapReadPoll, CodexError, CodexResource, JsonlTransport,
    LaterTurnCompletionObservation, LaterTurnTerminalStatus, TurnSubmissionStage, WriterPermit,
};
use podbay_core::Epoch;
use podbay_store::{EffectState, LaterCodexSendRecord};

use crate::codex_journal::{CodexCommandJournal, CodexJournalIdentity, CodexJournalStage};
use crate::codex_turn_journal::{
    CodexLaterTurnJournal, LaterTurnIntentResult, LaterTurnStage, LaterTurnTerminal, LaterTurnView,
};
use crate::manifest::PodError;

mod sealed {
    pub trait Sealed {}
}

trait ClaimedLaterTurn: sealed::Sealed {
    fn journal_identity(&self) -> &CodexJournalIdentity;
    fn resource_identity(&self) -> &podbay_adapter_codex::ResourceIdentity;
    fn writer_epoch(&self) -> u64;
    fn command_key(&self) -> &str;
    fn request_digest(&self) -> &str;
    fn client_message_id(&self) -> &str;
    fn text(&self) -> &str;
}

struct StoreClaimedLaterTurn<'a> {
    record: &'a LaterCodexSendRecord,
    journal_identity: CodexJournalIdentity,
    resource_identity: podbay_adapter_codex::ResourceIdentity,
}

impl sealed::Sealed for StoreClaimedLaterTurn<'_> {}

impl ClaimedLaterTurn for StoreClaimedLaterTurn<'_> {
    fn journal_identity(&self) -> &CodexJournalIdentity { &self.journal_identity }
    fn resource_identity(&self) -> &podbay_adapter_codex::ResourceIdentity { &self.resource_identity }
    fn writer_epoch(&self) -> u64 { self.record.writer_epoch() }
    fn command_key(&self) -> &str { &self.record.receipt().command_id }
    fn request_digest(&self) -> &str { &self.record.receipt().request_digest }
    fn client_message_id(&self) -> &str { &self.record.receipt().command_id }
    fn text(&self) -> &str { self.record.prompt_text() }
}

/// Only a freshly inspected, claimed store record can cross this production
/// seam. The caller rechecks OS manager, store, lease and child inside `recheck`.
pub(crate) fn submit_store_claimed<T: JsonlTransport>(
    resource: &mut CodexResource<T>,
    bootstrap: &mut CodexCommandJournal,
    later: &mut CodexLaterTurnJournal,
    record: &LaterCodexSendRecord,
    recheck: &mut impl FnMut(&mut CodexResource<T>) -> Result<(), PodError>,
) -> Result<LaterTurnView, PodError> {
    if record.effect_state() != EffectState::ClaimedUncertain {
        return Err(PodError::Refused("later turn has no claimed store effect"));
    }
    let target = record.native_target();
    let bootstrap_view = bootstrap.view();
    if bootstrap_view.native_thread_id.as_deref() != Some(record.native_thread_id()) {
        return Err(PodError::Refused("later turn store thread differs from bootstrap journal"));
    }
    let pod_epoch = Epoch::new(target.pod_incarnation)
        .map_err(|_| PodError::Invalid("later turn Pod incarnation"))?;
    let resource_epoch = Epoch::new(target.resource_epoch)
        .map_err(|_| PodError::Invalid("later turn Resource epoch"))?;
    let proof = StoreClaimedLaterTurn {
        record,
        journal_identity: CodexJournalIdentity::from_resource(
            &target.store_lineage, &target.scope_id, &target.session_id, &target.run_id,
            &target.attempt_id, &target.pod_id, pod_epoch, &target.resource_id, resource_epoch,
        ),
        resource_identity: podbay_adapter_codex::ResourceIdentity {
            session_id: target.session_id.clone(), run_id: target.run_id.clone(),
            attempt_id: target.attempt_id.clone(), pod_id: target.pod_id.clone(),
            resource_id: target.resource_id.clone(), resource_epoch,
        },
    };
    submit_claimed(resource, bootstrap, later, &proof, recheck)
}

fn current_anchor<T: JsonlTransport>(
    resource: &CodexResource<T>,
    bootstrap: &mut CodexCommandJournal,
    later: &mut CodexLaterTurnJournal,
    expected: &CodexJournalIdentity,
) -> Result<(), PodError> {
    if !bootstrap.matches_identity(expected) || !later.matches_identity(expected) {
        return Err(PodError::Refused("later-turn Resource differs"));
    }
    bootstrap.recheck_held_file()?;
    later.recheck_held_file()?;
    let anchor = bootstrap.view();
    if anchor.stage != CodexJournalStage::BootstrapCompleted {
        return Err(PodError::Refused("bootstrap completion is not fsynced"));
    }
    let native = resource
        .native_thread()
        .ok_or(PodError::Refused("later-turn native thread is absent"))?;
    if anchor.native_thread_id.as_deref() != Some(native.thread_id.as_str())
        || anchor.native_session_id.as_deref() != Some(native.session_id.as_str())
    {
        return Err(PodError::Refused("later-turn native anchor differs"));
    }
    Ok(())
}

fn uncertain_view(
    later: &mut CodexLaterTurnJournal,
    key: &str,
    digest: &str,
) -> Result<LaterTurnView, PodError> {
    later
        .record_submission_uncertain(key, digest)
        .map_err(|_| PodError::Uncertain("later-turn native outcome lacks durable receipt"))
}

/// Fsync one intent and attempt at most one native `turn/start`. `recheck`
/// is the current OS child and writer-lease boundary. A store record alone
/// never authenticates the connected manager or authorizes native input.
fn submit_claimed<T: JsonlTransport, P: ClaimedLaterTurn>(
    resource: &mut CodexResource<T>,
    bootstrap: &mut CodexCommandJournal,
    later: &mut CodexLaterTurnJournal,
    proof: &P,
    recheck: &mut impl FnMut(&mut CodexResource<T>) -> Result<(), PodError>,
) -> Result<LaterTurnView, PodError> {
    if resource.identity() != proof.resource_identity() {
        return Err(PodError::Refused("later-turn pod Resource differs"));
    }
    current_anchor(resource, bootstrap, later, proof.journal_identity())?;
    let key = proof.command_key();
    let digest = proof.request_digest();
    let view =
        match later.begin_turn(key, digest, proof.client_message_id(), proof.writer_epoch())? {
            LaterTurnIntentResult::Duplicate(view) => return Ok(view),
            LaterTurnIntentResult::NewlyDurable(view) => view,
        };
    if recheck(resource).is_err()
        || current_anchor(resource, bootstrap, later, proof.journal_identity()).is_err()
    {
        return uncertain_view(later, key, digest);
    }
    let epoch = match Epoch::new(proof.writer_epoch()) {
        Ok(epoch) => epoch,
        Err(_) => return uncertain_view(later, key, digest),
    };
    if resource
        .install_writer_epoch_from_trusted_boundary(epoch)
        .is_err()
    {
        return uncertain_view(later, key, digest);
    }
    let permit = WriterPermit::from_trusted_boundary(resource.identity().clone(), epoch);
    let submission = resource.send_turn_after_checkpoint_checked(
        &permit,
        &view.native_thread_id,
        &view.native_session_id,
        proof.text(),
        proof.client_message_id(),
        |native| {
            current_anchor(native, bootstrap, later, proof.journal_identity())
                .map_err(|_| CodexError::Blocked(BlockReason::ObservationUnknown))?;
            recheck(native).map_err(|_| CodexError::Blocked(BlockReason::ObservationUnknown))
        },
    );
    match submission {
        Ok(receipt) => match receipt.stage {
            TurnSubmissionStage::Accepted { turn_id } => later
                .record_submitted(key, digest, &turn_id)
                .or_else(|_| uncertain_view(later, key, digest)),
            TurnSubmissionStage::Uncertain => uncertain_view(later, key, digest),
        },
        Err(_) => uncertain_view(later, key, digest),
    }
}

fn terminal(status: LaterTurnTerminalStatus) -> LaterTurnTerminal {
    match status {
        LaterTurnTerminalStatus::Completed => LaterTurnTerminal::Completed,
        LaterTurnTerminalStatus::Failed => LaterTurnTerminal::Failed,
        LaterTurnTerminalStatus::Interrupted => LaterTurnTerminal::Interrupted,
    }
}

fn matches_active(view: &LaterTurnView, observed: &LaterTurnCompletionObservation) -> bool {
    view.native_thread_id == observed.native_thread_id
        && view.native_session_id == observed.native_session_id
        && view.native_turn_id.as_deref() == Some(observed.native_turn_id.as_str())
}

/// One nonblocking native step, then durable private observation and journal
/// advancement. The outer socket loop can answer status between these calls.
pub(crate) fn poll_once<T: JsonlTransport>(
    resource: &mut CodexResource<T>,
    bootstrap: &mut CodexCommandJournal,
    later: &mut CodexLaterTurnJournal,
    journal_identity: &CodexJournalIdentity,
    recheck: &mut impl FnMut(&mut CodexResource<T>) -> Result<(), PodError>,
    flush_native: &mut impl FnMut(&mut CodexResource<T>) -> Result<(), PodError>,
) -> Result<bool, PodError> {
    let view = later.active_view();
    if let Some(view) = view.as_ref()
        && let LaterTurnStage::CompletionObservedPendingIdleProof(expected_status) = view.stage
    {
        let observed =
            resource
                .last_later_turn_completion()
                .cloned()
                .ok_or(PodError::Uncertain(
                    "later-turn completion observation disappeared",
                ))?;
        if !matches_active(view, &observed) || terminal(observed.status) != expected_status {
            return Err(PodError::Uncertain("later-turn completion target changed"));
        }
        let progress = resource
            .poll_later_turn_read_proof_once(&observed)
            .map_err(|_| PodError::Uncertain("later-turn idle read outcome unknown"))?;
        flush_native(resource)?;
        return match progress {
            BootstrapReadPoll::Pending => Ok(false),
            BootstrapReadPoll::Advanced => Ok(true),
            BootstrapReadPoll::Verified => {
                recheck(resource)?;
                current_anchor(resource, bootstrap, later, journal_identity)?;
                if resource
                    .poll_later_turn_read_proof_once(&observed)
                    .map_err(|_| PodError::Uncertain("later-turn idle proof changed"))?
                    != BootstrapReadPoll::Verified
                {
                    return Ok(false);
                }
                flush_native(resource)?;
                later.record_terminal_after_fresh_idle(
                    &view.command_key,
                    &view.payload_digest,
                    &observed.native_turn_id,
                    expected_status,
                )?;
                Ok(true)
            }
        };
    }
    let consumed = resource
        .poll_available_once()
        .map_err(|_| PodError::Uncertain("later-turn native notification outcome unknown"))?;
    flush_native(resource)?;
    if let Some(view) = view
        && view.stage == LaterTurnStage::Submitted
        && let Some(observed) = resource.last_later_turn_completion().cloned()
        && matches_active(&view, &observed)
        && !resource.turn_control_state().external_conflict
    {
        recheck(resource)?;
        current_anchor(resource, bootstrap, later, journal_identity)?;
        later.record_completion_observed(
            &view.command_key,
            &view.payload_digest,
            &observed.native_turn_id,
            terminal(observed.status),
        )?;
        return Ok(true);
    }
    Ok(consumed)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::io::{self, Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use podbay_adapter_codex::{
        ApprovalPolicy, AvailableLine, AvailableWrite, NativeObservationKind,
        NativeObservationStatus, PinnedCodexConfig, ResourceIdentity, Sandbox, decode, encode,
    };
    use podbay_core::{AttemptId, PodId, ResourceId, RunId, ScopeId, SessionId, StoreLineageId};
    use serde_json::{Value, json};

    use super::*;
    use crate::linux_peer::LinuxPeerEvidence;
    use crate::native_events::{NativeEventIdentity, NativeEventKind, NativeEventSpool, NativeEventStatus};
    use crate::runtime::LinuxBackend;

    #[derive(Default)]
    struct FakeState {
        reads: VecDeque<Vec<u8>>,
        writes: Vec<Value>,
    }
    #[derive(Clone)]
    struct FakeTransport(Arc<Mutex<FakeState>>);
    impl JsonlTransport for FakeTransport {
        fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
            self.0.lock().unwrap().writes.push(decode(line).unwrap());
            Ok(())
        }
        fn read_line(&mut self) -> io::Result<Option<Vec<u8>>> {
            Ok(self.0.lock().unwrap().reads.pop_front())
        }
        fn try_write_line(&mut self, line: &[u8]) -> io::Result<AvailableWrite> {
            self.write_line(line)?;
            Ok(AvailableWrite::Written)
        }
        fn try_read_line(&mut self) -> io::Result<AvailableLine> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .reads
                .pop_front()
                .map_or(AvailableLine::Pending, AvailableLine::Frame))
        }
    }

    fn resource_identity() -> ResourceIdentity {
        ResourceIdentity {
            session_id: SessionId::try_from("session.fixture").unwrap(),
            run_id: RunId::try_from("run.fixture").unwrap(),
            attempt_id: AttemptId::try_from("attempt.fixture").unwrap(),
            pod_id: PodId::try_from("pod.fixture").unwrap(),
            resource_id: ResourceId::try_from("resource.fixture").unwrap(),
            resource_epoch: Epoch::new(1).unwrap(),
        }
    }
    fn journal_identity() -> CodexJournalIdentity {
        let native = resource_identity();
        CodexJournalIdentity::from_resource(
            &StoreLineageId::try_from("lineage.fixture").unwrap(),
            &ScopeId::try_from("scope.fixture").unwrap(),
            &native.session_id,
            &native.run_id,
            &native.attempt_id,
            &native.pod_id,
            Epoch::new(1).unwrap(),
            &native.resource_id,
            native.resource_epoch,
        )
    }
    fn event_identity() -> NativeEventIdentity {
        let native = resource_identity();
        NativeEventIdentity::from_resource(
            &StoreLineageId::try_from("lineage.fixture").unwrap(),
            &ScopeId::try_from("scope.fixture").unwrap(),
            &native.session_id,
            &native.run_id,
            &native.attempt_id,
            &native.pod_id,
            Epoch::new(1).unwrap(),
            &native.resource_id,
            native.resource_epoch,
        )
    }
    fn native_thread(status: &str, cwd: &Path) -> Value {
        json!({"id":"thread.fixture","sessionId":"native.session.fixture","cwd":cwd,
            "model":"gpt-6-sol","reasoningEffort":"medium",
            "status":{"type":status},"turns":[]})
    }
    fn read(id: u64, status: &str, cwd: &Path) -> Value {
        json!({"id":id,"result":{"thread":native_thread(status,cwd)}})
    }
    fn completed(turn: &str) -> Value {
        json!({"method":"turn/completed","params":{"threadId":"thread.fixture",
            "turn":{"id":turn,"status":"completed","items":[]}}})
    }
    fn idle() -> Value {
        json!({"method":"thread/status/changed","params":{
            "threadId":"thread.fixture","status":{"type":"idle"}}})
    }
    fn response(id: u64, turn: &str) -> Value {
        json!({"id":id,"result":{"turn":{"id":turn,"status":"inProgress","items":[]}}})
    }

    struct FixtureClaim {
        journal: CodexJournalIdentity,
        resource: ResourceIdentity,
        key: String,
        digest: String,
        message: String,
        text: String,
        writer_epoch: u64,
    }
    impl sealed::Sealed for FixtureClaim {}
    impl ClaimedLaterTurn for FixtureClaim {
        fn journal_identity(&self) -> &CodexJournalIdentity {
            &self.journal
        }
        fn resource_identity(&self) -> &ResourceIdentity {
            &self.resource
        }
        fn writer_epoch(&self) -> u64 {
            self.writer_epoch
        }
        fn command_key(&self) -> &str {
            &self.key
        }
        fn request_digest(&self) -> &str {
            &self.digest
        }
        fn client_message_id(&self) -> &str {
            &self.message
        }
        fn text(&self) -> &str {
            &self.text
        }
    }
    fn claim(number: u8) -> FixtureClaim {
        FixtureClaim {
            journal: journal_identity(),
            resource: resource_identity(),
            key: format!("command.later.{number}"),
            digest: format!("{number:064x}"),
            message: format!("message.later.{number}"),
            text: format!("fixture turn {number}"),
            writer_epoch: 1,
        }
    }

    struct Fixture {
        root: PathBuf,
        cwd: PathBuf,
        state: Arc<Mutex<FakeState>>,
        resource: CodexResource<FakeTransport>,
        bootstrap: CodexCommandJournal,
        later: CodexLaterTurnJournal,
        events: NativeEventSpool,
        owner: LinuxPeerEvidence,
        guard_child: Child,
        guard_birth: (u32, u64, String, String),
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.guard_child.kill();
            let _ = self.guard_child.wait();
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    fn child_birth(pid: u32) -> Result<(u32, u64, String, String), PodError> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let (_, fields) = stat
            .rsplit_once(") ")
            .ok_or(PodError::Refused("fixture child stat is malformed"))?;
        let ticks = fields
            .split_whitespace()
            .nth(19)
            .ok_or(PodError::Refused("fixture child birth is absent"))?
            .parse()
            .map_err(|_| PodError::Refused("fixture child birth is invalid"))?;
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
        Ok((pid, ticks, boot, cgroup))
    }
    fn recheck_child(
        child: &mut Child,
        expected: &(u32, u64, String, String),
    ) -> Result<(), PodError> {
        if child.try_wait()?.is_some() || child_birth(child.id())? != *expected {
            return Err(PodError::Refused(
                "fixture direct child birth or containment changed",
            ));
        }
        Ok(())
    }
    impl Fixture {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "podbay-later-controller-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let cwd = root.join("workspace");
            fs::create_dir(&cwd).unwrap();
            let state = Arc::new(Mutex::new(FakeState::default()));
            let transport = FakeTransport(state.clone());
            let config = PinnedCodexConfig::new(
                "gpt-6-sol",
                "medium",
                cwd.clone(),
                ApprovalPolicy::Never,
                Sandbox::DangerFullAccess,
            )
            .unwrap();
            let mut resource = CodexResource::new(transport, resource_identity(), config);
            let mut bootstrap = CodexCommandJournal::open(
                &LinuxBackend,
                &root.join("codex.commands.log"),
                journal_identity(),
            )
            .unwrap();
            Self::queue_into(
                &state,
                json!({"id":1,"result":{
                "codexHome":root.join("home"),"platformFamily":"unix",
                "platformOs":"linux","userAgent":"podbay/fixture"}}),
            );
            resource.initialize().unwrap();
            let key = "command.bootstrap";
            let digest = "a".repeat(64);
            bootstrap.begin_thread_create(key, &digest).unwrap();
            Self::queue_into(
                &state,
                json!({"id":2,"result":{
                "thread":native_thread("idle",&cwd),"cwd":cwd,
                "model":"gpt-6-sol","reasoningEffort":"medium",
                "approvalPolicy":"never","sandbox":{"type":"dangerFullAccess"}}}),
            );
            let thread = resource.start_thread_without_turn().unwrap();
            bootstrap
                .checkpoint_thread_created(key, &digest, &thread.thread_id, &thread.session_id)
                .unwrap();
            bootstrap
                .begin_bootstrap_intent(key, &digest, "message.bootstrap")
                .unwrap();
            resource
                .install_writer_epoch_from_trusted_boundary(Epoch::new(1).unwrap())
                .unwrap();
            Self::queue_into(&state, read(3, "idle", &cwd));
            Self::queue_into(&state, response(4, "turn.bootstrap"));
            let permit =
                WriterPermit::from_trusted_boundary(resource_identity(), Epoch::new(1).unwrap());
            let submitted = resource
                .submit_bootstrap_after_checkpoint(
                    &permit,
                    &thread.thread_id,
                    &thread.session_id,
                    "bootstrap fixture",
                    "message.bootstrap",
                )
                .unwrap();
            let turn_id = match submitted.stage {
                podbay_adapter_codex::BootstrapTurnStage::Submitted { turn_id } => turn_id,
                _ => panic!("fixture bootstrap did not submit"),
            };
            bootstrap
                .record_bootstrap_submitted(key, &digest, &turn_id)
                .unwrap();
            Self::queue_into(&state, completed("turn.bootstrap"));
            Self::queue_into(&state, idle());
            resource.poll_available_once().unwrap();
            resource.poll_available_once().unwrap();
            bootstrap
                .record_bootstrap_completion_observed(key, &digest, &turn_id)
                .unwrap();
            Self::queue_into(&state, read(5, "idle", &cwd));
            loop {
                if resource
                    .poll_bootstrap_read_proof_once(&thread.thread_id, &thread.session_id, &turn_id)
                    .unwrap()
                    == BootstrapReadPoll::Verified
                {
                    break;
                }
            }
            bootstrap
                .record_bootstrap_completed(key, &digest, &turn_id)
                .unwrap();
            let later = CodexLaterTurnJournal::open_after_completed_bootstrap(
                &LinuxBackend,
                &root.join("codex.turns.log"),
                journal_identity(),
                &mut bootstrap,
            )
            .unwrap();
            let events = NativeEventSpool::open(
                &LinuxBackend, &root.join("codex.native-events.log"), event_identity(),
            ).unwrap();
            let owner = LinuxPeerEvidence::for_current_process().unwrap();
            let guard_child = Command::new("/usr/bin/sleep")
                .arg("40")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let guard_birth = child_birth(guard_child.id()).unwrap();
            assert!(
                guard_birth
                    .3
                    .lines()
                    .any(|line| line.ends_with(owner.cgroup()))
            );
            Self {
                root,
                cwd,
                state,
                resource,
                bootstrap,
                later,
                events,
                owner,
                guard_child,
                guard_birth,
            }
        }
        fn queue_into(state: &Arc<Mutex<FakeState>>, value: Value) {
            state
                .lock()
                .unwrap()
                .reads
                .push_back(encode(&value).unwrap());
        }
        fn queue(&self, value: Value) {
            Self::queue_into(&self.state, value);
        }
        fn turn_starts(&self) -> usize {
            self.state
                .lock()
                .unwrap()
                .writes
                .iter()
                .filter(|value| value.get("method").and_then(Value::as_str) == Some("turn/start"))
                .count()
        }
        fn read_requests(&self) -> usize {
            self.state
                .lock()
                .unwrap()
                .writes
                .iter()
                .filter(|value| value.get("method").and_then(Value::as_str) == Some("thread/read"))
                .count()
        }
        fn submit(&mut self, claim: &FixtureClaim, alive: bool) -> Result<LaterTurnView, PodError> {
            let resource_id = resource_identity();
            let owner = self.owner.clone();
            let child = &mut self.guard_child;
            let birth = self.guard_birth.clone();
            submit_claimed(
                &mut self.resource,
                &mut self.bootstrap,
                &mut self.later,
                claim,
                &mut |resource| {
                    if !alive
                        || resource.identity() != &resource_id
                        || LinuxPeerEvidence::for_current_process().ok().as_ref() != Some(&owner)
                        || resource.turn_control_state().writer_epoch
                            != Some(Epoch::new(1).unwrap())
                    {
                        return Err(PodError::Refused("fixture child or writer fence changed"));
                    }
                    recheck_child(child, &birth)
                },
            )
        }
        fn tick(&mut self) -> Result<bool, PodError> {
            let events = &mut self.events;
            let owner = self.owner.clone();
            let child = &mut self.guard_child;
            let birth = self.guard_birth.clone();
            poll_once(
                &mut self.resource,
                &mut self.bootstrap,
                &mut self.later,
                &journal_identity(),
                &mut |resource| {
                    if resource.identity() != &resource_identity()
                        || LinuxPeerEvidence::for_current_process().ok().as_ref() != Some(&owner)
                        || resource.turn_control_state().writer_epoch
                            != Some(Epoch::new(1).unwrap())
                    {
                        return Err(PodError::Refused("fixture writer fence changed"));
                    }
                    recheck_child(child, &birth)
                },
                &mut |resource| {
                    while resource.has_unspooled_native_notifications() {
                        let sequence = events.next_source_sequence()?;
                        let observed = resource.take_applied_native_notification().ok_or(
                            PodError::Uncertain(
                                "fixture native frame disappeared after reservation",
                            ),
                        )?;
                        let kind = match observed.kind() {
                            NativeObservationKind::Status => NativeEventKind::Status,
                            NativeObservationKind::Output => NativeEventKind::Output,
                            NativeObservationKind::Question => NativeEventKind::Question,
                            NativeObservationKind::Permission => NativeEventKind::Permission,
                            NativeObservationKind::Opaque => NativeEventKind::Opaque,
                        };
                        let status = observed.status().map(|value| match value {
                            NativeObservationStatus::Idle => NativeEventStatus::Idle,
                            NativeObservationStatus::Active => NativeEventStatus::Active,
                            NativeObservationStatus::Waiting => NativeEventStatus::Waiting,
                            NativeObservationStatus::Completed => NativeEventStatus::Completed,
                            NativeObservationStatus::Failed => NativeEventStatus::Failed,
                            NativeObservationStatus::Interrupted => NativeEventStatus::Interrupted,
                            NativeObservationStatus::SystemError => NativeEventStatus::SystemError,
                        });
                        events.append_applied(
                            sequence,
                            observed.private_jsonl(),
                            kind,
                            status,
                            observed.external_conflict(),
                        )?;
                    }
                    Ok(())
                },
            )
        }
        fn settle(&mut self, key: &str) {
            for _ in 0..20 {
                if self.later.view(key).is_some_and(|view| {
                    view.stage == LaterTurnStage::Settled(LaterTurnTerminal::Completed)
                }) {
                    return;
                }
                self.tick().unwrap();
            }
            panic!("later turn did not settle");
        }
    }

    #[test]
    fn two_later_turns_duplicate_and_lost_reply_are_durable_without_resend() {
        let mut fixture = Fixture::new();
        let first = claim(1);
        fixture.queue(read(6, "idle", &fixture.cwd));
        fixture.queue(response(7, "turn.one"));
        assert_eq!(
            fixture.submit(&first, true).unwrap().stage,
            LaterTurnStage::Submitted
        );
        fixture.queue(completed("turn.one"));
        fixture.queue(idle());
        fixture.queue(read(8, "idle", &fixture.cwd));
        fixture.settle(&first.key);
        assert_eq!(fixture.turn_starts(), 2);
        assert_eq!(
            fixture.submit(&first, false).unwrap().stage,
            LaterTurnStage::Settled(LaterTurnTerminal::Completed)
        );
        assert_eq!(fixture.turn_starts(), 2);
        let second = claim(2);
        fixture.queue(read(9, "idle", &fixture.cwd));
        fixture.queue(response(10, "turn.two"));
        assert_eq!(
            fixture.submit(&second, true).unwrap().stage,
            LaterTurnStage::Submitted
        );
        fixture.queue(completed("turn.two"));
        fixture.queue(idle());
        fixture.queue(read(11, "idle", &fixture.cwd));
        fixture.settle(&second.key);
        assert_eq!(fixture.turn_starts(), 3);
        let lost = claim(3);
        fixture.queue(read(12, "idle", &fixture.cwd));
        assert_eq!(
            fixture.submit(&lost, true).unwrap().stage,
            LaterTurnStage::SubmissionUncertain
        );
        assert_eq!(
            fixture.submit(&lost, false).unwrap().stage,
            LaterTurnStage::SubmissionUncertain
        );
        assert_eq!(fixture.turn_starts(), 4);
        assert!(
            fixture
                .later
                .begin_turn("command.later.4", &"d".repeat(64), "message.later.4", 1)
                .is_err()
        );
        assert!(
            fixture
                .events
                .read_after(None, 16)
                .unwrap()
                .snapshot
                .watermark
                >= 4
        );
        let reopened_events = NativeEventSpool::open(
            &LinuxBackend, &fixture.root.join("codex.native-events.log"), event_identity(),
        ).unwrap();
        assert_eq!(
            reopened_events
                .read_after(None, 16)
                .unwrap()
                .snapshot
                .watermark,
            fixture
                .events
                .read_after(None, 16)
                .unwrap()
                .snapshot
                .watermark
        );
        let reopened_journal = CodexLaterTurnJournal::open_after_completed_bootstrap(
            &LinuxBackend,
            &fixture.root.join("codex.turns.log"),
            journal_identity(),
            &mut fixture.bootstrap,
        )
        .unwrap();
        assert_eq!(
            reopened_journal.view(&first.key).unwrap().stage,
            LaterTurnStage::Settled(LaterTurnTerminal::Completed)
        );
        assert_eq!(
            reopened_journal.view(&second.key).unwrap().stage,
            LaterTurnStage::Settled(LaterTurnTerminal::Completed)
        );
        assert_eq!(
            reopened_journal.view(&lost.key).unwrap().stage,
            LaterTurnStage::SubmissionUncertain
        );
    }

    #[test]
    fn fixture_child_or_writer_drift_refuses_before_native_turn_start() {
        let mut fixture = Fixture::new();
        let mut foreign = claim(1);
        foreign.resource.resource_id = ResourceId::try_from("resource.other").unwrap();
        assert!(matches!(
            fixture.submit(&foreign, true),
            Err(PodError::Refused(_))
        ));
        assert!(fixture.later.view("command.later.1").is_none());
        assert_eq!(fixture.turn_starts(), 1);
        let first = claim(1);
        assert_eq!(
            fixture.submit(&first, false).unwrap().stage,
            LaterTurnStage::SubmissionUncertain
        );
        assert_eq!(fixture.turn_starts(), 1);
        assert_eq!(
            fixture.submit(&first, true).unwrap().stage,
            LaterTurnStage::SubmissionUncertain
        );
        assert_eq!(fixture.turn_starts(), 1);

        let mut second_fixture = Fixture::new();
        let mut stale_writer = claim(2);
        stale_writer.writer_epoch = 2;
        second_fixture.queue(read(6, "idle", &second_fixture.cwd));
        assert_eq!(
            second_fixture.submit(&stale_writer, true).unwrap().stage,
            LaterTurnStage::SubmissionUncertain
        );
        assert_eq!(second_fixture.turn_starts(), 1);
        let mut dead_child = Fixture::new();
        dead_child.guard_child.kill().unwrap();
        dead_child.guard_child.wait().unwrap();
        assert_eq!(
            dead_child.submit(&claim(1), true).unwrap().stage,
            LaterTurnStage::SubmissionUncertain
        );
        assert_eq!(dead_child.turn_starts(), 1);
    }

    fn fixture_status(fixture: &Fixture) -> Value {
        let stage = |key: &str| {
            fixture
                .later
                .view(key)
                .map(|view| format!("{:?}", view.stage))
        };
        json!({
            "one": stage("command.later.1"),
            "two": stage("command.later.2"),
            "lost": stage("command.later.3"),
            "turnStarts": fixture.turn_starts(),
            "readRequests": fixture.read_requests(),
        })
    }

    /// The helper is a separate disposable test-harness process, never the
    /// normal pod binary. Its socket protocol is fixture-only and cannot be
    /// reached from a production V2/V3 manifest or `PodClient`.
    #[test]
    #[ignore = "disposable user-systemd fake later-turn fixture helper"]
    fn systemd_fixture_helper() {
        if std::env::var_os("PODBAY_LATER_FIXTURE_CHILD").is_none() {
            return;
        }
        let socket = PathBuf::from(std::env::var_os("PODBAY_LATER_FIXTURE_SOCKET").unwrap());
        let unit = std::env::var("PODBAY_LATER_FIXTURE_UNIT").unwrap();
        let peer = LinuxPeerEvidence::for_current_process().unwrap();
        assert_eq!(peer.cgroup().rsplit('/').next(), Some(unit.as_str()));
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut fixture = Fixture::new();
        let mut native_pump_available = true;
        let deadline = Instant::now() + Duration::from_secs(40);
        loop {
            assert!(Instant::now() < deadline, "fixture control timed out");
            if native_pump_available && fixture.tick().is_err() {
                native_pump_available = false;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut operation = String::new();
                    stream.read_to_string(&mut operation).unwrap();
                    let result = match operation.as_str() {
                        "first" => {
                            fixture.queue(read(6, "idle", &fixture.cwd));
                            fixture.queue(response(7, "turn.one"));
                            fixture.submit(&claim(1), true).unwrap();
                            fixture.queue(completed("turn.one"));
                            fixture.queue(idle());
                            fixture_status(&fixture)
                        }
                        "release_first" => {
                            fixture.queue(read(8, "idle", &fixture.cwd));
                            fixture_status(&fixture)
                        }
                        "duplicate_first" => {
                            fixture.submit(&claim(1), false).unwrap();
                            fixture_status(&fixture)
                        }
                        "second" => {
                            fixture.queue(read(9, "idle", &fixture.cwd));
                            fixture.queue(response(10, "turn.two"));
                            fixture.submit(&claim(2), true).unwrap();
                            fixture.queue(completed("turn.two"));
                            fixture.queue(idle());
                            fixture_status(&fixture)
                        }
                        "release_second" => {
                            fixture.queue(read(11, "idle", &fixture.cwd));
                            fixture_status(&fixture)
                        }
                        "lost" => {
                            fixture.queue(read(12, "idle", &fixture.cwd));
                            fixture.submit(&claim(3), true).unwrap();
                            fixture_status(&fixture)
                        }
                        "duplicate_lost" => {
                            fixture.submit(&claim(3), false).unwrap();
                            fixture_status(&fixture)
                        }
                        "status" | "stop" => fixture_status(&fixture),
                        _ => panic!("unknown fixture operation"),
                    };
                    stream
                        .write_all(serde_json::to_vec(&result).unwrap().as_slice())
                        .unwrap();
                    if operation == "stop" {
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("fixture socket accept failed: {error}"),
            }
        }
    }

    struct UnitGuard {
        unit: String,
        root: PathBuf,
    }
    impl Drop for UnitGuard {
        fn drop(&mut self) {
            let _ = Command::new("systemctl")
                .args(["--user", "stop", &self.unit])
                .output();
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    fn fixture_request(socket: &Path, operation: &str) -> Value {
        let mut stream = UnixStream::connect(socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(operation.as_bytes()).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut result = Vec::new();
        stream.read_to_end(&mut result).unwrap();
        serde_json::from_slice(&result).unwrap()
    }
    fn wait_stage(socket: &Path, field: &str, stage: &str) {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let status = fixture_request(socket, "status");
            if status[field].as_str() == Some(stage) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "fixture {field} did not reach {stage}: {status}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    #[ignore = "requires disposable user systemd; fake app-server only"]
    fn disposable_systemd_later_turns_keep_fixture_control_responsive() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "podbay-later-systemd-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.join("control.sock");
        let unit = format!("podbay-later-fixture-{nonce:x}.service");
        let guard = UnitGuard {
            unit: unit.clone(),
            root,
        };
        let exe = std::env::current_exe().unwrap();
        let output = Command::new("systemd-run")
            .args([
                "--user",
                "--collect",
                "--property=KillMode=control-group",
                "--property=NoNewPrivileges=yes",
                "--property=RuntimeMaxSec=45",
            ])
            .arg(format!("--unit={unit}"))
            .arg("--setenv=PODBAY_LATER_FIXTURE_CHILD=1")
            .arg(format!(
                "--setenv=PODBAY_LATER_FIXTURE_SOCKET={}",
                socket.display()
            ))
            .arg(format!("--setenv=PODBAY_LATER_FIXTURE_UNIT={unit}"))
            .arg(exe)
            .args([
                "--ignored",
                "--exact",
                "codex_later_turn::tests::systemd_fixture_helper",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "systemd-run: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let deadline = Instant::now() + Duration::from_secs(8);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "fixture socket did not appear");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(fixture_request(&socket, "first")["turnStarts"], 2);
        wait_stage(
            &socket,
            "one",
            "CompletionObservedPendingIdleProof(Completed)",
        );
        let read_deadline = Instant::now() + Duration::from_secs(3);
        while fixture_request(&socket, "status")["readRequests"]
            .as_u64()
            .unwrap()
            < 4
        {
            assert!(
                Instant::now() < read_deadline,
                "later idle probe was not written"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        for _ in 0..3 {
            let start = Instant::now();
            assert_eq!(fixture_request(&socket, "status")["turnStarts"], 2);
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "control blocked by native thread/read"
            );
        }
        fixture_request(&socket, "release_first");
        wait_stage(&socket, "one", "Settled(Completed)");
        assert_eq!(fixture_request(&socket, "duplicate_first")["turnStarts"], 2);
        assert_eq!(fixture_request(&socket, "second")["turnStarts"], 3);
        wait_stage(
            &socket,
            "two",
            "CompletionObservedPendingIdleProof(Completed)",
        );
        fixture_request(&socket, "release_second");
        wait_stage(&socket, "two", "Settled(Completed)");
        assert_eq!(
            fixture_request(&socket, "lost")["lost"],
            "SubmissionUncertain"
        );
        assert_eq!(fixture_request(&socket, "duplicate_lost")["turnStarts"], 4);
        fixture_request(&socket, "stop");
        drop(guard);
    }
}
