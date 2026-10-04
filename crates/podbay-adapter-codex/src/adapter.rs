use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fmt::{Debug, Formatter};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use podbay_core::{AttemptId, Epoch, PodId, ResourceId, RunId, SessionId};
use serde_json::{Value, json};

use crate::codec::{CodecError, MAX_FRAME_BYTES, decode, encode};
use crate::host_requests::{
    NativeAnswer, NativeAnswerError, NativeRequestParseError, NativeRequestStage, NativeRpcId,
    PendingNativeRequest, answer_value, parse_pending_request,
};

const MAX_PENDING_NOTIFICATIONS: usize = 1024;
const MAX_PENDING_REQUESTS: usize = 128;
const MAX_APPLIED_NOTIFICATIONS: usize = 1024;
const MAX_APPLIED_NOTIFICATION_BYTES: usize = 4 * 1_048_576;
const COMPLETION_READ_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_ATOMIC_READ_PROBE_FRAME: usize = 512;

/// A pod-owned byte transport. Implementations must enforce
/// `MAX_FRAME_BYTES` while assembling one complete JSONL frame per read;
/// this crate supplies no process launcher or socket client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AvailableLine {
    Pending,
    IncompleteFrame,
    Frame(Vec<u8>),
    EndOfStream,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvailableWrite {
    Pending,
    Written,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeObservationKind {
    Status,
    Output,
    Question,
    Permission,
    Opaque,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeObservationStatus {
    Idle,
    Active,
    Waiting,
    Completed,
    Failed,
    Interrupted,
    SystemError,
}

/// Full native JSONL stays private to the pod-owned log. Debug and the public
/// summary omit the bytes, question text, command, path, and answer payload.
pub struct AppliedNativeNotification {
    private_jsonl: Vec<u8>,
    kind: NativeObservationKind,
    status: Option<NativeObservationStatus>,
    external_conflict: bool,
}

impl Debug for AppliedNativeNotification {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppliedNativeNotification")
            .field("private_bytes", &self.private_jsonl.len())
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("external_conflict", &self.external_conflict)
            .finish()
    }
}

impl AppliedNativeNotification {
    pub fn private_jsonl(&self) -> &[u8] {
        &self.private_jsonl
    }
    pub fn kind(&self) -> NativeObservationKind {
        self.kind
    }
    pub fn status(&self) -> Option<NativeObservationStatus> {
        self.status
    }
    pub fn external_conflict(&self) -> bool {
        self.external_conflict
    }
}

pub trait JsonlTransport {
    fn write_line(&mut self, line: &[u8]) -> io::Result<()>;
    fn read_line(&mut self) -> io::Result<Option<Vec<u8>>>;

    /// One bounded nonblocking read step for an outer control loop. Existing
    /// transports refuse until they implement this separate contract.
    fn try_read_line(&mut self) -> io::Result<AvailableLine> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "nonblocking JSONL read is unavailable",
        ))
    }

    /// One atomic, nonblocking write of a small JSONL RPC. `Pending` proves
    /// that no byte was written; partial or ambiguous writes must return an
    /// error and may never be retried by the caller.
    fn try_write_line(&mut self, _line: &[u8]) -> io::Result<AvailableWrite> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "nonblocking JSONL write is unavailable",
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceIdentity {
    pub session_id: SessionId,
    pub run_id: RunId,
    pub attempt_id: AttemptId,
    pub pod_id: PodId,
    pub resource_id: ResourceId,
    pub resource_epoch: Epoch,
}

/// An input from the trusted PodBay control boundary, not an authority token.
/// The higher layer must prove that this writer epoch is currently durable and
/// that the native process still belongs to the named pod resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriterPermit {
    identity: ResourceIdentity,
    writer_epoch: Epoch,
}

impl WriterPermit {
    pub fn from_trusted_boundary(identity: ResourceIdentity, writer_epoch: Epoch) -> Self {
        Self {
            identity,
            writer_epoch,
        }
    }
}

/// The exact answer and native request identity authorised by a higher layer.
/// Construction is a trusted-boundary contract, not a cryptographic proof.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizedAnswerPermit {
    writer: WriterPermit,
    request_id: NativeRpcId,
    native_thread_id: String,
    native_turn_id: String,
    native_item_id: String,
    resource_epoch: Epoch,
    answer: NativeAnswer,
}

impl Debug for AuthorizedAnswerPermit {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizedAnswerPermit")
            .field("request_id", &self.request_id)
            .field("native_thread_id", &self.native_thread_id)
            .field("native_turn_id", &self.native_turn_id)
            .field("native_item_id", &self.native_item_id)
            .field("resource_epoch", &self.resource_epoch)
            .field("writer_epoch", &self.writer.writer_epoch)
            .field("answer", &self.answer)
            .finish()
    }
}

impl AuthorizedAnswerPermit {
    pub fn from_authorised_boundary(
        writer: WriterPermit,
        request: &PendingNativeRequest,
        answer: NativeAnswer,
    ) -> Self {
        Self {
            writer,
            request_id: request.request_id.clone(),
            native_thread_id: request.native_thread_id.clone(),
            native_turn_id: request.native_turn_id.clone(),
            native_item_id: request.native_item_id.clone(),
            resource_epoch: request.resource_epoch,
            answer,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AnswerWriteOutcome {
    WrittenAwaitingResolution { request_id: NativeRpcId },
    Uncertain { request_id: NativeRpcId },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalPolicy {
    Untrusted,
    OnRequest,
    Never,
}

impl ApprovalPolicy {
    fn wire(self) -> &'static str {
        match self {
            Self::Untrusted => "untrusted",
            Self::OnRequest => "on-request",
            Self::Never => "never",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Sandbox {
    ReadOnly,
    WorkspaceWrite,
    DangerFullAccess,
}

impl Sandbox {
    fn request_wire(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::WorkspaceWrite => "workspace-write",
            Self::DangerFullAccess => "danger-full-access",
        }
    }

    fn response_type(self) -> &'static str {
        match self {
            Self::ReadOnly => "readOnly",
            Self::WorkspaceWrite => "workspaceWrite",
            Self::DangerFullAccess => "dangerFullAccess",
        }
    }
}

/// Must be supplied by the reviewed PodBay launch descriptor. This crate
/// checks native application of the selection but grants no authority itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedCodexConfig {
    model: String,
    effort: String,
    cwd: PathBuf,
    approval_policy: ApprovalPolicy,
    sandbox: Sandbox,
}

impl PinnedCodexConfig {
    pub fn new(
        model: impl Into<String>,
        effort: impl Into<String>,
        cwd: PathBuf,
        approval_policy: ApprovalPolicy,
        sandbox: Sandbox,
    ) -> Result<Self, CodexError> {
        let model = model.into();
        let effort = effort.into();
        if !valid_token(&model) || !valid_token(&effort) {
            return Err(CodexError::InvalidInput("model or effort is invalid"));
        }
        if !cwd.is_absolute()
            || !cwd
                .to_str()
                .is_some_and(|text| !text.is_empty() && text.len() <= 32_768)
        {
            return Err(CodexError::InvalidInput(
                "cwd must be an absolute bounded UTF-8 path",
            ));
        }
        Ok(Self {
            model,
            effort,
            cwd,
            approval_policy,
            sandbox,
        })
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub fn effort(&self) -> &str {
        &self.effort
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadStatus {
    NotLoaded,
    Idle,
    Active,
    SystemError,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeThread {
    pub thread_id: String,
    pub session_id: String,
    pub status: ThreadStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BootstrapState {
    NotStarted,
    Submitted { turn_id: String },
    Completed { turn_id: String },
    Failed { turn_id: String },
    Interrupted { turn_id: String },
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapReadPoll {
    Pending,
    Advanced,
    Verified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaterTurnTerminalStatus {
    Completed,
    Failed,
    Interrupted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaterTurnCompletionObservation {
    pub native_thread_id: String,
    pub native_session_id: String,
    pub native_turn_id: String,
    pub status: LaterTurnTerminalStatus,
}

enum CompletionReadState {
    NotStarted,
    PendingWrite {
        id: u64,
        frame: Vec<u8>,
        thread_id: String,
        session_id: String,
        turn_id: String,
        deadline: Instant,
    },
    AwaitingReply {
        id: u64,
        thread_id: String,
        session_id: String,
        turn_id: String,
        deadline: Instant,
    },
    Draining {
        thread_id: String,
        session_id: String,
        turn_id: String,
        deadline: Instant,
    },
    Verified {
        thread_id: String,
        session_id: String,
        turn_id: String,
        deadline: Instant,
    },
    Inconclusive,
    Uncertain,
}

/// Prepared in memory only. The pod must fsync its command journal Intent
/// before passing this value to `begin_nonblocking_later_turn_after_intent`.
/// Private prompt text exists only inside the bounded native frame.
pub struct PreparedNonblockingLaterTurn {
    permit: WriterPermit,
    expected_thread_id: String,
    expected_session_id: String,
    client_message_id: String,
    read_id: u64,
    read_frame: Vec<u8>,
    start_id: u64,
    start_frame: Vec<u8>,
}

impl PreparedNonblockingLaterTurn {
    /// Exact serde_json frame bytes including newline; never exposes text.
    pub fn encoded_start_frame_bytes(&self) -> usize { self.start_frame.len() }
}

enum LaterSubmissionState {
    Idle,
    ReadPendingWrite { prepared: PreparedNonblockingLaterTurn, deadline: Instant },
    ReadAwaitingReply { prepared: PreparedNonblockingLaterTurn, deadline: Instant },
    StartPendingWrite { prepared: PreparedNonblockingLaterTurn, deadline: Instant },
    StartAwaitingReply { prepared: PreparedNonblockingLaterTurn, deadline: Instant },
    Submitted,
    Uncertain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LaterTurnStartPoll {
    Pending,
    Advanced,
    Submitted { turn_id: String },
    Uncertain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartReceipt {
    pub thread: NativeThread,
    pub bootstrap_turn_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BootstrapTurnStage {
    Submitted { turn_id: String },
    Uncertain,
}

/// Native receipt only. The pod must have journaled the bootstrap intent and
/// verified durable writer authority before invoking the split operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapTurnSubmission {
    pub native_thread_id: String,
    pub native_session_id: String,
    pub client_message_id: String,
    pub stage: BootstrapTurnStage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TurnMode {
    Start,
    Steer,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TurnSubmissionStage {
    Accepted { turn_id: String },
    Uncertain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnSubmission {
    pub client_message_id: String,
    pub mode: TurnMode,
    pub stage: TurnSubmissionStage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InterruptState {
    None,
    Requested { turn_id: String },
    Settled { turn_id: String },
    EndedWithoutInterrupt { turn_id: String },
    Uncertain { turn_id: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockReason {
    MissingWriterPermit,
    StaleResourcePermit,
    StaleWriterPermit,
    BootstrapUnsettled,
    PendingHostRequest,
    NativeWaiting,
    NativeBusy,
    StaleExpectedTurn,
    ExternalWriter,
    ObservationUnknown,
    DuplicateMessageKey,
    InterruptAlreadyRequested,
    StaleNativeRequest,
    AnswerAlreadyWritten,
    UnsupportedNativeAnswer,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnControlState {
    pub native_status: ThreadStatus,
    pub observed_active_turn_id: Option<String>,
    pub owned_active_turn_id: Option<String>,
    pub pending_request_ids: Vec<String>,
    pub status_waiting: bool,
    pub external_conflict: bool,
    pub writer_epoch: Option<Epoch>,
    pub last_submission: Option<TurnSubmission>,
    pub interrupt: InterruptState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodexError {
    InvalidInput(&'static str),
    InvalidState(&'static str),
    Unsupported(&'static str),
    Protocol(&'static str),
    Codec(CodecError),
    TransportUncertain,
    RemoteError(i64),
    Mismatch(&'static str),
    Blocked(BlockReason),
}

/// Only one RPC is outstanding at a time. Notifications arriving before its
/// response are retained in wire order and applied once the turn is known.
struct QueuedNotification {
    value: Value,
    raw_jsonl: Vec<u8>,
}

pub struct CodexResource<T: JsonlTransport> {
    io: T,
    identity: ResourceIdentity,
    config: PinnedCodexConfig,
    next_id: u64,
    initialized: bool,
    poisoned: bool,
    thread: Option<NativeThread>,
    bootstrap: BootstrapState,
    pending_requests: BTreeMap<String, PendingNativeRequest>,
    retired_requests: HashSet<String>,
    native_status: ThreadStatus,
    observed_active_turn_id: Option<String>,
    owned_active_turn_id: Option<String>,
    current_writer_epoch: Option<Epoch>,
    last_submission: Option<TurnSubmission>,
    interrupt: InterruptState,
    status_waiting: bool,
    idle_after_completion: bool,
    external_conflict: bool,
    queued: VecDeque<QueuedNotification>,
    applied_notifications: VecDeque<AppliedNativeNotification>,
    applied_notification_bytes: usize,
    completion_read: CompletionReadState,
    last_later_turn_completion: Option<LaterTurnCompletionObservation>,
    later_submission: LaterSubmissionState,
}

impl<T: JsonlTransport> CodexResource<T> {
    pub fn new(io: T, identity: ResourceIdentity, config: PinnedCodexConfig) -> Self {
        Self {
            io,
            identity,
            config,
            next_id: 1,
            initialized: false,
            poisoned: false,
            thread: None,
            bootstrap: BootstrapState::NotStarted,
            pending_requests: BTreeMap::new(),
            retired_requests: HashSet::new(),
            native_status: ThreadStatus::NotLoaded,
            observed_active_turn_id: None,
            owned_active_turn_id: None,
            current_writer_epoch: None,
            last_submission: None,
            interrupt: InterruptState::None,
            status_waiting: false,
            idle_after_completion: false,
            external_conflict: false,
            queued: VecDeque::new(),
            applied_notifications: VecDeque::new(),
            applied_notification_bytes: 0,
            completion_read: CompletionReadState::NotStarted,
            last_later_turn_completion: None,
            later_submission: LaterSubmissionState::Idle,
        }
    }

    pub fn identity(&self) -> &ResourceIdentity {
        &self.identity
    }

    pub fn transport(&self) -> &T {
        &self.io
    }

    pub fn native_thread(&self) -> Option<&NativeThread> {
        self.thread.as_ref()
    }

    pub fn bootstrap_state(&self) -> &BootstrapState {
        &self.bootstrap
    }

    pub fn last_later_turn_completion(&self) -> Option<&LaterTurnCompletionObservation> {
        self.last_later_turn_completion.as_ref()
    }

    /// This settles only the bootstrap requirement. Full dispatch readiness
    /// additionally needs PodBay's authority, writer lease and fresh liveness.
    pub fn bootstrap_ready(&self) -> bool {
        matches!(self.bootstrap, BootstrapState::Completed { .. })
            && self.pending_requests.is_empty()
            && self.native_status == ThreadStatus::Idle
            && self.owned_active_turn_id.is_none()
            && self.observed_active_turn_id.is_none()
            && self.idle_after_completion
            && !self.status_waiting
            && !self.external_conflict
            && !self.poisoned
    }

    pub fn pending_request_count(&self) -> usize {
        self.pending_requests.len()
    }

    pub fn turn_control_state(&self) -> TurnControlState {
        let mut pending_request_ids: Vec<_> = self.pending_requests.keys().cloned().collect();
        pending_request_ids.sort();
        TurnControlState {
            native_status: self.native_status,
            observed_active_turn_id: self.observed_active_turn_id.clone(),
            owned_active_turn_id: self.owned_active_turn_id.clone(),
            pending_request_ids,
            status_waiting: self.status_waiting,
            external_conflict: self.external_conflict,
            writer_epoch: self.current_writer_epoch,
            last_submission: self.last_submission.clone(),
            interrupt: self.interrupt.clone(),
        }
    }

    pub fn pending_native_requests(&self) -> Vec<PendingNativeRequest> {
        self.pending_requests.values().cloned().collect()
    }

    /// Drain one state-applied native frame for the pod's private durable
    /// event source. It must be appended before a manager read can publish it.
    pub fn take_applied_native_notification(&mut self) -> Option<AppliedNativeNotification> {
        let observed = self.applied_notifications.pop_front()?;
        self.applied_notification_bytes -= observed.private_jsonl.len();
        Some(observed)
    }

    pub fn has_unspooled_native_notifications(&self) -> bool {
        !self.applied_notifications.is_empty()
    }

    /// Records a monotonically advancing fence asserted by the authenticated
    /// pod control boundary. This local snapshot does not replace the durable
    /// writer grant or its fresh validation before the native side effect.
    pub fn install_writer_epoch_from_trusted_boundary(
        &mut self,
        writer_epoch: Epoch,
    ) -> Result<(), CodexError> {
        if self
            .current_writer_epoch
            .is_some_and(|current| writer_epoch < current)
        {
            return Err(CodexError::Blocked(BlockReason::StaleWriterPermit));
        }
        self.current_writer_epoch = Some(writer_epoch);
        Ok(())
    }

    /// Writes one answer frame at most. A successful pipe write is not native
    /// settlement; only `serverRequest/resolved` followed by fresh no-waiting
    /// native status retires the pending request.
    pub fn answer_pending(
        &mut self,
        permit: AuthorizedAnswerPermit,
    ) -> Result<AnswerWriteOutcome, CodexError> {
        self.check_permit(&permit.writer)?;
        if permit.resource_epoch != self.identity.resource_epoch {
            return Err(CodexError::Blocked(BlockReason::StaleResourcePermit));
        }
        let key = permit.request_id.key();
        let request = self
            .pending_requests
            .get(&key)
            .cloned()
            .ok_or(CodexError::Blocked(BlockReason::StaleNativeRequest))?;
        if request.request_id != permit.request_id
            || request.native_thread_id != permit.native_thread_id
            || request.native_turn_id != permit.native_turn_id
            || request.native_item_id != permit.native_item_id
            || request.resource_epoch != permit.resource_epoch
        {
            return Err(CodexError::Blocked(BlockReason::StaleNativeRequest));
        }
        if request.stage != NativeRequestStage::Pending {
            return Err(CodexError::Blocked(BlockReason::AnswerAlreadyWritten));
        }
        if self.poisoned {
            return Err(CodexError::Blocked(BlockReason::ObservationUnknown));
        }
        let bootstrap_turn = match &self.bootstrap {
            BootstrapState::Submitted { turn_id } => Some(turn_id.as_str()),
            _ => None,
        };
        if bootstrap_turn != Some(request.native_turn_id.as_str())
            && self.owned_active_turn_id.as_deref() != Some(request.native_turn_id.as_str())
        {
            return Err(CodexError::Blocked(BlockReason::StaleNativeRequest));
        }
        let answer = answer_value(&request, &permit.answer).map_err(|error| match error {
            NativeAnswerError::Unsupported => {
                CodexError::Blocked(BlockReason::UnsupportedNativeAnswer)
            }
            NativeAnswerError::WrongKind => {
                CodexError::InvalidInput("answer kind does not match native request")
            }
            NativeAnswerError::InvalidShape => CodexError::InvalidInput("answer shape is invalid"),
        })?;
        let frame = encode(&json!({"id":permit.request_id.wire_value(),"result":answer}))
            .map_err(CodexError::Codec)?;
        self.pending_requests
            .get_mut(&key)
            .ok_or(CodexError::Blocked(BlockReason::StaleNativeRequest))?
            .stage = NativeRequestStage::AnswerWriteUncertain;
        if self.io.write_line(&frame).is_err() {
            self.poisoned = true;
            return Ok(AnswerWriteOutcome::Uncertain {
                request_id: permit.request_id,
            });
        }
        self.pending_requests
            .get_mut(&key)
            .ok_or(CodexError::Blocked(BlockReason::StaleNativeRequest))?
            .stage = NativeRequestStage::AnswerWritten;
        Ok(AnswerWriteOutcome::WrittenAwaitingResolution {
            request_id: permit.request_id,
        })
    }

    pub fn initialize(&mut self) -> Result<(), CodexError> {
        if self.initialized || self.poisoned {
            return Err(CodexError::InvalidState(
                "connection was already initialized or lost",
            ));
        }
        let result = self.request(
            "initialize",
            json!({
                "clientInfo": {
                    "name": "podbay",
                    "title": "PodBay",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }),
        )?;
        for field in ["codexHome", "platformFamily", "platformOs", "userAgent"] {
            if nonempty_string(result.get(field)).is_none() {
                self.poisoned = true;
                return Err(CodexError::Protocol(
                    "initialize response omitted identity fields",
                ));
            }
        }
        self.notify("initialized", json!({}))?;
        self.initialized = true;
        Ok(())
    }

    /// Creates only an unmaterialized native thread. No turn or model input is
    /// sent. The higher layer must authorise and journal the create intent
    /// before this RPC, then durably checkpoint this exact thread ID before a
    /// later bootstrap turn. This receipt is neither writer authority nor
    /// native-session readiness.
    pub fn start_thread_without_turn(&mut self) -> Result<NativeThread, CodexError> {
        self.require_fresh_thread()?;
        let result = self.request("thread/start", self.thread_settings())?;
        let thread = self
            .validate_effective_thread(&result, None)
            .inspect_err(|_| {
                self.poisoned = true;
            })?;
        if thread.status != ThreadStatus::Idle {
            self.poisoned = true;
            return Err(CodexError::InvalidState("new native thread is not idle"));
        }
        self.thread = Some(thread.clone());
        self.native_status = thread.status;
        self.apply_queued()?;
        if self.external_conflict
            || self.status_waiting
            || self.native_status != ThreadStatus::Idle
            || !self.pending_requests.is_empty()
        {
            return Err(CodexError::InvalidState(
                "native thread became busy before bootstrap",
            ));
        }
        Ok(thread)
    }

    /// Creates one native thread, then submits one bootstrap turn. Any lost
    /// reply leaves this resource unusable for another start until reconciled.
    /// This compatibility path has no durable checkpoint between its RPCs;
    /// the pod must use a separate journaled turn path before exposing it.
    pub fn start_new(
        &mut self,
        bootstrap_text: &str,
        client_message_id: &str,
    ) -> Result<StartReceipt, CodexError> {
        self.require_fresh_thread()?;
        if bootstrap_text.is_empty()
            || bootstrap_text.len() > 1_000_000
            || !valid_token(client_message_id)
        {
            return Err(CodexError::InvalidInput("bootstrap text or key is invalid"));
        }
        let thread = self.start_thread_without_turn()?;
        self.bootstrap = BootstrapState::Unknown;
        let turn = self.request(
            "turn/start",
            json!({
                "threadId": thread.thread_id,
                "input": [{"type":"text", "text":bootstrap_text}],
                "clientUserMessageId": client_message_id,
                "model": self.config.model,
                "effort": self.config.effort,
            }),
        )?;
        let turn_id = nonempty_string(turn.pointer("/turn/id"))
            .ok_or(CodexError::Protocol("turn/start omitted turn id"))?
            .to_owned();
        if turn.pointer("/turn/status").and_then(Value::as_str) != Some("inProgress") {
            self.poisoned = true;
            return Err(CodexError::Protocol(
                "turn/start did not report an in-progress turn",
            ));
        }
        self.bootstrap = BootstrapState::Submitted {
            turn_id: turn_id.clone(),
        };
        self.native_status = ThreadStatus::Active;
        self.idle_after_completion = false;
        self.apply_queued()?;
        Ok(StartReceipt {
            thread,
            bootstrap_turn_id: turn_id,
        })
    }

    /// Submit the first native turn only after the higher layer has durably
    /// checkpointed the exact thread/session IDs and bootstrap intent. This
    /// method checks a local WriterPermit; it does not establish durable
    /// authority. Any attempted RPC without a trusted reply becomes Unknown
    /// and cannot be retried through this adapter instance. A fresh idle read
    /// cannot fence an uncontrolled external native writer by itself.
    pub fn submit_bootstrap_after_checkpoint(
        &mut self,
        permit: &WriterPermit,
        expected_thread_id: &str,
        expected_session_id: &str,
        bootstrap_text: &str,
        client_message_id: &str,
    ) -> Result<BootstrapTurnSubmission, CodexError> {
        self.submit_bootstrap_after_checkpoint_checked(
            permit,
            expected_thread_id,
            expected_session_id,
            bootstrap_text,
            client_message_id,
            |_| Ok(()),
        )
    }

    /// The pod's final durable/OS preflight runs after the fresh native idle
    /// read and immediately before the first `turn/start`. Failure poisons
    /// this instance because its external journal intent may already exist.
    pub fn submit_bootstrap_after_checkpoint_checked(
        &mut self,
        permit: &WriterPermit,
        expected_thread_id: &str,
        expected_session_id: &str,
        bootstrap_text: &str,
        client_message_id: &str,
        mut before_turn_start: impl FnMut(&mut Self) -> Result<(), CodexError>,
    ) -> Result<BootstrapTurnSubmission, CodexError> {
        self.check_permit(permit)?;
        if bootstrap_text.is_empty()
            || bootstrap_text.len() > 1_000_000
            || !valid_token(client_message_id)
        {
            return Err(CodexError::InvalidInput("bootstrap text or key is invalid"));
        }
        if !matches!(self.bootstrap, BootstrapState::NotStarted) {
            return Err(CodexError::Blocked(BlockReason::BootstrapUnsettled));
        }
        let bound = self
            .thread
            .as_ref()
            .ok_or(CodexError::InvalidState("native thread is not bound"))?;
        if bound.thread_id != expected_thread_id || bound.session_id != expected_session_id {
            return Err(CodexError::Mismatch("native thread checkpoint differs"));
        }
        self.check_native_blockers()?;
        let observed = self.read_thread()?;
        self.check_native_blockers()?;
        if !matches!(self.bootstrap, BootstrapState::NotStarted)
            || observed.thread_id != expected_thread_id
            || observed.session_id != expected_session_id
            || observed.status != ThreadStatus::Idle
            || self.native_status != ThreadStatus::Idle
            || self.owned_active_turn_id.is_some()
            || self.observed_active_turn_id.is_some()
        {
            return Err(CodexError::Blocked(BlockReason::NativeBusy));
        }
        if let Err(error) = before_turn_start(self) {
            self.bootstrap = BootstrapState::Unknown;
            self.poisoned = true;
            return Err(error);
        }
        let uncertain = BootstrapTurnSubmission {
            native_thread_id: expected_thread_id.into(),
            native_session_id: expected_session_id.into(),
            client_message_id: client_message_id.into(),
            stage: BootstrapTurnStage::Uncertain,
        };
        self.bootstrap = BootstrapState::Unknown;
        let response = match self.request(
            "turn/start",
            json!({
                "threadId": expected_thread_id,
                "input": [{"type":"text", "text":bootstrap_text}],
                "clientUserMessageId": client_message_id,
                "model": self.config.model,
                "effort": self.config.effort,
            }),
        ) {
            Ok(response) => response,
            Err(_) => {
                self.poisoned = true;
                return Ok(uncertain);
            }
        };
        let Some(turn_id) = nonempty_string(response.pointer("/turn/id")) else {
            self.poisoned = true;
            return Ok(uncertain);
        };
        if response.pointer("/turn/status").and_then(Value::as_str) != Some("inProgress") {
            self.poisoned = true;
            return Ok(uncertain);
        }
        let turn_id = turn_id.to_owned();
        self.bootstrap = BootstrapState::Submitted {
            turn_id: turn_id.clone(),
        };
        self.native_status = ThreadStatus::Active;
        self.idle_after_completion = false;
        if self.apply_queued().is_err() {
            // The turn/start receipt remains exact even when a later queued
            // notification makes observation uncertain.
            self.poisoned = true;
        }
        Ok(BootstrapTurnSubmission {
            stage: BootstrapTurnStage::Submitted { turn_id },
            ..uncertain
        })
    }

    /// Reads before resuming, then checks the effective policy returned by
    /// Codex. It never resubmits bootstrap or asserts that it settled.
    pub fn resume_existing(
        &mut self,
        expected_thread_id: &str,
    ) -> Result<NativeThread, CodexError> {
        self.require_fresh_thread()?;
        if !valid_token(expected_thread_id) {
            return Err(CodexError::InvalidInput("native thread id is invalid"));
        }
        let read = self.request("thread/read", json!({"threadId":expected_thread_id}))?;
        let observed = self
            .validate_read_thread(&read, expected_thread_id)
            .inspect_err(|_| {
                self.poisoned = true;
            })?;
        if observed.status == ThreadStatus::SystemError {
            return Err(CodexError::InvalidState(
                "native thread reported system error",
            ));
        }
        if observed.status == ThreadStatus::Active {
            return Err(CodexError::Unsupported(
                "active native thread cannot be resumed without verified turn identity",
            ));
        }
        let mut params = self.thread_settings();
        let map = params
            .as_object_mut()
            .ok_or(CodexError::Protocol("thread settings are not an object"))?;
        map.insert("threadId".into(), json!(expected_thread_id));
        map.remove("ephemeral");
        map.remove("serviceName");
        map.insert("excludeTurns".into(), json!(true));
        let result = self.request("thread/resume", params)?;
        let thread = self
            .validate_effective_thread(&result, Some(expected_thread_id))
            .inspect_err(|_| {
                self.poisoned = true;
            })?;
        if thread.status == ThreadStatus::Active {
            self.poisoned = true;
            return Err(CodexError::Unsupported(
                "active resumed thread has no verified turn identity",
            ));
        }
        self.thread = Some(thread.clone());
        self.native_status = thread.status;
        self.bootstrap = BootstrapState::Unknown;
        self.apply_queued()?;
        self.thread.clone().ok_or(CodexError::InvalidState(
            "native thread binding disappeared",
        ))
    }

    pub fn read_thread(&mut self) -> Result<NativeThread, CodexError> {
        let expected = self
            .thread
            .as_ref()
            .ok_or(CodexError::InvalidState("native thread is not bound"))?
            .thread_id
            .clone();
        let result = self.request("thread/read", json!({"threadId":expected}))?;
        let thread = self
            .validate_read_thread(&result, &expected)
            .inspect_err(|_| {
                self.poisoned = true;
            })?;
        self.thread = Some(thread.clone());
        self.native_status = thread.status;
        // Metadata-only thread/read says whether a turn is active, but carries
        // no turn identity. A prior receipt or notification is not a fresh
        // observation from this read. Retain local ownership separately.
        self.observed_active_turn_id = None;
        if thread.status == ThreadStatus::Active && self.owned_active_turn_id.is_none() {
            // Metadata reports activity, but this process never received the
            // matching turn/start receipt. It must not steer another writer.
            self.external_conflict = true;
        }
        self.status_waiting = waiting_flag(result.pointer("/thread/status")).inspect_err(|_| {
            self.poisoned = true;
        })?;
        if thread.status == ThreadStatus::Idle
            && matches!(self.bootstrap, BootstrapState::Completed { .. })
        {
            self.idle_after_completion = true;
        }
        self.retire_resolved_requests();
        self.apply_queued()?;
        Ok(thread)
    }

    /// Reconciles the native thread immediately before a submitted turn. The
    /// permit must come from a fresh higher-layer writer check; this local
    /// comparison cannot close a race with an uncontrolled external writer.
    pub fn send_turn(
        &mut self,
        permit: &WriterPermit,
        text: &str,
        client_message_id: &str,
        expected_active_turn_id: Option<&str>,
    ) -> Result<TurnSubmission, CodexError> {
        self.check_permit(permit)?;
        if text.is_empty() || text.len() > 1_000_000 || !valid_token(client_message_id) {
            return Err(CodexError::InvalidInput(
                "turn text or client message key is invalid",
            ));
        }
        if !matches!(self.bootstrap, BootstrapState::Completed { .. }) {
            return Err(CodexError::Blocked(BlockReason::BootstrapUnsettled));
        }
        if self
            .last_submission
            .as_ref()
            .is_some_and(|submission| submission.client_message_id == client_message_id)
        {
            return Err(CodexError::Blocked(BlockReason::DuplicateMessageKey));
        }
        self.check_native_blockers()?;
        self.read_thread()?;
        self.check_native_blockers()?;

        let (mode, active_turn_id) = match (
            self.native_status,
            self.owned_active_turn_id.as_deref(),
            expected_active_turn_id,
        ) {
            (ThreadStatus::Idle, None, None) if self.bootstrap_ready() => (TurnMode::Start, None),
            (ThreadStatus::Active, Some(owned), Some(expected)) if owned == expected => {
                // Native expectedTurnId is the final compare-and-set. The
                // metadata-only read establishes activity, not the turn ID.
                (TurnMode::Steer, Some(owned.to_owned()))
            }
            (ThreadStatus::Active, None, _) => {
                self.external_conflict = true;
                return Err(CodexError::Blocked(BlockReason::ExternalWriter));
            }
            (ThreadStatus::Active, Some(_), Some(_)) => {
                return Err(CodexError::Blocked(BlockReason::StaleExpectedTurn));
            }
            (ThreadStatus::Active, Some(_), None) => {
                return Err(CodexError::Blocked(BlockReason::NativeBusy));
            }
            (ThreadStatus::Idle, None, Some(_)) => {
                return Err(CodexError::Blocked(BlockReason::NativeBusy));
            }
            _ => return Err(CodexError::Blocked(BlockReason::ObservationUnknown)),
        };
        let thread_id = self
            .thread
            .as_ref()
            .ok_or(CodexError::Blocked(BlockReason::ObservationUnknown))?
            .thread_id
            .clone();
        let (method, params) = match mode {
            TurnMode::Start => (
                "turn/start",
                json!({
                    "threadId":thread_id,
                    "input":[{"type":"text","text":text}],
                    "clientUserMessageId":client_message_id,
                    "model":self.config.model,
                    "effort":self.config.effort,
                }),
            ),
            TurnMode::Steer => (
                "turn/steer",
                json!({
                    "threadId":thread_id,
                    "expectedTurnId":active_turn_id,
                    "input":[{"type":"text","text":text}],
                    "clientUserMessageId":client_message_id,
                }),
            ),
        };
        let uncertain = TurnSubmission {
            client_message_id: client_message_id.to_owned(),
            mode,
            stage: TurnSubmissionStage::Uncertain,
        };
        self.last_submission = Some(uncertain.clone());
        let response = match self.request(method, params) {
            Ok(value) => value,
            Err(CodexError::TransportUncertain) => return Ok(uncertain),
            Err(error @ CodexError::RemoteError(_)) if mode == TurnMode::Steer => {
                // A rejected exact-turn CAS may indicate a competing native
                // writer. Keep the native error and block further input.
                self.external_conflict = true;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let turn_id = match mode {
            TurnMode::Start => {
                let id = nonempty_string(response.pointer("/turn/id"));
                let status = response.pointer("/turn/status").and_then(Value::as_str);
                match (id, status) {
                    (Some(id), Some("inProgress")) => id.to_owned(),
                    _ => {
                        self.poisoned = true;
                        return Ok(uncertain);
                    }
                }
            }
            TurnMode::Steer => {
                let observed = nonempty_string(response.get("turnId"));
                match (observed, active_turn_id.as_deref()) {
                    (Some(observed), Some(expected)) if observed == expected => observed.to_owned(),
                    _ => {
                        self.external_conflict = true;
                        self.poisoned = true;
                        return Ok(uncertain);
                    }
                }
            }
        };
        if mode == TurnMode::Start {
            self.last_later_turn_completion = None;
            self.completion_read = CompletionReadState::NotStarted;
            self.owned_active_turn_id = Some(turn_id.clone());
            self.observed_active_turn_id = Some(turn_id.clone());
            self.native_status = ThreadStatus::Active;
            self.idle_after_completion = false;
        }
        let accepted = TurnSubmission {
            client_message_id: client_message_id.to_owned(),
            mode,
            stage: TurnSubmissionStage::Accepted { turn_id },
        };
        self.last_submission = Some(accepted.clone());
        self.apply_queued()?;
        Ok(accepted)
    }

    /// Start a later turn only after an external per-command intent has been
    /// fsynced. This is idle-only: steering needs a distinct durable contract.
    /// The caller's read-only preflight runs after the fresh native read and
    /// directly before `turn/start`; WriterPermit remains a local fence, not
    /// durable PodBay authority. Any attempted/lost native reply is Uncertain
    /// and this adapter instance cannot send it again.
    pub fn send_turn_after_checkpoint_checked(
        &mut self,
        permit: &WriterPermit,
        expected_thread_id: &str,
        expected_session_id: &str,
        text: &str,
        client_message_id: &str,
        mut before_turn_start: impl FnMut(&mut Self) -> Result<(), CodexError>,
    ) -> Result<TurnSubmission, CodexError> {
        self.check_permit(permit)?;
        if text.is_empty()
            || text.len() > 1_000_000
            || !valid_token(client_message_id)
            || !valid_native_id(expected_thread_id)
            || !valid_native_id(expected_session_id)
        {
            return Err(CodexError::InvalidInput(
                "later turn text or identity is invalid",
            ));
        }
        if !matches!(self.bootstrap, BootstrapState::Completed { .. }) {
            return Err(CodexError::Blocked(BlockReason::BootstrapUnsettled));
        }
        if self
            .last_submission
            .as_ref()
            .is_some_and(|submission| submission.client_message_id == client_message_id)
        {
            return Err(CodexError::Blocked(BlockReason::DuplicateMessageKey));
        }
        self.check_native_blockers()?;
        self.read_thread()?;
        self.check_native_blockers()?;
        let bound = self
            .thread
            .as_ref()
            .ok_or(CodexError::Blocked(BlockReason::ObservationUnknown))?;
        if bound.thread_id != expected_thread_id || bound.session_id != expected_session_id {
            self.poisoned = true;
            return Err(CodexError::Mismatch(
                "later-turn native thread or Session changed",
            ));
        }
        if !self.bootstrap_ready() {
            return Err(CodexError::Blocked(BlockReason::NativeBusy));
        }
        let uncertain = TurnSubmission {
            client_message_id: client_message_id.into(),
            mode: TurnMode::Start,
            stage: TurnSubmissionStage::Uncertain,
        };
        self.last_submission = Some(uncertain.clone());
        if let Err(error) = before_turn_start(self) {
            self.poisoned = true;
            return Err(error);
        }
        self.check_permit(permit)?;
        self.check_native_blockers()?;
        if self.thread.as_ref().is_none_or(|thread| {
            thread.thread_id != expected_thread_id || thread.session_id != expected_session_id
        }) || !self.bootstrap_ready()
        {
            self.poisoned = true;
            return Err(CodexError::Blocked(BlockReason::ObservationUnknown));
        }
        let response = match self.request(
            "turn/start",
            json!({
                "threadId": expected_thread_id,
                "input": [{"type":"text", "text":text}],
                "clientUserMessageId": client_message_id,
                "model": self.config.model,
                "effort": self.config.effort,
            }),
        ) {
            Ok(response) => response,
            Err(_) => {
                self.poisoned = true;
                return Ok(uncertain);
            }
        };
        let turn_id = match (
            nonempty_string(response.pointer("/turn/id")),
            response.pointer("/turn/status").and_then(Value::as_str),
        ) {
            (Some(turn_id), Some("inProgress")) => turn_id.to_owned(),
            _ => {
                self.poisoned = true;
                return Ok(uncertain);
            }
        };
        self.owned_active_turn_id = Some(turn_id.clone());
        self.last_later_turn_completion = None;
        self.completion_read = CompletionReadState::NotStarted;
        self.observed_active_turn_id = Some(turn_id.clone());
        self.native_status = ThreadStatus::Active;
        self.idle_after_completion = false;
        let accepted = TurnSubmission {
            client_message_id: client_message_id.into(),
            mode: TurnMode::Start,
            stage: TurnSubmissionStage::Accepted { turn_id },
        };
        self.last_submission = Some(accepted.clone());
        if self.apply_queued().is_err() {
            self.poisoned = true;
        }
        Ok(accepted)
    }

    /// Pure preflight for the atomic nonblocking pipe path. The complete
    /// encoded `turn/start` frame must fit PIPE_BUF before the pod fsyncs an
    /// intent; larger prompts require a distinct chunked transport contract.
    pub fn prepare_nonblocking_later_turn(
        &mut self,
        permit: &WriterPermit,
        expected_thread_id: &str,
        expected_session_id: &str,
        text: &str,
        client_message_id: &str,
    ) -> Result<PreparedNonblockingLaterTurn, CodexError> {
        self.check_permit(permit)?;
        if text.is_empty() || text.len() > 1_000_000 || !valid_token(client_message_id)
            || !valid_native_id(expected_thread_id) || !valid_native_id(expected_session_id)
        { return Err(CodexError::InvalidInput("later turn text or identity is invalid")); }
        if !matches!(self.bootstrap, BootstrapState::Completed { .. }) {
            return Err(CodexError::Blocked(BlockReason::BootstrapUnsettled));
        }
        if !matches!(self.later_submission, LaterSubmissionState::Idle | LaterSubmissionState::Submitted)
            || self.last_submission.as_ref().is_some_and(|prior|
                prior.client_message_id == client_message_id)
        { return Err(CodexError::Blocked(BlockReason::DuplicateMessageKey)); }
        self.check_native_blockers()?;
        if !self.bootstrap_ready() {
            return Err(CodexError::Blocked(BlockReason::NativeBusy));
        }
        let native = self.thread.as_ref().ok_or(CodexError::Blocked(BlockReason::ObservationUnknown))?;
        if native.thread_id != expected_thread_id || native.session_id != expected_session_id {
            return Err(CodexError::Mismatch("later-turn native anchor differs"));
        }
        let read_id = self.next_id;
        let start_id = read_id.checked_add(1).ok_or(CodexError::InvalidState("RPC id exhausted"))?;
        let read_frame = encode(&json!({"id":read_id,"method":"thread/read",
            "params":{"threadId":expected_thread_id}})).map_err(CodexError::Codec)?;
        let start_frame = encode(&json!({"id":start_id,"method":"turn/start",
            "params":{"threadId":expected_thread_id,
                "input":[{"type":"text","text":text}],
                "clientUserMessageId":client_message_id,
                "model":self.config.model,"effort":self.config.effort}}))
            .map_err(CodexError::Codec)?;
        if read_frame.len() > MAX_ATOMIC_READ_PROBE_FRAME
            || start_frame.len() > MAX_ATOMIC_READ_PROBE_FRAME
        { return Err(CodexError::Unsupported("later turn exceeds atomic pipe frame bound")); }
        Ok(PreparedNonblockingLaterTurn {
            permit: permit.clone(), expected_thread_id: expected_thread_id.into(),
            expected_session_id: expected_session_id.into(),
            client_message_id: client_message_id.into(), read_id, read_frame,
            start_id, start_frame,
        })
    }

    /// Called only after the pod fsyncs its exact later-turn journal Intent.
    /// This schedules no write; the outer control loop advances it by ticks.
    pub fn begin_nonblocking_later_turn_after_intent(
        &mut self,
        prepared: PreparedNonblockingLaterTurn,
    ) -> Result<(), CodexError> {
        self.check_permit(&prepared.permit)?;
        if self.next_id != prepared.read_id
            || !matches!(self.later_submission, LaterSubmissionState::Idle | LaterSubmissionState::Submitted)
        { return Err(CodexError::Blocked(BlockReason::ObservationUnknown)); }
        self.next_id = prepared.start_id.checked_add(1)
            .ok_or(CodexError::InvalidState("RPC id exhausted"))?;
        self.last_submission = Some(TurnSubmission {
            client_message_id: prepared.client_message_id.clone(),
            mode: TurnMode::Start, stage: TurnSubmissionStage::Uncertain,
        });
        self.later_submission = LaterSubmissionState::ReadPendingWrite {
            prepared, deadline: Instant::now() + COMPLETION_READ_TIMEOUT,
        };
        Ok(())
    }

    pub fn has_pending_nonblocking_later_turn(&self) -> bool {
        matches!(self.later_submission,
            LaterSubmissionState::ReadPendingWrite { .. }
            | LaterSubmissionState::ReadAwaitingReply { .. }
            | LaterSubmissionState::StartPendingWrite { .. }
            | LaterSubmissionState::StartAwaitingReply { .. })
    }

    fn later_submission_uncertain(&mut self) -> LaterTurnStartPoll {
        self.later_submission = LaterSubmissionState::Uncertain;
        self.poisoned = true;
        LaterTurnStartPoll::Uncertain
    }

    /// One atomic pipe write or one nonblocking frame read. `Pending` from
    /// try_write_line certifies zero bytes; a partial write is an error and
    /// never triggers a second `turn/start`. Notifications are applied before
    /// the matching response is interpreted.
    pub fn poll_nonblocking_later_turn_once(
        &mut self,
        mut before_turn_start: impl FnMut(&mut Self) -> Result<(), CodexError>,
    ) -> Result<LaterTurnStartPoll, CodexError> {
        let state = std::mem::replace(&mut self.later_submission, LaterSubmissionState::Uncertain);
        match state {
            LaterSubmissionState::Idle => Err(CodexError::InvalidState("later turn was not scheduled")),
            LaterSubmissionState::Submitted => {
                self.later_submission = LaterSubmissionState::Submitted;
                Err(CodexError::InvalidState("later turn was already submitted"))
            }
            LaterSubmissionState::Uncertain => Ok(LaterTurnStartPoll::Uncertain),
            LaterSubmissionState::ReadPendingWrite { prepared, deadline } => {
                if Instant::now() >= deadline { return Ok(self.later_submission_uncertain()); }
                match self.io.try_write_line(&prepared.read_frame) {
                    Ok(AvailableWrite::Pending) => {
                        self.later_submission = LaterSubmissionState::ReadPendingWrite { prepared, deadline };
                        Ok(LaterTurnStartPoll::Pending)
                    }
                    Ok(AvailableWrite::Written) => {
                        self.later_submission = LaterSubmissionState::ReadAwaitingReply { prepared, deadline };
                        Ok(LaterTurnStartPoll::Advanced)
                    }
                    Err(_) => Ok(self.later_submission_uncertain()),
                }
            }
            LaterSubmissionState::ReadAwaitingReply { prepared, deadline } => {
                if Instant::now() >= deadline { return Ok(self.later_submission_uncertain()); }
                let frame = match self.io.try_read_line() {
                    Ok(AvailableLine::Pending | AvailableLine::IncompleteFrame) => {
                        self.later_submission = LaterSubmissionState::ReadAwaitingReply { prepared, deadline };
                        return Ok(LaterTurnStartPoll::Pending);
                    }
                    Ok(AvailableLine::Frame(frame)) => frame,
                    Ok(AvailableLine::EndOfStream) | Err(_) => return Ok(self.later_submission_uncertain()),
                };
                let value = match decode(&frame) {
                    Ok(value) => value,
                    Err(_) => return Ok(self.later_submission_uncertain()),
                };
                if nonempty_string(value.get("method")).is_some() {
                    if self.apply_event_or_poison(&value, &frame).is_err() {
                        return Ok(self.later_submission_uncertain());
                    }
                    self.later_submission = LaterSubmissionState::ReadAwaitingReply { prepared, deadline };
                    return Ok(LaterTurnStartPoll::Advanced);
                }
                if value.get("id").and_then(Value::as_u64) != Some(prepared.read_id) {
                    return Ok(self.later_submission_uncertain());
                }
                let result = match value.get("result") {
                    Some(result) => result,
                    None => return Ok(self.later_submission_uncertain()),
                };
                let thread = match self.validate_read_thread(result, &prepared.expected_thread_id) {
                    Ok(thread) => thread,
                    Err(_) => return Ok(self.later_submission_uncertain()),
                };
                let waiting = match waiting_flag(result.pointer("/thread/status")) {
                    Ok(waiting) => waiting,
                    Err(_) => return Ok(self.later_submission_uncertain()),
                };
                self.thread = Some(thread.clone());
                self.native_status = thread.status;
                self.observed_active_turn_id = None;
                self.status_waiting = waiting;
                self.retire_resolved_requests();
                if thread.session_id != prepared.expected_session_id
                    || thread.status != ThreadStatus::Idle
                    || self.apply_queued().is_err()
                    || self.check_native_blockers().is_err()
                    || !self.bootstrap_ready()
                { return Ok(self.later_submission_uncertain()); }
                if before_turn_start(self).is_err() {
                    return Ok(self.later_submission_uncertain());
                }
                self.later_submission = LaterSubmissionState::StartPendingWrite {
                    prepared, deadline: Instant::now() + COMPLETION_READ_TIMEOUT,
                };
                Ok(LaterTurnStartPoll::Advanced)
            }
            LaterSubmissionState::StartPendingWrite { prepared, deadline } => {
                if Instant::now() >= deadline || before_turn_start(self).is_err()
                    || self.check_permit(&prepared.permit).is_err()
                    || self.check_native_blockers().is_err() || !self.bootstrap_ready()
                    || self.thread.as_ref().is_none_or(|thread|
                        thread.thread_id != prepared.expected_thread_id
                            || thread.session_id != prepared.expected_session_id)
                { return Ok(self.later_submission_uncertain()); }
                match self.io.try_write_line(&prepared.start_frame) {
                    Ok(AvailableWrite::Pending) => {
                        self.later_submission = LaterSubmissionState::StartPendingWrite { prepared, deadline };
                        Ok(LaterTurnStartPoll::Pending)
                    }
                    Ok(AvailableWrite::Written) => {
                        self.later_submission = LaterSubmissionState::StartAwaitingReply {
                            prepared, deadline: Instant::now() + COMPLETION_READ_TIMEOUT,
                        };
                        Ok(LaterTurnStartPoll::Advanced)
                    }
                    Err(_) => Ok(self.later_submission_uncertain()),
                }
            }
            LaterSubmissionState::StartAwaitingReply { prepared, deadline } => {
                if Instant::now() >= deadline { return Ok(self.later_submission_uncertain()); }
                let frame = match self.io.try_read_line() {
                    Ok(AvailableLine::Pending | AvailableLine::IncompleteFrame) => {
                        self.later_submission = LaterSubmissionState::StartAwaitingReply { prepared, deadline };
                        return Ok(LaterTurnStartPoll::Pending);
                    }
                    Ok(AvailableLine::Frame(frame)) => frame,
                    Ok(AvailableLine::EndOfStream) | Err(_) => return Ok(self.later_submission_uncertain()),
                };
                let value = match decode(&frame) {
                    Ok(value) => value,
                    Err(_) => return Ok(self.later_submission_uncertain()),
                };
                if nonempty_string(value.get("method")).is_some() {
                    if self.apply_event_or_poison(&value, &frame).is_err() {
                        return Ok(self.later_submission_uncertain());
                    }
                    self.later_submission = LaterSubmissionState::StartAwaitingReply { prepared, deadline };
                    return Ok(LaterTurnStartPoll::Advanced);
                }
                if value.get("id").and_then(Value::as_u64) != Some(prepared.start_id) {
                    return Ok(self.later_submission_uncertain());
                }
                let turn = value.pointer("/result/turn");
                let Some(turn_id) = nonempty_string(turn.and_then(|turn| turn.get("id"))) else {
                    return Ok(self.later_submission_uncertain());
                };
                if turn.and_then(|turn| turn.get("status")).and_then(Value::as_str)
                    != Some("inProgress")
                { return Ok(self.later_submission_uncertain()); }
                let turn_id = turn_id.to_owned();
                self.owned_active_turn_id = Some(turn_id.clone());
                self.last_later_turn_completion = None;
                self.completion_read = CompletionReadState::NotStarted;
                self.observed_active_turn_id = Some(turn_id.clone());
                self.native_status = ThreadStatus::Active;
                self.idle_after_completion = false;
                self.last_submission = Some(TurnSubmission {
                    client_message_id: prepared.client_message_id,
                    mode: TurnMode::Start,
                    stage: TurnSubmissionStage::Accepted { turn_id: turn_id.clone() },
                });
                self.later_submission = LaterSubmissionState::Submitted;
                if self.apply_queued().is_err() { self.poisoned = true; }
                Ok(LaterTurnStartPoll::Submitted { turn_id })
            }
        }
    }

    /// RPC success is only an interrupt request receipt. A matching native
    /// `turn/completed` with `status: interrupted` settles it.
    pub fn interrupt_turn(
        &mut self,
        permit: &WriterPermit,
        expected_turn_id: &str,
    ) -> Result<InterruptState, CodexError> {
        self.check_permit(permit)?;
        if !valid_token(expected_turn_id) {
            return Err(CodexError::InvalidInput("expected turn id is invalid"));
        }
        match self.owned_active_turn_id.as_deref() {
            None => return Err(CodexError::Blocked(BlockReason::NativeBusy)),
            Some(owned) if owned != expected_turn_id => {
                return Err(CodexError::Blocked(BlockReason::StaleExpectedTurn));
            }
            Some(_) => {}
        }
        if matches!(
            self.interrupt,
            InterruptState::Requested { .. } | InterruptState::Uncertain { .. }
        ) {
            return Err(CodexError::Blocked(BlockReason::InterruptAlreadyRequested));
        }
        self.read_thread()?;
        if self.native_status != ThreadStatus::Active
            || self.owned_active_turn_id.as_deref() != Some(expected_turn_id)
            || self.external_conflict
        {
            return Err(CodexError::Blocked(BlockReason::ExternalWriter));
        }
        let thread_id = self
            .thread
            .as_ref()
            .ok_or(CodexError::Blocked(BlockReason::ObservationUnknown))?
            .thread_id
            .clone();
        self.interrupt = InterruptState::Uncertain {
            turn_id: expected_turn_id.to_owned(),
        };
        let response = match self.request(
            "turn/interrupt",
            json!({"threadId":thread_id,"turnId":expected_turn_id}),
        ) {
            Ok(value) => value,
            Err(CodexError::TransportUncertain) => return Ok(self.interrupt.clone()),
            Err(error) => return Err(error),
        };
        if !response.is_object() {
            self.poisoned = true;
            return Ok(self.interrupt.clone());
        }
        self.interrupt = InterruptState::Requested {
            turn_id: expected_turn_id.to_owned(),
        };
        self.apply_queued()?;
        Ok(self.interrupt.clone())
    }

    fn check_permit(&self, permit: &WriterPermit) -> Result<(), CodexError> {
        if permit.identity != self.identity {
            return Err(CodexError::Blocked(BlockReason::StaleResourcePermit));
        }
        match self.current_writer_epoch {
            None => Err(CodexError::Blocked(BlockReason::MissingWriterPermit)),
            Some(current) if current != permit.writer_epoch => {
                Err(CodexError::Blocked(BlockReason::StaleWriterPermit))
            }
            Some(_) => Ok(()),
        }
    }

    fn check_native_blockers(&self) -> Result<(), CodexError> {
        if self.poisoned {
            return Err(CodexError::Blocked(BlockReason::ObservationUnknown));
        }
        if self.external_conflict {
            return Err(CodexError::Blocked(BlockReason::ExternalWriter));
        }
        if matches!(
            self.interrupt,
            InterruptState::Requested { .. } | InterruptState::Uncertain { .. }
        ) {
            return Err(CodexError::Blocked(BlockReason::InterruptAlreadyRequested));
        }
        if !self.pending_requests.is_empty() {
            return Err(CodexError::Blocked(BlockReason::PendingHostRequest));
        }
        if self.status_waiting {
            return Err(CodexError::Blocked(BlockReason::NativeWaiting));
        }
        Ok(())
    }

    /// Handles one native event frame. Pending host requests remain blocked
    /// until native resolution and a fresh no-waiting status observation.
    pub fn poll_once(&mut self) -> Result<(), CodexError> {
        if self.poisoned || !self.initialized {
            return Err(CodexError::InvalidState("native connection is unavailable"));
        }
        if let Some(event) = self.queued.pop_front() {
            return self.apply_event_or_poison(&event.value, &event.raw_jsonl);
        }
        let line = self.read_frame()?;
        let value = decode(&line).map_err(|error| self.poison_codec(error))?;
        if nonempty_string(value.get("method")).is_none() {
            self.poisoned = true;
            return Err(CodexError::Protocol("unsolicited RPC response"));
        }
        self.apply_event_or_poison(&value, &line)
    }

    /// Consume at most one already available native notification. Pending
    /// means the process has not produced a complete frame yet; it is neither
    /// EOF nor a transport failure and leaves control IPC free to run.
    pub fn poll_available_once(&mut self) -> Result<bool, CodexError> {
        if self.poisoned || !self.initialized {
            return Err(CodexError::InvalidState("native connection is unavailable"));
        }
        if matches!(
            self.completion_read,
            CompletionReadState::PendingWrite { .. }
                | CompletionReadState::AwaitingReply { .. }
                | CompletionReadState::Draining { .. }
        ) {
            return Err(CodexError::InvalidState(
                "completion read owns the native RPC",
            ));
        }
        if let Some(event) = self.queued.pop_front() {
            self.apply_event_or_poison(&event.value, &event.raw_jsonl)?;
            return Ok(true);
        }
        let line = match self.io.try_read_line() {
            Ok(AvailableLine::Pending | AvailableLine::IncompleteFrame) => return Ok(false),
            Ok(AvailableLine::Frame(frame)) => frame,
            Ok(AvailableLine::EndOfStream) | Err(_) => {
                self.poisoned = true;
                return Err(CodexError::TransportUncertain);
            }
        };
        let value = decode(&line).map_err(|error| self.poison_codec(error))?;
        if nonempty_string(value.get("method")).is_none() {
            self.poisoned = true;
            return Err(CodexError::Protocol("unsolicited RPC response"));
        }
        self.apply_event_or_poison(&value, &line)?;
        Ok(true)
    }

    /// Progress one read-only `thread/read` RPC after the exact bootstrap
    /// completion notification. Each tick performs at most one atomic pipe
    /// write or one nonblocking frame read, so pod control stays responsive.
    /// A lost or malformed response is terminally uncertain and never causes
    /// another native write. No thread content is retained.
    pub fn poll_bootstrap_read_proof_once(
        &mut self,
        expected_thread_id: &str,
        expected_session_id: &str,
        expected_turn_id: &str,
    ) -> Result<BootstrapReadPoll, CodexError> {
        if self.poisoned || !self.initialized {
            return Err(CodexError::InvalidState("native connection is unavailable"));
        }
        if self.thread.as_ref().is_none_or(|thread| {
            thread.thread_id != expected_thread_id || thread.session_id != expected_session_id
        }) || !matches!(&self.bootstrap, BootstrapState::Completed { turn_id }
            if turn_id == expected_turn_id)
        {
            return Err(CodexError::Blocked(BlockReason::BootstrapUnsettled));
        }
        self.poll_exact_completion_read_proof_once(
            expected_thread_id,
            expected_session_id,
            expected_turn_id,
        )
    }

    /// The same nonblocking read bridge serves later turns only after a
    /// matching state-applied native terminal notification. This proof is
    /// native idle/no-waiting/no-pending status, not PodBay command authority.
    pub fn poll_later_turn_read_proof_once(
        &mut self,
        expected: &LaterTurnCompletionObservation,
    ) -> Result<BootstrapReadPoll, CodexError> {
        if self.last_later_turn_completion.as_ref() != Some(expected)
            || self.external_conflict
            || !matches!(self.bootstrap, BootstrapState::Completed { .. })
        {
            return Err(CodexError::Blocked(BlockReason::ObservationUnknown));
        }
        self.poll_exact_completion_read_proof_once(
            &expected.native_thread_id,
            &expected.native_session_id,
            &expected.native_turn_id,
        )
    }

    fn poll_exact_completion_read_proof_once(
        &mut self,
        expected_thread_id: &str,
        expected_session_id: &str,
        expected_turn_id: &str,
    ) -> Result<BootstrapReadPoll, CodexError> {
        if self.poisoned || !self.initialized {
            return Err(CodexError::InvalidState("native connection is unavailable"));
        }
        if !completion_target_matches(
            &self.completion_read,
            expected_thread_id,
            expected_session_id,
            expected_turn_id,
        ) {
            return Err(CodexError::Mismatch("completion read target changed"));
        }
        let state = std::mem::replace(&mut self.completion_read, CompletionReadState::Uncertain);
        match state {
            CompletionReadState::NotStarted => {
                let id = self.next_id;
                self.next_id = id
                    .checked_add(1)
                    .ok_or(CodexError::InvalidState("RPC id exhausted"))?;
                let frame = encode(&json!({
                    "id": id, "method": "thread/read",
                    "params": {"threadId": expected_thread_id},
                }))
                .map_err(CodexError::Codec)?;
                if frame.len() > MAX_ATOMIC_READ_PROBE_FRAME {
                    self.completion_read = CompletionReadState::Inconclusive;
                    return Err(CodexError::Unsupported(
                        "completion read exceeds atomic pipe bound",
                    ));
                }
                self.completion_read = CompletionReadState::PendingWrite {
                    id,
                    frame,
                    thread_id: expected_thread_id.into(),
                    session_id: expected_session_id.into(),
                    turn_id: expected_turn_id.into(),
                    deadline: Instant::now() + COMPLETION_READ_TIMEOUT,
                };
                self.poll_exact_completion_read_proof_once(
                    expected_thread_id,
                    expected_session_id,
                    expected_turn_id,
                )
            }
            CompletionReadState::PendingWrite {
                id,
                frame,
                thread_id,
                session_id,
                turn_id,
                deadline,
            } => {
                if Instant::now() >= deadline {
                    self.completion_read = CompletionReadState::Inconclusive;
                    return Err(CodexError::TransportUncertain);
                }
                match self.io.try_write_line(&frame) {
                    Ok(AvailableWrite::Pending) => {
                        self.completion_read = CompletionReadState::PendingWrite {
                            id,
                            frame,
                            thread_id,
                            session_id,
                            turn_id,
                            deadline,
                        };
                        Ok(BootstrapReadPoll::Pending)
                    }
                    Ok(AvailableWrite::Written) => {
                        self.completion_read = CompletionReadState::AwaitingReply {
                            id,
                            thread_id,
                            session_id,
                            turn_id,
                            deadline: Instant::now() + COMPLETION_READ_TIMEOUT,
                        };
                        Ok(BootstrapReadPoll::Advanced)
                    }
                    Err(_) => {
                        self.poisoned = true;
                        Err(CodexError::TransportUncertain)
                    }
                }
            }
            CompletionReadState::AwaitingReply {
                id,
                thread_id,
                session_id,
                turn_id,
                deadline,
            } => {
                if Instant::now() >= deadline {
                    self.poisoned = true;
                    return Err(CodexError::TransportUncertain);
                }
                if let Some(event) = self.queued.pop_front() {
                    self.apply_event_or_poison(&event.value, &event.raw_jsonl)?;
                    self.completion_read = CompletionReadState::AwaitingReply {
                        id,
                        thread_id,
                        session_id,
                        turn_id,
                        deadline,
                    };
                    return Ok(BootstrapReadPoll::Advanced);
                }
                let frame = match self.io.try_read_line() {
                    Ok(AvailableLine::Pending | AvailableLine::IncompleteFrame) => {
                        self.completion_read = CompletionReadState::AwaitingReply {
                            id,
                            thread_id,
                            session_id,
                            turn_id,
                            deadline,
                        };
                        return Ok(BootstrapReadPoll::Pending);
                    }
                    Ok(AvailableLine::Frame(frame)) => frame,
                    Ok(AvailableLine::EndOfStream) | Err(_) => {
                        self.poisoned = true;
                        return Err(CodexError::TransportUncertain);
                    }
                };
                let value = decode(&frame).map_err(|error| self.poison_codec(error))?;
                if nonempty_string(value.get("method")).is_some() {
                    self.apply_event_or_poison(&value, &frame)?;
                    self.completion_read = CompletionReadState::AwaitingReply {
                        id,
                        thread_id,
                        session_id,
                        turn_id,
                        deadline,
                    };
                    return Ok(BootstrapReadPoll::Advanced);
                }
                if value.get("id").and_then(Value::as_u64) != Some(id)
                    || value.get("error").is_some()
                {
                    self.poisoned = true;
                    return Err(CodexError::Protocol(
                        "completion read reply identity differs",
                    ));
                }
                let result = value.get("result").ok_or_else(|| {
                    self.poisoned = true;
                    CodexError::Protocol("completion read omitted result")
                })?;
                let thread = self
                    .validate_read_thread(result, &thread_id)
                    .inspect_err(|_| {
                        self.poisoned = true;
                    })?;
                let waiting = waiting_flag(result.pointer("/thread/status")).inspect_err(|_| {
                    self.poisoned = true;
                })?;
                if thread.status == ThreadStatus::Idle
                    && result
                        .pointer("/thread/status/activeFlags")
                        .is_some_and(|flags| !flags.as_array().is_some_and(Vec::is_empty))
                {
                    self.poisoned = true;
                    return Err(CodexError::Protocol(
                        "idle completion read carries active flags",
                    ));
                }
                if thread.session_id != session_id {
                    self.poisoned = true;
                    return Err(CodexError::Mismatch(
                        "completion read native Session differs",
                    ));
                }
                self.native_status = thread.status;
                self.thread = Some(thread);
                self.status_waiting = waiting;
                self.observed_active_turn_id = None;
                self.idle_after_completion = self.native_status == ThreadStatus::Idle;
                self.retire_resolved_requests();
                if !self.bootstrap_ready() || waiting {
                    self.completion_read = CompletionReadState::Inconclusive;
                    return Ok(BootstrapReadPoll::Advanced);
                }
                self.completion_read = CompletionReadState::Draining {
                    thread_id,
                    session_id,
                    turn_id,
                    deadline,
                };
                Ok(BootstrapReadPoll::Advanced)
            }
            CompletionReadState::Draining {
                thread_id,
                session_id,
                turn_id,
                deadline,
            } => {
                if Instant::now() >= deadline {
                    self.poisoned = true;
                    return Err(CodexError::TransportUncertain);
                }
                match self.io.try_read_line() {
                    Ok(AvailableLine::Pending) if self.bootstrap_ready() => {
                        self.completion_read = CompletionReadState::Verified {
                            thread_id,
                            session_id,
                            turn_id,
                            deadline,
                        };
                        Ok(BootstrapReadPoll::Verified)
                    }
                    Ok(AvailableLine::Pending) => {
                        self.completion_read = CompletionReadState::Inconclusive;
                        Ok(BootstrapReadPoll::Pending)
                    }
                    Ok(AvailableLine::IncompleteFrame) => {
                        self.completion_read = CompletionReadState::Draining {
                            thread_id,
                            session_id,
                            turn_id,
                            deadline,
                        };
                        Ok(BootstrapReadPoll::Pending)
                    }
                    Ok(AvailableLine::Frame(frame)) => {
                        let value = decode(&frame).map_err(|error| self.poison_codec(error))?;
                        if nonempty_string(value.get("method")).is_none() {
                            self.poisoned = true;
                            return Err(CodexError::Protocol(
                                "unsolicited completion read response",
                            ));
                        }
                        self.apply_event_or_poison(&value, &frame)?;
                        self.completion_read = if self.bootstrap_ready() {
                            CompletionReadState::Draining {
                                thread_id,
                                session_id,
                                turn_id,
                                deadline,
                            }
                        } else {
                            CompletionReadState::Inconclusive
                        };
                        Ok(BootstrapReadPoll::Advanced)
                    }
                    Ok(AvailableLine::EndOfStream) | Err(_) => {
                        self.poisoned = true;
                        Err(CodexError::TransportUncertain)
                    }
                }
            }
            CompletionReadState::Verified {
                thread_id,
                session_id,
                turn_id,
                deadline,
            } => {
                if Instant::now() >= deadline {
                    self.poisoned = true;
                    return Err(CodexError::TransportUncertain);
                }
                match self.io.try_read_line() {
                    Ok(AvailableLine::Pending) if self.bootstrap_ready() => {
                        self.completion_read = CompletionReadState::Verified {
                            thread_id,
                            session_id,
                            turn_id,
                            deadline,
                        };
                        Ok(BootstrapReadPoll::Verified)
                    }
                    Ok(AvailableLine::Pending | AvailableLine::IncompleteFrame) => {
                        self.completion_read = CompletionReadState::Draining {
                            thread_id,
                            session_id,
                            turn_id,
                            deadline,
                        };
                        Ok(BootstrapReadPoll::Pending)
                    }
                    Ok(AvailableLine::Frame(frame)) => {
                        let value = decode(&frame).map_err(|error| self.poison_codec(error))?;
                        if nonempty_string(value.get("method")).is_none() {
                            self.poisoned = true;
                            return Err(CodexError::Protocol(
                                "unsolicited completion read response",
                            ));
                        }
                        self.apply_event_or_poison(&value, &frame)?;
                        self.completion_read = if self.bootstrap_ready() {
                            CompletionReadState::Draining {
                                thread_id,
                                session_id,
                                turn_id,
                                deadline,
                            }
                        } else {
                            CompletionReadState::Inconclusive
                        };
                        Ok(BootstrapReadPoll::Advanced)
                    }
                    Ok(AvailableLine::EndOfStream) | Err(_) => {
                        self.poisoned = true;
                        Err(CodexError::TransportUncertain)
                    }
                }
            }
            CompletionReadState::Inconclusive => {
                self.completion_read = CompletionReadState::Inconclusive;
                Ok(BootstrapReadPoll::Pending)
            }
            CompletionReadState::Uncertain => Err(CodexError::TransportUncertain),
        }
    }

    fn require_fresh_thread(&self) -> Result<(), CodexError> {
        if !self.initialized || self.poisoned || self.thread.is_some() {
            Err(CodexError::InvalidState(
                "resource cannot create another native binding",
            ))
        } else {
            Ok(())
        }
    }

    fn thread_settings(&self) -> Value {
        json!({
            "model": self.config.model,
            "cwd": self.config.cwd,
            "approvalPolicy": self.config.approval_policy.wire(),
            "sandbox": self.config.sandbox.request_wire(),
            "ephemeral": false,
            "serviceName": "podbay",
            "config": {"model_reasoning_effort": self.config.effort},
        })
    }

    fn validate_effective_thread(
        &self,
        value: &Value,
        expected_id: Option<&str>,
    ) -> Result<NativeThread, CodexError> {
        let thread = self.validate_thread(value.get("thread"), expected_id)?;
        if value.get("model").and_then(Value::as_str) != Some(self.config.model.as_str()) {
            return Err(CodexError::Mismatch("Codex selected another model"));
        }
        if value.get("reasoningEffort").and_then(Value::as_str) != Some(self.config.effort.as_str())
        {
            return Err(CodexError::Mismatch("Codex selected another effort"));
        }
        if value.get("approvalPolicy").and_then(Value::as_str)
            != Some(self.config.approval_policy.wire())
        {
            return Err(CodexError::Mismatch(
                "Codex selected another approval policy",
            ));
        }
        if value.pointer("/sandbox/type").and_then(Value::as_str)
            != Some(self.config.sandbox.response_type())
        {
            return Err(CodexError::Mismatch("Codex selected another sandbox"));
        }
        if !same_path(value.get("cwd"), &self.config.cwd) {
            return Err(CodexError::Mismatch("Codex selected another cwd"));
        }
        Ok(thread)
    }

    fn validate_read_thread(
        &self,
        value: &Value,
        expected_id: &str,
    ) -> Result<NativeThread, CodexError> {
        self.validate_thread(value.get("thread"), Some(expected_id))
    }

    fn validate_thread(
        &self,
        value: Option<&Value>,
        expected_id: Option<&str>,
    ) -> Result<NativeThread, CodexError> {
        let value = value.ok_or(CodexError::Protocol("thread response omitted thread"))?;
        let thread_id = nonempty_string(value.get("id"))
            .ok_or(CodexError::Protocol("thread response omitted id"))?;
        let session_id = nonempty_string(value.get("sessionId"))
            .ok_or(CodexError::Protocol("thread response omitted session id"))?;
        if expected_id.is_some_and(|expected| expected != thread_id) {
            return Err(CodexError::Mismatch("Codex returned another native thread"));
        }
        if !same_path(value.get("cwd"), &self.config.cwd) {
            return Err(CodexError::Mismatch("Codex returned another native cwd"));
        }
        if let Some(model) = value.get("model").and_then(Value::as_str) {
            if model != self.config.model {
                return Err(CodexError::Mismatch("thread records another model"));
            }
        }
        if let Some(effort) = value.get("reasoningEffort").and_then(Value::as_str) {
            if effort != self.config.effort {
                return Err(CodexError::Mismatch("thread records another effort"));
            }
        }
        if !value.get("turns").is_some_and(Value::is_array) {
            return Err(CodexError::Protocol("thread response omitted turns"));
        }
        let status = match value.pointer("/status/type").and_then(Value::as_str) {
            Some("notLoaded") => ThreadStatus::NotLoaded,
            Some("idle") => ThreadStatus::Idle,
            Some("active") => ThreadStatus::Active,
            Some("systemError") => ThreadStatus::SystemError,
            _ => return Err(CodexError::Protocol("thread response has unknown status")),
        };
        Ok(NativeThread {
            thread_id: thread_id.to_owned(),
            session_id: session_id.to_owned(),
            status,
        })
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), CodexError> {
        let bytes = encode(&json!({"method":method,"params":params})).map_err(CodexError::Codec)?;
        if self.io.write_line(&bytes).is_err() {
            self.poisoned = true;
            return Err(CodexError::TransportUncertain);
        }
        Ok(())
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, CodexError> {
        if self.poisoned {
            return Err(CodexError::InvalidState("native connection is unavailable"));
        }
        if matches!(
            self.completion_read,
            CompletionReadState::PendingWrite { .. }
                | CompletionReadState::AwaitingReply { .. }
                | CompletionReadState::Draining { .. }
        ) {
            return Err(CodexError::InvalidState(
                "completion read owns the native RPC",
            ));
        }
        let id = self.next_id;
        self.next_id = id
            .checked_add(1)
            .ok_or(CodexError::InvalidState("RPC id exhausted"))?;
        let bytes =
            encode(&json!({"id":id,"method":method,"params":params})).map_err(CodexError::Codec)?;
        if self.io.write_line(&bytes).is_err() {
            self.poisoned = true;
            return Err(CodexError::TransportUncertain);
        }
        loop {
            let line = self.read_frame()?;
            let value = decode(&line).map_err(|error| self.poison_codec(error))?;
            if nonempty_string(value.get("method")).is_some() {
                if self.queued.len() >= MAX_PENDING_NOTIFICATIONS {
                    self.poisoned = true;
                    return Err(CodexError::Protocol("notification backlog exceeded"));
                }
                self.queued.push_back(QueuedNotification {
                    value,
                    raw_jsonl: line,
                });
                continue;
            }
            if value.get("id").and_then(Value::as_u64) != Some(id) {
                self.poisoned = true;
                return Err(CodexError::Protocol("unmatched RPC response"));
            }
            if let Some(result) = value.get("result") {
                if value.get("error").is_some() {
                    self.poisoned = true;
                    return Err(CodexError::Protocol("RPC returned result and error"));
                }
                return Ok(result.clone());
            }
            let code = value.pointer("/error/code").and_then(Value::as_i64);
            self.poisoned = true;
            return code.map_or(
                Err(CodexError::Protocol(
                    "RPC response omitted result and error",
                )),
                |code| Err(CodexError::RemoteError(code)),
            );
        }
    }

    fn read_frame(&mut self) -> Result<Vec<u8>, CodexError> {
        match self.io.read_line() {
            Ok(Some(frame)) => Ok(frame),
            Ok(None) | Err(_) => {
                self.poisoned = true;
                Err(CodexError::TransportUncertain)
            }
        }
    }

    fn poison_codec(&mut self, error: CodecError) -> CodexError {
        self.poisoned = true;
        CodexError::Codec(error)
    }

    fn apply_queued(&mut self) -> Result<(), CodexError> {
        while let Some(event) = self.queued.pop_front() {
            self.apply_event_or_poison(&event.value, &event.raw_jsonl)?;
        }
        Ok(())
    }

    fn retire_resolved_requests(&mut self) {
        if self.status_waiting
            || matches!(
                self.native_status,
                ThreadStatus::NotLoaded | ThreadStatus::SystemError
            )
        {
            return;
        }
        let resolved: Vec<_> = self
            .pending_requests
            .iter()
            .filter(|(_, request)| request.stage == NativeRequestStage::ResolvedAwaitingStatus)
            .map(|(key, _)| key.clone())
            .collect();
        for key in resolved {
            self.pending_requests.remove(&key);
            self.retired_requests.insert(key);
        }
    }

    fn apply_event_or_poison(&mut self, event: &Value, raw_jsonl: &[u8]) -> Result<(), CodexError> {
        let exact_bound_thread = self.thread.as_ref().is_some_and(|thread| {
            event.pointer("/params/threadId").and_then(Value::as_str)
                == Some(thread.thread_id.as_str())
        });
        if let Err(error) = self.apply_event(event) {
            self.poisoned = true;
            return Err(error);
        }
        if self.applied_notifications.len() >= MAX_APPLIED_NOTIFICATIONS {
            self.poisoned = true;
            return Err(CodexError::Protocol("native observation backlog exceeded"));
        }
        if raw_jsonl.is_empty() || raw_jsonl.len() > MAX_FRAME_BYTES {
            self.poisoned = true;
            return Err(CodexError::Protocol(
                "native observation raw frame is unbounded",
            ));
        }
        let private_jsonl = raw_jsonl.to_vec();
        let next_bytes = self
            .applied_notification_bytes
            .checked_add(private_jsonl.len())
            .filter(|value| *value <= MAX_APPLIED_NOTIFICATION_BYTES);
        let Some(next_bytes) = next_bytes else {
            self.poisoned = true;
            return Err(CodexError::Protocol(
                "native observation byte backlog exceeded",
            ));
        };
        let (mut kind, mut status) = classify_native_observation(event);
        if !exact_bound_thread || self.external_conflict {
            kind = NativeObservationKind::Opaque;
            status = None;
        }
        self.applied_notifications
            .push_back(AppliedNativeNotification {
                private_jsonl,
                kind,
                status,
                external_conflict: self.external_conflict,
            });
        self.applied_notification_bytes = next_bytes;
        Ok(())
    }

    fn apply_event(&mut self, event: &Value) -> Result<(), CodexError> {
        let method = nonempty_string(event.get("method"))
            .ok_or(CodexError::Protocol("native event omitted method"))?;
        let bound = match self.thread.as_ref() {
            Some(thread) => thread.thread_id.as_str(),
            None => return Ok(()),
        };
        let params = event
            .get("params")
            .and_then(Value::as_object)
            .ok_or(CodexError::Protocol("native event omitted params"))?;
        let thread_id = params.get("threadId").and_then(Value::as_str);
        if thread_id != Some(bound) {
            return Ok(());
        }
        if event.get("id").is_some() {
            let request =
                parse_pending_request(event, self.identity.resource_epoch).map_err(|error| {
                    match error {
                        NativeRequestParseError::MissingIdentity => {
                            CodexError::Protocol("native request omitted identity")
                        }
                        NativeRequestParseError::InvalidRequestId => {
                            CodexError::Protocol("native request has invalid id")
                        }
                    }
                })?;
            let key = request.key();
            if self.pending_requests.len() >= MAX_PENDING_REQUESTS {
                self.poisoned = true;
                return Err(CodexError::Protocol("pending host request limit exceeded"));
            }
            if self.retired_requests.contains(&key) || self.pending_requests.contains_key(&key) {
                return Err(CodexError::Protocol("native request id was reused"));
            }
            self.pending_requests.insert(key, request);
            return Ok(());
        }
        match method {
            "serverRequest/resolved" => {
                let key = request_key(params.get("requestId"))
                    .ok_or(CodexError::Protocol("resolved request omitted id"))?;
                if let Some(request) = self.pending_requests.get_mut(&key) {
                    request.stage = NativeRequestStage::ResolvedAwaitingStatus;
                }
            }
            "thread/status/changed" => {
                let status = params.get("status");
                self.native_status = match status
                    .and_then(|value| value.get("type"))
                    .and_then(Value::as_str)
                {
                    Some("notLoaded") => ThreadStatus::NotLoaded,
                    Some("idle") => ThreadStatus::Idle,
                    Some("active") => ThreadStatus::Active,
                    Some("systemError") => ThreadStatus::SystemError,
                    _ => {
                        self.poisoned = true;
                        return Err(CodexError::Protocol("thread status update is invalid"));
                    }
                };
                if let Some(thread) = self.thread.as_mut() {
                    thread.status = self.native_status;
                }
                if self.native_status == ThreadStatus::Idle {
                    self.observed_active_turn_id = None;
                }
                self.status_waiting = waiting_flag(status)?;
                self.retire_resolved_requests();
                if self.native_status == ThreadStatus::Idle
                    && matches!(self.bootstrap, BootstrapState::Completed { .. })
                {
                    self.idle_after_completion = true;
                } else {
                    self.idle_after_completion = false;
                }
            }
            "turn/started" | "turn/completed" => {
                let turn_id = nonempty_string(params.get("turn").and_then(|turn| turn.get("id")))
                    .ok_or(CodexError::Protocol("turn notification omitted id"))?;
                if let BootstrapState::Submitted { turn_id: bootstrap } = &self.bootstrap {
                    if turn_id != bootstrap {
                        self.external_conflict = true;
                        return Ok(());
                    }
                    if method == "turn/started" {
                        self.observed_active_turn_id = Some(turn_id.to_owned());
                        return Ok(());
                    }
                    let status = params
                        .get("turn")
                        .and_then(|turn| turn.get("status"))
                        .and_then(Value::as_str);
                    self.bootstrap = match status {
                        Some("completed") => BootstrapState::Completed {
                            turn_id: turn_id.to_owned(),
                        },
                        Some("failed") => BootstrapState::Failed {
                            turn_id: turn_id.to_owned(),
                        },
                        Some("interrupted") => BootstrapState::Interrupted {
                            turn_id: turn_id.to_owned(),
                        },
                        _ => {
                            return Err(CodexError::Protocol(
                                "bootstrap completion status is invalid",
                            ));
                        }
                    };
                    self.observed_active_turn_id = None;
                    self.idle_after_completion = false;
                    return Ok(());
                }
                if self.owned_active_turn_id.as_deref() != Some(turn_id) {
                    self.external_conflict = true;
                    return Ok(());
                }
                if method == "turn/started" {
                    self.observed_active_turn_id = Some(turn_id.to_owned());
                    return Ok(());
                }
                let status = params
                    .get("turn")
                    .and_then(|turn| turn.get("status"))
                    .and_then(Value::as_str);
                let terminal = match status {
                    Some("completed") => LaterTurnTerminalStatus::Completed,
                    Some("failed") => LaterTurnTerminalStatus::Failed,
                    Some("interrupted") => LaterTurnTerminalStatus::Interrupted,
                    _ => return Err(CodexError::Protocol("turn completion status is invalid")),
                };
                if matches!(
                    self.interrupt,
                    InterruptState::Requested { .. } | InterruptState::Uncertain { .. }
                ) {
                    self.interrupt = if status == Some("interrupted") {
                        InterruptState::Settled {
                            turn_id: turn_id.to_owned(),
                        }
                    } else {
                        InterruptState::EndedWithoutInterrupt {
                            turn_id: turn_id.to_owned(),
                        }
                    };
                }
                let session_id = self
                    .thread
                    .as_ref()
                    .ok_or(CodexError::InvalidState("native thread disappeared"))?
                    .session_id
                    .clone();
                self.last_later_turn_completion = Some(LaterTurnCompletionObservation {
                    native_thread_id: bound.to_owned(),
                    native_session_id: session_id,
                    native_turn_id: turn_id.to_owned(),
                    status: terminal,
                });
                self.owned_active_turn_id = None;
                self.observed_active_turn_id = None;
            }
            "model/rerouted" => self.external_conflict = true,
            _ => {}
        }
        Ok(())
    }
}

impl CodexResource<crate::process_transport::ProcessJsonlTransport> {
    /// Recheck only the owned direct child's kernel identity. This keeps the
    /// mutable JSONL writer private while the pod verifies process liveness.
    pub fn attest_owned_child_birth(
        &mut self,
    ) -> io::Result<crate::process_transport::KernelChildBirthObservation> {
        self.io.attest_kernel_birth()
    }

    /// Observe only the owned direct child's exit. A returned observation is
    /// from the retained Child handle; None means it was still running then.
    pub fn observe_owned_child_exit(
        &mut self,
    ) -> io::Result<Option<crate::process_transport::ChildExitObservation>> {
        self.io.observe_exit()
    }

    /// Request bounded direct-child termination and return only an observed
    /// reap. Errors do not prove exit; no raw JSONL writer is exposed.
    pub fn dispose_owned_child(
        &mut self,
    ) -> io::Result<crate::process_transport::ChildExitObservation> {
        self.io.dispose()
    }
}

fn request_key(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(text) if !text.is_empty() => Some(format!("s:{text}")),
        Value::Number(number) if number.is_i64() || number.is_u64() => Some(format!("n:{number}")),
        _ => None,
    }
}

fn waiting_flag(status: Option<&Value>) -> Result<bool, CodexError> {
    let status = status.ok_or(CodexError::Protocol("native status is missing"))?;
    match status.get("type").and_then(Value::as_str) {
        Some("active") => {
            let flags = status
                .get("activeFlags")
                .and_then(Value::as_array)
                .ok_or(CodexError::Protocol("active status omitted flags"))?;
            if flags.len() > 64 {
                return Err(CodexError::Protocol("active status has too many flags"));
            }
            let mut waiting = false;
            for flag in flags {
                match flag.as_str() {
                    Some("waitingOnApproval" | "waitingOnUserInput") => waiting = true,
                    Some(_) => waiting = true, // unknown flag cannot prove dispatchable status
                    None => return Err(CodexError::Protocol("active status flag is invalid")),
                }
            }
            Ok(waiting)
        }
        Some("notLoaded" | "idle" | "systemError") => Ok(false),
        _ => Err(CodexError::Protocol("native status type is invalid")),
    }
}

fn classify_native_observation(
    event: &Value,
) -> (NativeObservationKind, Option<NativeObservationStatus>) {
    let method = event.get("method").and_then(Value::as_str).unwrap_or("");
    let status = match method {
        "thread/status/changed" => {
            match event.pointer("/params/status/type").and_then(Value::as_str) {
                Some("idle") => Some(NativeObservationStatus::Idle),
                Some("active") => Some(
                    if event
                        .pointer("/params/status/activeFlags")
                        .and_then(Value::as_array)
                        .is_some_and(|flags| !flags.is_empty())
                    {
                        NativeObservationStatus::Waiting
                    } else {
                        NativeObservationStatus::Active
                    },
                ),
                Some("systemError") => Some(NativeObservationStatus::SystemError),
                _ => None,
            }
        }
        "turn/started" => Some(NativeObservationStatus::Active),
        "turn/completed" => match event.pointer("/params/turn/status").and_then(Value::as_str) {
            Some("completed") => Some(NativeObservationStatus::Completed),
            Some("failed") => Some(NativeObservationStatus::Failed),
            Some("interrupted") => Some(NativeObservationStatus::Interrupted),
            _ => None,
        },
        _ => None,
    };
    let kind = match method {
        "item/tool/requestUserInput" => NativeObservationKind::Question,
        "item/commandExecution/requestApproval"
        | "item/fileChange/requestApproval"
        | "item/permissions/requestApproval" => NativeObservationKind::Permission,
        "thread/status/changed" | "turn/started" | "turn/completed" | "serverRequest/resolved" => {
            NativeObservationKind::Status
        }
        method if method.starts_with("item/") && event.get("id").is_none() => {
            NativeObservationKind::Output
        }
        _ => NativeObservationKind::Opaque,
    };
    (kind, status)
}

fn nonempty_string(value: Option<&Value>) -> Option<&str> {
    value?
        .as_str()
        .filter(|text| !text.is_empty() && text.len() <= 512)
}

fn completion_target_matches(
    state: &CompletionReadState,
    thread: &str,
    session: &str,
    turn: &str,
) -> bool {
    match state {
        CompletionReadState::PendingWrite {
            thread_id,
            session_id,
            turn_id,
            ..
        }
        | CompletionReadState::AwaitingReply {
            thread_id,
            session_id,
            turn_id,
            ..
        }
        | CompletionReadState::Draining {
            thread_id,
            session_id,
            turn_id,
            ..
        }
        | CompletionReadState::Verified {
            thread_id,
            session_id,
            turn_id,
            ..
        } => thread_id == thread && session_id == session && turn_id == turn,
        CompletionReadState::NotStarted
        | CompletionReadState::Inconclusive
        | CompletionReadState::Uncertain => true,
    }
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_native_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn same_path(value: Option<&Value>, expected: &Path) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|text| Path::new(text) == expected)
}

#[cfg(test)]
mod split_thread_tests {
    use super::*;

    fn frame(value: Value) -> Vec<u8> {
        let mut encoded = serde_json::to_vec(&value).unwrap();
        encoded.push(b'\n');
        encoded
    }

    struct FakeTransport {
        reads: VecDeque<Vec<u8>>,
        writes: Vec<Vec<u8>>,
    }

    impl JsonlTransport for FakeTransport {
        fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
            self.writes.push(line.to_vec());
            Ok(())
        }

        fn read_line(&mut self) -> io::Result<Option<Vec<u8>>> {
            Ok(self.reads.pop_front())
        }
    }

    #[test]
    fn thread_start_can_stop_before_any_bootstrap_turn() {
        let cwd = PathBuf::from("/tmp/podbay-codex-thread-fixture");
        let io = FakeTransport {
            reads: VecDeque::from([
                frame(json!({
                    "id": 1,
                    "result": {
                        "codexHome": "/tmp/codex.fixture",
                        "platformFamily": "unix",
                        "platformOs": "linux",
                        "userAgent": "fixture"
                    }
                })),
                frame(json!({
                    "id": 2,
                    "result": {
                        "thread": {
                            "id": "thread.fixture",
                            "sessionId": "session.fixture",
                            "cwd": cwd,
                            "status": {"type": "idle"},
                            "turns": []
                        },
                        "model": "gpt-6-sol",
                        "reasoningEffort": "medium",
                        "approvalPolicy": "never",
                        "sandbox": {"type": "dangerFullAccess"},
                        "cwd": cwd
                    }
                })),
            ]),
            writes: Vec::new(),
        };
        let identity = ResourceIdentity {
            session_id: SessionId::try_from("session.fixture").unwrap(),
            run_id: RunId::try_from("run.fixture").unwrap(),
            attempt_id: AttemptId::try_from("attempt.fixture").unwrap(),
            pod_id: PodId::try_from("pod.fixture").unwrap(),
            resource_id: ResourceId::try_from("resource.fixture").unwrap(),
            resource_epoch: Epoch::new(1).unwrap(),
        };
        let config = PinnedCodexConfig::new(
            "gpt-6-sol",
            "medium",
            cwd,
            ApprovalPolicy::Never,
            Sandbox::DangerFullAccess,
        )
        .unwrap();
        let mut resource = CodexResource::new(io, identity, config);
        resource.initialize().unwrap();
        let thread = resource.start_thread_without_turn().unwrap();
        assert_eq!(thread.thread_id, "thread.fixture");
        assert_eq!(resource.native_thread(), Some(&thread));
        assert_eq!(resource.bootstrap_state(), &BootstrapState::NotStarted);
        assert!(!resource.bootstrap_ready());
        let methods = resource
            .transport()
            .writes
            .iter()
            .map(|line| {
                serde_json::from_slice::<Value>(line).unwrap()["method"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(methods, ["initialize", "initialized", "thread/start"]);
        assert!(matches!(
            resource.start_new("bootstrap", "message.fixture"),
            Err(CodexError::InvalidState(_))
        ));
        assert_eq!(resource.transport().writes.len(), 3);
    }

    #[test]
    fn final_preflight_after_idle_read_refuses_before_turn_start() {
        let cwd = PathBuf::from("/tmp/podbay-codex-preflight-fixture");
        let thread = json!({
            "id": "thread.fixture",
            "sessionId": "session.fixture",
            "cwd": cwd,
            "status": {"type": "idle"},
            "turns": []
        });
        let io = FakeTransport {
            reads: VecDeque::from([
                frame(json!({"id":1,"result":{
                    "codexHome":"/tmp/codex.fixture","platformFamily":"unix",
                    "platformOs":"linux","userAgent":"fixture"}})),
                frame(json!({"id":2,"result":{
                    "thread":thread,"model":"gpt-6-sol","reasoningEffort":"medium",
                    "approvalPolicy":"never","sandbox":{"type":"dangerFullAccess"},
                    "cwd":cwd}})),
                frame(json!({"id":3,"result":{"thread":thread}})),
            ]),
            writes: Vec::new(),
        };
        let identity = ResourceIdentity {
            session_id: SessionId::try_from("session.fixture").unwrap(),
            run_id: RunId::try_from("run.fixture").unwrap(),
            attempt_id: AttemptId::try_from("attempt.fixture").unwrap(),
            pod_id: PodId::try_from("pod.fixture").unwrap(),
            resource_id: ResourceId::try_from("resource.fixture").unwrap(),
            resource_epoch: Epoch::new(1).unwrap(),
        };
        let config = PinnedCodexConfig::new(
            "gpt-6-sol",
            "medium",
            cwd,
            ApprovalPolicy::Never,
            Sandbox::DangerFullAccess,
        )
        .unwrap();
        let mut resource = CodexResource::new(io, identity.clone(), config);
        resource.initialize().unwrap();
        resource.start_thread_without_turn().unwrap();
        resource
            .install_writer_epoch_from_trusted_boundary(Epoch::new(1).unwrap())
            .unwrap();
        let permit = WriterPermit::from_trusted_boundary(identity, Epoch::new(1).unwrap());
        let mut called = false;
        assert!(matches!(
            resource.submit_bootstrap_after_checkpoint_checked(
                &permit,
                "thread.fixture",
                "session.fixture",
                "bootstrap",
                "message.fixture",
                |_| {
                    called = true;
                    Err(CodexError::Blocked(BlockReason::ObservationUnknown))
                },
            ),
            Err(CodexError::Blocked(BlockReason::ObservationUnknown))
        ));
        assert!(called);
        assert_eq!(resource.bootstrap_state(), &BootstrapState::Unknown);
        let methods = resource
            .transport()
            .writes
            .iter()
            .map(|line| {
                serde_json::from_slice::<Value>(line).unwrap()["method"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            methods,
            ["initialize", "initialized", "thread/start", "thread/read"]
        );
    }
}
