use std::collections::{HashSet, VecDeque};
use std::io;
use std::path::{Path, PathBuf};

use podbay_core::{AttemptId, Epoch, PodId, ResourceId, RunId, SessionId};
use serde_json::{Value, json};

use crate::codec::{CodecError, decode, encode};

const MAX_PENDING_NOTIFICATIONS: usize = 1024;
const MAX_PENDING_REQUESTS: usize = 128;

/// A pod-owned byte transport. Implementations must enforce
/// `MAX_FRAME_BYTES` while assembling one complete JSONL frame per read;
/// this crate supplies no process launcher or socket client.
pub trait JsonlTransport {
    fn write_line(&mut self, line: &[u8]) -> io::Result<()>;
    fn read_line(&mut self) -> io::Result<Option<Vec<u8>>>;
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
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartReceipt {
    pub thread: NativeThread,
    pub bootstrap_turn_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodexError {
    InvalidInput(&'static str),
    InvalidState(&'static str),
    Protocol(&'static str),
    Codec(CodecError),
    TransportUncertain,
    RemoteError(i64),
    Mismatch(&'static str),
}

/// Only one RPC is outstanding at a time. Notifications arriving before its
/// response are retained in wire order and applied once the turn is known.
pub struct CodexResource<T: JsonlTransport> {
    io: T,
    identity: ResourceIdentity,
    config: PinnedCodexConfig,
    next_id: u64,
    initialized: bool,
    poisoned: bool,
    thread: Option<NativeThread>,
    bootstrap: BootstrapState,
    pending_requests: HashSet<String>,
    native_status: ThreadStatus,
    status_waiting: bool,
    idle_after_completion: bool,
    external_conflict: bool,
    queued: VecDeque<Value>,
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
            pending_requests: HashSet::new(),
            native_status: ThreadStatus::NotLoaded,
            status_waiting: false,
            idle_after_completion: false,
            external_conflict: false,
            queued: VecDeque::new(),
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

    /// This settles only the bootstrap requirement. Full dispatch readiness
    /// additionally needs PodBay's authority, writer lease and fresh liveness.
    pub fn bootstrap_ready(&self) -> bool {
        matches!(self.bootstrap, BootstrapState::Completed { .. })
            && self.pending_requests.is_empty()
            && self.native_status == ThreadStatus::Idle
            && self.idle_after_completion
            && !self.status_waiting
            && !self.external_conflict
            && !self.poisoned
    }

    pub fn pending_request_count(&self) -> usize {
        self.pending_requests.len()
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

    /// Creates one native thread, then submits one bootstrap turn. Any lost
    /// reply leaves this resource unusable for another start until reconciled.
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
        let read = self.request(
            "thread/read",
            json!({"threadId":expected_thread_id,"includeTurns":true}),
        )?;
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
        let mut params = self.thread_settings();
        let map = params
            .as_object_mut()
            .ok_or(CodexError::Protocol("thread settings are not an object"))?;
        map.insert("threadId".into(), json!(expected_thread_id));
        map.remove("ephemeral");
        map.remove("serviceName");
        let result = self.request("thread/resume", params)?;
        let thread = self
            .validate_effective_thread(&result, Some(expected_thread_id))
            .inspect_err(|_| {
                self.poisoned = true;
            })?;
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
        let result = self.request(
            "thread/read",
            json!({"threadId":expected,"includeTurns":true}),
        )?;
        let thread = self
            .validate_read_thread(&result, &expected)
            .inspect_err(|_| {
                self.poisoned = true;
            })?;
        self.thread = Some(thread.clone());
        self.native_status = thread.status;
        self.status_waiting = waiting_flag(result.pointer("/thread/status"));
        if thread.status == ThreadStatus::Idle
            && matches!(self.bootstrap, BootstrapState::Completed { .. })
        {
            self.idle_after_completion = true;
        }
        self.apply_queued()?;
        Ok(thread)
    }

    /// Handles one native event frame. Server requests are observed and block
    /// readiness; this atom deliberately has no permission-answer API.
    pub fn poll_once(&mut self) -> Result<(), CodexError> {
        if self.poisoned || !self.initialized {
            return Err(CodexError::InvalidState("native connection is unavailable"));
        }
        self.apply_queued()?;
        let line = self.read_frame()?;
        let value = decode(&line).map_err(|error| self.poison_codec(error))?;
        if nonempty_string(value.get("method")).is_none() {
            self.poisoned = true;
            return Err(CodexError::Protocol("unsolicited RPC response"));
        }
        self.apply_event_or_poison(&value)
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
                self.queued.push_back(value);
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
            self.apply_event_or_poison(&event)?;
        }
        Ok(())
    }

    fn apply_event_or_poison(&mut self, event: &Value) -> Result<(), CodexError> {
        let result = self.apply_event(event);
        if result.is_err() {
            self.poisoned = true;
        }
        result
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
            let key = request_key(event.get("id"))
                .ok_or(CodexError::Protocol("native request has invalid id"))?;
            if self.pending_requests.len() >= MAX_PENDING_REQUESTS {
                self.poisoned = true;
                return Err(CodexError::Protocol("pending host request limit exceeded"));
            }
            self.pending_requests.insert(key);
            return Ok(());
        }
        match method {
            "serverRequest/resolved" => {
                let key = request_key(params.get("requestId"))
                    .ok_or(CodexError::Protocol("resolved request omitted id"))?;
                self.pending_requests.remove(&key);
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
                self.status_waiting = waiting_flag(status);
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
                let expected = match &self.bootstrap {
                    BootstrapState::Submitted { turn_id } => turn_id.as_str(),
                    _ => {
                        self.external_conflict = true;
                        return Ok(());
                    }
                };
                if turn_id != expected {
                    self.external_conflict = true;
                    return Ok(());
                }
                if method == "turn/completed" {
                    let status = params
                        .get("turn")
                        .and_then(|turn| turn.get("status"))
                        .and_then(Value::as_str);
                    self.bootstrap = if status == Some("completed") {
                        BootstrapState::Completed {
                            turn_id: turn_id.to_owned(),
                        }
                    } else {
                        BootstrapState::Failed {
                            turn_id: turn_id.to_owned(),
                        }
                    };
                    self.idle_after_completion = false;
                }
            }
            "model/rerouted" => self.external_conflict = true,
            _ => {}
        }
        Ok(())
    }
}

fn request_key(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(text) if !text.is_empty() => Some(format!("s:{text}")),
        Value::Number(number) if number.is_i64() || number.is_u64() => Some(format!("n:{number}")),
        _ => None,
    }
}

fn waiting_flag(status: Option<&Value>) -> bool {
    status
        .and_then(|value| value.get("activeFlags"))
        .and_then(Value::as_array)
        .is_some_and(|flags| {
            flags.iter().any(|flag| {
                matches!(
                    flag.as_str(),
                    Some("waitingOnApproval" | "waitingOnUserInput")
                )
            })
        })
}

fn nonempty_string(value: Option<&Value>) -> Option<&str> {
    value?
        .as_str()
        .filter(|text| !text.is_empty() && text.len() <= 512)
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn same_path(value: Option<&Value>, expected: &Path) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|text| Path::new(text) == expected)
}
