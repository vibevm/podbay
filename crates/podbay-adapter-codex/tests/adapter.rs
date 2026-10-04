use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::path::PathBuf;

use podbay_adapter_codex::{
    AnswerWriteOutcome, ApprovalDecision, ApprovalPolicy, AuthorizedAnswerPermit, AvailableLine,
    AvailableWrite, BlockReason, BootstrapReadPoll, BootstrapState, BootstrapTurnStage, CodecError,
    CodexError, CodexResource, InterruptState, JsonlTransport, MAX_FRAME_BYTES, NativeAnswer,
    NativeObservationKind, NativeRequestKind, NativeRequestStage, NativeRpcId, PinnedCodexConfig,
    ResourceIdentity, Sandbox, TESTED_CODEX_CLI_VERSION, TESTED_V2_SCHEMA_SHA256, TurnMode,
    TurnSubmissionStage, WriterPermit, decode, encode,
};
use podbay_core::{AttemptId, Epoch, PodId, ResourceId, RunId, SessionId};
use serde_json::{Value, json};

#[derive(Default)]
struct FakeTransport {
    reads: VecDeque<Vec<u8>>,
    writes: Vec<Value>,
    fail_answer_write: bool,
    answer_write_attempts: usize,
    pending_probe_writes: usize,
    eof_on_empty: bool,
}

impl FakeTransport {
    fn with_reads(reads: impl IntoIterator<Item = Value>) -> Self {
        Self {
            reads: reads
                .into_iter()
                .map(|value| encode(&value).unwrap())
                .collect(),
            writes: Vec::new(),
            fail_answer_write: false,
            answer_write_attempts: 0,
            pending_probe_writes: 0,
            eof_on_empty: false,
        }
    }

    fn with_raw_read(raw: Vec<u8>) -> Self {
        Self {
            reads: VecDeque::from([raw]),
            writes: Vec::new(),
            fail_answer_write: false,
            answer_write_attempts: 0,
            pending_probe_writes: 0,
            eof_on_empty: false,
        }
    }

    fn fail_answer_write(mut self) -> Self {
        self.fail_answer_write = true;
        self
    }

    fn methods(&self) -> Vec<&str> {
        self.writes
            .iter()
            .filter_map(|value| value.get("method").and_then(Value::as_str))
            .collect()
    }
}

impl JsonlTransport for FakeTransport {
    fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        let value = decode(line).unwrap();
        if value.get("method").is_none() {
            self.answer_write_attempts += 1;
            self.writes.push(value);
            if self.fail_answer_write {
                self.fail_answer_write = false;
                return Err(io::Error::other("ambiguous response write"));
            }
            return Ok(());
        }
        self.writes.push(value);
        Ok(())
    }

    fn read_line(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.reads.pop_front())
    }

    fn try_read_line(&mut self) -> io::Result<AvailableLine> {
        match self.reads.pop_front() {
            Some(frame) if frame.is_empty() => Ok(AvailableLine::Pending),
            Some(frame) if frame == [0] => Ok(AvailableLine::IncompleteFrame),
            Some(frame) => Ok(AvailableLine::Frame(frame)),
            None if self.eof_on_empty => Ok(AvailableLine::EndOfStream),
            None => Ok(AvailableLine::Pending),
        }
    }

    fn try_write_line(&mut self, line: &[u8]) -> io::Result<AvailableWrite> {
        if self.pending_probe_writes > 0 {
            self.pending_probe_writes -= 1;
            return Ok(AvailableWrite::Pending);
        }
        self.write_line(line)?;
        Ok(AvailableWrite::Written)
    }
}

fn identity(resource: &str) -> ResourceIdentity {
    ResourceIdentity {
        session_id: SessionId::try_from("session.one").unwrap(),
        run_id: RunId::try_from("run.one").unwrap(),
        attempt_id: AttemptId::try_from("attempt.one").unwrap(),
        pod_id: PodId::try_from("pod.one").unwrap(),
        resource_id: ResourceId::try_from(resource).unwrap(),
        resource_epoch: Epoch::new(1).unwrap(),
    }
}

fn config() -> PinnedCodexConfig {
    PinnedCodexConfig::new(
        "gpt-6-sol",
        "medium",
        PathBuf::from("/tmp/podbay-codex-work"),
        ApprovalPolicy::OnRequest,
        Sandbox::WorkspaceWrite,
    )
    .unwrap()
}

fn initialized() -> Value {
    json!({"id":1,"result":{
        "codexHome":"/tmp/codex-home",
        "platformFamily":"unix",
        "platformOs":"linux",
        "userAgent":"podbay/0.1.0"
    }})
}

fn native_thread(id: &str, status: &str) -> Value {
    let native_status = if status == "active" {
        json!({"type":"active","activeFlags":[]})
    } else {
        json!({"type":status})
    };
    json!({
        "id":id,
        "sessionId":id,
        "cwd":"/tmp/podbay-codex-work",
        "model":"gpt-6-sol",
        "reasoningEffort":"medium",
        "status":native_status,
        "turns":[]
    })
}

fn effective(id: u64, thread_id: &str) -> Value {
    json!({"id":id,"result":{
        "thread":native_thread(thread_id,"idle"),
        "cwd":"/tmp/podbay-codex-work",
        "model":"gpt-6-sol",
        "reasoningEffort":"medium",
        "approvalPolicy":"on-request",
        "sandbox":{"type":"workspaceWrite","writableRoots":["/tmp/podbay-codex-work"]}
    }})
}

fn turn_started_response() -> Value {
    json!({"id":3,"result":{"turn":{"id":"turn.bootstrap","status":"inProgress","items":[]}}})
}

fn completed(turn_id: &str, status: &str) -> Value {
    json!({"method":"turn/completed","params":{
        "threadId":"thread.one",
        "turn":{"id":turn_id,"status":status,"items":[]}
    }})
}

fn status(kind: &str, active_flags: &[&str]) -> Value {
    let state = if kind == "active" {
        json!({"type":"active","activeFlags":active_flags})
    } else {
        json!({"type":kind})
    };
    json!({"method":"thread/status/changed","params":{
        "threadId":"thread.one","status":state
    }})
}

fn read_response(id: u64, kind: &str, _active_turn_id: Option<&str>) -> Value {
    // Metadata-only thread/read always has an empty turns projection.
    json!({"id":id,"result":{"thread":native_thread("thread.one", kind)}})
}

fn work_turn_response(id: u64, turn_id: &str) -> Value {
    json!({"id":id,"result":{"turn":{"id":turn_id,"status":"inProgress","items":[]}}})
}

fn writer_permit(epoch: u64) -> WriterPermit {
    WriterPermit::from_trusted_boundary(identity("resource.structured"), Epoch::new(epoch).unwrap())
}

fn resource(reads: impl IntoIterator<Item = Value>) -> CodexResource<FakeTransport> {
    CodexResource::new(
        FakeTransport::with_reads(reads),
        identity("resource.structured"),
        config(),
    )
}

fn bootstrapped(extra: impl IntoIterator<Item = Value>) -> CodexResource<FakeTransport> {
    let mut reads = vec![
        initialized(),
        effective(2, "thread.one"),
        turn_started_response(),
        completed("turn.bootstrap", "completed"),
        status("idle", &[]),
    ];
    reads.extend(extra);
    let mut adapter = resource(reads);
    adapter.initialize().unwrap();
    adapter
        .start_new("Begin work", "bootstrap:session.one")
        .unwrap();
    adapter.poll_once().unwrap();
    adapter.poll_once().unwrap();
    assert!(adapter.bootstrap_ready());
    adapter
        .install_writer_epoch_from_trusted_boundary(Epoch::new(1).unwrap())
        .unwrap();
    adapter
}

fn command_request(id: i64) -> Value {
    json!({"id":id,"method":"item/commandExecution/requestApproval","params":{
        "threadId":"thread.one","turnId":"turn.bootstrap","itemId":"item.command",
        "startedAtMs":1,"kind":"command","command":"echo reviewed"
    }})
}

fn file_request(id: i64) -> Value {
    json!({"id":id,"method":"item/fileChange/requestApproval","params":{
        "threadId":"thread.one","turnId":"turn.bootstrap","itemId":"item.file",
        "startedAtMs":1,"grantRoot":"/tmp/podbay-codex-work"
    }})
}

fn permissions_request(id: i64) -> Value {
    json!({"id":id,"method":"item/permissions/requestApproval","params":{
        "threadId":"thread.one","turnId":"turn.bootstrap","itemId":"item.permissions",
        "startedAtMs":1,"cwd":"/tmp/podbay-codex-work",
        "permissions":{"network":{"enabled":true}}
    }})
}

fn user_input_request(id: i64) -> Value {
    json!({"id":id,"method":"item/tool/requestUserInput","params":{
        "threadId":"thread.one","turnId":"turn.bootstrap","itemId":"item.question",
        "isBlocking":true,"questions":[{"id":"question.one","header":"Choice",
        "question":"Which action?","options":[{"label":"A","description":"Option A"}]}]
    }})
}

#[test]
fn applied_native_fact_preserves_private_question_but_redacts_public_debug() {
    let mut adapter = resource([
        initialized(),
        effective(2, "thread.one"),
        user_input_request(70),
        turn_started_response(),
    ]);
    adapter.initialize().unwrap();
    adapter
        .start_new("Begin work", "bootstrap:session.one")
        .unwrap();
    let observed = adapter
        .take_applied_native_notification()
        .expect("queued request fact");
    assert_eq!(observed.kind(), NativeObservationKind::Question);
    assert!(String::from_utf8_lossy(observed.private_jsonl()).contains("Which action?"));
    let redacted = format!("{observed:?}");
    assert!(!redacted.contains("Which action?"));
    assert!(!redacted.contains("Option A"));
    assert!(adapter.take_applied_native_notification().is_none());
    assert_eq!(adapter.pending_request_count(), 1);

    let raw = b"{ \"method\" : \"item/agentMessage/delta\", \"params\": {\"threadId\":\"thread.one\",\"delta\":\"private output\"} }\n".to_vec();
    let mut io = FakeTransport::with_reads([
        initialized(),
        effective(2, "thread.one"),
        turn_started_response(),
    ]);
    io.reads.push_back(raw.clone());
    let mut adapter = CodexResource::new(io, identity("resource.structured"), config());
    adapter.initialize().unwrap();
    adapter
        .start_new("Begin work", "bootstrap:session.one")
        .unwrap();
    adapter.poll_available_once().unwrap();
    let observed = adapter.take_applied_native_notification().unwrap();
    assert_eq!(observed.kind(), NativeObservationKind::Output);
    assert_eq!(observed.private_jsonl(), raw);
    assert!(!format!("{observed:?}").contains("private output"));
}

#[test]
fn foreign_turn_completion_is_opaque_conflict_not_public_completed_status() {
    let mut adapter = resource([
        initialized(),
        effective(2, "thread.one"),
        turn_started_response(),
        completed("turn.other", "completed"),
    ]);
    adapter.initialize().unwrap();
    adapter
        .start_new("Begin work", "bootstrap:session.one")
        .unwrap();
    adapter.poll_available_once().unwrap();
    let observed = adapter.take_applied_native_notification().unwrap();
    assert_eq!(observed.kind(), NativeObservationKind::Opaque);
    assert_eq!(observed.status(), None);
    assert!(observed.external_conflict());
    assert!(!adapter.bootstrap_ready());

    let mut foreign_status = status("idle", &[]);
    foreign_status["params"]["threadId"] = json!("thread.other");
    let mut adapter = resource([
        initialized(),
        effective(2, "thread.one"),
        turn_started_response(),
        foreign_status,
    ]);
    adapter.initialize().unwrap();
    adapter
        .start_new("Begin work", "bootstrap:session.one")
        .unwrap();
    adapter.poll_available_once().unwrap();
    let observed = adapter.take_applied_native_notification().unwrap();
    assert_eq!(observed.kind(), NativeObservationKind::Opaque);
    assert_eq!(observed.status(), None);
}

#[test]
fn applied_native_fact_queue_has_a_byte_bound_before_publication() {
    let huge = json!({"method":"item/agentMessage/delta","params":{
        "threadId":"thread.one","delta":"x".repeat(4 * 1_048_576),
    }});
    let mut adapter = resource([
        initialized(),
        effective(2, "thread.one"),
        turn_started_response(),
        huge,
    ]);
    adapter.initialize().unwrap();
    adapter
        .start_new("Begin work", "bootstrap:session.one")
        .unwrap();
    assert_eq!(
        adapter.poll_available_once(),
        Err(CodexError::Protocol(
            "native observation byte backlog exceeded"
        )),
    );
    assert!(adapter.take_applied_native_notification().is_none());
    assert!(!adapter.bootstrap_ready());
}

fn pending_bootstrap_reads(request: Value, extra: impl IntoIterator<Item = Value>) -> Vec<Value> {
    let mut reads = vec![
        initialized(),
        effective(2, "thread.one"),
        turn_started_response(),
        request,
    ];
    reads.extend(extra);
    reads
}

fn pending_bootstrap_with_fake(fake: FakeTransport) -> CodexResource<FakeTransport> {
    let mut adapter = CodexResource::new(fake, identity("resource.structured"), config());
    adapter.initialize().unwrap();
    adapter
        .start_new("Begin work", "bootstrap:session.one")
        .unwrap();
    adapter
        .install_writer_epoch_from_trusted_boundary(Epoch::new(1).unwrap())
        .unwrap();
    adapter.poll_once().unwrap();
    assert_eq!(adapter.pending_request_count(), 1);
    adapter
}

fn pending_bootstrap(
    request: Value,
    extra: impl IntoIterator<Item = Value>,
) -> CodexResource<FakeTransport> {
    pending_bootstrap_with_fake(FakeTransport::with_reads(pending_bootstrap_reads(
        request, extra,
    )))
}

fn answer_permit(
    request: &podbay_adapter_codex::PendingNativeRequest,
    answer: NativeAnswer,
) -> AuthorizedAnswerPermit {
    AuthorizedAnswerPermit::from_authorised_boundary(writer_permit(1), request, answer)
}

#[test]
fn schema_receipt_and_exact_model_effort_are_pinned_before_bootstrap_ready() {
    assert_eq!(TESTED_CODEX_CLI_VERSION, "0.159.3");
    assert_eq!(TESTED_V2_SCHEMA_SHA256.len(), 64);
    let mut adapter = resource([
        initialized(),
        effective(2, "thread.one"),
        turn_started_response(),
        completed("turn.bootstrap", "completed"),
        status("idle", &[]),
    ]);
    adapter.initialize().unwrap();
    let receipt = adapter
        .start_new("Begin work", "bootstrap:session.one")
        .unwrap();
    assert_eq!(receipt.thread.thread_id, "thread.one");
    assert_eq!(receipt.bootstrap_turn_id, "turn.bootstrap");
    assert!(!adapter.bootstrap_ready());
    assert_eq!(
        adapter.transport().methods(),
        ["initialize", "initialized", "thread/start", "turn/start"]
    );
    let start = &adapter.transport().writes[2]["params"];
    assert_eq!(start["model"], "gpt-6-sol");
    assert_eq!(start["config"]["model_reasoning_effort"], "medium");
    assert_eq!(start["approvalPolicy"], "on-request");
    assert_eq!(start["sandbox"], "workspace-write");
    let bootstrap = &adapter.transport().writes[3]["params"];
    assert_eq!(bootstrap["model"], "gpt-6-sol");
    assert_eq!(bootstrap["effort"], "medium");
    assert_eq!(bootstrap["clientUserMessageId"], "bootstrap:session.one");
    adapter.poll_once().unwrap();
    assert!(!adapter.bootstrap_ready());
    adapter.poll_once().unwrap();
    assert!(adapter.bootstrap_ready());
}

#[test]
fn nonblocking_bootstrap_poll_distinguishes_delay_completion_and_interruption() {
    let mut io = FakeTransport::with_reads([
        initialized(),
        effective(2, "thread.one"),
        turn_started_response(),
    ]);
    io.reads.push_back(Vec::new());
    io.reads
        .push_back(encode(&completed("turn.bootstrap", "completed")).unwrap());
    io.reads.push_back(encode(&status("idle", &[])).unwrap());
    let mut adapter = CodexResource::new(io, identity("resource.structured"), config());
    adapter.initialize().unwrap();
    adapter
        .start_new("Begin work", "bootstrap:session.one")
        .unwrap();
    assert!(!adapter.poll_available_once().unwrap());
    assert_eq!(
        adapter.bootstrap_state(),
        &BootstrapState::Submitted {
            turn_id: "turn.bootstrap".into()
        }
    );
    assert!(adapter.poll_available_once().unwrap());
    assert_eq!(
        adapter.bootstrap_state(),
        &BootstrapState::Completed {
            turn_id: "turn.bootstrap".into()
        }
    );
    assert!(adapter.poll_available_once().unwrap());
    assert!(adapter.bootstrap_ready());
    assert!(!adapter.poll_available_once().unwrap());
    assert_eq!(
        adapter.transport().methods(),
        ["initialize", "initialized", "thread/start", "turn/start"]
    );

    for (wire, expected) in [
        (
            "failed",
            BootstrapState::Failed {
                turn_id: "turn.bootstrap".into(),
            },
        ),
        (
            "interrupted",
            BootstrapState::Interrupted {
                turn_id: "turn.bootstrap".into(),
            },
        ),
    ] {
        let mut adapter = resource([
            initialized(),
            effective(2, "thread.one"),
            turn_started_response(),
            completed("turn.bootstrap", wire),
            status("idle", &[]),
        ]);
        adapter.initialize().unwrap();
        adapter
            .start_new("Begin work", "bootstrap:session.one")
            .unwrap();
        adapter.poll_available_once().unwrap();
        adapter.poll_available_once().unwrap();
        assert_eq!(adapter.bootstrap_state(), &expected);
        assert!(!adapter.bootstrap_ready());
        assert_eq!(
            adapter.poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.bootstrap"),
            Err(CodexError::Blocked(BlockReason::BootstrapUnsettled)),
        );
    }
}

#[test]
fn nonblocking_poll_never_treats_unrelated_turn_or_pending_question_as_ready() {
    let mut unrelated = resource([
        initialized(),
        effective(2, "thread.one"),
        turn_started_response(),
        completed("turn.other", "completed"),
        completed("turn.bootstrap", "completed"),
        status("idle", &[]),
    ]);
    unrelated.initialize().unwrap();
    unrelated
        .start_new("Begin work", "bootstrap:session.one")
        .unwrap();
    for _ in 0..3 {
        unrelated.poll_available_once().unwrap();
    }
    assert!(unrelated.turn_control_state().external_conflict);
    assert!(!unrelated.bootstrap_ready());

    let mut pending = resource([
        initialized(),
        effective(2, "thread.one"),
        turn_started_response(),
        command_request(70),
        completed("turn.bootstrap", "completed"),
        status("idle", &[]),
    ]);
    pending.initialize().unwrap();
    pending
        .start_new("Begin work", "bootstrap:session.one")
        .unwrap();
    for _ in 0..3 {
        pending.poll_available_once().unwrap();
    }
    assert_eq!(pending.pending_request_count(), 1);
    assert!(!pending.bootstrap_ready());
}

#[test]
fn split_bootstrap_uses_checkpointed_thread_and_one_fresh_idle_turn_start() {
    let mut adapter = resource([
        initialized(),
        effective(2, "thread.one"),
        read_response(3, "idle", None),
        work_turn_response(4, "turn.split.bootstrap"),
    ]);
    adapter.initialize().unwrap();
    let thread = adapter.start_thread_without_turn().unwrap();
    assert_eq!(thread.thread_id, "thread.one");
    assert_eq!(thread.session_id, "thread.one");
    assert_eq!(adapter.bootstrap_state(), &BootstrapState::NotStarted);
    adapter
        .install_writer_epoch_from_trusted_boundary(Epoch::new(1).unwrap())
        .unwrap();
    let receipt = adapter
        .submit_bootstrap_after_checkpoint(
            &writer_permit(1),
            &thread.thread_id,
            &thread.session_id,
            "Begin work",
            "bootstrap:session.one",
        )
        .unwrap();
    assert_eq!(receipt.native_thread_id, "thread.one");
    assert_eq!(receipt.native_session_id, "thread.one");
    assert_eq!(receipt.client_message_id, "bootstrap:session.one");
    assert_eq!(
        receipt.stage,
        BootstrapTurnStage::Submitted {
            turn_id: "turn.split.bootstrap".into()
        }
    );
    assert_eq!(
        adapter.bootstrap_state(),
        &BootstrapState::Submitted {
            turn_id: "turn.split.bootstrap".into()
        }
    );
    assert_eq!(
        adapter.transport().methods(),
        [
            "initialize",
            "initialized",
            "thread/start",
            "thread/read",
            "turn/start"
        ]
    );
    let params = &adapter.transport().writes[4]["params"];
    assert_eq!(params["threadId"], "thread.one");
    assert_eq!(params["clientUserMessageId"], "bootstrap:session.one");
    assert_eq!(params["model"], "gpt-6-sol");
    assert_eq!(params["effort"], "medium");
    assert!(matches!(
        adapter.submit_bootstrap_after_checkpoint(
            &writer_permit(1),
            "thread.one",
            "thread.one",
            "Begin work",
            "bootstrap:session.one"
        ),
        Err(CodexError::Blocked(BlockReason::BootstrapUnsettled))
    ));
    assert_eq!(adapter.transport().methods().len(), 5);
}

#[test]
fn split_bootstrap_applies_completion_queued_before_turn_start_reply() {
    let mut adapter = resource([
        initialized(),
        effective(2, "thread.one"),
        read_response(3, "idle", None),
        completed("turn.split.bootstrap", "completed"),
        status("idle", &[]),
        work_turn_response(4, "turn.split.bootstrap"),
    ]);
    adapter.initialize().unwrap();
    let thread = adapter.start_thread_without_turn().unwrap();
    adapter
        .install_writer_epoch_from_trusted_boundary(Epoch::new(1).unwrap())
        .unwrap();
    let receipt = adapter
        .submit_bootstrap_after_checkpoint(
            &writer_permit(1),
            &thread.thread_id,
            &thread.session_id,
            "Begin work",
            "bootstrap:session.one",
        )
        .unwrap();
    assert_eq!(
        receipt.stage,
        BootstrapTurnStage::Submitted {
            turn_id: "turn.split.bootstrap".into()
        }
    );
    assert_eq!(
        adapter.bootstrap_state(),
        &BootstrapState::Completed {
            turn_id: "turn.split.bootstrap".into()
        }
    );
    assert!(!adapter.poll_available_once().unwrap());
    assert_eq!(
        adapter.transport().methods(),
        [
            "initialize",
            "initialized",
            "thread/start",
            "thread/read",
            "turn/start"
        ]
    );
}

fn split_completed_with_probe_tail(
    tail: impl IntoIterator<Item = Vec<u8>>,
    pending_probe_writes: usize,
    eof_on_empty: bool,
) -> CodexResource<FakeTransport> {
    let mut io = FakeTransport::with_reads([
        initialized(),
        effective(2, "thread.one"),
        read_response(3, "idle", None),
        work_turn_response(4, "turn.split.bootstrap"),
        completed("turn.split.bootstrap", "completed"),
        status("idle", &[]),
    ]);
    io.reads.extend(tail);
    io.pending_probe_writes = pending_probe_writes;
    io.eof_on_empty = eof_on_empty;
    let mut adapter = CodexResource::new(io, identity("resource.structured"), config());
    adapter.initialize().unwrap();
    let thread = adapter.start_thread_without_turn().unwrap();
    adapter
        .install_writer_epoch_from_trusted_boundary(Epoch::new(1).unwrap())
        .unwrap();
    assert_eq!(
        adapter
            .submit_bootstrap_after_checkpoint(
                &writer_permit(1),
                &thread.thread_id,
                &thread.session_id,
                "Begin work",
                "bootstrap:session.one",
            )
            .unwrap()
            .stage,
        BootstrapTurnStage::Submitted {
            turn_id: "turn.split.bootstrap".into()
        },
    );
    adapter.poll_available_once().unwrap();
    adapter.poll_available_once().unwrap();
    assert_eq!(
        adapter.bootstrap_state(),
        &BootstrapState::Completed {
            turn_id: "turn.split.bootstrap".into()
        }
    );
    adapter
}

#[test]
fn async_completion_read_waits_without_blocking_and_verifies_exact_idle_reply() {
    let mut adapter = split_completed_with_probe_tail(
        [
            Vec::new(),
            encode(&read_response(5, "idle", None)).unwrap(),
            Vec::new(),
        ],
        1,
        false,
    );
    let poll = |adapter: &mut CodexResource<FakeTransport>| {
        adapter.poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap")
    };
    assert_eq!(poll(&mut adapter).unwrap(), BootstrapReadPoll::Pending);
    assert_eq!(
        adapter
            .transport()
            .methods()
            .iter()
            .filter(|method| **method == "thread/read")
            .count(),
        1
    );
    assert_eq!(poll(&mut adapter).unwrap(), BootstrapReadPoll::Advanced);
    assert_eq!(poll(&mut adapter).unwrap(), BootstrapReadPoll::Pending);
    assert_eq!(poll(&mut adapter).unwrap(), BootstrapReadPoll::Advanced);
    assert_eq!(poll(&mut adapter).unwrap(), BootstrapReadPoll::Verified);
    assert_eq!(poll(&mut adapter).unwrap(), BootstrapReadPoll::Verified);
    assert_eq!(
        adapter
            .transport()
            .methods()
            .iter()
            .filter(|method| **method == "thread/read")
            .count(),
        2
    );
    assert_eq!(
        adapter
            .transport()
            .methods()
            .iter()
            .filter(|method| **method == "turn/start")
            .count(),
        1
    );
    assert_eq!(
        adapter.transport().writes.last().unwrap()["params"]["threadId"],
        "thread.one"
    );
}

#[test]
fn async_completion_read_refuses_malformed_busy_pending_and_lost_reply() {
    let mut malformed = split_completed_with_probe_tail(
        [encode(&json!({"id":5,"result":{"thread":{"id":"thread.one"}}})).unwrap()],
        0,
        false,
    );
    malformed
        .poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap")
        .unwrap();
    assert!(matches!(
        malformed.poll_bootstrap_read_proof_once(
            "thread.one",
            "thread.one",
            "turn.split.bootstrap"
        ),
        Err(CodexError::Protocol(_)),
    ));
    assert_eq!(
        malformed
            .transport()
            .methods()
            .iter()
            .filter(|method| **method == "thread/read")
            .count(),
        2
    );

    let mut wrong_session = read_response(5, "idle", None);
    wrong_session["result"]["thread"]["sessionId"] = json!("native.other");
    let mut wrong = split_completed_with_probe_tail([encode(&wrong_session).unwrap()], 0, false);
    wrong
        .poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap")
        .unwrap();
    assert_eq!(
        wrong.poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap"),
        Err(CodexError::Mismatch(
            "completion read native Session differs"
        )),
    );

    let mut foreign_reply = split_completed_with_probe_tail(
        [encode(&read_response(99, "idle", None)).unwrap()],
        0,
        false,
    );
    foreign_reply
        .poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap")
        .unwrap();
    assert!(matches!(
        foreign_reply.poll_bootstrap_read_proof_once(
            "thread.one",
            "thread.one",
            "turn.split.bootstrap"
        ),
        Err(CodexError::Protocol(_)),
    ));

    let mut contradictory = read_response(5, "idle", None);
    contradictory["result"]["thread"]["status"]["activeFlags"] = json!(["waitingOnApproval"]);
    let mut waiting = split_completed_with_probe_tail([encode(&contradictory).unwrap()], 0, false);
    waiting
        .poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap")
        .unwrap();
    assert!(matches!(
        waiting.poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap"),
        Err(CodexError::Protocol(_)),
    ));

    let mut busy = split_completed_with_probe_tail(
        [encode(&read_response(5, "active", None)).unwrap()],
        0,
        false,
    );
    busy.poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap")
        .unwrap();
    assert_eq!(
        busy.poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap")
            .unwrap(),
        BootstrapReadPoll::Advanced
    );
    assert_ne!(
        busy.poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap")
            .unwrap(),
        BootstrapReadPoll::Verified
    );

    let mut question = split_completed_with_probe_tail(
        [
            encode(&command_request(70)).unwrap(),
            encode(&read_response(5, "idle", None)).unwrap(),
        ],
        0,
        false,
    );
    question
        .poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap")
        .unwrap();
    question
        .poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap")
        .unwrap();
    question
        .poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap")
        .unwrap();
    assert_eq!(question.pending_request_count(), 1);
    assert_ne!(
        question
            .poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap")
            .unwrap(),
        BootstrapReadPoll::Verified
    );

    let mut partial_question = split_completed_with_probe_tail(
        [
            encode(&read_response(5, "idle", None)).unwrap(),
            vec![0],
            encode(&command_request(71)).unwrap(),
        ],
        0,
        false,
    );
    partial_question
        .poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap")
        .unwrap();
    partial_question
        .poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap")
        .unwrap();
    assert_eq!(
        partial_question
            .poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap")
            .unwrap(),
        BootstrapReadPoll::Pending,
    );
    assert_ne!(
        partial_question
            .poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap")
            .unwrap(),
        BootstrapReadPoll::Verified,
    );
    assert_eq!(partial_question.pending_request_count(), 1);

    let mut late_question = split_completed_with_probe_tail(
        [
            encode(&read_response(5, "idle", None)).unwrap(),
            Vec::new(),
            encode(&command_request(72)).unwrap(),
        ],
        0,
        false,
    );
    late_question
        .poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap")
        .unwrap();
    late_question
        .poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap")
        .unwrap();
    assert_eq!(
        late_question
            .poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap")
            .unwrap(),
        BootstrapReadPoll::Verified
    );
    assert_ne!(
        late_question
            .poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap")
            .unwrap(),
        BootstrapReadPoll::Verified
    );
    assert_eq!(late_question.pending_request_count(), 1);

    let mut lost = split_completed_with_probe_tail([], 0, true);
    lost.poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap")
        .unwrap();
    assert_eq!(
        lost.poll_bootstrap_read_proof_once("thread.one", "thread.one", "turn.split.bootstrap"),
        Err(CodexError::TransportUncertain)
    );
    assert_eq!(
        lost.transport()
            .methods()
            .iter()
            .filter(|method| **method == "thread/read")
            .count(),
        2
    );
    assert_eq!(
        lost.transport()
            .methods()
            .iter()
            .filter(|method| **method == "turn/start")
            .count(),
        1
    );
}

#[test]
fn split_bootstrap_refuses_wrong_checkpoint_stale_writer_and_native_busy() {
    let mut wrong = resource([initialized(), effective(2, "thread.one")]);
    wrong.initialize().unwrap();
    wrong.start_thread_without_turn().unwrap();
    wrong
        .install_writer_epoch_from_trusted_boundary(Epoch::new(1).unwrap())
        .unwrap();
    assert!(matches!(
        wrong.submit_bootstrap_after_checkpoint(
            &writer_permit(1),
            "thread.other",
            "thread.one",
            "Begin work",
            "bootstrap:session.one"
        ),
        Err(CodexError::Mismatch(_))
    ));
    assert_eq!(wrong.transport().methods().len(), 3);

    let mut wrong_session = resource([initialized(), effective(2, "thread.one")]);
    wrong_session.initialize().unwrap();
    wrong_session.start_thread_without_turn().unwrap();
    wrong_session
        .install_writer_epoch_from_trusted_boundary(Epoch::new(1).unwrap())
        .unwrap();
    assert!(matches!(
        wrong_session.submit_bootstrap_after_checkpoint(
            &writer_permit(1),
            "thread.one",
            "session.other",
            "Begin work",
            "bootstrap:session.one"
        ),
        Err(CodexError::Mismatch(_))
    ));
    assert_eq!(wrong_session.transport().methods().len(), 3);

    let mut stale = resource([initialized(), effective(2, "thread.one")]);
    stale.initialize().unwrap();
    stale.start_thread_without_turn().unwrap();
    stale
        .install_writer_epoch_from_trusted_boundary(Epoch::new(2).unwrap())
        .unwrap();
    assert_eq!(
        stale.submit_bootstrap_after_checkpoint(
            &writer_permit(1),
            "thread.one",
            "thread.one",
            "Begin work",
            "bootstrap:session.one"
        ),
        Err(CodexError::Blocked(BlockReason::StaleWriterPermit))
    );
    assert_eq!(stale.transport().methods().len(), 3);
    let wrong_resource =
        WriterPermit::from_trusted_boundary(identity("resource.other"), Epoch::new(2).unwrap());
    assert_eq!(
        stale.submit_bootstrap_after_checkpoint(
            &wrong_resource,
            "thread.one",
            "thread.one",
            "Begin work",
            "bootstrap:session.one"
        ),
        Err(CodexError::Blocked(BlockReason::StaleResourcePermit))
    );
    assert_eq!(stale.transport().methods().len(), 3);

    let mut busy = resource([
        initialized(),
        effective(2, "thread.one"),
        read_response(3, "active", None),
    ]);
    busy.initialize().unwrap();
    busy.start_thread_without_turn().unwrap();
    busy.install_writer_epoch_from_trusted_boundary(Epoch::new(1).unwrap())
        .unwrap();
    assert!(matches!(
        busy.submit_bootstrap_after_checkpoint(
            &writer_permit(1),
            "thread.one",
            "thread.one",
            "Begin work",
            "bootstrap:session.one"
        ),
        Err(CodexError::Blocked(
            BlockReason::ExternalWriter | BlockReason::NativeBusy
        ))
    ));
    assert_eq!(
        busy.transport().methods(),
        ["initialize", "initialized", "thread/start", "thread/read"]
    );
}

#[test]
fn split_bootstrap_lost_reply_is_uncertain_and_never_retried() {
    let mut adapter = resource([
        initialized(),
        effective(2, "thread.one"),
        read_response(3, "idle", None),
    ]);
    adapter.initialize().unwrap();
    adapter.start_thread_without_turn().unwrap();
    adapter
        .install_writer_epoch_from_trusted_boundary(Epoch::new(1).unwrap())
        .unwrap();
    let receipt = adapter
        .submit_bootstrap_after_checkpoint(
            &writer_permit(1),
            "thread.one",
            "thread.one",
            "Begin work",
            "bootstrap:session.one",
        )
        .unwrap();
    assert_eq!(receipt.stage, BootstrapTurnStage::Uncertain);
    assert_eq!(adapter.bootstrap_state(), &BootstrapState::Unknown);
    assert!(
        adapter
            .submit_bootstrap_after_checkpoint(
                &writer_permit(1),
                "thread.one",
                "thread.one",
                "Begin work",
                "bootstrap:session.one"
            )
            .is_err()
    );
    assert_eq!(
        adapter.transport().methods(),
        [
            "initialize",
            "initialized",
            "thread/start",
            "thread/read",
            "turn/start"
        ]
    );

    let mut malformed = resource([
        initialized(),
        effective(2, "thread.one"),
        read_response(3, "idle", None),
        json!({"id":4,"result":{"turn":{"id":"turn.maybe","status":"completed"}}}),
    ]);
    malformed.initialize().unwrap();
    malformed.start_thread_without_turn().unwrap();
    malformed
        .install_writer_epoch_from_trusted_boundary(Epoch::new(1).unwrap())
        .unwrap();
    let uncertain = malformed
        .submit_bootstrap_after_checkpoint(
            &writer_permit(1),
            "thread.one",
            "thread.one",
            "Begin work",
            "bootstrap:session.one",
        )
        .unwrap();
    assert_eq!(uncertain.stage, BootstrapTurnStage::Uncertain);
    assert_eq!(malformed.bootstrap_state(), &BootstrapState::Unknown);
    assert_eq!(
        malformed.transport().methods(),
        [
            "initialize",
            "initialized",
            "thread/start",
            "thread/read",
            "turn/start"
        ]
    );
}

#[test]
fn danger_full_access_never_policy_is_exact_and_effective_drift_refuses() {
    let selected = PinnedCodexConfig::new(
        "gpt-6-sol",
        "medium",
        PathBuf::from("/tmp/podbay-codex-work"),
        ApprovalPolicy::Never,
        Sandbox::DangerFullAccess,
    )
    .unwrap();
    let mut accepted = effective(2, "thread.one");
    accepted["result"]["approvalPolicy"] = json!("never");
    accepted["result"]["sandbox"] = json!({"type":"dangerFullAccess"});

    let mut adapter = CodexResource::new(
        FakeTransport::with_reads([
            initialized(),
            accepted.clone(),
            turn_started_response(),
            completed("turn.bootstrap", "completed"),
            status("idle", &[]),
        ]),
        identity("resource.danger"),
        selected.clone(),
    );
    adapter.initialize().unwrap();
    adapter
        .start_new("Begin work", "bootstrap:session.one")
        .unwrap();
    let sent = &adapter.transport().writes[2]["params"];
    assert_eq!(sent["model"], "gpt-6-sol");
    assert_eq!(sent["config"]["model_reasoning_effort"], "medium");
    assert_eq!(sent["sandbox"], "danger-full-access");
    assert_eq!(sent["approvalPolicy"], "never");
    assert!(!adapter.bootstrap_ready());
    adapter.poll_once().unwrap();
    assert!(!adapter.bootstrap_ready());
    adapter.poll_once().unwrap();
    assert!(adapter.bootstrap_ready());

    for (field, value) in [
        ("sandbox", json!({"type":"workspaceWrite"})),
        ("approvalPolicy", json!("on-request")),
    ] {
        let mut drifted = accepted.clone();
        drifted["result"][field] = value;
        let mut adapter = CodexResource::new(
            FakeTransport::with_reads([initialized(), drifted]),
            identity("resource.danger"),
            selected.clone(),
        );
        adapter.initialize().unwrap();
        assert!(matches!(
            adapter.start_new("Begin work", "bootstrap:session.one"),
            Err(CodexError::Mismatch(_))
        ));
        assert_eq!(
            adapter.transport().methods(),
            ["initialize", "initialized", "thread/start"]
        );
        assert!(!adapter.bootstrap_ready());
    }
}

#[test]
fn matching_completion_remains_blocked_while_native_approval_is_pending() {
    let approval = json!({"id":44,"method":"item/commandExecution/requestApproval","params":{
        "threadId":"thread.one","turnId":"turn.bootstrap","itemId":"item.one",
        "startedAtMs":1
    }});
    let resolved = json!({"method":"serverRequest/resolved","params":{
        "threadId":"thread.one","requestId":44
    }});
    let mut adapter = resource([
        initialized(),
        effective(2, "thread.one"),
        turn_started_response(),
        approval,
        completed("turn.bootstrap", "completed"),
        resolved,
        status("idle", &[]),
    ]);
    adapter.initialize().unwrap();
    adapter
        .start_new("Begin work", "bootstrap:session.one")
        .unwrap();
    adapter.poll_once().unwrap();
    assert_eq!(adapter.pending_request_count(), 1);
    adapter.poll_once().unwrap();
    assert!(!adapter.bootstrap_ready());
    adapter.poll_once().unwrap();
    assert!(!adapter.bootstrap_ready());
    adapter.poll_once().unwrap();
    assert!(adapter.bootstrap_ready());
}

#[test]
fn unknown_resolution_and_completion_cannot_clear_waiting_status() {
    let resolved_unknown = json!({"method":"serverRequest/resolved","params":{
        "threadId":"thread.one","requestId":999
    }});
    let mut adapter = resource([
        initialized(),
        effective(2, "thread.one"),
        turn_started_response(),
        status("active", &["waitingOnApproval"]),
        resolved_unknown,
        completed("turn.bootstrap", "completed"),
        status("idle", &[]),
    ]);
    adapter.initialize().unwrap();
    adapter
        .start_new("Begin work", "bootstrap:session.one")
        .unwrap();
    adapter.poll_once().unwrap();
    adapter.poll_once().unwrap();
    adapter.poll_once().unwrap();
    assert_eq!(adapter.pending_request_count(), 0);
    assert!(!adapter.bootstrap_ready());
    adapter.poll_once().unwrap();
    assert!(adapter.bootstrap_ready());
}

#[test]
fn active_without_waiting_flags_blocks_until_fresh_idle_after_completion() {
    let mut adapter = resource([
        initialized(),
        effective(2, "thread.one"),
        turn_started_response(),
        completed("turn.bootstrap", "completed"),
        status("active", &[]),
        status("idle", &[]),
    ]);
    adapter.initialize().unwrap();
    adapter
        .start_new("Begin work", "bootstrap:session.one")
        .unwrap();
    adapter.poll_once().unwrap();
    assert!(!adapter.bootstrap_ready());
    adapter.poll_once().unwrap();
    assert!(!adapter.bootstrap_ready());
    adapter.poll_once().unwrap();
    assert!(adapter.bootstrap_ready());
}

#[test]
fn wrong_turn_completion_never_settles_bootstrap() {
    let mut adapter = resource([
        initialized(),
        effective(2, "thread.one"),
        turn_started_response(),
        completed("turn.other", "completed"),
        completed("turn.bootstrap", "completed"),
    ]);
    adapter.initialize().unwrap();
    adapter
        .start_new("Begin work", "bootstrap:session.one")
        .unwrap();
    adapter.poll_once().unwrap();
    assert!(!adapter.bootstrap_ready());
    adapter.poll_once().unwrap();
    assert!(!adapter.bootstrap_ready());
}

#[test]
fn changed_effective_model_effort_or_permissions_refuse_before_bootstrap() {
    let changes = [
        ("model", json!("gpt-other")),
        ("reasoningEffort", json!("high")),
        ("approvalPolicy", json!("never")),
        ("sandbox", json!({"type":"dangerFullAccess"})),
        ("cwd", json!("/tmp/other")),
    ];
    for (field, value) in changes {
        let mut response = effective(2, "thread.one");
        response["result"][field] = value;
        let mut adapter = resource([initialized(), response]);
        adapter.initialize().unwrap();
        assert!(matches!(
            adapter.start_new("Begin work", "bootstrap:session.one"),
            Err(CodexError::Mismatch(_))
        ));
        assert_eq!(
            adapter.transport().methods(),
            ["initialize", "initialized", "thread/start"]
        );
        assert!(!adapter.bootstrap_ready());
    }
}

#[test]
fn resume_reads_exact_thread_before_resuming_and_never_replays_bootstrap() {
    let read = json!({"id":2,"result":{"thread":native_thread("thread.one","notLoaded")}});
    let mut adapter = resource([initialized(), read, effective(3, "thread.one")]);
    adapter.initialize().unwrap();
    let thread = adapter.resume_existing("thread.one").unwrap();
    assert_eq!(thread.thread_id, "thread.one");
    assert_eq!(adapter.bootstrap_state(), &BootstrapState::Unknown);
    assert!(!adapter.bootstrap_ready());
    assert_eq!(
        adapter.transport().methods(),
        ["initialize", "initialized", "thread/read", "thread/resume"]
    );
    assert!(
        adapter.transport().writes[2]["params"]
            .get("includeTurns")
            .is_none()
    );
    assert_eq!(
        adapter.transport().writes[3]["params"]["threadId"],
        "thread.one"
    );
    assert_eq!(
        adapter.transport().writes[3]["params"]["excludeTurns"],
        true
    );
}

#[test]
fn resume_refuses_wrong_native_thread_before_subscribing() {
    let read = json!({"id":2,"result":{"thread":native_thread("thread.other","notLoaded")}});
    let mut adapter = resource([initialized(), read]);
    adapter.initialize().unwrap();
    assert_eq!(
        adapter.resume_existing("thread.one"),
        Err(CodexError::Mismatch("Codex returned another native thread"))
    );
    assert_eq!(
        adapter.transport().methods(),
        ["initialize", "initialized", "thread/read"]
    );
}

#[test]
fn resume_refuses_changed_effective_settings_after_read() {
    let read = json!({"id":2,"result":{"thread":native_thread("thread.one","notLoaded")}});
    let mut changed = effective(3, "thread.one");
    changed["result"]["reasoningEffort"] = json!("high");
    let mut adapter = resource([initialized(), read, changed]);
    adapter.initialize().unwrap();
    assert_eq!(
        adapter.resume_existing("thread.one"),
        Err(CodexError::Mismatch("Codex selected another effort"))
    );
    assert!(adapter.native_thread().is_none());
    assert!(!adapter.bootstrap_ready());
}

#[test]
fn resume_refuses_active_metadata_without_a_verified_turn_identity() {
    let read = json!({"id":2,"result":{"thread":native_thread("thread.one","active")}});
    let mut adapter = resource([initialized(), read]);
    adapter.initialize().unwrap();
    assert_eq!(
        adapter.resume_existing("thread.one"),
        Err(CodexError::Unsupported(
            "active native thread cannot be resumed without verified turn identity"
        ))
    );
    assert_eq!(
        adapter.transport().methods(),
        ["initialize", "initialized", "thread/read"]
    );
    assert!(adapter.native_thread().is_none());
}

#[test]
fn resume_refuses_active_effective_response_without_claiming_readiness() {
    let read = json!({"id":2,"result":{"thread":native_thread("thread.one","notLoaded")}});
    let mut active = effective(3, "thread.one");
    active["result"]["thread"] = native_thread("thread.one", "active");
    let mut adapter = resource([initialized(), read, active]);
    adapter.initialize().unwrap();
    assert_eq!(
        adapter.resume_existing("thread.one"),
        Err(CodexError::Unsupported(
            "active resumed thread has no verified turn identity"
        ))
    );
    assert!(!adapter.bootstrap_ready());
    assert!(adapter.native_thread().is_none());
}

#[test]
fn malformed_or_oversize_jsonl_poison_connection_without_retry() {
    for raw in [b"{broken\n".to_vec(), vec![b' '; MAX_FRAME_BYTES + 1]] {
        let fake = FakeTransport::with_raw_read(raw);
        let mut adapter = CodexResource::new(fake, identity("resource.structured"), config());
        assert!(matches!(adapter.initialize(), Err(CodexError::Codec(_))));
        assert!(matches!(
            adapter.initialize(),
            Err(CodexError::InvalidState(_))
        ));
        assert_eq!(adapter.transport().methods(), ["initialize"]);
    }
    assert_eq!(decode(b"{}"), Err(CodecError::MissingNewline));
    assert_eq!(decode(b"{}\n{}\n"), Err(CodecError::MultipleLines));
}

#[test]
fn malformed_native_event_poison_blocks_previous_readiness() {
    let mut adapter = resource([
        initialized(),
        effective(2, "thread.one"),
        turn_started_response(),
        completed("turn.bootstrap", "completed"),
        status("idle", &[]),
        json!({"method":"thread/status/changed"}),
    ]);
    adapter.initialize().unwrap();
    adapter
        .start_new("Begin work", "bootstrap:session.one")
        .unwrap();
    adapter.poll_once().unwrap();
    adapter.poll_once().unwrap();
    assert!(adapter.bootstrap_ready());
    assert_eq!(
        adapter.poll_once(),
        Err(CodexError::Protocol("native event omitted params"))
    );
    assert!(!adapter.bootstrap_ready());
}

#[test]
fn lost_bootstrap_reply_is_uncertain_and_cannot_submit_a_second_turn() {
    let mut adapter = resource([initialized(), effective(2, "thread.one")]);
    adapter.initialize().unwrap();
    assert_eq!(
        adapter.start_new("Begin work", "bootstrap:session.one"),
        Err(CodexError::TransportUncertain)
    );
    assert_eq!(adapter.bootstrap_state(), &BootstrapState::Unknown);
    assert!(matches!(
        adapter.start_new("Begin work", "bootstrap:session.one"),
        Err(CodexError::InvalidState(_))
    ));
    assert_eq!(
        adapter.transport().methods(),
        ["initialize", "initialized", "thread/start", "turn/start"]
    );
}

#[test]
fn idle_native_thread_starts_one_pinned_turn_after_reconciliation() {
    let mut adapter = bootstrapped([
        read_response(4, "idle", None),
        work_turn_response(5, "turn.work"),
        read_response(6, "idle", None),
    ]);
    let sent = adapter
        .send_turn(&writer_permit(1), "Do the task", "message.one", None)
        .unwrap();
    assert_eq!(sent.client_message_id, "message.one");
    assert_eq!(sent.mode, TurnMode::Start);
    assert_eq!(
        sent.stage,
        TurnSubmissionStage::Accepted {
            turn_id: "turn.work".into()
        }
    );
    assert_eq!(
        adapter.transport().methods(),
        [
            "initialize",
            "initialized",
            "thread/start",
            "turn/start",
            "thread/read",
            "turn/start"
        ]
    );
    let params = &adapter.transport().writes[5]["params"];
    assert_eq!(params["threadId"], "thread.one");
    assert_eq!(params["clientUserMessageId"], "message.one");
    assert_eq!(params["model"], "gpt-6-sol");
    assert_eq!(params["effort"], "medium");
    assert_eq!(
        adapter.turn_control_state().owned_active_turn_id.as_deref(),
        Some("turn.work")
    );
    adapter.read_thread().unwrap();
    assert!(!adapter.bootstrap_ready());
}

#[test]
fn exact_owned_active_turn_steers_with_expected_turn_id() {
    let mut adapter = bootstrapped([
        read_response(4, "idle", None),
        work_turn_response(5, "turn.work"),
        read_response(6, "active", Some("turn.work")),
        json!({"id":7,"result":{"turnId":"turn.work"}}),
    ]);
    adapter
        .send_turn(&writer_permit(1), "First", "message.one", None)
        .unwrap();
    assert_eq!(
        adapter
            .turn_control_state()
            .observed_active_turn_id
            .as_deref(),
        Some("turn.work")
    );
    let steered = adapter
        .send_turn(
            &writer_permit(1),
            "Change direction",
            "message.two",
            Some("turn.work"),
        )
        .unwrap();
    assert_eq!(steered.mode, TurnMode::Steer);
    assert_eq!(adapter.turn_control_state().observed_active_turn_id, None);
    assert_eq!(
        adapter.turn_control_state().owned_active_turn_id.as_deref(),
        Some("turn.work")
    );
    assert_eq!(steered.client_message_id, "message.two");
    assert_eq!(
        steered.stage,
        TurnSubmissionStage::Accepted {
            turn_id: "turn.work".into()
        }
    );
    assert_eq!(adapter.transport().methods().last(), Some(&"turn/steer"));
    let params = &adapter.transport().writes[7]["params"];
    assert_eq!(params["expectedTurnId"], "turn.work");
    assert_eq!(params["clientUserMessageId"], "message.two");
}

#[test]
fn stale_caller_turn_id_refuses_without_poisoning_the_owned_turn() {
    let mut adapter = bootstrapped([
        read_response(4, "idle", None),
        work_turn_response(5, "turn.work"),
        read_response(6, "active", Some("turn.work")),
        read_response(7, "active", Some("turn.work")),
        json!({"id":8,"result":{"turnId":"turn.work"}}),
    ]);
    adapter
        .send_turn(&writer_permit(1), "First", "message.one", None)
        .unwrap();
    assert_eq!(
        adapter.send_turn(
            &writer_permit(1),
            "Wrong target",
            "message.two",
            Some("turn.other"),
        ),
        Err(CodexError::Blocked(BlockReason::StaleExpectedTurn))
    );
    assert_eq!(adapter.transport().methods().last(), Some(&"thread/read"));
    assert!(!adapter.turn_control_state().external_conflict);
    let accepted = adapter
        .send_turn(
            &writer_permit(1),
            "Correct target",
            "message.two",
            Some("turn.work"),
        )
        .unwrap();
    assert_eq!(accepted.mode, TurnMode::Steer);
    assert_eq!(adapter.transport().methods().last(), Some(&"turn/steer"));
}

#[test]
fn competing_native_turn_refuses_without_start_or_steer() {
    let mut adapter = bootstrapped([read_response(4, "active", Some("turn.external"))]);
    assert_eq!(
        adapter.send_turn(&writer_permit(1), "Do the task", "message.one", None),
        Err(CodexError::Blocked(BlockReason::ExternalWriter))
    );
    assert!(adapter.turn_control_state().external_conflict);
    assert_eq!(adapter.transport().methods().last(), Some(&"thread/read"));
}

#[test]
fn owned_active_turn_does_not_depend_on_a_paginated_lifetime_history() {
    let older = (0..129)
        .map(|index| json!({"id":format!("turn.old.{index}"),"status":"completed","items":[]}))
        .collect::<Vec<_>>();
    let unused_history_page = json!({"id":10,"result":{"data":older,"nextCursor":"older"}});
    let mut adapter = bootstrapped([
        read_response(4, "idle", None),
        work_turn_response(5, "turn.work"),
        read_response(6, "active", Some("turn.work")),
        json!({"id":7,"result":{"turnId":"turn.work"}}),
        read_response(8, "active", Some("turn.work")),
        json!({"id":9,"result":{}}),
        unused_history_page,
    ]);
    adapter
        .send_turn(&writer_permit(1), "First", "message.one", None)
        .unwrap();
    let steered = adapter
        .send_turn(
            &writer_permit(1),
            "Continue",
            "message.two",
            Some("turn.work"),
        )
        .unwrap();
    assert_eq!(steered.mode, TurnMode::Steer);
    assert_eq!(
        adapter.interrupt_turn(&writer_permit(1), "turn.work"),
        Ok(InterruptState::Requested {
            turn_id: "turn.work".into()
        })
    );
    assert_eq!(
        adapter.transport().writes[7]["params"]["expectedTurnId"],
        "turn.work"
    );
    assert!(!adapter.transport().methods().contains(&"thread/turns/list"));
    assert_eq!(
        adapter.transport().methods().last(),
        Some(&"turn/interrupt")
    );
    assert_eq!(
        adapter.transport().reads.len(),
        1,
        "paginated history was not consulted"
    );
}

#[test]
fn rejected_native_expected_turn_cas_marks_conflict_and_never_retries() {
    let mut adapter = bootstrapped([
        read_response(4, "idle", None),
        work_turn_response(5, "turn.work"),
        read_response(6, "active", Some("turn.work")),
        json!({"id":7,"error":{"code":-32600,"message":"expected turn changed"}}),
    ]);
    adapter
        .send_turn(&writer_permit(1), "First", "message.one", None)
        .unwrap();
    assert_eq!(
        adapter.send_turn(&writer_permit(1), "Steer", "message.two", Some("turn.work")),
        Err(CodexError::RemoteError(-32600))
    );
    assert!(adapter.turn_control_state().external_conflict);
    assert_eq!(adapter.transport().methods().last(), Some(&"turn/steer"));
    let writes = adapter.transport().writes.len();
    assert_eq!(
        adapter.send_turn(&writer_permit(1), "Retry", "message.two", Some("turn.work")),
        Err(CodexError::Blocked(BlockReason::DuplicateMessageKey))
    );
    assert_eq!(adapter.transport().writes.len(), writes);
    assert_eq!(
        adapter.send_turn(
            &writer_permit(1),
            "Another",
            "message.three",
            Some("turn.work")
        ),
        Err(CodexError::Blocked(BlockReason::ObservationUnknown))
    );
    assert_eq!(adapter.transport().writes.len(), writes);
}

#[test]
fn pending_native_approval_blocks_send_and_exposes_exact_request_id() {
    let approval = json!({"id":44,"method":"item/commandExecution/requestApproval","params":{
        "threadId":"thread.one","turnId":"turn.work","itemId":"item.one",
        "startedAtMs":1
    }});
    let mut adapter = bootstrapped([approval]);
    adapter.poll_once().unwrap();
    assert_eq!(
        adapter.send_turn(&writer_permit(1), "Do the task", "message.one", None),
        Err(CodexError::Blocked(BlockReason::PendingHostRequest))
    );
    assert_eq!(adapter.turn_control_state().pending_request_ids, ["n:44"]);
    assert_eq!(adapter.transport().methods().last(), Some(&"turn/start"));
}

#[test]
fn interrupt_rpc_receipt_waits_for_matching_interrupted_completion() {
    let mut adapter = bootstrapped([
        read_response(4, "idle", None),
        work_turn_response(5, "turn.work"),
        read_response(6, "active", Some("turn.work")),
        json!({"id":7,"result":{}}),
        completed("turn.other", "interrupted"),
        completed("turn.work", "interrupted"),
    ]);
    adapter
        .send_turn(&writer_permit(1), "First", "message.one", None)
        .unwrap();
    let before = adapter.transport().writes.len();
    assert_eq!(
        adapter.interrupt_turn(&writer_permit(1), "turn.other"),
        Err(CodexError::Blocked(BlockReason::StaleExpectedTurn))
    );
    assert_eq!(adapter.transport().writes.len(), before);
    assert_eq!(
        adapter
            .interrupt_turn(&writer_permit(1), "turn.work")
            .unwrap(),
        InterruptState::Requested {
            turn_id: "turn.work".into()
        }
    );
    assert_eq!(
        adapter.transport().methods().last(),
        Some(&"turn/interrupt")
    );
    let before = adapter.transport().writes.len();
    assert_eq!(
        adapter.send_turn(
            &writer_permit(1),
            "Steer after cancel",
            "message.two",
            Some("turn.work"),
        ),
        Err(CodexError::Blocked(BlockReason::InterruptAlreadyRequested))
    );
    assert_eq!(adapter.transport().writes.len(), before);
    adapter.poll_once().unwrap();
    assert_eq!(
        adapter.turn_control_state().interrupt,
        InterruptState::Requested {
            turn_id: "turn.work".into()
        }
    );
    adapter.poll_once().unwrap();
    assert_eq!(
        adapter.turn_control_state().interrupt,
        InterruptState::Settled {
            turn_id: "turn.work".into()
        }
    );
}

#[test]
fn lost_turn_reply_retains_message_key_and_never_resends() {
    let mut adapter = bootstrapped([read_response(4, "idle", None)]);
    let uncertain = adapter
        .send_turn(&writer_permit(1), "First", "message.exact", None)
        .unwrap();
    assert_eq!(uncertain.client_message_id, "message.exact");
    assert_eq!(uncertain.stage, TurnSubmissionStage::Uncertain);
    assert_eq!(
        adapter.turn_control_state().last_submission,
        Some(uncertain)
    );
    assert_eq!(
        adapter.send_turn(&writer_permit(1), "First", "message.exact", None),
        Err(CodexError::Blocked(BlockReason::DuplicateMessageKey))
    );
    assert_eq!(
        adapter.send_turn(&writer_permit(1), "Different", "message.other", None),
        Err(CodexError::Blocked(BlockReason::ObservationUnknown))
    );
    assert_eq!(
        adapter
            .transport()
            .methods()
            .into_iter()
            .filter(|method| *method == "turn/start")
            .count(),
        2 // bootstrap plus one uncertain submission
    );
}

#[test]
fn native_rpc_conflict_retains_uncertain_key_and_never_resends() {
    let mut adapter = bootstrapped([
        read_response(4, "idle", None),
        json!({"id":5,"error":{"code":-32000,"message":"active turn changed"}}),
    ]);
    assert_eq!(
        adapter.send_turn(&writer_permit(1), "First", "message.exact", None),
        Err(CodexError::RemoteError(-32000))
    );
    assert_eq!(
        adapter
            .turn_control_state()
            .last_submission
            .unwrap()
            .client_message_id,
        "message.exact"
    );
    assert_eq!(
        adapter.send_turn(&writer_permit(1), "Second", "message.other", None),
        Err(CodexError::Blocked(BlockReason::ObservationUnknown))
    );
    assert_eq!(adapter.transport().methods().last(), Some(&"turn/start"));
}

#[test]
fn stale_resource_or_writer_permit_refuses_before_any_native_rpc() {
    let mut adapter = bootstrapped([]);
    let before = adapter.transport().writes.len();
    let mut wrong = identity("resource.structured");
    let distinct = [
        {
            let mut value = wrong.clone();
            value.session_id = SessionId::try_from("session.other").unwrap();
            value
        },
        {
            let mut value = wrong.clone();
            value.run_id = RunId::try_from("run.other").unwrap();
            value
        },
        {
            let mut value = wrong.clone();
            value.attempt_id = AttemptId::try_from("attempt.other").unwrap();
            value
        },
        {
            let mut value = wrong.clone();
            value.pod_id = PodId::try_from("pod.other").unwrap();
            value
        },
        {
            let mut value = wrong.clone();
            value.resource_id = ResourceId::try_from("resource.other").unwrap();
            value
        },
        {
            wrong.resource_epoch = Epoch::new(2).unwrap();
            wrong
        },
    ];
    for identity in distinct {
        let stale = WriterPermit::from_trusted_boundary(identity, Epoch::new(1).unwrap());
        assert_eq!(
            adapter.send_turn(&stale, "First", "message.one", None),
            Err(CodexError::Blocked(BlockReason::StaleResourcePermit))
        );
        assert_eq!(adapter.transport().writes.len(), before);
    }
    adapter
        .install_writer_epoch_from_trusted_boundary(Epoch::new(2).unwrap())
        .unwrap();
    assert_eq!(
        adapter.send_turn(&writer_permit(1), "First", "message.one", None),
        Err(CodexError::Blocked(BlockReason::StaleWriterPermit))
    );
    assert_eq!(adapter.transport().writes.len(), before);
}

#[test]
fn all_four_native_request_kinds_write_only_explicit_schema_shaped_answers() {
    let mut answers = BTreeMap::new();
    answers.insert("question.one".to_owned(), vec!["A".to_owned()]);
    let mut user_request = user_input_request(47);
    user_request["id"] = json!("req.user.1");
    let cases = [
        (
            command_request(44),
            NativeAnswer::CommandDecision(ApprovalDecision::Accept),
            json!({"decision":"accept"}),
        ),
        (
            file_request(45),
            NativeAnswer::FileDecision(ApprovalDecision::Decline),
            json!({"decision":"decline"}),
        ),
        (
            permissions_request(46),
            NativeAnswer::PermissionsDenyAll,
            json!({"permissions":{},"scope":"turn"}),
        ),
        (
            user_request,
            NativeAnswer::UserInputAnswers(answers),
            json!({"answers":{"question.one":{"answers":["A"]}}}),
        ),
    ];
    for (request_event, answer, expected_result) in cases {
        let mut adapter = pending_bootstrap(request_event, []);
        let pending = adapter.pending_native_requests().pop().unwrap();
        assert_eq!(pending.native_thread_id, "thread.one");
        assert_eq!(pending.native_turn_id, "turn.bootstrap");
        assert_eq!(pending.resource_epoch, Epoch::new(1).unwrap());
        assert_eq!(pending.stage, NativeRequestStage::Pending);
        assert_eq!(adapter.transport().answer_write_attempts, 0);
        assert!(!adapter.bootstrap_ready());
        let permit = answer_permit(&pending, answer);
        assert_eq!(
            adapter.answer_pending(permit.clone()).unwrap(),
            AnswerWriteOutcome::WrittenAwaitingResolution {
                request_id: pending.request_id.clone()
            }
        );
        let written = adapter.transport().writes.last().unwrap();
        let expected_id = match &pending.request_id {
            NativeRpcId::Number(number) => json!(number),
            NativeRpcId::Text(text) => json!(text),
        };
        assert_eq!(written["id"], expected_id);
        assert_eq!(written["result"], expected_result);
        assert_eq!(adapter.transport().answer_write_attempts, 1);
        assert_eq!(
            adapter.pending_native_requests()[0].stage,
            NativeRequestStage::AnswerWritten
        );
        assert_eq!(
            adapter.answer_pending(permit),
            Err(CodexError::Blocked(BlockReason::AnswerAlreadyWritten))
        );
        assert_eq!(adapter.transport().answer_write_attempts, 1);
    }
}

#[test]
fn user_input_answers_require_exact_question_ids_and_no_synthetic_empty_answer() {
    let mut adapter = pending_bootstrap(user_input_request(51), []);
    let pending = adapter.pending_native_requests().pop().unwrap();
    match &pending.kind {
        NativeRequestKind::UserInput { questions, .. } => {
            assert_eq!(questions.len(), 1);
            assert_eq!(questions[0].id, "question.one");
        }
        other => panic!("wrong parsed request: {other:?}"),
    }
    let no_answer = answer_permit(&pending, NativeAnswer::UserInputAnswers(BTreeMap::new()));
    assert_eq!(
        adapter.answer_pending(no_answer),
        Err(CodexError::InvalidInput("answer shape is invalid"))
    );
    let mut wrong = BTreeMap::new();
    wrong.insert("question.other".to_owned(), vec!["A".to_owned()]);
    assert_eq!(
        adapter.answer_pending(answer_permit(
            &pending,
            NativeAnswer::UserInputAnswers(wrong)
        )),
        Err(CodexError::InvalidInput("answer shape is invalid"))
    );
    assert_eq!(adapter.transport().answer_write_attempts, 0);
    assert_eq!(
        adapter.pending_native_requests()[0].stage,
        NativeRequestStage::Pending
    );
}

#[test]
fn valid_multiline_user_text_is_preserved_and_null_command_kind_is_unsupported() {
    let mut input = user_input_request(52);
    input["params"]["questions"][0]["question"] = json!("First line\nSecond line");
    let mut adapter = pending_bootstrap(input, []);
    let pending = adapter.pending_native_requests().pop().unwrap();
    let mut answers = BTreeMap::new();
    answers.insert("question.one".to_owned(), vec!["A\nB".to_owned()]);
    adapter
        .answer_pending(answer_permit(
            &pending,
            NativeAnswer::UserInputAnswers(answers),
        ))
        .unwrap();
    assert_eq!(
        adapter.transport().writes.last().unwrap()["result"]["answers"]["question.one"]["answers"]
            [0],
        "A\nB"
    );

    let mut malformed = command_request(53);
    malformed["params"]["kind"] = Value::Null;
    let mut adapter = pending_bootstrap(malformed, []);
    let pending = adapter.pending_native_requests().pop().unwrap();
    assert!(matches!(&pending.kind, NativeRequestKind::Unsupported(_)));
    assert_eq!(
        adapter.answer_pending(answer_permit(
            &pending,
            NativeAnswer::CommandDecision(ApprovalDecision::Accept),
        )),
        Err(CodexError::Blocked(BlockReason::UnsupportedNativeAnswer))
    );
    assert_eq!(adapter.transport().answer_write_attempts, 0);
}

#[test]
fn answer_resolution_waits_for_fresh_native_no_waiting_status() {
    let resolved = json!({"method":"serverRequest/resolved","params":{
        "threadId":"thread.one","requestId":44
    }});
    let mut adapter = pending_bootstrap(
        command_request(44),
        [
            completed("turn.bootstrap", "completed"),
            status("active", &["waitingOnApproval"]),
            resolved,
            status("idle", &[]),
        ],
    );
    let pending = adapter.pending_native_requests().pop().unwrap();
    let permit = answer_permit(
        &pending,
        NativeAnswer::CommandDecision(ApprovalDecision::Accept),
    );
    adapter.answer_pending(permit.clone()).unwrap();
    adapter.poll_once().unwrap();
    adapter.poll_once().unwrap();
    adapter.poll_once().unwrap();
    assert_eq!(adapter.pending_request_count(), 1);
    assert_eq!(
        adapter.pending_native_requests()[0].stage,
        NativeRequestStage::ResolvedAwaitingStatus
    );
    assert!(!adapter.bootstrap_ready());
    adapter.poll_once().unwrap();
    assert_eq!(adapter.pending_request_count(), 0);
    assert!(adapter.bootstrap_ready());
    assert_eq!(
        adapter.answer_pending(permit),
        Err(CodexError::Blocked(BlockReason::StaleNativeRequest))
    );
    assert_eq!(adapter.transport().answer_write_attempts, 1);
}

#[test]
fn malformed_active_status_cannot_retire_resolved_request() {
    let resolved = json!({"method":"serverRequest/resolved","params":{
        "threadId":"thread.one","requestId":54
    }});
    let malformed = json!({"method":"thread/status/changed","params":{
        "threadId":"thread.one","status":{"type":"active"}
    }});
    let mut adapter = pending_bootstrap(
        command_request(54),
        [
            completed("turn.bootstrap", "completed"),
            resolved,
            malformed,
        ],
    );
    let pending = adapter.pending_native_requests().pop().unwrap();
    adapter
        .answer_pending(answer_permit(
            &pending,
            NativeAnswer::CommandDecision(ApprovalDecision::Decline),
        ))
        .unwrap();
    adapter.poll_once().unwrap();
    adapter.poll_once().unwrap();
    assert_eq!(adapter.pending_request_count(), 1);
    assert_eq!(
        adapter.poll_once(),
        Err(CodexError::Protocol("active status omitted flags"))
    );
    assert_eq!(adapter.pending_request_count(), 1);
    assert!(!adapter.bootstrap_ready());
}

#[test]
fn not_loaded_status_does_not_retire_resolved_request() {
    let resolved = json!({"method":"serverRequest/resolved","params":{
        "threadId":"thread.one","requestId":57
    }});
    let mut adapter = pending_bootstrap(
        command_request(57),
        [
            completed("turn.bootstrap", "completed"),
            resolved,
            status("notLoaded", &[]),
            status("idle", &[]),
        ],
    );
    adapter.poll_once().unwrap();
    adapter.poll_once().unwrap();
    adapter.poll_once().unwrap();
    assert_eq!(adapter.pending_request_count(), 1);
    assert!(!adapter.bootstrap_ready());
    adapter.poll_once().unwrap();
    assert_eq!(adapter.pending_request_count(), 0);
    assert!(adapter.bootstrap_ready());
}

#[test]
fn wrong_request_turn_resource_or_writer_epoch_refuses_before_response_write() {
    let mut adapter = pending_bootstrap(file_request(55), []);
    let pending = adapter.pending_native_requests().pop().unwrap();
    let answer = NativeAnswer::FileDecision(ApprovalDecision::Decline);
    let mut wrong_turn = pending.clone();
    wrong_turn.native_turn_id = "turn.other".into();
    assert_eq!(
        adapter.answer_pending(answer_permit(&wrong_turn, answer.clone())),
        Err(CodexError::Blocked(BlockReason::StaleNativeRequest))
    );
    let mut wrong_id = pending.clone();
    wrong_id.request_id = NativeRpcId::Number(56);
    assert_eq!(
        adapter.answer_pending(answer_permit(&wrong_id, answer.clone())),
        Err(CodexError::Blocked(BlockReason::StaleNativeRequest))
    );
    let mut wrong_epoch = pending.clone();
    wrong_epoch.resource_epoch = Epoch::new(2).unwrap();
    assert_eq!(
        adapter.answer_pending(answer_permit(&wrong_epoch, answer.clone())),
        Err(CodexError::Blocked(BlockReason::StaleResourcePermit))
    );
    let wrong_writer =
        WriterPermit::from_trusted_boundary(identity("resource.other"), Epoch::new(1).unwrap());
    assert_eq!(
        adapter.answer_pending(AuthorizedAnswerPermit::from_authorised_boundary(
            wrong_writer,
            &pending,
            answer.clone(),
        )),
        Err(CodexError::Blocked(BlockReason::StaleResourcePermit))
    );
    adapter
        .install_writer_epoch_from_trusted_boundary(Epoch::new(2).unwrap())
        .unwrap();
    assert_eq!(
        adapter.answer_pending(answer_permit(&pending, answer)),
        Err(CodexError::Blocked(BlockReason::StaleWriterPermit))
    );
    assert_eq!(adapter.transport().answer_write_attempts, 0);
}

#[test]
fn ambiguous_answer_write_is_recorded_once_and_never_retried() {
    let fake = FakeTransport::with_reads(pending_bootstrap_reads(command_request(60), []))
        .fail_answer_write();
    let mut adapter = pending_bootstrap_with_fake(fake);
    let pending = adapter.pending_native_requests().pop().unwrap();
    let permit = answer_permit(
        &pending,
        NativeAnswer::CommandDecision(ApprovalDecision::Decline),
    );
    assert_eq!(
        adapter.answer_pending(permit.clone()).unwrap(),
        AnswerWriteOutcome::Uncertain {
            request_id: NativeRpcId::Number(60)
        }
    );
    assert_eq!(adapter.transport().answer_write_attempts, 1);
    assert_eq!(
        adapter.pending_native_requests()[0].stage,
        NativeRequestStage::AnswerWriteUncertain
    );
    assert_eq!(
        adapter.answer_pending(permit),
        Err(CodexError::Blocked(BlockReason::AnswerAlreadyWritten))
    );
    assert_eq!(adapter.transport().answer_write_attempts, 1);
    assert!(!adapter.bootstrap_ready());
}

#[test]
fn duplicate_native_request_id_poison_blocks_any_answer_write() {
    let duplicate = command_request(61);
    let mut adapter = pending_bootstrap(command_request(61), [duplicate]);
    assert_eq!(
        adapter.poll_once(),
        Err(CodexError::Protocol("native request id was reused"))
    );
    let pending = adapter.pending_native_requests().pop().unwrap();
    assert_eq!(
        adapter.answer_pending(answer_permit(
            &pending,
            NativeAnswer::CommandDecision(ApprovalDecision::Decline),
        )),
        Err(CodexError::Blocked(BlockReason::ObservationUnknown))
    );
    assert_eq!(adapter.transport().answer_write_attempts, 0);
}

#[test]
fn unsupported_grants_amendments_and_unknown_request_stay_redacted_pending() {
    for (request, answer) in [
        (
            command_request(70),
            NativeAnswer::CommandExecPolicyAmendmentUnsupported,
        ),
        (
            command_request(71),
            NativeAnswer::CommandNetworkPolicyAmendmentUnsupported,
        ),
        (
            permissions_request(72),
            NativeAnswer::PermissionsGrantUnsupported,
        ),
        (
            json!({"id":73,"method":"item/tool/unknownApproval","params":{
                "threadId":"thread.one","turnId":"turn.bootstrap","itemId":"item.unknown",
                "opaqueSecret":"do not echo"
            }}),
            NativeAnswer::CommandDecision(ApprovalDecision::Accept),
        ),
    ] {
        let mut adapter = pending_bootstrap(request, []);
        let pending = adapter.pending_native_requests().pop().unwrap();
        assert!(pending.redacted.field_names.contains(&"itemId".to_owned()));
        assert!(!format!("{:?}", pending.redacted).contains("do not echo"));
        assert_eq!(
            adapter.answer_pending(answer_permit(&pending, answer)),
            Err(CodexError::Blocked(BlockReason::UnsupportedNativeAnswer))
        );
        assert_eq!(adapter.pending_request_count(), 1);
        assert_eq!(adapter.transport().answer_write_attempts, 0);
    }
}

#[test]
fn debug_of_pending_requests_answers_and_permits_redacts_private_values() {
    let secret = "PB10C_PRIVATE_SENTINEL";
    let mut command = command_request(80);
    command["params"]["command"] = json!(secret);
    let command_adapter = pending_bootstrap(command, []);
    let command_pending = command_adapter.pending_native_requests().pop().unwrap();
    assert!(!format!("{command_pending:?}").contains(secret));

    let mut file = file_request(81);
    file["params"]["reason"] = json!(secret);
    file["params"]["grantRoot"] = json!(format!("/tmp/{secret}"));
    let file_adapter = pending_bootstrap(file, []);
    let file_pending = file_adapter.pending_native_requests().pop().unwrap();
    assert!(!format!("{file_pending:?}").contains(secret));

    let mut input = user_input_request(82);
    input["params"]["questions"][0]["question"] = json!(secret);
    input["params"]["questions"][0]["options"][0]["description"] = json!(secret);
    input["params"]["questions"][0]["isSecret"] = json!(true);
    let input_adapter = pending_bootstrap(input, []);
    let input_pending = input_adapter.pending_native_requests().pop().unwrap();
    assert!(!format!("{input_pending:?}").contains(secret));
    let mut answers = BTreeMap::new();
    answers.insert("question.one".to_owned(), vec![secret.to_owned()]);
    let answer = NativeAnswer::UserInputAnswers(answers);
    let permit = answer_permit(&input_pending, answer.clone());
    assert!(!format!("{answer:?}").contains(secret));
    assert!(!format!("{permit:?}").contains(secret));
}
