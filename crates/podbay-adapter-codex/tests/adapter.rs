use std::collections::VecDeque;
use std::io;
use std::path::PathBuf;

use podbay_adapter_codex::{
    ApprovalPolicy, BootstrapState, CodecError, CodexError, CodexResource, JsonlTransport,
    MAX_FRAME_BYTES, PinnedCodexConfig, ResourceIdentity, Sandbox, TESTED_CODEX_CLI_VERSION,
    TESTED_V2_SCHEMA_SHA256, decode, encode,
};
use podbay_core::{AttemptId, Epoch, PodId, ResourceId, RunId, SessionId};
use serde_json::{Value, json};

#[derive(Default)]
struct FakeTransport {
    reads: VecDeque<Vec<u8>>,
    writes: Vec<Value>,
}

impl FakeTransport {
    fn with_reads(reads: impl IntoIterator<Item = Value>) -> Self {
        Self {
            reads: reads
                .into_iter()
                .map(|value| encode(&value).unwrap())
                .collect(),
            writes: Vec::new(),
        }
    }

    fn with_raw_read(raw: Vec<u8>) -> Self {
        Self {
            reads: VecDeque::from([raw]),
            writes: Vec::new(),
        }
    }

    fn methods(&self) -> Vec<&str> {
        self.writes
            .iter()
            .map(|value| value["method"].as_str().unwrap())
            .collect()
    }
}

impl JsonlTransport for FakeTransport {
    fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        self.writes.push(decode(line).unwrap());
        Ok(())
    }

    fn read_line(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.reads.pop_front())
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
    json!({
        "id":id,
        "sessionId":id,
        "cwd":"/tmp/podbay-codex-work",
        "model":"gpt-6-sol",
        "reasoningEffort":"medium",
        "status":{"type":status},
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

fn resource(reads: impl IntoIterator<Item = Value>) -> CodexResource<FakeTransport> {
    CodexResource::new(
        FakeTransport::with_reads(reads),
        identity("resource.structured"),
        config(),
    )
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
        "threadId":"thread.one","turnId":"turn.bootstrap","itemId":"item.one"
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
    assert_eq!(
        adapter.transport().writes[2]["params"]["includeTurns"],
        true
    );
    assert_eq!(
        adapter.transport().writes[3]["params"]["threadId"],
        "thread.one"
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
