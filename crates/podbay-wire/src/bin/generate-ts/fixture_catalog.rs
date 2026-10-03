//! Rust-constructed cross-language vectors for every advertised PB03c operation.
use std::error::Error;

use podbay_wire::{
    CommandEnvelope, DecimalString, Guard, MutationOperation, ReadEnvelope, ReadOperation, Target,
};
use serde_json::{Value, json};

type FixtureResult<T> = Result<T, Box<dyn Error>>;

fn mutation(
    name: &'static str,
    operation: MutationOperation,
    target: Target,
    body: Value,
) -> FixtureResult<(&'static str, CommandEnvelope)> {
    let slug = name
        .trim_start_matches("command-")
        .trim_end_matches(".json");
    Ok((
        name,
        CommandEnvelope::new_json(
            format!("request.pb03c.{slug}.1"),
            format!("key.pb03c.{slug}.1"),
            target,
            Some(Guard {
                manager_epoch: Some(DecimalString::new(42)),
                ..Guard::default()
            }),
            None,
            operation,
            body,
        )?,
    ))
}

pub fn additional_commands() -> FixtureResult<Vec<(&'static str, CommandEnvelope)>> {
    use MutationOperation as Op;
    let scope = || Target::Scope {
        scope_id: "scope.fixture".to_owned(),
    };
    let session = || Target::Session {
        session_id: "session.fixture".to_owned(),
    };
    let run = || Target::Run {
        run_id: "run.fixture".to_owned(),
    };
    let delivery = || Target::Delivery {
        delivery_id: "delivery.fixture".to_owned(),
    };
    let resource = || Target::Resource {
        pod_id: "pod.fixture".to_owned(),
        resource_id: "resource.pty".to_owned(),
    };
    let question = || Target::Question {
        question_id: "question.fixture".to_owned(),
    };
    let permission = || Target::Permission {
        permission_id: "permission.fixture".to_owned(),
    };
    let launch = json!({
        "session": {"kind":"new"},
        "role":"coordinator",
        "work":{"kind":"service","resultContractRef":"contract.fixture"},
        "profileRef":"profile.fixture",
        "selection":{"modelId":"model.fixture","fallback":"none"},
        "workspace":{"scopeId":"scope.fixture","relativeCwd":".","basisRef":"revision.fixture","access":"read_write"},
        "toolBundleRefs":["tools.fixture"],
        "authority":{"grantRef":"grant.fixture"},
        "limits":{"wallSeconds":"3600","maxChildren":"4"}
    });
    let mut fixtures = vec![
        mutation("command-launch.json", Op::Launch, scope(), launch.clone())?,
        mutation(
            "command-session-close.json",
            Op::SessionClose,
            session(),
            json!({}),
        )?,
        mutation(
            "command-run-interrupt.json",
            Op::RunInterrupt,
            run(),
            json!({"expectedIntervalId":"interval.fixture"}),
        )?,
        mutation(
            "command-run-report.json",
            Op::RunReport,
            run(),
            json!({"summary":"Worker declared completion","artifactRefs":["artifact.fixture"],
                "evidenceRefs":["evidence.fixture"],"declaration":"succeeded"}),
        )?,
        mutation(
            "command-run-finish.json",
            Op::RunFinish,
            run(),
            json!({"childPolicy":"join"}),
        )?,
        mutation(
            "command-delivery-ack.json",
            Op::DeliveryAck,
            delivery(),
            json!({"kind":"received","evidenceRef":"evidence.delivery"}),
        )?,
        mutation(
            "command-delivery-cancel.json",
            Op::DeliveryCancel,
            delivery(),
            json!({"reason":"Input is no longer needed"}),
        )?,
        mutation(
            "command-control-acquire.json",
            Op::ControlAcquire,
            resource(),
            json!({"expectedLeaseEpoch":"0","holder":"human"}),
        )?,
        mutation(
            "command-control-release.json",
            Op::ControlRelease,
            resource(),
            json!({"leaseId":"lease.fixture"}),
        )?,
        mutation(
            "command-terminal-detach.json",
            Op::TerminalDetach,
            resource(),
            json!({"viewerId":"viewer.fixture"}),
        )?,
        mutation(
            "command-question-ask.json",
            Op::QuestionAsk,
            run(),
            json!({"recipient":{"kind":"human"},"title":"Choose approach",
                "context":"A scoped decision is required",
                "items":[{"itemId":"item.route","prompt":"Select one route","required":true,
                    "answerMode":"single_choice","options":["A","B"]}],
                "independentWorkAvailable":true}),
        )?,
        mutation(
            "command-question-answer.json",
            Op::QuestionAnswer,
            question(),
            json!({"expectedRevision":"3","response":{"kind":"submit",
                "answers":[{"itemId":"item.route","value":"A"}]}}),
        )?,
        mutation(
            "command-question-cancel.json",
            Op::QuestionCancel,
            question(),
            json!({"expectedRevision":"3","reason":"Decision no longer applies"}),
        )?,
        mutation(
            "command-permission-request.json",
            Op::PermissionRequest,
            resource(),
            json!({"action":"tool.invoke","subjectDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "runId":"run.fixture","attemptId":"attempt.fixture","requestEpoch":"2",
                "grantDurationSeconds":"300","expiresAt":"2026-10-03T12:05:00Z"}),
        )?,
        mutation(
            "command-permission-decide.json",
            Op::PermissionDecide,
            permission(),
            json!({"expectedRevision":"3","requestEpoch":"2","decision":{"kind":"allow_once"}}),
        )?,
    ];
    let mut existing = launch;
    existing["session"] = json!({"kind":"existing","sessionId":"session.fixture"});
    existing["role"] = json!("worker");
    existing["work"] = json!({"kind":"task","input":[{"kind":"text","text":"Review the result"}],
        "taskRef":{"namespace":"sample","id":"task.42"},"resultContractRef":"contract.fixture"});
    let existing = CommandEnvelope::new_json(
        "request.pb03c.launch-existing.1",
        fixtures[0].1.key.clone(),
        scope(),
        Some(Guard {
            manager_epoch: Some(DecimalString::new(42)),
            ..Guard::default()
        }),
        None,
        Op::Launch,
        existing,
    )?;
    fixtures.push(("command-launch-existing.json", existing));
    Ok(fixtures)
}

fn read(
    name: &'static str,
    operation: ReadOperation,
    target: Target,
    body: Value,
) -> FixtureResult<(&'static str, ReadEnvelope)> {
    let slug = name.trim_start_matches("read-").trim_end_matches(".json");
    Ok((
        name,
        ReadEnvelope::new_json(
            format!("request.pb03c.read.{slug}.1"),
            target,
            operation,
            body,
        )?,
    ))
}

pub fn reads() -> FixtureResult<Vec<(&'static str, ReadEnvelope)>> {
    use ReadOperation as Op;
    let scope = || Target::Scope {
        scope_id: "scope.fixture".to_owned(),
    };
    let resource = || Target::Resource {
        pod_id: "pod.fixture".to_owned(),
        resource_id: "resource.pty".to_owned(),
    };
    let cursor = json!({"storeLineage":"store.fixture","scopeId":"scope.fixture","sequence":"0"});
    Ok(vec![
        read(
            "read-capabilities-get.json",
            Op::CapabilitiesGet,
            scope(),
            json!({}),
        )?,
        read(
            "read-commands-get.json",
            Op::CommandsGet,
            scope(),
            json!({"selector":{"kind":"key","key":"key.pb03c.launch.1"}}),
        )?,
        read(
            "read-run-get.json",
            Op::RunGet,
            Target::Run {
                run_id: "run.fixture".to_owned(),
            },
            json!({}),
        )?,
        read(
            "read-session-get.json",
            Op::SessionGet,
            Target::Session {
                session_id: "session.fixture".to_owned(),
            },
            json!({}),
        )?,
        read(
            "read-delivery-get.json",
            Op::DeliveryGet,
            Target::Delivery {
                delivery_id: "delivery.fixture".to_owned(),
            },
            json!({}),
        )?,
        read(
            "read-snapshot-get.json",
            Op::SnapshotGet,
            scope(),
            json!({}),
        )?,
        read(
            "read-event-subscribe.json",
            Op::EventsSubscribe,
            scope(),
            json!({"after":cursor.clone()}),
        )?,
        read(
            "read-history-read.json",
            Op::HistoryRead,
            scope(),
            json!({"after":cursor,"limit":"100"}),
        )?,
        read(
            "read-terminal-snapshot.json",
            Op::TerminalSnapshot,
            resource(),
            json!({}),
        )?,
        read(
            "read-terminal-attach.json",
            Op::TerminalAttach,
            resource(),
            json!({"after":"0"}),
        )?,
        read(
            "read-terminal-observe.json",
            Op::TerminalObserve,
            resource(),
            json!({"after":"0"}),
        )?,
    ])
}
