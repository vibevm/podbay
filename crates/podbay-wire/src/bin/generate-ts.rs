//! Regenerate or check the thin TypeScript v1 binding from Rust-owned wire definitions.
#[path = "generate-ts/fixture_catalog.rs"]
mod fixture_catalog;
use std::env;
use std::fs;
use std::path::PathBuf;

use podbay_wire::{
    CommandBody, CommandEnvelope, ContentBlock, DecimalString, Guard, PausePolicy, ResourceAction,
    ResourceCommandBody, ResumePolicy, RunPauseBody, RunResumeBody, RunStopBody, SendPolicy,
    SessionSendBody, SessionWriterLeaseRenewBody, StopScope, Target, contract_manifest, typescript_source,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let check = match env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => false,
        [flag] if flag == "--check" => true,
        _ => return Err("usage: cargo run -p podbay-wire --bin generate-ts -- [--check]".into()),
    };
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = vec![
        (
            root.join("bindings/typescript/src/generated.ts"),
            typescript_source(),
        ),
        (
            root.join("schema/v1/contract.json"),
            format!("{}\n", serde_json::to_string_pretty(&contract_manifest())?),
        ),
    ];
    for (name, command) in command_fixtures()? {
        let value: serde_json::Value = serde_json::from_slice(&command.encode_json()?)?;
        files.push((
            root.join("schema/v1").join(name),
            format!("{}\n", serde_json::to_string_pretty(&value)?),
        ));
    }
    for (name, command) in fixture_catalog::additional_commands()? {
        let value: serde_json::Value = serde_json::from_slice(&command.encode_json()?)?;
        files.push((
            root.join("schema/v1").join(name),
            format!("{}\n", serde_json::to_string_pretty(&value)?),
        ));
    }
    for (name, request) in fixture_catalog::reads()? {
        let value: serde_json::Value = serde_json::from_slice(&request.encode_json()?)?;
        files.push((
            root.join("schema/v1").join(name),
            format!("{}\n", serde_json::to_string_pretty(&value)?),
        ));
    }
    for (path, expected) in files {
        if check {
            let actual = fs::read_to_string(&path)?;
            if actual != expected {
                return Err(format!("generated artifact is stale: {}", path.display()).into());
            }
        } else {
            fs::write(&path, expected)?;
            println!("generated {}", path.display());
        }
    }
    Ok(())
}

fn command_fixtures() -> Result<Vec<(&'static str, CommandEnvelope)>, Box<dyn std::error::Error>> {
    let run = || Target::Run {
        run_id: "run.fixture".to_owned(),
    };
    let run_guard = || {
        Some(Guard {
            manager_epoch: Some(DecimalString::new(42)),
            target_revision: Some(DecimalString::new(5)),
            ..Guard::default()
        })
    };
    Ok(vec![
        (
            "command-session-writerLease-renew.json",
            CommandEnvelope::new(
                "request.pb24.renew.1", "key.pb24.renew.1",
                Target::Session { session_id: "session.fixture".to_owned() },
                Some(Guard { manager_epoch: Some(DecimalString::new(42)),
                    writer_epoch: Some(DecimalString::new(1)), ..Guard::default() }),
                None,
                CommandBody::SessionWriterLeaseRenew(SessionWriterLeaseRenewBody {
                    expected_writer_epoch: DecimalString::new(1),
                    expected_lease_expires_at_unix_seconds: DecimalString::new(1_800_000_000),
                }),
            )?,
        ),
        (
            "command-session-send.json",
            CommandEnvelope::new(
                "request.pb03.send.1",
                "key.pb03.send.1",
                Target::Session {
                    session_id: "session.fixture".to_owned(),
                },
                Some(Guard {
                    manager_epoch: Some(DecimalString::new(42)),
                    ..Guard::default()
                }),
                None,
                CommandBody::SessionSend(SessionSendBody {
                    content: vec![ContentBlock::Text {
                        text: "Hello PodBay".to_owned(),
                    }],
                    policy: SendPolicy::WhenIdle,
                }),
            )?,
        ),
        (
            "command-run-pause.json",
            CommandEnvelope::new(
                "request.pb03.pause.1",
                "key.pb03.pause.1",
                run(),
                run_guard(),
                None,
                CommandBody::RunPause(RunPauseBody {
                    policy: PausePolicy::Drain,
                }),
            )?,
        ),
        (
            "command-run-resume.json",
            CommandEnvelope::new(
                "request.pb03.resume.1",
                "key.pb03.resume.1",
                run(),
                run_guard(),
                None,
                CommandBody::RunResume(RunResumeBody {
                    policy: ResumePolicy::LiveOnly,
                }),
            )?,
        ),
        (
            "command-run-stop.json",
            CommandEnvelope::new(
                "request.pb03.stop.1",
                "key.pb03.stop.1",
                run(),
                run_guard(),
                None,
                CommandBody::RunStop(RunStopBody {
                    scope: StopScope::SelfOnly,
                }),
            )?,
        ),
        (
            "command-resource-write.json",
            CommandEnvelope::new(
                "request.pb03.1",
                "key.pb03.write.1",
                Target::Resource {
                    pod_id: "pod.fixture".to_owned(),
                    resource_id: "resource.pty".to_owned(),
                },
                Some(Guard {
                    manager_epoch: Some(DecimalString::new(42)),
                    pod_epoch: Some(DecimalString::new(7)),
                    resource_epoch: Some(DecimalString::new(3)),
                    lease_epoch: Some(DecimalString::new(19)),
                    ..Guard::default()
                }),
                Some("2026-10-03T12:00:00Z".to_owned()),
                CommandBody::ResourceCommand(ResourceCommandBody {
                    command: ResourceAction::Write {
                        content_ref: "artifact.input.1".to_owned(),
                    },
                }),
            )?,
        ),
    ])
}
