//! Selector-only control receipt for an already claimed Codex later turn.
//! The request reuses the exact bounded selector frame in codex_bootstrap;
//! neither direction contains prompt text or a writer permit.

use serde::{Deserialize, Serialize};

use crate::codex_bootstrap::BootstrapControlRequest;
use crate::codex_journal::CodexJournalView;
use crate::codex_turn_journal::{LaterTurnStage, LaterTurnTerminal, LaterTurnView};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LaterTurnControlStage {
    RefusedBeforeEffect,
    ClaimedUnobserved,
    IntentUncertain,
    SubmissionUncertain,
    Submitted {
        native_turn_id: String,
    },
    CompletionObservedPendingIdleProof {
        native_turn_id: String,
        terminal: LaterTurnTerminal,
    },
    Settled {
        native_turn_id: String,
        terminal: LaterTurnTerminal,
    },
    StorageUncertain,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaterTurnControlReceipt {
    pub protocol: String,
    pub command_id: String,
    pub store_lineage: String,
    pub scope_id: String,
    pub session_id: String,
    pub run_id: String,
    pub attempt_id: String,
    pub pod_id: String,
    pub pod_incarnation: u64,
    pub resource_id: String,
    pub resource_epoch: u64,
    pub resource_input_epoch: u64,
    pub writer_epoch: u64,
    pub request_digest: Option<String>,
    pub native_thread_id: Option<String>,
    pub native_session_id: Option<String>,
    pub stage: LaterTurnControlStage,
}

impl LaterTurnControlReceipt {
    pub(crate) fn refused(request: &BootstrapControlRequest) -> Self {
        Self::new(request, None, None)
    }

    pub(crate) fn uncertain(request: &BootstrapControlRequest, digest: &str) -> Self {
        let mut receipt = Self::new(request, Some(digest), None);
        receipt.stage = LaterTurnControlStage::SubmissionUncertain;
        receipt
    }

    pub(crate) fn new(
        request: &BootstrapControlRequest,
        digest: Option<&str>,
        view: Option<&LaterTurnView>,
    ) -> Self {
        let stage = match view {
            None if digest.is_some() => LaterTurnControlStage::ClaimedUnobserved,
            None => LaterTurnControlStage::RefusedBeforeEffect,
            Some(view) => match view.stage {
                LaterTurnStage::IntentDurable | LaterTurnStage::IntentUnknownAfterReopen => {
                    LaterTurnControlStage::IntentUncertain
                }
                LaterTurnStage::SubmissionUncertain => LaterTurnControlStage::SubmissionUncertain,
                LaterTurnStage::Submitted => view.native_turn_id.as_ref().map_or(
                    LaterTurnControlStage::SubmissionUncertain,
                    |id| LaterTurnControlStage::Submitted {
                        native_turn_id: id.clone(),
                    },
                ),
                LaterTurnStage::CompletionObservedPendingIdleProof(terminal) => {
                    view.native_turn_id.as_ref().map_or(
                        LaterTurnControlStage::SubmissionUncertain,
                        |id| LaterTurnControlStage::CompletionObservedPendingIdleProof {
                            native_turn_id: id.clone(),
                            terminal,
                        },
                    )
                }
                LaterTurnStage::Settled(terminal) => view.native_turn_id.as_ref().map_or(
                    LaterTurnControlStage::SubmissionUncertain,
                    |id| LaterTurnControlStage::Settled {
                        native_turn_id: id.clone(),
                        terminal,
                    },
                ),
                LaterTurnStage::StorageUncertain => LaterTurnControlStage::StorageUncertain,
            },
        };
        Self {
            protocol: request.protocol.clone(),
            command_id: request.command_id.clone(),
            store_lineage: request.store_lineage.clone(),
            scope_id: request.scope_id.clone(),
            session_id: request.session_id.clone(),
            run_id: request.run_id.clone(),
            attempt_id: request.attempt_id.clone(),
            pod_id: request.pod_id.clone(),
            pod_incarnation: request.pod_incarnation,
            resource_id: request.resource_id.clone(),
            resource_epoch: request.resource_epoch,
            resource_input_epoch: request.resource_input_epoch,
            writer_epoch: request.writer_epoch,
            request_digest: digest.map(str::to_owned),
            native_thread_id: view.map(|value| value.native_thread_id.clone()),
            native_session_id: view.map(|value| value.native_session_id.clone()),
            stage,
        }
    }
}

/// Read-only, nonce-bound pod journal observation. The producer must have
/// checked current manager/lease and a held BootstrapCompleted journal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexAnchorInspectReceipt {
    pub protocol: String,
    pub nonce: String,
    pub bootstrap_command_id: String,
    pub store_lineage: String,
    pub scope_id: String,
    pub session_id: String,
    pub run_id: String,
    pub attempt_id: String,
    pub pod_id: String,
    pub pod_incarnation: u64,
    pub resource_id: String,
    pub resource_epoch: u64,
    pub resource_input_epoch: u64,
    pub writer_epoch: u64,
    pub bootstrap_request_digest: String,
    pub native_thread_id: String,
    pub native_session_id: String,
    pub native_turn_id: String,
}

impl CodexAnchorInspectReceipt {
    pub(crate) fn from_completed(
        request: &BootstrapControlRequest,
        digest: &str,
        journal: &CodexJournalView,
    ) -> Option<Self> {
        use crate::codex_journal::CodexJournalStage;
        if journal.stage != CodexJournalStage::BootstrapCompleted
            || journal.command_key.as_deref() != Some(request.command_id.as_str())
            || journal.payload_digest.as_deref() != Some(digest)
        {
            return None;
        }
        Some(Self {
            protocol: request.protocol.clone(),
            nonce: request.nonce.clone()?,
            bootstrap_command_id: request.command_id.clone(),
            store_lineage: request.store_lineage.clone(),
            scope_id: request.scope_id.clone(),
            session_id: request.session_id.clone(),
            run_id: request.run_id.clone(),
            attempt_id: request.attempt_id.clone(),
            pod_id: request.pod_id.clone(),
            pod_incarnation: request.pod_incarnation,
            resource_id: request.resource_id.clone(),
            resource_epoch: request.resource_epoch,
            resource_input_epoch: request.resource_input_epoch,
            writer_epoch: request.writer_epoch,
            bootstrap_request_digest: digest.into(),
            native_thread_id: journal.native_thread_id.clone()?,
            native_session_id: journal.native_session_id.clone()?,
            native_turn_id: journal.native_turn_id.clone()?,
        })
    }
}

#[cfg(test)]
mod anchor_tests {
    use super::*;
    use crate::codex_journal::CodexJournalStage;

    fn request() -> BootstrapControlRequest {
        BootstrapControlRequest {
            protocol: "podbay.codex-anchor.inspect/1".into(),
            operation: "codex.anchor.inspect".into(),
            token: "fixture.token".into(),
            command_id: "command.bootstrap.fixture".into(),
            store_lineage: "lineage.fixture".into(),
            scope_id: "scope.fixture".into(),
            session_id: "session.fixture".into(),
            run_id: "run.fixture".into(),
            attempt_id: "attempt.fixture".into(),
            pod_id: "pod.fixture".into(),
            pod_incarnation: 1,
            resource_id: "resource.fixture".into(),
            resource_epoch: 1,
            resource_input_epoch: 2,
            writer_epoch: 2,
            nonce: Some("nonce.fixture".into()),
        }
    }

    #[test]
    fn anchor_receipt_requires_fsynced_completion_and_exact_native_turn() {
        let request = request();
        let digest = "a".repeat(64);
        let mut journal = CodexJournalView {
            stage: CodexJournalStage::BootstrapSubmitted,
            command_key: Some(request.command_id.clone()),
            payload_digest: Some(digest.clone()),
            native_thread_id: Some("thread.fixture".into()),
            native_session_id: Some("native.session.fixture".into()),
            client_message_id: Some("message.fixture".into()),
            native_turn_id: Some("turn.fixture".into()),
        };
        for stage in [
            CodexJournalStage::BootstrapSubmitted,
            CodexJournalStage::BootstrapCompletionObservedPendingIdleProof,
            CodexJournalStage::BootstrapFailed,
            CodexJournalStage::BootstrapInterrupted,
            CodexJournalStage::StorageUncertain,
        ] {
            journal.stage = stage;
            assert!(
                CodexAnchorInspectReceipt::from_completed(&request, &digest, &journal).is_none()
            );
        }
        journal.stage = CodexJournalStage::BootstrapCompleted;
        let completed = CodexAnchorInspectReceipt::from_completed(&request, &digest, &journal)
            .expect("completed journal has exact native IDs");
        assert_eq!(completed.native_turn_id, "turn.fixture");
        assert_eq!(completed.writer_epoch, 2);
        journal.native_turn_id = None;
        assert!(CodexAnchorInspectReceipt::from_completed(&request, &digest, &journal).is_none());
        journal.native_turn_id = Some("turn.fixture".into());
        journal.command_key = Some("command.other".into());
        assert!(CodexAnchorInspectReceipt::from_completed(&request, &digest, &journal).is_none());
    }
}
