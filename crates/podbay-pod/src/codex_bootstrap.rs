//! Selector-only local control for one claimed Codex V2 bootstrap. The socket
//! frame never carries prompt bytes or an in-memory writer permit.

use podbay_core::{
    AttemptId, CommandId, PodId, ResourceId, RunId, ScopeId, SessionId, StoreLineageId,
};
use podbay_store::{BootstrapSendSelector, NativeWriterTarget};
use serde::{Deserialize, Serialize};

use crate::manifest::{BoundPeerManifest, LaunchDescriptor, PodError};

pub const CODEX_BOOTSTRAP_PROTOCOL: &str = "podbay.codex-bootstrap/1";
pub const CODEX_BOOTSTRAP_INSPECT_PROTOCOL: &str = "podbay.codex-bootstrap.inspect/1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BootstrapControlRequest {
    pub protocol: String,
    pub operation: String,
    pub token: String,
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
}

impl BootstrapControlRequest {
    pub(crate) fn from_selector(
        selector: &BootstrapSendSelector,
        writer_epoch: u64,
        token: &str,
    ) -> Self {
        let target = &selector.native_target;
        Self {
            protocol: CODEX_BOOTSTRAP_PROTOCOL.into(),
            operation: "codex.bootstrap".into(),
            token: token.into(),
            command_id: selector.command_id.as_str().into(),
            store_lineage: target.store_lineage.as_str().into(),
            scope_id: selector.scope_id.as_str().into(),
            session_id: target.session_id.as_str().into(),
            run_id: target.run_id.as_str().into(),
            attempt_id: target.attempt_id.as_str().into(),
            pod_id: target.pod_id.as_str().into(),
            pod_incarnation: target.pod_incarnation,
            resource_id: target.resource_id.as_str().into(),
            resource_epoch: target.resource_epoch,
            resource_input_epoch: target.resource_input_epoch,
            writer_epoch,
        }
    }

    pub(crate) fn for_inspection(
        selector: &BootstrapSendSelector,
        writer_epoch: u64,
        token: &str,
    ) -> Self {
        let mut request = Self::from_selector(selector, writer_epoch, token);
        request.protocol = CODEX_BOOTSTRAP_INSPECT_PROTOCOL.into();
        request.operation = "codex.bootstrap.inspect".into();
        request
    }

    /// Request values are selectors. Compare them to the immutable manifest
    /// before using them to read the claimed command from the store.
    pub(crate) fn checked_selector(
        &self,
        binding: &BoundPeerManifest,
        launch: &LaunchDescriptor,
    ) -> Result<(BootstrapSendSelector, u64), PodError> {
        self.checked_selector_for(binding, launch, CODEX_BOOTSTRAP_PROTOCOL, "codex.bootstrap")
    }

    pub(crate) fn checked_inspection_selector(
        &self,
        binding: &BoundPeerManifest,
        launch: &LaunchDescriptor,
    ) -> Result<(BootstrapSendSelector, u64), PodError> {
        self.checked_selector_for(
            binding,
            launch,
            CODEX_BOOTSTRAP_INSPECT_PROTOCOL,
            "codex.bootstrap.inspect",
        )
    }

    fn checked_selector_for(
        &self,
        binding: &BoundPeerManifest,
        launch: &LaunchDescriptor,
        protocol: &str,
        operation: &str,
    ) -> Result<(BootstrapSendSelector, u64), PodError> {
        if self.protocol != protocol
            || self.operation != operation
            || self.store_lineage != binding.store_lineage
            || self.scope_id != launch.scope_id
            || self.session_id != launch.session_id
            || self.run_id != launch.run_id
            || self.attempt_id != launch.attempt_id
            || self.pod_id != launch.pod_id
            || self.pod_incarnation != launch.incarnation
            || self.resource_id != launch.resource_id
            || self.resource_epoch != binding.resource_epoch
            || binding.resource_input_epochs.len() != 1
            || binding.resource_input_epochs.get(&self.resource_id)
                != Some(&self.resource_input_epoch)
            || self.writer_epoch == 0
        {
            return Err(PodError::Refused(
                "Codex bootstrap selector differs from binding",
            ));
        }
        let target = NativeWriterTarget {
            store_lineage: StoreLineageId::try_from(self.store_lineage.as_str())
                .map_err(|_| PodError::Invalid("bootstrap lineage selector"))?,
            scope_id: ScopeId::try_from(self.scope_id.as_str())
                .map_err(|_| PodError::Invalid("bootstrap scope selector"))?,
            session_id: SessionId::try_from(self.session_id.as_str())
                .map_err(|_| PodError::Invalid("bootstrap Session selector"))?,
            run_id: RunId::try_from(self.run_id.as_str())
                .map_err(|_| PodError::Invalid("bootstrap Run selector"))?,
            attempt_id: AttemptId::try_from(self.attempt_id.as_str())
                .map_err(|_| PodError::Invalid("bootstrap Attempt selector"))?,
            pod_id: PodId::try_from(self.pod_id.as_str())
                .map_err(|_| PodError::Invalid("bootstrap Pod selector"))?,
            pod_incarnation: self.pod_incarnation,
            resource_id: ResourceId::try_from(self.resource_id.as_str())
                .map_err(|_| PodError::Invalid("bootstrap Resource selector"))?,
            resource_epoch: self.resource_epoch,
            resource_input_epoch: self.resource_input_epoch,
        };
        let selector = BootstrapSendSelector {
            scope_id: target.scope_id.clone(),
            command_id: CommandId::try_from(self.command_id.as_str())
                .map_err(|_| PodError::Invalid("bootstrap CommandId selector"))?,
            native_target: target,
        };
        Ok((selector, self.writer_epoch))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BootstrapControlStage {
    RefusedBeforeEffect,
    /// Current claimed command, with no durable native journal fact in this pod.
    ClaimedUnobserved,
    ThreadCreateUncertain,
    ThreadCreated {
        native_thread_id: String,
        native_session_id: String,
    },
    BootstrapUncertain {
        native_thread_id: String,
        native_session_id: String,
    },
    Submitted {
        native_thread_id: String,
        native_session_id: String,
        native_turn_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapControlReceipt {
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
    pub stage: BootstrapControlStage,
}

impl BootstrapControlReceipt {
    pub(crate) fn new(
        request: &BootstrapControlRequest,
        request_digest: Option<&str>,
        stage: BootstrapControlStage,
    ) -> Self {
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
            request_digest: request_digest.map(str::to_owned),
            stage,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selector() -> BootstrapSendSelector {
        let target = NativeWriterTarget {
            store_lineage: StoreLineageId::try_from("lineage.fixture").unwrap(),
            scope_id: ScopeId::try_from("scope.fixture").unwrap(),
            session_id: SessionId::try_from("session.fixture").unwrap(),
            run_id: RunId::try_from("run.fixture").unwrap(),
            attempt_id: AttemptId::try_from("attempt.fixture").unwrap(),
            pod_id: PodId::try_from("pod.fixture").unwrap(),
            pod_incarnation: 1,
            resource_id: ResourceId::try_from("resource.fixture").unwrap(),
            resource_epoch: 1,
            resource_input_epoch: 1,
        };
        BootstrapSendSelector {
            scope_id: target.scope_id.clone(),
            command_id: CommandId::try_from("command.fixture").unwrap(),
            native_target: target,
        }
    }

    #[test]
    fn bootstrap_frame_carries_only_selectors_and_rejects_prompt_field() {
        let request = BootstrapControlRequest::from_selector(&selector(), 3, "bearer.fixture");
        let encoded = serde_json::to_vec(&request).unwrap();
        let decoded: BootstrapControlRequest = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, request);
        assert!(!encoded.windows(6).any(|window| window == b"prompt"));
        let mut extra: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        extra["prompt"] = serde_json::Value::String("must refuse".into());
        assert!(serde_json::from_value::<BootstrapControlRequest>(extra).is_err());
    }

    #[test]
    fn submitted_receipt_is_exact_native_insertion_not_completion() {
        let request = BootstrapControlRequest::from_selector(&selector(), 3, "bearer.fixture");
        let receipt = BootstrapControlReceipt::new(
            &request,
            Some(&"a".repeat(64)),
            BootstrapControlStage::Submitted {
                native_thread_id: "thread.fixture".into(),
                native_session_id: "session.native.fixture".into(),
                native_turn_id: "turn.fixture".into(),
            },
        );
        let encoded = serde_json::to_vec(&receipt).unwrap();
        assert_eq!(
            serde_json::from_slice::<BootstrapControlReceipt>(&encoded).unwrap(),
            receipt
        );
        assert!(!encoded.windows(9).any(|window| window == b"completed"));
    }

    #[test]
    fn inspection_frame_is_distinct_and_contains_no_native_input() {
        let request = BootstrapControlRequest::for_inspection(&selector(), 3, "bearer.fixture");
        let encoded = serde_json::to_vec(&request).unwrap();
        assert_eq!(request.protocol, CODEX_BOOTSTRAP_INSPECT_PROTOCOL);
        assert_eq!(request.operation, "codex.bootstrap.inspect");
        assert!(!encoded.windows(6).any(|window| window == b"prompt"));
        assert!(!encoded.windows(6).any(|window| window == b"permit"));
        let reply = BootstrapControlReceipt::new(
            &request,
            Some(&"a".repeat(64)),
            BootstrapControlStage::ClaimedUnobserved,
        );
        assert_eq!(reply.protocol, CODEX_BOOTSTRAP_INSPECT_PROTOCOL);
        assert_eq!(
            serde_json::from_slice::<BootstrapControlReceipt>(&serde_json::to_vec(&reply).unwrap())
                .unwrap(),
            reply,
        );
    }
}
