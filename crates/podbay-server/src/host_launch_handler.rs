//! Explicitly configured host-backed `launch` plus the existing read surface.
//! This slice admits only the host planner's no-input Coordinator/Service root.

use podbay_host::{
    AuthenticatedTransport, DurableAuthority, HostDispatchPort, HostError, LaunchPodError,
    LaunchPodReceipt, StablePortReceipt, TrustedWireRootLaunchPolicy,
};
use podbay_store::{BoundLaunchRecord, LaunchDispatchStage, StoreError};
use podbay_wire::{
    CommandBody, CommandEnvelope, CommandStage, DecimalString, EventCursor, ProtocolVersion,
    ReadEnvelope, Receipt, RuntimeError, RuntimeErrorCode, Target,
};
use serde_json::{Value, json};

use crate::{Handler, host_read_handler::HostReadHandler};

pub(crate) struct HostLaunchHandler<'a, P: HostDispatchPort> {
    authority: &'a mut DurableAuthority<P>,
    policy: &'a TrustedWireRootLaunchPolicy,
}

impl<'a, P: HostDispatchPort> HostLaunchHandler<'a, P> {
    pub(crate) fn new(
        authority: &'a mut DurableAuthority<P>,
        policy: &'a TrustedWireRootLaunchPolicy,
    ) -> Self {
        Self { authority, policy }
    }
}

impl<P: HostDispatchPort> Handler for HostLaunchHandler<'_, P>
where
    P::Receipt: StablePortReceipt,
{
    fn command<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        request: CommandEnvelope,
    ) -> Result<Receipt<Value>, RuntimeError> {
        if !matches!(&request.body, CommandBody::Launch(_)) {
            return Err(refusal(
                RuntimeErrorCode::Unsupported,
                "mutation is unavailable on this manager endpoint",
            ));
        }
        let Target::Scope { scope_id } = &request.target else {
            return Err(refusal(
                RuntimeErrorCode::InvalidInput,
                "scope target required",
            ));
        };
        let scope_id = scope_id.clone();
        let mut canonical_intent = b"podbay.wire-launch/1\0".to_vec();
        canonical_intent.extend_from_slice(request.payload_digest.as_bytes());
        let command_key = request.key.clone();
        let outcome = self
            .authority
            .launch_new_root_codex_v2_from_wire(transport, request, self.policy)
            .map_err(launch_error)?;
        let command_id = outcome.receipt.command_id.clone();
        let scope = podbay_core::ScopeId::try_from(scope_id.as_str())
            .map_err(|_| committed_projection_error(&command_id))?;
        let binding = self
            .authority
            .lookup_bound_root_codex_v2_by_key(transport, &scope, &command_key, &canonical_intent)
            .map_err(|_| committed_projection_error(&command_id))?
            .ok_or_else(|| committed_projection_error(&command_id))?;
        if binding.receipt != outcome.receipt {
            return Err(committed_projection_error(&command_id));
        }
        project_launch_receipt(self.authority, &scope_id, outcome, &binding)
    }

    fn read<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        request: ReadEnvelope,
    ) -> Result<Value, RuntimeError> {
        HostReadHandler::new(self.authority).read(transport, request)
    }
}

fn project_launch_receipt<P: HostDispatchPort>(
    authority: &DurableAuthority<P>,
    scope_id: &str,
    outcome: LaunchPodReceipt,
    binding: &BoundLaunchRecord,
) -> Result<Receipt<Value>, RuntimeError> {
    let original = outcome.receipt;
    let command_id = original.command_id;
    let event_sequence = u64::try_from(original.event_sequence)
        .ok()
        .filter(|sequence| *sequence > 0)
        .ok_or_else(|| committed_projection_error(&command_id))?;
    let outbox_id = u64::try_from(original.outbox_id)
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| committed_projection_error(&command_id))?;
    let (state, launch_stage) = match outcome.status.stage {
        LaunchDispatchStage::Prepared => (CommandStage::Persisted, "prepared"),
        LaunchDispatchStage::ClaimedUncertain => (CommandStage::Uncertain, "claimed_uncertain"),
        LaunchDispatchStage::RefusedBeforeEffect => {
            (CommandStage::Rejected, "refused_before_effect")
        }
        LaunchDispatchStage::UncertainAfterPossibleEffect => {
            (CommandStage::Uncertain, "uncertain_after_possible_effect")
        }
        LaunchDispatchStage::HostAccepted => (CommandStage::HostAccepted, "host_accepted"),
        // The port's settled host call is not provider consumption or a
        // completed task. Preserve its exact stage in value; project only the
        // weaker established host acceptance into the public command stage.
        LaunchDispatchStage::PortSettled => (CommandStage::HostAccepted, "port_settled"),
    };
    let position = DecimalString::new(event_sequence);
    let receipt = Receipt {
        protocol: ProtocolVersion::V1,
        command_id: command_id.clone(),
        state,
        value: json!({
            "revisionKind": "admission_event_sequence",
            "launchStage": launch_stage,
            "eventSequence": event_sequence.to_string(),
            "outboxId": outbox_id.to_string(),
            "digestVersion": original.digest_version,
            "requestDigest": original.request_digest,
            "portReceiptRef": outcome.status.receipt_ref,
            "duplicate": outcome.duplicate,
            "portCalled": outcome.port_called,
            "scopeId": binding.scope_id,
            "sessionId": binding.session_id,
            "runId": binding.run_id,
            "attemptId": binding.attempt_id,
            "podId": binding.pod_id,
            "podIncarnation": binding.pod_incarnation.to_string(),
            "resources": binding.resources.iter().map(|resource| json!({
                "resourceId": resource.id,
                "kind": resource.kind,
                "epoch": resource.epoch.to_string(),
            })).collect::<Vec<_>>(),
        }),
        revision: position,
        cursor: EventCursor {
            store_lineage: authority.store_lineage_for_receipt().to_owned(),
            scope_id: scope_id.to_owned(),
            sequence: position,
        },
    };
    receipt
        .validate()
        .map_err(|_| committed_projection_error(&command_id))?;
    Ok(receipt)
}

fn committed_projection_error(command_id: &str) -> RuntimeError {
    RuntimeError {
        code: RuntimeErrorCode::Uncertain,
        message: "committed launch receipt cannot be projected; query command".into(),
        retry: "query_command".into(),
        command_id: Some(command_id.into()),
    }
}

fn refusal(code: RuntimeErrorCode, message: &str) -> RuntimeError {
    RuntimeError {
        code,
        message: message.into(),
        retry: "never".into(),
        command_id: None,
    }
}

fn launch_error(error: LaunchPodError) -> RuntimeError {
    match error {
        LaunchPodError::CommittedDispatchUnavailable { receipt, .. }
        | LaunchPodError::OutcomeNotRecorded { receipt, .. } => RuntimeError {
            code: RuntimeErrorCode::Uncertain,
            message: "launch admission committed; dispatch outcome must be queried".into(),
            retry: "query_command".into(),
            command_id: Some(receipt.command_id),
        },
        LaunchPodError::Host(host) => match host {
            HostError::Unauthenticated | HostError::Unauthorised => {
                refusal(RuntimeErrorCode::Forbidden, "launch authority unavailable")
            }
            HostError::InvalidInput => {
                refusal(RuntimeErrorCode::InvalidInput, "launch input is invalid")
            }
            HostError::StaleGuard => {
                refusal(RuntimeErrorCode::StaleGuard, "launch authority changed")
            }
            HostError::DeadlineExpired => refusal(
                RuntimeErrorCode::DeadlineExceeded,
                "launch deadline elapsed",
            ),
            HostError::Unsupported | HostError::NativeResolutionUnverified => refusal(
                RuntimeErrorCode::Unsupported,
                "launch capability is unavailable",
            ),
            HostError::AuthorityStoreUnavailable => refusal(
                RuntimeErrorCode::StorageFailure,
                "launch authority store unavailable",
            ),
            HostError::UncertainAfterPossibleEffect { .. } => RuntimeError {
                code: RuntimeErrorCode::Uncertain,
                message: "launch outcome uncertain; query the original key".into(),
                retry: "query_command".into(),
                command_id: None,
            },
            HostError::RefusedBeforeEffect => refusal(
                RuntimeErrorCode::Unavailable,
                "launch refused before host effect",
            ),
            _ => refusal(RuntimeErrorCode::Unavailable, "launch unavailable"),
        },
        LaunchPodError::Store(store) => match store {
            StoreError::NotFound | StoreError::WrongScope => {
                refusal(RuntimeErrorCode::Forbidden, "launch unavailable")
            }
            StoreError::Conflict(_) => {
                refusal(RuntimeErrorCode::Conflict, "launch key or state conflicts")
            }
            StoreError::InvalidInput(_) => {
                refusal(RuntimeErrorCode::InvalidInput, "launch input is invalid")
            }
            StoreError::StaleEpoch => refusal(
                RuntimeErrorCode::StaleGuard,
                "launch owner or target changed",
            ),
            _ => refusal(RuntimeErrorCode::StorageFailure, "launch store unavailable"),
        },
        LaunchPodError::IdMint(_) => refusal(
            RuntimeErrorCode::Unavailable,
            "launch identity mint unavailable",
        ),
        LaunchPodError::WrongOperation => refusal(
            RuntimeErrorCode::Unsupported,
            "launch operation unavailable",
        ),
    }
}
