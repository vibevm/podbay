//! Explicitly configured host-backed `launch` plus the existing read surface.
//! This slice admits only the host planner's no-input Coordinator/Service root.

use podbay_host::{
    AuthenticatedTransport, BootstrapPortObservation, BootstrapSendError, BootstrapSendReceipt,
    DurableAuthority, HostDispatchPort, HostError, InitialBootstrapGuard, LaunchPodError,
    LaunchPodReceipt, StablePortReceipt, TrustedBootstrapSendPolicy, TrustedWireRootLaunchPolicy,
};
use podbay_store::{BoundLaunchRecord, EffectState, LaunchDispatchStage, StoreError};
use podbay_wire::{
    CommandBody, CommandEnvelope, CommandStage, DecimalString, EventCursor, ProtocolVersion,
    ReadEnvelope, Receipt, RuntimeError, RuntimeErrorCode, Target,
};
use serde_json::{Value, json};

use crate::{Handler, host_read_handler::HostReadHandler};

pub(crate) struct HostLaunchHandler<'a, P: HostDispatchPort> {
    authority: &'a mut DurableAuthority<P>,
    policy: &'a TrustedWireRootLaunchPolicy,
    bootstrap_send_policy: Option<&'a TrustedBootstrapSendPolicy>,
}

impl<'a, P: HostDispatchPort> HostLaunchHandler<'a, P> {
    pub(crate) fn new(
        authority: &'a mut DurableAuthority<P>,
        policy: &'a TrustedWireRootLaunchPolicy,
    ) -> Self {
        Self {
            authority,
            policy,
            bootstrap_send_policy: None,
        }
    }

    pub(crate) fn with_first_send(
        authority: &'a mut DurableAuthority<P>,
        policy: &'a TrustedWireRootLaunchPolicy,
        bootstrap_send_policy: &'a TrustedBootstrapSendPolicy,
    ) -> Self {
        Self {
            authority,
            policy,
            bootstrap_send_policy: Some(bootstrap_send_policy),
        }
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
        if matches!(&request.body, CommandBody::SessionSend(_)) {
            let policy = self.bootstrap_send_policy.ok_or_else(|| {
                refusal(
                    RuntimeErrorCode::Unsupported,
                    "session.send is unavailable on this manager endpoint",
                )
            })?;
            let outcome = self
                .authority
                .send_codex_session_from_wire(transport, request, policy)
                .map_err(bootstrap_error)?;
            return project_bootstrap_send_receipt(self.authority, outcome);
        }
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
        let bootstrap_guard = if matches!(
            outcome.status.stage,
            LaunchDispatchStage::HostAccepted | LaunchDispatchStage::PortSettled
        ) {
            self.bootstrap_send_policy.and_then(|policy| {
                let session = podbay_core::SessionId::try_from(binding.session_id.as_str()).ok()?;
                let guard = self
                    .authority
                    .acquire_initial_bootstrap_guard(transport, &session, policy)
                    .ok()?;
                (guard.target().scope_id.as_str() == binding.scope_id
                    && guard.target().session_id.as_str() == binding.session_id
                    && guard.target().run_id.as_str() == binding.run_id
                    && guard.target().attempt_id.as_str() == binding.attempt_id
                    && guard.target().pod_id.as_str() == binding.pod_id
                    && guard.target().pod_incarnation == binding.pod_incarnation
                    && binding.resources.len() == 1
                    && guard.target().resource_id.as_str() == binding.resources[0].id
                    && guard.target().resource_epoch == binding.resources[0].epoch)
                    .then_some(guard)
            })
        } else {
            None
        };
        project_launch_receipt(
            self.authority,
            &scope_id,
            outcome,
            &binding,
            bootstrap_guard.as_ref(),
        )
    }

    fn read<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        request: ReadEnvelope,
    ) -> Result<Value, RuntimeError> {
        match self.bootstrap_send_policy {
            Some(policy) => HostReadHandler::with_bootstrap_policy(self.authority, policy)
                .read(transport, request),
            None => HostReadHandler::new(self.authority).read(transport, request),
        }
    }
}

fn project_bootstrap_send_receipt<P: HostDispatchPort>(
    authority: &DurableAuthority<P>,
    outcome: BootstrapSendReceipt,
) -> Result<Receipt<Value>, RuntimeError> {
    let scope_id = outcome.scope_id.as_str().to_owned();
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
    let (state, effect_state) = match outcome.effect_state {
        EffectState::Prepared => (CommandStage::Persisted, "prepared"),
        EffectState::ClaimedUncertain => (CommandStage::Uncertain, "claimed_uncertain"),
        EffectState::Observed => (CommandStage::Uncertain, "observed_unclassified"),
    };
    let port_observation = match outcome.port_observation {
        None => Value::Null,
        Some(BootstrapPortObservation::PodAccepted(reference)) => json!({
            "kind": "pod_accepted", "receiptRef": reference,
            "durability": "pod_journal_only"
        }),
        Some(BootstrapPortObservation::RefusedBeforeEffect) => json!({
            "kind": "refused_before_effect"
        }),
        Some(BootstrapPortObservation::UncertainAfterPossibleEffect(reference)) => json!({
            "kind": "uncertain_after_possible_effect", "receiptRef": reference
        }),
    };
    let position = DecimalString::new(event_sequence);
    let receipt = Receipt {
        protocol: ProtocolVersion::V1,
        command_id: command_id.clone(),
        state,
        value: json!({
            "revisionKind": "admission_event_sequence",
            "effectState": effect_state,
            "eventSequence": event_sequence.to_string(),
            "outboxId": outbox_id.to_string(),
            "digestVersion": original.digest_version,
            "requestDigest": original.request_digest,
            "duplicate": outcome.duplicate,
            "portCalled": outcome.port_called,
            "portObservation": port_observation,
        }),
        revision: position,
        cursor: EventCursor {
            store_lineage: authority.store_lineage_for_receipt().to_owned(),
            scope_id,
            sequence: position,
        },
    };
    receipt
        .validate()
        .map_err(|_| committed_projection_error(&command_id))?;
    Ok(receipt)
}

fn bootstrap_error(error: BootstrapSendError) -> RuntimeError {
    match error {
        BootstrapSendError::PostAdmission { receipt, .. } => RuntimeError {
            code: RuntimeErrorCode::Uncertain,
            message: "session.send admission committed; query the original command".into(),
            retry: "query_command".into(),
            command_id: Some(receipt.command_id),
        },
        BootstrapSendError::Host(host) => match host {
            HostError::Unauthenticated | HostError::Unauthorised => refusal(
                RuntimeErrorCode::Forbidden,
                "session.send authority unavailable",
            ),
            HostError::InvalidInput => refusal(
                RuntimeErrorCode::InvalidInput,
                "session.send input is invalid",
            ),
            HostError::StaleGuard => refusal(
                RuntimeErrorCode::StaleGuard,
                "session.send authority changed",
            ),
            HostError::DeadlineExpired => refusal(
                RuntimeErrorCode::DeadlineExceeded,
                "session.send deadline elapsed",
            ),
            HostError::Unsupported | HostError::NativeResolutionUnverified => refusal(
                RuntimeErrorCode::Unsupported,
                "session.send capability is unavailable",
            ),
            HostError::AuthorityStoreUnavailable => refusal(
                RuntimeErrorCode::StorageFailure,
                "session.send store unavailable",
            ),
            HostError::UncertainAfterPossibleEffect { .. } => RuntimeError {
                code: RuntimeErrorCode::Uncertain,
                message: "session.send effect is uncertain; query the original key".into(),
                retry: "query_command".into(),
                command_id: None,
            },
            HostError::RefusedBeforeEffect => refusal(
                RuntimeErrorCode::Unavailable,
                "session.send refused before effect",
            ),
            _ => refusal(RuntimeErrorCode::Unavailable, "session.send unavailable"),
        },
        BootstrapSendError::Store(store) => match store {
            StoreError::NotFound | StoreError::WrongScope => refusal(
                RuntimeErrorCode::Forbidden,
                "session.send target unavailable",
            ),
            StoreError::Conflict(_) => refusal(
                RuntimeErrorCode::Conflict,
                "session.send key or state conflicts",
            ),
            StoreError::InvalidInput(_) => refusal(
                RuntimeErrorCode::InvalidInput,
                "session.send input is invalid",
            ),
            StoreError::StaleEpoch => refusal(
                RuntimeErrorCode::StaleGuard,
                "session.send owner or target changed",
            ),
            _ => refusal(
                RuntimeErrorCode::StorageFailure,
                "session.send store unavailable",
            ),
        },
        BootstrapSendError::Authority(_) => refusal(
            RuntimeErrorCode::StorageFailure,
            "session.send authority unavailable",
        ),
    }
}

fn project_launch_receipt<P: HostDispatchPort>(
    authority: &DurableAuthority<P>,
    scope_id: &str,
    outcome: LaunchPodReceipt,
    binding: &BoundLaunchRecord,
    bootstrap_guard: Option<&InitialBootstrapGuard>,
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
            "bootstrapGuard": bootstrap_guard.map(bootstrap_guard_json)
                .unwrap_or_else(|| json!({"available": false})),
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

pub(crate) fn bootstrap_guard_json(guard: &InitialBootstrapGuard) -> Value {
    let target = guard.target();
    json!({
        "available": true,
        "scopeId": target.scope_id.as_str(),
        "sessionId": target.session_id.as_str(),
        "runId": target.run_id.as_str(),
        "attemptId": target.attempt_id.as_str(),
        "podId": target.pod_id.as_str(),
        "resourceId": target.resource_id.as_str(),
        "resourceInputEpoch": target.resource_input_epoch.to_string(),
        "leaseExpiresAtUnixSeconds": guard.expires_at_unix_seconds().to_string(),
        "guard": {
            "managerEpoch": guard.owner_epoch().to_string(),
            "podEpoch": target.pod_incarnation.to_string(),
            "resourceEpoch": target.resource_epoch.to_string(),
            "writerEpoch": guard.writer_epoch().to_string(),
            "targetRevision": guard.session_revision().to_string(),
        },
    })
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
