//! Narrow host-backed `commands.get` projection. No mutation reaches a port.

use podbay_core::{CommandId, ScopeId};
use podbay_host::{
    AuthenticatedTransport, BootstrapNativeObservation, BootstrapNativeStage,
    CommandNativeObservation, CurrentLaterSendGuard, DurableAuthority, DurableAuthorityError,
    HostDispatchPort, HostError, InitialBootstrapGuard, LaterTurnNativeObservation,
    LaterTurnNativeStage, LaterTurnNativeTerminal, TrustedBootstrapSendPolicy,
};
use podbay_store::{
    CommandInspection, CommandLookupSelector, CurrentObservation, CurrentScopeSnapshot,
    EffectState, LaunchDispatchStage, ObservedStage, StoreError,
};
use podbay_wire::{
    CommandEnvelope, CommandSelector, CommandStage, ReadBody, ReadEnvelope, Receipt, RuntimeError,
    RuntimeErrorCode, Target,
};
use serde_json::{Value, json};

use crate::{Handler, host_launch_handler::bootstrap_guard_json};

pub(crate) struct HostReadHandler<'a, P: HostDispatchPort> {
    authority: &'a mut DurableAuthority<P>,
    bootstrap_policy: Option<&'a TrustedBootstrapSendPolicy>,
}

impl<'a, P: HostDispatchPort> HostReadHandler<'a, P> {
    pub(crate) fn new(authority: &'a mut DurableAuthority<P>) -> Self {
        Self {
            authority,
            bootstrap_policy: None,
        }
    }

    pub(crate) fn with_bootstrap_policy(
        authority: &'a mut DurableAuthority<P>,
        policy: &'a TrustedBootstrapSendPolicy,
    ) -> Self {
        Self {
            authority,
            bootstrap_policy: Some(policy),
        }
    }
}

impl<P: HostDispatchPort> Handler for HostReadHandler<'_, P> {
    fn command<T: AuthenticatedTransport>(
        &mut self,
        _transport: &T,
        _request: CommandEnvelope,
    ) -> Result<Receipt<Value>, RuntimeError> {
        Err(refusal(
            RuntimeErrorCode::Unsupported,
            "mutation is unavailable on this read endpoint",
        ))
    }

    fn read<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        request: ReadEnvelope,
    ) -> Result<Value, RuntimeError> {
        let Target::Scope { scope_id } = request.target else {
            return Err(refusal(
                RuntimeErrorCode::InvalidInput,
                "scope target required",
            ));
        };
        let scope = ScopeId::try_from(scope_id.as_str())
            .map_err(|_| refusal(RuntimeErrorCode::InvalidInput, "invalid scope target"))?;
        match request.body {
            ReadBody::SnapshotGet(_) => self
                .authority
                .current_scope_snapshot(transport, &scope)
                .map(snapshot_json)
                .map_err(snapshot_authority_error),
            ReadBody::CommandsGet(body) => {
                let selector = match body.selector {
                    CommandSelector::Id { command_id } => CommandLookupSelector::Id { command_id },
                    CommandSelector::Key { key } => CommandLookupSelector::Key { key },
                };
                let (inspected, native) = self
                    .authority
                    .lookup_command_with_any_native_observation(transport, &scope, &selector)
                    .map_err(authority_error)?;
                let later_guard = if inspected.launch_dispatch_status.is_some() {
                    self.bootstrap_policy.and_then(|policy| {
                        let command_id =
                            CommandId::try_from(inspected.receipt.command_id.as_str()).ok()?;
                        self.authority
                            .read_current_later_send_guard_for_launch(
                                transport,
                                &scope,
                                &command_id,
                                policy,
                            )
                            .ok()
                            .flatten()
                    })
                } else {
                    None
                };
                let bootstrap_guard = later_guard
                    .as_ref()
                    .and_then(CurrentLaterSendGuard::as_initial_bootstrap_guard);
                Ok(inspection_json(
                    inspected,
                    native.as_ref(),
                    bootstrap_guard.as_ref(),
                    later_guard.as_ref(),
                ))
            }
            _ => Err(refusal(
                RuntimeErrorCode::Unsupported,
                "read operation is unavailable",
            )),
        }
    }
}

fn snapshot_json(snapshot: CurrentScopeSnapshot) -> Value {
    let sessions = snapshot
        .sessions
        .into_iter()
        .map(|session| {
            let run = session.run.map(|run| {
                let attempt = run.attempt.map(|attempt| {
                    let pod = attempt.pod;
                    json!({
                        "attemptId": attempt.attempt_id,
                        "ordinal": attempt.ordinal.to_string(),
                        "epoch": attempt.epoch.to_string(),
                        "observation": observation_json(attempt.observation),
                        "pod": {
                            "podId": pod.pod_id,
                            "incarnation": pod.incarnation.to_string(),
                            "observation": observation_json(pod.observation),
                            "resources": pod.resources.into_iter().map(|resource| json!({
                                "resourceId": resource.resource_id,
                                "kind": resource.kind,
                                "epoch": resource.epoch.to_string(),
                                "inputEpoch": resource.input_epoch.to_string(),
                                "observation": observation_json(resource.observation),
                            })).collect::<Vec<_>>(),
                        },
                    })
                });
                json!({
                    "runId": run.run_id,
                    "role": run.role,
                    "workKind": run.work_kind,
                    "parentRunId": run.parent_run_id,
                    "revision": run.revision.to_string(),
                    "admissionState": run.admission_state,
                    "desiredMode": run.desired_mode,
                    "executionState": run.execution_state,
                    "observation": observation_json(run.observation),
                    "attempt": attempt,
                })
            });
            json!({
                "sessionId": session.session_id,
                "actorId": session.actor_id,
                "revision": session.revision.to_string(),
                "state": session.state,
                "run": run,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "kind": "current_scope_snapshot",
        "cursor": {
            "storeLineage": snapshot.cursor.store_lineage,
            "scopeId": snapshot.cursor.scope_id,
            "sequence": snapshot.cursor.sequence.to_string(),
        },
        "ownerEpoch": snapshot.owner_epoch.to_string(),
        "managerCredentialEpoch": snapshot.manager_credential_epoch.to_string(),
        "authorityRevision": snapshot.authority_revision.to_string(),
        "sessions": sessions,
    })
}

fn observation_json(value: CurrentObservation) -> &'static str {
    match value {
        CurrentObservation::Unavailable => "unavailable",
    }
}

fn inspection_json(
    inspected: CommandInspection,
    native: Option<&CommandNativeObservation>,
    guard: Option<&InitialBootstrapGuard>,
    later_guard: Option<&CurrentLaterSendGuard>,
) -> Value {
    // These are the facts established by the store. A claimed effect remains
    // uncertain; host acceptance does not imply provider consumption.
    let (generic_state, outbox_state) = match inspected.effect_state {
        EffectState::Prepared => (CommandStage::Persisted, "prepared"),
        EffectState::ClaimedUncertain => (CommandStage::Uncertain, "claimed_uncertain"),
        EffectState::Observed => match inspected.observed_stage {
            Some(ObservedStage::HostAccepted) => (CommandStage::HostAccepted, "observed"),
            Some(ObservedStage::LegacyUnverified) | None => (CommandStage::Uncertain, "observed"),
        },
    };
    let launch = inspected.launch_dispatch_status.as_ref();
    let (state, effect_state, launch_stage) = match launch.map(|status| status.stage) {
        Some(LaunchDispatchStage::Prepared) => {
            (CommandStage::Persisted, "prepared", Some("prepared"))
        }
        Some(LaunchDispatchStage::ClaimedUncertain) => (
            CommandStage::Uncertain,
            "claimed_uncertain",
            Some("claimed_uncertain"),
        ),
        Some(LaunchDispatchStage::RefusedBeforeEffect) => (
            CommandStage::Rejected,
            "refused_before_effect",
            Some("refused_before_effect"),
        ),
        Some(LaunchDispatchStage::UncertainAfterPossibleEffect) => (
            CommandStage::Uncertain,
            "uncertain_after_possible_effect",
            Some("uncertain_after_possible_effect"),
        ),
        Some(LaunchDispatchStage::HostAccepted) => (
            CommandStage::HostAccepted,
            "host_accepted",
            Some("host_accepted"),
        ),
        Some(LaunchDispatchStage::PortSettled) => (
            CommandStage::HostAccepted,
            "port_settled",
            Some("port_settled"),
        ),
        None => (generic_state, outbox_state, None),
    };
    let receipt = inspected.receipt;
    let mut response = json!({
        "receipt": {
            "commandId": receipt.command_id,
            "eventSequence": receipt.event_sequence.to_string(),
            "outboxId": receipt.outbox_id.to_string(),
            "digestVersion": receipt.digest_version,
            "requestDigest": receipt.request_digest,
        },
        "state": state,
        "effectState": effect_state,
    });
    if let Some(stage) = inspected.observed_stage {
        response["observedStage"] = json!(match stage {
            ObservedStage::HostAccepted => "host_accepted",
            ObservedStage::LegacyUnverified => "legacy_unverified",
        });
    }
    if let Some(sequence) = inspected.observation_event_sequence {
        response["observationEventSequence"] = json!(sequence.to_string());
    }
    if let Some(stage) = launch_stage {
        response["launchStage"] = json!(stage);
        response["outboxState"] = json!(outbox_state);
        response["bootstrapGuard"] = guard
            .map(bootstrap_guard_json)
            .unwrap_or_else(|| json!({"available": false}));
        response["currentLaterSendGuard"] = later_guard
            .map(current_later_send_guard_json)
            .unwrap_or_else(|| json!({"available": false}));
        if let Some(reference) = launch.and_then(|status| status.receipt_ref.as_deref()) {
            response["portReceiptRef"] = json!(reference);
        }
    }
    if let Some(native) = native {
        response["nativeObservation"] = native_json(native);
    }
    response
}

fn current_later_send_guard_json(guard: &CurrentLaterSendGuard) -> Value {
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
        "managerCredentialEpoch": guard.manager_credential_epoch().to_string(),
        "leaseExpiresAtUnixSeconds": guard.expires_at_unix_seconds().to_string(),
        "policyFenceEpoch": guard.policy_fence_epoch().map(|value| value.to_string()),
        "guard": {
            "managerEpoch": guard.owner_epoch().to_string(),
            "podEpoch": target.pod_incarnation.to_string(),
            "resourceEpoch": target.resource_epoch.to_string(),
            "writerEpoch": guard.writer_epoch().to_string(),
            "targetRevision": guard.session_revision().to_string(),
        },
    })
}

fn native_json(observation: &CommandNativeObservation) -> Value {
    match observation {
        CommandNativeObservation::Bootstrap(value) => bootstrap_native_json(value),
        CommandNativeObservation::LaterTurn(value) => later_turn_native_json(value),
    }
}

fn later_turn_native_json(observation: &LaterTurnNativeObservation) -> Value {
    let mut value = json!({
        "source": "pod_journal",
        "kind": "codex_turn",
        "requestDigest": observation.request_digest(),
    });
    let terminal = |value| match value {
        LaterTurnNativeTerminal::Completed => "completed",
        LaterTurnNativeTerminal::Failed => "failed",
        LaterTurnNativeTerminal::Interrupted => "interrupted",
    };
    match observation.stage() {
        LaterTurnNativeStage::ClaimedUnobserved => value["stage"] = json!("claimed_unobserved"),
        LaterTurnNativeStage::IntentUncertain => value["stage"] = json!("intent_uncertain"),
        LaterTurnNativeStage::SubmissionUncertain => value["stage"] = json!("submission_uncertain"),
        LaterTurnNativeStage::StorageUncertain => value["stage"] = json!("storage_uncertain"),
        LaterTurnNativeStage::Submitted { native_thread_id, native_session_id, native_turn_id } => {
            value["stage"] = json!("submitted");
            value["nativeThreadId"] = json!(native_thread_id);
            value["nativeSessionId"] = json!(native_session_id);
            value["nativeTurnId"] = json!(native_turn_id);
        }
        LaterTurnNativeStage::CompletionObservedPendingIdleProof { native_turn_id, terminal: status } => {
            value["stage"] = json!("completion_observed_pending_idle_proof");
            value["nativeTurnId"] = json!(native_turn_id);
            value["terminal"] = json!(terminal(*status));
        }
        LaterTurnNativeStage::Settled { native_turn_id, terminal: status } => {
            value["stage"] = json!("native_settled");
            value["nativeTurnId"] = json!(native_turn_id);
            value["terminal"] = json!(terminal(*status));
        }
    }
    value
}

fn bootstrap_native_json(observation: &BootstrapNativeObservation) -> Value {
    let mut value = json!({
        "source": "pod_journal",
        "requestDigest": observation.request_digest(),
    });
    match observation.stage() {
        BootstrapNativeStage::ClaimedUnobserved => {
            value["stage"] = json!("claimed_unobserved");
        }
        BootstrapNativeStage::ThreadCreateUncertain => {
            value["stage"] = json!("thread_create_uncertain");
        }
        BootstrapNativeStage::ThreadCreated {
            native_thread_id,
            native_session_id,
        } => {
            value["stage"] = json!("thread_created");
            value["nativeThreadId"] = json!(native_thread_id);
            value["nativeSessionId"] = json!(native_session_id);
        }
        BootstrapNativeStage::BootstrapUncertain {
            native_thread_id,
            native_session_id,
        } => {
            value["stage"] = json!("bootstrap_uncertain");
            value["nativeThreadId"] = json!(native_thread_id);
            value["nativeSessionId"] = json!(native_session_id);
        }
        BootstrapNativeStage::Submitted {
            native_thread_id,
            native_session_id,
            native_turn_id,
        } => {
            value["stage"] = json!("submitted");
            value["nativeThreadId"] = json!(native_thread_id);
            value["nativeSessionId"] = json!(native_session_id);
            value["nativeTurnId"] = json!(native_turn_id);
        }
    }
    value
}

fn refusal(code: RuntimeErrorCode, message: &str) -> RuntimeError {
    RuntimeError {
        code,
        message: message.into(),
        retry: "never".into(),
        command_id: None,
    }
}

fn authority_error(error: DurableAuthorityError) -> RuntimeError {
    let (code, message) = match error {
        DurableAuthorityError::Store(StoreError::NotFound) => {
            (RuntimeErrorCode::Forbidden, "command unavailable")
        }
        DurableAuthorityError::Store(StoreError::CurrentSnapshotLimitExceeded { .. }) => (
            RuntimeErrorCode::LimitExceeded,
            "current scope snapshot limit exceeded; pagination is unavailable",
        ),
        DurableAuthorityError::Store(StoreError::InvalidInput(_)) => (
            RuntimeErrorCode::InvalidInput,
            "command selector is invalid",
        ),
        DurableAuthorityError::Store(StoreError::Conflict(_)) => (
            RuntimeErrorCode::Conflict,
            "command record is ambiguous or inconsistent",
        ),
        DurableAuthorityError::Store(StoreError::StaleEpoch)
        | DurableAuthorityError::Host(HostError::StaleGuard) => (
            RuntimeErrorCode::StaleGuard,
            "manager or actor state changed",
        ),
        DurableAuthorityError::Host(HostError::Unauthenticated | HostError::Unauthorised) => (
            RuntimeErrorCode::Forbidden,
            "authenticated actor unavailable",
        ),
        DurableAuthorityError::Host(HostError::Unsupported) => {
            (RuntimeErrorCode::Unsupported, "host read unavailable")
        }
        DurableAuthorityError::Busy => (RuntimeErrorCode::Busy, "manager is busy"),
        DurableAuthorityError::Store(_)
        | DurableAuthorityError::Io(_)
        | DurableAuthorityError::Corrupt(_) => (
            RuntimeErrorCode::StorageFailure,
            "durable command read unavailable",
        ),
        DurableAuthorityError::Host(_) => (RuntimeErrorCode::Unavailable, "host read unavailable"),
    };
    refusal(code, message)
}

fn snapshot_authority_error(error: DurableAuthorityError) -> RuntimeError {
    match error {
        DurableAuthorityError::Store(StoreError::NotFound) => {
            refusal(RuntimeErrorCode::Forbidden, "scope unavailable")
        }
        DurableAuthorityError::Store(StoreError::CurrentSnapshotLimitExceeded { limit }) => {
            RuntimeError {
                code: RuntimeErrorCode::LimitExceeded,
                message: format!(
                    "current scope snapshot exceeds {limit} entities; pagination is unavailable"
                ),
                retry: "never".into(),
                command_id: None,
            }
        }
        other => authority_error(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use podbay_store::{
        CurrentAttemptSnapshot, CurrentPodSnapshot, CurrentResourceSnapshot, CurrentRunSnapshot,
        CurrentSessionSnapshot, EventCursor as StoreEventCursor,
    };

    #[test]
    fn current_snapshot_projection_keeps_all_identities_and_unavailable_observation() {
        let unavailable = CurrentObservation::Unavailable;
        let value = snapshot_json(CurrentScopeSnapshot {
            cursor: StoreEventCursor {
                store_lineage: "lineage.fixture".into(),
                scope_id: "scope.fixture".into(),
                sequence: 17,
            },
            owner_epoch: 2,
            manager_credential_epoch: 2,
            authority_revision: 7,
            sessions: vec![CurrentSessionSnapshot {
                session_id: "session.fixture".into(),
                actor_id: "actor.fixture".into(),
                revision: 3,
                state: "open".into(),
                run: Some(CurrentRunSnapshot {
                    run_id: "run.fixture".into(),
                    role: "coordinator".into(),
                    work_kind: "service".into(),
                    parent_run_id: None,
                    revision: 4,
                    admission_state: "admitted".into(),
                    desired_mode: "run".into(),
                    execution_state: "starting".into(),
                    observation: unavailable,
                    attempt: Some(CurrentAttemptSnapshot {
                        attempt_id: "attempt.fixture".into(),
                        ordinal: 1,
                        epoch: 1,
                        observation: unavailable,
                        pod: CurrentPodSnapshot {
                            pod_id: "pod.fixture".into(),
                            incarnation: 1,
                            observation: unavailable,
                            resources: vec![CurrentResourceSnapshot {
                                resource_id: "resource.fixture".into(),
                                kind: "structured_provider".into(),
                                epoch: 1,
                                input_epoch: 2,
                                observation: unavailable,
                            }],
                        },
                    }),
                }),
            }],
        });
        assert_eq!(value["cursor"]["sequence"], "17");
        assert_eq!(value["authorityRevision"], "7");
        assert_eq!(value["sessions"][0]["run"]["runId"], "run.fixture");
        assert_eq!(value["sessions"][0]["run"]["desiredMode"], "run");
        assert_eq!(value["sessions"][0]["run"]["executionState"], "starting");
        assert_eq!(value["sessions"][0]["run"]["observation"], "unavailable");
        assert_eq!(
            value["sessions"][0]["run"]["attempt"]["attemptId"],
            "attempt.fixture"
        );
        assert_eq!(
            value["sessions"][0]["run"]["attempt"]["pod"]["podId"],
            "pod.fixture"
        );
        assert_eq!(
            value["sessions"][0]["run"]["attempt"]["pod"]["resources"][0]["resourceId"],
            "resource.fixture"
        );
        assert!(value.get("completion").is_none());
        assert!(value.get("receipts").is_none());
    }

    fn inspection(state: EffectState, observed_stage: Option<ObservedStage>) -> CommandInspection {
        CommandInspection {
            receipt: podbay_store::Receipt {
                command_id: "command.fixture".into(),
                event_sequence: 7,
                outbox_id: 9,
                digest_version: "pb04-request-bytes/1",
                request_digest: "a".repeat(64),
            },
            effect_state: state,
            observed_stage,
            observation_event_sequence: observed_stage.map(|_| 11),
            launch_dispatch_status: None,
        }
    }

    #[test]
    fn uncertain_and_host_accepted_are_never_projected_as_settled() {
        let uncertain =
            inspection_json(inspection(EffectState::ClaimedUncertain, None), None, None);
        assert_eq!(uncertain["state"], "uncertain");
        assert_eq!(uncertain["effectState"], "claimed_uncertain");
        assert_eq!(uncertain["receipt"]["eventSequence"], "7");
        let accepted = inspection_json(
            inspection(EffectState::Observed, Some(ObservedStage::HostAccepted)),
            None,
            None,
        );
        assert_eq!(accepted["state"], "host_accepted");
        assert_eq!(accepted["observedStage"], "host_accepted");
        assert_eq!(accepted["observationEventSequence"], "11");
        assert!(accepted.get("payload").is_none());
    }

    #[test]
    fn bound_launch_outcome_overrides_raw_claimed_outbox_without_provider_settlement() {
        for (stage, label) in [
            (LaunchDispatchStage::HostAccepted, "host_accepted"),
            (LaunchDispatchStage::PortSettled, "port_settled"),
        ] {
            let mut fact = inspection(EffectState::ClaimedUncertain, None);
            fact.launch_dispatch_status = Some(podbay_store::LaunchDispatchStatus {
                stage,
                receipt_ref: Some("host.receipt.one".into()),
            });
            let response = inspection_json(fact, None, None);
            assert_eq!(response["state"], "host_accepted");
            assert_eq!(response["effectState"], label);
            assert_eq!(response["launchStage"], label);
            assert_eq!(response["outboxState"], "claimed_uncertain");
            assert_eq!(response["portReceiptRef"], "host.receipt.one");
        }
    }

    #[test]
    fn current_snapshot_overflow_has_a_distinct_error_code() {
        let error = snapshot_authority_error(DurableAuthorityError::Store(
            StoreError::CurrentSnapshotLimitExceeded { limit: 256 },
        ));
        assert_eq!(error.code, RuntimeErrorCode::LimitExceeded);
        assert!(error.message.contains("256"));
    }

    #[test]
    fn later_turn_native_projection_never_settles_the_store_command() {
        use podbay_core::{AttemptId, PodId, ResourceId, RunId, SessionId, StoreLineageId};
        use podbay_store::{LaterCodexSendSelector, NativeWriterTarget};
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
        let selector = LaterCodexSendSelector {
            scope_id: target.scope_id.clone(),
            command_id: CommandId::try_from("command.fixture").unwrap(),
            native_target: target,
        };
        let observed = LaterTurnNativeObservation::from_attested_pod(
            "podbay.codex-turn.inspect/1", selector.clone(), 2, "a".repeat(64),
            LaterTurnNativeStage::Settled {
                native_turn_id: "turn.native.fixture".into(),
                terminal: LaterTurnNativeTerminal::Completed,
            },
        ).unwrap();
        let native = CommandNativeObservation::LaterTurn(observed);
        let projected = inspection_json(
            inspection(EffectState::ClaimedUncertain, None), Some(&native), None,
        );
        assert_eq!(projected["state"], "uncertain");
        assert_eq!(projected["effectState"], "claimed_uncertain");
        assert_eq!(projected["nativeObservation"]["stage"], "native_settled");
        assert_eq!(projected["nativeObservation"]["terminal"], "completed");
        assert_eq!(projected["nativeObservation"]["nativeTurnId"], "turn.native.fixture");
        let uncertain = LaterTurnNativeObservation::from_attested_pod(
            "podbay.codex-turn.inspect/1", selector, 2, "a".repeat(64),
            LaterTurnNativeStage::SubmissionUncertain,
        ).unwrap();
        let redacted = native_json(&CommandNativeObservation::LaterTurn(uncertain));
        assert_eq!(redacted["stage"], "submission_uncertain");
        assert!(redacted.get("nativeTurnId").is_none());
    }
}
