//! Narrow host-backed `commands.get` projection. No mutation reaches a port.

use podbay_core::ScopeId;
use podbay_host::{
    AuthenticatedTransport, BootstrapNativeObservation, BootstrapNativeStage, DurableAuthority,
    DurableAuthorityError, HostDispatchPort, HostError,
};
use podbay_store::{
    CommandInspection, CommandLookupSelector, EffectState, LaunchDispatchStage, ObservedStage,
    StoreError,
};
use podbay_wire::{
    CommandEnvelope, CommandSelector, CommandStage, ReadBody, ReadEnvelope, Receipt, RuntimeError,
    RuntimeErrorCode, Target,
};
use serde_json::{Value, json};

use crate::Handler;

pub(crate) struct HostReadHandler<'a, P: HostDispatchPort> {
    authority: &'a mut DurableAuthority<P>,
}

impl<'a, P: HostDispatchPort> HostReadHandler<'a, P> {
    pub(crate) fn new(authority: &'a mut DurableAuthority<P>) -> Self {
        Self { authority }
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
        let ReadBody::CommandsGet(body) = request.body else {
            return Err(refusal(
                RuntimeErrorCode::Unsupported,
                "read operation is unavailable",
            ));
        };
        let Target::Scope { scope_id } = request.target else {
            return Err(refusal(
                RuntimeErrorCode::InvalidInput,
                "scope target required",
            ));
        };
        let scope = ScopeId::try_from(scope_id.as_str())
            .map_err(|_| refusal(RuntimeErrorCode::InvalidInput, "invalid scope target"))?;
        let selector = match body.selector {
            CommandSelector::Id { command_id } => CommandLookupSelector::Id { command_id },
            CommandSelector::Key { key } => CommandLookupSelector::Key { key },
        };
        let (inspected, native) = self
            .authority
            .lookup_command_with_native_observation(transport, &scope, &selector)
            .map_err(authority_error)?;
        Ok(inspection_json(inspected, native.as_ref()))
    }
}

fn inspection_json(
    inspected: CommandInspection,
    native: Option<&BootstrapNativeObservation>,
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
        // An indexed CommandId→current writer lease lookup is not available
        // in this store API. Never reconstruct a guard by scanning pods or
        // replaying a prior launch receipt on a generic read.
        response["bootstrapGuard"] = json!({"available": false});
        if let Some(reference) = launch.and_then(|status| status.receipt_ref.as_deref()) {
            response["portReceiptRef"] = json!(reference);
        }
    }
    if let Some(native) = native {
        response["nativeObservation"] = native_json(native);
    }
    response
}

fn native_json(observation: &BootstrapNativeObservation) -> Value {
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let uncertain = inspection_json(inspection(EffectState::ClaimedUncertain, None), None);
        assert_eq!(uncertain["state"], "uncertain");
        assert_eq!(uncertain["effectState"], "claimed_uncertain");
        assert_eq!(uncertain["receipt"]["eventSequence"], "7");
        let accepted = inspection_json(
            inspection(EffectState::Observed, Some(ObservedStage::HostAccepted)),
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
            let response = inspection_json(fact, None);
            assert_eq!(response["state"], "host_accepted");
            assert_eq!(response["effectState"], label);
            assert_eq!(response["launchStage"], label);
            assert_eq!(response["outboxState"], "claimed_uncertain");
            assert_eq!(response["portReceiptRef"], "host.receipt.one");
        }
    }
}
