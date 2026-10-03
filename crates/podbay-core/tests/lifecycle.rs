use std::collections::HashSet;

use podbay_core::{
    ActorId, AdmissionState, Attempt, AttemptId, CommandAdmission, CommandId, Delivery,
    DeliveryEvidenceLookup, DeliveryId, DeliveryStage, DesiredMode, Epoch, EventId, ExecutionState,
    ForegroundEvidence, ForegroundState, ObservationEvidence, ObservationFreshness, Pod, PodId,
    ProcessObservation, ProcessState, ReportId, Resource, ResourceId, ResourceKind, ResultState,
    Role, Run, RunCommandKind, RunId, RunOutcome, ScopeId, Session, SessionId, SourceId,
    TransitionError, WorkKind,
};

fn id<T: TryFrom<String>>(value: impl Into<String>) -> T
where
    <T as TryFrom<String>>::Error: std::fmt::Debug,
{
    T::try_from(value.into()).unwrap()
}

fn source() -> SourceId {
    id("source.primary")
}

#[derive(Default)]
struct Ledger(HashSet<(CommandId, RunId, RunCommandKind)>);

impl Ledger {
    fn admit(&mut self, command_id: &CommandId, run_id: &RunId, kind: RunCommandKind) {
        self.0.insert((command_id.clone(), run_id.clone(), kind));
    }
}

impl CommandAdmission for Ledger {
    fn admits_run(&self, command_id: &CommandId, run_id: &RunId, kind: RunCommandKind) -> bool {
        self.0.contains(&(command_id.clone(), run_id.clone(), kind))
    }
}

#[derive(Default)]
struct Events(HashSet<(EventId, DeliveryId, DeliveryStage)>);

impl Events {
    fn record(&mut self, event_id: &EventId, delivery_id: &DeliveryId, stage: DeliveryStage) {
        self.0
            .insert((event_id.clone(), delivery_id.clone(), stage));
    }
}

impl DeliveryEvidenceLookup for Events {
    fn proves_stage(
        &self,
        event_id: &EventId,
        delivery_id: &DeliveryId,
        stage: DeliveryStage,
    ) -> bool {
        self.0
            .contains(&(event_id.clone(), delivery_id.clone(), stage))
    }
}

fn setup(role: Role, suffix: &str) -> (Session, Run, Attempt, Pod, Resource, CommandId, Ledger) {
    let mut session = Session::new(
        id::<SessionId>(format!("session.{suffix}")),
        id::<ActorId>(format!("actor.{suffix}")),
        id::<ScopeId>(format!("scope.{suffix}")),
    );
    let mut run = Run::new(
        id::<RunId>(format!("run.{suffix}")),
        &session,
        role,
        WorkKind::Service,
        None,
    );
    session.bind_run(session.revision(), &run).unwrap();
    let command_id: CommandId = id(format!("command.{suffix}"));
    let mut ledger = Ledger::default();
    ledger.admit(&command_id, run.id(), RunCommandKind::Launch);
    run.admit(run.revision(), &command_id, &ledger).unwrap();
    let mut attempt = Attempt::new(
        id::<AttemptId>(format!("attempt.{suffix}")),
        run.id().clone(),
        1,
        Epoch::new(1).unwrap(),
    )
    .unwrap();
    run.start_attempt(run.revision(), &attempt).unwrap();
    let mut pod = Pod::new(
        id::<PodId>(format!("pod.{suffix}")),
        attempt.id().clone(),
        Epoch::new(1).unwrap(),
    );
    attempt.attach_pod(attempt.revision(), &pod).unwrap();
    let resource = Resource::new(
        id::<ResourceId>(format!("resource.{suffix}")),
        pod.id().clone(),
        ResourceKind::StructuredProvider,
        Epoch::new(1).unwrap(),
    );
    pod.attach_resource(pod.revision(), &resource).unwrap();
    (session, run, attempt, pod, resource, command_id, ledger)
}

#[test]
fn coordinator_worker_and_advisor_share_required_identity_and_lifecycle() {
    for (role, suffix) in [
        (Role::Coordinator, "coordinator"),
        (Role::Worker, "worker"),
        (Role::Advisor, "advisor"),
    ] {
        let (session, mut run, mut attempt, pod, resource, _, _) = setup(role, suffix);
        assert_eq!(session.current_run_id(), Some(run.id()));
        assert_eq!(run.session_id(), session.id());
        assert_eq!(run.actor_id(), session.actor_id());
        assert_eq!(run.scope_id(), session.scope_id());
        assert_eq!(run.role(), role);
        assert_eq!(run.admission(), AdmissionState::Admitted);
        assert_eq!(run.execution(), ExecutionState::Starting);
        assert_eq!(run.current_attempt_id(), Some(attempt.id()));
        assert_eq!(attempt.pod_id(), Some(pod.id()));
        assert_eq!(pod.resource_ids(), &[resource.id().clone()]);
        assert_eq!(resource.pod_id(), pod.id());

        attempt
            .observe_process(
                attempt.revision(),
                ObservationEvidence {
                    subject_id: attempt.id().clone(),
                    subject_epoch: attempt.epoch(),
                    source_id: source(),
                    source_epoch: Epoch::new(1).unwrap(),
                    source_sequence: 1,
                    freshness: ObservationFreshness::Fresh,
                    observed: ProcessObservation::Alive,
                },
            )
            .unwrap();
        run.mark_active(run.revision(), &attempt).unwrap();
        assert_eq!(run.execution(), ExecutionState::Active);
    }
}

#[test]
fn process_exit_never_erases_a_report_or_manufactures_acceptance() {
    let (mut session, mut run, mut attempt, _, _, launch_command, mut ledger) =
        setup(Role::Worker, "result");
    attempt
        .observe_process(
            attempt.revision(),
            ObservationEvidence {
                subject_id: attempt.id().clone(),
                subject_epoch: attempt.epoch(),
                source_id: source(),
                source_epoch: Epoch::new(1).unwrap(),
                source_sequence: 1,
                freshness: ObservationFreshness::Fresh,
                observed: ProcessObservation::Alive,
            },
        )
        .unwrap();
    run.mark_active(run.revision(), &attempt).unwrap();
    let report_id: ReportId = id("report.result");
    let report_command: CommandId = id("command.report.result");
    ledger.admit(&report_command, run.id(), RunCommandKind::Report);
    assert_eq!(
        run.record_report(run.revision(), &launch_command, &ledger, report_id.clone()),
        Err(TransitionError::UnknownCommand)
    );
    run.record_report(run.revision(), &report_command, &ledger, report_id.clone())
        .unwrap();
    attempt
        .observe_process(
            attempt.revision(),
            ObservationEvidence {
                subject_id: attempt.id().clone(),
                subject_epoch: attempt.epoch(),
                source_id: source(),
                source_epoch: Epoch::new(1).unwrap(),
                source_sequence: 2,
                freshness: ObservationFreshness::Fresh,
                observed: ProcessObservation::Exited { code: Some(1) },
            },
        )
        .unwrap();
    run.end_execution(run.revision(), &attempt).unwrap();
    assert_eq!(run.execution(), ExecutionState::Ended);
    assert_eq!(run.result(), &ResultState::Reported { report_id });
    assert_eq!(run.outcome(), None, "process exit is not a result decision");
    assert!(
        !run.is_ended(),
        "a retained report still needs an explicit outcome"
    );
    let outcome_command: CommandId = id("command.fail.result");
    ledger.admit(
        &outcome_command,
        run.id(),
        RunCommandKind::Outcome(RunOutcome::Failed),
    );
    assert_eq!(
        run.record_outcome(run.revision(), &launch_command, &ledger, RunOutcome::Failed),
        Err(TransitionError::UnknownCommand)
    );
    run.record_outcome(
        run.revision(),
        &outcome_command,
        &ledger,
        RunOutcome::Failed,
    )
    .unwrap();
    session.release_run(session.revision(), &run).unwrap();
    assert_eq!(session.current_run_id(), None);
    assert_eq!(
        run.result(),
        &ResultState::Reported {
            report_id: id("report.result")
        }
    );
}

#[test]
fn stale_epoch_and_unproved_foreground_cannot_override_fresh_state() {
    let (_, mut run, mut attempt, _, _, _, _) = setup(Role::Coordinator, "epoch");
    attempt
        .observe_process(
            attempt.revision(),
            ObservationEvidence {
                subject_id: attempt.id().clone(),
                subject_epoch: attempt.epoch(),
                source_id: source(),
                source_epoch: Epoch::new(1).unwrap(),
                source_sequence: 1,
                freshness: ObservationFreshness::Fresh,
                observed: ProcessObservation::Alive,
            },
        )
        .unwrap();
    run.mark_active(run.revision(), &attempt).unwrap();
    run.observe_foreground(
        run.revision(),
        &attempt,
        ForegroundEvidence {
            attempt_id: attempt.id().clone(),
            subject_epoch: attempt.epoch(),
            source_id: source(),
            source_epoch: Epoch::new(2).unwrap(),
            source_sequence: 1,
            freshness: ObservationFreshness::Fresh,
            state: ForegroundState::Busy,
        },
    )
    .unwrap();
    let prior_revision = run.revision();
    assert_eq!(
        run.observe_foreground(
            prior_revision,
            &attempt,
            ForegroundEvidence {
                attempt_id: attempt.id().clone(),
                subject_epoch: attempt.epoch(),
                source_id: source(),
                source_epoch: Epoch::new(1).unwrap(),
                source_sequence: 2,
                freshness: ObservationFreshness::Fresh,
                state: ForegroundState::Idle,
            },
        ),
        Err(TransitionError::WrongEpoch)
    );
    assert_eq!(run.foreground(), ForegroundState::Busy);
    assert_eq!(run.revision(), prior_revision);
    assert_eq!(
        run.observe_foreground(
            run.revision(),
            &attempt,
            ForegroundEvidence {
                attempt_id: attempt.id().clone(),
                subject_epoch: attempt.epoch(),
                source_id: id("source.secondary"),
                source_epoch: Epoch::new(3).unwrap(),
                source_sequence: 1,
                freshness: ObservationFreshness::Fresh,
                state: ForegroundState::Idle,
            },
        ),
        Err(TransitionError::SourceChanged),
        "a higher epoch from another observer is not an implicit rebind"
    );
    assert_eq!(run.foreground(), ForegroundState::Busy);
    assert_eq!(
        attempt.observe_process(
            attempt.revision(),
            ObservationEvidence {
                subject_id: attempt.id().clone(),
                subject_epoch: Epoch::new(2).unwrap(),
                source_id: source(),
                source_epoch: Epoch::new(2).unwrap(),
                source_sequence: 2,
                freshness: ObservationFreshness::Fresh,
                observed: ProcessObservation::Exited { code: None },
            },
        ),
        Err(TransitionError::WrongEpoch)
    );
    assert_eq!(attempt.process(), ProcessState::Alive);
    assert_eq!(
        attempt.observe_process(
            attempt.revision(),
            ObservationEvidence {
                subject_id: attempt.id().clone(),
                subject_epoch: attempt.epoch(),
                source_id: id("source.secondary"),
                source_epoch: Epoch::new(3).unwrap(),
                source_sequence: 1,
                freshness: ObservationFreshness::Fresh,
                observed: ProcessObservation::Exited { code: None },
            },
        ),
        Err(TransitionError::SourceChanged)
    );
    assert_eq!(attempt.process(), ProcessState::Alive);
    assert_eq!(
        run.observe_foreground(
            run.revision(),
            &attempt,
            ForegroundEvidence {
                attempt_id: attempt.id().clone(),
                subject_epoch: attempt.epoch(),
                source_id: source(),
                source_epoch: Epoch::new(2).unwrap(),
                source_sequence: 2,
                freshness: ObservationFreshness::Disconnected,
                state: ForegroundState::Idle,
            },
        ),
        Err(TransitionError::MissingEvidence)
    );
    assert_eq!(run.foreground(), ForegroundState::Busy);
}

#[test]
fn fresh_unknown_observation_does_not_prove_a_live_attempt() {
    let (_, mut run, mut attempt, _, _, _, _) = setup(Role::Worker, "unknown");
    attempt
        .observe_process(
            attempt.revision(),
            ObservationEvidence {
                subject_id: attempt.id().clone(),
                subject_epoch: attempt.epoch(),
                source_id: source(),
                source_epoch: Epoch::new(1).unwrap(),
                source_sequence: 1,
                freshness: ObservationFreshness::Fresh,
                observed: ProcessObservation::Alive,
            },
        )
        .unwrap();
    run.mark_active(run.revision(), &attempt).unwrap();
    attempt
        .observe_process(
            attempt.revision(),
            ObservationEvidence {
                subject_id: attempt.id().clone(),
                subject_epoch: attempt.epoch(),
                source_id: source(),
                source_epoch: Epoch::new(1).unwrap(),
                source_sequence: 2,
                freshness: ObservationFreshness::Disconnected,
                observed: ProcessObservation::Unknown,
            },
        )
        .unwrap();
    run.mark_recovering(run.revision(), &attempt).unwrap();
    attempt
        .observe_process(
            attempt.revision(),
            ObservationEvidence {
                subject_id: attempt.id().clone(),
                subject_epoch: attempt.epoch(),
                source_id: source(),
                source_epoch: Epoch::new(1).unwrap(),
                source_sequence: 3,
                freshness: ObservationFreshness::Fresh,
                observed: ProcessObservation::Unknown,
            },
        )
        .unwrap();
    assert_eq!(
        attempt.process(),
        ProcessState::Alive,
        "last known fact is retained"
    );
    assert_eq!(
        attempt.last_process_observation(),
        Some(ProcessObservation::Unknown)
    );
    assert_eq!(
        run.mark_active(run.revision(), &attempt),
        Err(TransitionError::MissingEvidence)
    );
    assert_eq!(run.execution(), ExecutionState::Recovering);
}

#[test]
fn unknown_command_and_reversed_delivery_fail_closed() {
    let session = Session::new(
        id("session.commands"),
        id("actor.commands"),
        id("scope.commands"),
    );
    let mut run = Run::new(
        id("run.commands"),
        &session,
        Role::Coordinator,
        WorkKind::Service,
        None,
    );
    let unknown: CommandId = id("command.unknown");
    let ledger = Ledger::default();
    assert_eq!(
        run.admit(run.revision(), &unknown, &ledger),
        Err(TransitionError::UnknownCommand)
    );
    assert_eq!(run.admission(), AdmissionState::Queued);
    let mut ledger = Ledger::default();
    let known: CommandId = id("command.known");
    ledger.admit(&known, run.id(), RunCommandKind::Launch);
    run.admit(run.revision(), &known, &ledger).unwrap();
    assert_eq!(
        run.request_mode(run.revision(), &unknown, &ledger, DesiredMode::Pause),
        Err(TransitionError::UnknownCommand)
    );
    assert_eq!(run.desired(), DesiredMode::Run);
    assert_eq!(
        run.request_mode(run.revision(), &known, &ledger, DesiredMode::Pause),
        Err(TransitionError::UnknownCommand),
        "a valid launch command is not a pause command"
    );
    assert_eq!(
        run.record_report(run.revision(), &known, &ledger, id("report.commands")),
        Err(TransitionError::UnknownCommand),
        "a valid launch command is not a report command"
    );
    assert_eq!(
        run.record_outcome(run.revision(), &known, &ledger, RunOutcome::Finished),
        Err(TransitionError::UnknownCommand),
        "a valid launch command is not an outcome command"
    );

    let send_command: CommandId = id("command.send");
    let mut delivery = Delivery::new(
        id::<DeliveryId>("delivery.commands"),
        send_command.clone(),
        session.id().clone(),
    );
    let mut events = Events::default();
    delivery
        .advance(
            delivery.revision(),
            &send_command,
            DeliveryStage::Dispatching,
            None,
            &events,
        )
        .unwrap();
    assert_eq!(
        delivery.advance(
            delivery.revision(),
            &send_command,
            DeliveryStage::HostAccepted,
            None,
            &events,
        ),
        Err(TransitionError::MissingEvidence)
    );
    let accepted_event: EventId = id("event.accepted");
    assert_eq!(
        delivery.advance(
            delivery.revision(),
            &send_command,
            DeliveryStage::HostAccepted,
            Some(accepted_event.clone()),
            &events,
        ),
        Err(TransitionError::MissingEvidence),
        "an EventId without a matching recorded observation proves nothing"
    );
    events.record(
        &accepted_event,
        delivery.id(),
        DeliveryStage::ProviderQueued,
    );
    assert_eq!(
        delivery.advance(
            delivery.revision(),
            &send_command,
            DeliveryStage::HostAccepted,
            Some(accepted_event.clone()),
            &events,
        ),
        Err(TransitionError::MissingEvidence),
        "provider queued evidence cannot assert host acceptance"
    );
    events.record(&accepted_event, delivery.id(), DeliveryStage::HostAccepted);
    delivery
        .advance(
            delivery.revision(),
            &send_command,
            DeliveryStage::HostAccepted,
            Some(accepted_event),
            &events,
        )
        .unwrap();
    assert!(matches!(
        delivery.advance(
            delivery.revision(),
            &send_command,
            DeliveryStage::Cancelled,
            None,
            &events
        ),
        Err(TransitionError::InvalidTransition(_))
    ));
    assert_eq!(
        delivery.advance(
            delivery.revision(),
            &unknown,
            DeliveryStage::ProviderInserted,
            Some(id::<EventId>("event.inserted")),
            &events,
        ),
        Err(TransitionError::UnknownCommand)
    );
}

#[test]
fn session_cannot_acquire_second_writer_or_reuse_stopped_run() {
    let (mut session, mut run, _, _, _, launch_command, mut ledger) =
        setup(Role::Coordinator, "single");
    let second = Run::new(
        id("run.second"),
        &session,
        Role::Worker,
        WorkKind::Task,
        None,
    );
    assert!(matches!(
        session.bind_run(session.revision(), &second),
        Err(TransitionError::InvalidTransition(_))
    ));
    assert_eq!(
        run.request_mode(run.revision(), &launch_command, &ledger, DesiredMode::Stop),
        Err(TransitionError::UnknownCommand)
    );
    let stop_command: CommandId = id("command.stop.single");
    ledger.admit(&stop_command, run.id(), RunCommandKind::Stop);
    run.request_mode(run.revision(), &stop_command, &ledger, DesiredMode::Stop)
        .unwrap();
    let resume_command: CommandId = id("command.resume.single");
    ledger.admit(&resume_command, run.id(), RunCommandKind::Resume);
    assert!(matches!(
        run.request_mode(run.revision(), &resume_command, &ledger, DesiredMode::Run),
        Err(TransitionError::InvalidTransition(_))
    ));
}
