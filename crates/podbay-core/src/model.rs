//! Role-neutral runtime aggregates and guarded state transitions.
use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::{
    ActorId, AdmissionState, AttemptId, CommandId, DeliveryId, DeliveryStage, DesiredMode, Epoch,
    EventId, ExecutionState, ForegroundState, IdError, Observation, ObservationFreshness, PodId,
    ProcessObservation, ProcessState, ReportId, ResourceId, ResourceKind, ResultState, Revision,
    Role, RunId, RunOutcome, ScopeId, SessionId, SessionState, SourceId, WorkKind,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransitionError {
    StaleRevision {
        expected: Revision,
        actual: Revision,
    },
    UnknownCommand,
    WrongAssociation,
    WrongEpoch,
    SourceChanged,
    StaleObservation,
    MissingEvidence,
    InvalidTransition(&'static str),
    CounterOverflow,
}

impl Display for TransitionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StaleRevision { expected, actual } => {
                write!(formatter, "expected revision {expected}, found {actual}")
            }
            Self::UnknownCommand => {
                formatter.write_str("command is not durably admitted for target")
            }
            Self::WrongAssociation => {
                formatter.write_str("identity does not belong to this aggregate")
            }
            Self::WrongEpoch => formatter.write_str("observation belongs to another incarnation"),
            Self::SourceChanged => formatter.write_str("observation source changed without rebind"),
            Self::StaleObservation => formatter.write_str("observation sequence did not advance"),
            Self::MissingEvidence => formatter.write_str("transition lacks fresh source evidence"),
            Self::InvalidTransition(reason) => formatter.write_str(reason),
            Self::CounterOverflow => formatter.write_str("revision or ordinal exhausted its range"),
        }
    }
}

impl Error for TransitionError {}

impl From<IdError> for TransitionError {
    fn from(_: IdError) -> Self {
        Self::CounterOverflow
    }
}

/// The persistence layer implements this from its admitted command ledger.
/// A caller-supplied command ID alone never authorizes a run mutation.
pub trait CommandAdmission {
    fn admits_run(&self, command_id: &CommandId, run_id: &RunId, kind: RunCommandKind) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RunCommandKind {
    Launch,
    Pause,
    Resume,
    Stop,
    Report,
    Outcome(RunOutcome),
}

/// The persistence layer verifies that an immutable event actually proves a
/// delivery observation for this delivery and stage.
pub trait DeliveryEvidenceLookup {
    fn proves_stage(
        &self,
        event_id: &EventId,
        delivery_id: &DeliveryId,
        stage: DeliveryStage,
    ) -> bool;
}

fn next_revision(current: Revision, expected: Revision) -> Result<Revision, TransitionError> {
    if current != expected {
        return Err(TransitionError::StaleRevision {
            expected,
            actual: current,
        });
    }
    current.checked_next().map_err(Into::into)
}

fn admitted(
    lookup: &impl CommandAdmission,
    command_id: &CommandId,
    run_id: &RunId,
    kind: RunCommandKind,
) -> Result<(), TransitionError> {
    if lookup.admits_run(command_id, run_id, kind) {
        Ok(())
    } else {
        Err(TransitionError::UnknownCommand)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    id: SessionId,
    actor_id: ActorId,
    scope_id: ScopeId,
    state: SessionState,
    current_run_id: Option<RunId>,
    revision: Revision,
}

impl Session {
    pub fn new(id: SessionId, actor_id: ActorId, scope_id: ScopeId) -> Self {
        Self {
            id,
            actor_id,
            scope_id,
            state: SessionState::Open,
            current_run_id: None,
            revision: Revision::INITIAL,
        }
    }

    pub fn id(&self) -> &SessionId {
        &self.id
    }
    pub fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }
    pub fn scope_id(&self) -> &ScopeId {
        &self.scope_id
    }
    pub fn state(&self) -> SessionState {
        self.state
    }
    pub fn current_run_id(&self) -> Option<&RunId> {
        self.current_run_id.as_ref()
    }
    pub fn revision(&self) -> Revision {
        self.revision
    }

    pub fn bind_run(&mut self, expected: Revision, run: &Run) -> Result<Revision, TransitionError> {
        let next = next_revision(self.revision, expected)?;
        if self.state != SessionState::Open || self.current_run_id.is_some() {
            return Err(TransitionError::InvalidTransition(
                "session already has a writer or is closed",
            ));
        }
        if run.session_id != self.id
            || run.actor_id != self.actor_id
            || run.scope_id != self.scope_id
        {
            return Err(TransitionError::WrongAssociation);
        }
        self.current_run_id = Some(run.id.clone());
        self.revision = next;
        Ok(next)
    }

    pub fn release_run(
        &mut self,
        expected: Revision,
        run: &Run,
    ) -> Result<Revision, TransitionError> {
        let next = next_revision(self.revision, expected)?;
        if self.current_run_id.as_ref() != Some(&run.id) {
            return Err(TransitionError::WrongAssociation);
        }
        if !run.is_ended() {
            return Err(TransitionError::InvalidTransition("run has not ended"));
        }
        self.current_run_id = None;
        self.revision = next;
        Ok(next)
    }

    pub fn close(&mut self, expected: Revision) -> Result<Revision, TransitionError> {
        let next = next_revision(self.revision, expected)?;
        if self.state != SessionState::Open || self.current_run_id.is_some() {
            return Err(TransitionError::InvalidTransition(
                "active or closed session cannot close",
            ));
        }
        self.state = SessionState::Closed;
        self.revision = next;
        Ok(next)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Run {
    id: RunId,
    session_id: SessionId,
    actor_id: ActorId,
    scope_id: ScopeId,
    parent_run_id: Option<RunId>,
    role: Role,
    work_kind: WorkKind,
    admission: AdmissionState,
    desired: DesiredMode,
    execution: ExecutionState,
    foreground: ForegroundState,
    observation: Observation,
    result: ResultState,
    outcome: Option<RunOutcome>,
    current_attempt_id: Option<AttemptId>,
    last_attempt_ordinal: u64,
    foreground_observation: Observation,
    revision: Revision,
}

impl Run {
    pub fn new(
        id: RunId,
        session: &Session,
        role: Role,
        work_kind: WorkKind,
        parent_run_id: Option<RunId>,
    ) -> Self {
        Self {
            id,
            session_id: session.id.clone(),
            actor_id: session.actor_id.clone(),
            scope_id: session.scope_id.clone(),
            parent_run_id,
            role,
            work_kind,
            admission: AdmissionState::Queued,
            desired: DesiredMode::Run,
            execution: ExecutionState::Queued,
            foreground: ForegroundState::Unknown,
            observation: Observation::UNAVAILABLE,
            result: ResultState::Unreported,
            outcome: None,
            current_attempt_id: None,
            last_attempt_ordinal: 0,
            foreground_observation: Observation::UNAVAILABLE,
            revision: Revision::INITIAL,
        }
    }

    pub fn id(&self) -> &RunId {
        &self.id
    }
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }
    pub fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }
    pub fn scope_id(&self) -> &ScopeId {
        &self.scope_id
    }
    pub fn parent_run_id(&self) -> Option<&RunId> {
        self.parent_run_id.as_ref()
    }
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn work_kind(&self) -> WorkKind {
        self.work_kind
    }
    pub fn admission(&self) -> AdmissionState {
        self.admission
    }
    pub fn desired(&self) -> DesiredMode {
        self.desired
    }
    pub fn execution(&self) -> ExecutionState {
        self.execution
    }
    pub fn foreground(&self) -> ForegroundState {
        self.foreground
    }
    pub fn observation(&self) -> Observation {
        self.observation.clone()
    }
    pub fn result(&self) -> &ResultState {
        &self.result
    }
    pub fn outcome(&self) -> Option<RunOutcome> {
        self.outcome
    }
    pub fn current_attempt_id(&self) -> Option<&AttemptId> {
        self.current_attempt_id.as_ref()
    }
    pub fn revision(&self) -> Revision {
        self.revision
    }
    pub fn is_ended(&self) -> bool {
        self.admission == AdmissionState::Rejected
            || (self.execution == ExecutionState::Ended && self.outcome.is_some())
    }

    pub fn admit(
        &mut self,
        expected: Revision,
        command_id: &CommandId,
        lookup: &impl CommandAdmission,
    ) -> Result<Revision, TransitionError> {
        let next = next_revision(self.revision, expected)?;
        admitted(lookup, command_id, &self.id, RunCommandKind::Launch)?;
        if self.admission != AdmissionState::Queued {
            return Err(TransitionError::InvalidTransition(
                "run admission cannot reverse",
            ));
        }
        self.admission = AdmissionState::Admitted;
        self.revision = next;
        Ok(next)
    }

    pub fn reject(
        &mut self,
        expected: Revision,
        command_id: &CommandId,
        lookup: &impl CommandAdmission,
    ) -> Result<Revision, TransitionError> {
        let next = next_revision(self.revision, expected)?;
        admitted(lookup, command_id, &self.id, RunCommandKind::Launch)?;
        if self.admission != AdmissionState::Queued {
            return Err(TransitionError::InvalidTransition(
                "run admission cannot reverse",
            ));
        }
        self.admission = AdmissionState::Rejected;
        self.execution = ExecutionState::Ended;
        self.revision = next;
        Ok(next)
    }

    pub fn request_mode(
        &mut self,
        expected: Revision,
        command_id: &CommandId,
        lookup: &impl CommandAdmission,
        mode: DesiredMode,
    ) -> Result<Revision, TransitionError> {
        let next = next_revision(self.revision, expected)?;
        let kind = match mode {
            DesiredMode::Run => RunCommandKind::Resume,
            DesiredMode::Pause => RunCommandKind::Pause,
            DesiredMode::Stop => RunCommandKind::Stop,
        };
        admitted(lookup, command_id, &self.id, kind)?;
        if self.admission != AdmissionState::Admitted || self.execution == ExecutionState::Ended {
            return Err(TransitionError::InvalidTransition(
                "terminal or unadmitted run cannot change mode",
            ));
        }
        let valid = matches!(
            (self.desired, mode),
            (DesiredMode::Run, DesiredMode::Pause)
                | (DesiredMode::Run, DesiredMode::Stop)
                | (DesiredMode::Pause, DesiredMode::Run)
                | (DesiredMode::Pause, DesiredMode::Stop)
        );
        if !valid {
            return Err(TransitionError::InvalidTransition(
                "desired mode cannot reverse or repeat",
            ));
        }
        self.desired = mode;
        self.revision = next;
        Ok(next)
    }

    pub fn start_attempt(
        &mut self,
        expected: Revision,
        attempt: &Attempt,
    ) -> Result<Revision, TransitionError> {
        let next = next_revision(self.revision, expected)?;
        if attempt.run_id != self.id {
            return Err(TransitionError::WrongAssociation);
        }
        if self.admission != AdmissionState::Admitted
            || self.desired != DesiredMode::Run
            || !matches!(
                self.execution,
                ExecutionState::Queued | ExecutionState::Recovering
            )
            || self.current_attempt_id.is_some()
            || attempt.ordinal
                != self
                    .last_attempt_ordinal
                    .checked_add(1)
                    .ok_or(TransitionError::CounterOverflow)?
        {
            return Err(TransitionError::InvalidTransition(
                "attempt lacks a free, ordered run slot",
            ));
        }
        self.current_attempt_id = Some(attempt.id.clone());
        self.last_attempt_ordinal = attempt.ordinal;
        self.execution = ExecutionState::Starting;
        self.foreground = ForegroundState::Unknown;
        self.observation = Observation::UNAVAILABLE;
        self.foreground_observation = Observation::UNAVAILABLE;
        self.revision = next;
        Ok(next)
    }

    pub fn mark_active(
        &mut self,
        expected: Revision,
        attempt: &Attempt,
    ) -> Result<Revision, TransitionError> {
        let next = next_revision(self.revision, expected)?;
        self.check_attempt(attempt)?;
        if !matches!(
            self.execution,
            ExecutionState::Starting | ExecutionState::Recovering
        ) || attempt.process != ProcessState::Alive
            || attempt.observation.freshness != ObservationFreshness::Fresh
            || attempt.last_process_observation != Some(ProcessObservation::Alive)
        {
            return Err(TransitionError::MissingEvidence);
        }
        self.execution = ExecutionState::Active;
        self.observation = attempt.observation.clone();
        self.revision = next;
        Ok(next)
    }

    pub fn mark_recovering(
        &mut self,
        expected: Revision,
        attempt: &Attempt,
    ) -> Result<Revision, TransitionError> {
        let next = next_revision(self.revision, expected)?;
        self.check_attempt(attempt)?;
        if !matches!(
            self.execution,
            ExecutionState::Starting | ExecutionState::Active
        ) || (attempt.process == ProcessState::Alive
            && attempt.observation.freshness == ObservationFreshness::Fresh
            && attempt.last_process_observation == Some(ProcessObservation::Alive))
        {
            return Err(TransitionError::InvalidTransition(
                "healthy attempt cannot enter recovery",
            ));
        }
        self.execution = ExecutionState::Recovering;
        self.foreground = ForegroundState::Unknown;
        self.observation = attempt.observation.clone();
        self.revision = next;
        Ok(next)
    }

    pub fn release_exited_attempt(
        &mut self,
        expected: Revision,
        attempt: &Attempt,
    ) -> Result<Revision, TransitionError> {
        let next = next_revision(self.revision, expected)?;
        self.check_attempt(attempt)?;
        if self.execution != ExecutionState::Recovering
            || !matches!(attempt.process, ProcessState::Exited { .. })
            || attempt.observation.freshness != ObservationFreshness::Fresh
            || !matches!(
                attempt.last_process_observation,
                Some(ProcessObservation::Exited { .. })
            )
        {
            return Err(TransitionError::MissingEvidence);
        }
        self.current_attempt_id = None;
        self.revision = next;
        Ok(next)
    }

    pub fn end_execution(
        &mut self,
        expected: Revision,
        attempt: &Attempt,
    ) -> Result<Revision, TransitionError> {
        let next = next_revision(self.revision, expected)?;
        self.check_attempt(attempt)?;
        if !matches!(
            self.execution,
            ExecutionState::Starting | ExecutionState::Active | ExecutionState::Recovering
        ) || !matches!(attempt.process, ProcessState::Exited { .. })
            || attempt.observation.freshness != ObservationFreshness::Fresh
            || !matches!(
                attempt.last_process_observation,
                Some(ProcessObservation::Exited { .. })
            )
        {
            return Err(TransitionError::MissingEvidence);
        }
        self.current_attempt_id = None;
        self.execution = ExecutionState::Ended;
        self.foreground = ForegroundState::Unknown;
        self.observation = attempt.observation.clone();
        self.revision = next;
        Ok(next)
    }

    pub fn observe_foreground(
        &mut self,
        expected: Revision,
        attempt: &Attempt,
        evidence: ForegroundEvidence,
    ) -> Result<Revision, TransitionError> {
        let next = next_revision(self.revision, expected)?;
        self.check_attempt(attempt)?;
        if evidence.attempt_id != attempt.id {
            return Err(TransitionError::WrongAssociation);
        }
        if evidence.subject_epoch != attempt.epoch {
            return Err(TransitionError::WrongEpoch);
        }
        validate_source_cursor(
            &self.foreground_observation,
            &evidence.source_id,
            evidence.source_epoch,
            evidence.source_sequence,
        )?;
        if self.execution != ExecutionState::Active {
            return Err(TransitionError::InvalidTransition(
                "foreground requires active execution",
            ));
        }
        if evidence.freshness == ObservationFreshness::Unavailable {
            return Err(TransitionError::MissingEvidence);
        }
        if evidence.freshness == ObservationFreshness::Fresh {
            self.foreground = evidence.state;
        } else if evidence.state != ForegroundState::Unknown {
            return Err(TransitionError::MissingEvidence);
        }
        self.observation = Observation {
            freshness: evidence.freshness,
            source_id: Some(evidence.source_id.clone()),
            source_epoch: Some(evidence.source_epoch),
            source_sequence: Some(evidence.source_sequence),
        };
        self.foreground_observation = self.observation.clone();
        self.revision = next;
        Ok(next)
    }

    pub fn record_report(
        &mut self,
        expected: Revision,
        command_id: &CommandId,
        lookup: &impl CommandAdmission,
        report_id: ReportId,
    ) -> Result<Revision, TransitionError> {
        let next = next_revision(self.revision, expected)?;
        admitted(lookup, command_id, &self.id, RunCommandKind::Report)?;
        if self.admission != AdmissionState::Admitted || self.result != ResultState::Unreported {
            return Err(TransitionError::InvalidTransition(
                "report already exists or run was not admitted",
            ));
        }
        self.result = ResultState::Reported { report_id };
        self.revision = next;
        Ok(next)
    }

    pub fn record_outcome(
        &mut self,
        expected: Revision,
        command_id: &CommandId,
        lookup: &impl CommandAdmission,
        outcome: RunOutcome,
    ) -> Result<Revision, TransitionError> {
        let next = next_revision(self.revision, expected)?;
        admitted(
            lookup,
            command_id,
            &self.id,
            RunCommandKind::Outcome(outcome),
        )?;
        if self.admission != AdmissionState::Admitted
            || self.execution != ExecutionState::Ended
            || self.outcome.is_some()
        {
            return Err(TransitionError::InvalidTransition(
                "outcome requires ended execution and cannot be replaced",
            ));
        }
        self.outcome = Some(outcome);
        self.revision = next;
        Ok(next)
    }

    fn check_attempt(&self, attempt: &Attempt) -> Result<(), TransitionError> {
        if attempt.run_id != self.id || self.current_attempt_id.as_ref() != Some(&attempt.id) {
            Err(TransitionError::WrongAssociation)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// A source observation after the ingress layer has authenticated its source.
/// Core checks identity, incarnation and monotonic cursor; it cannot attest a
/// provider or pod merely because a caller constructed this value.
pub struct ProcessEvidence<I> {
    pub subject_id: I,
    /// Process, pod or resource incarnation being observed.
    pub subject_epoch: Epoch,
    /// Stable identity of the attested observer; switching sources needs a separate rebind.
    pub source_id: SourceId,
    /// Independent source incarnation; may advance while the subject stays alive.
    pub source_epoch: Epoch,
    pub source_sequence: u64,
    pub freshness: ObservationFreshness,
    pub observed: ProcessObservation,
}

pub type ObservationEvidence = ProcessEvidence<AttemptId>;
pub type PodObservationEvidence = ProcessEvidence<PodId>;
pub type ResourceObservationEvidence = ProcessEvidence<ResourceId>;

fn validate_source_cursor(
    previous: &Observation,
    source_id: &SourceId,
    source_epoch: Epoch,
    source_sequence: u64,
) -> Result<(), TransitionError> {
    if source_sequence == 0 {
        return Err(TransitionError::StaleObservation);
    }
    if previous
        .source_id
        .as_ref()
        .is_some_and(|old| old != source_id)
    {
        return Err(TransitionError::SourceChanged);
    }
    if let Some(previous_epoch) = previous.source_epoch {
        if source_epoch < previous_epoch {
            return Err(TransitionError::WrongEpoch);
        }
        if source_epoch == previous_epoch
            && previous
                .source_sequence
                .is_some_and(|last| source_sequence <= last)
        {
            return Err(TransitionError::StaleObservation);
        }
    }
    Ok(())
}

fn observe_process(
    process: ProcessState,
    previous: &Observation,
    source_id: &SourceId,
    source_epoch: Epoch,
    source_sequence: u64,
    freshness: ObservationFreshness,
    observed: ProcessObservation,
) -> Result<(ProcessState, Observation, Option<ProcessObservation>), TransitionError> {
    validate_source_cursor(previous, source_id, source_epoch, source_sequence)?;
    if freshness == ObservationFreshness::Unavailable {
        return Err(TransitionError::MissingEvidence);
    }
    let next_process = if freshness == ObservationFreshness::Fresh {
        match observed {
            ProcessObservation::Unknown => process,
            ProcessObservation::Alive => {
                if matches!(process, ProcessState::Exited { .. }) {
                    return Err(TransitionError::InvalidTransition(
                        "exited process cannot become alive in one epoch",
                    ));
                }
                ProcessState::Alive
            }
            ProcessObservation::Exited { code } => {
                if matches!(process, ProcessState::Exited { code: previous_code } if previous_code != code)
                {
                    return Err(TransitionError::InvalidTransition(
                        "one process cannot have conflicting exit observations",
                    ));
                }
                ProcessState::Exited { code }
            }
        }
    } else if observed == ProcessObservation::Unknown {
        process
    } else {
        return Err(TransitionError::MissingEvidence);
    };
    Ok((
        next_process,
        Observation {
            freshness,
            source_id: Some(source_id.clone()),
            source_epoch: Some(source_epoch),
            source_sequence: Some(source_sequence),
        },
        (freshness == ObservationFreshness::Fresh).then_some(observed),
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attempt {
    id: AttemptId,
    run_id: RunId,
    ordinal: u64,
    epoch: Epoch,
    pod_id: Option<PodId>,
    process: ProcessState,
    observation: Observation,
    last_process_observation: Option<ProcessObservation>,
    revision: Revision,
}

impl Attempt {
    pub fn new(
        id: AttemptId,
        run_id: RunId,
        ordinal: u64,
        epoch: Epoch,
    ) -> Result<Self, TransitionError> {
        if ordinal == 0 {
            return Err(TransitionError::InvalidTransition(
                "attempt ordinal must be positive",
            ));
        }
        Ok(Self {
            id,
            run_id,
            ordinal,
            epoch,
            pod_id: None,
            process: ProcessState::Starting,
            observation: Observation::UNAVAILABLE,
            last_process_observation: None,
            revision: Revision::INITIAL,
        })
    }
    pub fn id(&self) -> &AttemptId {
        &self.id
    }
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }
    pub fn ordinal(&self) -> u64 {
        self.ordinal
    }
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }
    pub fn pod_id(&self) -> Option<&PodId> {
        self.pod_id.as_ref()
    }
    pub fn process(&self) -> ProcessState {
        self.process
    }
    pub fn observation(&self) -> Observation {
        self.observation.clone()
    }
    pub fn last_process_observation(&self) -> Option<ProcessObservation> {
        self.last_process_observation
    }
    pub fn revision(&self) -> Revision {
        self.revision
    }

    pub fn attach_pod(
        &mut self,
        expected: Revision,
        pod: &Pod,
    ) -> Result<Revision, TransitionError> {
        let next = next_revision(self.revision, expected)?;
        if pod.attempt_id != self.id {
            return Err(TransitionError::WrongAssociation);
        }
        if self.pod_id.is_some() {
            return Err(TransitionError::InvalidTransition(
                "attempt already has a pod",
            ));
        }
        self.pod_id = Some(pod.id.clone());
        self.revision = next;
        Ok(next)
    }

    pub fn observe_process(
        &mut self,
        expected: Revision,
        evidence: ObservationEvidence,
    ) -> Result<Revision, TransitionError> {
        let next = next_revision(self.revision, expected)?;
        if evidence.subject_id != self.id {
            return Err(TransitionError::WrongAssociation);
        }
        if evidence.subject_epoch != self.epoch {
            return Err(TransitionError::WrongEpoch);
        }
        let (process, observation, last_process_observation) = observe_process(
            self.process,
            &self.observation,
            &evidence.source_id,
            evidence.source_epoch,
            evidence.source_sequence,
            evidence.freshness,
            evidence.observed,
        )?;
        self.process = process;
        self.observation = observation;
        self.last_process_observation = last_process_observation;
        self.revision = next;
        Ok(next)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pod {
    id: PodId,
    attempt_id: AttemptId,
    epoch: Epoch,
    resource_ids: Vec<ResourceId>,
    supervisor: ProcessState,
    observation: Observation,
    last_process_observation: Option<ProcessObservation>,
    revision: Revision,
}

impl Pod {
    pub fn new(id: PodId, attempt_id: AttemptId, epoch: Epoch) -> Self {
        Self {
            id,
            attempt_id,
            epoch,
            resource_ids: Vec::new(),
            supervisor: ProcessState::Starting,
            observation: Observation::UNAVAILABLE,
            last_process_observation: None,
            revision: Revision::INITIAL,
        }
    }
    pub fn id(&self) -> &PodId {
        &self.id
    }
    pub fn attempt_id(&self) -> &AttemptId {
        &self.attempt_id
    }
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }
    pub fn resource_ids(&self) -> &[ResourceId] {
        &self.resource_ids
    }
    pub fn supervisor(&self) -> ProcessState {
        self.supervisor
    }
    pub fn observation(&self) -> Observation {
        self.observation.clone()
    }
    pub fn last_process_observation(&self) -> Option<ProcessObservation> {
        self.last_process_observation
    }
    pub fn revision(&self) -> Revision {
        self.revision
    }

    pub fn attach_resource(
        &mut self,
        expected: Revision,
        resource: &Resource,
    ) -> Result<Revision, TransitionError> {
        let next = next_revision(self.revision, expected)?;
        if resource.pod_id != self.id {
            return Err(TransitionError::WrongAssociation);
        }
        if self.resource_ids.contains(&resource.id) {
            return Err(TransitionError::InvalidTransition(
                "resource already belongs to pod",
            ));
        }
        self.resource_ids.push(resource.id.clone());
        self.revision = next;
        Ok(next)
    }

    pub fn observe_supervisor(
        &mut self,
        expected: Revision,
        evidence: PodObservationEvidence,
    ) -> Result<Revision, TransitionError> {
        let next = next_revision(self.revision, expected)?;
        if evidence.subject_id != self.id {
            return Err(TransitionError::WrongAssociation);
        }
        if evidence.subject_epoch != self.epoch {
            return Err(TransitionError::WrongEpoch);
        }
        let (process, observation, last_process_observation) = observe_process(
            self.supervisor,
            &self.observation,
            &evidence.source_id,
            evidence.source_epoch,
            evidence.source_sequence,
            evidence.freshness,
            evidence.observed,
        )?;
        self.supervisor = process;
        self.observation = observation;
        self.last_process_observation = last_process_observation;
        self.revision = next;
        Ok(next)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Resource {
    id: ResourceId,
    pod_id: PodId,
    kind: ResourceKind,
    epoch: Epoch,
    process: ProcessState,
    observation: Observation,
    last_process_observation: Option<ProcessObservation>,
    revision: Revision,
}

impl Resource {
    pub fn new(id: ResourceId, pod_id: PodId, kind: ResourceKind, epoch: Epoch) -> Self {
        Self {
            id,
            pod_id,
            kind,
            epoch,
            process: ProcessState::Starting,
            observation: Observation::UNAVAILABLE,
            last_process_observation: None,
            revision: Revision::INITIAL,
        }
    }
    pub fn id(&self) -> &ResourceId {
        &self.id
    }
    pub fn pod_id(&self) -> &PodId {
        &self.pod_id
    }
    pub fn kind(&self) -> ResourceKind {
        self.kind
    }
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }
    pub fn process(&self) -> ProcessState {
        self.process
    }
    pub fn observation(&self) -> Observation {
        self.observation.clone()
    }
    pub fn last_process_observation(&self) -> Option<ProcessObservation> {
        self.last_process_observation
    }
    pub fn revision(&self) -> Revision {
        self.revision
    }

    pub fn observe_process(
        &mut self,
        expected: Revision,
        evidence: ResourceObservationEvidence,
    ) -> Result<Revision, TransitionError> {
        let next = next_revision(self.revision, expected)?;
        if evidence.subject_id != self.id {
            return Err(TransitionError::WrongAssociation);
        }
        if evidence.subject_epoch != self.epoch {
            return Err(TransitionError::WrongEpoch);
        }
        let (process, observation, last_process_observation) = observe_process(
            self.process,
            &self.observation,
            &evidence.source_id,
            evidence.source_epoch,
            evidence.source_sequence,
            evidence.freshness,
            evidence.observed,
        )?;
        self.process = process;
        self.observation = observation;
        self.last_process_observation = last_process_observation;
        self.revision = next;
        Ok(next)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForegroundEvidence {
    pub attempt_id: AttemptId,
    pub subject_epoch: Epoch,
    pub source_id: SourceId,
    pub source_epoch: Epoch,
    pub source_sequence: u64,
    pub freshness: ObservationFreshness,
    pub state: ForegroundState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delivery {
    id: DeliveryId,
    command_id: CommandId,
    session_id: SessionId,
    stage: DeliveryStage,
    evidence_event_id: Option<EventId>,
    revision: Revision,
}

impl Delivery {
    pub fn new(id: DeliveryId, command_id: CommandId, session_id: SessionId) -> Self {
        Self {
            id,
            command_id,
            session_id,
            stage: DeliveryStage::Persisted,
            evidence_event_id: None,
            revision: Revision::INITIAL,
        }
    }
    pub fn id(&self) -> &DeliveryId {
        &self.id
    }
    pub fn command_id(&self) -> &CommandId {
        &self.command_id
    }
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }
    pub fn stage(&self) -> DeliveryStage {
        self.stage
    }
    pub fn evidence_event_id(&self) -> Option<&EventId> {
        self.evidence_event_id.as_ref()
    }
    pub fn revision(&self) -> Revision {
        self.revision
    }

    pub fn advance(
        &mut self,
        expected: Revision,
        command_id: &CommandId,
        next_stage: DeliveryStage,
        evidence_event_id: Option<EventId>,
        observations: &impl DeliveryEvidenceLookup,
    ) -> Result<Revision, TransitionError> {
        let next = next_revision(self.revision, expected)?;
        if command_id != &self.command_id {
            return Err(TransitionError::UnknownCommand);
        }
        if !delivery_step(self.stage, next_stage) {
            return Err(TransitionError::InvalidTransition(
                "delivery stage cannot reverse or skip safety boundary",
            ));
        }
        let observed_stage = matches!(
            next_stage,
            DeliveryStage::HostAccepted
                | DeliveryStage::ProviderQueued
                | DeliveryStage::ProviderInserted
                | DeliveryStage::ReplyObserved
                | DeliveryStage::Acknowledged
        );
        if observed_stage && evidence_event_id.is_none() {
            return Err(TransitionError::MissingEvidence);
        }
        if let Some(event_id) = evidence_event_id.as_ref() {
            if !observations.proves_stage(event_id, &self.id, next_stage) {
                return Err(TransitionError::MissingEvidence);
            }
        }
        self.stage = next_stage;
        if evidence_event_id.is_some() {
            self.evidence_event_id = evidence_event_id;
        }
        self.revision = next;
        Ok(next)
    }
}

fn delivery_step(current: DeliveryStage, next: DeliveryStage) -> bool {
    use DeliveryStage::*;
    match current {
        Persisted => matches!(next, Blocked | Dispatching | Cancelled | Rejected),
        Blocked => matches!(next, Dispatching | Cancelled | Rejected),
        Dispatching => matches!(
            next,
            HostAccepted | ProviderQueued | ProviderInserted | Uncertain | Rejected
        ),
        HostAccepted => matches!(
            next,
            ProviderQueued | ProviderInserted | ReplyObserved | Acknowledged | Uncertain
        ),
        ProviderQueued => matches!(
            next,
            ProviderInserted | ReplyObserved | Acknowledged | Uncertain
        ),
        ProviderInserted => matches!(next, ReplyObserved | Acknowledged | Uncertain),
        Uncertain => matches!(
            next,
            HostAccepted
                | ProviderQueued
                | ProviderInserted
                | ReplyObserved
                | Acknowledged
                | Rejected
        ),
        ReplyObserved => next == Acknowledged,
        Acknowledged | Cancelled | Rejected => false,
    }
}
