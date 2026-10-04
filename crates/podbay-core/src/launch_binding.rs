//! Immutable identity snapshot for one current run attempt and its whole pod.
//! It validates aggregate associations; durable admission and OS launch policy
//! remain separate proofs supplied by the manager and store.
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::{
    ActorId, AdmissionState, Attempt, AttemptId, DesiredMode, Epoch, ExecutionState, Pod, PodId,
    Resource, ResourceId, ResourceKind, Role, Run, RunId, ScopeId, Session, SessionId,
    SessionState, WorkKind,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchBindingError {
    SessionUnavailable,
    RunNotAdmitted,
    RunNotQueued,
    WrongPhase,
    WrongSessionRun,
    MissingCurrentAttempt,
    WrongRunAttempt,
    MissingAttemptPod,
    WrongAttemptPod,
    EmptyResources,
    DuplicateResource,
    ResourceSetMismatch,
    WrongResourcePod,
    InvalidEpoch,
}

impl Display for LaunchBindingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::SessionUnavailable => "session is closed or has no current run",
            Self::RunNotAdmitted => "run has no admitted launch state",
            Self::RunNotQueued => "planned root run is not queued and unadmitted",
            Self::WrongPhase => "planned and admitted launch binding phases differ",
            Self::WrongSessionRun => "run differs from the session actor, scope or current writer",
            Self::MissingCurrentAttempt => "run has no current attempt",
            Self::WrongRunAttempt => "attempt is not the run's current attempt",
            Self::MissingAttemptPod => "attempt has no attached pod",
            Self::WrongAttemptPod => "pod is not the attempt's attached pod",
            Self::EmptyResources => "pod has no declared resources",
            Self::DuplicateResource => "resource inventory repeats an ID",
            Self::ResourceSetMismatch => "resource inventory does not equal the pod's ordered set",
            Self::WrongResourcePod => "resource belongs to another pod",
            Self::InvalidEpoch => "attempt, pod or resource epoch is not positive",
        })
    }
}
impl Error for LaunchBindingError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundResource {
    id: ResourceId,
    kind: ResourceKind,
    epoch: Epoch,
}

impl BoundResource {
    pub fn id(&self) -> &ResourceId {
        &self.id
    }
    pub fn kind(&self) -> ResourceKind {
        self.kind
    }
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchBinding {
    phase: BindingPhase,
    scope_id: ScopeId,
    actor_id: ActorId,
    session_id: SessionId,
    run_id: RunId,
    parent_run_id: Option<RunId>,
    role: Role,
    work_kind: WorkKind,
    attempt_id: AttemptId,
    attempt_ordinal: u64,
    attempt_epoch: Epoch,
    pod_id: PodId,
    pod_incarnation: Epoch,
    resources: Vec<BoundResource>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BindingPhase {
    Planned,
    Admitted,
}

/// Identity-only first-root plan. Its Run has not been admitted; only the
/// store transaction may turn it into a current LaunchBinding after inserting
/// the command row. Holding this value grants no launch authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedRootBinding {
    identity: LaunchBinding,
}

impl PlannedRootBinding {
    /// The returned snapshot retains its private planned phase. V1 and
    /// admitted-binding APIs must reject it; it is never an admission proof.
    pub fn identity(&self) -> &LaunchBinding {
        &self.identity
    }

    /// Recheck a copied identity at the V2 store boundary. The identity was
    /// produced by a core constructor; a queued Run cannot claim admission.
    pub fn from_queued_snapshot(
        session: &Session,
        run: &Run,
        identity: &LaunchBinding,
    ) -> Result<Self, LaunchBindingError> {
        require_queued_root(run)?;
        if identity.phase != BindingPhase::Planned {
            return Err(LaunchBindingError::WrongPhase);
        }
        if session.state() != SessionState::Open || session.current_run_id() != Some(run.id()) {
            return Err(LaunchBindingError::SessionUnavailable);
        }
        if identity.session_id() != session.id()
            || identity.actor_id() != session.actor_id()
            || identity.scope_id() != session.scope_id()
            || identity.run_id() != run.id()
            || run.session_id() != session.id()
            || run.actor_id() != session.actor_id()
            || run.scope_id() != session.scope_id()
            || identity.role() != run.role()
            || identity.work_kind() != run.work_kind()
            || identity.parent_run_id().is_some()
            || identity.attempt_ordinal() != 1
        {
            return Err(LaunchBindingError::WrongSessionRun);
        }
        Ok(Self {
            identity: identity.clone(),
        })
    }

    /// Rebuild the strict post-command binding from the transitioned Run and
    /// the already-checked planned identities. This never supplies a command
    /// witness; the store must call it only after its inserted-row proof.
    pub fn confirm_after_admission(
        &self,
        session: &Session,
        run: &Run,
    ) -> Result<LaunchBinding, LaunchBindingError> {
        let identity = &self.identity;
        let mut attempt = Attempt::new(
            identity.attempt_id.clone(),
            identity.run_id.clone(),
            identity.attempt_ordinal,
            identity.attempt_epoch,
        )
        .map_err(|_| LaunchBindingError::WrongRunAttempt)?;
        let mut pod = Pod::new(
            identity.pod_id.clone(),
            identity.attempt_id.clone(),
            identity.pod_incarnation,
        );
        attempt
            .attach_pod(attempt.revision(), &pod)
            .map_err(|_| LaunchBindingError::WrongAttemptPod)?;
        let mut resources = Vec::with_capacity(identity.resources.len());
        for bound in &identity.resources {
            let resource = Resource::new(
                bound.id.clone(),
                identity.pod_id.clone(),
                bound.kind,
                bound.epoch,
            );
            pod.attach_resource(pod.revision(), &resource)
                .map_err(|_| LaunchBindingError::ResourceSetMismatch)?;
            resources.push(resource);
        }
        let strict = LaunchBinding::from_aggregates(session, run, &attempt, &pod, &resources)?;
        let mut expected = identity.clone();
        expected.phase = BindingPhase::Admitted;
        if strict != expected {
            return Err(LaunchBindingError::WrongPhase);
        }
        Ok(strict)
    }
}

fn require_queued_root(run: &Run) -> Result<(), LaunchBindingError> {
    if run.admission() != AdmissionState::Queued
        || run.execution() != ExecutionState::Queued
        || run.desired() != DesiredMode::Run
        || run.current_attempt_id().is_some()
        || run.last_attempt_ordinal() != 0
        || run.parent_run_id().is_some()
    {
        return Err(LaunchBindingError::RunNotQueued);
    }
    Ok(())
}

impl LaunchBinding {
    /// Produces a copy of existing aggregate identities. No IDs, epochs,
    /// process handles, provider settings or launch paths are allocated here.
    /// Run retains the current attempt ID and ordinal, but not its epoch;
    /// the durable attempt record must verify that epoch before OS effect.
    pub fn from_aggregates(
        session: &Session,
        run: &Run,
        attempt: &Attempt,
        pod: &Pod,
        resources: &[Resource],
    ) -> Result<Self, LaunchBindingError> {
        if session.state() != SessionState::Open || session.current_run_id().is_none() {
            return Err(LaunchBindingError::SessionUnavailable);
        }
        if run.admission() != AdmissionState::Admitted {
            return Err(LaunchBindingError::RunNotAdmitted);
        }
        if session.current_run_id() != Some(run.id())
            || run.session_id() != session.id()
            || run.actor_id() != session.actor_id()
            || run.scope_id() != session.scope_id()
        {
            return Err(LaunchBindingError::WrongSessionRun);
        }
        let current_attempt = run
            .current_attempt_id()
            .ok_or(LaunchBindingError::MissingCurrentAttempt)?;
        if current_attempt != attempt.id()
            || attempt.run_id() != run.id()
            || attempt.ordinal() != run.last_attempt_ordinal()
        {
            return Err(LaunchBindingError::WrongRunAttempt);
        }
        Self::copy_associations(
            session,
            run,
            attempt,
            pod,
            resources,
            BindingPhase::Admitted,
        )
    }

    /// Capture the same identity bytes before first-root admission. The Run
    /// remains queued; no fake `CommandAdmission` witness is needed to review
    /// native policy or form a V2 descriptor.
    pub fn plan_first_root(
        session: &Session,
        run: &Run,
        attempt: &Attempt,
        pod: &Pod,
        resources: &[Resource],
    ) -> Result<PlannedRootBinding, LaunchBindingError> {
        require_queued_root(run)?;
        if attempt.run_id() != run.id() || attempt.ordinal() != 1 {
            return Err(LaunchBindingError::WrongRunAttempt);
        }
        let identity =
            Self::copy_associations(session, run, attempt, pod, resources, BindingPhase::Planned)?;
        Ok(PlannedRootBinding { identity })
    }

    fn copy_associations(
        session: &Session,
        run: &Run,
        attempt: &Attempt,
        pod: &Pod,
        resources: &[Resource],
        phase: BindingPhase,
    ) -> Result<Self, LaunchBindingError> {
        if session.state() != SessionState::Open || session.current_run_id().is_none() {
            return Err(LaunchBindingError::SessionUnavailable);
        }
        if session.current_run_id() != Some(run.id())
            || run.session_id() != session.id()
            || run.actor_id() != session.actor_id()
            || run.scope_id() != session.scope_id()
            || attempt.run_id() != run.id()
        {
            return Err(LaunchBindingError::WrongSessionRun);
        }
        let attached_pod = attempt
            .pod_id()
            .ok_or(LaunchBindingError::MissingAttemptPod)?;
        if attached_pod != pod.id() || pod.attempt_id() != attempt.id() {
            return Err(LaunchBindingError::WrongAttemptPod);
        }
        if attempt.ordinal() == 0 || attempt.epoch().get() == 0 || pod.epoch().get() == 0 {
            return Err(LaunchBindingError::InvalidEpoch);
        }
        if pod.resource_ids().is_empty() || resources.is_empty() {
            return Err(LaunchBindingError::EmptyResources);
        }
        if pod.resource_ids().len() != resources.len() {
            return Err(LaunchBindingError::ResourceSetMismatch);
        }
        let mut seen = BTreeSet::new();
        let mut bound = Vec::with_capacity(resources.len());
        for (declared_id, resource) in pod.resource_ids().iter().zip(resources) {
            if !seen.insert(resource.id().clone()) {
                return Err(LaunchBindingError::DuplicateResource);
            }
            if resource.id() != declared_id {
                return Err(LaunchBindingError::ResourceSetMismatch);
            }
            if resource.pod_id() != pod.id() {
                return Err(LaunchBindingError::WrongResourcePod);
            }
            if resource.epoch().get() == 0 {
                return Err(LaunchBindingError::InvalidEpoch);
            }
            bound.push(BoundResource {
                id: resource.id().clone(),
                kind: resource.kind(),
                epoch: resource.epoch(),
            });
        }
        Ok(Self {
            phase,
            scope_id: session.scope_id().clone(),
            actor_id: session.actor_id().clone(),
            session_id: session.id().clone(),
            run_id: run.id().clone(),
            parent_run_id: run.parent_run_id().cloned(),
            role: run.role(),
            work_kind: run.work_kind(),
            attempt_id: attempt.id().clone(),
            attempt_ordinal: attempt.ordinal(),
            attempt_epoch: attempt.epoch(),
            pod_id: pod.id().clone(),
            pod_incarnation: pod.epoch(),
            resources: bound,
        })
    }

    pub fn is_admitted(&self) -> bool {
        self.phase == BindingPhase::Admitted
    }

    pub fn is_planned(&self) -> bool {
        self.phase == BindingPhase::Planned
    }

    pub fn scope_id(&self) -> &ScopeId {
        &self.scope_id
    }
    pub fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }
    pub fn run_id(&self) -> &RunId {
        &self.run_id
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
    pub fn attempt_id(&self) -> &AttemptId {
        &self.attempt_id
    }
    pub fn attempt_ordinal(&self) -> u64 {
        self.attempt_ordinal
    }
    pub fn attempt_epoch(&self) -> Epoch {
        self.attempt_epoch
    }
    pub fn pod_id(&self) -> &PodId {
        &self.pod_id
    }
    pub fn pod_incarnation(&self) -> Epoch {
        self.pod_incarnation
    }
    pub fn resources(&self) -> &[BoundResource] {
        &self.resources
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommandAdmission, CommandId, RunCommandKind};

    struct Admitted;
    impl CommandAdmission for Admitted {
        fn admits_run(&self, _: &CommandId, _: &RunId, kind: RunCommandKind) -> bool {
            kind == RunCommandKind::Launch
        }
    }
    fn fixture(role: Role, work: WorkKind) -> (Session, Run, Attempt, Pod, Vec<Resource>) {
        let mut session = Session::new(
            SessionId::try_from("session.binding.fixture").unwrap(),
            ActorId::try_from("actor.binding.fixture").unwrap(),
            ScopeId::try_from("scope.binding.fixture").unwrap(),
        );
        let mut run = Run::new(
            RunId::try_from("run.binding.fixture").unwrap(),
            &session,
            role,
            work,
            Some(RunId::try_from("run.parent.fixture").unwrap()),
        );
        let command = CommandId::try_from("command.binding.fixture").unwrap();
        run.admit(run.revision(), &command, &Admitted).unwrap();
        session.bind_run(session.revision(), &run).unwrap();
        let mut attempt = Attempt::new(
            AttemptId::try_from("attempt.binding.fixture").unwrap(),
            run.id().clone(),
            1,
            Epoch::new(3).unwrap(),
        )
        .unwrap();
        run.start_attempt(run.revision(), &attempt).unwrap();
        let mut pod = Pod::new(
            PodId::try_from("pod.binding.fixture").unwrap(),
            attempt.id().clone(),
            Epoch::new(7).unwrap(),
        );
        attempt.attach_pod(attempt.revision(), &pod).unwrap();
        let resources = vec![
            Resource::new(
                ResourceId::try_from("resource.pty.fixture").unwrap(),
                pod.id().clone(),
                ResourceKind::Pty,
                Epoch::new(11).unwrap(),
            ),
            Resource::new(
                ResourceId::try_from("resource.provider.fixture").unwrap(),
                pod.id().clone(),
                ResourceKind::StructuredProvider,
                Epoch::new(12).unwrap(),
            ),
        ];
        for resource in &resources {
            pod.attach_resource(pod.revision(), resource).unwrap();
        }
        (session, run, attempt, pod, resources)
    }

    #[test]
    fn coordinator_and_worker_share_ordered_multi_resource_snapshot() {
        for (role, work) in [
            (Role::Coordinator, WorkKind::Service),
            (Role::Worker, WorkKind::Task),
        ] {
            let (session, run, attempt, pod, resources) = fixture(role, work);
            let binding =
                LaunchBinding::from_aggregates(&session, &run, &attempt, &pod, &resources).unwrap();
            assert_eq!(binding.session_id(), session.id());
            assert_eq!(binding.run_id(), run.id());
            assert_eq!(binding.actor_id(), session.actor_id());
            assert_eq!(binding.scope_id(), session.scope_id());
            assert_eq!(binding.parent_run_id(), run.parent_run_id());
            assert_eq!(binding.role(), role);
            assert_eq!(binding.work_kind(), work);
            assert_eq!(binding.attempt_id(), attempt.id());
            assert_eq!(binding.attempt_epoch(), Epoch::new(3).unwrap());
            assert_eq!(binding.pod_id(), pod.id());
            assert_eq!(binding.pod_incarnation(), Epoch::new(7).unwrap());
            assert_eq!(
                binding
                    .resources()
                    .iter()
                    .map(|resource| resource.id().as_str())
                    .collect::<Vec<_>>(),
                vec!["resource.pty.fixture", "resource.provider.fixture"]
            );
            assert_eq!(
                binding.resources()[1].kind(),
                ResourceKind::StructuredProvider
            );
            assert_eq!(binding.resources()[1].epoch(), Epoch::new(12).unwrap());
        }
    }

    #[test]
    fn missing_or_stale_links_refuse_a_snapshot() {
        let (session, run, attempt, pod, resources) = fixture(Role::Worker, WorkKind::Task);
        let unbound = Session::new(
            session.id().clone(),
            session.actor_id().clone(),
            session.scope_id().clone(),
        );
        assert_eq!(
            LaunchBinding::from_aggregates(&unbound, &run, &attempt, &pod, &resources),
            Err(LaunchBindingError::SessionUnavailable)
        );
        let foreign_session = Session::new(
            SessionId::try_from("session.other").unwrap(),
            session.actor_id().clone(),
            session.scope_id().clone(),
        );
        let unadmitted_run = Run::new(
            RunId::try_from("run.other").unwrap(),
            &foreign_session,
            Role::Worker,
            WorkKind::Task,
            None,
        );
        assert_eq!(
            LaunchBinding::from_aggregates(&session, &unadmitted_run, &attempt, &pod, &resources),
            Err(LaunchBindingError::RunNotAdmitted)
        );
        let mut foreign_run = unadmitted_run;
        foreign_run
            .admit(
                foreign_run.revision(),
                &CommandId::try_from("command.foreign").unwrap(),
                &Admitted,
            )
            .unwrap();
        assert_eq!(
            LaunchBinding::from_aggregates(&session, &foreign_run, &attempt, &pod, &resources),
            Err(LaunchBindingError::WrongSessionRun)
        );
        let mut no_attempt = Run::new(
            RunId::try_from("run.binding.fixture").unwrap(),
            &session,
            Role::Worker,
            WorkKind::Task,
            None,
        );
        no_attempt
            .admit(
                no_attempt.revision(),
                &CommandId::try_from("command.no-attempt").unwrap(),
                &Admitted,
            )
            .unwrap();
        assert_eq!(
            LaunchBinding::from_aggregates(&session, &no_attempt, &attempt, &pod, &resources),
            Err(LaunchBindingError::MissingCurrentAttempt)
        );
        let wrong_attempt = Attempt::new(
            AttemptId::try_from("attempt.other").unwrap(),
            run.id().clone(),
            2,
            Epoch::new(4).unwrap(),
        )
        .unwrap();
        assert_eq!(
            LaunchBinding::from_aggregates(&session, &run, &wrong_attempt, &pod, &resources),
            Err(LaunchBindingError::WrongRunAttempt)
        );
        let mut same_id_wrong_ordinal = Attempt::new(
            attempt.id().clone(),
            run.id().clone(),
            attempt.ordinal() + 1,
            attempt.epoch(),
        )
        .unwrap();
        same_id_wrong_ordinal
            .attach_pod(same_id_wrong_ordinal.revision(), &pod)
            .unwrap();
        assert_eq!(
            LaunchBinding::from_aggregates(
                &session,
                &run,
                &same_id_wrong_ordinal,
                &pod,
                &resources
            ),
            Err(LaunchBindingError::WrongRunAttempt)
        );
        let unattached_attempt = Attempt::new(
            attempt.id().clone(),
            run.id().clone(),
            attempt.ordinal(),
            attempt.epoch(),
        )
        .unwrap();
        assert_eq!(
            LaunchBinding::from_aggregates(&session, &run, &unattached_attempt, &pod, &resources),
            Err(LaunchBindingError::MissingAttemptPod)
        );
        let wrong_pod = Pod::new(
            PodId::try_from("pod.other").unwrap(),
            attempt.id().clone(),
            Epoch::new(8).unwrap(),
        );
        assert_eq!(
            LaunchBinding::from_aggregates(&session, &run, &attempt, &wrong_pod, &resources),
            Err(LaunchBindingError::WrongAttemptPod)
        );
    }

    #[test]
    fn full_resource_inventory_is_required_in_pod_order() {
        let (session, run, attempt, pod, resources) = fixture(Role::Coordinator, WorkKind::Service);
        assert_eq!(
            LaunchBinding::from_aggregates(&session, &run, &attempt, &pod, &[]),
            Err(LaunchBindingError::EmptyResources)
        );
        assert_eq!(
            LaunchBinding::from_aggregates(&session, &run, &attempt, &pod, &resources[..1]),
            Err(LaunchBindingError::ResourceSetMismatch)
        );
        let reversed = vec![resources[1].clone(), resources[0].clone()];
        assert_eq!(
            LaunchBinding::from_aggregates(&session, &run, &attempt, &pod, &reversed),
            Err(LaunchBindingError::ResourceSetMismatch)
        );
        let duplicate = vec![resources[0].clone(), resources[0].clone()];
        assert_eq!(
            LaunchBinding::from_aggregates(&session, &run, &attempt, &pod, &duplicate),
            Err(LaunchBindingError::DuplicateResource)
        );
        let foreign = Resource::new(
            resources[0].id().clone(),
            PodId::try_from("pod.other").unwrap(),
            ResourceKind::Pty,
            Epoch::new(11).unwrap(),
        );
        assert_eq!(
            LaunchBinding::from_aggregates(
                &session,
                &run,
                &attempt,
                &pod,
                &[foreign, resources[1].clone()]
            ),
            Err(LaunchBindingError::WrongResourcePod)
        );
        assert!(Epoch::new(0).is_err());
    }
}
