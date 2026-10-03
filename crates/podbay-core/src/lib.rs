//! Provider-neutral identities and lifecycle facts shared by coordinators and workers.
#![forbid(unsafe_code)]

mod ids;
mod model;
mod state;

pub use ids::{
    ActorId, AttemptId, CommandId, DeliveryId, Epoch, EventId, IdError, PodId, ReportId,
    ResourceId, Revision, RunId, ScopeId, SessionId, SourceId, WorkIntervalId,
};
pub use model::{
    Attempt, CommandAdmission, Delivery, DeliveryEvidenceLookup, ForegroundEvidence,
    ObservationEvidence, Pod, PodObservationEvidence, ProcessEvidence, Resource,
    ResourceObservationEvidence, Run, RunCommandKind, Session, TransitionError,
};
pub use state::{
    AdmissionState, DeliveryStage, DesiredMode, ExecutionState, ForegroundState, Observation,
    ObservationFreshness, ProcessObservation, ProcessState, ResourceKind, ResultState, Role,
    RunOutcome, SessionState, WorkKind,
};
