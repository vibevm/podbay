//! Provider-neutral identities and lifecycle facts shared by coordinators and workers.
#![forbid(unsafe_code)]

mod ids;
mod launch_binding;
mod model;
mod peer_fence;
mod state;

pub use ids::{
    ActorId, AttemptId, CommandId, CommandKey, CredentialEpoch, DeliveryId, Epoch, EventId,
    IdError, InputEpoch, OwnerEpoch, PeerGrantId, PodId, ReportId, ResourceId, Revision, RunId,
    ScopeId, SessionId, SourceId, StoreLineageId, WorkIntervalId,
};
pub use launch_binding::{BoundResource, LaunchBinding, LaunchBindingError, PlannedRootBinding};
pub use model::{
    Attempt, CommandAdmission, Delivery, DeliveryEvidenceLookup, ForegroundEvidence,
    ObservationEvidence, Pod, PodObservationEvidence, ProcessEvidence, Resource,
    ResourceObservationEvidence, Run, RunCommandKind, Session, TransitionError,
};
pub use peer_fence::{
    AttestedPeer, FenceError, FenceOperation, FenceTarget, GrantKind, ManagerLiveness,
    OwnerEpochWitness, POD_FENCE_CHECKPOINT_VERSION, PeerGrant, PeerRequest, PodFenceCheckpoint,
    PodFenceIdentity, PodPeerFence, RebindLedger, RebindPhase, RebindProposal, RequestDigest,
};
pub use state::{
    AdmissionState, DeliveryStage, DesiredMode, ExecutionState, ForegroundState, Observation,
    ObservationFreshness, ProcessObservation, ProcessState, ResourceKind, ResultState, Role,
    RunOutcome, SessionState, WorkKind,
};
