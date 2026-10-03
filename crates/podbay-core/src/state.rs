//! Independent state axes. None of these enums stands in for another axis.
use crate::{Epoch, ReportId, SourceId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Coordinator,
    Worker,
    Advisor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkKind {
    Task,
    Service,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    Open,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionState {
    Queued,
    Admitted,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DesiredMode {
    Run,
    Pause,
    Stop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionState {
    Queued,
    Starting,
    Active,
    Recovering,
    Ended,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForegroundState {
    Unknown,
    Idle,
    Busy,
    RequiresAction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationFreshness {
    Fresh,
    Stale,
    Disconnected,
    Unavailable,
}

/// Last accepted observer cursor and freshness for one state axis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Observation {
    pub freshness: ObservationFreshness,
    pub source_id: Option<SourceId>,
    pub source_epoch: Option<Epoch>,
    pub source_sequence: Option<u64>,
}

impl Observation {
    pub const UNAVAILABLE: Self = Self {
        freshness: ObservationFreshness::Unavailable,
        source_id: None,
        source_epoch: None,
        source_sequence: None,
    };
}

/// Last retained process fact. A disconnected observer does not erase it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessState {
    Unknown,
    Starting,
    Alive,
    Exited { code: Option<i32> },
}

/// One incoming source observation, before epoch/sequence/freshness checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessObservation {
    Unknown,
    Alive,
    Exited { code: Option<i32> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResultState {
    Unreported,
    Reported { report_id: ReportId },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RunOutcome {
    Finished,
    Failed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DeliveryStage {
    Persisted,
    Blocked,
    Dispatching,
    HostAccepted,
    ProviderQueued,
    ProviderInserted,
    ReplyObserved,
    Acknowledged,
    Cancelled,
    Rejected,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceKind {
    StructuredProvider,
    Pty,
    Auxiliary,
}
