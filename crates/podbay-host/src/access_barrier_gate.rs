//! Inert v1 recovery calculus. Inputs are assertions, not OS attestations.
//! No decision performs I/O, releases an issuer or constructs authority.
#![allow(dead_code)]

const VERSION: u8 = 1;

mod codec;

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SubjectV1 {
    version: u8,
    canonical_name: String,
    staging_name: String,
    migration_key: String,
    activation_key: String,
    request_digest: [u8; 32],
    lineage: String,
    manager_lock: FileIdentity,
    source: FileIdentity,
    staging: FileIdentity,
    previous_boot: String,
    current_boot: String,
    policy_digest: [u8; 32],
    artifact_digest: [u8; 32],
    generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    Forward,
    Rollback,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Intent,
    Converted,
    Published,
    Activated,
    RolledBack,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Activation {
    Absent,
    Present,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct DurableV1 {
    subject: SubjectV1,
    direction: Direction,
    phase: Phase,
    activation: Activation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Orientation {
    AbsentStage,
    PartialStage,
    CopiedV24,
    ConvertedV25,
    Published,
    RolledBack,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Journal {
    Clean,
    Hot,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Barrier {
    Closed,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Issuers {
    NeverStarted,
    LateEngagement,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct ObservationV1 {
    subject: SubjectV1,
    orientation: Orientation,
    journal: Journal,
    barrier: Barrier,
    issuers: Issuers,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestKind {
    ResumeForward,
    RequestRollback,
    ResumeRollback,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct RequestV1 {
    subject: SubjectV1,
    kind: RequestKind,
}

/// Planning data only. In particular there is no Open, Admit or Release variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DecisionV1 {
    RebuildSameStage { next_generation: u64 },
    VerifyCopiedStage,
    VerifyConvertedStage,
    CompletePublication,
    InspectHotJournal,
    PersistRollbackDirection { next_generation: u64 },
    CompleteRollback,
    AlreadyRolledBack,
    ForwardRepairOnly,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    Malformed,
    ForeignSubject,
    UnknownEvidence,
    LateEngagement,
    AmbiguousOrientation,
    DirectionConflict,
    RollbackAfterActivation,
    GenerationExhausted,
}

fn valid_subject(s: &SubjectV1) -> bool {
    let literal =
        |v: &str| !v.is_empty() && v.len() <= 256 && !v.bytes().any(|b| b.is_ascii_control());
    let basename = |v: &str| literal(v) && v != "." && v != ".." && !v.contains(['/', '\\']);
    s.version == VERSION
        && s.generation > 0
        && basename(&s.canonical_name)
        && basename(&s.staging_name)
        && s.canonical_name != s.staging_name
        && literal(&s.migration_key)
        && literal(&s.activation_key)
        && s.migration_key != s.activation_key
        && literal(&s.lineage)
        && literal(&s.previous_boot)
        && literal(&s.current_boot)
        && s.previous_boot != s.current_boot
        && s.source.inode != 0
        && s.staging.inode != 0
        && s.manager_lock.inode != 0
        && s.source.device == s.staging.device
        && s.source.device == s.manager_lock.device
        && s.source != s.staging
        && s.source != s.manager_lock
        && s.staging != s.manager_lock
        && s.policy_digest != [0; 32]
        && s.request_digest != [0; 32]
        && s.artifact_digest != [0; 32]
}

fn decide(
    expected: &SubjectV1,
    durable: &DurableV1,
    observed: &ObservationV1,
    request: &RequestV1,
) -> Result<DecisionV1, Refusal> {
    if !valid_subject(expected)
        || !valid_subject(&durable.subject)
        || !valid_subject(&observed.subject)
        || !valid_subject(&request.subject)
    {
        return Err(Refusal::Malformed);
    }
    if &durable.subject != expected || &observed.subject != expected || &request.subject != expected
    {
        return Err(Refusal::ForeignSubject);
    }
    if observed.issuers == Issuers::LateEngagement {
        return Err(Refusal::LateEngagement);
    }
    if observed.barrier != Barrier::Closed
        || observed.issuers == Issuers::Unknown
        || observed.journal == Journal::Unknown
        || durable.activation == Activation::Unknown
    {
        return Err(Refusal::UnknownEvidence);
    }
    if observed.orientation == Orientation::Unknown {
        return Err(Refusal::AmbiguousOrientation);
    }
    let activated = durable.activation == Activation::Present;
    if (durable.phase == Phase::Activated) != activated
        || (activated && durable.direction == Direction::Rollback)
        || (durable.phase == Phase::RolledBack && durable.direction != Direction::Rollback)
    {
        return Err(Refusal::Malformed);
    }
    // Exchange-back may be durable before its terminal receipt. The persisted
    // rollback direction permits finalization of that verified orientation.
    let orientation_matches = (durable.direction == Direction::Rollback
        && observed.orientation == Orientation::RolledBack)
        || match durable.phase {
            Phase::Intent => observed.orientation != Orientation::RolledBack,
            Phase::Converted => matches!(
                observed.orientation,
                Orientation::ConvertedV25 | Orientation::Published
            ),
            Phase::Published | Phase::Activated => observed.orientation == Orientation::Published,
            Phase::RolledBack => observed.orientation == Orientation::RolledBack,
        };
    if !orientation_matches {
        return Err(Refusal::AmbiguousOrientation);
    }
    if activated {
        return if request.kind == RequestKind::ResumeForward {
            Ok(DecisionV1::ForwardRepairOnly)
        } else {
            Err(Refusal::RollbackAfterActivation)
        };
    }
    if durable.direction == Direction::Rollback && request.kind == RequestKind::ResumeForward {
        return Err(Refusal::DirectionConflict);
    }
    if durable.direction == Direction::Forward && request.kind == RequestKind::ResumeRollback {
        return Err(Refusal::DirectionConflict);
    }
    // A hot journal is never interpreted as a validated snapshot or permission
    // to exchange. A separate adapter must resolve it and supply new evidence.
    if observed.journal == Journal::Hot {
        return Ok(DecisionV1::InspectHotJournal);
    }
    if durable.direction == Direction::Rollback {
        return Ok(if durable.phase == Phase::RolledBack {
            DecisionV1::AlreadyRolledBack
        } else {
            DecisionV1::CompleteRollback
        });
    }
    let next = || {
        expected
            .generation
            .checked_add(1)
            .ok_or(Refusal::GenerationExhausted)
    };
    if request.kind == RequestKind::RequestRollback {
        return Ok(DecisionV1::PersistRollbackDirection {
            next_generation: next()?,
        });
    }
    Ok(match observed.orientation {
        Orientation::AbsentStage | Orientation::PartialStage => DecisionV1::RebuildSameStage {
            next_generation: next()?,
        },
        Orientation::CopiedV24 => DecisionV1::VerifyCopiedStage,
        Orientation::ConvertedV25 => DecisionV1::VerifyConvertedStage,
        Orientation::Published => DecisionV1::CompletePublication,
        Orientation::RolledBack | Orientation::Unknown => {
            return Err(Refusal::AmbiguousOrientation);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn fixture() -> (SubjectV1, DurableV1, ObservationV1, RequestV1) {
        let s = SubjectV1 {
            version: VERSION,
            canonical_name: "db.sqlite".into(),
            staging_name: "stage.sqlite".into(),
            migration_key: "migration.1".into(),
            activation_key: "activation.1".into(),
            request_digest: [4; 32],
            lineage: "lineage.1".into(),
            manager_lock: FileIdentity {
                device: 1,
                inode: 3,
            },
            source: FileIdentity {
                device: 1,
                inode: 1,
            },
            staging: FileIdentity {
                device: 1,
                inode: 2,
            },
            previous_boot: "boot.old".into(),
            current_boot: "boot.new".into(),
            policy_digest: [1; 32],
            artifact_digest: [2; 32],
            generation: 1,
        };
        (
            s.clone(),
            DurableV1 {
                subject: s.clone(),
                direction: Direction::Forward,
                phase: Phase::Intent,
                activation: Activation::Absent,
            },
            ObservationV1 {
                subject: s.clone(),
                orientation: Orientation::AbsentStage,
                journal: Journal::Clean,
                barrier: Barrier::Closed,
                issuers: Issuers::NeverStarted,
            },
            RequestV1 {
                subject: s,
                kind: RequestKind::ResumeForward,
            },
        )
    }
    #[test]
    fn exhaustive_states_never_invent_rollback_or_release() {
        let (s, mut d, mut o, mut r) = fixture();
        let mut count = 0;
        for direction in [Direction::Forward, Direction::Rollback] {
            for phase in [
                Phase::Intent,
                Phase::Converted,
                Phase::Published,
                Phase::Activated,
                Phase::RolledBack,
            ] {
                for activation in [Activation::Absent, Activation::Present, Activation::Unknown] {
                    for orientation in [
                        Orientation::AbsentStage,
                        Orientation::PartialStage,
                        Orientation::CopiedV24,
                        Orientation::ConvertedV25,
                        Orientation::Published,
                        Orientation::RolledBack,
                        Orientation::Unknown,
                    ] {
                        for journal in [Journal::Clean, Journal::Hot, Journal::Unknown] {
                            for barrier in [Barrier::Closed, Barrier::Unknown] {
                                for issuers in [
                                    Issuers::NeverStarted,
                                    Issuers::LateEngagement,
                                    Issuers::Unknown,
                                ] {
                                    for kind in [
                                        RequestKind::ResumeForward,
                                        RequestKind::RequestRollback,
                                        RequestKind::ResumeRollback,
                                    ] {
                                        d.direction = direction;
                                        d.phase = phase;
                                        d.activation = activation;
                                        o.orientation = orientation;
                                        o.journal = journal;
                                        o.barrier = barrier;
                                        o.issuers = issuers;
                                        r.kind = kind;
                                        let result = decide(&s, &d, &o, &r);
                                        count += 1;
                                        if issuers == Issuers::LateEngagement {
                                            assert_eq!(result, Err(Refusal::LateEngagement));
                                        }
                                        if let Ok(decision) = result {
                                            assert_eq!(barrier, Barrier::Closed);
                                            assert_eq!(issuers, Issuers::NeverStarted);
                                            assert_ne!(activation, Activation::Unknown);
                                            assert_ne!(journal, Journal::Unknown);
                                            assert_ne!(orientation, Orientation::Unknown);
                                            match decision {
                                                DecisionV1::CompleteRollback
                                                | DecisionV1::AlreadyRolledBack => {
                                                    assert_eq!(direction, Direction::Rollback);
                                                    assert_eq!(activation, Activation::Absent);
                                                }
                                                DecisionV1::PersistRollbackDirection { .. } => {
                                                    assert_eq!(kind, RequestKind::RequestRollback);
                                                    assert_eq!(activation, Activation::Absent);
                                                }
                                                DecisionV1::ForwardRepairOnly => {
                                                    assert_eq!(activation, Activation::Present);
                                                    assert_eq!(kind, RequestKind::ResumeForward);
                                                }
                                                DecisionV1::RebuildSameStage { .. }
                                                | DecisionV1::VerifyCopiedStage
                                                | DecisionV1::VerifyConvertedStage
                                                | DecisionV1::CompletePublication => {
                                                    assert_eq!(direction, Direction::Forward);
                                                    assert_eq!(activation, Activation::Absent);
                                                    assert_eq!(kind, RequestKind::ResumeForward);
                                                }
                                                DecisionV1::InspectHotJournal => {
                                                    assert_eq!(journal, Journal::Hot)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(count, 11340);
    }
    #[test]
    fn foreign_and_malformed_subjects_refuse() {
        let (s, d, o, r) = fixture();
        for field in 0..14 {
            let mut foreign = s.clone();
            match field {
                0 => foreign.canonical_name = "other.sqlite".into(),
                1 => foreign.staging_name = "other-stage.sqlite".into(),
                2 => foreign.migration_key = "other-key".into(),
                3 => foreign.activation_key = "other-activation".into(),
                4 => foreign.lineage = "other-lineage".into(),
                5 => foreign.manager_lock.inode = 4,
                6 => foreign.source.inode = 4,
                7 => foreign.staging.inode = 4,
                8 => foreign.previous_boot = "other-old".into(),
                9 => foreign.current_boot = "other-new".into(),
                10 => foreign.policy_digest = [3; 32],
                11 => foreign.artifact_digest = [3; 32],
                12 => foreign.generation = 2,
                _ => foreign.request_digest = [5; 32],
            }
            let mut dd = d.clone();
            dd.subject = foreign.clone();
            assert_eq!(decide(&s, &dd, &o, &r), Err(Refusal::ForeignSubject));
            let mut oo = o.clone();
            oo.subject = foreign.clone();
            assert_eq!(decide(&s, &d, &oo, &r), Err(Refusal::ForeignSubject));
            let mut rr = r.clone();
            rr.subject = foreign;
            assert_eq!(decide(&s, &d, &o, &rr), Err(Refusal::ForeignSubject));
        }
        for field in 0..6 {
            let mut bad = s.clone();
            match field {
                0 => bad.version = 2,
                1 => bad.generation = 0,
                2 => bad.current_boot = bad.previous_boot.clone(),
                3 => bad.staging_name = "../foreign".into(),
                4 => bad.manager_lock = bad.source.clone(),
                _ => bad.policy_digest = [0; 32],
            };
            assert_eq!(decide(&bad, &d, &o, &r), Err(Refusal::Malformed));
        }
    }
    #[test]
    fn sequence_direction_and_activation_are_monotonic() {
        let (s, mut d, mut o, mut r) = fixture();
        r.kind = RequestKind::ResumeRollback;
        assert_eq!(decide(&s, &d, &o, &r), Err(Refusal::DirectionConflict));
        r.kind = RequestKind::RequestRollback;
        assert_eq!(
            decide(&s, &d, &o, &r),
            Ok(DecisionV1::PersistRollbackDirection { next_generation: 2 })
        );
        // Merely returning a plan did not mutate durable direction.
        assert_eq!(d.direction, Direction::Forward);
        d.direction = Direction::Rollback;
        r.kind = RequestKind::ResumeRollback;
        assert_eq!(decide(&s, &d, &o, &r), Ok(DecisionV1::CompleteRollback));
        r.kind = RequestKind::ResumeForward;
        assert_eq!(decide(&s, &d, &o, &r), Err(Refusal::DirectionConflict));
        d.direction = Direction::Forward;
        d.phase = Phase::Activated;
        d.activation = Activation::Present;
        o.orientation = Orientation::Published;
        assert_eq!(decide(&s, &d, &o, &r), Ok(DecisionV1::ForwardRepairOnly));
        r.kind = RequestKind::RequestRollback;
        assert_eq!(
            decide(&s, &d, &o, &r),
            Err(Refusal::RollbackAfterActivation)
        );
        o.issuers = Issuers::LateEngagement;
        assert_eq!(decide(&s, &d, &o, &r), Err(Refusal::LateEngagement));
    }

    #[test]
    fn rollback_exchange_crash_before_terminal_receipt_can_finalize() {
        let (s, mut d, mut o, mut r) = fixture();
        d.direction = Direction::Rollback;
        d.phase = Phase::Published;
        o.orientation = Orientation::RolledBack;
        r.kind = RequestKind::ResumeRollback;
        assert_eq!(decide(&s, &d, &o, &r), Ok(DecisionV1::CompleteRollback));
        r.kind = RequestKind::ResumeForward;
        assert_eq!(decide(&s, &d, &o, &r), Err(Refusal::DirectionConflict));
        r.kind = RequestKind::ResumeRollback;
        o.orientation = Orientation::Unknown;
        assert_eq!(decide(&s, &d, &o, &r), Err(Refusal::AmbiguousOrientation));
        o.orientation = Orientation::RolledBack;
        o.subject.request_digest = [9; 32];
        assert_eq!(decide(&s, &d, &o, &r), Err(Refusal::ForeignSubject));
    }
    #[test]
    fn generations_cannot_wrap_and_hot_journal_never_authorizes_exchange() {
        let (mut s, mut d, mut o, mut r) = fixture();
        s.generation = u64::MAX;
        d.subject = s.clone();
        o.subject = s.clone();
        r.subject = s.clone();
        assert_eq!(decide(&s, &d, &o, &r), Err(Refusal::GenerationExhausted));
        r.kind = RequestKind::RequestRollback;
        assert_eq!(decide(&s, &d, &o, &r), Err(Refusal::GenerationExhausted));
        o.journal = Journal::Hot;
        assert_eq!(decide(&s, &d, &o, &r), Ok(DecisionV1::InspectHotJournal));
    }
}
