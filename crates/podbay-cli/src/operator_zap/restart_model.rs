//! Pure candidate ledger semantics. Verified inputs below are explicit model
//! premises, not signature verification or application readiness evidence.
#![allow(dead_code)]

const VERSION: u8 = 1;

// Disposable persistence of modeled allocation only; no operator CLI hook.
#[cfg(all(test, target_os = "linux"))]
#[path = "restart_model/disposable_files.rs"]
mod disposable_files;

#[derive(Clone, Debug, PartialEq, Eq)]
struct PinsV1 {
    pod_artifact: [u8; 32],
    node_artifact: [u8; 32],
    zap_artifact: [u8; 32],
    configuration: [u8; 32],
    database: [u8; 32],
    profile: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct IdentitiesV1([String; 8]); // actor, scope, Pod, session, Run, attempt, resource, command
#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedTerminalV1 {
    version: u8,
    owner: String,
    digest: [u8; 32],
    generation: u64,
    identities: IdentitiesV1,
    pins: PinsV1,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum TerminalInput {
    ModelVerified(VerifiedTerminalV1),
    UnsignedOrUnknown,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct RequestV1 {
    version: u8,
    owner: String,
    key: String,
    terminal_digest: [u8; 32],
    pins: PinsV1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PriorEffect {
    Settled,
    Uncertain,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PriorChild {
    Gone,
    Live,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AllocationV1 {
    version: u8,
    request: RequestV1,
    predecessor: VerifiedTerminalV1,
    generation: u64,
    directory_slot: String,
    identities: IdentitiesV1,
    stage: StageV1,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum StageV1 {
    Allocated,
    Prepared,
    Claimed,
    LaunchUncertain,
    HostAccepted {
        receipt: [u8; 32],
        child_birth: u64,
    },
    Ready {
        receipt: [u8; 32],
        child_birth: u64,
        readiness_digest: [u8; 32],
    },
    ChildExited {
        accepted: Option<[u8; 32]>,
    },
    ConfigConflict {
        accepted: Option<[u8; 32]>,
    },
    ReadinessTimeout {
        accepted: [u8; 32],
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct LedgerV1 {
    version: u8,
    owner: String,
    generation: u64,
    allocations: Vec<AllocationV1>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum OutcomeV1 {
    Allocated(AllocationV1),
    ExactReplay(AllocationV1),
    NonReady(AllocationV1),
    Ready(AllocationV1),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    Malformed,
    UnverifiedTerminal,
    Foreign,
    KeyConflict,
    PredecessorConflict,
    PriorUncertain,
    PriorLive,
    Overflow,
    IdentityCollision,
    StageConflict,
    UnverifiedReadiness,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct ModelReadinessV1 {
    generation: u64,
    identities: IdentitiesV1,
    pins: PinsV1,
    launch_receipt: [u8; 32],
    child_birth: u64,
    nonce: [u8; 32],
    expected_nonce: [u8; 32],
    digest: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum EventV1 {
    Prepared,
    Claimed,
    LaunchUncertain,
    HostAccepted { receipt: [u8; 32], child_birth: u64 },
    ModelVerifiedReady(ModelReadinessV1),
    UnverifiedReady,
    ChildExited,
    ConfigConflict,
    ReadinessTimeout,
}

fn literal(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}
fn pins_valid(p: &PinsV1) -> bool {
    literal(&p.profile)
        && [
            p.pod_artifact,
            p.node_artifact,
            p.zap_artifact,
            p.configuration,
            p.database,
        ]
        .iter()
        .all(|d| *d != [0; 32])
}
fn ids_valid(ids: &IdentitiesV1) -> bool {
    ids.0.iter().all(|s| literal(s))
        && ids
            .0
            .iter()
            .enumerate()
            .all(|(i, s)| !ids.0[..i].contains(s))
}
fn disjoint(a: &IdentitiesV1, b: &IdentitiesV1) -> bool {
    a.0.iter().all(|id| !b.0.contains(id))
}
fn valid_stage(stage: &StageV1) -> bool {
    match stage {
        StageV1::HostAccepted {
            receipt,
            child_birth,
        } => *receipt != [0; 32] && *child_birth > 0,
        StageV1::Ready {
            receipt,
            child_birth,
            readiness_digest,
        } => *receipt != [0; 32] && *child_birth > 0 && *readiness_digest != [0; 32],
        StageV1::ChildExited { accepted } | StageV1::ConfigConflict { accepted } => {
            accepted.is_none_or(|receipt| receipt != [0; 32])
        }
        StageV1::ReadinessTimeout { accepted } => *accepted != [0; 32],
        _ => true,
    }
}
fn validate_ledger(l: &LedgerV1) -> Result<(), Refusal> {
    if l.version != VERSION || !literal(&l.owner) || l.allocations.len() as u64 != l.generation {
        return Err(Refusal::Malformed);
    }
    for (i, a) in l.allocations.iter().enumerate() {
        if a.version != VERSION
            || a.generation != i as u64 + 1
            || a.request.owner != l.owner
            || a.predecessor.owner != l.owner
            || a.request.version != VERSION
            || a.predecessor.version != VERSION
            || a.predecessor.generation != i as u64
            || !valid_stage(&a.stage)
            || !literal(&a.request.key)
            || !pins_valid(&a.request.pins)
            || a.request.pins != a.predecessor.pins
            || a.request.terminal_digest != a.predecessor.digest
            || a.predecessor.digest == [0; 32]
            || !ids_valid(&a.identities)
            || !ids_valid(&a.predecessor.identities)
            || !disjoint(&a.identities, &a.predecessor.identities)
            || a.directory_slot != format!("generation-{:020}", a.generation)
        {
            return Err(Refusal::Malformed);
        }
        if i > 0
            && (a.predecessor.identities != l.allocations[i - 1].identities
                || a.predecessor.pins != l.allocations[i - 1].request.pins)
        {
            return Err(Refusal::Malformed);
        }
        for prior in &l.allocations[..i] {
            if prior.request.key == a.request.key
                || prior.predecessor.digest == a.predecessor.digest
                || !disjoint(&prior.identities, &a.identities)
                || !disjoint(&prior.predecessor.identities, &a.identities)
            {
                return Err(Refusal::Malformed);
            }
        }
    }
    Ok(())
}

fn allocate(
    l: &LedgerV1,
    request: &RequestV1,
    terminal: &TerminalInput,
    effect: PriorEffect,
    child: PriorChild,
) -> Result<(LedgerV1, OutcomeV1), Refusal> {
    // Distinguish checked arithmetic exhaustion from a malformed finite ledger.
    if l.generation == u64::MAX {
        return Err(Refusal::Overflow);
    }
    validate_ledger(l)?;
    let TerminalInput::ModelVerified(t) = terminal else {
        return Err(Refusal::UnverifiedTerminal);
    };
    if request.version != VERSION
        || t.version != VERSION
        || !literal(&request.key)
        || !pins_valid(&request.pins)
        || !ids_valid(&t.identities)
        || t.digest == [0; 32]
    {
        return Err(Refusal::Malformed);
    }
    if request.owner != l.owner || t.owner != l.owner {
        return Err(Refusal::Foreign);
    }
    if let Some(a) = l.allocations.iter().find(|a| a.request.key == request.key) {
        return if a.request == *request && a.predecessor == *t {
            Ok((l.clone(), OutcomeV1::ExactReplay(a.clone())))
        } else {
            Err(Refusal::KeyConflict)
        };
    }
    if request.terminal_digest != t.digest || request.pins != t.pins {
        return Err(Refusal::Foreign);
    }
    if l.allocations
        .iter()
        .any(|a| a.predecessor.digest == t.digest)
    {
        return Err(Refusal::PredecessorConflict);
    }
    if effect != PriorEffect::Settled {
        return Err(Refusal::PriorUncertain);
    }
    if child != PriorChild::Gone {
        return Err(Refusal::PriorLive);
    }
    if t.generation != l.generation {
        return Err(Refusal::Foreign);
    }
    if let Some(prior) = l.allocations.last() {
        if prior.identities != t.identities || prior.request.pins != t.pins {
            return Err(Refusal::Foreign);
        }
    }
    let generation = l.generation.checked_add(1).ok_or(Refusal::Overflow)?;
    let identities = IdentitiesV1(std::array::from_fn(|slot| {
        format!("restart.{}.{}.{}", l.owner, generation, slot)
    }));
    if !ids_valid(&identities)
        || !disjoint(&identities, &t.identities)
        || l.allocations.iter().any(|a| {
            !disjoint(&identities, &a.identities)
                || !disjoint(&identities, &a.predecessor.identities)
        })
    {
        return Err(Refusal::IdentityCollision);
    }
    let a = AllocationV1 {
        version: VERSION,
        request: request.clone(),
        predecessor: t.clone(),
        generation,
        directory_slot: format!("generation-{generation:020}"),
        identities,
        stage: StageV1::Allocated,
    };
    let mut updated = l.clone();
    updated.generation = generation;
    updated.allocations.push(a.clone());
    validate_ledger(&updated)?;
    Ok((updated, OutcomeV1::Allocated(a)))
}

fn accepted(stage: &StageV1) -> Option<([u8; 32], u64)> {
    match stage {
        StageV1::HostAccepted {
            receipt,
            child_birth,
        }
        | StageV1::Ready {
            receipt,
            child_birth,
            ..
        } => Some((*receipt, *child_birth)),
        _ => None,
    }
}
fn transition(
    l: &LedgerV1,
    generation: u64,
    request: &RequestV1,
    event: &EventV1,
) -> Result<(LedgerV1, OutcomeV1), Refusal> {
    validate_ledger(l)?;
    let index = l
        .allocations
        .iter()
        .position(|a| a.generation == generation)
        .ok_or(Refusal::Foreign)?;
    let a = &l.allocations[index];
    if a.request != *request {
        return Err(Refusal::Foreign);
    }
    // A later verified terminal/allocation supersedes callbacks for an old generation.
    if generation != l.generation {
        return Err(Refusal::StageConflict);
    }
    let stage = match (&a.stage, event) {
        (StageV1::Allocated, EventV1::Prepared) | (StageV1::Prepared, EventV1::Prepared) => {
            StageV1::Prepared
        }
        (StageV1::Prepared, EventV1::Claimed) | (StageV1::Claimed, EventV1::Claimed) => {
            StageV1::Claimed
        }
        (StageV1::Claimed, EventV1::LaunchUncertain)
        | (StageV1::LaunchUncertain, EventV1::LaunchUncertain) => StageV1::LaunchUncertain,
        (
            StageV1::Claimed | StageV1::LaunchUncertain,
            EventV1::HostAccepted {
                receipt,
                child_birth,
            },
        ) if *receipt != [0; 32] && *child_birth > 0 => StageV1::HostAccepted {
            receipt: *receipt,
            child_birth: *child_birth,
        },
        (
            StageV1::HostAccepted {
                receipt,
                child_birth,
            },
            EventV1::HostAccepted {
                receipt: r,
                child_birth: b,
            },
        ) if receipt == r && child_birth == b => a.stage.clone(),
        (_, EventV1::UnverifiedReady) => return Err(Refusal::UnverifiedReadiness),
        (
            StageV1::HostAccepted {
                receipt,
                child_birth,
            }
            | StageV1::Ready {
                receipt,
                child_birth,
                ..
            },
            EventV1::ModelVerifiedReady(r),
        ) => {
            if r.generation != a.generation
                || r.identities != a.identities
                || r.pins != a.request.pins
                || r.launch_receipt != *receipt
                || r.child_birth != *child_birth
                || r.nonce == [0; 32]
                || r.nonce != r.expected_nonce
                || r.digest == [0; 32]
            {
                return Err(Refusal::UnverifiedReadiness);
            }
            if matches!(&a.stage,StageV1::Ready{readiness_digest,..} if *readiness_digest!=r.digest)
            {
                return Err(Refusal::StageConflict);
            }
            StageV1::Ready {
                receipt: *receipt,
                child_birth: *child_birth,
                readiness_digest: r.digest,
            }
        }
        (StageV1::Allocated | StageV1::Prepared, EventV1::ConfigConflict) => {
            StageV1::ConfigConflict { accepted: None }
        }
        (StageV1::HostAccepted { receipt, .. }, EventV1::ConfigConflict) => {
            StageV1::ConfigConflict {
                accepted: Some(*receipt),
            }
        }
        (StageV1::HostAccepted { receipt, .. }, EventV1::ChildExited) => StageV1::ChildExited {
            accepted: Some(*receipt),
        },
        (StageV1::HostAccepted { receipt, .. }, EventV1::ReadinessTimeout) => {
            StageV1::ReadinessTimeout { accepted: *receipt }
        }
        (StageV1::ChildExited { .. }, EventV1::ChildExited)
        | (StageV1::ConfigConflict { .. }, EventV1::ConfigConflict)
        | (StageV1::ReadinessTimeout { .. }, EventV1::ReadinessTimeout) => a.stage.clone(),
        _ => return Err(Refusal::StageConflict),
    };
    let mut updated = l.clone();
    updated.allocations[index].stage = stage;
    let result = updated.allocations[index].clone();
    let outcome = if matches!(result.stage, StageV1::Ready { .. }) {
        OutcomeV1::Ready(result)
    } else {
        OutcomeV1::NonReady(result)
    };
    Ok((updated, outcome))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (LedgerV1, RequestV1, TerminalInput) {
        let pins = PinsV1 {
            pod_artifact: [1; 32],
            node_artifact: [2; 32],
            zap_artifact: [3; 32],
            configuration: [4; 32],
            database: [5; 32],
            profile: "profile.one".into(),
        };
        let t = VerifiedTerminalV1 {
            version: 1,
            owner: "owner".into(),
            digest: [6; 32],
            generation: 0,
            identities: IdentitiesV1(std::array::from_fn(|i| format!("old.{i}"))),
            pins: pins.clone(),
        };
        (
            LedgerV1 {
                version: 1,
                owner: "owner".into(),
                generation: 0,
                allocations: vec![],
            },
            RequestV1 {
                version: 1,
                owner: "owner".into(),
                key: "restart.one".into(),
                terminal_digest: t.digest,
                pins,
            },
            TerminalInput::ModelVerified(t),
        )
    }
    #[test]
    fn allocation_is_once_and_exact_after_lost_response() {
        let (l, r, t) = fixture();
        let (a, out) = allocate(&l, &r, &t, PriorEffect::Settled, PriorChild::Gone).unwrap();
        assert!(matches!(out, OutcomeV1::Allocated(_)));
        validate_ledger(&a).unwrap();
        let (same, replay) = allocate(&a, &r, &t, PriorEffect::Unknown, PriorChild::Live).unwrap();
        assert_eq!(same, a);
        assert!(matches!(replay, OutcomeV1::ExactReplay(_)));
        let mut changed = r.clone();
        changed.pins.configuration = [9; 32];
        assert!(allocate(&a, &changed, &t, PriorEffect::Settled, PriorChild::Gone).is_err());
        changed = r.clone();
        changed.key = "alternate".into();
        assert_eq!(
            allocate(&a, &changed, &t, PriorEffect::Settled, PriorChild::Gone),
            Err(Refusal::PredecessorConflict)
        );
        assert!(disjoint(
            &a.allocations[0].identities,
            &a.allocations[0].predecessor.identities
        ));
    }
    #[test]
    fn second_generation_cannot_reuse_an_earlier_predecessor_identity() {
        let (initial, first_request, terminal) = fixture();
        let TerminalInput::ModelVerified(mut first_terminal) = terminal else {
            panic!("fixture terminal must be modeled verified");
        };
        first_terminal.identities.0[0] = "restart.owner.2.0".into();
        let (first, _) = allocate(
            &initial,
            &first_request,
            &TerminalInput::ModelVerified(first_terminal),
            PriorEffect::Settled,
            PriorChild::Gone,
        )
        .unwrap();
        validate_ledger(&first).unwrap();
        let mut second_request = first_request.clone();
        second_request.key = "restart.two".into();
        second_request.terminal_digest = [7; 32];
        let second_terminal = TerminalInput::ModelVerified(VerifiedTerminalV1 {
            version: VERSION,
            owner: first.owner.clone(),
            digest: [7; 32],
            generation: first.generation,
            identities: first.allocations[0].identities.clone(),
            pins: first_request.pins,
        });
        assert_eq!(
            allocate(
                &first,
                &second_request,
                &second_terminal,
                PriorEffect::Settled,
                PriorChild::Gone,
            ),
            Err(Refusal::IdentityCollision)
        );
    }
    #[test]
    fn unknown_foreign_live_and_overflow_never_allocate() {
        let (l, r, t) = fixture();
        for effect in [
            PriorEffect::Settled,
            PriorEffect::Uncertain,
            PriorEffect::Unknown,
        ] {
            for child in [PriorChild::Gone, PriorChild::Live, PriorChild::Unknown] {
                let result = allocate(&l, &r, &t, effect, child);
                assert_eq!(
                    result.is_ok(),
                    effect == PriorEffect::Settled && child == PriorChild::Gone
                );
            }
        }
        assert_eq!(
            allocate(
                &l,
                &r,
                &TerminalInput::UnsignedOrUnknown,
                PriorEffect::Settled,
                PriorChild::Gone
            ),
            Err(Refusal::UnverifiedTerminal)
        );
        let mut foreign = r.clone();
        foreign.owner = "foreign".into();
        assert_eq!(
            allocate(&l, &foreign, &t, PriorEffect::Settled, PriorChild::Gone),
            Err(Refusal::Foreign)
        );
        let mut max = l;
        max.generation = u64::MAX;
        assert_eq!(
            allocate(&max, &r, &t, PriorEffect::Settled, PriorChild::Gone),
            Err(Refusal::Overflow)
        );
    }
    #[test]
    fn crash_trace_cannot_launch_twice_or_invent_readiness() {
        let (l, r, t) = fixture();
        let (mut l, _) = allocate(&l, &r, &t, PriorEffect::Settled, PriorChild::Gone).unwrap();
        for event in [
            EventV1::Prepared,
            EventV1::Claimed,
            EventV1::LaunchUncertain,
            EventV1::HostAccepted {
                receipt: [7; 32],
                child_birth: 42,
            },
        ] {
            let (next, _) = transition(&l, 1, &r, &event).unwrap();
            let (retry, _) = transition(&next, 1, &r, &event).unwrap();
            assert_eq!(retry, next);
            let (replayed, _) =
                allocate(&next, &r, &t, PriorEffect::Unknown, PriorChild::Unknown).unwrap();
            assert_eq!(replayed, next);
            l = next;
        }
        assert_eq!(
            transition(&l, 1, &r, &EventV1::Prepared),
            Err(Refusal::StageConflict)
        );
        assert_eq!(
            transition(&l, 1, &r, &EventV1::UnverifiedReady),
            Err(Refusal::UnverifiedReadiness)
        );
        let ready = ModelReadinessV1 {
            generation: 1,
            identities: l.allocations[0].identities.clone(),
            pins: r.pins.clone(),
            launch_receipt: [7; 32],
            child_birth: 42,
            nonce: [8; 32],
            expected_nonce: [8; 32],
            digest: [9; 32],
        };
        let (done, out) =
            transition(&l, 1, &r, &EventV1::ModelVerifiedReady(ready.clone())).unwrap();
        assert!(matches!(out, OutcomeV1::Ready(_)));
        assert_eq!(
            transition(&done, 1, &r, &EventV1::ModelVerifiedReady(ready.clone()))
                .unwrap()
                .0,
            done
        );
        for field in 0..6 {
            let mut bad = ready.clone();
            match field {
                0 => bad.generation = 2,
                1 => bad.child_birth = 43,
                2 => bad.nonce = [1; 32],
                3 => bad.pins.database = [1; 32],
                4 => bad.identities.0[0] = "foreign".into(),
                _ => bad.launch_receipt = [1; 32],
            };
            assert_eq!(
                transition(&l, 1, &r, &EventV1::ModelVerifiedReady(bad)),
                Err(Refusal::UnverifiedReadiness)
            );
        }
    }
    #[test]
    fn typed_failed_generation_keeps_accepted_identity() {
        let (l, r, t) = fixture();
        let (l, _) = allocate(&l, &r, &t, PriorEffect::Settled, PriorChild::Gone).unwrap();
        let (l, _) = transition(&l, 1, &r, &EventV1::Prepared).unwrap();
        let (l, _) = transition(&l, 1, &r, &EventV1::Claimed).unwrap();
        let (l, _) = transition(
            &l,
            1,
            &r,
            &EventV1::HostAccepted {
                receipt: [7; 32],
                child_birth: 42,
            },
        )
        .unwrap();
        for e in [
            EventV1::ChildExited,
            EventV1::ConfigConflict,
            EventV1::ReadinessTimeout,
        ] {
            let (failed, out) = transition(&l, 1, &r, &e).unwrap();
            assert!(matches!(out, OutcomeV1::NonReady(_)));
            assert_eq!(
                failed.allocations[0].identities,
                l.allocations[0].identities
            );
            assert!(transition(&failed, 1, &r, &EventV1::Prepared).is_err());
            assert_eq!(
                allocate(&failed, &r, &t, PriorEffect::Unknown, PriorChild::Live)
                    .unwrap()
                    .0,
                failed
            );
        }
    }

    #[test]
    fn successor_requires_new_exact_terminal_and_blocks_old_callbacks() {
        let (l, r, t) = fixture();
        let (first, _) = allocate(&l, &r, &t, PriorEffect::Settled, PriorChild::Gone).unwrap();
        let terminal = VerifiedTerminalV1 {
            version: VERSION,
            owner: r.owner.clone(),
            digest: [10; 32],
            generation: 1,
            identities: first.allocations[0].identities.clone(),
            pins: r.pins.clone(),
        };
        let mut second_request = r.clone();
        second_request.key = "restart.two".into();
        second_request.terminal_digest = terminal.digest;
        let input = TerminalInput::ModelVerified(terminal);
        assert_eq!(
            allocate(
                &first,
                &second_request,
                &input,
                PriorEffect::Unknown,
                PriorChild::Gone
            ),
            Err(Refusal::PriorUncertain)
        );
        assert_eq!(
            allocate(
                &first,
                &second_request,
                &input,
                PriorEffect::Settled,
                PriorChild::Live
            ),
            Err(Refusal::PriorLive)
        );
        let (second, _) = allocate(
            &first,
            &second_request,
            &input,
            PriorEffect::Settled,
            PriorChild::Gone,
        )
        .unwrap();
        assert_eq!(second.generation, 2);
        assert!(disjoint(
            &second.allocations[0].identities,
            &second.allocations[1].identities
        ));
        assert_eq!(
            transition(&second, 1, &r, &EventV1::Prepared),
            Err(Refusal::StageConflict)
        );
        let mut corrupt = second.clone();
        corrupt.allocations[1].predecessor.generation = 0;
        assert_eq!(validate_ledger(&corrupt), Err(Refusal::Malformed));
        corrupt = first;
        corrupt.allocations[0].stage = StageV1::HostAccepted {
            receipt: [0; 32],
            child_birth: 0,
        };
        assert_eq!(validate_ledger(&corrupt), Err(Refusal::Malformed));
    }

    #[test]
    fn finite_stage_event_matrix_preserves_allocation_and_ready_boundary() {
        let (l, r, t) = fixture();
        let (l, _) = allocate(&l, &r, &t, PriorEffect::Settled, PriorChild::Gone).unwrap();
        let ready = ModelReadinessV1 {
            generation: 1,
            identities: l.allocations[0].identities.clone(),
            pins: r.pins.clone(),
            launch_receipt: [7; 32],
            child_birth: 42,
            nonce: [8; 32],
            expected_nonce: [8; 32],
            digest: [9; 32],
        };
        let stages = [
            StageV1::Allocated,
            StageV1::Prepared,
            StageV1::Claimed,
            StageV1::LaunchUncertain,
            StageV1::HostAccepted {
                receipt: [7; 32],
                child_birth: 42,
            },
            StageV1::Ready {
                receipt: [7; 32],
                child_birth: 42,
                readiness_digest: [9; 32],
            },
            StageV1::ChildExited {
                accepted: Some([7; 32]),
            },
            StageV1::ConfigConflict {
                accepted: Some([7; 32]),
            },
            StageV1::ReadinessTimeout { accepted: [7; 32] },
        ];
        let events = [
            EventV1::Prepared,
            EventV1::Claimed,
            EventV1::LaunchUncertain,
            EventV1::HostAccepted {
                receipt: [7; 32],
                child_birth: 42,
            },
            EventV1::ModelVerifiedReady(ready),
            EventV1::UnverifiedReady,
            EventV1::ChildExited,
            EventV1::ConfigConflict,
            EventV1::ReadinessTimeout,
        ];
        let mut cases = 0;
        for stage in stages {
            for event in &events {
                let mut before = l.clone();
                before.allocations[0].stage = stage.clone();
                let result = transition(&before, 1, &r, event);
                cases += 1;
                if let Ok((after, outcome)) = result {
                    assert_eq!(after.generation, before.generation);
                    assert_eq!(
                        after.allocations[0].identities,
                        before.allocations[0].identities
                    );
                    assert_eq!(after.allocations[0].request, before.allocations[0].request);
                    if matches!(outcome, OutcomeV1::Ready(_)) {
                        assert!(matches!(
                            stage,
                            StageV1::HostAccepted { .. } | StageV1::Ready { .. }
                        ));
                        assert!(matches!(event, EventV1::ModelVerifiedReady(_)));
                    }
                }
            }
        }
        assert_eq!(cases, 81);
    }
}
