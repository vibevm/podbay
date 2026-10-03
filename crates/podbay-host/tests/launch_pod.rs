use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use podbay_core::{ActorId, PodId, Role, ScopeId};
use podbay_host::{
    ActorRegistration, AuthenticatedPeer, AuthenticatedProcessSubject, AuthenticatedTransport,
    AuthorisedDispatch, CredentialGeneration, DurableAuthority, DurableAuthorityError, GrantId,
    GrantMode, GrantSpec, GuardSet, HostAction, HostDispatchPort, HostError, HostRequest,
    LaunchPodError, LaunchPodRequest, ManagerEpoch, Operation, PodIncarnation, PodRegistration,
    PortDispatchError, PortDispatchOutcome, PortReceiptRef, Right, Target,
};
use podbay_store::{EffectClaim, LaunchDispatchStage, PodBayStore, StoreError};

struct Fixture {
    directory: PathBuf,
    database: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("podbay-launch-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        Self {
            database: directory.join("podbay.sqlite"),
            directory,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Accepted = 0,
    Refused = 1,
    LostReply = 2,
    Settled = 3,
}

struct FakeLaunchPort {
    mode: Arc<AtomicU8>,
    port_calls: Arc<AtomicUsize>,
    possible_effects: Arc<AtomicUsize>,
}

impl FakeLaunchPort {
    fn new(mode: Mode) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let port_calls = Arc::new(AtomicUsize::new(0));
        let possible_effects = Arc::new(AtomicUsize::new(0));
        (
            Self {
                mode: Arc::new(AtomicU8::new(mode as u8)),
                port_calls: port_calls.clone(),
                possible_effects: possible_effects.clone(),
            },
            port_calls,
            possible_effects,
        )
    }
}

impl HostDispatchPort for FakeLaunchPort {
    type Receipt = PortReceiptRef;

    fn dispatch(
        &mut self,
        _action: AuthorisedDispatch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        self.port_calls.fetch_add(1, Ordering::SeqCst);
        match self.mode.load(Ordering::SeqCst) {
            1 => Err(PortDispatchError::RefusedBeforeEffect),
            2 => {
                self.possible_effects.fetch_add(1, Ordering::SeqCst);
                Err(PortDispatchError::UncertainAfterPossibleEffect {
                    receipt_ref: Some(PortReceiptRef::from_port("receipt.launch.one").unwrap()),
                })
            }
            3 => {
                self.possible_effects.fetch_add(1, Ordering::SeqCst);
                Ok(PortDispatchOutcome::Settled(
                    PortReceiptRef::from_port("receipt.launch.one").unwrap(),
                ))
            }
            _ => {
                self.possible_effects.fetch_add(1, Ordering::SeqCst);
                Ok(PortDispatchOutcome::Accepted(
                    PortReceiptRef::from_port("receipt.launch.one").unwrap(),
                ))
            }
        }
    }
}

#[derive(Clone)]
struct FakeTransport(AuthenticatedPeer);

impl AuthenticatedTransport for FakeTransport {
    fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError> {
        Ok(self.0.clone())
    }
}

struct Identity {
    scope: ScopeId,
    pod: PodId,
    actor: ActorId,
    process: AuthenticatedProcessSubject,
    transport: FakeTransport,
}

fn identity() -> Identity {
    let scope = ScopeId::try_from("scope.launch").unwrap();
    let pod = PodId::try_from("pod.launch").unwrap();
    let actor = ActorId::try_from("actor.launcher").unwrap();
    let process = AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(
        1000,
        701,
        801,
        "/user.slice/session-launch.scope",
    )
    .unwrap();
    let transport = FakeTransport(AuthenticatedPeer::owner_cli_from_authenticated_transport(
        process.clone(),
        CredentialGeneration::new(1).unwrap(),
    ));
    Identity {
        scope,
        pod,
        actor,
        process,
        transport,
    }
}

fn initial_authority(
    path: &PathBuf,
    port: FakeLaunchPort,
    who: &Identity,
) -> (DurableAuthority<FakeLaunchPort>, GrantId) {
    let mut host = DurableAuthority::open(path, port).unwrap();
    host.register_pod_from_trusted_policy(PodRegistration {
        scope_id: who.scope.clone(),
        pod_id: who.pod.clone(),
        incarnation: PodIncarnation::new(1).unwrap(),
    })
    .unwrap();
    host.register_actor_from_trusted_policy(ActorRegistration::owner_cli_from_trusted_policy(
        who.actor.clone(),
        who.scope.clone(),
        who.process.clone(),
        CredentialGeneration::new(1).unwrap(),
    ))
    .unwrap();
    let grant = host
        .install_grant_from_trusted_policy(
            &who.actor,
            GrantSpec {
                scope_id: who.scope.clone(),
                mode: GrantMode::Controller,
                rights: [Right::new(
                    Operation::LaunchPod,
                    Target::Pod(who.pod.clone()),
                )]
                .into_iter()
                .collect::<BTreeSet<_>>(),
                remaining_delegation_depth: 0,
            },
        )
        .unwrap();
    (host, grant)
}

fn replay(host: &mut DurableAuthority<FakeLaunchPort>, who: &Identity, grant: GrantId) {
    host.reattest_actor_from_trusted_replay(
        &who.transport,
        ActorRegistration::owner_cli_from_trusted_policy(
            who.actor.clone(),
            who.scope.clone(),
            who.process.clone(),
            CredentialGeneration::new(1).unwrap(),
        ),
    )
    .unwrap();
    host.activate_grant_from_trusted_replay(grant).unwrap();
}

fn launch_request(
    who: &Identity,
    grant: GrantId,
    current_owner: u64,
    admission_owner: u64,
    body: &[u8],
) -> LaunchPodRequest {
    LaunchPodRequest {
        host_request: HostRequest {
            scope_id: who.scope.clone(),
            grant_id: grant,
            guards: GuardSet {
                manager_epoch: ManagerEpoch::new(current_owner).unwrap(),
                pod_incarnation: PodIncarnation::new(1).unwrap(),
                resource_epoch: None,
                credential_generation: CredentialGeneration::new(1).unwrap(),
            },
            command_key: "launch.same-key".into(),
            correlation_id: "correlation.launch".into(),
            deadline: Instant::now() + Duration::from_secs(30),
            action: HostAction::LaunchPod {
                pod_id: who.pod.clone(),
                role: Role::Worker,
                credential: None,
            },
        },
        canonical_request: body.to_vec(),
        admission_owner_epoch: ManagerEpoch::new(admission_owner).unwrap(),
        admission_pod_incarnation: PodIncarnation::new(1).unwrap(),
    }
}

#[test]
fn launch_admits_once_and_retries_return_original_receipt() {
    let fixture = Fixture::new();
    let who = identity();
    let (port, calls, effects) = FakeLaunchPort::new(Mode::Accepted);
    let (mut host, grant) = initial_authority(&fixture.database, port, &who);
    let request = launch_request(&who, grant, 1, 1, b"canonical.launch.one");
    let first = host.launch_pod(&who.transport, request.clone()).unwrap();
    assert!(!first.duplicate);
    assert!(first.port_called);
    assert_eq!(first.status.stage, LaunchDispatchStage::HostAccepted);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    let retry = host.launch_pod(&who.transport, request.clone()).unwrap();
    assert!(retry.duplicate);
    assert!(!retry.port_called);
    assert_eq!(retry.receipt, first.receipt);
    assert_eq!(retry.status, first.status);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let mut changed = request;
    changed.canonical_request = b"changed.launch.body".to_vec();
    assert!(matches!(
        host.launch_pod(&who.transport, changed),
        Err(LaunchPodError::Store(StoreError::Conflict(_)))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        host.dispatch(
            &who.transport,
            launch_request(&who, grant, 1, 1, b"canonical.launch.one").host_request,
        ),
        Err(HostError::Unsupported)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn prepared_intent_survives_restart_and_dispatches_once_after_replay() {
    let fixture = Fixture::new();
    let who = identity();
    let (first_port, first_calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut first, grant) = initial_authority(&fixture.database, first_port, &who);
    let original = launch_request(&who, grant, 1, 1, b"canonical.prepared");
    let persisted = first.admit_launch_pod(&who.transport, original).unwrap();
    assert_eq!(persisted.status.stage, LaunchDispatchStage::Prepared);
    assert!(!persisted.port_called);
    assert_eq!(first_calls.load(Ordering::SeqCst), 0);
    drop(first);

    let (second_port, second_calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let mut second = DurableAuthority::open(&fixture.database, second_port).unwrap();
    assert_eq!(second.owner_epoch().get(), 2);
    replay(&mut second, &who, grant);
    let resumed = second
        .launch_pod(
            &who.transport,
            launch_request(&who, grant, 2, 1, b"canonical.prepared"),
        )
        .unwrap();
    assert!(resumed.duplicate);
    assert!(resumed.port_called);
    assert_eq!(resumed.receipt, persisted.receipt);
    assert_eq!(resumed.status.stage, LaunchDispatchStage::HostAccepted);
    assert_eq!(second_calls.load(Ordering::SeqCst), 1);
    let replayed = second
        .launch_pod(
            &who.transport,
            launch_request(&who, grant, 2, 1, b"canonical.prepared"),
        )
        .unwrap();
    assert!(!replayed.port_called);
    assert_eq!(second_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn lost_reply_remains_uncertain_across_manager_restart() {
    let fixture = Fixture::new();
    let who = identity();
    let (first_port, first_calls, first_effects) = FakeLaunchPort::new(Mode::LostReply);
    let (mut first, grant) = initial_authority(&fixture.database, first_port, &who);
    let first_result = first
        .launch_pod(
            &who.transport,
            launch_request(&who, grant, 1, 1, b"canonical.uncertain"),
        )
        .unwrap();
    assert_eq!(
        first_result.status.stage,
        LaunchDispatchStage::UncertainAfterPossibleEffect
    );
    assert_eq!(first_calls.load(Ordering::SeqCst), 1);
    assert_eq!(first_effects.load(Ordering::SeqCst), 1);
    drop(first);

    let (second_port, second_calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let mut second = DurableAuthority::open(&fixture.database, second_port).unwrap();
    replay(&mut second, &who, grant);
    let replayed = second
        .launch_pod(
            &who.transport,
            launch_request(&who, grant, 2, 1, b"canonical.uncertain"),
        )
        .unwrap();
    assert!(replayed.duplicate);
    assert!(!replayed.port_called);
    assert_eq!(replayed.receipt, first_result.receipt);
    assert_eq!(replayed.status, first_result.status);
    assert_eq!(second_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn refusal_is_recorded_and_second_manager_cannot_overlap_launch() {
    let fixture = Fixture::new();
    let who = identity();
    let (port, calls, effects) = FakeLaunchPort::new(Mode::Refused);
    let (mut first, grant) = initial_authority(&fixture.database, port, &who);
    assert!(matches!(
        DurableAuthority::open(&fixture.database, FakeLaunchPort::new(Mode::Accepted).0),
        Err(DurableAuthorityError::Busy)
    ));
    let result = first
        .launch_pod(
            &who.transport,
            launch_request(&who, grant, 1, 1, b"canonical.refused"),
        )
        .unwrap();
    assert_eq!(
        result.status.stage,
        LaunchDispatchStage::RefusedBeforeEffect
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    let again = first
        .launch_pod(
            &who.transport,
            launch_request(&who, grant, 1, 1, b"canonical.refused"),
        )
        .unwrap();
    assert!(!again.port_called);
    assert_eq!(again.status.stage, LaunchDispatchStage::RefusedBeforeEffect);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn port_settled_stage_does_not_claim_run_completion() {
    let fixture = Fixture::new();
    let who = identity();
    let (port, calls, effects) = FakeLaunchPort::new(Mode::Settled);
    let (mut host, grant) = initial_authority(&fixture.database, port, &who);
    let result = host
        .launch_pod(
            &who.transport,
            launch_request(&who, grant, 1, 1, b"canonical.port-settled"),
        )
        .unwrap();
    assert_eq!(result.status.stage, LaunchDispatchStage::PortSettled);
    assert_eq!(
        result.status.receipt_ref.as_deref(),
        Some("receipt.launch.one")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(effects.load(Ordering::SeqCst), 1);
}

#[test]
fn committed_claim_without_port_result_is_not_replayed() {
    let fixture = Fixture::new();
    let who = identity();
    let (first_port, first_calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let (mut first, grant) = initial_authority(&fixture.database, first_port, &who);
    let admitted = first
        .admit_launch_pod(
            &who.transport,
            launch_request(&who, grant, 1, 1, b"canonical.claim-crash"),
        )
        .unwrap();
    assert_eq!(first_calls.load(Ordering::SeqCst), 0);
    drop(first);

    // This is the crash window after the claim commits but before a port call
    // or outcome write. Recovery cannot infer that the effect did not happen.
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    assert_eq!(
        store
            .claim_effect(
                admitted.receipt.outbox_id,
                who.scope.as_str(),
                who.pod.as_str(),
                1,
                1,
                &format!("claim.{}", admitted.receipt.command_id),
            )
            .unwrap(),
        EffectClaim::NewClaim
    );
    drop(store);

    let (second_port, second_calls, _) = FakeLaunchPort::new(Mode::Accepted);
    let mut second = DurableAuthority::open(&fixture.database, second_port).unwrap();
    replay(&mut second, &who, grant);
    let recovered = second
        .launch_pod(
            &who.transport,
            launch_request(&who, grant, 2, 1, b"canonical.claim-crash"),
        )
        .unwrap();
    assert!(recovered.duplicate);
    assert!(!recovered.port_called);
    assert_eq!(
        recovered.status.stage,
        LaunchDispatchStage::ClaimedUncertain
    );
    assert_eq!(second_calls.load(Ordering::SeqCst), 0);
}
