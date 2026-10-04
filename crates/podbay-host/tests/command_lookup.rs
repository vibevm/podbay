use std::cell::Cell;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_core::{ActorId, ScopeId};
use podbay_host::{
    ActorRegistration, AuthenticatedPeer, AuthenticatedProcessSubject, AuthenticatedTransport,
    AuthorisedBoundLaunch, AuthorisedDispatch, CredentialGeneration, DurableAuthority,
    DurableAuthorityError, HostDispatchPort, HostError, PortDispatchError, PortDispatchOutcome,
};
use podbay_store::{
    Admission, CommandLookupSelector, CommandRequest, EffectState, PodBayStore, StoreError,
    VerifiedPrincipal,
};

struct Fixture {
    directory: PathBuf,
    database: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "podbay-host-command-lookup-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        Self {
            database: directory.join("podbay.sqlite"),
            directory,
        }
    }

    fn counts(&self) -> (usize, usize, i64) {
        let mut store = PodBayStore::open(&self.database).unwrap();
        let snapshot = store.scope_snapshot("scope.fixture").unwrap();
        (
            snapshot.receipts.len(),
            snapshot.effects.len(),
            snapshot.cursor.sequence,
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[derive(Default)]
struct NoPort {
    calls: usize,
}

impl HostDispatchPort for NoPort {
    type Receipt = ();

    fn dispatch(
        &mut self,
        _action: AuthorisedDispatch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        self.calls += 1;
        Err(PortDispatchError::RefusedBeforeEffect)
    }

    fn launch_bound(
        &mut self,
        _launch: AuthorisedBoundLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        self.calls += 1;
        Err(PortDispatchError::RefusedBeforeEffect)
    }
}

struct FakeTransport(AuthenticatedPeer);

impl AuthenticatedTransport for FakeTransport {
    fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError> {
        Ok(self.0.clone())
    }
}

struct DiesAfterFirstCheck {
    peer: AuthenticatedPeer,
    calls: Cell<usize>,
}

impl AuthenticatedTransport for DiesAfterFirstCheck {
    fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError> {
        let prior = self.calls.get();
        self.calls.set(prior + 1);
        if prior == 0 {
            Ok(self.peer.clone())
        } else {
            Err(HostError::Unauthenticated)
        }
    }
}

fn process(pid: u32, birth: u64) -> AuthenticatedProcessSubject {
    AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(
        1000,
        pid,
        birth,
        "/user.slice/owner-cli.scope",
    )
    .unwrap()
}

fn register_owner(
    authority: &mut DurableAuthority<NoPort>,
    scope: &ScopeId,
    actor_id: &ActorId,
    process: &AuthenticatedProcessSubject,
) -> FakeTransport {
    let generation = CredentialGeneration::new(1).unwrap();
    authority
        .register_actor_from_trusted_policy(ActorRegistration::owner_cli_from_trusted_policy(
            actor_id.clone(),
            scope.clone(),
            process.clone(),
            generation,
        ))
        .unwrap();
    FakeTransport(AuthenticatedPeer::owner_cli_from_authenticated_transport(
        process.clone(),
        generation,
    ))
}

fn seed_command(fixture: &Fixture, actor_id: &ActorId, scope: &ScopeId) -> podbay_store::Receipt {
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    store
        .advance_target_epoch(scope.as_str(), "target.fixture", 0, 1)
        .unwrap();
    let request = CommandRequest {
        principal: VerifiedPrincipal::from_authenticated_boundary(actor_id.as_str()).unwrap(),
        namespace: "namespace.fixture".into(),
        command_key: "key.fixture".into(),
        scope_id: scope.as_str().into(),
        target_id: "target.fixture".into(),
        expected_owner_epoch: 1,
        expected_target_epoch: 1,
        canonical_request: b"canonical fixture".to_vec(),
        event_kind: "command.admitted".into(),
        event_payload: b"event fixture".to_vec(),
        effect_kind: "pod.offer".into(),
        effect_payload: b"effect fixture".to_vec(),
    };
    match store.admit(&request).unwrap() {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected committed receipt: {other:?}"),
    }
}

fn by_id(id: &str) -> CommandLookupSelector {
    CommandLookupSelector::Id {
        command_id: id.into(),
    }
}

fn by_key(key: &str) -> CommandLookupSelector {
    CommandLookupSelector::Key { key: key.into() }
}

#[test]
fn live_actor_reads_only_own_command_in_exact_scope_without_effect() {
    let fixture = Fixture::new();
    let mut authority = DurableAuthority::open(&fixture.database, NoPort::default()).unwrap();
    let scope = ScopeId::try_from("scope.fixture").unwrap();
    let actor_id = ActorId::try_from("actor.fixture").unwrap();
    let foreign_id = ActorId::try_from("actor.foreign").unwrap();
    let owner = register_owner(&mut authority, &scope, &actor_id, &process(101, 201));
    let foreign = register_owner(&mut authority, &scope, &foreign_id, &process(102, 202));
    let receipt = seed_command(&fixture, &actor_id, &scope);
    let counts = fixture.counts();

    let found = authority
        .lookup_command(&owner, &scope, &by_id(&receipt.command_id))
        .unwrap();
    assert_eq!(found.receipt, receipt);
    assert_eq!(found.effect_state, EffectState::Prepared);
    assert_eq!(
        authority
            .lookup_command(&owner, &scope, &by_key("key.fixture"))
            .unwrap(),
        found
    );
    assert!(matches!(
        authority.lookup_command(&foreign, &scope, &by_id(&receipt.command_id)),
        Err(DurableAuthorityError::Store(StoreError::NotFound))
    ));
    assert!(matches!(
        authority.lookup_command(
            &owner,
            &ScopeId::try_from("scope.foreign").unwrap(),
            &by_id(&receipt.command_id),
        ),
        Err(DurableAuthorityError::Store(StoreError::NotFound))
    ));
    assert!(matches!(
        authority.lookup_command(&owner, &scope, &by_key("missing.key")),
        Err(DurableAuthorityError::Store(StoreError::NotFound))
    ));
    assert_eq!(authority.port().calls, 0);
    assert_eq!(fixture.counts(), counts);
}

#[test]
fn stale_generation_and_owner_refuse_even_historical_receipt_read() {
    let fixture = Fixture::new();
    let mut authority = DurableAuthority::open(&fixture.database, NoPort::default()).unwrap();
    let scope = ScopeId::try_from("scope.fixture").unwrap();
    let actor_id = ActorId::try_from("actor.fixture").unwrap();
    let observed = process(111, 211);
    let old_transport = register_owner(&mut authority, &scope, &actor_id, &observed);
    let receipt = seed_command(&fixture, &actor_id, &scope);
    authority
        .advance_credential_generation_from_trusted_policy(
            &actor_id,
            CredentialGeneration::new(1).unwrap(),
            CredentialGeneration::new(2).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        authority.lookup_command(&old_transport, &scope, &by_id(&receipt.command_id)),
        Err(DurableAuthorityError::Host(HostError::Unauthenticated))
    ));
    let renewed = FakeTransport(AuthenticatedPeer::owner_cli_from_authenticated_transport(
        observed,
        CredentialGeneration::new(2).unwrap(),
    ));
    assert_eq!(
        authority
            .lookup_command(&renewed, &scope, &by_id(&receipt.command_id))
            .unwrap()
            .receipt,
        receipt
    );
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    store.advance_owner_epoch(1, 2).unwrap();
    assert!(
        authority
            .lookup_command(&renewed, &scope, &by_id(&receipt.command_id))
            .is_err()
    );
    assert_eq!(authority.port().calls, 0);
}

#[test]
fn transport_must_still_verify_after_store_read() {
    let fixture = Fixture::new();
    let mut authority = DurableAuthority::open(&fixture.database, NoPort::default()).unwrap();
    let scope = ScopeId::try_from("scope.fixture").unwrap();
    let actor_id = ActorId::try_from("actor.fixture").unwrap();
    let owner = register_owner(&mut authority, &scope, &actor_id, &process(121, 221));
    let receipt = seed_command(&fixture, &actor_id, &scope);
    let transport = DiesAfterFirstCheck {
        peer: owner.0,
        calls: Cell::new(0),
    };
    assert!(matches!(
        authority.lookup_command(&transport, &scope, &by_id(&receipt.command_id)),
        Err(DurableAuthorityError::Host(HostError::Unauthenticated))
    ));
    assert_eq!(transport.calls.get(), 2);
    assert_eq!(authority.port().calls, 0);
}
