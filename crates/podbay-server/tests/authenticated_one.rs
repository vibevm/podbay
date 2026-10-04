#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_compact::{KeyPair, Seed};
use podbay_client::{ClientAuthStage, PodBayClient, authenticate_existing_linux_stream};
use podbay_core::{ActorId, ScopeId};
use podbay_host::{
    ActorRegistration, AuthenticatedPeer, AuthenticatedProcessSubject, AuthenticatedTransport,
    AuthorisedBoundLaunch, AuthorisedDispatch, CredentialGeneration, DurableAuthority,
    HostDispatchPort, HostError, PortDispatchError, PortDispatchOutcome,
};
use podbay_server::{
    Handler, LinuxAcceptedPeerEvidence, LinuxServeOneFault, serve_authenticated_linux_one,
};
use podbay_store::PodBayStore;
use podbay_wire::{
    CommandEnvelope, ReadEnvelope, ReadOperation, Receipt, RuntimeError, RuntimeErrorCode, Target,
};
use serde_json::{Value, json};

struct Fixture {
    root: PathBuf,
    database: PathBuf,
    listener: UnixListener,
    socket_path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("podbay-auth-one-{}-{stamp}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let socket_path = root.join("peer.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        Self {
            database: root.join("store.sqlite"),
            root,
            listener,
            socket_path,
        }
    }
    fn pair(&self) -> (UnixStream, UnixStream) {
        let client = UnixStream::connect(&self.socket_path).unwrap();
        let (server, _) = self.listener.accept().unwrap();
        (server, client)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Default)]
struct NoPort;
impl HostDispatchPort for NoPort {
    type Receipt = ();
    fn dispatch(
        &mut self,
        _: AuthorisedDispatch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        panic!("read fixture must not dispatch an effect")
    }
    fn launch_bound(
        &mut self,
        _: AuthorisedBoundLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        panic!("read fixture must not launch a pod")
    }
}
struct FakeTransport(AuthenticatedPeer);
impl AuthenticatedTransport for FakeTransport {
    fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError> {
        Ok(self.0.clone())
    }
}

fn prepared_authority(
    fixture: &Fixture,
    process: AuthenticatedProcessSubject,
    public_key: [u8; 32],
) -> (DurableAuthority<NoPort>, ActorId) {
    let actor = ActorId::try_from("actor.auth.one").unwrap();
    let scope = ScopeId::try_from("scope.auth.one").unwrap();
    let generation = CredentialGeneration::new(1).unwrap();
    let registration = ActorRegistration::owner_cli_from_trusted_policy(
        actor.clone(),
        scope,
        process.clone(),
        generation,
    );
    let peer = AuthenticatedPeer::owner_cli_from_authenticated_transport(process, generation);
    let mut first = DurableAuthority::open(&fixture.database, NoPort).unwrap();
    first
        .register_actor_from_trusted_policy(registration.clone())
        .unwrap();
    let record = first.recorded_snapshot().actors[0].clone();
    drop(first);
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let snapshot = store.authority_snapshot().unwrap();
    store
        .register_actor_verifier_from_trusted_host(
            snapshot.owner_epoch,
            snapshot.revision,
            &record,
            public_key,
        )
        .unwrap();
    drop(store);
    let mut authority = DurableAuthority::open(&fixture.database, NoPort).unwrap();
    authority
        .reattest_actor_from_trusted_replay(&FakeTransport(peer), registration)
        .unwrap();
    (authority, actor)
}

#[derive(Default)]
struct ReadOnlyHandler {
    reads: usize,
    commands: usize,
}
impl Handler for ReadOnlyHandler {
    fn command<T: AuthenticatedTransport>(
        &mut self,
        _: &T,
        _: CommandEnvelope,
    ) -> Result<Receipt<Value>, RuntimeError> {
        self.commands += 1;
        Err(RuntimeError {
            code: RuntimeErrorCode::Unsupported,
            message: "no mutation fixture".into(),
            retry: "never".into(),
            command_id: None,
        })
    }
    fn read<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        _: ReadEnvelope,
    ) -> Result<Value, RuntimeError> {
        transport.verified_peer().map_err(|_| RuntimeError {
            code: RuntimeErrorCode::Forbidden,
            message: "peer changed".into(),
            retry: "never".into(),
            command_id: None,
        })?;
        self.reads += 1;
        Ok(json!({"state":"ready"}))
    }
}

fn read_request() -> ReadEnvelope {
    ReadEnvelope::new_json(
        "request.auth.one",
        Target::Scope {
            scope_id: "scope.auth.one".into(),
        },
        ReadOperation::CapabilitiesGet,
        json!({}),
    )
    .unwrap()
}

#[test]
fn proved_actor_reads_one_podbay_envelope_over_accepted_socket() {
    let fixture = Fixture::new();
    let (server, client) = fixture.pair();
    let observed = LinuxAcceptedPeerEvidence::from_accepted(&server).unwrap();
    let signer = KeyPair::from_seed(Seed::new([7; 32]));
    let (mut authority, actor) =
        prepared_authority(&fixture, observed.subject().clone(), *signer.pk);
    let expected_process = observed.subject().process_identity().to_owned();
    let client_actor = actor.as_str().to_owned();
    let worker = thread::spawn(move || {
        let signer = KeyPair::from_seed(Seed::new([7; 32]));
        let stream = authenticate_existing_linux_stream(client, &client_actor, |challenge| {
            if challenge.actor_id != client_actor
                || challenge.scope_id != "scope.auth.one"
                || challenge.credential_generation != 1
                || challenge.process_identity != expected_process
                || challenge.store_lineage.is_empty()
            {
                return None;
            }
            let signed = signer.sk.sign(challenge.bytes, None);
            let mut signature = [0_u8; 64];
            signature.copy_from_slice(signed.as_ref());
            Some(signature)
        })
        .unwrap();
        let mut client = PodBayClient::new(stream);
        let response: Value = client.read(&read_request()).unwrap();
        assert_eq!(response, json!({"state":"ready"}));
    });
    let mut handler = ReadOnlyHandler::default();
    serve_authenticated_linux_one(server, &mut authority, &mut handler).unwrap();
    worker.join().unwrap();
    assert_eq!(handler.reads, 1);
    assert_eq!(handler.commands, 0);
}

#[test]
fn wrong_signature_refuses_before_podbay_request_or_handler() {
    let fixture = Fixture::new();
    let (server, client) = fixture.pair();
    let observed = LinuxAcceptedPeerEvidence::from_accepted(&server).unwrap();
    let signer = KeyPair::from_seed(Seed::new([7; 32]));
    let (mut authority, actor) =
        prepared_authority(&fixture, observed.subject().clone(), *signer.pk);
    let client_actor = actor.as_str().to_owned();
    let worker = thread::spawn(move || {
        let error = authenticate_existing_linux_stream(client, &client_actor, |_| Some([0; 64]))
            .err()
            .unwrap();
        assert_eq!(error.stage, ClientAuthStage::SignaturePossiblyWritten);
    });
    let mut handler = ReadOnlyHandler::default();
    assert!(matches!(
        serve_authenticated_linux_one(server, &mut authority, &mut handler),
        Err(LinuxServeOneFault::Authentication(_))
    ));
    worker.join().unwrap();
    assert_eq!(handler.reads, 0);
    assert_eq!(handler.commands, 0);
}
