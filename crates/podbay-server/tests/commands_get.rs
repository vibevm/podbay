#![cfg(target_os = "linux")]

use std::fs;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_compact::{KeyPair, Seed};
use podbay_client::authenticate_existing_linux_stream;
use podbay_core::{ActorId, ScopeId};
use podbay_host::{
    ActorRegistration, AuthenticatedPeer, AuthenticatedProcessSubject, AuthenticatedTransport,
    AuthorisedBoundLaunch, AuthorisedDispatch, CredentialGeneration, DurableAuthority,
    HostDispatchPort, HostError, PortDispatchError, PortDispatchOutcome,
};
use podbay_server::{
    LinuxAcceptedPeerEvidence, LinuxServeOneFault, ServerFault,
    serve_authenticated_linux_commands_get_one,
};
use podbay_store::{Admission, CommandRequest, PodBayStore, Receipt, VerifiedPrincipal};
use podbay_wire::{ReadEnvelope, ReadOperation, Target};
use serde_json::{Value, json};

struct Fixture {
    root: PathBuf,
    database: PathBuf,
    listener: UnixListener,
    socket_path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "podbay-commands-get-{}-{nonce}",
            std::process::id()
        ));
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

    fn counts(&self) -> (usize, usize, i64, u64) {
        let mut store = PodBayStore::open(&self.database).unwrap();
        let snapshot = store.scope_snapshot("scope.auth.one").unwrap();
        (
            snapshot.receipts.len(),
            snapshot.effects.len(),
            snapshot.cursor.sequence,
            store.owner_epoch().unwrap(),
        )
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
        panic!("commands.get must not dispatch a host effect")
    }

    fn launch_bound(
        &mut self,
        _: AuthorisedBoundLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        panic!("commands.get must not launch a pod")
    }
}

struct FakeTransport(AuthenticatedPeer);

impl AuthenticatedTransport for FakeTransport {
    fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError> {
        Ok(self.0.clone())
    }
}

fn seed_command(store: &mut PodBayStore, principal: &str, target: &str, key: &str) -> Receipt {
    store
        .advance_target_epoch("scope.auth.one", target, 0, 1)
        .unwrap();
    let request = CommandRequest {
        principal: VerifiedPrincipal::from_authenticated_boundary(principal).unwrap(),
        namespace: "namespace.fixture".into(),
        command_key: key.into(),
        scope_id: "scope.auth.one".into(),
        target_id: target.into(),
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
        other => panic!("expected admitted command: {other:?}"),
    }
}

fn prepared_authority(
    fixture: &Fixture,
    process: AuthenticatedProcessSubject,
    public_key: [u8; 32],
) -> (DurableAuthority<NoPort>, ActorId, Receipt, Receipt) {
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
    let own = seed_command(&mut store, actor.as_str(), "target.own", "key.own");
    let foreign = seed_command(&mut store, "actor.foreign", "target.foreign", "key.foreign");
    drop(store);

    let mut authority = DurableAuthority::open(&fixture.database, NoPort).unwrap();
    authority
        .reattest_actor_from_trusted_replay(&FakeTransport(peer), registration)
        .unwrap();
    (authority, actor, own, foreign)
}

fn read_request(request_id: &str, scope: &str, selector: Value) -> ReadEnvelope {
    ReadEnvelope::new_json(
        request_id,
        Target::Scope {
            scope_id: scope.into(),
        },
        ReadOperation::CommandsGet,
        json!({"selector": selector}),
    )
    .unwrap()
}

fn send_read(mut stream: impl Read + Write, request: &ReadEnvelope) -> Value {
    let bytes = request.encode_json().unwrap();
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(&bytes).unwrap();
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).unwrap();
    let len = u32::from_be_bytes(prefix) as usize;
    assert!(len <= 1_048_576);
    let mut response = vec![0_u8; len];
    stream.read_exact(&mut response).unwrap();
    serde_json::from_slice(&response).unwrap()
}

fn exchange(
    fixture: &Fixture,
    authority: &mut DurableAuthority<NoPort>,
    actor: &ActorId,
    request: ReadEnvelope,
) -> Value {
    let (server, client) = fixture.pair();
    let actor = actor.as_str().to_owned();
    let worker = thread::spawn(move || {
        let signer = KeyPair::from_seed(Seed::new([7; 32]));
        let stream = authenticate_existing_linux_stream(client, &actor, |challenge| {
            let signature = signer.sk.sign(challenge.bytes, None);
            let mut bytes = [0_u8; 64];
            bytes.copy_from_slice(signature.as_ref());
            Some(bytes)
        })
        .unwrap();
        send_read(stream, &request)
    });
    serve_authenticated_linux_commands_get_one(server, authority).unwrap();
    worker.join().unwrap()
}

#[test]
fn real_authenticated_commands_get_returns_receipt_and_truthful_status() {
    let fixture = Fixture::new();
    let (server, client) = fixture.pair();
    let observed = LinuxAcceptedPeerEvidence::from_accepted(&server).unwrap();
    let signer = KeyPair::from_seed(Seed::new([7; 32]));
    let (mut authority, actor, own, foreign) =
        prepared_authority(&fixture, observed.subject().clone(), *signer.pk);
    let counts = fixture.counts();
    let actor_name = actor.as_str().to_owned();
    let own_id = own.command_id.clone();
    let worker = thread::spawn(move || {
        let signer = KeyPair::from_seed(Seed::new([7; 32]));
        let stream = authenticate_existing_linux_stream(client, &actor_name, |challenge| {
            let signature = signer.sk.sign(challenge.bytes, None);
            let mut bytes = [0_u8; 64];
            bytes.copy_from_slice(signature.as_ref());
            Some(bytes)
        })
        .unwrap();
        send_read(
            stream,
            &read_request(
                "request.commands.own",
                "scope.auth.one",
                json!({"kind":"id","commandId":own_id}),
            ),
        )
    });
    serve_authenticated_linux_commands_get_one(server, &mut authority).unwrap();
    let own_response = worker.join().unwrap();
    assert_eq!(own_response["requestId"], "request.commands.own");
    assert_eq!(own_response["ok"]["receipt"]["commandId"], own.command_id);
    assert_eq!(
        own_response["ok"]["receipt"]["eventSequence"],
        own.event_sequence.to_string()
    );
    assert_eq!(own_response["ok"]["state"], "persisted");
    assert_eq!(own_response["ok"]["effectState"], "prepared");
    assert_eq!(fixture.counts(), counts);

    let foreign_response = exchange(
        &fixture,
        &mut authority,
        &actor,
        read_request(
            "request.commands.foreign",
            "scope.auth.one",
            json!({"kind":"id","commandId":foreign.command_id}),
        ),
    );
    let absent_response = exchange(
        &fixture,
        &mut authority,
        &actor,
        read_request(
            "request.commands.absent",
            "scope.auth.one",
            json!({"kind":"key","key":"key.absent"}),
        ),
    );
    let wrong_scope_response = exchange(
        &fixture,
        &mut authority,
        &actor,
        read_request(
            "request.commands.scope",
            "scope.foreign",
            json!({"kind":"id","commandId":own.command_id}),
        ),
    );
    for response in [&foreign_response, &absent_response, &wrong_scope_response] {
        assert_eq!(response["error"]["code"], "forbidden");
        assert_eq!(response["error"]["message"], "command unavailable");
        assert_eq!(response["error"]["retry"], "never");
    }
    assert_eq!(foreign_response["requestId"], "request.commands.foreign");
    assert_eq!(wrong_scope_response["requestId"], "request.commands.scope");
    assert_eq!(fixture.counts(), counts);
    assert_eq!(authority.owner_epoch().get(), 2);
}

#[test]
fn other_read_is_correlated_unsupported_after_authentication() {
    let fixture = Fixture::new();
    let (server, client) = fixture.pair();
    let observed = LinuxAcceptedPeerEvidence::from_accepted(&server).unwrap();
    let signer = KeyPair::from_seed(Seed::new([7; 32]));
    let (mut authority, actor, _, _) =
        prepared_authority(&fixture, observed.subject().clone(), *signer.pk);
    let counts = fixture.counts();
    let actor_name = actor.as_str().to_owned();
    let worker = thread::spawn(move || {
        let signer = KeyPair::from_seed(Seed::new([7; 32]));
        let stream = authenticate_existing_linux_stream(client, &actor_name, |challenge| {
            let signature = signer.sk.sign(challenge.bytes, None);
            let mut bytes = [0_u8; 64];
            bytes.copy_from_slice(signature.as_ref());
            Some(bytes)
        })
        .unwrap();
        send_read(
            stream,
            &ReadEnvelope::new_json(
                "request.unsupported",
                Target::Scope {
                    scope_id: "scope.auth.one".into(),
                },
                ReadOperation::CapabilitiesGet,
                json!({}),
            )
            .unwrap(),
        )
    });
    serve_authenticated_linux_commands_get_one(server, &mut authority).unwrap();
    let response = worker.join().unwrap();
    assert_eq!(response["requestId"], "request.unsupported");
    assert_eq!(response["error"]["code"], "unsupported");
    assert_eq!(response["error"]["retry"], "never");
    assert_eq!(fixture.counts(), counts);
}

#[test]
fn lost_read_reply_reports_transport_loss_without_replay() {
    let fixture = Fixture::new();
    let (server, client) = fixture.pair();
    let observed = LinuxAcceptedPeerEvidence::from_accepted(&server).unwrap();
    let signer = KeyPair::from_seed(Seed::new([7; 32]));
    let (mut authority, actor, own, _) =
        prepared_authority(&fixture, observed.subject().clone(), *signer.pk);
    let counts = fixture.counts();
    let actor_name = actor.as_str().to_owned();
    let worker = thread::spawn(move || {
        let signer = KeyPair::from_seed(Seed::new([7; 32]));
        let mut stream = authenticate_existing_linux_stream(
            client.try_clone().unwrap(),
            &actor_name,
            |challenge| {
                let signature = signer.sk.sign(challenge.bytes, None);
                let mut bytes = [0_u8; 64];
                bytes.copy_from_slice(signature.as_ref());
                Some(bytes)
            },
        )
        .unwrap();
        let request = read_request(
            "request.lost.reply",
            "scope.auth.one",
            json!({"kind":"id","commandId":own.command_id}),
        );
        let bytes = request.encode_json().unwrap();
        stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .unwrap();
        client.shutdown(Shutdown::Read).unwrap();
        stream.write_all(&bytes).unwrap();
    });
    let outcome = serve_authenticated_linux_commands_get_one(server, &mut authority);
    worker.join().unwrap();
    assert!(matches!(
        outcome,
        Err(LinuxServeOneFault::Exchange(ServerFault::ResponseLost {
            key: None,
            command_id: None,
            ..
        }))
    ));
    assert_eq!(fixture.counts(), counts);
}
