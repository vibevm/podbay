#![cfg(target_os = "linux")]

use std::fs;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_compact::{KeyPair, Seed};
use podbay_core::{ActorId, PodId, Role, ScopeId};
use podbay_host::{
    ActorRegistration, AuthenticatedPeer, AuthenticatedProcessSubject, AuthenticatedTransport,
    AuthorisedBoundLaunch, AuthorisedDispatch, CredentialGeneration, DurableAuthority,
    HostDispatchPort, HostError, PodIncarnation, PodRegistration, PortDispatchError,
    PortDispatchOutcome,
};
use podbay_server::{
    AUTH_PRELUDE_PROTOCOL, LinuxAcceptedPeerEvidence, LinuxAuthPreludeError,
    LinuxAuthPreludeLimits, authenticate_accepted_linux_stream,
    authenticate_accepted_linux_stream_with_limits,
};
use podbay_store::PodBayStore;
use serde_json::json;

struct FixtureDir {
    root: PathBuf,
    database: PathBuf,
}
impl FixtureDir {
    fn new() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "podbay-auth-prelude-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        Self {
            database: root.join("store.sqlite"),
            root,
        }
    }
}
impl Drop for FixtureDir {
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
        panic!("authentication must not dispatch a command")
    }
    fn launch_bound(
        &mut self,
        _: AuthorisedBoundLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        panic!("authentication must not launch a pod")
    }
}

struct FakeTransport(AuthenticatedPeer);
impl AuthenticatedTransport for FakeTransport {
    fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError> {
        Ok(self.0.clone())
    }
}

#[derive(Clone, Copy)]
enum Origin {
    Owner,
    Pod,
}

fn prepared_authority(
    process: AuthenticatedProcessSubject,
    origin: Origin,
    public_key: [u8; 32],
) -> (
    FixtureDir,
    DurableAuthority<NoPort>,
    ActorId,
    CredentialGeneration,
) {
    let fixture = FixtureDir::new();
    let scope = ScopeId::try_from("scope.auth.prelude").unwrap();
    let actor = ActorId::try_from("actor.auth.prelude").unwrap();
    let generation = CredentialGeneration::new(1).unwrap();
    let pod = PodId::try_from("pod.auth.prelude").unwrap();
    let registration = match origin {
        Origin::Owner => ActorRegistration::owner_cli_from_trusted_policy(
            actor.clone(),
            scope.clone(),
            process.clone(),
            generation,
        ),
        Origin::Pod => ActorRegistration::pod_from_trusted_policy(
            actor.clone(),
            scope.clone(),
            Role::Worker,
            pod.clone(),
            PodIncarnation::new(1).unwrap(),
            None,
            process.clone(),
            generation,
        ),
    };
    let peer = match origin {
        Origin::Owner => {
            AuthenticatedPeer::owner_cli_from_authenticated_transport(process, generation)
        }
        Origin::Pod => AuthenticatedPeer::pod_from_authenticated_transport(
            actor.clone(),
            pod.clone(),
            PodIncarnation::new(1).unwrap(),
            process,
            generation,
        ),
    };
    let mut first = DurableAuthority::open(&fixture.database, NoPort).unwrap();
    if matches!(origin, Origin::Pod) {
        first
            .register_pod_from_trusted_policy(PodRegistration {
                scope_id: scope,
                pod_id: pod,
                incarnation: PodIncarnation::new(1).unwrap(),
            })
            .unwrap();
    }
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
    (fixture, authority, actor, generation)
}

fn selector(actor: &ActorId) -> Vec<u8> {
    serde_json::to_vec(&json!({"protocol": AUTH_PRELUDE_PROTOCOL, "actorId": actor.as_str()}))
        .unwrap()
}

fn send_frame(socket: &mut UnixStream, bytes: &[u8]) {
    socket
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    socket.write_all(bytes).unwrap();
}

fn receive_frame(socket: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut prefix = [0_u8; 4];
    socket.read_exact(&mut prefix)?;
    let length = u32::from_be_bytes(prefix) as usize;
    assert!((1..=8_192).contains(&length));
    let mut bytes = vec![0_u8; length];
    socket.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn sign_challenge(mut client: UnixStream, actor: ActorId, seed: u8) -> (Vec<u8>, Vec<u8>) {
    send_frame(&mut client, &selector(&actor));
    let challenge = receive_frame(&mut client).unwrap();
    assert!(challenge.starts_with(b"podbay.actor-credential.challenge\0"));
    let signer = KeyPair::from_seed(Seed::new([seed; 32]));
    let signature = signer.sk.sign(&challenge, None).as_ref().to_vec();
    send_frame(&mut client, &signature);
    let acknowledgement = receive_frame(&mut client).unwrap();
    assert_eq!(
        acknowledgement,
        b"{\"protocol\":\"podbay.auth/1\",\"ok\":true}"
    );
    (challenge, signature)
}

#[test]
fn owner_and_pod_prove_one_current_process_without_dispatch() {
    for (origin, seed) in [(Origin::Owner, 7_u8), (Origin::Pod, 9_u8)] {
        let (server, client) = UnixStream::pair().unwrap();
        let observed = LinuxAcceptedPeerEvidence::from_accepted(&server).unwrap();
        let signer = KeyPair::from_seed(Seed::new([seed; 32]));
        let (_fixture, mut authority, actor, _) =
            prepared_authority(observed.subject().clone(), origin, *signer.pk);
        let client_actor = actor.clone();
        let worker = thread::spawn(move || sign_challenge(client, client_actor, seed));
        let authenticated = authenticate_accepted_linux_stream(server, &mut authority).unwrap();
        assert!(authenticated.verified_peer().is_ok());
        worker.join().unwrap();
    }
}

#[test]
fn wrong_and_replayed_signatures_are_refused_with_new_challenges() {
    let (server, client) = UnixStream::pair().unwrap();
    let observed = LinuxAcceptedPeerEvidence::from_accepted(&server).unwrap();
    let signer = KeyPair::from_seed(Seed::new([7; 32]));
    let (_fixture, mut authority, actor, _) =
        prepared_authority(observed.subject().clone(), Origin::Owner, *signer.pk);
    let client_actor = actor.clone();
    let first = thread::spawn(move || sign_challenge(client, client_actor, 7));
    let authenticated = authenticate_accepted_linux_stream(server, &mut authority).unwrap();
    assert!(authenticated.verified_peer().is_ok());
    let (first_challenge, first_signature) = first.join().unwrap();

    let (server, mut client) = UnixStream::pair().unwrap();
    let client_actor = actor.clone();
    let replay = thread::spawn(move || {
        send_frame(&mut client, &selector(&client_actor));
        let challenge = receive_frame(&mut client).unwrap();
        send_frame(&mut client, &first_signature);
        challenge
    });
    assert!(matches!(
        authenticate_accepted_linux_stream(server, &mut authority),
        Err(LinuxAuthPreludeError::Proof(_))
    ));
    assert_ne!(first_challenge, replay.join().unwrap());

    let (server, mut client) = UnixStream::pair().unwrap();
    let wrong_actor = actor.clone();
    let wrong = thread::spawn(move || {
        send_frame(&mut client, &selector(&wrong_actor));
        let challenge = receive_frame(&mut client).unwrap();
        let wrong_signer = KeyPair::from_seed(Seed::new([8; 32]));
        send_frame(&mut client, wrong_signer.sk.sign(&challenge, None).as_ref());
    });
    assert!(matches!(
        authenticate_accepted_linux_stream(server, &mut authority),
        Err(LinuxAuthPreludeError::Proof(_))
    ));
    wrong.join().unwrap();
}

#[test]
fn verifier_rotation_fences_returned_transport_without_mutable_authority() {
    let (server, client) = UnixStream::pair().unwrap();
    let observed = LinuxAcceptedPeerEvidence::from_accepted(&server).unwrap();
    let signer = KeyPair::from_seed(Seed::new([7; 32]));
    let (fixture, mut authority, actor, generation) =
        prepared_authority(observed.subject().clone(), Origin::Owner, *signer.pk);
    let client_actor = actor.clone();
    let worker = thread::spawn(move || sign_challenge(client, client_actor, 7));
    let authenticated = authenticate_accepted_linux_stream(server, &mut authority).unwrap();
    worker.join().unwrap();
    assert!(authenticated.verified_peer().is_ok());

    authority
        .advance_credential_generation_from_trusted_policy(
            &actor,
            generation,
            CredentialGeneration::new(2).unwrap(),
        )
        .unwrap();
    let next_record = authority.recorded_snapshot().actors[0].clone();
    let next = KeyPair::from_seed(Seed::new([10; 32]));
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let snapshot = store.authority_snapshot().unwrap();
    store
        .register_actor_verifier_from_trusted_host(
            snapshot.owner_epoch,
            snapshot.revision,
            &next_record,
            *next.pk,
        )
        .unwrap();
    assert!(authenticated.verified_peer().is_err());
}

#[test]
fn failed_acknowledgement_never_returns_authenticated_stream() {
    let (server, mut client) = UnixStream::pair().unwrap();
    let observed = LinuxAcceptedPeerEvidence::from_accepted(&server).unwrap();
    let signer = KeyPair::from_seed(Seed::new([7; 32]));
    let (_fixture, mut authority, actor, _) =
        prepared_authority(observed.subject().clone(), Origin::Owner, *signer.pk);
    let worker = thread::spawn(move || {
        send_frame(&mut client, &selector(&actor));
        let challenge = receive_frame(&mut client).unwrap();
        let signature = KeyPair::from_seed(Seed::new([7; 32]))
            .sk
            .sign(&challenge, None);
        client.write_all(&(64_u32).to_be_bytes()).unwrap();
        client.write_all(&signature.as_ref()[..63]).unwrap();
        client.shutdown(Shutdown::Read).unwrap();
        client.write_all(&signature.as_ref()[63..]).unwrap();
    });
    assert!(matches!(
        authenticate_accepted_linux_stream(server, &mut authority),
        Err(LinuxAuthPreludeError::Io(_))
    ));
    worker.join().unwrap();
}

#[test]
fn partial_selector_hits_absolute_handshake_deadline() {
    let (server, mut client) = UnixStream::pair().unwrap();
    let observed = LinuxAcceptedPeerEvidence::from_accepted(&server).unwrap();
    let signer = KeyPair::from_seed(Seed::new([7; 32]));
    let (_fixture, mut authority, _actor, _) =
        prepared_authority(observed.subject().clone(), Origin::Owner, *signer.pk);
    let worker = thread::spawn(move || {
        client.write_all(&[0, 0]).unwrap();
        thread::sleep(Duration::from_millis(150));
    });
    let limits =
        LinuxAuthPreludeLimits::new(Duration::from_millis(40), Duration::from_secs(1)).unwrap();
    let result = authenticate_accepted_linux_stream_with_limits(server, &mut authority, limits);
    assert!(matches!(result, Err(LinuxAuthPreludeError::Io(_))));
    worker.join().unwrap();
}

#[test]
fn signature_requires_exact_length_and_a_complete_frame_before_deadline() {
    let (registration_socket, _registration_client) = UnixStream::pair().unwrap();
    let observed = LinuxAcceptedPeerEvidence::from_accepted(&registration_socket).unwrap();
    let signer = KeyPair::from_seed(Seed::new([7; 32]));
    let (_fixture, mut authority, actor, _) =
        prepared_authority(observed.subject().clone(), Origin::Owner, *signer.pk);

    let (server, mut client) = UnixStream::pair().unwrap();
    let malformed_actor = actor.clone();
    let malformed = thread::spawn(move || {
        send_frame(&mut client, &selector(&malformed_actor));
        receive_frame(&mut client).unwrap();
        client.write_all(&(65_u32).to_be_bytes()).unwrap();
    });
    assert!(matches!(
        authenticate_accepted_linux_stream(server, &mut authority),
        Err(LinuxAuthPreludeError::InvalidSignatureFrame)
    ));
    malformed.join().unwrap();

    let (server, mut client) = UnixStream::pair().unwrap();
    let partial = thread::spawn(move || {
        send_frame(&mut client, &selector(&actor));
        let challenge = receive_frame(&mut client).unwrap();
        let signature = KeyPair::from_seed(Seed::new([7; 32]))
            .sk
            .sign(&challenge, None);
        client.write_all(&(64_u32).to_be_bytes()).unwrap();
        client.write_all(&signature.as_ref()[..63]).unwrap();
        thread::sleep(Duration::from_millis(150));
    });
    let limits =
        LinuxAuthPreludeLimits::new(Duration::from_millis(40), Duration::from_secs(1)).unwrap();
    let result = authenticate_accepted_linux_stream_with_limits(server, &mut authority, limits);
    assert!(matches!(result, Err(LinuxAuthPreludeError::Io(_))));
    partial.join().unwrap();
}

#[test]
fn selector_rejects_duplicate_unknown_and_oversized_fields_before_challenge() {
    let (registration_socket, _registration_client) = UnixStream::pair().unwrap();
    let observed = LinuxAcceptedPeerEvidence::from_accepted(&registration_socket).unwrap();
    let signer = KeyPair::from_seed(Seed::new([7; 32]));
    let (_fixture, mut authority, actor, _) =
        prepared_authority(observed.subject().clone(), Origin::Owner, *signer.pk);
    let duplicate = format!(
        "{{\"protocol\":\"podbay.auth/1\",\"actorId\":\"{actor}\",\"actorId\":\"{actor}\"}}"
    );
    let unknown = format!("{{\"protocol\":\"podbay.auth/1\",\"actorId\":\"{actor}\",\"pid\":1}}");
    for raw in [duplicate.as_bytes(), unknown.as_bytes()] {
        let (server, mut client) = UnixStream::pair().unwrap();
        send_frame(&mut client, raw);
        assert!(matches!(
            authenticate_accepted_linux_stream(server, &mut authority),
            Err(LinuxAuthPreludeError::InvalidSelector)
        ));
    }
    let (server, mut client) = UnixStream::pair().unwrap();
    client.write_all(&(513_u32).to_be_bytes()).unwrap();
    assert!(matches!(
        authenticate_accepted_linux_stream(server, &mut authority),
        Err(LinuxAuthPreludeError::InvalidSelector)
    ));
}

#[test]
fn same_uid_sibling_cannot_select_the_registered_owner_actor() {
    let (registered_socket, _registered_client) = UnixStream::pair().unwrap();
    let registered = LinuxAcceptedPeerEvidence::from_accepted(&registered_socket).unwrap();
    let signer = KeyPair::from_seed(Seed::new([7; 32]));
    let (_fixture, mut authority, actor, _) =
        prepared_authority(registered.subject().clone(), Origin::Owner, *signer.pk);

    let socket_dir = FixtureDir::new();
    let socket_path = socket_dir.root.join("sibling.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "auth_sibling_helper", "--nocapture"])
            .env("PODBAY_AUTH_SIBLING_SOCKET", &socket_path)
            .env("PODBAY_AUTH_SIBLING_ACTOR", actor.as_str())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let accepted = accept_bounded(&listener, &mut child.0);
    let sibling = LinuxAcceptedPeerEvidence::from_accepted(&accepted).unwrap();
    assert_eq!(
        sibling.subject().os_identity(),
        registered.subject().os_identity()
    );
    assert_ne!(
        sibling.subject().process_identity(),
        registered.subject().process_identity()
    );
    assert_ne!(
        sibling.subject().start_identity(),
        registered.subject().start_identity()
    );
    let result = authenticate_accepted_linux_stream(accepted, &mut authority);
    assert!(matches!(result, Err(LinuxAuthPreludeError::Authority(_))));
    child.terminate();
}

#[test]
fn auth_sibling_helper() {
    let (Some(path), Some(actor)) = (
        std::env::var_os("PODBAY_AUTH_SIBLING_SOCKET"),
        std::env::var("PODBAY_AUTH_SIBLING_ACTOR").ok(),
    ) else {
        return;
    };
    let mut stream = UnixStream::connect(path).unwrap();
    let actor = ActorId::try_from(actor.as_str()).unwrap();
    send_frame(&mut stream, &selector(&actor));
    let mut byte = [0_u8; 1];
    let _ = stream.read(&mut byte);
}

struct ChildGuard(Child);
impl ChildGuard {
    fn terminate(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.terminate();
    }
}

fn accept_bounded(listener: &UnixListener, child: &mut Child) -> UnixStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "sibling exited before connect"
                );
                assert!(Instant::now() < deadline, "sibling did not connect");
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("sibling accept failed: {error}"),
        }
    }
}
