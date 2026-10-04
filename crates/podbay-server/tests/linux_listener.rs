#![cfg(target_os = "linux")]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_compact::{KeyPair, Seed};
use podbay_client::authenticate_existing_linux_stream;
use podbay_core::{ActorId, ScopeId};
use podbay_host::{
    ActorRegistration, AuthenticatedPeer, AuthenticatedTransport, AuthorisedBoundLaunch,
    AuthorisedDispatch, CredentialGeneration, DurableAuthority, HostDispatchPort, HostError,
    PortDispatchError, PortDispatchOutcome,
};
use podbay_server::{
    LinuxAcceptedPeerEvidence, LinuxListenerError, LinuxManagerCommandsGetListener,
    MANAGER_SOCKET_NAME,
};
use podbay_store::{Admission, CommandRequest, PodBayStore, VerifiedPrincipal};
use podbay_wire::{ReadEnvelope, ReadOperation, Target};
use serde_json::{Value, json};

struct Fixture {
    root: PathBuf,
    database: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "podbay-manager-listener-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            database: root.join("store.sqlite"),
            root,
        }
    }

    fn counts(&self) -> (usize, usize, i64, u64) {
        let mut store = PodBayStore::open(&self.database).unwrap();
        let snapshot = store.scope_snapshot("scope.listener").unwrap();
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

struct NoPort;
impl HostDispatchPort for NoPort {
    type Receipt = ();

    fn dispatch(
        &mut self,
        _: AuthorisedDispatch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        panic!("read listener must not dispatch a host effect")
    }

    fn launch_bound(
        &mut self,
        _: AuthorisedBoundLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        panic!("read listener must not launch a pod")
    }
}

struct ReplayTransport(AuthenticatedPeer);
impl AuthenticatedTransport for ReplayTransport {
    fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError> {
        Ok(self.0.clone())
    }
}

fn prepared_authority(fixture: &Fixture) -> (DurableAuthority<NoPort>, ActorId, String) {
    let (server, _client) = UnixStream::pair().unwrap();
    let process = LinuxAcceptedPeerEvidence::from_accepted(&server)
        .unwrap()
        .subject()
        .clone();
    let actor = ActorId::try_from("actor.listener").unwrap();
    let scope = ScopeId::try_from("scope.listener").unwrap();
    let generation = CredentialGeneration::new(1).unwrap();
    let registration = ActorRegistration::owner_cli_from_trusted_policy(
        actor.clone(),
        scope,
        process.clone(),
        generation,
    );
    let transport = ReplayTransport(AuthenticatedPeer::owner_cli_from_authenticated_transport(
        process, generation,
    ));
    let mut first = DurableAuthority::open(&fixture.database, NoPort).unwrap();
    first
        .register_actor_from_trusted_policy(registration.clone())
        .unwrap();
    let record = first.recorded_snapshot().actors[0].clone();
    drop(first);

    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let snapshot = store.authority_snapshot().unwrap();
    let signer = KeyPair::from_seed(Seed::new([7; 32]));
    store
        .register_actor_verifier_from_trusted_host(
            snapshot.owner_epoch,
            snapshot.revision,
            &record,
            *signer.pk,
        )
        .unwrap();
    store
        .advance_target_epoch("scope.listener", "target.listener", 0, 1)
        .unwrap();
    let receipt = match store
        .admit(&CommandRequest {
            principal: VerifiedPrincipal::from_authenticated_boundary(actor.as_str()).unwrap(),
            namespace: "namespace.listener".into(),
            command_key: "key.listener".into(),
            scope_id: "scope.listener".into(),
            target_id: "target.listener".into(),
            expected_owner_epoch: 1,
            expected_target_epoch: 1,
            canonical_request: b"listener fixture".to_vec(),
            event_kind: "command.admitted".into(),
            event_payload: b"event fixture".to_vec(),
            effect_kind: "pod.offer".into(),
            effect_payload: b"effect fixture".to_vec(),
        })
        .unwrap()
    {
        Admission::Committed(receipt) => receipt,
        other => panic!("expected one committed command: {other:?}"),
    };
    drop(store);

    let mut authority = DurableAuthority::open(&fixture.database, NoPort).unwrap();
    authority
        .reattest_actor_from_trusted_replay(&transport, registration)
        .unwrap();
    (authority, actor, receipt.command_id)
}

fn request(id: &str, command_id: &str) -> ReadEnvelope {
    ReadEnvelope::new_json(
        id,
        Target::Scope {
            scope_id: "scope.listener".into(),
        },
        ReadOperation::CommandsGet,
        json!({"selector":{"kind":"id","commandId":command_id}}),
    )
    .unwrap()
}

fn exchange(mut stream: impl Read + Write, request: &ReadEnvelope) -> Value {
    let bytes = request.encode_json().unwrap();
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(&bytes).unwrap();
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).unwrap();
    let length = u32::from_be_bytes(prefix) as usize;
    assert!(length <= 1_048_576);
    let mut response = vec![0_u8; length];
    stream.read_exact(&mut response).unwrap();
    serde_json::from_slice(&response).unwrap()
}

struct StopOnDrop(Arc<AtomicBool>);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[test]
fn manager_listener_owns_socket_and_serves_one_authenticated_read_per_connection() {
    let fixture = Fixture::new();
    let (mut authority, actor, command_id) = prepared_authority(&fixture);
    let counts = fixture.counts();
    let mut listener = LinuxManagerCommandsGetListener::bind(&fixture.root).unwrap();
    assert_eq!(listener.path(), fixture.root.join(MANAGER_SOCKET_NAME));
    assert!(LinuxManagerCommandsGetListener::bind(&fixture.root).is_err());
    let socket_path = listener.path().to_path_buf();
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = stop.clone();
    let client_command_id = command_id.clone();
    let worker = thread::spawn(move || {
        let _stop = StopOnDrop(worker_stop);
        let mut replies = Vec::new();
        for number in 1..=2 {
            let socket = UnixStream::connect(&socket_path).unwrap();
            let actor_name = actor.as_str().to_owned();
            let signer = KeyPair::from_seed(Seed::new([7; 32]));
            let mut authenticated =
                authenticate_existing_linux_stream(socket, &actor_name, |challenge| {
                    let signature = signer.sk.sign(challenge.bytes, None);
                    let mut bytes = [0_u8; 64];
                    bytes.copy_from_slice(signature.as_ref());
                    Some(bytes)
                })
                .unwrap();
            replies.push(exchange(
                &mut authenticated,
                &request(&format!("request.listener.{number}"), &client_command_id),
            ));
            // The server drops this stream after its first exchange. A second
            // request requires a new connection and fresh actor challenge.
            let mut byte = [0_u8; 1];
            assert_eq!(authenticated.read(&mut byte).unwrap(), 0);
        }
        replies
    });
    let report = listener.serve_until(&mut authority, &stop).unwrap();
    let replies = worker.join().unwrap();
    assert_eq!(report.accepted, 2);
    assert_eq!(report.completed, 2);
    assert_eq!(report.authentication_failures, 0);
    assert_eq!(report.exchange_failures, 0);
    assert!(report.last_failure.is_none());
    for (index, reply) in replies.iter().enumerate() {
        assert_eq!(
            reply["requestId"],
            format!("request.listener.{}", index + 1)
        );
        assert_eq!(reply["ok"]["receipt"]["commandId"], command_id);
        assert_eq!(reply["ok"]["effectState"], "prepared");
    }
    assert_eq!(fixture.counts(), counts);
    let path = listener.path().to_path_buf();
    listener.shutdown().unwrap();
    assert!(!path.exists());

    // Shutdown must never unlink a different socket later placed at its path.
    let replacement_owner = LinuxManagerCommandsGetListener::bind(&fixture.root).unwrap();
    fs::remove_file(&path).unwrap();
    let replacement = UnixListener::bind(&path).unwrap();
    assert!(matches!(
        replacement_owner.shutdown(),
        Err(LinuxListenerError::SocketIdentityChanged)
    ));
    assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
    drop(replacement);
    fs::remove_file(path).unwrap();
}
