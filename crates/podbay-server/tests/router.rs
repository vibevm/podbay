use std::cell::Cell;
use std::io::{self, Cursor, Read, Write};

use podbay_client::{MutationError, PodBayClient};
use podbay_host::{
    AuthenticatedPeer, AuthenticatedProcessSubject, AuthenticatedTransport, CredentialGeneration,
    HostError,
};
use podbay_server::{Handler, ServerFault, serve_one};
use podbay_wire::{
    CommandEnvelope, ErrorEnvelope, MutationOperation, ReadEnvelope, ReadOperation, Receipt,
    RuntimeError, RuntimeErrorCode, Target, decode_frame_bytes, encode_frame,
};
use serde_json::{Value, json};

fn peer() -> AuthenticatedPeer {
    AuthenticatedPeer::owner_cli_from_authenticated_transport(
        AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(
            1000,
            2345,
            9,
            "/podbay.test",
        )
        .unwrap(),
        CredentialGeneration::new(1).unwrap(),
    )
}

struct ProbeStream {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    read_calls: usize,
    authenticated: bool,
}
impl ProbeStream {
    fn new(input: Vec<u8>, authenticated: bool) -> Self {
        Self {
            input: Cursor::new(input),
            output: Vec::new(),
            read_calls: 0,
            authenticated,
        }
    }
}
impl Read for ProbeStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.read_calls += 1;
        self.input.read(bytes)
    }
}
impl Write for ProbeStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl AuthenticatedTransport for ProbeStream {
    fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError> {
        if self.authenticated {
            Ok(peer())
        } else {
            Err(HostError::Unauthenticated)
        }
    }
}

#[derive(Default)]
struct FakeHandler {
    calls: usize,
    keys: Vec<String>,
}
impl Handler for FakeHandler {
    fn command<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        request: CommandEnvelope,
    ) -> Result<Receipt<Value>, RuntimeError> {
        transport.verified_peer().map_err(|_| denied_peer())?;
        self.calls += 1;
        self.keys.push(request.key);
        Err(RuntimeError {
            code: RuntimeErrorCode::Uncertain,
            message: "admission outcome must be queried".into(),
            retry: "query_command".into(),
            command_id: Some("command.fixture".into()),
        })
    }
    fn read<T: AuthenticatedTransport>(
        &mut self,
        transport: &T,
        _: ReadEnvelope,
    ) -> Result<Value, RuntimeError> {
        transport.verified_peer().map_err(|_| denied_peer())?;
        self.calls += 1;
        Ok(json!({"state":"ready"}))
    }
}
fn denied_peer() -> RuntimeError {
    RuntimeError {
        code: RuntimeErrorCode::Forbidden,
        message: "peer generation changed before admission".into(),
        retry: "never".into(),
        command_id: None,
    }
}

fn read_request() -> ReadEnvelope {
    ReadEnvelope::new_json(
        "request.read",
        Target::Scope {
            scope_id: "scope.fixture".into(),
        },
        ReadOperation::CapabilitiesGet,
        json!({}),
    )
    .unwrap()
}
fn command_request() -> CommandEnvelope {
    CommandEnvelope::new_json(
        "request.command",
        "key.exact",
        Target::Session {
            session_id: "session.fixture".into(),
        },
        None,
        None,
        MutationOperation::SessionClose,
        json!({}),
    )
    .unwrap()
}

#[test]
fn unauthenticated_transport_is_not_even_read() {
    let mut stream = ProbeStream::new(
        encode_frame(&json!({"protocol":"podbay/1"})).unwrap(),
        false,
    );
    let mut handler = FakeHandler::default();
    assert!(matches!(
        serve_one(&mut stream, &mut handler),
        Err(ServerFault::Unauthenticated)
    ));
    assert_eq!(stream.read_calls, 0);
    assert_eq!(handler.calls, 0);
    assert!(stream.output.is_empty());
}

struct ChangingPeerStream {
    inner: ProbeStream,
    checks: Cell<u32>,
    change_after: u32,
}
impl Read for ChangingPeerStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.inner.read(bytes)
    }
}
impl Write for ChangingPeerStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
impl AuthenticatedTransport for ChangingPeerStream {
    fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError> {
        let count = self.checks.get();
        self.checks.set(count + 1);
        if count < self.change_after {
            Ok(peer())
        } else {
            Ok(AuthenticatedPeer::owner_cli_from_authenticated_transport(
                AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(
                    1000,
                    2345,
                    9,
                    "/podbay.test",
                )
                .unwrap(),
                CredentialGeneration::new(2).unwrap(),
            ))
        }
    }
}
#[test]
fn peer_generation_change_before_dispatch_fences_handler() {
    let input = encode_frame(
        &serde_json::from_slice::<Value>(&read_request().encode_json().unwrap()).unwrap(),
    )
    .unwrap();
    let mut stream = ChangingPeerStream {
        inner: ProbeStream::new(input, true),
        checks: Cell::new(0),
        change_after: 1,
    };
    let mut handler = FakeHandler::default();
    assert!(matches!(
        serve_one(&mut stream, &mut handler),
        Err(ServerFault::Unauthenticated)
    ));
    assert_eq!(handler.calls, 0);
    assert_eq!(stream.checks.get(), 2);
    assert!(stream.inner.output.is_empty());
}

#[test]
fn handler_side_live_witness_catches_change_after_router_check() {
    let input = encode_frame(
        &serde_json::from_slice::<Value>(&command_request().encode_json().unwrap()).unwrap(),
    )
    .unwrap();
    let mut stream = ChangingPeerStream {
        inner: ProbeStream::new(input, true),
        checks: Cell::new(0),
        change_after: 2,
    };
    let mut handler = FakeHandler::default();
    serve_one(&mut stream, &mut handler).unwrap();
    assert_eq!(stream.checks.get(), 3);
    assert_eq!(handler.calls, 0);
    let error: ErrorEnvelope =
        serde_json::from_slice(decode_frame_bytes(&stream.inner.output).unwrap()).unwrap();
    assert_eq!(error.request_id, "request.command");
    assert_eq!(error.error.code, RuntimeErrorCode::Forbidden);
}

#[test]
fn bad_digest_unknown_operation_and_oversize_never_dispatch() {
    let command = command_request();
    let mut value: Value = serde_json::from_slice(&command.encode_json().unwrap()).unwrap();
    value["payloadDigest"] = json!("0".repeat(64));
    let mut stream = ProbeStream::new(encode_frame(&value).unwrap(), true);
    let mut handler = FakeHandler::default();
    serve_one(&mut stream, &mut handler).unwrap();
    let error: ErrorEnvelope =
        serde_json::from_slice(decode_frame_bytes(&stream.output).unwrap()).unwrap();
    assert_eq!(error.request_id, "request.command");
    assert_eq!(error.error.code, RuntimeErrorCode::InvalidInput);
    assert_eq!(handler.calls, 0);

    let mut stream = ProbeStream::new(
        encode_frame(&json!({"protocol":"podbay/1",
        "requestId":"request.unknown","operation":"future.mutate"}))
        .unwrap(),
        true,
    );
    serve_one(&mut stream, &mut handler).unwrap();
    let error: ErrorEnvelope =
        serde_json::from_slice(decode_frame_bytes(&stream.output).unwrap()).unwrap();
    assert_eq!(error.error.code, RuntimeErrorCode::Unsupported);
    assert_eq!(handler.calls, 0);

    let mut stream = ProbeStream::new(
        ((podbay_wire::MAX_FRAME_BYTES + 1) as u32)
            .to_be_bytes()
            .to_vec(),
        true,
    );
    serve_one(&mut stream, &mut handler).unwrap();
    assert_eq!(handler.calls, 0);
    let error: ErrorEnvelope =
        serde_json::from_slice(decode_frame_bytes(&stream.output).unwrap()).unwrap();
    assert_eq!(error.error.code, RuntimeErrorCode::InvalidInput);
}

#[test]
fn valid_wire_request_ids_remain_correlated_on_malformed_body() {
    let mut handler = FakeHandler::default();
    for request_id in ["request with spaces".to_owned(), "x".repeat(200)] {
        let malformed = json!({"protocol":"podbay/1", "operation":"capabilities.get",
            "requestId":request_id, "target":{"kind":"scope","scopeId":"scope.fixture"},
            "body":{"unexpected":true}});
        let mut stream = ProbeStream::new(encode_frame(&malformed).unwrap(), true);
        serve_one(&mut stream, &mut handler).unwrap();
        let error: ErrorEnvelope =
            serde_json::from_slice(decode_frame_bytes(&stream.output).unwrap()).unwrap();
        assert_eq!(error.request_id, request_id);
        assert_eq!(error.error.code, RuntimeErrorCode::InvalidInput);
    }
    assert_eq!(handler.calls, 0);
}

struct BrokenOutputStream(ProbeStream);
impl Read for BrokenOutputStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.0.read(bytes)
    }
}
impl Write for BrokenOutputStream {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl AuthenticatedTransport for BrokenOutputStream {
    fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError> {
        Ok(peer())
    }
}
#[test]
fn lost_admitted_reply_retains_key_and_command_identity() {
    let command = command_request();
    let value: Value = serde_json::from_slice(&command.encode_json().unwrap()).unwrap();
    let mut stream = BrokenOutputStream(ProbeStream::new(encode_frame(&value).unwrap(), true));
    let mut handler = FakeHandler::default();
    match serve_one(&mut stream, &mut handler) {
        Err(ServerFault::ResponseLost {
            key, command_id, ..
        }) => {
            assert_eq!(key.as_deref(), Some("key.exact"));
            assert_eq!(command_id.as_deref(), Some("command.fixture"));
        }
        other => panic!("expected uncertain response loss, got {other:?}"),
    }
    assert_eq!(handler.calls, 1);
}

mod memory_roundtrip {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::mpsc;
    use std::thread;

    struct Duplex {
        receiver: mpsc::Receiver<Vec<u8>>,
        sender: mpsc::Sender<Vec<u8>>,
        pending: VecDeque<u8>,
    }
    impl Duplex {
        fn pair() -> (Self, Self) {
            let (left_sender, left_receiver) = mpsc::channel();
            let (right_sender, right_receiver) = mpsc::channel();
            (
                Self {
                    receiver: left_receiver,
                    sender: right_sender,
                    pending: VecDeque::new(),
                },
                Self {
                    receiver: right_receiver,
                    sender: left_sender,
                    pending: VecDeque::new(),
                },
            )
        }
    }
    impl Read for Duplex {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if bytes.is_empty() {
                return Ok(0);
            }
            while self.pending.is_empty() {
                let next = self
                    .receiver
                    .recv()
                    .map_err(|_| io::Error::from(io::ErrorKind::UnexpectedEof))?;
                self.pending.extend(next);
            }
            let count = bytes.len().min(self.pending.len());
            for byte in &mut bytes[..count] {
                *byte = self.pending.pop_front().unwrap();
            }
            Ok(count)
        }
    }
    impl Write for Duplex {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.sender
                .send(bytes.to_vec())
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct AuthorizedStream(Duplex);
    impl Read for AuthorizedStream {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.0.read(bytes)
        }
    }
    impl Write for AuthorizedStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }
    impl AuthenticatedTransport for AuthorizedStream {
        fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError> {
            Ok(peer())
        }
    }
    #[test]
    fn client_and_server_read_envelopes_roundtrip_once() {
        let (server, client) = Duplex::pair();
        let worker = thread::spawn(move || {
            let mut stream = AuthorizedStream(server);
            let mut handler = FakeHandler::default();
            serve_one(&mut stream, &mut handler).unwrap();
            handler.calls
        });
        let mut client = PodBayClient::new(client);
        let reply: Value = client.read(&read_request()).unwrap();
        assert_eq!(reply, json!({"state":"ready"}));
        assert_eq!(worker.join().unwrap(), 1);
    }
    #[test]
    fn uncertain_mutation_preserves_the_exact_key_and_command_id() {
        let (server, client) = Duplex::pair();
        let worker = thread::spawn(move || {
            let mut stream = AuthorizedStream(server);
            let mut handler = FakeHandler::default();
            serve_one(&mut stream, &mut handler).unwrap();
            handler.keys
        });
        let mut client = PodBayClient::new(client);
        let error = client.command::<Value>(&command_request()).unwrap_err();
        match error {
            MutationError::ServerUncertain { key, envelope } => {
                assert_eq!(key, "key.exact");
                assert_eq!(
                    envelope.error.command_id.as_deref(),
                    Some("command.fixture")
                );
            }
            other => panic!("expected admitted uncertainty, got {other:?}"),
        }
        assert_eq!(worker.join().unwrap(), vec!["key.exact"]);
    }
}
