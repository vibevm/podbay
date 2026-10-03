use std::io::{self, Read, Write};

use podbay_client::{ClientFault, MutationError, PodBayClient, ReadError};
use podbay_wire::{
    CommandEnvelope, CommandStage, EmptyReadBody, ErrorEnvelope, ProtocolVersion, ReadBody,
    ReadEnvelope, Receipt, SuccessEnvelope, Target, WireError, decode_command_json,
    decode_frame_bytes, encode_frame,
};
use serde_json::Value;

struct FakeStream {
    written: Vec<u8>,
    reply: Vec<u8>,
    read_at: usize,
    write_chunk: usize,
    fail_write_after: Option<usize>,
}
impl FakeStream {
    fn new(reply: Vec<u8>) -> Self {
        Self {
            written: Vec::new(),
            reply,
            read_at: 0,
            write_chunk: usize::MAX,
            fail_write_after: None,
        }
    }
}
impl Read for FakeStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = output
            .len()
            .min(3)
            .min(self.reply.len().saturating_sub(self.read_at));
        output[..count].copy_from_slice(&self.reply[self.read_at..self.read_at + count]);
        self.read_at += count;
        Ok(count)
    }
}
impl Write for FakeStream {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if self
            .fail_write_after
            .is_some_and(|at| self.written.len() >= at)
        {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "synthetic partial write",
            ));
        }
        let count = input.len().min(self.write_chunk).min(
            self.fail_write_after
                .map_or(usize::MAX, |at| at.saturating_sub(self.written.len())),
        );
        self.written.extend_from_slice(&input[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn command() -> CommandEnvelope {
    decode_command_json(include_bytes!(
        "../../../schema/v1/command-resource-write.json"
    ))
    .unwrap()
}
fn receipt() -> Receipt<Value> {
    serde_json::from_slice(include_bytes!("../../../schema/v1/receipt-persisted.json")).unwrap()
}
fn reply<T: serde::Serialize>(request_id: &str, ok: T) -> Vec<u8> {
    encode_frame(&SuccessEnvelope {
        protocol: ProtocolVersion::V1,
        request_id: request_id.into(),
        ok,
    })
    .unwrap()
}
fn encode_raw(bytes: &[u8]) -> Vec<u8> {
    let mut frame = (bytes.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(bytes);
    frame
}

#[test]
fn partial_writes_and_reads_preserve_exact_request_and_receipt() {
    let command = command();
    let mut stream = FakeStream::new(reply(&command.request_id, receipt()));
    stream.write_chunk = 2;
    let mut client = PodBayClient::new(stream);
    let received: Receipt<Value> = client.command(&command).unwrap();
    assert_eq!(received.state, CommandStage::Persisted);
    let stream = client.into_inner();
    let sent = decode_frame_bytes(&stream.written).unwrap();
    let decoded = decode_command_json(sent).unwrap();
    assert_eq!(decoded.key, command.key);
    assert_eq!(decoded.payload_digest, command.payload_digest);
    assert_eq!(decoded.request_id, command.request_id);
}

#[test]
fn lost_reply_and_partial_write_are_uncertain_with_original_key_and_no_resend() {
    let command = command();
    let mut client = PodBayClient::new(FakeStream::new(Vec::new()));
    match client.command::<Value>(&command) {
        Err(MutationError::Uncertain {
            key,
            request_id,
            cause: ClientFault::Io(_),
        }) => {
            assert_eq!(key, command.key);
            assert_eq!(request_id, command.request_id);
        }
        other => panic!("expected uncertain lost reply: {other:?}"),
    }
    assert!(client.is_poisoned());
    assert!(matches!(
        client.command::<Value>(&command),
        Err(MutationError::NotSent(ClientFault::Poisoned))
    ));
    assert!(client.into_inner().written.len() > 0);

    let mut stream = FakeStream::new(reply(&command.request_id, receipt()));
    stream.write_chunk = 2;
    stream.fail_write_after = Some(5);
    let mut client = PodBayClient::new(stream);
    assert!(
        matches!(client.command::<Value>(&command), Err(MutationError::Uncertain { key, .. }) if key == command.key)
    );
    assert_eq!(client.into_inner().written.len(), 5);
}

#[test]
fn malformed_oversized_or_uncorrelated_reply_poison_mutation_transport() {
    let command = command();
    for reply in [
        vec![0, 16, 0, 1],
        encode_raw(b"not-json"),
        reply("request.other", receipt()),
    ] {
        let mut client = PodBayClient::new(FakeStream::new(reply));
        assert!(
            matches!(client.command::<Value>(&command), Err(MutationError::Uncertain { key, .. }) if key == command.key)
        );
        assert!(client.is_poisoned());
    }
}

#[test]
fn structured_server_error_is_correlated_and_local_validation_writes_nothing() {
    let command = command();
    let error: ErrorEnvelope =
        serde_json::from_slice(include_bytes!("../../../schema/v1/error-stale-guard.json"))
            .unwrap();
    let mut client = PodBayClient::new(FakeStream::new(encode_frame(&error).unwrap()));
    match client.command::<Value>(&command) {
        Err(MutationError::Server { key, envelope }) => {
            assert_eq!(key, command.key);
            assert_eq!(
                envelope.error.code,
                podbay_wire::RuntimeErrorCode::StaleGuard
            );
            assert_eq!(envelope.request_id, command.request_id);
        }
        other => panic!("expected structured server refusal: {other:?}"),
    }
    assert!(!client.is_poisoned());

    let mut invalid = command;
    invalid.payload_digest = "tampered".into();
    let mut client = PodBayClient::new(FakeStream::new(Vec::new()));
    assert!(matches!(
        client.command::<Value>(&invalid),
        Err(MutationError::BeforeEffect(WireError::DigestMismatch))
    ));
    assert!(client.into_inner().written.is_empty());
}

#[test]
fn server_uncertain_and_admitted_deadline_keep_key_and_command_reference() {
    let command = command();
    let original: ErrorEnvelope =
        serde_json::from_slice(include_bytes!("../../../schema/v1/error-stale-guard.json"))
            .unwrap();
    for code in [
        podbay_wire::RuntimeErrorCode::Uncertain,
        podbay_wire::RuntimeErrorCode::DeadlineExceeded,
    ] {
        let mut error = original.clone();
        error.error.code = code;
        let mut client = PodBayClient::new(FakeStream::new(encode_frame(&error).unwrap()));
        match client.command::<Value>(&command) {
            Err(MutationError::ServerUncertain { key, envelope }) => {
                assert_eq!(key, command.key);
                assert_eq!(
                    envelope.error.command_id.as_deref(),
                    Some("command.fixture.1")
                );
                assert_eq!(envelope.error.code, code);
            }
            other => panic!("expected server uncertainty: {other:?}"),
        }
        assert!(!client.is_poisoned());
    }
}

#[test]
fn read_transport_loss_is_unavailable_and_read_request_is_correlated() {
    let request = ReadEnvelope::new(
        "request.read.1",
        Target::Scope {
            scope_id: "project.fixture".into(),
        },
        ReadBody::CapabilitiesGet(EmptyReadBody {}),
    )
    .unwrap();
    let mut lost = PodBayClient::new(FakeStream::new(Vec::new()));
    assert!(matches!(
        lost.read::<Value>(&request),
        Err(ReadError::Unavailable(ClientFault::Io(_)))
    ));
    let mut client = PodBayClient::new(FakeStream::new(reply(
        &request.request_id,
        serde_json::json!({"ready": true}),
    )));
    let value: Value = client.read(&request).unwrap();
    assert_eq!(value["ready"], true);
}
