#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use podbay_client::{
    ActorChallengeOrigin, ClientAuthFailureKind, ClientAuthStage, LinuxClientAuthLimits,
    authenticate_existing_linux_stream, authenticate_existing_linux_stream_with_limits,
};
use serde_json::Value;

const ACTOR: &str = "actor.client.fixture";
const ACK: &[u8] = b"{\"protocol\":\"podbay.auth/1\",\"ok\":true}";

#[test]
fn exact_selector_canonical_challenge_signature_and_ack_roundtrip() {
    for pod in [false, true] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let server_task = thread::spawn(move || {
            let selector: Value = serde_json::from_slice(&read_frame(&mut server)).unwrap();
            assert_eq!(selector["protocol"], "podbay.auth/1");
            assert_eq!(selector["actorId"], ACTOR);
            assert_eq!(selector.as_object().unwrap().len(), 2);
            let challenge = challenge(ACTOR, pod);
            let framed = frame(&challenge);
            server.write_all(&framed[..2]).unwrap();
            server.write_all(&framed[2..7]).unwrap();
            server.write_all(&framed[7..]).unwrap();
            let signature = read_frame(&mut server);
            assert_eq!(signature, [9_u8; 64]);
            server.write_all(&frame(ACK)).unwrap();
        });
        let stream = authenticate_existing_linux_stream(client, ACTOR, |challenge| {
            assert_eq!(challenge.store_lineage, "lineage.fixture");
            assert_eq!(challenge.actor_id, ACTOR);
            assert_eq!(challenge.scope_id, "scope.fixture");
            assert_eq!(challenge.credential_generation, 3);
            assert_eq!(challenge.os_identity, "linux.uid.1000");
            assert_eq!(challenge.process_identity, "linux.pid.2000");
            assert_eq!(challenge.start_identity, 777);
            assert_eq!(challenge.containment_identity, "/fixture.scope");
            assert_ne!(challenge.nonce, [0; 32]);
            if pod {
                assert_eq!(
                    challenge.origin,
                    ActorChallengeOrigin::Pod {
                        pod_id: "pod.fixture",
                        incarnation: 2
                    }
                );
            } else {
                assert_eq!(challenge.origin, ActorChallengeOrigin::OwnerCli);
            }
            Some([9; 64])
        })
        .unwrap();
        assert_eq!(
            stream.read_timeout().unwrap(),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            stream.write_timeout().unwrap(),
            Some(Duration::from_secs(30))
        );
        drop(stream);
        server_task.join().unwrap();
    }
}

#[test]
fn malformed_or_wrong_actor_challenge_never_reaches_signer() {
    let mut cases = Vec::new();
    let mut wrong_domain = challenge(ACTOR, false);
    wrong_domain[0] ^= 1;
    cases.push(wrong_domain);
    cases.push(challenge("actor.other", false));
    let mut trailing = challenge(ACTOR, false);
    trailing.push(0);
    cases.push(trailing);
    let mut wrong_tag = challenge(ACTOR, false);
    let tag_at = b"podbay.actor-credential.challenge\0".len() + 1;
    wrong_tag[tag_at] = 99;
    cases.push(wrong_tag);
    for bytes in cases {
        let (client, mut server) = UnixStream::pair().unwrap();
        let server_task = thread::spawn(move || {
            read_frame(&mut server);
            server.write_all(&frame(&bytes)).unwrap();
        });
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let error = authenticate_existing_linux_stream(client, ACTOR, |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            Some([0; 64])
        })
        .err()
        .unwrap();
        assert!(matches!(
            error.kind,
            ClientAuthFailureKind::MalformedChallenge
        ));
        assert_eq!(error.stage, ClientAuthStage::SelectorPossiblyWritten);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        server_task.join().unwrap();
    }
}

#[test]
fn signer_rejection_sends_no_signature() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let server_task = thread::spawn(move || {
        read_frame(&mut server);
        server.write_all(&frame(&challenge(ACTOR, false))).unwrap();
        let mut byte = [0_u8; 1];
        assert_eq!(server.read(&mut byte).unwrap(), 0);
    });
    let error = authenticate_existing_linux_stream(client, ACTOR, |challenge| {
        assert_eq!(challenge.store_lineage, "lineage.fixture");
        None
    })
    .err()
    .unwrap();
    assert!(matches!(error.kind, ClientAuthFailureKind::SignerRejected));
    assert_eq!(error.stage, ClientAuthStage::SelectorPossiblyWritten);
    server_task.join().unwrap();
}

#[test]
fn lost_or_malformed_ack_is_after_possible_signature_write_without_retry() {
    for ack in [
        None,
        Some(b"{\"protocol\":\"podbay.auth/1\",\"ok\":false}".as_slice()),
    ] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let server_task = thread::spawn(move || {
            read_frame(&mut server);
            server.write_all(&frame(&challenge(ACTOR, false))).unwrap();
            assert_eq!(read_frame(&mut server), [7_u8; 64]);
            if let Some(ack) = ack {
                server.write_all(&frame(ack)).unwrap();
            }
        });
        let error = authenticate_existing_linux_stream(client, ACTOR, |_| Some([7; 64]))
            .err()
            .unwrap();
        assert_eq!(error.stage, ClientAuthStage::SignaturePossiblyWritten);
        if ack.is_none() {
            assert!(matches!(error.kind, ClientAuthFailureKind::Io(_)));
        } else {
            assert!(matches!(
                error.kind,
                ClientAuthFailureKind::MalformedAcknowledgement
            ));
        }
        server_task.join().unwrap();
    }
}

#[test]
fn oversized_challenge_and_ack_fail_before_acceptance() {
    for oversized_ack in [false, true] {
        let (client, mut server) = UnixStream::pair().unwrap();
        let server_task = thread::spawn(move || {
            read_frame(&mut server);
            if oversized_ack {
                server.write_all(&frame(&challenge(ACTOR, false))).unwrap();
                assert_eq!(read_frame(&mut server), [1_u8; 64]);
                server
                    .write_all(&((ACK.len() + 1) as u32).to_be_bytes())
                    .unwrap();
            } else {
                server.write_all(&(8_193_u32).to_be_bytes()).unwrap();
            }
        });
        let error = authenticate_existing_linux_stream(client, ACTOR, |_| Some([1; 64]))
            .err()
            .unwrap();
        if oversized_ack {
            assert_eq!(error.stage, ClientAuthStage::SignaturePossiblyWritten);
            assert!(matches!(
                error.kind,
                ClientAuthFailureKind::MalformedAcknowledgement
            ));
        } else {
            assert_eq!(error.stage, ClientAuthStage::SelectorPossiblyWritten);
            assert!(matches!(
                error.kind,
                ClientAuthFailureKind::MalformedChallenge
            ));
        }
        server_task.join().unwrap();
    }
}

#[test]
fn partial_challenge_deadline_and_closed_peer_preserve_phase() {
    let (client, mut server) = UnixStream::pair().unwrap();
    let server_task = thread::spawn(move || {
        read_frame(&mut server);
        server.write_all(&[0, 0]).unwrap();
        thread::sleep(Duration::from_millis(150));
    });
    let limits =
        LinuxClientAuthLimits::new(Duration::from_millis(40), Duration::from_secs(1)).unwrap();
    let error =
        authenticate_existing_linux_stream_with_limits(client, ACTOR, limits, |_| Some([0; 64]))
            .err()
            .unwrap();
    assert_eq!(error.stage, ClientAuthStage::SelectorPossiblyWritten);
    assert!(matches!(error.kind, ClientAuthFailureKind::Io(_)));
    server_task.join().unwrap();

    let (client, server) = UnixStream::pair().unwrap();
    drop(server);
    let error = authenticate_existing_linux_stream(client, ACTOR, |_| Some([0; 64]))
        .err()
        .unwrap();
    assert_eq!(error.stage, ClientAuthStage::SelectorPossiblyWritten);
}

fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut result = (bytes.len() as u32).to_be_bytes().to_vec();
    result.extend_from_slice(bytes);
    result
}

fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).unwrap();
    let mut bytes = vec![0_u8; u32::from_be_bytes(prefix) as usize];
    stream.read_exact(&mut bytes).unwrap();
    bytes
}

fn put(bytes: &mut Vec<u8>, tag: u8, value: &[u8]) {
    bytes.push(tag);
    bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn challenge(actor: &str, pod: bool) -> Vec<u8> {
    let mut bytes = b"podbay.actor-credential.challenge\0".to_vec();
    bytes.push(1);
    put(&mut bytes, 1, &[3; 32]);
    put(&mut bytes, 2, b"lineage.fixture");
    put(&mut bytes, 3, actor.as_bytes());
    put(&mut bytes, 4, b"scope.fixture");
    put(&mut bytes, 5, &3_u64.to_be_bytes());
    put(&mut bytes, 6, &[1]);
    put(&mut bytes, 7, b"linux.uid.1000");
    put(&mut bytes, 8, b"linux.pid.2000");
    put(&mut bytes, 9, &777_u64.to_be_bytes());
    put(&mut bytes, 10, b"/fixture.scope");
    put(&mut bytes, 11, &[if pod { 2 } else { 1 }]);
    if pod {
        put(&mut bytes, 12, b"pod.fixture");
        put(&mut bytes, 13, &2_u64.to_be_bytes());
    }
    bytes
}
