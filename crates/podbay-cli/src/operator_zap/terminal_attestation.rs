//! Pure terminal assertion authentication, not terminal observation or authority.
//! Trust-anchor acquisition, historical key provenance and OS proof are external.
#![allow(dead_code)]
use ed25519_compact::{PublicKey, Signature};

const DOMAIN: &[u8] = b"podbay.operator-zap-terminal-attestation/1\0";
const VERSION: u8 = 1;
const MAX_BYTES: usize = 8192;

#[derive(Clone, Debug, PartialEq, Eq)]
struct SignerBindingV1 {
    lineage: String,
    actor: String,
    scope: String,
    generation: u64,
    binding_digest: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct TrustedSignerV1 {
    binding: SignerBindingV1,
    public_key: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct SubjectV1 {
    version: u8,
    signer: SignerBindingV1,
    policy_digest: [u8; 32],
    launch_command: String,
    launch_receipt_digest: [u8; 32],
    stop_key: String,
    stop_intent_digest: [u8; 32],
    pod: String,
    incarnation: u64,
    session: String,
    run: String,
    attempt: String,
    resource: String,
    manifest_digest: [u8; 32],
    unit: String,
    boot: String,
    supervisor_pid: u32,
    supervisor_birth: u64,
    child_pid: u32,
    child_birth: u64,
    socket_device: u64,
    socket_inode: u64,
    terminal_observation_digest: [u8; 32],
    pod_artifact: [u8; 32],
    node_artifact: [u8; 32],
    zap_artifact: [u8; 32],
    configuration_digest: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct SignedAssertionV1 {
    subject: SubjectV1,
    signature: [u8; 64],
}
/// Inert authenticated bytes. It grants no stop, restart, launch or OS capability.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthenticatedAssertionV1 {
    subject: SubjectV1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Error {
    InvalidSubject,
    ExpectedMismatch,
    SignerMismatch,
    InvalidKey,
    InvalidSignature,
}

fn put(out: &mut Vec<u8>, tag: u8, bytes: &[u8]) -> Result<(), Error> {
    let n = u16::try_from(bytes.len()).map_err(|_| Error::InvalidSubject)?;
    out.push(tag);
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(bytes);
    if out.len() > MAX_BYTES {
        return Err(Error::InvalidSubject);
    }
    Ok(())
}
fn text(out: &mut Vec<u8>, tag: u8, value: &str) -> Result<(), Error> {
    if value.is_empty() || value.len() > 256 || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Error::InvalidSubject);
    }
    put(out, tag, value.as_bytes())
}
fn hash(out: &mut Vec<u8>, tag: u8, value: &[u8; 32]) -> Result<(), Error> {
    if *value == [0; 32] {
        return Err(Error::InvalidSubject);
    }
    put(out, tag, value)
}
fn number(out: &mut Vec<u8>, tag: u8, value: u64) -> Result<(), Error> {
    if value == 0 {
        return Err(Error::InvalidSubject);
    }
    put(out, tag, &value.to_be_bytes())
}

/// Fixed ordered tags, u16 byte lengths and u64 big-endian numbers. Outcome tag
/// 255 is exactly terminal-observed; this schema has no live/unknown outcome.
fn transcript(s: &SubjectV1) -> Result<Vec<u8>, Error> {
    if s.version != VERSION {
        return Err(Error::InvalidSubject);
    }
    let mut out = DOMAIN.to_vec();
    out.push(s.version);
    text(&mut out, 1, &s.signer.lineage)?;
    text(&mut out, 2, &s.signer.actor)?;
    text(&mut out, 3, &s.signer.scope)?;
    number(&mut out, 4, s.signer.generation)?;
    hash(&mut out, 5, &s.signer.binding_digest)?;
    hash(&mut out, 6, &s.policy_digest)?;
    text(&mut out, 7, &s.launch_command)?;
    hash(&mut out, 8, &s.launch_receipt_digest)?;
    text(&mut out, 9, &s.stop_key)?;
    hash(&mut out, 10, &s.stop_intent_digest)?;
    text(&mut out, 11, &s.pod)?;
    number(&mut out, 12, s.incarnation)?;
    text(&mut out, 13, &s.session)?;
    text(&mut out, 14, &s.run)?;
    text(&mut out, 15, &s.attempt)?;
    text(&mut out, 16, &s.resource)?;
    hash(&mut out, 17, &s.manifest_digest)?;
    text(&mut out, 18, &s.unit)?;
    text(&mut out, 19, &s.boot)?;
    number(&mut out, 20, s.supervisor_pid as u64)?;
    number(&mut out, 21, s.supervisor_birth)?;
    number(&mut out, 22, s.child_pid as u64)?;
    number(&mut out, 23, s.child_birth)?;
    number(&mut out, 24, s.socket_device)?;
    number(&mut out, 25, s.socket_inode)?;
    hash(&mut out, 26, &s.terminal_observation_digest)?;
    hash(&mut out, 27, &s.pod_artifact)?;
    hash(&mut out, 28, &s.node_artifact)?;
    hash(&mut out, 29, &s.zap_artifact)?;
    hash(&mut out, 30, &s.configuration_digest)?;
    put(&mut out, 255, &[1])?;
    Ok(out)
}

fn verify(
    receipt: &SignedAssertionV1,
    expected: &SubjectV1,
    trusted: &TrustedSignerV1,
) -> Result<AuthenticatedAssertionV1, Error> {
    transcript(expected)?;
    let bytes = transcript(&receipt.subject)?;
    if receipt.subject != *expected {
        return Err(Error::ExpectedMismatch);
    }
    if receipt.subject.signer != trusted.binding {
        return Err(Error::SignerMismatch);
    }
    let key = PublicKey::from_slice(&trusted.public_key).map_err(|_| Error::InvalidKey)?;
    key.validate().map_err(|_| Error::InvalidKey)?;
    let sig = Signature::from_slice(&receipt.signature).map_err(|_| Error::InvalidSignature)?;
    key.verify(&bytes, &sig)
        .map_err(|_| Error::InvalidSignature)?;
    Ok(AuthenticatedAssertionV1 {
        subject: receipt.subject.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_compact::{KeyPair, Seed};
    fn fixture() -> (SubjectV1, TrustedSignerV1, KeyPair) {
        let key = KeyPair::from_seed(Seed::new([7; 32]));
        let signer = SignerBindingV1 {
            lineage: "lineage.one".into(),
            actor: "owner.one".into(),
            scope: "scope.one".into(),
            generation: 3,
            binding_digest: [1; 32],
        };
        let s = SubjectV1 {
            version: 1,
            signer: signer.clone(),
            policy_digest: [2; 32],
            launch_command: "launch.one".into(),
            launch_receipt_digest: [3; 32],
            stop_key: "stop.one".into(),
            stop_intent_digest: [4; 32],
            pod: "pod.one".into(),
            incarnation: 1,
            session: "session.one".into(),
            run: "run.one".into(),
            attempt: "attempt.one".into(),
            resource: "resource.one".into(),
            manifest_digest: [5; 32],
            unit: "podbay-pod-one.service".into(),
            boot: "boot.one".into(),
            supervisor_pid: 101,
            supervisor_birth: 102,
            child_pid: 103,
            child_birth: 104,
            socket_device: 105,
            socket_inode: 106,
            terminal_observation_digest: [6; 32],
            pod_artifact: [8; 32],
            node_artifact: [9; 32],
            zap_artifact: [10; 32],
            configuration_digest: [11; 32],
        };
        (
            s,
            TrustedSignerV1 {
                binding: signer,
                public_key: *key.pk,
            },
            key,
        )
    }
    fn sign(s: &SubjectV1, key: &KeyPair) -> SignedAssertionV1 {
        SignedAssertionV1 {
            subject: s.clone(),
            signature: *key.sk.sign(transcript(s).unwrap(), None),
        }
    }
    #[test]
    fn exact_transcript_replay_is_deterministic_and_inert() {
        let (s, t, k) = fixture();
        let receipt = sign(&s, &k);
        assert_eq!(sign(&s, &k), receipt);
        let result = verify(&receipt, &s, &t).unwrap();
        assert_eq!(result.subject, s);
        assert_eq!(verify(&receipt, &s, &t).unwrap(), result);
        let bytes = transcript(&s).unwrap();
        assert!(bytes.starts_with(DOMAIN));
        assert!(bytes.len() <= MAX_BYTES);
        assert_eq!(&bytes[bytes.len() - 4..], &[255, 0, 1, 1]);
    }
    #[test]
    fn every_subject_field_is_bound() {
        let (s, t, k) = fixture();
        let receipt = sign(&s, &k);
        for field in 0..31 {
            let mut changed = s.clone();
            match field {
                0 => changed.version = 2,
                1 => changed.signer.lineage = "other".into(),
                2 => changed.signer.actor = "other".into(),
                3 => changed.signer.scope = "other".into(),
                4 => changed.signer.generation += 1,
                5 => changed.signer.binding_digest = [12; 32],
                6 => changed.policy_digest = [12; 32],
                7 => changed.launch_command = "other".into(),
                8 => changed.launch_receipt_digest = [12; 32],
                9 => changed.stop_key = "other".into(),
                10 => changed.stop_intent_digest = [12; 32],
                11 => changed.pod = "other".into(),
                12 => changed.incarnation += 1,
                13 => changed.session = "other".into(),
                14 => changed.run = "other".into(),
                15 => changed.attempt = "other".into(),
                16 => changed.resource = "other".into(),
                17 => changed.manifest_digest = [12; 32],
                18 => changed.unit = "other".into(),
                19 => changed.boot = "other".into(),
                20 => changed.supervisor_pid += 1,
                21 => changed.supervisor_birth += 1,
                22 => changed.child_pid += 1,
                23 => changed.child_birth += 1,
                24 => changed.socket_device += 1,
                25 => changed.socket_inode += 1,
                26 => changed.terminal_observation_digest = [12; 32],
                27 => changed.pod_artifact = [12; 32],
                28 => changed.node_artifact = [12; 32],
                29 => changed.zap_artifact = [12; 32],
                _ => changed.configuration_digest = [12; 32],
            };
            let altered = SignedAssertionV1 {
                subject: changed.clone(),
                signature: receipt.signature,
            };
            assert!(verify(&altered, &s, &t).is_err(), "field {field}");
            assert!(
                verify(&altered, &changed, &t).is_err(),
                "coherent field {field}"
            );
        }
    }
    #[test]
    fn trusted_key_and_binding_cannot_be_selected_by_receipt() {
        let (s, t, k) = fixture();
        let receipt = sign(&s, &k);
        let other = KeyPair::from_seed(Seed::new([13; 32]));
        let impostor = sign(&s, &other);
        assert_eq!(verify(&impostor, &s, &t), Err(Error::InvalidSignature));
        let mut foreign = t.clone();
        foreign.binding.generation += 1;
        assert_eq!(verify(&receipt, &s, &foreign), Err(Error::SignerMismatch));
        for bytes in [[0; 32], [255; 32]] {
            foreign = t.clone();
            foreign.public_key = bytes;
            assert!(verify(&receipt, &s, &foreign).is_err());
        }
        let mut forged = receipt;
        for index in 0..64 {
            forged.signature[index] ^= 1;
            assert!(verify(&forged, &s, &t).is_err());
            forged.signature[index] ^= 1;
        }
    }
    #[test]
    fn foreign_domains_and_unsigned_legacy_body_cannot_authenticate() {
        let (s, t, k) = fixture();
        let correct = transcript(&s).unwrap();
        for domain in [
            b"podbay.actor-credential.challenge\0".as_slice(),
            b"podbay.owner-recovery/1\0",
            b"podbay.initial-owner-enrollment/1\0",
        ] {
            let mut bytes = domain.to_vec();
            bytes.extend_from_slice(&correct[DOMAIN.len()..]);
            let receipt = SignedAssertionV1 {
                subject: s.clone(),
                signature: *k.sk.sign(bytes, None),
            };
            assert_eq!(verify(&receipt, &s, &t), Err(Error::InvalidSignature));
        }
        let legacy = super::super::StopTerminal {
            schema: super::super::STOP_TERMINAL_SCHEMA.into(),
            policy_digest: "legacy".into(),
            stop_key: s.stop_key.clone(),
            launch_command_id: s.launch_command.clone(),
            intent_digest: "legacy-intent".into(),
        };
        let legacy_bytes = serde_json::to_vec(&legacy).unwrap();
        let receipt = SignedAssertionV1 {
            subject: s.clone(),
            signature: *k.sk.sign(legacy_bytes, None),
        };
        assert_eq!(verify(&receipt, &s, &t), Err(Error::InvalidSignature));
        let unsigned = SignedAssertionV1 {
            subject: s.clone(),
            signature: [0; 64],
        };
        assert_eq!(verify(&unsigned, &s, &t), Err(Error::InvalidSignature));
        let mut outcome = correct;
        let last = outcome.len() - 1;
        outcome[last] = 2;
        let receipt = SignedAssertionV1 {
            subject: s.clone(),
            signature: *k.sk.sign(outcome, None),
        };
        assert_eq!(verify(&receipt, &s, &t), Err(Error::InvalidSignature));
    }
    #[test]
    fn bounds_empty_and_zero_inputs_refuse() {
        let (s, _, _) = fixture();
        let mut bounded = s.clone();
        bounded.unit = "a".repeat(256);
        assert!(transcript(&bounded).is_ok());
        bounded.unit.push('a');
        assert_eq!(transcript(&bounded), Err(Error::InvalidSubject));
        for case in 0..5 {
            let mut bad = s.clone();
            match case {
                0 => bad.unit.clear(),
                1 => bad.boot = "bad boot".into(),
                2 => bad.child_birth = 0,
                3 => bad.terminal_observation_digest = [0; 32],
                _ => bad.signer.generation = 0,
            };
            assert_eq!(transcript(&bad), Err(Error::InvalidSubject));
        }
        bounded = s;
        bounded.supervisor_birth = u64::MAX;
        assert!(transcript(&bounded).is_ok());
    }
}
