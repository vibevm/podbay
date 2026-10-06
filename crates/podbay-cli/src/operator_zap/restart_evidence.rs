//! Bounded passive prototype. No production origin constructor is available.
//! Filesystem privacy, caller JSON and matching rows never become origin proof.
//! Even a valid signature is refused until independent signing-time admission.
#![allow(dead_code)]
use super::{historical_signer, terminal_attestation};
use std::path::Path;
use terminal_attestation::{EnvelopeError, SubjectV1};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EvidenceRefusal {
    OriginUnavailable,
    Envelope(EnvelopeError),
    HistoricalSigner(historical_signer::Error),
    Authentication(terminal_attestation::Error),
    SigningTimeUnavailable { generation: u64 },
}

/// This type has no safe constructor in a normal production build. The
/// Infallible field makes that restriction explicit, beyond field privacy.
struct AcquiredOrigin {
    readback: podbay_store::HistoricalOwnerReadbackV1,
    expected: SubjectV1,
    #[cfg(not(test))]
    production_construction_disabled: std::convert::Infallible,
}

pub(super) struct RestartEvidenceReader;
impl RestartEvidenceReader {
    /// Deliberately before parsing, stat, policy loading, SQLite, key custody,
    /// publication repair or any other I/O. Existing restart CLI stays closed.
    pub(super) fn read_existing(_policy_path: &Path, _request_key: &str) -> EvidenceRefusal {
        EvidenceRefusal::OriginUnavailable
    }

    /// Pure classification after an independently acquired origin. There is
    /// still no success/verified-terminal return type or generation allocation.
    fn classify(origin: &AcquiredOrigin, bytes: &[u8]) -> EvidenceRefusal {
        let envelope = match terminal_attestation::decode_envelope(bytes) {
            Ok(value) => value,
            Err(error) => return EvidenceRefusal::Envelope(error),
        };
        let expected = &origin.expected;
        let signer = match historical_signer::resolve_readback(
            &expected.signer.lineage,
            &expected.signer.actor,
            &expected.signer.scope,
            &origin.readback,
            expected.signer.generation,
        ) {
            Ok(value) => value,
            Err(error) => return EvidenceRefusal::HistoricalSigner(error),
        };
        if let Err(error) =
            terminal_attestation::authenticate_envelope(&envelope, expected, &signer)
        {
            return EvidenceRefusal::Authentication(error);
        }
        EvidenceRefusal::SigningTimeUnavailable {
            generation: expected.signer.generation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_compact::{KeyPair, Seed};
    use podbay_store::{
        AuthorityActorRecord, AuthorityMutation, PodBayStore, TrustedOwnerRotationProof,
    };
    use rusqlite::Connection;
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Explicit fixture-only origin: a fresh disposable store created by this
    /// test, not a filesystem-privacy or real Owner authentication claim.
    struct Fixture {
        root: PathBuf,
        database: PathBuf,
        readback: podbay_store::HistoricalOwnerReadbackV1,
        key1: KeyPair,
        key2: KeyPair,
    }
    impl Fixture {
        fn new(rotated: bool) -> Self {
            let root = std::env::temp_dir().join(format!(
                "podbay-restart-evidence-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            let database = root.join("schema24.sqlite");
            let key1 = KeyPair::from_seed(Seed::new([7; 32]));
            let key2 = KeyPair::from_seed(Seed::new([8; 32]));
            let mut writer = PodBayStore::open(&database).unwrap();
            let initial = writer.begin_authority_replay(0, 1).unwrap();
            let actor = AuthorityActorRecord {
                actor_id: "owner.fixture".into(),
                scope_id: "scope.fixture".into(),
                role: "coordinator".into(),
                origin: "owner_cli".into(),
                parent_actor_id: None,
                pod_id: None,
                pod_incarnation: None,
                credential_generation: 1,
                platform: "linux".into(),
                os_identity: "linux.uid.1000".into(),
                process_identity: "linux.pid.123".into(),
                start_identity: 456,
                containment_identity: "/fixture.scope".into(),
            };
            let revision = writer
                .apply_authority_mutation(
                    1,
                    initial.revision,
                    AuthorityMutation::PutActor(actor.clone()),
                )
                .unwrap();
            let revision = writer
                .register_actor_verifier_from_trusted_host(1, revision, &actor, *key1.pk)
                .unwrap();
            let lineage: String = Connection::open(&database)
                .unwrap()
                .query_row(
                    "SELECT lineage FROM store_identity WHERE singleton=1",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            if rotated {
                let mut next = actor.clone();
                next.credential_generation = 2;
                next.process_identity = "linux.pid.124".into();
                next.start_identity = 457;
                writer
                    .rotate_owner_actor_from_trusted_host(&TrustedOwnerRotationProof {
                        store_lineage: lineage.clone(),
                        expected_owner_epoch: 1,
                        expected_revision: revision,
                        rotation_key: "rotation.fixture.2".into(),
                        expected_actor: actor.clone(),
                        expected_public_key: *key1.pk,
                        next_actor: next,
                        next_public_key: *key2.pk,
                    })
                    .unwrap();
            }
            // Setup only. The reader never changes journal mode or checkpoints.
            drop(writer);
            let setup = Connection::open(&database).unwrap();
            setup
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;")
                .unwrap();
            drop(setup);
            let before = directory_bytes(&root);
            let mut observer = PodBayStore::open_existing_read_only(&database).unwrap();
            let readback = observer
                .historical_owner_readback_v1(&lineage, &actor.actor_id, &actor.scope_id)
                .unwrap();
            drop(observer);
            assert_eq!(directory_bytes(&root), before);
            Self {
                root,
                database,
                readback,
                key1,
                key2,
            }
        }
        fn origin(&self, generation: u64) -> AcquiredOrigin {
            let binding = if generation == self.readback.actor().credential_generation {
                self.readback.binding_digest()
            } else {
                self.readback.rotations()[0].prior_binding()
            };
            AcquiredOrigin {
                readback: self.readback.clone(),
                expected: SubjectV1 {
                    version: 1,
                    signer: terminal_attestation::SignerBindingV1 {
                        lineage: self.readback.lineage().into(),
                        actor: "owner.fixture".into(),
                        scope: "scope.fixture".into(),
                        generation,
                        binding_digest: binding,
                    },
                    policy_digest: [1; 32],
                    launch_command: "launch.fixture".into(),
                    launch_receipt_digest: [2; 32],
                    stop_key: "stop.fixture".into(),
                    stop_intent_digest: [3; 32],
                    pod: "pod.fixture".into(),
                    incarnation: 1,
                    session: "session.fixture".into(),
                    run: "run.fixture".into(),
                    attempt: "attempt.fixture".into(),
                    resource: "resource.fixture".into(),
                    manifest_digest: [4; 32],
                    unit: "podbay-fixture.service".into(),
                    boot: "boot.fixture".into(),
                    supervisor_pid: 10,
                    supervisor_birth: 11,
                    child_pid: 12,
                    child_birth: 13,
                    socket_device: 14,
                    socket_inode: 15,
                    terminal_observation_digest: [5; 32],
                    pod_artifact: [6; 32],
                    node_artifact: [7; 32],
                    zap_artifact: [8; 32],
                    configuration_digest: [9; 32],
                },
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }
    fn directory_bytes(root: &Path) -> BTreeMap<String, Vec<u8>> {
        fs::read_dir(root)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.file_name().into_string().unwrap(),
                    fs::read(e.path()).unwrap(),
                )
            })
            .collect()
    }
    fn sign(origin: &AcquiredOrigin, key: &KeyPair) -> Vec<u8> {
        terminal_attestation::sign_envelope_for_fixture(&origin.expected, key)
    }

    #[test]
    fn production_origin_unavailable_precedes_all_io() {
        let missing =
            std::env::temp_dir().join("never-create-restart-origin/operator-zap-policy.json");
        assert!(!missing.exists());
        assert_eq!(
            RestartEvidenceReader::read_existing(&missing, "restart.fixture"),
            EvidenceRefusal::OriginUnavailable
        );
        assert!(!missing.exists());
        let f = Fixture::new(false);
        let before = directory_bytes(&f.root);
        assert_eq!(
            RestartEvidenceReader::read_existing(&f.database, "restart.fixture"),
            EvidenceRefusal::OriginUnavailable
        );
        assert_eq!(directory_bytes(&f.root), before);
    }
    #[test]
    fn passive_snapshot_exposure_refuses_writer_and_never_changes_bytes() {
        let f = Fixture::new(true);
        let before = directory_bytes(&f.root);
        for _ in 0..3 {
            let mut r = PodBayStore::open_existing_read_only(&f.database).unwrap();
            assert_eq!(
                r.historical_owner_readback_v1(
                    f.readback.lineage(),
                    "owner.fixture",
                    "scope.fixture"
                )
                .unwrap(),
                f.readback
            );
        }
        assert_eq!(directory_bytes(&f.root), before);
        let mut writer = PodBayStore::open(&f.database).unwrap();
        assert!(
            writer
                .historical_owner_readback_v1(
                    f.readback.lineage(),
                    "owner.fixture",
                    "scope.fixture"
                )
                .is_err()
        );
    }
    #[test]
    fn valid_current_signature_is_not_terminal_authority() {
        let f = Fixture::new(false);
        let origin = f.origin(1);
        let bytes = sign(&origin, &f.key1);
        let before = directory_bytes(&f.root);
        assert_eq!(
            RestartEvidenceReader::classify(&origin, &bytes),
            EvidenceRefusal::SigningTimeUnavailable { generation: 1 }
        );
        assert_eq!(directory_bytes(&f.root), before);
    }
    #[test]
    fn post_rotation_old_key_signature_remains_refused() {
        let f = Fixture::new(true);
        assert_eq!(f.readback.actor().credential_generation, 2);
        let origin = f.origin(1);
        // Signature is deliberately created AFTER the database rotation.
        let bytes = sign(&origin, &f.key1);
        let before = directory_bytes(&f.root);
        assert_eq!(
            RestartEvidenceReader::classify(&origin, &bytes),
            EvidenceRefusal::SigningTimeUnavailable { generation: 1 }
        );
        let current = f.origin(2);
        assert_eq!(
            RestartEvidenceReader::classify(&current, &sign(&current, &f.key2)),
            EvidenceRefusal::SigningTimeUnavailable { generation: 2 }
        );
        assert_eq!(directory_bytes(&f.root), before);
    }
    #[test]
    fn legacy_unsigned_foreign_and_self_authenticating_inputs_refuse() {
        let f = Fixture::new(false);
        let origin = f.origin(1);
        let legacy = super::super::StopTerminal {
            schema: super::super::STOP_TERMINAL_SCHEMA.into(),
            policy_digest: "legacy".into(),
            stop_key: "stop.fixture".into(),
            launch_command_id: "launch.fixture".into(),
            intent_digest: "legacy".into(),
        };
        assert_eq!(
            RestartEvidenceReader::classify(&origin, &serde_json::to_vec(&legacy).unwrap()),
            EvidenceRefusal::Envelope(EnvelopeError::LegacyUnsigned)
        );
        let mut foreign = origin.expected.clone();
        foreign.policy_digest = [99; 32];
        let bytes = terminal_attestation::sign_envelope_for_fixture(&foreign, &f.key1);
        assert_eq!(
            RestartEvidenceReader::classify(&origin, &bytes),
            EvidenceRefusal::Authentication(terminal_attestation::Error::ExpectedMismatch)
        );
        let attacker = KeyPair::from_seed(Seed::new([99; 32]));
        assert_eq!(
            RestartEvidenceReader::classify(&origin, &sign(&origin, &attacker)),
            EvidenceRefusal::Authentication(terminal_attestation::Error::InvalidSignature)
        );
        let mut self_selected: serde_json::Value =
            serde_json::from_slice(&sign(&origin, &attacker)).unwrap();
        self_selected["public_key"] = serde_json::to_value(vec![99u8; 32]).unwrap();
        assert_eq!(
            RestartEvidenceReader::classify(&origin, &serde_json::to_vec(&self_selected).unwrap()),
            EvidenceRefusal::Envelope(EnvelopeError::Malformed)
        );
    }
    #[test]
    fn strict_envelope_refuses_ambiguity_bounds_and_claimed_time() {
        let f = Fixture::new(false);
        let origin = f.origin(1);
        let bytes = sign(&origin, &f.key1);
        let mut trailing = bytes.clone();
        trailing.push(b'\n');
        assert_eq!(
            RestartEvidenceReader::classify(&origin, &trailing),
            EvidenceRefusal::Envelope(EnvelopeError::NonCanonical)
        );
        assert_eq!(
            RestartEvidenceReader::classify(&origin, &vec![b' '; 8193]),
            EvidenceRefusal::Envelope(EnvelopeError::TooLarge)
        );
        assert_eq!(
            RestartEvidenceReader::classify(&origin, &bytes[..bytes.len() - 1]),
            EvidenceRefusal::Envelope(EnvelopeError::Malformed)
        );
        let mut claimed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        claimed["signing_time_verified"] = true.into();
        assert_eq!(
            RestartEvidenceReader::classify(&origin, &serde_json::to_vec(&claimed).unwrap()),
            EvidenceRefusal::Envelope(EnvelopeError::Malformed)
        );
        let duplicate = [b"{\"schema\":\"duplicate\",".as_slice(), &bytes[1..]].concat();
        assert_eq!(
            RestartEvidenceReader::classify(&origin, &duplicate),
            EvidenceRefusal::Envelope(EnvelopeError::Malformed)
        );
    }
}
