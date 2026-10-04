//! Process-owned actor credential. The secret remains inside this value and
//! is never accepted from a wire request or included in a receipt.

use ed25519_compact::{KeyPair, Seed};
use zeroize::Zeroize;

#[cfg(target_os = "linux")]
use crate::linux_auth::parse_challenge;
#[cfg(target_os = "linux")]
use crate::{ActorChallengeOrigin, CanonicalActorChallenge};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActorKeyError {
    EntropyUnavailable,
    InvalidSeed,
    ChallengeMismatch,
}

/// Generate this inside the actor process. Only the public key is exported for
/// trusted registration. The type deliberately has no Clone or Debug impl;
/// the underlying secret key wipes its storage on drop.
pub struct ActorCredentialKey {
    pair: KeyPair,
}

impl ActorCredentialKey {
    pub fn generate() -> Result<Self, ActorKeyError> {
        let mut seed = [0_u8; 32];
        getrandom::fill(&mut seed).map_err(|_| ActorKeyError::EntropyUnavailable)?;
        let mut owned_seed = Seed::new(seed);
        seed.zeroize();
        let pair = KeyPair::try_from_seed(owned_seed);
        owned_seed.wipe_mut();
        Ok(Self {
            pair: pair.map_err(|_| ActorKeyError::InvalidSeed)?,
        })
    }

    pub fn public_key(&self) -> [u8; 32] {
        *self.pair.pk
    }

    /// Sign only a challenge whose entire identity and process binding match
    /// independently trusted local expectations. The caller must separately
    /// verify that its connected server endpoint is the expected manager.
    #[cfg(target_os = "linux")]
    pub fn sign_checked_linux(
        &self,
        challenge: &CanonicalActorChallenge<'_>,
        expected: &ExpectedLinuxActorChallenge<'_>,
    ) -> Result<[u8; 64], ActorKeyError> {
        let parsed = parse_challenge(challenge.bytes, expected.actor_id)
            .ok_or(ActorKeyError::ChallengeMismatch)?;
        if parsed.nonce != challenge.nonce
            || parsed.store_lineage != challenge.store_lineage
            || parsed.actor_id != challenge.actor_id
            || parsed.scope_id != challenge.scope_id
            || parsed.credential_generation != challenge.credential_generation
            || parsed.os_identity != challenge.os_identity
            || parsed.process_identity != challenge.process_identity
            || parsed.start_identity != challenge.start_identity
            || parsed.containment_identity != challenge.containment_identity
            || parsed.origin != challenge.origin
            || parsed.store_lineage != expected.store_lineage
            || parsed.scope_id != expected.scope_id
            || parsed.credential_generation != expected.credential_generation
            || parsed.os_identity != expected.os_identity
            || parsed.process_identity != expected.process_identity
            || parsed.start_identity != expected.start_identity
            || parsed.containment_identity != expected.containment_identity
            || parsed.origin != expected.origin
        {
            return Err(ActorKeyError::ChallengeMismatch);
        }
        let signature = self.pair.sk.sign(parsed.bytes, None);
        let mut bytes = [0_u8; 64];
        bytes.copy_from_slice(signature.as_ref());
        Ok(bytes)
    }
}

/// Values must come from the actor's trusted launch context and local process
/// observation, never copied from the received challenge itself.
#[cfg(target_os = "linux")]
pub struct ExpectedLinuxActorChallenge<'a> {
    pub store_lineage: &'a str,
    pub actor_id: &'a str,
    pub scope_id: &'a str,
    pub credential_generation: u64,
    pub os_identity: &'a str,
    pub process_identity: &'a str,
    pub start_identity: u64,
    pub containment_identity: &'a str,
    pub origin: ActorChallengeOrigin<'a>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_signs_and_is_distinct() {
        let first = ActorCredentialKey::generate().unwrap();
        let second = ActorCredentialKey::generate().unwrap();
        assert_ne!(first.public_key(), second.public_key());
        assert_ne!(first.public_key(), [0; 32]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exact_trusted_challenge_signs_and_changed_process_refuses() {
        use ed25519_compact::{PublicKey, Signature};

        fn field(bytes: &mut Vec<u8>, tag: u8, value: &[u8]) {
            bytes.push(tag);
            bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
            bytes.extend_from_slice(value);
        }

        let mut transcript = b"podbay.actor-credential.challenge\0".to_vec();
        transcript.push(1);
        field(&mut transcript, 1, &[1; 32]);
        field(&mut transcript, 2, b"lineage.fixture");
        field(&mut transcript, 3, b"actor.fixture");
        field(&mut transcript, 4, b"scope.fixture");
        field(&mut transcript, 5, &3_u64.to_be_bytes());
        field(&mut transcript, 6, &[1]);
        field(&mut transcript, 7, b"linux.uid.1000");
        field(&mut transcript, 8, b"linux.pid.2000");
        field(&mut transcript, 9, &44_u64.to_be_bytes());
        field(&mut transcript, 10, b"/pod.scope");
        field(&mut transcript, 11, &[2]);
        field(&mut transcript, 12, b"pod.fixture");
        field(&mut transcript, 13, &2_u64.to_be_bytes());

        let key = ActorCredentialKey {
            pair: KeyPair::from_seed(Seed::new([7; 32])),
        };
        let challenge = CanonicalActorChallenge {
            bytes: &transcript,
            nonce: [1; 32],
            store_lineage: "lineage.fixture",
            actor_id: "actor.fixture",
            scope_id: "scope.fixture",
            credential_generation: 3,
            os_identity: "linux.uid.1000",
            process_identity: "linux.pid.2000",
            start_identity: 44,
            containment_identity: "/pod.scope",
            origin: ActorChallengeOrigin::Pod {
                pod_id: "pod.fixture",
                incarnation: 2,
            },
        };
        let mut expected = ExpectedLinuxActorChallenge {
            store_lineage: "lineage.fixture",
            actor_id: "actor.fixture",
            scope_id: "scope.fixture",
            credential_generation: 3,
            os_identity: "linux.uid.1000",
            process_identity: "linux.pid.2000",
            start_identity: 44,
            containment_identity: "/pod.scope",
            origin: ActorChallengeOrigin::Pod {
                pod_id: "pod.fixture",
                incarnation: 2,
            },
        };
        let signature = key.sign_checked_linux(&challenge, &expected).unwrap();
        PublicKey::from_slice(&key.public_key())
            .unwrap()
            .verify(challenge.bytes, &Signature::from_slice(&signature).unwrap())
            .unwrap();
        expected.start_identity += 1;
        assert_eq!(
            key.sign_checked_linux(&challenge, &expected),
            Err(ActorKeyError::ChallengeMismatch)
        );
        expected.start_identity -= 1;
        let mut fabricated = challenge;
        fabricated.bytes = b"arbitrary message";
        assert_eq!(
            key.sign_checked_linux(&fabricated, &expected),
            Err(ActorKeyError::ChallengeMismatch)
        );
    }
}
