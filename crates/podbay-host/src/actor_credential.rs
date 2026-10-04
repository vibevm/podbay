//! Pure verification of one actor credential challenge. Nonce generation,
//! replay tracking, process attestation, and public-key lookup belong to the
//! trusted local transport and authority boundary, not this verifier.

use ed25519_compact::{PublicKey, Signature};
use podbay_core::{ActorId, PodId, ScopeId, StoreLineageId};

use crate::{AuthenticatedProcessSubject, CredentialGeneration, HostPlatform, PodIncarnation};

const DOMAIN: &[u8] = b"podbay.actor-credential.challenge\0";
const VERSION: u8 = 1;
const MAX_TRANSCRIPT_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActorChallengeOrigin<'a> {
    OwnerCli,
    Pod {
        pod_id: &'a PodId,
        incarnation: PodIncarnation,
    },
}

/// All identities come from trusted host state. `process` must be freshly
/// kernel-attested, and `nonce` must be generated and consumed once by the
/// caller. The verifier cannot establish freshness or key registration alone.
#[derive(Clone, Debug)]
pub struct ActorChallenge<'a> {
    nonce: [u8; 32],
    store_lineage: &'a StoreLineageId,
    actor_id: &'a ActorId,
    scope_id: &'a ScopeId,
    credential_generation: CredentialGeneration,
    process: &'a AuthenticatedProcessSubject,
    origin: ActorChallengeOrigin<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActorCredentialError {
    InvalidTranscript,
    InvalidPublicKey,
    InvalidSignature,
}

impl<'a> ActorChallenge<'a> {
    pub fn from_trusted_context(
        nonce: [u8; 32],
        store_lineage: &'a StoreLineageId,
        actor_id: &'a ActorId,
        scope_id: &'a ScopeId,
        credential_generation: CredentialGeneration,
        process: &'a AuthenticatedProcessSubject,
        origin: ActorChallengeOrigin<'a>,
    ) -> Result<Self, ActorCredentialError> {
        if nonce.iter().all(|byte| *byte == 0) {
            return Err(ActorCredentialError::InvalidTranscript);
        }
        let challenge = Self {
            nonce,
            store_lineage,
            actor_id,
            scope_id,
            credential_generation,
            process,
            origin,
        };
        challenge.transcript_bytes()?;
        Ok(challenge)
    }

    /// Canonical v1 bytes to send to the actor for signing. Each variable
    /// field has a one-byte tag and big-endian u16 length; numbers are u64 BE.
    /// The domain and version prevent reuse as another PodBay signature.
    pub fn transcript_bytes(&self) -> Result<Vec<u8>, ActorCredentialError> {
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(DOMAIN);
        bytes.push(VERSION);
        put_bytes(&mut bytes, 1, &self.nonce, 32)?;
        put_text(&mut bytes, 2, self.store_lineage.as_str(), 256)?;
        put_text(&mut bytes, 3, self.actor_id.as_str(), 256)?;
        put_text(&mut bytes, 4, self.scope_id.as_str(), 256)?;
        put_bytes(
            &mut bytes,
            5,
            &self.credential_generation.get().to_be_bytes(),
            8,
        )?;
        let platform = match self.process.platform() {
            HostPlatform::Linux => 1,
            HostPlatform::MacOs => 2,
            HostPlatform::Windows => 3,
        };
        put_bytes(&mut bytes, 6, &[platform], 1)?;
        put_text(&mut bytes, 7, self.process.os_identity(), 256)?;
        put_text(&mut bytes, 8, self.process.process_identity(), 256)?;
        put_bytes(
            &mut bytes,
            9,
            &self.process.start_identity().to_be_bytes(),
            8,
        )?;
        put_text(&mut bytes, 10, self.process.containment_identity(), 4096)?;
        match self.origin {
            ActorChallengeOrigin::OwnerCli => put_bytes(&mut bytes, 11, &[1], 1)?,
            ActorChallengeOrigin::Pod {
                pod_id,
                incarnation,
            } => {
                put_bytes(&mut bytes, 11, &[2], 1)?;
                put_text(&mut bytes, 12, pod_id.as_str(), 256)?;
                put_bytes(&mut bytes, 13, &incarnation.get().to_be_bytes(), 8)?;
            }
        }
        if bytes.len() > MAX_TRANSCRIPT_BYTES {
            return Err(ActorCredentialError::InvalidTranscript);
        }
        Ok(bytes)
    }
}

/// Verify one response against a trusted registered public key. The key must
/// be the host's actor key, never a value supplied by the request being signed.
pub fn verify_actor_challenge(
    challenge: &ActorChallenge<'_>,
    public_key_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<(), ActorCredentialError> {
    let public_key = PublicKey::from_slice(public_key_bytes)
        .map_err(|_| ActorCredentialError::InvalidPublicKey)?;
    public_key
        .validate()
        .map_err(|_| ActorCredentialError::InvalidPublicKey)?;
    let signature = Signature::from_slice(signature_bytes)
        .map_err(|_| ActorCredentialError::InvalidSignature)?;
    public_key
        .verify(challenge.transcript_bytes()?, &signature)
        .map_err(|_| ActorCredentialError::InvalidSignature)
}

fn put_text(
    out: &mut Vec<u8>,
    tag: u8,
    value: &str,
    max: usize,
) -> Result<(), ActorCredentialError> {
    if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(ActorCredentialError::InvalidTranscript);
    }
    put_bytes(out, tag, value.as_bytes(), max)
}

fn put_bytes(
    out: &mut Vec<u8>,
    tag: u8,
    value: &[u8],
    max: usize,
) -> Result<(), ActorCredentialError> {
    if value.is_empty() || value.len() > max {
        return Err(ActorCredentialError::InvalidTranscript);
    }
    let length = u16::try_from(value.len()).map_err(|_| ActorCredentialError::InvalidTranscript)?;
    out.push(tag);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    if out.len() > MAX_TRANSCRIPT_BYTES {
        return Err(ActorCredentialError::InvalidTranscript);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_compact::{KeyPair, Seed};

    use super::*;

    fn subject(uid: u32, pid: u32, birth: u64, cgroup: &str) -> AuthenticatedProcessSubject {
        AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(uid, pid, birth, cgroup)
            .unwrap()
    }

    #[test]
    fn deterministic_signature_binds_every_actor_and_process_field() {
        let key_pair = KeyPair::from_seed(Seed::new([7_u8; 32]));
        let public_key = key_pair.pk.as_ref();
        let lineage = StoreLineageId::try_from("lineage.one").unwrap();
        let other_lineage = StoreLineageId::try_from("lineage.two").unwrap();
        let actor = ActorId::try_from("actor.one").unwrap();
        let other_actor = ActorId::try_from("actor.two").unwrap();
        let scope = ScopeId::try_from("scope.one").unwrap();
        let other_scope = ScopeId::try_from("scope.two").unwrap();
        let process = subject(1000, 200, 300, "/user.slice/pod-one.scope");
        let wrong_uid = subject(1001, 200, 300, "/user.slice/pod-one.scope");
        let wrong_pid = subject(1000, 201, 300, "/user.slice/pod-one.scope");
        let wrong_birth = subject(1000, 200, 301, "/user.slice/pod-one.scope");
        let wrong_cgroup = subject(1000, 200, 300, "/user.slice/pod-two.scope");
        let pod = PodId::try_from("pod.one").unwrap();
        let other_pod = PodId::try_from("pod.two").unwrap();
        let generation = CredentialGeneration::new(1).unwrap();
        let origin = ActorChallengeOrigin::Pod {
            pod_id: &pod,
            incarnation: PodIncarnation::new(1).unwrap(),
        };
        let base = ActorChallenge::from_trusted_context(
            [1; 32], &lineage, &actor, &scope, generation, &process, origin,
        )
        .unwrap();
        let transcript = base.transcript_bytes().unwrap();
        assert!(transcript.starts_with(DOMAIN));
        assert!(transcript.len() <= MAX_TRANSCRIPT_BYTES);
        assert_eq!(transcript, base.transcript_bytes().unwrap());
        let signature = key_pair.sk.sign(&transcript, None);
        verify_actor_challenge(&base, public_key, signature.as_ref()).unwrap();

        let mut tampered = Vec::new();
        let mut changed = base.clone();
        changed.nonce = [2; 32];
        tampered.push(changed);
        let mut changed = base.clone();
        changed.store_lineage = &other_lineage;
        tampered.push(changed);
        let mut changed = base.clone();
        changed.actor_id = &other_actor;
        tampered.push(changed);
        let mut changed = base.clone();
        changed.scope_id = &other_scope;
        tampered.push(changed);
        let mut changed = base.clone();
        changed.credential_generation = CredentialGeneration::new(2).unwrap();
        tampered.push(changed);
        for different in [&wrong_uid, &wrong_pid, &wrong_birth, &wrong_cgroup] {
            let mut changed = base.clone();
            changed.process = different;
            tampered.push(changed);
        }
        let mut changed = base.clone();
        changed.origin = ActorChallengeOrigin::OwnerCli;
        tampered.push(changed);
        let mut changed = base.clone();
        changed.origin = ActorChallengeOrigin::Pod {
            pod_id: &other_pod,
            incarnation: PodIncarnation::new(1).unwrap(),
        };
        tampered.push(changed);
        let mut changed = base.clone();
        changed.origin = ActorChallengeOrigin::Pod {
            pod_id: &pod,
            incarnation: PodIncarnation::new(2).unwrap(),
        };
        tampered.push(changed);
        for changed in tampered {
            assert_eq!(
                verify_actor_challenge(&changed, public_key, signature.as_ref()),
                Err(ActorCredentialError::InvalidSignature)
            );
        }
    }

    #[test]
    fn malformed_or_weak_key_and_signature_refuse() {
        let key_pair = KeyPair::from_seed(Seed::new([9_u8; 32]));
        let lineage = StoreLineageId::try_from("lineage.one").unwrap();
        let actor = ActorId::try_from("actor.one").unwrap();
        let scope = ScopeId::try_from("scope.one").unwrap();
        let process = subject(1000, 200, 300, "/user.slice/pod-one.scope");
        let challenge = ActorChallenge::from_trusted_context(
            [3; 32],
            &lineage,
            &actor,
            &scope,
            CredentialGeneration::new(1).unwrap(),
            &process,
            ActorChallengeOrigin::OwnerCli,
        )
        .unwrap();
        let signature = key_pair
            .sk
            .sign(challenge.transcript_bytes().unwrap(), None);
        assert_eq!(
            verify_actor_challenge(&challenge, &[0; 31], signature.as_ref()),
            Err(ActorCredentialError::InvalidPublicKey)
        );
        let mut weak = [0_u8; 32];
        weak[0] = 1; // compressed Edwards identity point
        assert_eq!(
            verify_actor_challenge(&challenge, &weak, signature.as_ref()),
            Err(ActorCredentialError::InvalidPublicKey)
        );
        assert_eq!(
            verify_actor_challenge(&challenge, &[0xff; 32], signature.as_ref()),
            Err(ActorCredentialError::InvalidPublicKey)
        );
        assert_eq!(
            verify_actor_challenge(&challenge, key_pair.pk.as_ref(), &[0; 63]),
            Err(ActorCredentialError::InvalidSignature)
        );
        assert_eq!(
            verify_actor_challenge(&challenge, key_pair.pk.as_ref(), &[0; 64]),
            Err(ActorCredentialError::InvalidSignature)
        );
        let mut changed_signature = [0_u8; 64];
        changed_signature.copy_from_slice(signature.as_ref());
        changed_signature[0] ^= 1;
        assert_eq!(
            verify_actor_challenge(&challenge, key_pair.pk.as_ref(), &changed_signature),
            Err(ActorCredentialError::InvalidSignature)
        );
        assert_eq!(
            ActorChallenge::from_trusted_context(
                [0; 32],
                &lineage,
                &actor,
                &scope,
                CredentialGeneration::new(1).unwrap(),
                &process,
                ActorChallengeOrigin::OwnerCli,
            )
            .unwrap_err(),
            ActorCredentialError::InvalidTranscript
        );
    }
}
