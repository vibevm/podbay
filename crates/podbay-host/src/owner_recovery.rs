//! Read-only, one-use dual-key owner recovery challenge. This module does not
//! rotate an actor, activate a grant, or open a manager socket.

use ed25519_compact::{PublicKey, Signature};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::ErrorKind;

use podbay_store::AuthorityActorRecord;

use crate::{AuthenticatedProcessSubject, HostError, HostPlatform};

const DOMAIN: &[u8] = b"podbay.owner-recovery/1\0";

pub struct PendingOwnerRecovery {
    prior: AuthorityActorRecord,
    old_public_key: [u8; 32],
    next_process: AuthenticatedProcessSubject,
    next_public_key: [u8; 32],
    store_lineage: String,
    owner_epoch: u64,
    manager_credential_epoch: u64,
    authority_revision: u64,
    rotation_key: String,
    transcript: Vec<u8>,
}

pub struct ProvenOwnerRecovery {
    prior: AuthorityActorRecord,
    old_public_key: [u8; 32],
    next_process: AuthenticatedProcessSubject,
    next_public_key: [u8; 32],
    store_lineage: String,
    owner_epoch: u64,
    manager_credential_epoch: u64,
    authority_revision: u64,
    rotation_key: String,
}

impl PendingOwnerRecovery {
    pub(crate) fn from_trusted_host(
        prior: AuthorityActorRecord,
        old_public_key: [u8; 32],
        next_process: AuthenticatedProcessSubject,
        next_public_key: [u8; 32],
        store_lineage: String,
        owner_epoch: u64,
        manager_credential_epoch: u64,
        authority_revision: u64,
        nonce: [u8; 32],
    ) -> Result<Self, HostError> {
        if prior.origin != "owner_cli"
            || prior.role != "coordinator"
            || prior.parent_actor_id.is_some()
            || prior.pod_id.is_some()
            || prior.pod_incarnation.is_some()
            || prior.platform != "linux"
            || next_process.platform() != HostPlatform::Linux
            || prior.os_identity != next_process.os_identity()
            || (prior.process_identity == next_process.process_identity()
                && prior.start_identity == next_process.start_identity())
            || prior.credential_generation.checked_add(1).is_none()
            || owner_epoch == 0
            || manager_credential_epoch == 0
            || authority_revision == 0
            || store_lineage.is_empty()
            || nonce == [0; 32]
            || old_public_key == next_public_key
            || PublicKey::from_slice(&old_public_key)
                .and_then(|key| key.validate())
                .is_err()
            || PublicKey::from_slice(&next_public_key)
                .and_then(|key| key.validate())
                .is_err()
        {
            return Err(HostError::InvalidInput);
        }
        let mut key_hash = Sha256::new();
        key_hash.update(b"podbay.owner-recovery.key/1\0");
        key_hash.update(&nonce);
        key_hash.update(store_lineage.as_bytes());
        key_hash.update(prior.actor_id.as_bytes());
        key_hash.update(owner_epoch.to_be_bytes());
        let rotation_key = format!("rotation.owner.{}", hex(&key_hash.finalize()));
        let mut transcript = DOMAIN.to_vec();
        put(&mut transcript, 1, &nonce)?;
        put(&mut transcript, 2, store_lineage.as_bytes())?;
        put(&mut transcript, 3, &owner_epoch.to_be_bytes())?;
        put(&mut transcript, 4, &manager_credential_epoch.to_be_bytes())?;
        put(&mut transcript, 5, &authority_revision.to_be_bytes())?;
        put(&mut transcript, 6, rotation_key.as_bytes())?;
        put(&mut transcript, 7, prior.actor_id.as_bytes())?;
        put(&mut transcript, 8, prior.scope_id.as_bytes())?;
        put(
            &mut transcript,
            9,
            &prior.credential_generation.to_be_bytes(),
        )?;
        put(&mut transcript, 10, prior.os_identity.as_bytes())?;
        put(&mut transcript, 11, prior.process_identity.as_bytes())?;
        put(&mut transcript, 12, &prior.start_identity.to_be_bytes())?;
        put(&mut transcript, 13, prior.containment_identity.as_bytes())?;
        put(&mut transcript, 14, next_process.os_identity().as_bytes())?;
        put(
            &mut transcript,
            15,
            next_process.process_identity().as_bytes(),
        )?;
        put(
            &mut transcript,
            16,
            &next_process.start_identity().to_be_bytes(),
        )?;
        put(
            &mut transcript,
            17,
            next_process.containment_identity().as_bytes(),
        )?;
        put(&mut transcript, 18, &old_public_key)?;
        put(&mut transcript, 19, &next_public_key)?;
        Ok(Self {
            prior,
            old_public_key,
            next_process,
            next_public_key,
            store_lineage,
            owner_epoch,
            manager_credential_epoch,
            authority_revision,
            rotation_key,
            transcript,
        })
    }

    pub fn challenge_bytes(&self) -> &[u8] {
        &self.transcript
    }
    pub fn actor_id(&self) -> &str {
        &self.prior.actor_id
    }
    pub fn scope_id(&self) -> &str {
        &self.prior.scope_id
    }
    pub fn prior_generation(&self) -> u64 {
        self.prior.credential_generation
    }
    pub fn next_generation(&self) -> u64 {
        self.prior.credential_generation + 1
    }
    pub fn store_lineage(&self) -> &str {
        &self.store_lineage
    }
    pub fn old_public_key(&self) -> &[u8; 32] {
        &self.old_public_key
    }
    pub fn next_public_key(&self) -> &[u8; 32] {
        &self.next_public_key
    }
    pub fn next_process(&self) -> &AuthenticatedProcessSubject {
        &self.next_process
    }
    pub fn owner_epoch(&self) -> u64 {
        self.owner_epoch
    }
    pub fn authority_revision(&self) -> u64 {
        self.authority_revision
    }

    pub fn verify(
        self,
        old_signature: &[u8],
        next_signature: &[u8],
    ) -> Result<ProvenOwnerRecovery, HostError> {
        for (key, signature) in [
            (&self.old_public_key, old_signature),
            (&self.next_public_key, next_signature),
        ] {
            let public = PublicKey::from_slice(key).map_err(|_| HostError::Unauthenticated)?;
            let signed =
                Signature::from_slice(signature).map_err(|_| HostError::Unauthenticated)?;
            public
                .verify(&self.transcript, &signed)
                .map_err(|_| HostError::Unauthenticated)?;
        }
        Ok(ProvenOwnerRecovery {
            prior: self.prior,
            old_public_key: self.old_public_key,
            next_process: self.next_process,
            next_public_key: self.next_public_key,
            store_lineage: self.store_lineage,
            owner_epoch: self.owner_epoch,
            manager_credential_epoch: self.manager_credential_epoch,
            authority_revision: self.authority_revision,
            rotation_key: self.rotation_key,
        })
    }
}

impl ProvenOwnerRecovery {
    pub fn rotation_key(&self) -> &str {
        &self.rotation_key
    }
    pub fn actor_id(&self) -> &str {
        &self.prior.actor_id
    }
    pub fn scope_id(&self) -> &str {
        &self.prior.scope_id
    }
    pub fn next_generation(&self) -> u64 {
        self.prior.credential_generation + 1
    }
    pub fn prior_actor(&self) -> &AuthorityActorRecord {
        &self.prior
    }
    pub fn old_public_key(&self) -> &[u8; 32] {
        &self.old_public_key
    }
    pub fn next_process(&self) -> &AuthenticatedProcessSubject {
        &self.next_process
    }
    pub fn next_public_key(&self) -> &[u8; 32] {
        &self.next_public_key
    }
    pub fn store_lineage(&self) -> &str {
        &self.store_lineage
    }
    pub fn owner_epoch(&self) -> u64 {
        self.owner_epoch
    }
    pub fn manager_credential_epoch(&self) -> u64 {
        self.manager_credential_epoch
    }
    pub fn authority_revision(&self) -> u64 {
        self.authority_revision
    }
}

fn put(out: &mut Vec<u8>, tag: u8, value: &[u8]) -> Result<(), HostError> {
    let size = u16::try_from(value.len()).map_err(|_| HostError::InvalidInput)?;
    if size == 0 {
        return Err(HostError::InvalidInput);
    }
    out.push(tag);
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn hex(value: &[u8]) -> String {
    let mut out = String::with_capacity(value.len() * 2);
    for byte in value {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub(crate) fn prior_owner_gone(record: &AuthorityActorRecord) -> bool {
    let Some(pid) = record.process_identity.strip_prefix("linux.pid.") else {
        return false;
    };
    let Ok(pid) = pid.parse::<u32>() else {
        return false;
    };
    if pid == 0 {
        return false;
    }
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(value) => value,
        Err(error) if error.kind() == ErrorKind::NotFound => return true,
        Err(_) => return false,
    };
    let Some(end) = stat.rfind(')') else {
        return false;
    };
    let Some(start) = stat[end + 2..].split_whitespace().nth(19) else {
        return false;
    };
    start
        .parse::<u64>()
        .is_ok_and(|current| current != record.start_identity)
}

#[cfg(test)]
mod tests {
    use ed25519_compact::{KeyPair, Seed};
    use podbay_store::AuthorityActorRecord;

    use super::*;

    fn prior() -> AuthorityActorRecord {
        AuthorityActorRecord {
            scope_id: "scope.recovery".into(),
            actor_id: "actor.owner".into(),
            role: "coordinator".into(),
            origin: "owner_cli".into(),
            parent_actor_id: None,
            pod_id: None,
            pod_incarnation: None,
            credential_generation: 1,
            platform: "linux".into(),
            os_identity: "linux.uid.1000".into(),
            process_identity: "linux.pid.99999999".into(),
            start_identity: 456,
            containment_identity: "/user.slice/old.scope".into(),
        }
    }

    #[test]
    fn recovery_challenge_requires_both_exact_keys_and_new_process() {
        let old = KeyPair::from_seed(Seed::new([7; 32]));
        let next = KeyPair::from_seed(Seed::new([8; 32]));
        let process = AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(
            1000,
            2345,
            789,
            "/user.slice/new.scope",
        )
        .unwrap();
        let pending = || {
            PendingOwnerRecovery::from_trusted_host(
                prior(),
                *old.pk,
                process.clone(),
                *next.pk,
                "lineage.recovery".into(),
                2,
                2,
                7,
                [3; 32],
            )
            .unwrap()
        };
        let ready = pending();
        let transcript = ready.challenge_bytes().to_vec();
        let old_signature = old.sk.sign(&transcript, None);
        let next_signature = next.sk.sign(&transcript, None);
        let proven = ready
            .verify(old_signature.as_ref(), next_signature.as_ref())
            .unwrap();
        assert_eq!(proven.actor_id(), "actor.owner");
        assert_eq!(proven.scope_id(), "scope.recovery");
        assert_eq!(proven.next_generation(), 2);
        assert!(proven.rotation_key().starts_with("rotation.owner."));
        assert!(matches!(
            pending().verify(next_signature.as_ref(), old_signature.as_ref()),
            Err(HostError::Unauthenticated),
        ));
        assert!(
            PendingOwnerRecovery::from_trusted_host(
                prior(),
                *old.pk,
                process.clone(),
                *old.pk,
                "lineage.recovery".into(),
                2,
                2,
                7,
                [3; 32],
            )
            .is_err()
        );
        let same = AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(
            1000,
            99999999,
            456,
            "/user.slice/old.scope",
        )
        .unwrap();
        assert!(
            PendingOwnerRecovery::from_trusted_host(
                prior(),
                *old.pk,
                same,
                *next.pk,
                "lineage.recovery".into(),
                2,
                2,
                7,
                [3; 32],
            )
            .is_err()
        );
        assert!(
            PendingOwnerRecovery::from_trusted_host(
                prior(),
                *old.pk,
                process,
                *next.pk,
                "lineage.recovery".into(),
                2,
                2,
                7,
                [0; 32],
            )
            .is_err()
        );
    }
}
