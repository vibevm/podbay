use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_compact::{KeyPair, Seed};
use podbay_core::{ActorId, ScopeId};
use podbay_host::{
    AuthenticatedProcessSubject, AuthorisedBoundLaunch, AuthorisedDispatch, CredentialRef,
    DurableAuthority, DurableAuthorityError, HostDispatchPort, HostError, PortDispatchError,
    PortDispatchOutcome, TrustedInitialOwnerPolicy,
};
use podbay_store::PodBayStore;

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
            "podbay-host-initial-owner-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        Self {
            database: root.join("store.sqlite"),
            root,
        }
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
        Err(PortDispatchError::RefusedBeforeEffect)
    }

    fn launch_bound(
        &mut self,
        _: AuthorisedBoundLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        Err(PortDispatchError::RefusedBeforeEffect)
    }
}

fn policy() -> (ActorId, ScopeId, TrustedInitialOwnerPolicy) {
    let actor = ActorId::try_from("actor.initial.zap").unwrap();
    let scope = ScopeId::try_from("scope.initial.zap").unwrap();
    let credential = CredentialRef::from_trusted_vault(scope.clone(), "vault.initial").unwrap();
    let policy = TrustedInitialOwnerPolicy::from_trusted_manager_policy(
        actor.clone(),
        scope.clone(),
        credential,
    )
    .unwrap();
    (actor, scope, policy)
}

fn process(birth: u64) -> AuthenticatedProcessSubject {
    AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(
        1000,
        2000,
        birth,
        "/user.slice/zap.scope",
    )
    .unwrap()
}

#[test]
fn signed_initial_owner_enrollment_activates_only_after_atomic_commit() {
    let fixture = Fixture::new();
    let mut host = DurableAuthority::open(&fixture.database, NoPort).unwrap();
    let (actor, scope, policy) = policy();
    let observed = process(3000);
    let key = KeyPair::from_seed(Seed::new([7; 32]));
    let pending = host
        .begin_initial_owner_enrollment(policy.clone(), observed.clone(), *key.pk)
        .unwrap();
    assert!(
        pending
            .challenge_bytes()
            .starts_with(b"podbay.owner-initial-enrollment/1\0")
    );
    assert!(host.recorded_snapshot().actors.is_empty());
    assert!(host.recorded_snapshot().grants.is_empty());
    let signature = key.sk.sign(pending.challenge_bytes(), None);
    let proof = pending.verify(signature.as_ref()).unwrap();
    let receipt = host
        .commit_initial_owner_enrollment(proof, &observed)
        .unwrap();
    assert_eq!(receipt.actor_id, actor);
    assert_eq!(receipt.scope_id, scope);
    assert!(!receipt.duplicate);
    assert_eq!(host.recorded_snapshot().actors.len(), 1);
    assert_eq!(host.recorded_snapshot().grants.len(), 1);
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let snapshot = store.authority_snapshot().unwrap();
    assert_eq!(snapshot.revision, receipt.authority_revision);
    assert_eq!(snapshot.grants[0].grant_id, receipt.grant_id.get());
    assert_eq!(
        store
            .current_actor_verifier(snapshot.owner_epoch, snapshot.revision, &snapshot.actors[0])
            .unwrap(),
        *key.pk
    );
    drop(store);
    let candidate = host
        .challenge_candidate_for_observed_process(&actor, &observed)
        .unwrap();
    let normal = candidate.begin_challenge([1; 32]).unwrap();
    let normal_signature = key.sk.sign(normal.transcript_bytes().unwrap(), None);
    assert!(normal.verify(&observed, normal_signature.as_ref()).is_ok());

    let again = host
        .begin_initial_owner_enrollment(policy, observed.clone(), *key.pk)
        .unwrap();
    let signature = key.sk.sign(again.challenge_bytes(), None);
    let repeated = host
        .commit_initial_owner_enrollment(again.verify(signature.as_ref()).unwrap(), &observed)
        .unwrap();
    assert_eq!(repeated.grant_id, receipt.grant_id);
    assert_eq!(repeated.authority_revision, receipt.authority_revision);
    assert!(repeated.duplicate);
    assert_eq!(host.recorded_snapshot().grants.len(), 1);
}

#[test]
fn wrong_key_birth_and_reopened_manager_refuse_initial_enrollment() {
    let fixture = Fixture::new();
    let mut host = DurableAuthority::open(&fixture.database, NoPort).unwrap();
    let (_, _, policy) = policy();
    let observed = process(3000);
    let key = KeyPair::from_seed(Seed::new([7; 32]));
    let other = KeyPair::from_seed(Seed::new([8; 32]));
    let wrong_key = host
        .begin_initial_owner_enrollment(policy.clone(), observed.clone(), *key.pk)
        .unwrap();
    let signature = other.sk.sign(wrong_key.challenge_bytes(), None);
    assert_eq!(
        wrong_key.verify(signature.as_ref()).err(),
        Some(HostError::Unauthenticated)
    );
    let wrong_birth = host
        .begin_initial_owner_enrollment(policy.clone(), process(3001), *key.pk)
        .unwrap();
    let signature = key.sk.sign(wrong_birth.challenge_bytes(), None);
    assert!(matches!(
        host.commit_initial_owner_enrollment(
            wrong_birth.verify(signature.as_ref()).unwrap(),
            &observed,
        ),
        Err(DurableAuthorityError::Host(HostError::Unauthenticated))
    ));
    assert!(host.recorded_snapshot().actors.is_empty());
    let valid = host
        .begin_initial_owner_enrollment(policy.clone(), observed.clone(), *key.pk)
        .unwrap();
    let signature = key.sk.sign(valid.challenge_bytes(), None);
    host.commit_initial_owner_enrollment(valid.verify(signature.as_ref()).unwrap(), &observed)
        .unwrap();
    drop(host);
    let mut reopened = DurableAuthority::open(&fixture.database, NoPort).unwrap();
    assert!(matches!(
        reopened.begin_initial_owner_enrollment(policy, observed, *key.pk),
        Err(DurableAuthorityError::Host(HostError::Unauthorised))
    ));
}

#[test]
fn restarted_manager_requires_old_and_new_key_proofs_before_any_owner_mutation() {
    let fixture = Fixture::new();
    let mut first = DurableAuthority::open(&fixture.database, NoPort).unwrap();
    let (_, _, policy) = policy();
    let observed = process(3000);
    let old = KeyPair::from_seed(Seed::new([7; 32]));
    let next = KeyPair::from_seed(Seed::new([8; 32]));
    let pending = first
        .begin_initial_owner_enrollment(policy.clone(), observed.clone(), *old.pk)
        .unwrap();
    let signature = old.sk.sign(pending.challenge_bytes(), None);
    first.commit_initial_owner_enrollment(
        pending.verify(signature.as_ref()).unwrap(), &observed,
    ).unwrap();
    drop(first);

    let mut restarted = DurableAuthority::open(&fixture.database, NoPort).unwrap();
    let before = restarted.recorded_snapshot().clone();
    assert_eq!(before.owner_epoch, 2);
    assert!(matches!(
        restarted.begin_owner_recovery(&policy, process(3001), *next.pk, *next.pk),
        Err(DurableAuthorityError::Host(HostError::Unauthenticated))
    ));
    let candidate = restarted.begin_owner_recovery(
        &policy, process(3001), *old.pk, *next.pk,
    ).unwrap();
    assert!(candidate.challenge_bytes().starts_with(b"podbay.owner-recovery/1\0"));
    let old_signature = old.sk.sign(candidate.challenge_bytes(), None);
    let next_signature = next.sk.sign(candidate.challenge_bytes(), None);
    assert!(matches!(
        restarted.begin_owner_recovery(&policy, process(3001), *old.pk, *next.pk)
            .unwrap().verify(next_signature.as_ref(), old_signature.as_ref()),
        Err(HostError::Unauthenticated)
    ));
    let proven = candidate.verify(old_signature.as_ref(), next_signature.as_ref()).unwrap();
    assert_eq!(proven.actor_id(), "actor.initial.zap");
    assert_eq!(proven.next_generation(), 2);
    assert_eq!(restarted.recorded_snapshot(), &before);
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    assert_eq!(store.authority_snapshot().unwrap(), before);
}

#[test]
fn proved_recovery_rotates_owner_and_only_recorded_grant_without_pod_effect() {
    let fixture = Fixture::new();
    let mut first = DurableAuthority::open(&fixture.database, NoPort).unwrap();
    let (actor, scope, policy) = policy();
    let old_process = process(3000);
    let old = KeyPair::from_seed(Seed::new([7; 32]));
    let next = KeyPair::from_seed(Seed::new([8; 32]));
    let pending = first.begin_initial_owner_enrollment(
        policy.clone(), old_process.clone(), *old.pk,
    ).unwrap();
    let signature = old.sk.sign(pending.challenge_bytes(), None);
    let enrollment = first.commit_initial_owner_enrollment(
        pending.verify(signature.as_ref()).unwrap(), &old_process,
    ).unwrap();
    drop(first);

    let mut restarted = DurableAuthority::open(&fixture.database, NoPort).unwrap();
    let new_process = process(3001);
    let pending = restarted.begin_owner_recovery(
        &policy, new_process.clone(), *old.pk, *next.pk,
    ).unwrap();
    let old_signature = old.sk.sign(pending.challenge_bytes(), None);
    let next_signature = next.sk.sign(pending.challenge_bytes(), None);
    let proof = pending.verify(old_signature.as_ref(), next_signature.as_ref()).unwrap();
    assert!(matches!(
        restarted.commit_owner_recovery(proof, &process(3002)),
        Err(DurableAuthorityError::Host(HostError::Unauthenticated))
    ));
    assert_eq!(restarted.recorded_snapshot().actors[0].credential_generation, 1);
    let pending = restarted.begin_owner_recovery(
        &policy, new_process.clone(), *old.pk, *next.pk,
    ).unwrap();
    let old_signature = old.sk.sign(pending.challenge_bytes(), None);
    let next_signature = next.sk.sign(pending.challenge_bytes(), None);
    let receipt = restarted.commit_owner_recovery(
        pending.verify(old_signature.as_ref(), next_signature.as_ref()).unwrap(),
        &new_process,
    ).unwrap();
    assert_eq!(receipt.prior_generation, 1);
    assert_eq!(receipt.next_generation, 2);
    assert_eq!(restarted.recorded_snapshot().actors[0].start_identity, 3001);
    assert_eq!(restarted.recorded_snapshot().grants.len(), 1);
    assert_eq!(restarted.recorded_snapshot().grants[0].grant_id, enrollment.grant_id.get());
    assert_eq!(restarted.recorded_snapshot().grants[0].credential_generation, 2);
    assert!(restarted.challenge_candidate_for_observed_process(&actor, &old_process).is_err());
    let candidate = restarted.challenge_candidate_for_observed_process(&actor, &new_process).unwrap();
    let normal = candidate.begin_challenge([2; 32]).unwrap();
    let signature = next.sk.sign(normal.transcript_bytes().unwrap(), None);
    assert!(normal.verify(&new_process, signature.as_ref()).is_ok());
    assert!(restarted.activate_recorded_grant_for_actor_from_trusted_replay(
        &actor, &scope, enrollment.grant_id.get(),
    ).is_ok());
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    assert_eq!(store.authority_snapshot().unwrap(), *restarted.recorded_snapshot());
    assert!(store.current_actor_verifier(
        receipt.owner_epoch, receipt.authority_revision,
        &restarted.recorded_snapshot().actors[0],
    ).is_ok());
}
