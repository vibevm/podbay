use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_compact::{KeyPair, Seed};
use podbay_core::{ActorId, PodId, Role, ScopeId};
use podbay_host::{
    ActorAuthProofError, ActorRegistration, AuthenticatedPeer, AuthenticatedProcessSubject,
    AuthenticatedTransport, AuthorisedBoundLaunch, AuthorisedDispatch, CredentialGeneration,
    DurableAuthority, DurableAuthorityError, HostDispatchPort, HostError, PodIncarnation,
    PodRegistration, PortDispatchError, PortDispatchOutcome,
};
use podbay_store::{AuthorityMutation, PodBayStore};

struct Fixture {
    directory: PathBuf,
    database: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("podbay-actor-auth-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        Self {
            database: directory.join("podbay.sqlite"),
            directory,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[derive(Default)]
struct NoPort;

impl HostDispatchPort for NoPort {
    type Receipt = ();

    fn dispatch(
        &mut self,
        _action: AuthorisedDispatch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        Err(PortDispatchError::RefusedBeforeEffect)
    }

    fn launch_bound(
        &mut self,
        _launch: AuthorisedBoundLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        Err(PortDispatchError::RefusedBeforeEffect)
    }
}

struct FakeTransport(AuthenticatedPeer);

impl AuthenticatedTransport for FakeTransport {
    fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError> {
        Ok(self.0.clone())
    }
}

fn process(pid: u32, birth: u64, cgroup: &str) -> AuthenticatedProcessSubject {
    AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(1000, pid, birth, cgroup)
        .unwrap()
}

fn reopen_with_verifier(
    fixture: &Fixture,
    pod: Option<PodRegistration>,
    actor: ActorRegistration,
    public_key: [u8; 32],
) -> DurableAuthority<NoPort> {
    let mut first = DurableAuthority::open(&fixture.database, NoPort).unwrap();
    if let Some(pod) = pod {
        first.register_pod_from_trusted_policy(pod).unwrap();
    }
    first.register_actor_from_trusted_policy(actor).unwrap();
    let record = first.recorded_snapshot().actors[0].clone();
    drop(first);

    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let snapshot = store.authority_snapshot().unwrap();
    store
        .register_actor_verifier_from_trusted_host(
            snapshot.owner_epoch,
            snapshot.revision,
            &record,
            public_key,
        )
        .unwrap();
    drop(store);
    DurableAuthority::open(&fixture.database, NoPort).unwrap()
}

#[test]
fn owner_candidate_requires_active_exact_process_and_valid_one_time_proof() {
    let fixture = Fixture::new();
    let signer = KeyPair::from_seed(Seed::new([7; 32]));
    let wrong_signer = KeyPair::from_seed(Seed::new([8; 32]));
    let scope = ScopeId::try_from("scope.auth.owner").unwrap();
    let actor_id = ActorId::try_from("actor.auth.owner").unwrap();
    let observed = process(701, 801, "/user.slice/owner-cli.scope");
    let generation = CredentialGeneration::new(1).unwrap();
    let registration = ActorRegistration::owner_cli_from_trusted_policy(
        actor_id.clone(),
        scope,
        observed.clone(),
        generation,
    );
    let expected_peer =
        AuthenticatedPeer::owner_cli_from_authenticated_transport(observed.clone(), generation);
    let transport = FakeTransport(expected_peer.clone());
    let mut authority = reopen_with_verifier(&fixture, None, registration.clone(), *signer.pk);

    assert!(matches!(
        authority.challenge_candidate_for_observed_process(&actor_id, &observed),
        Err(DurableAuthorityError::Host(HostError::Unauthenticated))
    ));
    authority
        .reattest_actor_from_trusted_replay(&transport, registration)
        .unwrap();
    let wrong_actor = ActorId::try_from("actor.auth.other").unwrap();
    assert!(matches!(
        authority.challenge_candidate_for_observed_process(&wrong_actor, &observed),
        Err(DurableAuthorityError::Host(HostError::Unauthenticated))
    ));
    for sibling in [
        process(701, 802, "/user.slice/owner-cli.scope"),
        process(701, 801, "/user.slice/sibling.scope"),
    ] {
        assert!(matches!(
            authority.challenge_candidate_for_observed_process(&actor_id, &sibling),
            Err(DurableAuthorityError::Host(HostError::Unauthenticated))
        ));
    }

    let candidate = authority
        .challenge_candidate_for_observed_process(&actor_id, &observed)
        .unwrap();
    let pending = candidate.begin_challenge([1; 32]).unwrap();
    let transcript = pending.transcript_bytes().unwrap();
    let signature = signer.sk.sign(&transcript, None);
    let session = pending.verify(&observed, signature.as_ref()).unwrap();
    assert_eq!(session.verified_peer(&observed).unwrap(), expected_peer);
    assert_eq!(
        session.verified_peer(&process(701, 802, "/user.slice/owner-cli.scope")),
        Err(ActorAuthProofError::ProcessChanged)
    );

    let pending = authority
        .challenge_candidate_for_observed_process(&actor_id, &observed)
        .unwrap()
        .begin_challenge([2; 32])
        .unwrap();
    let wrong_signature = wrong_signer
        .sk
        .sign(pending.transcript_bytes().unwrap(), None);
    assert!(matches!(
        pending.verify(&observed, wrong_signature.as_ref()),
        Err(ActorAuthProofError::Credential(_))
    ));

    // A completed signature keeps the exact actor binding through an
    // unrelated authority revision, while revocation still ends the session.
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let snapshot = store.authority_snapshot().unwrap();
    let record = snapshot.actors[0].clone();
    let revision = store
        .apply_authority_mutation(
            snapshot.owner_epoch,
            snapshot.revision,
            AuthorityMutation::PutActor(record.clone()),
        )
        .unwrap();
    assert_eq!(session.verified_peer(&observed).unwrap(), expected_peer);
    store
        .revoke_actor_verifier_from_trusted_host(snapshot.owner_epoch, revision, &record)
        .unwrap();
    assert_eq!(
        session.verified_peer(&observed),
        Err(ActorAuthProofError::StaleVerifier)
    );
}

#[test]
fn pod_proof_is_bound_to_active_pod_and_rotation_fences_session() {
    let fixture = Fixture::new();
    let signer = KeyPair::from_seed(Seed::new([9; 32]));
    let next_signer = KeyPair::from_seed(Seed::new([10; 32]));
    let scope = ScopeId::try_from("scope.auth.pod").unwrap();
    let pod_id = PodId::try_from("pod.auth.pod").unwrap();
    let actor_id = ActorId::try_from("actor.auth.pod").unwrap();
    let observed = process(711, 811, "/user.slice/pod-auth.scope");
    let generation = CredentialGeneration::new(1).unwrap();
    let registration = ActorRegistration::pod_from_trusted_policy(
        actor_id.clone(),
        scope.clone(),
        Role::Worker,
        pod_id.clone(),
        PodIncarnation::new(1).unwrap(),
        None,
        observed.clone(),
        generation,
    );
    let expected_peer = AuthenticatedPeer::pod_from_authenticated_transport(
        actor_id.clone(),
        pod_id.clone(),
        PodIncarnation::new(1).unwrap(),
        observed.clone(),
        generation,
    );
    let mut authority = reopen_with_verifier(
        &fixture,
        Some(PodRegistration {
            scope_id: scope,
            pod_id: pod_id.clone(),
            incarnation: PodIncarnation::new(1).unwrap(),
        }),
        registration.clone(),
        *signer.pk,
    );
    authority
        .reattest_actor_from_trusted_replay(&FakeTransport(expected_peer.clone()), registration)
        .unwrap();
    let pending = authority
        .challenge_candidate_for_observed_process(&actor_id, &observed)
        .unwrap()
        .begin_challenge([3; 32])
        .unwrap();
    let signature = signer.sk.sign(pending.transcript_bytes().unwrap(), None);
    let session = pending.verify(&observed, signature.as_ref()).unwrap();
    assert_eq!(session.verified_peer(&observed).unwrap(), expected_peer);

    authority
        .advance_credential_generation_from_trusted_policy(
            &actor_id,
            generation,
            CredentialGeneration::new(2).unwrap(),
        )
        .unwrap();
    let new_record = authority.recorded_snapshot().actors[0].clone();
    let mut store = PodBayStore::open(&fixture.database).unwrap();
    let snapshot = store.authority_snapshot().unwrap();
    store
        .register_actor_verifier_from_trusted_host(
            snapshot.owner_epoch,
            snapshot.revision,
            &new_record,
            *next_signer.pk,
        )
        .unwrap();
    assert_eq!(
        session.verified_peer(&observed),
        Err(ActorAuthProofError::StaleVerifier)
    );
}

#[test]
fn revoked_verifier_and_owner_or_revision_drift_refuse_pending_proof() {
    for drift in ["revoke", "revision", "owner"] {
        let fixture = Fixture::new();
        let signer = KeyPair::from_seed(Seed::new([11; 32]));
        let scope = ScopeId::try_from("scope.auth.drift").unwrap();
        let actor_id = ActorId::try_from("actor.auth.drift").unwrap();
        let observed = process(721, 821, "/user.slice/owner-drift.scope");
        let generation = CredentialGeneration::new(1).unwrap();
        let registration = ActorRegistration::owner_cli_from_trusted_policy(
            actor_id.clone(),
            scope,
            observed.clone(),
            generation,
        );
        let peer =
            AuthenticatedPeer::owner_cli_from_authenticated_transport(observed.clone(), generation);
        let mut authority = reopen_with_verifier(&fixture, None, registration.clone(), *signer.pk);
        authority
            .reattest_actor_from_trusted_replay(&FakeTransport(peer), registration)
            .unwrap();
        let signed = authority
            .challenge_candidate_for_observed_process(&actor_id, &observed)
            .unwrap()
            .begin_challenge([5; 32])
            .unwrap();
        let signed_signature = signer.sk.sign(signed.transcript_bytes().unwrap(), None);
        let session = signed.verify(&observed, signed_signature.as_ref()).unwrap();
        let pending = authority
            .challenge_candidate_for_observed_process(&actor_id, &observed)
            .unwrap()
            .begin_challenge([4; 32])
            .unwrap();
        let signature = signer.sk.sign(pending.transcript_bytes().unwrap(), None);
        let mut store = PodBayStore::open(&fixture.database).unwrap();
        let snapshot = store.authority_snapshot().unwrap();
        let record = snapshot.actors[0].clone();
        match drift {
            "revoke" => {
                store
                    .revoke_actor_verifier_from_trusted_host(
                        snapshot.owner_epoch,
                        snapshot.revision,
                        &record,
                    )
                    .unwrap();
            }
            "revision" => {
                store
                    .apply_authority_mutation(
                        snapshot.owner_epoch,
                        snapshot.revision,
                        AuthorityMutation::PutActor(record),
                    )
                    .unwrap();
            }
            "owner" => {
                store
                    .advance_owner_epoch(snapshot.owner_epoch, snapshot.owner_epoch + 1)
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            pending.verify(&observed, signature.as_ref()),
            Err(ActorAuthProofError::StaleVerifier)
        ));
        if drift == "revision" {
            assert!(session.verified_peer(&observed).is_ok());
        } else {
            assert_eq!(
                session.verified_peer(&observed),
                Err(ActorAuthProofError::StaleVerifier)
            );
        }
    }
}
