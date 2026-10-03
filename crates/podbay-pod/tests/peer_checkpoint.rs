#![cfg(target_os = "linux")]
use std::collections::BTreeMap;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use podbay_core::{
    AttemptId, AttestedPeer, CommandKey, CredentialEpoch, Epoch, FenceError, FenceOperation,
    FenceTarget, InputEpoch, ManagerLiveness, OwnerEpoch, OwnerEpochWitness, PeerGrantId,
    PeerRequest, PodFenceIdentity, PodId, PodPeerFence, RebindLedger, RebindPhase, RebindProposal,
    RequestDigest, ResourceId, ScopeId, StoreLineageId,
};
use podbay_pod::{
    PeerCheckpointError, decode_peer_checkpoint, encode_peer_checkpoint, read_peer_checkpoint,
    write_peer_checkpoint,
};
use sha2::{Digest, Sha256};

struct Fixture {
    directory: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "podbay-peer-checkpoint-{}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self { directory }
    }
    fn checkpoint_paths(&self) -> Vec<PathBuf> {
        let mut paths = std::fs::read_dir(&self.directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("peer-")
                    && path.extension().is_some_and(|extension| extension == "chk")
            })
            .collect::<Vec<_>>();
        paths.sort();
        paths
    }
    fn only_checkpoint_path(&self) -> PathBuf {
        let paths = self.checkpoint_paths();
        assert_eq!(paths.len(), 1);
        paths[0].clone()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn identity() -> PodFenceIdentity {
    PodFenceIdentity {
        scope_id: ScopeId::try_from("scope.fixture").unwrap(),
        pod_id: PodId::try_from("pod.fixture").unwrap(),
        attempt_id: AttemptId::try_from("attempt.fixture").unwrap(),
        incarnation: Epoch::new(7).unwrap(),
        store_lineage: StoreLineageId::try_from("store.fixture").unwrap(),
    }
}
fn peer(pid: &str, birth: &str) -> AttestedPeer {
    AttestedPeer::from_port("uid.1000", pid, "boot.fixture", birth, "manager.unit").unwrap()
}
fn first() -> ResourceId {
    ResourceId::try_from("resource.first").unwrap()
}
fn second() -> ResourceId {
    ResourceId::try_from("resource.second").unwrap()
}
fn owner(value: u64) -> OwnerEpoch {
    OwnerEpoch::new(value).unwrap()
}
fn credential(value: u64) -> CredentialEpoch {
    CredentialEpoch::new(value).unwrap()
}
fn input(value: u64) -> InputEpoch {
    InputEpoch::new(value).unwrap()
}
fn fence() -> PodPeerFence {
    PodPeerFence::new(
        identity(),
        peer("pid.100", "birth.100"),
        owner(1),
        credential(1),
        BTreeMap::from([(first(), input(1)), (second(), input(1))]),
        100,
        800,
    )
    .unwrap()
}
fn proposal() -> RebindProposal {
    RebindProposal {
        identity: identity(),
        expected_owner_epoch: owner(1),
        next_owner_epoch: owner(2),
        expected_credential_epoch: credential(1),
        next_credential_epoch: credential(2),
        expected_input_epochs: BTreeMap::from([(first(), input(1)), (second(), input(1))]),
        next_input_epochs: BTreeMap::from([(first(), input(2)), (second(), input(2))]),
        next_manager: peer("pid.200", "birth.200"),
        command_key: CommandKey::try_from("rebind.fixture").unwrap(),
        digest: RequestDigest::parse(&"a".repeat(64)).unwrap(),
    }
}
struct Witness(OwnerEpoch);
impl OwnerEpochWitness for Witness {
    fn current_owner_epoch(&self, lineage: &StoreLineageId, scope: &ScopeId) -> Option<OwnerEpoch> {
        (lineage == &identity().store_lineage && scope == &identity().scope_id).then_some(self.0)
    }
}
struct Ledger {
    proposal: RebindProposal,
    active: bool,
}
impl RebindLedger for Ledger {
    fn pending(&self, proposal: &RebindProposal) -> bool {
        proposal == &self.proposal
    }
    fn activated(&self, proposal: &RebindProposal) -> bool {
        self.active && proposal == &self.proposal
    }
}
fn request(owner_epoch: OwnerEpoch, credential_epoch: CredentialEpoch) -> PeerRequest {
    PeerRequest {
        identity: identity(),
        grant_id: PeerGrantId::try_from("grant.control").unwrap(),
        owner_epoch,
        credential_epoch,
        target: FenceTarget::Resource(first()),
        operation: FenceOperation::ObserveResource,
        input_epoch: None,
    }
}

#[test]
fn private_file_roundtrip_preserves_identity_and_restores_no_controls() {
    let fixture = Fixture::new();
    let fence = fence();
    let bytes = encode_peer_checkpoint(&fence.checkpoint()).unwrap();
    assert_eq!(decode_peer_checkpoint(&bytes).unwrap(), fence.checkpoint());
    write_peer_checkpoint(&fixture.directory, &identity(), &fence.checkpoint()).unwrap();
    let mut restored = read_peer_checkpoint(&fixture.directory, &identity()).unwrap();
    assert_eq!(restored.identity(), &identity());
    assert_eq!(restored.input_epoch(&first()), Some(input(1)));
    assert_eq!(restored.input_epoch(&second()), Some(input(1)));
    assert_eq!(
        restored.authorize(
            &peer("pid.100", "birth.100"),
            &request(owner(1), credential(1)),
            &Witness(owner(1)),
            120
        ),
        Err(FenceError::LeaseExpired)
    );
    restored
        .renew_manager_lease(&peer("pid.100", "birth.100"), &Witness(owner(1)), 120, 400)
        .unwrap();
    assert_eq!(
        restored.authorize(
            &peer("pid.100", "birth.100"),
            &request(owner(1), credential(1)),
            &Witness(owner(1)),
            130
        ),
        Err(FenceError::GrantDenied)
    );
    let metadata = std::fs::metadata(fixture.only_checkpoint_path()).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o077, 0);
}

#[test]
fn both_pending_phases_and_active_survive_private_file_replacement() {
    let fixture = Fixture::new();
    let mut fence = fence();
    let proposal = proposal();
    let mut ledger = Ledger {
        proposal: proposal.clone(),
        active: false,
    };
    let successor = peer("pid.200", "birth.200");
    assert_eq!(
        fence
            .prepare_rebind(
                proposal.clone(),
                &successor,
                ManagerLiveness::DeadAttested,
                &Witness(owner(2)),
                &ledger,
                170
            )
            .unwrap(),
        RebindPhase::PendingStore
    );
    write_peer_checkpoint(&fixture.directory, &identity(), &fence.checkpoint()).unwrap();
    let mut pending = read_peer_checkpoint(&fixture.directory, &identity()).unwrap();
    assert_eq!(pending.phase(), RebindPhase::PendingStore);
    assert_eq!(pending.input_epoch(&first()), Some(input(2)));
    assert_eq!(pending.input_epoch(&second()), Some(input(2)));
    assert_eq!(
        pending.authorize(
            &peer("pid.100", "birth.100"),
            &request(owner(1), credential(1)),
            &Witness(owner(2)),
            180
        ),
        Err(FenceError::PendingRebind)
    );
    pending
        .confirm_pod_bound(&proposal, &successor, &Witness(owner(2)), &ledger)
        .unwrap();
    write_peer_checkpoint(&fixture.directory, &identity(), &pending.checkpoint()).unwrap();
    let mut acknowledged = read_peer_checkpoint(&fixture.directory, &identity()).unwrap();
    assert_eq!(acknowledged.phase(), RebindPhase::PendingPod);
    ledger.active = true;
    acknowledged
        .activate_rebind(&proposal, &successor, &Witness(owner(2)), &ledger)
        .unwrap();
    write_peer_checkpoint(&fixture.directory, &identity(), &acknowledged.checkpoint()).unwrap();
    let mut active = read_peer_checkpoint(&fixture.directory, &identity()).unwrap();
    assert_eq!(active.phase(), RebindPhase::Active);
    assert_eq!(active.owner_epoch(), owner(2));
    assert_eq!(active.input_epoch(&first()), Some(input(2)));
    assert_eq!(active.input_epoch(&second()), Some(input(2)));
    assert_eq!(
        active.authorize(
            &peer("pid.100", "birth.100"),
            &request(owner(1), credential(1)),
            &Witness(owner(2)),
            200
        ),
        Err(FenceError::LeaseExpired)
    );
    assert_eq!(
        active.prepare_rebind(
            proposal.clone(),
            &successor,
            ManagerLiveness::Unknown,
            &Witness(owner(2)),
            &ledger,
            210
        ),
        Ok(RebindPhase::Active)
    );
    let mut changed = proposal;
    changed.digest = RequestDigest::parse(&"b".repeat(64)).unwrap();
    assert_eq!(
        active.prepare_rebind(
            changed,
            &successor,
            ManagerLiveness::Unknown,
            &Witness(owner(2)),
            &ledger,
            210
        ),
        Err(FenceError::IdempotencyConflict)
    );
}

#[test]
fn digest_version_identity_and_truncated_crash_windows_fail_closed() {
    let fixture = Fixture::new();
    let checkpoint = fence().checkpoint();
    assert!(matches!(
        read_peer_checkpoint(&fixture.directory, &identity()),
        Err(PeerCheckpointError::Io(_))
    ));
    let temporary = fixture.directory.join("peer-uncommitted.chk.tmp.crash");
    std::fs::write(&temporary, b"truncated temp before rename").unwrap();
    assert!(matches!(
        read_peer_checkpoint(&fixture.directory, &identity()),
        Err(PeerCheckpointError::Io(_))
    ));
    write_peer_checkpoint(&fixture.directory, &identity(), &checkpoint).unwrap();
    assert!(read_peer_checkpoint(&fixture.directory, &identity()).is_ok());
    let path = fixture.only_checkpoint_path();
    let mut foreign = identity();
    foreign.pod_id = PodId::try_from("pod.foreign").unwrap();
    assert!(matches!(
        read_peer_checkpoint(&fixture.directory, &foreign),
        Err(PeerCheckpointError::Io(_))
    ));
    let foreign_checkpoint = PodPeerFence::new(
        foreign,
        peer("pid.100", "birth.100"),
        owner(1),
        credential(1),
        BTreeMap::from([(first(), input(1)), (second(), input(1))]),
        100,
        800,
    )
    .unwrap()
    .checkpoint();
    std::fs::write(&path, encode_peer_checkpoint(&foreign_checkpoint).unwrap()).unwrap();
    assert!(matches!(
        read_peer_checkpoint(&fixture.directory, &identity()),
        Err(PeerCheckpointError::ForeignIdentity)
    ));
    let mut bytes = encode_peer_checkpoint(&checkpoint).unwrap();
    bytes[20] ^= 1;
    std::fs::write(&path, &bytes).unwrap();
    assert!(matches!(
        read_peer_checkpoint(&fixture.directory, &identity()),
        Err(PeerCheckpointError::DigestMismatch)
    ));
    let mut versioned = encode_peer_checkpoint(&checkpoint).unwrap();
    let magic = b"podbay.peer-fence-checkpoint/1\0";
    versioned[magic.len() + 1] = 2;
    let body_len = versioned.len() - 32;
    let digest = Sha256::digest(&versioned[..body_len]);
    versioned[body_len..].copy_from_slice(&digest);
    std::fs::write(&path, &versioned).unwrap();
    assert!(matches!(
        read_peer_checkpoint(&fixture.directory, &identity()),
        Err(PeerCheckpointError::UnsupportedVersion)
    ));
    std::fs::write(&path, b"truncated final").unwrap();
    assert!(read_peer_checkpoint(&fixture.directory, &identity()).is_err());
}

#[test]
fn symlink_checkpoint_or_directory_is_refused_without_following() {
    let fixture = Fixture::new();
    let checkpoint = fence().checkpoint();
    write_peer_checkpoint(&fixture.directory, &identity(), &checkpoint).unwrap();
    let path = fixture.only_checkpoint_path();
    std::fs::remove_file(&path).unwrap();
    let target = fixture.directory.join("target.chk");
    std::fs::write(&target, b"sentinel").unwrap();
    symlink(&target, &path).unwrap();
    assert!(write_peer_checkpoint(&fixture.directory, &identity(), &checkpoint).is_err());
    assert!(read_peer_checkpoint(&fixture.directory, &identity()).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"sentinel");
    let alias = fixture.directory.with_extension("alias");
    symlink(&fixture.directory, &alias).unwrap();
    assert!(write_peer_checkpoint(&alias, &identity(), &checkpoint).is_err());
    std::fs::remove_file(alias).unwrap();
}

#[test]
fn trusted_identity_derives_distinct_slots_and_wrong_write_preserves_prior_bytes() {
    let fixture = Fixture::new();
    let first_identity = identity();
    let first_checkpoint = fence().checkpoint();
    write_peer_checkpoint(&fixture.directory, &first_identity, &first_checkpoint).unwrap();
    let first_path = fixture.only_checkpoint_path();
    let original_bytes = std::fs::read(&first_path).unwrap();

    let mut second_identity = identity();
    second_identity.pod_id = PodId::try_from("pod.second").unwrap();
    let second_checkpoint = PodPeerFence::new(
        second_identity.clone(),
        peer("pid.200", "birth.200"),
        owner(1),
        credential(1),
        BTreeMap::from([(first(), input(1)), (second(), input(1))]),
        100,
        800,
    )
    .unwrap()
    .checkpoint();
    assert!(matches!(
        write_peer_checkpoint(&fixture.directory, &first_identity, &second_checkpoint),
        Err(PeerCheckpointError::ForeignIdentity)
    ));
    assert_eq!(std::fs::read(&first_path).unwrap(), original_bytes);
    assert_eq!(fixture.checkpoint_paths().len(), 1);

    write_peer_checkpoint(&fixture.directory, &second_identity, &second_checkpoint).unwrap();
    let paths = fixture.checkpoint_paths();
    assert_eq!(paths.len(), 2);
    assert_ne!(paths[0], paths[1]);
    assert_eq!(std::fs::read(&first_path).unwrap(), original_bytes);
    assert_eq!(
        read_peer_checkpoint(&fixture.directory, &first_identity)
            .unwrap()
            .identity(),
        &first_identity
    );
    assert_eq!(
        read_peer_checkpoint(&fixture.directory, &second_identity)
            .unwrap()
            .identity(),
        &second_identity
    );
    let mut absent = identity();
    absent.attempt_id = AttemptId::try_from("attempt.absent").unwrap();
    assert!(matches!(
        read_peer_checkpoint(&fixture.directory, &absent),
        Err(PeerCheckpointError::Io(_))
    ));
}
