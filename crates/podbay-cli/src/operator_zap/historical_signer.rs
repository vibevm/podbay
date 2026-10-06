//! Pure verification of independently captured, trusted-host database assertions.
//! No signatures are replayed here. Historical registration does not establish
//! signing time, terminal truth, current authority, or trusted snapshot acquisition.
#![allow(dead_code)]
use super::terminal_attestation::{SignerBindingV1, TrustedSignerV1};
use ed25519_compact::PublicKey;

const VERSION: u8 = 1;
const MAX_ROWS: usize = 4096;
#[derive(Clone, Debug, PartialEq, Eq)]
struct ExpectedOwnerV1 {
    version: u8,
    lineage: String,
    actor: String,
    scope: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct CurrentVerifierV1 {
    version: u8,
    lineage: String,
    actor: String,
    scope: String,
    origin: Origin,
    role: Role,
    generation: u64,
    key: [u8; 32],
    binding: [u8; 32],
    revoked: bool,
    owner_epoch: u64,
    authority_revision: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Origin {
    OwnerCli,
    Other,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Coordinator,
    Other,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct RotationV1 {
    version: u8,
    lineage: String,
    actor: String,
    scope: String,
    rotation_key: String,
    intent_digest: [u8; 32],
    prior_generation: u64,
    next_generation: u64,
    prior_key: [u8; 32],
    next_key: [u8; 32],
    prior_binding: [u8; 32],
    next_binding: [u8; 32],
    prior_revoked: bool,
    owner_epoch: u64,
    authority_revision: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct TrustedSnapshotV1 {
    version: u8,
    current: CurrentVerifierV1,
    rotations: Vec<RotationV1>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Error {
    Malformed,
    Foreign,
    Bounds,
    UntrustedOwner,
    Revocation,
    GapOrFork,
    Seam,
    KeyReuse,
    Order,
    Tail,
    Target,
}
fn literal(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| b.is_ascii_graphic())
}
fn key_valid(k: &[u8; 32]) -> bool {
    PublicKey::from_slice(k).and_then(|p| p.validate()).is_ok()
}

fn resolve(
    expected: &ExpectedOwnerV1,
    snapshot: &TrustedSnapshotV1,
    target: u64,
) -> Result<TrustedSignerV1, Error> {
    if expected.version != VERSION
        || snapshot.version != VERSION
        || snapshot.current.version != VERSION
        || !literal(&expected.lineage)
        || !literal(&expected.actor)
        || !literal(&expected.scope)
    {
        return Err(Error::Malformed);
    }
    let current = &snapshot.current;
    if current.lineage != expected.lineage
        || current.actor != expected.actor
        || current.scope != expected.scope
    {
        return Err(Error::Foreign);
    }
    if current.origin != Origin::OwnerCli || current.role != Role::Coordinator {
        return Err(Error::UntrustedOwner);
    }
    if current.revoked {
        return Err(Error::Revocation);
    }
    if snapshot.rotations.len() > MAX_ROWS
        || current.generation > MAX_ROWS as u64 + 1
        || target > MAX_ROWS as u64 + 1
    {
        return Err(Error::Bounds);
    }
    if current.generation == 0
        || current.owner_epoch == 0
        || current.authority_revision == 0
        || current.binding == [0; 32]
        || !key_valid(&current.key)
    {
        return Err(Error::Malformed);
    }
    if target == 0 || target > current.generation {
        return Err(Error::Target);
    }
    if snapshot.rotations.len() as u64 + 1 != current.generation {
        return Err(Error::GapOrFork);
    }
    let (mut key, mut binding) = snapshot
        .rotations
        .first()
        .map(|r| (r.prior_key, r.prior_binding))
        .unwrap_or((current.key, current.binding));
    if !key_valid(&key) || binding == [0; 32] {
        return Err(Error::Malformed);
    }
    let mut keys = vec![key];
    let mut rotation_keys = Vec::new();
    let mut selected = if target == 1 {
        Some((key, binding))
    } else {
        None
    };
    let mut epoch = 0;
    let mut revision = 0;
    for (i, r) in snapshot.rotations.iter().enumerate() {
        if r.version != VERSION
            || !literal(&r.rotation_key)
            || r.intent_digest == [0; 32]
            || r.prior_binding == [0; 32]
            || r.next_binding == [0; 32]
            || !key_valid(&r.prior_key)
            || !key_valid(&r.next_key)
            || r.owner_epoch == 0
            || r.authority_revision == 0
        {
            return Err(Error::Malformed);
        }
        if r.lineage != expected.lineage || r.actor != expected.actor || r.scope != expected.scope {
            return Err(Error::Foreign);
        }
        if !r.prior_revoked {
            return Err(Error::Revocation);
        }
        if r.prior_generation != i as u64 + 1
            || r.prior_generation.checked_add(1) != Some(r.next_generation)
        {
            return Err(Error::GapOrFork);
        }
        if rotation_keys.contains(&r.rotation_key) {
            return Err(Error::GapOrFork);
        }
        rotation_keys.push(r.rotation_key.clone());
        if r.prior_key != key || r.prior_binding != binding {
            return Err(Error::Seam);
        }
        if keys.contains(&r.next_key) {
            return Err(Error::KeyReuse);
        }
        keys.push(r.next_key);
        if r.owner_epoch < epoch
            || r.authority_revision <= revision
            || r.owner_epoch > current.owner_epoch
            || r.authority_revision > current.authority_revision
        {
            return Err(Error::Order);
        }
        epoch = r.owner_epoch;
        revision = r.authority_revision;
        key = r.next_key;
        binding = r.next_binding;
        if target == r.next_generation {
            selected = Some((key, binding));
        }
    }
    if key != current.key || binding != current.binding {
        return Err(Error::Tail);
    }
    let (key, binding) = selected.ok_or(Error::Target)?;
    Ok(TrustedSignerV1 {
        binding: SignerBindingV1 {
            lineage: expected.lineage.clone(),
            actor: expected.actor.clone(),
            scope: expected.scope.clone(),
            generation: target,
            binding_digest: binding,
        },
        public_key: key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_compact::{KeyPair, Seed};
    fn key(n: u8) -> [u8; 32] {
        *KeyPair::from_seed(Seed::new([n; 32])).pk
    }
    fn fixture() -> (ExpectedOwnerV1, TrustedSnapshotV1) {
        let e = ExpectedOwnerV1 {
            version: 1,
            lineage: "lineage".into(),
            actor: "owner".into(),
            scope: "scope".into(),
        };
        let rows = (1..=2)
            .map(|g| RotationV1 {
                version: 1,
                lineage: e.lineage.clone(),
                actor: e.actor.clone(),
                scope: e.scope.clone(),
                rotation_key: format!("rotation.{g}"),
                intent_digest: [g as u8; 32],
                prior_generation: g,
                next_generation: g + 1,
                prior_key: key(g as u8),
                next_key: key(g as u8 + 1),
                prior_binding: [g as u8; 32],
                next_binding: [g as u8 + 1; 32],
                prior_revoked: true,
                owner_epoch: g,
                authority_revision: g + 1,
            })
            .collect();
        let c = CurrentVerifierV1 {
            version: 1,
            lineage: e.lineage.clone(),
            actor: e.actor.clone(),
            scope: e.scope.clone(),
            origin: Origin::OwnerCli,
            role: Role::Coordinator,
            generation: 3,
            key: key(3),
            binding: [3; 32],
            revoked: false,
            owner_epoch: 3,
            authority_revision: 4,
        };
        (
            e,
            TrustedSnapshotV1 {
                version: 1,
                current: c,
                rotations: rows,
            },
        )
    }
    #[test]
    fn resolves_every_historical_generation_and_initial_registration() {
        let (e, s) = fixture();
        for g in 1..=3 {
            let result = resolve(&e, &s, g).unwrap();
            assert_eq!(result.public_key, key(g as u8));
            assert_eq!(result.binding.generation, g);
            assert_eq!(result.binding.binding_digest, [g as u8; 32]);
        }
        let mut initial = s;
        initial.rotations.clear();
        initial.current.generation = 1;
        initial.current.key = key(1);
        initial.current.binding = [1; 32];
        assert_eq!(resolve(&e, &initial, 1).unwrap().public_key, key(1));
    }
    #[test]
    fn gaps_generic_replacement_forks_duplicates_and_reuse_refuse() {
        let (e, s) = fixture();
        let mut bad = s.clone();
        bad.rotations.remove(0);
        assert_eq!(resolve(&e, &bad, 1), Err(Error::GapOrFork));
        bad = s.clone();
        bad.current.generation = 4;
        assert_eq!(resolve(&e, &bad, 1), Err(Error::GapOrFork));
        bad = s.clone();
        bad.rotations[1] = bad.rotations[0].clone();
        assert_eq!(resolve(&e, &bad, 1), Err(Error::GapOrFork));
        bad = s.clone();
        bad.rotations[1].rotation_key = bad.rotations[0].rotation_key.clone();
        assert_eq!(resolve(&e, &bad, 1), Err(Error::GapOrFork));
        bad = s.clone();
        bad.rotations[1].next_key = key(1);
        bad.current.key = key(1);
        assert_eq!(resolve(&e, &bad, 1), Err(Error::KeyReuse));
        bad = s.clone();
        bad.rotations.swap(0, 1);
        assert_eq!(resolve(&e, &bad, 1), Err(Error::GapOrFork));
    }
    #[test]
    fn foreign_seams_revocation_order_and_tail_refuse() {
        let (e, s) = fixture();
        for dimension in 0..12 {
            let mut bad = s.clone();
            match dimension {
                0 => bad.current.lineage = "foreign".into(),
                1 => bad.rotations[0].actor = "foreign".into(),
                2 => bad.rotations[1].scope = "foreign".into(),
                3 => bad.rotations[1].prior_key = key(8),
                4 => bad.rotations[1].prior_binding = [8; 32],
                5 => bad.rotations[0].prior_revoked = false,
                6 => bad.current.revoked = true,
                7 => bad.rotations[1].authority_revision = bad.rotations[0].authority_revision,
                8 => bad.rotations[1].owner_epoch = 0,
                9 => bad.current.key = key(8),
                10 => bad.current.binding = [8; 32],
                _ => bad.current.origin = Origin::Other,
            };
            assert!(resolve(&e, &bad, 1).is_err(), "dimension {dimension}");
        }
        let mut bad = s;
        bad.current.role = Role::Other;
        assert_eq!(resolve(&e, &bad, 1), Err(Error::UntrustedOwner));
    }
    #[test]
    fn malformed_versions_keys_and_target_bounds_refuse() {
        let (e, s) = fixture();
        for target in [0, 4, u64::MAX] {
            assert!(resolve(&e, &s, target).is_err());
        }
        for field in 0..5 {
            let mut bad = s.clone();
            match field {
                0 => bad.version = 2,
                1 => bad.rotations[0].version = 2,
                2 => bad.current.key = [0; 32],
                3 => bad.rotations[0].next_key = [255; 32],
                _ => bad.rotations[0].intent_digest = [0; 32],
            };
            assert!(resolve(&e, &bad, 1).is_err());
        }
        let before = s.clone();
        assert_eq!(resolve(&e, &s, 2), resolve(&e, &s, 2));
        assert_eq!(s, before);
    }
}
