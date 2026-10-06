//! Pure closed codec; a valid record is inert data, never filesystem evidence.
use super::*;
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"PBGATE01";
const DOMAIN: &[u8] = b"podbay.inert-access-barrier-record/1\0";
const MAX_BYTES: usize = 8192;

// Disposable adapter is absent from ordinary production builds.
#[cfg(all(test, target_os = "linux"))]
mod disposable_files;

// Scratch-only acquisition prototype. Never compiled into production.
#[cfg(all(test, target_os = "linux"))]
mod closed_origin;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    InitialClosed,
    ForwardProgress,
    RollbackRequested,
    RollbackCompleted,
    ActivationRecorded,
    LateEngagement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordV1 {
    durable: DurableV1,
    kind: Kind,
    parent: FileIdentity,
    previous_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CodecError {
    TooLarge,
    Truncated,
    Tag,
    Utf8,
    Trailing,
    Digest,
    Subject,
    State,
    Chain,
    Overflow,
}

fn digest(body: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(body);
    hash.finalize().into()
}

fn validate(r: &RecordV1) -> Result<(), CodecError> {
    let d = &r.durable;
    if !valid_subject(&d.subject)
        || r.parent.inode == 0
        || r.parent.device != d.subject.source.device
        || r.parent == d.subject.source
        || r.parent == d.subject.staging
        || r.parent == d.subject.manager_lock
    {
        return Err(CodecError::Subject);
    }
    if (d.subject.generation == 1) != (r.previous_digest == [0; 32])
        || (d.subject.generation == 1) != (r.kind == Kind::InitialClosed)
    {
        return Err(CodecError::Chain);
    }
    let valid = match r.kind {
        Kind::InitialClosed => {
            d.direction == Direction::Forward
                && d.phase == Phase::Intent
                && d.activation == Activation::Absent
        }
        Kind::ForwardProgress => {
            d.direction == Direction::Forward
                && matches!(d.phase, Phase::Intent | Phase::Converted | Phase::Published)
                && d.activation == Activation::Absent
        }
        Kind::RollbackRequested => {
            d.direction == Direction::Rollback
                && matches!(d.phase, Phase::Intent | Phase::Converted | Phase::Published)
                && d.activation == Activation::Absent
        }
        Kind::RollbackCompleted => {
            d.direction == Direction::Rollback
                && d.phase == Phase::RolledBack
                && d.activation == Activation::Absent
        }
        Kind::ActivationRecorded => {
            d.direction == Direction::Forward
                && d.phase == Phase::Activated
                && d.activation == Activation::Present
        }
        Kind::LateEngagement => {
            d.activation != Activation::Unknown
                && ((d.phase == Phase::Activated) == (d.activation == Activation::Present))
                && !(d.direction == Direction::Rollback && d.activation == Activation::Present)
                && (d.phase != Phase::RolledBack || d.direction == Direction::Rollback)
        }
    };
    if valid {
        Ok(())
    } else {
        Err(CodecError::State)
    }
}

fn put_text(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(&(text.len() as u16).to_be_bytes());
    out.extend_from_slice(text.as_bytes());
}
fn put_id(out: &mut Vec<u8>, id: &FileIdentity) {
    out.extend_from_slice(&id.device.to_be_bytes());
    out.extend_from_slice(&id.inode.to_be_bytes());
}

fn encode(r: &RecordV1) -> Result<Vec<u8>, CodecError> {
    validate(r)?;
    let s = &r.durable.subject;
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(s.version);
    out.extend_from_slice(&s.generation.to_be_bytes());
    out.extend_from_slice(&r.previous_digest);
    out.push(match r.kind {
        Kind::InitialClosed => 0,
        Kind::ForwardProgress => 1,
        Kind::RollbackRequested => 2,
        Kind::RollbackCompleted => 3,
        Kind::ActivationRecorded => 4,
        Kind::LateEngagement => 5,
    });
    out.push(match r.durable.direction {
        Direction::Forward => 0,
        Direction::Rollback => 1,
    });
    out.push(match r.durable.phase {
        Phase::Intent => 0,
        Phase::Converted => 1,
        Phase::Published => 2,
        Phase::Activated => 3,
        Phase::RolledBack => 4,
    });
    out.push(match r.durable.activation {
        Activation::Absent => 0,
        Activation::Present => 1,
        Activation::Unknown => return Err(CodecError::State),
    });
    for t in [
        &s.canonical_name,
        &s.staging_name,
        &s.migration_key,
        &s.activation_key,
        &s.lineage,
        &s.previous_boot,
        &s.current_boot,
    ] {
        put_text(&mut out, t);
    }
    for id in [&s.manager_lock, &s.source, &s.staging, &r.parent] {
        put_id(&mut out, id);
    }
    for hash in [&s.request_digest, &s.policy_digest, &s.artifact_digest] {
        out.extend_from_slice(hash);
    }
    let hash = digest(&out);
    out.extend_from_slice(&hash);
    if out.len() > MAX_BYTES {
        return Err(CodecError::TooLarge);
    }
    Ok(out)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let end = self.offset.checked_add(n).ok_or(CodecError::Overflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CodecError::Truncated)?;
        self.offset = end;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }
    fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| CodecError::Truncated)?,
        ))
    }
    fn hash(&mut self) -> Result<[u8; 32], CodecError> {
        self.take(32)?.try_into().map_err(|_| CodecError::Truncated)
    }
    fn text(&mut self) -> Result<String, CodecError> {
        let n = u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| CodecError::Truncated)?,
        ) as usize;
        if n == 0 || n > 256 {
            return Err(CodecError::Subject);
        }
        std::str::from_utf8(self.take(n)?)
            .map(str::to_owned)
            .map_err(|_| CodecError::Utf8)
    }
    fn id(&mut self) -> Result<FileIdentity, CodecError> {
        Ok(FileIdentity {
            device: self.u64()?,
            inode: self.u64()?,
        })
    }
}

fn decode(bytes: &[u8]) -> Result<RecordV1, CodecError> {
    if bytes.len() > MAX_BYTES {
        return Err(CodecError::TooLarge);
    }
    let split = bytes.len().checked_sub(32).ok_or(CodecError::Truncated)?;
    let (body, hash) = bytes.split_at(split);
    if digest(body).as_slice() != hash {
        return Err(CodecError::Digest);
    }
    let mut r = Reader {
        bytes: body,
        offset: 0,
    };
    if r.take(8)? != MAGIC {
        return Err(CodecError::Tag);
    }
    let version = r.byte()?;
    let generation = r.u64()?;
    let previous_digest = r.hash()?;
    let kind = match r.byte()? {
        0 => Kind::InitialClosed,
        1 => Kind::ForwardProgress,
        2 => Kind::RollbackRequested,
        3 => Kind::RollbackCompleted,
        4 => Kind::ActivationRecorded,
        5 => Kind::LateEngagement,
        _ => return Err(CodecError::Tag),
    };
    let direction = match r.byte()? {
        0 => Direction::Forward,
        1 => Direction::Rollback,
        _ => return Err(CodecError::Tag),
    };
    let phase = match r.byte()? {
        0 => Phase::Intent,
        1 => Phase::Converted,
        2 => Phase::Published,
        3 => Phase::Activated,
        4 => Phase::RolledBack,
        _ => return Err(CodecError::Tag),
    };
    let activation = match r.byte()? {
        0 => Activation::Absent,
        1 => Activation::Present,
        _ => return Err(CodecError::Tag),
    };
    let canonical_name = r.text()?;
    let staging_name = r.text()?;
    let migration_key = r.text()?;
    let activation_key = r.text()?;
    let lineage = r.text()?;
    let previous_boot = r.text()?;
    let current_boot = r.text()?;
    let manager_lock = r.id()?;
    let source = r.id()?;
    let staging = r.id()?;
    let parent = r.id()?;
    let request_digest = r.hash()?;
    let policy_digest = r.hash()?;
    let artifact_digest = r.hash()?;
    if r.offset != body.len() {
        return Err(CodecError::Trailing);
    }
    let record = RecordV1 {
        durable: DurableV1 {
            subject: SubjectV1 {
                version,
                generation,
                canonical_name,
                staging_name,
                migration_key,
                activation_key,
                lineage,
                previous_boot,
                current_boot,
                manager_lock,
                source,
                staging,
                request_digest,
                policy_digest,
                artifact_digest,
            },
            direction,
            phase,
            activation,
        },
        kind,
        parent,
        previous_digest,
    };
    validate(&record)?;
    Ok(record)
}

/// Checks a supplied adjacent chain. It cannot establish completeness, storage
/// origin or absence of another chain on disk.
fn check_next(previous: &RecordV1, next: &RecordV1) -> Result<(), CodecError> {
    validate(previous)?;
    validate(next)?;
    let generation = previous
        .durable
        .subject
        .generation
        .checked_add(1)
        .ok_or(CodecError::Overflow)?;
    let mut expected = previous.durable.subject.clone();
    expected.generation = generation;
    let previous_bytes = encode(previous)?;
    if next.durable.subject != expected
        || next.parent != previous.parent
        || next.previous_digest != digest(&previous_bytes[..previous_bytes.len() - 32])
    {
        return Err(CodecError::Chain);
    }
    // Late engagement latches a refusal; it cannot also claim progress or
    // activation. Repeated late records retain that same durable boundary.
    if next.kind == Kind::LateEngagement
        && (next.durable.direction != previous.durable.direction
            || next.durable.phase != previous.durable.phase
            || next.durable.activation != previous.durable.activation)
    {
        return Err(CodecError::State);
    }
    if previous.kind == Kind::LateEngagement && next.kind != Kind::LateEngagement
        || previous.durable.direction == Direction::Rollback
            && next.durable.direction != Direction::Rollback
        || previous.durable.activation == Activation::Present
            && next.durable.activation != Activation::Present
        || previous.durable.phase == Phase::RolledBack && next.durable.phase != Phase::RolledBack
    {
        return Err(CodecError::State);
    }
    if previous.durable.direction == Direction::Forward
        && next.durable.direction == Direction::Rollback
        && next.kind != Kind::RollbackRequested
    {
        return Err(CodecError::State);
    }
    if next.kind == Kind::ActivationRecorded
        && !matches!(previous.durable.phase, Phase::Published | Phase::Activated)
    {
        return Err(CodecError::State);
    }
    // Forward phases cannot regress; rollback may change Published to RolledBack.
    let rank = |p| match p {
        Phase::Intent => 0,
        Phase::Converted => 1,
        Phase::Published => 2,
        Phase::Activated => 3,
        Phase::RolledBack => 4,
    };
    if rank(next.durable.phase) < rank(previous.durable.phase) {
        return Err(CodecError::State);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn initial() -> RecordV1 {
        let (_, durable, _, _) = super::super::tests::fixture();
        RecordV1 {
            durable,
            kind: Kind::InitialClosed,
            parent: FileIdentity {
                device: 1,
                inode: 9,
            },
            previous_digest: [0; 32],
        }
    }
    pub(super) fn next(p: &RecordV1, kind: Kind) -> RecordV1 {
        let mut r = p.clone();
        r.kind = kind;
        r.durable.subject.generation = p.durable.subject.generation.checked_add(1).unwrap();
        let bytes = encode(p).unwrap();
        r.previous_digest = digest(&bytes[..bytes.len() - 32]);
        r
    }
    fn resign(mut b: Vec<u8>) -> Vec<u8> {
        b.truncate(b.len() - 32);
        let hash = digest(&b);
        b.extend_from_slice(&hash);
        b
    }
    #[test]
    fn roundtrip_complete_subject_and_endian_boundary() {
        let r = initial();
        let b = encode(&r).unwrap();
        assert_eq!(&b[..8], MAGIC);
        assert_eq!(&b[9..17], &1u64.to_be_bytes());
        assert_eq!(decode(&b), Ok(r.clone()));
        assert_eq!(encode(&decode(&b).unwrap()).unwrap(), b);
        let mut n = next(&r, Kind::ForwardProgress);
        n.durable.subject.generation = u64::MAX;
        assert_eq!(decode(&encode(&n).unwrap()), Ok(n));
        let mut unicode = r.clone();
        unicode.durable.subject.lineage = "é".repeat(128);
        assert_eq!(decode(&encode(&unicode).unwrap()), Ok(unicode.clone()));
        unicode.durable.subject.lineage.push('x');
        assert_eq!(encode(&unicode), Err(CodecError::Subject));
    }
    #[test]
    fn corrupt_and_rehashed_malformed_bytes_refuse() {
        let r = initial();
        let b = encode(&r).unwrap();
        let mut wrong_domain = b.clone();
        let body_len = b.len() - 32;
        wrong_domain[body_len..].copy_from_slice(&Sha256::digest(&b[..body_len]));
        assert_eq!(decode(&wrong_domain), Err(CodecError::Digest));
        for i in 0..b.len() {
            let mut bad = b.clone();
            bad[i] ^= 1;
            assert!(decode(&bad).is_err(), "byte {i}");
        }
        for n in 0..b.len() {
            assert!(decode(&b[..n]).is_err());
        }
        for i in [0, 8, 49, 50, 51, 52] {
            let mut bad = b.clone();
            bad[i] = 255;
            assert!(decode(&resign(bad)).is_err());
        }
        let mut trailing = b.clone();
        trailing.insert(trailing.len() - 32, 0);
        assert_eq!(decode(&resign(trailing)), Err(CodecError::Trailing));
        let mut utf = b.clone();
        utf[55] = 255;
        assert_eq!(decode(&resign(utf)), Err(CodecError::Utf8));
        let mut length = b.clone();
        length[53..55].copy_from_slice(&257u16.to_be_bytes());
        assert_eq!(decode(&resign(length)), Err(CodecError::Subject));
        assert_eq!(decode(&vec![0; MAX_BYTES + 1]), Err(CodecError::TooLarge));
    }
    #[test]
    fn exact_chain_mismatch_fork_and_overflow_refuse() {
        let p = initial();
        let n = next(&p, Kind::ForwardProgress);
        assert_eq!(check_next(&p, &n), Ok(()));
        let mut fork = n.clone();
        fork.previous_digest = [8; 32];
        assert_eq!(check_next(&p, &fork), Err(CodecError::Chain));
        let mut foreign = n.clone();
        foreign.durable.subject.request_digest = [8; 32];
        assert_eq!(check_next(&p, &foreign), Err(CodecError::Chain));
        foreign = n.clone();
        foreign.parent.inode = 10;
        assert_eq!(check_next(&p, &foreign), Err(CodecError::Chain));
        let mut gap = n.clone();
        gap.durable.subject.generation = 3;
        assert_eq!(check_next(&p, &gap), Err(CodecError::Chain));
        let mut max = n.clone();
        max.durable.subject.generation = u64::MAX;
        assert_eq!(check_next(&max, &n), Err(CodecError::Overflow));
        let mut zero = n;
        zero.previous_digest = [0; 32];
        assert_eq!(encode(&zero), Err(CodecError::Chain));
    }
    #[test]
    fn rollback_activation_and_late_records_are_sticky() {
        let p = initial();
        let mut rollback = next(&p, Kind::RollbackRequested);
        rollback.durable.direction = Direction::Rollback;
        assert_eq!(check_next(&p, &rollback), Ok(()));
        let mut completed = next(&rollback, Kind::RollbackCompleted);
        completed.durable.phase = Phase::RolledBack;
        assert_eq!(check_next(&rollback, &completed), Ok(()));
        let mut reversed = next(&rollback, Kind::ForwardProgress);
        reversed.durable.direction = Direction::Forward;
        assert_eq!(check_next(&rollback, &reversed), Err(CodecError::State));
        let mut published = next(&p, Kind::ForwardProgress);
        published.durable.phase = Phase::Published;
        assert_eq!(check_next(&p, &published), Ok(()));
        let mut premature = next(&p, Kind::ActivationRecorded);
        premature.durable.phase = Phase::Activated;
        premature.durable.activation = Activation::Present;
        assert_eq!(check_next(&p, &premature), Err(CodecError::State));
        let mut activated = next(&published, Kind::ActivationRecorded);
        activated.durable.phase = Phase::Activated;
        activated.durable.activation = Activation::Present;
        assert_eq!(check_next(&published, &activated), Ok(()));
        let mut reverse = next(&activated, Kind::RollbackRequested);
        reverse.durable.direction = Direction::Rollback;
        reverse.durable.phase = Phase::Published;
        reverse.durable.activation = Activation::Absent;
        assert_eq!(check_next(&activated, &reverse), Err(CodecError::State));
        let late = next(&p, Kind::LateEngagement);
        assert_eq!(check_next(&p, &late), Ok(()));
        let repeated = next(&late, Kind::LateEngagement);
        assert_eq!(check_next(&late, &repeated), Ok(()));
        let mut late_activation = late.clone();
        late_activation.durable.phase = Phase::Activated;
        late_activation.durable.activation = Activation::Present;
        assert_eq!(check_next(&p, &late_activation), Err(CodecError::State));
        let mut late_progress = late.clone();
        late_progress.durable.phase = Phase::Published;
        assert_eq!(check_next(&p, &late_progress), Err(CodecError::State));
        let mut late_direction = late.clone();
        late_direction.durable.direction = Direction::Rollback;
        assert_eq!(check_next(&p, &late_direction), Err(CodecError::State));
        let mut repeated_progress = repeated;
        repeated_progress.durable.phase = Phase::Converted;
        assert_eq!(
            check_next(&late, &repeated_progress),
            Err(CodecError::State)
        );
        let clean = next(&late, Kind::ForwardProgress);
        assert_eq!(check_next(&late, &clean), Err(CodecError::State));
    }
}
