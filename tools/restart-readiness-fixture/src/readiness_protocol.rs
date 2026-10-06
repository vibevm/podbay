//! Inert fixture protocol. Signed data authentication is not Lens readiness.
//! No Ready tag, database identity, admission token or production constructor.
use ed25519_compact::{KeyPair, PublicKey, Signature};
const DOMAIN: &[u8] = b"podbay.private-readiness-fixture/1\0";
const MAX_FRAME: usize = 8192;
const ID_BOUND: usize = 160;
const PATH_BOUND: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq)]
struct SubjectV1 {
    nonce: [u8; 32],
    generation: u64,
    manager_epoch: u64,
    accepted_launch_digest: [u8; 32],
    policy_digest: [u8; 32],
    artifact_digest: [u8; 32],
    config_digest: [u8; 32],
    profile_digest: [u8; 32],
    command_id: String,
    actor_id: String,
    scope_id: String,
    pod_id: String,
    session_id: String,
    run_id: String,
    attempt_id: String,
    resource_id: String,
    child_pid: u32,
    child_birth: u64,
    boot_id: String,
    // Requested target only. Never an observation of a SQLite handle/inode/UUID.
    requested_state_db: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Observation {
    IdentityUnavailable,
    ForeignOwner,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Refusal {
    Malformed,
    Version,
    Authentication,
    Binding,
    ForeignOwner,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthenticatedIdentityUnavailable {
    subject: SubjectV1,
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= ID_BOUND
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn valid(subject: &SubjectV1) -> bool {
    let ids = [
        &subject.command_id,
        &subject.actor_id,
        &subject.scope_id,
        &subject.pod_id,
        &subject.session_id,
        &subject.run_id,
        &subject.attempt_id,
        &subject.resource_id,
    ];
    let path = std::path::Path::new(&subject.requested_state_db);
    subject.nonce != [0; 32]
        && subject.generation > 0
        && subject.manager_epoch > 0
        && subject.child_pid > 0
        && subject.child_birth > 0
        && [
            &subject.accepted_launch_digest,
            &subject.policy_digest,
            &subject.artifact_digest,
            &subject.config_digest,
            &subject.profile_digest,
        ]
        .iter()
        .all(|p| **p != [0; 32])
        && ids.iter().all(|s| token(s))
        && subject.boot_id.len() == 36
        && subject.boot_id.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
        && subject.requested_state_db.len() <= PATH_BOUND
        && !subject.requested_state_db.contains('\0')
        && path.is_absolute()
        && path.components().all(|c| {
            matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}
fn string(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(&(text.len() as u16).to_be_bytes());
    out.extend_from_slice(text.as_bytes());
}
fn body(subject: &SubjectV1, observation: Observation) -> Result<Vec<u8>, Refusal> {
    if !valid(subject) {
        return Err(Refusal::Malformed);
    }
    let mut out = DOMAIN.to_vec();
    out.push(1);
    out.push(match observation {
        Observation::IdentityUnavailable => 1,
        Observation::ForeignOwner => 2,
    });
    out.extend_from_slice(&subject.nonce);
    for value in [subject.generation, subject.manager_epoch] {
        out.extend_from_slice(&value.to_be_bytes());
    }
    for digest in [
        &subject.accepted_launch_digest,
        &subject.policy_digest,
        &subject.artifact_digest,
        &subject.config_digest,
        &subject.profile_digest,
    ] {
        out.extend_from_slice(digest);
    }
    for text in [
        &subject.command_id,
        &subject.actor_id,
        &subject.scope_id,
        &subject.pod_id,
        &subject.session_id,
        &subject.run_id,
        &subject.attempt_id,
        &subject.resource_id,
    ] {
        string(&mut out, text);
    }
    out.extend_from_slice(&subject.child_pid.to_be_bytes());
    out.extend_from_slice(&subject.child_birth.to_be_bytes());
    string(&mut out, &subject.boot_id);
    string(&mut out, &subject.requested_state_db);
    if out.len() + 64 > MAX_FRAME {
        return Err(Refusal::Malformed);
    }
    Ok(out)
}
struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Decoder<'a> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], Refusal> {
        let end = self.offset.checked_add(N).ok_or(Refusal::Malformed)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(Refusal::Malformed)?
            .try_into()
            .map_err(|_| Refusal::Malformed)?;
        self.offset = end;
        Ok(value)
    }
    fn string(&mut self, bound: usize) -> Result<String, Refusal> {
        let n = u16::from_be_bytes(self.take()?) as usize;
        if n > bound {
            return Err(Refusal::Malformed);
        }
        let end = self.offset.checked_add(n).ok_or(Refusal::Malformed)?;
        let s = std::str::from_utf8(self.bytes.get(self.offset..end).ok_or(Refusal::Malformed)?)
            .map_err(|_| Refusal::Malformed)?
            .to_owned();
        self.offset = end;
        Ok(s)
    }
}
fn decode(bytes: &[u8]) -> Result<(SubjectV1, Observation), Refusal> {
    if bytes.len() > MAX_FRAME || !bytes.starts_with(DOMAIN) {
        return Err(Refusal::Malformed);
    }
    let mut d = Decoder {
        bytes,
        offset: DOMAIN.len(),
    };
    if d.take::<1>()? != [1] {
        return Err(Refusal::Version);
    }
    let observation = match d.take::<1>()?[0] {
        1 => Observation::IdentityUnavailable,
        2 => Observation::ForeignOwner,
        _ => return Err(Refusal::Malformed),
    };
    let value = SubjectV1 {
        nonce: d.take()?,
        generation: u64::from_be_bytes(d.take()?),
        manager_epoch: u64::from_be_bytes(d.take()?),
        accepted_launch_digest: d.take()?,
        policy_digest: d.take()?,
        artifact_digest: d.take()?,
        config_digest: d.take()?,
        profile_digest: d.take()?,
        command_id: d.string(ID_BOUND)?,
        actor_id: d.string(ID_BOUND)?,
        scope_id: d.string(ID_BOUND)?,
        pod_id: d.string(ID_BOUND)?,
        session_id: d.string(ID_BOUND)?,
        run_id: d.string(ID_BOUND)?,
        attempt_id: d.string(ID_BOUND)?,
        resource_id: d.string(ID_BOUND)?,
        child_pid: u32::from_be_bytes(d.take()?),
        child_birth: u64::from_be_bytes(d.take()?),
        boot_id: d.string(36)?,
        requested_state_db: d.string(PATH_BOUND)?,
    };
    if d.offset != bytes.len() || !valid(&value) || body(&value, observation)? != bytes {
        return Err(Refusal::Malformed);
    }
    Ok((value, observation))
}
fn sign(subject: &SubjectV1, observation: Observation, key: &KeyPair) -> Result<Vec<u8>, Refusal> {
    let mut bytes = body(subject, observation)?;
    let signature = key.sk.sign(&bytes, None);
    bytes.extend_from_slice(signature.as_ref());
    Ok(bytes)
}
fn verify(
    bytes: &[u8],
    expected: &SubjectV1,
    trusted_key: &PublicKey,
) -> Result<AuthenticatedIdentityUnavailable, Refusal> {
    if !valid(expected) || bytes.len() < 64 || bytes.len() > MAX_FRAME {
        return Err(Refusal::Malformed);
    }
    let (message, raw_signature) = bytes.split_at(bytes.len() - 64);
    let (subject, observation) = decode(message)?;
    let signature = Signature::from_slice(raw_signature).map_err(|_| Refusal::Authentication)?;
    trusted_key
        .verify(message, &signature)
        .map_err(|_| Refusal::Authentication)?;
    if subject != *expected {
        return Err(Refusal::Binding);
    }
    if observation == Observation::ForeignOwner {
        return Err(Refusal::ForeignOwner);
    }
    Ok(AuthenticatedIdentityUnavailable { subject })
}

#[cfg(test)]
mod tests;
