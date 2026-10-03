//! Host-testable PodBay/1 pipe envelope and capability fence.
use crate::{ProcessIdentity, Win32Error};

pub const MAX_FRAME: usize = 64 * 1024;
const MAGIC: &[u8; 8] = b"PDBPIPE1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipeRole {
    Viewer,
    Controller,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipeAction {
    Observe,
    Input,
    Resize,
}
impl PipeAction {
    fn byte(self) -> u8 {
        match self {
            Self::Observe => 1,
            Self::Input => 2,
            Self::Resize => 3,
        }
    }
    fn from_byte(value: u8) -> Result<Self, Win32Error> {
        match value {
            1 => Ok(Self::Observe),
            2 => Ok(Self::Input),
            3 => Ok(Self::Resize),
            _ => Err(Win32Error::Invalid("unknown pipe action")),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PipeRequest {
    pub pod_id: String,
    pub incarnation: u64,
    pub generation: u64,
    pub action: PipeAction,
    pub capability: [u8; 32],
    pub payload: Vec<u8>,
}
impl std::fmt::Debug for PipeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeRequest")
            .field("pod_id", &self.pod_id)
            .field("incarnation", &self.incarnation)
            .field("generation", &self.generation)
            .field("action", &self.action)
            .field("capability", &"<redacted>")
            .field("payload_bytes", &self.payload.len())
            .finish()
    }
}
impl PipeRequest {
    pub fn encode(&self) -> Result<Vec<u8>, Win32Error> {
        validate_pod_id(&self.pod_id)?;
        if self.incarnation == 0 || self.generation == 0 || self.payload.len() > MAX_FRAME {
            return Err(Win32Error::Invalid("pipe target or payload bound"));
        }
        let mut body = Vec::with_capacity(63 + self.pod_id.len() + self.payload.len());
        body.extend_from_slice(MAGIC);
        body.push(self.action.byte());
        body.extend_from_slice(&(self.pod_id.len() as u16).to_be_bytes());
        body.extend_from_slice(self.pod_id.as_bytes());
        body.extend_from_slice(&self.incarnation.to_be_bytes());
        body.extend_from_slice(&self.generation.to_be_bytes());
        body.extend_from_slice(&self.capability);
        body.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        body.extend_from_slice(&self.payload);
        if body.len() > MAX_FRAME {
            return Err(Win32Error::Invalid("pipe frame bound"));
        }
        Ok(body)
    }
    pub fn decode(body: &[u8]) -> Result<Self, Win32Error> {
        if body.len() < 63 || body.len() > MAX_FRAME || &body[..8] != MAGIC {
            return Err(Win32Error::Invalid("pipe frame header"));
        }
        let action = PipeAction::from_byte(body[8])?;
        let pod_len = u16::from_be_bytes([body[9], body[10]]) as usize;
        if !(3..=160).contains(&pod_len) || body.len() < 63 + pod_len {
            return Err(Win32Error::Invalid("pipe pod ID length"));
        }
        let pod_id = std::str::from_utf8(&body[11..11 + pod_len])
            .map_err(|_| Win32Error::Invalid("pipe pod ID encoding"))?
            .to_owned();
        validate_pod_id(&pod_id)?;
        let mut offset = 11 + pod_len;
        let incarnation = u64::from_be_bytes(body[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let generation = u64::from_be_bytes(body[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let mut capability = [0; 32];
        capability.copy_from_slice(&body[offset..offset + 32]);
        offset += 32;
        let payload_len = u32::from_be_bytes(body[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if incarnation == 0 || generation == 0 || body.len() != offset + payload_len {
            return Err(Win32Error::Invalid("pipe frame length or epoch"));
        }
        Ok(Self {
            pod_id,
            incarnation,
            generation,
            action,
            capability,
            payload: body[offset..].to_vec(),
        })
    }
}

#[derive(Clone)]
pub struct PeerGrant {
    pub expected_process: ProcessIdentity,
    pub pod_id: String,
    pub incarnation: u64,
    pub generation: u64,
    pub role: PipeRole,
    pub capability: [u8; 32],
}
impl PeerGrant {
    pub fn validate(&self) -> Result<(), Win32Error> {
        validate_pod_id(&self.pod_id)?;
        if self.expected_process.pid == 0
            || self.expected_process.creation_100ns == 0
            || self.incarnation == 0
            || self.generation == 0
            || self.capability == [0; 32]
        {
            return Err(Win32Error::Invalid("pipe grant identity or capability"));
        }
        Ok(())
    }
    pub fn authorize(
        &self,
        actual: ProcessIdentity,
        request: &PipeRequest,
    ) -> Result<(), Win32Error> {
        self.validate()?;
        if actual != self.expected_process {
            return Err(Win32Error::Unsupported("pipe peer birth identity mismatch"));
        }
        if request.pod_id != self.pod_id
            || request.incarnation != self.incarnation
            || request.generation != self.generation
        {
            return Err(Win32Error::Unsupported("pipe scope or generation mismatch"));
        }
        if self.role == PipeRole::Viewer && request.action != PipeAction::Observe {
            return Err(Win32Error::Unsupported("viewer capability cannot mutate"));
        }
        let mismatch = self
            .capability
            .iter()
            .zip(request.capability)
            .fold(0_u8, |acc, (&a, b)| acc | (a ^ b));
        if mismatch != 0 {
            return Err(Win32Error::Unsupported("pipe capability mismatch"));
        }
        Ok(())
    }
}

fn validate_pod_id(value: &str) -> Result<(), Win32Error> {
    if !(3..=160).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(Win32Error::Invalid("pipe pod ID"));
    }
    Ok(())
}

#[cfg(any(windows, test))]
pub(crate) fn protected_sddl(logon_sid: &str) -> Result<String, Win32Error> {
    let parts = logon_sid
        .strip_prefix("S-1-5-5-")
        .and_then(|tail| tail.split_once('-'));
    if !matches!(parts, Some((left, right)) if !left.is_empty() && !right.is_empty() &&
        left.parse::<u32>().is_ok() && right.parse::<u32>().is_ok())
        || !logon_sid[1..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-')
        || logon_sid.len() > 80
    {
        return Err(Win32Error::Invalid("logon SID is not exact"));
    }
    // System may administer the pipe; this logon SID gets only data read/write
    // and SYNCHRONIZE (0x00100003), not FILE_CREATE_PIPE_INSTANCE (0x4).
    Ok(format!("D:P(A;;GA;;;SY)(A;;0x00100003;;;{logon_sid})"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn grant() -> PeerGrant {
        PeerGrant {
            expected_process: ProcessIdentity {
                pid: 41,
                creation_100ns: 7,
            },
            pod_id: "pod.fixture".into(),
            incarnation: 3,
            generation: 9,
            role: PipeRole::Viewer,
            capability: [5; 32],
        }
    }
    #[test]
    fn viewer_and_same_account_sibling_are_refused_before_dispatch() {
        let grant = grant();
        let mut request = PipeRequest {
            pod_id: grant.pod_id.clone(),
            incarnation: 3,
            generation: 9,
            action: PipeAction::Observe,
            capability: [5; 32],
            payload: vec![],
        };
        assert!(grant.authorize(grant.expected_process, &request).is_ok());
        request.action = PipeAction::Input;
        assert!(grant.authorize(grant.expected_process, &request).is_err());
        request.action = PipeAction::Observe;
        assert!(
            grant
                .authorize(
                    ProcessIdentity {
                        pid: 42,
                        creation_100ns: 7
                    },
                    &request
                )
                .is_err()
        );
        assert!(
            grant
                .authorize(
                    ProcessIdentity {
                        pid: 41,
                        creation_100ns: 8
                    },
                    &request
                )
                .is_err()
        );
        request.capability = [6; 32];
        assert!(grant.authorize(grant.expected_process, &request).is_err());
    }
    #[test]
    fn frame_roundtrip_and_bounds_are_exact() {
        let request = PipeRequest {
            pod_id: "pod.fixture".into(),
            incarnation: 3,
            generation: 9,
            action: PipeAction::Resize,
            capability: [5; 32],
            payload: vec![1; 100],
        };
        let bytes = request.encode().unwrap();
        assert_eq!(PipeRequest::decode(&bytes).unwrap(), request);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(PipeRequest::decode(&trailing).is_err());
        let mut oversized = request;
        oversized.payload = vec![0; MAX_FRAME];
        assert!(oversized.encode().is_err());
    }
    #[test]
    fn pipe_dacl_never_grants_everyone_or_instance_creation_to_client() {
        let value = protected_sddl("S-1-5-5-100-200").unwrap();
        assert!(
            value.contains("0x00100003") && !value.contains(";;;WD") && !value.contains(";;;AN")
        );
        assert!(protected_sddl("S-1-1-0").is_err());
        assert!(protected_sddl("S-1-5-5-1-2)(A;;GA;;;WD").is_err());
    }
}
