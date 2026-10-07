//! Fixed binary pipe records; values bind a live launch, never create authority.
#![forbid(unsafe_code)]
use sha2::{Digest, Sha256};

pub const MAGIC: &[u8; 8] = b"R1READ01";
pub const CHALLENGE_BYTES: usize = 72;
pub const SEALED_BYTES: usize = 64;
pub const RESULT_BYTES: usize = 168;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Subject {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
}
pub fn sealed(pid: u32, subject: Subject) -> [u8; SEALED_BYTES] {
    let mut out = [0; SEALED_BYTES];
    out[..8].copy_from_slice(MAGIC);
    out[8] = 1;
    out[12..16].copy_from_slice(&pid.to_le_bytes());
    out[16..24].copy_from_slice(&subject.device.to_le_bytes());
    out[24..32].copy_from_slice(&subject.inode.to_le_bytes());
    out[32..40].copy_from_slice(&subject.size.to_le_bytes());
    out
}
pub fn verify_sealed(raw: &[u8], pid: u32, subject: Subject) -> bool {
    raw == sealed(pid, subject)
}
pub fn challenge(nonce: [u8; 32], generation: [u8; 32]) -> [u8; CHALLENGE_BYTES] {
    let mut out = [0; CHALLENGE_BYTES];
    out[..8].copy_from_slice(MAGIC);
    out[8..40].copy_from_slice(&nonce);
    out[40..].copy_from_slice(&generation);
    out
}
pub fn parse_challenge(raw: &[u8], generation: [u8; 32]) -> Option<[u8; 32]> {
    if raw.len() != CHALLENGE_BYTES || &raw[..8] != MAGIC || raw[40..] != generation {
        return None;
    }
    raw[8..40].try_into().ok()
}
pub fn result(source: [u8; 32], bound: [u8; 32], nonce: [u8;32], generation: [u8;32], subject: Subject) -> [u8; RESULT_BYTES] {
    let mut out = [0; RESULT_BYTES];
    out[..8].copy_from_slice(MAGIC);
    out[8] = 2;
    out[16..48].copy_from_slice(&source);
    out[48..80].copy_from_slice(&bound);
    out[80..112].copy_from_slice(&nonce);
    out[112..144].copy_from_slice(&generation);
    out[144..152].copy_from_slice(&subject.device.to_le_bytes());
    out[152..160].copy_from_slice(&subject.inode.to_le_bytes());
    out[160..168].copy_from_slice(&subject.size.to_le_bytes());
    out
}
pub fn parse_result(raw: &[u8], nonce: [u8;32], generation: [u8;32], subject: Subject) -> Option<([u8; 32], [u8; 32])> {
    if raw.len() != RESULT_BYTES || &raw[..8] != MAGIC || raw[8] != 2 || raw[9..16] != [0; 7] {
        return None;
    }
    let expected=result([0;32],[0;32],nonce,generation,subject);
    if raw[80..]!=expected[80..] { return None; }
    Some((raw[16..48].try_into().ok()?, raw[48..80].try_into().ok()?))
}
pub fn bound_hasher(nonce: &[u8; 32]) -> Sha256 {
    let mut h = Sha256::new();
    h.update(b"podbay.appliance.read/1\0");
    h.update(nonce);
    h
}
pub fn hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn digest(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_records_reject_truncation_foreign_and_extra() {
        let s = Subject {
            device: 1,
            inode: 2,
            size: 3,
        };
        let mut r = sealed(7, s);
        assert!(verify_sealed(&r, 7, s));
        r[63] = 1;
        assert!(!verify_sealed(&r, 7, s));
        let c = challenge([1; 32], [2; 32]);
        assert_eq!(parse_challenge(&c, [2; 32]), Some([1; 32]));
        assert!(parse_challenge(&c[..71], [2; 32]).is_none());
        assert!(parse_challenge(&c, [3; 32]).is_none());
        let mut r = result([4; 32], [5; 32], [1;32], [2;32], s);
        assert_eq!(parse_result(&r,[1;32],[2;32],s), Some(([4; 32], [5; 32])));
        r[9] = 1;
        assert!(parse_result(&r,[1;32],[2;32],s).is_none());
    }
    #[test]
    fn nonce_binding_is_not_config_echo() {
        let mut a = bound_hasher(&[1; 32]);
        a.update(b"source");
        let mut b = bound_hasher(&[2; 32]);
        b.update(b"source");
        assert_ne!(a.finalize(), b.finalize());
    }
}
