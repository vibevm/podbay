//! Host-testable PB27d record and checkpoint recovery calculus.
use sha2::{Digest, Sha256};

pub const MAX_RECORD: usize = 1_048_576;
pub const MAX_LOG: usize = 64 * 1_048_576;
const MAGIC: &[u8; 8] = b"PDBDUR01";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    Event,
    Snapshot,
    Commit,
}
impl RecordKind {
    fn byte(self) -> u8 {
        match self {
            Self::Event => 1,
            Self::Snapshot => 2,
            Self::Commit => 3,
        }
    }
    fn from_byte(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Event),
            2 => Some(Self::Snapshot),
            3 => Some(Self::Commit),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub kind: RecordKind,
    pub sequence: u64,
    pub payload: Vec<u8>,
}
impl Record {
    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        if self.sequence == 0 || self.payload.len() > MAX_RECORD - 21 {
            return Err("record identity or size bound");
        }
        let mut body = Vec::with_capacity(21 + self.payload.len());
        body.extend_from_slice(MAGIC);
        body.push(self.kind.byte());
        body.extend_from_slice(&self.sequence.to_be_bytes());
        body.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        body.extend_from_slice(&self.payload);
        let digest = digest(&body);
        let mut frame = Vec::with_capacity(36 + body.len());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&digest);
        frame.extend_from_slice(&body);
        Ok(frame)
    }
}

pub fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"podbay-win32-durable/1\0");
    hash.update(bytes);
    hash.finalize().into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Unknown {
    /// Diagnostic only. Never use this as an accepted current checkpoint.
    pub last_valid_sequence: Option<u64>,
    pub gap_at: Option<u64>,
    pub reason: &'static str,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckpointRecovery {
    None,
    Ready { sequence: u64, bytes: Vec<u8> },
    Unknown(Unknown),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurabilityEvidence {
    /// File FlushFileBuffers returned; NTFS directory-entry power-loss
    /// persistence and reopened ACL equality have no native receipt yet.
    ProvisionalNtfsFlush,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlushReceipt {
    pub sequence: u64,
    pub evidence: DurabilityEvidence,
}

#[cfg(any(windows, test))]
#[derive(Default)]
pub(crate) struct WriteFence {
    uncertain: bool,
}
#[cfg(any(windows, test))]
impl WriteFence {
    pub(crate) fn mark_uncertain(&mut self) {
        self.uncertain = true;
    }
    pub(crate) fn is_uncertain(&self) -> bool {
        self.uncertain
    }
    pub(crate) fn permits_ack(&self) -> bool {
        !self.uncertain
    }
}

pub fn decode_log(
    bytes: &[u8],
    kind: RecordKind,
    expected_start: Option<u64>,
) -> Result<Vec<Record>, Unknown> {
    if bytes.len() > MAX_LOG {
        return Err(Unknown {
            last_valid_sequence: None,
            gap_at: expected_start,
            reason: "log byte bound",
        });
    }
    let mut cursor = 0_usize;
    let mut previous = None;
    let mut records = Vec::new();
    while cursor < bytes.len() {
        if bytes.len() - cursor < 36 {
            return Err(Unknown {
                last_valid_sequence: previous,
                gap_at: previous
                    .and_then(|s: u64| s.checked_add(1))
                    .or(expected_start),
                reason: "torn frame header",
            });
        }
        let length = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        if !(21..=MAX_RECORD).contains(&length) || bytes.len() - cursor < 36 + length {
            return Err(Unknown {
                last_valid_sequence: previous,
                gap_at: previous
                    .and_then(|s: u64| s.checked_add(1))
                    .or(expected_start),
                reason: "torn or oversized frame",
            });
        }
        let checksum = &bytes[cursor + 4..cursor + 36];
        let body = &bytes[cursor + 36..cursor + 36 + length];
        if checksum != digest(body) {
            return Err(Unknown {
                last_valid_sequence: previous,
                gap_at: previous
                    .and_then(|s: u64| s.checked_add(1))
                    .or(expected_start),
                reason: "frame checksum changed",
            });
        }
        if &body[..8] != MAGIC || RecordKind::from_byte(body[8]) != Some(kind) {
            return Err(Unknown {
                last_valid_sequence: previous,
                gap_at: None,
                reason: "record kind or version changed",
            });
        }
        let sequence = u64::from_be_bytes(body[9..17].try_into().unwrap());
        let payload_len = u32::from_be_bytes(body[17..21].try_into().unwrap()) as usize;
        if sequence == 0
            || payload_len != length - 21
            || previous.is_some_and(|last| sequence <= last)
        {
            return Err(Unknown {
                last_valid_sequence: previous,
                gap_at: Some(sequence),
                reason: "record sequence or length changed",
            });
        }
        if let Some(expected) = expected_start {
            let next = previous.map_or(expected, |last: u64| last.saturating_add(1));
            if sequence != next {
                return Err(Unknown {
                    last_valid_sequence: previous,
                    gap_at: Some(next),
                    reason: "event sequence gap",
                });
            }
        }
        records.push(Record {
            kind,
            sequence,
            payload: body[21..].to_vec(),
        });
        previous = Some(sequence);
        cursor += 36 + length;
    }
    Ok(records)
}

pub fn recover_checkpoint(
    commit_log: &[u8],
    mut load_generation: impl FnMut(u64) -> Option<Vec<u8>>,
) -> CheckpointRecovery {
    let commits = match decode_log(commit_log, RecordKind::Commit, None) {
        Ok(commits) => commits,
        Err(unknown) => return CheckpointRecovery::Unknown(unknown),
    };
    let Some(latest) = commits.last() else {
        return CheckpointRecovery::None;
    };
    if latest.payload.len() != 32 {
        return CheckpointRecovery::Unknown(Unknown {
            last_valid_sequence: Some(latest.sequence),
            gap_at: Some(latest.sequence),
            reason: "checkpoint digest missing",
        });
    }
    let Some(generation) = load_generation(latest.sequence) else {
        return CheckpointRecovery::Unknown(Unknown {
            last_valid_sequence: Some(latest.sequence),
            gap_at: Some(latest.sequence),
            reason: "committed generation missing",
        });
    };
    if latest.payload != digest(&generation) {
        return CheckpointRecovery::Unknown(Unknown {
            last_valid_sequence: Some(latest.sequence),
            gap_at: Some(latest.sequence),
            reason: "committed generation digest changed",
        });
    }
    match decode_log(&generation, RecordKind::Snapshot, Some(latest.sequence)) {
        Ok(records) if records.len() == 1 => CheckpointRecovery::Ready {
            sequence: latest.sequence,
            bytes: records[0].payload.clone(),
        },
        _ => CheckpointRecovery::Unknown(Unknown {
            last_valid_sequence: Some(latest.sequence),
            gap_at: Some(latest.sequence),
            reason: "committed generation malformed",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot(sequence: u64, payload: &[u8]) -> Vec<u8> {
        Record {
            kind: RecordKind::Snapshot,
            sequence,
            payload: payload.to_vec(),
        }
        .encode()
        .unwrap()
    }
    fn commit(sequence: u64, generation: &[u8]) -> Vec<u8> {
        Record {
            kind: RecordKind::Commit,
            sequence,
            payload: digest(generation).to_vec(),
        }
        .encode()
        .unwrap()
    }
    #[test]
    fn committed_generation_roundtrip_and_orphan_exclusion() {
        let generation = snapshot(9, b"screen at nine");
        assert_eq!(
            recover_checkpoint(&[], |_| Some(generation.clone())),
            CheckpointRecovery::None
        );
        assert_eq!(
            recover_checkpoint(&commit(9, &generation), |_| Some(generation.clone())),
            CheckpointRecovery::Ready {
                sequence: 9,
                bytes: b"screen at nine".to_vec()
            }
        );
    }
    #[test]
    fn torn_commit_and_corrupt_or_missing_generation_are_unknown() {
        let generation = snapshot(9, b"screen");
        let mut torn = commit(9, &generation);
        torn.pop();
        assert!(matches!(
            recover_checkpoint(&torn, |_| Some(generation.clone())),
            CheckpointRecovery::Unknown(_)
        ));
        assert!(matches!(
            recover_checkpoint(&commit(9, &generation), |_| None),
            CheckpointRecovery::Unknown(_)
        ));
        let mut corrupt = generation.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(matches!(
            recover_checkpoint(&commit(9, &generation), |_| Some(corrupt.clone())),
            CheckpointRecovery::Unknown(_)
        ));
        let newer = snapshot(10, b"newer");
        let mut log = commit(9, &generation);
        log.extend_from_slice(&commit(10, &newer)[..12]);
        assert!(matches!(
            recover_checkpoint(&log, |_| Some(generation.clone())),
            CheckpointRecovery::Unknown(Unknown {
                last_valid_sequence: Some(9),
                ..
            })
        ));
    }
    #[test]
    fn event_log_gap_and_torn_tail_are_explicit() {
        let one = Record {
            kind: RecordKind::Event,
            sequence: 1,
            payload: vec![1],
        }
        .encode()
        .unwrap();
        let three = Record {
            kind: RecordKind::Event,
            sequence: 3,
            payload: vec![3],
        }
        .encode()
        .unwrap();
        let mut gap = one.clone();
        gap.extend_from_slice(&three);
        assert_eq!(
            decode_log(&gap, RecordKind::Event, Some(1))
                .unwrap_err()
                .gap_at,
            Some(2)
        );
        let mut torn = one.clone();
        torn.extend_from_slice(&three[..10]);
        assert_eq!(
            decode_log(&torn, RecordKind::Event, Some(1))
                .unwrap_err()
                .gap_at,
            Some(2)
        );
    }
    #[test]
    fn ambiguous_flush_latches_and_cannot_settle_input() {
        let mut fence = WriteFence::default();
        assert!(fence.permits_ack());
        fence.mark_uncertain();
        assert!(fence.is_uncertain());
        assert!(!fence.permits_ack());
    }
    #[test]
    fn successful_flush_carries_only_provisional_evidence() {
        let receipt = FlushReceipt {
            sequence: 4,
            evidence: DurabilityEvidence::ProvisionalNtfsFlush,
        };
        assert_eq!(receipt.evidence, DurabilityEvidence::ProvisionalNtfsFlush);
    }
}
