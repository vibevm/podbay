//! Host-testable bounded raw-output projection. It does not infer TUI success.
use std::collections::VecDeque;
use std::time::Duration;

use crate::Win32Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputChunk {
    pub sequence: u64,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputPage {
    pub chunks: Vec<OutputChunk>,
    pub through: u64,
    pub next_cursor: u64,
    pub has_more: bool,
    pub gap: Option<u64>,
    /// PB27b has raw bounded bytes only; no durable parser checkpoint yet.
    pub partial: bool,
    pub unknown: bool,
}
pub(crate) struct OutputState {
    sequence: u64,
    bytes: usize,
    chunks: VecDeque<OutputChunk>,
    unknown: bool,
}
impl OutputState {
    pub(crate) fn new() -> Self {
        Self {
            sequence: 0,
            bytes: 0,
            chunks: VecDeque::new(),
            unknown: false,
        }
    }
    pub(crate) fn mark_unknown(&mut self) {
        self.unknown = true;
    }
    pub(crate) fn push(&mut self, bytes: &[u8]) {
        let Some(next) = self.sequence.checked_add(1) else {
            self.unknown = true;
            return;
        };
        self.sequence = next;
        self.bytes += bytes.len();
        self.chunks.push_back(OutputChunk {
            sequence: self.sequence,
            bytes: bytes.to_vec(),
        });
        while self.chunks.len() > 256 || self.bytes > 1_048_576 {
            if let Some(old) = self.chunks.pop_front() {
                self.bytes -= old.bytes.len();
            }
        }
    }
    pub(crate) fn page(&self, after: u64, limit: usize) -> Result<OutputPage, Win32Error> {
        if !(1..=256).contains(&limit) {
            return Err(Win32Error::Invalid("output page limit"));
        }
        if after > self.sequence {
            return Err(Win32Error::Invalid("output cursor is in the future"));
        }
        let first = self
            .chunks
            .front()
            .map_or(self.sequence + 1, |chunk| chunk.sequence);
        let gap = (after.saturating_add(1) < first).then_some(first);
        let mut chunks = Vec::new();
        let mut bytes = 0_usize;
        for chunk in self.chunks.iter().filter(|chunk| chunk.sequence > after) {
            if chunks.len() >= limit
                || (!chunks.is_empty() && bytes + chunk.bytes.len() > 64 * 1024)
            {
                break;
            }
            bytes += chunk.bytes.len();
            chunks.push(chunk.clone());
        }
        let next_cursor = chunks.last().map_or(after, |chunk| chunk.sequence);
        Ok(OutputPage {
            chunks,
            through: self.sequence,
            next_cursor,
            has_more: next_cursor < self.sequence,
            gap,
            partial: true,
            unknown: self.unknown,
        })
    }
}

pub(crate) fn geometry(rows: u16, cols: u16) -> Result<(), Win32Error> {
    if rows == 0 || rows > 200 || cols == 0 || cols > 400 {
        Err(Win32Error::Invalid("ConPTY geometry bound"))
    } else {
        Ok(())
    }
}
pub(crate) fn validate_timeout(value: Duration) -> Result<(), Win32Error> {
    if value.is_zero() || value > Duration::from_secs(5) {
        Err(Win32Error::Invalid("ConPTY timeout bound"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_raw_output_has_exact_gap_and_bounded_pages() {
        let mut state = OutputState::new();
        for _ in 0..300 {
            state.push(&vec![b'x'; 4_096]);
        }
        let page = state.page(0, 256).unwrap();
        assert!(page.gap.is_some() && page.partial && !page.unknown);
        assert!(page.chunks.len() <= 16 && page.has_more);
        let next = state.page(page.next_cursor, 256).unwrap();
        assert_eq!(next.gap, None);
        assert_eq!(next.chunks.first().unwrap().sequence, page.next_cursor + 1);
        assert!(state.page(301, 1).is_err());
        state.mark_unknown();
        assert!(state.page(299, 1).unwrap().unknown);
    }
    #[test]
    fn geometry_and_deadlines_refuse_out_of_bounds() {
        assert!(geometry(0, 80).is_err());
        assert!(geometry(24, 401).is_err());
        assert!(geometry(24, 80).is_ok());
        assert!(validate_timeout(Duration::ZERO).is_err());
        assert!(validate_timeout(Duration::from_secs(6)).is_err());
        assert!(validate_timeout(Duration::from_secs(2)).is_ok());
    }
}
