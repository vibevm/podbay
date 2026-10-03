//! Bounded JSONL framing for the Codex app-server transport.

use serde_json::Value;

/// The same upper bound is applied to requests and inbound frames.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    Empty,
    MissingNewline,
    MultipleLines,
    TooLarge,
    InvalidJson,
    NotObject,
}

pub fn encode(value: &Value) -> Result<Vec<u8>, CodecError> {
    if !value.is_object() {
        return Err(CodecError::NotObject);
    }
    let mut bytes = serde_json::to_vec(value).map_err(|_| CodecError::InvalidJson)?;
    if bytes.len() >= MAX_FRAME_BYTES {
        return Err(CodecError::TooLarge);
    }
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn decode(frame: &[u8]) -> Result<Value, CodecError> {
    if frame.is_empty() {
        return Err(CodecError::Empty);
    }
    if frame.len() > MAX_FRAME_BYTES {
        return Err(CodecError::TooLarge);
    }
    if frame.last() != Some(&b'\n') {
        return Err(CodecError::MissingNewline);
    }
    if frame[..frame.len() - 1].contains(&b'\n') {
        return Err(CodecError::MultipleLines);
    }
    let value: Value =
        serde_json::from_slice(&frame[..frame.len() - 1]).map_err(|_| CodecError::InvalidJson)?;
    if !value.is_object() {
        return Err(CodecError::NotObject);
    }
    Ok(value)
}
