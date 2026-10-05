//! Private local transport uses one bounded big-endian u32 length followed by JSON bytes.
use serde::Serialize;

use crate::WireError;

pub const MAX_FRAME_BYTES: usize = 16 * 1_048_576;

pub fn encode_frame(value: &impl Serialize) -> Result<Vec<u8>, WireError> {
    let payload = serde_json::to_vec(value)?;
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge);
    }
    let length = u32::try_from(payload.len()).map_err(|_| WireError::FrameTooLarge)?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_frame_bytes(frame: &[u8]) -> Result<&[u8], WireError> {
    if frame.len() < 4 {
        return Err(WireError::FrameLengthMismatch);
    }
    let declared = u32::from_be_bytes(frame[..4].try_into().expect("four-byte prefix")) as usize;
    if declared == 0 || declared > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge);
    }
    if frame.len() != declared + 4 {
        return Err(WireError::FrameLengthMismatch);
    }
    Ok(&frame[4..])
}
