use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::DecimalString;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireError {
    Json(String),
    UnsupportedVersion,
    UnsupportedOperation(String),
    InvalidField(&'static str),
    InvalidCounter,
    DigestMismatch,
    FrameTooLarge,
    FrameLengthMismatch,
    ForeignLineage,
    ForeignScope,
    FutureCursor,
    ReplayGap { earliest: DecimalString },
}

impl Display for WireError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(message) => write!(formatter, "invalid JSON: {message}"),
            Self::UnsupportedVersion => formatter.write_str("unsupported PodBay protocol version"),
            Self::UnsupportedOperation(operation) => {
                write!(formatter, "unsupported mutation operation: {operation}")
            }
            Self::InvalidField(field) => write!(formatter, "invalid wire field: {field}"),
            Self::InvalidCounter => {
                formatter.write_str("counter is not a canonical decimal string")
            }
            Self::DigestMismatch => {
                formatter.write_str("command payload digest does not match content")
            }
            Self::FrameTooLarge => formatter.write_str("wire frame exceeds configured bound"),
            Self::FrameLengthMismatch => {
                formatter.write_str("wire frame length does not match prefix")
            }
            Self::ForeignLineage => formatter.write_str("cursor belongs to another store lineage"),
            Self::ForeignScope => formatter.write_str("cursor belongs to another query scope"),
            Self::FutureCursor => formatter.write_str("cursor exceeds the committed event head"),
            Self::ReplayGap { earliest } => {
                write!(formatter, "cursor precedes retained history at {earliest}")
            }
        }
    }
}

impl Error for WireError {}

impl From<serde_json::Error> for WireError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}
