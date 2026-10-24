//! Error type shared by every layer of the parser.
//!
//! Every variant carries the byte offset where the problem was detected so a
//! corrupted file can be inspected with a hex editor. Offsets are relative to
//! the structure named in the message: file offsets for file/chunk framing,
//! chunk-relative offsets for anything inside a chunk (records, BinXML).

use thiserror::Error;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, EvtxError>;

/// Everything that can go wrong while decoding an EVTX file.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EvtxError {
    /// A read would run past the end of the available bytes.
    #[error("truncated data at offset {offset:#x}: need {need} bytes, {available} available")]
    Truncated {
        /// Offset of the attempted read.
        offset: usize,
        /// Bytes requested.
        need: usize,
        /// Bytes that were actually available.
        available: usize,
    },

    /// A structure did not start with its expected magic bytes.
    #[error("bad {what} signature at offset {offset:#x}")]
    BadSignature {
        /// Which structure (file header, chunk, record).
        what: &'static str,
        /// Offset of the signature.
        offset: usize,
    },

    /// A structurally invalid field (size, offset, count) was found.
    #[error("invalid {what} at offset {offset:#x}: {reason}")]
    Invalid {
        /// Field or structure name.
        what: &'static str,
        /// Offset of the offending field.
        offset: usize,
        /// Human-readable explanation.
        reason: String,
    },

    /// The BinXML stream contained a byte that is not a known token.
    #[error("unknown BinXML token {token:#04x} at offset {offset:#x}")]
    UnknownToken {
        /// The token byte.
        token: u8,
        /// Chunk-relative offset of the token.
        offset: usize,
    },

    /// A known token appeared somewhere it is not allowed.
    #[error("unexpected BinXML token {token:#04x} at offset {offset:#x}: {context}")]
    UnexpectedToken {
        /// The token byte.
        token: u8,
        /// Chunk-relative offset of the token.
        offset: usize,
        /// Why it is not allowed here.
        context: &'static str,
    },

    /// A substitution value used a type this parser cannot decode.
    #[error("unsupported value type {value_type:#04x} at offset {offset:#x}")]
    UnsupportedValueType {
        /// The value type byte.
        value_type: u8,
        /// Chunk-relative offset of the value.
        offset: usize,
    },

    /// A fixed-size value had a size that does not match its type.
    #[error("value type {value_type:#04x} cannot have size {size} (offset {offset:#x})")]
    BadValueSize {
        /// The value type byte.
        value_type: u8,
        /// Declared size in bytes.
        size: usize,
        /// Chunk-relative offset of the value.
        offset: usize,
    },

    /// Nested BinXML fragments or elements exceeded the configured depth.
    #[error("nesting depth limit ({limit}) exceeded at offset {offset:#x}")]
    DepthLimit {
        /// The configured limit.
        limit: usize,
        /// Offset where the limit was hit.
        offset: usize,
    },

    /// Template instantiation (array expansion) produced too many nodes.
    #[error("template expansion limit ({limit} nodes) exceeded")]
    ExpansionLimit {
        /// The configured limit.
        limit: usize,
    },

    /// An operating-system I/O error (message only, so the type stays `Clone`).
    #[error("I/O error: {0}")]
    Io(String),
}

impl From<std::io::Error> for EvtxError {
    fn from(err: std::io::Error) -> Self {
        EvtxError::Io(err.to_string())
    }
}

impl EvtxError {
    /// Convenience constructor for [`EvtxError::Invalid`].
    pub fn invalid(what: &'static str, offset: usize, reason: impl Into<String>) -> Self {
        EvtxError::Invalid {
            what,
            offset,
            reason: reason.into(),
        }
    }
}
