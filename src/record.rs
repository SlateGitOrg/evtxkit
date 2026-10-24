//! Event record framing.
//!
//! | off | size | field |
//! |----:|-----:|-------|
//! | 0   | 4    | `2a 2a 00 00` |
//! | 4   | 4    | record size (header + body + trailing size copy) |
//! | 8   | 8    | event record identifier |
//! | 16  | 8    | written time (FILETIME) |
//! | 24  | n    | BinXML body |
//! | size-4 | 4 | copy of the record size |

use crate::bytes::{u32_at, u64_at};
use crate::error::{EvtxError, Result};
use crate::model::Element;
use crate::time::FileTime;

/// Record signature bytes.
pub const RECORD_MAGIC: [u8; 4] = [0x2a, 0x2a, 0x00, 0x00];
/// Fixed record header size before the BinXML body.
pub const RECORD_HEADER_SIZE: usize = 24;

/// The fixed fields that frame a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    /// Total record size in bytes.
    pub size: u32,
    /// Whether the trailing size copy matches. Windows leaves it zero while a
    /// record is being written, so a mismatch is reported but not fatal.
    pub size_copy_valid: bool,
    /// Event record identifier.
    pub record_id: u64,
    /// When the record was written.
    pub timestamp: FileTime,
}

impl RecordHeader {
    /// Validates framing of the record at `pos` that must end before `limit`.
    pub fn parse(data: &[u8], pos: usize, limit: usize) -> Result<Self> {
        let limit = limit.min(data.len());
        if pos + RECORD_HEADER_SIZE > limit {
            return Err(EvtxError::Truncated {
                offset: pos,
                need: RECORD_HEADER_SIZE,
                available: limit.saturating_sub(pos),
            });
        }
        if data[pos..pos + 4] != RECORD_MAGIC {
            return Err(EvtxError::BadSignature {
                what: "record",
                offset: pos,
            });
        }
        let size = u32_at(data, pos + 4)?;
        let total = size as usize;
        if total < RECORD_HEADER_SIZE + 4 || pos + total > limit {
            return Err(EvtxError::invalid(
                "record size",
                pos + 4,
                format!("{size} does not fit the chunk"),
            ));
        }
        let copy = u32_at(data, pos + total - 4)?;
        Ok(RecordHeader {
            size,
            size_copy_valid: copy == size,
            record_id: u64_at(data, pos + 8)?,
            timestamp: FileTime(u64_at(data, pos + 16)?),
        })
    }
}

/// A fully decoded event record.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    /// Index of the chunk the record came from.
    pub chunk_index: usize,
    /// Absolute file offset of the record.
    pub file_offset: usize,
    /// Event record identifier from the record header.
    pub record_id: u64,
    /// Written time from the record header.
    pub timestamp: FileTime,
    /// False when the trailing size copy disagrees with the header.
    pub size_copy_valid: bool,
    /// True when the record was found by scanning forward after a framing
    /// error earlier in the same chunk (see `Records`).
    pub recovered: bool,
    /// The `<Event>` tree.
    pub root: Element,
}

/// A record (or record-shaped region) that could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordError {
    /// Chunk index.
    pub chunk_index: usize,
    /// Absolute file offset of the failing record.
    pub file_offset: usize,
    /// Record identifier, when framing was intact enough to read it.
    pub record_id: Option<u64>,
    /// The underlying error.
    pub error: EvtxError,
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "chunk {} @ {:#x}", self.chunk_index, self.file_offset)?;
        if let Some(id) = self.record_id {
            write!(f, " (record {id})")?;
        }
        write!(f, ": {}", self.error)
    }
}

impl std::error::Error for RecordError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(size: u32, copy: u32) -> Vec<u8> {
        let mut v = vec![0u8; size as usize];
        v[..4].copy_from_slice(&RECORD_MAGIC);
        v[4..8].copy_from_slice(&size.to_le_bytes());
        v[8..16].copy_from_slice(&7u64.to_le_bytes());
        v[16..24].copy_from_slice(&9u64.to_le_bytes());
        let n = v.len();
        v[n - 4..].copy_from_slice(&copy.to_le_bytes());
        v
    }

    #[test]
    fn framing_validation() {
        let ok = frame(32, 32);
        let h = RecordHeader::parse(&ok, 0, ok.len()).unwrap();
        assert_eq!((h.size, h.record_id, h.timestamp), (32, 7, FileTime(9)));
        assert!(h.size_copy_valid);
        assert!(
            !RecordHeader::parse(&frame(32, 33), 0, 32)
                .unwrap()
                .size_copy_valid
        );
        assert!(RecordHeader::parse(&ok, 0, 31).is_err());
        let mut bad = ok.clone();
        bad[0] = 0;
        assert!(matches!(
            RecordHeader::parse(&bad, 0, 32),
            Err(EvtxError::BadSignature { .. })
        ));
        let mut tiny = frame(32, 32);
        tiny[4..8].copy_from_slice(&8u32.to_le_bytes());
        assert!(RecordHeader::parse(&tiny, 0, 32).is_err());
        assert!(RecordHeader::parse(&ok, 20, 32).is_err());
    }

    #[test]
    fn error_display() {
        let e = RecordError {
            chunk_index: 2,
            file_offset: 0x10,
            record_id: Some(5),
            error: EvtxError::Io("x".into()),
        };
        assert_eq!(e.to_string(), "chunk 2 @ 0x10 (record 5): I/O error: x");
    }
}
