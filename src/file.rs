//! The EVTX file: a 4 KiB header followed by 64 KiB chunks.
//!
//! File header layout (only the first 128 bytes are used):
//!
//! | off | size | field |
//! |----:|-----:|-------|
//! | 0   | 8    | `ElfFile\0` |
//! | 8   | 8    | first chunk number |
//! | 16  | 8    | last chunk number |
//! | 24  | 8    | next record identifier |
//! | 32  | 4    | header size (128) |
//! | 36  | 2    | minor version (1 or 2) |
//! | 38  | 2    | major version (3) |
//! | 40  | 2    | header block size (4096) |
//! | 42  | 2    | chunk count |
//! | 120 | 4    | flags (0x1 dirty, 0x2 full, 0x4 no CRC32) |
//! | 124 | 4    | CRC32 of bytes `0..120` |
//!
//! The chunk count in the header is not trusted: dirty or carved files often
//! hold valid chunks beyond it, so every complete 64 KiB slot is examined.

use crate::bytes::{u16_at, u32_at, u64_at};
use crate::chunk::{CHUNK_SIZE, Chunk, ChunkSlot, CrcStatus};
use crate::crc32::crc32;
use crate::error::{EvtxError, Result};
use crate::record::{Record, RecordError};
use std::path::Path;

/// Size of the file header block.
pub const FILE_HEADER_SIZE: usize = 4096;
/// File signature.
pub const FILE_MAGIC: &[u8; 8] = b"ElfFile\0";
/// File flag: dirty (not cleanly closed).
pub const FILE_FLAG_DIRTY: u32 = 0x1;
/// File flag: full.
pub const FILE_FLAG_FULL: u32 = 0x2;
/// File flag: CRC32 values are not maintained.
pub const FILE_FLAG_NO_CRC32: u32 = 0x4;

/// Decoded file header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    /// First chunk number.
    pub first_chunk_number: u64,
    /// Last chunk number.
    pub last_chunk_number: u64,
    /// Next record identifier the writer would use.
    pub next_record_id: u64,
    /// Declared header size.
    pub header_size: u32,
    /// Minor format version.
    pub minor_version: u16,
    /// Major format version.
    pub major_version: u16,
    /// Header block size.
    pub header_block_size: u16,
    /// Declared chunk count.
    pub chunk_count: u16,
    /// Flags.
    pub flags: u32,
    /// Stored checksum.
    pub checksum: u32,
    /// Checksum verification.
    pub crc: CrcStatus,
}

impl FileHeader {
    /// Decodes and validates the header signature.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 128 {
            return Err(EvtxError::Truncated {
                offset: 0,
                need: 128,
                available: data.len(),
            });
        }
        if &data[..8] != FILE_MAGIC {
            return Err(EvtxError::BadSignature {
                what: "file header",
                offset: 0,
            });
        }
        let flags = u32_at(data, 120)?;
        let checksum = u32_at(data, 124)?;
        let crc = if flags & FILE_FLAG_NO_CRC32 != 0 {
            CrcStatus::Disabled
        } else {
            let computed = crc32(&data[..120]);
            if computed == checksum {
                CrcStatus::Valid
            } else {
                CrcStatus::Mismatch {
                    stored: checksum,
                    computed,
                }
            }
        };
        Ok(FileHeader {
            first_chunk_number: u64_at(data, 8)?,
            last_chunk_number: u64_at(data, 16)?,
            next_record_id: u64_at(data, 24)?,
            header_size: u32_at(data, 32)?,
            minor_version: u16_at(data, 36)?,
            major_version: u16_at(data, 38)?,
            header_block_size: u16_at(data, 40)?,
            chunk_count: u16_at(data, 42)?,
            flags,
            checksum,
            crc,
        })
    }

    /// True if the dirty flag is set.
    pub fn is_dirty(&self) -> bool {
        self.flags & FILE_FLAG_DIRTY != 0
    }
}

/// An EVTX file held in memory.
#[derive(Debug, Clone)]
pub struct EvtxFile {
    data: Vec<u8>,
    header: FileHeader,
}

impl EvtxFile {
    /// Reads and validates the file at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_bytes(std::fs::read(path)?)
    }

    /// Wraps bytes already in memory.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        if data.len() < FILE_HEADER_SIZE {
            return Err(EvtxError::Truncated {
                offset: 0,
                need: FILE_HEADER_SIZE,
                available: data.len(),
            });
        }
        let header = FileHeader::parse(&data)?;
        Ok(EvtxFile { data, header })
    }

    /// The decoded file header.
    pub fn header(&self) -> &FileHeader {
        &self.header
    }

    /// Raw file bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// Number of chunk slots, including a trailing partial one.
    pub fn slot_count(&self) -> usize {
        (self.data.len() - FILE_HEADER_SIZE).div_ceil(CHUNK_SIZE)
    }

    /// Decodes slot `index` (`index < slot_count()`).
    pub fn chunk(&self, index: usize) -> ChunkSlot<'_> {
        let start = FILE_HEADER_SIZE + index * CHUNK_SIZE;
        let end = (start + CHUNK_SIZE).min(self.data.len());
        if start >= end {
            return ChunkSlot::Corrupt {
                index,
                error: EvtxError::invalid("chunk index", start, "past end of file"),
            };
        }
        Chunk::parse(index, start, &self.data[start..end])
    }

    /// Iterates over every chunk slot in file order.
    pub fn chunks(&self) -> impl Iterator<Item = ChunkSlot<'_>> + '_ {
        (0..self.slot_count()).map(|i| self.chunk(i))
    }

    /// Iterates sequentially over every record of every decodable chunk.
    ///
    /// Corrupt chunks surface as a single [`RecordError`] each.
    pub fn records(&self) -> impl Iterator<Item = std::result::Result<Record, RecordError>> + '_ {
        self.chunks()
            .flat_map(|slot| -> Box<dyn Iterator<Item = _>> {
                match slot {
                    ChunkSlot::Chunk(chunk) => Box::new(chunk.records()),
                    ChunkSlot::Empty { .. } => Box::new(std::iter::empty()),
                    ChunkSlot::Corrupt { index, error } => {
                        Box::new(std::iter::once(Err(RecordError {
                            chunk_index: index,
                            file_offset: FILE_HEADER_SIZE + index * CHUNK_SIZE,
                            record_id: None,
                            error,
                        })))
                    }
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_bytes() -> Vec<u8> {
        let mut h = vec![0u8; FILE_HEADER_SIZE];
        h[..8].copy_from_slice(FILE_MAGIC);
        h[32..36].copy_from_slice(&128u32.to_le_bytes());
        h[36..38].copy_from_slice(&1u16.to_le_bytes());
        h[38..40].copy_from_slice(&3u16.to_le_bytes());
        h[40..42].copy_from_slice(&4096u16.to_le_bytes());
        let c = crc32(&h[..120]);
        h[124..128].copy_from_slice(&c.to_le_bytes());
        h
    }

    #[test]
    fn header_only_file() {
        let f = EvtxFile::from_bytes(header_bytes()).unwrap();
        assert_eq!(f.header().major_version, 3);
        assert_eq!(f.header().crc, CrcStatus::Valid);
        assert!(!f.header().is_dirty());
        assert_eq!(f.slot_count(), 0);
        assert_eq!(f.records().count(), 0);
        assert!(matches!(f.chunk(0), ChunkSlot::Corrupt { .. }));
    }

    #[test]
    fn header_errors_and_crc_states() {
        assert!(matches!(
            EvtxFile::from_bytes(vec![0; 100]),
            Err(EvtxError::Truncated { .. })
        ));
        let mut bad = header_bytes();
        bad[0] = b'X';
        assert!(matches!(
            EvtxFile::from_bytes(bad),
            Err(EvtxError::BadSignature { .. })
        ));
        let mut h = header_bytes();
        h[24] = 1; // changes CRC-covered bytes
        assert!(matches!(
            FileHeader::parse(&h).unwrap().crc,
            CrcStatus::Mismatch { .. }
        ));
        h[120] = 0x5; // dirty + no-crc
        let parsed = FileHeader::parse(&h).unwrap();
        assert_eq!(parsed.crc, CrcStatus::Disabled);
        assert!(parsed.is_dirty());
        assert!(FileHeader::parse(&h[..64]).is_err());
    }

    #[test]
    fn trailing_partial_and_zero_slots() {
        let mut data = header_bytes();
        data.extend(vec![0u8; CHUNK_SIZE]);
        data.extend(b"ElfChnk\0garbage");
        let f = EvtxFile::from_bytes(data).unwrap();
        assert_eq!(f.slot_count(), 2);
        assert!(matches!(f.chunk(0), ChunkSlot::Empty { index: 0 }));
        assert!(matches!(f.chunk(1), ChunkSlot::Corrupt { index: 1, .. }));
        let errs: Vec<_> = f.records().collect();
        assert_eq!(errs.len(), 1);
        assert!(errs[0].is_err());
    }
}
