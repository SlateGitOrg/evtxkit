//! Chunks: 64 KiB self-contained blocks holding records plus their string and
//! template tables.
//!
//! Layout (offsets inside the chunk):
//!
//! | off | size | field |
//! |----:|-----:|-------|
//! | 0   | 8    | `ElfChnk\0` |
//! | 8   | 8    | first record number |
//! | 16  | 8    | last record number |
//! | 24  | 8    | first record identifier |
//! | 32  | 8    | last record identifier |
//! | 40  | 4    | header size (128) |
//! | 44  | 4    | offset of last record |
//! | 48  | 4    | free space offset (end of record data) |
//! | 52  | 4    | CRC32 of record data `512..free_space_offset` |
//! | 120 | 4    | flags (0x1 dirty, 0x4 no CRC32) |
//! | 124 | 4    | CRC32 of bytes `0..120` and `128..512` |
//! | 128 | 256  | common string offset table (64 buckets) |
//! | 384 | 128  | template pointer table (32 buckets) |
//! | 512 | ...  | event records |
//!
//! Because every name and template a record references lives in the same
//! chunk, chunks can be decoded independently, which is what makes the
//! chunk-parallel pipeline possible.

use crate::binxml::{ChunkContext, Limits};
use crate::bytes::{u32_at, u64_at};
use crate::crc32::{Crc32, crc32};
use crate::error::{EvtxError, Result};
use crate::record::{RECORD_HEADER_SIZE, Record, RecordError, RecordHeader};
use std::collections::HashSet;

/// Size of every chunk.
pub const CHUNK_SIZE: usize = 0x10000;
/// Size of the chunk header (including string/template tables).
pub const CHUNK_HEADER_SIZE: usize = 512;
/// Chunk signature.
pub const CHUNK_MAGIC: &[u8; 8] = b"ElfChnk\0";
/// Chunk flag: CRC32 fields are not maintained.
pub const CHUNK_FLAG_NO_CRC32: u32 = 0x4;

/// Decoded chunk header fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkHeader {
    /// First record number in the chunk.
    pub first_record_number: u64,
    /// Last record number in the chunk.
    pub last_record_number: u64,
    /// First record identifier.
    pub first_record_id: u64,
    /// Last record identifier.
    pub last_record_id: u64,
    /// Declared header size (128).
    pub header_size: u32,
    /// Offset of the last record.
    pub last_record_offset: u32,
    /// Offset where unused space begins.
    pub free_space_offset: u32,
    /// Stored CRC32 of the record data.
    pub records_crc: u32,
    /// Chunk flags.
    pub flags: u32,
    /// Stored CRC32 of the header.
    pub header_crc: u32,
}

/// Outcome of verifying one stored checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrcStatus {
    /// Stored and computed values agree.
    Valid,
    /// They differ.
    Mismatch {
        /// Value stored in the file.
        stored: u32,
        /// Value computed from the data.
        computed: u32,
    },
    /// The structure's flags say no CRC is maintained.
    Disabled,
}

impl CrcStatus {
    fn check(stored: u32, computed: u32, disabled: bool) -> Self {
        if disabled {
            CrcStatus::Disabled
        } else if stored == computed {
            CrcStatus::Valid
        } else {
            CrcStatus::Mismatch { stored, computed }
        }
    }

    /// True unless this is a mismatch.
    pub fn is_ok(self) -> bool {
        !matches!(self, CrcStatus::Mismatch { .. })
    }
}

impl ChunkHeader {
    /// Decodes the header; fails only on truncation or a bad signature.
    pub fn parse(data: &[u8], file_offset: usize) -> Result<Self> {
        if data.len() < CHUNK_HEADER_SIZE {
            return Err(EvtxError::Truncated {
                offset: file_offset,
                need: CHUNK_HEADER_SIZE,
                available: data.len(),
            });
        }
        if &data[..8] != CHUNK_MAGIC {
            return Err(EvtxError::BadSignature {
                what: "chunk",
                offset: file_offset,
            });
        }
        Ok(ChunkHeader {
            first_record_number: u64_at(data, 8)?,
            last_record_number: u64_at(data, 16)?,
            first_record_id: u64_at(data, 24)?,
            last_record_id: u64_at(data, 32)?,
            header_size: u32_at(data, 40)?,
            last_record_offset: u32_at(data, 44)?,
            free_space_offset: u32_at(data, 48)?,
            records_crc: u32_at(data, 52)?,
            flags: u32_at(data, 120)?,
            header_crc: u32_at(data, 124)?,
        })
    }

    /// End of record data, clamped into the chunk.
    pub fn records_end(&self, chunk_len: usize) -> usize {
        let fso = self.free_space_offset as usize;
        if fso < CHUNK_HEADER_SIZE || fso > chunk_len {
            chunk_len
        } else {
            fso
        }
    }
}

/// A decoded chunk borrowing its bytes from the file buffer.
#[derive(Debug, Clone)]
pub struct Chunk<'a> {
    /// Zero-based chunk index in the file.
    pub index: usize,
    /// Absolute file offset of the chunk.
    pub file_offset: usize,
    /// Decoded header.
    pub header: ChunkHeader,
    /// Header checksum verification.
    pub header_crc: CrcStatus,
    /// Record-area checksum verification.
    pub records_crc: CrcStatus,
    data: &'a [u8],
}

/// Classification of one 64 KiB slot of the file.
#[derive(Debug, Clone)]
pub enum ChunkSlot<'a> {
    /// A chunk with a valid signature.
    Chunk(Chunk<'a>),
    /// An all-zero, never-used slot (pre-allocated file space).
    Empty {
        /// Slot index.
        index: usize,
    },
    /// A slot that could not be decoded.
    Corrupt {
        /// Slot index.
        index: usize,
        /// Why.
        error: EvtxError,
    },
}

impl<'a> Chunk<'a> {
    /// Classifies and decodes the slot at `index` whose bytes are `data`.
    pub fn parse(index: usize, file_offset: usize, data: &'a [u8]) -> ChunkSlot<'a> {
        if data.iter().all(|&b| b == 0) {
            return ChunkSlot::Empty { index };
        }
        let header = match ChunkHeader::parse(data, file_offset) {
            Ok(h) => h,
            Err(error) => return ChunkSlot::Corrupt { index, error },
        };
        if data.len() < CHUNK_SIZE {
            return ChunkSlot::Corrupt {
                index,
                error: EvtxError::Truncated {
                    offset: file_offset,
                    need: CHUNK_SIZE,
                    available: data.len(),
                },
            };
        }
        let no_crc = header.flags & CHUNK_FLAG_NO_CRC32 != 0;
        let mut h = Crc32::new();
        h.update(&data[..120]);
        h.update(&data[128..CHUNK_HEADER_SIZE]);
        let header_crc = CrcStatus::check(header.header_crc, h.finish(), no_crc);
        let end = header.records_end(data.len());
        let records_crc = CrcStatus::check(
            header.records_crc,
            crc32(&data[CHUNK_HEADER_SIZE..end]),
            no_crc,
        );
        ChunkSlot::Chunk(Chunk {
            index,
            file_offset,
            header,
            header_crc,
            records_crc,
            data,
        })
    }

    /// The raw 64 KiB of the chunk.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// True if both checksums are valid or disabled.
    pub fn crc_ok(&self) -> bool {
        self.header_crc.is_ok() && self.records_crc.is_ok()
    }

    /// Iterates over the records with default limits.
    pub fn records(&self) -> Records<'a> {
        self.records_with(Limits::default())
    }

    /// Iterates over the records using explicit resource limits.
    pub fn records_with(&self, limits: Limits) -> Records<'a> {
        Records {
            ctx: ChunkContext::new(self.data, limits),
            chunk_index: self.index,
            file_offset: self.file_offset,
            pos: CHUNK_HEADER_SIZE,
            end: self.header.records_end(self.data.len()),
            resynced: false,
        }
    }

    /// Offsets of template definitions reachable from the template pointer table.
    pub fn template_offsets(&self) -> Vec<usize> {
        self.walk_table(384, 32)
    }

    /// Offsets of names reachable from the common string table.
    pub fn common_string_offsets(&self) -> Vec<usize> {
        self.walk_table(128, 64)
    }

    /// Follows the `next` links (first `u32` of each entry) of a hash table.
    /// Cycle-safe: each offset is visited once.
    fn walk_table(&self, table: usize, buckets: usize) -> Vec<usize> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for b in 0..buckets {
            let mut off = u32_at(self.data, table + b * 4).unwrap_or(0) as usize;
            while off >= CHUNK_HEADER_SIZE && off + 4 <= self.data.len() && seen.insert(off) {
                out.push(off);
                off = u32_at(self.data, off).unwrap_or(0) as usize;
            }
        }
        out.sort_unstable();
        out
    }
}

/// Iterator over the records of one chunk.
///
/// Framing errors (bad signature, impossible size) are reported once and the
/// iterator then scans forward for the next plausible record header, so one
/// damaged record does not hide the rest of the chunk.
pub struct Records<'a> {
    ctx: ChunkContext<'a>,
    chunk_index: usize,
    file_offset: usize,
    pos: usize,
    end: usize,
    resynced: bool,
}

impl<'a> Records<'a> {
    /// Templates successfully parsed so far in this chunk.
    pub fn templates_seen(&self) -> usize {
        self.ctx.templates_seen()
    }

    fn framing_at(&self, pos: usize) -> Result<RecordHeader> {
        RecordHeader::parse(self.ctx.data(), pos, self.end)
    }

    /// Finds the next offset after `from` that holds a well-framed record.
    fn resync(&self, from: usize) -> usize {
        let data = self.ctx.data();
        let mut p = from;
        while p + RECORD_HEADER_SIZE <= self.end {
            // Resynchronisation is stricter than normal framing: the size copy
            // must match too, which makes false positives inside data unlikely.
            if data[p..p + 4] == crate::record::RECORD_MAGIC
                && self.framing_at(p).is_ok_and(|h| h.size_copy_valid)
            {
                return p;
            }
            p += 1;
        }
        self.end
    }

    fn error(&self, offset: usize, record_id: Option<u64>, error: EvtxError) -> RecordError {
        RecordError {
            chunk_index: self.chunk_index,
            file_offset: self.file_offset + offset,
            record_id,
            error,
        }
    }
}

impl Iterator for Records<'_> {
    type Item = std::result::Result<Record, RecordError>;

    fn next(&mut self) -> Option<Self::Item> {
        let data = self.ctx.data();
        if self.pos + RECORD_HEADER_SIZE > self.end {
            return None;
        }
        let pos = self.pos;
        let header = match self.framing_at(pos) {
            Ok(h) => h,
            Err(err) => {
                // Zero padding after the last record is normal: stop quietly.
                if data[pos..self.end].iter().all(|&b| b == 0) {
                    self.pos = self.end;
                    return None;
                }
                self.pos = self.resync(pos + 1);
                self.resynced = true;
                return Some(Err(self.error(pos, None, err)));
            }
        };
        if !header.size_copy_valid {
            tracing::debug!(
                chunk = self.chunk_index,
                offset = pos,
                "record size copy mismatch (record may be partially written)"
            );
        }
        self.pos = pos + header.size as usize;
        let body_start = pos + RECORD_HEADER_SIZE;
        let body_end = pos + header.size as usize - 4;
        Some(match self.ctx.parse_record(body_start, body_end) {
            Ok(root) => Ok(Record {
                chunk_index: self.chunk_index,
                file_offset: self.file_offset + pos,
                record_id: header.record_id,
                timestamp: header.timestamp,
                size_copy_valid: header.size_copy_valid,
                recovered: self.resynced,
                root,
            }),
            Err(err) => Err(self.error(pos, Some(header.record_id), err)),
        })
    }
}
