//! Building synthetic multi-chunk EVTX files from real chunks.
//!
//! Chunks are self-contained, so concatenating valid chunks from several files
//! behind a fresh file header yields a valid EVTX file. This is how the
//! throughput benchmark builds a large input from the small committed samples,
//! and how tests produce files with many chunks for the parallel pipeline.
//! The output repeats real events; it adds no new ones.

use crate::chunk::ChunkSlot;
use crate::crc32::crc32;
use crate::file::{EvtxFile, FILE_HEADER_SIZE, FILE_MAGIC};

/// A file header for `chunk_count` chunks with a valid CRC32.
pub fn file_header(chunk_count: usize, next_record_id: u64) -> Vec<u8> {
    let mut h = vec![0u8; FILE_HEADER_SIZE];
    h[..8].copy_from_slice(FILE_MAGIC);
    let last = chunk_count.saturating_sub(1) as u64;
    h[16..24].copy_from_slice(&last.to_le_bytes());
    h[24..32].copy_from_slice(&next_record_id.to_le_bytes());
    h[32..36].copy_from_slice(&128u32.to_le_bytes());
    h[36..38].copy_from_slice(&1u16.to_le_bytes());
    h[38..40].copy_from_slice(&3u16.to_le_bytes());
    h[40..42].copy_from_slice(&4096u16.to_le_bytes());
    let count = u16::try_from(chunk_count).unwrap_or(u16::MAX);
    h[42..44].copy_from_slice(&count.to_le_bytes());
    let c = crc32(&h[..120]);
    h[124..128].copy_from_slice(&c.to_le_bytes());
    h
}

/// Concatenates every decodable chunk of `sources`, `copies` times over.
pub fn stitch(sources: &[&EvtxFile], copies: usize) -> Vec<u8> {
    let chunks: Vec<&[u8]> = sources
        .iter()
        .flat_map(|f| f.chunks())
        .filter_map(|slot| match slot {
            ChunkSlot::Chunk(c) => Some(c.data()),
            _ => None,
        })
        .collect();
    let total = chunks.len() * copies;
    let mut out = file_header(total, 1);
    out.reserve(total * crate::chunk::CHUNK_SIZE);
    for _ in 0..copies {
        for c in &chunks {
            out.extend_from_slice(c);
        }
    }
    out
}
