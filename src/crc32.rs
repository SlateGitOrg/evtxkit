//! CRC-32 (IEEE 802.3, reflected polynomial `0xEDB88320`) implemented from scratch.
//!
//! EVTX protects three regions with this checksum: the first 120 bytes of the
//! file header, chunk header bytes `0..120` + `128..512`, and the record area
//! `512..free_space_offset` of each chunk.
//!
//! The implementation is "slicing-by-8": eight 256-entry tables (built at
//! compile time by a `const fn`) let the inner loop consume 8 bytes per
//! iteration with 8 independent table lookups instead of 8 dependent ones.
//! Time O(n), space O(1) beyond the 8 KiB of static tables.

const POLY: u32 = 0xEDB8_8320;

const fn build_tables() -> [[u32; 256]; 8] {
    let mut tables = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
            bit += 1;
        }
        tables[0][i] = crc;
        i += 1;
    }
    let mut t = 1;
    while t < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = tables[t - 1][i];
            tables[t][i] = (prev >> 8) ^ tables[0][(prev & 0xff) as usize];
            i += 1;
        }
        t += 1;
    }
    tables
}

static TABLES: [[u32; 256]; 8] = build_tables();

/// Incremental CRC-32 hasher.
#[derive(Debug, Clone, Copy)]
pub struct Crc32 {
    state: u32,
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32 {
    /// Starts a new checksum.
    pub const fn new() -> Self {
        Crc32 { state: !0 }
    }

    /// Feeds more bytes.
    pub fn update(&mut self, data: &[u8]) {
        let mut crc = self.state;
        let mut blocks = data.chunks_exact(8);
        for b in &mut blocks {
            let lo = crc ^ u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            crc = TABLES[7][(lo & 0xff) as usize]
                ^ TABLES[6][((lo >> 8) & 0xff) as usize]
                ^ TABLES[5][((lo >> 16) & 0xff) as usize]
                ^ TABLES[4][(lo >> 24) as usize]
                ^ TABLES[3][b[4] as usize]
                ^ TABLES[2][b[5] as usize]
                ^ TABLES[1][b[6] as usize]
                ^ TABLES[0][b[7] as usize];
        }
        for &byte in blocks.remainder() {
            crc = (crc >> 8) ^ TABLES[0][((crc ^ u32::from(byte)) & 0xff) as usize];
        }
        self.state = crc;
    }

    /// Returns the final checksum.
    pub const fn finish(self) -> u32 {
        !self.state
    }
}

/// One-shot CRC-32 of `data`.
pub fn crc32(data: &[u8]) -> u32 {
    let mut h = Crc32::new();
    h.update(data);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }

    #[test]
    fn incremental_matches_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 31 % 251) as u8).collect();
        for split in [0, 1, 7, 8, 9, 500, 999, 1000] {
            let mut h = Crc32::default();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finish(), crc32(&data), "split {split}");
        }
    }
}
