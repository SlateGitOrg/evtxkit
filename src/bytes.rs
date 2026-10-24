//! Bounds-checked little-endian reading.
//!
//! All parsing goes through [`Cursor`], which never indexes out of bounds: every
//! read returns [`EvtxError::Truncated`] instead of panicking. Positions are
//! absolute offsets into the underlying slice (for BinXML that slice is the
//! whole 64 KiB chunk, because names and templates are referenced by
//! chunk-relative offsets).

use crate::error::{EvtxError, Result};

/// A forward-only reader over `data[pos..end]`.
#[derive(Debug, Clone)]
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> Cursor<'a> {
    /// Creates a cursor reading `data[pos..end]`; `end` is clamped to `data.len()`.
    pub fn new(data: &'a [u8], pos: usize, end: usize) -> Self {
        let end = end.min(data.len());
        Cursor {
            data,
            pos: pos.min(end),
            end,
        }
    }

    /// Current absolute position.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Absolute end of the readable window.
    pub fn end(&self) -> usize {
        self.end
    }

    /// Bytes left before `end`.
    pub fn remaining(&self) -> usize {
        self.end - self.pos
    }

    /// True when no bytes are left.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.end
    }

    /// The whole underlying slice (used to follow chunk-relative offsets).
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    fn truncated(&self, need: usize) -> EvtxError {
        EvtxError::Truncated {
            offset: self.pos,
            need,
            available: self.remaining(),
        }
    }

    /// Takes the next `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(self.truncated(n));
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// Skips `n` bytes.
    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.take(n).map(|_| ())
    }

    /// Looks at the next byte without consuming it.
    pub fn peek_u8(&self) -> Option<u8> {
        if self.pos < self.end {
            Some(self.data[self.pos])
        } else {
            None
        }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Reads a `u8`.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    /// Reads a little-endian `u16`.
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    /// Reads a little-endian `u32`.
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    /// Reads a little-endian `u64`.
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// Reads `count` UTF-16LE code units and decodes them (lossy on bad surrogates).
    pub fn utf16(&mut self, count: usize) -> Result<String> {
        let need = count
            .checked_mul(2)
            .ok_or_else(|| self.truncated(usize::MAX))?;
        let bytes = self.take(need)?;
        Ok(decode_utf16_lossy(bytes))
    }

    /// Reads a `u16` character count followed by that many UTF-16LE code units.
    pub fn len_prefixed_utf16(&mut self) -> Result<String> {
        let count = self.u16()? as usize;
        self.utf16(count)
    }
}

/// Reads a little-endian `u16` at `offset`.
pub fn u16_at(data: &[u8], offset: usize) -> Result<u16> {
    if offset.checked_add(2).is_none_or(|e| e > data.len()) {
        return Err(truncated_at(data, offset, 2));
    }
    Cursor::new(data, offset, data.len()).u16()
}

/// Reads a little-endian `u32` at `offset`.
pub fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    if offset.checked_add(4).is_none_or(|e| e > data.len()) {
        return Err(truncated_at(data, offset, 4));
    }
    Cursor::new(data, offset, data.len()).u32()
}

/// Reads a little-endian `u64` at `offset`.
pub fn u64_at(data: &[u8], offset: usize) -> Result<u64> {
    if offset.checked_add(8).is_none_or(|e| e > data.len()) {
        return Err(truncated_at(data, offset, 8));
    }
    Cursor::new(data, offset, data.len()).u64()
}

fn truncated_at(data: &[u8], offset: usize, need: usize) -> EvtxError {
    EvtxError::Truncated {
        offset,
        need,
        available: data.len().saturating_sub(offset),
    }
}

/// Decodes UTF-16LE bytes, replacing unpaired surrogates with U+FFFD.
/// A trailing odd byte is ignored.
pub fn decode_utf16_lossy(bytes: &[u8]) -> String {
    let units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    char::decode_utf16(units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Decodes UTF-16LE bytes up to (not including) the first NUL code unit.
pub fn decode_utf16_until_nul(bytes: &[u8]) -> String {
    let len = bytes
        .chunks_exact(2)
        .position(|pair| pair == [0, 0])
        .map_or(bytes.len() & !1, |units| units * 2);
    decode_utf16_lossy(&bytes[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_little_endian_and_reports_truncation() {
        let data = [1u8, 0, 2, 0, 0, 0, 9];
        let mut c = Cursor::new(&data, 0, data.len());
        assert_eq!(c.u16().unwrap(), 1);
        assert_eq!(c.u32().unwrap(), 2);
        assert_eq!(c.remaining(), 1);
        let err = c.u32().unwrap_err();
        assert_eq!(
            err,
            EvtxError::Truncated {
                offset: 6,
                need: 4,
                available: 1
            }
        );
        assert_eq!(c.peek_u8(), Some(9));
        assert_eq!(c.u8().unwrap(), 9);
        assert!(c.is_empty());
        assert_eq!(c.peek_u8(), None);
    }

    #[test]
    fn window_is_clamped() {
        let data = [0u8; 4];
        let c = Cursor::new(&data, 10, 100);
        assert_eq!(c.end(), 4);
        assert_eq!(c.pos(), 4);
        assert!(c.is_empty());
    }

    #[test]
    fn absolute_reads_check_bounds() {
        let data = [0xffu8; 8];
        assert_eq!(u16_at(&data, 6).unwrap(), 0xffff);
        assert!(u16_at(&data, 7).is_err());
        assert_eq!(u32_at(&data, 4).unwrap(), u32::MAX);
        assert!(u32_at(&data, 5).is_err());
        assert!(u32_at(&data, usize::MAX).is_err());
        assert_eq!(u64_at(&data, 0).unwrap(), u64::MAX);
        assert!(u64_at(&data, 1).is_err());
    }

    #[test]
    fn utf16_decoding_is_lossy_and_nul_aware() {
        let bytes = [b'h', 0, b'i', 0, 0, 0, b'x', 0];
        assert_eq!(decode_utf16_until_nul(&bytes), "hi");
        assert_eq!(decode_utf16_lossy(&[0x00, 0xd8, b'a', 0]), "\u{fffd}a");
        assert_eq!(decode_utf16_until_nul(&[b'a', 0, b'b']), "a");
        let mut c = Cursor::new(&[2u8, 0, b'o', 0, b'k', 0], 0, 6);
        assert_eq!(c.len_prefixed_utf16().unwrap(), "ok");
        let mut c = Cursor::new(&[5u8, 0, b'o', 0], 0, 4);
        assert!(c.len_prefixed_utf16().is_err());
    }
}
