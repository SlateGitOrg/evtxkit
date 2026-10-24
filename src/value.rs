//! BinXML value types: decoding from substitution bytes and text rendering.
//!
//! Text rendering follows the conventions of the reference parser so golden
//! comparisons are byte-exact: GUIDs uppercase without braces, binary as
//! uppercase hex, `HexInt*`/`SizeT` as `0x` + lowercase hex, times with six
//! fractional digits, arrays as comma-separated items.

use crate::bytes::{decode_utf16_lossy, decode_utf16_until_nul};
use crate::error::{EvtxError, Result};
use crate::time::{FileTime, Precision, SystemTime};
use std::fmt::{self, Write as _};

/// The array flag on a value type byte.
pub const ARRAY_FLAG: u8 = 0x80;

/// Base value type codes (MS-EVEN6 2.2.13 / BinXML value types).
pub mod ty {
    #![allow(missing_docs)]
    pub const NULL: u8 = 0x00;
    pub const STRING: u8 = 0x01;
    pub const ANSI_STRING: u8 = 0x02;
    pub const INT8: u8 = 0x03;
    pub const UINT8: u8 = 0x04;
    pub const INT16: u8 = 0x05;
    pub const UINT16: u8 = 0x06;
    pub const INT32: u8 = 0x07;
    pub const UINT32: u8 = 0x08;
    pub const INT64: u8 = 0x09;
    pub const UINT64: u8 = 0x0a;
    pub const REAL32: u8 = 0x0b;
    pub const REAL64: u8 = 0x0c;
    pub const BOOL: u8 = 0x0d;
    pub const BINARY: u8 = 0x0e;
    pub const GUID: u8 = 0x0f;
    pub const SIZE_T: u8 = 0x10;
    pub const FILETIME: u8 = 0x11;
    pub const SYSTIME: u8 = 0x12;
    pub const SID: u8 = 0x13;
    pub const HEX_INT32: u8 = 0x14;
    pub const HEX_INT64: u8 = 0x15;
    pub const EVT_HANDLE: u8 = 0x20;
    pub const BIN_XML: u8 = 0x21;
    pub const EVT_XML: u8 = 0x23;
}

/// A 16-byte GUID in its on-disk (mixed-endian) layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Guid(pub [u8; 16]);

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            u16::from_le_bytes([b[4], b[5]]),
            u16::from_le_bytes([b[6], b[7]]),
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        )
    }
}

/// A Windows security identifier, kept as raw bytes and rendered leniently.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sid(pub Vec<u8>);

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let &[revision, sub_count, a0, a1, a2, a3, a4, a5, ref subs @ ..] = self.0.as_slice()
        else {
            return f.write_str("S-?");
        };
        let authority = u64::from_be_bytes([0, 0, a0, a1, a2, a3, a4, a5]);
        write!(f, "S-{revision}-{authority}")?;
        for sub in subs.chunks_exact(4).take(usize::from(sub_count)) {
            write!(
                f,
                "-{}",
                u32::from_le_bytes([sub[0], sub[1], sub[2], sub[3]])
            )?;
        }
        Ok(())
    }
}

/// A decoded BinXML scalar or array value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Type 0x00, or an absent value.
    Null,
    /// UTF-16 string (type 0x01), truncated at the first NUL.
    String(String),
    /// Codepage string (type 0x02), decoded as Windows-1252.
    AnsiString(String),
    /// Type 0x03.
    Int8(i8),
    /// Type 0x04.
    UInt8(u8),
    /// Type 0x05.
    Int16(i16),
    /// Type 0x06.
    UInt16(u16),
    /// Type 0x07.
    Int32(i32),
    /// Type 0x08.
    UInt32(u32),
    /// Type 0x09.
    Int64(i64),
    /// Type 0x0a.
    UInt64(u64),
    /// Type 0x0b.
    Real32(f32),
    /// Type 0x0c.
    Real64(f64),
    /// Type 0x0d (stored as a 32-bit integer; any non-zero is true).
    Bool(bool),
    /// Type 0x0e.
    Binary(Vec<u8>),
    /// Type 0x0f.
    Guid(Guid),
    /// Type 0x10 (pointer-sized integer, 4 or 8 bytes).
    SizeT(u64),
    /// Type 0x11.
    FileTime(FileTime),
    /// Type 0x12.
    SysTime(SystemTime),
    /// Type 0x13.
    Sid(Sid),
    /// Type 0x14.
    HexInt32(u32),
    /// Type 0x15.
    HexInt64(u64),
    /// Any base type with the 0x80 array flag; items share one base type.
    Array(Vec<Value>),
}

/// Size in bytes of fixed-width base types (`None` for variable-width ones).
fn fixed_size(base: u8) -> Option<usize> {
    Some(match base {
        ty::INT8 | ty::UINT8 => 1,
        ty::INT16 | ty::UINT16 => 2,
        ty::INT32 | ty::UINT32 | ty::REAL32 | ty::BOOL | ty::HEX_INT32 => 4,
        ty::INT64 | ty::UINT64 | ty::REAL64 | ty::FILETIME | ty::HEX_INT64 => 8,
        ty::GUID | ty::SYSTIME => 16,
        _ => return None,
    })
}

fn le<const N: usize>(b: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&b[..N]);
    out
}

/// Windows-1252 code points for bytes 0x80..=0x9F (undefined slots map to U+FFFD).
const CP1252_HIGH: [char; 32] = [
    '\u{20AC}', '\u{FFFD}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}',
    '\u{02C6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{FFFD}', '\u{017D}', '\u{FFFD}',
    '\u{FFFD}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}',
    '\u{02DC}', '\u{2122}', '\u{0161}', '\u{203A}', '\u{0153}', '\u{FFFD}', '\u{017E}', '\u{0178}',
];

/// Decodes Windows-1252 bytes up to the first NUL.
pub fn decode_cp1252(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| match b {
            0x80..=0x9f => CP1252_HIGH[usize::from(b - 0x80)],
            _ => char::from(b),
        })
        .collect()
}

impl Value {
    /// Decodes a substitution value of `value_type` from exactly `bytes`.
    ///
    /// `offset` is only used for error messages. BinXML (0x21) values are not
    /// handled here; the BinXML parser expands them into element trees.
    pub fn decode(value_type: u8, bytes: &[u8], offset: usize) -> Result<Value> {
        if value_type & ARRAY_FLAG != 0 {
            return Self::decode_array(value_type & !ARRAY_FLAG, bytes, offset);
        }
        let bad_size = || EvtxError::BadValueSize {
            value_type,
            size: bytes.len(),
            offset,
        };
        if let Some(n) = fixed_size(value_type) {
            // Bool is officially 4 bytes but some writers emit other widths.
            if value_type == ty::BOOL && (1..=8).contains(&bytes.len()) {
                return Ok(Value::Bool(bytes.iter().any(|&b| b != 0)));
            }
            if bytes.len() != n {
                return Err(bad_size());
            }
        }
        Ok(match value_type {
            ty::NULL => Value::Null,
            ty::STRING => Value::String(decode_utf16_until_nul(bytes)),
            ty::ANSI_STRING => Value::AnsiString(decode_cp1252(bytes)),
            ty::INT8 => Value::Int8(bytes[0] as i8),
            ty::UINT8 => Value::UInt8(bytes[0]),
            ty::INT16 => Value::Int16(i16::from_le_bytes(le(bytes))),
            ty::UINT16 => Value::UInt16(u16::from_le_bytes(le(bytes))),
            ty::INT32 => Value::Int32(i32::from_le_bytes(le(bytes))),
            ty::UINT32 => Value::UInt32(u32::from_le_bytes(le(bytes))),
            ty::INT64 => Value::Int64(i64::from_le_bytes(le(bytes))),
            ty::UINT64 => Value::UInt64(u64::from_le_bytes(le(bytes))),
            ty::REAL32 => Value::Real32(f32::from_le_bytes(le(bytes))),
            ty::REAL64 => Value::Real64(f64::from_le_bytes(le(bytes))),
            ty::BINARY => Value::Binary(bytes.to_vec()),
            ty::GUID => Value::Guid(Guid(le(bytes))),
            ty::SIZE_T => match bytes.len() {
                4 => Value::SizeT(u64::from(u32::from_le_bytes(le(bytes)))),
                8 => Value::SizeT(u64::from_le_bytes(le(bytes))),
                _ => return Err(bad_size()),
            },
            ty::FILETIME => Value::FileTime(FileTime(u64::from_le_bytes(le(bytes)))),
            ty::SYSTIME => Value::SysTime(SystemTime::from_bytes(&le(bytes))),
            ty::SID => Value::Sid(Sid(bytes.to_vec())),
            ty::HEX_INT32 => Value::HexInt32(u32::from_le_bytes(le(bytes))),
            ty::HEX_INT64 => Value::HexInt64(u64::from_le_bytes(le(bytes))),
            other => {
                return Err(EvtxError::UnsupportedValueType {
                    value_type: other,
                    offset,
                });
            }
        })
    }

    fn decode_array(base: u8, bytes: &[u8], offset: usize) -> Result<Value> {
        let items = match base {
            ty::STRING => {
                let units: Vec<&[u8]> = bytes.chunks_exact(2).collect();
                let mut items: Vec<Value> = units
                    .split(|u| *u == [0, 0])
                    .map(|piece| Value::String(decode_utf16_lossy(&piece.concat())))
                    .collect();
                // A trailing NUL terminates the last item rather than starting a new one.
                if matches!(items.last(), Some(Value::String(s)) if s.is_empty()) {
                    items.pop();
                }
                items
            }
            ty::ANSI_STRING => {
                let mut items: Vec<Value> = bytes
                    .split(|&b| b == 0)
                    .map(|piece| Value::AnsiString(decode_cp1252(piece)))
                    .collect();
                if matches!(items.last(), Some(Value::AnsiString(s)) if s.is_empty()) {
                    items.pop();
                }
                items
            }
            ty::SIZE_T if bytes.len() % 8 == 0 => bytes
                .chunks_exact(8)
                .map(|c| Value::SizeT(u64::from_le_bytes(le(c))))
                .collect(),
            ty::SID => {
                // SIDs are self-describing: 8 header bytes + 4 per sub-authority.
                let mut items = Vec::new();
                let mut rest = bytes;
                while rest.len() >= 8 {
                    let len = 8 + 4 * usize::from(rest[1]);
                    if len > rest.len() {
                        return Err(EvtxError::BadValueSize {
                            value_type: base | ARRAY_FLAG,
                            size: bytes.len(),
                            offset,
                        });
                    }
                    items.push(Value::Sid(Sid(rest[..len].to_vec())));
                    rest = &rest[len..];
                }
                items
            }
            _ => {
                let size = fixed_size(base).ok_or(EvtxError::UnsupportedValueType {
                    value_type: base | ARRAY_FLAG,
                    offset,
                })?;
                if bytes.len() % size != 0 {
                    return Err(EvtxError::BadValueSize {
                        value_type: base | ARRAY_FLAG,
                        size: bytes.len(),
                        offset,
                    });
                }
                bytes
                    .chunks_exact(size)
                    .map(|c| Value::decode(base, c, offset))
                    .collect::<Result<_>>()?
            }
        };
        Ok(Value::Array(items))
    }

    /// True when an *optional* substitution with this value must be omitted.
    pub fn is_empty(&self) -> bool {
        match self {
            Value::Null => true,
            Value::String(s) | Value::AnsiString(s) => s.is_empty(),
            Value::Binary(b) => b.is_empty(),
            Value::Array(items) => items.is_empty(),
            _ => false,
        }
    }

    /// Number of items if this is an array value.
    pub fn array_len(&self) -> Option<usize> {
        match self {
            Value::Array(items) => Some(items.len()),
            _ => None,
        }
    }

    /// Appends the textual rendering of the value to `out`.
    pub fn write_text(&self, out: &mut String) {
        match self {
            Value::Null => {}
            Value::String(s) | Value::AnsiString(s) => out.push_str(s),
            Value::Int8(v) => push_display(out, v),
            Value::UInt8(v) => push_display(out, v),
            Value::Int16(v) => push_display(out, v),
            Value::UInt16(v) => push_display(out, v),
            Value::Int32(v) => push_display(out, v),
            Value::UInt32(v) => push_display(out, v),
            Value::Int64(v) => push_display(out, v),
            Value::UInt64(v) => push_display(out, v),
            Value::Real32(v) => push_display(out, v),
            Value::Real64(v) => push_display(out, v),
            Value::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
            Value::Binary(bytes) => {
                for b in bytes {
                    let _ = write!(out, "{b:02X}");
                }
            }
            Value::Guid(g) => push_display(out, g),
            Value::SizeT(v) | Value::HexInt64(v) => {
                let _ = write!(out, "0x{v:x}");
            }
            Value::HexInt32(v) => {
                let _ = write!(out, "0x{v:x}");
            }
            Value::FileTime(ft) => ft.write_iso(out, Precision::Micros),
            Value::SysTime(st) => st.write_iso(out),
            Value::Sid(sid) => push_display(out, sid),
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_text(out);
                }
            }
        }
    }

    /// Returns the textual rendering as a new string.
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        self.write_text(&mut s);
        s
    }
}

fn push_display(out: &mut String, v: &impl fmt::Display) {
    let _ = write!(out, "{v}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn scalars_render_like_windows() {
        let cases: Vec<(u8, Vec<u8>, &str)> = vec![
            (ty::INT8, vec![0xff], "-1"),
            (ty::UINT8, vec![0xff], "255"),
            (ty::INT16, (-2i16).to_le_bytes().to_vec(), "-2"),
            (ty::UINT16, 513u16.to_le_bytes().to_vec(), "513"),
            (ty::INT32, (-7i32).to_le_bytes().to_vec(), "-7"),
            (ty::UINT32, 4624u32.to_le_bytes().to_vec(), "4624"),
            (ty::INT64, (-9i64).to_le_bytes().to_vec(), "-9"),
            (
                ty::UINT64,
                u64::MAX.to_le_bytes().to_vec(),
                "18446744073709551615",
            ),
            (ty::REAL32, 1.5f32.to_le_bytes().to_vec(), "1.5"),
            (ty::REAL64, 0.25f64.to_le_bytes().to_vec(), "0.25"),
            (ty::BOOL, 1u32.to_le_bytes().to_vec(), "true"),
            (ty::BOOL, vec![0, 0, 0, 0], "false"),
            (ty::BOOL, vec![2], "true"),
            (ty::BINARY, vec![0xde, 0xad, 0x01], "DEAD01"),
            (ty::HEX_INT32, 0x20u32.to_le_bytes().to_vec(), "0x20"),
            (
                ty::HEX_INT64,
                0x8020_0000_0000_0000u64.to_le_bytes().to_vec(),
                "0x8020000000000000",
            ),
            (ty::SIZE_T, 0x10u32.to_le_bytes().to_vec(), "0x10"),
            (ty::SIZE_T, 0x0u64.to_le_bytes().to_vec(), "0x0"),
            (ty::NULL, vec![], ""),
        ];
        for (t, bytes, want) in cases {
            assert_eq!(
                Value::decode(t, &bytes, 0).unwrap().to_text(),
                want,
                "type {t:#x}"
            );
        }
    }

    #[test]
    fn strings_guid_sid_time() {
        let mut s = utf16("SYSTEM");
        s.extend_from_slice(&[0, 0, b'x', 0]);
        assert_eq!(
            Value::decode(ty::STRING, &s, 0).unwrap().to_text(),
            "SYSTEM"
        );
        assert_eq!(
            Value::decode(ty::ANSI_STRING, &[b'a', 0x80, 0x81, 0xe9, 0, b'z'], 0)
                .unwrap()
                .to_text(),
            "a\u{20ac}\u{fffd}\u{e9}"
        );
        let guid = [
            0x25, 0x96, 0x84, 0x54, 0x78, 0x54, 0x94, 0x49, 0xa5, 0xba, 0x3e, 0x3b, 0x03, 0x28,
            0xc3, 0x0d,
        ];
        assert_eq!(
            Value::decode(ty::GUID, &guid, 0).unwrap().to_text(),
            "54849625-5478-4994-A5BA-3E3B0328C30D"
        );
        let sid = [1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        assert_eq!(
            Value::decode(ty::SID, &sid, 0).unwrap().to_text(),
            "S-1-5-18"
        );
        assert_eq!(Value::decode(ty::SID, &[1, 2], 0).unwrap().to_text(), "S-?");
        let ft = 131_124_751_716_816_408u64.to_le_bytes();
        assert_eq!(
            Value::decode(ty::FILETIME, &ft, 0).unwrap().to_text(),
            "2016-07-08T18:12:51.681640Z"
        );
        let mut st = [0u8; 16];
        st[0..2].copy_from_slice(&2020u16.to_le_bytes());
        st[2..4].copy_from_slice(&1u16.to_le_bytes());
        st[6..8].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            Value::decode(ty::SYSTIME, &st, 0).unwrap().to_text(),
            "2020-01-02T00:00:00.000000Z"
        );
    }

    #[test]
    fn arrays() {
        let mut bytes = utf16("a");
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend(utf16("bc"));
        bytes.extend_from_slice(&[0, 0]);
        let v = Value::decode(ty::STRING | ARRAY_FLAG, &bytes, 0).unwrap();
        assert_eq!(v.array_len(), Some(3));
        assert_eq!(v.to_text(), "a,,bc");
        let v = Value::decode(ty::UINT16 | ARRAY_FLAG, &[1, 0, 2, 0], 0).unwrap();
        assert_eq!(v.to_text(), "1,2");
        assert!(Value::decode(ty::UINT16 | ARRAY_FLAG, &[1, 0, 2], 0).is_err());
        let v = Value::decode(ty::ANSI_STRING | ARRAY_FLAG, b"x\0yz\0", 0).unwrap();
        assert_eq!(v.to_text(), "x,yz");
        let v = Value::decode(ty::SIZE_T | ARRAY_FLAG, &[0u8; 16], 0).unwrap();
        assert_eq!(v.to_text(), "0x0,0x0");
        let sids = [
            1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5,
        ];
        assert_eq!(
            Value::decode(ty::SID | ARRAY_FLAG, &sids, 0)
                .unwrap()
                .to_text(),
            "S-1-5-18,S-1-5"
        );
        assert!(Value::decode(ty::SID | ARRAY_FLAG, &[1u8, 9, 0, 0, 0, 0, 0, 5], 0).is_err());
        assert!(Value::decode(ty::EVT_HANDLE | ARRAY_FLAG, &[], 0).is_err());
        assert!(Value::Array(vec![]).is_empty());
    }

    #[test]
    fn size_and_type_errors() {
        assert!(matches!(
            Value::decode(ty::UINT32, &[1, 2], 7),
            Err(EvtxError::BadValueSize { offset: 7, .. })
        ));
        assert!(Value::decode(ty::SIZE_T, &[1, 2], 0).is_err());
        assert!(matches!(
            Value::decode(ty::EVT_HANDLE, &[], 3),
            Err(EvtxError::UnsupportedValueType {
                value_type: 0x20,
                offset: 3
            })
        ));
        assert!(Value::Null.is_empty());
        assert!(Value::String(String::new()).is_empty());
        assert!(Value::Binary(vec![]).is_empty());
        assert!(!Value::UInt8(0).is_empty());
        assert_eq!(Value::UInt8(0).array_len(), None);
    }
}
