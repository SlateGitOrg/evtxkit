//! Hand-assembles EVTX chunks for tests: BinXML token streams, inline names,
//! inline template definitions and substitution arrays, with correct CRC32s.
//! This covers token paths the public samples never exercise.

use evtxkit::crc32::{Crc32, crc32};
use std::collections::HashMap;

pub const CHUNK: usize = 0x10000;

/// A typed substitution value: (value type byte, raw bytes).
pub type Val = (u8, Vec<u8>);

pub fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

pub fn v_str(s: &str) -> Val {
    (0x01, utf16(s))
}

pub fn v_u32(v: u32) -> Val {
    (0x08, v.to_le_bytes().to_vec())
}

pub fn v_null() -> Val {
    (0x00, Vec::new())
}

/// A UInt8 array (type 0x84) holding `n` items.
pub fn v_u8_array(n: usize) -> Val {
    (0x84, (0..n).map(|i| i as u8).collect())
}

pub fn v_str_array(items: &[&str]) -> Val {
    let mut b = Vec::new();
    for i in items {
        b.extend(utf16(i));
        b.extend([0, 0]);
    }
    (0x81, b)
}

pub struct ChunkBuilder {
    pub data: Vec<u8>,
    pub pos: usize,
    names: HashMap<String, u32>,
    in_template: bool,
    first_id: Option<u64>,
    last_id: u64,
    last_record: usize,
    pub flags: u32,
}

impl Default for ChunkBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkBuilder {
    pub fn new() -> Self {
        ChunkBuilder {
            data: vec![0; CHUNK],
            pos: 512,
            names: HashMap::new(),
            in_template: false,
            first_id: None,
            last_id: 0,
            last_record: 512,
            flags: 0,
        }
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.data[self.pos] = v;
        self.pos += 1;
        self
    }

    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.raw(&v.to_le_bytes())
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.raw(&v.to_le_bytes())
    }

    pub fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.data[self.pos..self.pos + b.len()].copy_from_slice(b);
        self.pos += b.len();
        self
    }

    /// Writes a name reference: inline the first time, by offset afterwards.
    pub fn name(&mut self, name: &str) -> &mut Self {
        if let Some(&off) = self.names.get(name) {
            return self.u32(off);
        }
        let off = (self.pos + 4) as u32;
        self.names.insert(name.to_string(), off);
        self.u32(off)
            .u32(0)
            .u16(0)
            .u16(name.encode_utf16().count() as u16);
        let units = utf16(name);
        self.raw(&units).u16(0)
    }

    pub fn fragment_header(&mut self) -> &mut Self {
        self.raw(&[0x0f, 1, 1, 0])
    }

    pub fn open(&mut self, name: &str, has_attrs: bool) -> &mut Self {
        self.u8(if has_attrs { 0x41 } else { 0x01 });
        if self.in_template {
            self.u16(0xffff);
        }
        self.u32(0).name(name);
        if has_attrs {
            self.u32(0);
        }
        self
    }

    pub fn attr(&mut self, name: &str) -> &mut Self {
        self.u8(0x06).name(name)
    }

    pub fn close_start(&mut self) -> &mut Self {
        self.u8(0x02)
    }

    pub fn close_empty(&mut self) -> &mut Self {
        self.u8(0x03)
    }

    pub fn end(&mut self) -> &mut Self {
        self.u8(0x04)
    }

    pub fn text(&mut self, s: &str) -> &mut Self {
        self.u8(0x05).u8(0x01).u16(s.encode_utf16().count() as u16);
        let units = utf16(s);
        self.raw(&units)
    }

    pub fn sub(&mut self, index: u16, ty: u8, optional: bool) -> &mut Self {
        self.u8(if optional { 0x0e } else { 0x0d })
            .u16(index)
            .u8(ty)
    }

    pub fn char_ref(&mut self, c: u16) -> &mut Self {
        self.u8(0x08).u16(c)
    }

    pub fn entity_ref(&mut self, name: &str) -> &mut Self {
        self.u8(0x09).name(name)
    }

    pub fn cdata(&mut self, s: &str) -> &mut Self {
        self.u8(0x07).u16(s.encode_utf16().count() as u16);
        let units = utf16(s);
        self.raw(&units)
    }

    pub fn pi(&mut self, target: &str, data: &str) -> &mut Self {
        self.u8(0x0a).name(target);
        self.u8(0x0b).u16(data.encode_utf16().count() as u16);
        let units = utf16(data);
        self.raw(&units)
    }

    pub fn eof(&mut self) -> &mut Self {
        self.u8(0x00)
    }

    /// Writes a template instance with an inline definition built by `def`.
    /// Returns the definition offset so later instances can reference it.
    pub fn template_inline(&mut self, def: impl FnOnce(&mut Self), values: &[Val]) -> u32 {
        self.u8(0x0c).u8(1).u32(0x1234);
        let def_offset = (self.pos + 4) as u32;
        self.u32(def_offset);
        self.u32(0).raw(&[0xab; 16]);
        let size_at = self.pos;
        self.u32(0);
        let start = self.pos;
        let was = self.in_template;
        self.in_template = true;
        self.fragment_header();
        def(self);
        self.eof();
        self.in_template = was;
        let size = (self.pos - start) as u32;
        self.data[size_at..size_at + 4].copy_from_slice(&size.to_le_bytes());
        self.values(values);
        def_offset
    }

    /// Writes a template instance referring to an existing definition.
    pub fn template_ref(&mut self, def_offset: u32, values: &[Val]) -> &mut Self {
        self.u8(0x0c).u8(1).u32(0x1234).u32(def_offset);
        self.values(values);
        self
    }

    pub fn values(&mut self, values: &[Val]) -> &mut Self {
        self.u32(values.len() as u32);
        for (ty, bytes) in values {
            self.u16(bytes.len() as u16).u8(*ty).u8(0);
        }
        for (_, bytes) in values {
            self.raw(bytes);
        }
        self
    }

    /// Appends a record (header, BinXML body written by `body`, size copy).
    pub fn record(&mut self, id: u64, body: impl FnOnce(&mut Self)) -> &mut Self {
        let start = self.pos;
        self.raw(&[0x2a, 0x2a, 0, 0]).u32(0).raw(&id.to_le_bytes());
        self.raw(&(132_000_000_000_000_000u64 + id).to_le_bytes());
        body(self);
        while (self.pos + 4 - start) % 8 != 0 {
            self.u8(0);
        }
        let size = (self.pos + 4 - start) as u32;
        self.u32(size);
        self.data[start + 4..start + 8].copy_from_slice(&size.to_le_bytes());
        self.first_id.get_or_insert(id);
        self.last_id = id;
        self.last_record = start;
        self
    }

    /// Writes a record whose template instance has one BinXML-typed value whose
    /// content is produced by `nested` (written in place, so names resolve).
    pub fn template_with_nested(
        &mut self,
        def: impl FnOnce(&mut Self),
        nested: impl FnOnce(&mut Self),
    ) {
        self.template_with_values_then_nested(def, &[], nested);
    }

    /// Like [`Self::template_with_nested`], but the instance starts with the
    /// plain values `pre` (substitution indexes `0..pre.len()`); the BinXML
    /// value written by `nested` gets index `pre.len()`.
    pub fn template_with_values_then_nested(
        &mut self,
        def: impl FnOnce(&mut Self),
        pre: &[Val],
        nested: impl FnOnce(&mut Self),
    ) {
        self.u8(0x0c).u8(1).u32(0x1234);
        let def_offset = (self.pos + 4) as u32;
        self.u32(def_offset);
        self.u32(0).raw(&[0xcd; 16]);
        let size_at = self.pos;
        self.u32(0);
        let start = self.pos;
        let was = self.in_template;
        self.in_template = true;
        self.fragment_header();
        def(self);
        self.eof();
        self.in_template = was;
        let size = (self.pos - start) as u32;
        self.data[size_at..size_at + 4].copy_from_slice(&size.to_le_bytes());
        self.u32(pre.len() as u32 + 1);
        for (ty, bytes) in pre {
            self.u16(bytes.len() as u16).u8(*ty).u8(0);
        }
        // The BinXML descriptor's size is patched after the fragment is written.
        let desc_at = self.pos;
        self.u16(0).u8(0x21).u8(0);
        for (_, bytes) in pre {
            self.raw(bytes);
        }
        let vstart = self.pos;
        self.fragment_header();
        nested(self);
        self.eof();
        let vsize = (self.pos - vstart) as u16;
        self.data[desc_at..desc_at + 2].copy_from_slice(&vsize.to_le_bytes());
    }

    pub fn finish(mut self) -> Vec<u8> {
        let d = &mut self.data;
        d[..8].copy_from_slice(b"ElfChnk\0");
        let first = self.first_id.unwrap_or(0);
        d[8..16].copy_from_slice(&first.to_le_bytes());
        d[16..24].copy_from_slice(&self.last_id.to_le_bytes());
        d[24..32].copy_from_slice(&first.to_le_bytes());
        d[32..40].copy_from_slice(&self.last_id.to_le_bytes());
        d[40..44].copy_from_slice(&128u32.to_le_bytes());
        d[44..48].copy_from_slice(&(self.last_record as u32).to_le_bytes());
        d[48..52].copy_from_slice(&(self.pos as u32).to_le_bytes());
        let rc = crc32(&d[512..self.pos]);
        d[52..56].copy_from_slice(&rc.to_le_bytes());
        d[120..124].copy_from_slice(&self.flags.to_le_bytes());
        let mut h = Crc32::new();
        h.update(&d[..120]);
        h.update(&d[128..512]);
        let hc = h.finish();
        d[124..128].copy_from_slice(&hc.to_le_bytes());
        self.data
    }
}

/// A complete file: synthetic header + the given chunks.
pub fn file(chunks: &[Vec<u8>]) -> Vec<u8> {
    let mut out = evtxkit::synth::file_header(chunks.len(), 1);
    for c in chunks {
        out.extend_from_slice(c);
    }
    out
}

/// A standard `<Event><System><EventID>%0</EventID></System><EventData><Data Name="X">%1</Data></EventData></Event>` definition.
pub fn simple_event_def(b: &mut ChunkBuilder) {
    b.open("Event", false).close_start();
    b.open("System", false).close_start();
    b.open("EventID", false)
        .close_start()
        .sub(0, 0x08, false)
        .end();
    b.end();
    b.open("EventData", false).close_start();
    b.open("Data", true)
        .attr("Name")
        .text("X")
        .close_start()
        .sub(1, 0x01, false)
        .end();
    b.end();
    b.end();
}
