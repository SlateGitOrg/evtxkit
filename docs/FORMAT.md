# The EVTX format, as implemented by evtxkit

This is a working description of the Windows XML Event Log (EVTX) format at
the level needed to write a parser, written while building evtxkit. The
authoritative sources are Microsoft's [MS-EVEN6] specification (BinXML and
value types) and Joachim Metz's libevtx documentation (file and chunk
layout). Where the two leave gaps, behaviour was checked against the pinned
sample files and the reference parser (see `DATA.md`). All integers are
little-endian. Offsets in tables are relative to the start of the structure.

[MS-EVEN6]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/

## 1. File layout

```
+-------------------+  offset 0
| file header       |  4096 bytes (128 used)
+-------------------+  offset 4096
| chunk 0           |  65536 bytes
+-------------------+
| chunk 1           |
+-------------------+
| ...               |  file size = 4096 + n * 65536 (+ partial slot when damaged)
```

### 1.1 File header (`src/file.rs`)

| off | size | field |
|----:|-----:|-------|
| 0   | 8    | signature `ElfFile\0` |
| 8   | 8    | first chunk number |
| 16  | 8    | last chunk number |
| 24  | 8    | next record identifier |
| 32  | 4    | header size (128) |
| 36  | 2    | minor version (1; 2 in newer files) |
| 38  | 2    | major version (3) |
| 40  | 2    | header block size (4096) |
| 42  | 2    | number of chunks |
| 44  | 76   | unused |
| 120 | 4    | flags: `0x1` dirty, `0x2` full, `0x4` no CRC32 |
| 124 | 4    | CRC32 of bytes `0..120` |

The chunk count is **not** authoritative. A dirty (not cleanly closed) log can
hold valid chunks beyond it (`sysmon.evtx` declares 1 and holds 9), so evtxkit
examines every 64 KiB slot and classifies it:

| slot | rule |
|------|------|
| chunk | starts with `ElfChnk\0` and is complete |
| empty | all 65536 bytes are zero (pre-allocated space) |
| slack | no chunk signature **and** index ≥ declared chunk count (stale data) |
| corrupt | anything else (bad signature inside the declared range, truncated chunk) |

## 2. Chunks (`src/chunk.rs`)

Each chunk is self-contained: the names and templates its records reference
are stored inside the same 64 KiB, addressed by chunk-relative offsets. This is
what allows chunks to be decoded in parallel.

| off | size | field |
|----:|-----:|-------|
| 0   | 8    | signature `ElfChnk\0` |
| 8   | 8    | first event record number |
| 16  | 8    | last event record number |
| 24  | 8    | first event record identifier |
| 32  | 8    | last event record identifier |
| 40  | 4    | header size (128) |
| 44  | 4    | offset of the last record |
| 48  | 4    | free space offset (end of record data) |
| 52  | 4    | CRC32 of record data `512..free_space_offset` |
| 56  | 64   | unused |
| 120 | 4    | flags (`0x4` = no CRC32) |
| 124 | 4    | CRC32 of bytes `0..120` and `128..512` |
| 128 | 256  | common string offset table: 64 × u32 bucket heads |
| 384 | 128  | template pointer table: 32 × u32 bucket heads |
| 512 | …    | event records |

The two tables are hash tables whose buckets chain through the first `u32` of
each entry (name or template definition). Parsing never needs them — every
reference is a direct offset — but `Chunk::template_offsets` and
`common_string_offsets` walk them (cycle-safe) for diagnostics.

### 2.1 Checksums

| region | stored at | covers |
|--------|-----------|--------|
| file header | file 124 | file bytes `0..120` |
| chunk header | chunk 124 | chunk bytes `0..120` ‖ `128..512` |
| record data | chunk 52 | chunk bytes `512..free_space_offset` |

CRC32 is the IEEE 802.3 polynomial (reflected `0xEDB88320`, init and final
XOR `0xFFFFFFFF`), implemented in `src/crc32.rs` with slicing-by-8 tables.
When the `NO_CRC32` flag is set the stored values are meaningless and the
status is `disabled`. Windows routinely leaves the record-data CRC stale in
dirty files, so by default a mismatch is reported but the chunk is still
decoded; `--strict-crc` skips such chunks instead.

## 3. Records (`src/record.rs`)

| off | size | field |
|----:|-----:|-------|
| 0   | 4    | signature `2a 2a 00 00` |
| 4   | 4    | size of the whole record |
| 8   | 8    | event record identifier |
| 16  | 8    | written time (FILETIME) |
| 24  | n    | BinXML fragment |
| size−4 | 4 | copy of the size |

A record whose trailing size copy is zero is being written (seen in
`HelloForBusiness-Operational.evtx`); it is decoded and flagged
`size_copy_valid = false`. A framing failure (bad signature, impossible size)
cannot be skipped by size, so the iterator **resynchronises**: it scans
forward byte by byte for the next offset whose signature, size and size copy
all agree, and marks records found that way `recovered = true`. Zero padding
after the last record ends the chunk silently.

## 4. BinXML (`src/binxml/`)

A record body is a stream of one-byte tokens. Tokens `0x01` and `0x05`–`0x09`
may carry the `0x40` flag (for `0x01` it means "has attributes", for `0x06`
"more attributes follow").

| token | name | payload |
|------:|------|---------|
| 0x00 | EOF | – |
| 0x01 / 0x41 | OpenStartElement | [u16 dependency id — *template definitions only*], u32 data size, u32 name offset, [u32 attribute list size if 0x41] |
| 0x02 | CloseStartElement | – |
| 0x03 | CloseEmptyElement | – |
| 0x04 | EndElement | – |
| 0x05 / 0x45 | Value | u8 value type (always 0x01), u16 char count, UTF-16 text |
| 0x06 / 0x46 | Attribute | u32 name offset; the value follows as Value/Substitution/reference tokens |
| 0x07 / 0x47 | CDATA section | u16 char count, UTF-16 text |
| 0x08 / 0x48 | Character reference | u16 code unit |
| 0x09 / 0x49 | Entity reference | u32 name offset |
| 0x0A | PI target | u32 name offset |
| 0x0B | PI data | u16 char count, UTF-16 text |
| 0x0C | TemplateInstance | see §4.2 |
| 0x0D | NormalSubstitution | u16 index, u8 value type |
| 0x0E | OptionalSubstitution | u16 index, u8 value type |
| 0x0F | FragmentHeader | u8 major (1), u8 minor (1), u8 flags (0) |

### 4.1 Names and the inline rule

A *name* is `u32 next-in-bucket, u16 hash, u16 char count, UTF-16 chars, u16
NUL`. Tokens refer to names by chunk offset. The first time a name is used it
is written **inline**: the offset field then equals the position right after
itself, and the parser must decode the name there and skip `8 + 2·count + 2`
bytes. Template definitions use the same rule (§4.2). evtxkit caches decoded
names per chunk (`HashMap<offset, Arc<str>>`).

### 4.2 Templates and instances

Almost every record is `FragmentHeader, TemplateInstance, EOF`:

```
0x0C  u8 unknown (1)  u32 template id  u32 definition offset
      [inline definition if offset == current position:
         u32 next definition, 16-byte GUID, u32 data size, <data size bytes of BinXML>]
      u32 value count
      count × (u16 size, u8 value type, u8 padding)
      the values, back to back
```

The definition is a BinXML fragment whose element starts carry the 2-byte
dependency id and whose variable parts are substitution tokens referring to
value indexes. Definitions are parsed once per chunk and cached by offset
(including failures, so a corrupt definition is not re-parsed per record).

Instantiation rules (`src/binxml/template.rs`). The pinned samples exercise
optional substitutions, embedded BinXML values and array values, and the
golden tests check the resulting trees against the reference parser; the
corner cases (cross-product expansion, out-of-range indexes, node budget) are
covered by synthetic tests in `tests/synthetic.rs` and unit tests:

1. A substitution whose index is out of range produces nothing.
2. An **optional** substitution whose value is empty (null, empty string,
   empty binary, empty array) produces nothing. An attribute whose value ends
   up empty is dropped entirely; an element is never dropped.
3. A normal substitution with a null value produces an empty text node (the
   attribute or element is kept, empty).
4. A value of type `0x21` (BinXML) is itself a fragment, parsed in place
   (no dependency ids; it may contain its own template instance) and spliced
   into the tree.
5. An **array** value with more than one item repeats the *containing element*
   once per item (MS-EVEN6 §3.1.4.7.5). Children are searched before
   attributes; several arrays in one element expand recursively (a cross
   product). One-item arrays render as their item.

Limits keep hostile input bounded: fragment nesting ≤ 8, element depth ≤ 64
per fragment, and ≤ 100 000 nodes created per template instance.

### 4.3 Value types (`src/value.rs`)

| type | name | size | text rendering |
|-----:|------|-----:|----------------|
| 0x00 | Null | 0 | empty |
| 0x01 | String | n | UTF-16LE, cut at first NUL |
| 0x02 | AnsiString | n | Windows-1252, cut at first NUL |
| 0x03/0x04 | Int8/UInt8 | 1 | decimal |
| 0x05/0x06 | Int16/UInt16 | 2 | decimal |
| 0x07/0x08 | Int32/UInt32 | 4 | decimal |
| 0x09/0x0A | Int64/UInt64 | 8 | decimal |
| 0x0B/0x0C | Real32/Real64 | 4/8 | shortest round-trip decimal |
| 0x0D | Bool | 4 | `true`/`false` (any non-zero is true) |
| 0x0E | Binary | n | uppercase hex |
| 0x0F | GUID | 16 | `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`, uppercase, no braces |
| 0x10 | SizeT | 4/8 | `0x` + lowercase hex |
| 0x11 | FILETIME | 8 | `YYYY-MM-DDTHH:MM:SS.ffffffZ` |
| 0x12 | SYSTEMTIME | 16 | same format, milliseconds widened |
| 0x13 | SID | 8+4k | `S-rev-authority-sub-…` |
| 0x14/0x15 | HexInt32/HexInt64 | 4/8 | `0x` + lowercase hex |
| 0x20 | EvtHandle | – | unsupported (error) |
| 0x21 | BinXml | n | parsed as a nested fragment |
| 0x23 | EvtXml | – | unsupported (error) |
| `0x80 \| t` | array of t | n | items joined with `,` (or element repetition, §4.2) |

String arrays are NUL-separated UTF-16 strings; a trailing NUL terminates the
last item. SID arrays are split by each SID's own sub-authority count.

## 5. Output mappings

### 5.1 JSONL (`evtxkit dump`, `src/render/json.rs`)

```json
{"record_id": 2, "timestamp": "2016-07-08T18:12:51.6816408Z", "event": { ... }}
```

`timestamp` is the record header's FILETIME at full 100 ns precision. The
`event` object maps the element tree:

* a leaf element without attributes → scalar: `null` if empty, a JSON
  number/bool if it holds exactly one numeric/bool value, otherwise its text;
* any other element → object with `"@Attr"` keys, child elements by name
  (repeated names → array) and non-blank text as `"#text"`;
* `<Data Name="X">v</Data>` → `"X": v`, so `EventData` becomes a flat object;
  unnamed `Data` elements group as `"Data": [...]`;
* `xmlns` attributes are omitted.

With `--emit-errors`, undecodable records add
`{"error": true, "chunk": n, "offset": file_offset, "record_id"?: id, "message": "..."}`.

### 5.2 Flat fields (`-f fields`, `src/fields.rs`)

`{"_record_id", "_timestamp", "_logsource"?, "fields": {name: text}}` where

* `System/X` → `X`; attributes → `X_Attr` (`Provider_Name`,
  `TimeCreated_SystemTime`, `Execution_ProcessID`, `Security_UserID`, …);
* `EventData/Data[@Name=N]` → `N`; unnamed `Data` → `Data_1`, `Data_2`, …;
* `UserData/<Wrapper>/Leaf` → `Leaf`;
* any other section `S` (e.g. `RenderingInfo`) → `S_Leaf`.

Values are text; repeated names become arrays. With `--sigma` or `--mapping`,
fields are renamed per `mappings/*.yml` and `_logsource` carries the Sigma
`product`/`service`/`category`.
