# Decisions

Rulings made while building evtxkit, in the order they came up. Format:
`Ruling: <what> — <why> — <cost if wrong>`.

## Scope and data

- Ruling: use nine samples from the `omerbenamram/EVTX` repository pinned at commit `9b99074d` (the `evtx 0.12.3` release commit) and commit them (5.5 MB) — public, small, cover clean, dirty, no-CRC, forwarded and damaged logs, and match the reference parser version exactly — samples have no per-file provenance upstream; if any turned out to be unredistributable they would have to be replaced and goldens regenerated.
- Ruling: the reference parser is the `evtx` crate 0.12.3, used only by `tools/refdump` (a separate, non-workspace crate) to generate committed golden files — keeps `make check` free of the reference dependency and keeps the parser "from scratch" — goldens must be regenerated with `scripts/gen-golden.sh` if the reference is bumped.
- Ruling: golden comparison is semantic (canonical tree: element names, attribute order and values, merged text, whitespace-only text dropped) rather than byte-for-byte XML — the two parsers' pretty-printers differ in indentation and escaping, which says nothing about parse correctness — a difference in whitespace-only text nodes would go unnoticed.
- Ruling: records that evtxkit recovers by resynchronising after a framing error are excluded from golden equality and asserted to occur only in the damaged sample — the reference parser abandons the rest of such a chunk, so they have no reference value — those 31 records are validated only by strict framing and successful decoding, not by an oracle.
- Ruling: `Microsoft-Windows-HelloForBusiness%4Operational.evtx` is stored as `HelloForBusiness-Operational.evtx` — `%` in paths is awkward in shells and URLs — none (checksum recorded in DATA.md).

## Format semantics

- Ruling: value rendering follows the reference parser (GUIDs uppercase without braces, `0x` lowercase hex for HexInt/SizeT, 6-digit FILETIME fractions in XML/JSON values, 7 digits for the record header timestamp) — needed for golden equality and matches common EVTX tooling — Event Viewer shows GUIDs with braces, so string comparisons against Event Viewer exports need normalising.
- Ruling: a record-data CRC mismatch is reported but the chunk is still decoded by default; `--strict-crc` skips it — Windows leaves record CRCs stale in dirty logs (3 of the 4 chunks in the damaged sample), and skipping by default would hide most of the evidence — a genuinely corrupted chunk may yield garbage records, which then surface as record errors.
- Ruling: a zero/mismatched trailing size copy does not reject a record (flagged `size_copy_valid=false`) — Windows writes the copy last, the reference parser accepts such records, and golden equality on two samples requires it — a truncated record body is still caught by BinXML parsing.
- Ruling: resynchronisation requires signature + plausible size + matching size copy — stricter than normal framing so random bytes are unlikely to be taken for a record — a damaged record whose own trailer is damaged is not recovered.
- Ruling: slots without a chunk signature beyond the header's chunk count are "slack", not "corrupt", and are not logged as warnings — `sysmon.evtx` has 8 such slots of stale data after 9 valid chunks; warning on them is noise — real damage beyond a stale chunk count would be under-reported (still counted in `stats`).
- Ruling: the header chunk count is not trusted; every 64 KiB slot is examined — dirty files hold valid chunks beyond it (sysmon: declares 1, holds 9) — none observed.
- Ruling: Windows-1252 for ANSI strings, implemented as a 32-entry table — the only codepage the samples need and the reference parser's default — logs written under other codepages render high bytes incorrectly.
- Ruling: resource limits are fragment depth 8, element depth 64, 100 000 nodes per template instance — the 4,836 records decoded from the samples reach element depth 4 and at most 44 elements; the limits stop stack and memory exhaustion — an unusual but genuine record exceeding them would be reported as an error.
- Ruling: reject value types EvtHandle (0x20) and EvtXml (0x23) with an error — they do not occur in stored logs and the reference parser rejects them too — a log containing them would lose those records.

## Output and detection layer

- Ruling: JSON keeps typed scalars (numbers/bools) for single-value leaves, `@`-prefixed attributes, `#text`, and keys `Data` children by their `Name` — makes `EventData` a flat object that detection tools can index — not identical to any other tool's JSON shape, so consumers must use this documented mapping.
- Ruling: drop `xmlns` attributes from JSON — constant per record, ~70 bytes per line — anyone needing the namespace must use XML output.
- Ruling: the flat field view is a separate output (`-f fields`) with text values and Sigma-style names (`Provider_Name`, `Data_1`, …) — detection rules compare strings and need a flat namespace — numeric typing is lost there (filters parse numbers on demand).
- Ruling: field mapping config is YAML with `services` / `rename` / `categories` (first matching rule wins, renames simultaneous) and the built-in Sigma Windows mapping is embedded with `include_str!` — mirrors how Sigma pipelines are written and lets 4688's `ProcessId→ParentProcessId` / `NewProcessId→ProcessId` swap work — `serde_yaml` 0.9 is unmaintained upstream; a replacement would be needed if a vulnerability appears.
- Ruling: filter syntax is `Field|mod=value` with Sigma modifiers, case-insensitive by default, Sigma backslash escaping — familiar to detection engineers and Windows paths need no doubling — a value that must end in a literal backslash before `*` needs `\\*`.
- Ruling: `grep` exits 1 when nothing matches, 2 on errors — same contract as `grep(1)` so it composes in shell pipelines — none.

## Engineering

- Ruling: own CRC32 (slicing-by-8), own FILETIME calendar math, own JSON writer — the brief asks for a from-scratch parser and these are on the hot path — more code to maintain; each is cross-checked (crc32fast oracle, calendar tests, JSON round-trip tests).
- Ruling: parallelism with `std::thread::scope` + `sync_channel` + condvar window instead of rayon — ordered output with bounded memory is the core requirement and is ~100 lines — no work stealing inside a chunk; one huge chunk cannot be split (chunks are fixed 64 KiB, so this is bounded).
- Ruling: read whole files into memory rather than memory-mapping — no `unsafe`, simpler, logs are size-capped by Windows — multi-GB carved images would need mmap (roadmap).
- Ruling: XML output writes C0 control characters as `&#xNN;` references — keeps hostile content from driving terminals — such references are not well-formed XML 1.0, so strict XML parsers reject those (rare) records.
- Ruling: coverage is measured with `cargo llvm-cov` (threshold 80% lines) and includes the binary via the CLI integration tests — matches what users run — the figure also counts unit-test code inside `src/` files; `scripts/loc.sh` reports that code separately.
