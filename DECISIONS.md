# Design decisions

Key design decisions in evtxkit, each with the reasoning and what it would cost if it turned out wrong.
Format: `<decision> — <why> — <cost if wrong>`.

## Scope and data

- use nine samples from the `omerbenamram/EVTX` repository pinned at commit `9b99074d` (the `evtx 0.12.3` release commit) and commit them (5.5 MB) — public, small, cover clean, dirty, no-CRC, forwarded and damaged logs, and match the reference parser version exactly — samples have no per-file provenance upstream; if any turned out to be unredistributable they would have to be replaced and goldens regenerated.
- the reference parser is the `evtx` crate 0.12.3, used only by `tools/refdump` (a separate, non-workspace crate) to generate committed golden files — keeps `make check` free of the reference dependency and keeps the parser "from scratch" — goldens must be regenerated with `scripts/gen-golden.sh` if the reference is bumped.
- golden comparison is semantic (canonical tree: element names, attribute order and values, merged text, whitespace-only text dropped) rather than byte-for-byte XML — the two parsers' pretty-printers differ in indentation and escaping, which says nothing about parse correctness — a difference in whitespace-only text nodes would go unnoticed.
- records that evtxkit recovers by resynchronising after a framing error are excluded from golden equality and asserted to occur only in the damaged sample — the reference parser abandons the rest of such a chunk, so they have no reference value — those 31 records are validated only by strict framing and successful decoding, not by an oracle.
- `Microsoft-Windows-HelloForBusiness%4Operational.evtx` is stored as `HelloForBusiness-Operational.evtx` — `%` in paths is awkward in shells and URLs — none (checksum recorded in DATA.md).

## Format semantics

- value rendering follows the reference parser (GUIDs uppercase without braces, `0x` lowercase hex for HexInt/SizeT, 6-digit FILETIME fractions in XML/JSON values, 7 digits for the record header timestamp) — needed for golden equality and matches common EVTX tooling — Event Viewer shows GUIDs with braces, so string comparisons against Event Viewer exports need normalising.
- a record-data CRC mismatch is reported but the chunk is still decoded by default; `--strict-crc` skips it — Windows leaves record CRCs stale in dirty logs (3 of the 4 chunks in the damaged sample), and skipping by default would hide most of the evidence — a genuinely corrupted chunk may yield garbage records, which then surface as record errors.
- a zero/mismatched trailing size copy does not reject a record (flagged `size_copy_valid=false`) — Windows writes the copy last, the reference parser accepts such records, and golden equality on two samples requires it — a truncated record body is still caught by BinXML parsing.
- resynchronisation requires signature + plausible size + matching size copy — stricter than normal framing so random bytes are unlikely to be taken for a record — a damaged record whose own trailer is damaged is not recovered.
- slots without a chunk signature beyond the header's chunk count are "slack", not "corrupt", and are not logged as warnings — `sysmon.evtx` has 8 such slots of stale data after 9 valid chunks; warning on them is noise — real damage beyond a stale chunk count would be under-reported (still counted in `stats`).
- the header chunk count is not trusted; every 64 KiB slot is examined — dirty files hold valid chunks beyond it (sysmon: declares 1, holds 9) — none observed.
- Windows-1252 for ANSI strings, implemented as a 32-entry table — the only codepage the samples need and the reference parser's default — logs written under other codepages render high bytes incorrectly.
- resource limits are fragment depth 8, element depth 64, and node budgets of 100 000 units per record and 1 000 000 per chunk (originally 100 000 nodes per template instance; see Expansion budgets below) — the 4,836 records decoded from the samples reach element depth 4 and at most 44 elements; the limits stop stack and memory exhaustion — an unusual but genuine record exceeding them would be reported as an error.
- reject value types EvtHandle (0x20) and EvtXml (0x23) with an error — they do not occur in stored logs and the reference parser rejects them too — a log containing them would lose those records.

## Output and detection layer

- JSON keeps typed scalars (numbers/bools) for single-value leaves, `@`-prefixed attributes, `#text`, and keys `Data` children by their `Name` — makes `EventData` a flat object that detection tools can index — not identical to any other tool's JSON shape, so consumers must use this documented mapping.
- drop `xmlns` attributes from JSON — constant per record, ~70 bytes per line — anyone needing the namespace must use XML output.
- the flat field view is a separate output (`-f fields`) with text values and Sigma-style names (`Provider_Name`, `Data_1`, …) — detection rules compare strings and need a flat namespace — numeric typing is lost there (filters parse numbers on demand).
- field mapping config is YAML with `services` / `rename` / `categories` (first matching rule wins, renames simultaneous) and the built-in Sigma Windows mapping is embedded with `include_str!` — mirrors how Sigma pipelines are written and lets 4688's `ProcessId→ParentProcessId` / `NewProcessId→ProcessId` swap work — `serde_yaml` 0.9 is unmaintained upstream; a replacement would be needed if a vulnerability appears.
- filter syntax is `Field|mod=value` with Sigma modifiers, case-insensitive by default, Sigma backslash escaping — familiar to detection engineers and Windows paths need no doubling — a value that must end in a literal backslash before `*` needs `\\*`.
- `grep` exits 1 when nothing matches, 2 on errors — same contract as `grep(1)` so it composes in shell pipelines — none.

## Engineering

- own CRC32 (slicing-by-8), own FILETIME calendar math, own JSON writer — the parser is written from scratch and these are on the hot path — more code to maintain; each is cross-checked (crc32fast oracle, calendar tests, JSON round-trip tests).
- parallelism with `std::thread::scope` + `sync_channel` + condvar window instead of rayon — ordered output with bounded memory is the core requirement and is ~100 lines — no work stealing inside a chunk; one huge chunk cannot be split (chunks are fixed 64 KiB, so this is bounded).
- read whole files into memory rather than memory-mapping — no `unsafe`, simpler, logs are size-capped by Windows — multi-GB carved images would need mmap (roadmap).
- XML output writes C0 control characters as `&#xNN;` references — keeps hostile content from driving terminals — such references are not well-formed XML 1.0, so strict XML parsers reject those (rare) records.
- coverage is measured with `cargo llvm-cov` (threshold 80% lines) and includes the binary via the CLI integration tests — matches what users run — the figure also counts unit-test code inside `src/` files; `scripts/loc.sh` reports that code separately.

## Expansion budgets

- every array copy is charged its full deep size (`element_cost`) before it is cloned, and the array is lifted out of the element first so copies do not clone it — the old charge of `1 + children + attributes` let a crafted 68 KB file reach roughly 660–940 MB peak RSS through deep clones — over-charges nested cross products by up to about 2x, so a genuine record with several large arrays could hit the limit sooner than before.
- the budget is shared by everything one record decodes (all its template instances, nested BinXML values included) instead of being fresh per template instance — a record holding many instances, or values that each hold an instance, otherwise multiplies the allowance (one 68 KB record with 20 instances: about 116 MB with a fresh budget per instance, extrapolating to ~2.2 GB at 400) — a genuine record with many large embedded fragments shares one allowance; the samples need at most 255 units per record against 100 000 (`cargo test --release --test budget sample_budget_needs -- --ignored --nocapture`).
- add a per-chunk budget, `Limits::max_chunk_nodes`, default 1 000 000 units; units spent by failed records count too — a chunk can hold ~1,600 minimal records that each stay under a per-record budget, and `decode_slot` keeps all of a chunk's records alive together, so per-record limits alone do not bound memory; measured worst case after the fix (`make hostile-rss`) is about 270–310 MB (`-t 1`) and 680–700 MB (`-t 8`) peak RSS with a stalled output consumer, flat from 64 to 1,024 hostile chunks apart from the input file itself — the samples' busiest chunk needs 12,849 units (78x headroom); once a hostile chunk exhausts it, every later record of that chunk is reported as an error.
- budget units are one per node plus one per 64 heap bytes of payload (strings, binary, SIDs, array items), not a pure node count — a long string cloned into every array copy costs few nodes but many bytes (16,000-character string x 25,000 items: about 402 MB when charged by node count alone) — a genuine record with very large strings spends more units; a 32 KB PowerShell script block costs about 500.
- `EvtxError::ExpansionLimit` gains a `scope` field (`"record"` or `"chunk"`) and its message says which budget ran out — a chunk-level refusal must not look like the record itself being oversized — breaking change for code that matched the variant exhaustively; the crate is pre-1.0 and unpublished.
- `parse_record` still keeps only the first root and drops any others (e.g. a root element repeated by an array) — the budget now charges every root it builds, so the dropped ones can no longer cost unbounded memory, and records in the samples have exactly one root — extra roots in a malformed record are still silently discarded rather than reported.

