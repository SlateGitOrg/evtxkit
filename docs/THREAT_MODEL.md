# Threat model

## Context

evtxkit is a defensive, offline tool: an analyst or a detection pipeline runs
it over `.evtx` files collected from Windows machines, often machines that are
suspected to be compromised. It never talks to the network, never touches a
live event log service and never writes anything except its own output.

The **input is attacker-controlled**. Anyone who controlled the source machine
could have planted or edited the log files, and carved or damaged logs are
routine in incident response. The parser must therefore treat every byte as
hostile.

## Assets

1. Availability of the analysis host and pipeline (no crash, hang or
   unbounded resource use on a crafted file).
2. Integrity of the output (what the analyst reads is what the file says;
   no injection into downstream JSON consumers or terminals).
3. Honest signalling of damage (corruption is reported, never silently
   hidden or silently "repaired").

## Threats and mitigations

| # | threat | mitigation | evidence |
|---|--------|------------|----------|
| T1 | Memory-safety bug triggered by a crafted file | No `unsafe` code (`unsafe_code = "forbid"`); all reads via the bounds-checked `Cursor` | `src/bytes.rs`; lint config in `Cargo.toml` |
| T2 | Panic (index out of range, overflow, `unwrap`) aborts a batch job | Every structural value is validated before use; `clippy::unwrap_used` fails the lint gate; the only `panic!` in library code guards the compiled-in mapping file (validated by a unit test); fuzz-style property tests | `tests/corruption.rs` (mutated real files, random token streams, random bytes, exhaustive byte flips) |
| T3 | Stack exhaustion through deep nesting | Element nesting is handled with an explicit heap stack; fragment recursion ≤ 8; element depth ≤ 64 per fragment | `Limits`; `element_depth_is_limited`, `fragment_depth_and_expansion_limits` tests |
| T4 | "Billion laughs"-style blow-up via array substitutions (cross products, deep copies), repeated or nested template instances, large values cloned many times, many small amplifying records, or huge substitution counts | Every created or cloned node is charged its full deep size (1 unit per node + 1 per 64 payload bytes) against a budget of 100 000 units per record, shared by all of the record's template instances, and 1 000 000 units per chunk; descriptor counts checked against remaining bytes before allocating. Fix round 1 replaced a per-instance budget that charged array copies only their direct children (a 68 KB file reached 937 MB) | `array_copies_are_charged_their_full_deep_size`, `spent_units_cover_everything_returned`, `hostile_expansions_hit_the_record_budget`, `hostile_record_floods_hit_the_chunk_budget`, `hostile_expansion_is_a_record_error`, `cross_product_is_bounded` |
| T5 | Quadratic work from many framing errors | Resynchronisation never rescans bytes: O(chunk) per chunk | `framing_errors_resynchronise` |
| T6 | Template/name offset loops or self-references | Offsets are only followed through caches keyed by offset; hash-table walks use a visited set | `template_and_string_tables_are_walked` |
| T7 | Regex denial of service in `-w 'F|re=…'` | `regex` crate (finite automata, linear time), compiled size capped at 1 MiB | `src/filter.rs` |
| T8 | Output injection: crafted strings breaking JSONL framing | Own JSON escaper escapes quotes, backslashes and every C0 control character; output parsed back in tests | `render::json::tests::escapes`, `tests/cli.rs` |
| T9 | Terminal escape injection when reading output in a terminal | JSON escapes control characters; XML output turns C0 controls into `&#x..;`; text `stats` escapes control characters | `render::xml::tests`, `stats::printable` |
| T10 | Silent loss of evidence (damaged chunk hides the rest) | Damage is scoped to the smallest unit; corrupt slots, CRC mismatches, size-copy mismatches and recovered records are all counted and reported; `--emit-errors` keeps them in the output stream | `stats` output, `tests/golden.rs` recovery test |
| T11 | Memory exhaustion from a huge input | Whole-file read is bounded by the file size; the pipeline keeps at most `window + threads` decoded chunks alive, each bounded by the chunk budget (T4). Measured by `make hostile-rss` on hostile files where every chunk exhausts its budget, with a stalled output consumer: about 270–310 MB peak RSS at `-t 1` and 680–700 MB at `-t 8`, flat from 64 to 1,024 chunks apart from the input file itself | `src/pipeline.rs`, `hostile_record_floods_hit_the_chunk_budget` |

## Explicit non-goals and residual risks

* **CRC32 is not authentication.** It detects accidental corruption only; an
  attacker who edits a log can recompute every checksum. evtxkit cannot tell
  a well-forged log from a genuine one, and a "CRC ok" status must not be read
  as "untampered".
* Record *removal* (for example clearing or splicing out events) is visible
  only indirectly: gaps in `EventRecordID` ranges are reported by `stats`
  (`ids a .. b` vs. record count) but are not analysed further.
* Recovered records (`recovered: true`) come from scanning damaged regions.
  They passed strict framing checks but are, by definition, less trustworthy
  than records reached by normal iteration.
* The tool reads the whole file into memory; a multi-gigabyte input will use
  that much RAM.
* The decoder has been fuzzed with proptest for a bounded number of cases per
  run (256 per property, plus an exhaustive single-byte-flip sweep of one
  small file), not with a coverage-guided fuzzer for CPU-days.

## Ethics

The project is for defensive and educational use. All bundled data are
public test logs (see `DATA.md`); demos and benchmarks run only against those
files and synthetic files stitched from them. There is no capability to
collect logs from remote machines, alter logs, or evade logging.
