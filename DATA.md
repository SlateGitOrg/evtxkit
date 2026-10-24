# Data

All test data is committed under `tests/` (5.5 MB of samples + 268 KB of golden
output). Nothing is downloaded at test time.

## Sample EVTX files (`tests/data/`)

| File | Size | Records (reference) | What it exercises |
|------|-----:|-----:|-------------------|
| `security.evtx` | 2.1 MB | 2,261 | Security channel, 26 chunks + 7 zero-filled slots, logon events |
| `system.evtx` | 1.1 MB | 1,881 | System channel, classic (non-manifest) providers, `Qualifiers` attributes |
| `sysmon.evtx` | 1.1 MB | 358 | Sysmon/Operational; 8 slots of non-zero slack after the last chunk |
| `sample_with_a_bad_chunk_magic.evtx` | 1.0 MB | 270 | Dirty file: two corrupt chunk slots, partially written records, record-CRC mismatches |
| `Application_no_crc32.evtx` | 68 KB | 17 | `NO_CRC32` flags on file and chunk (format 3.2) |
| `HelloForBusiness-Operational.evtx` | 68 KB | 6 | Dirty chunk with a record whose trailing size copy is zero |
| `MSExchange_Management_wec.evtx` | 68 KB | 1 | Event forwarded through WEC, non-ASCII text |
| `new-user-security.evtx` | 68 KB | 4 | Account-creation events |
| `Security_short_selected.evtx` | 68 KB | 7 | Small Security export |

**Source:** the `samples/` directory of the `omerbenamram/EVTX` repository
(<https://github.com/omerbenamram/EVTX>), pinned to commit
`9b99074d8b4fa5c8b72df6974952e38b9a93e74d`, which is the commit the crates.io
release `evtx 0.12.3` was published from. Files were downloaded from
`https://raw.githubusercontent.com/omerbenamram/EVTX/<commit>/samples/<name>`.

**License:** the repository is dual-licensed MIT / Apache-2.0. The samples are
distributed in that repository as test fixtures; their individual provenance
(which machine produced each log) is not documented upstream. They contain
lab/test-machine hostnames and SIDs, no credentials.

**Renamed:** `Microsoft-Windows-HelloForBusiness%4Operational.evtx` is stored as
`HelloForBusiness-Operational.evtx` to keep `%` out of paths.

**Integrity:** `tests/data/SHA256SUMS`, checked by `scripts/verify-data.sh`
(part of `make check`).

## Golden reference output (`tests/golden/*.jsonl.gz`)

Produced by `scripts/gen-golden.sh`, which builds `tools/refdump` against the
reference parser **`evtx` = 0.12.3** (crates.io, MIT/Apache-2.0) and writes one
canonical tree per record (`gzip -n`, deterministic). evtxkit does **not** link
the reference parser; it is only used to generate these files.

## Synthetic data

* `evtxkit::synth::stitch` builds larger files by concatenating valid chunks of
  the samples above (chunks are self-contained, so the result is a valid EVTX
  file). Used by the throughput benchmark and pipeline tests. The benchmark
  input is therefore **repeated real chunks**, not new events.
* `tests/common/builder.rs` hand-assembles tiny chunks (templates, arrays,
  CDATA, entity references, nested BinXML) to cover token paths the public
  samples never use. These are synthetic by construction.
