#!/usr/bin/env bash
# Offline end-to-end demo against the bundled sample logs (tests/data).
# Run via `make demo` (which builds the release binary first).
set -euo pipefail
cd "$(dirname "$0")/.."
BIN="${CARGO_TARGET_DIR:-target}/release/evtxkit"
[ -x "$BIN" ] || cargo build --locked --release --quiet
D=tests/data
if [ -t 1 ]; then B=$'\033[1m' N=$'\033[0m'; else B='' N=''; fi
step() { printf '\n%s==> %s%s\n$ %s\n' "$B" "$1" "$N" "$2"; }
hash() { if command -v sha256sum >/dev/null; then sha256sum | cut -c1-16; else shasum -a 256 | cut -c1-16; fi; }

step "1. File health: chunks, CRC32 verification, record counts" \
     "evtxkit stats $D/security.evtx"
"$BIN" stats "$D/security.evtx"

step "2. One record as JSON Lines (EventData flattened by Data/@Name)" \
     "evtxkit dump $D/new-user-security.evtx | head -n 1"
"$BIN" dump "$D/new-user-security.evtx" | head -n 1

step "3. The same record as XML" \
     "evtxkit dump -f xml $D/new-user-security.evtx | head -n 31"
"$BIN" dump -f xml "$D/new-user-security.evtx" | head -n 31

step "4. Sigma-style hunting: process creations spawned by cmd.exe" \
     "evtxkit grep --category process_creation -w 'ParentImage|endswith=\\cmd.exe' -c $D/sysmon.evtx"
"$BIN" grep --category process_creation -w 'ParentImage|endswith=\cmd.exe' -c "$D/sysmon.evtx"

step "5. ...stacked by Image (top 5), using the Sigma field mapping" \
     "evtxkit stats --sigma --by Image --top 5 $D/sysmon.evtx | tail -n 1"
"$BIN" stats --sigma --by Image --top 5 "$D/sysmon.evtx" | tail -n 1

step "6. First match as a flat Sigma field object" \
     "evtxkit grep --sigma -f fields -w 'Image|endswith=\\ping.exe' -w 'CommandLine|contains=127.0.0.1' $D/sysmon.evtx | head -n 1"
"$BIN" grep --sigma -f fields -w 'Image|endswith=\ping.exe' -w 'CommandLine|contains=127.0.0.1' "$D/sysmon.evtx" | head -n 1

step "7. Logon events by logon type" \
     "evtxkit grep -c -w EventID=4624 -w 'LogonType|in=2,10,11' $D/security.evtx  (interactive/remote/cached)"
"$BIN" grep -c -w EventID=4624 -w 'LogonType|in=2,10,11' "$D/security.evtx" || true

step "8. A damaged log: corrupt slots, stale record CRCs, records recovered by resync" \
     "evtxkit stats --chunks $D/sample_with_a_bad_chunk_magic.evtx"
"$BIN" stats --chunks "$D/sample_with_a_bad_chunk_magic.evtx" 2>&1

step "9. Strict CRC policy drops chunks whose checksums fail" \
     "evtxkit grep -c -q --strict-crc -e AppXDeployment $D/sample_with_a_bad_chunk_magic.evtx"
"$BIN" grep -c -q --strict-crc -e AppXDeployment "$D/sample_with_a_bad_chunk_magic.evtx" || true

step "10. Chunk-parallel output is byte-identical to single-threaded output" \
      "evtxkit dump -t 1 $D/system.evtx | sha256 ; evtxkit dump -t 8 $D/system.evtx | sha256"
printf 't=1  %s\n' "$("$BIN" dump -t 1 "$D/system.evtx" | hash)"
printf 't=8  %s\n' "$("$BIN" dump -t 8 "$D/system.evtx" | hash)"
