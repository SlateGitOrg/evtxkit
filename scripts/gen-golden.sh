#!/usr/bin/env bash
# Regenerate tests/golden/*.jsonl.gz from the reference parser (evtx crate, pinned in
# tools/refdump/Cargo.toml). Requires network on first run to fetch the crate.
# Output is deterministic: gzip -n omits file names and mtimes.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release --manifest-path tools/refdump/Cargo.toml
target="${CARGO_TARGET_DIR:-tools/refdump/target}"
bin="$target/release/refdump"
mkdir -p tests/golden
for f in tests/data/*.evtx; do
  name="$(basename "$f" .evtx)"
  "$bin" "$f" | gzip -9 -n > "tests/golden/$name.jsonl.gz"
  echo "golden: $name ($(gzip -dc "tests/golden/$name.jsonl.gz" | wc -l | tr -d ' ') lines)"
done
