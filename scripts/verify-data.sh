#!/usr/bin/env bash
# Verify the committed sample EVTX files against tests/data/SHA256SUMS.
set -euo pipefail
cd "$(dirname "$0")/../tests/data"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum --quiet -c SHA256SUMS
else
  shasum -a 256 --quiet -c SHA256SUMS
fi
echo "data: $(wc -l < SHA256SUMS | tr -d ' ') sample files verified"
