#!/usr/bin/env bash
# Line counts: shipped (non-test) Rust source vs tests. Unit tests live at the
# bottom of each src file after `#[cfg(test)]`, so lines from that marker on
# are counted as tests. "code" excludes blank lines and `//` comment lines.
set -euo pipefail
cd "$(dirname "$0")/.."
awk '
  FNR == 1 { in_test = 0 }
  /^#\[cfg\(test\)\]/ { in_test = 1 }
  {
    blank = ($0 ~ /^[[:space:]]*$/)
    comment = ($0 ~ /^[[:space:]]*\/\//)
    if (in_test) { t_all++; if (!blank && !comment) t_code++ }
    else { s_all++; if (!blank && !comment) s_code++ }
  }
  END {
    printf "src (non-test): %d lines, %d code\n", s_all, s_code
    printf "src unit tests: %d lines, %d code\n", t_all, t_code
  }
' $(find src -name '*.rs' | sort)
find tests benches -name '*.rs' | sort | xargs awk '
  { all++; if ($0 !~ /^[[:space:]]*$/ && $0 !~ /^[[:space:]]*\/\//) code++ }
  END { printf "tests + benches: %d lines, %d code\n", all, code }'
