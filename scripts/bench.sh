#!/usr/bin/env bash
# Runs the throughput benchmark and writes bench/RESULTS.md.
# Extra arguments go to the benchmark, e.g. ./scripts/bench.sh --copies 32 --runs 7
set -euo pipefail
cd "$(dirname "$0")/.."
args=("$@")
[ ${#args[@]} -eq 0 ] && args=(--copies 16 --runs 7 --threads 1,2,4,8)
out="$(cargo bench --locked --bench throughput -- "${args[@]}" 2>/dev/null)"
cpu="$( (sysctl -n machdep.cpu.brand_string 2>/dev/null || grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2) | sed 's/^ *//')"
load="$( (uptime 2>/dev/null | sed 's/.*load average[s]*: //') || echo unknown)"
mkdir -p bench
{
  echo "# Throughput benchmark results"
  echo
  echo "Command: \`./scripts/bench.sh ${args[*]}\` (runs \`cargo bench --bench throughput\`)"
  echo
  echo "- Date: $(date -u +%Y-%m-%d)"
  echo "- Machine: ${cpu:-unknown} ($(uname -sm))"
  echo "- Load average when started: ${load}"
  echo "- Input: synthetic file stitched from the committed samples' chunks (see DATA.md)"
  echo
  echo "$out"
} > bench/RESULTS.md
cat bench/RESULTS.md
