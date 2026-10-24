#!/bin/sh
# Peak RSS of `evtxkit dump` on hand-built hostile files (threat model T4/T11).
#
#   scripts/hostile-rss.sh                     this checkout's release build, all files
#   EVTXKIT_BIN=/path/evtxkit SET=small scripts/hostile-rss.sh
#                                              another build (e.g. one made from commit
#                                              0a97b0a, before fix round 1); SET=small
#                                              skips the files that need many GB there
#
# File shapes are documented in tests/common/hostile.rs. "stalled" runs pipe
# stdout into a consumer that sleeps 4 s first, so the pipeline window fills.
set -eu
cd "$(dirname "$0")/.."
dir="${CARGO_TARGET_DIR:-target}/hostile"
mkdir -p "$dir"
dir=$(cd "$dir" && pwd)
EVTXKIT_HOSTILE_DIR="$dir" cargo test --locked --release --quiet --test budget write_hostile_files -- --ignored >/dev/null
if [ -z "${EVTXKIT_BIN:-}" ]; then
  cargo build --locked --release --quiet
  EVTXKIT_BIN="${CARGO_TARGET_DIR:-target}/release/evtxkit"
fi

case "$(uname)" in
  Darwin) time_flag=-l ;;
  *) time_flag=-v ;;
esac

# Prints peak RSS in MB from /usr/bin/time output (macOS bytes, GNU kbytes).
peak_mb() {
  awk '/maximum resident set size/ { print int($1 / 1048576) }
       /Maximum resident set size/ { print int($NF / 1024) }' "$1"
}

run() { # file threads stalled
  log=$(mktemp)
  if [ "$3" = yes ]; then
    { /usr/bin/time $time_flag "$EVTXKIT_BIN" dump -q -t "$2" "$dir/$1.evtx" 2>"$log"; } | { sleep 4; cat >/dev/null; }
  else
    /usr/bin/time $time_flag "$EVTXKIT_BIN" dump -q -t "$2" "$dir/$1.evtx" 2>"$log" >/dev/null
  fi
  errors=$("$EVTXKIT_BIN" dump -q -t 1 --emit-errors "$dir/$1.evtx" | grep -c '"error":true' || true)
  printf '%-20s %9s %7s %7s %11s %13s\n' "$1" "$(wc -c <"$dir/$1.evtx" | tr -d ' ')" "$2" "$3" "$(peak_mb "$log")" "$errors"
  rm -f "$log"
}

printf '%-20s %9s %7s %7s %11s %13s\n' file bytes threads stalled peak_rss_MB record_errors
for f in A-array-10 A-array-100 A-array-500 B-instances-5 B-instances-20 \
         C-records-5 C-records-20 D-string-1000 D-string-25000; do
  run "$f" 1 no
done
[ "${SET:-full}" = small ] && exit 0
for f in B-instances-400 C-records-300; do
  run "$f" 1 no
done
for f in C-records-300-x64 C-records-300-x1024; do
  run "$f" 1 yes
  run "$f" 8 yes
done
