#!/usr/bin/env bash
# Fails unless the active nargo and bb are the versions Perch pins in
# vendor/perch/scripts/zk-toolchain.sh. NARGO and BB name the binaries
# (default: nargo and bb on PATH); scripts/toolchain.sh sets both.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
pins="$root/vendor/perch/scripts/zk-toolchain.sh"
[ -f "$pins" ] || { echo "check-toolchain: $pins is missing; run git submodule update --init" >&2; exit 1; }
want_nargo="$(sed -n 's/^NOIR_VERSION="\(.*\)"$/\1/p' "$pins")"
want_bb="$(sed -n 's/^BB_VERSION="\(.*\)"$/\1/p' "$pins")"
[ -n "$want_nargo" ] && [ -n "$want_bb" ] || { echo "check-toolchain: cannot read the pins from $pins" >&2; exit 1; }

nargo="${NARGO:-nargo}"
bb="${BB:-bb}"
got_nargo="$("$nargo" --version 2>/dev/null | sed -n 's/^nargo version = //p' || true)"
got_bb="$("$bb" --version 2>/dev/null | head -n 1 | sed 's/^v//' || true)"

status=0
if [ "$got_nargo" != "$want_nargo" ]; then
  echo "check-toolchain: $nargo is nargo ${got_nargo:-<not found>}; Perch pins $want_nargo" >&2
  status=1
fi
if [ "$got_bb" != "$want_bb" ]; then
  echo "check-toolchain: $bb is bb ${got_bb:-<not found>}; Perch pins $want_bb" >&2
  status=1
fi
[ "$status" -eq 0 ] && echo "nargo $got_nargo and bb $got_bb match Perch's pins"
exit "$status"
