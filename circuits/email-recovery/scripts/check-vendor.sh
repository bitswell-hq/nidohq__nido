#!/usr/bin/env bash
# Fails if any vendored Noir library under circuits/email-recovery/vendor
# differs from its CHECKSUMS.sha256, or holds a file the checksums do not
# list. See each library's NOTICE for its upstream commit.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
status=0
for dir in "$here"/vendor/*/; do
  (
    cd "$dir"
    shasum -a 256 -c --quiet CHECKSUMS.sha256
    listed="$(cut -c67- CHECKSUMS.sha256 | LC_ALL=C sort)"
    present="$(find . -type f ! -name CHECKSUMS.sha256 | sed 's|^\./||' | LC_ALL=C sort)"
    [ "$listed" = "$present" ] || { echo "check-vendor: $dir has files not in CHECKSUMS.sha256" >&2; exit 1; }
  ) || status=1
done
[ "$status" -eq 0 ] && echo "vendored libraries match their checksums"
exit "$status"
