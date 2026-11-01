#!/usr/bin/env bash
# Measures the email-recovery circuit and its components with Perch's pinned
# toolchain: installs and checks it, compiles every package, builds the
# TypeScript packages bb.js runs from (after `npm install` at the root), then
# runs scripts/measure.py, which rewrites the generated tables in
# MEASUREMENTS.md. RUNS=n sets the number of proving runs (default 3).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
eval "$("$here/scripts/toolchain.sh")"
"$here/scripts/check-toolchain.sh"
(cd "$here" && "$NARGO" compile --workspace --force --silence-warnings)
(cd "$here/../.." && npm run build -w @nidohq/email-mocks -w @nidohq/email-recovery >/dev/null)
NARGO="$NARGO" BB="$BB" python3 "$here/scripts/measure.py"
