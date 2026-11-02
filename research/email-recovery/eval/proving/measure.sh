#!/usr/bin/env bash
# Proving on this machine (proving/measure.mjs): installs and checks Perch's
# pinned nargo and bb, compiles the recovery circuit (measure.mjs checks the
# bytecode is the committed artifact's), builds the npm packages bb.js runs
# from, and measures. RUNS=n sets the runs per configuration (default 5).
# Run it on an otherwise idle machine; the browser rows come from
# browser-prover.json (measure-browser.mjs).
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$root"
eval "$(circuits/email-recovery/scripts/toolchain.sh)"
circuits/email-recovery/scripts/check-toolchain.sh
(cd circuits/email-recovery && "$NARGO" compile --package recovery --silence-warnings)
npm run build -w @nidohq/email-mocks -w @nidohq/email-recovery >/dev/null
NARGO="$NARGO" BB="$BB" node research/email-recovery/eval/proving/measure.mjs
node research/email-recovery/eval/report.mjs
