#!/usr/bin/env bash
# The circuit parser checks (research/email-recovery/eval/parser/README.md):
# compiles the TEST-ONLY harness with Perch's pinned nargo, then runs part 1
# (real mail from corpus/manifest.json) and part 2 (grammar-based fuzzing).
#
#   check.sh          full run: every post of the manifest, 50,000 fuzz cases,
#                     the From finding on the recovery artifact; rewrites
#                     results/ and the README's tables
#   check.sh --ci     the first 10 posts per launch domain and the first 2,000
#                     fuzz cases; fails unless their verdicts are exactly the
#                     ones results/ records for the same posts and cases
#
# The harness is compiled from circuits/email-recovery/lib on every run, and
# the recovery artifact is circuits/email-recovery/artifacts/recovery.json
# (or PARSER_CHECK_ARTIFACT), so after a circuit change `just gen-email-proofs`
# then this script reruns everything against the new circuit.
#
# Needs `npm ci` and Python 3 (lib/from_ref.py uses only its standard
# library). Downloads are cached under target/email-recovery-parser/.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"
cd "$root"

eval "$(circuits/email-recovery/scripts/toolchain.sh)"
circuits/email-recovery/scripts/check-toolchain.sh
(cd "$here/harness" && "$NARGO" compile)
npm run build -w @nidohq/email-mocks -w @nidohq/email-recovery >/dev/null

if [[ "${1:-}" == "--ci" ]]; then
  out="$root/target/email-recovery-parser/ci"
  mkdir -p "$out"
  node "$here/differential.mjs" --per-domain 10 --out "$out/differential.json"
  node "$here/fuzz.mjs" --cases 2000 --out "$out/fuzz.json"
  node "$here/compare-results.mjs" "$out/differential.json" "$out/fuzz.json"
else
  node "$here/differential.mjs"
  node "$here/fuzz.mjs"
  node "$here/from-finding.mjs"
  node "$here/report.mjs"
fi
