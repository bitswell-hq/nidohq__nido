#!/usr/bin/env bash
# The email-factor recovery with every entry it reads archived, on the
# integration-test host (crates/integration-tests/tests/it/email_archival.rs):
# writes results/archival-test-host.json, then regenerates the tables of
# research/email-recovery/eval/README.md, which price it at mainnet's
# settings. Needs `just perch-infra` and `just build-contracts`.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$root"
NIDO_EMAIL_ARCHIVAL_OUT="$root/research/email-recovery/eval/results/archival-test-host.json" \
  cargo test -q -p nido-integration-tests --test it email_archival -- --test-threads=1
node research/email-recovery/eval/report.mjs
