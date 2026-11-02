#!/usr/bin/env bash
# An account's move to a new email guardian, the per-account step of a fix
# of the email circuit, on the integration-test host
# (crates/integration-tests/tests/it/email_migration.rs): writes
# results/migration-test-host.json, then regenerates the tables of
# research/email-recovery/eval/README.md, which price it at mainnet's
# settings. Needs `just perch-infra` and `just build-contracts`.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$root"
NIDO_EMAIL_MIGRATION_OUT="$root/research/email-recovery/eval/results/migration-test-host.json" \
  cargo test -q -p nido-integration-tests --test it email_migration -- --test-threads=1
node research/email-recovery/eval/report.mjs
