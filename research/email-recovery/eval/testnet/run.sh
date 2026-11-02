#!/usr/bin/env bash
# The email-recovery contracts on Stellar testnet and one complete
# email-factor recovery through them (testnet/run.mjs), then the tables of
# research/email-recovery/eval/README.md. Deploys new contract instances on
# every run, funded by friendbot. Needs `just perch-infra`, `just
# build-contracts`, `npm ci` and network access to testnet.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$root"
for w in nido_email_verifier nido_email_guardian nido_dkim_registry nido_enclave_image_registry; do
  [ -s "target/wasm32v1-none/contract/$w.wasm" ] || { echo "run 'just build-contracts' first" >&2; exit 1; }
done
cargo build -q -p nido-dns-attestation-mock
npm run build -w @nidohq/email-mocks -w @nidohq/email-recovery -w @nidohq/email-alerts >/dev/null
node research/email-recovery/eval/testnet/run.mjs
node research/email-recovery/eval/report.mjs
