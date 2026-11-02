#!/usr/bin/env bash
# Build what the evaluation's local network runs: Perch's account for the
# local network's stateless deployer (evaluation/scripts/local-stack.sh),
# the stateless deployer and image allowlist fixtures, the suite's TEST-ONLY
# fixtures, the DNS attester mock, the npm packages the suite imports (the
# wallet SDK among them, so a checkout whose dist/ predates its source runs
# the current SDK), and the TLS certificate
# of the RPC proxy (lib/tls.mjs), after checking that node_modules matches
# package-lock.json (lib/preflight.mjs). Needs the Stellar CLI, `npm ci`,
# `just perch-infra` and `just build-contracts` (the email contracts' wasm).
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$root"
out=target/email-attacks
mkdir -p "$out/wasm"

[ -s target/wasm32v1-none/contract/perch_account.wasm ] || { echo "run 'just perch-infra' first" >&2; exit 1; }
node research/email-recovery/eval/network/lib/preflight.mjs

# The local account and factory, rebuilt unless target/eval-local was built
# for the local registry path and this Perch commit.
registry=$(node --input-type=module -e 'import { registryChain } from "./tests/support/emailLocalStack.mjs"; console.log(registryChain().at(-1));')
perch_commit=$(git -C vendor/perch rev-parse HEAD)
if ! { [ -s target/eval-local/build.json ] \
  && [ "$(jq -r .registry target/eval-local/build.json)" = "$registry" ] \
  && [ "$(jq -r .perch_commit target/eval-local/build.json)" = "$perch_commit" ]; }; then
  evaluation/scripts/local-stack.sh "$registry"
fi
# The email contracts are `just build-contracts`' optimized wasm (lib/stack.mjs
# EMAIL_WASM), the bytes the testnet deployment runs.
for w in nido_email_verifier nido_email_guardian nido_dkim_registry; do
  [ -s "target/wasm32v1-none/contract/$w.wasm" ] || { echo "run 'just build-contracts' first" >&2; exit 1; }
done
# The stateless deployer and the image allowlist, as the end-to-end test's
# stack deploys them (tests/support/emailLocalStack.mjs).
e2e=target/email-e2e
mkdir -p "$e2e/wasm"
(cd evaluation/fixtures/stateless-deployer && CARGO_TARGET_DIR="$root/$e2e/cargo-sd" stellar contract build --out-dir "$root/$e2e/wasm")
(cd tests/e2e/local/fixtures/image-allowlist && CARGO_TARGET_DIR="$root/$e2e/cargo-ia" stellar contract build --out-dir "$root/$e2e/wasm")
for w in "$e2e"/wasm/nido_*.wasm; do stellar contract optimize --wasm "$w" --wasm-out "$w" >/dev/null; done
(cd research/email-recovery/eval/network/fixtures/foreign-controller && CARGO_TARGET_DIR="$root/$out/cargo-fc" stellar contract build --out-dir "$root/$out/wasm")
cargo build -q -p nido-dns-attestation-mock
npm run build -w @nidohq/passkey-sdk -w @nidohq/email-mocks -w @nidohq/email-recovery -w @nidohq/email-alerts >/dev/null
node --input-type=module -e "import('./research/email-recovery/eval/network/lib/tls.mjs').then((m) => m.cert('$out/tls'))"
