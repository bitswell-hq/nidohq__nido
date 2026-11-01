#!/usr/bin/env bash
# The email recovery end-to-end test on a local Stellar network
# (tests/e2e/local/email-recovery.local.spec.ts):
#
#   1. builds the Perch account for the local network's stateless deployer
#      (evaluation/scripts/local-stack.sh), the email contracts, and the
#      TEST-ONLY fixtures;
#   2. starts `stellar/quickstart --local` (pinned by digest) and deploys
#      everything onto it (tests/support/emailLocalStack.mjs);
#   3. starts the alert service with its mocks, the mail and DNS mocks, and
#      TLS in front of the RPC (tests/support/emailServices.mjs);
#   4. builds the wallet for that network, with the key list the registry
#      gives (packages/email-recovery/scripts/dkim-key-list.mjs);
#   5. runs the Playwright test, which drives enrollment and recovery in
#      Chromium with the real in-browser proof.
#
# Needs Docker, the Stellar CLI, `just perch-infra` done once, and
# Playwright's Chromium (`npx playwright install chromium`).
#
#   scripts/email-recovery-e2e.sh [--keep]     # --keep leaves the network and services up
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
keep="${1:-}"
out=target/email-e2e
mkdir -p "$out/wasm"
QUICKSTART="stellar/quickstart@sha256:487fe637ba48c972d5be0ed8965f8df1dcbc3e8e1ee53d24d915b25b6f2b6d99"
NAME=nido-email-e2e
export E2E_PORT="${E2E_PORT:-4399}" E2E_RPC_PORT=8443 E2E_ALERT_PORT=8471 E2E_CONTROL_PORT=8472

[ -s target/wasm32v1-none/contract/perch_account.wasm ] || { echo "run 'just perch-infra' first" >&2; exit 1; }

# 1. Contracts.
deployer=$(node --input-type=module -e '
import { Keypair, hash, xdr, Address, StrKey } from "@stellar/stellar-sdk";
import { createHash } from "node:crypto";
const kp = Keypair.fromRawEd25519Seed(createHash("sha256").update("nido-eval/deployer").digest());
const pre = xdr.HashIdPreimage.envelopeTypeContractId(new xdr.HashIdPreimageContractId({
  networkId: hash(Buffer.from("Standalone Network ; February 2017")),
  contractIdPreimage: xdr.ContractIdPreimage.contractIdPreimageFromAddress(new xdr.ContractIdPreimageFromAddress({ address: Address.fromString(kp.publicKey()).toScAddress(), salt: Buffer.alloc(32, 0x5e) })),
}));
console.log(StrKey.encodeContract(hash(pre.toXDR())));')
[ -s target/eval-local/build.json ] && grep -q "$deployer" target/eval-local/build.json || evaluation/scripts/local-stack.sh "$deployer"
for p in nido-email-verifier nido-email-guardian nido-dkim-registry; do
  CARGO_TARGET_DIR="$out/cargo" stellar contract build --package "$p" --out-dir "$out/wasm"
done
(cd evaluation/fixtures/stateless-deployer && CARGO_TARGET_DIR="$root/$out/cargo-sd" stellar contract build --out-dir "$root/$out/wasm")
(cd tests/e2e/local/fixtures/image-allowlist && CARGO_TARGET_DIR="$root/$out/cargo-ia" stellar contract build --out-dir "$root/$out/wasm")
for w in "$out"/wasm/nido_*.wasm; do stellar contract optimize --wasm "$w" --wasm-out "$w" >/dev/null; done
npm run build -w @nidohq/email-mocks -w @nidohq/email-recovery -w @nidohq/email-alerts

# 2. The network and the stack.
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --rm --name "$NAME" -p 127.0.0.1:8000:8000 "$QUICKSTART" --local --enable rpc >/dev/null
services=""
cleanup() {
  [ -n "$services" ] && kill "$services" 2>/dev/null || true
  [ "$keep" = "--keep" ] || docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT
# Ready: RPC healthy, the Soroban settings upgrade applied, and friendbot funding.
probe=$(node -e 'console.log(require("@stellar/stellar-sdk").Keypair.random().publicKey())')
for _ in $(seq 1 120); do
  if curl -fs -X POST -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' http://127.0.0.1:8000/rpc | grep -q healthy \
    && docker logs "$NAME" 2>&1 | grep -q "soroban config done" \
    && curl -fs "http://127.0.0.1:8000/friendbot?addr=$probe" >/dev/null; then break; fi
  sleep 3
done
node tests/support/emailLocalStack.mjs --rpc http://127.0.0.1:8000 >/dev/null

# 3. The services.
node tests/support/emailServices.mjs >"$out/services.json" 2>"$out/services.log" &
services=$!
for _ in $(seq 1 60); do [ -s "$out/services.json" ] && break; sleep 1; done
[ -s "$out/services.json" ] || { cat "$out/services.log" >&2; exit 1; }

# 4. The wallet, built for this network, and the key list.
node tests/support/emailBuildEnv.mjs >"$out/build.env"
# shellcheck disable=SC1091
. "$out/build.env"
npx astro build --root ./packages/frontend >"$out/astro.log"
node packages/email-recovery/scripts/dkim-key-list.mjs --rpc http://127.0.0.1:8000/rpc \
  --registry "$(node -p 'require("./target/email-e2e/stack.json").email.registry')" \
  --network "Standalone Network ; February 2017" --start-ledger 1 --out packages/frontend/dist/dkim-keys.json

# 5. The test.
npx playwright test --project=email-local
