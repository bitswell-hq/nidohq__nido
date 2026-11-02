#!/usr/bin/env bash
# The email factor's attack suite (research/email-recovery/eval/README.md):
#
#   1. builds what the local network runs: Perch's account for the local
#      network's stateless deployer (evaluation/scripts/local-stack.sh), the
#      email contracts, and the suite's TEST-ONLY fixtures;
#   2. starts `stellar/quickstart --local` (pinned by digest) and runs
#      attacks.mjs against it, which deploys the stack, runs every scenario,
#      and writes results/attacks-local.json;
#   3. runs the three registry scenarios that need an elapsed timelock on the
#      integration-test host (email_guardian.rs, `registry_*`), which append
#      their rows to results/attacks-test-host.jsonl;
#   4. regenerates the tables of research/email-recovery/eval/README.md.
#
# Needs Docker, the Stellar CLI, `npm ci`, and `just perch-infra` done
# once; the test-host step also needs `just build-contracts`.
#
#   research/email-recovery/eval/network/run-attacks.sh [--keep] [--local-only]
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$root"
keep=0 local_only=0
for a in "$@"; do
  case "$a" in
    --keep) keep=1 ;;
    --local-only) local_only=1 ;;
    *) echo "unknown argument $a" >&2; exit 2 ;;
  esac
done
QUICKSTART="stellar/quickstart@sha256:487fe637ba48c972d5be0ed8965f8df1dcbc3e8e1ee53d24d915b25b6f2b6d99"
NAME=nido-email-attacks
PORT="${NIDO_EVAL_QUICKSTART_PORT:-8000}"
out=target/email-attacks
results=research/email-recovery/eval/results
mkdir -p "$out/wasm" "$results"

[ -s target/wasm32v1-none/contract/perch_account.wasm ] || { echo "run 'just perch-infra' first" >&2; exit 1; }

echo "== build" >&2
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
# The email contracts as the end-to-end test's stack deploys them (tests/support/emailLocalStack.mjs).
e2e=target/email-e2e
mkdir -p "$e2e/wasm"
for p in nido-email-verifier nido-email-guardian nido-dkim-registry; do
  CARGO_TARGET_DIR="$e2e/cargo" stellar contract build --package "$p" --out-dir "$e2e/wasm"
done
(cd evaluation/fixtures/stateless-deployer && CARGO_TARGET_DIR="$root/$e2e/cargo-sd" stellar contract build --out-dir "$root/$e2e/wasm")
(cd tests/e2e/local/fixtures/image-allowlist && CARGO_TARGET_DIR="$root/$e2e/cargo-ia" stellar contract build --out-dir "$root/$e2e/wasm")
for w in "$e2e"/wasm/nido_*.wasm; do stellar contract optimize --wasm "$w" --wasm-out "$w" >/dev/null; done
(cd research/email-recovery/eval/network/fixtures/foreign-controller && CARGO_TARGET_DIR="$root/$out/cargo-fc" stellar contract build --out-dir "$root/$out/wasm")
cargo build -q -p nido-dns-attestation-mock
npm run build -w @nidohq/email-mocks -w @nidohq/email-recovery -w @nidohq/email-alerts >/dev/null
node --input-type=module -e "import('./research/email-recovery/eval/network/lib/tls.mjs').then((m) => m.cert('$out/tls'))"

echo "== the local network" >&2
if [ -z "${NIDO_EVAL_QUICKSTART_URL:-}" ]; then
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --rm --name "$NAME" -p "127.0.0.1:$PORT:8000" "$QUICKSTART" --local --enable rpc >/dev/null
  cleanup() { [ "$keep" = 1 ] || docker rm -f "$NAME" >/dev/null 2>&1 || true; }
  trap cleanup EXIT
  export NIDO_EVAL_QUICKSTART_URL="http://127.0.0.1:$PORT"
  probe=$(node -e 'console.log(require("@stellar/stellar-sdk").Keypair.random().publicKey())')
  ready=0
  for _ in $(seq 1 120); do
    if curl -fs -X POST -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' "$NIDO_EVAL_QUICKSTART_URL/rpc" | grep -q healthy \
      && docker logs "$NAME" 2>&1 | grep -q "soroban config done" \
      && curl -fs "$NIDO_EVAL_QUICKSTART_URL/friendbot?addr=$probe" >/dev/null; then ready=1; break; fi
    sleep 3
  done
  [ "$ready" = 1 ] || { echo "the local network did not start" >&2; exit 1; }
fi
export NIDO_EVAL_QUICKSTART_IMAGE="$QUICKSTART"

echo "== the attack suite on the local network" >&2
rm -f "$out/stack.json"
NODE_EXTRA_CA_CERTS="$out/tls/cert.pem" node --test-concurrency=1 --test-reporter=spec --test research/email-recovery/eval/network/attacks.mjs

if [ "$local_only" = 0 ]; then
  echo "== the registry scenarios on the test host" >&2
  rows="$root/$results/attacks-test-host.jsonl"
  rm -f "$rows"
  NIDO_EMAIL_ATTACK_ROWS="$rows" cargo test -q -p nido-integration-tests --test it email_guardian::registry_ -- --test-threads=1
fi

echo "== report" >&2
node research/email-recovery/eval/report.mjs
