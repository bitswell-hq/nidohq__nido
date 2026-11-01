#!/usr/bin/env bash
# Run the evaluation's local-network stage: the attack suite and the workloads
# through the relay to a local Stellar network, relay throughput against the
# channel pool's size, and sibling sub-agents spending at once against a
# shared allowance. Writes evaluation/results/network-*.json and regenerates
# the result tables of evaluation/README.md. `just eval-network` runs this;
# evaluation/README.md says what each part measures.
#
# Needs Docker (it starts the pinned stellar/quickstart image in local mode
# and removes it afterwards), the Stellar CLI, the Perch stack and Nido's
# contracts (`just perch-infra`, `just build-contracts`), and the
# wasm32v1-none target. With NIDO_EVAL_QUICKSTART_URL set, it uses that
# already running quickstart instead.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
results="$root/evaluation/results"
contracts="$root/target/wasm32v1-none/contract"
[ -s "$contracts/nido_grant_signer.wasm" ] && [ -s "$contracts/perch_account.wasm" ] \
    || { echo "run 'just perch-infra' and 'just build-contracts' first" >&2; exit 1; }

echo "== the fixtures" >&2
for fixture in dapp deployer stateless-deployer; do
    cargo build --release --locked --target wasm32v1-none \
        --manifest-path "evaluation/fixtures/$fixture/Cargo.toml" --target-dir target/eval-fixtures
done

echo "== the Perch account and factory for the local network" >&2
evaluation/scripts/local-stack.sh "$(cargo run --locked -q -p nido-evaluation -- local-registry)"

echo "== local network: attacks, workloads, concurrent siblings, throughput" >&2
cargo run --release --locked -q -p nido-evaluation -- network \
    --fixtures target/eval-fixtures/wasm32v1-none/release \
    --local-stack target/eval-local/wasm --out "$results"

echo "== report" >&2
cargo run --locked -q -p nido-evaluation -- report --results "$results" --readme evaluation/README.md
