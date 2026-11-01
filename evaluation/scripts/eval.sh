#!/usr/bin/env bash
# Run the evaluation: regenerate evaluation/results/ and the result tables of
# evaluation/README.md. `just eval` runs this; evaluation/README.md says what
# each step measures.
#
# Needs the Perch stack and Nido's contracts (`just perch-infra`,
# `just build-contracts`), the wasm32v1-none target, and elan with the formal
# package's dependencies fetched (`cd formal && lake exe cache get`).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
results="$root/evaluation/results"
contracts="$root/target/wasm32v1-none/contract"
[ -s "$contracts/nido_grant_signer.wasm" ] && [ -s "$contracts/perch_account.wasm" ] \
    || { echo "run 'just perch-infra' and 'just build-contracts' first" >&2; exit 1; }
mkdir -p "$results"

echo "== the dApp fixture" >&2
cargo build --release --locked --target wasm32v1-none \
    --manifest-path evaluation/fixtures/dapp/Cargo.toml --target-dir target/eval-fixtures
dapp="$root/target/eval-fixtures/wasm32v1-none/release/nido_eval_dapp.wasm"

echo "== machine and versions" >&2
if [ "$(uname)" = Darwin ]; then
    cpu=$(sysctl -n machdep.cpu.brand_string)
    memory="$(( $(sysctl -n hw.memsize) / 1073741824 )) GiB"
    os="macOS $(sw_vers -productVersion)"
else
    cpu=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')
    memory="$(( $(grep MemTotal /proc/meminfo | awk '{print $2}') / 1048576 )) GiB"
    os="$(uname -sr)"
fi
locked() { grep -A1 "^name = \"$2\"$" "$1" | sed -n 's/^version = "\(.*\)"/\1/p' | head -1; }
jq -n --arg cpu "$cpu" --arg memory "$memory" --arg os "$os" \
    --arg rustc "$(rustc --version)" \
    --arg lean "$(cat formal/lean-toolchain)" \
    --arg host "$(locked Cargo.lock soroban-env-host)" \
    --arg sdk "$(locked Cargo.lock soroban-sdk)" \
    --arg wasmtime "$(locked crates/agent-host/Cargo.lock wasmtime)" \
    --arg dapp "$(shasum -a 256 "$dapp" | cut -d' ' -f1)" \
    --arg signer "$(shasum -a 256 "$contracts/nido_grant_signer.wasm" | cut -d' ' -f1)" \
    --arg account "$(shasum -a 256 "$contracts/perch_account.wasm" | cut -d' ' -f1)" \
    '{cpu: $cpu, memory: $memory, os: $os, rustc: $rustc,
      "soroban-env-host": $host, "soroban-sdk": $sdk, wasmtime: $wasmtime, lean: $lean,
      "nido_grant_signer.wasm sha256": $signer, "perch_account.wasm sha256": $account,
      "nido_eval_dapp.wasm sha256": $dapp}' >"$results/machine.json"

echo "== Soroban simulation: costs, attacks, workloads" >&2
cargo run --locked -q -p nido-evaluation -- soroban --dapp "$dapp" --out "$results"

echo "== Lean step counts and bounds" >&2
(cd formal && lake build >&2 && lake env lean --run ../evaluation/cost-bound/Steps.lean "$results/lean-cases.json") \
    >"$results/lean-steps.jsonl"

echo "== agent host: workload, attacks, per-check cost, throughput" >&2
cargo run --release --locked -q --manifest-path evaluation/agent-host/Cargo.toml \
    --target-dir crates/agent-host/target -- --out "$results"

echo "== report" >&2
cargo run --locked -q -p nido-evaluation -- report --results "$results" --readme evaluation/README.md
