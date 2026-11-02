#!/usr/bin/env bash
# Build the Perch account and Nido's factory for the local network.
#
# A Perch account finds its doc compiler, interpreter and spending limit at
# `deployer(<registry>, sha256(wasm))`, where <registry> is the end of the
# chain its build-time `wasm/registry.path` names (perch-registry-resolve):
# a root an account deployed with `sha256(root-salt)`, then one named deploy
# per path segment. Perch's committed path is rooted in the Stellar Registry,
# which no local network has, so this script builds the same account source
# (vendor/perch at its pinned commit) with one change: its registry.path is
# evaluation/fixtures/local-registry.path, whose chain `nido-eval network`
# and tests/support/emailLocalStack.mjs deploy, and whose last registry is
# what `nido-eval local-registry` prints. The tier-0 pins (the doc compiler,
# interpreter and spending limit wasm hashes) are unchanged: the local
# network runs the fetched testnet bytes of those contracts. Nido's factory
# pins the account by hash (contracts/factory/wasm/perch-account.sha256), so
# it is built from a copy of this tree whose pin is the local account's hash.
#
# Output: target/eval-local/wasm/{perch_account,nido_factory}.wasm and
# build.json (the registry id, the Perch commit and every hash).
#
# Usage: evaluation/scripts/local-stack.sh <registry C…>
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
registry="${1:?usage: local-stack.sh <registry C…>}"
[[ "$registry" =~ ^C[A-Z2-7]{55}$ ]] || { echo "not a contract address: $registry" >&2; exit 1; }
out="$root/target/eval-local"
fetched="$root/target/wasm32v1-none/contract"
[ -s "$fetched/perch_account.wasm" ] || { echo "run 'just perch-infra' first" >&2; exit 1; }

sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }

mkdir -p "$out/wasm"
rsync -a --delete --exclude target --exclude .git "$root/vendor/perch/" "$out/perch/"
cp "$root/evaluation/fixtures/local-registry.path" "$out/perch/crates/perch-smart-account/wasm/registry.path"
for pin in perch-doc-compiler perch-interpreter perch-spending-limit; do
    want=$(cat "$out/perch/crates/perch-smart-account/wasm/$pin.sha256")
    got=$(sha256 "$fetched/${pin//-/_}.wasm")
    [ "$want" = "$got" ] || { echo "$pin: pinned $want, fetched $got" >&2; exit 1; }
done

(cd "$out/perch" && CARGO_TARGET_DIR="$out/perch-target" stellar contract build --package perch-account --out-dir "$out/wasm")
account=$(sha256 "$out/wasm/perch_account.wasm")

# The factory, from a copy of the Rust workspace with the local account pin.
rsync -a --delete --exclude target --exclude .git --exclude node_modules --exclude vendor \
    --exclude research --exclude paper --exclude formal --exclude packages --exclude infra \
    --exclude frontend --exclude examples --exclude .lake \
    "$root/" "$out/nido-src/"
printf '%s\n' "$account" >"$out/nido-src/contracts/factory/wasm/perch-account.sha256"
(cd "$out/nido-src" && CARGO_TARGET_DIR="$out/nido" stellar contract build --package nido-factory --out-dir "$out/wasm")
stellar contract optimize --wasm "$out/wasm/nido_factory.wasm" --wasm-out "$out/wasm/nido_factory.wasm"

jq -n --arg registry "$registry" \
    --arg perch_commit "$(git -C "$root/vendor/perch" rev-parse HEAD)" \
    --arg account "$account" \
    --arg fetched_account "$(sha256 "$fetched/perch_account.wasm")" \
    --arg factory "$(sha256 "$out/wasm/nido_factory.wasm")" \
    --arg stellar "$(stellar --version | head -1)" \
    '{registry: $registry, perch_commit: $perch_commit,
      perch_account_sha256: $account, testnet_perch_account_sha256: $fetched_account,
      nido_factory_sha256: $factory, stellar_cli: $stellar}' >"$out/build.json"
cat "$out/build.json"
