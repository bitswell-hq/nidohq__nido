#!/usr/bin/env bash
# Build the Perch account and Nido's factory for the local network.
#
# A Perch account finds its doc compiler, interpreter and spending limit at
# the addresses `deployer(stateless.id, sha256(wasm))` derives on the current
# network (perch-registry-resolve). The account `just perch-infra` fetches
# names the testnet registry, which no local network has, so this script
# builds the same account source (vendor/perch at its pinned commit) with one
# change: `stateless.id` is the evaluation's stateless deployer on the local
# network (`nido-eval local-registry`). The tier-0 pins (the doc compiler,
# interpreter and spending limit wasm hashes) are unchanged: the local network
# runs the fetched testnet bytes of those contracts. Nido's factory is then
# built around that account, as `just build-contracts` builds it around the
# fetched one.
#
# Output: target/eval-local/wasm/{perch_account,nido_factory}.wasm and
# build.json (the registry id and every hash).
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

mkdir -p "$out/wasm" "$out/nido/wasm32v1-none/contract"
rsync -a --delete --exclude target --exclude .git "$root/vendor/perch/" "$out/perch/"
printf '%s' "$registry" >"$out/perch/crates/perch-smart-account/wasm/stateless.id"
for pin in perch-doc-compiler perch-interpreter perch-spending-limit; do
    want=$(cat "$out/perch/crates/perch-smart-account/wasm/$pin.sha256")
    got=$(sha256 "$fetched/${pin//-/_}.wasm")
    [ "$want" = "$got" ] || { echo "$pin: pinned $want, fetched $got" >&2; exit 1; }
done

(cd "$out/perch" && CARGO_TARGET_DIR="$out/perch-target" stellar contract build --package perch-account --out-dir "$out/wasm")
cp "$out/wasm/perch_account.wasm" "$out/nido/wasm32v1-none/contract/perch_account.wasm"
(cd "$root" && CARGO_TARGET_DIR="$out/nido" stellar contract build --package nido-factory --out-dir "$out/wasm")
stellar contract optimize --wasm "$out/wasm/nido_factory.wasm" --wasm-out "$out/wasm/nido_factory.wasm"

jq -n --arg registry "$registry" \
    --arg perch_commit "$(git -C "$root/vendor/perch" rev-parse HEAD)" \
    --arg account "$(sha256 "$out/wasm/perch_account.wasm")" \
    --arg fetched_account "$(sha256 "$fetched/perch_account.wasm")" \
    --arg factory "$(sha256 "$out/wasm/nido_factory.wasm")" \
    --arg stellar "$(stellar --version | head -1)" \
    '{registry: $registry, perch_commit: $perch_commit,
      perch_account_sha256: $account, testnet_perch_account_sha256: $fetched_account,
      nido_factory_sha256: $factory, stellar_cli: $stellar}' >"$out/build.json"
cat "$out/build.json"
