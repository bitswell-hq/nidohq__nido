#!/usr/bin/env bash
# `just perch-infra`: put the Perch stack Nido tests against into
# target/wasm32v1-none/contract/ and write the factory's perch-account pin,
# contracts/factory/wasm/perch-account.sha256, which the factory's
# `registry_contract!` compiles in.
#
# Where the stack comes from follows the submodule's remote (.gitmodules):
#
# - fetch: a pin on Perch's upstream (stellar-registry/perch) is a deployed
#   Perch. Its stack is fetched with vendor/perch/scripts/fetch-infra-wasm.sh
#   by the hashes in its deployment manifest, reading the chain through the
#   endpoint scripts/stellar-rpc.sh chooses (RPC_URL/STELLAR_RPC_URL override,
#   else the manifest's rpc_url, else a guarded fallback while that is down;
#   docs/RUNBOOKS.md "RPC endpoints"). The pin is the manifest's
#   `perch-account` hash; a manifest without one fails, so the pin never
#   comes from another network.
#
#   A Perch fetch script that sources stellar-rpc.sh itself chooses and fails
#   over per fetch; it is run as is. An older one reads only the manifest's
#   rpc_url, so it is given a copy of the manifest whose rpc_url is the chosen
#   endpoint (every other field, so every hash and content address it checks,
#   unchanged). If that run fails because the endpoint failed a fetch after the
#   script's own retries, the run moves to the next guarded fallback and starts
#   again. Any other failure (a hash or content-address mismatch, a contract
#   error, a missing entry) fails as it is.
#
# - build: a pin on any other remote (the bitswell fork's M6 stack, which no
#   network runs) is built from the submodule's source with `stellar contract
#   build`, under Nido's pinned toolchain (rust-toolchain.toml) and into
#   target/perch-build/, so the bytes depend on the commit, the toolchain and
#   the Stellar CLI only. The account is built from its committed build-time
#   pins, so it derives its infra at the content addresses the Perch crates'
#   `infra` module derives, which is where the integration tests register the
#   built infra. The pin is the built account's hash, and
#   target/perch-build/stack.json records the commit, the toolchain and every
#   built hash for scripts/check-perch-drift.sh.
#
# Env: NIDO_PERCH_STACK (fetch|build) overrides the choice; STELLAR_NETWORK
# (default testnet) picks vendor/perch/deployments/<net>.json for a fetch;
# NIDO_PERCH_DIR overrides vendor/perch and NIDO_FACTORY_PIN the pin file
# (tests).
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
perch="${NIDO_PERCH_DIR:-$repo_root/vendor/perch}"
stack="$repo_root/target/wasm32v1-none/contract"
manifest="$perch/deployments/${STELLAR_NETWORK:-testnet}.json"
fetch="$perch/scripts/fetch-infra-wasm.sh"
[ -f "$manifest" ] || { echo "error: no manifest at $manifest (git submodule update --init)" >&2; exit 1; }
command -v jq >/dev/null || { echo "error: jq not found" >&2; exit 1; }

pin="${NIDO_FACTORY_PIN:-$repo_root/contracts/factory/wasm/perch-account.sha256}"

mode="${NIDO_PERCH_STACK:-$(bash "$repo_root/scripts/perch-stack-source.sh")}"
case "$mode" in
    fetch) ;;
    build) exec bash "$repo_root/scripts/perch-build-stack.sh" "$perch" "$stack" "$pin" ;;
    *) echo "error: NIDO_PERCH_STACK is fetch or build, not '$mode'" >&2; exit 1 ;;
esac

account="$(jq -r '.contracts["perch-account"].sha256 // empty' "$manifest")"
[[ "$account" =~ ^[0-9a-f]{64}$ ]] ||
    { echo "error: $manifest has no perch-account hash for the factory to pin" >&2; exit 1; }
printf '%s\n' "$account" >"$pin"

if grep -q 'stellar-rpc\.sh' "$fetch"; then
    cd "$perch" && exec bash "$fetch" --manifest "$manifest" --stack "$stack"
fi

# shellcheck source=scripts/stellar-rpc.sh
. "$repo_root/scripts/stellar-rpc.sh"
rpc_select "$(jq -r .rpc_url "$manifest")" "$(jq -r .network_passphrase "$manifest")" ||
    { echo "error: no usable RPC endpoint" >&2; exit 1; }

copy="$repo_root/target/perch-infra/$(basename "$manifest")"
mkdir -p "$(dirname "$copy")"
err="$(mktemp)"
trap 'rm -f "$_rpc_state" "$err"' EXIT
while :; do
    url="$(rpc_url)"
    jq --arg u "$url" '.rpc_url = $u' "$manifest" >"$copy"
    _rpc_log "fetch-infra-wasm.sh: every fetch in this run <- $url"
    rc=0
    # stderr to the terminal and to $err; stdout untouched.
    { (cd "$perch" && bash "$fetch" --manifest "$copy" --stack "$stack") 2>&1 1>&3 | tee "$err" >&2; } 3>&1 || rc=$?
    [ "$rc" -ne 0 ] || exit 0
    # The fetch script exhausted its retries against the endpoint ("fetch
    # failed after N attempts"); anything else is not the endpoint's fault.
    grep -q 'fetch failed after' "$err" || exit "$rc"
    _rpc_server_error=false
    ! _rpc_server_side "$err" || _rpc_server_error=true
    rpc_failover || exit "$rc"
done
