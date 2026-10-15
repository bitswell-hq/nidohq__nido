#!/usr/bin/env bash
#
# Check Nido's factory record (packages/passkey-sdk/src/perch/
# factory.<network>.json, written by scripts/deploy-factory.sh) against the
# chain. One RPC read of the factory's instance: its executable wasm hash,
# the account hash it deploys (`Account`, the cache `create_account` reads),
# its pinned WebAuthn verifier (`PinnedVerifier`), and its admin (`ADMIN`)
# must equal the record's. Read-only: no identity, nothing signed.
#
# The record's account and verifier are checked against Perch's manifest by
# packages/passkey-sdk/src/perch/deployment.test.ts; together the two say the
# deployed factory mints the account the manifest names.
#
# Usage: scripts/check-factory.sh [network]   (default "testnet")
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }

NETWORK="${1:-testnet}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RECORD="$REPO_ROOT/packages/passkey-sdk/src/perch/factory.$NETWORK.json"

command -v stellar >/dev/null || die "stellar CLI not found"
command -v jq >/dev/null || die "jq not found"
[ -f "$RECORD" ] || die "no factory record at $RECORD"

r() { jq -r "$1" "$RECORD"; }
FACTORY="$(r .factory)"
[[ "$FACTORY" =~ ^C[A-Z2-7]{55}$ ]] || die "$RECORD has no factory address"

instance="$(stellar ledger entry fetch contract-data --contract "$FACTORY" --instance --network "$NETWORK" --output json \
    | jq -c '[.. | objects | select(has("contract_instance")) | .contract_instance][0]')"
[ "$instance" != null ] || die "no contract instance for $FACTORY on $NETWORK"

stored() { jq -r --arg k "$1" '.storage[]? | select(.key.symbol == $k) | .val | (.bytes // .address)' <<<"$instance"; }
problems=0
check() {
    if [ "$2" = "$3" ]; then
        echo "  $1: $2"
    else
        echo "error: $1 is ${2:-<none>} on chain, ${3} in the record" >&2
        problems=$((problems + 1))
    fi
}

echo "factory $FACTORY ($NETWORK)"
check "wasm" "$(jq -r '.executable.wasm' <<<"$instance")" "$(r .wasm_hash)"
check "account it deploys" "$(stored Account)" "$(r .account_wasm_hash)"
check "pinned verifier" "$(stored PinnedVerifier)" "$(r .pinned_verifier)"
check "admin" "$(stored ADMIN)" "$(r .admin)"
[ "$problems" -eq 0 ] || die "$RECORD does not describe the deployed factory ($problems mismatches)"
