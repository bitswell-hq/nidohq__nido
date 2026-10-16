#!/usr/bin/env bash
#
# Check Nido's factory record (packages/passkey-sdk/src/perch/
# factory.<network>.json, written by scripts/deploy-factory.sh) against the
# chain. One RPC read of the factory's instance: its executable wasm hash,
# the account hash it deploys (`Account`, the cache `create_account` reads),
# its pinned WebAuthn verifier (`PinnedVerifier`), its admin (`ADMIN`), and,
# when the record has one, its change delay (`Delay`) must equal the
# record's. Read-only: no identity, nothing signed.
#
# The record's account and verifier are checked against Perch's manifest by
# packages/passkey-sdk/src/perch/deployment.test.ts; together the two say the
# deployed factory mints the account the manifest names.
#
# The read goes through scripts/stellar-rpc.sh: RPC_URL/STELLAR_RPC_URL if
# set, else Perch's manifest's rpc_url (vendor/perch/deployments/<network>.json),
# else a guarded fallback while that is down, also mid-run (docs/RUNBOOKS.md
# "RPC endpoints").
#
# Usage: scripts/check-factory.sh [network]   (default "testnet")
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }

NETWORK="${1:-testnet}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RECORD="$REPO_ROOT/packages/passkey-sdk/src/perch/factory.$NETWORK.json"

command -v stellar >/dev/null || die "stellar CLI not found"
command -v jq >/dev/null || die "jq not found"
command -v curl >/dev/null || die "curl not found"
[ -f "$RECORD" ] || die "no factory record at $RECORD"
MANIFEST="$REPO_ROOT/vendor/perch/deployments/$NETWORK.json"
[ -f "$MANIFEST" ] || die "no Perch manifest at $MANIFEST (git submodule update --init)"

r() { jq -r "$1" "$RECORD"; }
FACTORY="$(r .factory)"
[[ "$FACTORY" =~ ^C[A-Z2-7]{55}$ ]] || die "$RECORD has no factory address"

PASSPHRASE="$(r .network_passphrase)"
[ "$PASSPHRASE" = "$(jq -r .network_passphrase "$MANIFEST")" ] || die "$RECORD and $MANIFEST name different networks"
# shellcheck source=scripts/stellar-rpc.sh
. "$REPO_ROOT/scripts/stellar-rpc.sh"
rpc_select "$(jq -r .rpc_url "$MANIFEST")" "$PASSPHRASE" || die "no usable RPC endpoint for $NETWORK"

instance="$(rpc_stellar ledger entry fetch contract-data --contract "$FACTORY" --instance --output json \
    | jq -c '[.. | objects | select(has("contract_instance")) | .contract_instance][0]')"
[ "$instance" != null ] || die "no contract instance for $FACTORY on $NETWORK"

stored() { jq -r --arg k "$1" '.storage[]? | select(.key.symbol == $k) | .val | (.bytes // .address // .u32)' <<<"$instance"; }
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
# Factories from before the change delay have none, and neither do their records.
[ "$(r '.change_delay // empty')" = "" ] || check "change delay" "$(stored Delay)" "$(r .change_delay)"
[ "$problems" -eq 0 ] || die "$RECORD does not describe the deployed factory ($problems mismatches)"
