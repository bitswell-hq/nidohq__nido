#!/usr/bin/env bash
# Start the evaluation's local Stellar network: `stellar/quickstart --local`,
# pinned by digest in quickstart.env, at protocol 29, the protocol
# mainnet and testnet run, with mainnet's Soroban settings loaded at start
# (network/limits/mainnet.json, written from results/settings/mainnet.json
# by fees/settings.mjs). Quickstart's local mode keeps closing about one
# ledger a second. Waits until RPC is healthy, both settings upgrades have
# applied and friendbot funds an account, then archives the network's
# settings as results/settings/<name>.json when ARCHIVE names one.
#
#   research/email-recovery/eval/network/start-local.sh NAME PORT
#
# Prints the network's base URL. Exports nothing; the caller removes the
# container (`docker rm -f NAME`).
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
name="$1" port="$2"
# shellcheck source-path=SCRIPTDIR source=quickstart.env
. "$root/research/email-recovery/eval/network/quickstart.env"
QUICKSTART="${NIDO_EVAL_QUICKSTART_IMAGE:-$QUICKSTART_IMAGE}"
limits="$root/research/email-recovery/eval/network/limits/mainnet.json"
base="http://127.0.0.1:$port"

docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --rm --name "$name" -p "127.0.0.1:$port:8000" \
  -v "$limits:/opt/stellar-default/local/core/etc/config-settings/p29/mainnet.json:ro" \
  "$QUICKSTART" --local --enable rpc --protocol-version 29 --limits mainnet >/dev/null
probe=$(cd "$root" && node -e 'console.log(require("@stellar/stellar-sdk").Keypair.random().publicKey())')
for _ in $(seq 1 200); do
  if [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" != true ]; then
    echo "the local network stopped while starting" >&2
    exit 1
  fi
  # Two upgrades: quickstart's enabling one, then mainnet's settings.
  if [ "$(docker logs "$name" 2>&1 | grep -c 'soroban config done')" -ge 2 ] \
    && curl -fs -X POST -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' "$base/rpc" | grep -q healthy \
    && curl -fs "$base/friendbot?addr=$probe" >/dev/null; then
    if [ -n "${ARCHIVE:-}" ]; then
      (cd "$root" && node research/email-recovery/eval/fees/settings.mjs "$ARCHIVE=$base/rpc")
    fi
    echo "$base"
    exit 0
  fi
  if docker logs "$name" 2>&1 | grep -q 'Unable to upgrade Soroban Config Settings'; then
    echo "the local network refused the settings upgrade" >&2
    exit 1
  fi
  sleep 3
done
echo "the local network did not start" >&2
exit 1
