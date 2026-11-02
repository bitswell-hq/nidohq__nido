#!/bin/sh
# Read-only companion to activate-channels.sh: confirms what's actually
# stored in the channels plugin's KV pool (straight from
# @openzeppelin/relayer-plugin-channels' own management API — its
# `listChannelAccounts`/`stats` actions read the same KV key
# `setChannelAccounts` writes), rather than just trusting that the
# activation POST succeeded.
# The relayer's authenticated port is not exposed through Caddy; tunnel first:
#   fly proxy 8090:8090 -a nido
# Usage: API_KEY=... PLUGIN_ADMIN_SECRET=... ./channel-status.sh <relayer-base-url> [action]
#   [action]  listChannelAccounts (default, just the configured relayer ids)
#             or stats (pool size + locked/available + fee config)
set -eu
BASE="${1:?usage: channel-status.sh <relayer-base-url> [listChannelAccounts|stats]}"
ACTION="${2:-listChannelAccounts}"
: "${API_KEY:?}" ; : "${PLUGIN_ADMIN_SECRET:?}"
case "$PLUGIN_ADMIN_SECRET" in *[\"\\]*) echo 'PLUGIN_ADMIN_SECRET must not contain " or \' >&2; exit 1;; esac
curl -sS --fail-with-body -X POST "$BASE/api/v1/plugins/channels/call" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"params\":{\"management\":{\"action\":\"$ACTION\",\"adminSecret\":\"$PLUGIN_ADMIN_SECRET\"}}}"
echo
