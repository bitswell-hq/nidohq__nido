#!/usr/bin/env bash
# The keeper's costs on a local network with mainnet's settings
# (keeper-costs.mjs): builds what the network runs (network/build.sh),
# starts its own local network (network/start-local.sh), deploys the stack,
# runs the keeper once, writes results/keeper-local.json, and regenerates
# the tables of research/email-recovery/eval/README.md.
#
#   research/email-recovery/eval/network/run-keeper.sh
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$root"
NAME="${NIDO_EVAL_KEEPER_NAME:-nido-email-keeper}"
PORT="${NIDO_EVAL_KEEPER_PORT:-8002}"
# shellcheck source-path=SCRIPTDIR source=quickstart.env
. research/email-recovery/eval/network/quickstart.env
export NIDO_EVAL_QUICKSTART_IMAGE="${NIDO_EVAL_QUICKSTART_IMAGE:-$QUICKSTART_IMAGE}"
research/email-recovery/eval/network/build.sh
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
NIDO_EVAL_QUICKSTART_URL=$(research/email-recovery/eval/network/start-local.sh "$NAME" "$PORT")
export NIDO_EVAL_QUICKSTART_URL
NODE_EXTRA_CA_CERTS=target/email-attacks/tls/cert.pem node research/email-recovery/eval/network/keeper-costs.mjs
node research/email-recovery/eval/report.mjs
