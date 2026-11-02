#!/usr/bin/env bash
# Email votes against a registry root on a local network (registry-root.mjs):
# builds what the network runs (network/build.sh), starts its own local
# network (network/start-local.sh, container nido-email-registry-root), and
# runs the setup, the wait for the attested 72-hour timelock (51,840 ledgers,
# about 14.4 hours at the local network's one ledger a second) and the votes,
# then regenerates the tables of research/email-recovery/eval/README.md. The
# container is left running when the run fails, so `--resume` can finish it
# from target/email-registry-root/state.json.
#
#   research/email-recovery/eval/network/run-registry-root.sh [--resume]
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$root"
NAME="${NIDO_EVAL_REGISTRY_ROOT_NAME:-nido-email-registry-root}"
PORT="${NIDO_EVAL_REGISTRY_ROOT_PORT:-8001}"
# shellcheck source-path=SCRIPTDIR source=quickstart.env
. research/email-recovery/eval/network/quickstart.env
export NIDO_EVAL_QUICKSTART_IMAGE="${NIDO_EVAL_QUICKSTART_IMAGE:-$QUICKSTART_IMAGE}"

if [ "${1:-}" = --resume ]; then
  export NIDO_EVAL_QUICKSTART_URL="http://127.0.0.1:$PORT"
else
  echo "== build" >&2
  research/email-recovery/eval/network/build.sh
  echo "== the local network" >&2
  rm -f target/email-registry-root/state.json
  NIDO_EVAL_QUICKSTART_URL=$(research/email-recovery/eval/network/start-local.sh "$NAME" "$PORT")
  export NIDO_EVAL_QUICKSTART_URL
fi
echo "== setup, wait, votes" >&2
NODE_EXTRA_CA_CERTS=target/email-attacks/tls/cert.pem node research/email-recovery/eval/network/registry-root.mjs
docker rm -f "$NAME" >/dev/null 2>&1 || true
echo "== report" >&2
node research/email-recovery/eval/report.mjs
