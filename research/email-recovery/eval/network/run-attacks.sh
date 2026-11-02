#!/usr/bin/env bash
# The email factor's attack suite (research/email-recovery/eval/README.md):
#
#   1. builds what the local network runs (network/build.sh, which first
#      checks that node_modules matches package-lock.json);
#   2. starts the local network (network/start-local.sh: quickstart pinned
#      by digest, protocol 29, mainnet's settings), archives its settings as
#      results/settings/local.json, and runs attacks.mjs against it, which
#      deploys the stack, runs every scenario, and writes
#      results/attacks-local.json;
#   3. runs the three registry scenarios that need an elapsed timelock on the
#      integration-test host (email_guardian.rs, `registry_*`), which append
#      their rows to results/attacks-test-host.jsonl;
#   4. regenerates the tables of research/email-recovery/eval/README.md.
#
# Needs Docker, the Stellar CLI, `npm ci`, `just perch-infra` and `just
# build-contracts` done once. Each run gets its own
# container name and a free port (NIDO_EVAL_QUICKSTART_PORT overrides the
# port), so concurrent runs on one machine do not stop each other's network.
#
#   research/email-recovery/eval/network/run-attacks.sh [--keep] [--local-only]
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$root"
keep=0 local_only=0
for a in "$@"; do
  case "$a" in
    --keep) keep=1 ;;
    --local-only) local_only=1 ;;
    *) echo "unknown argument $a" >&2; exit 2 ;;
  esac
done
NAME="${NIDO_EVAL_QUICKSTART_NAME:-nido-email-attacks-$$-$(date +%s)}"
PORT="${NIDO_EVAL_QUICKSTART_PORT:-$(node -e 'const s=require("net").createServer().listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})')}"
out=target/email-attacks
results=research/email-recovery/eval/results
mkdir -p "$out/wasm" "$results"

echo "== build" >&2
research/email-recovery/eval/network/build.sh

echo "== the local network" >&2
if [ -z "${NIDO_EVAL_QUICKSTART_URL:-}" ]; then
  cleanup() { [ "$keep" = 1 ] || docker rm -f "$NAME" >/dev/null 2>&1 || true; }
  trap cleanup EXIT
  NIDO_EVAL_QUICKSTART_URL=$(ARCHIVE=local research/email-recovery/eval/network/start-local.sh "$NAME" "$PORT")
  export NIDO_EVAL_QUICKSTART_URL
fi
# shellcheck source-path=SCRIPTDIR source=quickstart.env
. research/email-recovery/eval/network/quickstart.env
export NIDO_EVAL_QUICKSTART_IMAGE="${NIDO_EVAL_QUICKSTART_IMAGE:-$QUICKSTART_IMAGE}"

echo "== the attack suite on the local network" >&2
rm -f "$out/stack.json"
NODE_EXTRA_CA_CERTS="$out/tls/cert.pem" node --test-concurrency=1 --test-reporter=spec --test research/email-recovery/eval/network/attacks.mjs

if [ "$local_only" = 0 ]; then
  echo "== the registry scenarios on the test host" >&2
  rows="$root/$results/attacks-test-host.jsonl"
  rm -f "$rows"
  NIDO_EMAIL_ATTACK_ROWS="$rows" cargo test -q -p nido-integration-tests --test it email_guardian::registry_ -- --test-threads=1
fi

echo "== report" >&2
node research/email-recovery/eval/report.mjs
