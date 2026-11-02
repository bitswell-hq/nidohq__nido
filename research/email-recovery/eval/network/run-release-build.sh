#!/usr/bin/env bash
# The email votes of the attack suite with the email contracts built the way
# the end-to-end test builds them (`stellar contract build --package <p>`,
# the release profile without spec shaking, then `stellar contract
# optimize`), beside the wasm `just build-contracts` writes that the suite
# otherwise deploys: results/release-build-votes-local.json, which the
# metering table of research/email-recovery/eval/README.md compares.
#
#   research/email-recovery/eval/network/run-release-build.sh
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$root"
NAME="${NIDO_EVAL_QUICKSTART_NAME:-nido-email-release-$$-$(date +%s)}"
PORT="${NIDO_EVAL_QUICKSTART_PORT:-$(node -e 'const s=require("net").createServer().listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})')}"
# shellcheck source-path=SCRIPTDIR source=quickstart.env
. research/email-recovery/eval/network/quickstart.env
export NIDO_EVAL_QUICKSTART_IMAGE="${NIDO_EVAL_QUICKSTART_IMAGE:-$QUICKSTART_IMAGE}"
release=target/email-release
mkdir -p "$release/wasm"
research/email-recovery/eval/network/build.sh
for p in nido-email-verifier nido-email-guardian nido-dkim-registry; do
  CARGO_TARGET_DIR="$release/cargo" stellar contract build --package "$p" --out-dir "$release/wasm"
done
for w in "$release"/wasm/nido_*.wasm; do stellar contract optimize --wasm "$w" --wasm-out "$w" >/dev/null; done
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
NIDO_EVAL_QUICKSTART_URL=$(research/email-recovery/eval/network/start-local.sh "$NAME" "$PORT")
export NIDO_EVAL_QUICKSTART_URL
run="$release/attacks.json"
NIDO_EVAL_EMAIL_WASM="$root/$release/wasm/" NIDO_EVAL_ATTACKS_OUT="$root/$run" NODE_EXTRA_CA_CERTS=target/email-attacks/tls/cert.pem \
  node --test-concurrency=1 --test-reporter=dot --test research/email-recovery/eval/network/attacks.mjs
node --input-type=module - "$run" "$release/wasm" <<'EOF'
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
const [run, dir] = process.argv.slice(2);
const r = JSON.parse(readFileSync(run, 'utf8'));
const file = (f) => { const b = readFileSync(`${dir}/${f}`); return { sha256: createHash('sha256').update(b).digest('hex'), bytes: b.length }; };
const votes = r.transactions
  .filter((t) => t.status === 'SUCCESS' && /^submit_guardian \(email/.test(t.label) && t.metered)
  .map(({ label, hash, ledger, metered, declared, feeCharged, feeSplit, envelopeBytes }) => ({ label, hash, ledger, metered: { cpu_insn: metered.cpu_insn, mem_byte: metered.mem_byte }, declared, feeCharged, feeSplit, envelopeBytes }));
const out = {
  about: "The attack suite's email votes on the local network (protocol 29, mainnet's settings) with the email contracts built as the end-to-end test builds them (stellar contract build --package <p>, the release profile without spec shaking, then stellar contract optimize); written by network/run-release-build.sh.",
  generated: r.generated,
  network: r.network,
  rows: { total: r.rows.length, asExpected: r.rows.filter((x) => x.observed === x.expected).length },
  wasm: { 'nido-email-verifier': file('nido_email_verifier.wasm'), 'nido-email-guardian': file('nido_email_guardian.wasm'), 'nido-dkim-registry': file('nido_dkim_registry.wasm') },
  votes,
};
writeFileSync('research/email-recovery/eval/results/release-build-votes-local.json', JSON.stringify(out, null, 1) + '\n');
console.error(`release-build-votes-local.json: ${votes.length} votes`);
EOF
