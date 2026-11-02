#!/usr/bin/env bash
# The DKIM key registry's entry points on the integration-test host
# (crates/integration-tests/tests/it/dkim_registry.rs, `dkim_registry_costs`):
# writes results/registry-costs-test-host.jsonl, one reading per call, with
# the resources `cost_estimate()` reports. The test host is deterministic, so
# a re-run writes the same file. Needs `just perch-infra` and
# `just build-contracts`.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$root"
NIDO_REGISTRY_COST_ROWS="$root/research/email-recovery/eval/results/registry-costs-test-host.jsonl" \
  cargo test -q -p nido-integration-tests --test it dkim_registry::dkim_registry_costs -- --exact
