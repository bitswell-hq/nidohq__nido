#!/usr/bin/env bash
# Print where the Perch stack Nido tests against comes from, `fetch` or
# `build`, by the remote .gitmodules declares for vendor/perch: Perch's
# upstream (stellar-registry/perch) publishes deployment manifests whose
# stack is fetched; any other remote (the bitswell fork's M6 stack, which no
# network runs) is built from the submodule's source. scripts/perch-infra.sh
# and scripts/check-perch-drift.sh both read it, so the two agree.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
url="$(git -C "$repo_root" config -f .gitmodules submodule.vendor/perch.url || true)"
case "${url%.git}" in
    https://github.com/stellar-registry/perch) echo fetch ;;
    "") echo "error: .gitmodules declares no url for vendor/perch" >&2; exit 1 ;;
    *) echo build ;;
esac
