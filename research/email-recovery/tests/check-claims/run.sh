#!/usr/bin/env bash
# Self-tests for check-claims.pl. Each cases/<name>/ holds a ledger, a .tex
# source, and `expect`: a line the checker must print (to stdout on success,
# stderr on failure). Evidence paths resolve against repo/, a stand-in
# repository, and figure placeholders against repo/eval/run-figures.json. A
# case expecting success must exit 0; any other must exit 1.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
checker="$here/../../check-claims.pl"
failed=0
for dir in "$here"/cases/*/; do
    name="$(basename "$dir")"
    expect="$(cat "$dir/expect")"
    set +e
    out="$(perl "$checker" --ledger "$dir/claims.yaml" --sources "$dir" --repo "$here/repo" --figures "$here/repo/eval/run-figures.json" 2>&1)"
    status=$?
    set -e
    want_status=1
    [ "$name" = ok ] && want_status=0
    if [ "$status" -ne "$want_status" ] || ! grep -qF -- "$expect" <<<"$out"; then
        echo "FAIL $name (exit $status, want $want_status; want output containing: $expect)"
        echo "$out" | sed 's/^/    /'
        failed=1
    fi
done
[ "$failed" -eq 0 ] && echo "check-claims self-tests: all $(ls -d "$here"/cases/*/ | wc -l | tr -d ' ') cases pass"
exit "$failed"
