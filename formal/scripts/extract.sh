#!/usr/bin/env bash
# Regenerate formal/AttenuatingGrants/Extracted/ from crates/grant-eval:
# Charon translates the crate to LLBC, Aeneas translates the LLBC to Lean.
#
# Both tools come from Aeneas's Nix flake at AENEAS_REV. Its flake.lock pins
# Charon (7b462d9159db2ed3015162352183906a30bfafc6, the commit Aeneas's
# charon-pin names) and Charon's Rust nightly, so one rev fixes the whole
# toolchain. formal/lakefile.toml requires Aeneas's Lean library at the same
# rev: the generated code and the library it is written against always come
# from the same Aeneas.
#
# Needs Nix with flakes. Without Nix, run it in the nixos/nix image from the
# repository root:
#
#   docker run --rm -v "$PWD":/src -w /src nixos/nix:2.28.3 formal/scripts/extract.sh
#
# `--check` regenerates into a temporary directory and fails if the result
# differs from the committed files.
set -euo pipefail

AENEAS_REV=ab34bd28458a08c150b7cbf1873e59af74588138

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="$root/formal/AttenuatingGrants/Extracted"

check=
case "${1:-}" in
  "") ;;
  --check) check=1 ;;
  *) echo "usage: $0 [--check]" >&2; exit 2 ;;
esac

# Re-run under `nix shell` with the pinned charon and aeneas on PATH.
if [[ -z "${GRANT_EVAL_EXTRACT_PINNED:-}" ]]; then
  export NIX_CONFIG="experimental-features = nix-command flakes
extra-substituters = https://hacl.cachix.org
extra-trusted-public-keys = hacl.cachix.org-1:FzsZ2xsByOwKwIWNPII7yMOelJNDZ12mDAj3d1eGX0c="
  GRANT_EVAL_EXTRACT_PINNED=1 exec nix shell \
    "github:AeneasVerif/aeneas/$AENEAS_REV#aeneas" \
    --command bash "$0" "$@"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

(
  cd "$root/crates/grant-eval"
  CARGO_TARGET_DIR="$tmp/target" charon cargo \
    --preset=aeneas --error-on-warnings \
    --dest-file "$tmp/grant_eval.llbc"
)

aeneas -backend lean -warnings-as-errors -abort-on-error \
  -dest "$tmp/lean" "$tmp/grant_eval.llbc"

if [[ -n "$check" ]]; then
  # `git diff --no-index` compares plain files; run it outside any repository.
  cd "$tmp"
  stale=
  while IFS= read -r -d '' f; do
    rel="${f#"$tmp/lean/"}"
    git diff --no-index --exit-code -- "$out/$rel" "$f" || stale=1
  done < <(find "$tmp/lean" -type f -print0)
  while IFS= read -r -d '' f; do
    rel="${f#"$out/"}"
    if [[ ! -e "$tmp/lean/$rel" ]]; then
      echo "not produced by the extraction: $rel" >&2
      stale=1
    fi
  done < <(find "$out" -type f -name '*.lean' -print0)
  if [[ -n "$stale" ]]; then
    echo "formal/AttenuatingGrants/Extracted is stale: run formal/scripts/extract.sh" >&2
    exit 1
  fi
  echo "formal/AttenuatingGrants/Extracted matches a fresh extraction"
else
  find "$out" -name '*.lean' -delete 2>/dev/null || true
  mkdir -p "$out"
  cp -R "$tmp/lean/." "$out/"
  echo "wrote $out"
fi
