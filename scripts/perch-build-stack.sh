#!/usr/bin/env bash
# Build the Perch stack Nido tests against from the submodule's source: the
# `build` source of scripts/perch-infra.sh, which runs it.
#
# Each contract Nido consumes is built with `stellar contract build` from
# the checked-out commit, under one pinned Rust toolchain (so the bytes do not
# drift with Perch's `stable`), into target/perch-build/ (so the submodule
# stays clean), and copied into the stack directory. The toolchain is 1.97.1,
# Perch's: the account is within a few hundred bytes of the network's
# 131,072-byte contract code entry, and 1.97.1 builds the 130,398-byte account
# Perch's docs/recovery/budgets.md records (1.96.0 builds 130,740). Nothing is
# restaged: the account compiles in the build-time pins Perch commits, so it
# derives its infra at the same content addresses as the Perch crates'
# `infra` module, which the integration tests register the built infra at.
#
# Then the factory's pin is the built account's sha256, and
# target/perch-build/stack.json records the commit, the toolchain and each
# contract's sha256 and size, which scripts/check-perch-drift.sh checks the
# stack and the pin against.
#
# Usage: scripts/perch-build-stack.sh <perch-dir> <stack-dir> <pin-file>
set -euo pipefail

[ $# -eq 3 ] || { echo "usage: $0 <perch-dir> <stack-dir> <pin-file>" >&2; exit 1; }
perch="$1" stack="$2" pin="$3"
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
build="$repo_root/target/perch-build"
for tool in stellar jq git rustup; do
    command -v "$tool" >/dev/null || { echo "error: $tool not found" >&2; exit 1; }
done
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

# The contracts Nido's tests and factory consume (crates/integration-tests/src/lib.rs).
CONTRACTS=(perch-doc-compiler perch-interpreter perch-spending-limit perch-webauthn-verifier
           perch-zk-pool perch-zk-adapter perch-recovery perch-account)

toolchain=1.97.1
# A no-op when the toolchain and its wasm target are already installed.
rustup toolchain install "$toolchain" --profile minimal --target wasm32v1-none >&2
commit="$(git -C "$perch" rev-parse HEAD)"
dirty=false
[ -z "$(git -C "$perch" status --porcelain --untracked-files=no)" ] || dirty=true

mkdir -p "$build/wasm" "$stack"
contracts='{}'
for name in "${CONTRACTS[@]}"; do
    echo "== perch-build-stack: $name @ ${commit:0:7}" >&2
    (cd "$perch" && RUSTUP_TOOLCHAIN="$toolchain" CARGO_TARGET_DIR="$build/cargo" \
        stellar contract build --package "$name" --out-dir "$build/wasm" >&2)
    file="${name//-/_}.wasm"
    [ -s "$build/wasm/$file" ] || { echo "error: $build/wasm/$file not produced" >&2; exit 1; }
    cp "$build/wasm/$file" "$stack/$file"
    contracts="$(jq -c --arg n "$name" --arg f "$file" --arg h "$(sha256 "$stack/$file")" \
        --argjson b "$(wc -c <"$stack/$file" | tr -d ' ')" \
        '. + {($n): {wasm: $f, sha256: $h, bytes: $b}}' <<<"$contracts")"
done

account="$(jq -r '.["perch-account"].sha256' <<<"$contracts")"
printf '%s\n' "$account" >"$pin"
jq -n --arg commit "$commit" --argjson dirty "$dirty" \
    --arg rustc "$(RUSTUP_TOOLCHAIN="$toolchain" rustc --version)" \
    --arg stellar "$(stellar --version | head -1)" --argjson contracts "$contracts" \
    '{source: {commit: $commit, dirty: $dirty}, toolchain: {rustc: $rustc, stellar: $stellar},
      contracts: $contracts}' >"$build/stack.json"
jq -r '.contracts | to_entries[] | "\(.value.sha256)  \(.value.bytes)  \(.key)"' "$build/stack.json" >&2
echo "wrote $build/stack.json and the factory pin $account" >&2
