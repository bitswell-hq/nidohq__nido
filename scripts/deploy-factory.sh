#!/usr/bin/env bash
#
# Deploy Nido's account factory around Perch's deployed account (RUNBOOKS §2.2).
#
#   1. Check the staged account wasm (target/wasm32v1-none/contract/
#      perch_account.wasm, from `just perch-infra`) is the manifest's
#      `perch-account`, and install it on the network: the factory deploys
#      accounts by its hash.
#   2. Build Nido's contracts (`just build-contracts`; the factory embeds that
#      wasm) unless SKIP_BUILD is set.
#   3. Deploy the factory with the paying identity as its admin, Perch's
#      WebAuthn verifier pinned, and the change delay DELAY_LEDGERS, all
#      constructor arguments: account creation never consults the registry,
#      and every later change to the code or the pin waits out the delay.
#   4. Read the pin and the delay back.
#   5. Ask the factory for the account hash it deploys (admin-gated
#      `refresh_account_wasm_hash`) and check it against the manifest.
#   6. Hand the factory to ADMIN (`set_admin`, which needs only the current
#      admin's signature) and read the admin back. Last, so the hash is
#      checked while the paying identity can still sign for it, and a
#      multisig ADMIN never has to sign during the deploy.
#   7. Write the factory record, packages/passkey-sdk/src/perch/
#      factory.<network>.json: the address, its wasm hash, the account hash,
#      verifier, and delay read back in steps 4-5, the admin, and the Nido and
#      Perch commits and toolchain it was built from. deployment.test.ts
#      checks the record's account and verifier against the manifest, and
#      scripts/check-factory.sh checks the record against the chain.
#
# If any step after the factory exists fails, the script stops and names the
# factory and the step: don't register or use that factory. It is never
# handed over unpinned: the pin is a constructor argument.
#
# Prints the factory address. It registers no name in any registry: repointing
# `factory` is a separate, deliberate step (RUNBOOKS §2.2). Set
# `perch.TESTNET.factory` to the printed address and commit it with the record.
#
# Usage:
#   scripts/deploy-factory.sh <identity> [network]
#
#   <identity>  A `stellar keys` identity that pays for the deploy.
#   [network]   Default "testnet". The Perch manifest read is
#               vendor/perch/deployments/<network>.json.
#
# The endpoint is chosen once, before anything is submitted, by
# scripts/stellar-rpc.sh: RPC_URL/STELLAR_RPC_URL if set, else the manifest's
# rpc_url, else a guarded fallback while that is down (docs/RUNBOOKS.md "RPC
# endpoints"). Every read and write in the run goes there. It never fails
# over mid-run: a write whose response was lost may still have landed, so a
# failure stops the run (see above).
#
# Env:
#   ADMIN          The factory's final admin (default: the identity's address,
#                  fine only on testnet). On mainnet this must be the multisig.
#   DELAY_LEDGERS  Ledgers every change to the factory waits between
#                  `schedule_change` and `execute_change` (`change_delay()`).
#                  Fixed for the factory's life. Required except on testnet,
#                  where it defaults to 720 (an hour at five-second ledgers).
#   SKIP_BUILD     Skip `just build-contracts`. The record's toolchain is then
#                  null: this script did not see what built the wasm.
#
# The Stellar CLI keeps identities under $XDG_CONFIG_HOME/stellar (or
# ~/.config/stellar); set XDG_CONFIG_HOME to use another directory.
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }
note() { echo "→ $*" >&2; }

IDENTITY="${1:-}"
NETWORK="${2:-testnet}"
[ -n "$IDENTITY" ] || die "usage: $0 <identity> [network]"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
MANIFEST="vendor/perch/deployments/$NETWORK.json"
ACCOUNT_WASM="target/wasm32v1-none/contract/perch_account.wasm"
FACTORY_WASM="target/wasm32v1-none/contract/nido_factory.wasm"
RECORD="packages/passkey-sdk/src/perch/factory.$NETWORK.json"

command -v stellar >/dev/null || die "stellar CLI not found"
command -v jq >/dev/null || die "jq not found"
command -v curl >/dev/null || die "curl not found"
[ -f "$MANIFEST" ] || die "no Perch manifest at $MANIFEST (git submodule update --init)"

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
m() { jq -r "$1" "$MANIFEST"; }

ACCOUNT_HASH="$(m '.contracts["perch-account"].sha256')"
VERIFIER="$(m '.contracts["perch-webauthn-verifier"].address')"
[[ "$ACCOUNT_HASH" =~ ^[0-9a-f]{64}$ ]] || die "manifest has no perch-account hash"
[[ "$VERIFIER" =~ ^C[A-Z2-7]{55}$ ]] || die "manifest has no perch-webauthn-verifier address"
DEPLOYER="$(stellar keys address "$IDENTITY")"
ADMIN="${ADMIN:-$DEPLOYER}"
[[ "$ADMIN" =~ ^[GC][A-Z2-7]{55}$ ]] || die "ADMIN '$ADMIN' is not an address"
if [ -z "${DELAY_LEDGERS:-}" ]; then
    [ "$NETWORK" = testnet ] || die "set DELAY_LEDGERS, the factory's change delay, for $NETWORK"
    DELAY_LEDGERS=720
fi
[[ "$DELAY_LEDGERS" =~ ^[0-9]+$ ]] || die "DELAY_LEDGERS '$DELAY_LEDGERS' is not a ledger count"
# shellcheck source=scripts/stellar-rpc.sh
. scripts/stellar-rpc.sh
rpc_select "$(m .rpc_url)" "$(m .network_passphrase)" || die "no usable RPC endpoint for $NETWORK"
RPC="$(rpc_url)"
NET=(--source-account "$IDENTITY" --rpc-url "$RPC" --network-passphrase "$(m .network_passphrase)")

note "account wasm"
[ -f "$ACCOUNT_WASM" ] || die "$ACCOUNT_WASM missing: run 'just perch-infra'"
[ "$(sha256 "$ACCOUNT_WASM")" = "$ACCOUNT_HASH" ] || die "$ACCOUNT_WASM is not the manifest's perch-account ($ACCOUNT_HASH)"
installed="$(stellar contract upload --wasm "$ACCOUNT_WASM" "${NET[@]}" 2>/dev/null | grep -oE '[0-9a-f]{64}' | tail -1)"
[ "$installed" = "$ACCOUNT_HASH" ] || die "installed account hash ${installed:-<none>} != $ACCOUNT_HASH"
echo "  installed $ACCOUNT_HASH" >&2

TOOLCHAIN=null
if [ -z "${SKIP_BUILD:-}" ]; then
    note "build"
    just build-contracts >&2
    TOOLCHAIN="$(jq -n --arg rustc "$(rustc --version)" --arg stellar "$(stellar --version | head -1)" \
        --arg scaffold "$(stellar-scaffold --version | head -1)" '{rustc: $rustc, stellar: $stellar, scaffold: $scaffold}')"
fi
[ -f "$FACTORY_WASM" ] || die "$FACTORY_WASM missing"
FACTORY_WASM_HASH="$(sha256 "$FACTORY_WASM")"

note "deploy factory (admin $DEPLOYER until step 6, verifier $VERIFIER, delay $DELAY_LEDGERS ledgers)"
FACTORY="$(stellar contract deploy --wasm "$FACTORY_WASM" "${NET[@]}" -- \
    --admin "$DEPLOYER" --verifier "$VERIFIER" --delay_ledgers "$DELAY_LEDGERS" | tail -1)"
[[ "$FACTORY" =~ ^C[A-Z2-7]{55}$ ]] || die "deploy returned '$FACTORY'"
echo "  factory $FACTORY (wasm $FACTORY_WASM_HASH)" >&2

# From here on the factory exists: any failure names it and the step.
step=""
abandoned() {
    echo "error: factory $FACTORY was created, but the deploy stopped at: $step." >&2
    echo "       The steps after that one didn't run. Don't register or use this" >&2
    echo "       factory; rerun this script for a fresh one." >&2
}
trap abandoned ERR
fail() { echo "error: $*" >&2; false; }

step="check the verifier pin and the change delay"; note "$step"
pinned="$(stellar contract invoke --id "$FACTORY" "${NET[@]}" --send=no -- pinned_verifier | tr -d '"')"
[ "$pinned" = "$VERIFIER" ] || fail "pinned verifier reads back as '$pinned'"
delay="$(stellar contract invoke --id "$FACTORY" "${NET[@]}" --send=no -- change_delay)"
[ "$delay" = "$DELAY_LEDGERS" ] || fail "change delay reads back as '$delay'"

step="check the account hash the factory deploys"; note "$step"
deploys="$(stellar contract invoke --id "$FACTORY" "${NET[@]}" -- refresh_account_wasm_hash | tr -d '"')"
[ "$deploys" = "$ACCOUNT_HASH" ] || fail "factory deploys $deploys, manifest says $ACCOUNT_HASH"

if [ "$ADMIN" != "$DEPLOYER" ]; then
    step="hand the factory to $ADMIN"; note "$step"
    stellar contract invoke --id "$FACTORY" "${NET[@]}" -- set_admin --new_admin "$ADMIN" >/dev/null
fi
admin="$(stellar contract invoke --id "$FACTORY" "${NET[@]}" --send=no -- admin | tr -d '"')"
[ "$admin" = "$ADMIN" ] || fail "admin reads back as '$admin', expected $ADMIN"
trap - ERR

# The factory is complete; a failure here leaves it usable but unrecorded.
note "record $RECORD"
dirty=false
[ -z "$(git status --porcelain --untracked-files=no)" ] || dirty=true
jq -n \
    --arg network "$NETWORK" \
    --arg passphrase "$(m .network_passphrase)" \
    --arg factory "$FACTORY" \
    --arg wasm "$FACTORY_WASM_HASH" \
    --arg account "$deploys" \
    --arg verifier "$pinned" \
    --argjson delay "$delay" \
    --arg admin "$admin" \
    --arg commit "$(git rev-parse HEAD)" \
    --argjson dirty "$dirty" \
    --arg perch "$(git -C vendor/perch rev-parse HEAD)" \
    --argjson toolchain "$TOOLCHAIN" \
    --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{schema: 1, network: $network, network_passphrase: $passphrase, factory: $factory,
      wasm_hash: $wasm, account_wasm_hash: $account, pinned_verifier: $verifier, change_delay: $delay, admin: $admin,
      source: {commit: $commit, dirty: $dirty, perch_commit: $perch},
      toolchain: $toolchain, deployed_at: $at}' > "$RECORD" \
    || die "factory $FACTORY is deployed and checked, but writing $RECORD failed"

echo "$FACTORY"
