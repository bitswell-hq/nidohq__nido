# List available recipes
default:
    @just --list

# The email recovery end-to-end test on a local Stellar network: Docker runs
# stellar/quickstart, the script deploys Perch's stack and the email
# contracts, starts the alert service and the third-party mocks, builds the
# wallet for that network, and Playwright drives enrollment and recovery in
# Chromium with the real in-browser proof. Needs `just perch-infra` once.
test-e2e-email-local:
    scripts/email-recovery-e2e.sh

# Run all workspace tests. Needs the contract wasm (`just build-contracts`),
# which the integration tests embed.
test:
    cargo test --workspace
    cargo test --manifest-path crates/agent-host/Cargo.toml

# The grant relay's opt-in suites: Nido's TypeScript relay client against the
# relay (needs Node 22.6+), and the relay end to end on a local Stellar network
# with the Dfns mock (needs Docker). See crates/grant-relay/README.md.
test-relay-local:
    cargo test -p grant-relay --test frontend_client --test local_network -- --ignored --nocapture

# Run the evaluation: the Soroban simulation (costs, attacks, workloads), the
# Lean step counts and bounds of the measured checks, and the agent host
# (workload, attacks, per-check cost, throughput). Rewrites
# evaluation/results/ and the result tables of evaluation/README.md. Needs
# `just perch-infra`, `just build-contracts` and the formal package's Lean
# dependencies (`cd formal && lake exe cache get`). See evaluation/README.md.
eval:
    evaluation/scripts/eval.sh

# The evaluation's local-network stage: the attack suite and the workloads
# through the relay to a local Stellar network, relay throughput against the
# channel pool's size, and concurrent sibling spends against a shared
# allowance. Rewrites evaluation/results/network-*.json and the result
# tables. Needs Docker, the Stellar CLI, `just perch-infra` and
# `just build-contracts`. See evaluation/README.md.
eval-network:
    evaluation/scripts/eval-network.sh

# Build all crates (native)
build:
    cargo build --workspace

# Fetch the Perch stack Nido builds and tests against: Perch's testnet
# deployment, by the hashes in vendor/perch/deployments/testnet.json
# (STELLAR_NETWORK picks another manifest). Writes the factory's account pin,
# contracts/factory/wasm/perch-account.sha256, from that manifest first. Puts
# every deployed contract's wasm in target/wasm32v1-none/contract/
# (perch_*.wasm), so the tests run the deployed bytes, including the account
# whose hash the factory pins. (The Perch crates build from the pins Perch commits; cargo
# fetches them at the submodule's commit, see the root Cargo.toml.) Perch's script refuses any
# file whose sha256 or content address differs from the manifest. Needs the
# Stellar CLI, curl and jq. Run once after cloning and after bumping
# vendor/perch. Reads the chain through the manifest's rpc_url, an
# RPC_URL/STELLAR_RPC_URL override, or a guarded fallback while the manifest's
# endpoint is down (scripts/perch-infra.sh; docs/RUNBOOKS.md "RPC endpoints").
perch-infra:
    scripts/perch-infra.sh

# Re-pin vendor/perch to a Perch commit (full 40-hex) and regenerate what the
# pin derives: the stack by manifest hash, Nido's contracts, the Perch
# bindings, the SDK's Perch pins, and the lockfiles; then the drift check
# and the Rust suites. Nido's factory is not redeployed: a re-pin that moves
# the account or verifier needs `just deploy-factory` on its branch before it
# merges. The perch-repin workflow runs this when Perch announces a
# deployment. See scripts/repin-perch.sh.
repin-perch commit:
    scripts/repin-perch.sh {{commit}}

# Check the vendored Perch stack hasn't drifted from what Nido builds against:
# the submodule at its recorded commit (on its declared branch), the fetched
# wasm, pin cache, and factory pin equal to the manifest's, and npm resolving
# Perch's packages to the submodule. See scripts/check-perch-drift.sh. Run after
# `just perch-infra` and `just build-contracts`.
check-vendor-drift:
    bash scripts/check-perch-drift.sh

# Regenerate the real UltraHonk proofs the recovery integration tests replay
# (crates/integration-tests/fixtures/zk/). Installs Perch's pinned nargo/bb
# under vendor/perch/target/zk-toolchain/, compiles Perch's circuit, and runs
# the integration suites in prove mode: each ZK test builds its statement through
# the real controller, proves it natively, verifies it through the deployed
# adapter, and writes the fixture. The proofs are zero-knowledge, so proving is
# randomized and the proof bytes change on every run; the fixture metadata
# (statement digest, root, nullifier) must not:
# `git diff --exit-code -- 'crates/integration-tests/fixtures/zk/*/fixture.json'`.
gen-zk-fixtures:
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(bash vendor/perch/scripts/zk-toolchain.sh)"
    (cd vendor/perch/circuits && "$NARGO" compile --workspace)
    NIDO_ZK_PROVE=1 cargo test -p nido-integration-tests --test it -- --test-threads=1

# Installs Perch's pinned nargo/bb
# under target/zk-toolchain/, compiles circuits/email-recovery/recovery,
# writes circuits/email-recovery/artifacts/recovery.json and the verifier's
# key (contracts/email-verifier/vk/email_recovery.vk), rebuilds the
# contracts with it, writes the provider keys the registry admits
# (fixtures/email/keys.json, from @nidohq/email-mocks), and runs the email
# suites in prove mode: each approval's statement comes from the real
# controller, @nidohq/email-mocks signs the recovery email, the
# @nidohq/email-recovery encoder writes the circuit's inputs, bb proves them,
# and the test then verifies the proof through the deployed verifier. The
# Gmail fixture's inputs become the Prover.toml of the recovery package and
# of its 1024-byte comparison build (bench/recovery_1024), which
# scripts/measure.sh proves, and bb.js (the browser's prover) proves the
# Gmail fixture again from its message.eml (proof.bbjs). Proofs
# are randomized; the emails and each fixture.json must not change:
# `git diff -- crates/integration-tests/fixtures/email` shows only proof
# bytes.
# Regenerate the email circuit's artifact and key, and the email proof fixtures
gen-email-proofs:
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(circuits/email-recovery/scripts/toolchain.sh)"
    circuits/email-recovery/scripts/check-toolchain.sh
    (cd circuits/email-recovery && "$NARGO" compile --package recovery)
    node circuits/email-recovery/scripts/recovery-artifact.mjs
    mkdir -p target/email-vk
    "$BB" write_vk --scheme ultra_honk --oracle_hash keccak -b circuits/email-recovery/target/recovery.json -o target/email-vk
    cp target/email-vk/vk contracts/email-verifier/vk/email_recovery.vk
    just build-contracts
    npm run build -w @nidohq/email-mocks -w @nidohq/email-recovery
    node packages/email-recovery/scripts/email-fixture.mjs keys > crates/integration-tests/fixtures/email/keys.json
    NIDO_EMAIL_PROVE=1 cargo test -p nido-integration-tests --test it email -- --test-threads=1
    gmail=crates/integration-tests/fixtures/email/provider-gmail-com
    node packages/email-recovery/scripts/email-fixture.mjs toml "$gmail" > circuits/email-recovery/recovery/Prover.toml
    node packages/email-recovery/scripts/email-fixture.mjs toml "$gmail" 1024 > circuits/email-recovery/bench/recovery_1024/Prover.toml
    node packages/email-recovery/scripts/measure-bbjs.mjs "$gmail" 1 --proof-out target/email-bbjs
    cp target/email-bbjs/proof crates/integration-tests/fixtures/email/provider-gmail-com/proof.bbjs

# Check the DKIM key registry's hashing against Noir: regenerate the Noir
# inputs from the fixture key records (crates/dns-attestation-mock/testdata/),
# then run contracts/dkim-registry/vectors/ with Perch's pinned nargo, which
# recomputes every key hash, leaf, and root with noir-lang/poseidon v0.2.0
# and asserts the values the contract's `noir_vectors` test asserts. Fails if
# the regenerated inputs differ from the committed ones.
dkim-registry-vectors:
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(bash vendor/perch/scripts/zk-toolchain.sh)"
    dir=contracts/dkim-registry/vectors
    cargo run -q -p nido-dns-attestation-mock -- noir-inputs > "$dir/src/inputs.nr"
    "$NARGO" fmt --program-dir "$dir"
    git diff --exit-code -- "$dir/src/inputs.nr"
    "$NARGO" test --program-dir "$dir"

# Build and optimize Nido's Soroban contracts. The factory compiles in the
# perch-account hash in contracts/factory/wasm/perch-account.sha256
# (`registry_contract!`; `just perch-infra` writes it), and fails without it.
#
# SOROBAN_SDK_BUILD_SYSTEM_SUPPORTS_SPEC_SHAKING_V2: scaffold invokes raw
# `cargo rustc` rather than `stellar contract build`, so it does not set the
# signal soroban-sdk's build script expects; we set it here (we build with a
# new enough stellar-cli) so the build does not abort on spec-shaking.
#
# Scaffold does NOT run wasm-opt, so we optimize Nido's wasm in place
# afterwards; deployed wasm must stay optimized.
build-contracts:
    SOROBAN_SDK_BUILD_SYSTEM_SUPPORTS_SPEC_SHAKING_V2=1 stellar-scaffold build --profile contract
    @for wasm in target/wasm32v1-none/contract/nido_*.wasm; do \
        case "$wasm" in *.optimized.wasm) continue;; esac; \
        echo "→ optimize $wasm"; \
        stellar contract optimize --wasm "$wasm" --wasm-out "$wasm"; \
    done

# Runs latexmk inside a TeX Live image pinned by digest, so it needs Docker.
# Fails on undefined references or citations and on any claim-ledger
# inconsistency. See research/email-recovery/README.md.
# Build the email-recovery paper and slides into research/email-recovery/build/
email-recovery-docs:
    bash research/email-recovery/build.sh

# Runs latexmk inside a TeX Live image pinned by digest, so it needs Docker.
# Fails on undefined references or citations and on any claim-ledger
# inconsistency. See paper/README.md.
# Build the attenuating-grants paper and slides into paper/build/
paper:
    make -C paper

# Needs elan, which fetches the Lean release lean-toolchain pins.
# See research/email-recovery/formal/README.md.
# Build and check the email-recovery Lean model and proofs
email-recovery-formal:
    cd research/email-recovery/formal && lake build

# Test the email-recovery circuit components with Perch's pinned nargo and bb
# (installed into target/zk-toolchain). See circuits/email-recovery/README.md.
test-email-circuits:
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(circuits/email-recovery/scripts/toolchain.sh)"
    circuits/email-recovery/scripts/check-toolchain.sh
    circuits/email-recovery/scripts/check-vendor.sh
    cd circuits/email-recovery && "$NARGO" test --workspace

build-ts:
    npx tsc -p ./packages/passkey-sdk/tsconfig.json

# Check formatting and clippy
check:
    cargo fmt --all -- --check
    cargo clippy --all --tests -- -Dclippy::pedantic
    cargo fmt --manifest-path crates/agent-host/Cargo.toml --all -- --check
    cargo clippy --manifest-path crates/agent-host/Cargo.toml --all --tests -- -Dclippy::pedantic
    cargo fmt --manifest-path evaluation/agent-host/Cargo.toml --all -- --check
    cargo clippy --manifest-path evaluation/agent-host/Cargo.toml --target-dir crates/agent-host/target --all --tests -- -Dclippy::pedantic

fmt:
    cargo fmt --all
    cargo fmt --manifest-path crates/agent-host/Cargo.toml --all
    cargo fmt --manifest-path evaluation/agent-host/Cargo.toml --all

# formal/scripts/extract.sh pins Charon and Aeneas and needs Nix with flakes
# (formal/README.md gives a Docker alternative). `--check` compares with the
# committed files instead of writing them.
# Regenerate the Lean translation of crates/grant-eval (formal/AttenuatingGrants/Extracted/)
extract-lean *args:
    formal/scripts/extract.sh {{args}}

# Clean build artifacts
clean:
    cargo clean

check-astro:
    npx astro check --root ./packages/frontend

build-astro:
    npx astro build --root ./packages/frontend

cloudflare-deploy: build-astro
    npx wrangler pages deploy packages/frontend/dist/ --project-name mysoroban --branch main

dev: build-ts
    (cd packages/frontend; npm run dev)

# Deploy Nido's factory around Perch's deployed account and pin Perch's
# WebAuthn verifier, and write its record
# (packages/passkey-sdk/src/perch/factory.<network>.json). Registers no name.
# See scripts/deploy-factory.sh.
deploy-factory identity network="testnet":
    ./scripts/deploy-factory.sh {{identity}} {{network}}

# Check the factory record against the chain: the deployed factory's wasm,
# the account hash it deploys (also against the manifest), its pinned
# verifier, its admin, and its manager. Read-only.
# See scripts/check-factory.sh.
check-factory network="testnet":
    ./scripts/check-factory.sh {{network}}

# Deploy a Nido-owned stellar-registry instance and register factory/verifier
# into it (plan A3). Fetches the reference registry wasm, redeploys it under our
# owner, records the wasm hash. Rehearse on testnet before mainnet; set
# FACTORY/VERIFIER (+ OWNER/ctor args). See scripts/deploy-registry.sh.
publish-registry alias network="testnet":
    ./scripts/deploy-registry.sh {{alias}} {{network}}

# Regenerate one binding from a fresh .wasm and apply post-gen fixes.
# Usage: just bindings factory
# Run after `just build-contracts`. See scripts/fix-bindings.sh for what
# the post-gen pass does (stellar-sdk pin alignment + Context shim).
bindings name:
    stellar contract bindings typescript \
        --overwrite \
        --output-dir packages/contract-bindings/{{name}} \
        --wasm target/wasm32v1-none/contract/nido_{{replace(name, '-', '_')}}.wasm
    ./scripts/fix-bindings.sh

# Regenerate ALL bindings (assumes wasms in target/) and apply post-gen
# fixes once at the end.
bindings-all:
    @for name in factory multisig-policy spending-limit-policy status-message; do \
        wasm="target/wasm32v1-none/contract/nido_$(echo $name | tr - _).wasm"; \
        echo "→ $name ($wasm)"; \
        stellar contract bindings typescript --overwrite \
            --output-dir packages/contract-bindings/$name \
            --wasm "$wasm"; \
    done
    ./scripts/fix-bindings.sh

# Regenerate the TypeScript clients for Perch's deployables
# (packages/contract-bindings/perch-*) from the deployed wasm `just perch-infra`
# fetched. Local stand-ins until Perch publishes @stellar-registry/perch-contracts.
bindings-perch:
    @for name in perch-account perch-recovery perch-zk-pool perch-zk-adapter perch-doc-compiler; do \
        wasm="target/wasm32v1-none/contract/$(echo $name | tr - _).wasm"; \
        echo "→ $name ($wasm)"; \
        stellar contract bindings typescript --overwrite \
            --output-dir packages/contract-bindings/$name \
            --wasm "$wasm"; \
        git checkout -- packages/contract-bindings/$name/package.json; \
    done
    ./scripts/fix-bindings.sh

# Run TestAuthenticator unit tests (vitest, node)
test-support:
    npx vitest run --config vitest.support.config.ts

# Fast UI e2e tier (shim) across all browsers; builds the frontend first
test-e2e:
    PUBLIC_PERCH_DEPLOYMENT=none npx astro build --root ./packages/frontend
    npx playwright test --grep @fast

# Chromium CDP virtual-authenticator fidelity lane; builds the frontend first
test-e2e-cdp:
    PUBLIC_PERCH_DEPLOYMENT=none npx astro build --root ./packages/frontend
    npx playwright test --project=chromium-cdp

# Sources tests/.env.testnet if present (set NIDO_TEST_BANK_SECRET there to a
# funded testnet G-account secret to skip friendbot for the name submitter);
# otherwise the app funds its own submitter via friendbot.
# Quarantined real-testnet e2e tier (create+deploy + name-claim); builds first
test-e2e-testnet: build-astro
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -f tests/.env.testnet ]; then set -a; source tests/.env.testnet; set +a; fi
    npx playwright test --project=testnet-chromium --project=testnet-webkit
