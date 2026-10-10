# Audit scope

What to audit in Nido, at which revisions, who reviews each part, and in what
order. Perch, which supplies Nido's account, verifier, and recovery stack, has
its own audit manifest; this file assigns every Perch input Nido consumes.

## Audit manifest

The audit covers fixed revisions. No branch is part of the audit identity.

### Reviewed source

| Item | Identity | How to record or check it |
| --- | --- | --- |
| Nido source | The commit that contains this file. | At handoff: `git rev-parse HEAD` (full SHA). |
| Perch source | The `vendor/perch` gitlink of that commit. Every commit-pinned Perch link in Nido's documents names it. | `git -C vendor/perch rev-parse HEAD`, which must equal `git ls-tree HEAD vendor/perch`. `scripts/check-perch-drift.sh` fails otherwise. |
| OZ `stellar-accounts` fork | theahaco/stellar-contracts-OZ at rev `33726766a1fd5e7e3d2977d79f64ee29e1ea3ca9`, the same rev in Nido's and Perch's `Cargo.toml`. | `Cargo.lock` (`source = "git+…?rev=3372676…"`). |
| `admin-sep` | crates.io `0.27.0`. | `Cargo.lock` checksum `b45f70e98918c7ecfcda164bc45811cfc282be96f38e57e1198f401d9466eb7a`. |
| Toolchains | `rust-toolchain.toml` at the Nido commit (Nido's wasm and tests); Perch's [`scripts/zk-toolchain.sh`](https://github.com/stellar-registry/perch/blob/bb746f9d03c593f0d5a2518c6900e00c938f95ec/scripts/zk-toolchain.sh) (`vendor/perch/scripts/zk-toolchain.sh`) at the Perch commit (`nargo`, `bb`, each download checked against a pinned SHA-256). | Both files at the recorded commits. Pins and known gaps: [SUPPLY_CHAIN.md](./SUPPLY_CHAIN.md). |
| npm packages | `package-lock.json` at the Nido commit. The Perch packages the wallet runs are below. | `npm ci` refuses a tarball whose integrity differs. |
| Audit date | Recorded with the handoff. | |

Perch packages in the wallet:

| Package | Source | Version | Integrity (`package-lock.json`) |
| --- | --- | --- | --- |
| `@stellar-registry/perch` (Perch's `packages/perch-js`) | npm | 0.3.2 | `sha512-34lGg5GJpfzTsWNEski31WFMgCgXSNp6ShyHuFT3CfWAA1FRLF+SWZ3QoJJ38w/TGAfUxf69cf8+J3SeZnzvYg==` |
| `@stellar-registry/perch-interpreter` (Perch's `packages/perch-interpreter-js`) | npm | 0.1.0 | `sha512-ZUW1+/ojzTw0tjlfOxjHtWB7b+I6kWEMz5oQIH6wZrpk2H2vsPfdsc5wnQCU8NNWrLqWJlRKG+yxsbHB/p7Vtw==` |
| `@stellar-registry/perch-zk` | npm workspace link to `vendor/perch/packages/perch-zk` | 0.1.0 | None: its identity is the Perch source commit. |

Perch publishes the two npm packages from release tags (`perch-js-v0.3.2`,
`perch-interpreter-js-v0.1.0`), not from the Perch source commit. Their
sources must equal the Perch source commit's; check with
`git -C vendor/perch diff --stat HEAD perch-js-v0.3.2 -- packages/perch-js/src`
and `git -C vendor/perch diff --stat HEAD perch-interpreter-js-v0.1.0 -- packages/perch-interpreter-js/src`
(empty output). Nothing in Nido's CI checks that the published `dist` is a
build of that source; that comparison is part of the explicit dependency
review below.

### Deployed artifacts (provenance, not review targets)

| Artifact | Record |
| --- | --- |
| Perch's testnet stack | Perch's manifest [`deployments/testnet.json`](https://github.com/stellar-registry/perch/blob/bb746f9d03c593f0d5a2518c6900e00c938f95ec/deployments/testnet.json) (`vendor/perch/deployments/testnet.json`) at the Perch source commit: the build commit (`source.commit`, with `dirty`), the build toolchain (`toolchain`), and every contract's version, `sha256`, and address. |
| Nido's testnet factory | [DEPLOYED.md](../DEPLOYED.md#nidos-factory): wasm hash, build commit, toolchain, verifier pin, admin. |

The deployed Perch wasm was built from `source.commit`, which can be an
ancestor of the Perch source commit (for example, when the later commit only
adds the deployment record). The handoff confirms that the contract sources
are the same in both:
`git -C vendor/perch diff --stat <source.commit> HEAD -- crates circuits vendor Cargo.toml Cargo.lock ':!**/test_snapshots/**'`
(empty output). Nido's tests run the deployed bytes, fetched by the manifest's
hashes (`just perch-infra`), not a local build of the Perch source.

## Responsibility matrix

Four review streams. If one engagement covers Nido and Perch, it runs all
four; otherwise Nido's engagement runs the first and the fourth and Perch's
runs the second and third (Perch's two audit units).

| Stream | What it covers |
| --- | --- |
| **Nido integration and browser review** | Nido's factory and name registry, wallet, SDK, infrastructure, the Perch JavaScript the wallet runs, the scripts that select which Perch artifacts Nido builds and tests against, and whether Nido uses Perch as Perch's specification intends. |
| **Perch core** (Perch unit 1) | The backend-independent stack: controller, statement, ZK primitives, pool, adapter, circuit, compiler and CANON, interpreter, the account's recovery and capability paths, the WebAuthn verifier, and the ZK verifier delta. |
| **Perch OZ materialization** (Perch unit 2) | Perch's rule reconciler and install paths, the document caps, `perch-spending-limit`, and the three OZ fork deltas. |
| **Explicit dependency review** | Third-party code on an authority path that neither project wrote, read in full or checked against its audited release. |

Perch's two units are a boundary for Perch's audit; a later Perch backend
still needs its own integration review in Nido. Perch's map of its paths to
the two units is its audit manifest,
[`docs/audit-scope.md`](https://github.com/stellar-registry/perch/blob/bb746f9d03c593f0d5a2518c6900e00c938f95ec/docs/audit-scope.md)
(`vendor/perch/docs/audit-scope.md`).

| Item | Path or identity | Stream |
| --- | --- | --- |
| Factory | `contracts/factory/`: deterministic deployment of `perch-account` with the passkey admin rule; the embedded account wasm and its hash cache across upgrades; admin, upgrade, and verifier pin; the registry fallback for an unpinned verifier | Nido integration |
| Name registry | `contracts/name-registry/`: name ownership and release | Nido integration |
| `admin-sep` 0.27.0 | `admin`, `set_admin`, and `upgrade` for the factory (whose `upgrade` override also clears the account-hash cache), the name registry, and the multisig and spending-limit policies. About 50 lines. `admin()` reads the stored admin with `unwrap_unchecked`, and `set_admin` requires no authorization while no admin is stored; the factory's constructor stores one. | Explicit dependency review: read in full |
| Passkey SDK | `packages/passkey-sdk/`: `src/perch/` (statement encodings, recovery builders, document helpers, proving), `src/policyDoc/`, WebAuthn parsing, auth-entry signing | Nido integration |
| Wallet | `packages/frontend/`: recovery pages (`src/lib/recovery/`), onboarding and the setup secret (`src/pages/new-account/`, `src/lib/createNido.ts`), signing flows, the storage bridge, `public/_headers` | Nido integration |
| Wallets Kit module | `packages/stellar-wallets-kit-module/`: dApp signing handoff | Nido integration |
| Infrastructure | `infra/relayer/` (fee sponsorship and submission, the channels plugin, key custody), `infra/nido-resolver/` (name resolution), `frontend/worker-proxy-nido/` (subdomain proxy, security headers) | Nido integration |
| Integration harness | `crates/integration-tests/`: that it runs under enforcing authorization with real proofs and that its fixtures cannot drift silently (`src/zk.rs`) | Nido integration |
| `@stellar-registry/perch` 0.3.2 (perch-js) | Statement and document encodings, `applyDocument`, rule selection, signing digests, as the wallet uses them. Perch excludes its JS from both units. | Nido integration; tarball against source: explicit dependency review |
| `@stellar-registry/perch-interpreter` 0.1.0 | Interpreter install parameters and bindings the SDK uses (`src/policyDoc/params.ts`) | Nido integration; tarball against source: explicit dependency review |
| `perch-zk` | [`packages/perch-zk`](https://github.com/stellar-registry/perch/tree/bb746f9d03c593f0d5a2518c6900e00c938f95ec/packages/perch-zk) (`vendor/perch/packages/perch-zk`): in-page proving and the circuit artifact it ships | Nido integration |
| Generated Perch clients | `packages/contract-bindings/perch-*`, generated from the deployed wasm (`just bindings-perch`) | Nido integration (provenance) |
| Artifact selection | `just perch-infra` (runs Perch's [`scripts/fetch-infra-wasm.sh`](https://github.com/stellar-registry/perch/blob/bb746f9d03c593f0d5a2518c6900e00c938f95ec/scripts/fetch-infra-wasm.sh) (`vendor/perch/scripts/fetch-infra-wasm.sh`) `--stack`), `scripts/check-perch-drift.sh`, `scripts/deploy-factory.sh`, `packages/passkey-sdk/src/perch/deployment.ts` (`perch.TESTNET`) and its test. Perch reviews its release machinery with its release, outside both units. | Nido integration |
| Perch contracts | `perch-account`, `perch-smart-account` (recovery and capability paths), `perch-recovery`, `perch-zk-pool`, `perch-zk-adapter`, `perch-doc-compiler`, `perch-interpreter`, `perch-webauthn-verifier`, in Perch's [`crates/`](https://github.com/stellar-registry/perch/tree/bb746f9d03c593f0d5a2518c6900e00c938f95ec/crates) (`vendor/perch/crates/`) | Perch core |
| Circuit | Perch's [`circuits/`](https://github.com/stellar-registry/perch/tree/bb746f9d03c593f0d5a2518c6900e00c938f95ec/circuits) (`vendor/perch/circuits/`), specialist review: soundness, domain separation, nullifier binding | Perch core |
| ZK verifier delta | Perch's `UltraKeccakZKFlavor` delta on NethermindEth's UltraHonk verifier, in Perch's `vendor/ultrahonk-soroban-verifier/`: `src/zk.rs` (new), `src/lib.rs` (+3 lines: the module and its re-exports), and visibility-only changes to `src/transcript.rs`, `src/sumcheck.rs`, `src/utils.rs`, and `src/verifier.rs`, as listed in its [`NOTICE`](https://github.com/stellar-registry/perch/blob/bb746f9d03c593f0d5a2518c6900e00c938f95ec/vendor/ultrahonk-soroban-verifier/NOTICE) (`vendor/perch/vendor/ultrahonk-soroban-verifier/NOTICE`). Not audited. | Perch core |
| Upstream UltraHonk verifier | The rest of Perch's [`vendor/ultrahonk-soroban-verifier/`](https://github.com/stellar-registry/perch/tree/bb746f9d03c593f0d5a2518c6900e00c938f95ec/vendor/ultrahonk-soroban-verifier) (`vendor/perch/vendor/ultrahonk-soroban-verifier/`): NethermindEth's verifier at the upstream commit its `NOTICE` names, audited by OpenZeppelin for the non-ZK flavor only. Confirm the vendored bytes are upstream's (`UPSTREAM.sha256`, `CHECKSUMS.sha256`, Perch's `crates/perch-zk-adapter/tests/vendor.rs`). | Explicit dependency review: provenance only |
| Rule reconciler, install paths, caps, spending limit | `perch-smart-account/src/rules.rs`, the install half of `apply`, the caps in `perch-doc-compiler`, `perch-spending-limit` (all in Perch's `crates/`) | Perch OZ materialization |
| OZ fork #3: CAP-0071 delegated auth | [theahaco/stellar-contracts-OZ#3](https://github.com/theahaco/stellar-contracts-OZ/pull/3), in the rev above | Perch OZ materialization |
| OZ fork #4: `_no_events` mutations | [theahaco/stellar-contracts-OZ#4](https://github.com/theahaco/stellar-contracts-OZ/pull/4), in the rev above | Perch OZ materialization |
| OZ fork #5: `reconcile_signers` | [theahaco/stellar-contracts-OZ#5](https://github.com/theahaco/stellar-contracts-OZ/pull/5), in the rev above | Perch OZ materialization |

Named exclusions:

| Excluded | Why |
| --- | --- |
| `contracts/status-message/` | Demo contract for the example dApp; excluded from mainnet (MAINNET_READINESS E3). |
| `contracts/*-policy` (multisig, spending limit, pre-auth sweep) | Pre-Perch OZ policies a Perch document cannot attach; in scope only if a product decision keeps them (MAINNET_READINESS D6). |
| `soroban-sdk`, `soroban-sdk-tools`, the Stellar Registry contract | Pinned third-party dependencies or external contracts ([SUPPLY_CHAIN.md](./SUPPLY_CHAIN.md)). |
| Noir, Barretenberg, `@aztec/bb.js`, `@noir-lang/noir_js` | Pinned third-party proving toolchain; a proof from any other version fails verification. |
| Perch's `packages/perch-relay` and `packages/perch-contracts` | Not used by Nido. |
| `perch-zk-prover` | The native prover Nido's tests use to write the proof fixtures (`just gen-zk-fixtures`). A wrong proof fails verification in the deployed adapter, which the tests run from its deployed wasm. |
| The Stellar protocol, consensus, and RPC | Trusted ([THREAT_MODEL.md](./THREAT_MODEL.md#trusted)). |
| Retired Nido contracts | Nido's former smart account, WebAuthn verifier, recovery controllers, recovery verifier, ZK pool and verifier, circuits, and pool indexer. Their source is not in this tree and none may be deployed to mainnet. The deployments that current code still reaches are in DEPLOYED.md's [compatibility appendix](../DEPLOYED.md#compatibility-appendix). |
| The recovery-relay worker | `relay.nido.fyi` and its KV namespace are still deployed; their source is not in this tree and no wallet code calls them. The SDK still exports the relay-era handoff format (`packages/passkey-sdk/src/friendSigning.ts`), which no wallet page imports. Deleting the worker is MAINNET_READINESS D6. |

## Reading order

1. This file: the manifest and who reviews what.
2. [ARCHITECTURE.md](../ARCHITECTURE.md): components, flows, diagrams.
3. [THREAT_MODEL.md](./THREAT_MODEL.md): assets, adversaries, what is
   trusted; [STRIDE_THREAT_MODEL.md](./STRIDE_THREAT_MODEL.md) groups the same
   threats by STRIDE category.
4. Perch's recovery specification,
   [`docs/recovery/spec.md`](https://github.com/stellar-registry/perch/blob/bb746f9d03c593f0d5a2518c6900e00c938f95ec/docs/recovery/spec.md)
   (`vendor/perch/docs/recovery/spec.md`): the single source of truth for
   recovery semantics.
5. [SECURITY_INVARIANTS.md](./SECURITY_INVARIANTS.md): each property and the
   test that pins it.
6. [DEFERRED.md](./DEFERRED.md): what is deferred until after the audit,
   and what Nido does instead.
7. [SUPPLY_CHAIN.md](./SUPPLY_CHAIN.md): third-party inputs and pins.
8. [DEPLOYED.md](../DEPLOYED.md): what is deployed, and from which revisions.
9. [RUNBOOKS.md](./RUNBOOKS.md) and [MAINNET_READINESS.md](./MAINNET_READINESS.md):
   how it is built, deployed, and operated, and what is still open.
10. Perch's audit manifest,
    [`docs/audit-scope.md`](https://github.com/stellar-registry/perch/blob/bb746f9d03c593f0d5a2518c6900e00c938f95ec/docs/audit-scope.md)
    (`vendor/perch/docs/audit-scope.md`), for the Perch streams.

Not in the reading order, because they are historical records rather than
descriptions of current behaviour: `docs/superpowers/` (design notes),
`docs/APPLICATION.md` (the funding application) and `docs/REQUIREMENTS.md`
(the request it answered).

## Integration with Perch

The Nido integration stream checks that Nido uses Perch as Perch's
specification intends:

- The factory's constructor rule and the wallet's first document (admin rule
  scoped to the account, recovery member, guardian rule scoped to the
  controller) match what the specification assumes.
- The wallet builds evidence and documents only from chain reads and
  controller-built statements (`packages/passkey-sdk/src/perch/`), never from
  link contents a guardian can't check.
- The integration tests are sound evidence: they run under enforcing
  authorization with real proofs, and the fixtures can't drift silently.
- The wallet's deployment (`perch.TESTNET`) is the Perch manifest plus Nido's
  factory, and the artifact-selection scripts accept only the manifest's
  bytes.

## Questions we want answered

1. **Factory admin.** The factory admin can change the account code and the
   verifier new accounts get (THREAT_MODEL 8). Is a multisig plus a visible
   upgrade delay enough, or should the factory pin its verifier at build time
   as Perch's does?
2. **The ZK verifier delta.** Proofs are zero-knowledge, verified by Perch's
   unaudited `UltraKeccakZKFlavor` delta on the audited verifier
   (THREAT_MODEL 13). Is it sound?
3. **Guardian checks.** Is what the guardian page verifies (W2, W3) enough for
   a guardian who follows its instructions?
4. **Setup secret.** Is the window between creating a salt and deploying
   acceptable (THREAT_MODEL 5)?
5. **Deployment.** `perch.TESTNET` is checked against Perch's manifest in a
   test, and the manifest against the chain by Perch's `verify-deployment.sh`.
   Is that enough, and should a `PUBLIC_PERCH_DEPLOYMENT` override be checked
   the same way at build time (THREAT_MODEL 9)?
6. **Archival.** Is the stepwise restoration procedure (RUNBOOKS §6) safe and
   complete for both automatic-restoration and explicit-restore simulation
   responses? The wallet does not run it.
