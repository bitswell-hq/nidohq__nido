# Email-recovery circuit

The recovery circuit (`recovery/`) proves, in zero knowledge, what a
DKIM-signed recovery email says: that a mail provider's RSA-2048 key, whose
leaf is in a key tree with a given root, signed a header block whose From
address opens the account's commitment and whose Subject opens to the
recovery statement's digest (`docs/email-recovery/spec.md` §6). It is built
from the Noir components in `lib/`, and built and proven with exactly
Perch's pinned toolchain (nargo 1.0.0-beta.9, bb 0.87.0, zero-knowledge
UltraHonk with the keccak transcript), so its proofs verify with Perch's
Soroban verifier (`contracts/email-verifier`).

## Layout

| Path | What it is |
| --- | --- |
| `recovery/` | The recovery circuit: its public inputs, in spec §6.1's order, and a call to `email_recovery::recovery`; `Prover.toml` holds the Gmail fixture's inputs |
| `artifacts/recovery.json` | The compiled circuit without debug paths, what noir_js and bb.js run (`scripts/recovery-artifact.mjs` writes and checks it) |
| `lib/` | The library `email_recovery`; each module's header states its grammar and checks |
| `tests/` | `email_recovery_tests`: 123 tests, including the recovery relation with every public input and linking witness changed (`src/recovery_tests.nr`), one negative test per publicly documented soundness issue class (`src/soundness.nr`), and parity with the DKIM key registry's host hashing (`src/registry_parity.nr`) |
| `bench/` | One binary package per component, and the recovery relation at a 1024-byte header bound (`bench/recovery_1024`), for gate counts and proving measurements |
| `tools/blinded_value/` | Computes the Subject value `T` for the test-vector generator |
| `vendor/` | Vendored noir-bignum and sha256 (`THIRD_PARTY.md`) |
| `scripts/` | Toolchain install and check, vector generation, measurements, vendor check |
| `SECURITY.md` | Issue classes and their tests, toolchain advisories, what is proven, tested and assumed |
| `MEASUREMENTS.md` | Gate counts and native proving figures |

## Components and the spec's obligations

| Module | Checks | Spec |
| --- | --- | --- |
| `rsa` | RSA-2048 PKCS#1 v1.5 / SHA-256, exponent 65537: modulus of exactly 2048 bits, `σ < N`, the full 256-byte encoding | C1 |
| `header` | The signed block: zero past its length, CRLF-only line ends, no folded line, no empty line, no trailing CRLF, exactly one `from:` and one `subject:` line | C2, C3, C5 |
| `from_address` | The From value and its address (§4.5 grammar, up to `ADDR_MAX` = 124 bytes) | C3 |
| `dkim_signature` | The DKIM-Signature field being verified: `v=1`, `a=rsa-sha256`, relaxed header canonicalization, `h=` with `from` and `subject`, empty `b=`, lowercase `d=` equal to the lowercase From domain (at most 62 bytes) | C2, C4 |
| `subject` | Subject = phrase + 64 lowercase hex characters; `assert_subject_opens` checks the value is `hex(P2(DOM_BLIND, digest_hi, digest_lo, rho))` | C5 |
| `pack` | `pack(bytes, max)`, the commitment `C = P2(DOM_COMMIT, len, pack(addr, 124), account_code)`, the key hash `P2(DOM_KEY, 18 limbs)` | C3, C6 |
| `registry` | The registry leaf `P2(DOM_LEAF, len, pack(domain, 62), key_hash)` and the depth-16 Merkle root | C6 |
| `body` | `bh=` against the SHA-256 of a bounded canonicalized body, refusing `l=`; for uses that bind the body (the recovery proof does not, spec §4.4) | |
| `dkim` | `verify_dkim_header`: all of the above over one header block, with the prover's hints computed by `find_hints` and checked | C1 to C5, key hash of C6 |
| `recovery` | `verify_recovery_email`: `verify_dkim_header` at `HEADER_MAX`, then `C` opened by the signed address and `account_code`, the Subject opened by the digest and `rho`, and the leaf `(lowercase d=, key hash)` at the leaf index of the tree with root `key_root` | C1 to C6 |
| `spec` | The constants the spec fixes: domain tags, `ADDR_MAX`, the 62-byte leaf domain, the registry depth, the Subject phrases, `HEADER_MAX` and the DKIM-Signature field bounds | |

The circuit takes the canonicalized bytes the signature covers and never
canonicalizes. Positions in the header are prover hints, always checked.

## The recovery circuit

| | |
| --- | --- |
| Public inputs | `commitment` (`C`), `digest_hi`, `digest_lo`, `key_root`: the 128 bytes the email guardian hands its verifier |
| Private inputs | `header` (the signed header block, at most `HEADER_MAX` = 1536 bytes), `modulus`, `redc` (noir-bignum's Barrett hint, read only by unconstrained code), `signature`, `rho`, `account_code`, `key_index`, `key_siblings` (16) |
| Size | 251,561 UltraHonk gates, padded to 2^18 (`MEASUREMENTS.md`); `bench/recovery_1024` is the same relation at 1024-byte headers, 189,503 gates, also 2^18 |
| Verification key | `contracts/email-verifier/vk/email_recovery.vk` (`bb write_vk --scheme ultra_honk --oracle_hash keccak`), compiled into the verifier contract |

The leaf's domain is the lowercase `d=` value the circuit reads from `H`,
which `dkim_signature` proves equal to the lowercase From domain, so C4 holds
by construction. Positions inside `H` are computed by `find_hints` in
unconstrained code and checked.

`packages/email-recovery` turns a raw `.eml` into these inputs
(`encodeRecoveryEmail`), and its `test/attacks.test.ts` runs every
adversarial email of `packages/email-mocks` through the committed circuit
with noir_js. `just gen-email-proofs` compiles the circuit, writes the
artifact and the key, and proves one recovery email per launch domain plus
the integration tests' approvals, all generated by the provider mocks
(`crates/integration-tests/fixtures/email/`).

### Header bound

`HEADER_MAX` = 1536 bytes. The signed header blocks of the committed
launch-domain fixtures (`first.last@<domain>`, with or without a 10-byte
display name), in the provider mocks' formats
(`packages/email-mocks/PROVIDERS.md`):

| Domain | Signed block | DKIM-Signature field | Tags | Longest display name with a 124-byte address |
| --- | --- | --- | --- | --- |
| gmail.com | 645 | 296 | 11 | 797 |
| outlook.com | 558 | 218 | 8 | 886 |
| hotmail.com | 545 | 218 | 8 | 886 |
| icloud.com | 601 | 230 | 10 | 842 |
| yahoo.com | 477 | 197 | 9 | 965 |
| proton.me | 653 | 278 | 10 | 789 |
| protonmail.com | 655 | 283 | 10 | 779 |
| fastmail.com | 660 | 304 | 10 | 785 |
| gmx.net | 795 | 355 | 11 | 539 |
| gmx.de | 779 | 353 | 11 | 540 |
| web.de | 796 | 353 | 11 | 536 |

The last column is the longest display name whose block still fits with the
longest address the spec allows (124 bytes), found by generating the mock
email for each length. GMX and WEB.DE are the tightest because their signed
fields carry the address twice. At 1024 bytes those two would leave only 24
to 28 bytes for a display name with a 124-byte address; 1536 keeps the
circuit at 2^18, like 1024 (`MEASUREMENTS.md` compares the two). The field
and tag bounds (512 bytes, 16 tags) hold every launch format. The
integration test `email_proofs.rs::long_address_at_web_de_counts_one_vote`
proves a 124-byte address with a 299-byte display name at WEB.DE. All of
these figures come from the mocks' formats; real provider mail is not
measured.

## Build and test

```sh
git submodule update --init                       # vendor/perch, for the pins and Poseidon2
eval "$(circuits/email-recovery/scripts/toolchain.sh)"   # pinned nargo and bb in target/zk-toolchain
circuits/email-recovery/scripts/check-toolchain.sh
cd circuits/email-recovery
"$NARGO" test --workspace                         # about a minute on 18 cores
scripts/check-vendor.sh
```

`just test-email-circuits` runs the same from the repository root.

`scripts/toolchain.sh` runs Perch's own installer
(`vendor/perch/scripts/zk-toolchain.sh`), which checks every download
against a pinned SHA-256 and never touches a global `~/.nargo` or `~/.bb`.
`scripts/check-toolchain.sh` fails if the active `nargo` or `bb` differs
from Perch's pins.

## Test vectors

`scripts/gen-test-vectors.mjs` writes `tests/src/vectors.nr` and the
`Prover.toml` of every bench package. It derives test-only RSA keys from
fixed seeds (no private key is stored), builds relaxed-canonicalized header
blocks in the published DKIM format (RFC 6376 §3.4.2 and §3.7), signs them
with PKCS#1 v1.5, and checks every honest signature with `node:crypto`'s
independent verifier. The recovery Subject's value comes from the circuit's
own `P2` through `tools/blinded_value`, so the generator needs the pinned
nargo:

```sh
NARGO=... node scripts/gen-test-vectors.mjs           # regenerate
NARGO=... node scripts/gen-test-vectors.mjs --check   # fail if anything is stale
```

These vectors are the minimum the circuit's tests need. Fixtures that match
each launch provider's signing format live in `packages/email-mocks`; the
recovery circuit's proofs are made from them (`just gen-email-proofs`).

## Measurements

`scripts/measure.sh` installs and checks the toolchain, compiles every
package, counts gates with `bb gates`, proves the recovery circuit and each
proved bench package with `bb prove --zk` (and verifies every proof), proves
the recovery circuit with bb.js on one thread and on every core, and
rewrites the tables in `MEASUREMENTS.md`.
