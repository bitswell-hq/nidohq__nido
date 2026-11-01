# Email-recovery circuit components

Noir components that prove, in zero knowledge, what a DKIM-signed recovery
email says: that a mail provider's RSA-2048 key signed a header block whose
From address, signing domain and Subject are the ones the email-recovery
interface specification (`docs/email-recovery/spec.md`) requires. They are
built and proven with exactly Perch's pinned toolchain (nargo
1.0.0-beta.9, bb 0.87.0, zero-knowledge UltraHonk with the keccak
transcript), so a circuit made from them verifies with Perch's Soroban
verifier.

The top-level recovery circuit, which fixes the public inputs of spec §6.1
and composes these components, is not built yet.

## Layout

| Path | What it is |
| --- | --- |
| `lib/` | The library `email_recovery`; each module's header states its grammar and checks |
| `tests/` | `email_recovery_tests`: 104 tests, including one negative test per publicly documented soundness issue class (`src/soundness.nr`) and parity with the DKIM key registry's host hashing (`src/registry_parity.nr`) |
| `bench/` | One binary package per component, for gate counts and proving measurements |
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
| `spec` | The constants the spec fixes: domain tags, `ADDR_MAX`, the 62-byte leaf domain, the registry depth, the Subject phrases | |

The circuit takes the canonicalized bytes the signature covers and never
canonicalizes. Positions in the header are prover hints, always checked.

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
each launch provider's real signing format live in `packages/email-mocks`.

## Measurements

`scripts/measure.sh` installs and checks the toolchain, compiles every
package, counts gates with `bb gates`, proves each proved bench package
with `bb prove --zk` (and verifies every proof), and rewrites the tables in
`MEASUREMENTS.md`.
