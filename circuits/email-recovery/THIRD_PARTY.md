# Third-party code

Every library compiled into these circuits, with its source commit and
licence. Vendored copies are pinned file by file in their
`CHECKSUMS.sha256`; `scripts/check-vendor.sh` fails on any drift. Path
dependencies freeze the source, because nargo has no lockfile and a git tag
can move.

| Library | Where | Upstream | Commit | Licence | Changes |
| --- | --- | --- | --- | --- | --- |
| noir-bignum | `vendor/bignum` | https://github.com/noir-lang/noir-bignum | v0.7.5, `4f0b42abed0fe426e816b6d993acdf7b877bf01e` | Apache-2.0 | `Nargo.toml` points its `poseidon` dependency at Perch's copy (see `vendor/bignum/NOTICE`) |
| sha256 | `vendor/sha256` | https://github.com/noir-lang/sha256 | `50f5fda729d94848aabcd9d54dc7751460e9143a` | Apache-2.0 | none |
| poseidon | `vendor/perch/circuits/vendor/poseidon` (Perch's vendored copy, used as is) | https://github.com/noir-lang/poseidon | v0.2.0, `4bc50d88dd8d94a00a95730fd76501e676417abf` | Apache-2.0 | none (Perch pins it in its own `CHECKSUMS.sha256`) |
| Noir standard library | ships with nargo 1.0.0-beta.9 | https://github.com/noir-lang/noir | `6abff2f16e1c1314ba30708d1cf032a536de3d19` | MIT or Apache-2.0 | none |

## What each is used for, and how it was reviewed

**noir-bignum** provides the 2048-bit modular multiplication in
`lib/src/rsa.nr` (`RuntimeBigNum` and `BigNumParams`). Only the
multiplication path is used: `mul`, which computes the product in
unconstrained code and constrains it with `evaluate_quadratic_expression`.
v0.7.5 is the latest release that compiles with nargo 1.0.0-beta.9. Reading
that path against the upstream fixes released in v0.11.0
(https://github.com/noir-lang/noir-bignum/pull/270):

- `evaluate_quadratic_expression` does not range-check its operands in
  v0.7.5. `rsa.nr` range-checks the modulus, the signature and every product
  (17 limbs below 2^120 and a top limb below 2^8) before it is used again.
- `validate_in_field` proves `x <= p` in v0.7.5. `rsa.nr` does not use it;
  it proves `signature < modulus` with its own borrow chain.
- The Barrett parameter `redc` is read only by unconstrained witness code
  (`expressions.nr` lines 35 to 60 and 176 to 210, `unconstrained_ops.nr`),
  never by a constraint, so it is a prover hint.

The soundness of the limb-wise identity check in
`evaluate_quadratic_expression` (borrow flags, the 126-bit carry range
checks) is used as noir-bignum states it; it is not re-proven here.

**sha256** provides `sha256_var`, the only function used: SHA-256 of the
first `message_size` bytes of a bounded array. Read in full: each message
block is rebuilt from the input bytes and compared word by word with the
unconstrained block, bytes at or past `message_size` are read as zero,
`message_size <= N` is asserted, and the length block is checked against
`8 * message_size`. The partial-hash functions are not used.

**poseidon** provides `Poseidon2::hash`, the `P2` of the interface spec,
shared with Perch's circuit and Soroban's host. Used as Perch ships it.

**No parser was reused.** The header, From, DKIM-Signature, Subject and
base64 code in `lib/src` is written for this circuit against the grammar
in its module headers.
