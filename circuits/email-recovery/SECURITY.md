# Security notes

What these components check, the publicly documented attacks on email
circuits they refuse, the toolchain advisories that apply to the pinned
compiler and prover, and what is proven, tested or assumed. The obligations
the components serve are C1 to C6 of `docs/email-recovery/spec.md` §6.2.

## 1. Publicly documented soundness issue classes

Every class below has a negative test in `tests/src/soundness.nr` that
names its public source. Each test signs its header with the test key, so
the RSA check passes and the rejection comes from the check under test, and
pins the exact failing assertion with `should_fail_with`. Where an attack is
a choice of prover hints rather than of header bytes, the test starts from
the honest hints, changes them as an attacker would, and expects the
constraint that refuses them.

| Class | Public sources | How the circuit refuses it | Tests |
| --- | --- | --- | --- |
| Long or address-like display names spoofing From | Matter Labs finding 1, Consensys Diligence 5.4, Zellic 3.2 | The address is the angle-addr that ends the From line, or the whole value; the value holds exactly one `<` and one `>` or none; a quoted local part is outside the grammar | `decoy_angle_addr_in_display_name_is_refused`, `decoy_angle_addr_cannot_be_claimed`, `address_like_display_name_cannot_be_claimed`, `quoted_local_part_is_refused`, `address_inside_quoted_local_part_cannot_be_claimed`, `suffix_of_quoted_local_part_cannot_be_claimed` |
| Folded From under simple canonicalization | Consensys Diligence 5.1 | No CRLF in the signed block is followed by SP or HTAB; `c=` must be relaxed for headers | `folded_from_under_simple_canonicalization_is_refused`, `simple_header_canonicalization_is_refused` |
| Header fields spanning lines (To/From) | Veridise V-ZEML-VUL-006, Consensys Diligence 5.2, zkemail.nr issue #57 | The From field's start and its closing CR lie on the same line (per-byte line index from the structural scan) | `from_value_cannot_span_into_the_next_field` |
| `σ + N` signatures | Veridise V-ZEML-VUL-003 and VUL-004 | Signature limbs range-checked and `σ < N` proven strictly | `signature_plus_modulus_is_refused`; in `rsa_tests.nr`, `signature_plus_modulus_has_the_same_power` shows the bound is what stops it |
| Regex or parser resets | Matter Labs finding 2, zkSecurity #03, zk-regex issue #119 | A field starts only at byte 0 or after CRLF; no regex automaton | `from_text_inside_another_field_cannot_be_claimed` |
| `bh=` confusion | Veridise V-ZEML-VUL-001, Consensys Diligence 5.10, zkemail.nr PR #68, yAcademy issue 1 | Tags are read only at scanned tag starts, and the prover's tag list must be exactly those starts; `bh=` must be unique and canonical base64 where the body is bound | `bh_inside_another_tag_cannot_be_listed`, `duplicate_bh_is_refused`, `bh_with_a_non_base64_character_is_refused` |
| `l=` | RFC 6376 §8.2, Veridise V-ZEML-VUL-013 | Refused wherever the body is bound; a tag cannot be hidden from the tag list. The header-only proof binds nothing `l=` affects (spec §4.4) | `l_tag_is_refused_where_the_body_is_bound`, `l_tag_with_space_is_refused_where_the_body_is_bound`, `l_tag_cannot_be_left_out_of_the_tag_list`, `l_tag_does_not_affect_the_header_only_proof` |
| Misaligned `d=` | Veridise V-ZEML-VUL-013, email-wallet issue #80, old.archive.zk.email issue #88, RFC 7489 §3.1.1 | Lowercase `d=` equals the lowercase From domain byte for byte | `third_party_signing_domain_is_refused`, `subdomain_signing_domain_is_refused` |
| Unsigned headers and data past the signed length | RFC 6376 §3.7 and §5.4, ens-contracts PR #38, zk-email-verify issue #166 | Only the signed block is hashed and parsed; bytes past its length are zero; From must be in it and in `h=`; the verified DKIM-Signature field is the last line, with an empty `b=` | `unsigned_field_cannot_be_added`, `bytes_past_the_signed_length_are_refused`, `unsigned_from_is_refused`, `h_without_from_is_refused`, `h_without_subject_is_refused`, `last_field_must_be_the_dkim_signature`, `block_must_not_end_with_crlf`, `signed_field_with_a_b_value_is_refused` |
| Duplicated headers | RFC 6376 §5.4.2 and §8.15, Veridise V-ZEML-VUL-005 | Exactly one line starts with `from:` and exactly one with `subject:` | `two_from_fields_are_refused`, `two_subject_fields_are_refused` |

Source URLs:

- Matter Labs (2024-10-25): https://docs.zk.email/files/matterlabs-zkemail-audit-report.pdf
- Zellic (2024-08-30): https://docs.zk.email/files/zkemail-zellic-audit-report.pdf
- zkSecurity (2024-05-27): https://docs.zk.email/files/zk_email_zksecurity_audit.pdf
- yAcademy (2023): https://docs.zk.email/files/yacademy-zkemail-audit-report.pdf
- Veridise, zkemail.nr (2024-12-03): https://github.com/zkemail/zkemail.nr/blob/main/audits/v1/veridise_v1.pdf
- Consensys Diligence, zkemail.nr (2024-12): https://github.com/zkemail/zkemail.nr/blob/main/audits/v1/consensys_diligence_v1.pdf
- zkemail.nr issue #57: https://github.com/zkemail/zkemail.nr/issues/57; PR #68: https://github.com/zkemail/zkemail.nr/pull/68
- zk-regex issue #119: https://github.com/zkemail/zk-regex/issues/119
- email-wallet issue #80: https://github.com/zkemail/email-wallet/issues/80
- old.archive.zk.email issue #88: https://github.com/zkemail/old.archive.zk.email/issues/88
- ens-contracts PR #38: https://github.com/zkemail/ens-contracts/pull/38
- zk-email-verify issue #166: https://github.com/zkemail/zk-email-verify/issues/166
- RFC 6376: https://www.rfc-editor.org/rfc/rfc6376; RFC 7489: https://www.rfc-editor.org/rfc/rfc7489

Classes from the same reports that do not arise here: partial-SHA state
aliasing (Consensys Diligence 5.5 to 5.8; no partial hashing is used), an
unbound Barrett parameter (Veridise V-ZEML-VUL-002; `redc` enters no
constraint and is not hashed, see `THIRD_PARTY.md`), and all-zero SHA output
(zkSecurity #02, a circom template not used here).

## 2. Toolchain advisories

The pins are Perch's: nargo 1.0.0-beta.9
(`6abff2f16e1c1314ba30708d1cf032a536de3d19`) and bb 0.87.0, proving
`ultra_honk --oracle_hash keccak --zk`. The public GitHub security advisories
were fetched on 2026-11-01: 55 for noir-lang/noir, 3 for
AztecProtocol/aztec-packages, none for AztecProtocol/barretenberg,
noir-bignum, sha256, poseidon, noir_rsa or noir_string_search. Each was read
in full. Where an advisory's example is a Noir program it was run with the
pinned nargo; where it is compiler-internal, the cited code was read at the
`v1.0.0-beta.9` tag. The scratch programs are not part of this repository.

### Why unconstrained-code bugs cannot make this circuit accept a false statement

Many advisories make Brillig (unconstrained) code return a wrong value. In
these circuits every unconstrained value is a hint that constrained code
re-checks completely:

- `find_hints` (positions in the header): each position is checked against
  the structural scan, the tag-start scan, and byte comparisons;
- `header::to_u32` and `dkim_signature::to_u64`: the result is constrained
  equal to the field it converts;
- `rsa::borrows_of_b_minus_a_minus_one`: every limb difference it implies is
  range-checked, which fixes each borrow;
- noir-bignum's quotient and product hints: checked by
  `evaluate_quadratic_expression` plus the range checks in `rsa.nr`;
- sha256's message-block hint: rebuilt from the input bytes and compared.

Every hint returns an integer or boolean type, and nargo 1.0.0-beta.9 adds a
range constraint of that type's width to each unconstrained-call output
(checked by compiling a probe with `--print-acir`). A wrong hint can
therefore make an honest proof fail; it cannot make a false statement
provable. That is the "Brillig only" exposure in the tables below.

### Advisories whose stated range includes 1.0.0-beta.9

| Advisory | Sev. | Trigger | This code |
| --- | --- | --- | --- |
| [GHSA-cp84-xrj5-49vg](https://github.com/noir-lang/noir/security/advisories/GHSA-cp84-xrj5-49vg) | critical | `Field as u128` in constrained code (truncation check not strict) | Not exposed: no constrained `Field as u128` in `lib/src` or the vendored paths used; Field-to-integer conversions go through hints constrained by equality (`to_u32`, `to_u64`) |
| [GHSA-jj7c-x25r-r8r3](https://github.com/noir-lang/noir/security/advisories/GHSA-jj7c-x25r-r8r3) (CVE-2026-41197) | critical | Oracle returning nested arrays of composite elements | Not exposed: no oracle is called (sha256's `oracle_tests` are test-only and never invoked) |
| [GHSA-j54m-w23j-938w](https://github.com/noir-lang/noir/security/advisories/GHSA-j54m-w23j-938w) | critical | Array last used in a `while` condition, passed by value to a non-inlined mutating function | Not exposed: no `while` loops |
| [GHSA-h47v-w5hw-q4x3](https://github.com/noir-lang/noir/security/advisories/GHSA-h47v-w5hw-q4x3) | critical | `pop_front`/`pop_back`/`remove` on a logically empty slice | Not exposed: no slices in compiled paths (`BoundedVec` is array-based) |
| [GHSA-rj6g-3r23-hw6x](https://github.com/noir-lang/noir/security/advisories/GHSA-rj6g-3r23-hw6x) | critical | Conditionally modified slice merged by an if-else | Not exposed: no slices |
| [GHSA-wv86-2vvh-2j7g](https://github.com/noir-lang/noir/security/advisories/GHSA-wv86-2vvh-2j7g) | critical | `insert`/`remove` on slices of heterogeneous elements | Not exposed: no slices |
| [GHSA-fjwm-gpjw-cjqh](https://github.com/noir-lang/noir/security/advisories/GHSA-fjwm-gpjw-cjqh) | critical | `pop_back` on slices of elements holding arrays | Not exposed: no slices |
| [GHSA-rh9h-x248-64rw](https://github.com/noir-lang/noir/security/advisories/GHSA-rh9h-x248-64rw) | high | Call mutating through `&mut &mut T` | Not exposed: no references in compiled paths (bignum's `set_limb` is unused) |
| [GHSA-ghvp-f453-vh53](https://github.com/noir-lang/noir/security/advisories/GHSA-ghvp-f453-vh53) | high | Jump argument that is a reference of unknown alias set | Not exposed: no references |
| [GHSA-fch6-63xj-6qgm](https://github.com/noir-lang/noir/security/advisories/GHSA-fch6-63xj-6qgm) | high | Nested arrays of references | Not exposed: no references |
| [GHSA-wq62-cp93-4556](https://github.com/noir-lang/noir/security/advisories/GHSA-wq62-cp93-4556) | high | Unpredicated always-fail assertion (division by an overflowed constant, zero-length `pop_back`) in an inactive branch | Completeness only (over-constrains); no runtime division or slices in constrained code, and every honest test vector proves |
| [GHSA-jcmw-4hvr-rvcc](https://github.com/noir-lang/noir/security/advisories/GHSA-jcmw-4hvr-rvcc) | high | Slices of nested arrays in dynamic arrays | Not exposed: no slices |
| [GHSA-qqgg-vpmp-766w](https://github.com/noir-lang/noir/security/advisories/GHSA-qqgg-vpmp-766w) | high | `push_back` overwrite path | Not present in beta.9 (the code path does not exist); no slices here anyway |
| [GHSA-7cqc-cj32-3xq2](https://github.com/noir-lang/noir/security/advisories/GHSA-7cqc-cj32-3xq2) | high | `aes128_encrypt` inputs list | Not exposed: AES is not used |
| [GHSA-x8xh-hm9j-f85p](https://github.com/noir-lang/noir/security/advisories/GHSA-x8xh-hm9j-f85p) | high | ECDSA `verify_signature` under a condition in a loop | Not exposed: ECDSA is not used |
| [GHSA-2v53-vfw3-w489](https://github.com/noir-lang/noir/security/advisories/GHSA-2v53-vfw3-w489) | medium | `i128::MIN / -1` in `expand_signed_math` | Not present in beta.9 (the pass does not exist); no signed integers here |
| [GHSA-w58m-gfcx-8pjq](https://github.com/noir-lang/noir/security/advisories/GHSA-w58m-gfcx-8pjq) | medium | `assert_max_bit_size` and a cast of the same Field in sibling branches of one unconstrained function | Not exposed: no unconstrained function here range-asserts; bignum's `get_msb` asserts and casts in the same branch, and it feeds only re-checked hints |
| [GHSA-62rj-6v4x-8xcq](https://github.com/noir-lang/noir/security/advisories/GHSA-62rj-6v4x-8xcq) | medium | Array mutated through `&mut [T; N]` in a callee (Brillig) | Not exposed: no references; Brillig only in any case |
| [GHSA-pgh4-36hc-pmrx](https://github.com/noir-lang/noir/security/advisories/GHSA-pgh4-36hc-pmrx) | medium | Store to a reference observed later | Not exposed: no references |
| [GHSA-hjcm-2547-whv2](https://github.com/noir-lang/noir/security/advisories/GHSA-hjcm-2547-whv2) | medium | 32-bit wrap in Brillig internals (sizes near 2^31) | Brillig only, and sizes here are at most a few thousand |
| [GHSA-24hw-hj99-xgg2](https://github.com/noir-lang/noir/security/advisories/GHSA-24hw-hj99-xgg2) | medium | `array_set` under a disabled predicate folded into a later `array_get` | Not exposed: every array write in constrained code is unconditional or under a compile-time condition |
| [GHSA-6j45-727g-vcr2](https://github.com/noir-lang/noir/security/advisories/GHSA-6j45-727g-vcr2) | medium | ECDSA with R at infinity (solver panic) | Not exposed: ECDSA is not used |
| [GHSA-7w64-wfwp-hh3q](https://github.com/noir-lang/noir/security/advisories/GHSA-7w64-wfwp-hh3q) | medium | Dynamic index into `call_data` arrays | Not exposed: no data bus |
| [GHSA-9v2p-vwxc-jfh4](https://github.com/noir-lang/noir/security/advisories/GHSA-9v2p-vwxc-jfh4) | medium | `as_witness` on a value only used in `return_data` | Not exposed: no data bus (`as_witness` is used on accumulators that later constraints use) |
| [GHSA-q37h-c4fp-pq32](https://github.com/noir-lang/noir/security/advisories/GHSA-q37h-c4fp-pq32) | medium | Merge optimizer and a Brillig predicate; the result is a compile-time rejection | Not exposed: every package compiles and its honest vectors prove |
| [GHSA-g27f-jh2j-c39x](https://github.com/noir-lang/noir/security/advisories/GHSA-g27f-jh2j-c39x) | medium | Slice of a zero-sized type (compiler crash) | Not exposed: no slices |
| [GHSA-3878-8pjf-wgcq](https://github.com/noir-lang/noir/security/advisories/GHSA-3878-8pjf-wgcq) | medium | Unused `multi_scalar_mul` or `embedded_curve_add` result removed | Not exposed: neither is used |
| [GHSA-8wpq-5mw8-8j85](https://github.com/noir-lang/noir/security/advisories/GHSA-8wpq-5mw8-8j85) | medium | Unused signed `MIN / -1` | Not exposed: no signed integers |
| [GHSA-4462-q25g-3fmc](https://github.com/noir-lang/noir/security/advisories/GHSA-4462-q25g-3fmc) | medium | Data-bus values during loop unrolling | Not exposed: no data bus |
| [GHSA-xw6r-48f5-gc77](https://github.com/noir-lang/noir/security/advisories/GHSA-xw6r-48f5-gc77) | medium | Conditional `push_back` merge of slices | Not exposed: no slices |

### Advisories with a commit or nightly in place of a version range, reproduced on beta.9

| Advisory | Sev. | Trigger | This code |
| --- | --- | --- | --- |
| [GHSA-j4p3-qjx6-rmvx](https://github.com/noir-lang/noir/security/advisories/GHSA-j4p3-qjx6-rmvx) | high | If-else selecting a `&mut` (Brillig) | Not exposed: no references; Brillig only |
| [GHSA-mfqg-6wvq-m7mr](https://github.com/noir-lang/noir/security/advisories/GHSA-mfqg-6wvq-m7mr) | medium | Conditional reference alias (Brillig) | Not exposed: no references; Brillig only |
| [GHSA-3fmx-gqpv-c758](https://github.com/noir-lang/noir/security/advisories/GHSA-3fmx-gqpv-c758) | medium | Array passed by value twice to an unconstrained callee that mutates it in a `while` loop | Not exposed: hint functions only read their array arguments; Brillig only |
| [GHSA-wc93-74wp-hpjh](https://github.com/noir-lang/noir/security/advisories/GHSA-wc93-74wp-hpjh) | medium | Tuple of arrays aliasing (Brillig) | Not exposed: no tuples of arrays in hint code; Brillig only |
| [GHSA-vx9w-r3qr-jh3v](https://github.com/noir-lang/noir/security/advisories/GHSA-vx9w-r3qr-jh3v) | medium | `&mut` into a tuple field in a comptime loop | Not exposed: the compile-time tables (`tables.nr`) use plain arrays, and the tests exercise every class they define |
| [GHSA-7qph-55xp-rwfj](https://github.com/noir-lang/noir/security/advisories/GHSA-7qph-55xp-rwfj) | low | `while true {}` in an unconstrained function (compiler crash) | Not exposed: no such loop |
| [GHSA-qqxj-59g5-7jcv](https://github.com/noir-lang/noir/security/advisories/GHSA-qqxj-59g5-7jcv) | medium | Non-inlined function mutating an array parameter (reproduced only with inlining disabled) | Not exposed: default inlining, and no such function; Brillig only |

The other 18 commit-ranged advisories (GHSA-v2q4-prvf-7h73,
GHSA-wvh3-mhm3-7wwv, GHSA-35pp-g9jq-9vf7, GHSA-35h6-769r-84c9,
GHSA-jhqf-jg5f-f357, GHSA-683h-pgp9-8cq4, GHSA-mh2f-jqp7-m6gm,
GHSA-5pjx-p7xp-457j, GHSA-pw32-6mqc-pr39, GHSA-43f8-pw4p-5f5g,
GHSA-4wj9-6h6c-499v, GHSA-fvmx-g2j7-8v59, GHSA-7c3c-hwwp-2r9v,
GHSA-h8h7-5532-qm79, GHSA-jf3m-p678-f68m, GHSA-r693-v6fg-mvqw,
GHSA-g6r5-jjj6-7pj2, GHSA-959m-2cmp-9f4w) did not reproduce on beta.9 with
their own examples, and none of their triggers (references, arrays of
references, `while` loops, bit shifts by negative amounts, dynamic dispatch)
occurs in this code.

### bb 0.87.0

No public advisory covers bb 0.87.0. GHSA-2hc8-mq24-76v2 and
GHSA-73xc-j27q-wg75 (aztec-packages) concern the native UltraHonk verifier's
pairing-point aggregation for recursive proofs, from 1.0.0-staging and
4.0.0 pre-releases on; GHSA-778c-2h5c-8r96 concerns the Aztec node. These
circuits are not recursive, and on-chain verification is Perch's Soroban
verifier.

## 3. Compiler diagnostics

`nargo compile` prints two kinds of `bug:` diagnostic ("Brillig function
call isn't properly covered by a manual constraint"). Both are the
compiler's heuristic under-constrained-value check, and both are expected:

- on `find_hints`: its outputs are positions, checked through dynamic reads
  of the scan's arrays and byte comparisons, which the heuristic does not
  follow;
- on noir-bignum's `compute_quadratic_expression_with_borrow_flags`: one of
  its three outputs (the remainder) is discarded by the caller; the quotient
  and borrow flags it uses are constrained.


## 4. What is proven, tested and assumed

**Proven:** nothing formally.

**Tested** (`nargo test --workspace`, 123 tests): the recovery relation
(`tests/src/recovery_tests.nr`): the honest witness at any leaf index, and
a commitment to another address, to a case variant of it or under another
account code, another digest, swapped digest limbs, another `rho`, a root
without the key, the key under another domain, another key for the domain,
a wrong leaf index, an index of 16 or more bits, the leaf as the root, and a
signature under another key, each refused at its obligation; honest headers in the
shapes of Gmail and Outlook.com signatures, with the address, domain,
Subject value, key hash, body hash and timestamp each compared with the
signed values; the Subject opening to the statement digest; every class in
section 1; RSA with valid signatures under two keys, `σ + N`, `σ = N`,
another key, another digest, a 1024-bit modulus, and four non-conforming
encodings; the From grammar (every `atext` symbol, digit-leading labels,
the 124-byte maximum, hyphen and length limits on labels, printable display
names); the body hash; the spec's `P2` formulas spelled out against the
library's helpers; and the key hash, registry leaf, Merkle roots and empty
root equal to the values the DKIM key registry contract computes with the
host's Poseidon2 (`tests/src/registry_parity.nr`, against the values
`contracts/dkim-registry/src/test.rs::noir_vectors` asserts; both run).

**Assumed:** the soundness of noir-bignum's limb-wise product check, of the
sha256 library's block reconstruction, of Barretenberg's SHA-256
compression and Poseidon2 gadgets, and of nargo 1.0.0-beta.9 beyond the
advisories above. The test vectors come from test keys and a minimal
generator; matching each launch provider's signing format is the job of the
provider fixtures in `packages/email-mocks`.

**Tested against the provider mocks** (`packages/email-recovery`, through
the committed circuit with noir_js): an honest recovery email from each of
the 13 domains the mocks sign for, and one with a 124-byte address and a
500-byte display name at each launch domain, is accepted
(`test/recoveryInputs.test.ts`), and every adversarial email of
`packages/email-mocks` gets its pinned outcome (`test/attacks.test.ts`, 56
cases): each case a standard DKIM verifier passes but whose claim must not be
provable is refused at a named assertion, including the four whose signing
key the registry would never hold, which are refused even with a key tree
planted with that key; each case no signature of verifies is refused too,
except a body swapped after signing, which the header-only proof does not
bind (spec §4.4). Real proofs of each launch domain's email verify on chain
(`crates/integration-tests/tests/it/email_proofs.rs`).

**Open:** no external audit; no fuzzing; `HEADER_MAX` is confirmed against
the provider mocks' formats, not against real provider mail (spec §13 item
6, `README.md` "Header bound").
