# Email recovery: Lean model and proofs

The four properties of the email recovery factor (`docs/email-recovery/spec.md`
§11.2), stated and proven in Lean 4 over a model of the email guardian's checks
(§8.3), the email circuit's relation (§6.2), and Perch's recovery controller
(`vendor/perch/docs/recovery/spec.md`, cited as Perch §N), with the wallet
policy of §9.3 as a separate theorem. The cryptographic assumptions of §11.1
are hypotheses of the theorems or named breaks in their conclusions, never
axioms.

## Build

```sh
just email-recovery-formal          # or: cd research/email-recovery/formal && lake build
```

`lean-toolchain` pins Lean `v4.35.0`. The package has no Lake dependencies:
core Lean's `Nat` and `List` lemmas suffice, so it does not use Mathlib.
Install Lean with [elan](https://github.com/leanprover/elan); it reads
`lean-toolchain` and fetches the pinned release on the first `lake` call.

CI (`.github/workflows/email-recovery-formal.yml`) runs `lake build` on every
pull request that touches this directory, after rejecting any `sorry`, `admit`,
`native_decide`, `partial`, `unsafe`, `implemented_by`, `extern` or `axiom` in
the sources. `EmailRecovery/Axioms.lean` pins each theorem's axiom dependencies
with `#guard_msgs`: every theorem depends on at most Lean's built-in `propext`,
`Quot.sound` and `Classical.choice`.

## Modules

| Module | Contents |
| --- | --- |
| `Basic` | Byte strings, the BN254 modulus and canonical field elements, Perch's `split_hi_lo`, the domain tags, SHA-256 and Poseidon2 as abstract functions, and their breaks (`Sha256Collision`, `P2Collision`, `P2HitsZero`) |
| `Statement` | Perch's `RecoveryStatement` (Perch §4), the fields the guardian reads (`View`), the encoding and its code facts (`Encoding.Facts`), the digest, entry points and authorization contexts |
| `Merkle` | The depth-16 key trees (§7.2), membership paths, and `path_binds` |
| `Pack` | `pack` (§2) and `pack_injective` |
| `Circuit` | The commitment (§5.3), key hash and leaf (§7.1, §7.2), salt leaf and pin root (§7.4), the blinded Subject (§4.2), and `Relation`, one field per obligation C1 to C6 (§6.2) |
| `Guardian` | `GuardianConfig` (§8.1), `construct` (§8.2), `check` (§8.3), and `check_eq_ok_iff` |
| `Soundness` | Theorem 1 |
| `Controller` | Perch's controller as a state machine (T1 to T9) with its event log |
| `Invariants` | `Inv`, the invariant of every reachable controller state |
| `OneFactor` | Theorem 4 |
| `Replay` | Theorem 3, and the guardian composed with the controller (`emailAuth`) |
| `Privacy` | Theorem 2 |
| `WalletPolicy` | The §9.3 rules as a predicate, and the wallet part of Theorem 4 |
| `Examples` | Concrete values satisfying the hypotheses of Theorems 1 and 4 |
| `Axioms` | The axiom dependencies of every theorem |

## Model

**The guardian.** `check` is `contract.rs::check`: the twelve checks of §8.3 in
order, each returning its `EmailGuardianError` code, with the registry's
`is_accepted_root` and the verifier's `verify_proof` as the behaviour of the
contract at the configured address (`Env`). `check_eq_ok_iff` shows that `check`
returns `ok` exactly when the facts of `Accepted` hold, one per check.

**The circuit.** `Relation x w` holds when the private inputs `w` satisfy C1 to
C6 for the public inputs `x = (C, digest_hi, digest_lo, key_root)`. C1 is
arithmetic: `s < n`, `2^2047 ≤ n < 2^2048`, `s^65537 mod n` equals the PKCS#1
v1.5 encoding of `SHA-256(H)`. The header-level functions (which bytes are the
`From` address, the Subject value, the `d=` value; lowercasing; `hex`; the
modulus limbs; the PKCS#1 encoding) are abstract (`Format`): computing them as
§4.3 and §4.5 say is the circuit's obligation, outside this model. The
commitment, key leaf, salt leaf, pin tree, blinded token and packing are the
spec's formulas.

**Perch's controller.** `Controller.lean` models one controller serving one
account: the stored configuration (profile, mode with guardian set and quorum,
timing), the epoch, the attempt counter, `invalidate_below`, the authorized
pointer, attempt records with their initiation and cancellation votes, the
cancellation count, change records keyed by digest, the account's applied
document identity, and the event log. Each transition cites the Perch section
it implements:

| Model | Perch |
| --- | --- |
| `beginAttempt` | T1 `begin_lost_key`, `begin_compromise` (§6.3) |
| `submitGuardian` | T2 `submit_guardian` |
| `submitZk` | T3 `submit_zk` |
| `promote` | T4 (`invalidate_below`, the windows, lost-key invalidation) |
| `complete` | T5 `enforce` and `rcv_sync`'s completion (§10) |
| `cancelAttempt` | T6 and T7 |
| `ownerCancel` | T7 `rcv_cancel` |
| `approveChange`, `submitZkChange`, `requireCondition` | §5 change evidence and `require_condition` |
| `applyDoc` | `rcv_sync`: no change, enrollment, reconfiguration, removal (§10, T9) |
| `executeUpgrade` | `rcv_upgrade(Execute)` (§12) |
| `State.isLive`, `authorizedLive` | §6.2 "live", `authorized_live` |

`Reachable W doc P` is the set of states reachable from an unenrolled account
by transactions satisfying `P`. Beside each event, the log records the
configuration stored when the transaction began (`Entry.config`); Perch emits
the event alone, and the model records the configuration so that theorems can
name the configuration an attempt was authorized under.

## Theorems

All are **proven** (no `sorry`; checked by `lake build`).

| Property (§11.2) | Lean | Statement |
| --- | --- | --- |
| 1 Soundness | `EmailRecovery.email_of_check` | If `check` accepts an approval and the verifier has a knowledge extractor, there is an email (`EmailFactor`): its header carries a valid RSA-2048 DKIM signature under `n`; the leaf `leaf(domain, key_hash(n))` has a path to the accepted root, which is the unexpired pin or a root the registry accepts; its `From` address and an account code open `C`; the address's domain is `d=` and the leaf domain; its Subject opens to `d`; and the statement bytes hash to `d` and name the guardian's account, controller and network, an allowed action through its entry point, and an unexpired bound |
| | `EmailRecovery.soundness` | Adds the registry (A5) and the honest enrollment (A7): the `From` address is the enrolled address and the key's leaf is trusted, unless Poseidon2 collides or maps an input to 0 |
| 2 Privacy | `EmailRecovery.privacy_noninterference` | For every run of the controller composed with the guardian, the chain's view (the guardian's configuration, and the controller's state and event log) is a function of the public values, the transactions, `C`, and the pin root |
| | `EmailRecovery.check_noninterference`, `enroll_factors`, `publicInputs_enroll`, `privacy_two_runs` | The same for the deployed configuration and every verdict; the proof's public inputs are `C`, the digest limbs and the root |
| 3 Replay | `EmailRecovery.accepted_names_digest`, `accepted_context_unique`, `accepted_account_unique` | An approval is accepted only in the context `controller.fn((sha256(statement),))`, in exactly one context, and for exactly one account, controller and network |
| | `EmailRecovery.digest_fixes` | The digest fixes the account, network, controller, action, attempt or request id and epoch, unless SHA-256 collides |
| | `EmailRecovery.Perch.votes_counted_once`, `change_votes_counted_once`, `counted_vote_refused_again` | The controller records an address at most once per attempt and domain, and once per change digest; a resubmitted vote is refused |
| | `EmailRecovery.Perch.email_vote_replay`, `email_vote_binds_statement`, `email_change_binds_statement` | Composed with the controller: an email approval that counts in two `submit_guardian` calls counts for one attempt, one domain, one epoch, unless SHA-256 collides; a change approval is recorded only under its own statement's digest |
| | `EmailRecovery.check_payload_irrelevant`, `emailAuth_payload_irrelevant` | The verdict ignores the authorization entry the approval is wrapped in; the controller's transitions have no submitter input. A copy submitted by anyone records the same vote |
| 4 One-factor safety | `EmailRecovery.Perch.completion_waits_for_delay` | In every trace, every completion is preceded in the log by its attempt's authorization, under a configuration with `delay_ledgers > 0`, at least `delay_ledgers` ledgers earlier |
| | `EmailRecovery.Perch.email_only_authorizes_only_at_quorum_one`, `email_only_never_authorizes` | In every trace whose only evidence is approvals by the email guardian `G` (owner-authorized transactions allowed), every authorization is under a guardian-only configuration with quorum 1 listing `G`; so with quorum at least 2, or in `combined` or `zk-only` mode, none happens |
| | `EmailRecovery.Perch.one_factor_safety` | The two combined, for every completed recovery |
| | `EmailRecovery.Perch.quorum_one_of_conditionMet` | `G`'s approval alone meets `require_condition` (Protected reconfiguration and upgrade) only at quorum 1, guardian-only |
| | `EmailRecovery.Perch.owner_can_cancel` | During the delay a `Loss` owner's cancellation of a live attempt succeeds (T7) |
| 4, wallet policy | `EmailRecovery.Perch.wallet_policy_email_alone`, `one_factor_under_wallet_policy` | Under the §9.3 rules (`WalletPolicy`), the email guardian alone reaches the quorum only under `loss`, with `delay_ledgers ≥ 120,960` and a second alert channel |
| | `EmailRecovery.Perch.wallet_policy_needed_email_allows_every_action` | Rule 4: a needed email vote allows every action |

Supporting results: `path_binds` (a Merkle path to a tree's root shows the
tree holds the leaf at that index, unless Poseidon2 collides), `commit_binds`
(the commitment binds the address and account code, unless Poseidon2
collides), `pack_injective`, `digest_binds`, `split_injective`, and
`enroll_subject_ne_recovery_subject` (an enrollment Subject never satisfies
C5).

**Non-vacuity.** `Examples.lean` gives concrete values for which every
hypothesis holds: a guardian, a ledger and an approval that `check` accepts,
with `SoundnessAssumptions` for them (`assumptions₀`, `check₀`); and a run
from an unenrolled account, with one guardian's approvals as the only
evidence, that enrolls, opens an attempt, authorizes it with that one vote at
quorum 1, and completes it after the delay (`trace₀`, `trace₀_events`).

## Assumptions

| Id (§11.1) | In the model | Used by |
| --- | --- | --- |
| A1 RSA-2048 PKCS#1 v1.5 is unforgeable; providers keep keys secret | Not stated. Theorem 1 concludes that a valid signature under the key exists; A1 is the step from there to "the provider signed this header", a computational claim | The argument after Theorem 1 |
| A2 SHA-256 collision resistance | The break `Sha256Collision` appears as an alternative in the conclusion | Theorem 3 (`digest_fixes`, `email_vote_replay`) |
| A3 Poseidon2 collision resistance | The breaks `P2Collision` and `P2HitsZero` appear as alternatives in the conclusion | Theorem 1 (`soundness`, `from_is_enrolled`, `key_is_trusted`) |
| A3 Poseidon2 as a random function | Not stated: indistinguishability of `C`, the pin root and the blinded Subject is computational | The step from Theorem 2 to indistinguishability |
| A4 knowledge soundness | Hypothesis `Extractor`: an extractor that returns a witness of `Relation` for every accepted proof, the deterministic form of knowledge soundness | Theorem 1 |
| A4 zero knowledge | Not stated: computational | The step from Theorem 2 to indistinguishability |
| A5 the registry holds only real keys | Hypothesis `RegistryTrees`: every accepted root is the root of a depth-16 tree whose non-empty leaves are `Trusted`. The tree's shape is the registry contract's (tested); that its leaves are trusted is the registry's governance (§7.6) | `soundness`, `key_is_trusted` |
| A6 `account_code` and `rho` secret and uniform | Not stated: it is what makes `C` hide the address; Theorem 2 reduces privacy to the secrecy of `C`'s and the pin root's preimages | The step from Theorem 2 to indistinguishability |
| A7 honest enrollment | Hypotheses `HonestCommitment` (`C` is the enrolled address's commitment) and `HonestPin` (the pin root is the wallet's pin tree over `Trusted` leaves) | `soundness` |

`SoundnessAssumptions` bundles A4, A5 and A7 for Theorem 1. Theorems 2 and 4
need no cryptographic hypothesis.

**`P2HitsZero`.** The key trees' empty leaf is `0`. A key leaf
`P2(DOM_LEAF, ...)` equal to `0` would stand in for an empty slot of any
registry or pin tree, and that is a Poseidon2 input mapping to `0`, not a
collision. `key_is_trusted` therefore names it as a separate break. Under A3's
random-function model finding one is as hard as hitting any fixed value;
collision resistance alone does not exclude it.

**Code facts.** Two properties of Perch's encoding are hypotheses
(`Encoding.Facts`), used only by Theorem 3: the encoding is injective, and the
guardian's parser reads back the fields of every encoding. They are tested, not
proven: `statement_encodings_and_digests_match` in
`vendor/perch/crates/perch-recovery-interface/tests/vectors.rs` pins Perch's
encoder against independent vectors, and
`statement_parser_reads_perch_encodings` in
`contracts/email-guardian/src/test.rs` parses every statement shape Perch's
encoder produces.

## Model and code

The proofs are about the model. Agreement between the Rust code and the model
is tested, not proven.

- **Guardian.** `check` mirrors `contracts/email-guardian/src/contract.rs::check`
  and `construct` mirrors `validate`, check for check. Every refusal is pinned by
  a test in `contracts/email-guardian/src/test.rs`
  (`refuses_anything_but_one_controller_call_carrying_a_digest` through
  `refuses_a_tampered_proof`, and the `construction_refuses_*` tests).
- **Controller.** The transitions mirror `vendor/perch/crates/perch-recovery/src/contract.rs`
  (`begin`, `submit_guardian`, `submit_zk`, `after_evidence`, `promote`,
  `cancel`, `authorize_completion` and `complete`, `rcv_sync`, `rcv_cancel`,
  `rcv_upgrade`, `approve_change`, `submit_zk_change`, `require_condition`,
  `is_live`, `authorized_live`, `check_config`). The email guardian on Perch's
  deployed wasm is pinned by `crates/integration-tests/tests/it/email_guardian.rs`
  (`email_approval_counts_as_exactly_one_guardian_vote`,
  `the_same_email_approval_is_not_counted_twice`,
  `an_email_approval_cannot_be_replayed_into_another_attempt`,
  `an_email_approval_cannot_be_replayed_into_another_account`,
  `email_approvals_alone_never_complete_a_recovery`,
  `email_approval_counts_toward_a_protected_reconfiguration`).
- **Abstractions**, each of which only adds behaviours, so a safety property of
  the model holds of the contract: ledger arithmetic is unbounded (Perch refuses
  `u32` overflow); storage never expires (Perch's temporary entries do); the doc
  compiler's `derive_target`, the ZK adapter's verdict, and the host's
  acceptance of a guardian authorization entry are fields of the transaction.
- **Identifications**: a configuration is compared by value where Perch
  compares `config_hash`, which agree unless SHA-256 collides on two canonical
  recovery members (Perch §3.2); a derived target's configuration is the
  current one, since the ZK rotation of §7.3 rule 4 is not represented; the two
  halves of a completion (`enforce`, then `rcv_sync`) are one transition, since
  a completion marker counts only in the ledger `enforce` wrote it. Scheduling
  an upgrade writes no controller state and is omitted.
- **Not modelled**: the account's own state beyond its applied document
  identity (the freeze mirror, the revoked set, the recovery generation, the
  upgrade request), the ZK membership pool and nullifiers, the circuit's
  header parsing, and Noir or Rust semantics. Proving the Rust or Noir code
  correct is out of scope.
- **Wallet policy.** `WalletPolicy` mirrors `checkEmailGuardian` in
  `packages/passkey-sdk/src/perch/doc.ts` rule for rule: at most one email
  guardian, a second alert channel, `loss` and at least 120,960 ledgers when
  the mode is guardian-only with quorum 1, and `ALLOW_ALL` when the other
  listed guardians number fewer than the quorum. `recoverySpec.test.ts` pins
  each rule at its boundary; agreement with the predicate is tested, not
  proven. The theorem is about configurations that satisfy the predicate.
- **Registry.** `contracts/dkim-registry` builds the tree `RegistryTrees`
  describes (§7.2: depth 16, untagged interior nodes, empty leaves `0`, and
  retirement and revocation emptying a leaf) and accepts only its current
  root and roots in grace (§7.3). Its hashing is cross-checked against Noir
  (`just dkim-registry-vectors`), not proven. That the non-empty leaves are
  keys their domains control is A5, which the registry reduces to its
  governance (§7.6).

## What was run and what was read

Run: `lake build` on Lean `v4.35.0` (all modules, including the `#guard_msgs`
axiom checks and the examples), and `#print axioms` for every theorem.
Read: the spec, Perch's recovery spec and statement layout, the guardian's
`contract.rs` and `statement.rs`, and Perch's controller `contract.rs`, against
which the model was written.
