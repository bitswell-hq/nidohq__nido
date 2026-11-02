# Email recovery: Lean model and proofs

The four properties of the email recovery factor (`docs/email-recovery/spec.md`
§11.2), stated and proven in Lean 4 over a model of the email guardian's checks
(§8.3), the email circuit's relation (§6.2), and Perch's recovery controller
(`vendor/perch/docs/recovery/spec.md`, cited as Perch §N), with the wallet
policy of §9.3 as a separate theorem. The cryptographic assumptions of §11.1
are named breaks in the theorems' conclusions, each on inputs the theorem
computes, or hypotheses; privacy is proven in an ideal model of the commitment
and the proofs (below). None is an axiom.

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
| `Basic` | Byte strings, the BN254 modulus and canonical field elements, Perch's `split_hi_lo`, the domain tags, SHA-256 and Poseidon2 as abstract functions (SHA-256's outputs 32 bytes, Poseidon2's field elements), and their breaks on given inputs (`Sha256Collides`; `P2Collides` and `P2Zero` on lists of field elements) |
| `Statement` | Perch's `RecoveryStatement` (Perch §4), the fields the guardian reads (`View`), the encoding and its code facts (`Encoding.Facts`), the digest, entry points and authorization contexts |
| `Merkle` | The depth-16 key trees (§7.2), membership paths, `pathBreak` (the pairs a path collides on), and `path_binds` |
| `Pack` | `pack` (§2) and `pack_injective` |
| `Circuit` | The modulus limbs (§7.1); `hex` (§2); the Poseidon2 inputs and values of the commitment (§5.3), key hash and leaf (§7.1, §7.2), salt leaf and pin tree (§7.4); key-tree slots; the blinded Subject (§4.2); `Relation`, one field per obligation C1 to C6 (§6.2); and the binding lemmas |
| `Guardian` | `GuardianConfig` (§8.1), `construct` (§8.2), `check` (§8.3), and `check_eq_ok_iff` |
| `Soundness` | Theorem 1, and the email binding one statement |
| `Controller` | Perch's controller as a state machine (T1 to T9) with its event log |
| `Invariants` | `Inv`, the invariant of every reachable controller state |
| `OneFactor` | Theorem 4 |
| `Replay` | Theorem 3, and the guardian composed with the controller (`emailAuth`) |
| `Privacy` | Theorem 2: the honest wallet, the ideal model, the adversary's view and its simulator, and the structural lemma |
| `WalletPolicy` | The §9.3 rules as a predicate, and the wallet part of Theorem 4 |
| `Examples` | Concrete values satisfying the hypotheses of Theorems 1, 2 and 4, and a leaky prover that Theorem 2's view detects |
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
`From` address, the Subject value, the `d=` value; lowercasing; the PKCS#1
encoding) are abstract (`Format`): computing them as §4.3 and §4.5 say is the
circuit's obligation, outside this model. The modulus limbs, the packing, `hex`,
the commitment, key hash, key leaf, salt leaf, pin tree and blinded token are
the spec's formulas. `hex` is §2's 64 lowercase hexadecimal characters of the
32-byte big-endian encoding (the circuit's `hex_of_field`), and it is injective
below `2^256` (`hex_injective`); Poseidon2's outputs are field elements
(`Hashes.p2_canonical`, the type Noir gives them), so the Subject's 64
characters determine the token `T`. `modulusLimbs` is §7.1's 18 little-endian 120-bit limbs
(`modulusLimbs_spec`: for `n < 2^2048` there are 18, each below `2^120`,
recomposing to `n`), and different moduli have different limbs
(`modulusLimbs_injective`), so the key hash binds the modulus itself.
The relation also bounds the private inputs the circuit types as `Field`
(`codeCanonical`, `rhoCanonical`, `siblingsCanonical`), so every list the
circuit hashes is a list of field elements: the domain tags, the address and
domain lengths, the 31-byte limbs `pack` cuts (`pack_canonical`, below
`2^248`), the 120-bit modulus limbs, the digest limbs (below `2^128`, since
SHA-256 returns 32 bytes) and Poseidon2's own outputs.

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

All are **proven** (no `sorry`; checked by `lake build`); Theorem 2 is proven
in its ideal model (see "The privacy model").

| Property (§11.2) | Lean | Statement |
| --- | --- | --- |
| 1 Soundness | `EmailRecovery.email_of_check` | If `check` accepts an approval, its twelve checks hold (`Accepted`), and for every extractor `X` either `X`'s witness for the approval's proof is an email (`SignedEmail`) or `X` fails on that accepted proof (`ExtractionFails`). The email: its header carries a valid RSA-2048 DKIM signature under `n`; the leaf `leaf(domain, key_hash(n))` has a path to the accepted root, which is the unexpired pin or a root the registry accepts; its `From` address and an account code open `C`; the address's domain is `d=` and the leaf domain; its Subject opens to `d`; and the statement bytes hash to `d` and name the guardian's account, controller and network, an allowed action through its entry point, and an unexpired bound |
| | `EmailRecovery.soundness` | Adds the registry (A5) and the honest enrollment (A7): the email's `From` address and account code are the enrolled ones and `(leaf domain, n)` is a trusted key, unless a Poseidon2 break on inputs computed from the extracted witness, the enrollment and the accepted root's tree holds (`SoundnessAssumptions.Break`) |
| | `EmailRecovery.email_binds_statement`, `signedEmail_binds_statement` | The email binds one statement: if two guardians accept two approvals and `X`'s witnesses for their proofs carry one header, the two approvals carry the same statement bytes, unless the two blinding inputs `(DOM_BLIND, digest_hi, digest_lo, rho)` collide under Poseidon2, the two statements collide under SHA-256, or `X` fails on one of the two accepted proofs. So an email accepted once approves no other statement, and an old recovery email approves nothing new |
| 2 Privacy | `EmailRecovery.privacy_simulation` | In the ideal model (`Functionalities.Ideal`), for every private state of the wallet and every adaptive adversary, the adversary's view (the deployed configuration, every approval the wallet hands out with its proof, every transaction, the guardian's verdict on its approval in every context, the controller's results, states and events) equals a simulator's view computed from the public deployment, two handles, the proof system's simulator and the adversary's own moves |
| | `EmailRecovery.privacy_two_runs` | So two wallets with any two private states, including different addresses and account codes, give every adversary the same view |
| | `EmailRecovery.structural_noninterference`, `enroll_factors`, `publicInputs_enroll` | Structural: for any fixed sequence of transactions, the guardian's configuration and verdicts and the controller's results, states and events are a function of the public values, the transactions, `C` and the pin root; the proof's public inputs are `C`, the digest limbs and the root. The contracts store and emit nothing about the address beyond `C` and the pin root |
| 3 Replay | `EmailRecovery.accepted_names_digest`, `accepted_context_unique`, `accepted_account_unique` | An approval is accepted only in the context `controller.fn((sha256(statement),))`, in exactly one context, and for exactly one account, controller and network |
| | `EmailRecovery.digest_fixes` | The digest fixes the account, network, controller, action, attempt or request id and epoch, unless the two statements' encodings are a SHA-256 collision |
| | `EmailRecovery.Perch.votes_counted_once`, `change_votes_counted_once`, `counted_vote_refused_again` | The controller records an address at most once per attempt and domain, and once per change digest; a resubmitted vote is refused |
| | `EmailRecovery.Perch.email_vote_replay`, `email_vote_binds_statement`, `email_change_binds_statement` | Composed with the controller: an email approval that counts in two `submit_guardian` calls counts for one attempt, one domain, one epoch, unless the encodings of the two statements the controller built from its stored configuration and attempts are a SHA-256 collision; a change approval is recorded only under its own statement's digest |
| | `EmailRecovery.check_payload_irrelevant`, `emailAuth_payload_irrelevant` | The verdict ignores the authorization entry the approval is wrapped in; the controller's transitions have no submitter input. A copy submitted by anyone records the same vote |
| 4 One-factor safety | `EmailRecovery.Perch.completion_waits_for_delay` | In every trace, every completion is preceded in the log by its attempt's authorization, under a configuration with `delay_ledgers > 0`, at least `delay_ledgers` ledgers earlier |
| | `EmailRecovery.Perch.email_only_authorizes_only_at_quorum_one`, `email_only_never_authorizes` | In every trace whose only evidence is approvals by the email guardian `G` (owner-authorized transactions allowed), every authorization is under a guardian-only configuration with quorum 1 listing `G`; so with quorum at least 2, or in `combined` or `zk-only` mode, none happens |
| | `EmailRecovery.Perch.one_factor_safety` | The two combined, for every completed recovery |
| | `EmailRecovery.Perch.quorum_one_of_conditionMet` | `G`'s approval alone meets `require_condition` (Protected reconfiguration and upgrade) only at quorum 1, guardian-only |
| | `EmailRecovery.Perch.owner_can_cancel` | During the delay a `Loss` owner's cancellation of a live attempt succeeds (T7) |
| 4, wallet policy | `EmailRecovery.Perch.wallet_policy_email_alone`, `one_factor_under_wallet_policy` | Under the §9.3 rules (`WalletPolicy`), the email guardian alone reaches the quorum only under `loss`, with a delay lasting at least 7 days at the network's target ledger close time (`emailOnlyFloor_lasts`: `604,800,000 ≤ t · ⌈604,800,000 / t⌉` ms for every `t > 0`; 120,960 ledgers at 5,000 ms) and a second alert channel |
| | `EmailRecovery.Perch.wallet_policy_needed_email_allows_every_action` | Rule 4: a needed email vote allows every action |

Supporting lemmas. The binding lemmas each conclude equality, or a collision on
the inputs they name: `path_binds` (a Merkle path to a tree's root shows the
tree holds the leaf at that index, unless the pairs `pathBreak` computes
collide), `commit_binds` (the commitment binds the address and account code),
`keyHash_binds` (the key hash binds the modulus), `keyLeaf_binds` (a leaf binds
its domain and key hash), `slot_binds` (a slot whose leaf is a key's leaf holds
that key, unless `SlotBreak` holds; `slot_fits` shows every slot behind an
accepted root holds an RSA-2048 key of a domain of at most 62 bytes, the
16-byte salt, or nothing), `subject_binds_digest` (a header whose
Subject opens to two digests (C5) opens to one, unless the two blinding inputs
collide) and `digest_binds` (a digest binds the statement, unless the two
encodings collide under SHA-256). The injectivity lemmas are `pack_injective`,
`modulusLimbs_injective`, `split_injective` and `hex_injective`.
`enroll_subject_ne_recovery_subject` is a lemma about two constants (the
enrollment and recovery phrases differ in their first byte, so an enrollment
Subject never satisfies C5), not a security property of its own.

**Non-vacuity.** `Examples.lean` gives concrete values for which every
hypothesis holds: a guardian, a ledger and an approval that `check` accepts,
with `SoundnessAssumptions` for them and an extractor that does not fail on the
approval (`assumptions₀`, `check₀`, `extraction₀`); a run from an unenrolled
account, with one guardian's approvals as the only evidence, that enrolls,
opens an attempt, authorizes it with that one vote at quorum 1, and completes it
after the delay (`trace₀`, `trace₀_events`); and two wallets with different
addresses and account codes under tools in the ideal model (`privacy₀`).
`leaky_prover_distinguishes` shows the privacy theorem's view contains the
proofs: with a prover that writes the address into its proof, one query gives
the two wallets different views. `aliased_code_is_no_break` shows why the
relation bounds its `Field` inputs: under a hash that reads its inputs modulo
`r`, as Poseidon2 does, the account codes `code` and `code + r` open one
commitment, and siblings `s` and `s + r` hash alike, though nothing is broken.

## Reading the breaks

A conclusion "`P`, unless `B`" says something about `P` only if `B` can be
false. "Poseidon2 has a collision somewhere" cannot: by pigeonhole it is true of
every function from unbounded inputs to a finite field. So every break here is a
proposition about specific inputs, built from the theorem's data: the commitment
inputs of the extracted address and code and of the enrolled ones; the pair of
children `pathBreak` finds along the extracted path; the extracted key's leaf
input and the input of the slot it sits in; the two moduli's key-hash inputs;
the blinding inputs of two Subjects; the two statements' encodings. Each theorem is then a reduction: anyone who
violates `P` hands over a collision computed from the data. A Poseidon2 break
is a collision on `F_r^k`: `P2Collides` and `P2Zero` require every entry of the
lists they name to be a canonical field element. Poseidon2 reads its inputs
modulo `r`, so a pair such as `code` and `code + r` hashes alike without
anything being broken; the relation's bounds on the witness, the enrollment's
16-byte code and the registry's and pin's key shapes make every pair the
theorems name a list of field elements, so each is a genuine collision. That is the reading
of collision resistance for a fixed, unkeyed hash function (P. Rogaway,
"Formalizing Human Ignorance: Collision-Resistant Hashing without the Keys",
VIETCRYPT 2006, <https://eprint.iacr.org/2006/281>). Existentially quantified
values in a conclusion are pinned to the theorem's data by equations
(`s.attempts id = some a`).

Extraction is isolated as A4's bad event on the accepted proof, which is not
a reduction in the sense above. A collision break names inputs computed from
the theorem's data; `ExtractionFails` is the complement of the circuit relation
on `X`'s witness, so the disjunction in Theorem 1 holds by excluded middle and
says only where A4 enters. An extractor that succeeds on every accepted proof
would be perfect soundness, which a succinct argument does not have: accepting
proofs of false statements exist. So Theorem 1 takes any function `X` from
public inputs and proof to witness and concludes, for the one approval the
guardian accepted, the email facts about `X`'s witness or `ExtractionFails` on
that approval's public inputs and proof.

`X` is not "a function of the public inputs and the proof" in the sense of one
extractor that works from public data: such an extractor, applied to an honest
approval, would compute the user's address from the chain, against A3, A6 and
A4's zero knowledge. It is the per-run output of A4's extractor. A4 (spec
§11.1) is simulation extractability with zero knowledge: for every efficient
adversary with access to honest proofs (an adversary that reads the chain sees
every honest approval with its proof), there is an efficient extractor for that
adversary, which may read its code, coins and random-oracle queries, such that
whenever the adversary outputs an accepted proof for public inputs that no proof
it was given has, the extractor returns a witness for them except with
negligible probability. In one run, take `X` to be that extractor's output on
each such proof, and the wallet's own witness on a proof for public inputs the
wallet proved, which satisfies the relation. `ExtractionFails` then holds on an
accepted approval only with negligible probability, so Theorem 1 holds against
adversaries who have seen honest approvals.

This is the weak form of simulation extractability: it extracts only for public
inputs no given proof has. The strong form, which also extracts from a new proof
for the public inputs of a given one, implies it and is not needed: such a proof
approves the digest the wallet approved, which the controller counts once
(Theorem 3). We know of no published proof of either form for UltraHonk, so A4 is
stated, not established. The nearest published results are for Plonk-family
and sumcheck-based arguments with other commitment schemes; spec §11.1 lists
them.

## The privacy model

Privacy is a statement about what an adversary sees, so Theorem 2 models the
adversary and the honest wallet. The wallet holds a private state (`Private`:
the address, account code and pinned keys, and for each request the recovery
email, blinding value and key path), and is written once over its tools
(`Functionalities`: the commitment, the pin root and the prover). Enrolling, it
deploys the configuration those tools give; asked for an approval of a request
(statement bytes and the source of its root), it builds the circuit witness
from its private state and returns the statement, the root and a proof of the
witness for the public inputs the guardian will build. The adversary
(`Adversary`) picks each move from the deployed configuration and everything it
has observed: it asks the wallet for an approval, or runs a transaction of its
choice through the guardian and the controller, which may carry any approval,
including a copy of one the wallet handed out. Its view is the configuration
and every observation, proofs included.

`Functionalities.real` is the spec's Poseidon2 formulas and a prover
(`enroll_real`). The ideal model (`Functionalities.Ideal hC hR sim`) has the
commitment return the handle `hC` and the pin root the handle `hR` whatever the
secret, and every proof be `sim` of its public inputs. `privacy_simulation`
proves that in the ideal model the view is `simView`, which takes no private
input. The step from the ideal model to the real tools is assumed, not proven:

- the pair `(C, pin root)` for a uniform secret `account_code` (A6) is
  indistinguishable from two uniform handles when Poseidon2 is a random
  function (A3): each is a Poseidon2 output computed from the code;
- an honest UltraHonk proof of a valid witness is indistinguishable from the
  simulator's output on its public inputs (A4, zero knowledge).

What the view shows besides the handles is each approval's statement and the
source of its root (the pin, or which registry root), the time of each
transaction, and everything public about the deployment, as spec §11.2 item 2
lists. The model's wallet answers every request; a real wallet can answer only
requests it holds a valid witness for, and it picks the source itself
(`chooseKeyPath`: the pin when the signing key is pinned and the pin is live,
the registry root otherwise), so the source of an approval's root is revealed
information about the signing key, as listed. What the mail provider sees off
chain (`T`, and the timing of the email) is outside this view.

## Assumptions

| Id (§11.1) | In the model | Used by |
| --- | --- | --- |
| A1a RSA-2048 PKCS#1 v1.5 is unforgeable; providers keep keys secret | Not stated. Theorem 1 concludes that a valid signature under the key exists; A1a is the step from there to "the provider signed this header", a computational claim | The argument after Theorem 1 |
| A1b providers sign a `from` naming one of their mailboxes only for its holder | Not stated. The model's `Format` reads the From address from the signed header; A1b is the step from "the provider signed this From" to "the mailbox's holder sent it", a property of each provider (`research/email-recovery/eval/parser/sender-authentication.md`) | The argument after Theorem 1 |
| A2 SHA-256 collision resistance | `Sha256Collides` on the encodings of the two statements, an alternative in the conclusion | Theorem 3 (`digest_fixes`, `email_vote_replay`); `email_binds_statement` |
| A3 Poseidon2 collision resistance on `F_r^k` | `P2Collides` (two different lists of field elements with one hash) on the commitment inputs, the path pairs, the leaf and slot inputs, the key-hash inputs, or the two blinding inputs, and `P2Zero` on the key's leaf input, alternatives in the conclusion (`SoundnessAssumptions.Break`, `email_binds_statement`) | Theorem 1 (`soundness`, `from_is_enrolled`, `key_is_trusted`, `email_binds_statement`) |
| A3 Poseidon2 as a random function | The ideal model's handles: with A6, `(C, pin root)` is indistinguishable from two uniform handles (computational, assumed) | The step from Theorem 2's ideal model to the real tools |
| A4 simulation extractability | `ExtractionFails` on the accepted approval's public inputs and proof, an alternative in the conclusion, for every extractor; A4 is that, for the per-run extractor above, it holds only with negligible probability | Theorem 1 (`soundness`, `email_binds_statement`) |
| A4 zero knowledge | The ideal model's prover: an honest proof is `sim` of its public inputs (computational, assumed) | The step from Theorem 2's ideal model to the real tools |
| A5 the registry holds only real keys | Hypothesis `RegistryTrees`: for every accepted root, the keys at the leaves of its depth-16 tree (`keyAt`), each `Trusted` and each an RSA-2048 modulus of a domain of 1 to 62 bytes (`fits`). The tree's shape and the key and domain checks are the registry contract's (tested); that its keys are trusted is the registry's governance (§7.6) | `soundness`, `key_is_trusted` |
| A6 `account_code` and `rho` secret and uniform | Not stated: with A3 it makes `C` and the pin root hide the address and pinned keys | The step from Theorem 2's ideal model to the real tools |
| A7 honest enrollment | Hypotheses `HonestCommitment` (`C` is the enrolled address's commitment under a 16-byte account code) and `HonestPin` (the pin root is the wallet's pin tree over that code and `Trusted` RSA-2048 keys of domains of at most 62 bytes) | `soundness` |

`SoundnessAssumptions` bundles A5 and A7 for Theorem 1. Theorem 4 needs no
cryptographic hypothesis. Theorem 2's cryptography is its ideal model, and the
step from that model to the real tools is assumed.

**`P2Zero`.** The key trees' empty leaf is `0`. A key leaf
`P2(DOM_LEAF, ...)` equal to `0` would stand in for an empty slot of any
registry or pin tree, and that is a Poseidon2 input mapping to `0`, not a
collision. `slot_binds` therefore names it as a separate break, on the key's
own leaf input. Under A3's random-function model finding one is as hard as
hitting any fixed value; collision resistance alone does not exclude it.

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
  `refuses_a_tampered_proof`, and the `construction_refuses_*` tests). Its
  `Env` carries two clocks, as the contract reads them: the ledger number
  (`sequence()`), which check 9 compares with the statement's expiry, and the
  close time (`timestamp()`), which check 11 and `construct` compare with
  the pin's `valid_until`.
  A call to a dependency that fails, a registry or verifier that traps or is
  archived, is part of checks 11 and 12: the world's registry answers
  `none` and its verifier `callFailed` or `vkParseError`, and `check` refuses
  with `registryUnavailable` or `verifierUnavailable`. Such a refusal accepts
  nothing, so the safety theorems are unaffected (`Accepted` needs the
  registry to answer `some true` or the pin to hold, and the verifier `ok`).
  It affects liveness: while a dependency fails, the email factor approves
  nothing. An archived dependency is restored by whoever submits the next
  transaction that reads it, and its bytes are unchanged; the cost is in
  `research/email-recovery/eval/README.md`, "Archival and the keeper".
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
  `u32` overflow); storage never expires (see below); the doc compiler's
  `derive_target`, the ZK adapter's verdict, and the host's acceptance of a
  guardian authorization entry are fields of the transaction.
- **Why storage that never expires is sound.** On the network, persistent
  entries are archived, not lost: a transaction that reads one restores the
  same bytes first, so archival changes cost and liveness, not state.
  Temporary entries do expire, and Perch keeps exactly one kind of record
  in them: a collecting attempt, with the votes it has counted
  (`perch-recovery` `contract.rs`, `save`). `save` extends that record to
  live at least until the attempt's evidence deadline, and moves an attempt
  that is authorized, completed, or has an evidence window longer than a
  temporary entry may live into persistent storage. A collecting attempt's
  record therefore expires only after its evidence deadline has passed, when
  `is_live` is already false. Every transition that changes an attempt
  (`submit_guardian`, `submit_zk`, `rcv_cancel`) loads it through
  `load_live`, which refuses it then: `AttemptNotLive` while the record is
  present, `NoSuchAttempt` once it has expired; only the read-only views
  (`attempt`, `statement`) tell the two apart. Expiry turns one refusal into
  another and removes no record that a live attempt reads, so a vote can
  neither be counted twice nor counted for an attempt the model refuses:
  the contract's accepted transitions are the model's.
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
  guardian, a second alert channel, `loss` and at least `⌈604,800,000 / t⌉`
  ledgers for the network's target close time `t` (milliseconds, a field of
  `Member`) when the mode is guardian-only with quorum 1, and `ALLOW_ALL` when the other
  listed guardians number fewer than the quorum. `recoverySpec.test.ts` pins
  each rule at its boundary; agreement with the predicate is tested, not
  proven. The theorem is about configurations that satisfy the predicate.
- **Registry.** `contracts/dkim-registry` builds the tree `RegistryTrees`
  describes (§7.2: depth 16, untagged interior nodes, empty leaves `0`, and
  retirement and revocation emptying a leaf; it computes each leaf from the
  domain and the modulus an addition carries) and accepts only its current
  root and roots in grace (§7.3). Its hashing is cross-checked against Noir
  (`just dkim-registry-vectors`), not proven. That the keys at its leaves are
  keys their domains control is A5, which the registry reduces to its
  governance (§7.6).
- **Wallet.** The privacy model's wallet mirrors the browser prover (§6.5):
  it proves the witness `encodeRecoveryEmail` builds from the email and the
  secret, for the public inputs the guardian builds, with the root
  `chooseKeyPath` picks (`packages/frontend/src/lib/recovery/emailModel.ts`).
  Agreement is by reading, not tested against the model.

## What was run and what was read

Run: `lake build` on Lean `v4.35.0` (all modules, including the `#guard_msgs`
axiom checks and the examples), `#print axioms` for every theorem, and the
CI workflow's scan for unchecked declarations.
Read: the spec, Perch's recovery spec and statement layout, the guardian's
`contract.rs` and `statement.rs`, Perch's controller `contract.rs`, the
circuit's `hex_of_field` (`circuits/email-recovery/lib/src/subject.nr`), and
the wallet's `chooseKeyPath`, against which the model was written; and the
publications A4's literature paragraph (spec §11.1) cites.
