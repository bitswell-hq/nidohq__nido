import EmailRecovery.Soundness
import EmailRecovery.Privacy
import EmailRecovery.Replay
import EmailRecovery.OneFactor
import EmailRecovery.WalletPolicy
import EmailRecovery.Examples

/-!
# Axioms

Every theorem this package delivers depends on at most Lean's built-in axioms
(`propext`, `Quot.sound`, `Classical.choice`): no `sorryAx`, no
`Lean.ofReduceBool`, and nothing declared by this package. The cryptographic
and code assumptions are hypotheses of the theorems, never axioms.
`#guard_msgs` fails the build if any of these lists changes.
-/

/-- info: 'EmailRecovery.soundness' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.soundness

/-- info: 'EmailRecovery.email_of_check' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.email_of_check

/-- info: 'EmailRecovery.from_is_enrolled' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.from_is_enrolled

/-- info: 'EmailRecovery.key_is_trusted' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.key_is_trusted

/-- info: 'EmailRecovery.check_eq_ok_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.check_eq_ok_iff

/-- info: 'EmailRecovery.check_payload_irrelevant' depends on axioms: [propext] -/
#guard_msgs in
#print axioms EmailRecovery.check_payload_irrelevant

/-- info: 'EmailRecovery.structural_noninterference' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.structural_noninterference

/-- info: 'EmailRecovery.privacy_simulation' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.privacy_simulation

/-- info: 'EmailRecovery.privacy_two_runs' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.privacy_two_runs

/-- info: 'EmailRecovery.enroll_factors' depends on axioms: [propext] -/
#guard_msgs in
#print axioms EmailRecovery.enroll_factors

/-- info: 'EmailRecovery.publicInputs_enroll' depends on axioms: [propext] -/
#guard_msgs in
#print axioms EmailRecovery.publicInputs_enroll

/-- info: 'EmailRecovery.accepted_names_digest' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.accepted_names_digest

/-- info: 'EmailRecovery.accepted_context_unique' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.accepted_context_unique

/-- info: 'EmailRecovery.accepted_account_unique' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.accepted_account_unique

/-- info: 'EmailRecovery.digest_fixes' does not depend on any axioms -/
#guard_msgs in
#print axioms EmailRecovery.digest_fixes

/-- info: 'EmailRecovery.Perch.email_vote_replay' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.Perch.email_vote_replay

/-- info: 'EmailRecovery.Perch.email_vote_binds_statement' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.Perch.email_vote_binds_statement

/-- info: 'EmailRecovery.Perch.email_change_binds_statement' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.Perch.email_change_binds_statement

/-- info: 'EmailRecovery.Perch.votes_counted_once' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.Perch.votes_counted_once

/-- info: 'EmailRecovery.Perch.change_votes_counted_once' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.Perch.change_votes_counted_once

/-- info: 'EmailRecovery.Perch.counted_vote_refused_again' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.Perch.counted_vote_refused_again

/-- info: 'EmailRecovery.emailAuth_payload_irrelevant' depends on axioms: [propext] -/
#guard_msgs in
#print axioms EmailRecovery.emailAuth_payload_irrelevant

/-- info: 'EmailRecovery.Perch.one_factor_safety' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.Perch.one_factor_safety

/-- info: 'EmailRecovery.Perch.completion_waits_for_delay' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.Perch.completion_waits_for_delay

/--
info: 'EmailRecovery.Perch.email_only_authorizes_only_at_quorum_one' depends on axioms: [propext,
 Classical.choice,
 Quot.sound]
-/
#guard_msgs in
#print axioms EmailRecovery.Perch.email_only_authorizes_only_at_quorum_one

/-- info: 'EmailRecovery.Perch.email_only_never_authorizes' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.Perch.email_only_never_authorizes

/-- info: 'EmailRecovery.Perch.quorum_one_of_conditionMet' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.Perch.quorum_one_of_conditionMet

/-- info: 'EmailRecovery.Perch.owner_can_cancel' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.Perch.owner_can_cancel

/-- info: 'EmailRecovery.Perch.wallet_policy_email_alone' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.Perch.wallet_policy_email_alone

/-- info: 'EmailRecovery.Perch.emailOnlyFloor_lasts' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.Perch.emailOnlyFloor_lasts

/-- info: 'EmailRecovery.Perch.one_factor_under_wallet_policy' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.Perch.one_factor_under_wallet_policy

/-- info: 'EmailRecovery.Perch.wallet_policy_needed_email_allows_every_action' depends on axioms: [propext] -/
#guard_msgs in
#print axioms EmailRecovery.Perch.wallet_policy_needed_email_allows_every_action

/-- info: 'EmailRecovery.path_binds' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.path_binds

/-- info: 'EmailRecovery.commit_binds' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.commit_binds

/-- info: 'EmailRecovery.keyHash_binds' depends on axioms: [propext] -/
#guard_msgs in
#print axioms EmailRecovery.keyHash_binds

/-- info: 'EmailRecovery.keyLeaf_binds' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.keyLeaf_binds

/-- info: 'EmailRecovery.slot_binds' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.slot_binds

/-- info: 'EmailRecovery.modulusLimbs_injective' depends on axioms: [propext] -/
#guard_msgs in
#print axioms EmailRecovery.modulusLimbs_injective

/-- info: 'EmailRecovery.modulusLimbs_spec' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.modulusLimbs_spec

/-- info: 'EmailRecovery.pack_injective' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.pack_injective

/-- info: 'EmailRecovery.digest_binds' does not depend on any axioms -/
#guard_msgs in
#print axioms EmailRecovery.digest_binds

/-- info: 'EmailRecovery.enroll_subject_ne_recovery_subject' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.enroll_subject_ne_recovery_subject

/-- info: 'EmailRecovery.Examples.trace₀' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.Examples.trace₀

/-- info: 'EmailRecovery.Examples.check₀' depends on axioms: [propext] -/
#guard_msgs in
#print axioms EmailRecovery.Examples.check₀

/-- info: 'EmailRecovery.Examples.extraction₀' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.Examples.extraction₀

/-- info: 'EmailRecovery.Examples.privacy₀' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.Examples.privacy₀

/-- info: 'EmailRecovery.Examples.leaky_prover_distinguishes' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms EmailRecovery.Examples.leaky_prover_distinguishes
