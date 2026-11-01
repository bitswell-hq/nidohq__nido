import AttenuatingGrants.Budget
import AttenuatingGrants.Grant
import AttenuatingGrants.Vocab.Chain
import AttenuatingGrants.Vocab.Files
import AttenuatingGrants.Vocab.Network
import AttenuatingGrants.Vocab.Signing
import AttenuatingGrants.Cost.Chain
import AttenuatingGrants.Cost.Files
import AttenuatingGrants.Cost.Network
import AttenuatingGrants.Cost.Signing

import AttenuatingGrants.Equiv.Chain
import AttenuatingGrants.Equiv.Files
import AttenuatingGrants.Equiv.Network
import AttenuatingGrants.Equiv.Signing
import AttenuatingGrants.Equiv.Budget

/-!
# Axioms

Each delivered theorem depends on at most Lean's built-in axioms (`propext`,
`Quot.sound`, `Classical.choice`): no `sorryAx`, no `Lean.ofReduceBool`,
nothing declared by this package, and none of the axioms Aeneas's Lean library
declares. That covers the model's theorems and every theorem about the
extracted evaluator. `#guard_msgs` fails the build if any of these dependency
lists changes.
-/

namespace AttenuatingGrants

/-- info: 'AttenuatingGrants.attenuate_narrows' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms attenuate_narrows

/-- info: 'AttenuatingGrants.attenuateAll_narrows' depends on axioms: [propext] -/
#guard_msgs in
#print axioms attenuateAll_narrows

/-- info: 'AttenuatingGrants.narrower_refl' does not depend on any axioms -/
#guard_msgs in
#print axioms narrower_refl

/-- info: 'AttenuatingGrants.narrower_trans' does not depend on any axioms -/
#guard_msgs in
#print axioms narrower_trans

/-- info: 'AttenuatingGrants.Delegates.narrower' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Delegates.narrower

/-- info: 'AttenuatingGrants.Grant.delegate_delegates' does not depend on any axioms -/
#guard_msgs in
#print axioms Grant.delegate_delegates

/-- info: 'AttenuatingGrants.delegate_narrows' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms delegate_narrows

/-- info: 'AttenuatingGrants.allowsAll_of_narrower' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms allowsAll_of_narrower

/-- info: 'AttenuatingGrants.Grant.allows_iff' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Grant.allows_iff

/-- info: 'AttenuatingGrants.Grant.allowsAll_iff' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Grant.allowsAll_iff

/-- info: 'AttenuatingGrants.Grant.allows_attenuateAll' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Grant.allows_attenuateAll

/-- info: 'AttenuatingGrants.Chain.contractIn_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.contractIn_iff

/-- info: 'AttenuatingGrants.Chain.functionIn_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.functionIn_iff

/-- info: 'AttenuatingGrants.Chain.argI128AtMost_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.argI128AtMost_iff

/-- info: 'AttenuatingGrants.Chain.argEq_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.argEq_iff

/-- info: 'AttenuatingGrants.Chain.argEq_kind' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.argEq_kind

/-- info: 'AttenuatingGrants.Chain.argEq_false_of_kind_ne' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.argEq_false_of_kind_ne

/-- info: 'AttenuatingGrants.Chain.argEq_bytes_false_of_other' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.argEq_bytes_false_of_other

/-- info: 'AttenuatingGrants.Chain.holds_createContract' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.holds_createContract

/-- info: 'AttenuatingGrants.Chain.restricted_denies_createContract' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.restricted_denies_createContract

/-- info: 'AttenuatingGrants.Files.isPrefix_iff' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Files.isPrefix_iff

/-- info: 'AttenuatingGrants.Files.pathUnder_iff' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Files.pathUnder_iff

/-- info: 'AttenuatingGrants.Files.modeIn_iff' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Files.modeIn_iff

/-- info: 'AttenuatingGrants.Files.readOnly_denies_write' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Files.readOnly_denies_write

/-- info: 'AttenuatingGrants.Files.home_a_not_prefix_home_ab' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Files.home_a_not_prefix_home_ab

/-- info: 'AttenuatingGrants.Files.home_a_not_under_home_ab' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Files.home_a_not_under_home_ab

/-- info: 'AttenuatingGrants.Network.hostIn_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Network.hostIn_iff

/-- info: 'AttenuatingGrants.Network.portIn_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Network.portIn_iff

/-- info: 'AttenuatingGrants.Network.schemeIn_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Network.schemeIn_iff

/-- info: 'AttenuatingGrants.Signing.keyIn_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Signing.keyIn_iff

/-- info: 'AttenuatingGrants.Signing.networkIn_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Signing.networkIn_iff

/-- info: 'AttenuatingGrants.Signing.payloadIn_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Signing.payloadIn_iff

/-! ## Cost (theorem 1) -/

/-- info: 'AttenuatingGrants.Cost.bytesEq_fst' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Cost.bytesEq_fst

/-- info: 'AttenuatingGrants.Cost.bytesEq_snd_le' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Cost.bytesEq_snd_le

/-- info: 'AttenuatingGrants.Cost.bytesEq_snd_le_right' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Cost.bytesEq_snd_le_right

/-- info: 'AttenuatingGrants.Cost.scalarEq_fst' does not depend on any axioms -/
#guard_msgs in
#print axioms Cost.scalarEq_fst

/-- info: 'AttenuatingGrants.Cost.mem_fst' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Cost.mem_fst

/-- info: 'AttenuatingGrants.Cost.mem_bytesEq_fst' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Cost.mem_bytesEq_fst

/-- info: 'AttenuatingGrants.Cost.mem_scalarEq_fst' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Cost.mem_scalarEq_fst

/-- info: 'AttenuatingGrants.Cost.mem_snd_le' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Cost.mem_snd_le

/-- info: 'AttenuatingGrants.Cost.mem_bytesEq_snd_le' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Cost.mem_bytesEq_snd_le

/-- info: 'AttenuatingGrants.Cost.mem_scalarEq_snd_le' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Cost.mem_scalarEq_snd_le

/-- info: 'AttenuatingGrants.Cost.get?_fst' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Cost.get?_fst

/-- info: 'AttenuatingGrants.Cost.get?_snd_le' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Cost.get?_snd_le

/-- info: 'AttenuatingGrants.Cost.allowsCounted_fst' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Cost.allowsCounted_fst

/-- info: 'AttenuatingGrants.Cost.allowsAllCounted_fst' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Cost.allowsAllCounted_fst

/-- info: 'AttenuatingGrants.Cost.allowsCounted_steps_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Cost.allowsCounted_steps_le

/-- info: 'AttenuatingGrants.Cost.allowsAllCounted_steps_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Cost.allowsAllCounted_steps_le

/-- info: 'AttenuatingGrants.Cost.allowsAllCounted_nil_steps' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Cost.allowsAllCounted_nil_steps

/-- info: 'AttenuatingGrants.Chain.valEq_fst' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Chain.valEq_fst

/-- info: 'AttenuatingGrants.Chain.valEq_snd_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.valEq_snd_le

/-- info: 'AttenuatingGrants.Chain.length_le_args_size' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Chain.length_le_args_size

/-- info: 'AttenuatingGrants.Chain.holdsCounted_fst' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.holdsCounted_fst

/-- info: 'AttenuatingGrants.Chain.allowsCounted_fst' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.allowsCounted_fst

/-- info: 'AttenuatingGrants.Chain.allowsAllCounted_fst' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.allowsAllCounted_fst

/-- info: 'AttenuatingGrants.Chain.holdsCounted_steps_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.holdsCounted_steps_le

/-- info: 'AttenuatingGrants.Chain.allows_cost_bound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.allows_cost_bound

/-- info: 'AttenuatingGrants.Chain.allowsAll_cost_bound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.allowsAll_cost_bound

/-- info: 'AttenuatingGrants.Files.isPrefixCounted_fst' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Files.isPrefixCounted_fst

/-- info: 'AttenuatingGrants.Files.isPrefixCounted_snd_le' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Files.isPrefixCounted_snd_le

/-- info: 'AttenuatingGrants.Files.holdsCounted_fst' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Files.holdsCounted_fst

/-- info: 'AttenuatingGrants.Files.allowsCounted_fst' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Files.allowsCounted_fst

/-- info: 'AttenuatingGrants.Files.allowsAllCounted_fst' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Files.allowsAllCounted_fst

/-- info: 'AttenuatingGrants.Files.holdsCounted_steps_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Files.holdsCounted_steps_le

/-- info: 'AttenuatingGrants.Files.allows_cost_bound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Files.allows_cost_bound

/-- info: 'AttenuatingGrants.Files.allowsAll_cost_bound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Files.allowsAll_cost_bound

/-- info: 'AttenuatingGrants.Network.holdsCounted_fst' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Network.holdsCounted_fst

/-- info: 'AttenuatingGrants.Network.allowsCounted_fst' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Network.allowsCounted_fst

/-- info: 'AttenuatingGrants.Network.allowsAllCounted_fst' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Network.allowsAllCounted_fst

/-- info: 'AttenuatingGrants.Network.holdsCounted_steps_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Network.holdsCounted_steps_le

/-- info: 'AttenuatingGrants.Network.allows_cost_bound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Network.allows_cost_bound

/-- info: 'AttenuatingGrants.Network.allowsAll_cost_bound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Network.allowsAll_cost_bound

/-- info: 'AttenuatingGrants.Signing.holdsCounted_fst' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Signing.holdsCounted_fst

/-- info: 'AttenuatingGrants.Signing.allowsCounted_fst' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Signing.allowsCounted_fst

/-- info: 'AttenuatingGrants.Signing.allowsAllCounted_fst' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Signing.allowsAllCounted_fst

/-- info: 'AttenuatingGrants.Signing.holdsCounted_steps_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Signing.holdsCounted_steps_le

/-- info: 'AttenuatingGrants.Signing.allows_cost_bound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Signing.allows_cost_bound

/-- info: 'AttenuatingGrants.Signing.allowsAll_cost_bound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Signing.allowsAll_cost_bound

/-! ## Extracted evaluator: loops, byte strings, the generic evaluator, carry-over -/

/-- info: 'AttenuatingGrants.Extraction.index_usize_eq' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Extraction.index_usize_eq

/-- info: 'AttenuatingGrants.Extraction.incr_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Extraction.incr_eq

/-- info: 'AttenuatingGrants.Extraction.loop_any' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Extraction.loop_any

/-- info: 'AttenuatingGrants.Extraction.loop_all' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Extraction.loop_all

/-- info: 'AttenuatingGrants.Extraction.any_eq_mem' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Extraction.any_eq_mem

/-- info: 'AttenuatingGrants.Extraction.byte_injective' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Extraction.byte_injective

/-- info: 'AttenuatingGrants.Extraction.bytesOf_inj' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Extraction.bytesOf_inj

/-- info: 'AttenuatingGrants.Extraction.zip_all_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Extraction.zip_all_eq

/-- info: 'AttenuatingGrants.Extraction.slice_len_bne' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Extraction.slice_len_bne

/-- info: 'AttenuatingGrants.Extraction.bytes_eq_loop_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Extraction.bytes_eq_loop_eq

/-- info: 'AttenuatingGrants.Extraction.bytes_eq_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Extraction.bytes_eq_eq

/-- info: 'AttenuatingGrants.Extraction.bytes_in_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Extraction.bytes_in_eq

/-- info: 'AttenuatingGrants.Extraction.any_bytes_eq_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Extraction.any_bytes_eq_mem

/-- info: 'AttenuatingGrants.Extraction.eval_allows_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Extraction.eval_allows_eq

/-- info: 'AttenuatingGrants.Extraction.eval_allows_all_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Extraction.eval_allows_all_eq

/-- info: 'AttenuatingGrants.Extraction.grant_allows_map' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Extraction.grant_allows_map

/-- info: 'AttenuatingGrants.Extraction.implements_iff_all' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Extraction.implements_iff_all

/-- info: 'AttenuatingGrants.Extraction.implementsAll_iff_all' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Extraction.implementsAll_iff_all

/-- info: 'AttenuatingGrants.Extraction.Narrower.refl' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Extraction.Narrower.refl

/-- info: 'AttenuatingGrants.Extraction.Narrower.trans' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Extraction.Narrower.trans

/-- info: 'AttenuatingGrants.Extraction.Implements.allows_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Extraction.Implements.allows_iff

/-- info: 'AttenuatingGrants.Extraction.Implements.narrower_of_subset' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Extraction.Implements.narrower_of_subset

/-- info: 'AttenuatingGrants.Extraction.Implements.narrower_push' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Extraction.Implements.narrower_push

/-- info: 'AttenuatingGrants.Extraction.Implements.narrower_of_delegates' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs in
#print axioms Extraction.Implements.narrower_of_delegates

/-- info: 'AttenuatingGrants.Extraction.ImplementsAll.allows_all_of_narrower' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs in
#print axioms Extraction.ImplementsAll.allows_all_of_narrower

/-! ## Extracted evaluator: Network -/

/-- info: 'AttenuatingGrants.Network.denotePort_injective' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Network.denotePort_injective

/-- info: 'AttenuatingGrants.Network.denoteGrant_allows' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Network.denoteGrant_allows

/-- info: 'AttenuatingGrants.Network.scheme_eq_eq' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Network.scheme_eq_eq

/-- info: 'AttenuatingGrants.Network.scheme_in_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Network.scheme_in_eq

/-- info: 'AttenuatingGrants.Network.port_in_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Network.port_in_eq

/-- info: 'AttenuatingGrants.Network.holds_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Network.holds_eq

/-- info: 'AttenuatingGrants.Network.inst_holds_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Network.inst_holds_eq

/-- info: 'AttenuatingGrants.Network.extracted_allows' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Network.extracted_allows

/-- info: 'AttenuatingGrants.Network.extracted_allowsAll' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Network.extracted_allowsAll

/-- info: 'AttenuatingGrants.Network.implements' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Network.implements

/-- info: 'AttenuatingGrants.Network.implementsAll' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Network.implementsAll

/-- info: 'AttenuatingGrants.Network.extracted_narrower_of_subset' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Network.extracted_narrower_of_subset

/-- info: 'AttenuatingGrants.Network.extracted_narrower_push' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Network.extracted_narrower_push

/-- info: 'AttenuatingGrants.Network.extracted_delegates_narrower' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Network.extracted_delegates_narrower

/-- info: 'AttenuatingGrants.Network.extracted_allowsAll_of_delegates' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Network.extracted_allowsAll_of_delegates

/-! ## Extracted evaluator: Signing -/

/-- info: 'AttenuatingGrants.Signing.denoteGrant_allows' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Signing.denoteGrant_allows

/-- info: 'AttenuatingGrants.Signing.payload_eq_eq' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Signing.payload_eq_eq

/-- info: 'AttenuatingGrants.Signing.payload_in_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Signing.payload_in_eq

/-- info: 'AttenuatingGrants.Signing.holds_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Signing.holds_eq

/-- info: 'AttenuatingGrants.Signing.inst_holds_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Signing.inst_holds_eq

/-- info: 'AttenuatingGrants.Signing.extracted_allows' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Signing.extracted_allows

/-- info: 'AttenuatingGrants.Signing.extracted_allowsAll' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Signing.extracted_allowsAll

/-- info: 'AttenuatingGrants.Signing.implements' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Signing.implements

/-- info: 'AttenuatingGrants.Signing.implementsAll' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Signing.implementsAll

/-- info: 'AttenuatingGrants.Signing.extracted_narrower_of_subset' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Signing.extracted_narrower_of_subset

/-- info: 'AttenuatingGrants.Signing.extracted_narrower_push' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Signing.extracted_narrower_push

/-- info: 'AttenuatingGrants.Signing.extracted_delegates_narrower' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Signing.extracted_delegates_narrower

/-- info: 'AttenuatingGrants.Signing.extracted_allowsAll_of_delegates' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Signing.extracted_allowsAll_of_delegates

/-! ## Extracted evaluator: Files -/

/-- info: 'AttenuatingGrants.Files.denoteGrant_allows' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Files.denoteGrant_allows

/-- info: 'AttenuatingGrants.Files.mode_eq_eq' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Files.mode_eq_eq

/-- info: 'AttenuatingGrants.Files.mode_in_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Files.mode_in_eq

/-- info: 'AttenuatingGrants.Files.isPrefix_denotePath' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Files.isPrefix_denotePath

/-- info: 'AttenuatingGrants.Files.isPrefix_length_le' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Files.isPrefix_length_le

/-- info: 'AttenuatingGrants.Files.is_prefix_loop_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Files.is_prefix_loop_eq

/-- info: 'AttenuatingGrants.Files.slice_len_gt' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Files.slice_len_gt

/-- info: 'AttenuatingGrants.Files.is_prefix_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Files.is_prefix_eq

/-- info: 'AttenuatingGrants.Files.holds_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Files.holds_eq

/-- info: 'AttenuatingGrants.Files.inst_holds_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Files.inst_holds_eq

/-- info: 'AttenuatingGrants.Files.extracted_allows' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Files.extracted_allows

/-- info: 'AttenuatingGrants.Files.extracted_allowsAll' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Files.extracted_allowsAll

/-- info: 'AttenuatingGrants.Files.implements' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Files.implements

/-- info: 'AttenuatingGrants.Files.implementsAll' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Files.implementsAll

/-- info: 'AttenuatingGrants.Files.extracted_narrower_of_subset' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Files.extracted_narrower_of_subset

/-- info: 'AttenuatingGrants.Files.extracted_narrower_push' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Files.extracted_narrower_push

/-- info: 'AttenuatingGrants.Files.extracted_delegates_narrower' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Files.extracted_delegates_narrower

/-- info: 'AttenuatingGrants.Files.extracted_allowsAll_of_delegates' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Files.extracted_allowsAll_of_delegates

/-! ## Extracted evaluator: Chain -/

/-- info: 'AttenuatingGrants.Chain.denoteGrant_allows' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.denoteGrant_allows

/-- info: 'AttenuatingGrants.Chain.i128_bv_inj' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Chain.i128_bv_inj

/-- info: 'AttenuatingGrants.Chain.denoteU64_inj' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Chain.denoteU64_inj

/-- info: 'AttenuatingGrants.Chain.val_eq_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.val_eq_eq

/-- info: 'AttenuatingGrants.Chain.extracted_val_eq_kind' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.extracted_val_eq_kind

/-- info: 'AttenuatingGrants.Chain.extracted_val_eq_other_bytes' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.extracted_val_eq_other_bytes

/-- info: 'AttenuatingGrants.Chain.slice_get_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.slice_get_eq

/-- info: 'AttenuatingGrants.Chain.cast_index_val' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Chain.cast_index_val

/-- info: 'AttenuatingGrants.Chain.holds_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.holds_eq

/-- info: 'AttenuatingGrants.Chain.inst_holds_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.inst_holds_eq

/-- info: 'AttenuatingGrants.Chain.extracted_allows' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.extracted_allows

/-- info: 'AttenuatingGrants.Chain.extracted_allowsAll' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.extracted_allowsAll

/-- info: 'AttenuatingGrants.Chain.implements' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.implements

/-- info: 'AttenuatingGrants.Chain.implementsAll' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.implementsAll

/-- info: 'AttenuatingGrants.Chain.extracted_denies_createContract' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.extracted_denies_createContract

/-- info: 'AttenuatingGrants.Chain.extracted_narrower_of_subset' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.extracted_narrower_of_subset

/-- info: 'AttenuatingGrants.Chain.extracted_narrower_push' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.extracted_narrower_push

/-- info: 'AttenuatingGrants.Chain.extracted_delegates_narrower' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.extracted_delegates_narrower

/-- info: 'AttenuatingGrants.Chain.extracted_allowsAll_of_delegates' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Chain.extracted_allowsAll_of_delegates

/-! ## Budgets (theorem 4) -/

/-- info: 'AttenuatingGrants.Budget.Ledger.mem_walk' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Budget.Ledger.mem_walk

/-- info: 'AttenuatingGrants.Budget.Ledger.spend_ok_charges' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.Ledger.spend_ok_charges

/-- info: 'AttenuatingGrants.Budget.Ledger.spend_ok_unchanged' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.Ledger.spend_ok_unchanged

/-- info: 'AttenuatingGrants.Budget.Ledger.spend_ok_length' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Budget.Ledger.spend_ok_length

/-- info: 'AttenuatingGrants.Budget.Ledger.spend_error' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Budget.Ledger.spend_error

/-- info: 'AttenuatingGrants.Budget.Ledger.spend_overdrawn' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Budget.Ledger.spend_overdrawn

/-- info: 'AttenuatingGrants.Budget.Ledger.parentOf_spend' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.Ledger.parentOf_spend

/-- info: 'AttenuatingGrants.Budget.Ledger.parentOf_refill' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Budget.Ledger.parentOf_refill

/-- info: 'AttenuatingGrants.Budget.Ledger.spend_withinAllowance' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.Ledger.spend_withinAllowance

/-- info: 'AttenuatingGrants.Budget.Ledger.refill_withinAllowance' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Budget.Ledger.refill_withinAllowance

/-- info: 'AttenuatingGrants.Budget.Ledger.run_withinAllowance' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.Ledger.run_withinAllowance

/-- info: 'AttenuatingGrants.Budget.Ledger.spend_bounded' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.Ledger.spend_bounded

/-- info: 'AttenuatingGrants.Budget.Ledger.refill_bounded' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Budget.Ledger.refill_bounded

/-- info: 'AttenuatingGrants.Budget.Ledger.spent_run' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.Ledger.spent_run

/-- info: 'AttenuatingGrants.Budget.Ledger.spentUnder_le_allowance' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.Ledger.spentUnder_le_allowance

/-- info: 'AttenuatingGrants.Budget.Ledger.append_ok_iff' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Budget.Ledger.append_ok_iff

/-- info: 'AttenuatingGrants.Budget.Ledger.append_error' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Budget.Ledger.append_error

/-- info: 'AttenuatingGrants.Budget.Ledger.getElem?_append_of_lt' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Budget.Ledger.getElem?_append_of_lt

/-- info: 'AttenuatingGrants.Budget.Ledger.append_withinAllowance' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Budget.Ledger.append_withinAllowance

/-- info: 'AttenuatingGrants.Budget.Ledger.append_bounded' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Budget.Ledger.append_bounded

/-- info: 'AttenuatingGrants.Budget.Ledger.spend_parentsFirst' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.Ledger.spend_parentsFirst

/-- info: 'AttenuatingGrants.Budget.Ledger.refill_parentsFirst' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Budget.Ledger.refill_parentsFirst

/-- info: 'AttenuatingGrants.Budget.Ledger.append_parentsFirst' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms Budget.Ledger.append_parentsFirst

/-- info: 'AttenuatingGrants.Budget.Ledger.run_parentsFirst' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.Ledger.run_parentsFirst

/-- info: 'AttenuatingGrants.Budget.Ledger.run_extends' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.Ledger.run_extends

/-- info: 'AttenuatingGrants.Budget.Ledger.within_of_walk' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Budget.Ledger.within_of_walk

/-- info: 'AttenuatingGrants.Budget.Ledger.parentOf_run' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.Ledger.parentOf_run

/-- info: 'AttenuatingGrants.Budget.Ledger.spentUnder_run' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.Ledger.spentUnder_run

/-! ## Extracted evaluator: Budgets -/

/-- info: 'AttenuatingGrants.Budget.denoteLedger_injective' depends on axioms: [propext] -/
#guard_msgs in
#print axioms Budget.denoteLedger_injective

/-- info: 'AttenuatingGrants.Budget.fits_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.fits_eq

/-- info: 'AttenuatingGrants.Budget.extracted_check_spend' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.extracted_check_spend

/-- info: 'AttenuatingGrants.Budget.charge_loop_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.charge_loop_eq

/-- info: 'AttenuatingGrants.Budget.extracted_spend' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.extracted_spend

/-- info: 'AttenuatingGrants.Budget.extracted_spend_error' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.extracted_spend_error

/-- info: 'AttenuatingGrants.Budget.extracted_refill' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.extracted_refill

/-- info: 'AttenuatingGrants.Budget.extracted_refill_error' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.extracted_refill_error

/-- info: 'AttenuatingGrants.Budget.extracted_append' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.extracted_append

/-- info: 'AttenuatingGrants.Budget.extracted_append_error' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.extracted_append_error

/-- info: 'AttenuatingGrants.Budget.extracted_spend_ok_charges' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.extracted_spend_ok_charges

/-- info: 'AttenuatingGrants.Budget.extracted_spend_ok_unchanged' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.extracted_spend_ok_unchanged

/-- info: 'AttenuatingGrants.Budget.extracted_spend_ok_length' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.extracted_spend_ok_length

/-- info: 'AttenuatingGrants.Budget.extracted_spend_overdrawn' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.extracted_spend_overdrawn

/-- info: 'AttenuatingGrants.Budget.extracted_spend_withinAllowance' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.extracted_spend_withinAllowance

/-- info: 'AttenuatingGrants.Budget.extracted_refill_withinAllowance' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.extracted_refill_withinAllowance

/-- info: 'AttenuatingGrants.Budget.extracted_append_withinAllowance' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.extracted_append_withinAllowance

/-- info: 'AttenuatingGrants.Budget.extracted_run' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.extracted_run

/-- info: 'AttenuatingGrants.Budget.extracted_run_withinAllowance' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.extracted_run_withinAllowance

/-- info: 'AttenuatingGrants.Budget.extracted_spentUnder_le_allowance' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms Budget.extracted_spentUnder_le_allowance

end AttenuatingGrants
