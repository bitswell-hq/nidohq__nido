import AttenuatingGrants.Grant
import AttenuatingGrants.Vocab.Chain
import AttenuatingGrants.Vocab.Files
import AttenuatingGrants.Vocab.Network
import AttenuatingGrants.Vocab.Signing
import AttenuatingGrants.Cost.Chain
import AttenuatingGrants.Cost.Files
import AttenuatingGrants.Cost.Network
import AttenuatingGrants.Cost.Signing

/-!
# Axioms

Each delivered theorem depends on at most Lean's built-in axioms (`propext`,
`Quot.sound`, `Classical.choice`): no `sorryAx`, no `Lean.ofReduceBool`, and
nothing declared by this package. `#guard_msgs` fails the build if any of these
dependency lists changes.
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

end AttenuatingGrants
