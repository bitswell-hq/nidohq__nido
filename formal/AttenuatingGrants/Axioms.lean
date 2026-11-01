import AttenuatingGrants.Grant
import AttenuatingGrants.Vocab.Chain
import AttenuatingGrants.Vocab.Files
import AttenuatingGrants.Vocab.Network
import AttenuatingGrants.Vocab.Signing

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

end AttenuatingGrants
