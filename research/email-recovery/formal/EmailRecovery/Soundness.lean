import EmailRecovery.Guardian

/-!
# Theorem 1: soundness of the email factor (spec §11.2 item 1)

Both theorems are statements about one accepted approval, and each names the
break it reduces to on that approval's own data.

`email_of_check`: if the guardian's `__check_auth` succeeds, every check of
§8.3 holds (`Accepted`), and for every extractor `X`, either the witness `X`
returns for the approval's proof satisfies the circuit relation, so it is an
email (`SignedEmail`) whose signed header block carries a valid RSA-2048 DKIM
signature under a modulus whose leaf is in the tree of the accepted root, whose
`From` address opens the guardian's commitment, whose domain is the `d=` value
and the leaf domain, and whose Subject opens to the authorized digest; or `X`
fails on this accepted proof (`ExtractionFails`, the break of A4).

`soundness` adds the registry (A5) and the honest enrollment (A7): the email's
`From` address and account code are the enrolled ones and its modulus is a
trusted key of the leaf domain, unless one of the Poseidon2 breaks
`SoundnessBreak` lists holds, each on inputs computed from the extracted
witness, the enrollment and the accepted root's tree.

Knowledge soundness is not a hypothesis. The theorems hold for every function
`X`; A4 is the computational statement that the proof system has an efficient
extractor (which may use the prover's code) for which an efficient prover
makes the guardian accept a proof on which `ExtractionFails` holds only with
negligible probability.

What is not in these statements, and why: A1 (DKIM unforgeability) is the step
from "a valid signature under the provider's key exists" to "the provider signed
this header", a computational claim with no meaningful statement here; it
starts where the conclusion ends.
-/

namespace EmailRecovery

/-- An extractor: a witness for each proof, as a function of its public inputs
and bytes. Any function is one. -/
abbrev Extractor := PublicInputs → Bytes → Witness

/-- The public inputs the guardian verifies an approval's proof against (§8.3
check 12): `C`, the limbs of the statement's digest, and the approval's root. -/
def approvalInputs (H : Hashes) (c : GuardianConfig) (ap : Approval) : PublicInputs :=
  publicInputs c (H.sha256 ap.statement) ap.keyRoot

/-- The witness `X` returns for an approval's proof. -/
def extracted (H : Hashes) (X : Extractor) (c : GuardianConfig) (ap : Approval) : Witness :=
  X (approvalInputs H c ap) ap.proof

/-- The break of A4 on one proof: the verifier accepts `π` for `x`, and the
witness `X` returns for it does not satisfy the circuit relation. -/
def ExtractionFails (H : Hashes) (F : Format) (verify : PublicInputs → Bytes → VerifyResult)
    (X : Extractor) (x : PublicInputs) (π : Bytes) : Prop :=
  verify x π = .ok ∧ ¬ Relation H F x (X x π)

/-- Spec §11.2 item 1, the email: what the circuit relation says about a witness
`w` of an approval `ap` that `c` accepted for digest `d`. -/
structure SignedEmail (H : Hashes) (F : Format) (c : GuardianConfig) (ap : Approval) (d : Nat)
    (w : Witness) : Prop where
  /-- `H` carries a valid DKIM RSA-2048 signature under `n` (C1). -/
  signed : RsaValid H F w.modulus w.signature w.header
  /-- `H` is a well-formed signed header block (C2). -/
  wellFormed : F.wellFormed w.header
  /-- `leaf(domain, key_hash(n))` is in the tree with the accepted root (C6). -/
  leafIndex : w.leafIndex < 2 ^ treeDepth
  siblings : w.siblings.length = treeDepth
  leafDomainLength : w.leafDomain.length ≤ 62
  keyInTree :
    pathRoot H (keyLeaf H w.leafDomain (keyHash H w.modulus)) w.leafIndex w.siblings = ap.keyRoot
  /-- The `From` address of `H` and an account code open `C` (C3). -/
  fromAddress : F.fromAddr w.header = some w.address
  addressLength : w.address.length ≤ 124
  committed : commit H w.address w.accountCode = c.commitment
  /-- The address's domain is `d=` and the leaf's domain (C4). -/
  dkimDomain : F.dkimDomain w.header = some w.dkimD
  aligned : F.lower (F.domainOf w.address) = F.lower w.dkimD
  leafDomain : F.lower w.dkimD = w.leafDomain
  /-- The Subject of `H` opens to `d` (C5). -/
  subject : F.subject w.header = some (recoveryPhrase ++ F.hex (blind H d w.rho))

variable {H : Hashes} {F : Format} {E : Encoding} {c : GuardianConfig} {env : Env} {p : Nat}
  {ap : Approval} {contexts : List AuthContext}

theorem signedEmail_of_relation {w : Witness} (r : Relation H F (approvalInputs H c ap) w) :
    SignedEmail H F c ap (H.sha256 ap.statement) w :=
  ⟨r.signed, r.wellFormed, r.leafIndex, r.siblings, r.leafDomainLength.2, r.path, r.fromAddr,
    r.addressLength.2, r.opensCommitment, r.dkimDomain, r.aligned, r.leafDomain, r.subject⟩

/-- Guardian acceptance establishes the twelve checks, and, for every extractor,
the email statement of §11.2 item 1 for the extracted witness, or the
extractor's failure on this accepted proof. -/
theorem email_of_check (X : Extractor) (h : check H E c env p ap contexts = .ok ()) :
    ∃ fn v, Accepted H E c env ap contexts fn (H.sha256 ap.statement) v ∧
      (SignedEmail H F c ap (H.sha256 ap.statement) (extracted H X c ap) ∨
        ExtractionFails H F (env.verifier c.verifier) X (approvalInputs H c ap) ap.proof) := by
  obtain ⟨fn, d, v, a⟩ := accepted_of_check h
  have hd := a.digest
  subst hd
  refine ⟨fn, v, a, ?_⟩
  by_cases r : Relation H F (approvalInputs H c ap) (extracted H X c ap)
  · exact Or.inl (signedEmail_of_relation r)
  · exact Or.inr ⟨a.proof, r⟩

/-! ## The enrolled address and the trusted key -/

/-- Assumption A7 for the commitment: the enrolling wallet computed `C` from the
enrollment email's `From` address (at most `ADDR_MAX` bytes) and the account
code it drew. -/
def HonestCommitment (H : Hashes) (c : GuardianConfig) (address : Bytes) (code : Nat) : Prop :=
  address.length ≤ 124 ∧ c.commitment = commit H address code

/-- The slots of a registry tree whose leaf `i` holds `keyAt i`. -/
def registrySlot (keyAt : Nat → Option (Bytes × Nat)) (i : Nat) : Slot :=
  match keyAt i with
  | some k => .key k.1 k.2
  | none => .empty

/-- Assumption A5, with §7.3 rule 4: the tree behind every root the registry
accepts. `keyAt root i` is the key `(domain, modulus)` at leaf `i` of that tree,
`none` for an empty leaf, and every key it holds is `Trusted` (a key its
domain's operator controls). -/
structure RegistryTrees (H : Hashes) (env : Env) (registry : Nat) (Trusted : Bytes → Nat → Prop) where
  keyAt : Nat → Nat → Option (Bytes × Nat)
  root : ∀ root, env.registry registry root = some true →
    treeRoot H treeDepth (fun i => (registrySlot (keyAt root) i).leaf H) = root
  trusted : ∀ root i k, env.registry registry root = some true → keyAt root i = some k →
    Trusted k.1 k.2

/-- Assumption A7 for the pin: a pinned root is the root the enrolling wallet
computed from the account code and the keys it pinned, each `Trusted` (§7.4). -/
def HonestPin (H : Hashes) (c : GuardianConfig) (code : Nat) (keys : List (Bytes × Nat))
    (Trusted : Bytes → Nat → Prop) : Prop :=
  (∀ q, c.pin = some q → q.root = pinRoot H code keys) ∧ ∀ k ∈ keys, Trusted k.1 k.2

/-- The hypotheses of Theorem 1, by spec §11.1 id. A2 does not appear (the
guardian's own checks need no hash property), A3's collision resistance appears
as the named breaks of the conclusion, and A4 as `ExtractionFails`. -/
structure SoundnessAssumptions (H : Hashes) (c : GuardianConfig) (env : Env)
    (Trusted : Bytes → Nat → Prop) where
  /-- A5: the registry's accepted roots are trees of trusted keys. -/
  registry : RegistryTrees H env c.registry Trusted
  /-- A7: the enrolled address and account code the wallet committed to. -/
  enrolledAddress : Bytes
  enrolledCode : Nat
  commitment : HonestCommitment H c enrolledAddress enrolledCode
  /-- A7: the keys the wallet pinned, each trusted. -/
  pinnedKeys : List (Bytes × Nat)
  pin : HonestPin H c enrolledCode pinnedKeys Trusted

variable {Trusted : Bytes → Nat → Prop}

namespace SoundnessAssumptions

/-- The slots of the tree behind a root check 11 accepted: the pin's tree when
the pin accepts the root (the check the guardian makes first), the registry's
otherwise. -/
def slot (A : SoundnessAssumptions H c env Trusted) (root : Nat) : Nat → Slot :=
  if c.pinned env.ledger root then pinSlot A.enrolledCode A.pinnedKeys
  else registrySlot (A.registry.keyAt root)

/-- The good outcome of Theorem 1 for a witness: the enrolled address and
account code, and a trusted key of the leaf domain. -/
def Enrolled (A : SoundnessAssumptions H c env Trusted) (w : Witness) : Prop :=
  w.address = A.enrolledAddress ∧ w.accountCode = A.enrolledCode ∧ Trusted w.leafDomain w.modulus

/-- The breaks Theorem 1 names for the key of witness `w` under root `root`,
on inputs computed from `w` and the root's tree: a collision on the pairs
`pathBreak` finds along `w`'s path, or the break of the slot at `w`'s leaf index
(`SlotBreak`: a collision with that slot's leaf input, a collision of key-hash
inputs, or the key's leaf input mapping to the empty leaf). -/
def KeyBreak (A : SoundnessAssumptions H c env Trusted) (root : Nat) (w : Witness) : Prop :=
  H.P2Collides (pathBreak H (fun i => (A.slot root i).leaf H)
      (keyLeaf H w.leafDomain (keyHash H w.modulus)) w.leafIndex w.siblings) ∨
    SlotBreak H w.leafDomain w.modulus (A.slot root w.leafIndex)

/-- Every break Theorem 1 names besides A4's: a collision of `w`'s commitment
input with the enrolled one, or a `KeyBreak`. -/
def Break (A : SoundnessAssumptions H c env Trusted) (root : Nat) (w : Witness) : Prop :=
  H.P2Collides (commitInput w.address w.accountCode, commitInput A.enrolledAddress A.enrolledCode) ∨
    A.KeyBreak root w

end SoundnessAssumptions

/-- The `From` address and account code of an accepted email are the enrolled
ones, unless the two commitment inputs collide. -/
theorem from_is_enrolled {d : Nat} {w : Witness} {address : Bytes} {code : Nat}
    (e : SignedEmail H F c ap d w) (hc : HonestCommitment H c address code) :
    (w.address = address ∧ w.accountCode = code) ∨
      H.P2Collides (commitInput w.address w.accountCode, commitInput address code) :=
  commit_binds e.addressLength (e.committed.trans hc.2)

theorem pinSlot_key {code : Nat} {keys : List (Bytes × Nat)} {i : Nat} {d : Bytes} {n : Nat}
    (h : pinSlot code keys i = .key d n) : (d, n) ∈ keys := by
  cases i with
  | zero => simp [pinSlot] at h
  | succ i =>
    simp only [pinSlot] at h
    split at h
    · rename_i k hk
      simp only [Slot.key.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      exact List.mem_of_getElem? hk
    · simp at h

theorem registrySlot_key {keyAt : Nat → Option (Bytes × Nat)} {i : Nat} {d : Bytes} {n : Nat}
    (h : registrySlot keyAt i = .key d n) : keyAt i = some (d, n) := by
  unfold registrySlot at h
  split at h
  · rename_i k hk
    simp only [Slot.key.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact hk
  · simp at h

/-- The tree behind the accepted root has that root. -/
theorem slot_root (A : SoundnessAssumptions H c env Trusted) {root : Nat}
    (h : RootAccepted c env root) :
    treeRoot H treeDepth (fun i => (A.slot root i).leaf H) = root := by
  unfold SoundnessAssumptions.slot
  by_cases hp : c.pinned env.ledger root = true
  · rw [ite_eq_left hp]
    unfold GuardianConfig.pinned at hp
    split at hp
    · rename_i q hq
      simp only [Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hp
      rw [← hp.1, A.pin.1 q hq]
      rfl
    · contradiction
  · rw [ite_eq_right hp]
    rcases h with ⟨q, hq, hqr, hl⟩ | hr
    · exact absurd (by simp [GuardianConfig.pinned, hq, hqr, hl]) hp
    · exact A.registry.root _ hr

/-- A key in the tree behind an accepted root is trusted. -/
theorem slot_trusted (A : SoundnessAssumptions H c env Trusted) {root i : Nat} {d : Bytes} {n : Nat}
    (h : RootAccepted c env root) (hk : A.slot root i = .key d n) : Trusted d n := by
  unfold SoundnessAssumptions.slot at hk
  by_cases hp : c.pinned env.ledger root = true
  · rw [ite_eq_left hp] at hk
    exact A.pin.2 _ (pinSlot_key hk)
  · rw [ite_eq_right hp] at hk
    have hr : env.registry c.registry root = some true := by
      rcases h with ⟨q, hq, hqr, hl⟩ | hr
      · exact absurd (by simp [GuardianConfig.pinned, hq, hqr, hl]) hp
      · exact hr
    exact A.registry.trusted root i _ hr (registrySlot_key hk)

/-- The modulus behind an accepted email is a trusted key of the leaf domain,
unless a `KeyBreak` holds. -/
theorem key_is_trusted (A : SoundnessAssumptions H c env Trusted) {d : Nat} {w : Witness}
    (e : SignedEmail H F c ap d w) (hroot : RootAccepted c env ap.keyRoot) :
    Trusted w.leafDomain w.modulus ∨ A.KeyBreak ap.keyRoot w := by
  rcases path_binds e.siblings e.leafIndex (e.keyInTree.trans (slot_root A hroot).symm)
    with hslot | hc
  · rcases slot_binds e.leafDomainLength hslot with hk | hb
    · exact Or.inl (slot_trusted A hroot hk)
    · exact Or.inr (Or.inr hb)
  · exact Or.inr (Or.inl hc)

/-! ## Theorem 1 -/

/-- **Theorem 1 (soundness of the email factor).** If the email guardian accepts
an approval, its twelve checks hold, and for every extractor `X`: the witness
`X` returns for the approval's proof is an email satisfying §11.2 item 1
(`SignedEmail`) whose `From` address and account code are the enrolled ones and
whose modulus is a trusted key of the leaf domain, unless a Poseidon2 break on
inputs computed from that witness, the enrollment and the accepted root's tree
holds (`SoundnessAssumptions.Break`); or `X` fails on this accepted proof
(`ExtractionFails`). -/
theorem soundness (X : Extractor) (A : SoundnessAssumptions H c env Trusted)
    (h : check H E c env p ap contexts = .ok ()) :
    ∃ fn v, Accepted H E c env ap contexts fn (H.sha256 ap.statement) v ∧
      ((SignedEmail H F c ap (H.sha256 ap.statement) (extracted H X c ap) ∧
          (A.Enrolled (extracted H X c ap) ∨ A.Break ap.keyRoot (extracted H X c ap))) ∨
        ExtractionFails H F (env.verifier c.verifier) X (approvalInputs H c ap) ap.proof) := by
  obtain ⟨fn, v, a, he⟩ := email_of_check (F := F) X h
  refine ⟨fn, v, a, ?_⟩
  rcases he with e | hx
  · refine Or.inl ⟨e, ?_⟩
    rcases from_is_enrolled e A.commitment with ⟨ha, hc⟩ | hcoll
    · rcases key_is_trusted A e a.root with ht | hb
      · exact Or.inl ⟨ha, hc, ht⟩
      · exact Or.inr (Or.inr hb)
    · exact Or.inr (Or.inl hcoll)
  · exact Or.inr hx

end EmailRecovery
