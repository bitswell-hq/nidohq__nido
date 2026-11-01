import EmailRecovery.Guardian

/-!
# Theorem 1: soundness of the email factor (spec §11.2 item 1)

`email_of_check`: if the guardian's `__check_auth` succeeds, then the verifier's
knowledge-soundness extractor (A4) yields an email whose signed header block
carries a valid RSA-2048 DKIM signature under a key whose leaf is in the tree of
the accepted root, whose `From` address opens the guardian's commitment, whose
domain is the `d=` value and the leaf domain, and whose Subject opens to the
authorized digest; and the digest's preimage names this guardian's account,
controller and network, an allowed action and an unexpired bound.

`soundness` adds the registry (A5) and the honest enrollment (A7): the `From`
address is the enrolled address and the key's leaf is a trusted leaf, unless
Poseidon2 collides or maps an input to the empty leaf.

What is not in these statements, and why: A1 (DKIM unforgeability) is the step
from "a valid signature under the provider's key exists" to "the provider signed
this header", a computational claim with no meaningful statement here; it
starts where the conclusion ends.
-/

namespace EmailRecovery

/-- Assumption A4 (knowledge soundness), idealized: an extractor that returns a
witness of the circuit relation for every proof the verifier accepts. The
computational statement (an efficient extractor that succeeds except with
negligible probability against every efficient prover) cannot be stated in this
model; this structure is its deterministic form. -/
structure Extractor (H : Hashes) (F : Format) (verify : PublicInputs → Bytes → VerifyResult) where
  extract : PublicInputs → Bytes → Witness
  sound : ∀ x π, verify x π = .ok → Relation H F x (extract x π)

/-- Spec §11.2 item 1: the context and statement an approval was accepted for,
and the email its proof establishes. -/
structure EmailFactor (H : Hashes) (F : Format) (E : Encoding) (c : GuardianConfig) (env : Env)
    (ap : Approval) (contexts : List AuthContext) (fn : Fn) (d : Nat) (v : View) (w : Witness) :
    Prop where
  /-- The only context is `controller.fn((d,))`. -/
  context : contexts = [AuthContext.approval c.controller fn d]
  /-- `d = sha256(S)` for the statement bytes `S` of the approval. -/
  statementDigest : H.sha256 ap.statement = d
  /-- `S` names this guardian's account, controller and network. -/
  statementView : E.parseView ap.statement = some v
  account : v.account = c.account
  controller : v.controller = c.controller
  network : v.network = env.network
  /-- `S` carries an allowed action, approved through its own entry point. -/
  allowed : c.allows v.action = true
  entryPoint : fn = entryPoint v.action
  /-- `S` has not expired at this ledger. -/
  unexpired : env.ledger ≤ v.validUntil
  /-- The root is the unexpired pin or a root the registry accepts now. -/
  root : RootAccepted c env ap.keyRoot
  /-- `H` carries a valid DKIM RSA-2048 signature under `n` (C1). -/
  signed : RsaValid H F w.modulus w.signature w.header
  /-- `H` is a well-formed signed header block (C2). -/
  wellFormed : F.wellFormed w.header
  /-- `leaf(domain, key_hash(n))` is in the tree with the accepted root (C6). -/
  leafIndex : w.leafIndex < 2 ^ treeDepth
  siblings : w.siblings.length = treeDepth
  keyInTree :
    pathRoot H (keyLeaf H w.leafDomain (keyHash H F w.modulus)) w.leafIndex w.siblings = ap.keyRoot
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

/-- Guardian acceptance, the circuit relation, and knowledge soundness imply the
email statement of §11.2 item 1. -/
theorem email_of_check (X : Extractor H F (env.verifier c.verifier))
    (h : check H E c env p ap contexts = .ok ()) :
    ∃ fn d v w, EmailFactor H F E c env ap contexts fn d v w := by
  obtain ⟨fn, d, v, a⟩ := accepted_of_check h
  have r := X.sound _ _ a.proof
  exact ⟨fn, d, v, X.extract (publicInputs c d ap.keyRoot) ap.proof,
    a.context, a.digest, a.parsed, a.account, a.controller, a.network, a.allowed, a.entryPoint,
    a.fresh, a.root, r.signed, r.wellFormed, r.leafIndex, r.siblings, r.path, r.fromAddr,
    r.addressLength.2, r.opensCommitment, r.dkimDomain, r.aligned, r.leafDomain, r.subject⟩

/-! ## The enrolled address and the trusted key -/

/-- Assumption A7 for the commitment: the enrolling wallet computed `C` from the
enrollment email's `From` address (at most `ADDR_MAX` bytes) and the account
code it drew. -/
def HonestCommitment (H : Hashes) (c : GuardianConfig) (address : Bytes) (code : Nat) : Prop :=
  address.length ≤ 124 ∧ c.commitment = commit H address code

/-- Assumption A5, with §7.3 rule 4: every root the registry accepts is the root
of a depth-16 tree whose non-empty leaves are `Trusted` (each a leaf for a key
its domain's operator controls). -/
def RegistryTrees (H : Hashes) (env : Env) (registry : Nat) (Trusted : Nat → Prop) : Prop :=
  ∀ root, env.registry registry root = some true →
    ∃ f : Nat → Nat, treeRoot H treeDepth f = root ∧ ∀ i, f i ≠ 0 → Trusted (f i)

/-- Assumption A7 for the pin: a pinned root is the root the enrolling wallet
computed from its account code and `Trusted` key leaves (§7.4). -/
def HonestPin (H : Hashes) (c : GuardianConfig) (Trusted : Nat → Prop) : Prop :=
  ∀ q, c.pin = some q → ∃ code keys, q.root = pinRoot H code keys ∧ ∀ k ∈ keys, Trusted k

/-- The `From` address of an accepted email is the enrolled address, unless
Poseidon2 collides. -/
theorem from_is_enrolled {fn : Fn} {d : Nat} {v : View} {w : Witness} {address : Bytes}
    {code : Nat} (e : EmailFactor H F E c env ap contexts fn d v w)
    (hc : HonestCommitment H c address code) :
    (w.address = address ∧ w.accountCode = code) ∨ H.P2Collision :=
  commit_binds H e.addressLength (e.committed.trans hc.2)

/-- No key leaf can stand for the salt leaf: their inputs have different counts. -/
theorem keyLeaf_ne_saltLeaf_or {domain : Bytes} {kh code : Nat}
    (h : keyLeaf H domain kh = saltLeaf H code) : H.P2Collision := by
  refine ⟨_, _, ?_, h⟩
  intro heq
  have := congrArg List.length heq
  simp [pack_length] at this

/-- A key leaf at a position of a tree of `Trusted` leaves is `Trusted`, unless
Poseidon2 maps it to the empty leaf. -/
theorem trusted_of_slot {Trusted : Nat → Prop} {f : Nat → Nat} {i leaf : Nat}
    (hf : ∀ i, f i ≠ 0 → Trusted (f i)) (hi : f i = leaf) (hleaf : ∃ xs, H.p2 xs = leaf) :
    Trusted leaf ∨ H.P2HitsZero := by
  by_cases h0 : leaf = 0
  · obtain ⟨xs, hxs⟩ := hleaf
    exact Or.inr ⟨xs, hxs.trans h0⟩
  · exact Or.inl (hi ▸ hf i (hi ▸ h0))

/-- The key behind an accepted email has a `Trusted` leaf, unless Poseidon2
collides or maps an input to the empty leaf. -/
theorem key_is_trusted {Trusted : Nat → Prop} {fn : Fn} {d : Nat} {v : View} {w : Witness}
    (e : EmailFactor H F E c env ap contexts fn d v w)
    (hreg : RegistryTrees H env c.registry Trusted) (hpin : HonestPin H c Trusted) :
    Trusted (keyLeaf H w.leafDomain (keyHash H F w.modulus)) ∨ H.P2Collision ∨ H.P2HitsZero := by
  have hleaf : ∃ xs, H.p2 xs = keyLeaf H w.leafDomain (keyHash H F w.modulus) := ⟨_, rfl⟩
  rcases e.root with ⟨q, hq, hroot, _⟩ | hr
  · obtain ⟨code, keys, hqr, hkeys⟩ := hpin q hq
    have hpath : pathRoot H (keyLeaf H w.leafDomain (keyHash H F w.modulus)) w.leafIndex
        w.siblings = treeRoot H treeDepth (pinLeaf H code keys) := by
      rw [e.keyInTree, ← hroot, hqr]; rfl
    rcases path_binds e.siblings e.leafIndex hpath with hslot | hcoll
    · cases hi : w.leafIndex with
      | zero =>
        rw [hi] at hslot
        exact Or.inr (Or.inl (keyLeaf_ne_saltLeaf_or hslot.symm))
      | succ i =>
        rw [hi] at hslot
        simp only [pinLeaf] at hslot
        by_cases hlt : i < keys.length
        · simp only [List.getD, List.getElem?_eq_getElem hlt, Option.getD_some] at hslot
          exact Or.inl (hslot ▸ hkeys _ (List.getElem_mem hlt))
        · simp only [List.getD, List.getElem?_eq_none (Nat.le_of_not_lt hlt),
            Option.getD_none] at hslot
          obtain ⟨xs, hxs⟩ := hleaf
          exact Or.inr (Or.inr ⟨xs, hxs.trans hslot.symm⟩)
    · exact Or.inr (Or.inl hcoll)
  · obtain ⟨f, hroot, hf⟩ := hreg _ hr
    rcases path_binds e.siblings e.leafIndex (e.keyInTree.trans hroot.symm) with hslot | hcoll
    · rcases trusted_of_slot hf hslot hleaf with h | h
      · exact Or.inl h
      · exact Or.inr (Or.inr h)
    · exact Or.inr (Or.inl hcoll)

/-! ## Theorem 1 -/

/-- The hypotheses of Theorem 1, by spec §11.1 id. A2 does not appear (the
guardian's own checks need no hash property), and A3's collision resistance
appears as the named breaks of the conclusion. -/
structure SoundnessAssumptions (H : Hashes) (F : Format) (c : GuardianConfig) (env : Env)
    (Trusted : Nat → Prop) where
  /-- A4: knowledge soundness of the verifier the guardian is configured with. -/
  extractor : Extractor H F (env.verifier c.verifier)
  /-- A5: the registry's accepted roots are trees of trusted leaves. -/
  registry : RegistryTrees H env c.registry Trusted
  /-- A7: the enrolled address and account code the wallet committed to. -/
  enrolledAddress : Bytes
  enrolledCode : Nat
  commitment : HonestCommitment H c enrolledAddress enrolledCode
  /-- A7: the pin holds only trusted leaves. -/
  pin : HonestPin H c Trusted

/-- **Theorem 1 (soundness of the email factor).** If the email guardian accepts
an approval, there is an email satisfying §11.2 item 1 (`EmailFactor`) whose
`From` address is the enrolled address and whose key has a trusted leaf, unless
Poseidon2 collides or maps an input to the empty leaf. -/
theorem soundness {Trusted : Nat → Prop} (A : SoundnessAssumptions H F c env Trusted)
    (h : check H E c env p ap contexts = .ok ()) :
    ∃ fn d v w, EmailFactor H F E c env ap contexts fn d v w ∧
      ((w.address = A.enrolledAddress ∧ Trusted (keyLeaf H w.leafDomain (keyHash H F w.modulus)))
        ∨ H.P2Collision ∨ H.P2HitsZero) := by
  obtain ⟨fn, d, v, w, e⟩ := email_of_check A.extractor h
  refine ⟨fn, d, v, w, e, ?_⟩
  rcases from_is_enrolled e A.commitment with ⟨ha, _⟩ | hcoll
  · rcases key_is_trusted e A.registry A.pin with ht | hbreak
    · exact Or.inl ⟨ha, ht⟩
    · exact Or.inr hbreak
  · exact Or.inr (Or.inl hcoll)

end EmailRecovery
