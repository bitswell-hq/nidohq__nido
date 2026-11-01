import EmailRecovery.Merkle
import EmailRecovery.Pack

/-!
# The email circuit's relation

The commitment (spec §5.3), the DKIM key hash and registry leaf (§7.1, §7.2),
the salted pin tree (§7.4), the blinded Subject token (§4.2), and the relation
the circuit proves between its four public inputs (§6.1) and its private inputs
(§6.2), one field per obligation C1 to C6.

The header-level functions (which bytes are the `From` address, the Subject
value, the `d=` value, and so on) are abstract (`Format`): the relation is stated
in their terms, and computing them as §4.3 and §4.5 say is the circuit's
obligation, outside this model.
-/

namespace EmailRecovery

/-- The header-level functions the circuit computes. -/
structure Format where
  /-- C2: `H` is a well-formed signed header block under §4.3 rules 3 to 6. -/
  wellFormed : Bytes → Prop
  /-- The `addr-spec` of the single signed `from` field (§4.5); `none` when the
  field is missing or repeated, or its value does not parse. -/
  fromAddr : Bytes → Option Bytes
  /-- The value of the single signed `subject` field; `none` when it is missing
  or repeated. -/
  subject : Bytes → Option Bytes
  /-- The `d=` value of the selected `DKIM-Signature` field (§4.3 rule 1). -/
  dkimDomain : Bytes → Option Bytes
  /-- The domain of an `addr-spec`. -/
  domainOf : Bytes → Bytes
  /-- ASCII lowercase. -/
  lower : Bytes → Bytes
  /-- `hex(x)` (spec §2). -/
  hex : Nat → Bytes
  /-- The 18 little-endian 120-bit limbs of an RSA-2048 modulus (§7.1). -/
  limbs : Nat → List Nat
  /-- The EMSA-PKCS1-v1_5 encoding of a SHA-256 digest, as a 2048-bit integer. -/
  emsa : Nat → Nat

variable (H : Hashes) (F : Format)

/-- Spec §5.3: `C = P2(DOM_COMMIT, len, a_0, a_1, a_2, a_3, account_code)`. -/
def commit (address : Bytes) (code : Nat) : Nat :=
  H.p2 ([domCommit, address.length] ++ pack address 124 ++ [code])

/-- Spec §7.1: `key_hash = P2(DOM_KEY, n_0, ..., n_17)`. -/
def keyHash (n : Nat) : Nat := H.p2 (domKey :: F.limbs n)

/-- Spec §7.2: `leaf = P2(DOM_LEAF, len(domain), d_0, d_1, key_hash)`. -/
def keyLeaf (domain : Bytes) (kh : Nat) : Nat :=
  H.p2 ([domLeaf, domain.length] ++ pack domain 62 ++ [kh])

/-- Spec §7.4: the pin tree's leaf 0, `P2(DOM_PIN_SALT, account_code)`. -/
def saltLeaf (code : Nat) : Nat := H.p2 [domPinSalt, code]

/-- The pin tree's leaves: the salt leaf at 0, the pinned key leaves at
`1 .. k`, empty leaves after them (§7.4). -/
def pinLeaf (code : Nat) (keys : List Nat) : Nat → Nat
  | 0 => saltLeaf H code
  | i + 1 => keys.getD i 0

/-- The pin root the enrolling wallet computes. -/
def pinRoot (code : Nat) (keys : List Nat) : Nat := treeRoot H treeDepth (pinLeaf H code keys)

/-- Spec §4.2: `T = P2(DOM_BLIND, digest_hi, digest_lo, rho)`. -/
def blind (d rho : Nat) : Nat := H.p2 [domBlind, hi d, lo d, rho]

/-- The bytes of an ASCII string. -/
def ascii (s : String) : Bytes := s.toList.map fun c => c.toNat.toUInt8

/-- The 30-byte recovery phrase, with its trailing space (§4.2). -/
def recoveryPhrase : Bytes := ascii "APPROVE NIDO ACCOUNT RECOVERY "

/-- The enrollment phrase (§5.4). -/
def enrollPhrase : Bytes := ascii "ENROLL NIDO ACCOUNT RECOVERY "

theorem recoveryPhrase_length : recoveryPhrase.length = 30 := by decide

/-- An enrollment Subject never satisfies C5: the two phrases differ in their
first byte, whatever follows them. -/
theorem enroll_subject_ne_recovery_subject (x y : Bytes) :
    enrollPhrase ++ x ≠ recoveryPhrase ++ y := by
  intro h
  have he : enrollPhrase.head? = some 69 := by decide
  have hr : recoveryPhrase.head? = some 65 := by decide
  have := congrArg List.head? h
  rw [List.head?_append, List.head?_append, he, hr] at this
  simp at this

/-- C1: `s < n`, `n` has exactly 2048 bits, and `s^65537 mod n` is the
EMSA-PKCS1-v1_5 encoding of `SHA-256(H)`. -/
def RsaValid (n s : Nat) (header : Bytes) : Prop :=
  s < n ∧ 2 ^ 2047 ≤ n ∧ n < 2 ^ 2048 ∧ s ^ 65537 % n = F.emsa (H.sha256 header)

/-- The circuit's public inputs, in order (§6.1). -/
structure PublicInputs where
  commitment : Nat
  digestHi : Nat
  digestLo : Nat
  keyRoot : Nat
  deriving DecidableEq, Repr

/-- The circuit's private inputs (§6.2). The positions of the `From` address,
the Subject token and the `d=` value are represented by the values at those
positions. -/
structure Witness where
  header : Bytes
  signature : Nat
  modulus : Nat
  address : Bytes
  dkimD : Bytes
  rho : Nat
  accountCode : Nat
  leafDomain : Bytes
  leafIndex : Nat
  siblings : List Nat

/-- The circuit relation, one field per obligation of §6.2. -/
structure Relation (x : PublicInputs) (w : Witness) : Prop where
  /-- C1 -/
  signed : RsaValid H F w.modulus w.signature w.header
  /-- C2 -/
  wellFormed : F.wellFormed w.header
  /-- C3: exactly one `from` field, parsing to `addr-spec` -/
  fromAddr : F.fromAddr w.header = some w.address
  /-- C3: `1 ≤ len(addr-spec) ≤ ADDR_MAX` -/
  addressLength : 1 ≤ w.address.length ∧ w.address.length ≤ 124
  /-- C3: the address and `account_code` open `C` -/
  opensCommitment : commit H w.address w.accountCode = x.commitment
  /-- C4: the selected signature's `d=` -/
  dkimDomain : F.dkimDomain w.header = some w.dkimD
  /-- C4: `lowercase(domain(addr-spec)) = lowercase(d=)` -/
  aligned : F.lower (F.domainOf w.address) = F.lower w.dkimD
  /-- C4: `lowercase(d=) = leaf domain` -/
  leafDomain : F.lower w.dkimD = w.leafDomain
  /-- C5: exactly one `subject` field, the phrase and `hex(T)` for the digest limbs -/
  subject : F.subject w.header =
    some (recoveryPhrase ++ F.hex (H.p2 [domBlind, x.digestHi, x.digestLo, w.rho]))
  /-- C6: the leaf index decomposes into `treeDepth` bits -/
  leafIndex : w.leafIndex < 2 ^ treeDepth
  /-- C6: one sibling per level -/
  siblings : w.siblings.length = treeDepth
  /-- C6: the leaf domain fits its two limbs -/
  leafDomainLength : 1 ≤ w.leafDomain.length ∧ w.leafDomain.length ≤ 62
  /-- C6: the path from the key's leaf reaches `key_root` -/
  path : pathRoot H (keyLeaf H w.leafDomain (keyHash H F w.modulus)) w.leafIndex w.siblings =
    x.keyRoot

/-- The commitment binds the address and `account_code`, unless Poseidon2
collides. -/
theorem commit_binds {a b : Bytes} {c d : Nat} (ha : a.length ≤ 124)
    (h : commit H a c = commit H b d) : (a = b ∧ c = d) ∨ H.P2Collision := by
  rcases H.p2_eq h with h | h
  · simp only [List.cons_append, List.cons.injEq, true_and] at h
    obtain ⟨hlen, h⟩ := h
    have hpack : pack a (31 * 4) = pack b (31 * 4) := List.append_inj_left h (by simp [pack_length])
    have hcode : [c] = [d] := List.append_inj_right h (by simp [pack_length])
    simp only [List.cons.injEq, and_true] at hcode
    exact Or.inl ⟨pack_injective hlen (by omega) hpack, hcode⟩
  · exact Or.inr h

end EmailRecovery
