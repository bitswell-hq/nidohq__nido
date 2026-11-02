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
obligation, outside this model. The modulus limbs, the packing, `hex` and every
Poseidon2 input are the spec's formulas.

Each binding lemma (`commit_binds`, `keyHash_binds`, `keyLeaf_binds`,
`slot_binds`, `subject_binds_digest`) concludes that the hashed values are
equal, or names a Poseidon2 break on inputs it computes from its arguments.
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
  /-- The EMSA-PKCS1-v1_5 encoding of a SHA-256 digest, as a 2048-bit integer. -/
  emsa : Nat → Nat

/-! ## Modulus limbs (§7.1) -/

/-- `k + 1` little-endian limbs of 120 bits; the last holds every remaining
bit. -/
def limbs : Nat → Nat → List Nat
  | 0, n => [n]
  | k + 1, n => n % 2 ^ 120 :: limbs k (n / 2 ^ 120)

/-- §7.1: the 18 limbs `n_0, ..., n_17` of an RSA-2048 modulus. -/
def modulusLimbs (n : Nat) : List Nat := limbs 17 n

/-- `sum_i n_i * 2^(120 i)`. -/
def unlimbs : List Nat → Nat
  | [] => 0
  | l :: ls => l + 2 ^ 120 * unlimbs ls

theorem unlimbs_limbs : ∀ (k n : Nat), unlimbs (limbs k n) = n
  | 0, n => by simp [limbs, unlimbs]
  | k + 1, n => by simp only [limbs, unlimbs, unlimbs_limbs k]; exact Nat.mod_add_div n _

theorem limbs_length : ∀ (k n : Nat), (limbs k n).length = k + 1
  | 0, _ => rfl
  | k + 1, n => by simp [limbs, limbs_length k]

/-- Every limb of a number below `2 ^ (120 (k + 1))` is below `2 ^ 120`. -/
theorem limbs_lt : ∀ (k n : Nat), n < 2 ^ (120 * (k + 1)) → ∀ l ∈ limbs k n, l < 2 ^ 120
  | 0, n, hn, l, hl => by
    simp only [limbs, List.mem_singleton] at hl
    subst hl
    simpa using hn
  | k + 1, n, hn, l, hl => by
    simp only [limbs, List.mem_cons] at hl
    rcases hl with rfl | hl
    · exact Nat.mod_lt _ (Nat.pow_pos (by decide))
    · refine limbs_lt k (n / 2 ^ 120) ?_ l hl
      rw [Nat.div_lt_iff_lt_mul (Nat.pow_pos (by decide)), ← Nat.pow_add]
      have : 120 * (k + 1) + 120 = 120 * (k + 1 + 1) := by omega
      rw [this]
      exact hn

set_option exponentiation.threshold 2200 in
/-- The limbs are the spec's: 18 of them, each below `2 ^ 120`, recomposing to
the modulus. -/
theorem modulusLimbs_spec {n : Nat} (hn : n < 2 ^ 2048) :
    (modulusLimbs n).length = 18 ∧ (∀ l ∈ modulusLimbs n, l < 2 ^ 120) ∧
      unlimbs (modulusLimbs n) = n := by
  have hle : 2 ^ 2048 ≤ 2 ^ (120 * (17 + 1)) := Nat.pow_le_pow_right (by decide) (by decide)
  exact ⟨limbs_length 17 n, limbs_lt 17 n (Nat.lt_of_lt_of_le hn hle), unlimbs_limbs 17 n⟩

/-- Different moduli have different limbs. -/
theorem modulusLimbs_injective {n m : Nat} (h : modulusLimbs n = modulusLimbs m) : n = m := by
  rw [← unlimbs_limbs 17 n, ← unlimbs_limbs 17 m]
  exact congrArg unlimbs h

/-! ## `hex` (spec §2) -/

/-- The lowercase hexadecimal digit of `v < 16` as an ASCII byte (the circuit's
`hex_digit`: `v + 48` below 10, `v + 87` from 10). -/
def hexDigit (v : Nat) : UInt8 := if v < 10 then (v + 48).toUInt8 else (v + 87).toUInt8

/-- The last `k` hexadecimal digits of `x`, most significant first. -/
def hexDigits : Nat → Nat → Bytes
  | 0, _ => []
  | k + 1, x => hexDigits k (x / 16) ++ [hexDigit (x % 16)]

/-- `hex(x)`: the 64 lowercase hexadecimal characters of the 32-byte big-endian
encoding of a field element `x` (the circuit's `hex_of_field`, two digits per
byte of `x.to_be_bytes()`, high nibble first). -/
def hex (x : Nat) : Bytes := hexDigits 64 x

theorem hexDigits_length : ∀ (k x : Nat), (hexDigits k x).length = k
  | 0, _ => rfl
  | k + 1, x => by simp [hexDigits, hexDigits_length k]

theorem hex_length (x : Nat) : (hex x).length = 64 := hexDigits_length 64 x

/-- Different digits are different characters. -/
theorem hexDigit_injective : ∀ a, a < 16 → ∀ b, b < 16 → hexDigit a = hexDigit b → a = b := by
  decide

theorem hexDigits_injective :
    ∀ (k x y : Nat), x < 16 ^ k → y < 16 ^ k → hexDigits k x = hexDigits k y → x = y
  | 0, x, y, hx, hy, _ => by simp at hx hy; omega
  | k + 1, x, y, hx, hy, h => by
    simp only [hexDigits] at h
    obtain ⟨hhigh, hlow⟩ := List.append_inj h (by simp [hexDigits_length])
    simp only [List.cons.injEq, and_true] at hlow
    have hmod := hexDigit_injective _ (Nat.mod_lt x (by decide)) _ (Nat.mod_lt y (by decide)) hlow
    rw [Nat.pow_succ] at hx hy
    have hdiv := hexDigits_injective k (x / 16) (y / 16)
      ((Nat.div_lt_iff_lt_mul (by decide)).2 hx) ((Nat.div_lt_iff_lt_mul (by decide)).2 hy) hhigh
    rw [← Nat.div_add_mod x 16, ← Nat.div_add_mod y 16, hdiv, hmod]

/-- `hex` is injective on 32-byte values, so on field elements: a Subject's
64 characters determine its token. -/
theorem hex_injective {x y : Nat} (hx : x < 2 ^ 256) (hy : y < 2 ^ 256) (h : hex x = hex y) :
    x = y := by
  have e : (2 : Nat) ^ 256 = 16 ^ 64 := by decide
  rw [e] at hx hy
  exact hexDigits_injective 64 x y hx hy h

/-! ## Poseidon2 inputs and values -/

/-- The input of the commitment, spec §5.3:
`(DOM_COMMIT, len, a_0, a_1, a_2, a_3, account_code)`. -/
def commitInput (address : Bytes) (code : Nat) : List Nat :=
  [domCommit, address.length] ++ pack address 124 ++ [code]

/-- The input of the key hash, spec §7.1: `(DOM_KEY, n_0, ..., n_17)`. -/
def keyHashInput (n : Nat) : List Nat := domKey :: modulusLimbs n

/-- The input of a registry leaf, spec §7.2: `(DOM_LEAF, len(domain), d_0, d_1, key_hash)`. -/
def leafInput (domain : Bytes) (kh : Nat) : List Nat :=
  [domLeaf, domain.length] ++ pack domain 62 ++ [kh]

/-- The input of the pin tree's leaf 0, spec §7.4: `(DOM_PIN_SALT, account_code)`. -/
def saltInput (code : Nat) : List Nat := [domPinSalt, code]

/-- The input of the blinded Subject token, spec §4.2:
`(DOM_BLIND, digest_hi, digest_lo, rho)`. -/
def blindInput (d rho : Nat) : List Nat := [domBlind, hi d, lo d, rho]

variable (H : Hashes) (F : Format)

/-- `C`. -/
def commit (address : Bytes) (code : Nat) : Nat := H.p2 (commitInput address code)

/-- `key_hash`. -/
def keyHash (n : Nat) : Nat := H.p2 (keyHashInput n)

/-- A registry-format leaf. -/
def keyLeaf (domain : Bytes) (kh : Nat) : Nat := H.p2 (leafInput domain kh)

/-- The pin tree's salt leaf. -/
def saltLeaf (code : Nat) : Nat := H.p2 (saltInput code)

/-! ## Key-tree slots -/

/-- What a leaf of a key tree holds: a key `(domain, modulus)`, the pin's salt,
or nothing. -/
inductive Slot
  | key (domain : Bytes) (modulus : Nat)
  | salt (code : Nat)
  | empty
  deriving DecidableEq, Repr

/-- The leaf value of a slot (§7.2, §7.4): empty slots are `0`. -/
def Slot.leaf : Slot → Nat
  | .key domain n => keyLeaf H domain (keyHash H n)
  | .salt code => saltLeaf H code
  | .empty => 0

/-- The pin tree's slots (§7.4): the salt at 0, the pinned keys at `1 .. k`,
empty slots after them. -/
def pinSlot (code : Nat) (keys : List (Bytes × Nat)) : Nat → Slot
  | 0 => .salt code
  | i + 1 =>
    match keys[i]? with
    | some k => .key k.1 k.2
    | none => .empty

/-- The pin root the enrolling wallet computes from its account code and the
pinned keys. -/
def pinRoot (code : Nat) (keys : List (Bytes × Nat)) : Nat :=
  treeRoot H treeDepth fun i => (pinSlot code keys i).leaf H

/-- Spec §4.2: `T = P2(DOM_BLIND, digest_hi, digest_lo, rho)`. -/
def blind (d rho : Nat) : Nat := H.p2 (blindInput d rho)

/-- The bytes of an ASCII string. -/
def ascii (s : String) : Bytes := s.toList.map fun c => c.toNat.toUInt8

/-- The 30-byte recovery phrase, with its trailing space (§4.2). -/
def recoveryPhrase : Bytes := ascii "APPROVE NIDO ACCOUNT RECOVERY "

/-- The enrollment phrase (§5.4). -/
def enrollPhrase : Bytes := ascii "ENROLL NIDO ACCOUNT RECOVERY "

theorem recoveryPhrase_length : recoveryPhrase.length = 30 := by decide

/-- Lemma: the enrollment and recovery phrases differ in their first byte, so a
Subject that starts with the enrollment phrase never satisfies C5. A fact about
two constants, not a security property of its own. -/
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
    some (recoveryPhrase ++ hex (H.p2 [domBlind, x.digestHi, x.digestLo, w.rho]))
  /-- C6: the leaf index decomposes into `treeDepth` bits -/
  leafIndex : w.leafIndex < 2 ^ treeDepth
  /-- C6: one sibling per level -/
  siblings : w.siblings.length = treeDepth
  /-- C6: the leaf domain fits its two limbs -/
  leafDomainLength : 1 ≤ w.leafDomain.length ∧ w.leafDomain.length ≤ 62
  /-- C6: the path from the key's leaf reaches `key_root` -/
  path : pathRoot H (keyLeaf H w.leafDomain (keyHash H w.modulus)) w.leafIndex w.siblings =
    x.keyRoot

/-! ## Binding -/

variable {H}

/-- The commitment binds the address and `account_code`, unless the two
commitment inputs are a Poseidon2 collision. -/
theorem commit_binds {a b : Bytes} {c d : Nat} (ha : a.length ≤ 124)
    (h : commit H a c = commit H b d) :
    (a = b ∧ c = d) ∨ H.P2Collides (commitInput a c, commitInput b d) := by
  rcases H.p2_eq h with h | h
  · simp only [commitInput, List.cons_append, List.cons.injEq, true_and] at h
    obtain ⟨hlen, h⟩ := h
    have hpack : pack a (31 * 4) = pack b (31 * 4) := List.append_inj_left h (by simp [pack_length])
    have hcode : [c] = [d] := List.append_inj_right h (by simp [pack_length])
    simp only [List.cons.injEq, and_true] at hcode
    exact Or.inl ⟨pack_injective hlen (by omega) hpack, hcode⟩
  · exact Or.inr h

/-- The key hash binds the modulus, unless the two key-hash inputs are a
Poseidon2 collision. -/
theorem keyHash_binds {n m : Nat} (h : keyHash H n = keyHash H m) :
    n = m ∨ H.P2Collides (keyHashInput n, keyHashInput m) := by
  rcases H.p2_eq h with h | h
  · simp only [keyHashInput, List.cons.injEq, true_and] at h
    exact Or.inl (modulusLimbs_injective h)
  · exact Or.inr h

/-- A registry leaf binds its domain and key hash, unless the two leaf inputs
are a Poseidon2 collision. -/
theorem keyLeaf_binds {a b : Bytes} {k l : Nat} (ha : a.length ≤ 62)
    (h : keyLeaf H a k = keyLeaf H b l) :
    (a = b ∧ k = l) ∨ H.P2Collides (leafInput a k, leafInput b l) := by
  rcases H.p2_eq h with h | h
  · simp only [leafInput, List.cons_append, List.cons.injEq, true_and] at h
    obtain ⟨hlen, h⟩ := h
    have hpack : pack a (31 * 2) = pack b (31 * 2) := List.append_inj_left h (by simp [pack_length])
    have hkh : [k] = [l] := List.append_inj_right h (by simp [pack_length])
    simp only [List.cons.injEq, and_true] at hkh
    exact Or.inl ⟨pack_injective hlen (by omega) hpack, hkh⟩
  · exact Or.inr h

variable {F} in
/-- A Subject binds the digest: if one header's Subject opens to the digests
`d₁` and `d₂` (C5), they are equal, unless the two blinding inputs are a
Poseidon2 collision. -/
theorem subject_binds_digest {hdr : Bytes} {d₁ d₂ ρ₁ ρ₂ : Nat}
    (h₁ : F.subject hdr = some (recoveryPhrase ++ hex (blind H d₁ ρ₁)))
    (h₂ : F.subject hdr = some (recoveryPhrase ++ hex (blind H d₂ ρ₂))) :
    d₁ = d₂ ∨ H.P2Collides (blindInput d₁ ρ₁, blindInput d₂ ρ₂) := by
  have h := h₁.symm.trans h₂
  simp only [Option.some.injEq, List.append_cancel_left_eq] at h
  rcases H.p2_eq (hex_injective (H.p2_canonical _).lt_two_pow (H.p2_canonical _).lt_two_pow h)
    with h | h
  · simp only [blindInput, List.cons.injEq, true_and, and_true] at h
    exact Or.inl (split_injective h.1 h.2.1)
  · exact Or.inr h

/-- The break a key leaf equal to the leaf of `slot` names: a collision of the
key's leaf input with the slot's leaf input (or, for a key, of the two
key-hash inputs), or, for an empty slot, the key's leaf input mapping to `0`. -/
def SlotBreak (H : Hashes) (domain : Bytes) (n : Nat) : Slot → Prop
  | .key d m => H.P2Collides (leafInput domain (keyHash H n), leafInput d (keyHash H m)) ∨
      H.P2Collides (keyHashInput n, keyHashInput m)
  | .salt code => H.P2Collides (leafInput domain (keyHash H n), saltInput code)
  | .empty => H.P2Zero (leafInput domain (keyHash H n))

/-- A slot whose leaf is the leaf of key `(domain, n)` holds that key, unless
`SlotBreak` holds. -/
theorem slot_binds {slot : Slot} {domain : Bytes} {n : Nat} (hd : domain.length ≤ 62)
    (h : slot.leaf H = keyLeaf H domain (keyHash H n)) :
    slot = .key domain n ∨ SlotBreak H domain n slot := by
  cases slot with
  | key d m =>
    rcases keyLeaf_binds hd h.symm with ⟨rfl, hk⟩ | hc
    · rcases keyHash_binds hk with rfl | hc
      · exact Or.inl rfl
      · exact Or.inr (Or.inr hc)
    · exact Or.inr (Or.inl hc)
  | salt code =>
    refine Or.inr ⟨?_, h.symm⟩
    intro heq
    have := congrArg List.length heq
    simp [leafInput, saltInput, pack_length] at this
  | empty => exact Or.inr h.symm

end EmailRecovery
