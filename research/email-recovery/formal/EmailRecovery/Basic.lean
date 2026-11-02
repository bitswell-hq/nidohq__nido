/-!
# Values and hash primitives

Byte strings, BN254 field elements, Perch's digest split, the domain tags of
`docs/email-recovery/spec.md` §2, and the two hash functions the email factor
uses (SHA-256 and Poseidon2), as abstract functions.

No property of either hash function is assumed anywhere in this package,
beyond their types: SHA-256 returns 32 bytes (`sha256_lt`) and Poseidon2 returns
a field element (`p2_canonical`). Where a theorem needs collision resistance
(assumptions A2 and A3 of spec §11.1), its conclusion names the break as an
alternative, with the inputs that collide given as terms built from the
theorem's data: the theorem holds for every function, and the assumption is
that nobody can compute those inputs. That is the reading of collision
resistance for a fixed, unkeyed function: a theorem of this form is a reduction
that turns any violation of its main conclusion into an explicit collision.

A3 is about Poseidon2 on `F_r^k`, so a named Poseidon2 break (`P2Collides`,
`P2Zero`) consists of lists of canonical field elements. Poseidon2 reads every
input modulo `r`, so `x` and `x + r` hash alike and are no collision; every
value the circuit hashes is a `Field`, and the relation and the enrollment
carry the bounds that make each named pair one
(`Examples.aliased_code_is_no_break`).

Identifiers (contract ids, digests, roots, field elements) are natural numbers;
the model compares them and, for digests, splits them, and does no other
arithmetic on them.
-/

namespace EmailRecovery

/-- A byte string. -/
abbrev Bytes := List UInt8

/-- The BN254 scalar field modulus `r` (spec §2). -/
def fieldModulus : Nat :=
  0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001

/-- A canonical field element: below `r` (Perch's `is_canonical_field`). -/
def Canonical (x : Nat) : Prop := x < fieldModulus

instance (x : Nat) : Decidable (Canonical x) :=
  inferInstanceAs (Decidable (x < fieldModulus))

/-- A field element fits 32 bytes. -/
theorem Canonical.lt_two_pow {x : Nat} (h : Canonical x) : x < 2 ^ 256 :=
  Nat.lt_trans h (by decide)

/-- A value below a bound no larger than `r` is a field element. -/
theorem Canonical.of_lt {x b : Nat} (h : x < b) (hb : b ≤ fieldModulus) : Canonical x :=
  Nat.lt_of_lt_of_le h hb

/-- The high limb of Perch's `split_hi_lo` (spec §2, §3.2): the first 16 bytes
of a 32-byte big-endian value. -/
def hi (d : Nat) : Nat := d / 2 ^ 128

/-- The low limb of Perch's `split_hi_lo`: the last 16 bytes. -/
def lo (d : Nat) : Nat := d % 2 ^ 128

/-- The high limb of a 32-byte value is below `2 ^ 128`. -/
theorem hi_lt {d : Nat} (h : d < 2 ^ 256) : hi d < 2 ^ 128 :=
  (Nat.div_lt_iff_lt_mul (Nat.pow_pos (by decide))).2 (by rw [← Nat.pow_add]; exact h)

theorem lo_lt (d : Nat) : lo d < 2 ^ 128 := Nat.mod_lt _ (Nat.pow_pos (by decide))

/-- `split` loses nothing: the two limbs determine the value. -/
theorem split_injective {d e : Nat} (h₁ : hi d = hi e) (h₂ : lo d = lo e) : d = e := by
  have hd := Nat.div_add_mod d (2 ^ 128)
  have he := Nat.div_add_mod e (2 ^ 128)
  unfold hi at h₁
  unfold lo at h₂
  rw [← hd, ← he, h₁, h₂]

/-! ## Domain tags (spec §2)

Each is `BE(sha256(label)) mod r`; the values are the spec's table, which
`contracts/email-guardian/src/test.rs::spec_domain_tags_follow_the_label_rule`
recomputes from the labels. No theorem here depends on their values: the
separations the proofs use come from distinct input counts. -/

/-- `nido/email-recovery/v1/commit` -/
def domCommit : Nat := 0x28c44578265e026b7cecaa4b01b79fef9a1d1e4340e270596de3a724f044ee56
/-- `nido/email-recovery/v1/blind` -/
def domBlind : Nat := 0x2e13b680b3b2cbdab71f094fdf34f9ccd940c01ac6158ebc826ee5bdb05d0726
/-- `nido/email-recovery/v1/enroll` -/
def domEnroll : Nat := 0x2bfe80f315441c3aadf9e7de0ab78fae545af772c0671cf5a512eb1ae713c9e7
/-- `nido/email-recovery/v1/key` -/
def domKey : Nat := 0x1f6d4c7ed15d3b9480457cf9ff55d0ffff201158605d66399703659bf4d765f5
/-- `nido/email-recovery/v1/leaf` -/
def domLeaf : Nat := 0x1ddd7b4c7e2eba95d7da44139642c575589aa685188088b0555d3d4fbb5b1f7e
/-- `nido/email-recovery/v1/pin-salt` -/
def domPinSalt : Nat := 0x03d73ecb3a706d8271405c0c77fb8020c22717b7db10c5eb91f480ea1456bff6

/-! ## Hash functions -/

/-- Every entry is a canonical field element: the list is in `F_r^k`. -/
def CanonicalList (xs : List Nat) : Prop := ∀ x ∈ xs, Canonical x

/-- SHA-256 and Poseidon2 as abstract functions. `sha256` returns a 32-byte
digest, read big-endian. `p2 xs` is Noir's `Poseidon2::hash(xs, xs.len())`; its
initial state depends on the input count (`noir-lang/poseidon` v0.2.0), so it is
modelled as one function on lists and hashes of different input counts are
different inputs. It returns a `Field`, so its outputs are canonical field
elements. -/
structure Hashes where
  sha256 : Bytes → Nat
  sha256_lt : ∀ b, sha256 b < 2 ^ 256
  p2 : List Nat → Nat
  p2_canonical : ∀ xs, Canonical (p2 xs)

namespace Hashes

variable (H : Hashes)

/-- The pair is a SHA-256 collision: two different byte strings with one digest
(a break of A2). -/
def Sha256Collides (p : Bytes × Bytes) : Prop := p.1 ≠ p.2 ∧ H.sha256 p.1 = H.sha256 p.2

/-- The pair is a Poseidon2 collision on field elements: two different lists of
canonical field elements with one hash (a break of A3's collision resistance). -/
def P2Collides (p : List Nat × List Nat) : Prop :=
  CanonicalList p.1 ∧ CanonicalList p.2 ∧ p.1 ≠ p.2 ∧ H.p2 p.1 = H.p2 p.2

/-- Poseidon2 maps the list of field elements `x` to `0`, the empty leaf of the
key trees (spec §7.2). Collision resistance alone does not exclude it; A3's
random-function model makes finding one as hard as hitting a fixed value. -/
def P2Zero (x : List Nat) : Prop := CanonicalList x ∧ H.p2 x = 0

theorem sha256_eq {a b : Bytes} (h : H.sha256 a = H.sha256 b) :
    a = b ∨ H.Sha256Collides (a, b) :=
  if hab : a = b then Or.inl hab else Or.inr ⟨hab, h⟩

theorem p2_eq {x y : List Nat} (hx : CanonicalList x) (hy : CanonicalList y)
    (h : H.p2 x = H.p2 y) : x = y ∨ H.P2Collides (x, y) :=
  if hxy : x = y then Or.inl hxy else Or.inr ⟨hx, hy, hxy, h⟩

end Hashes

end EmailRecovery
