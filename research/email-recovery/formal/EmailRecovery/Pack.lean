import EmailRecovery.Basic

/-!
# Packing bytes into field elements

Spec §2 `pack(bytes, max)`: right-pad with `0x00` to `max` bytes, cut into
31-byte chunks, and read each chunk as a big-endian integer. The commitment
(§5.3) packs the address into four limbs and the registry leaf (§7.2) packs the
domain into two, each next to the byte length.

`pack_injective` proves the spec's remark that "the length is always hashed
alongside, so padding is unambiguous": two byte strings of the same length that
pack to the same limbs are equal.
-/

namespace EmailRecovery

/-- The big-endian value of a byte string. -/
def beNat : Bytes → Nat
  | [] => 0
  | b :: t => b.toNat * 256 ^ t.length + beNat t

/-- `k` chunks of 31 bytes, each read big-endian. -/
def chunks : Nat → Bytes → List Nat
  | 0, _ => []
  | k + 1, bs => beNat (bs.take 31) :: chunks k (bs.drop 31)

/-- Spec §2 `pack(bytes, max)`, for `max` a multiple of 31. -/
def pack (bs : Bytes) (max : Nat) : List Nat :=
  chunks (max / 31) (bs ++ List.replicate (max - bs.length) 0)

theorem chunks_length : ∀ (k : Nat) (bs : Bytes), (chunks k bs).length = k
  | 0, _ => rfl
  | k + 1, bs => by simp [chunks, chunks_length k]

theorem pack_length (bs : Bytes) (max : Nat) : (pack bs max).length = max / 31 :=
  chunks_length _ _

theorem beNat_lt : ∀ bs : Bytes, beNat bs < 256 ^ bs.length
  | [] => by simp [beNat]
  | b :: t => by
    have ht := beNat_lt t
    have hb : b.toNat < 256 := b.toNat_lt
    simp only [beNat, List.length_cons, Nat.pow_succ]
    have : b.toNat * 256 ^ t.length + beNat t < (b.toNat + 1) * 256 ^ t.length := by
      rw [Nat.add_mul, Nat.one_mul]; omega
    have : (b.toNat + 1) * 256 ^ t.length ≤ 256 * 256 ^ t.length :=
      Nat.mul_le_mul_right _ hb
    rw [Nat.mul_comm (256 ^ t.length)]
    omega

/-- A chunk of at most 31 bytes is a field element. -/
theorem beNat_take_canonical (bs : Bytes) : Canonical (beNat (bs.take 31)) := by
  refine Canonical.of_lt (Nat.lt_of_lt_of_le (beNat_lt _) ?_) (by decide : 256 ^ 31 ≤ fieldModulus)
  exact Nat.pow_le_pow_right (by decide) (List.length_take_le _ _)

theorem chunks_canonical : ∀ (k : Nat) (bs : Bytes), CanonicalList (chunks k bs)
  | 0, _ => by simp [chunks, CanonicalList]
  | k + 1, bs => by
    intro x hx
    simp only [chunks, List.mem_cons] at hx
    rcases hx with rfl | hx
    · exact beNat_take_canonical bs
    · exact chunks_canonical k _ x hx

/-- Every limb `pack` cuts is a field element (below `2 ^ 248`). -/
theorem pack_canonical (bs : Bytes) (max : Nat) : CanonicalList (pack bs max) :=
  chunks_canonical _ _

theorem beNat_injective : ∀ a b : Bytes, a.length = b.length → beNat a = beNat b → a = b
  | [], [], _, _ => rfl
  | x :: s, y :: t, hlen, h => by
    simp only [List.length_cons, Nat.add_right_cancel_iff] at hlen
    simp only [beNat] at h
    have hs := beNat_lt s
    have ht := beNat_lt t
    rw [hlen] at h hs
    have hk : 0 < 256 ^ t.length := Nat.pow_pos (by decide)
    have hmod : beNat s = beNat t := by
      have h1 := congrArg (· % 256 ^ t.length) h
      simp only [Nat.mul_comm _ (256 ^ t.length), Nat.mul_add_mod, Nat.mod_eq_of_lt hs,
        Nat.mod_eq_of_lt ht] at h1
      exact h1
    have hdiv : x.toNat = y.toNat := by
      rw [hmod] at h
      exact Nat.eq_of_mul_eq_mul_right hk (Nat.add_right_cancel h)
    rw [UInt8.toNat_inj.mp hdiv, beNat_injective s t (by rw [hlen]) hmod]
  | [], _ :: _, hlen, _ => by simp at hlen
  | _ :: _, [], hlen, _ => by simp at hlen

theorem chunks_injective :
    ∀ (k : Nat) (a b : Bytes), a.length = 31 * k → b.length = 31 * k →
      chunks k a = chunks k b → a = b
  | 0, a, b, ha, hb, _ => by
    simp at ha hb
    rw [ha, hb]
  | k + 1, a, b, ha, hb, h => by
    simp only [chunks, List.cons.injEq] at h
    have htake : a.take 31 = b.take 31 :=
      beNat_injective _ _ (by simp [List.length_take, ha, hb]) h.1
    have hdrop : a.drop 31 = b.drop 31 :=
      chunks_injective k _ _ (by simp [List.length_drop, ha]; omega)
        (by simp [List.length_drop, hb]; omega) h.2
    rw [← List.take_append_drop 31 a, ← List.take_append_drop 31 b, htake, hdrop]

/-- Same length, same limbs, same bytes. -/
theorem pack_injective {a b : Bytes} {k : Nat} (hlen : a.length = b.length)
    (hfit : a.length ≤ 31 * k) (h : pack a (31 * k) = pack b (31 * k)) : a = b := by
  unfold pack at h
  rw [Nat.mul_div_cancel_left k (by decide)] at h
  have hpad := chunks_injective k _ _ (by simp; omega) (by simp; omega) h
  rw [hlen] at hpad
  exact List.append_cancel_right hpad

end EmailRecovery
