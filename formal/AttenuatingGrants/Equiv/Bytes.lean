import AttenuatingGrants.Bytes
import AttenuatingGrants.Equiv.Loop

/-!
# Byte strings in the extracted evaluator

A Rust byte string is a `Vec<u8>` or `&[u8]`; Aeneas represents both by a
structure whose `val` is a `List Std.U8`. Its denotation in the readable model
is `bytesOf v.val : Bytes`, mapping each `Std.U8` to the `UInt8` with the same
bit vector. The map is injective (`bytesOf_inj`), so bytewise equality of the
Rust values is equality of their denotations.

* `bytes_eq_eq`: `bytes_eq a b` returns `ok (decide (a.val = b.val))`.
* `bytes_in_eq`: `bytes_in x list` returns `ok` of whether some element of
  `list` equals `x`.
-/

namespace AttenuatingGrants.Extraction

open Aeneas Aeneas.Std Result ControlFlow grant_eval

/-- A Rust `u8` as a byte of the readable model. -/
def byte (x : Std.U8) : UInt8 := UInt8.ofBitVec x.bv

theorem byte_injective : Function.Injective byte := by
  intro x y h
  have hbv : x.bv = y.bv := congrArg UInt8.toBitVec h
  cases x
  cases y
  simp_all

/-- A Rust byte string as a readable `Bytes`. -/
def bytesOf (l : List Std.U8) : Bytes := l.map byte

theorem bytesOf_inj {l₁ l₂ : List Std.U8} : bytesOf l₁ = bytesOf l₂ ↔ l₁ = l₂ :=
  (List.map_injective_iff.mpr byte_injective).eq_iff

/-- Element-wise equality of two lists of the same length is list equality. -/
theorem zip_all_eq {α : Type} [DecidableEq α] :
    ∀ (l₁ l₂ : List α), l₁.length = l₂.length →
      (l₁.zip l₂).all (fun x => decide (x.1 = x.2)) = decide (l₁ = l₂)
  | [], [], _ => rfl
  | [], _ :: _, h => by simp at h
  | _ :: _, [], h => by simp at h
  | a :: l₁, b :: l₂, h => by
    simp only [List.length_cons, Nat.add_right_cancel_iff] at h
    simp only [List.zip_cons_cons, List.all_cons, zip_all_eq l₁ l₂ h, List.cons.injEq]
    by_cases hab : a = b <;> simp [hab]

theorem slice_len_bne {α : Type} (a b : Slice α) :
    (Slice.len a != Slice.len b) = !decide (a.length = b.length) := by
  by_cases h : a.length = b.length
  · have : Slice.len a = Slice.len b := by
      apply UScalar.eq_of_val_eq
      simp [h]
    simp [this, h]
  · have : Slice.len a ≠ Slice.len b := by
      intro he
      have := congrArg UScalar.val he
      simp at this
      exact h this
    simp [this, h]

theorem bytes_eq_loop_eq (a b : Slice Std.U8) (hlen : a.length = b.length) (i : Usize) :
    bytes.bytes_eq_loop a b i =
      ok (((a.val.zip b.val).drop i.val).all (fun x => decide (x.1 = x.2))) := by
  simp only [Slice.length] at hlen
  unfold bytes.bytes_eq_loop
  apply loop_all
  · intro i hi
    have hz : i.val < a.val.length ∧ i.val < b.val.length := by
      simpa [List.length_zip] using hi
    have ha : i.val < a.length := hz.1
    have hb : i.val < b.length := hz.2
    obtain ⟨j, hj, hj'⟩ := incr_eq a i ha
    refine ⟨j, hj', ?_⟩
    simp only [bytes.bytes_eq_loop.body, slice_len_lt, ha, ↓reduceIte,
      index_usize_eq _ _ ha, index_usize_eq _ _ hb, hj, List.getElem_zip]
    by_cases he : a.val[i.val] = b.val[i.val]
    · simp [he]
    · simp [he]
      exact fun h => he (UScalar.eq_of_val_eq h)
  · intro i hi
    have hz : a.val.length ≤ i.val ∨ b.val.length ≤ i.val := by
      simpa [List.length_zip] using hi
    have ha : ¬ i.val < a.length := by simp only [Slice.length]; omega
    simp [bytes.bytes_eq_loop.body, ha]

theorem bytes_eq_eq (a b : Slice Std.U8) :
    bytes.bytes_eq a b = ok (decide (a.val = b.val)) := by
  simp only [bytes.bytes_eq, slice_len_bne]
  by_cases h : a.length = b.length
  · simp only [h, decide_true, Bool.not_true, Bool.false_eq_true, ↓reduceIte]
    have h' : a.val.length = b.val.length := h
    rw [bytes_eq_loop_eq a b h]
    simp [zip_all_eq _ _ h']
  · have hne : a.val ≠ b.val := fun he => h (by simp [Slice.length, he])
    simp [h, hne]

theorem bytes_in_eq (x : Slice Std.U8) (list : Slice (alloc.vec.Vec Std.U8)) :
    bytes.bytes_in x list = ok (list.val.any (fun y => decide (x.val = y.val))) := by
  unfold bytes.bytes_in bytes.bytes_in_loop
  rw [loop_any list.val (fun y => decide (x.val = y.val))]
  · simp
  · intro i hi
    obtain ⟨j, hj, hj'⟩ := incr_eq list i hi
    refine ⟨j, hj', ?_⟩
    simp only [bytes.bytes_in_loop.body, slice_len_lt, hi, ↓reduceIte,
      index_usize_eq _ _ hi, bytes_eq_eq, vec_deref_val, hj]
    by_cases he : x.val = list.val[i.val].val <;> simp [he]
  · intro i hi
    have : ¬ i.val < list.length := by simp only [Slice.length]; omega
    simp [bytes.bytes_in_loop.body, this]

/-- `bytes_in` is membership of the denotation. -/
theorem any_bytes_eq_mem (x : List Std.U8) (list : List (alloc.vec.Vec Std.U8)) :
    list.any (fun y => decide (x = y.val)) =
      decide (bytesOf x ∈ list.map (fun v => bytesOf v.val)) := by
  rw [Bool.eq_iff_iff, List.any_eq_true, decide_eq_true_iff, List.mem_map]
  constructor
  · rintro ⟨y, hy, he⟩
    exact ⟨y, hy, bytesOf_inj.mpr (of_decide_eq_true he).symm⟩
  · rintro ⟨y, hy, he⟩
    exact ⟨y, hy, decide_eq_true (bytesOf_inj.mp he).symm⟩

end AttenuatingGrants.Extraction
