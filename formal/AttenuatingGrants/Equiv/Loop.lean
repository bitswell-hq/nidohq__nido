import AttenuatingGrants.Extracted.GrantEval

/-!
# Loops of the extracted evaluator

Aeneas translates each `while i < s.len()` loop of `crates/grant-eval` to
`loop body i`, where `loop` is Aeneas's `partial_fixpoint` combinator and
`body` returns `cont j` to go round again or `done b` to exit. `loop` is not
total by construction, so a theorem `loop body i = ok b` is a proof that the
loop neither fails nor diverges.

Every loop in the evaluator is one of two scans over a list `l` (a slice, or
two slices zipped together):

* `loop_any`: exit with `true` at the first element satisfying `p`, with
  `false` at the end;
* `loop_all`: exit with `false` at the first element not satisfying `p`, with
  `true` at the end.

Each takes, as hypotheses, what one round of the body returns, and concludes
`loop body i = ok ((l.drop i).any p)` (or `.all p`) by induction on the
number of elements left.
-/

namespace AttenuatingGrants.Extraction

open Aeneas Aeneas.Std Result ControlFlow

/-! ## Primitive operations -/

theorem index_usize_eq {α : Type} (s : Slice α) (i : Usize) (h : i.val < s.length) :
    Slice.index_usize s i = ok s.val[i.val] := by
  simp [Slice.index_usize, h]

/-- The loop counter's `i + 1` succeeds: `i` indexes a slice, whose length is at
most `Usize.max`. -/
theorem incr_eq {α : Type} (s : Slice α) (i : Usize) (h : i.val < s.length) :
    ∃ j : Usize, i + 1#usize = ok j ∧ j.val = i.val + 1 := by
  have hmax : i.val + (1#usize).val ≤ UScalar.max .Usize := by
    have := s.property
    simp only [Slice.length] at h
    rw [UScalar.max_USize_eq]
    simp
    omega
  have := UScalar.add_spec (ty := .Usize) hmax
  revert this
  cases (i + 1#usize) with
  | ret r => intro hr; exact ⟨r, rfl, by simpa using hr⟩
  | vis e k => intro hr; simp at hr
  | div => intro hr; simp at hr

@[simp] theorem slice_len_lt {α : Type} (s : Slice α) (i : Usize) :
    (i < Slice.len s) = (i.val < s.length) := by
  apply propext
  show i.val < (Slice.len s).val ↔ _
  rw [Slice.len_val]

@[simp] theorem vec_deref_val {α : Type} (v : alloc.vec.Vec α) :
    (alloc.vec.Vec.deref v).val = v.val := by
  simp [alloc.vec.Vec.deref, alloc.vec.Vec.val]

/-! ## Scans -/

theorem loop_any {α : Type} (l : List α) (p : α → Bool)
    (body : Usize → Result (ControlFlow Usize Bool))
    (hlt : ∀ (i : Usize) (h : i.val < l.length), ∃ j : Usize, j.val = i.val + 1 ∧
      body i = ok (if p l[i.val] then done true else cont j))
    (hge : ∀ i : Usize, l.length ≤ i.val → body i = ok (done false))
    (i : Usize) :
    loop body i = ok ((l.drop i.val).any p) := by
  rw [loop]
  by_cases hi : i.val < l.length
  · obtain ⟨j, hj, hb⟩ := hlt i hi
    rw [hb, bind_ok, List.drop_eq_getElem_cons hi, List.any_cons]
    cases p l[i.val]
    · simp only [Bool.false_eq_true, ↓reduceIte, Bool.false_or]
      rw [loop_any l p body hlt hge j, hj]
    · simp
  · rw [hge i (Nat.le_of_not_lt hi), bind_ok, List.drop_of_length_le (Nat.le_of_not_lt hi)]
    rfl
termination_by l.length - i.val
decreasing_by omega

theorem loop_all {α : Type} (l : List α) (p : α → Bool)
    (body : Usize → Result (ControlFlow Usize Bool))
    (hlt : ∀ (i : Usize) (h : i.val < l.length), ∃ j : Usize, j.val = i.val + 1 ∧
      body i = ok (if p l[i.val] then cont j else done false))
    (hge : ∀ i : Usize, l.length ≤ i.val → body i = ok (done true))
    (i : Usize) :
    loop body i = ok ((l.drop i.val).all p) := by
  rw [loop]
  by_cases hi : i.val < l.length
  · obtain ⟨j, hj, hb⟩ := hlt i hi
    rw [hb, bind_ok, List.drop_eq_getElem_cons hi, List.all_cons]
    cases p l[i.val]
    · simp
    · simp only [↓reduceIte, Bool.true_and]
      rw [loop_all l p body hlt hge j, hj]
  · rw [hge i (Nat.le_of_not_lt hi), bind_ok, List.drop_of_length_le (Nat.le_of_not_lt hi)]
    rfl
termination_by l.length - i.val
decreasing_by omega

/-- A scan for an element whose image under `f` is `x` is membership of `x`
in the image of the list. -/
theorem any_eq_mem {α β : Type} [DecidableEq β] (f : α → β) (x : β) (l : List α) :
    l.any (fun y => decide (x = f y)) = decide (x ∈ l.map f) := by
  rw [Bool.eq_iff_iff, List.any_eq_true, decide_eq_true_iff, List.mem_map]
  constructor
  · rintro ⟨y, hy, he⟩
    exact ⟨y, hy, (of_decide_eq_true he).symm⟩
  · rintro ⟨y, hy, he⟩
    exact ⟨y, hy, decide_eq_true he.symm⟩

end AttenuatingGrants.Extraction
