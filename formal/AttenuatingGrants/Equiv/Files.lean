import AttenuatingGrants.Vocab.Files
import AttenuatingGrants.Equiv.Bytes
import AttenuatingGrants.Equiv.Eval

/-!
# Files: the extracted evaluator agrees with the model

`denoteAction` and `denoteCaveat` map the extracted `grant_eval.files` types to
the readable ones: a path's components by `bytesOf`, modes constructor for
constructor.

* `is_prefix_eq`: the extracted `is_prefix` is the model's component-wise
  `isPrefix` on the denoted paths.
* `extracted_allows`: `files.allows g a` returns `ok` of `Grant.allows` on the
  denoted grant and action, for every input.
* `extracted_allowsAll`: likewise `files.allows_all` and `Grant.allowsAll`.
* `extracted_narrower_push`, `extracted_delegates_narrower`,
  `extracted_allowsAll_of_delegates`: attenuation and chaining for the
  extracted evaluator on caveat slices.
-/

namespace AttenuatingGrants.Files

open Aeneas Aeneas.Std Result ControlFlow Extraction

/-! ## Denotation -/

def denoteMode : grant_eval.files.Mode → Mode
  | .Read => .read
  | .Write => .write
  | .Execute => .execute

/-- A Rust path (a list of components) as a readable `Path`. -/
def denotePath (p : List (alloc.vec.Vec Std.U8)) : Path :=
  p.map fun c => bytesOf c.val

def denoteAction (a : grant_eval.files.Action) : Action where
  path := denotePath a.path.val
  mode := denoteMode a.mode

def denoteCaveat : grant_eval.files.Caveat → Caveat
  | .PathUnder pathPrefix => .pathUnder (denotePath pathPrefix.val)
  | .ModeIn modes => .modeIn (modes.val.map denoteMode)

/-- The readable grant a Rust caveat slice denotes. -/
def denoteGrant (g : Slice grant_eval.files.Caveat) : Grant Action :=
  grant (g.val.map denoteCaveat)

theorem denoteGrant_allows (g : Slice grant_eval.files.Caveat) (a : Action) :
    (denoteGrant g).allows a = g.val.all fun c => (denoteCaveat c).holds a := by
  simp [denoteGrant, grant, Grant.allows, List.all_map, Function.comp_def]

/-! ## Modes -/

theorem mode_eq_eq (a b : grant_eval.files.Mode) :
    grant_eval.files.mode_eq a b = ok (decide (denoteMode a = denoteMode b)) := by
  cases a <;> cases b <;> rfl

theorem mode_in_eq (m : grant_eval.files.Mode) (list : Slice grant_eval.files.Mode) :
    grant_eval.files.mode_in m list = ok (decide (denoteMode m ∈ list.val.map denoteMode)) := by
  unfold grant_eval.files.mode_in grant_eval.files.mode_in_loop
  rw [loop_any list.val (fun y => decide (denoteMode m = denoteMode y))]
  · simp [any_eq_mem]
  · intro i hi
    obtain ⟨j, hj, hj'⟩ := incr_eq list i hi
    refine ⟨j, hj', ?_⟩
    simp only [grant_eval.files.mode_in_loop.body, slice_len_lt, hi, ↓reduceIte,
      index_usize_eq _ _ hi, mode_eq_eq, bind_ok, hj]
    cases decide (denoteMode m = denoteMode list.val[i.val]) <;> rfl
  · intro i hi
    have : ¬ i.val < list.length := by simp only [Slice.length]; omega
    simp [grant_eval.files.mode_in_loop.body, this]

/-! ## Path prefixes -/

/-- On paths no longer than `q`, the model's `isPrefix` compares components
pairwise. -/
theorem isPrefix_denotePath :
    ∀ (p q : List (alloc.vec.Vec Std.U8)), p.length ≤ q.length →
      isPrefix (denotePath p) (denotePath q) =
        (p.zip q).all (fun x => decide (x.1.val = x.2.val))
  | [], _, _ => by simp [denotePath, isPrefix]
  | _ :: _, [], h => by simp at h
  | c :: p, d :: q, h => by
    simp only [List.length_cons, Nat.add_le_add_iff_right] at h
    simp only [denotePath, List.map_cons, isPrefix, List.zip_cons_cons, List.all_cons,
      bytesOf_inj]
    rw [← denotePath, ← denotePath, isPrefix_denotePath p q h]

theorem isPrefix_length_le {p q : Path} (h : isPrefix p q = true) : p.length ≤ q.length :=
  ((isPrefix_iff p q).mp h).length_le

theorem is_prefix_loop_eq (p q : Slice (alloc.vec.Vec Std.U8)) (hlen : p.length ≤ q.length)
    (i : Usize) :
    grant_eval.files.is_prefix_loop p q i =
      ok (((p.val.zip q.val).drop i.val).all (fun x => decide (x.1.val = x.2.val))) := by
  simp only [Slice.length] at hlen
  unfold grant_eval.files.is_prefix_loop
  apply loop_all
  · intro i hi
    have hz : i.val < p.val.length ∧ i.val < q.val.length := by
      simpa [List.length_zip] using hi
    have hp : i.val < p.length := hz.1
    have hq : i.val < q.length := hz.2
    obtain ⟨j, hj, hj'⟩ := incr_eq p i hp
    refine ⟨j, hj', ?_⟩
    simp only [grant_eval.files.is_prefix_loop.body, slice_len_lt, hp, ↓reduceIte,
      index_usize_eq _ _ hp, index_usize_eq _ _ hq, bytes_eq_eq, vec_deref_val, bind_ok, hj,
      List.getElem_zip]
    cases decide (p.val[i.val].val = q.val[i.val].val) <;> rfl
  · intro i hi
    have hz : p.val.length ≤ i.val ∨ q.val.length ≤ i.val := by
      simpa [List.length_zip] using hi
    have hp : ¬ i.val < p.length := by simp only [Slice.length]; omega
    simp [grant_eval.files.is_prefix_loop.body, hp]

theorem slice_len_gt {α : Type} (a b : Slice α) :
    (Slice.len a > Slice.len b) = (b.length < a.length) := by
  apply propext
  show (Slice.len b).val < (Slice.len a).val ↔ _
  rw [Slice.len_val, Slice.len_val]

/-- The extracted `is_prefix` returns `ok` of the model's `isPrefix` on the
denoted paths. -/
theorem is_prefix_eq (p q : Slice (alloc.vec.Vec Std.U8)) :
    grant_eval.files.is_prefix p q = ok (isPrefix (denotePath p.val) (denotePath q.val)) := by
  simp only [grant_eval.files.is_prefix, slice_len_gt]
  by_cases h : q.length < p.length
  · have hf : isPrefix (denotePath p.val) (denotePath q.val) = false := by
      apply Bool.eq_false_iff.mpr
      intro ht
      have := isPrefix_length_le ht
      simp only [denotePath, List.length_map] at this
      simp only [Slice.length] at h
      omega
    simp [h, hf]
  · have hle : p.length ≤ q.length := Nat.le_of_not_lt h
    simp only [h, ↓reduceIte]
    rw [is_prefix_loop_eq p q hle, isPrefix_denotePath p.val q.val hle]
    simp

/-! ## Caveats -/

theorem holds_eq (c : grant_eval.files.Caveat) (a : grant_eval.files.Action) :
    grant_eval.files.holds c a = ok ((denoteCaveat c).holds (denoteAction a)) := by
  cases c with
  | PathUnder pathPrefix =>
    simp [grant_eval.files.holds, is_prefix_eq, denoteCaveat, denoteAction, Caveat.holds]
  | ModeIn modes =>
    simp [grant_eval.files.holds, mode_in_eq, denoteCaveat, denoteAction, Caveat.holds]

/-! ## Equivalence -/

theorem inst_holds_eq (c : grant_eval.files.Caveat) (a : grant_eval.files.Action) :
    grant_eval.files.Caveat.Insts.Grant_evalEvalCheckAction.holds c a =
      ok ((denoteCaveat c).holds (denoteAction a)) :=
  holds_eq c a

/-- The extracted `allows` returns `ok` on every input, and its result is
`Grant.allows` of the denoted grant and action. -/
theorem extracted_allows (g : Slice grant_eval.files.Caveat) (a : grant_eval.files.Action) :
    grant_eval.files.allows g a = ok ((denoteGrant g).allows (denoteAction a)) := by
  unfold grant_eval.files.allows
  rw [eval_allows_eq _ _ inst_holds_eq, denoteGrant_allows]

/-- The extracted `allows_all` returns `ok` on every input, and its result is
`Grant.allowsAll` of the denoted grant and actions. -/
theorem extracted_allowsAll (g : Slice grant_eval.files.Caveat)
    (acts : Slice grant_eval.files.Action) :
    grant_eval.files.allows_all g acts =
      ok ((denoteGrant g).allowsAll (acts.val.map denoteAction)) := by
  unfold grant_eval.files.allows_all
  rw [eval_allows_all_eq _ _ inst_holds_eq]
  simp [Grant.allowsAll, List.all_map, Function.comp_def, denoteGrant_allows]

theorem implements :
    Implements grant_eval.files.allows fun c a => (denoteCaveat c).holds (denoteAction a) :=
  (implements_iff_all _ _).mpr fun g a => by
    rw [extracted_allows, denoteGrant_allows]

theorem implementsAll :
    ImplementsAll grant_eval.files.allows_all
      fun c a => (denoteCaveat c).holds (denoteAction a) :=
  (implementsAll_iff_all _ _).mpr fun g acts => by
    unfold grant_eval.files.allows_all
    exact eval_allows_all_eq _ _ inst_holds_eq g acts

/-! ## Attenuation and chaining on caveat slices -/

theorem extracted_narrower_of_subset {g g' : Slice grant_eval.files.Caveat}
    (hsub : ∀ c ∈ g.val, c ∈ g'.val) : Narrower grant_eval.files.allows g' g :=
  implements.narrower_of_subset hsub

theorem extracted_narrower_push {g g' : Slice grant_eval.files.Caveat}
    {c : grant_eval.files.Caveat} (hpush : g'.val = g.val ++ [c]) :
    Narrower grant_eval.files.allows g' g :=
  implements.narrower_push hpush

theorem extracted_delegates_narrower {root g : Slice grant_eval.files.Caveat}
    (h : Extraction.Delegates root g) : Narrower grant_eval.files.allows g root :=
  implements.narrower_of_delegates h

theorem extracted_allowsAll_of_delegates {root g : Slice grant_eval.files.Caveat}
    (h : Extraction.Delegates root g) (acts : Slice grant_eval.files.Action) :
    grant_eval.files.allows_all g acts = ok true →
      grant_eval.files.allows_all root acts = ok true :=
  implementsAll.allows_all_of_narrower implements (extracted_delegates_narrower h) acts

end AttenuatingGrants.Files
