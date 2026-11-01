import AttenuatingGrants.Grant
import AttenuatingGrants.Equiv.Loop

/-!
# The generic evaluator

`grant_eval::allows` and `grant_eval::allows_all` (defined in `src/eval.rs`)
are generic over the caveat type `C` and action type `A`, with the caveat check
passed as the `Check<A>` trait instance `inst`. Given that `inst.holds c a`
returns `ok (holds c a)` for a function `holds : C → A → Bool`:

* `eval_allows_eq`: `eval.allows inst g a` returns `ok` of whether `holds c a`
  for every caveat `c` of `g`;
* `eval_allows_all_eq`: `eval.allows_all inst g acts` returns `ok` of whether
  that holds for every action in `acts`.

## Carry-over

Each vocabulary proves that its extracted `allows` and `allows_all` compute
`Grant.allows` and `Grant.allowsAll` of the denoted grant
(`Implements`, `ImplementsAll`). From that alone, attenuation and chaining
(theorems 2 and 3) hold for the extracted evaluator on Rust caveat slices:

* `Implements.narrower_of_subset`: a slice holding every caveat of `g` is
  narrower than `g`; in particular `g` with a caveat pushed
  (`Implements.narrower_push`);
* `Narrower.trans`: narrowness of slices is transitive;
* `Implements.narrower_of_delegates`: a slice reached from `root` by pushing
  caveats, one step per sub-agent, is narrower than `root`;
* `ImplementsAll.allows_all_of_narrower`: a narrower slice allows a batch of
  actions (every context of a Soroban authorization tree) only if its ancestor
  does.

`Narrower` is stated on the extracted evaluator's results, with no reference to
the model: the theorems are about the code.
-/

namespace AttenuatingGrants.Extraction

open Aeneas Aeneas.Std Result ControlFlow grant_eval

variable {A C : Type}

/-! ## Evaluation -/

theorem eval_allows_eq (inst : eval.Check C A) (holds : C → A → Bool)
    (h : ∀ c a, inst.holds c a = ok (holds c a)) (g : Slice C) (a : A) :
    eval.allows inst g a = ok (g.val.all (holds · a)) := by
  unfold eval.allows eval.allows_loop
  rw [loop_all g.val (holds · a)]
  · simp
  · intro i hi
    obtain ⟨j, hj, hj'⟩ := incr_eq g i hi
    refine ⟨j, hj', ?_⟩
    simp only [eval.allows_loop.body, slice_len_lt, hi, ↓reduceIte, index_usize_eq _ _ hi, h, hj]
    cases hh : holds g.val[i.val] a <;> simp [hh]
  · intro i hi
    have : ¬ i.val < g.length := by simp only [Slice.length]; omega
    simp [eval.allows_loop.body, this]

theorem eval_allows_all_eq (inst : eval.Check C A) (holds : C → A → Bool)
    (h : ∀ c a, inst.holds c a = ok (holds c a)) (g : Slice C) (acts : Slice A) :
    eval.allows_all inst g acts = ok (acts.val.all fun a => g.val.all (holds · a)) := by
  unfold eval.allows_all eval.allows_all_loop
  rw [loop_all acts.val (fun a => g.val.all (holds · a))]
  · simp
  · intro i hi
    obtain ⟨j, hj, hj'⟩ := incr_eq acts i hi
    refine ⟨j, hj', ?_⟩
    simp only [eval.allows_all_loop.body, slice_len_lt, hi, ↓reduceIte, index_usize_eq _ _ hi,
      eval_allows_eq inst holds h, bind_ok, hj]
    cases g.val.all (holds · acts.val[i.val]) <;> simp only [Bool.false_eq_true, ↓reduceIte]
  · intro i hi
    have : ¬ i.val < acts.length := by simp only [Slice.length]; omega
    simp [eval.allows_all_loop.body, this]

/-! ## Carry-over -/

/-- `allows` is an extracted `allows` that computes `Grant.allows` of the grant
whose caveats are `holds c` for each `c` in the slice. -/
def Implements (allows : Slice C → A → Result Bool) (holds : C → A → Bool) : Prop :=
  ∀ g a, allows g a = ok ((Grant.mk (g.val.map holds)).allows a)

/-- `allowsAll` is an extracted `allows_all` that computes `Grant.allowsAll`. -/
def ImplementsAll (allowsAll : Slice C → Slice A → Result Bool) (holds : C → A → Bool) :
    Prop :=
  ∀ g acts, allowsAll g acts = ok ((Grant.mk (g.val.map holds)).allowsAll acts.val)

theorem grant_allows_map (l : List C) (holds : C → A → Bool) :
    (Grant.mk (l.map holds)).allows = fun a => l.all (holds · a) := by
  funext a
  simp [Grant.allows, List.all_map, Function.comp_def]

theorem implements_iff_all (allows : Slice C → A → Result Bool) (holds : C → A → Bool) :
    Implements allows holds ↔ ∀ g a, allows g a = ok (g.val.all (holds · a)) := by
  simp only [Implements, grant_allows_map]

theorem implementsAll_iff_all (allowsAll : Slice C → Slice A → Result Bool)
    (holds : C → A → Bool) :
    ImplementsAll allowsAll holds ↔
      ∀ g acts, allowsAll g acts = ok (acts.val.all fun a => g.val.all (holds · a)) := by
  simp only [ImplementsAll, Grant.allowsAll, grant_allows_map]

/-- `g` is narrower than `h` on the extracted evaluator `allows`: every action
`allows g` accepts, `allows h` accepts too. -/
def Narrower (allows : Slice C → A → Result Bool) (g h : Slice C) : Prop :=
  ∀ a, allows g a = ok true → allows h a = ok true

theorem Narrower.refl (allows : Slice C → A → Result Bool) (g : Slice C) :
    Narrower allows g g :=
  fun _ ha => ha

theorem Narrower.trans {allows : Slice C → A → Result Bool} {g h k : Slice C} :
    Narrower allows g h → Narrower allows h k → Narrower allows g k :=
  fun gh hk a ha => hk a (gh a ha)

theorem Implements.allows_iff {allows : Slice C → A → Result Bool} {holds : C → A → Bool}
    (hi : Implements allows holds) (g : Slice C) (a : A) :
    allows g a = ok true ↔ ∀ c ∈ g.val, holds c a = true := by
  rw [(implements_iff_all allows holds).mp hi g a]
  constructor
  · intro h
    have := Result.ok_injective h
    simpa using this
  · intro h
    simp [List.all_eq_true.mpr h]

/-- Attenuation: a slice holding every caveat of `g` is narrower than `g`. -/
theorem Implements.narrower_of_subset {allows : Slice C → A → Result Bool}
    {holds : C → A → Bool} (hi : Implements allows holds) {g g' : Slice C}
    (hsub : ∀ c ∈ g.val, c ∈ g'.val) :
    Narrower allows g' g := by
  intro a ha
  rw [hi.allows_iff] at ha ⊢
  exact fun c hc => ha c (hsub c hc)

/-- Attenuation: pushing a caveat onto a slice narrows it. -/
theorem Implements.narrower_push {allows : Slice C → A → Result Bool}
    {holds : C → A → Bool} (hi : Implements allows holds) {g g' : Slice C} {c : C}
    (hpush : g'.val = g.val ++ [c]) :
    Narrower allows g' g :=
  hi.narrower_of_subset fun c' hc' => by simp [hpush, hc']

/-- `Delegates root g`: the caveat slice `g` is reached from `root` by zero or
more steps, each a sub-agent pushing one caveat onto the slice it was
handed. -/
inductive Delegates (root : Slice C) : Slice C → Prop where
  | refl : Delegates root root
  | push {g g' : Slice C} (c : C) : Delegates root g → g'.val = g.val ++ [c] →
      Delegates root g'

/-- Chaining: every slice in a delegation chain stays inside the root. -/
theorem Implements.narrower_of_delegates {allows : Slice C → A → Result Bool}
    {holds : C → A → Bool} (hi : Implements allows holds) {root g : Slice C}
    (h : Delegates root g) : Narrower allows g root := by
  induction h with
  | refl => exact Narrower.refl allows root
  | push c _ hpush ih => exact Narrower.trans (hi.narrower_push hpush) ih

/-- A narrower slice allows a batch of actions only if its ancestor does. -/
theorem ImplementsAll.allows_all_of_narrower {allows : Slice C → A → Result Bool}
    {allowsAll : Slice C → Slice A → Result Bool} {holds : C → A → Bool}
    (hi : Implements allows holds) (hia : ImplementsAll allowsAll holds) {g h : Slice C}
    (gh : Narrower allows g h) (acts : Slice A) :
    allowsAll g acts = ok true → allowsAll h acts = ok true := by
  rw [(implementsAll_iff_all allowsAll holds).mp hia g acts,
    (implementsAll_iff_all allowsAll holds).mp hia h acts]
  intro hg
  have hg := Result.ok_injective hg
  simp only [List.all_eq_true] at hg
  have : ∀ a ∈ acts.val, h.val.all (holds · a) = true := by
    intro a ha
    have := gh a (by
      rw [(implements_iff_all allows holds).mp hi g a, List.all_eq_true.mpr (hg a ha)])
    rw [(implements_iff_all allows holds).mp hi h a] at this
    exact Result.ok_injective this
  simp [List.all_eq_true.mpr this]

end AttenuatingGrants.Extraction
