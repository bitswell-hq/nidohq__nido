import AttenuatingGrants.Vocab.Network
import AttenuatingGrants.Equiv.Bytes
import AttenuatingGrants.Equiv.Eval

/-!
# Network: the extracted evaluator agrees with the model

`denoteAction` and `denoteCaveat` map the extracted `grant_eval.network` types
to the readable ones: byte strings by `bytesOf`, `u16` to the `UInt16` with the
same bit vector, enums constructor for constructor.

* `extracted_allows`: `network.allows g a` returns `ok` of `Grant.allows` on
  the denoted grant and action, for every input.
* `extracted_allowsAll`: likewise `network.allows_all` and `Grant.allowsAll`.
* `extracted_narrower_push`, `extracted_delegates_narrower`,
  `extracted_allowsAll_of_delegates`: attenuation and chaining for the
  extracted evaluator on caveat slices.
-/

namespace AttenuatingGrants.Network

open Aeneas Aeneas.Std Result ControlFlow Extraction

/-! ## Denotation -/

def denoteScheme : grant_eval.network.Scheme → Scheme
  | .Http => .http
  | .Https => .https

def denotePort (p : Std.U16) : UInt16 := UInt16.ofBitVec p.bv

theorem denotePort_injective : Function.Injective denotePort := by
  intro x y h
  have hbv : x.bv = y.bv := congrArg UInt16.toBitVec h
  cases x
  cases y
  simp_all

def denoteAction (a : grant_eval.network.Action) : Action where
  host := bytesOf a.host.val
  port := denotePort a.port
  scheme := denoteScheme a.scheme

def denoteCaveat : grant_eval.network.Caveat → Caveat
  | .HostIn hosts => .hostIn (hosts.val.map fun h => bytesOf h.val)
  | .PortIn ports => .portIn (ports.val.map denotePort)
  | .SchemeIn schemes => .schemeIn (schemes.val.map denoteScheme)

/-- The readable grant a Rust caveat slice denotes. -/
def denoteGrant (g : Slice grant_eval.network.Caveat) : Grant Action :=
  grant (g.val.map denoteCaveat)

theorem denoteGrant_allows (g : Slice grant_eval.network.Caveat) (a : Action) :
    (denoteGrant g).allows a = g.val.all fun c => (denoteCaveat c).holds a := by
  simp [denoteGrant, grant, Grant.allows, List.all_map, Function.comp_def]

/-! ## Caveats -/

theorem scheme_eq_eq (a b : grant_eval.network.Scheme) :
    grant_eval.network.scheme_eq a b = ok (decide (denoteScheme a = denoteScheme b)) := by
  cases a <;> cases b <;> rfl

theorem scheme_in_eq (s : grant_eval.network.Scheme) (list : Slice grant_eval.network.Scheme) :
    grant_eval.network.scheme_in s list =
      ok (decide (denoteScheme s ∈ list.val.map denoteScheme)) := by
  unfold grant_eval.network.scheme_in grant_eval.network.scheme_in_loop
  rw [loop_any list.val (fun y => decide (denoteScheme s = denoteScheme y))]
  · simp [any_eq_mem]
  · intro i hi
    obtain ⟨j, hj, hj'⟩ := incr_eq list i hi
    refine ⟨j, hj', ?_⟩
    simp only [grant_eval.network.scheme_in_loop.body, slice_len_lt, hi, ↓reduceIte,
      index_usize_eq _ _ hi, scheme_eq_eq, bind_ok, hj]
    cases decide (denoteScheme s = denoteScheme list.val[i.val]) <;> rfl
  · intro i hi
    have : ¬ i.val < list.length := by simp only [Slice.length]; omega
    simp [grant_eval.network.scheme_in_loop.body, this]

theorem port_in_eq (p : Std.U16) (list : Slice Std.U16) :
    grant_eval.network.port_in p list = ok (decide (denotePort p ∈ list.val.map denotePort)) := by
  unfold grant_eval.network.port_in grant_eval.network.port_in_loop
  rw [loop_any list.val (fun y => decide (denotePort p = denotePort y))]
  · simp [any_eq_mem]
  · intro i hi
    obtain ⟨j, hj, hj'⟩ := incr_eq list i hi
    refine ⟨j, hj', ?_⟩
    simp only [grant_eval.network.port_in_loop.body, slice_len_lt, hi, ↓reduceIte,
      index_usize_eq _ _ hi, bind_ok, hj, denotePort_injective.eq_iff]
    by_cases he : p = list.val[i.val] <;> simp [he]
  · intro i hi
    have : ¬ i.val < list.length := by simp only [Slice.length]; omega
    simp [grant_eval.network.port_in_loop.body, this]

theorem holds_eq (c : grant_eval.network.Caveat) (a : grant_eval.network.Action) :
    grant_eval.network.holds c a = ok ((denoteCaveat c).holds (denoteAction a)) := by
  cases c with
  | HostIn hosts =>
    simp [grant_eval.network.holds, bytes_in_eq, any_bytes_eq_mem, denoteCaveat, denoteAction,
      Caveat.holds]
  | PortIn ports =>
    simp [grant_eval.network.holds, port_in_eq, denoteCaveat, denoteAction, Caveat.holds]
  | SchemeIn schemes =>
    simp [grant_eval.network.holds, scheme_in_eq, denoteCaveat, denoteAction, Caveat.holds]

/-! ## Equivalence -/

theorem inst_holds_eq (c : grant_eval.network.Caveat) (a : grant_eval.network.Action) :
    grant_eval.network.Caveat.Insts.Grant_evalEvalCheckAction.holds c a =
      ok ((denoteCaveat c).holds (denoteAction a)) :=
  holds_eq c a

/-- The extracted `allows` returns `ok` on every input, and its result is
`Grant.allows` of the denoted grant and action. -/
theorem extracted_allows (g : Slice grant_eval.network.Caveat) (a : grant_eval.network.Action) :
    grant_eval.network.allows g a = ok ((denoteGrant g).allows (denoteAction a)) := by
  unfold grant_eval.network.allows
  rw [eval_allows_eq _ _ inst_holds_eq, denoteGrant_allows]

/-- The extracted `allows_all` returns `ok` on every input, and its result is
`Grant.allowsAll` of the denoted grant and actions. -/
theorem extracted_allowsAll (g : Slice grant_eval.network.Caveat)
    (acts : Slice grant_eval.network.Action) :
    grant_eval.network.allows_all g acts =
      ok ((denoteGrant g).allowsAll (acts.val.map denoteAction)) := by
  unfold grant_eval.network.allows_all
  rw [eval_allows_all_eq _ _ inst_holds_eq]
  simp [Grant.allowsAll, List.all_map, Function.comp_def, denoteGrant_allows]

theorem implements :
    Implements grant_eval.network.allows fun c a => (denoteCaveat c).holds (denoteAction a) :=
  (implements_iff_all _ _).mpr fun g a => by
    rw [extracted_allows, denoteGrant_allows]

theorem implementsAll :
    ImplementsAll grant_eval.network.allows_all
      fun c a => (denoteCaveat c).holds (denoteAction a) :=
  (implementsAll_iff_all _ _).mpr fun g acts => by
    unfold grant_eval.network.allows_all
    exact eval_allows_all_eq _ _ inst_holds_eq g acts

/-! ## Attenuation and chaining on caveat slices -/

theorem extracted_narrower_of_subset {g g' : Slice grant_eval.network.Caveat}
    (hsub : ∀ c ∈ g.val, c ∈ g'.val) : Narrower grant_eval.network.allows g' g :=
  implements.narrower_of_subset hsub

theorem extracted_narrower_push {g g' : Slice grant_eval.network.Caveat}
    {c : grant_eval.network.Caveat} (hpush : g'.val = g.val ++ [c]) :
    Narrower grant_eval.network.allows g' g :=
  implements.narrower_push hpush

theorem extracted_delegates_narrower {root g : Slice grant_eval.network.Caveat}
    (h : Extraction.Delegates root g) : Narrower grant_eval.network.allows g root :=
  implements.narrower_of_delegates h

theorem extracted_allowsAll_of_delegates {root g : Slice grant_eval.network.Caveat}
    (h : Extraction.Delegates root g) (acts : Slice grant_eval.network.Action) :
    grant_eval.network.allows_all g acts = ok true →
      grant_eval.network.allows_all root acts = ok true :=
  implementsAll.allows_all_of_narrower implements (extracted_delegates_narrower h) acts

end AttenuatingGrants.Network
