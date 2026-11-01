import AttenuatingGrants.Vocab.Chain
import AttenuatingGrants.Equiv.Bytes
import AttenuatingGrants.Equiv.Eval

/-!
# Chain: the extracted evaluator agrees with the model

`denoteVal`, `denoteAction` and `denoteCaveat` map the extracted
`grant_eval.chain` types to the readable ones: an `i128` to its bit vector
(compared signed on both sides), a `u64` to the `UInt64` with the same bit
vector, byte strings by `bytesOf`, an argument index `u32` to its value as a
`Nat`.

* `val_eq_eq`: the extracted `val_eq` is equality of the denoted values.
* `extracted_allows`: `chain.allows g a` returns `ok` of `Grant.allows` on the
  denoted grant and action, for every input.
* `extracted_allowsAll`: likewise `chain.allows_all` and `Grant.allowsAll`.
* `extracted_narrower_push`, `extracted_delegates_narrower`,
  `extracted_allowsAll_of_delegates`: attenuation and chaining for the
  extracted evaluator on caveat slices.
* `extracted_denies_createContract`: a non-empty extracted chain grant denies
  every contract deployment.
-/

namespace AttenuatingGrants.Chain

open Aeneas Aeneas.Std Result ControlFlow Extraction

/-! ## Denotation -/

def denoteU64 (x : Std.U64) : UInt64 := UInt64.ofBitVec x.bv

def denoteVal : grant_eval.chain.Val → Val
  | .I128 x => .i128 x.bv
  | .U64 x => .u64 (denoteU64 x)
  | .Bool b => .bool b
  | .Bytes v => .bytes (bytesOf v.val)
  | .Address v => .address (bytesOf v.val)
  | .Symbol v => .symbol (bytesOf v.val)

def denoteAction : grant_eval.chain.Action → Action
  | .Invoke contract function args =>
    .invoke (bytesOf contract.val) (bytesOf function.val) (args.val.map denoteVal)
  | .CreateContract wasmHash => .createContract (bytesOf wasmHash.val)

def denoteCaveat : grant_eval.chain.Caveat → Caveat
  | .ContractIn contracts => .contractIn (contracts.val.map fun c => bytesOf c.val)
  | .FunctionIn functions => .functionIn (functions.val.map fun f => bytesOf f.val)
  | .ArgI128AtMost index n => .argI128AtMost index.val n.bv
  | .ArgEq index val => .argEq index.val (denoteVal val)

/-- The readable grant a Rust caveat slice denotes. -/
def denoteGrant (g : Slice grant_eval.chain.Caveat) : Grant Action :=
  grant (g.val.map denoteCaveat)

theorem denoteGrant_allows (g : Slice grant_eval.chain.Caveat) (a : Action) :
    (denoteGrant g).allows a = g.val.all fun c => (denoteCaveat c).holds a := by
  simp [denoteGrant, grant, Grant.allows, List.all_map, Function.comp_def]

/-! ## Values -/

theorem i128_bv_inj {x y : Std.I128} : x.bv = y.bv ↔ x = y := by
  constructor
  · intro h
    cases x
    cases y
    simp_all
  · intro h
    rw [h]

theorem denoteU64_inj {x y : Std.U64} : denoteU64 x = denoteU64 y ↔ x = y := by
  constructor
  · intro h
    have hbv : x.bv = y.bv := congrArg UInt64.toBitVec h
    cases x
    cases y
    simp_all
  · intro h
    rw [h]

theorem val_eq_eq (a b : grant_eval.chain.Val) :
    grant_eval.chain.val_eq a b = ok (decide (denoteVal a = denoteVal b)) := by
  cases a <;> cases b <;>
    simp [grant_eval.chain.val_eq, denoteVal, bytes_eq_eq, bytesOf_inj, i128_bv_inj,
      denoteU64_inj]

/-! ## Caveats -/

theorem slice_get_eq {α : Type} (s : Slice α) (i : Usize) :
    core.slice.Slice.get (core.slice.index.SliceIndexUsizeSlice α) s i = ok s.val[i.val]? := by
  simp [core.slice.Slice.get]

theorem cast_index_val (index : Std.U32) : (UScalar.cast .Usize index).val = index.val :=
  U32.cast_Usize_val_eq index

theorem holds_eq (c : grant_eval.chain.Caveat) (a : grant_eval.chain.Action) :
    grant_eval.chain.holds c a = ok ((denoteCaveat c).holds (denoteAction a)) := by
  cases a with
  | CreateContract wasmHash =>
    cases c <;> simp [grant_eval.chain.holds, denoteAction, holds_createContract]
  | Invoke contract function args =>
    cases c with
    | ContractIn contracts =>
      simp [grant_eval.chain.holds, bytes_in_eq, any_bytes_eq_mem, denoteCaveat, denoteAction,
        Caveat.holds]
    | FunctionIn functions =>
      simp [grant_eval.chain.holds, bytes_in_eq, any_bytes_eq_mem, denoteCaveat, denoteAction,
        Caveat.holds]
    | ArgI128AtMost index n =>
      simp only [grant_eval.chain.holds, lift, bind_ok, slice_get_eq, vec_deref_val,
        cast_index_val, denoteCaveat, denoteAction, Caveat.holds, List.getElem?_map]
      cases args.val[index.val]? with
      | none => rfl
      | some v =>
        cases v <;> simp [denoteVal]
    | ArgEq index val =>
      simp only [grant_eval.chain.holds, lift, bind_ok, slice_get_eq, vec_deref_val,
        cast_index_val, denoteCaveat, denoteAction, Caveat.holds, List.getElem?_map]
      cases args.val[index.val]? with
      | none => simp
      | some v => simp [val_eq_eq]

/-! ## Equivalence -/

theorem inst_holds_eq (c : grant_eval.chain.Caveat) (a : grant_eval.chain.Action) :
    grant_eval.chain.Caveat.Insts.Grant_evalEvalCheckAction.holds c a =
      ok ((denoteCaveat c).holds (denoteAction a)) :=
  holds_eq c a

/-- The extracted `allows` returns `ok` on every input, and its result is
`Grant.allows` of the denoted grant and action. -/
theorem extracted_allows (g : Slice grant_eval.chain.Caveat) (a : grant_eval.chain.Action) :
    grant_eval.chain.allows g a = ok ((denoteGrant g).allows (denoteAction a)) := by
  unfold grant_eval.chain.allows
  rw [eval_allows_eq _ _ inst_holds_eq, denoteGrant_allows]

/-- The extracted `allows_all` returns `ok` on every input, and its result is
`Grant.allowsAll` of the denoted grant and actions: every context of a Soroban
authorization tree. -/
theorem extracted_allowsAll (g : Slice grant_eval.chain.Caveat)
    (acts : Slice grant_eval.chain.Action) :
    grant_eval.chain.allows_all g acts =
      ok ((denoteGrant g).allowsAll (acts.val.map denoteAction)) := by
  unfold grant_eval.chain.allows_all
  rw [eval_allows_all_eq _ _ inst_holds_eq]
  simp [Grant.allowsAll, List.all_map, Function.comp_def, denoteGrant_allows]

theorem implements :
    Implements grant_eval.chain.allows fun c a => (denoteCaveat c).holds (denoteAction a) :=
  (implements_iff_all _ _).mpr fun g a => by
    rw [extracted_allows, denoteGrant_allows]

theorem implementsAll :
    ImplementsAll grant_eval.chain.allows_all
      fun c a => (denoteCaveat c).holds (denoteAction a) :=
  (implementsAll_iff_all _ _).mpr fun g acts => by
    unfold grant_eval.chain.allows_all
    exact eval_allows_all_eq _ _ inst_holds_eq g acts

/-- A non-empty extracted chain grant denies every contract deployment. -/
theorem extracted_denies_createContract (g : Slice grant_eval.chain.Caveat) (h : g.val ≠ [])
    (wasmHash : alloc.vec.Vec Std.U8) :
    grant_eval.chain.allows g (.CreateContract wasmHash) = ok false := by
  rw [extracted_allows]
  exact congrArg ok (restricted_denies_createContract (by simpa using h) _)

/-! ## Attenuation and chaining on caveat slices -/

theorem extracted_narrower_of_subset {g g' : Slice grant_eval.chain.Caveat}
    (hsub : ∀ c ∈ g.val, c ∈ g'.val) : Narrower grant_eval.chain.allows g' g :=
  implements.narrower_of_subset hsub

theorem extracted_narrower_push {g g' : Slice grant_eval.chain.Caveat}
    {c : grant_eval.chain.Caveat} (hpush : g'.val = g.val ++ [c]) :
    Narrower grant_eval.chain.allows g' g :=
  implements.narrower_push hpush

theorem extracted_delegates_narrower {root g : Slice grant_eval.chain.Caveat}
    (h : Extraction.Delegates root g) : Narrower grant_eval.chain.allows g root :=
  implements.narrower_of_delegates h

theorem extracted_allowsAll_of_delegates {root g : Slice grant_eval.chain.Caveat}
    (h : Extraction.Delegates root g) (acts : Slice grant_eval.chain.Action) :
    grant_eval.chain.allows_all g acts = ok true →
      grant_eval.chain.allows_all root acts = ok true :=
  implementsAll.allows_all_of_narrower implements (extracted_delegates_narrower h) acts

end AttenuatingGrants.Chain
