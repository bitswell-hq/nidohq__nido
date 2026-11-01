import AttenuatingGrants.Signer
import AttenuatingGrants.Equiv.Budget

/-!
# The grant signer's calls to the extracted budget code

The contract holds an authorization's lineage ledger as a vector of
`budget::Node` and calls the extracted functions on its slice:
`check_spend` at the last node for `overdrawn_at`, and `spend` at the last
node once per metered transfer for `__check_auth`, stopping at the first
error. `spendAllExtracted` is that loop as a Lean definition over the
extracted `spend`.

* `extracted_spendAll`: the loop returns, and its result denotes the model's
  `spendAll` on the denoted ledger.
* `extracted_spendAll_lineage`: on a slice denoting the lineage ledger of a
  whole ledger whose parents precede their children, the loop's result
  denotes the whole ledger's batch at the signing grant, restricted to the
  lineage. With `Signer.Step.exists_run`, the contract's stored result is a
  run of the whole ledger, so `Signer.spentUnder_le_allowance` holds for it.
* `extracted_check_spend_lineage`: `check_spend` on such a slice has the
  whole ledger's outcome at the signing grant, with node `k` standing for
  grant `gid ps k`: the grant `overdrawn_at` names.

That the contract's vector denotes `chain ps` for the lineage it loaded is
the wiring `contracts/grant-signer/src/contract.rs` (`ledger`) does, not
proven here.
-/

namespace AttenuatingGrants.Budget

open Aeneas Aeneas.Std Result grant_eval Ledger

/-- The contract's spends of one authorization through the extracted `spend`:
each amount in order at node `i`, stopping at the first error; `none` if one
failed. -/
def spendAllExtracted (s : Slice budget.Node) (i : Usize) :
    List Std.U128 → Result (Option (Slice budget.Node))
  | [] => ok (some s)
  | x :: xs =>
    Aeneas.Std.bind (budget.spend s i x) fun (r, s') =>
      match r with
      | .Ok () => spendAllExtracted s' i xs
      | .Err _ => ok none

/-- The loop returns, and its result denotes the model's batch. -/
theorem extracted_spendAll (s : Slice budget.Node) (i : Usize) (xs : List Std.U128) :
    ∃ r, spendAllExtracted s i xs = ok r ∧
      r.map (fun s' => denoteLedger s'.val) =
        (denoteLedger s.val).spendAll i.val (xs.map (·.val)) := by
  induction xs generalizing s with
  | nil => exact ⟨some s, rfl, rfl⟩
  | cons x xs ih =>
    obtain ⟨r, s', hs, hr, hd⟩ := extracted_spend s i x
    have hmodel :
        (denoteLedger s.val).spend i.val x.val = (denoteSpend r, denoteLedger s'.val) := by
      rw [hr, hd]
    cases r with
    | Ok u =>
      obtain ⟨r', hr', hd'⟩ := ih s'
      refine ⟨r', ?_, ?_⟩
      · simp only [spendAllExtracted, hs, bind_ok, hr']
      · simp only [List.map_cons, spendAll, hmodel, denoteSpend]
        exact hd'
    | Err e =>
      refine ⟨none, ?_, ?_⟩
      · simp only [spendAllExtracted, hs, bind_ok]
      · simp only [List.map_cons, spendAll, hmodel, denoteSpend, Option.map_none]

/-- On a slice denoting the lineage ledger of `ps`, the loop's result denotes
the whole ledger's batch at the signing grant, restricted to the lineage. -/
theorem extracted_spendAll_lineage {l : Ledger} (hpf : l.ParentsFirst) {ps : List (Nat × Node)}
    (hl : l.IsLineage ps) {e : Nat × Node} (hlast : ps.getLast? = some e)
    {s : Slice budget.Node} (hs : denoteLedger s.val = chain ps) {i : Usize}
    (hi : i.val = ps.length - 1) (xs : List Std.U128) :
    ∃ r, spendAllExtracted s i xs = ok r ∧
      r.map (fun s' => denoteLedger s'.val) =
        (l.spendAll e.1 (xs.map (·.val))).map (fun l' => chain (reread l' ps)) := by
  obtain ⟨r, hr, hd⟩ := extracted_spendAll s i xs
  refine ⟨r, hr, ?_⟩
  rw [hd, hs, hi, spendAll_lineage hpf hl hlast]

/-- On a slice denoting the lineage ledger of `ps`, `check_spend` at the last
node has the whole ledger's outcome at the signing grant, with node `k`
standing for grant `gid ps k`. -/
theorem extracted_check_spend_lineage {l : Ledger} (hpf : l.ParentsFirst)
    {ps : List (Nat × Node)} (hl : l.IsLineage ps) {e : Nat × Node}
    (hlast : ps.getLast? = some e) {s : Slice budget.Node} (hs : denoteLedger s.val = chain ps)
    {i : Usize} (hi : i.val = ps.length - 1) (x : Std.U128) :
    ∃ r, budget.check_spend s i x = ok r ∧
      (denoteSpend r).mapError (renameError ps) = (l.chargePath e.1 x.val).map (fun _ => ()) := by
  obtain ⟨r, hr, hd⟩ := extracted_check_spend s i x
  refine ⟨r, hr, ?_⟩
  rw [hd, hs, hi, chargePath_lineage hpf hl hlast, mapError_map_unit]

end AttenuatingGrants.Budget
