import AttenuatingGrants.Budget
import AttenuatingGrants.Equiv.Loop

/-!
# Budgets in the extracted evaluator

`grant_eval::budget` keeps the ledger as a slice (for `append`, a `Vec`) of
`Node { parent: Option<usize>, allowance: u128, spent: u128 }`. Its
denotation `denoteLedger` maps each node to the model's `Node` by the values
of its scalars, so a Rust ledger denotes a model ledger whose fields fit in
`u128`, and the theorems below hold for every Rust ledger. `denoteLedger` is
injective (`denoteLedger_injective`), so the denotation of a returned ledger
determines it.

Equivalence, for every slice `s`, index `i` and amount `x`, with
`L = denoteLedger s.val`:

* `extracted_check_spend`: `check_spend s i x` returns `ok`, and its outcome
  denotes `L.chargePath i x` with the path dropped.
* `extracted_spend`: `spend s i x` returns `ok (r, s')` with `r` denoting the
  model's outcome and `s'` denoting the model's ledger after it.
  `extracted_spend_error`: on `Err`, `s'` is `s` itself.
* `extracted_refill`, `extracted_refill_error`: the same for `refill`.
* `extracted_append`: on a vector holding fewer than `Usize.max` nodes,
  `append v p x` returns the model's outcome and ledger.
  `extracted_append_error`: on `Err`, the vector is returned unchanged.

The building blocks are `fits_eq` (Rust's `checked_add` test is the model's
comparison), `check_spend_loop_eq` (the checking loop is the model's `walk`
with the steps left as fuel) and `charge_loop_eq` (after a successful walk of
`path`, the charging loop adds the amount to exactly the nodes of `path`). The
charging loop's plain `spent + amount` is discharged there: the walk found
`spent + amount ≤ allowance ≤ u128::MAX` at each node, and the loop visits
each node of the path once, so the addition never overflows.

Budget safety for the extracted code, as corollaries:

* `extracted_spend_ok_charges`, `extracted_spend_ok_unchanged`,
  `extracted_spend_ok_length`, `extracted_spend_error` (theorem 4): a
  successful `spend` charges the spender and every ancestor and changes
  nothing else; a failed one returns its input.
* `extracted_spend_overdrawn`: an `Overdrawn` error names a node on the
  spender's chain that the spend would overdraw.
* `extracted_spend_withinAllowance`, `extracted_refill_withinAllowance`,
  `extracted_append_withinAllowance`, `extracted_run_withinAllowance`: every
  node's spent stays within its allowance.
* `extracted_run`, `extracted_spentUnder_le_allowance`: over any run of the
  extracted functions (`runExtracted`, which calls them as a Rust caller
  holding the ledger in a `Vec` does), the result is the model's run, so from
  a ledger with nothing spent the total successfully spent at or under a node
  never exceeds its allowance.

`Vec::push` is the one call that can fail in Aeneas's model: it fails once a
vector holds `Usize.max` elements. `extracted_append` and the run theorems
therefore assume the ledger stays below that many nodes.
-/

namespace AttenuatingGrants.Budget

open Aeneas Aeneas.Std Result ControlFlow grant_eval Extraction

/-! ## Denotation -/

theorem u128_le_max (x : Std.U128) : x.val ≤ amountMax := by
  have := x.hBounds
  rw [UScalarTy.U128_numBits_eq] at this
  simp only [amountMax]
  omega


/-- A Rust ledger node as a model node. -/
def denoteNode (n : budget.Node) : Node :=
  ⟨n.parent.map (·.val), n.allowance.val, n.spent.val⟩

/-- A Rust ledger as a model ledger. -/
def denoteLedger (l : List budget.Node) : Ledger :=
  l.map denoteNode

def denoteSpendError : budget.SpendError → SpendError
  | .NoSuchNode i => .noSuchNode i.val
  | .BadParent i => .badParent i.val
  | .Overdrawn i => .overdrawn i.val

def denoteRefillError : budget.RefillError → RefillError
  | .NoSuchNode i => .noSuchNode i.val
  | .Overflow i => .overflow i.val

def denoteAppendError : budget.AppendError → AppendError
  | .NoSuchNode i => .noSuchNode i.val

/-- A Rust spend outcome as a model one. -/
def denoteSpend : core.result.Result Unit budget.SpendError → Except SpendError Unit
  | .Ok () => .ok ()
  | .Err e => .error (denoteSpendError e)

/-- A Rust refill outcome as a model one. -/
def denoteRefill : core.result.Result Unit budget.RefillError → Except RefillError Unit
  | .Ok () => .ok ()
  | .Err e => .error (denoteRefillError e)

/-- A Rust append outcome as a model one. -/
def denoteAppend : core.result.Result Usize budget.AppendError → Except AppendError Nat
  | .Ok k => .ok k.val
  | .Err e => .error (denoteAppendError e)

theorem denoteNode_injective : Function.Injective denoteNode := by
  intro a b h
  obtain ⟨pa, aa, sa⟩ := a
  obtain ⟨pb, ab, sb⟩ := b
  simp only [denoteNode, Node.mk.injEq] at h
  obtain ⟨hp, ha, hs⟩ := h
  have hp' : pa = pb := by
    cases pa <;> cases pb <;> simp_all
    exact UScalar.eq_of_val_eq hp
  have ha' : aa = ab := UScalar.eq_of_val_eq ha
  have hs' : sa = sb := UScalar.eq_of_val_eq hs
  subst hp' ha' hs'
  rfl

theorem denoteLedger_injective : Function.Injective denoteLedger :=
  List.map_injective_iff.mpr denoteNode_injective

theorem getElem?_denoteLedger (l : List budget.Node) (i : Nat) :
    (denoteLedger l)[i]? = l[i]?.map denoteNode := by
  simp [denoteLedger]

theorem length_denoteLedger (l : List budget.Node) : (denoteLedger l).length = l.length := by
  simp [denoteLedger]

theorem denoteLedger_set (l : List budget.Node) (i : Nat) (n : budget.Node) :
    denoteLedger (l.set i n) = (denoteLedger l).set i (denoteNode n) := by
  simp [denoteLedger, List.map_set]

/-- Every denoted allowance is at most `amountMax`. -/
theorem denoteLedger_bounded (l : List budget.Node) : (denoteLedger l).Bounded := by
  intro n hn
  obtain ⟨m, -, rfl⟩ := List.mem_map.mp hn
  exact u128_le_max m.allowance

/-! ## Scalars -/


/-- The charging addition succeeds when the sum fits. -/
theorem u128_add_eq (x y : Std.U128) (h : x.val + y.val ≤ amountMax) :
    ∃ z : Std.U128, x + y = ok z ∧ z.val = x.val + y.val := by
  have hmax : x.val + y.val ≤ UScalar.max .U128 := by
    rw [UScalar.max_UScalarTy_U128_eq, U128.max_eq]
    simp only [amountMax] at h
    omega
  have := UScalar.add_spec (ty := .U128) hmax
  revert this
  cases (x + y) with
  | ret r => intro hr; exact ⟨r, rfl, by simpa using hr⟩
  | vis e k => intro hr; simp at hr
  | div => intro hr; simp at hr

/-- `fits` is the model's test that a node can take `amount`. -/
theorem fits_eq (n : budget.Node) (x : Std.U128) :
    budget.fits n x = ok (decide (n.spent.val + x.val ≤ n.allowance.val)) := by
  have spec := U128.checked_add_bv_spec n.spent x
  unfold budget.fits
  simp only [lift, bind_ok]
  cases hc : U128.checked_add n.spent x with
  | none =>
    rw [hc] at spec
    have := u128_le_max n.allowance
    simp only [U128.max_eq, amountMax] at spec this
    have : ¬ n.spent.val + x.val ≤ n.allowance.val := by omega
    simp [this]
  | some z =>
    rw [hc] at spec
    obtain ⟨-, hz, -⟩ := spec
    simp only [ok.injEq, decide_eq_decide]
    rw [← hz]
    rfl

/-! ## `check_spend` -/

theorem except_map_cons_const {ε : Type} (e : Except ε (List Nat)) (i : Nat) :
    (e.map (i :: ·)).map (fun _ => ()) = e.map (fun _ => ()) := by
  cases e <;> rfl

theorem check_spend_loop_unfold (s : Slice budget.Node) (x : Std.U128) (cur step : Usize) :
    budget.check_spend_loop s x cur step =
      Aeneas.Std.bind (budget.check_spend_loop.body s x cur step) (fun r =>
        match r with
        | cont p => budget.check_spend_loop s x p.1 p.2
        | done r => ok r) := by
  unfold budget.check_spend_loop
  rw [loop]
  congr 1
  funext r
  cases r <;> rfl

/-- The walk of `check_spend` from `cur` with `step` steps taken is the
model's walk with the remaining steps as fuel. -/
theorem check_spend_loop_eq (s : Slice budget.Node) (x : Std.U128) :
    ∀ (fuel : Nat) (cur step : Usize), step.val + fuel = s.length →
      ∃ r, budget.check_spend_loop s x cur step = ok r ∧
        denoteSpend r = ((denoteLedger s.val).walk x.val fuel cur.val).map (fun _ => ())
  | 0, cur, step, h => by
    have hs : ¬ step.val < s.length := by omega
    rw [check_spend_loop_unfold]
    simp [budget.check_spend_loop.body, hs, Ledger.walk, denoteSpend, denoteSpendError,
      Except.map]
  | fuel + 1, cur, step, h => by
    have hs : step.val < s.length := by omega
    rw [check_spend_loop_unfold]
    simp only [budget.check_spend_loop.body, slice_len_lt, hs, ↓reduceIte,
      core.slice.Slice.get, core.slice.index.Usize.get, Slice.getElem?_Usize_eq, bind_ok]
    cases hn : s.val[cur.val]? with
    | none =>
      simp [Ledger.walk, getElem?_denoteLedger, hn, denoteSpend, denoteSpendError, Except.map]
    | some n =>
      simp only [fits_eq, bind_ok]
      by_cases hfit : n.spent.val + x.val ≤ n.allowance.val
      · have hnot : ¬ n.allowance.val < n.spent.val + x.val := by omega
        simp only [hfit, decide_true, ↓reduceIte]
        cases hp : n.parent with
        | none =>
          simp [Ledger.walk, getElem?_denoteLedger, hn, denoteNode, hp, hnot, denoteSpend,
            Except.map]
        | some p =>
          by_cases hpc : p.val < cur.val
          · have hge : ¬ (p ≥ cur) := by
              intro h'; have : cur.val ≤ p.val := h'; omega
            obtain ⟨step1, hstep1, hstep1'⟩ := incr_eq s step hs
            obtain ⟨r, hr, hd⟩ := check_spend_loop_eq s x fuel p step1 (by omega)
            simp only [hge, ↓reduceIte, hstep1, bind_ok]
            refine ⟨r, hr, ?_⟩
            rw [hd]
            simp [Ledger.walk, getElem?_denoteLedger, hn, denoteNode, hp, hnot, hpc,
              except_map_cons_const]
          · have hge : p ≥ cur := by show cur.val ≤ p.val; omega
            simp [hge, Ledger.walk, getElem?_denoteLedger, hn, denoteNode, hp, hnot, hpc,
              denoteSpend, denoteSpendError, Except.map]
      · have hover : n.allowance.val < n.spent.val + x.val := by omega
        simp [hfit, Ledger.walk, getElem?_denoteLedger, hn, denoteNode, hover, denoteSpend,
          denoteSpendError, Except.map]

/-- `check_spend` returns the model's outcome on the denoted ledger. -/
theorem extracted_check_spend (s : Slice budget.Node) (i : Usize) (x : Std.U128) :
    ∃ r, budget.check_spend s i x = ok r ∧
      denoteSpend r = ((denoteLedger s.val).chargePath i.val x.val).map (fun _ => ()) := by
  obtain ⟨r, hr, hd⟩ := check_spend_loop_eq s x s.length i 0#usize (by simp)
  refine ⟨r, hr, ?_⟩
  rw [hd, Ledger.chargePath, length_denoteLedger]

/-! ## Charging -/

namespace Ledger

/-- The walk from `i` reads only nodes at or before `i`. -/
theorem walk_congr {l l' : Ledger} {amount : Nat} :
    ∀ {fuel i}, (∀ j ≤ i, l[j]? = l'[j]?) → l.walk amount fuel i = l'.walk amount fuel i
  | 0, _, _ => rfl
  | fuel + 1, i, h => by
    unfold walk
    rw [← h i (Nat.le_refl i)]
    cases l[i]? with
    | none => rfl
    | some n =>
      simp only
      split
      · rfl
      · cases n.parent with
        | none => rfl
        | some p =>
          simp only
          split
          · rename_i hp
            rw [walk_congr (fun j hj => h j (by omega))]
          · rfl

/-- Every node the walk returns is at or before its start. -/
theorem walk_le {l : Ledger} {amount : Nat} :
    ∀ {fuel i path}, l.walk amount fuel i = .ok path → ∀ j ∈ path, j ≤ i
  | 0, _, _, h => by simp [walk] at h
  | fuel + 1, i, path, h => by
    unfold walk at h
    cases hi : l[i]? with
    | none => simp [hi] at h
    | some n =>
      simp only [hi] at h
      split at h
      · simp at h
      · cases hp : n.parent with
        | none =>
          simp only [hp, Except.ok.injEq] at h
          subst h
          simp
        | some p =>
          simp only [hp] at h
          split at h
          · rename_i hpi
            cases hw : l.walk amount fuel p with
            | error e => simp [hw, Except.map] at h
            | ok rest =>
              simp only [hw, Except.map, Except.ok.injEq] at h
              subst h
              intro j hj
              rcases List.mem_cons.mp hj with rfl | hj
              · exact Nat.le_refl _
              · exact Nat.le_of_lt (Nat.lt_of_le_of_lt (walk_le hw j hj) hpi)
          · simp at h

theorem charge_nil (l : Ledger) (amount : Nat) : l.charge [] amount = l := by
  apply List.ext_getElem?
  intro j
  rw [getElem?_charge]
  cases l[j]? <;> simp

/-- Charging `i` and then `rest` is charging `i :: rest`, when `i` is not in
`rest`. -/
theorem charge_set {l : Ledger} {i amount : Nat} {n : Node} (hi : l[i]? = some n)
    (rest : List Nat) (hni : i ∉ rest) :
    Ledger.charge (l.set i { n with spent := n.spent + amount }) rest amount =
      l.charge (i :: rest) amount := by
  apply List.ext_getElem?
  intro j
  rw [getElem?_charge, getElem?_charge, List.getElem?_set]
  by_cases hj : i = j
  · subst hj
    simp [lt_length_of_getElem? hi, getElem_of_getElem? hi, hni]
  · simp [hj, Ne.symm hj]

end Ledger

theorem set_opt_some {α : Type} (l : List α) (i : Nat) (y : α) :
    l.set_opt i (some y) = l.set i y := by
  induction l generalizing i with
  | nil => simp
  | cons hd tl ih =>
    cases i with
    | zero => simp
    | succ k => simp [List.set_opt, ih]

theorem charge_loop_unfold (s : Slice budget.Node) (x : Std.U128) (cur step : Usize) :
    budget.charge_loop s x cur step =
      Aeneas.Std.bind (budget.charge_loop.body x s cur step) (fun r =>
        match r with
        | cont p => budget.charge_loop p.1 x p.2.1 p.2.2
        | done r => ok r) := by
  unfold budget.charge_loop
  rw [loop]
  congr 1
  funext r
  cases r <;> rfl

/-- One round of the charging loop at an existing node. -/
theorem charge_loop_body_some (x : Std.U128) (s : Slice budget.Node) (cur step : Usize)
    (n : budget.Node) (hs : step.val < s.length) (hn : s.val[cur.val]? = some n) :
    budget.charge_loop.body x s cur step =
      Aeneas.Std.bind (n.spent + x) (fun i1 =>
        match n.parent with
        | none => ok (done (s.set_opt cur (some { n with spent := i1 })))
        | some parent => Aeneas.Std.bind (step + 1#usize) (fun step1 =>
            ok (cont (s.set_opt cur (some { n with spent := i1 }), parent, step1)))) := by
  simp only [budget.charge_loop.body, slice_len_lt, hs, ↓reduceIte,
    core.slice.Slice.get_mut, core.slice.index.Usize.get_mut, Slice.getElem?_Usize_eq, hn,
    bind_ok]
  rfl

/-- After a successful walk of `path` from `cur` with `step` steps taken, the
charging loop adds the amount to exactly the nodes of `path`. -/
theorem charge_loop_eq (x : Std.U128) :
    ∀ (fuel : Nat) (s : Slice budget.Node) (cur step : Usize) (path : List Nat),
      step.val + fuel = s.length →
      (denoteLedger s.val).walk x.val fuel cur.val = .ok path →
      ∃ s', budget.charge_loop s x cur step = ok s' ∧
        denoteLedger s'.val = (denoteLedger s.val).charge path x.val
  | 0, _, _, _, _, _, hw => by simp [Ledger.walk] at hw
  | fuel + 1, s, cur, step, path, h, hw => by
    have hs : step.val < s.length := by omega
    have hw' := hw
    unfold Ledger.walk at hw'
    rw [getElem?_denoteLedger] at hw'
    cases hn : s.val[cur.val]? with
    | none => simp [hn] at hw'
    | some n =>
      simp only [hn, Option.map_some] at hw'
      split at hw'
      · simp at hw'
      · rename_i hfit
        have hfit' : n.spent.val + x.val ≤ n.allowance.val := by
          simp only [denoteNode] at hfit; omega
        obtain ⟨z, hz, hzv⟩ := u128_add_eq n.spent x
          (Nat.le_trans hfit' (u128_le_max n.allowance))
        have hdn : (denoteLedger s.val)[cur.val]? = some (denoteNode n) := by
          simp [getElem?_denoteLedger, hn]
        have hset : denoteLedger (s.val.set cur.val { n with spent := z }) =
            (denoteLedger s.val).set cur.val
              { denoteNode n with spent := (denoteNode n).spent + x.val } := by
          rw [denoteLedger_set]
          simp [denoteNode, hzv]
        rw [charge_loop_unfold, charge_loop_body_some x s cur step n hs hn, hz, bind_ok]
        cases hp : n.parent with
        | none =>
          simp only [denoteNode, hp, Option.map_none, Except.ok.injEq] at hw'
          subst hw'
          rw [hp] at hset
          simp only [bind_ok]
          refine ⟨_, rfl, ?_⟩
          rw [Slice.set_opt_val_eq, set_opt_some, hset]
          exact (Ledger.charge_nil _ _).symm.trans (Ledger.charge_set hdn [] List.not_mem_nil)
        | some p =>
          simp only [denoteNode, hp, Option.map_some] at hw'
          split at hw'
          · rename_i hpc
            cases hrest : (denoteLedger s.val).walk x.val fuel p.val with
            | error e => simp [hrest, Except.map] at hw'
            | ok rest =>
              simp only [hrest, Except.map, Except.ok.injEq] at hw'
              subst hw'
              obtain ⟨step1, hstep1, hstep1'⟩ := incr_eq s step hs
              simp only [hstep1, bind_ok]
              rw [hp] at hset
              let s1 := s.set_opt cur (some ⟨some p, n.allowance, z⟩)
              have hs1 : s1.val = s.val.set cur.val ⟨some p, n.allowance, z⟩ := by
                simp [s1, Slice.set_opt_val_eq, set_opt_some]
              have hlen1 : s1.length = s.length := by
                simp [Slice.length, hs1]
              have hw1 : (denoteLedger s1.val).walk x.val fuel p.val = .ok rest := by
                rw [← hrest]
                apply Ledger.walk_congr
                intro j hj
                rw [hs1, getElem?_denoteLedger, getElem?_denoteLedger,
                  List.getElem?_set_ne (by omega)]
              obtain ⟨s', hs', hd⟩ := charge_loop_eq x fuel s1 p step1 rest (by omega) hw1
              refine ⟨s', hs', ?_⟩
              rw [hd, hs1, hset]
              apply Ledger.charge_set hdn
              intro hm
              have := Ledger.walk_le hrest _ hm
              omega
          · simp at hw'

theorem set_opt_none {α : Type} (l : List α) (i : Nat) : l.set_opt i none = l := by
  induction l generalizing i with
  | nil => simp
  | cons hd tl ih =>
    cases i with
    | zero => simp
    | succ k => simp [List.set_opt, ih]

theorem slice_set_opt_none {α : Type} (s : Slice α) (i : Usize) : s.set_opt i none = s := by
  apply Slice.eq_iff _ _ |>.mpr
  rw [Slice.set_opt_val_eq, set_opt_none]

theorem slice_set_opt_self {α : Type} (s : Slice α) (i : Usize) (n : α)
    (hn : s.val[i.val]? = some n) : s.set_opt i (some n) = s := by
  apply Slice.eq_iff _ _ |>.mpr
  rw [Slice.set_opt_val_eq, set_opt_some]
  obtain ⟨hlt, rfl⟩ := List.getElem?_eq_some_iff.mp hn
  exact List.set_getElem_self hlt

/-! ## Spend and refill -/

/-- `spend` returns the model's outcome and the model's ledger after it: on
success, the denoted ledger with the spender and every ancestor charged; on
failure, the model's error. It never fails. -/
theorem extracted_spend (s : Slice budget.Node) (i : Usize) (x : Std.U128) :
    ∃ r s', budget.spend s i x = ok (r, s') ∧
      denoteSpend r = ((denoteLedger s.val).spend i.val x.val).1 ∧
      denoteLedger s'.val = ((denoteLedger s.val).spend i.val x.val).2 := by
  obtain ⟨r, hr, hd⟩ := extracted_check_spend s i x
  unfold budget.spend
  rw [hr, bind_ok]
  cases r with
  | Ok u =>
    cases hc : (denoteLedger s.val).chargePath i.val x.val with
    | error e => simp [hc, denoteSpend, Except.map] at hd
    | ok path =>
      have hw : (denoteLedger s.val).walk x.val (s.length - (0#usize).val) i.val = .ok path := by
        simpa [Ledger.chargePath, length_denoteLedger] using hc
      obtain ⟨s', hs', hd'⟩ := charge_loop_eq x (s.length - (0#usize).val) s i 0#usize path
        (by simp) hw
      simp only [budget.charge, hs', bind_ok]
      refine ⟨_, _, rfl, ?_, ?_⟩
      · simp [Ledger.spend, hc, denoteSpend]
      · simp [Ledger.spend, hc, hd']
  | Err e =>
    cases hc : (denoteLedger s.val).chargePath i.val x.val with
    | ok path => simp [hc, denoteSpend, Except.map] at hd
    | error e' =>
      simp only [hc, denoteSpend, Except.map, Except.error.injEq] at hd
      refine ⟨_, _, rfl, ?_, ?_⟩
      · simp [Ledger.spend, hc, denoteSpend, hd]
      · simp [Ledger.spend, hc]

/-- A failed `spend` returns its input slice unchanged. -/
theorem extracted_spend_error {s s' : Slice budget.Node} {i : Usize} {x : Std.U128}
    {e : budget.SpendError} (h : budget.spend s i x = ok (.Err e, s')) : s' = s := by
  obtain ⟨r, hr, -⟩ := extracted_check_spend s i x
  unfold budget.spend at h
  rw [hr, bind_ok] at h
  cases r with
  | Ok u =>
    revert h
    simp only [budget.charge]
    cases budget.charge_loop s x i 0#usize <;> simp
  | Err e' => simp only [ok.injEq, Prod.mk.injEq] at h; exact h.2.symm

theorem refill_none (s : Slice budget.Node) (i : Usize) (x : Std.U128)
    (hn : s.val[i.val]? = none) :
    budget.refill s i x = ok (.Err (.NoSuchNode i), s) := by
  have : budget.refill s i x = ok (.Err (.NoSuchNode i), s.set_opt i none) := by
    simp only [budget.refill, core.slice.Slice.get_mut, core.slice.index.Usize.get_mut,
      Slice.getElem?_Usize_eq, hn, bind_ok]
    rfl
  rw [this, slice_set_opt_none]

theorem refill_some (s : Slice budget.Node) (i : Usize) (x : Std.U128) (n : budget.Node)
    (hn : s.val[i.val]? = some n) :
    budget.refill s i x =
      match U128.checked_add n.allowance x with
      | none => ok (.Err (.Overflow i), s)
      | some a => ok (.Ok (), s.set_opt i (some { n with allowance := a })) := by
  have : budget.refill s i x =
      match U128.checked_add n.allowance x with
      | none => ok (.Err (.Overflow i), s.set_opt i (some n))
      | some a => ok (.Ok (), s.set_opt i (some { n with allowance := a })) := by
    simp only [budget.refill, core.slice.Slice.get_mut, core.slice.index.Usize.get_mut,
      Slice.getElem?_Usize_eq, hn, lift, bind_ok]
    rfl
  rw [this, slice_set_opt_self s i n hn]

/-- `refill` returns the model's outcome and the model's ledger after it. It
never fails. -/
theorem extracted_refill (s : Slice budget.Node) (i : Usize) (x : Std.U128) :
    ∃ r s', budget.refill s i x = ok (r, s') ∧
      denoteRefill r = ((denoteLedger s.val).refill i.val x.val).1 ∧
      denoteLedger s'.val = ((denoteLedger s.val).refill i.val x.val).2 := by
  cases hn : s.val[i.val]? with
  | none =>
    rw [refill_none s i x hn]
    refine ⟨_, _, rfl, ?_, ?_⟩
    · simp [Ledger.refill, getElem?_denoteLedger, hn, denoteRefill, denoteRefillError]
    · simp [Ledger.refill, getElem?_denoteLedger, hn]
  | some n =>
    have spec := U128.checked_add_bv_spec n.allowance x
    rw [refill_some s i x n hn]
    cases hc : U128.checked_add n.allowance x with
    | none =>
      rw [hc] at spec
      have hover : amountMax < n.allowance.val + x.val := by
        simp only [U128.max_eq] at spec; simp only [amountMax]; omega
      refine ⟨_, _, rfl, ?_, ?_⟩
      · simp [Ledger.refill, getElem?_denoteLedger, hn, denoteNode, hover, denoteRefill,
          denoteRefillError]
      · simp [Ledger.refill, getElem?_denoteLedger, hn, denoteNode, hover]
    | some a =>
      rw [hc] at spec
      obtain ⟨hfit, ha, -⟩ := spec
      have hfit' : ¬ amountMax < n.allowance.val + x.val := by
        simp only [U128.max_eq] at hfit; simp only [amountMax]; omega
      refine ⟨_, _, rfl, ?_, ?_⟩
      · simp [Ledger.refill, getElem?_denoteLedger, hn, denoteNode, hfit', denoteRefill]
      · simp only [Ledger.refill, getElem?_denoteLedger, hn, Option.map_some, denoteNode,
          hfit', ↓reduceIte, Slice.set_opt_val_eq, set_opt_some, denoteLedger_set, ha]

/-- A failed `refill` returns its input slice unchanged. -/
theorem extracted_refill_error {s s' : Slice budget.Node} {i : Usize} {x : Std.U128}
    {e : budget.RefillError} (h : budget.refill s i x = ok (.Err e, s')) : s' = s := by
  cases hn : s.val[i.val]? with
  | none =>
    rw [refill_none s i x hn] at h
    simp only [ok.injEq, Prod.mk.injEq] at h
    exact h.2.symm
  | some n =>
    rw [refill_some s i x n hn] at h
    cases hc : U128.checked_add n.allowance x with
    | none =>
      rw [hc] at h
      simp only [ok.injEq, Prod.mk.injEq] at h
      exact h.2.symm
    | some a =>
      rw [hc] at h
      simp at h

/-! ## Append -/

/-- `Vec::push` succeeds while the vector holds fewer than `Usize.max`
elements, the bound Aeneas's model of `Vec` carries. -/
theorem push_eq {α : Type} (v : alloc.vec.Vec α) (y : α) (h : v.length < Usize.max) :
    ∃ v' : alloc.vec.Vec α, v.push y = ok v' ∧ v'.val = v.val ++ [y] := by
  have := alloc.vec.Vec.push_spec v y h
  revert this
  cases v.push y with
  | ret r => intro hr; exact ⟨r, rfl, by simpa using hr⟩
  | vis e k => intro hr; simp at hr
  | div => intro hr; simp at hr

theorem denoteLedger_push (l : List budget.Node) (p : Option Usize) (x : Std.U128) :
    denoteLedger (l ++ [{ parent := p, allowance := x, spent := 0#u128 }]) =
      denoteLedger l ++ [⟨p.map (·.val), x.val, 0⟩] := by
  simp [denoteLedger, denoteNode]

/-- `append` returns the model's outcome and the model's ledger after it,
on every ledger holding fewer than `Usize.max` nodes. -/
theorem extracted_append (v : alloc.vec.Vec budget.Node) (p : Option Usize) (x : Std.U128)
    (hcap : v.length < Usize.max) :
    ∃ r v', budget.append v p x = ok (r, v') ∧
      denoteAppend r = ((denoteLedger v.val).append (p.map (·.val)) x.val).1 ∧
      denoteLedger v'.val = ((denoteLedger v.val).append (p.map (·.val)) x.val).2 := by
  unfold budget.append
  cases p with
  | none =>
    obtain ⟨v', hv', hval⟩ := push_eq v { parent := none, allowance := x, spent := 0#u128 } hcap
    simp only [hv', bind_ok]
    refine ⟨_, _, rfl, ?_, ?_⟩
    · simp [Ledger.append, denoteAppend, length_denoteLedger]
    · rw [hval, denoteLedger_push]
      rfl
  | some q =>
    by_cases hq : q.val < v.val.length
    · have hge : ¬ (q ≥ alloc.vec.Vec.len v) := by
        intro h'
        have : (alloc.vec.Vec.len v).val ≤ q.val := h'
        simp at this
        omega
      obtain ⟨v', hv', hval⟩ :=
        push_eq v { parent := some q, allowance := x, spent := 0#u128 } hcap
      simp only [hge, ↓reduceIte, hv', bind_ok]
      refine ⟨_, _, rfl, ?_, ?_⟩
      · simp [Ledger.append, denoteAppend, length_denoteLedger, hq]
      · rw [hval, denoteLedger_push]
        simp [Ledger.append, length_denoteLedger, hq]
    · have hge : q ≥ alloc.vec.Vec.len v := by
        show (alloc.vec.Vec.len v).val ≤ q.val
        simp
        omega
      simp only [hge, ↓reduceIte]
      refine ⟨_, _, rfl, ?_, ?_⟩
      · simp [Ledger.append, denoteAppend, denoteAppendError, length_denoteLedger, hq]
      · simp [Ledger.append, length_denoteLedger, hq]

/-- A failed `append` returns its input vector unchanged. -/
theorem extracted_append_error {v v' : alloc.vec.Vec budget.Node} {p : Option Usize}
    {x : Std.U128} {e : budget.AppendError} (h : budget.append v p x = ok (.Err e, v')) :
    v' = v := by
  unfold budget.append at h
  cases p with
  | none =>
    revert h
    cases alloc.vec.Vec.push v { parent := none, allowance := x, spent := 0#u128 } <;> simp
  | some q =>
    by_cases hge : q ≥ alloc.vec.Vec.len v
    · simp only [hge, ↓reduceIte, ok.injEq, Prod.mk.injEq] at h
      exact h.2.symm
    · revert h
      simp only [hge, ↓reduceIte]
      cases alloc.vec.Vec.push v { parent := some q, allowance := x, spent := 0#u128 } <;> simp

/-! ## Budget safety for the extracted code -/

/-- What a returned outcome and ledger say about the model. -/
theorem spend_model {s s' : Slice budget.Node} {i : Usize} {x : Std.U128}
    {r : core.result.Result Unit budget.SpendError} (h : budget.spend s i x = ok (r, s')) :
    (denoteLedger s.val).spend i.val x.val = (denoteSpend r, denoteLedger s'.val) := by
  obtain ⟨r', s'', h', hr, hs⟩ := extracted_spend s i x
  rw [h] at h'
  simp only [ok.injEq, Prod.mk.injEq] at h'
  obtain ⟨rfl, rfl⟩ := h'
  rw [hr, hs]

theorem refill_model {s s' : Slice budget.Node} {i : Usize} {x : Std.U128}
    {r : core.result.Result Unit budget.RefillError} (h : budget.refill s i x = ok (r, s')) :
    (denoteLedger s.val).refill i.val x.val = (denoteRefill r, denoteLedger s'.val) := by
  obtain ⟨r', s'', h', hr, hs⟩ := extracted_refill s i x
  rw [h] at h'
  simp only [ok.injEq, Prod.mk.injEq] at h'
  obtain ⟨rfl, rfl⟩ := h'
  rw [hr, hs]

theorem append_model {v v' : alloc.vec.Vec budget.Node} {p : Option Usize} {x : Std.U128}
    {r : core.result.Result Usize budget.AppendError} (hcap : v.length < Usize.max)
    (h : budget.append v p x = ok (r, v')) :
    (denoteLedger v.val).append (p.map (·.val)) x.val = (denoteAppend r, denoteLedger v'.val) := by
  obtain ⟨r', v'', h', hr, hs⟩ := extracted_append v p x hcap
  rw [h] at h'
  simp only [ok.injEq, Prod.mk.injEq] at h'
  obtain ⟨rfl, rfl⟩ := h'
  rw [hr, hs]

/-- Budget safety, success half: a successful `spend` charges the spender
and every ancestor by the amount. -/
theorem extracted_spend_ok_charges {s s' : Slice budget.Node} {i : Usize} {x : Std.U128}
    (h : budget.spend s i x = ok (.Ok (), s')) {a : Nat}
    (ha : (denoteLedger s.val).Within i.val a) :
    (denoteLedger s'.val)[a]? =
      (denoteLedger s.val)[a]?.map fun n => { n with spent := n.spent + x.val } :=
  Ledger.spend_ok_charges (spend_model h) ha

/-- A successful `spend` leaves every node off the spender's chain exactly as
it was. -/
theorem extracted_spend_ok_unchanged {s s' : Slice budget.Node} {i : Usize} {x : Std.U128}
    (h : budget.spend s i x = ok (.Ok (), s')) {a : Nat}
    (ha : ¬ (denoteLedger s.val).Within i.val a) :
    s'.val[a]? = s.val[a]? := by
  have := Ledger.spend_ok_unchanged (spend_model h) ha
  rw [getElem?_denoteLedger, getElem?_denoteLedger] at this
  exact Option.map_injective denoteNode_injective this

/-- A successful `spend` adds or removes no node. -/
theorem extracted_spend_ok_length {s s' : Slice budget.Node} {i : Usize} {x : Std.U128}
    (h : budget.spend s i x = ok (.Ok (), s')) : s'.length = s.length := by
  have := Ledger.spend_ok_length (spend_model h)
  simpa [length_denoteLedger] using this

/-- The node an `Overdrawn` error names is the spender or one of its
ancestors, and the spend would overdraw it. -/
theorem extracted_spend_overdrawn {s s' : Slice budget.Node} {i a : Usize} {x : Std.U128}
    (h : budget.spend s i x = ok (.Err (.Overdrawn a), s')) :
    (denoteLedger s.val).Within i.val a.val ∧
      ∃ n, s.val[a.val]? = some n ∧ n.allowance.val < n.spent.val + x.val := by
  have hm := spend_model h
  have hov : ((denoteLedger s.val).spend i.val x.val).1 = .error (.overdrawn a.val) := by
    rw [hm]; rfl
  obtain ⟨w, n, hn, hlt⟩ := Ledger.spend_overdrawn hov
  rw [getElem?_denoteLedger] at hn
  obtain ⟨m, hm', rfl⟩ := Option.map_eq_some_iff.mp hn
  exact ⟨w, m, hm', hlt⟩

theorem withinAllowance_denoteLedger (l : List budget.Node) :
    (denoteLedger l).WithinAllowance ↔ ∀ n ∈ l, n.spent.val ≤ n.allowance.val := by
  constructor
  · intro h n hn
    exact h (denoteNode n) (List.mem_map_of_mem hn)
  · intro h n hn
    obtain ⟨m, hm, rfl⟩ := List.mem_map.mp hn
    exact h m hm

/-- Every node's spent stays within its allowance across `spend`. -/
theorem extracted_spend_withinAllowance {s s' : Slice budget.Node} {i : Usize}
    {x : Std.U128} {r : core.result.Result Unit budget.SpendError}
    (hw : ∀ n ∈ s.val, n.spent.val ≤ n.allowance.val) (h : budget.spend s i x = ok (r, s')) :
    ∀ n ∈ s'.val, n.spent.val ≤ n.allowance.val := by
  have := Ledger.spend_withinAllowance ((withinAllowance_denoteLedger _).mpr hw) i.val x.val
  rw [spend_model h] at this
  exact (withinAllowance_denoteLedger _).mp this

/-- Every node's spent stays within its allowance across `refill`. -/
theorem extracted_refill_withinAllowance {s s' : Slice budget.Node} {i : Usize}
    {x : Std.U128} {r : core.result.Result Unit budget.RefillError}
    (hw : ∀ n ∈ s.val, n.spent.val ≤ n.allowance.val) (h : budget.refill s i x = ok (r, s')) :
    ∀ n ∈ s'.val, n.spent.val ≤ n.allowance.val := by
  have := Ledger.refill_withinAllowance ((withinAllowance_denoteLedger _).mpr hw) i.val x.val
  rw [refill_model h] at this
  exact (withinAllowance_denoteLedger _).mp this

/-- Every node's spent stays within its allowance across `append`. -/
theorem extracted_append_withinAllowance {v v' : alloc.vec.Vec budget.Node} {p : Option Usize}
    {x : Std.U128} {r : core.result.Result Usize budget.AppendError}
    (hw : ∀ n ∈ v.val, n.spent.val ≤ n.allowance.val) (hcap : v.length < Usize.max)
    (h : budget.append v p x = ok (r, v')) :
    ∀ n ∈ v'.val, n.spent.val ≤ n.allowance.val := by
  have := Ledger.append_withinAllowance ((withinAllowance_denoteLedger _).mpr hw)
    (p.map (·.val)) x.val
  rw [append_model hcap h] at this
  exact (withinAllowance_denoteLedger _).mp this

/-! ## Runs of the extracted code -/

/-- One ledger operation with Rust arguments. -/
inductive RustOp where
  | spend (i : Usize) (amount : Std.U128)
  | refill (i : Usize) (extra : Std.U128)
  | append (parent : Option Usize) (allowance : Std.U128)

/-- A Rust operation as a model one. -/
def RustOp.denote : RustOp → Op
  | .spend i x => .spend i.val x.val
  | .refill i x => .refill i.val x.val
  | .append p x => .append (p.map (·.val)) x.val

/-- Apply `ops` in order through the extracted functions to a ledger held in
a `Vec`, as a Rust caller does: `spend` and `refill` on the vector's slice
(`deref_mut`), `append` on the vector. Returns the final ledger and the
successful spends, oldest first. -/
def runExtracted :
    alloc.vec.Vec budget.Node → List RustOp →
      Result (alloc.vec.Vec budget.Node × List (Usize × Std.U128))
  | v, [] => ok (v, [])
  | v, .spend i x :: ops =>
    Aeneas.Std.bind (budget.spend (alloc.vec.Vec.deref_mut v).1 i x) fun (r, s) =>
      Aeneas.Std.bind (runExtracted ((alloc.vec.Vec.deref_mut v).2 s) ops) fun (v', log) =>
        match r with
        | .Ok () => ok (v', (i, x) :: log)
        | .Err _ => ok (v', log)
  | v, .refill i x :: ops =>
    Aeneas.Std.bind (budget.refill (alloc.vec.Vec.deref_mut v).1 i x) fun (_, s) =>
      runExtracted ((alloc.vec.Vec.deref_mut v).2 s) ops
  | v, .append p x :: ops =>
    Aeneas.Std.bind (budget.append v p x) fun (_, v') => runExtracted v' ops

theorem deref_mut_fst_val {α : Type} (v : alloc.vec.Vec α) :
    (alloc.vec.Vec.deref_mut v).1.val = v.val := rfl

theorem deref_mut_snd_val {α : Type} (v : alloc.vec.Vec α) (s : Slice α) :
    ((alloc.vec.Vec.deref_mut v).2 s).val = s.val := rfl

/-- A run of the extracted functions returns the model's final ledger and
log, on every ledger and every run that stays under `Usize.max` nodes. -/
theorem extracted_run (v : alloc.vec.Vec budget.Node) (ops : List RustOp)
    (hcap : v.length + ops.length ≤ Usize.max) :
    ∃ v' log, runExtracted v ops = ok (v', log) ∧
      denoteLedger v'.val = ((denoteLedger v.val).run (ops.map RustOp.denote)).1 ∧
      log.map (fun e => (e.1.val, e.2.val)) =
        ((denoteLedger v.val).run (ops.map RustOp.denote)).2 := by
  induction ops generalizing v with
  | nil => exact ⟨v, [], rfl, rfl, rfl⟩
  | cons op ops ih =>
    simp only [List.length_cons] at hcap
    cases op with
    | spend i x =>
      obtain ⟨r, s', hs, hr, hd⟩ := extracted_spend (alloc.vec.Vec.deref_mut v).1 i x
      rw [deref_mut_fst_val] at hr hd
      have hlen : s'.val.length = v.val.length := by
        have := congrArg List.length hd
        rwa [Ledger.length_spend, length_denoteLedger, length_denoteLedger] at this
      obtain ⟨v', log, hrun, hv', hlog⟩ := ih ((alloc.vec.Vec.deref_mut v).2 s') (by
        simp only [alloc.vec.Vec.length, deref_mut_snd_val, hlen]
        simp only [alloc.vec.Vec.length] at hcap
        omega)
      rw [deref_mut_snd_val] at hv' hlog
      have hmodel : (denoteLedger v.val).spend i.val x.val = (denoteSpend r, denoteLedger s'.val) := by
        rw [hr, hd]
      cases r with
      | Ok u =>
        refine ⟨v', (i, x) :: log, ?_, ?_, ?_⟩
        · simp only [runExtracted, hs, bind_ok, hrun]
        · simp only [List.map_cons, RustOp.denote, Ledger.run, hmodel, denoteSpend]
          exact hv'
        · simp only [List.map_cons, RustOp.denote, Ledger.run, hmodel, denoteSpend]
          rw [hlog]
      | Err e =>
        refine ⟨v', log, ?_, ?_, ?_⟩
        · simp only [runExtracted, hs, bind_ok, hrun]
        · simp only [List.map_cons, RustOp.denote, Ledger.run, hmodel, denoteSpend]
          exact hv'
        · simp only [List.map_cons, RustOp.denote, Ledger.run, hmodel, denoteSpend]
          exact hlog
    | refill i x =>
      obtain ⟨r, s', hs, hr, hd⟩ := extracted_refill (alloc.vec.Vec.deref_mut v).1 i x
      rw [deref_mut_fst_val] at hr hd
      have hlen : s'.val.length = v.val.length := by
        have := congrArg List.length hd
        rwa [Ledger.length_refill, length_denoteLedger, length_denoteLedger] at this
      obtain ⟨v', log, hrun, hv', hlog⟩ := ih ((alloc.vec.Vec.deref_mut v).2 s') (by
        simp only [alloc.vec.Vec.length, deref_mut_snd_val, hlen]
        simp only [alloc.vec.Vec.length] at hcap
        omega)
      rw [deref_mut_snd_val] at hv' hlog
      refine ⟨v', log, ?_, ?_, ?_⟩
      · simp only [runExtracted, hs, bind_ok, hrun]
      · simp only [List.map_cons, RustOp.denote, Ledger.run]
        rw [← hd]
        exact hv'
      · simp only [List.map_cons, RustOp.denote, Ledger.run]
        rw [← hd]
        exact hlog
    | append p x =>
      obtain ⟨r, v1, hs, hr, hd⟩ := extracted_append v p x (by omega)
      have hlen : v1.val.length ≤ v.val.length + 1 := by
        have hl : ((denoteLedger v.val).append (p.map (·.val)) x.val).2.length ≤
            (denoteLedger v.val).length + 1 := by
          unfold Ledger.append
          cases p.map (·.val) with
          | none => simp
          | some q => by_cases hq : q < (denoteLedger v.val).length <;> simp [hq]
        rw [← hd, length_denoteLedger, length_denoteLedger] at hl
        exact hl
      obtain ⟨v', log, hrun, hv', hlog⟩ := ih v1 (by
        simp only [alloc.vec.Vec.length] at hcap ⊢
        omega)
      refine ⟨v', log, ?_, ?_, ?_⟩
      · simp only [runExtracted, hs, bind_ok, hrun]
      · simp only [List.map_cons, RustOp.denote, Ledger.run]
        rw [← hd]
        exact hv'
      · simp only [List.map_cons, RustOp.denote, Ledger.run]
        rw [← hd]
        exact hlog

/-- Every node's spent stays within its allowance over any run of the
extracted functions. -/
theorem extracted_run_withinAllowance (v : alloc.vec.Vec budget.Node) (ops : List RustOp)
    (hcap : v.length + ops.length ≤ Usize.max)
    (hw : ∀ n ∈ v.val, n.spent.val ≤ n.allowance.val) :
    ∃ v' log, runExtracted v ops = ok (v', log) ∧
      ∀ n ∈ v'.val, n.spent.val ≤ n.allowance.val := by
  obtain ⟨v', log, hrun, hv', -⟩ := extracted_run v ops hcap
  refine ⟨v', log, hrun, (withinAllowance_denoteLedger _).mp ?_⟩
  rw [hv']
  exact Ledger.run_withinAllowance ((withinAllowance_denoteLedger _).mpr hw) _

/-- Budget safety over any run of the extracted functions: from a ledger
with nothing spent, after any sequence of spends, refills and appends, the
total successfully spent at or under node `a` never exceeds `a`'s allowance,
however much its children's allowances oversubscribe it. -/
theorem extracted_spentUnder_le_allowance (v : alloc.vec.Vec budget.Node) (ops : List RustOp)
    (hcap : v.length + ops.length ≤ Usize.max) (h0 : ∀ n ∈ v.val, n.spent.val = 0) :
    ∃ v' log, runExtracted v ops = ok (v', log) ∧
      ∀ (a : Nat) (n : budget.Node), v'.val[a]? = some n →
        spentUnder (denoteLedger v'.val) (log.map fun e => (e.1.val, e.2.val)) a ≤
          n.allowance.val := by
  obtain ⟨v', log, hrun, hv', hlog⟩ := extracted_run v ops hcap
  refine ⟨v', log, hrun, fun a n ha => ?_⟩
  have h0' : ∀ m ∈ denoteLedger v.val, m.spent = 0 := by
    intro m hm
    obtain ⟨k, hk, rfl⟩ := List.mem_map.mp hm
    exact h0 k hk
  have ha' : ((denoteLedger v.val).run (ops.map RustOp.denote)).1[a]? = some (denoteNode n) := by
    rw [← hv', getElem?_denoteLedger, ha]
    rfl
  have := Ledger.spentUnder_le_allowance h0' (ops.map RustOp.denote) ha'
  rw [← hv', ← hlog] at this
  exact this

end AttenuatingGrants.Budget
