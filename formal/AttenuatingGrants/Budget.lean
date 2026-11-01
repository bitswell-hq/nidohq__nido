/-!
# Budgets

A budget is an allowance attached to a grant. Grants form a delegation tree,
so allowances do too: the ledger holds one node per grant, each with an
allowance, the amount spent at or under it, and a link to its parent toward
the root. A parent precedes its children in the ledger; a spend that meets a
parent link breaking that order fails with `badParent`.

Allowances may oversubscribe: the allowances of a node's children can sum to
more than the node's own. That stays safe because a spend charges the spender
and every ancestor up to the root, as one transaction: it succeeds only if no
node on that chain would be overdrawn, and otherwise fails, changing nothing
and naming the first node on the chain, counting from the spender, that would
be overdrawn. That node is where a refill request goes; it travels up the
delegation chain to a human approver. A refill raises one node's allowance and
is an admin-document action, never an agent's.

Amounts are `Nat`. The Rust evaluator stores them as `u128`; `amountMax` is
the largest `u128`, and a refill that would raise an allowance past it fails,
as Rust's checked addition does. A spend needs no such bound: an allowance is
at most `amountMax`, so a sum that overflows `u128` exceeds the allowance and
the spend fails as overdrawn in both.

Theorems:

* `spend_ok_charges`, `spend_ok_unchanged`, `spend_ok_length` (budget safety,
  success half): a successful spend charges the spender and every ancestor by
  the amount and changes nothing else.
* `spend_error` (budget safety, failure half): a failed spend leaves the
  ledger unchanged.
* `spend_overdrawn`: the node a failure names is on the spender's chain and
  would be overdrawn.
* `spend_withinAllowance`, `refill_withinAllowance`, `run_withinAllowance`:
  every node's spent stays within its allowance.
* `spend_bounded`, `refill_bounded`: every allowance stays within `amountMax`.
* `spent_run`, `spentUnder_le_allowance`: over any sequence of spends and
  refills from a ledger with nothing spent, the total successfully spent at or
  under a node never exceeds that node's allowance.
-/

namespace AttenuatingGrants.Budget

/-- The largest `u128`, the bound on every amount in the Rust evaluator. -/
def amountMax : Nat := 2 ^ 128 - 1

/-- One grant's allowance. `spent` counts every successful spend at or under
this node. -/
structure Node where
  parent : Option Nat
  allowance : Nat
  spent : Nat
  deriving DecidableEq, Repr

/-- The delegation tree, indexed from zero. -/
abbrev Ledger := List Node

inductive SpendError where
  /-- No node has this index. -/
  | noSuchNode (i : Nat)
  /-- This node's parent link does not point to an earlier node. -/
  | badParent (i : Nat)
  /-- Charging this node would take its spent past its allowance. -/
  | overdrawn (i : Nat)
  deriving DecidableEq, Repr

inductive RefillError where
  | noSuchNode (i : Nat)
  /-- The raised allowance would exceed `amountMax`. -/
  | overflow (i : Nat)
  deriving DecidableEq, Repr

namespace Ledger

/-- The parent link of node `i`, if `i` exists and has one. -/
def parentOf (l : Ledger) (i : Nat) : Option Nat :=
  l[i]?.bind (·.parent)

/-- `Within l i a`: node `a` is `i` or one of its ancestors, so a spend at `i`
charges `a`. Equivalently, `i` is at or under `a`. -/
inductive Within (l : Ledger) : Nat → Nat → Prop where
  | self (i : Nat) : Within l i i
  | up {i p a : Nat} : l.parentOf i = some p → Within l p a → Within l i a

/-- The walk from node `i` toward the root, checking that each node can take
`amount`. It returns the nodes to charge, spender first, or the first error.
Each step moves to a strictly earlier node, so `fuel` steps (the ledger's
length) always suffice; running out happens only on an empty ledger. -/
def walk (l : Ledger) (amount : Nat) : Nat → Nat → Except SpendError (List Nat)
  | 0, i => .error (.noSuchNode i)
  | fuel + 1, i =>
    match l[i]? with
    | none => .error (.noSuchNode i)
    | some n =>
      if n.allowance < n.spent + amount then .error (.overdrawn i)
      else
        match n.parent with
        | none => .ok [i]
        | some p =>
          if p < i then (walk l amount fuel p).map (i :: ·)
          else .error (.badParent i)

/-- The nodes a spend of `amount` at `i` charges, or why it fails. -/
def chargePath (l : Ledger) (i amount : Nat) : Except SpendError (List Nat) :=
  walk l amount l.length i

/-- Add `amount` to the spent of every node in `path`. -/
def charge (l : Ledger) (path : List Nat) (amount : Nat) : Ledger :=
  l.mapIdx fun j n => if j ∈ path then { n with spent := n.spent + amount } else n

/-- Spend `amount` at node `i`: the outcome and the ledger after it. -/
def spend (l : Ledger) (i amount : Nat) : Except SpendError Unit × Ledger :=
  match l.chargePath i amount with
  | .ok path => (.ok (), l.charge path amount)
  | .error e => (.error e, l)

/-- Raise node `i`'s allowance by `extra`: the outcome and the ledger after
it. An admin-document action. -/
def refill (l : Ledger) (i extra : Nat) : Except RefillError Unit × Ledger :=
  match l[i]? with
  | none => (.error (.noSuchNode i), l)
  | some n =>
    if amountMax < n.allowance + extra then (.error (.overflow i), l)
    else (.ok (), l.set i { n with allowance := n.allowance + extra })

/-- Every node's spent is within its allowance. -/
def WithinAllowance (l : Ledger) : Prop :=
  ∀ n ∈ l, n.spent ≤ n.allowance

/-- Every allowance fits in a `u128`. -/
def Bounded (l : Ledger) : Prop :=
  ∀ n ∈ l, n.allowance ≤ amountMax

end Ledger

/-- One operation on the ledger. -/
inductive Op where
  | spend (i amount : Nat)
  | refill (i extra : Nat)

/-- Apply `ops` in order. Returns the final ledger and the successful spends,
oldest first, as `(node, amount)`. -/
def Ledger.run : Ledger → List Op → Ledger × List (Nat × Nat)
  | l, [] => (l, [])
  | l, .spend i x :: ops =>
    match l.spend i x with
    | (.ok (), l') => let r := l'.run ops; (r.1, (i, x) :: r.2)
    | (.error _, l') => l'.run ops
  | l, .refill i x :: ops => (l.refill i x).2.run ops

open Classical in
/-- The total of the logged spends made at or under node `a`. -/
noncomputable def spentUnder (l : Ledger) (log : List (Nat × Nat)) (a : Nat) : Nat :=
  ((log.filter fun e => decide (l.Within e.1 a)).map (·.2)).sum

namespace Ledger

/-! ## The walk -/

theorem within_root {l : Ledger} {i a : Nat} (h : l.parentOf i = none) :
    l.Within i a ↔ a = i := by
  constructor
  · intro w
    cases w with
    | self => rfl
    | up hp _ => simp [h] at hp
  · rintro rfl; exact .self _

theorem within_step {l : Ledger} {i p a : Nat} (h : l.parentOf i = some p) :
    l.Within i a ↔ a = i ∨ l.Within p a := by
  constructor
  · intro w
    cases w with
    | self => exact .inl rfl
    | up hq w => rw [h] at hq; cases hq; exact .inr w
  · rintro (rfl | w)
    · exact .self _
    · exact .up h w

/-- The walk charges exactly the spender and its ancestors. -/
theorem mem_walk {l : Ledger} {amount : Nat} :
    ∀ {fuel i path}, l.walk amount fuel i = .ok path → ∀ a, a ∈ path ↔ l.Within i a
  | 0, _, _, h => by simp [walk] at h
  | fuel + 1, i, path, h => by
    intro a
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
          rw [within_root (by simp [parentOf, hi, hp])]
          simp
        | some p =>
          simp only [hp] at h
          split at h
          · cases hw : l.walk amount fuel p with
            | error e => simp [hw, Except.map] at h
            | ok rest =>
              simp only [hw, Except.map, Except.ok.injEq] at h
              subst h
              rw [within_step (p := p) (by simp [parentOf, hi, hp]), List.mem_cons,
                mem_walk hw a]
          · simp at h

/-- Every node the walk returns can take `amount`. -/
theorem walk_fits {l : Ledger} {amount : Nat} :
    ∀ {fuel i path}, l.walk amount fuel i = .ok path →
      ∀ j ∈ path, ∃ n, l[j]? = some n ∧ n.spent + amount ≤ n.allowance
  | 0, _, _, h => by simp [walk] at h
  | fuel + 1, i, path, h => by
    unfold walk at h
    cases hi : l[i]? with
    | none => simp [hi] at h
    | some n =>
      simp only [hi] at h
      split at h
      · simp at h
      · rename_i hfit
        have here : ∃ n, l[i]? = some n ∧ n.spent + amount ≤ n.allowance :=
          ⟨n, hi, Nat.le_of_not_lt hfit⟩
        cases hp : n.parent with
        | none =>
          simp only [hp, Except.ok.injEq] at h
          subst h
          simpa using here
        | some p =>
          simp only [hp] at h
          split at h
          · cases hw : l.walk amount fuel p with
            | error e => simp [hw, Except.map] at h
            | ok rest =>
              simp only [hw, Except.map, Except.ok.injEq] at h
              subst h
              intro j hj
              rcases List.mem_cons.mp hj with rfl | hj
              · exact here
              · exact walk_fits hw j hj
          · simp at h

/-- The node an overdrawn failure names is on the spender's chain and would
be overdrawn by the spend. -/
theorem walk_overdrawn {l : Ledger} {amount : Nat} :
    ∀ {fuel i a}, l.walk amount fuel i = .error (.overdrawn a) →
      l.Within i a ∧ ∃ n, l[a]? = some n ∧ n.allowance < n.spent + amount
  | 0, _, _, h => by simp [walk] at h
  | fuel + 1, i, a, h => by
    unfold walk at h
    cases hi : l[i]? with
    | none => simp [hi] at h
    | some n =>
      simp only [hi] at h
      split at h
      · rename_i hover
        simp only [Except.error.injEq, SpendError.overdrawn.injEq] at h
        subst h
        exact ⟨.self _, n, hi, hover⟩
      · cases hp : n.parent with
        | none => simp [hp] at h
        | some p =>
          simp only [hp] at h
          split at h
          · cases hw : l.walk amount fuel p with
            | error e =>
              simp only [hw, Except.map, Except.error.injEq] at h
              subst h
              have ⟨w, rest⟩ := walk_overdrawn hw
              exact ⟨.up (by simp [parentOf, hi, hp]) w, rest⟩
            | ok rest => simp [hw, Except.map] at h
          · simp at h

/-! ## Charging -/

theorem lt_length_of_getElem? {l : Ledger} {i : Nat} {n : Node} (h : l[i]? = some n) :
    i < l.length :=
  (List.getElem?_eq_some_iff.mp h).1

theorem getElem_of_getElem? {l : Ledger} {i : Nat} {n : Node} (h : l[i]? = some n) :
    l[i]'(lt_length_of_getElem? h) = n :=
  (List.getElem?_eq_some_iff.mp h).2

theorem length_charge (l : Ledger) (path : List Nat) (amount : Nat) :
    (l.charge path amount).length = l.length := by
  simp [charge]

theorem getElem?_charge (l : Ledger) (path : List Nat) (amount j : Nat) :
    (l.charge path amount)[j]? =
      l[j]?.map fun n => if j ∈ path then { n with spent := n.spent + amount } else n := by
  simp [charge, List.getElem?_mapIdx]

theorem parentOf_charge (l : Ledger) (path : List Nat) (amount : Nat) :
    (l.charge path amount).parentOf = l.parentOf := by
  funext j
  simp only [parentOf, getElem?_charge]
  cases l[j]? <;> simp
  split <;> rfl

/-! ## Budget safety (theorem 4) -/

theorem spend_ok_iff {l l' : Ledger} {i amount : Nat} :
    l.spend i amount = (.ok (), l') ↔
      ∃ path, l.chargePath i amount = .ok path ∧ l' = l.charge path amount := by
  unfold spend
  cases h : l.chargePath i amount with
  | ok path => simp [eq_comm]
  | error e => simp

/-- Success charges the spender and every ancestor by the amount. -/
theorem spend_ok_charges {l l' : Ledger} {i amount : Nat}
    (h : l.spend i amount = (.ok (), l')) {a : Nat} (ha : l.Within i a) :
    l'[a]? = l[a]?.map fun n => { n with spent := n.spent + amount } := by
  obtain ⟨path, hp, rfl⟩ := spend_ok_iff.mp h
  rw [getElem?_charge]
  have : a ∈ path := (mem_walk hp a).mpr ha
  simp [this]

/-- Success changes no node off the spender's chain. -/
theorem spend_ok_unchanged {l l' : Ledger} {i amount : Nat}
    (h : l.spend i amount = (.ok (), l')) {a : Nat} (ha : ¬ l.Within i a) :
    l'[a]? = l[a]? := by
  obtain ⟨path, hp, rfl⟩ := spend_ok_iff.mp h
  rw [getElem?_charge]
  have : a ∉ path := fun m => ha ((mem_walk hp a).mp m)
  simp [this]

/-- Success adds or removes no node. -/
theorem spend_ok_length {l l' : Ledger} {i amount : Nat}
    (h : l.spend i amount = (.ok (), l')) : l'.length = l.length := by
  obtain ⟨path, _, rfl⟩ := spend_ok_iff.mp h
  exact length_charge l path amount

/-- Failure leaves the ledger unchanged. -/
theorem spend_error {l : Ledger} {i amount : Nat} {e : SpendError}
    (h : (l.spend i amount).1 = .error e) : (l.spend i amount).2 = l := by
  unfold spend at h ⊢
  cases hc : l.chargePath i amount with
  | ok path => simp [hc] at h
  | error e' => rfl

theorem spend_eq_error {l l' : Ledger} {i amount : Nat} {e : SpendError}
    (h : l.spend i amount = (.error e, l')) : l' = l := by
  have h2 := spend_error (l := l) (i := i) (amount := amount) (e := e) (by rw [h])
  rw [h] at h2
  exact h2

/-- The node an overdrawn failure names, the target of the refill request, is
the spender or one of its ancestors, and the spend would overdraw it. -/
theorem spend_overdrawn {l : Ledger} {i amount a : Nat}
    (h : (l.spend i amount).1 = .error (.overdrawn a)) :
    l.Within i a ∧ ∃ n, l[a]? = some n ∧ n.allowance < n.spent + amount := by
  unfold spend at h
  cases hc : l.chargePath i amount with
  | ok path => simp [hc] at h
  | error e =>
    simp only [hc, Except.error.injEq] at h
    subst h
    exact walk_overdrawn hc

/-! ## Invariants -/

theorem parentOf_spend (l : Ledger) (i amount : Nat) :
    (l.spend i amount).2.parentOf = l.parentOf := by
  unfold spend
  cases l.chargePath i amount with
  | ok path => exact parentOf_charge l path amount
  | error e => rfl

theorem parentOf_refill (l : Ledger) (i extra : Nat) :
    (l.refill i extra).2.parentOf = l.parentOf := by
  unfold refill
  cases hi : l[i]? with
  | none => rfl
  | some n =>
    simp only
    split
    · rfl
    · funext j
      simp only [parentOf, List.getElem?_set]
      split
      · rename_i hj
        subst hj
        simp [lt_length_of_getElem? hi, getElem_of_getElem? hi]
      · rfl

theorem length_spend (l : Ledger) (i amount : Nat) :
    (l.spend i amount).2.length = l.length := by
  unfold spend
  cases l.chargePath i amount with
  | ok path => exact length_charge l path amount
  | error e => rfl

theorem length_refill (l : Ledger) (i extra : Nat) :
    (l.refill i extra).2.length = l.length := by
  unfold refill
  cases l[i]? with
  | none => rfl
  | some n => simp only; split <;> simp

theorem withinAllowance_iff {l : Ledger} :
    l.WithinAllowance ↔ ∀ (j : Nat) (n : Node), l[j]? = some n → n.spent ≤ n.allowance := by
  constructor
  · intro h j n hj
    exact h n (List.mem_of_getElem? hj)
  · intro h n hn
    obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hn
    exact h j n hj

theorem spend_withinAllowance {l : Ledger} (h : l.WithinAllowance) (i amount : Nat) :
    (l.spend i amount).2.WithinAllowance := by
  unfold spend
  cases hc : l.chargePath i amount with
  | error e => exact h
  | ok path =>
    rw [withinAllowance_iff] at h ⊢
    intro j n hj
    rw [getElem?_charge] at hj
    cases hl : l[j]? with
    | none => simp [hl] at hj
    | some m =>
      simp only [hl, Option.map_some, Option.some.injEq] at hj
      subst hj
      split
      · rename_i hm
        obtain ⟨m', hm', fit⟩ := walk_fits hc j hm
        rw [hl] at hm'
        cases hm'
        exact fit
      · exact h j m hl

theorem refill_withinAllowance {l : Ledger} (h : l.WithinAllowance) (i extra : Nat) :
    (l.refill i extra).2.WithinAllowance := by
  unfold refill
  cases hi : l[i]? with
  | none => exact h
  | some n =>
    simp only
    split
    · exact h
    · rw [withinAllowance_iff] at h ⊢
      intro j m hj
      rw [List.getElem?_set] at hj
      split at hj
      · rename_i hij
        subst hij
        simp only [lt_length_of_getElem? hi, ite_true, Option.some.injEq] at hj
        subst hj
        exact Nat.le_add_right_of_le (h _ n hi)
      · exact h j m hj

theorem spend_bounded {l : Ledger} (h : l.Bounded) (i amount : Nat) :
    (l.spend i amount).2.Bounded := by
  unfold spend
  cases l.chargePath i amount with
  | error e => exact h
  | ok path =>
    intro n hn
    obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hn
    rw [getElem?_charge] at hj
    cases hl : l[j]? with
    | none => simp [hl] at hj
    | some m =>
      simp only [hl, Option.map_some, Option.some.injEq] at hj
      have hm := h m (List.mem_of_getElem? hl)
      subst hj
      split <;> exact hm

theorem refill_bounded {l : Ledger} (h : l.Bounded) (i extra : Nat) :
    (l.refill i extra).2.Bounded := by
  unfold refill
  cases hi : l[i]? with
  | none => exact h
  | some n =>
    simp only
    split
    · exact h
    · rename_i hfit
      intro m hm
      obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hm
      rw [List.getElem?_set] at hj
      split at hj
      · rename_i hij
        subst hij
        simp only [lt_length_of_getElem? hi, ite_true, Option.some.injEq] at hj
        subst hj
        exact Nat.le_of_not_lt hfit
      · exact h m (List.mem_of_getElem? hj)

/-! ## Spending under a node never exceeds its allowance -/

theorem parentOf_run (l : Ledger) (ops : List Op) : (l.run ops).1.parentOf = l.parentOf := by
  induction ops generalizing l with
  | nil => rfl
  | cons op ops ih =>
    cases op with
    | spend i x =>
      unfold run
      have hpar := parentOf_spend l i x
      split
      · rename_i l' hs; rw [hs] at hpar; simp only; rw [ih, hpar]
      · rename_i l' hs; rw [hs] at hpar; rw [ih, hpar]
    | refill i x => unfold run; rw [ih, parentOf_refill]

theorem run_withinAllowance {l : Ledger} (h : l.WithinAllowance) (ops : List Op) :
    (l.run ops).1.WithinAllowance := by
  induction ops generalizing l with
  | nil => exact h
  | cons op ops ih =>
    cases op with
    | spend i x =>
      unfold run
      have hw := spend_withinAllowance h i x
      split
      · rename_i l' hs; rw [hs] at hw; exact ih hw
      · rename_i l' hs; rw [hs] at hw; exact ih hw
    | refill i x => exact ih (refill_withinAllowance h i x)

theorem spentUnder_congr {l l' : Ledger} (h : l.parentOf = l'.parentOf)
    (log : List (Nat × Nat)) (a : Nat) : spentUnder l log a = spentUnder l' log a := by
  have : ∀ i, l.Within i a ↔ l'.Within i a := by
    intro i
    constructor
    · intro w
      induction w with
      | self => exact .self _
      | up hp _ ih => exact .up (h ▸ hp) ih
    · intro w
      induction w with
      | self => exact .self _
      | up hp _ ih => exact .up (h.symm ▸ hp) ih
  unfold spentUnder
  congr 2
  exact List.filter_congr fun e _ => decide_eq_decide.mpr (this e.1)

open Classical in
theorem spentUnder_cons (l : Ledger) (i x : Nat) (log : List (Nat × Nat)) (a : Nat) :
    spentUnder l ((i, x) :: log) a = (if l.Within i a then x else 0) + spentUnder l log a := by
  unfold spentUnder
  by_cases w : l.Within i a <;> simp [w]

/-- Each node's spent is its starting spent plus every logged spend made at or
under it. -/
theorem spent_run (l : Ledger) (ops : List Op) (a : Nat) :
    (l.run ops).1[a]?.map (·.spent) =
      l[a]?.map (·.spent + spentUnder l (l.run ops).2 a) := by
  induction ops generalizing l with
  | nil =>
    simp only [run, spentUnder, List.filter_nil, List.map_nil, List.sum_nil, Nat.add_zero]
  | cons op ops ih =>
    cases op with
    | spend i x =>
      unfold run
      split
      · next l' hs =>
        have hpar : l'.parentOf = l.parentOf := by
          have := parentOf_spend l i x
          rwa [hs] at this
        simp only
        rw [ih, spentUnder_cons, spentUnder_congr hpar]
        by_cases w : l.Within i a
        · rw [spend_ok_charges hs w]
          cases l[a]? with
          | none => rfl
          | some m => simp [w]; omega
        · rw [spend_ok_unchanged hs w]
          cases l[a]? with
          | none => rfl
          | some m => simp [w]
      · next e l' hs =>
        rw [spend_eq_error hs]
        exact ih l
    | refill i x =>
      unfold run
      rw [ih, spentUnder_congr (parentOf_refill l i x)]
      unfold refill
      cases hi : l[i]? with
      | none => rfl
      | some n =>
        simp only
        split
        · rfl
        · rw [List.getElem?_set]
          split
          · rename_i hia
            subst hia
            simp [lt_length_of_getElem? hi, getElem_of_getElem? hi]
          · rfl

/-- Budget safety over any run: starting from a ledger with nothing spent,
the total successfully spent at or under node `a` never exceeds `a`'s
allowance, however much its children's allowances oversubscribe it. -/
theorem spentUnder_le_allowance {l : Ledger} (h0 : ∀ n ∈ l, n.spent = 0)
    (ops : List Op) {a : Nat} {n : Node} (ha : (l.run ops).1[a]? = some n) :
    spentUnder l (l.run ops).2 a ≤ n.allowance := by
  have hw : l.WithinAllowance := fun m hm => by rw [h0 m hm]; exact Nat.zero_le _
  have fits := withinAllowance_iff.mp (run_withinAllowance hw ops) a n ha
  have hs := spent_run l ops a
  rw [ha] at hs
  cases hl : l[a]? with
  | none => simp [hl] at hs
  | some m =>
    simp only [hl, Option.map_some, Option.some.injEq] at hs
    rw [h0 m (List.mem_of_getElem? hl), Nat.zero_add] at hs
    rw [← hs]
    exact fits

end Ledger

/-! ## Example: oversubscribed siblings

A root with allowance 10 delegates allowance 8 to each of two children. The
first child spends 8; the second child's spend of 3 is refused at the root,
which has only 2 left, and its spend of 2 succeeds. -/

private def siblings : Ledger :=
  [⟨none, 10, 0⟩, ⟨some 0, 8, 0⟩, ⟨some 0, 8, 0⟩]

example : ((siblings.spend 1 8).2.spend 2 3).1 = .error (.overdrawn 0) := rfl

example :
    ((siblings.spend 1 8).2.spend 2 2) =
      (.ok (), [⟨none, 10, 10⟩, ⟨some 0, 8, 8⟩, ⟨some 0, 8, 2⟩]) := rfl

end AttenuatingGrants.Budget
