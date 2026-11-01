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

The tree grows by appending. Delegating a grant appends a node under the
delegator's node, with any allowance, so delegation may oversubscribe; issuing
a new root grant, an admin-document action, appends a node with no parent. A
new node has nothing spent and the next index, so an append keeps every
parent before its children.

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
* `append_ok_iff`, `append_error`: an append adds exactly the new node at the
  next index, or fails changing nothing.
* `spend_withinAllowance`, `refill_withinAllowance`, `append_withinAllowance`,
  `run_withinAllowance`: every node's spent stays within its allowance.
* `spend_bounded`, `refill_bounded`, `append_bounded`: every allowance stays
  within `amountMax`.
* `spend_parentsFirst`, `refill_parentsFirst`, `append_parentsFirst`,
  `run_parentsFirst`: every parent link points to an earlier node.
* `run_extends`: a run keeps every existing node's parent link;
  `parentOf_run`, `spentUnder_run`: a run without appends changes none.
* `spent_run`, `spentUnder_le_allowance`: over any sequence of spends, refills
  and appends from a ledger with nothing spent, the total successfully spent
  at or under a node never exceeds that node's allowance.
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

inductive AppendError where
  /-- No node has the parent's index. -/
  | noSuchNode (i : Nat)
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

/-- Add a node with `allowance` and nothing spent under `parent`, or as a new
root for `none`: the outcome (the new node's index) and the ledger after it.
The allowance may exceed the parent's. -/
def append (l : Ledger) (parent : Option Nat) (allowance : Nat) :
    Except AppendError Nat × Ledger :=
  match parent with
  | none => (.ok l.length, l ++ [⟨none, allowance, 0⟩])
  | some p =>
    if p < l.length then (.ok l.length, l ++ [⟨some p, allowance, 0⟩])
    else (.error (.noSuchNode p), l)

/-- Every node's spent is within its allowance. -/
def WithinAllowance (l : Ledger) : Prop :=
  ∀ n ∈ l, n.spent ≤ n.allowance

/-- Every allowance fits in a `u128`. -/
def Bounded (l : Ledger) : Prop :=
  ∀ n ∈ l, n.allowance ≤ amountMax

/-- Every parent link points to an earlier node. -/
def ParentsFirst (l : Ledger) : Prop :=
  ∀ j p, l.parentOf j = some p → p < j

end Ledger

/-- One operation on the ledger. -/
inductive Op where
  | spend (i amount : Nat)
  | refill (i extra : Nat)
  | append (parent : Option Nat) (allowance : Nat)

/-- Apply `ops` in order. Returns the final ledger and the successful spends,
oldest first, as `(node, amount)`. -/
def Ledger.run : Ledger → List Op → Ledger × List (Nat × Nat)
  | l, [] => (l, [])
  | l, .spend i x :: ops =>
    match l.spend i x with
    | (.ok (), l') => let r := l'.run ops; (r.1, (i, x) :: r.2)
    | (.error _, l') => l'.run ops
  | l, .refill i x :: ops => (l.refill i x).2.run ops
  | l, .append p x :: ops => (l.append p x).2.run ops

open Classical in
/-- The total of the logged spends made at or under node `a` in the tree of
`l`. -/
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

/-! ## Growing the tree -/

theorem append_ok_iff {l l' : Ledger} {p : Option Nat} {x k : Nat} :
    l.append p x = (.ok k, l') ↔
      (∀ q, p = some q → q < l.length) ∧ k = l.length ∧ l' = l ++ [⟨p, x, 0⟩] := by
  unfold append
  cases p with
  | none =>
    simp only [Prod.mk.injEq, Except.ok.injEq, reduceCtorEq, false_implies, implies_true,
      true_and]
    constructor
    · rintro ⟨rfl, rfl⟩; exact ⟨rfl, rfl⟩
    · rintro ⟨rfl, rfl⟩; exact ⟨rfl, rfl⟩
  | some q =>
    by_cases hq : q < l.length
    · simp only [hq, ↓reduceIte, Prod.mk.injEq, Except.ok.injEq, Option.some.injEq]
      constructor
      · rintro ⟨rfl, rfl⟩; exact ⟨fun _ h => h ▸ hq, rfl, rfl⟩
      · rintro ⟨_, rfl, rfl⟩; exact ⟨rfl, rfl⟩
    · simp only [hq, ↓reduceIte, Prod.mk.injEq, reduceCtorEq, false_and, false_iff,
        not_and]
      intro h
      exact absurd (h q rfl) hq

/-- Failure leaves the ledger unchanged. -/
theorem append_error {l : Ledger} {p : Option Nat} {x : Nat} {e : AppendError}
    (h : (l.append p x).1 = .error e) : (l.append p x).2 = l := by
  unfold append at h ⊢
  cases p with
  | none => simp at h
  | some q => by_cases hq : q < l.length <;> simp [hq] at h ⊢

theorem length_append_ge (l : Ledger) (p : Option Nat) (x : Nat) :
    l.length ≤ (l.append p x).2.length := by
  unfold append
  cases p with
  | none => simp
  | some q => by_cases hq : q < l.length <;> simp [hq]

/-- An append changes no existing node. -/
theorem getElem?_append_of_lt (l : Ledger) (p : Option Nat) (x : Nat) {j : Nat}
    (hj : j < l.length) : (l.append p x).2[j]? = l[j]? := by
  unfold append
  cases p with
  | none => simp [List.getElem?_append_left hj]
  | some q => by_cases hq : q < l.length <;> simp [hq, List.getElem?_append_left hj]

/-- The new node, if any, has nothing spent. -/
theorem spent_append (l : Ledger) (p : Option Nat) (x a : Nat) :
    ((l.append p x).2[a]?.map (·.spent)).getD 0 = (l[a]?.map (·.spent)).getD 0 := by
  by_cases ha : a < l.length
  · rw [getElem?_append_of_lt l p x ha]
  · rw [List.getElem?_eq_none (Nat.le_of_not_lt ha)]
    unfold append
    have key : ∀ m : Node, m.spent = 0 →
        (((l ++ [m])[a]?).map (·.spent)).getD 0 = 0 := by
      intro m hm
      rw [List.getElem?_append_right (Nat.le_of_not_lt ha)]
      cases h : a - l.length with
      | zero => simp [hm]
      | succ k => simp
    cases p with
    | none => exact key _ rfl
    | some q =>
      by_cases hq : q < l.length
      · simp only [hq, ↓reduceIte]; exact key _ rfl
      · simp only [hq, ↓reduceIte]; simp [List.getElem?_eq_none (Nat.le_of_not_lt ha)]

theorem withinAllowance_push {l : Ledger} (h : l.WithinAllowance) (p : Option Nat) (x : Nat) :
    (l ++ [(⟨p, x, 0⟩ : Node)]).WithinAllowance := by
  intro n hn
  rcases List.mem_append.mp hn with hn | hn
  · exact h n hn
  · rw [List.mem_singleton.mp hn]; exact Nat.zero_le _

theorem append_withinAllowance {l : Ledger} (h : l.WithinAllowance) (p : Option Nat)
    (x : Nat) : (l.append p x).2.WithinAllowance := by
  unfold append
  cases p with
  | none => exact withinAllowance_push h _ _
  | some q =>
    by_cases hq : q < l.length
    · simp only [hq, ↓reduceIte]; exact withinAllowance_push h _ _
    · simp only [hq, ↓reduceIte]; exact h

/-- An append keeps every allowance within `amountMax` when the new one is. -/
theorem append_bounded {l : Ledger} (h : l.Bounded) (p : Option Nat) {x : Nat}
    (hx : x ≤ amountMax) : (l.append p x).2.Bounded := by
  have push : ∀ q : Option Nat, (l ++ [(⟨q, x, 0⟩ : Node)]).Bounded := by
    intro q n hn
    rcases List.mem_append.mp hn with hn | hn
    · exact h n hn
    · rw [List.mem_singleton.mp hn]; exact hx
  unfold append
  cases p with
  | none => exact push _
  | some q =>
    by_cases hq : q < l.length
    · simp only [hq, ↓reduceIte]; exact push _
    · simp only [hq, ↓reduceIte]; exact h

theorem spend_parentsFirst {l : Ledger} (h : l.ParentsFirst) (i amount : Nat) :
    (l.spend i amount).2.ParentsFirst := by
  unfold ParentsFirst
  rw [parentOf_spend]
  exact h

theorem refill_parentsFirst {l : Ledger} (h : l.ParentsFirst) (i extra : Nat) :
    (l.refill i extra).2.ParentsFirst := by
  unfold ParentsFirst
  rw [parentOf_refill]
  exact h

theorem append_parentsFirst {l : Ledger} (h : l.ParentsFirst) (p : Option Nat) (x : Nat) :
    (l.append p x).2.ParentsFirst := by
  intro j q hj
  by_cases hjl : j < l.length
  · have : (l.append p x).2.parentOf j = l.parentOf j := by
      simp only [parentOf, getElem?_append_of_lt l p x hjl]
    exact h j q (this ▸ hj)
  · cases hr : l.append p x with
    | mk r l' =>
      rw [hr] at hj
      cases r with
      | error e =>
        have := append_error (l := l) (p := p) (x := x) (e := e) (by rw [hr])
        rw [hr] at this
        simp only at this
        subst this
        simp [parentOf, List.getElem?_eq_none (Nat.le_of_not_lt hjl)] at hj
      | ok k =>
        obtain ⟨hp, -, rfl⟩ := append_ok_iff.mp hr
        simp only [parentOf, List.getElem?_append_right (Nat.le_of_not_lt hjl)] at hj
        cases hk : j - l.length with
        | zero =>
          have hjeq : j = l.length := by omega
          simp only [hk, List.getElem?_cons_zero, Option.bind_some] at hj
          rw [hjeq]
          exact hp q hj
        | succ k => simp [hk] at hj

/-! ## Runs -/

theorem run_spend_fst (l : Ledger) (i x : Nat) (ops : List Op) :
    (l.run (.spend i x :: ops)).1 = ((l.spend i x).2.run ops).1 := by
  rw [run.eq_2]
  split
  · rename_i l' hs; rw [hs]
  · rename_i e l' hs; rw [hs]

theorem run_withinAllowance {l : Ledger} (h : l.WithinAllowance) (ops : List Op) :
    (l.run ops).1.WithinAllowance := by
  induction ops generalizing l with
  | nil => exact h
  | cons op ops ih =>
    cases op with
    | spend i x => rw [run_spend_fst]; exact ih (spend_withinAllowance h i x)
    | refill i x => exact ih (refill_withinAllowance h i x)
    | append p x => exact ih (append_withinAllowance h p x)

theorem run_parentsFirst {l : Ledger} (h : l.ParentsFirst) (ops : List Op) :
    (l.run ops).1.ParentsFirst := by
  induction ops generalizing l with
  | nil => exact h
  | cons op ops ih =>
    cases op with
    | spend i x => rw [run_spend_fst]; exact ih (spend_parentsFirst h i x)
    | refill i x => exact ih (refill_parentsFirst h i x)
    | append p x => exact ih (append_parentsFirst h p x)

/-- A run never removes a node or changes an existing node's parent link. -/
theorem run_extends (l : Ledger) (ops : List Op) :
    l.length ≤ (l.run ops).1.length ∧
      ∀ j < l.length, (l.run ops).1.parentOf j = l.parentOf j := by
  induction ops generalizing l with
  | nil => exact ⟨Nat.le_refl _, fun _ _ => rfl⟩
  | cons op ops ih =>
    cases op with
    | spend i x =>
      rw [run_spend_fst]
      obtain ⟨hlen, hpar⟩ := ih (l.spend i x).2
      rw [length_spend] at hlen
      refine ⟨hlen, fun j hj => ?_⟩
      rw [hpar j (by rw [length_spend]; exact hj), parentOf_spend]
    | refill i x =>
      obtain ⟨hlen, hpar⟩ := ih (l.refill i x).2
      rw [length_refill] at hlen
      refine ⟨hlen, fun j hj => ?_⟩
      show ((l.refill i x).2.run ops).1.parentOf j = _
      rw [hpar j (by rw [length_refill]; exact hj), parentOf_refill]
    | append p x =>
      obtain ⟨hlen, hpar⟩ := ih (l.append p x).2
      refine ⟨Nat.le_trans (length_append_ge l p x) hlen, fun j hj => ?_⟩
      show ((l.append p x).2.run ops).1.parentOf j = _
      rw [hpar j (Nat.lt_of_lt_of_le hj (length_append_ge l p x))]
      simp only [parentOf, getElem?_append_of_lt l p x hj]

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

/-- A run of spends and refills changes no parent link. -/
theorem parentOf_run (l : Ledger) (ops : List Op)
    (h : ∀ op ∈ ops, ∀ p x, op ≠ .append p x) : (l.run ops).1.parentOf = l.parentOf := by
  induction ops generalizing l with
  | nil => rfl
  | cons op ops ih =>
    have h' : ∀ op ∈ ops, ∀ p x, op ≠ .append p x :=
      fun op hop => h op (List.mem_cons_of_mem _ hop)
    cases op with
    | spend i x => rw [run_spend_fst, ih _ h', parentOf_spend]
    | refill i x => exact (ih _ h').trans (parentOf_refill l i x)
    | append p x => exact absurd rfl (h _ List.mem_cons_self p x)

/-- On a run of spends and refills, measuring against the final tree is
measuring against the starting one. -/
theorem spentUnder_run (l : Ledger) (ops : List Op) (h : ∀ op ∈ ops, ∀ p x, op ≠ .append p x)
    (log : List (Nat × Nat)) (a : Nat) : spentUnder (l.run ops).1 log a = spentUnder l log a :=
  spentUnder_congr (parentOf_run l ops h) log a

/-- A successful walk fixes its chain in every ledger that keeps the walked
ledger's parent links: there too, the nodes at or above `i` are exactly the
walk's path. -/
theorem within_of_walk {l l' : Ledger} {amount : Nat}
    (hext : ∀ j < l.length, l'.parentOf j = l.parentOf j) :
    ∀ {fuel i path}, l.walk amount fuel i = .ok path → ∀ a, l'.Within i a ↔ a ∈ path
  | 0, _, _, h => by simp [walk] at h
  | fuel + 1, i, path, h => by
    intro a
    unfold walk at h
    cases hi : l[i]? with
    | none => simp [hi] at h
    | some n =>
      have hpi : l'.parentOf i = n.parent := by
        rw [hext i (lt_length_of_getElem? hi)]
        simp [parentOf, hi]
      simp only [hi] at h
      split at h
      · simp at h
      · cases hp : n.parent with
        | none =>
          simp only [hp, Except.ok.injEq] at h
          subst h
          rw [within_root (hpi.trans hp)]
          simp
        | some p =>
          simp only [hp] at h
          split at h
          · cases hw : l.walk amount fuel p with
            | error e => simp [hw, Except.map] at h
            | ok rest =>
              simp only [hw, Except.map, Except.ok.injEq] at h
              subst h
              rw [within_step (hpi.trans hp), List.mem_cons, within_of_walk hext hw a]
          · simp at h

theorem spentUnder_cons (l : Ledger) (i x : Nat) (log : List (Nat × Nat)) (a : Nat) :
    open Classical in
    spentUnder l ((i, x) :: log) a = (if l.Within i a then x else 0) + spentUnder l log a := by
  unfold spentUnder
  by_cases w : l.Within i a <;> simp [w]

theorem spent_refill (l : Ledger) (i extra a : Nat) :
    (l.refill i extra).2[a]?.map (·.spent) = l[a]?.map (·.spent) := by
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

/-- Each node's spent is its starting spent (nothing, for a node the run
appended) plus every logged spend made at or under it in the final tree. -/
theorem spent_run (l : Ledger) (ops : List Op) (a : Nat) {n : Node}
    (ha : (l.run ops).1[a]? = some n) :
    n.spent = (l[a]?.map (·.spent)).getD 0 + spentUnder (l.run ops).1 (l.run ops).2 a := by
  induction ops generalizing l with
  | nil =>
    simp only [run] at ha ⊢
    simp [spentUnder, ha]
  | cons op ops ih =>
    cases op with
    | spend i x =>
      unfold run at ha ⊢
      split at ha
      · next l' hs =>
        simp only at ha ⊢
        rw [ih l' ha, spentUnder_cons]
        obtain ⟨path, hp, -⟩ := spend_ok_iff.mp hs
        have hext : ∀ j < l.length, (l'.run ops).1.parentOf j = l.parentOf j := by
          intro j hj
          have hl : l'.length = l.length := spend_ok_length hs
          rw [(run_extends l' ops).2 j (hl ▸ hj)]
          have := parentOf_spend l i x
          rw [hs] at this
          rw [this]
        have hw : (l'.run ops).1.Within i a ↔ l.Within i a := by
          rw [within_of_walk hext hp a, mem_walk hp a]
        split
        · rename_i w
          rw [spend_ok_charges hs (hw.mp w)]
          obtain ⟨m, hm, -⟩ := walk_fits hp a ((mem_walk hp a).mpr (hw.mp w))
          simp [hm]
          omega
        · rename_i w
          rw [spend_ok_unchanged hs (fun w' => w (hw.mpr w'))]
          omega
      · next e l' hs =>
        rw [spend_eq_error hs] at ha ⊢
        exact ih l ha
    | refill i x =>
      unfold run at ha ⊢
      rw [ih _ ha]
      congr 1
      cases h : l[a]? with
      | none =>
        have := spent_refill l i x a
        rw [h] at this
        simp [this]
      | some m =>
        have := spent_refill l i x a
        rw [h] at this
        simp [this]
    | append p x =>
      unfold run at ha ⊢
      rw [ih _ ha, spent_append]

/-- Budget safety over any run: starting from a ledger with nothing spent,
after any sequence of spends, refills and appends, the total successfully
spent at or under node `a` never exceeds `a`'s allowance, however much its
children's allowances oversubscribe it. -/
theorem spentUnder_le_allowance {l : Ledger} (h0 : ∀ n ∈ l, n.spent = 0)
    (ops : List Op) {a : Nat} {n : Node} (ha : (l.run ops).1[a]? = some n) :
    spentUnder (l.run ops).1 (l.run ops).2 a ≤ n.allowance := by
  have hw : l.WithinAllowance := fun m hm => by rw [h0 m hm]; exact Nat.zero_le _
  have fits := withinAllowance_iff.mp (run_withinAllowance hw ops) a n ha
  have hs := spent_run l ops a ha
  have hz : (l[a]?.map (·.spent)).getD 0 = 0 := by
    cases hl : l[a]? with
    | none => rfl
    | some m => simp [h0 m (List.mem_of_getElem? hl)]
  rw [hz, Nat.zero_add] at hs
  rw [← hs]
  exact fits

end Ledger

/-! ## Examples: oversubscribed siblings and delegation

A root with allowance 10 delegates allowance 8 to each of two children. The
first child spends 8; the second child's spend of 3 is refused at the root,
which has only 2 left, and its spend of 2 succeeds.

The first child then delegates allowance 20, more than its own 8, to a new
node 3. Node 3's spend of 9 is refused at the first child, and its spend of 8
succeeds, charging node 3, the first child and the root. A spend at a node
that does not exist yet fails as `noSuchNode` and changes nothing. -/

private def siblings : Ledger :=
  [⟨none, 10, 0⟩, ⟨some 0, 8, 0⟩, ⟨some 0, 8, 0⟩]

example : ((siblings.spend 1 8).2.spend 2 3).1 = .error (.overdrawn 0) := rfl

example :
    ((siblings.spend 1 8).2.spend 2 2) =
      (.ok (), [⟨none, 10, 10⟩, ⟨some 0, 8, 8⟩, ⟨some 0, 8, 2⟩]) := rfl

example :
    siblings.run [.spend 3 1, .append (some 1) 20, .spend 3 9, .spend 3 8] =
      ([⟨none, 10, 8⟩, ⟨some 0, 8, 8⟩, ⟨some 0, 8, 0⟩, ⟨some 1, 20, 8⟩], [(3, 8)]) := rfl

example : (siblings.spend 3 9).1 = .error (.noSuchNode 3) := rfl

example : (siblings.append (some 3) 5) = (.error (.noSuchNode 3), siblings) := rfl

end AttenuatingGrants.Budget
