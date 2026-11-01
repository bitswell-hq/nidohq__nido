import AttenuatingGrants.Bytes
import AttenuatingGrants.Grant

/-!
# Step-counting evaluation

Each vocabulary has a counted evaluator: a copy of `Caveat.holds` that returns
the same `Bool` paired with the number of steps it took. A step is one
primitive comparison (two bytes, two scalars, an `i128` order test, or one
constructor test) or one traversal of a list cell. Reaching the end of a list
costs nothing, so the empty grant is checked in zero steps.

This module holds the shared pieces: counted byte-string equality, list
membership and indexing, the grant check over a list of caveats
(`allowsCounted`) and the batch check over a list of actions
(`allowsAllCounted`). Both checks stop at the first failure, as `List.all`
does.

Theorems:

* `allowsCounted_fst`, `allowsAllCounted_fst`: the counted checks return
  exactly `Grant.allows` and `Grant.allowsAll` of the readable grant.
* `allowsCounted_steps_le`: if every caveat costs at most
  `k * (1 + size c) * X` steps including its own list cell, the grant check
  costs at most `k * (number of caveats + total caveat size) * X`.
* `allowsAllCounted_steps_le`: the batch version, with one extra unit in the
  grant factor for the cell of each action.
* `allowsAllCounted_nil_steps`: the empty grant checks a batch in exactly one
  step per action, which is why the batch bound needs that extra unit.
-/

namespace AttenuatingGrants.Cost

/-! ## Counted primitives -/

/-- Bytewise equality, one step per pair of bytes compared. -/
def bytesEq : Bytes → Bytes → Bool × Nat
  | x :: xs, y :: ys =>
    if x = y then
      let r := bytesEq xs ys
      (r.1, r.2 + 1)
    else (false, 1)
  | [], [] => (true, 0)
  | _, _ => (false, 0)

/-- Equality of scalars (ports, schemes, modes, payload kinds): one step. -/
def scalarEq {α : Type} [DecidableEq α] (x y : α) : Bool × Nat :=
  (decide (x = y), 1)

/-- Membership of `x` in a list, by a counted equality: one step per cell
visited plus the steps of each comparison. Stops at the first match. -/
def mem {α : Type} (eq : α → α → Bool × Nat) (x : α) : List α → Bool × Nat
  | [] => (false, 0)
  | y :: ys =>
    let r := eq x y
    if r.1 then (true, r.2 + 1)
    else
      let s := mem eq x ys
      (s.1, r.2 + 1 + s.2)

/-- `l[i]?`, one step per cell visited. -/
def get? {α : Type} : List α → Nat → Option α × Nat
  | [], _ => (none, 0)
  | x :: _, 0 => (some x, 1)
  | _ :: xs, i + 1 =>
    let r := get? xs i
    (r.1, r.2 + 1)

/-- The size of a list of byte strings: one per cell plus each string's length. -/
def bytesListSize (l : List Bytes) : Nat :=
  (l.map (·.length + 1)).sum

theorem bytesEq_fst (x y : Bytes) : (bytesEq x y).1 = decide (x = y) := by
  induction x generalizing y with
  | nil => cases y <;> simp [bytesEq]
  | cons b x ih =>
    cases y with
    | nil => simp [bytesEq]
    | cons c y =>
      simp only [bytesEq]
      split <;> simp_all

theorem bytesEq_snd_le (x y : Bytes) : (bytesEq x y).2 ≤ x.length := by
  induction x generalizing y with
  | nil => cases y <;> simp [bytesEq]
  | cons b x ih =>
    cases y with
    | nil => simp [bytesEq]
    | cons c y =>
      simp only [bytesEq]
      split
      · simpa using ih y
      · simp

theorem bytesEq_snd_le_right (x y : Bytes) : (bytesEq x y).2 ≤ y.length := by
  induction x generalizing y with
  | nil => cases y <;> simp [bytesEq]
  | cons b x ih =>
    cases y with
    | nil => simp [bytesEq]
    | cons c y =>
      simp only [bytesEq]
      split
      · simpa using ih y
      · simp

theorem scalarEq_fst {α : Type} [DecidableEq α] (x y : α) :
    (scalarEq x y).1 = decide (x = y) := rfl

theorem mem_fst {α : Type} [DecidableEq α] (eq : α → α → Bool × Nat) (x : α)
    (h : ∀ y, (eq x y).1 = decide (x = y)) (l : List α) :
    (mem eq x l).1 = decide (x ∈ l) := by
  induction l with
  | nil => simp [mem]
  | cons y ys ih =>
    simp only [mem]
    split <;> simp_all

theorem mem_bytesEq_fst (x : Bytes) (l : List Bytes) :
    (mem bytesEq x l).1 = decide (x ∈ l) :=
  by rw [mem_fst bytesEq x (bytesEq_fst x) l]; congr

theorem mem_scalarEq_fst {α : Type} [DecidableEq α] (x : α) (l : List α) :
    (mem scalarEq x l).1 = decide (x ∈ l) :=
  mem_fst scalarEq x (scalarEq_fst x) l

theorem mem_snd_le {α : Type} (eq : α → α → Bool × Nat) (x : α) (m : Nat) (l : List α)
    (h : ∀ y ∈ l, (eq x y).2 ≤ m) :
    (mem eq x l).2 ≤ l.length * (m + 1) := by
  induction l with
  | nil => simp [mem]
  | cons y ys ih =>
    have hy := h y (by simp)
    have ih := ih fun z hz => h z (by simp [hz])
    simp only [mem, List.length_cons, Nat.succ_mul]
    split <;> simp <;> omega

/-- Membership by bytewise equality costs at most one step per cell plus the
length of the string looked up, for each cell. -/
theorem mem_bytesEq_snd_le (x : Bytes) (l : List Bytes) :
    (mem bytesEq x l).2 ≤ bytesListSize l * (x.length + 1) := by
  refine Nat.le_trans (mem_snd_le bytesEq x x.length l fun y _ => bytesEq_snd_le x y) ?_
  refine Nat.mul_le_mul_right _ ?_
  induction l with
  | nil => simp
  | cons y ys ih => simp [bytesListSize] at ih ⊢; omega

theorem mem_scalarEq_snd_le {α : Type} [DecidableEq α] (x : α) (l : List α) :
    (mem scalarEq x l).2 ≤ 2 * l.length := by
  have := mem_snd_le scalarEq x 1 l fun _ _ => Nat.le_refl 1
  omega

theorem get?_fst {α : Type} (l : List α) (i : Nat) : (get? l i).1 = l[i]? := by
  induction l generalizing i with
  | nil => simp [get?]
  | cons x xs ih => cases i <;> simp [get?, ih]

theorem get?_snd_le {α : Type} (l : List α) (i : Nat) : (get? l i).2 ≤ l.length := by
  induction l generalizing i with
  | nil => simp [get?]
  | cons x xs ih =>
    cases i with
    | zero => simp [get?]
    | succ i => simpa [get?] using ih i

/-! ## Counted grant checks -/

section Check

variable {C A : Type}

/-- The grant check of `a` against the caveats `cs`, by a counted caveat
evaluator: one step per caveat cell visited plus each caveat's steps. Stops at
the first caveat that fails. -/
def allowsCounted (holds : C → A → Bool × Nat) (a : A) : List C → Bool × Nat
  | [] => (true, 0)
  | c :: cs =>
    let r := holds c a
    if r.1 then
      let s := allowsCounted holds a cs
      (s.1, r.2 + 1 + s.2)
    else (false, r.2 + 1)

/-- The batch check of `actions` against the caveats `cs`: one step per action
cell visited plus each action's grant check. Stops at the first action denied. -/
def allowsAllCounted (holds : C → A → Bool × Nat) (cs : List C) : List A → Bool × Nat
  | [] => (true, 0)
  | a :: as =>
    let r := allowsCounted holds a cs
    if r.1 then
      let s := allowsAllCounted holds cs as
      (s.1, r.2 + 1 + s.2)
    else (false, r.2 + 1)

theorem allowsCounted_fst (holds : C → A → Bool × Nat) (spec : C → A → Bool)
    (h : ∀ c a, (holds c a).1 = spec c a) (cs : List C) (a : A) :
    (allowsCounted holds a cs).1 = (Grant.mk (cs.map spec)).allows a := by
  induction cs with
  | nil => rfl
  | cons c cs ih =>
    simp only [allowsCounted, Grant.allows, List.map_cons, List.all_cons] at ih ⊢
    rw [← h c a]
    split <;> simp_all

theorem allowsAllCounted_fst (holds : C → A → Bool × Nat) (spec : C → A → Bool)
    (h : ∀ c a, (holds c a).1 = spec c a) (cs : List C) (actions : List A) :
    (allowsAllCounted holds cs actions).1 = (Grant.mk (cs.map spec)).allowsAll actions := by
  induction actions with
  | nil => rfl
  | cons a as ih =>
    simp only [allowsAllCounted, Grant.allowsAll, List.all_cons] at ih ⊢
    rw [← allowsCounted_fst holds spec h cs a]
    split <;> simp_all

theorem allowsCounted_steps_le (holds : C → A → Bool × Nat) (size : C → Nat) (k X : Nat)
    (a : A) (cs : List C) (h : ∀ c ∈ cs, (holds c a).2 + 1 ≤ k * (1 + size c) * X) :
    (allowsCounted holds a cs).2 ≤ k * (cs.length + (cs.map size).sum) * X := by
  induction cs with
  | nil => simp [allowsCounted]
  | cons c cs ih =>
    have hc := h c (by simp)
    have ih := ih fun c' hc' => h c' (by simp [hc'])
    have split_bound : k * ((cs.length + 1) + (size c + (cs.map size).sum)) * X =
        k * (1 + size c) * X + k * (cs.length + (cs.map size).sum) * X := by
      grind
    simp only [allowsCounted, List.length_cons, List.map_cons, List.sum_cons, split_bound]
    split <;> simp <;> omega

/-- The batch bound. Each action costs one step for its own cell whatever the
grant, so the grant factor is the number of caveats plus the total caveat size
plus one. -/
theorem allowsAllCounted_steps_le (holds : C → A → Bool × Nat) (cs : List C) (G k : Nat)
    (size : A → Nat) (hk : 1 ≤ k) (actions : List A)
    (h : ∀ a ∈ actions, (allowsCounted holds a cs).2 ≤ k * G * (size a + 1)) :
    (allowsAllCounted holds cs actions).2 ≤
      k * (G + 1) * (actions.map (size · + 1)).sum := by
  induction actions with
  | nil => simp [allowsAllCounted]
  | cons a as ih =>
    have ha := h a (by simp)
    have ih := ih fun a' ha' => h a' (by simp [ha'])
    have one_le : 1 ≤ k * (size a + 1) :=
      Nat.mul_le_mul hk (Nat.le_add_left 1 _)
    have split_bound : k * (G + 1) * ((size a + 1) + (as.map (size · + 1)).sum) =
        k * G * (size a + 1) + k * (size a + 1) +
          k * (G + 1) * (as.map (size · + 1)).sum := by
      grind
    simp only [allowsAllCounted, List.map_cons, List.sum_cons, split_bound]
    split <;> simp <;> omega

/-- The empty grant checks a batch in exactly one step per action. -/
theorem allowsAllCounted_nil_steps (holds : C → A → Bool × Nat) (actions : List A) :
    (allowsAllCounted holds [] actions).2 = actions.length := by
  induction actions with
  | nil => rfl
  | cons a as ih => simp [allowsAllCounted, allowsCounted, ih]; omega

end Check

end AttenuatingGrants.Cost
