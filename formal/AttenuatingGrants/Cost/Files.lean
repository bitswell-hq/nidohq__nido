import AttenuatingGrants.Cost.Basic
import AttenuatingGrants.Vocab.Files

/-!
# Files cost

The size of an action is the size of its path (one per component plus each
component's length); the mode is a scalar compared in one step. The size of
`pathUnder p` is the size of `p`; the size of `modeIn modes` is its length.

`isPrefixCounted` walks the prefix and the path in step, one step per pair of
components plus the bytes compared, so its cost is bounded by the path alone.
-/

namespace AttenuatingGrants.Files

open Cost

def Action.size (a : Action) : Nat := bytesListSize a.path

def Caveat.size : Caveat → Nat
  | .pathUnder pathPrefix => bytesListSize pathPrefix
  | .modeIn modes => modes.length

def isPrefixCounted : Path → Path → Bool × Nat
  | [], _ => (true, 0)
  | _ :: _, [] => (false, 0)
  | c :: p, d :: q =>
    let r := bytesEq c d
    if r.1 then
      let s := isPrefixCounted p q
      (s.1, r.2 + 1 + s.2)
    else (false, r.2 + 1)

def Caveat.holdsCounted : Caveat → Action → Bool × Nat
  | .pathUnder pathPrefix, a => isPrefixCounted pathPrefix a.path
  | .modeIn modes, a => mem scalarEq a.mode modes

def allowsCounted (cs : List Caveat) (a : Action) : Bool × Nat :=
  Cost.allowsCounted Caveat.holdsCounted a cs

def allowsAllCounted (cs : List Caveat) (actions : List Action) : Bool × Nat :=
  Cost.allowsAllCounted Caveat.holdsCounted cs actions

theorem isPrefixCounted_fst (p q : Path) : (isPrefixCounted p q).1 = isPrefix p q := by
  induction p generalizing q with
  | nil => rfl
  | cons c p ih =>
    cases q with
    | nil => rfl
    | cons d q =>
      simp only [isPrefixCounted, isPrefix, bytesEq_fst]
      split <;> simp_all

theorem isPrefixCounted_snd_le (p q : Path) : (isPrefixCounted p q).2 ≤ bytesListSize q := by
  induction p generalizing q with
  | nil => simp [isPrefixCounted]
  | cons c p ih =>
    cases q with
    | nil => simp [isPrefixCounted]
    | cons d q =>
      have := bytesEq_snd_le_right c d
      have := ih q
      simp only [isPrefixCounted, bytesListSize, List.map_cons, List.sum_cons] at *
      split <;> simp <;> omega

theorem holdsCounted_fst (c : Caveat) (a : Action) : (c.holdsCounted a).1 = c.holds a := by
  cases c <;> simp [Caveat.holdsCounted, Caveat.holds, isPrefixCounted_fst, mem_scalarEq_fst]

theorem allowsCounted_fst (cs : List Caveat) (a : Action) :
    (allowsCounted cs a).1 = (grant cs).allows a :=
  Cost.allowsCounted_fst _ _ holdsCounted_fst cs a

theorem allowsAllCounted_fst (cs : List Caveat) (actions : List Action) :
    (allowsAllCounted cs actions).1 = (grant cs).allowsAll actions :=
  Cost.allowsAllCounted_fst _ _ holdsCounted_fst cs actions

theorem holdsCounted_steps_le (c : Caveat) (a : Action) :
    (c.holdsCounted a).2 + 1 ≤ 2 * (1 + c.size) * (a.size + 1) := by
  cases c with
  | pathUnder pathPrefix =>
    have := isPrefixCounted_snd_le pathPrefix a.path
    simp only [Caveat.holdsCounted, Caveat.size, Action.size] at *
    grind
  | modeIn modes =>
    have := mem_scalarEq_snd_le a.mode modes
    have := Nat.mul_le_mul_left (2 * (1 + modes.length)) (Nat.le_add_left 1 a.size)
    simp only [Caveat.holdsCounted, Caveat.size] at *
    omega

/-- Theorem 1 (cost bound), Files: checking an action costs at most
`2 * (number of caveats + total caveat size) * (action size + 1)` steps. -/
def AllowsCostBound : Prop :=
  ∀ (cs : List Caveat) (a : Action),
    (allowsCounted cs a).2 ≤ 2 * (cs.length + (cs.map Caveat.size).sum) * (a.size + 1)

/-- Theorem 1 (cost bound), Files batches: checking every action of a batch
costs at most `2 * (number of caveats + total caveat size + 1) * Σ (action size + 1)`. -/
def AllowsAllCostBound : Prop :=
  ∀ (cs : List Caveat) (actions : List Action),
    (allowsAllCounted cs actions).2 ≤
      2 * (cs.length + (cs.map Caveat.size).sum + 1) * (actions.map (·.size + 1)).sum

theorem allows_cost_bound : AllowsCostBound := fun cs a =>
  Cost.allowsCounted_steps_le _ _ 2 _ a cs fun c _ => holdsCounted_steps_le c a

theorem allowsAll_cost_bound : AllowsAllCostBound := fun cs actions =>
  Cost.allowsAllCounted_steps_le _ cs _ 2 Action.size (by decide) actions
    fun a _ => allows_cost_bound cs a

end AttenuatingGrants.Files
