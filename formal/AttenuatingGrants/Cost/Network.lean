import AttenuatingGrants.Cost.Basic
import AttenuatingGrants.Vocab.Network

/-!
# Network cost

The size of an action is the length of its host; the port and scheme are
scalars compared in one step. A caveat's size is its list length, counting the
length of each host for `hostIn`.
-/

namespace AttenuatingGrants.Network

open Cost

def Action.size (a : Action) : Nat := a.host.length

def Caveat.size : Caveat → Nat
  | .hostIn hosts => bytesListSize hosts
  | .portIn ports => ports.length
  | .schemeIn schemes => schemes.length

def Caveat.holdsCounted : Caveat → Action → Bool × Nat
  | .hostIn hosts, a => mem bytesEq a.host hosts
  | .portIn ports, a => mem scalarEq a.port ports
  | .schemeIn schemes, a => mem scalarEq a.scheme schemes

def allowsCounted (cs : List Caveat) (a : Action) : Bool × Nat :=
  Cost.allowsCounted Caveat.holdsCounted a cs

def allowsAllCounted (cs : List Caveat) (actions : List Action) : Bool × Nat :=
  Cost.allowsAllCounted Caveat.holdsCounted cs actions

theorem holdsCounted_fst (c : Caveat) (a : Action) : (c.holdsCounted a).1 = c.holds a := by
  cases c <;> simp [Caveat.holdsCounted, Caveat.holds, mem_bytesEq_fst, mem_scalarEq_fst]

theorem allowsCounted_fst (cs : List Caveat) (a : Action) :
    (allowsCounted cs a).1 = (grant cs).allows a :=
  Cost.allowsCounted_fst _ _ holdsCounted_fst cs a

theorem allowsAllCounted_fst (cs : List Caveat) (actions : List Action) :
    (allowsAllCounted cs actions).1 = (grant cs).allowsAll actions :=
  Cost.allowsAllCounted_fst _ _ holdsCounted_fst cs actions

theorem holdsCounted_steps_le (c : Caveat) (a : Action) :
    (c.holdsCounted a).2 + 1 ≤ 2 * (1 + c.size) * (a.size + 1) := by
  cases c with
  | hostIn hosts =>
    have := mem_bytesEq_snd_le a.host hosts
    simp only [Caveat.holdsCounted, Caveat.size, Action.size] at this ⊢
    grind
  | portIn ports =>
    have := mem_scalarEq_snd_le a.port ports
    have := Nat.mul_le_mul_left (2 * (1 + ports.length)) (Nat.le_add_left 1 a.size)
    simp only [Caveat.holdsCounted, Caveat.size] at *
    omega
  | schemeIn schemes =>
    have := mem_scalarEq_snd_le a.scheme schemes
    have := Nat.mul_le_mul_left (2 * (1 + schemes.length)) (Nat.le_add_left 1 a.size)
    simp only [Caveat.holdsCounted, Caveat.size] at *
    omega

/-- Theorem 1 (cost bound), Network: checking an action costs at most
`2 * (number of caveats + total caveat size) * (action size + 1)` steps. -/
def AllowsCostBound : Prop :=
  ∀ (cs : List Caveat) (a : Action),
    (allowsCounted cs a).2 ≤ 2 * (cs.length + (cs.map Caveat.size).sum) * (a.size + 1)

/-- Theorem 1 (cost bound), Network batches: checking every action of a batch
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

end AttenuatingGrants.Network
