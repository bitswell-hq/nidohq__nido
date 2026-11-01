import AttenuatingGrants.Cost.Basic
import AttenuatingGrants.Vocab.Signing

/-!
# Signing cost

The size of an action is the length of its key plus the length of its network
id; the payload kind is a scalar compared in one step. A caveat's size is its
list length, counting the length of each key or network id.
-/

namespace AttenuatingGrants.Signing

open Cost

def Action.size (a : Action) : Nat := a.key.length + a.network.length

def Caveat.size : Caveat → Nat
  | .keyIn keys => bytesListSize keys
  | .networkIn networks => bytesListSize networks
  | .payloadIn payloads => payloads.length

def Caveat.holdsCounted : Caveat → Action → Bool × Nat
  | .keyIn keys, a => mem bytesEq a.key keys
  | .networkIn networks, a => mem bytesEq a.network networks
  | .payloadIn payloads, a => mem scalarEq a.payload payloads

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
  | keyIn keys =>
    have := mem_bytesEq_snd_le a.key keys
    have := Nat.mul_le_mul_left (bytesListSize keys)
      (Nat.add_le_add_right (Nat.le_add_right a.key.length a.network.length) 1)
    simp only [Caveat.holdsCounted, Caveat.size, Action.size] at *
    grind
  | networkIn networks =>
    have := mem_bytesEq_snd_le a.network networks
    have := Nat.mul_le_mul_left (bytesListSize networks)
      (Nat.add_le_add_right (Nat.le_add_left a.network.length a.key.length) 1)
    simp only [Caveat.holdsCounted, Caveat.size, Action.size] at *
    grind
  | payloadIn payloads =>
    have := mem_scalarEq_snd_le a.payload payloads
    have := Nat.mul_le_mul_left (2 * (1 + payloads.length)) (Nat.le_add_left 1 a.size)
    simp only [Caveat.holdsCounted, Caveat.size] at *
    omega

/-- Theorem 1 (cost bound), Signing: checking an action costs at most
`2 * (number of caveats + total caveat size) * (action size + 1)` steps. -/
def AllowsCostBound : Prop :=
  ∀ (cs : List Caveat) (a : Action),
    (allowsCounted cs a).2 ≤ 2 * (cs.length + (cs.map Caveat.size).sum) * (a.size + 1)

/-- Theorem 1 (cost bound), Signing batches: checking every action of a batch
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

end AttenuatingGrants.Signing
