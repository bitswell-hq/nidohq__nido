import AttenuatingGrants.Cost.Basic
import AttenuatingGrants.Vocab.Chain

/-!
# Chain cost

A scalar `Val` (`i128`, `u64`, `bool`) has size 1; a byte-carrying one
(`bytes`, `address`, `symbol`) has its length plus 1. An invocation's size is
the lengths of its contract id and function name plus, for each argument, the
argument's size plus 1; a deployment's size is the length of its wasm hash.

`contractIn` and `functionIn` have their list size; `argI128AtMost` has size 2
(an index and a bound); `argEq i val` has size `1 + val.size`.

Every caveat starts with one step to test the action's kind. Reading
argument `i` walks at most every argument cell (`Cost.get?`), so the index
itself never adds cost beyond the argument list.
-/

namespace AttenuatingGrants.Chain

open Cost

def Val.size : Val → Nat
  | .i128 _ | .u64 _ | .bool _ => 1
  | .bytes v | .address v | .symbol v => v.length + 1

def Action.size : Action → Nat
  | .invoke contract function args =>
    contract.length + function.length + (args.map (·.size + 1)).sum
  | .createContract wasmHash => wasmHash.length

def Caveat.size : Caveat → Nat
  | .contractIn contracts => bytesListSize contracts
  | .functionIn functions => bytesListSize functions
  | .argI128AtMost _ _ => 2
  | .argEq _ val => 1 + val.size

/-- `Val` equality: one step for the kind test, then one step for a scalar or
the bytes compared for a byte string. -/
def valEq : Val → Val → Bool × Nat
  | .i128 x, .i128 y => (decide (x = y), 2)
  | .u64 x, .u64 y => (decide (x = y), 2)
  | .bool x, .bool y => (decide (x = y), 2)
  | .bytes x, .bytes y => let r := bytesEq x y; (r.1, r.2 + 1)
  | .address x, .address y => let r := bytesEq x y; (r.1, r.2 + 1)
  | .symbol x, .symbol y => let r := bytesEq x y; (r.1, r.2 + 1)
  | _, _ => (false, 1)

def Caveat.holdsCounted : Caveat → Action → Bool × Nat
  | .contractIn contracts, .invoke contract _ _ =>
    let r := mem bytesEq contract contracts
    (r.1, r.2 + 1)
  | .functionIn functions, .invoke _ function _ =>
    let r := mem bytesEq function functions
    (r.1, r.2 + 1)
  | .argI128AtMost i n, .invoke _ _ args =>
    let r := get? args i
    match r.1 with
    | some (.i128 v) => (decide (v.toInt ≤ n.toInt), r.2 + 4)
    | some _ => (false, r.2 + 3)
    | none => (false, r.2 + 2)
  | .argEq i val, .invoke _ _ args =>
    let r := get? args i
    match r.1 with
    | some v =>
      let e := valEq val v
      (e.1, r.2 + 2 + e.2)
    | none => (false, r.2 + 2)
  | _, .createContract _ => (false, 1)

def allowsCounted (cs : List Caveat) (a : Action) : Bool × Nat :=
  Cost.allowsCounted Caveat.holdsCounted a cs

def allowsAllCounted (cs : List Caveat) (actions : List Action) : Bool × Nat :=
  Cost.allowsAllCounted Caveat.holdsCounted cs actions

theorem valEq_fst (v w : Val) : (valEq v w).1 = decide (v = w) := by
  cases v <;> cases w <;> simp [valEq, bytesEq_fst]

theorem valEq_snd_le (v w : Val) : (valEq v w).2 ≤ v.size + 1 := by
  cases v <;> cases w <;> simp [valEq, Val.size] <;> grind [bytesEq_snd_le]

theorem length_le_args_size (args : List Val) :
    args.length ≤ (args.map (·.size + 1)).sum := by
  induction args with
  | nil => simp
  | cons v args ih => simp; omega

theorem holdsCounted_fst (c : Caveat) (a : Action) : (c.holdsCounted a).1 = c.holds a := by
  cases a with
  | createContract wasmHash => cases c <;> rfl
  | invoke contract function args =>
    cases c with
    | contractIn contracts => simp [Caveat.holdsCounted, Caveat.holds, mem_bytesEq_fst]
    | functionIn functions => simp [Caveat.holdsCounted, Caveat.holds, mem_bytesEq_fst]
    | argI128AtMost i n =>
      simp only [Caveat.holdsCounted, Caveat.holds, get?_fst]
      rcases args[i]? with _ | (_ | _ | _ | _ | _ | _) <;> rfl
    | argEq i val =>
      simp only [Caveat.holdsCounted, Caveat.holds, get?_fst]
      rcases args[i]? with _ | w
      · rfl
      · simp [valEq_fst, eq_comm]

theorem allowsCounted_fst (cs : List Caveat) (a : Action) :
    (allowsCounted cs a).1 = (grant cs).allows a :=
  Cost.allowsCounted_fst _ _ holdsCounted_fst cs a

theorem allowsAllCounted_fst (cs : List Caveat) (actions : List Action) :
    (allowsAllCounted cs actions).1 = (grant cs).allowsAll actions :=
  Cost.allowsAllCounted_fst _ _ holdsCounted_fst cs actions

theorem holdsCounted_steps_le (c : Caveat) (a : Action) :
    (c.holdsCounted a).2 + 1 ≤ 2 * (1 + c.size) * (a.size + 1) := by
  cases a with
  | createContract wasmHash =>
    have := Nat.mul_le_mul_left (2 * (1 + c.size)) (Nat.le_add_left 1 wasmHash.length)
    have : 2 ≤ 2 * (1 + c.size) := Nat.mul_le_mul_left 2 (Nat.le_add_right 1 _)
    cases c <;> simp only [Caveat.holdsCounted, Action.size] at * <;> omega
  | invoke contract function args =>
    have hargs := length_le_args_size args
    cases c with
    | contractIn contracts =>
      have := mem_bytesEq_snd_le contract contracts
      have := Nat.mul_le_mul_left (bytesListSize contracts)
        (Nat.add_le_add_right (Nat.le_add_right contract.length
          (function.length + (args.map (·.size + 1)).sum)) 1)
      simp only [Caveat.holdsCounted, Caveat.size, Action.size] at *
      grind
    | functionIn functions =>
      have := mem_bytesEq_snd_le function functions
      have := Nat.mul_le_mul_left (bytesListSize functions)
        (Nat.add_le_add_right (show function.length ≤
          contract.length + function.length + (args.map (·.size + 1)).sum by omega) 1)
      simp only [Caveat.holdsCounted, Caveat.size, Action.size] at *
      grind
    | argI128AtMost i n =>
      have := get?_snd_le args i
      simp only [Caveat.holdsCounted, Caveat.size, Action.size]
      split <;> grind
    | argEq i val =>
      have := get?_snd_le args i
      simp only [Caveat.holdsCounted, Caveat.size, Action.size]
      split
      · next w _ =>
        have := valEq_snd_le val w
        grind
      · grind

/-- Theorem 1 (cost bound), Chain: checking an action costs at most
`2 * (number of caveats + total caveat size) * (action size + 1)` steps. -/
def AllowsCostBound : Prop :=
  ∀ (cs : List Caveat) (a : Action),
    (allowsCounted cs a).2 ≤ 2 * (cs.length + (cs.map Caveat.size).sum) * (a.size + 1)

/-- Theorem 1 (cost bound), Chain batches (every context of an authorization
tree): checking every action costs at most
`2 * (number of caveats + total caveat size + 1) * Σ (action size + 1)`. -/
def AllowsAllCostBound : Prop :=
  ∀ (cs : List Caveat) (actions : List Action),
    (allowsAllCounted cs actions).2 ≤
      2 * (cs.length + (cs.map Caveat.size).sum + 1) * (actions.map (·.size + 1)).sum

theorem allows_cost_bound : AllowsCostBound := fun cs a =>
  Cost.allowsCounted_steps_le _ _ 2 _ a cs fun c _ => holdsCounted_steps_le c a

theorem allowsAll_cost_bound : AllowsAllCostBound := fun cs actions =>
  Cost.allowsAllCounted_steps_le _ cs _ 2 Action.size (by decide) actions
    fun a _ => allows_cost_bound cs a

end AttenuatingGrants.Chain
