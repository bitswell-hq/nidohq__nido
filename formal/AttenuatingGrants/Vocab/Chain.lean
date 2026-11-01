import AttenuatingGrants.Bytes
import AttenuatingGrants.Grant

/-!
# Chain vocabulary

Actions are the contexts of a Soroban authorization tree: a contract
invocation, or a contract-deploying host function. Every caveat is false on
`createContract`, so any chain grant with at least one caveat denies contract
deployment (`restricted_denies_createContract`).

Integer widths follow Soroban's `Val`: `i128` is `BitVec 128` compared as a
signed two's-complement integer, `u64` is `UInt64`. Aeneas represents Rust
`i128` and `u64` by structures over `BitVec 128` and `BitVec 64`, so the
equivalence relates them by their bit vectors.
-/

namespace AttenuatingGrants.Chain

/-- A Soroban `i128`, as a two's-complement bit vector. -/
abbrev I128 := BitVec 128

inductive Val where
  | i128 (v : I128)
  | u64 (v : UInt64)
  | bool (v : Bool)
  | bytes (v : Bytes)
  | address (v : Bytes)
  | symbol (v : Bytes)
  deriving DecidableEq

inductive Action where
  | invoke (contract : Bytes) (function : Bytes) (args : List Val)
  | createContract (wasmHash : Bytes)
  deriving DecidableEq

inductive Caveat where
  /-- The action invokes one of these contracts. -/
  | contractIn (contracts : List Bytes)
  /-- The action invokes one of these functions. -/
  | functionIn (functions : List Bytes)
  /-- Argument `index` exists, is an `i128`, and is at most `n` (signed). -/
  | argI128AtMost (index : Nat) (n : I128)
  /-- Argument `index` exists and equals `val`. -/
  | argEq (index : Nat) (val : Val)
  deriving DecidableEq

def Caveat.holds : Caveat → Action → Bool
  | .contractIn cs, .invoke contract _ _ => decide (contract ∈ cs)
  | .functionIn fs, .invoke _ function _ => decide (function ∈ fs)
  | .argI128AtMost i n, .invoke _ _ args =>
    match args[i]? with
    | some (.i128 v) => decide (v.toInt ≤ n.toInt)
    | _ => false
  | .argEq i val, .invoke _ _ args => decide (args[i]? = some val)
  | _, .createContract _ => false

/-- The grant whose caveats are the denotations of `cs`. -/
def grant (cs : List Caveat) : Grant Action :=
  { caveats := cs.map Caveat.holds }

/-! ## Each caveat's meaning -/

theorem contractIn_iff (cs : List Bytes) (contract function : Bytes) (args : List Val) :
    (Caveat.contractIn cs).holds (.invoke contract function args) = true ↔ contract ∈ cs := by
  simp [Caveat.holds]

theorem functionIn_iff (fs : List Bytes) (contract function : Bytes) (args : List Val) :
    (Caveat.functionIn fs).holds (.invoke contract function args) = true ↔ function ∈ fs := by
  simp [Caveat.holds]

theorem argI128AtMost_iff (i : Nat) (n : I128) (contract function : Bytes) (args : List Val) :
    (Caveat.argI128AtMost i n).holds (.invoke contract function args) = true ↔
      ∃ v, args[i]? = some (.i128 v) ∧ v.toInt ≤ n.toInt := by
  simp only [Caveat.holds]
  split <;> simp_all

theorem argEq_iff (i : Nat) (val : Val) (contract function : Bytes) (args : List Val) :
    (Caveat.argEq i val).holds (.invoke contract function args) = true ↔ args[i]? = some val := by
  simp [Caveat.holds]

/-! ## Contract deployment -/

@[simp] theorem holds_createContract (c : Caveat) (wasmHash : Bytes) :
    c.holds (.createContract wasmHash) = false := by
  cases c <;> rfl

/-- A chain grant with any caveat denies every contract deployment. -/
theorem restricted_denies_createContract {cs : List Caveat} (h : cs ≠ []) (wasmHash : Bytes) :
    (grant cs).allows (.createContract wasmHash) = false := by
  obtain ⟨c, cs', rfl⟩ := List.exists_cons_of_ne_nil h
  simp [grant, Grant.allows]

end AttenuatingGrants.Chain
