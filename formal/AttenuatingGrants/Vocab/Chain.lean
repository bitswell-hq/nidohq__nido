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

Every argument is one `Val`, and values of different constructors are never
equal, so an argument of one type never satisfies an `argEq` written for
another (`argEq_kind`). An argument type the vocabulary does not model
(`u32`, `i64`, `string`, `vec`, `map`, …) is `other` of its full `ScVal`
XDR, discriminant included: it keeps its position in the argument list, an
`argEq` can still pin it exactly, and it never equals a `bytes` value with
the same encoding.
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
  /-- An argument of a type the other constructors do not model, as its full
  `ScVal` XDR. -/
  | other (xdr : Bytes)
  deriving DecidableEq

/-- A value's constructor, without its payload. -/
inductive Kind where
  | i128 | u64 | bool | bytes | address | symbol | other
  deriving DecidableEq

def Val.kind : Val → Kind
  | .i128 _ => .i128
  | .u64 _ => .u64
  | .bool _ => .bool
  | .bytes _ => .bytes
  | .address _ => .address
  | .symbol _ => .symbol
  | .other _ => .other

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

/-! ## Argument types -/

/-- `argEq i val` holds only for an argument with `val`'s constructor. -/
theorem argEq_kind {i : Nat} {val : Val} {contract function : Bytes} {args : List Val}
    (h : (Caveat.argEq i val).holds (.invoke contract function args) = true) :
    ∃ w, args[i]? = some w ∧ w.kind = val.kind := by
  rw [argEq_iff] at h
  exact ⟨val, h, rfl⟩

/-- An argument of another constructor fails `argEq`, whatever its payload. -/
theorem argEq_false_of_kind_ne {i : Nat} {val w : Val} {contract function : Bytes}
    {args : List Val} (hw : args[i]? = some w) (hk : w.kind ≠ val.kind) :
    (Caveat.argEq i val).holds (.invoke contract function args) = false := by
  cases h : (Caveat.argEq i val).holds (.invoke contract function args)
  · rfl
  · obtain ⟨w', hw', hk'⟩ := argEq_kind h
    rw [hw] at hw'
    cases hw'
    exact absurd hk' hk

/-- An unmodeled argument never satisfies a `bytes` caveat, even when its XDR
is exactly the caveat's bytes. -/
theorem argEq_bytes_false_of_other {i : Nat} {b xdr : Bytes} {contract function : Bytes}
    {args : List Val} (hw : args[i]? = some (.other xdr)) :
    (Caveat.argEq i (.bytes b)).holds (.invoke contract function args) = false :=
  argEq_false_of_kind_ne hw (by simp [Val.kind])

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
