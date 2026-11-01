import AttenuatingGrants.Bytes
import AttenuatingGrants.Grant

/-!
# Files vocabulary

A path is a list of components, each a byte string, so `pathUnder` compares
whole components: `["home", "a"]` is not a prefix of `["home", "ab"]`
(`home_a_not_under_home_ab`). Resolving `..`, symlinks and case-insensitive
file systems into a canonical component list is host wiring.
-/

namespace AttenuatingGrants.Files

abbrev Path := List Bytes

inductive Mode where
  | read
  | write
  | execute
  deriving DecidableEq

structure Action where
  path : Path
  mode : Mode
  deriving DecidableEq

inductive Caveat where
  /-- The path lies under `pathPrefix`, component by component. -/
  | pathUnder (pathPrefix : Path)
  /-- The access mode is one of these. Read-only is `modeIn [.read]`. -/
  | modeIn (modes : List Mode)
  deriving DecidableEq

/-- `isPrefix p q`: `p` is a component-wise prefix of `q`. -/
def isPrefix : Path → Path → Bool
  | [], _ => true
  | _ :: _, [] => false
  | c :: p, d :: q => decide (c = d) && isPrefix p q

def Caveat.holds : Caveat → Action → Bool
  | .pathUnder pathPrefix, a => isPrefix pathPrefix a.path
  | .modeIn modes, a => decide (a.mode ∈ modes)

def grant (cs : List Caveat) : Grant Action :=
  { caveats := cs.map Caveat.holds }

/-! ## Each caveat's meaning -/

theorem isPrefix_iff (p q : Path) : isPrefix p q = true ↔ p <+: q := by
  induction p generalizing q with
  | nil => simp [isPrefix]
  | cons c p ih =>
    cases q with
    | nil => simp [isPrefix]
    | cons d q => simp [isPrefix, ih, List.cons_prefix_cons]

theorem pathUnder_iff (pathPrefix : Path) (a : Action) :
    (Caveat.pathUnder pathPrefix).holds a = true ↔ pathPrefix <+: a.path :=
  isPrefix_iff _ _

theorem modeIn_iff (modes : List Mode) (a : Action) :
    (Caveat.modeIn modes).holds a = true ↔ a.mode ∈ modes := by
  simp [Caveat.holds]

/-- A read-only grant allows no write. -/
theorem readOnly_denies_write (path : Path) :
    (Caveat.modeIn [.read]).holds { path, mode := .write } = false := rfl

/-! ## Component-wise prefixes -/

theorem home_a_not_prefix_home_ab :
    ¬ ([Bytes.ofString "home", Bytes.ofString "a"] <+:
      [Bytes.ofString "home", Bytes.ofString "ab"]) := by
  rw [← isPrefix_iff]
  decide +kernel

theorem home_a_not_under_home_ab (mode : Mode) :
    (Caveat.pathUnder [Bytes.ofString "home", Bytes.ofString "a"]).holds
      { path := [Bytes.ofString "home", Bytes.ofString "ab"], mode } = false :=
  Bool.eq_false_iff.mpr fun h => home_a_not_prefix_home_ab ((pathUnder_iff _ _).mp h)

end AttenuatingGrants.Files
