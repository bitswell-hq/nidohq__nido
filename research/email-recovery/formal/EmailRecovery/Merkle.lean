import EmailRecovery.Basic

/-!
# Key trees

The depth-16 Merkle trees of spec §7.2 (the registry) and §7.4 (the pin):
interior nodes are untagged `P2(left, right)`, empty leaves are `0`, and a
membership path climbs from a leaf, bit `i` of the leaf index saying whether
the node at level `i` is a right child.

`path_binds` is the binding property the soundness corollaries use: a path
from `leaf` at index `i` that reaches a tree's root shows that the tree holds
`leaf` at `i`, unless Poseidon2 collides.
-/

namespace EmailRecovery

variable (H : Hashes)

/-- The registry and pin tree depth (`REGISTRY_DEPTH`). -/
def treeDepth : Nat := 16

/-- One level up: node `i` hashes nodes `2i` and `2i + 1` of the level below. -/
def levelUp (f : Nat → Nat) : Nat → Nat := fun i => H.p2 [f (2 * i), f (2 * i + 1)]

/-- The level `n` steps above the leaves `f`. -/
def levels : Nat → (Nat → Nat) → (Nat → Nat)
  | 0, f => f
  | n + 1, f => levels n (levelUp H f)

/-- The root of the depth-`n` tree whose leaf at position `i < 2 ^ n` is `f i`. -/
def treeRoot (n : Nat) (f : Nat → Nat) : Nat := levels H n f 0

/-- The root a membership path computes from `cur` at `index` with the given
siblings, lowest level first. -/
def pathRoot : Nat → Nat → List Nat → Nat
  | cur, _, [] => cur
  | cur, index, s :: ss =>
      pathRoot (if index % 2 = 1 then H.p2 [s, cur] else H.p2 [cur, s]) (index / 2) ss

variable {H}

theorem levels_succ (n : Nat) (f : Nat → Nat) :
    levels H (n + 1) f = levels H n (levelUp H f) := rfl

/-- A path that reaches the node above position `index` shows that position
holds `cur`, unless Poseidon2 collides. -/
theorem path_binds_levels :
    ∀ (sibs : List Nat) (f : Nat → Nat) (cur index : Nat),
      pathRoot H cur index sibs = levels H sibs.length f (index / 2 ^ sibs.length) →
      f index = cur ∨ H.P2Collision := by
  intro sibs
  induction sibs with
  | nil =>
    intro f cur index h
    simp only [pathRoot, List.length_nil, Nat.pow_zero, Nat.div_one, levels] at h
    exact Or.inl h.symm
  | cons s ss ih =>
    intro f cur index h
    simp only [pathRoot, List.length_cons, levels_succ] at h
    have hdiv : index / 2 ^ (ss.length + 1) = index / 2 / 2 ^ ss.length := by
      rw [Nat.div_div_eq_div_mul, Nat.pow_succ, Nat.mul_comm]
    rw [hdiv] at h
    rcases ih (levelUp H f) _ (index / 2) h with h | h
    · have hidx := Nat.div_add_mod index 2
      simp only [levelUp] at h
      by_cases hodd : index % 2 = 1
      · simp only [hodd, ite_true] at h
        rcases H.p2_eq h with h | h
        · simp only [List.cons.injEq, and_true] at h
          rw [hodd] at hidx
          rw [← hidx]
          exact Or.inl h.2
        · exact Or.inr h
      · simp only [hodd, ite_false] at h
        rcases H.p2_eq h with h | h
        · simp only [List.cons.injEq, and_true] at h
          have hev : index % 2 = 0 := by omega
          rw [hev, Nat.add_zero] at hidx
          rw [← hidx]
          exact Or.inl h.1
        · exact Or.inr h
    · exact Or.inr h

/-- A path of `treeDepth` siblings from `cur` at `index < 2 ^ treeDepth` that
reaches the root of the tree over `f` shows `f index = cur`, unless Poseidon2
collides. -/
theorem path_binds {f : Nat → Nat} {cur index : Nat} {sibs : List Nat}
    (hlen : sibs.length = treeDepth) (hidx : index < 2 ^ treeDepth)
    (h : pathRoot H cur index sibs = treeRoot H treeDepth f) :
    f index = cur ∨ H.P2Collision := by
  apply path_binds_levels sibs f cur index
  rw [hlen, Nat.div_eq_of_lt hidx]
  exact h

end EmailRecovery
