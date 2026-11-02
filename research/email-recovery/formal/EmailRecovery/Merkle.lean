import EmailRecovery.Basic

/-!
# Key trees

The depth-16 Merkle trees of spec §7.2 (the registry) and §7.4 (the pin):
interior nodes are untagged `P2(left, right)`, empty leaves are `0`, and a
membership path climbs from a leaf, bit `i` of the leaf index saying whether
the node at level `i` is a right child.

`path_binds` is the binding property the soundness corollaries use: a path
from `leaf` at index `i` that reaches a tree's root shows that the tree holds
`leaf` at `i`, unless the two pairs `pathBreak` computes from the tree and the
path are a Poseidon2 collision.
-/

namespace EmailRecovery

variable (H : Hashes)

/-- The registry and pin tree depth (`REGISTRY_DEPTH`). -/
def treeDepth : Nat := 16

/-- The pair node `i` of the level above `f` hashes: nodes `2i` and `2i + 1`. -/
def levelPair (f : Nat → Nat) (i : Nat) : List Nat := [f (2 * i), f (2 * i + 1)]

/-- One level up. -/
def levelUp (f : Nat → Nat) : Nat → Nat := fun i => H.p2 (levelPair f i)

/-- The level `n` steps above the leaves `f`. -/
def levels : Nat → (Nat → Nat) → (Nat → Nat)
  | 0, f => f
  | n + 1, f => levels n (levelUp H f)

/-- The root of the depth-`n` tree whose leaf at position `i < 2 ^ n` is `f i`. -/
def treeRoot (n : Nat) (f : Nat → Nat) : Nat := levels H n f 0

/-- The pair a path hashes at one level: `cur` and its sibling `s`, the sibling
on the left when `index` is odd. -/
def pathPair (cur index s : Nat) : List Nat := if index % 2 = 1 then [s, cur] else [cur, s]

/-- The root a membership path computes from `cur` at `index` with the given
siblings, lowest level first. -/
def pathRoot : Nat → Nat → List Nat → Nat
  | cur, _, [] => cur
  | cur, index, s :: ss => pathRoot (H.p2 (pathPair cur index s)) (index / 2) ss

/-- The Poseidon2 inputs on which a path that reaches the tree's node without
`f index = cur` collides: at the lowest node the path computes that equals the
tree's node at its position, the tree's pair of children and the path's. -/
def pathBreak (f : Nat → Nat) : Nat → Nat → List Nat → List Nat × List Nat
  | _, _, [] => ([], [])
  | cur, index, s :: ss =>
    if levelUp H f (index / 2) = H.p2 (pathPair cur index s) then
      (levelPair f (index / 2), pathPair cur index s)
    else pathBreak (levelUp H f) (H.p2 (pathPair cur index s)) (index / 2) ss

variable {H}

theorem levels_succ (n : Nat) (f : Nat → Nat) :
    levels H (n + 1) f = levels H n (levelUp H f) := rfl

/-- Equal pairs at one level put `cur` at `index`. -/
theorem levelPair_eq {f : Nat → Nat} {cur index s : Nat}
    (h : levelPair f (index / 2) = pathPair cur index s) : f index = cur := by
  have hidx := Nat.div_add_mod index 2
  unfold levelPair pathPair at h
  by_cases hodd : index % 2 = 1
  · simp only [hodd, ite_true, List.cons.injEq, and_true] at h
    rw [hodd] at hidx
    rw [← hidx]
    exact h.2
  · simp only [hodd, ite_false, List.cons.injEq, and_true] at h
    have hev : index % 2 = 0 := by omega
    rw [hev, Nat.add_zero] at hidx
    rw [← hidx]
    exact h.1

/-- A path that reaches the node above position `index` shows that position
holds `cur`, unless the pairs `pathBreak` names collide. -/
theorem path_binds_levels :
    ∀ (sibs : List Nat) (f : Nat → Nat) (cur index : Nat),
      pathRoot H cur index sibs = levels H sibs.length f (index / 2 ^ sibs.length) →
      f index = cur ∨ H.P2Collides (pathBreak H f cur index sibs) := by
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
    have hup := ih (levelUp H f) _ (index / 2) h
    simp only [pathBreak]
    by_cases heq : levelUp H f (index / 2) = H.p2 (pathPair cur index s)
    · rw [ite_eq_left heq]
      by_cases hpair : levelPair f (index / 2) = pathPair cur index s
      · exact Or.inl (levelPair_eq hpair)
      · exact Or.inr ⟨hpair, heq⟩
    · rw [ite_eq_right heq]
      rcases hup with hup | hup
      · exact absurd hup heq
      · exact Or.inr hup

/-- A path of `treeDepth` siblings from `cur` at `index < 2 ^ treeDepth` that
reaches the root of the tree over `f` shows `f index = cur`, unless the pairs
`pathBreak` computes from `f` and the path are a Poseidon2 collision. -/
theorem path_binds {f : Nat → Nat} {cur index : Nat} {sibs : List Nat}
    (hlen : sibs.length = treeDepth) (hidx : index < 2 ^ treeDepth)
    (h : pathRoot H cur index sibs = treeRoot H treeDepth f) :
    f index = cur ∨ H.P2Collides (pathBreak H f cur index sibs) := by
  apply path_binds_levels sibs f cur index
  rw [hlen, Nat.div_eq_of_lt hidx]
  exact h

end EmailRecovery
