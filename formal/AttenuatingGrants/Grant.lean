/-!
# Grants

A grant is a list of caveats over an action type `α`. An action is allowed
exactly when every caveat holds for it, so the empty grant allows every action
and each added caveat can only remove actions.

A grant holder narrows its authority by attenuation: it adds a caveat and hands
the narrower copy to a sub-agent. Issuing, revoking and key rotation live in a
separate admin document that agents never hold, so attenuation is the only way
an agent derives a grant.

Theorems:

* `attenuate_narrows`: adding a caveat yields a grant narrower than its parent.
* `attenuateAll_narrows`: so does adding a list of caveats.
* `narrower_refl`, `narrower_trans`: `narrower` is a preorder.
* `Delegates.narrower`: every grant reachable from a root by delegation is
  narrower than the root.
* `allowsAll_of_narrower`: a narrower grant allows a batch of actions (every
  context of a Soroban authorization tree) only if its ancestor does.
-/

namespace AttenuatingGrants

variable {α : Type}

structure Grant (α : Type) where
  caveats : List (α → Bool)

def Grant.allows (g : Grant α) (a : α) : Bool :=
  g.caveats.all (· a)

/-- `g.narrower h`: every action `g` allows, `h` allows too. -/
def Grant.narrower (g h : Grant α) : Prop :=
  ∀ a, g.allows a = true → h.allows a = true

def Grant.attenuate (g : Grant α) (c : α → Bool) : Grant α :=
  { caveats := c :: g.caveats }

/-- Attenuation by several caveats at once. -/
def Grant.attenuateAll (g : Grant α) (cs : List (α → Bool)) : Grant α :=
  { caveats := cs ++ g.caveats }

/-- `g` allows every action in the batch. A Soroban authorization tree is
checked by collecting every context in it and requiring all of them. -/
def Grant.allowsAll (g : Grant α) (actions : List α) : Bool :=
  actions.all g.allows

/-! ## Evaluation -/

theorem Grant.allows_iff (g : Grant α) (a : α) :
    g.allows a = true ↔ ∀ c ∈ g.caveats, c a = true := by
  simp [Grant.allows]

/-- The empty grant allows every action. -/
@[simp] theorem Grant.allows_nil (a : α) : (Grant.mk []).allows a = true := rfl

@[simp] theorem Grant.allows_attenuate (g : Grant α) (c : α → Bool) (a : α) :
    (g.attenuate c).allows a = (c a && g.allows a) := rfl

@[simp] theorem Grant.allows_attenuateAll (g : Grant α) (cs : List (α → Bool)) (a : α) :
    (g.attenuateAll cs).allows a = (cs.all (· a) && g.allows a) := by
  simp [Grant.attenuateAll, Grant.allows, List.all_append]

theorem Grant.allowsAll_iff (g : Grant α) (actions : List α) :
    g.allowsAll actions = true ↔ ∀ a ∈ actions, g.allows a = true := by
  simp [Grant.allowsAll]

/-! ## Attenuation (theorem 2) -/

theorem attenuate_narrows (g : Grant α) (c : α → Bool) :
    (g.attenuate c).narrower g := by
  intro a h
  simp [Grant.attenuate, Grant.allows] at h ⊢
  exact h.2

theorem attenuateAll_narrows (g : Grant α) (cs : List (α → Bool)) :
    (g.attenuateAll cs).narrower g := by
  intro a h
  simp only [Grant.allows_attenuateAll, Bool.and_eq_true] at h
  exact h.2

theorem narrower_refl (g : Grant α) : g.narrower g :=
  fun _ ha => ha

/-! ## Chaining (theorem 3) -/

theorem narrower_trans {g h k : Grant α} :
    g.narrower h → h.narrower k → g.narrower k :=
  fun gh hk a ha => hk a (gh a ha)

/-- `Delegates root g`: `g` is reachable from `root` by zero or more
attenuation steps, each one a sub-agent adding a caveat to the grant it was
handed. -/
inductive Delegates (root : Grant α) : Grant α → Prop where
  | refl : Delegates root root
  | step {g : Grant α} (c : α → Bool) : Delegates root g → Delegates root (g.attenuate c)

/-- Every grant in a delegation chain stays inside the root grant. -/
theorem Delegates.narrower {root g : Grant α} (h : Delegates root g) : g.narrower root := by
  induction h with
  | refl => exact narrower_refl root
  | step c _ ih => exact narrower_trans (attenuate_narrows _ c) ih

/-- The grant at the end of a delegation chain whose steps add `cs` in order. -/
def Grant.delegate (root : Grant α) (cs : List (α → Bool)) : Grant α :=
  cs.foldl Grant.attenuate root

theorem Grant.delegate_delegates (root : Grant α) (cs : List (α → Bool)) :
    Delegates root (root.delegate cs) := by
  suffices ∀ g, Delegates root g → Delegates root (cs.foldl Grant.attenuate g) from
    this root .refl
  induction cs with
  | nil => exact fun _ h => h
  | cons c cs ih => exact fun g h => ih _ (.step c h)

theorem delegate_narrows (root : Grant α) (cs : List (α → Bool)) :
    (root.delegate cs).narrower root :=
  (root.delegate_delegates cs).narrower

/-- A narrower grant allows a batch of actions only if its ancestor does, so
checking every context of an authorization tree against a delegated grant
never accepts a tree the root grant would reject. -/
theorem allowsAll_of_narrower {g h : Grant α} (gh : g.narrower h) (actions : List α) :
    g.allowsAll actions = true → h.allowsAll actions = true := by
  simp only [Grant.allowsAll_iff]
  exact fun hg a ha => gh a (hg a ha)

end AttenuatingGrants
