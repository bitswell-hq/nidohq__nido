import AttenuatingGrants.Budget

/-!
# The grant signer's budget path

`contracts/grant-signer` stores one grant per id. A grant's `parent`,
`allowance` and `spent` are its node of one budget ledger indexed by grant id:
`issue` and `delegate` store a new grant at the next id with nothing spent, as
`Ledger.append` adds a node (`delegate` first loads the parent, so it fails
for a parent that does not exist). The contract never holds that ledger
whole:

* `refill` runs `rule_eval::refill` on a ledger of the one grant and stores the
  new allowance (`refillGrant`).
* An authorization loads the signing grant's lineage, the grant and its
  ancestors, root first (`IsLineage`); builds the lineage's own ledger, whose
  node `k` has parent `k - 1` (`chain`); calls `rule_eval::spend` on it at the
  last node once per metered transfer, stopping at the first failure
  (`spendAll`); and only if every spend succeeded stores each node's `spent`
  into its grant (`writeBack`).

The definitions here follow those steps of the contract. The theorems show
that the lineage ledger computes what the whole ledger computes, restricted
to the lineage, so the whole ledger's budget safety (theorem 4) holds for the
contract:

* `chargePath_lineage`, `spend_lineage`: on a ledger whose parents precede
  their children, a check or spend on the lineage ledger has the outcome of
  the same check or spend at the signing grant on the whole ledger, with node
  `k` standing for the lineage's `k`th grant (`gid`, `renameError`); the
  lineage ledger after it is the lineage of the whole ledger after it.
* `spendAll_lineage`: the same for the batch of one authorization.
* `writeBack_spendAll`: storing the batch's lineage ledger turns the whole
  ledger into the ledger after the batch.
* `spendAll_run`: a batch that succeeds is a `Ledger.run` of its spends.
* `refillGrant_eq`: the contract's refill is `Ledger.refill`.
* `Signer.Run.exists_run`, `Signer.spentUnder_le_allowance`: every sequence of
  the contract's calls changes the ledger as some `Ledger.run` does, so from
  no grants the total successfully spent at or under any grant never exceeds
  its allowance.

An authorization's batch is all or nothing: on any failure the contract
returns before writing. A refused authorization fails the call that asked for
it, which a caller can catch and survive; Soroban rolls back that call's
storage writes. The contract writes a successful batch in the `require_auth`
of the authorization's root, inside the call enclosing every call it allows,
so if that call fails, caught or not, the batch is rolled back with it.
Either every spend is stored or none is (`Signer.Step.refused`). That host
behaviour is a premise, tested by
`a_caught_refusal_or_failure_leaves_the_budget_as_if_the_call_never_ran`.
-/

namespace AttenuatingGrants.Budget

/-- An empty node, read where an index has no node. -/
def Node.empty : Node := ⟨none, 0, 0⟩

/-- The grant id of node `k` of the lineage ledger of `ps`. -/
def gid (ps : List (Nat × Node)) (k : Nat) : Nat :=
  (ps[k]?.map (·.1)).getD k

/-- A lineage ledger's error as the whole ledger's: node `k` is grant
`gid ps k`. The contract's `overdrawn_at` maps `Overdrawn(k)` so. -/
def renameError (ps : List (Nat × Node)) : SpendError → SpendError
  | .noSuchNode k => .noSuchNode (gid ps k)
  | .badParent k => .badParent (gid ps k)
  | .overdrawn k => .overdrawn (gid ps k)

namespace Ledger

/-- `ps` is a lineage of `l`, root first, as the contract's `lineage` returns
one: each entry is a node of `l` with its index, the first entry's node is a
root, and each later entry's node is the child of the entry before it. -/
structure IsLineage (l : Ledger) (ps : List (Nat × Node)) : Prop where
  ne_nil : ps ≠ []
  get : ∀ e ∈ ps, l[e.1]? = some e.2
  root : ∀ e, ps[0]? = some e → e.2.parent = none
  step : ∀ k d e, ps[k]? = some d → ps[k + 1]? = some e → e.2.parent = some d.1

/-- The ledger of a lineage, as the contract's `ledger` builds it: one node
per entry, root first, each node's parent the one before it. -/
def chain (ps : List (Nat × Node)) : Ledger :=
  ps.mapIdx fun k e => ⟨if k = 0 then none else some (k - 1), e.2.allowance, e.2.spent⟩

/-- The entries of `ps` with their nodes read again from `l`. -/
def reread (l : Ledger) (ps : List (Nat × Node)) : List (Nat × Node) :=
  ps.map fun e => (e.1, l[e.1]?.getD Node.empty)

/-- Spend each amount at `i` in order, stopping at the first failure: the
ledger after them all, or `none` if one failed. The contract's spends of one
authorization's metered transfers. -/
def spendAll (l : Ledger) (i : Nat) : List Nat → Option Ledger
  | [] => some l
  | x :: xs =>
    match l.spend i x with
    | (.ok (), l') => l'.spendAll i xs
    | (.error _, _) => none

/-- Store the lineage ledger `c` of `ps` into `l`, as the contract does after
an authorization's spends: entry `k`'s grant gets node `k`'s `spent`, keeping
the rest of the record it was loaded with, and is written only if that
changed it. -/
def writeBack (l : Ledger) (ps : List (Nat × Node)) (c : Ledger) : Ledger :=
  (ps.zip c).foldl
    (fun l q => if q.2.spent ≠ q.1.2.spent then l.set q.1.1 { q.1.2 with spent := q.2.spent }
      else l)
    l

/-- `refill` as the contract does it: `rule_eval::refill` on a ledger holding
only the grant's node, then the grant stored with the new allowance. -/
def refillGrant (l : Ledger) (i extra : Nat) : Ledger :=
  match l[i]? with
  | none => l
  | some n =>
    match Ledger.refill [⟨none, n.allowance, n.spent⟩] 0 extra with
    | (.ok (), c) => l.set i { n with allowance := (c[0]?.map (·.allowance)).getD n.allowance }
    | (.error _, _) => l

/-! ## The walk on a lineage -/

/-- Any fuel past the start index gives the same walk: each step moves to an
earlier node. -/
theorem walk_fuel {l : Ledger} {amount : Nat} :
    ∀ {f g i : Nat}, i < f → i < g → l.walk amount f i = l.walk amount g i
  | 0, _, _, h, _ => absurd h (Nat.not_lt_zero _)
  | _ + 1, 0, _, _, h => absurd h (Nat.not_lt_zero _)
  | f + 1, g + 1, i, hf, hg => by
    simp only [walk]
    cases l[i]? with
    | none => rfl
    | some n =>
      simp only
      split
      · rfl
      · cases n.parent with
        | none => rfl
        | some p =>
          simp only
          split
          · rename_i hp
            rw [walk_fuel (f := f) (g := g) (by omega) (by omega)]
          · rfl

theorem getElem?_chain (ps : List (Nat × Node)) (k : Nat) :
    (chain ps)[k]? =
      ps[k]?.map fun e => ⟨if k = 0 then none else some (k - 1), e.2.allowance, e.2.spent⟩ := by
  simp [chain, List.getElem?_mapIdx]

theorem length_chain (ps : List (Nat × Node)) : (chain ps).length = ps.length := by
  simp [chain]

theorem lt_of_isLineage {l : Ledger} {ps : List (Nat × Node)} (hl : l.IsLineage ps)
    {e : Nat × Node} (he : e ∈ ps) : e.1 < l.length :=
  lt_length_of_getElem? (hl.get e he)

theorem parentOf_of_get {l : Ledger} {i : Nat} {n : Node} (h : l[i]? = some n) :
    l.parentOf i = n.parent := by
  simp [parentOf, h]

/-- The walk from entry `k` of a lineage is the walk from node `k` of the
lineage ledger, with node `j` standing for grant `gid ps j`. -/
theorem walk_lineage {l : Ledger} (hpf : l.ParentsFirst) {ps : List (Nat × Node)}
    (hl : l.IsLineage ps) (amount : Nat) :
    ∀ (k : Nat) (e : Nat × Node), ps[k]? = some e →
      l.walk amount (e.1 + 1) e.1 =
        (((chain ps).walk amount (k + 1) k).map (·.map (gid ps))).mapError (renameError ps) := by
  intro k
  induction k with
  | zero =>
    intro e he
    have hget := hl.get e (List.mem_of_getElem? he)
    have hroot := hl.root e he
    have hgid : gid ps 0 = e.1 := by simp [gid, he]
    simp only [walk, hget, getElem?_chain, he, Option.map_some, ↓reduceIte]
    split
    · simp [Except.map, Except.mapError, renameError, hgid]
    · simp [hroot, Except.map, Except.mapError, hgid]
  | succ k ih =>
    intro e he
    have hlt : k < ps.length := by
      have := (List.getElem?_eq_some_iff.mp he).1
      omega
    obtain ⟨d, hd⟩ : ∃ d, ps[k]? = some d := ⟨ps[k], List.getElem?_eq_getElem hlt⟩
    have hget := hl.get e (List.mem_of_getElem? he)
    have hpar := hl.step k d e hd he
    have hdi : d.1 < e.1 := hpf e.1 d.1 (by rw [parentOf_of_get hget, hpar])
    have hgid : gid ps (k + 1) = e.1 := by simp [gid, he]
    have hw : l.walk amount e.1 d.1 = l.walk amount (d.1 + 1) d.1 :=
      walk_fuel hdi (Nat.lt_succ_self _)
    rw [walk.eq_2 l amount e.1 e.1, walk.eq_2 (chain ps) amount (k + 1) (k + 1)]
    simp only [hget, getElem?_chain, he, Option.map_some, Nat.add_one_ne_zero,
      ↓reduceIte, hpar, Nat.add_sub_cancel]
    split
    · simp [Except.map, Except.mapError, renameError, hgid]
    · simp only [↓reduceIte, Nat.lt_succ_self, hw, ih d hd]
      cases (chain ps).walk amount (k + 1) k <;> simp [Except.map, Except.mapError, hgid]

/-- A check on the lineage ledger is the check at the signing grant on the
whole ledger, with node `k` standing for grant `gid ps k`. -/
theorem chargePath_lineage {l : Ledger} (hpf : l.ParentsFirst) {ps : List (Nat × Node)}
    (hl : l.IsLineage ps) {e : Nat × Node} (hlast : ps.getLast? = some e) (amount : Nat) :
    l.chargePath e.1 amount =
      (((chain ps).chargePath (ps.length - 1) amount).map (·.map (gid ps))).mapError
        (renameError ps) := by
  have hne : ps.length ≠ 0 := by simpa using hl.ne_nil
  rw [List.getLast?_eq_getElem?] at hlast
  have hmem := List.mem_of_getElem? hlast
  unfold chargePath
  rw [walk_fuel (g := e.1 + 1) (lt_of_isLineage hl hmem) (Nat.lt_succ_self _),
    walk_lineage hpf hl amount _ e hlast, length_chain, Nat.sub_add_cancel (by omega)]

/-! ## Which nodes a spend charges -/

theorem within_congr {l l' : Ledger} (h : l.parentOf = l'.parentOf) {i a : Nat} :
    l.Within i a ↔ l'.Within i a := by
  constructor
  · intro w
    induction w with
    | self => exact .self _
    | up hp _ ih => exact .up (h ▸ hp) ih
  · intro w
    induction w with
    | self => exact .self _
    | up hp _ ih => exact .up (h.symm ▸ hp) ih

/-- The nodes at or above entry `k` of a lineage are the entries up to `k`. -/
theorem within_lineage_at {l : Ledger} {ps : List (Nat × Node)} (hl : l.IsLineage ps) :
    ∀ (k : Nat) (e : Nat × Node), ps[k]? = some e →
      ∀ a, l.Within e.1 a ↔ a ∈ (ps.take (k + 1)).map Prod.fst := by
  intro k
  induction k with
  | zero =>
    intro e he a
    have hget := hl.get e (List.mem_of_getElem? he)
    rw [within_root (by rw [parentOf_of_get hget, hl.root e he])]
    have : ps.take 1 = [e] := by
      cases ps with
      | nil => simp at he
      | cons p rest => simp at he; simp [he]
    simp [this]
  | succ k ih =>
    intro e he a
    have hlt : k < ps.length := by
      have := (List.getElem?_eq_some_iff.mp he).1
      omega
    obtain ⟨d, hd⟩ : ∃ d, ps[k]? = some d := ⟨ps[k], List.getElem?_eq_getElem hlt⟩
    have hget := hl.get e (List.mem_of_getElem? he)
    have htake : ps.take (k + 1 + 1) = ps.take (k + 1) ++ [e] := by
      rw [List.take_add_one, he]; rfl
    rw [within_step (by rw [parentOf_of_get hget, hl.step k d e hd he]), ih d hd a, htake]
    simp [or_comm]

/-- The nodes at or above the signing grant are its lineage's. -/
theorem within_lineage {l : Ledger} {ps : List (Nat × Node)} (hl : l.IsLineage ps)
    {e : Nat × Node} (hlast : ps.getLast? = some e) (a : Nat) :
    l.Within e.1 a ↔ a ∈ ps.map Prod.fst := by
  have hne : ps.length ≠ 0 := by simpa using hl.ne_nil
  rw [List.getLast?_eq_getElem?] at hlast
  rw [within_lineage_at hl _ e hlast, Nat.sub_add_cancel (by omega), List.take_length]

/-- Every node of a lineage ledger is at or above its last. -/
theorem within_chain (ps : List (Nat × Node)) :
    ∀ k j, k < ps.length → j ≤ k → (chain ps).Within k j := by
  intro k
  induction k with
  | zero =>
    intro j _ hj
    rw [Nat.le_zero.mp hj]
    exact .self _
  | succ k ih =>
    intro j hk hj
    rcases Nat.lt_or_eq_of_le hj with hj | rfl
    · have hp : (chain ps).parentOf (k + 1) = some k := by
        have hlt : k + 1 < ps.length := hk
        simp [parentOf, getElem?_chain, List.getElem?_eq_getElem hlt]
      exact .up hp (ih j (by omega) (by omega))
    · exact .self _

/-! ## One spend -/

theorem spend_fst (l : Ledger) (i amount : Nat) :
    (l.spend i amount).1 = (l.chargePath i amount).map (fun _ => ()) := by
  unfold spend
  cases l.chargePath i amount <;> rfl

theorem reread_of_isLineage {l : Ledger} {ps : List (Nat × Node)} (hl : l.IsLineage ps) :
    reread l ps = ps := by
  unfold reread
  conv => rhs; rw [← List.map_id ps]
  apply List.map_congr_left
  intro e he
  rw [hl.get e he]
  rfl

theorem reread_reread (l l' : Ledger) (ps : List (Nat × Node)) :
    reread l' (reread l ps) = reread l' ps := by
  simp [reread]

theorem length_reread (l : Ledger) (ps : List (Nat × Node)) :
    (reread l ps).length = ps.length := by
  simp [reread]

theorem getLast?_reread (l : Ledger) {ps : List (Nat × Node)} {e : Nat × Node}
    (h : ps.getLast? = some e) :
    (reread l ps).getLast? = some (e.1, l[e.1]?.getD Node.empty) := by
  simp [reread, List.getLast?_map, h]

/-- A ledger with the same length and parent links has the same lineages,
read again. -/
theorem isLineage_reread {l l' : Ledger} {ps : List (Nat × Node)} (hl : l.IsLineage ps)
    (hlen : l'.length = l.length) (hpar : l'.parentOf = l.parentOf) :
    l'.IsLineage (reread l' ps) := by
  have get' : ∀ e ∈ ps, l'[e.1]? = some (l'[e.1]?.getD Node.empty) := by
    intro e he
    have := lt_of_isLineage hl he
    rw [List.getElem?_eq_getElem (by omega)]
    rfl
  have par' : ∀ e ∈ ps, (l'[e.1]?.getD Node.empty).parent = e.2.parent := by
    intro e he
    have h1 := parentOf_of_get (get' e he)
    have h2 := parentOf_of_get (hl.get e he)
    rw [hpar] at h1
    rw [← h1, h2]
  refine ⟨by simpa [reread] using hl.ne_nil, ?_, ?_, ?_⟩
  · intro e he
    obtain ⟨f, hf, rfl⟩ := List.mem_map.mp he
    exact get' f hf
  · intro e he
    simp only [reread, List.getElem?_map] at he
    obtain ⟨f, hf, rfl⟩ := Option.map_eq_some_iff.mp he
    rw [par' f (List.mem_of_getElem? hf)]
    exact hl.root f hf
  · intro k d e hd he
    simp only [reread, List.getElem?_map] at hd he
    obtain ⟨f, hf, rfl⟩ := Option.map_eq_some_iff.mp hd
    obtain ⟨g, hg, rfl⟩ := Option.map_eq_some_iff.mp he
    rw [par' g (List.mem_of_getElem? hg)]
    exact hl.step k f g hf hg

theorem mapError_map_unit (e : Except SpendError (List Nat)) (f : Nat → Nat)
    (g : SpendError → SpendError) :
    ((e.map (·.map f)).mapError g).map (fun _ => ()) = (e.map (fun _ => ())).mapError g := by
  cases e <;> rfl

/-- A spend on the lineage ledger is the spend at the signing grant on the
whole ledger: the same outcome, with node `k` standing for grant `gid ps k`,
and the lineage ledger after it is the whole ledger's lineage after it. -/
theorem spend_lineage {l : Ledger} (hpf : l.ParentsFirst) {ps : List (Nat × Node)}
    (hl : l.IsLineage ps) {e : Nat × Node} (hlast : ps.getLast? = some e) (amount : Nat) :
    ((chain ps).spend (ps.length - 1) amount).1.mapError (renameError ps) =
        (l.spend e.1 amount).1 ∧
      ((chain ps).spend (ps.length - 1) amount).2 = chain (reread (l.spend e.1 amount).2 ps) := by
  have hc := chargePath_lineage hpf hl hlast amount
  refine ⟨?_, ?_⟩
  · rw [spend_fst, spend_fst, hc, mapError_map_unit]
  · cases hcp : (chain ps).chargePath (ps.length - 1) amount with
    | error err =>
      have hlp : l.chargePath e.1 amount = .error (renameError ps err) := by
        rw [hc, hcp]; rfl
      simp only [spend, hcp, hlp, reread_of_isLineage hl]
    | ok path =>
      have hlp : l.chargePath e.1 amount = .ok (path.map (gid ps)) := by
        rw [hc, hcp]; rfl
      have hcs : (chain ps).spend (ps.length - 1) amount =
          (.ok (), (chain ps).charge path amount) := by
        simp [spend, hcp]
      have hls : l.spend e.1 amount = (.ok (), l.charge (path.map (gid ps)) amount) := by
        simp [spend, hlp]
      rw [hcs, hls]
      dsimp only
      apply List.ext_getElem?
      intro j
      by_cases hj : j < ps.length
      · obtain ⟨f, hf⟩ : ∃ f, ps[j]? = some f := ⟨ps[j], List.getElem?_eq_getElem hj⟩
        have hw : (chain ps).Within (ps.length - 1) j := within_chain ps _ _ (by omega) (by omega)
        rw [spend_ok_charges hcs hw, getElem?_chain, getElem?_chain, hf]
        have hfw : l.Within e.1 f.1 :=
          (within_lineage hl hlast f.1).mpr (List.mem_map_of_mem (List.mem_of_getElem? hf))
        have hL := spend_ok_charges hls hfw
        rw [hl.get f (List.mem_of_getElem? hf)] at hL
        simp [reread, hf, hL]
      · have h1 : ps[j]? = none := List.getElem?_eq_none (by omega)
        have h2 : ((chain ps).charge path amount)[j]? = none := by
          rw [getElem?_charge, getElem?_chain, h1]; rfl
        rw [h2, getElem?_chain]
        simp [reread, h1]

/-! ## One authorization's spends -/

/-- The spends of one authorization on the lineage ledger are the same spends
at the signing grant on the whole ledger: both succeed or both fail, and the
lineage ledger after them is the whole ledger's lineage after them. -/
theorem spendAll_lineage {l : Ledger} (hpf : l.ParentsFirst) {ps : List (Nat × Node)}
    (hl : l.IsLineage ps) {e : Nat × Node} (hlast : ps.getLast? = some e) (xs : List Nat) :
    (chain ps).spendAll (ps.length - 1) xs =
      (l.spendAll e.1 xs).map (fun l' => chain (reread l' ps)) := by
  induction xs generalizing l ps e with
  | nil => simp [spendAll, reread_of_isLineage hl]
  | cons x xs ih =>
    obtain ⟨hout, hled⟩ := spend_lineage hpf hl hlast x
    unfold spendAll
    cases hs : l.spend e.1 x with
    | mk r l1 =>
      rw [hs] at hout hled
      cases r with
      | error err =>
        cases hc : (chain ps).spend (ps.length - 1) x with
        | mk rc c1 =>
          rw [hc] at hout
          cases rc with
          | ok u => simp [Except.mapError] at hout
          | error _ => rfl
      | ok u =>
        cases hc : (chain ps).spend (ps.length - 1) x with
        | mk rc c1 =>
          rw [hc] at hout hled
          cases rc with
          | error _ => simp [Except.mapError] at hout
          | ok u' =>
            simp only at hled ⊢
            have hlen : l1.length = l.length := by
              have := length_spend l e.1 x; rwa [hs] at this
            have hpar : l1.parentOf = l.parentOf := by
              have := parentOf_spend l e.1 x; rwa [hs] at this
            have hpf1 : l1.ParentsFirst := by
              have := spend_parentsFirst hpf e.1 x; rwa [hs] at this
            have hl1 := isLineage_reread hl hlen hpar
            have hlast1 := getLast?_reread l1 hlast
            rw [hled, ← length_reread l1 ps, ih hpf1 hl1 hlast1]
            simp [reread_reread]

/-- A batch that succeeds is a run of its spends: the ledger after it, and
every spend logged. -/
theorem spendAll_run {l l' : Ledger} {i : Nat} {xs : List Nat} (h : l.spendAll i xs = some l') :
    l.run (xs.map (Op.spend i)) = (l', xs.map (i, ·)) := by
  induction xs generalizing l with
  | nil => simp [spendAll] at h; subst h; rfl
  | cons x xs ih =>
    unfold spendAll at h
    cases hs : l.spend i x with
    | mk r l1 =>
      rw [hs] at h
      cases r with
      | error _ => simp at h
      | ok u =>
        simp only at h
        simp only [List.map_cons, run, hs, ih h]

/-- A batch that succeeds changes no node's parent link or record other than
`spent`, and no node off the spender's chain. -/
theorem spendAll_changes {l l' : Ledger} {i : Nat} {xs : List Nat} (h : l.spendAll i xs = some l') :
    l'.length = l.length ∧ l'.parentOf = l.parentOf ∧
      (∀ a : Nat, ¬ l.Within i a → l'[a]? = l[a]?) ∧
      (∀ (a : Nat) (n : Node), l[a]? = some n →
        l'[a]? = some { n with spent := (l'[a]?.getD n).spent }) := by
  induction xs generalizing l with
  | nil =>
    simp [spendAll] at h; subst h
    refine ⟨rfl, rfl, fun _ _ => rfl, fun a n hn => by simp [hn]⟩
  | cons x xs ih =>
    unfold spendAll at h
    cases hs : l.spend i x with
    | mk r l1 =>
      rw [hs] at h
      cases r with
      | error _ => simp at h
      | ok u =>
        simp only at h
        obtain ⟨hlen, hpar, hoff, hon⟩ := ih h
        have hs' : l.spend i x = (.ok (), l1) := by rw [hs]
        have hlen1 : l1.length = l.length := spend_ok_length hs'
        have hpar1 : l1.parentOf = l.parentOf := by
          have := parentOf_spend l i x; rwa [hs] at this
        refine ⟨hlen.trans hlen1, hpar.trans hpar1, ?_, ?_⟩
        · intro a ha
          rw [hoff a (fun w => ha ((within_congr hpar1).mp w)), spend_ok_unchanged hs' ha]
        · intro a n hn
          by_cases ha : l.Within i a
          · have h1 := spend_ok_charges hs' ha
            rw [hn] at h1
            have h2 := hon a _ h1
            rw [h2]
            simp
          · have h1 := spend_ok_unchanged hs' ha
            rw [hn] at h1
            exact hon a n h1

/-! ## Storing the lineage ledger -/

/-- The contract's store loop, by what it leaves: if `l'` differs from `l` only
in the `spent` of lineage entries, and `c` holds those `spent` values in
lineage order, storing `c` turns `l` into `l'`. -/
theorem writeBack_eq {l l' c : Ledger} {ps : List (Nat × Node)}
    (hget : ∀ e ∈ ps, l[e.1]? = some e.2) (hc : ps.length ≤ c.length)
    (hoff : ∀ a : Nat, a ∉ ps.map Prod.fst → l'[a]? = l[a]?)
    (hon : ∀ (k : Nat) (e : Nat × Node) (m : Node), ps[k]? = some e → c[k]? = some m →
      l'[e.1]? = some { e.2 with spent := m.spent }) :
    l.writeBack ps c = l' := by
  -- Every node is either already `l'`'s or still `l`'s and among the
  -- entries left to store.
  have key : ∀ (qs : List ((Nat × Node) × Node)) (cur : Ledger),
      (∀ q ∈ qs, l[q.1.1]? = some q.1.2 ∧ l'[q.1.1]? = some { q.1.2 with spent := q.2.spent }) →
      cur.length = l.length →
      (∀ b, cur[b]? = l'[b]? ∨ (b ∈ qs.map (·.1.1) ∧ cur[b]? = l[b]?)) →
      qs.foldl (fun l q => if q.2.spent ≠ q.1.2.spent then
          l.set q.1.1 { q.1.2 with spent := q.2.spent } else l) cur = l' := by
    intro qs
    induction qs with
    | nil =>
      intro cur _ _ hinv
      apply List.ext_getElem?
      intro b
      rcases hinv b with h | ⟨h, _⟩
      · exact h
      · simp at h
    | cons q rest ih =>
      intro cur hq hcur hinv
      obtain ⟨hql, hql'⟩ := hq q List.mem_cons_self
      have hlt : q.1.1 < cur.length := by rw [hcur]; exact lt_length_of_getElem? hql
      rw [List.foldl_cons]
      apply ih _ (fun q' h' => hq q' (List.mem_cons_of_mem _ h'))
      · split <;> simp [hcur]
      · intro b
        by_cases hb : b = q.1.1
        · subst hb
          left
          split
          · simp [hlt, hql']
          · rename_i heq
            have hsame : ({ q.1.2 with spent := q.2.spent } : Node) = q.1.2 := by
              simp only [ne_eq, Decidable.not_not] at heq
              rw [heq]
            rw [hsame] at hql'
            rcases hinv q.1.1 with h | ⟨_, h⟩
            · exact h
            · rw [h, hql, hql']
        · have hcur' : (if q.2.spent ≠ q.1.2.spent then
              cur.set q.1.1 { q.1.2 with spent := q.2.spent } else cur)[b]? = cur[b]? := by
            split
            · rw [List.getElem?_set]; simp [Ne.symm hb]
            · rfl
          rw [hcur']
          rcases hinv b with h | ⟨h, h'⟩
          · exact .inl h
          · right
            refine ⟨?_, h'⟩
            simp only [List.map_cons, List.mem_cons] at h
            rcases h with h | h
            · exact absurd h hb
            · exact h
  apply key
  · intro q hq
    obtain ⟨k, hk⟩ := List.mem_iff_getElem?.mp hq
    obtain ⟨he, hm⟩ := List.getElem?_zip_eq_some.mp hk
    exact ⟨hget _ (List.mem_of_getElem? he), hon k _ _ he hm⟩
  · rfl
  · intro b
    by_cases hb : b ∈ ps.map Prod.fst
    · right
      refine ⟨?_, rfl⟩
      obtain ⟨e, he, rfl⟩ := List.mem_map.mp hb
      obtain ⟨k, hk⟩ := List.mem_iff_getElem?.mp he
      have hkc : k < c.length := by
        have := (List.getElem?_eq_some_iff.mp hk).1; omega
      apply List.mem_map.mpr
      refine ⟨(e, c[k]), ?_, rfl⟩
      apply List.mem_iff_getElem?.mpr
      exact ⟨k, List.getElem?_zip_eq_some.mpr ⟨hk, List.getElem?_eq_getElem hkc⟩⟩
    · left
      exact (hoff b hb).symm

/-- After a batch that succeeds, the contract's store of the lineage ledger
leaves the whole ledger after the batch. -/
theorem writeBack_spendAll {l l' : Ledger} {ps : List (Nat × Node)} (hl : l.IsLineage ps)
    {e : Nat × Node} (hlast : ps.getLast? = some e) {xs : List Nat}
    (h : l.spendAll e.1 xs = some l') :
    l.writeBack ps (chain (reread l' ps)) = l' := by
  obtain ⟨hlen, -, hoff, hon⟩ := spendAll_changes h
  apply writeBack_eq hl.get (by simp [length_chain, length_reread])
  · intro a ha
    exact hoff a (fun w => ha ((within_lineage hl hlast a).mp w))
  · intro k f m hf hm
    rw [getElem?_chain, reread, List.getElem?_map, hf] at hm
    simp only [Option.map_some, Option.some.injEq] at hm
    subst hm
    rw [hon f.1 f.2 (hl.get f (List.mem_of_getElem? hf))]
    have hlt : f.1 < l'.length := by rw [hlen]; exact lt_of_isLineage hl (List.mem_of_getElem? hf)
    simp [List.getElem?_eq_getElem hlt]

/-! ## Refill -/

/-- The contract's refill is the whole ledger's. -/
theorem refillGrant_eq (l : Ledger) (i extra : Nat) :
    refillGrant l i extra = (l.refill i extra).2 := by
  unfold refillGrant refill
  cases hi : l[i]? with
  | none => rfl
  | some n =>
    simp only [List.getElem?_cons_zero]
    by_cases ho : amountMax < n.allowance + extra
    · simp [ho]
    · simp [ho]

/-! ## Runs -/

theorem run_append (l : Ledger) (ops ops' : List Op) :
    l.run (ops ++ ops') =
      (((l.run ops).1.run ops').1, (l.run ops).2 ++ ((l.run ops).1.run ops').2) := by
  induction ops generalizing l with
  | nil => rfl
  | cons op ops ih =>
    cases op with
    | spend i x =>
      simp only [List.cons_append, run]
      split <;> simp [ih]
    | refill i x => simp only [List.cons_append, run, ih]
    | append p x => simp only [List.cons_append, run, ih]

end Ledger

/-! ## The contract's calls -/

open Ledger

/-- One call of the grant signer, by what it does to the budget ledger (node
`k` is grant `k`'s `parent`, `allowance` and `spent`) and the transfers it
charges, each as `(grant, amount)`. -/
inductive Signer.Step : Ledger → Ledger → List (Nat × Nat) → Prop where
  /-- A refused call changes nothing, and neither does any call that fails,
  whether its transaction fails or a caller catches the failure. -/
  | refused (l : Ledger) : Step l l []
  /-- `issue`: a root grant at the next id. -/
  | issue (l : Ledger) (allowance : Nat) : Step l (l.append none allowance).2 []
  /-- `delegate`: a child of `parent` at the next id. -/
  | delegate (l : Ledger) (parent allowance : Nat) : Step l (l.append (some parent) allowance).2 []
  /-- `refill`. -/
  | refill (l : Ledger) (i extra : Nat) : Step l (refillGrant l i extra) []
  /-- An authorization by grant `e.1`, of lineage `ps`, whose metered
  transfers `xs` all fit: the lineage ledger after their spends, stored. -/
  | authorize (l : Ledger) (ps : List (Nat × Node)) (e : Nat × Node) (xs : List Nat) (c : Ledger) :
      l.IsLineage ps → ps.getLast? = some e → (chain ps).spendAll (ps.length - 1) xs = some c →
      Step l (l.writeBack ps c) (xs.map (e.1, ·))

/-- A sequence of the grant signer's calls, with every transfer charged,
oldest first. -/
inductive Signer.Run : Ledger → Ledger → List (Nat × Nat) → Prop where
  | nil (l : Ledger) : Run l l []
  | step {l l₁ l₂ : Ledger} {log₁ log₂ : List (Nat × Nat)} :
      Step l l₁ log₁ → Run l₁ l₂ log₂ → Run l l₂ (log₁ ++ log₂)

/-- Each call of the grant signer is a run of the whole ledger. -/
theorem Signer.Step.exists_run {l l' : Ledger} {log : List (Nat × Nat)} (hpf : l.ParentsFirst)
    (h : Signer.Step l l' log) : ∃ ops, l.run ops = (l', log) := by
  cases h with
  | refused => exact ⟨[], rfl⟩
  | issue x => exact ⟨[.append none x], rfl⟩
  | delegate p x => exact ⟨[.append (some p) x], rfl⟩
  | refill i x => exact ⟨[.refill i x], by rw [refillGrant_eq]; rfl⟩
  | authorize ps e xs c hl hlast hc =>
    rw [spendAll_lineage hpf hl hlast] at hc
    cases hs : l.spendAll e.1 xs with
    | none => rw [hs] at hc; simp at hc
    | some l1 =>
      rw [hs] at hc
      simp only [Option.map_some, Option.some.injEq] at hc
      subst hc
      exact ⟨xs.map (Op.spend e.1), by rw [writeBack_spendAll hl hlast hs, spendAll_run hs]⟩

/-- Every sequence of the grant signer's calls is a run of the whole ledger. -/
theorem Signer.Run.exists_run {l l' : Ledger} {log : List (Nat × Nat)} (hpf : l.ParentsFirst)
    (h : Signer.Run l l' log) : ∃ ops, l.run ops = (l', log) := by
  induction h with
  | nil l => exact ⟨[], rfl⟩
  | @step l l₁ l₂ log₁ log₂ hs _ ih =>
    obtain ⟨ops₁, h₁⟩ := hs.exists_run hpf
    have hpf₁ : l₁.ParentsFirst := by
      have := run_parentsFirst hpf ops₁; rwa [h₁] at this
    obtain ⟨ops₂, h₂⟩ := ih hpf₁
    exact ⟨ops₁ ++ ops₂, by rw [run_append, h₁]; simp only [h₂]⟩

/-- Budget safety for the grant signer: from no grants, after any sequence of
its calls, the total successfully spent at or under any grant never exceeds
that grant's allowance, however much its children's allowances
oversubscribe it. -/
theorem Signer.spentUnder_le_allowance {l : Ledger} {log : List (Nat × Nat)}
    (h : Signer.Run [] l log) {a : Nat} {n : Node} (ha : l[a]? = some n) :
    spentUnder l log a ≤ n.allowance := by
  obtain ⟨ops, hrun⟩ := h.exists_run (fun _ _ hj => by simp [parentOf] at hj)
  have := Ledger.spentUnder_le_allowance (l := []) (by simp) ops (a := a) (n := n)
    (by rw [hrun]; exact ha)
  rwa [hrun] at this

/-- Every grant's `spent` stays within its allowance over any sequence of the
grant signer's calls. -/
theorem Signer.withinAllowance {l l' : Ledger} {log : List (Nat × Nat)} (hpf : l.ParentsFirst)
    (hw : l.WithinAllowance) (h : Signer.Run l l' log) : l'.WithinAllowance := by
  obtain ⟨ops, hrun⟩ := h.exists_run hpf
  have := run_withinAllowance hw ops
  rwa [hrun] at this

/-- Parents precede their children over any sequence of the grant signer's
calls. -/
theorem Signer.parentsFirst {l l' : Ledger} {log : List (Nat × Nat)} (hpf : l.ParentsFirst)
    (h : Signer.Run l l' log) : l'.ParentsFirst := by
  obtain ⟨ops, hrun⟩ := h.exists_run hpf
  have := run_parentsFirst hpf ops
  rwa [hrun] at this

/-! ## Example

A root of 10 with children 1 and 2 of 8 each, and grant 3 of 20 under
grant 1. Grant 3's lineage is grants 0, 1 and 3; its lineage ledger has
nodes 0, 1 and 2, node 2 standing for grant 3. A spend of 9 by grant 3 is
refused at node 1 of the lineage ledger, which is grant 1, where the whole
ledger refuses it too. Transfers of 5 and 4 in one authorization fail as a
batch at the second. Transfers of 5 and 3 succeed, and storing the lineage
ledger charges grants 0, 1 and 3 by 8 and leaves grant 2, as the whole
ledger's run of the two spends does. -/

private def tree : Ledger :=
  [⟨none, 10, 0⟩, ⟨some 0, 8, 0⟩, ⟨some 0, 8, 0⟩, ⟨some 1, 20, 0⟩]

private def lineage3 : List (Nat × Node) :=
  [(0, ⟨none, 10, 0⟩), (1, ⟨some 0, 8, 0⟩), (3, ⟨some 1, 20, 0⟩)]

example : Ledger.chain lineage3 = [⟨none, 10, 0⟩, ⟨some 0, 8, 0⟩, ⟨some 1, 20, 0⟩] := rfl

example :
    ((Ledger.chain lineage3).spend 2 9).1.mapError (renameError lineage3) =
      .error (.overdrawn 1) := rfl

example : (tree.spend 3 9).1 = .error (.overdrawn 1) := rfl

example : (Ledger.chain lineage3).spendAll 2 [5, 4] = none := rfl

example :
    tree.writeBack lineage3 (((Ledger.chain lineage3).spendAll 2 [5, 3]).getD []) =
      [⟨none, 10, 8⟩, ⟨some 0, 8, 8⟩, ⟨some 0, 8, 0⟩, ⟨some 1, 20, 8⟩] := rfl

example :
    tree.run [.spend 3 5, .spend 3 3] =
      ([⟨none, 10, 8⟩, ⟨some 0, 8, 8⟩, ⟨some 0, 8, 0⟩, ⟨some 1, 20, 8⟩], [(3, 5), (3, 3)]) := rfl

end AttenuatingGrants.Budget
