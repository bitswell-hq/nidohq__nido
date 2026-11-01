import EmailRecovery.Invariants

/-!
# Theorem 4: one-factor safety (spec §11.2 item 4, §9.1)

Over every trace of the controller model:

* `completion_waits_for_delay`: every completed recovery was authorized
  earlier in the log, under a configuration with `delay_ledgers > 0`, and
  completed at least `delay_ledgers` ledgers after its authorization. This holds
  whatever the evidence.
* `email_only_authorizes_only_at_quorum_one`: in a trace whose only evidence is
  approvals by the email guardian `G` (no other guardian's approval and no ZK
  proof; owner-authorized transactions are allowed), every authorization
  happens under a guardian-only configuration with quorum 1 that lists `G`.
  So when the quorum is at least 2, or the mode is `combined` or `zk-only`,
  no attempt is authorized.
* `one_factor_safety` combines the two.

The email guardian is one address, so it is one vote: the controller counts an
address at most once per attempt and domain (`Inv.record`) or per change digest
(`Inv.changes`).
-/

namespace EmailRecovery.Perch

/-- A transaction whose evidence, if any, is an approval by `G`. -/
def Step.EvidenceOnlyFrom (G : Nat) (st : Step) : Prop :=
  match st.tx with
  | .submitGuardian _ _ g => g = G
  | .approveChange _ _ g => g = G
  | .submitZk .. => False
  | .submitZkChange .. => False
  | _ => True

/-- Every element of a list is `G`. -/
def OnlyFrom (G : Nat) (l : List Nat) : Prop := ∀ x ∈ l, x = G

theorem OnlyFrom.eq_nil {G : Nat} {l : List Nat} (h : OnlyFrom G l) (hG : G ∉ l) : l = [] := by
  cases l with
  | nil => rfl
  | cons x xs => exact absurd (h x (List.mem_cons_self ..) ▸ List.mem_cons_self ..) hG

theorem OnlyFrom.append {G : Nat} {l : List Nat} (h : OnlyFrom G l) :
    OnlyFrom G (l ++ [G]) := by
  intro x hx
  rcases List.mem_append.mp hx with hx | hx
  · exact h x hx
  · simpa using hx

/-- A duplicate-free list of `G`s has at most one element. -/
theorem OnlyFrom.length_le {G : Nat} {l : List Nat} (h : OnlyFrom G l) (hn : l.Nodup) :
    l.length ≤ 1 := by
  match l, h, hn with
  | [], _, _ => simp
  | [_], _, _ => simp
  | x :: y :: _, h, hn =>
    have hx := h x (by simp)
    have hy := h y (by simp)
    simp only [List.nodup_cons, List.mem_cons, not_or] at hn
    exact absurd (hx.trans hy.symm) hn.1.1

/-- An attempt's evidence is approvals by `G` only. -/
def VotesOnly (G : Nat) (a : Attempt) : Prop :=
  OnlyFrom G a.guardians ∧ a.zk = false ∧ OnlyFrom G a.cancelGuardians ∧ a.cancelZk = false

/-- The configuration an authorization was logged under is guardian-only with
quorum 1 and lists `G`. -/
def QuorumOne (G : Nat) (oc : Option Config) : Prop :=
  ∃ c gs, oc = some c ∧ c.mode = .guardianOnly gs 1 ∧ G ∈ gs

/-- The invariant of every state reachable by transactions whose only evidence
is `G`'s approvals. -/
structure InvG (G : Nat) (s : State) : Prop where
  votes : ∀ i a, s.attempts i = some a → VotesOnly G a
  changes : ∀ d r, s.approvals d = some r → OnlyFrom G r.guardians ∧ r.zk = false
  authorizations : ∀ e ∈ s.log, ∀ i xa ea, e.event = .attemptAuthorized i xa ea →
    QuorumOne G e.config

theorem InvG.init (G doc : Nat) : InvG G (State.init doc) where
  votes := by simp [State.init]
  changes := by simp [State.init]
  authorizations := by simp [State.init]

theorem InvG.of_eq {G : Nat} {s s' : State} (hg : InvG G s) (h₁ : s'.attempts = s.attempts)
    (h₂ : s'.approvals = s.approvals) (h₃ : s'.log = s.log) : InvG G s' :=
  ⟨h₁ ▸ hg.votes, h₂ ▸ hg.changes, h₃ ▸ hg.authorizations⟩

theorem InvG.put {G : Nat} {s : State} {a : Attempt} (hg : InvG G s) (ha : VotesOnly G a) :
    InvG G (s.put a) := by
  refine ⟨?_, by simpa using hg.changes, by simpa using hg.authorizations⟩
  intro i b hb
  simp only [State.put_attempts] at hb
  split at hb
  · simp only [Option.some.injEq] at hb
    exact hb ▸ ha
  · exact hg.votes i b hb

theorem InvG.emit {G : Nat} {s : State} {L : Nat} {c : Option Config} {e : Event}
    (hg : InvG G s) (he : ∀ i xa ea, e ≠ .attemptAuthorized i xa ea) : InvG G (s.emit L c e) := by
  refine ⟨by simpa using hg.votes, by simpa using hg.changes, ?_⟩
  intro x hx i xa ea hxe
  simp only [State.emit_log, List.mem_append, List.mem_singleton] at hx
  rcases hx with hx | hx
  · exact hg.authorizations x hx i xa ea hxe
  · subst hx
    exact absurd hxe (he i xa ea)

theorem VotesOnly.addVote {G : Nat} {a : Attempt} {d : Domain} (h : VotesOnly G a) :
    VotesOnly G (a.addVote G d) := by
  cases d
  · exact ⟨h.1.append, h.2.1, h.2.2⟩
  · exact ⟨h.1, h.2.1, h.2.2.1.append, h.2.2.2⟩

theorem VotesOnly.state {G : Nat} {a : Attempt} (h : VotesOnly G a) (st : AttemptState) :
    VotesOnly G { a with state := st } := h

/-- The heart of Theorem 4: one more vote from `G` on an attempt with no other
evidence meets the initiation condition only under a guardian-only
configuration with quorum 1 that lists `G`. -/
theorem quorum_one_of_initiationMet {account G : Nat} {c : Config} {a : Attempt} {gs : List Nat}
    {q : Nat} (hcfg : checkConfig account c = true) (hgs : c.mode.guardianSet = some (gs, q))
    (hG : G ∈ gs) (hv : VotesOnly G a) (hnot : G ∉ a.guardians)
    (hmet : initiationMet c (a.addVote G .initiate) = true) :
    ∃ gs', c.mode = .guardianOnly gs' 1 ∧ G ∈ gs' := by
  have hnil := hv.1.eq_nil hnot
  have hq := checkConfig_quorum hcfg hgs
  simp only [initiationMet, Attempt.addVote, hnil, List.nil_append, List.length_singleton, hgs,
    hv.2.1, Bool.and_eq_true, decide_eq_true_eq, Bool.or_false, Bool.not_eq_true'] at hmet
  cases hm : c.mode with
  | guardianOnly gs' q' =>
    rw [hm] at hgs
    simp only [Mode.guardianSet, Option.some.injEq, Prod.mk.injEq] at hgs
    obtain ⟨rfl, rfl⟩ := hgs
    exact ⟨gs', by rw [show q' = 1 by omega], hG⟩
  | zkOnly => rw [hm] at hgs; simp [Mode.guardianSet] at hgs
  | combined gs' q' => rw [hm] at hmet; simp [Mode.hasZk] at hmet

/-- The same count for a change record: `G`'s approval alone meets
`require_condition` only at quorum 1, guardian-only. -/
theorem quorum_one_of_conditionMet {account G : Nat} {c : Config} {r : ChangeRecord}
    (hcfg : checkConfig account c = true) (hr : OnlyFrom G r.guardians) (hn : r.guardians.Nodup)
    (hz : r.zk = false) (hmet : conditionMet c r = true) :
    ∃ gs, c.mode = .guardianOnly gs 1 ∧ G ∈ gs := by
  have hlen := hr.length_le hn
  cases hm : c.mode with
  | guardianOnly gs q =>
    have hgs : c.mode.guardianSet = some (gs, q) := by rw [hm]; rfl
    have hq := checkConfig_quorum hcfg hgs
    have hmet' : q ≤ (r.guardians.filter (fun x => decide (x ∈ gs))).length := by
      simpa [conditionMet, hm, Mode.guardianSet, Mode.hasZk] using hmet
    have hfl := (List.filter_sublist (p := fun x => decide (x ∈ gs)) (l := r.guardians)).length_le
    obtain ⟨x, hx⟩ : ∃ x, x ∈ r.guardians.filter (fun x => decide (x ∈ gs)) :=
      List.exists_mem_of_length_pos (by omega)
    simp only [List.mem_filter, decide_eq_true_eq] at hx
    exact ⟨gs, by rw [show q = 1 by omega], hr x hx.1 ▸ hx.2⟩
  | zkOnly => simp [conditionMet, hm, Mode.guardianSet, Mode.hasZk, hz] at hmet
  | combined gs q => simp [conditionMet, hm, Mode.guardianSet, Mode.hasZk, hz] at hmet

/-! ## Preservation -/

section
variable {W : World} {G : Nat} {s s' : State}

theorem InvG.beginAttempt {L : Nat} {k : Kind} {r td tb : Nat} {ok : Bool} (hg : InvG G s)
    (h : beginAttempt s L k r td tb ok = .ok s') : InvG G s' := by
  unfold Perch.beginAttempt at h
  split at h
  · contradiction
  · split at h
    · contradiction
    · split at h
      · contradiction
      · split at h
        · contradiction
        · simp only [Except.ok.injEq] at h
          subst h
          refine InvG.emit (InvG.put (hg.of_eq rfl rfl rfl) ?_) (by simp)
          simp [VotesOnly, OnlyFrom, newAttempt]

theorem InvG.promote {L : Nat} {c : Config} {a : Attempt} (hg : InvG G s) (ha : VotesOnly G a)
    (hq : ∃ gs, c.mode = .guardianOnly gs 1 ∧ G ∈ gs) (h : promote s L c a = .ok s') :
    InvG G s' := by
  unfold Perch.promote at h
  split at h
  · contradiction
  · split at h
    · simp only [Except.ok.injEq] at h
      subst h
      exact InvG.emit (hg.put (ha.state _)) (by simp)
    · simp only [Except.ok.injEq] at h
      subst h
      refine ⟨?_, by simpa using hg.changes, ?_⟩
      · intro i b hb
        simp only [State.emit_attempts, State.put_attempts] at hb
        split at hb
        · simp only [Option.some.injEq] at hb
          exact hb ▸ ha
        · exact hg.votes i b hb
      · intro x hx i xa ea hxe
        simp only [State.emit_log, State.put_log, List.mem_append, List.mem_singleton] at hx
        rcases hx with hx | hx
        · exact hg.authorizations x hx i xa ea hxe
        · subst hx
          obtain ⟨gs, hm, hG⟩ := hq
          exact ⟨c, gs, rfl, hm, hG⟩

theorem InvG.cancelAttempt {L : Nat} {c : Config} {a : Attempt} {counted : Bool}
    (hg : InvG G s) (ha : VotesOnly G a) (h : cancelAttempt s L c a counted = .ok s') :
    InvG G s' := by
  unfold Perch.cancelAttempt at h
  split at h
  · contradiction
  · simp only [Except.ok.injEq] at h
    subst h
    exact InvG.emit (InvG.put (hg.of_eq rfl rfl rfl) (ha.state _)) (by simp)

theorem InvG.submitGuardian {L : Nat} {auth : Nat → Fn → Nat → Bool} {id : Nat} {dom : Domain}
    (hs : Inv W s) (hg : InvG G s) (h : submitGuardian W s L auth id dom G = .ok s') :
    InvG G s' := by
  unfold Perch.submitGuardian at h
  dsimp only at h
  split at h
  · contradiction
  · rename_i c hc
    split at h
    · contradiction
    · rename_i gs q hgs
      split at h
      · contradiction
      · rename_i hG
        simp only [Decidable.not_not] at hG
        split at h
        · contradiction
        · rename_i a ha
          have hv := hg.votes id a ha
          split at h
          · contradiction
          · split at h
            · contradiction
            · split at h
              · contradiction
              · rename_i hnot
                split at h
                · contradiction
                · split at h
                  · contradiction
                  · cases dom with
                    | initiate =>
                      simp only [Perch.afterEvidence] at h
                      split at h
                      · rename_i hmet
                        exact hg.promote hv.addVote
                          (quorum_one_of_initiationMet (hs.config c hc) hgs hG hv hnot hmet) h
                      · simp only [Except.ok.injEq] at h
                        subst h
                        exact hg.put hv.addVote
                    | cancel =>
                      simp only [Perch.afterEvidence] at h
                      split at h
                      · exact hg.cancelAttempt hv.addVote h
                      · simp only [Except.ok.injEq] at h
                        subst h
                        exact hg.put hv.addVote

theorem InvG.approveChange {L : Nat} {auth : Nat → Fn → Nat → Bool} {sub : Subject} {vu : Nat}
    (hg : InvG G s) (h : approveChange W s L auth sub vu G = .ok s') : InvG G s' := by
  unfold Perch.approveChange at h
  dsimp only at h
  split at h
  · contradiction
  · split at h
    · contradiction
    · split at h
      · contradiction
      · split at h
        · contradiction
        · split at h
          · contradiction
          · split at h
            · contradiction
            · split at h
              · contradiction
              · split at h
                · contradiction
                · simp only [Except.ok.injEq] at h
                  subst h
                  refine InvG.emit ⟨by simpa using hg.votes, ?_, by simpa using hg.authorizations⟩
                    (by simp)
                  intro d r hr
                  simp only at hr
                  split at hr
                  · simp only [Option.some.injEq] at hr
                    subst hr
                    cases hd : s.approvals _ with
                    | none => simp [OnlyFrom]
                    | some r₀ =>
                      have := hg.changes _ r₀ hd
                      simpa [hd] using ⟨this.1.append, this.2⟩
                  · exact hg.changes d r hr

theorem InvG.applyDoc {L doc : Nat} {new : Option Config} {vu : Nat} (hg : InvG G s)
    (h : applyDoc W s L doc new vu = .ok s') : InvG G s' := by
  have hgd : InvG G { s with appliedDoc := doc } := hg.of_eq rfl rfl rfl
  unfold Perch.applyDoc at h
  split at h
  · contradiction
  · dsimp only at h
    split at h
    · simp only [Except.ok.injEq] at h
      subst h
      exact hgd
    · split at h
      · contradiction
      · split at h
        · contradiction
        · simp only [Except.ok.injEq] at h
          subst h
          exact InvG.emit (hgd.of_eq rfl rfl rfl) (by simp)
    · split at h
      · simp only [Except.ok.injEq] at h
        subst h
        exact hgd
      · split at h
        · contradiction
        · split at h
          · split at h
            · split at h
              · contradiction
              · simp only [Except.ok.injEq] at h
                subst h
                exact InvG.emit (hgd.of_eq rfl rfl rfl) (by simp)
            · simp only [Except.ok.injEq] at h
              subst h
              exact InvG.emit (hgd.of_eq rfl rfl rfl) (by simp)
          · simp only [Except.ok.injEq] at h
            subst h
            exact InvG.emit (hgd.of_eq rfl rfl rfl) (by simp)

theorem InvG.complete {L tb doc : Nat} {new : Config} (hg : InvG G s)
    (h : complete W s L tb doc new = .ok s') : InvG G s' := by
  unfold Perch.complete at h
  split at h
  · contradiction
  · split at h
    · contradiction
    · rename_i a ha
      obtain ⟨id, -, hrec, -⟩ := State.authorizedLive_spec ha
      have hv := hg.votes id a hrec
      split at h
      · contradiction
      · split at h
        · contradiction
        · split at h
          · contradiction
          · split at h
            · contradiction
            · dsimp only at h
              simp only [Except.ok.injEq] at h
              subst h
              exact InvG.emit (InvG.emit (InvG.put (hg.of_eq rfl rfl rfl) (hv.state _))
                (by simp)) (by simp)

theorem InvG.ownerCancel {L id : Nat} (hg : InvG G s) (h : ownerCancel s L id = .ok s') :
    InvG G s' := by
  unfold Perch.ownerCancel at h
  split at h
  · contradiction
  · split at h
    · contradiction
    · split at h
      · contradiction
      · rename_i a ha
        split at h
        · contradiction
        · exact hg.cancelAttempt (hg.votes id a ha) h

theorem InvG.executeUpgrade {L e : Nat} (hg : InvG G s) (h : executeUpgrade s L e = .ok s') :
    InvG G s' := by
  unfold Perch.executeUpgrade at h
  split at h
  · contradiction
  · split at h
    · contradiction
    · split at h
      · contradiction
      · simp only [Except.ok.injEq] at h
        subst h
        exact InvG.emit (hg.of_eq rfl rfl rfl) (by simp)

theorem InvG.step {st : Step} (hs : Inv W s) (hg : InvG G s) (hst : st.EvidenceOnlyFrom G)
    (h : step W s st = .ok s') : InvG G s' := by
  unfold Perch.step at h
  unfold Step.EvidenceOnlyFrom at hst
  cases htx : st.tx with
  | beginAttempt => simp only [htx] at h; exact hg.beginAttempt h
  | submitGuardian =>
    simp only [htx] at h hst
    subst hst
    exact hg.submitGuardian hs h
  | submitZk => simp only [htx] at hst
  | approveChange =>
    simp only [htx] at h hst
    subst hst
    exact hg.approveChange h
  | submitZkChange => simp only [htx] at hst
  | applyDoc => simp only [htx] at h; exact hg.applyDoc h
  | complete => simp only [htx] at h; exact hg.complete h
  | ownerCancel => simp only [htx] at h; exact hg.ownerCancel h
  | executeUpgrade => simp only [htx] at h; exact hg.executeUpgrade h

end

theorem Reachable.invG {W : World} {doc G : Nat} {s : State}
    (h : Reachable W doc (Step.EvidenceOnlyFrom G) s) : InvG G s := by
  induction h with
  | init => exact InvG.init G doc
  | step st hr hst hstep ih => exact ih.step hr.inv hst hstep

/-! ## Theorem 4 -/

/-- Every completion comes after its attempt's authorization, at least the
configured delay later, and the delay is positive. Holds for every trace. -/
theorem completion_waits_for_delay {W : World} {doc : Nat} {P : Step → Prop} {s : State}
    (h : Reachable W doc P s) :
    ∀ e ∈ s.log, ∀ i, e.event = .recoveryCompleted i →
      ∃ La xa ea c, [(⟨La, .attemptAuthorized i xa ea, some c⟩ : Entry), e].Sublist s.log ∧
        0 < c.delayLedgers ∧ La + c.delayLedgers ≤ e.ledger := by
  intro e he i hi
  obtain ⟨La, xa, ea, c, h1, h2, h3, h4⟩ := h.inv.completions e he i hi
  exact ⟨La, xa, ea, c, h4, h1, h2 ▸ h3⟩

/-- With approvals by `G` as the only evidence, every authorization happens
under a guardian-only configuration with quorum 1 that lists `G`. -/
theorem email_only_authorizes_only_at_quorum_one {W : World} {doc G : Nat} {s : State}
    (h : Reachable W doc (Step.EvidenceOnlyFrom G) s) :
    ∀ e ∈ s.log, ∀ i xa ea, e.event = .attemptAuthorized i xa ea → QuorumOne G e.config :=
  h.invG.authorizations

/-- So under a configuration with quorum at least 2, or in `combined` or
`zk-only` mode, approvals by `G` alone authorize nothing. -/
theorem email_only_never_authorizes {W : World} {doc G : Nat} {s : State}
    (h : Reachable W doc (Step.EvidenceOnlyFrom G) s) {e : Entry} (he : e ∈ s.log)
    {i xa ea : Nat} (hev : e.event = .attemptAuthorized i xa ea) {c : Config}
    (hc : e.config = some c) (hq : ∀ gs q, c.mode = .guardianOnly gs q → 2 ≤ q) : False := by
  obtain ⟨c', gs, hc', hm, -⟩ := email_only_authorizes_only_at_quorum_one h e he i xa ea hev
  rw [hc] at hc'
  simp only [Option.some.injEq] at hc'
  subst hc'
  exact absurd (hq gs 1 hm) (by decide)

/-- **Theorem 4 (one-factor safety).** In a trace whose only evidence is
approvals by the email guardian `G`, every completed recovery was authorized
earlier, under a guardian-only configuration with quorum 1 that lists `G`, and
completed at least that configuration's `delay_ledgers > 0` ledgers after its
authorization. -/
theorem one_factor_safety {W : World} {doc G : Nat} {s : State}
    (h : Reachable W doc (Step.EvidenceOnlyFrom G) s) :
    ∀ e ∈ s.log, ∀ i, e.event = .recoveryCompleted i →
      ∃ La xa ea c gs, [(⟨La, .attemptAuthorized i xa ea, some c⟩ : Entry), e].Sublist s.log ∧
        c.mode = .guardianOnly gs 1 ∧ G ∈ gs ∧ 0 < c.delayLedgers ∧
        La + c.delayLedgers ≤ e.ledger := by
  intro e he i hi
  obtain ⟨La, xa, ea, c, hsub, hd, hL⟩ := completion_waits_for_delay h e he i hi
  have hmem : (⟨La, .attemptAuthorized i xa ea, some c⟩ : Entry) ∈ s.log :=
    hsub.subset (List.mem_cons_self ..)
  obtain ⟨c', gs, hc', hm, hG⟩ :=
    email_only_authorizes_only_at_quorum_one h _ hmem i xa ea rfl
  simp only [Option.some.injEq] at hc'
  subst hc'
  exact ⟨La, xa, ea, c, gs, hsub, hm, hG, hd, hL⟩

/-- During the delay a `Loss` owner can cancel a live attempt (Perch §6.3 T7,
spec §9.1): the call succeeds and the attempt is cancelled. -/
theorem owner_can_cancel {s : State} {L id : Nat} {c : Config} {a : Attempt}
    (hc : s.config = some c) (hloss : c.profile = .loss) (ha : s.attempts id = some a)
    (hlive : s.isLive L a = true) :
    ∃ s', ownerCancel s L id = .ok s' ∧
      s'.attempts a.id = some { a with state := .cancelled } := by
  unfold Perch.ownerCancel Perch.cancelAttempt
  simp only [hc, hloss, ha, hlive, ne_eq, not_true_eq_false, ite_false, Bool.not_true,
    Bool.false_eq_true, Bool.false_and]
  exact ⟨_, rfl, by simp⟩

end EmailRecovery.Perch
