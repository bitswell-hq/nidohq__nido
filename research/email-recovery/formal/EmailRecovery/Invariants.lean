import EmailRecovery.Controller

/-!
# Invariants of the controller model

`Inv` holds in every reachable state, whatever the evidence:

* every stored configuration passes `check_config` (so `delay_ledgers > 0` and
  `1 ≤ quorum ≤ |guardians|`);
* attempt records sit under their own id, below the attempt counter, with a
  valid target configuration and duplicate-free vote lists;
* the authorized pointer names an authorized record;
* every authorized record's authorization is in the log, with
  `executable_after = authorized_at + delay_ledgers` of the configuration in
  force then;
* every completion in the log comes after its attempt's authorization, at
  least that configuration's delay later;
* change records hold each guardian at most once.
-/

namespace EmailRecovery.Perch

namespace State

@[simp] theorem put_attempts (s : State) (a : Attempt) (i : Nat) :
    (s.put a).attempts i = if i = a.id then some a else s.attempts i := rfl
@[simp] theorem put_config (s : State) (a : Attempt) : (s.put a).config = s.config := rfl
@[simp] theorem put_epoch (s : State) (a : Attempt) : (s.put a).epoch = s.epoch := rfl
@[simp] theorem put_nextAttempt (s : State) (a : Attempt) :
    (s.put a).nextAttempt = s.nextAttempt := rfl
@[simp] theorem put_authorized (s : State) (a : Attempt) :
    (s.put a).authorized = s.authorized := rfl
@[simp] theorem put_approvals (s : State) (a : Attempt) :
    (s.put a).approvals = s.approvals := rfl
@[simp] theorem put_log (s : State) (a : Attempt) : (s.put a).log = s.log := rfl

@[simp] theorem emit_attempts (s : State) (L : Nat) (c : Option Config) (e : Event) :
    (s.emit L c e).attempts = s.attempts := rfl
@[simp] theorem emit_config (s : State) (L : Nat) (c : Option Config) (e : Event) :
    (s.emit L c e).config = s.config := rfl
@[simp] theorem emit_nextAttempt (s : State) (L : Nat) (c : Option Config) (e : Event) :
    (s.emit L c e).nextAttempt = s.nextAttempt := rfl
@[simp] theorem emit_authorized (s : State) (L : Nat) (c : Option Config) (e : Event) :
    (s.emit L c e).authorized = s.authorized := rfl
@[simp] theorem emit_approvals (s : State) (L : Nat) (c : Option Config) (e : Event) :
    (s.emit L c e).approvals = s.approvals := rfl
@[simp] theorem emit_log (s : State) (L : Nat) (c : Option Config) (e : Event) :
    (s.emit L c e).log = s.log ++ [⟨L, e, c⟩] := rfl

end State

@[simp] theorem Attempt.addVote_id (a : Attempt) (g : Nat) (d : Domain) :
    (a.addVote g d).id = a.id := by cases d <;> rfl
@[simp] theorem Attempt.addVote_state (a : Attempt) (g : Nat) (d : Domain) :
    (a.addVote g d).state = a.state := by cases d <;> rfl
@[simp] theorem Attempt.addVote_targetConfig (a : Attempt) (g : Nat) (d : Domain) :
    (a.addVote g d).targetConfig = a.targetConfig := by cases d <;> rfl
@[simp] theorem Attempt.addVote_authorizedAt (a : Attempt) (g : Nat) (d : Domain) :
    (a.addVote g d).authorizedAt = a.authorizedAt := by cases d <;> rfl
@[simp] theorem Attempt.addVote_executableAfter (a : Attempt) (g : Nat) (d : Domain) :
    (a.addVote g d).executableAfter = a.executableAfter := by cases d <;> rfl
@[simp] theorem Attempt.addVote_expiresAt (a : Attempt) (g : Nat) (d : Domain) :
    (a.addVote g d).expiresAt = a.expiresAt := by cases d <;> rfl
@[simp] theorem Attempt.addZk_id (a : Attempt) (d : Domain) : (a.addZk d).id = a.id := by
  cases d <;> rfl
@[simp] theorem Attempt.addZk_state (a : Attempt) (d : Domain) :
    (a.addZk d).state = a.state := by cases d <;> rfl
@[simp] theorem Attempt.addZk_targetConfig (a : Attempt) (d : Domain) :
    (a.addZk d).targetConfig = a.targetConfig := by cases d <;> rfl
@[simp] theorem Attempt.addZk_authorizedAt (a : Attempt) (d : Domain) :
    (a.addZk d).authorizedAt = a.authorizedAt := by cases d <;> rfl
@[simp] theorem Attempt.addZk_executableAfter (a : Attempt) (d : Domain) :
    (a.addZk d).executableAfter = a.executableAfter := by cases d <;> rfl
@[simp] theorem Attempt.addZk_expiresAt (a : Attempt) (d : Domain) :
    (a.addZk d).expiresAt = a.expiresAt := by cases d <;> rfl
@[simp] theorem Attempt.addZk_guardians (a : Attempt) (d : Domain) :
    (a.addZk d).guardians = a.guardians := by cases d <;> rfl
@[simp] theorem Attempt.addZk_cancelGuardians (a : Attempt) (d : Domain) :
    (a.addZk d).cancelGuardians = a.cancelGuardians := by cases d <;> rfl

theorem checkConfig_delay {account : Nat} {c : Config} (h : checkConfig account c = true) :
    0 < c.delayLedgers := by
  simp only [checkConfig, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1.1.1

theorem checkConfig_quorum {account : Nat} {c : Config} {gs : List Nat} {q : Nat}
    (h : checkConfig account c = true) (hm : c.mode.guardianSet = some (gs, q)) :
    1 ≤ q ∧ q ≤ gs.length := by
  simp only [checkConfig, hm, Bool.and_eq_true, decide_eq_true_eq] at h
  exact ⟨h.2.1.2, h.2.2⟩

/-- The invariant of every reachable state. -/
structure Inv (W : World) (s : State) : Prop where
  config : ∀ c, s.config = some c → checkConfig W.account c = true
  record : ∀ i a, s.attempts i = some a →
    a.id = i ∧ i < s.nextAttempt ∧ checkConfig W.account a.targetConfig = true ∧
      a.guardians.Nodup ∧ a.cancelGuardians.Nodup
  pointer : ∀ i, s.authorized = some i → ∃ a, s.attempts i = some a ∧ a.state = .authorized
  authorized : ∀ i a, s.attempts i = some a → a.state = .authorized →
    ∃ c, (⟨a.authorizedAt, .attemptAuthorized i a.executableAfter a.expiresAt, some c⟩ : Entry)
        ∈ s.log ∧ a.executableAfter = a.authorizedAt + c.delayLedgers ∧ 0 < c.delayLedgers
  completions : ∀ e ∈ s.log, ∀ i, e.event = .recoveryCompleted i →
    ∃ La xa ea c, 0 < c.delayLedgers ∧ xa = La + c.delayLedgers ∧ xa ≤ e.ledger ∧
      [(⟨La, .attemptAuthorized i xa ea, some c⟩ : Entry), e].Sublist s.log
  changes : ∀ d r, s.approvals d = some r → r.guardians.Nodup

theorem Inv.init (W : World) (doc : Nat) : Inv W (State.init doc) where
  config := by simp [State.init]
  record := by simp [State.init]
  pointer := by simp [State.init]
  authorized := by simp [State.init]
  completions := by simp [State.init]
  changes := by simp [State.init]

/-! ## Appending to the log -/

/-- Appending events that are neither authorizations nor completions keeps the
log clauses. -/
theorem Inv.authorized_append {W : World} {s : State} (hs : Inv W s) (new : List Entry) :
    ∀ i a, s.attempts i = some a → a.state = .authorized →
      ∃ c, (⟨a.authorizedAt, .attemptAuthorized i a.executableAfter a.expiresAt, some c⟩ : Entry)
        ∈ s.log ++ new ∧ a.executableAfter = a.authorizedAt + c.delayLedgers ∧
          0 < c.delayLedgers := by
  intro i a ha hst
  obtain ⟨c, hm, h⟩ := hs.authorized i a ha hst
  exact ⟨c, List.mem_append_left _ hm, h⟩

theorem Inv.completions_append {W : World} {s : State} (hs : Inv W s) (new : List Entry)
    (hnew : ∀ e ∈ new, ∀ i, e.event ≠ .recoveryCompleted i) :
    ∀ e ∈ s.log ++ new, ∀ i, e.event = .recoveryCompleted i →
      ∃ La xa ea c, 0 < c.delayLedgers ∧ xa = La + c.delayLedgers ∧ xa ≤ e.ledger ∧
        [(⟨La, .attemptAuthorized i xa ea, some c⟩ : Entry), e].Sublist (s.log ++ new) := by
  intro e he i hi
  rcases List.mem_append.mp he with he | he
  · obtain ⟨La, xa, ea, c, h1, h2, h3, h4⟩ := hs.completions e he i hi
    exact ⟨La, xa, ea, c, h1, h2, h3, h4.trans (List.sublist_append_left _ _)⟩
  · exact absurd hi (hnew e he i)

/-! ## Building blocks -/

/-- Both vote lists of a record are duplicate-free. -/
def Attempt.NodupVotes (a : Attempt) : Prop := a.guardians.Nodup ∧ a.cancelGuardians.Nodup

theorem nodup_append_singleton {l : List Nat} {g : Nat} (h : l.Nodup) (hg : g ∉ l) :
    (l ++ [g]).Nodup := by
  rw [List.nodup_append]
  refine ⟨h, List.nodup_cons.mpr ⟨by simp, List.nodup_nil⟩, ?_⟩
  intro x hx y hy hxy
  simp only [List.mem_singleton] at hy
  subst hy hxy
  exact hg hx

theorem Attempt.nodupVotes_addVote {a : Attempt} {g : Nat} {d : Domain} (h : a.NodupVotes)
    (hg : g ∉ a.votes d) : (a.addVote g d).NodupVotes := by
  cases d
  · exact ⟨nodup_append_singleton h.1 hg, h.2⟩
  · exact ⟨h.1, nodup_append_singleton h.2 hg⟩

theorem Attempt.nodupVotes_addZk {a : Attempt} {d : Domain} (h : a.NodupVotes) :
    (a.addZk d).NodupVotes := by
  cases d <;> exact h

/-- Writing a record that keeps an existing record's id and target, keeps its
authorization logged, and stays authorized while the pointer names it. -/
theorem Inv.put {W : World} {s : State} {a₀ a : Attempt} (hs : Inv W s)
    (h₀ : s.attempts a₀.id = some a₀) (hid : a.id = a₀.id)
    (htc : a.targetConfig = a₀.targetConfig) (hn : a.NodupVotes)
    (hptr : s.authorized = some a₀.id → a.state = .authorized)
    (hauth : a.state = .authorized →
      ∃ c, (⟨a.authorizedAt, .attemptAuthorized a.id a.executableAfter a.expiresAt, some c⟩ : Entry)
        ∈ s.log ∧ a.executableAfter = a.authorizedAt + c.delayLedgers ∧ 0 < c.delayLedgers) :
    Inv W (s.put a) := by
  obtain ⟨_, hlt, hcfg, _⟩ := hs.record _ _ h₀
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · simpa using hs.config
  · intro i b hb
    simp only [State.put_attempts] at hb
    split at hb
    · rename_i hi
      simp only [Option.some.injEq] at hb
      subst hb
      exact ⟨hi.symm, by simpa [hi, hid] using hlt, by rw [htc]; exact hcfg, hn.1, hn.2⟩
    · simpa using hs.record i b hb
  · intro j hj
    simp only [State.put_authorized] at hj
    by_cases hja : j = a.id
    · subst hja
      exact ⟨a, by simp, hptr (hid ▸ hj)⟩
    · obtain ⟨b, hb, hst⟩ := hs.pointer j hj
      exact ⟨b, by simp [hja, hb], hst⟩
  · intro i b hb hst
    simp only [State.put_attempts] at hb
    split at hb
    · rename_i hi
      simp only [Option.some.injEq] at hb
      subst hb hi
      simpa using hauth hst
    · simpa using hs.authorized i b hb hst
  · simpa using hs.completions
  · simpa using hs.changes

/-- Appending an event other than a completion. -/
theorem Inv.emit {W : World} {s : State} {L : Nat} {c : Option Config} {e : Event}
    (hs : Inv W s) (he : ∀ i, e ≠ .recoveryCompleted i) : Inv W (s.emit L c e) := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · simpa using hs.config
  · simpa using hs.record
  · simpa using hs.pointer
  · simp only [State.emit_attempts, State.emit_log]
    exact hs.authorized_append _
  · simp only [State.emit_log]
    exact hs.completions_append _ (by simpa using he)
  · simpa using hs.changes

/-- Clearing the authorized pointer. -/
theorem Inv.clear {W : World} {s : State} (hs : Inv W s) : Inv W { s with authorized := none } :=
  ⟨hs.config, hs.record, by simp, hs.authorized, hs.completions, hs.changes⟩

/-- The cancellation count, sibling bound and applied document are outside `Inv`. -/
theorem Inv.cancels {W : World} {s : State} (hs : Inv W s) (n : Nat) :
    Inv W { s with cancels := n } :=
  ⟨hs.config, hs.record, hs.pointer, hs.authorized, hs.completions, hs.changes⟩

theorem Inv.appliedDoc {W : World} {s : State} (hs : Inv W s) (n : Nat) :
    Inv W { s with appliedDoc := n } :=
  ⟨hs.config, hs.record, hs.pointer, hs.authorized, hs.completions, hs.changes⟩

theorem Inv.cancelsClear {W : World} {s : State} (hs : Inv W s) (n : Nat) :
    Inv W { s with cancels := n, authorized := none } :=
  ⟨hs.config, hs.record, by simp, hs.authorized, hs.completions, hs.changes⟩

theorem Inv.epoch {W : World} {s : State} (hs : Inv W s) (n : Nat) :
    Inv W { s with epoch := n } :=
  ⟨hs.config, hs.record, hs.pointer, hs.authorized, hs.completions, hs.changes⟩

/-! ## T1 -/

theorem Inv.beginAttempt {W : World} {s s' : State} {L : Nat} {k : Kind} {r td tb : Nat}
    {ok : Bool} (hs : Inv W s) (h : beginAttempt s L k r td tb ok = .ok s') : Inv W s' := by
  unfold Perch.beginAttempt at h
  split at h
  · contradiction
  · rename_i c hc
    split at h
    · contradiction
    · split at h
      · contradiction
      · split at h
        · contradiction
        · simp only [Except.ok.injEq] at h
          subst h
          refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
          · simpa using hs.config
          · intro i a ha
            simp only [State.emit_attempts, State.put_attempts] at ha
            split at ha
            · rename_i hi
              simp only [Option.some.injEq] at ha
              subst ha hi
              exact ⟨rfl, by simp [newAttempt], hs.config c hc, List.nodup_nil, List.nodup_nil⟩
            · obtain ⟨h1, h2, h3⟩ := hs.record i a ha
              exact ⟨h1, by simp; omega, h3⟩
          · intro i hi
            obtain ⟨a, ha, hst⟩ := hs.pointer i (by simpa using hi)
            have hlt := (hs.record i a ha).2.1
            exact ⟨a, by simp [newAttempt, Nat.ne_of_lt hlt, ha], hst⟩
          · intro i a ha hst
            simp only [State.emit_attempts, State.put_attempts] at ha
            split at ha
            · simp only [Option.some.injEq] at ha
              subst ha
              simp [newAttempt] at hst
            · simp only [State.emit_log, State.put_log]
              exact hs.authorized_append _ i a ha hst
          · simp only [State.emit_log, State.put_log]
            exact hs.completions_append _ (by simp)
          · simpa using hs.changes

/-! ## T4, T6, T7 -/

/-- `a` is the record `a₀` with only its evidence changed. -/
structure SameRecord (a₀ a : Attempt) : Prop where
  id : a.id = a₀.id
  state : a.state = a₀.state
  authorizedAt : a.authorizedAt = a₀.authorizedAt
  executableAfter : a.executableAfter = a₀.executableAfter
  expiresAt : a.expiresAt = a₀.expiresAt
  targetConfig : a.targetConfig = a₀.targetConfig

theorem SameRecord.addVote (a : Attempt) (g : Nat) (d : Domain) : SameRecord a (a.addVote g d) :=
  ⟨by simp, by simp, by simp, by simp, by simp, by simp⟩

theorem SameRecord.addZk (a : Attempt) (d : Domain) : SameRecord a (a.addZk d) :=
  ⟨by simp, by simp, by simp, by simp, by simp, by simp⟩

/-- Writing back a record with only its evidence changed. -/
theorem Inv.put_same {W : World} {s : State} {a₀ a : Attempt} (hs : Inv W s)
    (h₀ : s.attempts a₀.id = some a₀) (hsame : SameRecord a₀ a) (hn : a.NodupVotes) :
    Inv W (s.put a) := by
  refine hs.put h₀ hsame.id hsame.targetConfig hn ?_ ?_
  · intro hp
    obtain ⟨b, hb, hst⟩ := hs.pointer _ hp
    rw [h₀] at hb
    simp only [Option.some.injEq] at hb
    rw [hsame.state, hb, hst]
  · intro hst
    obtain ⟨c, hm, h⟩ := hs.authorized _ _ h₀ (hsame.state ▸ hst)
    exact ⟨c, by rw [hsame.id, hsame.authorizedAt, hsame.executableAfter, hsame.expiresAt]; exact hm,
      by rw [hsame.executableAfter, hsame.authorizedAt]; exact h.1, h.2⟩

theorem Inv.promote {W : World} {s s' : State} {L : Nat} {c : Config} {a₀ a : Attempt}
    (hs : Inv W s) (hc : s.config = some c) (h₀ : s.attempts a₀.id = some a₀)
    (hsame : SameRecord a₀ a) (hcol : a₀.state = .collecting) (hn : a.NodupVotes)
    (h : promote s L c a = .ok s') : Inv W s' := by
  unfold Perch.promote at h
  have hnotptr : s.authorized ≠ some a₀.id := by
    intro hp
    obtain ⟨b, hb, hst⟩ := hs.pointer _ hp
    rw [h₀] at hb
    simp only [Option.some.injEq] at hb
    rw [← hb, hcol] at hst
    contradiction
  split at h
  · contradiction
  · split at h
    · simp only [Except.ok.injEq] at h
      subst h
      refine Inv.emit (hs.put h₀ hsame.id hsame.targetConfig hn ?_ ?_) (by simp)
      · intro hp; exact absurd hp hnotptr
      · simp
    · simp only [Except.ok.injEq] at h
      subst h
      have hd := checkConfig_delay (hs.config c hc)
      obtain ⟨_, hlt, hcfg, _⟩ := hs.record _ _ h₀
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
      · simpa using hs.config
      · intro i b hb
        simp only [State.emit_attempts, State.put_attempts] at hb
        split at hb
        · rename_i hi
          simp only [Option.some.injEq] at hb
          subst hb
          refine ⟨hi.symm, by simpa [hi, hsame.id] using hlt, by simpa [hsame.targetConfig]
            using hcfg, hn.1, hn.2⟩
        · simpa using hs.record i b hb
      · intro j hj
        simp only [State.emit_authorized, State.put_authorized, Option.some.injEq] at hj
        subst hj
        simp
      · intro i b hb hst
        simp only [State.emit_attempts, State.put_attempts] at hb
        split at hb
        · rename_i hi
          simp only [Option.some.injEq] at hb
          subst hb hi
          exact ⟨c, by simp, rfl, hd⟩
        · obtain ⟨c', hm, h⟩ := hs.authorized i b hb hst
          exact ⟨c', by simp [hm], h⟩
      · simp only [State.emit_log, State.put_log]
        exact hs.completions_append _ (by simp)
      · simpa using hs.changes

theorem Inv.cancelAttempt {W : World} {s s' : State} {L : Nat} {c : Config} {a₀ a : Attempt}
    {counted : Bool} (hs : Inv W s) (h₀ : s.attempts a₀.id = some a₀)
    (hsame : SameRecord a₀ a) (hn : a.NodupVotes) (h : cancelAttempt s L c a counted = .ok s') :
    Inv W s' := by
  unfold Perch.cancelAttempt at h
  split at h
  · contradiction
  · simp only [Except.ok.injEq] at h
    subst h
    refine Inv.emit ?_ (by simp)
    by_cases hwas : a.state = .authorized
    · simp only [hwas, beq_self_eq_true, ite_true]
      exact (hs.cancelsClear _).put h₀ hsame.id hsame.targetConfig hn (by simp) (by simp)
    · have hptr : s.authorized ≠ some a₀.id := by
        intro hp
        obtain ⟨b, hb, hst⟩ := hs.pointer _ hp
        rw [h₀] at hb
        simp only [Option.some.injEq] at hb
        exact hwas (hsame.state.trans (hb ▸ hst))
      have hne : (a.state == .authorized) = false := by simpa using hwas
      simp only [hne, Bool.and_false, Bool.false_eq_true, ite_false]
      exact (hs.cancels _).put h₀ hsame.id hsame.targetConfig hn (fun hp => absurd hp hptr)
        (by simp)

theorem Inv.afterEvidence {W : World} {s s' : State} {L : Nat} {c : Config} {a₀ a : Attempt}
    {dom : Domain} (hs : Inv W s) (hc : s.config = some c) (h₀ : s.attempts a₀.id = some a₀)
    (hsame : SameRecord a₀ a) (hn : a.NodupVotes)
    (hcol : dom = .initiate → a₀.state = .collecting)
    (h : afterEvidence s L c a dom = .ok s') : Inv W s' := by
  cases dom with
  | initiate =>
    simp only [Perch.afterEvidence] at h
    split at h
    · exact hs.promote hc h₀ hsame (hcol rfl) hn h
    · simp only [Except.ok.injEq] at h
      subst h
      exact hs.put_same h₀ hsame hn
  | cancel =>
    simp only [Perch.afterEvidence] at h
    split at h
    · exact hs.cancelAttempt h₀ hsame hn h
    · simp only [Except.ok.injEq] at h
      subst h
      exact hs.put_same h₀ hsame hn

/-! ## T2, T3 -/

theorem Inv.submitGuardian {W : World} {s s' : State} {L : Nat} {auth : Nat → Fn → Nat → Bool}
    {id : Nat} {dom : Domain} {g : Nat} (hs : Inv W s)
    (h : submitGuardian W s L auth id dom g = .ok s') : Inv W s' := by
  unfold Perch.submitGuardian at h
  dsimp only at h
  split at h
  · contradiction
  · rename_i c hc
    split at h
    · contradiction
    · split at h
      · contradiction
      · split at h
        · contradiction
        · rename_i a ha
          obtain ⟨hid, -, -, hn₁, hn₂⟩ := hs.record id a ha
          split at h
          · contradiction
          · split at h
            · contradiction
            · rename_i hcol
              split at h
              · contradiction
              · rename_i hnot
                split at h
                · contradiction
                · split at h
                  · contradiction
                  · refine hs.afterEvidence hc (hid ▸ ha) (SameRecord.addVote a g dom)
                      (Attempt.nodupVotes_addVote ⟨hn₁, hn₂⟩ hnot) ?_ h
                    exact fun hd => Classical.byContradiction fun hne => hcol ⟨hd, hne⟩

theorem Inv.submitZk {W : World} {s s' : State} {L : Nat} {id : Nat} {dom : Domain}
    {ok : Bool} (hs : Inv W s) (h : submitZk W s L id dom ok = .ok s') : Inv W s' := by
  unfold Perch.submitZk at h
  split at h
  · contradiction
  · rename_i c hc
    split at h
    · contradiction
    · split at h
      · contradiction
      · rename_i a ha
        obtain ⟨hid, -, -, hn₁, hn₂⟩ := hs.record id a ha
        split at h
        · contradiction
        · split at h
          · contradiction
          · rename_i hcol
            split at h
            · contradiction
            · split at h
              · contradiction
              · split at h
                · contradiction
                · refine hs.afterEvidence hc (hid ▸ ha) (SameRecord.addZk a dom)
                    (Attempt.nodupVotes_addZk ⟨hn₁, hn₂⟩) ?_ h
                  exact fun hd => Classical.byContradiction fun hne => hcol ⟨hd, hne⟩

/-! ## Change evidence (§5) -/

theorem Inv.approvals {W : World} {s : State} (hs : Inv W s) (f : Nat → Option ChangeRecord)
    (hf : ∀ d r, f d = some r → r.guardians.Nodup) : Inv W { s with approvals := f } :=
  ⟨hs.config, hs.record, hs.pointer, hs.authorized, hs.completions, hf⟩

theorem Inv.approveChange {W : World} {s s' : State} {L : Nat} {auth : Nat → Fn → Nat → Bool}
    {sub : Subject} {vu g : Nat} (hs : Inv W s)
    (h : approveChange W s L auth sub vu g = .ok s') : Inv W s' := by
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
              · rename_i hnot
                split at h
                · contradiction
                · simp only [Except.ok.injEq] at h
                  subst h
                  refine Inv.emit (hs.approvals _ ?_) (by simp)
                  intro d r hr
                  split at hr
                  · simp only [Option.some.injEq] at hr
                    subst hr
                    refine nodup_append_singleton ?_ hnot
                    cases hd : s.approvals _ with
                    | none => exact List.nodup_nil
                    | some r₀ => simpa [hd] using hs.changes _ r₀ hd
                  · exact hs.changes d r hr

theorem Inv.submitZkChange {W : World} {s s' : State} {L : Nat} {sub : Subject} {vu : Nat}
    {ok : Bool} (hs : Inv W s) (h : submitZkChange W s L sub vu ok = .ok s') : Inv W s' := by
  unfold Perch.submitZkChange at h
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
              · simp only [Except.ok.injEq] at h
                subst h
                refine Inv.emit (hs.approvals _ ?_) (by simp)
                intro d r hr
                split at hr
                · simp only [Option.some.injEq] at hr
                  subst hr
                  cases hd : s.approvals _ with
                  | none => exact List.nodup_nil
                  | some r₀ => simpa [hd] using hs.changes _ r₀ hd
                · exact hs.changes d r hr

/-! ## Configuration changes (§10, §12) -/

theorem Inv.configEpoch {W : World} {s : State} (hs : Inv W s) (x : Option Config)
    (hx : ∀ c, x = some c → checkConfig W.account c = true) (e : Nat) :
    Inv W { s with config := x, epoch := e } :=
  ⟨hx, hs.record, hs.pointer, hs.authorized, hs.completions, hs.changes⟩

theorem Inv.remove {W : World} {s : State} (hs : Inv W s) (e : Nat) :
    Inv W { s with config := none, authorized := none, epoch := e } :=
  ⟨by simp, hs.record, by simp, hs.authorized, hs.completions, hs.changes⟩

theorem Inv.store {W : World} {s : State} {L : Nat} {old : Option Config} {n : Config}
    (hs : Inv W s) (hn : checkConfig W.account n = true) : Inv W (State.store s L old n) :=
  Inv.emit (hs.configEpoch _ (by simpa using hn) _) (by simp)

theorem Inv.applyDoc {W : World} {s s' : State} {L doc : Nat} {new : Option Config} {vu : Nat}
    (hs : Inv W s) (h : applyDoc W s L doc new vu = .ok s') : Inv W s' := by
  unfold Perch.applyDoc at h
  split at h
  · contradiction
  · dsimp only at h
    have hs' := hs.appliedDoc doc
    split at h
    · simp only [Except.ok.injEq] at h
      subst h
      exact hs'
    · split at h
      · contradiction
      · split at h
        · contradiction
        · rename_i hn
          simp only [Except.ok.injEq] at h
          subst h
          exact hs'.store (by simpa using hn)
    · split at h
      · simp only [Except.ok.injEq] at h
        subst h
        exact hs'
      · split at h
        · contradiction
        · split at h
          · split at h
            · split at h
              · contradiction
              · rename_i hn
                simp only [Except.ok.injEq] at h
                subst h
                exact hs'.store (by simpa using hn)
            · simp only [Except.ok.injEq] at h
              subst h
              exact Inv.emit (hs'.remove _) (by simp)
          · simp only [Except.ok.injEq] at h
            subst h
            exact Inv.emit (hs'.remove _) (by simp)

theorem Inv.executeUpgrade {W : World} {s s' : State} {L e : Nat} (hs : Inv W s)
    (h : executeUpgrade s L e = .ok s') : Inv W s' := by
  unfold Perch.executeUpgrade at h
  split at h
  · contradiction
  · split at h
    · contradiction
    · split at h
      · contradiction
      · simp only [Except.ok.injEq] at h
        subst h
        exact Inv.emit (hs.epoch _) (by simp)

/-! ## T5, T7 -/

theorem State.authorizedLive_spec {s : State} {L : Nat} {a : Attempt}
    (h : s.authorizedLive L = some a) :
    ∃ id, s.authorized = some id ∧ s.attempts id = some a ∧ s.isLive L a = true := by
  unfold State.authorizedLive at h
  split at h
  · contradiction
  · rename_i id hid
    split at h
    · contradiction
    · rename_i b hb
      split at h
      · rename_i hl
        simp only [Option.some.injEq] at h
        subst h
        exact ⟨id, hid, hb, hl⟩
      · contradiction

/-- Appending a completion that comes at least the delay after its logged
authorization. -/
theorem Inv.emit_completion {W : World} {s : State} {L : Nat} {oc : Option Config} {i : Nat}
    (hs : Inv W s)
    (hprev : ∃ La xa ea c, 0 < c.delayLedgers ∧ xa = La + c.delayLedgers ∧ xa ≤ L ∧
      (⟨La, .attemptAuthorized i xa ea, some c⟩ : Entry) ∈ s.log) :
    Inv W (s.emit L oc (.recoveryCompleted i)) := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · simpa using hs.config
  · simpa using hs.record
  · simpa using hs.pointer
  · simp only [State.emit_attempts, State.emit_log]
    exact hs.authorized_append _
  · intro e he j hj
    simp only [State.emit_log, List.mem_append, List.mem_singleton] at he
    rcases he with he | he
    · obtain ⟨La, xa, ea, c, h1, h2, h3, h4⟩ := hs.completions e he j hj
      exact ⟨La, xa, ea, c, h1, h2, h3, h4.trans (List.sublist_append_left _ _)⟩
    · subst he
      simp only [Event.recoveryCompleted.injEq] at hj
      subst hj
      obtain ⟨La, xa, ea, c, h1, h2, h3, h4⟩ := hprev
      refine ⟨La, xa, ea, c, h1, h2, h3, ?_⟩
      simp only [State.emit_log]
      exact List.Sublist.append (List.singleton_sublist.mpr h4) (List.Sublist.refl _)
  · simpa using hs.changes

theorem Inv.complete {W : World} {s s' : State} {L tb doc : Nat} {new : Config} (hs : Inv W s)
    (h : complete W s L tb doc new = .ok s') : Inv W s' := by
  unfold Perch.complete at h
  split at h
  · contradiction
  · split at h
    · contradiction
    · rename_i a ha
      obtain ⟨id, hptr, hrec, _⟩ := State.authorizedLive_spec ha
      obtain ⟨b, hb, hst⟩ := hs.pointer id hptr
      rw [hrec] at hb
      simp only [Option.some.injEq] at hb
      subst hb
      obtain ⟨hid, -, hcfg, hn₁, hn₂⟩ := hs.record id a hrec
      obtain ⟨c', hm, hx, hd⟩ := hs.authorized id a hrec hst
      split at h
      · contradiction
      · rename_i hL
        split at h
        · contradiction
        · split at h
          · contradiction
          · split at h
            · contradiction
            · rename_i hnew
              dsimp only at h
              simp only [Except.ok.injEq] at h
              subst h
              have hnew' : new = a.targetConfig := by
                simp only [not_or, Decidable.not_not] at hnew
                exact hnew.2
              have hs₁ : Inv W
                  { s with authorized := none, config := some new, epoch := s.epoch + 1,
                           appliedDoc := a.targetDoc } :=
                ⟨by simpa [hnew'] using hcfg, hs.record, by simp, hs.authorized, hs.completions,
                  hs.changes⟩
              have hrec' : s.attempts a.id = some a := by rw [hid]; exact hrec
              refine Inv.emit_completion (Inv.emit (hs₁.put (a₀ := a)
                (a := { a with state := .completed }) hrec' rfl rfl ⟨hn₁, hn₂⟩
                (by simp) (by simp)) (by simp)) ?_
              refine ⟨a.authorizedAt, a.executableAfter, a.expiresAt, c', hd, hx,
                Nat.le_of_not_lt hL, ?_⟩
              simp only [State.emit_log, State.put_log, List.mem_append]
              exact Or.inl (hid ▸ hm)

theorem Inv.ownerCancel {W : World} {s s' : State} {L id : Nat} (hs : Inv W s)
    (h : ownerCancel s L id = .ok s') : Inv W s' := by
  unfold Perch.ownerCancel at h
  split at h
  · contradiction
  · split at h
    · contradiction
    · split at h
      · contradiction
      · rename_i a ha
        obtain ⟨hid, -, -, hn₁, hn₂⟩ := hs.record id a ha
        split at h
        · contradiction
        · exact hs.cancelAttempt (hid ▸ ha) ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩ ⟨hn₁, hn₂⟩ h

/-! ## Every reachable state -/

theorem Inv.step {W : World} {s s' : State} {st : Step} (hs : Inv W s)
    (h : step W s st = .ok s') : Inv W s' := by
  unfold Perch.step at h
  split at h
  · exact hs.beginAttempt h
  · exact hs.submitGuardian h
  · exact hs.submitZk h
  · exact hs.approveChange h
  · exact hs.submitZkChange h
  · exact hs.applyDoc h
  · exact hs.complete h
  · exact hs.ownerCancel h
  · exact hs.executeUpgrade h

theorem Reachable.inv {W : World} {doc : Nat} {P : Step → Prop} {s : State}
    (h : Reachable W doc P s) : Inv W s := by
  induction h with
  | init => exact Inv.init W doc
  | step _ _ _ hstep ih => exact ih.step hstep

end EmailRecovery.Perch
