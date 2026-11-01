import EmailRecovery.Guardian
import EmailRecovery.OneFactor

/-!
# Theorem 3: replay and front-running resistance (spec §11.2 item 3)

* `accepted_names_digest`: an approval is accepted only in a context naming
  `d = sha256(statement)`; `accepted_context_unique`: the same approval is
  accepted in exactly one context; `accepted_account_unique`: and for exactly one
  account, controller and network, whichever guardian checks it.
* `digest_fixes`: the digest fixes the account, network, controller, action,
  attempt or request id and epoch, unless SHA-256 collides (with the encoding's
  code facts).
* `votes_counted_once`, `change_votes_counted_once`,
  `counted_vote_refused_again`: the controller records an address at most once
  per attempt and domain, and once per change digest.
* `email_vote_binds_statement`, `email_vote_replay`: composed with the
  controller, an email approval that counts toward an attempt counts only
  toward the attempt and domain whose statement it was made for, unless SHA-256
  collides.
* `emailAuth_payload_irrelevant`: the verdict does not depend on the
  authorization entry the approval is wrapped in, and the controller's
  transition has no submitter, so a copy submitted by anyone records the same
  single vote.
-/

namespace EmailRecovery

variable {H : Hashes} {E : Encoding} {c c₁ c₂ : GuardianConfig} {env env₁ env₂ : Env}
  {p p₁ p₂ : Nat} {ap : Approval} {contexts contexts₁ contexts₂ : List AuthContext}

/-- An approval is accepted only in the context `controller.fn((d,))` with
`d = sha256(statement)`. -/
theorem accepted_names_digest (h : check H E c env p ap contexts = .ok ()) :
    ∃ fn, contexts = [AuthContext.approval c.controller fn (H.sha256 ap.statement)] := by
  obtain ⟨fn, d, v, a⟩ := accepted_of_check h
  exact ⟨fn, a.digest ▸ a.context⟩

/-- The same approval is accepted by a guardian in one context only: the digest
is the statement's, and the entry point is the statement's action's. -/
theorem accepted_context_unique (h₁ : check H E c env₁ p₁ ap contexts₁ = .ok ())
    (h₂ : check H E c env₂ p₂ ap contexts₂ = .ok ()) : contexts₁ = contexts₂ := by
  obtain ⟨fn₁, d₁, v₁, a₁⟩ := accepted_of_check h₁
  obtain ⟨fn₂, d₂, v₂, a₂⟩ := accepted_of_check h₂
  have hv : v₁ = v₂ := by
    have := a₁.parsed.symm.trans a₂.parsed
    simpa using this
  rw [a₁.context, a₂.context, a₁.entryPoint, a₂.entryPoint, hv, ← a₁.digest, ← a₂.digest]

/-- Whichever guardians accept an approval agree on its account, controller and
network: the statement bytes name them. Two guardians sharing one commitment
still cannot share an approval across accounts. -/
theorem accepted_account_unique (h₁ : check H E c₁ env₁ p₁ ap contexts₁ = .ok ())
    (h₂ : check H E c₂ env₂ p₂ ap contexts₂ = .ok ()) :
    c₁.account = c₂.account ∧ c₁.controller = c₂.controller ∧ env₁.network = env₂.network := by
  obtain ⟨_, _, v₁, a₁⟩ := accepted_of_check h₁
  obtain ⟨_, _, v₂, a₂⟩ := accepted_of_check h₂
  have hv : v₁ = v₂ := by
    have := a₁.parsed.symm.trans a₂.parsed
    simpa using this
  subst hv
  exact ⟨a₁.account.symm.trans a₂.account, a₁.controller.symm.trans a₂.controller,
    a₁.network.symm.trans a₂.network⟩

/-- A digest fixes one account, network, controller, action, nonce (attempt or
request id) and epoch, unless SHA-256 collides. -/
theorem digest_fixes (hE : E.Facts) {s t : Statement} (h : digest H E s = digest H E t) :
    (s.account = t.account ∧ s.network = t.network ∧ s.controller = t.controller ∧
      s.action = t.action ∧ s.subject.nonce = t.subject.nonce ∧ s.epoch = t.epoch) ∨
    H.Sha256Collision := by
  rcases digest_binds hE h with h | h
  · subst h
    exact Or.inl ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩
  · exact Or.inr h

/-! ## The controller counts each address once -/

namespace Perch

theorem votes_counted_once {W : World} {doc : Nat} {P : Step → Prop} {s : State}
    (h : Reachable W doc P s) {i : Nat} {a : Attempt} (ha : s.attempts i = some a) :
    a.guardians.Nodup ∧ a.cancelGuardians.Nodup :=
  let ⟨_, _, _, h₁, h₂⟩ := h.inv.record i a ha
  ⟨h₁, h₂⟩

theorem change_votes_counted_once {W : World} {doc : Nat} {P : Step → Prop} {s : State}
    (h : Reachable W doc P s) {d : Nat} {r : ChangeRecord} (hr : s.approvals d = some r) :
    r.guardians.Nodup :=
  h.inv.changes d r hr

/-- A vote already recorded for an attempt and domain is never recorded
again: resubmitting it, in any authorization entry, is refused. -/
theorem counted_vote_refused_again {W : World} {s s' : State} {L : Nat}
    {auth : Nat → Fn → Nat → Bool} {id : Nat} {dom : Domain} {g : Nat} {a : Attempt}
    (ha : s.attempts id = some a) (hg : g ∈ a.votes dom) :
    submitGuardian W s L auth id dom g ≠ .ok s' := by
  intro h
  unfold Perch.submitGuardian at h
  split at h
  · contradiction
  · split at h
    · contradiction
    · split at h
      · contradiction
      · split at h
        · contradiction
        · rename_i a' ha'
          rw [ha] at ha'
          simp only [Option.some.injEq] at ha'
          subst ha'
          split at h
          · contradiction
          · split at h
            · contradiction
            · contradiction

/-- `attempt_statement` names the attempt, the domain, and the epoch. -/
theorem attemptStatement_inj {W : World} {c₁ c₂ : Config} {a₁ a₂ : Attempt} {d₁ d₂ : Domain}
    (h : attemptStatement W c₁ a₁ d₁ = attemptStatement W c₂ a₂ d₂) :
    a₁.id = a₂.id ∧ d₁ = d₂ ∧ a₁.epoch = a₂.epoch := by
  cases d₁ <;> cases d₂ <;> cases hk₁ : a₁.kind <;> cases hk₂ : a₂.kind <;>
    simp [attemptStatement, initiationStatement, mkStatement, hk₁, hk₂] at h <;>
    exact ⟨by simp_all, rfl, h.1⟩

end Perch

/-! ## The guardian composed with the controller -/

/-- The host's authorization of address `g` in a transaction that carries the
approval `ap` in the email guardian's authorization entry (with host payload
`payload`): for the guardian's address `G` it runs `__check_auth` on the context
`here.fn((d,))`; every other address authorizes as `other` says. -/
def emailAuth (H : Hashes) (E : Encoding) (G : Nat) (cfg : GuardianConfig) (env : Env)
    (payload : Nat) (ap : Approval) (here : Nat) (other : Nat → Fn → Nat → Bool) :
    Nat → Fn → Nat → Bool :=
  fun g fn d =>
    if g = G then
      match check H E cfg env payload ap [AuthContext.approval here fn d] with
      | .ok () => true
      | .error _ => false
    else other g fn d

theorem emailAuth_payload_irrelevant {G : Nat} {cfg : GuardianConfig} {here : Nat}
    {other : Nat → Fn → Nat → Bool} :
    emailAuth H E G cfg env p₁ ap here other = emailAuth H E G cfg env p₂ ap here other := rfl

theorem check_of_emailAuth {G : Nat} {cfg : GuardianConfig} {here : Nat}
    {other : Nat → Fn → Nat → Bool} {fn : Fn} {d : Nat}
    (h : emailAuth H E G cfg env p ap here other G fn d = true) :
    check H E cfg env p ap [AuthContext.approval here fn d] = .ok () := by
  simp only [emailAuth, ite_true] at h
  split at h
  · rename_i heq; exact heq
  · contradiction

namespace Perch

variable {W : World} {G : Nat} {cfg : GuardianConfig} {other : Nat → Fn → Nat → Bool}

/-- An email vote that counts toward an attempt was made for that attempt's
statement in that domain: the approval's statement bytes hash to the digest the
controller built, and they name the guardian's account, controller and
network. -/
theorem email_vote_binds_statement {s s' : State} {L id : Nat} {dom : Domain}
    (h : submitGuardian W s L (emailAuth H E G cfg env p ap W.here other) id dom G = .ok s') :
    ∃ c a, s.config = some c ∧ s.attempts id = some a ∧
      H.sha256 ap.statement = W.digest (attemptStatement W c a dom) ∧
      ∃ v, E.parseView ap.statement = some v ∧ v.account = cfg.account ∧
        v.controller = cfg.controller ∧ v.network = env.network := by
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
                  · rename_i hauth
                    simp only [Bool.not_eq_true', Bool.not_eq_false] at hauth
                    obtain ⟨fn, d, v, acc⟩ := accepted_of_check (check_of_emailAuth hauth)
                    have hctx := acc.context
                    simp only [AuthContext.approval, List.cons.injEq, AuthContext.call.injEq,
                      Val.bytes32.injEq, and_true] at hctx
                    exact ⟨c, a, hc, ha, acc.digest.trans hctx.2.2.symm, v, acc.parsed, acc.account,
                      acc.controller, acc.network⟩

/-- **Theorem 3 (replay and front-running resistance).** One email approval
that counts in two `submit_guardian` calls counts for one attempt, in one
domain, at one epoch, unless SHA-256 collides. Whoever submits it, in whatever
authorization entry, records the same vote. -/
theorem email_vote_replay (hE : E.Facts) (hW : W.digest = digest H E)
    {s₁ s₁' s₂ s₂' : State} {L₁ L₂ id₁ id₂ : Nat} {dom₁ dom₂ : Domain} {env₁ env₂ : Env}
    {p₁ p₂ : Nat}
    (h₁ : submitGuardian W s₁ L₁ (emailAuth H E G cfg env₁ p₁ ap W.here other) id₁ dom₁ G =
      .ok s₁')
    (h₂ : submitGuardian W s₂ L₂ (emailAuth H E G cfg env₂ p₂ ap W.here other) id₂ dom₂ G =
      .ok s₂') :
    ∃ a₁ a₂, s₁.attempts id₁ = some a₁ ∧ s₂.attempts id₂ = some a₂ ∧
      ((a₁.id = a₂.id ∧ dom₁ = dom₂ ∧ a₁.epoch = a₂.epoch) ∨ H.Sha256Collision) := by
  obtain ⟨c₁, a₁, -, ha₁, hd₁, -⟩ := email_vote_binds_statement h₁
  obtain ⟨c₂, a₂, -, ha₂, hd₂, -⟩ := email_vote_binds_statement h₂
  refine ⟨a₁, a₂, ha₁, ha₂, ?_⟩
  rw [hW] at hd₁ hd₂
  rcases digest_binds hE (hd₁.symm.trans hd₂) with h | h
  · exact Or.inl (attemptStatement_inj h)
  · exact Or.inr h

/-- The same for reconfiguration and upgrade approvals: an email approval
recorded by `approve_change` was made for the change statement the controller
built, so it is recorded under that statement's digest only. -/
theorem email_change_binds_statement {s s' : State} {L vu : Nat} {sub : Subject}
    (h : approveChange W s L (emailAuth H E G cfg env p ap W.here other) sub vu G = .ok s') :
    ∃ c, s.config = some c ∧ H.sha256 ap.statement = W.digest (mkStatement W c s.epoch vu sub) := by
  unfold Perch.approveChange at h
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
        · split at h
          · contradiction
          · split at h
            · contradiction
            · split at h
              · contradiction
              · split at h
                · contradiction
                · rename_i hauth
                  simp only [Bool.not_eq_true', Bool.not_eq_false] at hauth
                  obtain ⟨fn, d, v, acc⟩ := accepted_of_check (check_of_emailAuth hauth)
                  have hctx := acc.context
                  simp only [AuthContext.approval, List.cons.injEq, AuthContext.call.injEq,
                    Val.bytes32.injEq, and_true] at hctx
                  exact ⟨c, hc, acc.digest.trans hctx.2.2.symm⟩

end Perch

end EmailRecovery
