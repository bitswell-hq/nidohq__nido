import EmailRecovery.OneFactor
import EmailRecovery.Guardian

/-!
# Nido's wallet policy (spec §9.3)

The rules `recoverySpec` (`packages/passkey-sdk/src/perch/doc.ts`) must enforce
on every recovery member it builds, as a predicate (`WalletPolicy`), and the
theorem that, under it, the email guardian alone reaches the quorum only under
the `loss` profile with `delay_ledgers ≥ 120,960` and a second alert channel
(spec §11.2 item 4, second sentence).

The chain accepts any configuration the owner applies, so this is a property of
configurations Nido's wallet builds, not of every configuration
(`one_factor_under_wallet_policy` takes the wallet-built member as a
hypothesis). `checkEmailGuardian` in `recoverySpec` implements the rules, and
`packages/passkey-sdk/src/perch/recoverySpec.test.ts` pins each at its boundary;
that the code and this predicate agree is tested, not proven.
-/

namespace EmailRecovery.Perch

/-- Seven days at 5-second ledgers (spec §2). -/
def sevenDays : Nat := 120960

/-- A recovery member as the wallet builds it: the Perch configuration, which
listed guardians are email guardians and the actions each allows, and whether a
second alert channel (Web Push to a passkey device) is registered. -/
structure Member where
  config : Config
  isEmail : Nat → Bool
  emailAllowed : Nat → Nat
  secondAlertChannel : Bool

/-- The member's guardians. -/
def Member.guardians (m : Member) : List Nat :=
  match m.config.mode.guardianSet with
  | some (gs, _) => gs
  | none => []

/-- The member's quorum. -/
def Member.quorum (m : Member) : Nat :=
  match m.config.mode.guardianSet with
  | some (_, q) => q
  | none => 0

/-- The listed guardians that are email guardians. -/
def Member.emailGuardians (m : Member) : List Nat := m.guardians.filter m.isEmail

/-- Spec §9.3 rules 1 to 4. -/
structure WalletPolicy (m : Member) : Prop where
  /-- 1: at most one email guardian. -/
  oneEmail : m.emailGuardians.length ≤ 1
  /-- 2: an email guardian requires a second alert channel. -/
  secondChannel : m.emailGuardians ≠ [] → m.secondAlertChannel = true
  /-- 3: if the email vote alone authorizes (guardian-only, quorum 1), the
  profile is `loss` and the delay at least seven days. -/
  emailPlusDelay : ∀ gs, m.config.mode = .guardianOnly gs 1 → m.emailGuardians ≠ [] →
    m.config.profile = .loss ∧ sevenDays ≤ m.config.delayLedgers
  /-- 4: an email guardian allows every action whenever its vote is needed to
  reach the quorum (the other guardians number fewer than the quorum). -/
  allowAllWhenNeeded : ∀ G ∈ m.emailGuardians, m.guardians.length - 1 < m.quorum →
    m.emailAllowed G = allowAll

/-- Under the wallet policy, an email guardian that alone reaches the quorum
does so only under `loss`, with at least seven days of delay and a second alert
channel. -/
theorem wallet_policy_email_alone {m : Member} (hp : WalletPolicy m) {G : Nat}
    (hG : m.isEmail G = true) {gs : List Nat} (hm : m.config.mode = .guardianOnly gs 1)
    (hgs : G ∈ gs) :
    m.config.profile = .loss ∧ sevenDays ≤ m.config.delayLedgers ∧
      m.secondAlertChannel = true := by
  have hne : m.emailGuardians ≠ [] := by
    have : G ∈ m.emailGuardians := by
      simp only [Member.emailGuardians, Member.guardians, hm, Mode.guardianSet, List.mem_filter]
      exact ⟨hgs, hG⟩
    exact List.ne_nil_of_mem this
  obtain ⟨h1, h2⟩ := hp.emailPlusDelay gs hm hne
  exact ⟨h1, h2, hp.secondChannel hne⟩

/-- Rule 4 keeps a needed email vote usable for every action, so a `Protected`
account whose quorum needs it can still reconfigure and upgrade. -/
theorem wallet_policy_needed_email_allows_every_action {m : Member} (hp : WalletPolicy m)
    {G : Nat} (hG : G ∈ m.emailGuardians) (hneed : m.guardians.length - 1 < m.quorum)
    (a : Action) : (m.emailAllowed G).testBit (a.code - 1) = true := by
  rw [hp.allowAllWhenNeeded G hG hneed]
  exact allowAll_allows a

/-- **Theorem 4, wallet part.** In a trace whose only evidence is approvals by
the email guardian `G`, an authorization under a configuration the wallet built
under its policy happens only under `loss`, with at least seven days of delay
and a second alert channel. -/
theorem one_factor_under_wallet_policy {W : World} {doc G : Nat} {s : State}
    (h : Reachable W doc (Step.EvidenceOnlyFrom G) s) {e : Entry} (he : e ∈ s.log)
    {i xa ea : Nat} (hev : e.event = .attemptAuthorized i xa ea) {m : Member}
    (hcfg : e.config = some m.config) (hp : WalletPolicy m) (hG : m.isEmail G = true) :
    m.config.profile = .loss ∧ sevenDays ≤ m.config.delayLedgers ∧
      m.secondAlertChannel = true := by
  obtain ⟨c, gs, hc, hm, hgs⟩ := email_only_authorizes_only_at_quorum_one h e he i xa ea hev
  rw [hcfg] at hc
  simp only [Option.some.injEq] at hc
  subst hc
  exact wallet_policy_email_alone hp hG hm hgs

end EmailRecovery.Perch
