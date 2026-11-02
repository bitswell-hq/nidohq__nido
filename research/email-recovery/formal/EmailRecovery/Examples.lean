import EmailRecovery.Soundness
import EmailRecovery.OneFactor
import EmailRecovery.Privacy

/-!
# The theorems' hypotheses are satisfiable

A theorem whose hypotheses can never hold together says nothing. This module
exhibits, for Theorems 1, 2 and 4, concrete values that satisfy every hypothesis:

* `assumptions₀` and `check₀`: a guardian, a ledger, an approval its `check`
  accepts, and `SoundnessAssumptions` for them, so `soundness` applies; and an
  extractor that does not fail on that approval (`extraction₀`), so the
  conclusion's email branch is the one that holds.
* `trace₀`: a run from an unenrolled account, with approvals by guardian `7` as
  the only evidence, that enrolls, opens an attempt, authorizes it with that one
  vote at quorum 1, and completes it once the delay has passed. Its log holds
  the authorization and the completion, so `one_factor_safety` applies to a
  completed recovery.
* `privacy₀`: two wallets with different addresses and account codes, and
  tools in the ideal model, so `privacy_two_runs` compares two distinct
  addresses; and `leaky_prover_distinguishes`: with a prover that writes the
  address into its proof, one query gives the two wallets different views, so
  the view contains the proofs and the theorem needs its zero-knowledge
  hypothesis.

The hash functions here are constants. They have none of the properties the
assumptions are about; consistency of the hypotheses needs none.
-/

namespace EmailRecovery.Examples

/-- SHA-256 as the constant 0 and Poseidon2 as the constant 1. -/
def H₀ : Hashes := ⟨fun _ => 0, fun _ => 1⟩

def F₀ : Format where
  wellFormed := fun _ => True
  fromAddr := fun _ => some [1]
  subject := fun _ => some recoveryPhrase
  dkimDomain := fun _ => some [1]
  domainOf := fun _ => [1]
  lower := id
  hex := fun _ => []
  emsa := fun _ => 0

def E₀ : Encoding := ⟨fun _ => [], fun _ => some ⟨.lostKey, 1, 2, 3, 100⟩⟩

def cfg₀ : GuardianConfig where
  account := 2
  controller := 3
  commitment := 1
  registry := 4
  pin := none
  allowedActions := allowAll
  verifier := 5
  circuitId := 6

def x₀ : PublicInputs := publicInputs cfg₀ 0 1

def w₀ : Witness where
  header := []
  signature := 0
  modulus := 2 ^ 2047
  address := [1]
  dkimD := [1]
  rho := 0
  accountCode := 0
  leafDomain := [1]
  leafIndex := 0
  siblings := List.replicate treeDepth 0

def env₀ : Env where
  ledger := 50
  network := 1
  registry := fun _ root => some (root == 1)
  verifier := fun _ x π => if x = x₀ ∧ π = [] then .ok else .rejected

def ap₀ : Approval := ⟨[], 1, []⟩

set_option exponentiation.threshold 70000 in
theorem relation₀ : Relation H₀ F₀ x₀ w₀ where
  signed := ⟨Nat.pow_pos (by decide), Nat.le_refl _, Nat.pow_lt_pow_right (by decide) (by decide),
    by simp only [w₀, F₀, H₀]⟩
  wellFormed := trivial
  fromAddr := rfl
  addressLength := by decide
  opensCommitment := rfl
  dkimDomain := rfl
  aligned := rfl
  leafDomain := rfl
  subject := by simp [F₀]
  leafIndex := by decide
  siblings := by simp [w₀]
  leafDomainLength := by decide
  path := rfl

def extractor₀ : Extractor := fun _ _ => w₀

def assumptions₀ : SoundnessAssumptions H₀ cfg₀ env₀ (fun _ _ => True) where
  registry := ⟨fun _ _ => none, fun root h => by
    simp only [env₀, Option.some.injEq, beq_iff_eq] at h
    subst h
    rfl, fun _ _ _ _ _ => trivial⟩
  enrolledAddress := [1]
  enrolledCode := 0
  commitment := ⟨by decide, rfl⟩
  pinnedKeys := []
  pin := ⟨fun q hq => by simp [cfg₀] at hq, fun _ _ => trivial⟩

theorem check₀ :
    check H₀ E₀ cfg₀ env₀ 0 ap₀ [AuthContext.approval 3 .submitGuardian 0] = .ok () := rfl

/-- The extractor does not fail on the accepted approval. -/
theorem extraction₀ :
    ¬ ExtractionFails H₀ F₀ (env₀.verifier cfg₀.verifier) extractor₀ (approvalInputs H₀ cfg₀ ap₀)
      ap₀.proof :=
  fun h => h.2 relation₀

/-- Theorem 1 applies to these values. -/
example := soundness (F := F₀) extractor₀ assumptions₀ check₀

/-! ## A completed recovery with one email vote -/

open Perch

def W₀ : World := ⟨1, 2, 3, fun _ => 0, fun _ => 0⟩

/-- Guardian-only, `loss`, the guardian `7` alone at quorum 1, a 10-ledger delay. -/
def cfgP : Config where
  profile := .loss
  mode := .guardianOnly [7] 1
  controller := 3
  baseline := none
  delayLedgers := 10
  expiryLedgers := 100
  maxCancels := 1

def yes : Nat → Fn → Nat → Bool := fun _ _ _ => true

def st₁ : Step := ⟨0, .applyDoc 5 (some cfgP) 0, yes⟩
def st₂ : Step := ⟨1, .beginAttempt .lostKey 0 6 8 true, yes⟩
def st₃ : Step := ⟨2, .submitGuardian 0 .initiate 7, yes⟩
def st₄ : Step := ⟨12, .complete 8 6 cfgP, yes⟩

def after (s : State) (st : Step) : State :=
  match step W₀ s st with
  | .ok s' => s'
  | .error _ => s

def s₁ : State := after (State.init 5) st₁
def s₂ : State := after s₁ st₂
def s₃ : State := after s₂ st₃
def s₄ : State := after s₃ st₄

theorem trace₀ : Reachable W₀ 5 (Step.EvidenceOnlyFrom 7) s₄ :=
  .step st₄ (.step st₃ (.step st₂ (.step st₁ .init trivial rfl) trivial rfl) rfl rfl) trivial rfl

theorem trace₀_events : s₄.log.map (·.event) =
    [.epochAdvanced 1, .attemptBegun 0, .attemptAuthorized 0 12 112, .epochAdvanced 2,
      .recoveryCompleted 0] := rfl

theorem trace₀_completes : ∃ e ∈ s₄.log, e.event = .recoveryCompleted 0 := by
  have h : Event.recoveryCompleted 0 ∈ s₄.log.map (·.event) := by
    rw [trace₀_events]; decide
  obtain ⟨e, he, hev⟩ := List.mem_map.mp h
  exact ⟨e, he, hev⟩

/-- Theorem 4 applies to a completed recovery. -/
example := one_factor_safety trace₀

/-! ## Privacy compares two addresses, and the proofs are in the view -/

def dep₀ : Deployment := ⟨2, 3, 4, 5, 6, allowAll, some 100⟩

def mail₀ : Mail := ⟨[], 0, 2 ^ 2047, [], 0, [], 0, []⟩

def alice : Private := ⟨⟨ascii "alice@gmail.com", 1, []⟩, fun _ => mail₀⟩
def bob : Private := ⟨⟨ascii "bob@outlook.com", 2, []⟩, fun _ => mail₀⟩

/-- Tools in the ideal model. -/
def idealTools : Functionalities := ⟨fun _ _ => 1, fun _ _ => 2, fun _ _ => []⟩

theorem idealTools_ideal : idealTools.Ideal 1 2 (fun _ => []) :=
  ⟨fun _ _ => rfl, fun _ _ => rfl, fun _ _ => rfl⟩

/-- Two different addresses (and account codes) give every adversary the same
view. -/
theorem privacy₀ :
    alice.secret.address ≠ bob.secret.address ∧ alice.secret.accountCode ≠ bob.secret.accountCode ∧
      ∀ adv s₀ n, view H₀ E₀ W₀ 7 idealTools dep₀ alice adv s₀ n =
        view H₀ E₀ W₀ 7 idealTools dep₀ bob adv s₀ n :=
  ⟨by decide, by decide, fun adv s₀ n => privacy_two_runs idealTools_ideal alice bob adv s₀ n⟩

/-- A prover that writes the address into its proof. -/
def leakyTools : Functionalities := ⟨fun _ _ => 1, fun _ _ => 2, fun _ w => w.address⟩

/-- An adversary that asks for one approval. -/
def queryOnce : Adversary := fun _ _ => .query ⟨[], .pin⟩

/-- With the leaky prover, the two wallets' views differ after one query. -/
theorem leaky_prover_distinguishes :
    view H₀ E₀ W₀ 7 leakyTools dep₀ alice queryOnce (State.init 5) 1 ≠
      view H₀ E₀ W₀ 7 leakyTools dep₀ bob queryOnce (State.init 5) 1 := by
  intro h
  have h₂ := congrArg (fun v => v.2) h
  simp only [view, game, play, queryOnce, List.nil_append, List.cons.injEq, Obs.approval.injEq,
    approve, leakyTools, Private.witness, alice, bob, and_true] at h₂
  exact absurd (congrArg Approval.proof h₂) (by decide)

end EmailRecovery.Examples
