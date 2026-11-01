import EmailRecovery.Statement
import EmailRecovery.Circuit

/-!
# The email guardian

The per-account guardian contract of spec §8 (`contracts/email-guardian`): its
configuration (§8.1), the constructor's refusals (§8.2), and `__check_auth` as
the ordered checks of §8.3, returning the first failure as the contract does.

`check` mirrors `contract.rs::check` branch for branch. The registry and the
verifier are other contracts, so they enter as the behaviour of the contract at
the configured address (`Env`). `accepted_of_check` turns a successful `check`
into the list of facts every later theorem uses, and `check_eq_ok_iff` shows the
list is exact.
-/

namespace EmailRecovery

/-- §8.1 `KeyPin`. -/
structure KeyPin where
  root : Nat
  validUntil : Nat
  deriving DecidableEq, Repr

/-- §8.1 `GuardianConfig`. Addresses are contract ids. -/
structure GuardianConfig where
  account : Nat
  controller : Nat
  commitment : Nat
  registry : Nat
  pin : Option KeyPin
  allowedActions : Nat
  verifier : Nat
  circuitId : Nat
  deriving DecidableEq, Repr

/-- `ALLOW_ALL`: bits 0 to 4. -/
def allowAll : Nat := 31

/-- The `ALLOW_*` bit of an action is bit `code - 1`. -/
def GuardianConfig.allows (c : GuardianConfig) (a : Action) : Bool :=
  c.allowedActions.testBit (a.code - 1)

theorem allowAll_allows (a : Action) : allowAll.testBit (a.code - 1) = true := by
  cases a <;> decide

/-! ## Construction (§8.2) -/

/-- `MAX_PIN_LIFETIME_LEDGERS`. -/
def maxPinLifetime : Nat := 6307200

/-- The construction variants of `EmailGuardianError`. -/
inductive ConstructError
  | accountNotContract
  | controllerNotContract
  | dependencyNotContract
  | nonCanonicalCommitment
  | invalidPin
  | invalidAllowedActions
  | circuitMismatch
  deriving DecidableEq, Repr

/-- What the constructor reads from the ledger. -/
structure DeployEnv where
  ledger : Nat
  isContract : Nat → Bool
  /-- `verifier.circuit_id()` of the contract at an address; `none` if the call
  fails. -/
  circuitIdOf : Nat → Option Nat

def pinInvalid (env : DeployEnv) : Option KeyPin → Bool
  | none => false
  | some p => !decide (Canonical p.root) || decide (p.validUntil < env.ledger) ||
      decide (env.ledger + maxPinLifetime < p.validUntil)

/-- `__constructor`'s checks, in `contract.rs::validate` order. A `Vec` of more
than one pin is unrepresentable here (`Option`). `allowed & !ALLOW_ALL != 0` on
a `u32` is `allowed > 31`. -/
def construct (env : DeployEnv) (c : GuardianConfig) : Except ConstructError Unit :=
  if !env.isContract c.account then .error .accountNotContract
  else if !env.isContract c.controller || c.controller == c.account then
    .error .controllerNotContract
  else if !env.isContract c.registry || !env.isContract c.verifier then
    .error .dependencyNotContract
  else if c.commitment = 0 ∨ ¬ Canonical c.commitment then .error .nonCanonicalCommitment
  else if pinInvalid env c.pin then .error .invalidPin
  else if c.allowedActions = 0 ∨ allowAll < c.allowedActions then .error .invalidAllowedActions
  else if env.circuitIdOf c.verifier = some c.circuitId then .ok ()
  else .error .circuitMismatch

/-! ## `__check_auth` (§8.3) -/

/-- What `verify_proof` returns: success, Perch's `ProofVerifierError`
(`VkParseError` or another variant), or a failed call. -/
inductive VerifyResult
  | ok
  | rejected
  | vkParseError
  | callFailed
  deriving DecidableEq, Repr

/-- The ledger and the other contracts as the guardian sees them during one
`__check_auth`. -/
structure Env where
  ledger : Nat
  network : Nat
  /-- `is_accepted_root` of the registry contract at an address, at this ledger;
  `none` when the call fails. -/
  registry : Nat → Nat → Option Bool
  /-- `verify_proof` of the verifier contract at an address. -/
  verifier : Nat → PublicInputs → Bytes → VerifyResult

/-- The `__check_auth` variants of `EmailGuardianError`. -/
inductive GuardianError
  | unexpectedContext
  | digestMismatch
  | malformedStatement
  | wrongNetwork
  | wrongAccount
  | wrongController
  | actionNotAllowed
  | wrongEntryPoint
  | statementExpired
  | nonCanonicalRoot
  | unknownRoot
  | registryUnavailable
  | proofRejected
  | verifierUnavailable
  deriving DecidableEq, Repr

/-- The ABI codes (`contracts/email-guardian/src/error.rs`). -/
def GuardianError.code : GuardianError → Nat
  | .unexpectedContext => 10
  | .digestMismatch => 11
  | .malformedStatement => 12
  | .wrongNetwork => 13
  | .wrongAccount => 14
  | .wrongController => 15
  | .actionNotAllowed => 16
  | .wrongEntryPoint => 17
  | .statementExpired => 18
  | .nonCanonicalRoot => 19
  | .unknownRoot => 20
  | .registryUnavailable => 21
  | .proofRejected => 22
  | .verifierUnavailable => 23

/-- §8.1 `EmailApproval`: the signature in the guardian's authorization entry. -/
structure Approval where
  statement : Bytes
  keyRoot : Nat
  proof : Bytes
  deriving DecidableEq, Repr

/-- `C ‖ digest_hi ‖ digest_lo ‖ key_root`, each taken from the configuration,
the authorized digest, and the root check 11 accepted (§6.1, §8.3 check 12). -/
def publicInputs (c : GuardianConfig) (d root : Nat) : PublicInputs :=
  ⟨c.commitment, hi d, lo d, root⟩

/-- The pin accepts `root` at ledger `L`. -/
def GuardianConfig.pinned (c : GuardianConfig) (L root : Nat) : Bool :=
  match c.pin with
  | some p => p.root == root && decide (L ≤ p.validUntil)
  | none => false

/-- Check 11. -/
def checkRoot (c : GuardianConfig) (env : Env) (root : Nat) : Except GuardianError Unit :=
  if c.pinned env.ledger root then .ok ()
  else match env.registry c.registry root with
    | some true => .ok ()
    | some false => .error .unknownRoot
    | none => .error .registryUnavailable

/-- Check 12. -/
def checkProof (c : GuardianConfig) (env : Env) (d : Nat) (ap : Approval) :
    Except GuardianError Unit :=
  match env.verifier c.verifier (publicInputs c d ap.keyRoot) ap.proof with
  | .ok => .ok ()
  | .rejected => .error .proofRejected
  | .vkParseError => .error .verifierUnavailable
  | .callFailed => .error .verifierUnavailable

/-- `__check_auth(signature_payload, approval, auth_contexts)`: checks 1 to 12
in order, returning the first failure. The host's `signature_payload` is not
read. -/
def check (H : Hashes) (E : Encoding) (c : GuardianConfig) (env : Env) (_payload : Nat)
    (ap : Approval) : List AuthContext → Except GuardianError Unit
  | [.call contract fn [.bytes32 d]] =>
    if contract ≠ c.controller then .error .unexpectedContext
    else if H.sha256 ap.statement ≠ d then .error .digestMismatch
    else match E.parseView ap.statement with
      | none => .error .malformedStatement
      | some v =>
        if v.network ≠ env.network then .error .wrongNetwork
        else if v.account ≠ c.account then .error .wrongAccount
        else if v.controller ≠ c.controller then .error .wrongController
        else if c.allows v.action = false then .error .actionNotAllowed
        else if fn ≠ entryPoint v.action then .error .wrongEntryPoint
        else if v.validUntil < env.ledger then .error .statementExpired
        else if ¬ Canonical ap.keyRoot then .error .nonCanonicalRoot
        else match checkRoot c env ap.keyRoot with
          | .error e => .error e
          | .ok () => checkProof c env d ap
  | _ => .error .unexpectedContext

/-! ## What acceptance establishes -/

/-- Check 11's rule: the pin with the ledger at most its `valid_until_ledger`,
or a root the registry accepts at this ledger. -/
def RootAccepted (c : GuardianConfig) (env : Env) (root : Nat) : Prop :=
  (∃ p, c.pin = some p ∧ p.root = root ∧ env.ledger ≤ p.validUntil) ∨
    env.registry c.registry root = some true

/-- Every check passed: the facts `check` returning `ok` amounts to. -/
structure Accepted (H : Hashes) (E : Encoding) (c : GuardianConfig) (env : Env)
    (ap : Approval) (contexts : List AuthContext) (fn : Fn) (d : Nat) (v : View) : Prop where
  /-- 1 -/
  context : contexts = [AuthContext.approval c.controller fn d]
  /-- 2 -/
  digest : H.sha256 ap.statement = d
  /-- 3 -/
  parsed : E.parseView ap.statement = some v
  /-- 4 -/
  network : v.network = env.network
  /-- 5 -/
  account : v.account = c.account
  /-- 6 -/
  controller : v.controller = c.controller
  /-- 7 -/
  allowed : c.allows v.action = true
  /-- 8 -/
  entryPoint : fn = entryPoint v.action
  /-- 9 -/
  fresh : env.ledger ≤ v.validUntil
  /-- 10 -/
  canonicalRoot : Canonical ap.keyRoot
  /-- 11 -/
  root : RootAccepted c env ap.keyRoot
  /-- 12 -/
  proof : env.verifier c.verifier (publicInputs c d ap.keyRoot) ap.proof = .ok

variable {H : Hashes} {E : Encoding} {c : GuardianConfig} {env : Env} {p : Nat}
  {ap : Approval} {contexts : List AuthContext}

theorem checkRoot_ok {root : Nat} (h : checkRoot c env root = .ok ()) :
    RootAccepted c env root := by
  unfold checkRoot at h
  split at h
  · rename_i hp
    left
    unfold GuardianConfig.pinned at hp
    split at hp
    · rename_i q hq
      simp only [Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hp
      exact ⟨q, hq, hp.1, hp.2⟩
    · contradiction
  · split at h
    · rename_i hr
      exact Or.inr hr
    · contradiction
    · contradiction

theorem checkRoot_of_rootAccepted {root : Nat} (h : RootAccepted c env root) :
    checkRoot c env root = .ok () := by
  unfold checkRoot
  rcases h with ⟨q, hq, hroot, hl⟩ | h
  · have : c.pinned env.ledger root = true := by
      simp [GuardianConfig.pinned, hq, hroot, hl]
    simp [this]
  · split
    · rfl
    · simp [h]

theorem checkProof_ok {d : Nat} (h : checkProof c env d ap = .ok ()) :
    env.verifier c.verifier (publicInputs c d ap.keyRoot) ap.proof = .ok := by
  unfold checkProof at h
  split at h <;> first | assumption | contradiction

/-- A successful `check` establishes every check of §8.3. -/
theorem accepted_of_check (h : check H E c env p ap contexts = .ok ()) :
    ∃ fn d v, Accepted H E c env ap contexts fn d v := by
  unfold check at h
  split at h
  · rename_i contract fn d
    by_cases h1 : contract = c.controller
    · subst h1
      by_cases h2 : H.sha256 ap.statement = d
      · simp only [ne_eq, not_true_eq_false, ite_false, h2] at h
        split at h
        · contradiction
        · rename_i v hv
          by_cases h4 : v.network = env.network
          · by_cases h5 : v.account = c.account
            · by_cases h6 : v.controller = c.controller
              · by_cases h7 : c.allows v.action = true
                · by_cases h8 : fn = entryPoint v.action
                  · by_cases h9 : v.validUntil < env.ledger
                    · simp [h4, h5, h6, h7, h8, h9] at h
                    · by_cases h10 : Canonical ap.keyRoot
                      · simp only [h4, h5, h6, h7, h8, h9, h10, not_true_eq_false,
                          Bool.true_eq_false, ite_false] at h
                        split at h
                        · contradiction
                        · rename_i hroot
                          exact ⟨fn, d, v, rfl, h2, hv, h4, h5, h6, h7, h8,
                            Nat.le_of_not_lt h9, h10, checkRoot_ok hroot, checkProof_ok h⟩
                      · simp [h4, h5, h6, h7, h8, h9, h10] at h
                  · simp [h4, h5, h6, h7, h8] at h
                · simp [h4, h5, h6, h7] at h
              · simp [h4, h5, h6] at h
            · simp [h4, h5] at h
          · simp [h4] at h
      · simp [h2] at h
    · simp [h1] at h
  · contradiction

/-- The facts of `Accepted` are exactly what `check` requires. -/
theorem check_eq_ok_iff :
    check H E c env p ap contexts = .ok () ↔ ∃ fn d v, Accepted H E c env ap contexts fn d v := by
  refine ⟨accepted_of_check, ?_⟩
  rintro ⟨fn, d, v, h⟩
  rw [h.context]
  have hfresh : ¬ v.validUntil < env.ledger := Nat.not_lt.mpr h.fresh
  simp only [check, AuthContext.approval, ne_eq, not_true_eq_false, ite_false, h.digest,
    h.parsed, h.network, h.account, h.controller, h.allowed, h.entryPoint, hfresh,
    h.canonicalRoot, Bool.true_eq_false, checkRoot_of_rootAccepted h.root]
  simp [checkProof, h.proof]

/-- The guardian never reads the host's signature payload, so an approval
re-wrapped in another authorization entry gets the same verdict. -/
theorem check_payload_irrelevant (p₁ p₂ : Nat) :
    check H E c env p₁ ap contexts = check H E c env p₂ ap contexts := rfl

end EmailRecovery
