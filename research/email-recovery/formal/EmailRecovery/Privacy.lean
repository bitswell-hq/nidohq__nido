import EmailRecovery.Replay

/-!
# Theorem 2: privacy (spec §11.2 item 2), the part that is a property of the model

Noninterference over the address: everything the chain holds or computes about
an email guardian depends on the enrolled address only through the commitment
`C` and the salted pin root.

* `enroll_factors`: the configuration the wallet deploys is a function of the
  public deployment parameters, `C`, and the pin root.
* `check_noninterference`: the guardian's verdict on any approval, in any
  context and ledger, is the same for two enrollments with the same `C` and pin
  root.
* `publicInputs_enroll`: the proof's public inputs are `C`, the digest limbs and
  the key root, and nothing else.
* `privacy_noninterference`: for every run of the controller composed with the
  guardian, the chain's view (the guardian's configuration and the controller's
  state with its event log) is a function of the public values, `C` and the pin
  root.

The rest of §11.2 item 2 is computational and is not stated here: that `C` and
the pin root reveal nothing about the address and pinned keys when
`account_code` is uniform and secret (A3's random-function model of Poseidon2,
A6), and that the proofs reveal nothing beyond their public inputs (A4,
zero knowledge). Together with this theorem they give the indistinguishability
of the spec's statement.
-/

namespace EmailRecovery

/-- What the enrolling wallet keeps to the user (spec §5, A6): the address, the
account code, and the registry-format leaves of the pinned keys. -/
structure Secret where
  address : Bytes
  accountCode : Nat
  pinnedKeys : List Nat

/-- Everything else a guardian is deployed with. All of it is public on chain. -/
structure Deployment where
  account : Nat
  controller : Nat
  registry : Nat
  verifier : Nat
  circuitId : Nat
  allowedActions : Nat
  pinValidUntil : Option Nat

variable (H : Hashes)

/-- The configuration the honest wallet deploys (§5.3, §5.4, §7.4, §8.2). -/
def enroll (dep : Deployment) (sec : Secret) : GuardianConfig where
  account := dep.account
  controller := dep.controller
  commitment := commit H sec.address sec.accountCode
  registry := dep.registry
  pin := dep.pinValidUntil.map fun v => ⟨pinRoot H sec.accountCode sec.pinnedKeys, v⟩
  allowedActions := dep.allowedActions
  verifier := dep.verifier
  circuitId := dep.circuitId

/-- A configuration built from public values, a commitment and a pin root. -/
def deployFrom (dep : Deployment) (C root : Nat) : GuardianConfig where
  account := dep.account
  controller := dep.controller
  commitment := C
  registry := dep.registry
  pin := dep.pinValidUntil.map fun v => ⟨root, v⟩
  allowedActions := dep.allowedActions
  verifier := dep.verifier
  circuitId := dep.circuitId

/-- The deployed configuration depends on the secret only through `C` and the
pin root. -/
theorem enroll_factors (dep : Deployment) (sec : Secret) :
    enroll H dep sec =
      deployFrom dep (commit H sec.address sec.accountCode)
        (pinRoot H sec.accountCode sec.pinnedKeys) := rfl

variable {H}

/-- Two enrollments with the same commitment and pin root deploy the same
guardian, whatever their addresses. -/
theorem enroll_noninterference {dep : Deployment} {sec₁ sec₂ : Secret}
    (hC : commit H sec₁.address sec₁.accountCode = commit H sec₂.address sec₂.accountCode)
    (hP : pinRoot H sec₁.accountCode sec₁.pinnedKeys = pinRoot H sec₂.accountCode sec₂.pinnedKeys) :
    enroll H dep sec₁ = enroll H dep sec₂ := by
  rw [enroll_factors, enroll_factors, hC, hP]

/-- So the guardian's verdict on every approval, in every context and at every
ledger, is the same for both. -/
theorem check_noninterference {E : Encoding} {dep : Deployment} {sec₁ sec₂ : Secret}
    (hC : commit H sec₁.address sec₁.accountCode = commit H sec₂.address sec₂.accountCode)
    (hP : pinRoot H sec₁.accountCode sec₁.pinnedKeys = pinRoot H sec₂.accountCode sec₂.pinnedKeys)
    (env : Env) (p : Nat) (ap : Approval) (contexts : List AuthContext) :
    check H E (enroll H dep sec₁) env p ap contexts = check H E (enroll H dep sec₂) env p ap contexts := by
  rw [enroll_noninterference hC hP]

/-- The public inputs of every proof the guardian verifies are `C`, the digest
limbs, and the key root (§6.1): nothing else about the address. -/
theorem publicInputs_enroll (dep : Deployment) (sec : Secret) (d root : Nat) :
    publicInputs (enroll H dep sec) d root =
      ⟨commit H sec.address sec.accountCode, hi d, lo d, root⟩ := rfl

/-! ## The composed system -/

/-- One transaction of the controller composed with the email guardian at `G`:
the controller call, the ledger, the guardian's view of the ledger, the
approval in the guardian's authorization entry and its host payload, and every
other address's authorizations. -/
structure SysStep where
  ledger : Nat
  tx : Perch.Tx
  env : Env
  approval : Approval
  payload : Nat
  other : Nat → Fn → Nat → Bool

/-- The controller step, with `G`'s authorization decided by the guardian. -/
def SysStep.toStep (H : Hashes) (E : Encoding) (G : Nat) (cfg : GuardianConfig) (here : Nat)
    (st : SysStep) : Perch.Step :=
  ⟨st.ledger, st.tx, emailAuth H E G cfg st.env st.payload st.approval here st.other⟩

/-- Run the composed system; a refused transaction changes nothing. -/
def runSystem (H : Hashes) (E : Encoding) (W : Perch.World) (G : Nat) (cfg : GuardianConfig) :
    Perch.State → List SysStep → Perch.State
  | s, [] => s
  | s, st :: sts =>
    runSystem H E W G cfg
      (match Perch.step W s (st.toStep H E G cfg W.here) with
        | .ok s' => s'
        | .error _ => s) sts

/-- What the chain shows about an email guardian after a run: its
configuration, and the controller's state with its event log. -/
def observe (H : Hashes) (E : Encoding) (W : Perch.World) (G : Nat) (cfg : GuardianConfig)
    (s₀ : Perch.State) (sts : List SysStep) : GuardianConfig × Perch.State :=
  (cfg, runSystem H E W G cfg s₀ sts)

/-- **Theorem 2 (privacy, noninterference).** For every run, what the chain
shows about the guardian is a function of the public deployment parameters,
the transactions, the commitment `C`, and the pin root: the address enters only
through `C` and the pin root. -/
theorem privacy_noninterference (E : Encoding) (W : Perch.World) (G : Nat) (dep : Deployment) :
    ∃ f : Nat → Nat → Perch.State → List SysStep → GuardianConfig × Perch.State,
      ∀ (sec : Secret) (s₀ : Perch.State) (sts : List SysStep),
        observe H E W G (enroll H dep sec) s₀ sts =
          f (commit H sec.address sec.accountCode) (pinRoot H sec.accountCode sec.pinnedKeys) s₀ sts :=
  ⟨fun C root s₀ sts => observe H E W G (deployFrom dep C root) s₀ sts,
    fun sec s₀ sts => by rw [enroll_factors]⟩

/-- In two-run form: enrollments of two addresses with the same commitment and
pin root are indistinguishable to every run. -/
theorem privacy_two_runs {E : Encoding} {W : Perch.World} {G : Nat} {dep : Deployment}
    {sec₁ sec₂ : Secret}
    (hC : commit H sec₁.address sec₁.accountCode = commit H sec₂.address sec₂.accountCode)
    (hP : pinRoot H sec₁.accountCode sec₁.pinnedKeys = pinRoot H sec₂.accountCode sec₂.pinnedKeys)
    (s₀ : Perch.State) (sts : List SysStep) :
    observe H E W G (enroll H dep sec₁) s₀ sts = observe H E W G (enroll H dep sec₂) s₀ sts := by
  rw [enroll_noninterference hC hP]

end EmailRecovery
