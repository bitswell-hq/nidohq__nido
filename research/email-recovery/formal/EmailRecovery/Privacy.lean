import EmailRecovery.Replay

/-!
# Theorem 2: privacy (spec §11.2 item 2)

Two results about what the chain, and anyone watching it and its transactions,
learns about an email guardian's enrolled address.

**Simulation** (`privacy_simulation`, `privacy_two_runs`). An adversary drives
the email guardian composed with Perch's controller. It chooses every
transaction from everything it has seen so far, and it asks the honest wallet
for approvals of statements of its choice, which it sees in full, proof bytes
included, and may then submit, copy into transactions of its own, or submit
ahead of anyone else. In the ideal model of the wallet's cryptographic tools, a
simulator that holds nothing about the user computes the adversary's whole view
from two handles, the proof system's simulator and the public statements: the
deployed configuration, every approval the wallet hands out, every transaction,
the guardian's verdict on its approval in every authorization context, and the
controller's result with its state and events. So any two private states of the
wallet (different addresses, account codes, pinned keys, emails and blinding
values) give the same view.

The ideal model (`Functionalities.Ideal`): the commitment and the pin root are
handles drawn independently of the secret, and an honest proof is the proof
system's simulator applied to the proof's public inputs alone. The step from the
ideal model to the real system is computational and is an assumption, not a
theorem here: with `account_code` uniform and secret (A6) and Poseidon2 a random
function (A3), the pair `(C, pin root)` is indistinguishable from two uniform
handles; and zero knowledge of UltraHonk (A4) makes an honest proof of a valid
witness indistinguishable from the simulator's output on its public inputs.
`Examples.leaky_prover_distinguishes` shows that the view contains the proofs:
with a prover that writes the address into its proof, one query tells two
addresses apart.

The public statement of an approval is its statement bytes and the source of its
root: the guardian's pin, or a named registry root (spec §7.7,
`chooseKeyPath`). Both are part of the approval, so both are revealed, as spec
§11.2 item 2 says.

**Structural** (`structural_noninterference`). For any fixed sequence of
transactions, the guardian's configuration, its verdicts, and the controller's
results, states and events depend on the enrolled secret only through `C` and
the pin root: the contracts store and emit nothing about the address beyond
them. This holds of the real functions with no assumption. It says nothing about
the proofs a transaction carries, which are among its arguments; the simulation
theorem covers those.
-/

namespace EmailRecovery

/-- What the enrolling wallet keeps to the user (spec §5, A6): the address, the
account code, and the keys it pinned. -/
structure Secret where
  address : Bytes
  accountCode : Nat
  pinnedKeys : List (Bytes × Nat)

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

/-- The public inputs of every proof the guardian verifies are `C`, the digest
limbs, and the key root (§6.1): nothing else about the address. -/
theorem publicInputs_enroll (dep : Deployment) (sec : Secret) (d root : Nat) :
    publicInputs (enroll H dep sec) d root =
      ⟨commit H sec.address sec.accountCode, hi d, lo d, root⟩ := rfl

/-! ## The honest wallet -/

/-- The wallet's cryptographic tools: the commitment, the pin root, and the
prover. -/
structure Functionalities where
  commit : Bytes → Nat → Nat
  pinRoot : Nat → List (Bytes × Nat) → Nat
  prove : PublicInputs → Witness → Bytes

/-- The real tools: the spec's Poseidon2 formulas (§5.3, §7.4) and a prover. -/
def Functionalities.real (prove : PublicInputs → Witness → Bytes) : Functionalities :=
  ⟨EmailRecovery.commit H, EmailRecovery.pinRoot H, prove⟩

/-- The ideal model: the commitment is the handle `hC` and the pin root the
handle `hR` whatever the secret, and every proof is `sim` of its public inputs,
whatever the witness. -/
structure Functionalities.Ideal (Fs : Functionalities) (hC hR : Nat) (sim : PublicInputs → Bytes) :
    Prop where
  commit : ∀ address code, Fs.commit address code = hC
  pinRoot : ∀ code keys, Fs.pinRoot code keys = hR
  prove : ∀ x w, Fs.prove x w = sim x

/-- The configuration the wallet deploys with the tools `Fs`. -/
def enrollWith (Fs : Functionalities) (dep : Deployment) (sec : Secret) : GuardianConfig :=
  deployFrom dep (Fs.commit sec.address sec.accountCode) (Fs.pinRoot sec.accountCode sec.pinnedKeys)

theorem enroll_real (prove : PublicInputs → Witness → Bytes) (dep : Deployment) (sec : Secret) :
    enroll H dep sec = enrollWith (Functionalities.real H prove) dep sec := rfl

/-- Where an approval's root comes from (§7.7 `chooseKeyPath`): the guardian's
pin, or a registry root. -/
inductive Source
  | pin
  | registry (root : Nat)

/-- The root a source names under configuration `cfg`. -/
def Source.root (cfg : GuardianConfig) : Source → Nat
  | .pin =>
    match cfg.pin with
    | some q => q.root
    | none => 0
  | .registry root => root

/-- A request for one approval: the statement bytes (Perch's encoding of a
statement the controller built) and the source of the root. Both end up in the
approval, so both are public. -/
structure Request where
  statement : Bytes
  source : Source

/-- The recovery email, blinding value and key path the wallet proves one
request with. -/
structure Mail where
  header : Bytes
  signature : Nat
  modulus : Nat
  dkimD : Bytes
  rho : Nat
  leafDomain : Bytes
  leafIndex : Nat
  siblings : List Nat

/-- Everything the honest wallet holds about the user: the enrollment secret,
and the email it proves each request with. -/
structure Private where
  secret : Secret
  mail : Request → Mail

/-- The circuit witness the wallet builds for a request (§6.2). -/
def Private.witness (priv : Private) (q : Request) : Witness where
  header := (priv.mail q).header
  signature := (priv.mail q).signature
  modulus := (priv.mail q).modulus
  address := priv.secret.address
  dkimD := (priv.mail q).dkimD
  rho := (priv.mail q).rho
  accountCode := priv.secret.accountCode
  leafDomain := (priv.mail q).leafDomain
  leafIndex := (priv.mail q).leafIndex
  siblings := (priv.mail q).siblings

/-- The honest wallet's approval for request `q` under configuration `cfg`
(§6.5): the statement, the root its source names, and a proof, for the public
inputs the guardian will build, of the witness from the wallet's email and
secret. -/
def approve (Fs : Functionalities) (cfg : GuardianConfig) (priv : Private) (q : Request) : Approval :=
  ⟨q.statement, q.source.root cfg,
    Fs.prove (publicInputs cfg (H.sha256 q.statement) (q.source.root cfg)) (priv.witness q)⟩

/-- The simulator's approval for request `q`: the same statement and root, and
`sim` of the public inputs. It reads nothing private. -/
def simApprove (sim : PublicInputs → Bytes) (cfg : GuardianConfig) (q : Request) : Approval :=
  ⟨q.statement, q.source.root cfg, sim (publicInputs cfg (H.sha256 q.statement) (q.source.root cfg))⟩

/-! ## The composed system and the adversary's view -/

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
def SysStep.toStep (E : Encoding) (G : Nat) (cfg : GuardianConfig) (here : Nat)
    (st : SysStep) : Perch.Step :=
  ⟨st.ledger, st.tx, emailAuth H E G cfg st.env st.payload st.approval here st.other⟩

/-- What a move shows: an approval the wallet handed out, or a transaction with
the guardian's verdict on its approval in every context and the controller's
result (its refusal, or the new state with its event log). -/
inductive Obs
  | approval (ap : Approval)
  | tx (st : SysStep) (verdict : List AuthContext → Except GuardianError Unit)
      (result : Perch.Result)

/-- What the adversary does next: ask the wallet for an approval, or run a
transaction of its choice, which may carry any approval, including a copy of one
the wallet handed out. -/
inductive Move
  | query (q : Request)
  | submit (st : SysStep)

/-- An adversary: its next move as a function of the deployed configuration
and everything it has observed. -/
abbrev Adversary := GuardianConfig → List Obs → Move

/-- Run one transaction in controller state `s`; a refused transaction changes
nothing. -/
def submitStep (E : Encoding) (W : Perch.World) (G : Nat) (cfg : GuardianConfig) (s : Perch.State)
    (st : SysStep) : Perch.State × Obs :=
  let r := Perch.step W s (st.toStep H E G cfg W.here)
  ((match r with
    | .ok s' => s'
    | .error _ => s), .tx st (check H E cfg st.env st.payload st.approval) r)

/-- One move; `wallet` answers queries. -/
def play (E : Encoding) (W : Perch.World) (G : Nat) (cfg : GuardianConfig)
    (wallet : Request → Approval) (s : Perch.State) : Move → Perch.State × Obs
  | .query q => (s, .approval (wallet q))
  | .submit st => submitStep H E W G cfg s st

/-- `n` moves of the adversary from controller state `s₀`: the state and the
observations, in order. -/
def game (E : Encoding) (W : Perch.World) (G : Nat) (cfg : GuardianConfig)
    (wallet : Request → Approval) (adv : Adversary) (s₀ : Perch.State) :
    Nat → Perch.State × List Obs
  | 0 => (s₀, [])
  | n + 1 =>
    let prev := game E W G cfg wallet adv s₀ n
    let next := play H E W G cfg wallet prev.1 (adv cfg prev.2)
    (next.1, prev.2 ++ [next.2])

/-- The adversary's view after `n` moves, the wallet holding `priv` and using
the tools `Fs`: the deployed configuration and every observation. -/
def view (E : Encoding) (W : Perch.World) (G : Nat) (Fs : Functionalities) (dep : Deployment)
    (priv : Private) (adv : Adversary) (s₀ : Perch.State) (n : Nat) : GuardianConfig × List Obs :=
  (enrollWith Fs dep priv.secret,
    (game H E W G (enrollWith Fs dep priv.secret)
      (approve H Fs (enrollWith Fs dep priv.secret) priv) adv s₀ n).2)

/-- The simulator's view: the configuration deployed from the handles, and the
same game with `simApprove` answering queries. Its arguments are public, the
handles, and `sim`. -/
def simView (E : Encoding) (W : Perch.World) (G : Nat) (dep : Deployment) (hC hR : Nat)
    (sim : PublicInputs → Bytes) (adv : Adversary) (s₀ : Perch.State) (n : Nat) :
    GuardianConfig × List Obs :=
  (deployFrom dep hC hR,
    (game H E W G (deployFrom dep hC hR) (simApprove H sim (deployFrom dep hC hR)) adv s₀ n).2)

variable {H} {E : Encoding} {W : Perch.World} {G : Nat} {Fs : Functionalities} {dep : Deployment}
  {hC hR : Nat} {sim : PublicInputs → Bytes}

theorem enrollWith_ideal (hI : Fs.Ideal hC hR sim) (sec : Secret) :
    enrollWith Fs dep sec = deployFrom dep hC hR := by
  simp only [enrollWith, hI.commit, hI.pinRoot]

theorem approve_ideal (hI : Fs.Ideal hC hR sim) (cfg : GuardianConfig) (priv : Private) :
    approve H Fs cfg priv = simApprove H sim cfg := by
  funext q
  simp only [approve, simApprove, hI.prove]

/-- **Theorem 2 (privacy, simulation).** In the ideal model, for every private
state of the wallet, every adversary, every initial controller state and every
number of moves, the adversary's view is the simulator's, which is computed
from the public deployment parameters, the handles, `sim` and the adversary's
own moves alone. -/
theorem privacy_simulation (hI : Fs.Ideal hC hR sim) (priv : Private) (adv : Adversary)
    (s₀ : Perch.State) (n : Nat) :
    view H E W G Fs dep priv adv s₀ n = simView H E W G dep hC hR sim adv s₀ n := by
  simp only [view, simView, enrollWith_ideal hI, approve_ideal hI]

/-- In two-run form: in the ideal model, two wallets holding any two private
states (different addresses and account codes included) give every adversary
the same view. -/
theorem privacy_two_runs (hI : Fs.Ideal hC hR sim) (priv₁ priv₂ : Private) (adv : Adversary)
    (s₀ : Perch.State) (n : Nat) :
    view H E W G Fs dep priv₁ adv s₀ n = view H E W G Fs dep priv₂ adv s₀ n := by
  rw [privacy_simulation hI, privacy_simulation hI]

/-! ## The structural lemma -/

variable (H E W G)

/-- Run a fixed sequence of transactions: one observation each. -/
def runFixed (cfg : GuardianConfig) : Perch.State → List SysStep → List Obs
  | _, [] => []
  | s, st :: sts => (submitStep H E W G cfg s st).2 :: runFixed cfg (submitStep H E W G cfg s st).1 sts

/-- **Structural lemma.** For any fixed sequence of transactions, the guardian's
configuration, its verdict on every transaction's approval in every context, and
the controller's results, states and events are a function of the public
deployment parameters, the initial state, the transactions, `C` and the pin
root: the contracts store and emit nothing about the address beyond `C` and the
pin root. -/
theorem structural_noninterference (dep : Deployment) :
    ∃ f : Nat → Nat → Perch.State → List SysStep → GuardianConfig × List Obs,
      ∀ (sec : Secret) (s₀ : Perch.State) (sts : List SysStep),
        (enroll H dep sec, runFixed H E W G (enroll H dep sec) s₀ sts) =
          f (commit H sec.address sec.accountCode) (pinRoot H sec.accountCode sec.pinnedKeys) s₀ sts :=
  ⟨fun C root s₀ sts => (deployFrom dep C root, runFixed H E W G (deployFrom dep C root) s₀ sts),
    fun sec s₀ sts => by rw [enroll_factors]⟩

end EmailRecovery
