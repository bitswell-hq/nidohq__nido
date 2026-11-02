import EmailRecovery.Statement

/-!
# Perch's recovery controller

The per-account state machine of Perch's recovery controller
(`vendor/perch/docs/recovery/spec.md`, cited as Perch §N;
`vendor/perch/crates/perch-recovery/src/contract.rs`): configurations with
guardian sets, quorum, profile and timing (§3); attempts with ids that are never
reused (§6.3 T1); guardian votes counted once per attempt and domain (T2) or
per change digest (§5); promotion (T4) with its delay; completion (T5);
cancellation by evidence (T6) and by the owner (T7); configuration changes
through `apply_doc` (§10, T9) and executed upgrades (§12), each bumping the
epoch (§3.3).

Modelling choices, each of which only adds behaviours, so a safety property of
this model holds of the contract:

* Ledger arithmetic is unbounded; Perch refuses on `u32` overflow
  (`LedgerOverflow`).
* Storage never expires. Perch's temporary entries expire (§3.6), but the
  only record Perch keeps in them is a collecting attempt, which `save`
  keeps alive until at least its evidence deadline; it expires only once
  the attempt is no longer live, when every transition that changes it
  already refuses (`research/email-recovery/formal/README.md`).
* What the controller learns from other contracts is a field of the call: the
  doc compiler's `derive_target` verdict and target digests at T1, the ZK
  adapter's verdict, and whether a guardian's authorization entry is accepted
  for a digest (`Step.auth`).
* A configuration is compared by value where Perch compares its `config_hash`
  (`World.configHash`), which agree unless SHA-256 collides on two canonical
  recovery members (Perch §3.2). A target's ZK rotation (§7.3 rule 4) is not
  represented, so a derived target's configuration is the current one.
* Owner-authorized calls (`apply_doc`, `cancel_recovery`, `execute_upgrade`)
  are transactions anyone holding the owner key can make; the model allows them
  in every trace. Scheduling an upgrade writes no controller state and is
  omitted; executing one is `executeUpgrade`.

Beside each event the controller emits, the log records the configuration that
was stored when the transaction began (`Entry.config`). Perch emits the event
alone; the configuration is recorded so that theorems can name the
configuration an attempt was authorized under.
-/

namespace EmailRecovery.Perch

/-- Perch §3.1 `profile`. -/
inductive Profile
  | loss
  | «protected»
  deriving DecidableEq, Repr

/-- Perch §3.1 `mode`; the ZK factor's fields are not represented. -/
inductive Mode
  | guardianOnly (guardians : List Nat) (quorum : Nat)
  | zkOnly
  | combined (guardians : List Nat) (quorum : Nat)
  deriving DecidableEq, Repr

/-- The guardian factor of a mode, if any. -/
def Mode.guardianSet : Mode → Option (List Nat × Nat)
  | .guardianOnly gs q => some (gs, q)
  | .zkOnly => none
  | .combined gs q => some (gs, q)

/-- Whether a mode has a ZK factor. -/
def Mode.hasZk : Mode → Bool
  | .guardianOnly _ _ => false
  | .zkOnly => true
  | .combined _ _ => true

/-- Perch §3.1, the compiled `recovery` member. -/
structure Config where
  profile : Profile
  mode : Mode
  controller : Nat
  baseline : Option Nat
  delayLedgers : Nat
  expiryLedgers : Nat
  maxCancels : Nat
  deriving DecidableEq, Repr

/-- `check_config`: non-zero timing terms, and a reachable quorum of guardians
that does not include the account (Perch §3.1, §15). -/
def checkConfig (account : Nat) (c : Config) : Bool :=
  decide (0 < c.delayLedgers) && decide (0 < c.expiryLedgers) && decide (0 < c.maxCancels) &&
    match c.mode.guardianSet with
    | none => true
    | some (gs, q) => decide (account ∉ gs) && decide (1 ≤ q) && decide (q ≤ gs.length)

/-- The fixed values of one controller instance serving one account. -/
structure World where
  network : Nat
  account : Nat
  /-- This controller's address. -/
  here : Nat
  /-- `config_hash` of a recovery member (Perch §3.2). -/
  configHash : Config → Nat
  /-- `digest = sha256(encoding)` (Perch §4). -/
  digest : Statement → Nat

/-- Perch §6.3 T1: what an attempt replaces. -/
inductive Kind
  | lostKey
  | compromise
  deriving DecidableEq, Repr

/-- `EvidenceDomain`. -/
inductive Domain
  | initiate
  | cancel
  deriving DecidableEq, Repr

/-- Perch §6.2 stored attempt states. -/
inductive AttemptState
  | collecting
  | authorized
  | completed
  | cancelled
  | invalidated
  deriving DecidableEq, Repr

/-- Perch's `Attempt` record (§6.3 T1). -/
structure Attempt where
  id : Nat
  kind : Kind
  epoch : Nat
  createdAt : Nat
  evidenceDeadline : Nat
  cancelUntil : Nat
  authorizedAt : Nat
  executableAfter : Nat
  expiresAt : Nat
  sourceDoc : Nat
  targetDoc : Nat
  targetBytes : Nat
  targetConfig : Config
  replacements : Nat
  state : AttemptState
  guardians : List Nat
  zk : Bool
  cancelGuardians : List Nat
  cancelZk : Bool

/-- Recorded reconfiguration or upgrade evidence for one digest (Perch §5). -/
structure ChangeRecord where
  guardians : List Nat
  zk : Bool

/-- The controller's events that the model tracks (Perch `contract.rs`). -/
inductive Event
  | attemptBegun (id : Nat)
  | attemptAuthorized (id executableAfter expiresAt : Nat)
  | attemptInvalidated (id : Nat)
  | attemptCancelled (id : Nat) (counted : Bool)
  | recoveryCompleted (id : Nat)
  | epochAdvanced (epoch : Nat)
  | changeEvidenceRecorded (digest : Nat)
  deriving DecidableEq, Repr

/-- One emitted event, the ledger it was emitted at, and the configuration that
was stored when its transaction began. -/
structure Entry where
  ledger : Nat
  event : Event
  config : Option Config

/-- The controller's storage for the account (Perch §3.6), the account's applied
document identity (read at T1 and T4), and the event log. -/
structure State where
  config : Option Config
  epoch : Nat
  nextAttempt : Nat
  invalidateBelow : Nat
  authorized : Option Nat
  attempts : Nat → Option Attempt
  cancels : Nat
  approvals : Nat → Option ChangeRecord
  appliedDoc : Nat
  log : List Entry

/-- An account that has applied document `doc` and never enrolled. -/
def State.init (doc : Nat) : State where
  config := none
  epoch := 0
  nextAttempt := 0
  invalidateBelow := 0
  authorized := none
  attempts := fun _ => none
  cancels := 0
  approvals := fun _ => none
  appliedDoc := doc
  log := []

/-- The refusals of the controller (`RecoveryError`) the model distinguishes,
and `notAuthorized` for a guardian authorization the host refuses. -/
inductive Error
  | notEnrolled
  | attemptAuthorized
  | invalidReplacements
  | noBaseline
  | modeHasNoGuardians
  | modeHasNoZk
  | notAGuardian
  | noSuchAttempt
  | attemptNotLive
  | attemptNotCollecting
  | alreadyCounted
  | evidenceExpired
  | invalidStatement
  | zkEvidenceRejected
  | maxCancelsReached
  | notExecutableYet
  | wrongTarget
  | ownerCancelRefused
  | invalidConfiguration
  | conditionNotMet
  | staleUpgrade
  | notAuthorized
  deriving DecidableEq, Repr

/-- A transition either refuses and writes nothing or succeeds with a new
state (Perch spec, "Refuse"). -/
abbrev Result := Except Error State

namespace State

/-- Write an attempt record under its id. -/
def put (s : State) (a : Attempt) : State :=
  { s with attempts := fun i => if i = a.id then some a else s.attempts i }

/-- Append an event. -/
def emit (s : State) (L : Nat) (c : Option Config) (e : Event) : State :=
  { s with log := s.log ++ [⟨L, e, c⟩] }

/-- Perch §6.2 "live". -/
def isLive (s : State) (L : Nat) (a : Attempt) : Bool :=
  a.epoch == s.epoch &&
    match a.state with
    | .collecting => decide (s.invalidateBelow ≤ a.id) && decide (L ≤ a.evidenceDeadline)
    | .authorized => s.authorized == some a.id && decide (L < a.expiresAt)
    | _ => false

/-- `authorized_live`: the recorded authorized attempt, if it is live. -/
def authorizedLive (s : State) (L : Nat) : Option Attempt :=
  match s.authorized with
  | none => none
  | some id =>
    match s.attempts id with
    | none => none
    | some a => if s.isLive L a then some a else none

end State

namespace Attempt

def votes (a : Attempt) : Domain → List Nat
  | .initiate => a.guardians
  | .cancel => a.cancelGuardians

def addVote (a : Attempt) (g : Nat) : Domain → Attempt
  | .initiate => { a with guardians := a.guardians ++ [g] }
  | .cancel => { a with cancelGuardians := a.cancelGuardians ++ [g] }

def hasZk (a : Attempt) : Domain → Bool
  | .initiate => a.zk
  | .cancel => a.cancelZk

def addZk (a : Attempt) : Domain → Attempt
  | .initiate => { a with zk := true }
  | .cancel => { a with cancelZk := true }

end Attempt

/-! ## Statements (Perch §4 "Construction") -/

/-- A statement the controller builds from its own state. -/
def mkStatement (W : World) (c : Config) (epoch validUntil : Nat) (subject : Subject) :
    Statement where
  network := W.network
  account := W.account
  controller := W.here
  epoch := epoch
  configHash := W.configHash c
  delayLedgers := c.delayLedgers
  expiryLedgers := c.expiryLedgers
  validUntil := validUntil
  subject := subject

/-- `initiation_statement`. -/
def initiationStatement (W : World) (c : Config) (a : Attempt) : Statement :=
  mkStatement W c a.epoch a.evidenceDeadline <|
    match a.kind with
    | .lostKey => .lostKey a.id a.sourceDoc a.targetDoc a.replacements
    | .compromise => .compromise a.id a.sourceDoc a.targetDoc a.replacements

/-- `attempt_statement`: the statement evidence for an attempt approves in a
domain. A cancellation binds the attempt's own initiation digest. -/
def attemptStatement (W : World) (c : Config) (a : Attempt) : Domain → Statement
  | .initiate => initiationStatement W c a
  | .cancel => mkStatement W c a.epoch a.cancelUntil
      (.cancel a.id (W.digest (initiationStatement W c a)))

/-- `check_fresh` (Perch §4 "Freshness"). -/
def fresh (L : Nat) (S : Statement) : Bool :=
  decide (L ≤ S.validUntil) &&
    match S.action with
    | .reconfigure | .upgrade => decide (S.validUntil - L ≤ S.expiryLedgers)
    | _ => true

/-! ## Conditions (Perch §5) -/

/-- `initiation_met`. -/
def initiationMet (c : Config) (a : Attempt) : Bool :=
  (match c.mode.guardianSet with
    | none => true
    | some (_, q) => decide (q ≤ a.guardians.length)) &&
  (!c.mode.hasZk || a.zk)

/-- `cancellation_met`. -/
def cancellationMet (c : Config) (a : Attempt) : Bool :=
  (match c.mode.guardianSet with
    | none => true
    | some (_, q) => decide (q ≤ a.cancelGuardians.length)) &&
  (!c.mode.hasZk || a.cancelZk)

/-- `require_condition`'s count over a change record: enrolled guardians only. -/
def conditionMet (c : Config) (r : ChangeRecord) : Bool :=
  (match c.mode.guardianSet with
    | none => true
    | some (gs, q) => decide (q ≤ (r.guardians.filter (· ∈ gs)).length)) &&
  (!c.mode.hasZk || r.zk)

/-! ## Transitions (Perch §6.3, §5, §10, §12) -/

section Transitions

variable (W : World)

/-- The source identity T1 reads (Perch §7.2): the applied document for
lost-key, the enrolled baseline for compromise. -/
def sourceOf (s : State) (c : Config) : Kind → Option Nat
  | .lostKey => some s.appliedDoc
  | .compromise => c.baseline

/-- The record T1 writes. The target configuration is the current one: a
derived target keeps the current recovery member (Perch §7.1, §7.3 rule 4). -/
def newAttempt (s : State) (L : Nat) (c : Config) (kind : Kind)
    (source replacements targetDoc targetBytes : Nat) : Attempt where
  id := s.nextAttempt
  kind := kind
  epoch := s.epoch
  createdAt := L
  evidenceDeadline := L + c.expiryLedgers
  cancelUntil := L + c.expiryLedgers + c.delayLedgers + c.expiryLedgers
  authorizedAt := 0
  executableAfter := 0
  expiresAt := 0
  sourceDoc := source
  targetDoc := targetDoc
  targetBytes := targetBytes
  targetConfig := c
  replacements := replacements
  state := .collecting
  guardians := []
  zk := false
  cancelGuardians := []
  cancelZk := false

/-- T1 `begin_lost_key` / `begin_compromise`. Permissionless. `derived` is the
outcome of every check that needs the doc compiler or the account's history
(`derive_target`, the replacement set's encoding and ZK enrollment,
`is_enrolled_id`, `is_revoked`, rule 8); refusing them is `InvalidReplacements`
or a variant the model does not distinguish. -/
def beginAttempt (s : State) (L : Nat) (kind : Kind) (replacements targetDoc targetBytes : Nat)
    (derived : Bool) : Result :=
  match s.config with
  | none => .error .notEnrolled
  | some c =>
    if (s.authorizedLive L).isSome then .error .attemptAuthorized
    else if !derived then .error .invalidReplacements
    else
      match sourceOf s c kind with
      | none => .error .noBaseline
      | some src =>
        .ok (({ s with nextAttempt := s.nextAttempt + 1 }.put
          (newAttempt s L c kind src replacements targetDoc targetBytes)).emit L (some c)
          (.attemptBegun s.nextAttempt))

/-- T4 `promote`: authorize, fixing the windows and invalidating every sibling;
or, for a lost-key attempt whose source is no longer the applied document,
record `Invalidated` and succeed. -/
def promote (s : State) (L : Nat) (c : Config) (a : Attempt) : Result :=
  if (s.authorizedLive L).isSome then .error .attemptAuthorized
  else if a.kind = .lostKey ∧ s.appliedDoc ≠ a.sourceDoc then
    .ok ((s.put { a with state := .invalidated }).emit L (some c) (.attemptInvalidated a.id))
  else
    let a' := { a with
      state := .authorized, authorizedAt := L,
      executableAfter := L + c.delayLedgers,
      expiresAt := L + c.delayLedgers + c.expiryLedgers }
    .ok (({ s with invalidateBelow := s.nextAttempt, authorized := some a.id }.put a').emit L
      (some c) (.attemptAuthorized a.id a'.executableAfter a'.expiresAt))

/-- T6 (`counted`) and T7. Cancelling a collecting attempt never counts; an
authorized one stops being the authorized attempt. -/
def cancelAttempt (s : State) (L : Nat) (c : Config) (a : Attempt) (counted : Bool) : Result :=
  if (counted && a.state == AttemptState.authorized) && decide (c.maxCancels ≤ s.cancels) then
    .error .maxCancelsReached
  else
    .ok (({ s with
        cancels := if counted && a.state == AttemptState.authorized then s.cancels + 1 else s.cancels,
        authorized := if a.state == AttemptState.authorized then none else s.authorized }.put
      { a with state := .cancelled }).emit L (some c)
      (.attemptCancelled a.id (counted && a.state == AttemptState.authorized)))

/-- `after_evidence`: promote (T4) or cancel (T6) once the domain's condition
holds; otherwise just record the evidence. -/
def afterEvidence (s : State) (L : Nat) (c : Config) (a : Attempt) : Domain → Result
  | .initiate => if initiationMet c a then promote s L c a else .ok (s.put a)
  | .cancel => if cancellationMet c a then cancelAttempt s L c a true else .ok (s.put a)

/-- T2 `submit_guardian(account, attempt_id, domain, guardian)`: requires
`guardian.require_auth_for_args((digest,))` for the attempt's statement in
`domain`. Whoever submits it is not an input. -/
def submitGuardian (s : State) (L : Nat) (auth : Nat → Fn → Nat → Bool) (id : Nat)
    (dom : Domain) (g : Nat) : Result :=
  match s.config with
  | none => .error .notEnrolled
  | some c =>
    match c.mode.guardianSet with
    | none => .error .modeHasNoGuardians
    | some (gs, _) =>
      if g ∉ gs then .error .notAGuardian
      else match s.attempts id with
        | none => .error .noSuchAttempt
        | some a =>
          if !s.isLive L a then .error .attemptNotLive
          else if dom = .initiate ∧ a.state ≠ .collecting then .error .attemptNotCollecting
          else if g ∈ a.votes dom then .error .alreadyCounted
          else
            let S := attemptStatement W c a dom
            if !fresh L S then .error .evidenceExpired
            else if !auth g .submitGuardian (W.digest S) then .error .notAuthorized
            else afterEvidence s L c (a.addVote g dom) dom

/-- T3 `submit_zk`: `accepted` is the adapter's verdict together with the
nullifier being unspent (§11). -/
def submitZk (s : State) (L : Nat) (id : Nat) (dom : Domain) (accepted : Bool) : Result :=
  match s.config with
  | none => .error .notEnrolled
  | some c =>
    if !c.mode.hasZk then .error .modeHasNoZk
    else match s.attempts id with
      | none => .error .noSuchAttempt
      | some a =>
        if !s.isLive L a then .error .attemptNotLive
        else if dom = .initiate ∧ a.state ≠ .collecting then .error .attemptNotCollecting
        else if a.hasZk dom then .error .alreadyCounted
        else if !fresh L (attemptStatement W c a dom) then .error .evidenceExpired
        else if !accepted then .error .zkEvidenceRejected
        else afterEvidence s L c (a.addZk dom) dom

/-- Whether a subject is one `approve_change` accepts. -/
def isChange : Subject → Bool
  | .reconfigure _ | .upgrade .. => true
  | _ => false

/-- `approve_change(account, subject, valid_until, guardian)` (Perch §5):
records one guardian's approval of a change statement under its digest. -/
def approveChange (s : State) (L : Nat) (auth : Nat → Fn → Nat → Bool) (subject : Subject)
    (validUntil g : Nat) : Result :=
  match s.config with
  | none => .error .notEnrolled
  | some c =>
    match c.mode.guardianSet with
    | none => .error .modeHasNoGuardians
    | some (gs, _) =>
      if g ∉ gs then .error .notAGuardian
      else if (s.authorizedLive L).isSome then .error .attemptAuthorized
      else if !isChange subject then .error .invalidStatement
      else
        let S := mkStatement W c s.epoch validUntil subject
        if !fresh L S then .error .evidenceExpired
        else
          let d := W.digest S
          let r := (s.approvals d).getD ⟨[], false⟩
          if g ∈ r.guardians then .error .alreadyCounted
          else if !auth g .approveChange d then .error .notAuthorized
          else .ok ({ s with approvals := fun d' =>
              if d' = d then some ⟨r.guardians ++ [g], r.zk⟩ else s.approvals d' }.emit L (some c)
            (.changeEvidenceRecorded d))

/-- `submit_zk_change` (Perch §5). -/
def submitZkChange (s : State) (L : Nat) (subject : Subject) (validUntil : Nat)
    (accepted : Bool) : Result :=
  match s.config with
  | none => .error .notEnrolled
  | some c =>
    if !c.mode.hasZk then .error .modeHasNoZk
    else if (s.authorizedLive L).isSome then .error .attemptAuthorized
    else if !isChange subject then .error .invalidStatement
    else
      let S := mkStatement W c s.epoch validUntil subject
      if !fresh L S then .error .evidenceExpired
      else
        let d := W.digest S
        let r := (s.approvals d).getD ⟨[], false⟩
        if r.zk then .error .alreadyCounted
        else if !accepted then .error .zkEvidenceRejected
        else .ok ({ s with approvals := fun d' =>
            if d' = d then some ⟨r.guardians, true⟩ else s.approvals d' }.emit L (some c)
          (.changeEvidenceRecorded d))

/-- `require_condition` over the recorded evidence for a change (Perch §5). -/
def requireCondition (s : State) (L : Nat) (c : Config) (subject : Subject)
    (validUntil : Nat) : Except Error Unit :=
  let S := mkStatement W c s.epoch validUntil subject
  if !fresh L S then .error .evidenceExpired
  else match s.approvals (W.digest S) with
    | none => .error .conditionNotMet
    | some r => if conditionMet c r then .ok () else .error .conditionNotMet

/-- Store a configuration and bump the epoch (`store_config`). -/
def State.store (s : State) (L : Nat) (old : Option Config) (n : Config) : State :=
  { s with config := some n, epoch := s.epoch + 1 }.emit L old (.epochAdvanced (s.epoch + 1))

/-- An ordinary owner-authorized `apply_doc` of a document with identity
`docHash` and compiled recovery member `new`, through `rcv_sync`'s
classification (Perch §10): no change, enrollment, reconfiguration, or
removal (a switch away is a removal here). Refused while an attempt is
authorized and live (D3). -/
def applyDoc (s : State) (L : Nat) (docHash : Nat) (new : Option Config)
    (approvalValidUntil : Nat) : Result :=
  if (s.authorizedLive L).isSome then .error .attemptAuthorized
  else
    let s := { s with appliedDoc := docHash }
    match s.config, new with
    | none, none => .ok s
    | none, some n =>
      if n.controller ≠ W.here then .error .invalidConfiguration
      else if !checkConfig W.account n then .error .invalidConfiguration
      else .ok (s.store L none n)
    | some old, _ =>
      if new = some old then .ok s
      else
        let change := match new with
          | some n => Change.set (W.configHash n)
          | none => Change.remove
        let gate : Except Error Unit :=
          if old.profile = .«protected» then
            requireCondition W s L old (.reconfigure change) approvalValidUntil
          else .ok ()
        match gate with
        | .error e => .error e
        | .ok () =>
          match new with
          | some n =>
            if n.controller = W.here then
              if !checkConfig W.account n then .error .invalidConfiguration
              else .ok (s.store L (some old) n)
            else
              .ok ({ s with config := none, authorized := none, epoch := s.epoch + 1 }.emit L
                (some old) (.epochAdvanced (s.epoch + 1)))
          | none =>
            .ok ({ s with config := none, authorized := none, epoch := s.epoch + 1 }.emit L
              (some old) (.epochAdvanced (s.epoch + 1)))

/-- T5: the `apply_doc` that selects the recovery rule. `enforce` requires an
authorized live attempt, the timelock passed, and the exact target bytes; the
same invocation's `rcv_sync` then requires the compiled identity and
configuration to be the attempt's target, marks it completed, stores the
target configuration and bumps the epoch. The two halves are one transaction:
a marker counts only in the ledger `enforce` wrote it (Perch T5), so a
completion by a leftover marker also passed `enforce` at that ledger. -/
def complete (s : State) (L : Nat) (targetBytes docHash : Nat) (new : Config) : Result :=
  match s.config with
  | none => .error .notEnrolled
  | some c =>
    match s.authorizedLive L with
    | none => .error .attemptNotLive
    | some a =>
      if L < a.executableAfter then .error .notExecutableYet
      else if targetBytes ≠ a.targetBytes then .error .wrongTarget
      else if docHash ≠ a.targetDoc then .error .wrongTarget
      else if new.controller ≠ W.here ∨ new ≠ a.targetConfig then .error .wrongTarget
      else
        let s₁ : State := { s with
          authorized := none, config := some new, epoch := s.epoch + 1, appliedDoc := a.targetDoc }
        .ok (((s₁.put { a with state := .completed }).emit L (some c)
          (.epochAdvanced (s.epoch + 1))).emit L (some c) (.recoveryCompleted a.id))

/-- T7: `cancel_recovery` under owner authorization (`rcv_cancel`), `Loss`
only, never counted toward `max-cancels`. -/
def ownerCancel (s : State) (L : Nat) (id : Nat) : Result :=
  match s.config with
  | none => .error .notEnrolled
  | some c =>
    if c.profile ≠ .loss then .error .ownerCancelRefused
    else match s.attempts id with
      | none => .error .noSuchAttempt
      | some a => if !s.isLive L a then .error .attemptNotLive else cancelAttempt s L c a false

/-- `rcv_upgrade(Execute(recorded_epoch))` (Perch §12). -/
def executeUpgrade (s : State) (L : Nat) (recordedEpoch : Nat) : Result :=
  match s.config with
  | none => .error .notEnrolled
  | some c =>
    if (s.authorizedLive L).isSome then .error .attemptAuthorized
    else if recordedEpoch ≠ s.epoch then .error .staleUpgrade
    else .ok ({ s with epoch := s.epoch + 1 }.emit L (some c) (.epochAdvanced (s.epoch + 1)))

end Transitions

/-- One transaction against the controller. -/
inductive Tx
  | beginAttempt (kind : Kind) (replacements targetDoc targetBytes : Nat) (derived : Bool)
  | submitGuardian (id : Nat) (domain : Domain) (guardian : Nat)
  | submitZk (id : Nat) (domain : Domain) (accepted : Bool)
  | approveChange (subject : Subject) (validUntil guardian : Nat)
  | submitZkChange (subject : Subject) (validUntil : Nat) (accepted : Bool)
  | applyDoc (docHash : Nat) (new : Option Config) (approvalValidUntil : Nat)
  | complete (targetBytes docHash : Nat) (new : Config)
  | ownerCancel (id : Nat)
  | executeUpgrade (recordedEpoch : Nat)

/-- A transaction, the ledger it runs at, and which guardian authorizations
the host accepts in it: `auth g fn d` holds when the transaction carries an
authorization entry for address `g` that the host accepts for
`controller.fn((d,))`. -/
structure Step where
  ledger : Nat
  tx : Tx
  auth : Nat → Fn → Nat → Bool

/-- Execute one transaction. -/
def step (W : World) (s : State) (st : Step) : Result :=
  match st.tx with
  | .beginAttempt k r td tb ok => beginAttempt s st.ledger k r td tb ok
  | .submitGuardian id dom g => submitGuardian W s st.ledger st.auth id dom g
  | .submitZk id dom ok => submitZk W s st.ledger id dom ok
  | .approveChange sub vu g => approveChange W s st.ledger st.auth sub vu g
  | .submitZkChange sub vu ok => submitZkChange W s st.ledger sub vu ok
  | .applyDoc doc new vu => applyDoc W s st.ledger doc new vu
  | .complete tb doc new => complete W s st.ledger tb doc new
  | .ownerCancel id => ownerCancel s st.ledger id
  | .executeUpgrade e => executeUpgrade s st.ledger e

/-- The states reachable from an unenrolled account by transactions satisfying
`P`. A refused transaction changes nothing, so it adds no state. -/
inductive Reachable (W : World) (doc : Nat) (P : Step → Prop) : State → Prop
  | init : Reachable W doc P (State.init doc)
  | step {s s' : State} (st : Step) :
      Reachable W doc P s → P st → step W s st = .ok s' → Reachable W doc P s'

end EmailRecovery.Perch
