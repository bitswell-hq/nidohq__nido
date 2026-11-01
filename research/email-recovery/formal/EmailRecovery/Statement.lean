import EmailRecovery.Basic

/-!
# Perch's recovery statement

The statement every piece of recovery evidence approves (Perch §4,
`vendor/perch/docs/recovery/statement.md`), the fields the email guardian reads
from its encoding (`contracts/email-guardian/src/statement.rs`), and the
controller entry points that collect guardian approvals.

The encoding is abstract. Two of its properties are code facts the model takes
as hypotheses (`Encoding.Facts`); they are tested, not proven: Perch's vectors
(`vendor/perch/crates/perch-recovery-interface/tests/vectors.rs`) pin the
encoder, and `contracts/email-guardian/src/test.rs` parses every statement shape
Perch's encoder produces.
-/

namespace EmailRecovery

/-- Statement action codes (statement.md, byte 25). -/
inductive Action
  | lostKey
  | compromise
  | cancel
  | reconfigure
  | upgrade
  deriving DecidableEq, Repr

/-- The byte at offset 25 of the encoding. -/
def Action.code : Action → Nat
  | .lostKey => 1
  | .compromise => 2
  | .cancel => 3
  | .reconfigure => 4
  | .upgrade => 5

/-- Perch §4 `Reconfigure(Remove | Set(new_config_hash))`. -/
inductive Change
  | remove
  | set (configHash : Nat)
  deriving DecidableEq, Repr

/-- Perch §4 `subject`. -/
inductive Subject
  | lostKey (attemptId sourceDoc targetDoc replacements : Nat)
  | compromise (attemptId sourceDoc targetDoc replacements : Nat)
  | cancel (attemptId attemptStatement : Nat)
  | reconfigure (change : Change)
  | upgrade (requestId wasmHash : Nat)
  deriving DecidableEq, Repr

def Subject.action : Subject → Action
  | .lostKey .. => .lostKey
  | .compromise .. => .compromise
  | .cancel .. => .cancel
  | .reconfigure _ => .reconfigure
  | .upgrade .. => .upgrade

/-- The single-use number a subject carries: the attempt id (lost-key,
compromise, cancel) or the upgrade request id. A reconfiguration's nonce is the
epoch alone (Perch §4 "Replay"). -/
def Subject.nonce : Subject → Option Nat
  | .lostKey id .. => some id
  | .compromise id .. => some id
  | .cancel id _ => some id
  | .reconfigure _ => none
  | .upgrade id _ => some id

/-- Perch §4 `RecoveryStatement`, with `config` and `timing` flattened. -/
structure Statement where
  network : Nat
  account : Nat
  controller : Nat
  epoch : Nat
  configHash : Nat
  delayLedgers : Nat
  expiryLedgers : Nat
  validUntil : Nat
  subject : Subject
  deriving DecidableEq, Repr

def Statement.action (s : Statement) : Action := s.subject.action

/-- The fields the guardian reads (`StatementView`). -/
structure View where
  action : Action
  network : Nat
  account : Nat
  controller : Nat
  validUntil : Nat
  deriving DecidableEq, Repr

def Statement.view (s : Statement) : View :=
  ⟨s.action, s.network, s.account, s.controller, s.validUntil⟩

/-- Perch's fixed-width encoding and the guardian's parser of it. `parseView`
returns `none` unless the bytes carry the domain prefix, version 2, a known
action code and that action's exact length (spec §8.3 check 3). -/
structure Encoding where
  encode : Statement → Bytes
  parseView : Bytes → Option View

/-- Code facts about the encoding: tested, not proven (see the module doc). -/
structure Encoding.Facts (E : Encoding) : Prop where
  /-- statement.md: "the encoding is injective without length prefixes". -/
  encode_injective : ∀ s t, E.encode s = E.encode t → s = t
  /-- The guardian's parser reads back the fields of every encoding. -/
  parseView_encode : ∀ s, E.parseView (E.encode s) = some s.view

/-- `digest = sha256(encoding)` (Perch §4, D13). -/
def digest (H : Hashes) (E : Encoding) (s : Statement) : Nat := H.sha256 (E.encode s)

/-- A digest fixes the whole statement, unless SHA-256 collides. -/
theorem digest_binds {H : Hashes} {E : Encoding} (hE : E.Facts) {s t : Statement}
    (h : digest H E s = digest H E t) : s = t ∨ H.Sha256Collision := by
  rcases H.sha256_eq h with h | h
  · exact Or.inl (hE.encode_injective s t h)
  · exact Or.inr h

/-! ## Controller entry points and authorization contexts -/

/-- A controller entry point, as the authorization context names it. -/
inductive Fn
  | submitGuardian
  | approveChange
  | other (name : Nat)
  deriving DecidableEq, Repr

/-- The entry point that collects guardian approvals of an action's statements:
`submit_guardian` for attempts and their cancellation (Perch §6.3 T2),
`approve_change` for reconfiguration and upgrades (Perch §5). -/
def entryPoint : Action → Fn
  | .lostKey | .compromise | .cancel => .submitGuardian
  | .reconfigure | .upgrade => .approveChange

/-- A contract-call argument: a `BytesN<32>` or anything else. -/
inductive Val
  | bytes32 (x : Nat)
  | other (x : Nat)
  deriving DecidableEq, Repr

/-- One entry of the `auth_contexts` the host hands `__check_auth`. -/
inductive AuthContext
  | call (contract : Nat) (fn : Fn) (args : List Val)
  | createContract (wasmHash : Nat)
  deriving DecidableEq, Repr

/-- The single context of `require_auth_for_args((digest,))` inside
`controller.fn`. -/
def AuthContext.approval (controller : Nat) (fn : Fn) (d : Nat) : AuthContext :=
  .call controller fn [.bytes32 d]

end EmailRecovery
