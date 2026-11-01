import AttenuatingGrants.Bytes
import AttenuatingGrants.Grant

/-!
# Network vocabulary

Hosts are byte strings compared exactly. Lowercasing and DNS resolution are
host wiring, done before an action reaches the evaluator.
-/

namespace AttenuatingGrants.Network

inductive Scheme where
  | http
  | https
  deriving DecidableEq

structure Action where
  host : Bytes
  port : UInt16
  scheme : Scheme
  deriving DecidableEq

inductive Caveat where
  | hostIn (hosts : List Bytes)
  | portIn (ports : List UInt16)
  /-- HTTPS only is `schemeIn [.https]`. -/
  | schemeIn (schemes : List Scheme)
  deriving DecidableEq

def Caveat.holds : Caveat → Action → Bool
  | .hostIn hosts, a => decide (a.host ∈ hosts)
  | .portIn ports, a => decide (a.port ∈ ports)
  | .schemeIn schemes, a => decide (a.scheme ∈ schemes)

def grant (cs : List Caveat) : Grant Action :=
  { caveats := cs.map Caveat.holds }

theorem hostIn_iff (hosts : List Bytes) (a : Action) :
    (Caveat.hostIn hosts).holds a = true ↔ a.host ∈ hosts := by
  simp [Caveat.holds]

theorem portIn_iff (ports : List UInt16) (a : Action) :
    (Caveat.portIn ports).holds a = true ↔ a.port ∈ ports := by
  simp [Caveat.holds]

theorem schemeIn_iff (schemes : List Scheme) (a : Action) :
    (Caveat.schemeIn schemes).holds a = true ↔ a.scheme ∈ schemes := by
  simp [Caveat.holds]

end AttenuatingGrants.Network
