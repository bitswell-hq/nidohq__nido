import AttenuatingGrants.Bytes
import AttenuatingGrants.Grant

/-!
# Signing vocabulary

A signing action names the key, the network the signature is for, and the
kind of payload being signed.
-/

namespace AttenuatingGrants.Signing

inductive Payload where
  | transaction
  | authEntry
  | message
  deriving DecidableEq

structure Action where
  key : Bytes
  network : Bytes
  payload : Payload
  deriving DecidableEq

inductive Caveat where
  | keyIn (keys : List Bytes)
  /-- Testnet only is `networkIn [testnet]` for the testnet's network id. -/
  | networkIn (networks : List Bytes)
  | payloadIn (payloads : List Payload)
  deriving DecidableEq

def Caveat.holds : Caveat → Action → Bool
  | .keyIn keys, a => decide (a.key ∈ keys)
  | .networkIn networks, a => decide (a.network ∈ networks)
  | .payloadIn payloads, a => decide (a.payload ∈ payloads)

def grant (cs : List Caveat) : Grant Action :=
  { caveats := cs.map Caveat.holds }

theorem keyIn_iff (keys : List Bytes) (a : Action) :
    (Caveat.keyIn keys).holds a = true ↔ a.key ∈ keys := by
  simp [Caveat.holds]

theorem networkIn_iff (networks : List Bytes) (a : Action) :
    (Caveat.networkIn networks).holds a = true ↔ a.network ∈ networks := by
  simp [Caveat.holds]

theorem payloadIn_iff (payloads : List Payload) (a : Action) :
    (Caveat.payloadIn payloads).holds a = true ↔ a.payload ∈ payloads := by
  simp [Caveat.holds]

end AttenuatingGrants.Signing
