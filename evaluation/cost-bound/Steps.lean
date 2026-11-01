import AttenuatingGrants
import Lean.Data.Json

/-!
# Step counts and cost bounds of measured chain checks

For each case in a JSON file (a chain grant and the actions of one
authorization), prints one JSON line with the step count of the counted
evaluator `Chain.allowsAllCounted` from `formal/AttenuatingGrants/Cost/Chain.lean`,
its verdict, and the value of the proven batch bound `Chain.AllowsAllCostBound`:

  `2 * (cs.length + Σ c.size + 1) * Σ (a.size + 1)`

The definitions are the formal package's own; this file only parses the input
and evaluates them. Run from `formal/`, after `lake build`:

```sh
lake env lean --run ../evaluation/cost-bound/Steps.lean cases.json
```

Input: `{"cases": [{"id": …, "caveats": [caveat], "actions": [action]}]}` with
byte strings in hex:

- caveat: `{"contract_in": [hex]}`, `{"function_in": [hex]}`,
  `{"arg_i128_at_most": {"index": n, "bound": "<decimal>"}}`,
  `{"arg_eq": {"index": n, "value": val}}`
- val: `{"i128": "<decimal>"}`, `{"u64": n}`, `{"bool": b}`, `{"bytes": hex}`,
  `{"address": hex}`, `{"symbol": hex}`, `{"other": hex}`
- action: `{"invoke": {"contract": hex, "function": hex, "args": [val]}}`,
  `{"create_contract": hex}`
-/

open Lean AttenuatingGrants AttenuatingGrants.Chain

def hexDigit (c : Char) : Except String Nat :=
  if '0' ≤ c ∧ c ≤ '9' then .ok (c.toNat - '0'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'f' then .ok (c.toNat - 'a'.toNat + 10)
  else if 'A' ≤ c ∧ c ≤ 'F' then .ok (c.toNat - 'A'.toNat + 10)
  else .error s!"not a hex digit: {c}"

def hexBytes : List Char → Except String Bytes
  | [] => .ok []
  | hi :: lo :: rest => do
    let b := (← hexDigit hi) * 16 + (← hexDigit lo)
    return UInt8.ofNat b :: (← hexBytes rest)
  | [_] => .error "odd-length hex"

def parseHex (j : Json) : Except String Bytes := do
  hexBytes (← j.getStr?).toList

def parseI128 (j : Json) : Except String I128 := do
  let s ← j.getStr?
  match s.toInt? with
  | some n => return BitVec.ofInt 128 n
  | none => throw s!"not an integer: {s}"

def parseVal (j : Json) : Except String Val :=
  (do return .i128 (← parseI128 (← j.getObjVal? "i128")))
  <|> (do return .u64 (UInt64.ofNat (← j.getObjValAs? Nat "u64")))
  <|> (do return .bool (← j.getObjValAs? Bool "bool"))
  <|> (do return .bytes (← parseHex (← j.getObjVal? "bytes")))
  <|> (do return .address (← parseHex (← j.getObjVal? "address")))
  <|> (do return .symbol (← parseHex (← j.getObjVal? "symbol")))
  <|> (do return .other (← parseHex (← j.getObjVal? "other")))
  <|> throw s!"not a value: {j.compress}"

def parseHexList (j : Json) : Except String (List Bytes) := do
  (← j.getArr?).toList.mapM parseHex

def parseCaveat (j : Json) : Except String Caveat :=
  (do return .contractIn (← parseHexList (← j.getObjVal? "contract_in")))
  <|> (do return .functionIn (← parseHexList (← j.getObjVal? "function_in")))
  <|> (do
    let c ← j.getObjVal? "arg_i128_at_most"
    return .argI128AtMost (← c.getObjValAs? Nat "index") (← parseI128 (← c.getObjVal? "bound")))
  <|> (do
    let c ← j.getObjVal? "arg_eq"
    return .argEq (← c.getObjValAs? Nat "index") (← parseVal (← c.getObjVal? "value")))
  <|> throw s!"not a caveat: {j.compress}"

def parseAction (j : Json) : Except String Action :=
  (do
    let i ← j.getObjVal? "invoke"
    let args ← (← i.getObjValAs? (Array Json) "args").toList.mapM parseVal
    return .invoke (← parseHex (← i.getObjVal? "contract")) (← parseHex (← i.getObjVal? "function")) args)
  <|> (do return .createContract (← parseHex (← j.getObjVal? "create_contract")))
  <|> throw s!"not an action: {j.compress}"

def evalCase (j : Json) : Except String Json := do
  let id ← j.getObjValAs? String "id"
  let cs ← (← j.getObjValAs? (Array Json) "caveats").toList.mapM parseCaveat
  let actions ← (← j.getObjValAs? (Array Json) "actions").toList.mapM parseAction
  let r := allowsAllCounted cs actions
  let caveatSize := (cs.map Caveat.size).sum
  let actionsSize := (actions.map (·.size + 1)).sum
  return Json.mkObj [
    ("id", toJson id),
    ("allowed", toJson r.1),
    ("steps", toJson r.2),
    ("caveats", toJson cs.length),
    ("caveat_size", toJson caveatSize),
    ("actions", toJson actions.length),
    ("actions_size", toJson actionsSize),
    ("bound", toJson (2 * (cs.length + caveatSize + 1) * actionsSize))]

def main (args : List String) : IO UInt32 := do
  let [path] := args
    | IO.eprintln "usage: lean --run Steps.lean <cases.json>"; return 2
  let text ← IO.FS.readFile path
  let cases ← match Json.parse text >>= (·.getObjValAs? (Array Json) "cases") with
    | .ok cs => pure cs
    | .error e => IO.eprintln s!"{path}: {e}"; return 1
  for c in cases do
    match evalCase c with
    | .ok out => IO.println out.compress
    | .error e => IO.eprintln s!"{path}: {e}"; return 1
  return 0
