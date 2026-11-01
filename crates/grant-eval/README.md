# grant-eval

The evaluator for attenuating grants. An agent's authority is a **grant**: a
list of **caveats** over one action type. The holder of a grant can only add
caveats and pass narrower copies on; issuing, revoking and key rotation live in
a separate admin document that agents never hold. The same evaluator runs at
two boundaries: inside the Soroban smart account's `__check_auth`, and in the
agent's WebAssembly host.

`#![no_std]` (with `alloc`), `#![forbid(unsafe_code)]`, no dependencies.
Builds for the host and for `wasm32v1-none`.

## Semantics

The readable Lean model the evaluator agrees with:

```lean
structure Grant (α : Type) where
  caveats : List (α → Bool)

def Grant.allows (g : Grant α) (a : α) : Bool :=
  g.caveats.all (· a)
```

- `allows(grant, action)` is true exactly when every caveat in `grant` holds
  for `action`. The empty grant allows every action.
- `allows_all(grant, actions)` is true exactly when `allows(grant, a)` holds for
  every `a` in `actions`. Every context of a Soroban authorization tree is
  checked this way, so one disallowed nested call denies the whole tree.
- Adding a caveat can only remove actions from what a grant allows
  (attenuation).

Identifiers (contract ids, function names, wasm hashes, hosts, key ids,
network ids, path components) are byte strings compared by exact bytewise
equality. The evaluator does no normalization.

The generic functions are `grant_eval::allows` and `grant_eval::allows_all`
over any caveat type implementing `Check<A>`. Each vocabulary module exports
its `Action` and `Caveat` types, a monomorphic `holds(caveat, action)`, and
`allows` / `allows_all` over `&[Caveat]`.

### `chain`

Action: `Invoke { contract, function, args: Vec<Val> }` or
`CreateContract { wasm_hash }` (the contract-deploying host functions in a
Soroban authorization context).
`Val` is `I128(i128) | U64(u64) | Bool(bool) | Bytes(bytes) | Address(bytes) | Symbol(bytes)`.

| Caveat | Holds iff |
| --- | --- |
| `ContractIn(list)` | the action is `Invoke` and its contract is in `list` |
| `FunctionIn(list)` | the action is `Invoke` and its function is in `list` |
| `ArgI128AtMost(index, n)` | the action is `Invoke`, `args[index]` exists, is `I128(v)`, and `v <= n` |
| `ArgEq(index, val)` | the action is `Invoke`, `args[index]` exists, and equals `val` (same variant, equal payload) |

Every chain caveat is false on `CreateContract`, so any grant with at least one
chain caveat denies contract deployment. A missing argument, or an argument of
another variant, fails the argument caveats.

### `files`

Action: `{ path: Vec<component>, mode: Read | Write | Execute }`.

| Caveat | Holds iff |
| --- | --- |
| `PathUnder(prefix)` | `prefix` is a component-wise prefix of `path` |
| `ModeIn(list)` | the mode is in `list` (read-only is `ModeIn([Read])`) |

Paths are component lists, so `["home", "a"]` is a prefix of
`["home", "a", "x"]` and never of `["home", "ab"]`.

### `network`

Action: `{ host, port: u16, scheme: Http | Https }`.
Caveats `HostIn(list)`, `PortIn(list)`, `SchemeIn(list)`, each holding iff
that field is in the list.

### `signing`

Action: `{ key, network, payload: Transaction | AuthEntry | Message }`.
Caveats `KeyIn(list)`, `NetworkIn(list)`, `PayloadIn(list)`, each holding iff
that field is in the list.

## Restricted subset

The evaluator is written so Charon and Aeneas can translate it to Lean, and so
the translation is a total function:

- Plain structs and enums. One trait, `Check<A>`, with static dispatch only; no
  trait objects, closures, iterator adaptors or derived equality. Enums
  compare through explicit `match` (`mode_eq`, `scheme_eq`, `payload_eq`,
  `val_eq`); byte strings through the `bytes_eq` loop.
- Each loop is a single `while i < s.len()` over one slice, with an early
  `return` and no nested loop, labelled `break` or `continue` (the loop forms
  Aeneas's README lists as supported).
- Nothing in the evaluation path can panic:
  - slice indexing `s[i]` happens only under `i < s.len()` (and, in
    `bytes_eq` and `is_prefix`, after checking the second slice is at least as
    long);
  - argument indices come from caveats, so they go through `args.get(index)`;
  - the only arithmetic is the loop counter `i + 1` with `i < s.len()`, which
    cannot overflow;
  - `index as usize` widens a `u32`, lossless on every target with at least
    32-bit pointers (a compile-time assertion in `chain.rs` checks this).

`charon cargo --preset=aeneas`, run from this directory, translates every item
in the crate.

## Trusted base

Trusted, not proven: `rustc`, the Soroban SDK, the Charon and Aeneas
translation, and the host wiring that builds actions. The wiring stays small
and auditable:

- File paths reach the evaluator canonical: `..`, symlinks and
  case-insensitive file systems are resolved by the host.
- Network caveats check the host name the agent requested; the runtime does
  the DNS lookup and the connecting. An HTTP redirect is a new action and is
  checked again.
- The Soroban integration turns each authorization context into a `chain`
  action.

**Grants control access, not information flow.** A grant decides which actions
an agent may take. It does not track what the agent learns from an allowed
action or where that data goes next through other allowed actions.

## Status

Tested: the unit tests in `tests/` cover allow and deny cases for every
caveat. They check attenuation monotonicity, and agreement with a
plain-Rust reading of the semantics, exhaustively over every grant of up to
three caveats drawn from a small universe per vocabulary. The checks run
against every action in that vocabulary's set.

Stated, not proven: that the code agrees with the Lean model, and the
attenuation property beyond the tested universes. The Aeneas translation and
the Lean equivalence proof are open.

## Commands

```sh
cargo test -p grant-eval
cargo build -p grant-eval --target wasm32v1-none --release
```
