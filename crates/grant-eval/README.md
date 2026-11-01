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
(defined in `src/eval.rs`) over any caveat type implementing `Check<A>`.
Each vocabulary module exports its `Action` and `Caveat` types, a monomorphic
`holds(caveat, action)`, and `allows` / `allows_all` over `&[Caveat]`.

### `chain`

Action: `Invoke { contract, function, args: Vec<Val> }` or
`CreateContract { wasm_hash }` (the contract-deploying host functions in a
Soroban authorization context).
`Val` is `I128(i128) | U64(u64) | Bool(bool) | Bytes(bytes) | Address(bytes) | Symbol(bytes) | Other(bytes)`.
`Other` is an argument of a type the other variants do not model (`u32`,
`i64`, `string`, `vec`, `map`, …), carried as its full `ScVal` XDR. The XDR
starts with the type's discriminant, so two `Other` values are equal only for
arguments of the same type and value, and because values of different
variants are never equal, an argument of one type never satisfies an `ArgEq`
written for another: an `Other` argument never matches a `Bytes` caveat with
the same bytes. One opaque variant, rather than a variant per Soroban type,
keeps the vocabulary at the types its caveats inspect; `ArgEq` is the only
caveat that reads an unmodeled argument, and it needs only equality.

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

### `budget`

Budgets are allowances along the delegation tree. The ledger is a slice of
`Node { parent: Option<usize>, allowance: u128, spent: u128 }`, one per grant,
where `spent` counts every successful spend at or under the node and a parent
precedes its children (its index is smaller).

| Function | Effect |
| --- | --- |
| `check_spend(ledger, node, amount)` | walks from `node` to its root and returns the first failure: `Overdrawn(i)` at the first node, counting from `node`, whose `spent + amount` overflows or exceeds its allowance; `NoSuchNode(i)` or `BadParent(i)` on a malformed ledger |
| `spend(ledger, node, amount)` | if `check_spend` succeeds, adds `amount` to `node` and every ancestor; otherwise returns its error and changes nothing |
| `refill(ledger, node, extra)` | raises `node`'s allowance by `extra`; `NoSuchNode` or `Overflow` change nothing |
| `append(ledger, parent, allowance)` | pushes a node with nothing spent under `parent`, or as a new root for `None`, and returns its index; `NoSuchNode(p)` if `p` is not an existing index, changing nothing |

Children's allowances may sum to more than their parent's, and `append`
accepts any allowance, so delegation may oversubscribe. Because every
ancestor is charged in the same transaction, the total spent at or under a
node never exceeds that node's allowance. `Overdrawn(i)` names where a refill
request goes; `refill` and issuing a new root are admin-document actions,
never an agent's. A new node takes the next index, so parents keep preceding
their children.

The Lean model is `formal/AttenuatingGrants/Budget.lean`. Amounts there are
unbounded `Nat`; a refill fails past `u128::MAX` as `checked_add` does, and a
spend whose sum overflows `u128` exceeds the allowance in both, so the two
agree on every `u128` input with no wrapped or saturated case.
`formal/AttenuatingGrants/Equiv/Budget.lean` proves that the Charon + Aeneas
translation of these functions computes the model on every ledger, so the
model's results hold for this code:

- `check_spend`, `spend` and `refill` return on every input, and `append` on
  every ledger below `usize::MAX` nodes, with the model's outcome and ledger;
- a successful `spend` charges the spender and every ancestor by the amount
  and changes nothing else; a failed one returns the ledger unchanged
  (theorem 4);
- the charging walk visits exactly the chain `check_spend` accepted, and its
  `spent += amount` never overflows;
- every node's spent stays within its allowance, and over any sequence of
  spends, refills and appends from a ledger with nothing spent, the total
  successfully spent at or under a node never exceeds its allowance.

`formal/README.md` lists the theorems.

## Restricted subset

The evaluator is written so Charon and Aeneas can translate it to Lean, and so
the translation is a total function:

- Plain structs and enums. One trait, `Check<A>`, with static dispatch only; no
  trait objects, closures, iterator adaptors or derived equality. Enums
  compare through explicit `match` (`mode_eq`, `scheme_eq`, `payload_eq`,
  `val_eq`); byte strings through the `bytes_eq` loop.
- Each loop is a single `while i < s.len()` over one slice, with an early
  `return` and no nested loop, labelled `break` or `continue` (the loop forms
  Aeneas's README lists as supported). The budget walks count steps with `i`
  against the ledger's length and follow parent links with a second
  variable.
- Nothing in the evaluation path can panic, and nothing in `budget` but the
  allocation in `append`:
  - slice indexing `s[i]` happens only under `i < s.len()` (and, in
    `bytes_eq` and `is_prefix`, after checking the second slice is at least as
    long);
  - argument indices come from caveats, so they go through `args.get(index)`;
    budget node indices come from the ledger, so they go through `get` and
    `get_mut`;
  - the loop counter `i + 1` runs under `i < s.len()`, so it cannot overflow;
  - budget amounts use `checked_add`, and an overflow fails the spend or
    refill. The one plain addition, `spent += amount` in the charging walk,
    runs only after `check_spend` found `spent + amount` within that node's
    allowance (proven: `Budget.charge_loop_eq`);
  - `append` calls `Vec::push`, which allocates; a failed allocation aborts.
    Aeneas models `push` as failing only once a vector holds `usize::MAX`
    elements, and the proofs about `append` assume the ledger stays below
    that;
  - `index as usize` widens a `u32`, lossless on every target with at least
    32-bit pointers (a compile-time assertion in `chain.rs` checks this).
- No function calls a function of the same name in another module by its bare
  path. Aeneas names each item relative to the crate, and Lean resolves a
  bare `allows` inside `def chain.allows` to `chain.allows` itself, so the
  generic `allows` and `allows_all` live in `src/eval.rs` (re-exported at the
  crate root) and the vocabulary wrappers' calls translate to `eval.allows`
  and `eval.allows_all`.

`formal/scripts/extract.sh` runs `charon cargo --preset=aeneas
--error-on-warnings` in this directory and Aeneas on the result; every item
translates, and the generated Lean builds against Aeneas's Lean library with
no `axiom` or `opaque` declaration.

## Trusted base

Trusted, not proven: `rustc`, the Soroban SDK, the Charon and Aeneas
translation together with Aeneas's Lean library (its models of the `core` and
`alloc` items the evaluator calls: slices, `Vec` with `len`, `push` and
`deref_mut`, indexing, `get`, `get_mut`, `len`, checked `usize` addition,
checked and unchecked `u128` addition, `u32 as usize`), the allocator, and
the host wiring that builds actions. The wiring stays small and auditable:

- File paths reach the evaluator canonical: `..`, symlinks and
  case-insensitive file systems are resolved by the host.
- Network caveats check the host name the agent requested; the runtime does
  the DNS lookup and the connecting. An HTTP redirect is a new action and is
  checked again.
- The Soroban integration turns each authorization context into a `chain`
  action.
- Budget wiring passes the node of the grant actually being spent under,
  appends a node under the delegator's when a grant is delegated, and exposes
  `refill` and root issuing (`append` with no parent) only to the admin
  document.

**Grants control access, not information flow.** A grant decides which actions
an agent may take. It does not track what the agent learns from an allowed
action or where that data goes next through other allowed actions.

## Status

Tested: the unit tests in `tests/` cover allow and deny cases for every
caveat. They check attenuation monotonicity, and agreement with a
plain-Rust reading of the semantics, exhaustively over every grant of up to
three caveats drawn from a small universe per vocabulary. The checks run
against every action in that vocabulary's set.

The budget tests cover oversubscribed siblings, a spend that exhausts a middle
ancestor, the error naming the nearest overdrawn node, overflow at the
spender and at an ancestor, refill overflow, and malformed ledgers, checking
after every failure that the ledger is identical field for field. An
exhaustive test runs every sequence of up to four spends and refills, from a
universe of ten, on a five-node oversubscribed forest, against a plain-Rust
reference. After each step it checks that a success charges exactly the
spender's chain and a failure changes nothing, that every spent is within its
allowance, and that each node's spent equals the total of successful spends
at or under it.

Proven in `formal/` about the Charon + Aeneas translation of this crate
(`formal/AttenuatingGrants/Extracted/`), for each vocabulary:

- `allows` and `allows_all` return a result for every input: no panic,
  overflow, out-of-bounds index or divergence;
- the result is the readable model's `Grant.allows` / `Grant.allowsAll` on
  the denoted grant and actions (`V.extracted_allows`,
  `V.extracted_allowsAll`);
- pushing a caveat onto a caveat slice can only narrow what it allows, and a
  slice reached from a root by any number of pushes allows, alone or across a
  batch of actions, only what the root allows (`V.extracted_narrower_push`,
  `V.extracted_delegates_narrower`, `V.extracted_allowsAll_of_delegates`).

`formal/README.md` lists the theorems and the pinned tool versions. These are
statements about the translation; that it has this code's semantics, and that
rustc compiles the code faithfully, is the trusted base above.

Stated, not proven: that the translation of `budget` agrees with
`formal/AttenuatingGrants/Budget.lean`. The extraction translates the module,
but no equivalence proof covers it yet; it must show that `spend` changes
nothing on every error path, that the charging walk visits exactly the chain
`check_spend` accepted, and that its addition never overflows.

## Commands

```sh
cargo test -p grant-eval
cargo build -p grant-eval --target wasm32v1-none --release
just extract-lean            # regenerate the Lean translation (needs Nix)
just extract-lean --check    # compare it with the committed one
```

After any change to this crate, regenerate the translation and re-run
`lake build` in `formal/`; CI fails if the committed translation is stale.
