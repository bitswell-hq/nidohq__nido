# Attenuating Grants: Lean model

The readable Lean specification of attenuating grants, its first four
theorems, a step-counting evaluator with a proven cost bound, and the proof
that the Rust evaluator in `crates/grant-eval`, translated to Lean by Charon
and Aeneas, agrees with the specification. An AI
agent's authority is a grant: a list of caveats over actions. A grant holder
can only add caveats and pass narrower copies to sub-agents; issuing,
revoking and key rotation live in a separate admin document that agents never
hold. One evaluator enforces grants at two boundaries, the agent's
WebAssembly host and the Soroban smart account, and this package is the
specification that evaluator is proven against.

## Build

```sh
cd formal
lake build
```

`lean-toolchain` pins Lean `v4.35.0`, the release Aeneas's Lean library
uses. Install Lean with [elan](https://github.com/leanprover/elan); it reads
`lean-toolchain` and fetches the pinned release on the first `lake` call.

The one Lake dependency is Aeneas's Lean library (`backends/lean` in
AeneasVerif/aeneas), pinned in `lakefile.toml` to commit
`ab34bd28458a08c150b7cbf1873e59af74588138`, the commit the extraction runs
(see [Extracted evaluator](#extracted-evaluator)). It requires Mathlib
`v4.35.0`. On a fresh checkout, fetch Mathlib's prebuilt oleans before the
first build:

```sh
cd formal
lake exe cache get
lake build
```

Lake downloads Aeneas's own oleans from the release archive tagged at the
pinned commit.

CI (`.github/workflows/formal.yml`) runs on every pull request that touches
`formal/**` or `crates/grant-eval/**` and on every push to `main`:

- **Lean**: rejects any `partial`, `unsafe`, `sorry`, `admit`,
  `native_decide`, `implemented_by`, `extern` or `axiom` in the sources
  (the generated translation included), fetches the Mathlib cache and runs
  `lake build`.
- **Extraction**: re-runs Charon and Aeneas on `crates/grant-eval`
  (`scripts/extract.sh --check`) and fails if the result differs from the
  committed `AttenuatingGrants/Extracted/`.

## Model

`AttenuatingGrants/Grant.lean`:

| Definition | Meaning |
|---|---|
| `Grant α` | `caveats : List (α → Bool)` |
| `Grant.allows g a` | every caveat of `g` holds for `a` (the empty grant allows every action) |
| `Grant.allowsAll g actions` | `g` allows every action in the list; how every context of a Soroban authorization tree is checked |
| `Grant.narrower g h` | every action `g` allows, `h` allows too (`g ≤ h`) |
| `Grant.attenuate g c` | `g` with caveat `c` added |
| `Grant.attenuateAll g cs` | `g` with every caveat in `cs` added |
| `Delegates root g` | `g` is reachable from `root` by zero or more attenuation steps |
| `Grant.delegate root cs` | the end of the delegation chain whose steps add `cs` in order |

Four action vocabularies plug into `Grant`. Each defines an `Action` type, a
`Caveat` type, the denotation `Caveat.holds : Caveat → Action → Bool`, and
`grant : List Caveat → Grant Action`.

| Module | Action | Caveats |
|---|---|---|
| `Vocab/Chain.lean` | `invoke contract function args` or `createContract wasmHash` | `contractIn`, `functionIn`, `argI128AtMost index n`, `argEq index val` |
| `Vocab/Files.lean` | `{ path : List Bytes, mode : read \| write \| execute }` | `pathUnder pathPrefix`, `modeIn modes` |
| `Vocab/Network.lean` | `{ host, port : UInt16, scheme : http \| https }` | `hostIn`, `portIn`, `schemeIn` |
| `Vocab/Signing.lean` | `{ key, network, payload : transaction \| authEntry \| message }` | `keyIn`, `networkIn`, `payloadIn` |

Identifiers (contract ids, function names, wasm hashes, hosts, key ids,
network ids, path components) are `Bytes := List UInt8`, compared by exact
bytewise equality. Aeneas translates a Rust `Vec<u8>` or slice to a structure
whose `val` is a `List` of bytes, so the equivalence relates the two by that
projection. Chain values follow Soroban's `Val`: `i128` is `BitVec 128`
compared as a signed integer (`BitVec.toInt`), `u64` is `UInt64`, and an
argument of a type the vocabulary does not model is `other` of its full
`ScVal` XDR. Values of different constructors are never equal, so `argEq`
holds only for an argument of its value's constructor. Host
normalization (lowercasing hosts, canonicalizing `..`, symlinks and
case-insensitive paths, DNS) happens before an action reaches the evaluator
and is not modelled.

Every Chain caveat is false on `createContract`, so any chain grant with at
least one caveat denies contract deployment. Paths are component lists, so
`["home", "a"]` is not a prefix of `["home", "ab"]`.

## Cost model

`AttenuatingGrants/Cost/` gives each vocabulary a counted evaluator,
`Caveat.holdsCounted : Caveat → Action → Bool × Nat`, which returns the same
`Bool` as `Caveat.holds` paired with a step count, and lifts it to a grant
check over a list of caveats (`allowsCounted`) and a batch check over a list
of actions (`allowsAllCounted`). Both checks stop at the first failure, as
`List.all` does.

A step is one primitive comparison or one traversal of a list cell:

- comparing two bytes, two scalars (ports, schemes, modes, payload kinds,
  `i128`/`u64`/`bool` values) or two `i128`s by signed order;
- testing a constructor (the kind of a Chain action, an `Option`, or a `Val`);
- visiting one cell of a list: a caveat in the grant, an action in a batch, a
  candidate in a membership list, an argument while indexing, a component of
  a path.

Reaching the end of a list costs nothing. Byte strings are compared pairwise
until the first mismatch or the end of the shorter one.

| Vocabulary | `Action.size` | `Caveat.size` |
|---|---|---|
| Chain | `invoke`: contract length + function length + `Σ (arg.size + 1)`, where a scalar `Val` has size 1 and a byte-carrying one its length + 1; `createContract`: wasm hash length | `contractIn`, `functionIn`: `Σ (length + 1)` over the list; `argI128AtMost`: 2; `argEq _ val`: `1 + val.size` |
| Files | `Σ (length + 1)` over the path's components | `pathUnder p`: `Σ (length + 1)` over `p`; `modeIn`: list length |
| Network | host length | `hostIn`: `Σ (length + 1)` over the hosts; `portIn`, `schemeIn`: list length |
| Signing | key length + network id length | `keyIn`, `networkIn`: `Σ (length + 1)` over the list; `payloadIn`: list length |

Reading argument `i` of an invocation walks at most every argument cell, so an
index past the end costs no more than the argument list, and `argI128AtMost`
has constant size whatever its index.

`AttenuatingGrants/Cost/Basic.lean` holds the counted primitives
(`bytesEq`, `scalarEq`, `mem`, `get?`), each with a lemma that its `Bool` is
the readable one (`bytesEq_fst`, `mem_fst`, `get?_fst`, ...) and a step bound
(`bytesEq_snd_le`, `mem_snd_le`, `get?_snd_le`, ...), and the generic grant
and batch checks with `allowsCounted_fst`, `allowsAllCounted_fst`,
`allowsCounted_steps_le` and `allowsAllCounted_steps_le`. Each vocabulary
module proves its per-caveat bound and instantiates the generic ones.

The step count measures this model, not the deployed evaluator. A real call
also pays a fixed overhead (entering the function, decoding the grant) that
the model counts as zero.

## Theorems

### 1. Termination and cost

Evaluation is total. `Grant.allows`, `Grant.allowsAll` and every
vocabulary's `Caveat.holds` (and `Files.isPrefix`) are ordinary Lean
definitions by structural recursion or `List.all`, with no `partial` or
`unsafe` anywhere in the package, so Lean's kernel checks that each one
terminates on every input.

The Rust evaluator is total too: for every input, the Lean translation of
each vocabulary's `allows` and `allows_all` returns `ok`, never a failure
(panic, overflow, out-of-bounds index) or divergence
(`V.extracted_allows`, `V.extracted_allowsAll`; see
[Extracted evaluator](#extracted-evaluator)). So is the budget code:
`check_spend`, `spend` and `refill` return `ok` on every ledger, and `append`
on every ledger below `Usize.max` nodes (`Budget.extracted_check_spend`,
`extracted_spend`, `extracted_refill`, `extracted_append`; see
[Budgets](#budgets)).

The cost bound is stated and proven over the step-counting evaluators
described in [Cost model](#cost-model). For each vocabulary `V`:

| Lean name | Statement |
|---|---|
| `V.AllowsCostBound` (proven by `V.allows_cost_bound`) | `(V.allowsCounted cs a).2 ≤ 2 * (cs.length + Σ c.size) * (a.size + 1)` |
| `V.AllowsAllCostBound` (proven by `V.allowsAll_cost_bound`) | `(V.allowsAllCounted cs actions).2 ≤ 2 * (cs.length + Σ c.size + 1) * Σ (a.size + 1)` |
| `V.allowsCounted_fst` | `(V.allowsCounted cs a).1 = (V.grant cs).allows a` |
| `V.allowsAllCounted_fst` | `(V.allowsAllCounted cs actions).1 = (V.grant cs).allowsAll actions` |
| `V.holdsCounted_fst` | `(c.holdsCounted a).1 = c.holds a` |
| `V.holdsCounted_steps_le` | `(c.holdsCounted a).2 + 1 ≤ 2 * (1 + c.size) * (a.size + 1)` |

`Σ c.size` is `(cs.map Caveat.size).sum` and `Σ (a.size + 1)` is
`(actions.map (·.size + 1)).sum`. The constant is `k = 2` in every
vocabulary.

The batch bound carries `+ 1` in its grant factor. Visiting each action's
list cell costs one step whatever the grant, so the empty grant checks a batch
of `n` actions in exactly `n` steps (`Cost.allowsAllCounted_nil_steps`), and a
grant factor of `cs.length + Σ c.size` alone, which is `0` for the empty
grant, would be false for every non-empty batch. The single-action bound has
no such term: the empty grant checks one action in zero steps.

### 2. Attenuation

| Lean name | Statement |
|---|---|
| `attenuate_narrows` | `(g.attenuate c).narrower g` |
| `attenuateAll_narrows` | `(g.attenuateAll cs).narrower g` |
| `narrower_refl` | `g.narrower g` |

### 3. Chaining

| Lean name | Statement |
|---|---|
| `narrower_trans` | `g.narrower h → h.narrower k → g.narrower k` |
| `Delegates.narrower` | `Delegates root g → g.narrower root` |
| `Grant.delegate_delegates` | `Delegates root (root.delegate cs)` |
| `delegate_narrows` | `(root.delegate cs).narrower root` |
| `allowsAll_of_narrower` | `g.narrower h → g.allowsAll actions = true → h.allowsAll actions = true` |

### Vocabulary lemmas

| Lean name | Statement |
|---|---|
| `Chain.contractIn_iff`, `functionIn_iff`, `argI128AtMost_iff`, `argEq_iff` | each Chain caveat on an `invoke` holds iff its condition does |
| `Chain.argEq_kind` | `argEq i val` holds only when `args[i]? = some w` with `w.kind = val.kind` (the same constructor) |
| `Chain.argEq_false_of_kind_ne`, `Chain.argEq_bytes_false_of_other` | an argument of another constructor fails `argEq`; an `other xdr` argument fails `argEq i (.bytes b)` for every `b`, `xdr` included |
| `Chain.holds_createContract` | every Chain caveat is false on `createContract` |
| `Chain.restricted_denies_createContract` | `cs ≠ [] → (grant cs).allows (.createContract h) = false` |
| `Files.isPrefix_iff`, `Files.pathUnder_iff` | `pathUnder p` holds iff `p <+: a.path` (`List.IsPrefix`) |
| `Files.home_a_not_prefix_home_ab` | `¬ ["home", "a"] <+: ["home", "ab"]` |
| `Files.home_a_not_under_home_ab` | `pathUnder ["home", "a"]` is false on `["home", "ab"]` |
| `Files.modeIn_iff`, `Files.readOnly_denies_write` | `modeIn` is membership; read-only denies writes |
| `Network.hostIn_iff`, `portIn_iff`, `schemeIn_iff` | each Network caveat is membership of its field |
| `Signing.keyIn_iff`, `networkIn_iff`, `payloadIn_iff` | each Signing caveat is membership of its field |

### 4. Budget safety

`AttenuatingGrants/Budget.lean` models budgets as allowances along the
delegation tree. The ledger is a list of nodes, one per grant:

| Definition | Meaning |
|---|---|
| `Node` | `parent : Option Nat` (toward the root), `allowance : Nat`, `spent : Nat` (every successful spend at or under the node) |
| `Ledger` | `List Node`, indexed from zero; a parent precedes its children |
| `Ledger.Within l i a` | `a` is `i` or an ancestor of `i`: a spend at `i` charges `a` |
| `Ledger.walk`, `Ledger.chargePath` | walk from the spender to its root, failing at the first node that cannot take the amount, a missing node, or a parent link that does not point to an earlier node |
| `Ledger.spend l i amount` | one transaction: the outcome and the ledger after it; success charges every node on the chain, failure returns `l` with `.overdrawn a`, `.noSuchNode a` or `.badParent a` |
| `Ledger.refill l i extra` | raise node `i`'s allowance by `extra`; fails past `amountMax`; an admin-document action, never an agent's |
| `Ledger.append l parent allowance` | add a node with nothing spent at index `l.length`, under `parent` (delegation, with any allowance) or as a new root for `none` (an admin-document action); fails with `.noSuchNode p` if `parent = some p` and `p ≥ l.length` |
| `Ledger.run l ops` | apply a list of spends, refills and appends; returns the final ledger and the log of successful spends |
| `spentUnder l log a` | the total of the logged spends made at or under `a` in the tree of `l` |
| `Ledger.ParentsFirst l` | every parent link points to an earlier node |

Allowances oversubscribe: children's allowances may sum to more than their
parent's, and nothing restricts a child's allowance relative to its
parent's, at delegation (`append`) or later. Because a spend charges every ancestor or fails changing nothing,
spending under a node still never exceeds that node's allowance. An
`.overdrawn a` error names the first node on the chain, counting from the
spender, that cannot take the amount; that node is where the refill request
goes, up the delegation chain to a human approver.

| Lean name | Statement |
|---|---|
| `Ledger.spend_ok_charges` | success: `l.Within i a → l'[a]? = l[a]?.map (spent + amount)` |
| `Ledger.spend_ok_unchanged` | success: `¬ l.Within i a → l'[a]? = l[a]?` |
| `Ledger.spend_ok_length` | success: `l'.length = l.length` |
| `Ledger.spend_error` | failure: `(l.spend i amount).1 = .error e → (l.spend i amount).2 = l` |
| `Ledger.spend_overdrawn` | `.overdrawn a` names a node with `l.Within i a` and `allowance < spent + amount` |
| `Ledger.mem_walk` | the walk returns exactly the nodes `a` with `l.Within i a` |
| `Ledger.parentOf_spend`, `parentOf_refill` | spends and refills change no parent link |
| `Ledger.append_ok_iff` | `l.append p x = (.ok k, l') ↔ (∀ q, p = some q → q < l.length) ∧ k = l.length ∧ l' = l ++ [⟨p, x, 0⟩]` |
| `Ledger.append_error` | failure: `(l.append p x).1 = .error e → (l.append p x).2 = l` |
| `Ledger.getElem?_append_of_lt` | `j < l.length → (l.append p x).2[j]? = l[j]?` |
| `Ledger.spend_withinAllowance`, `refill_withinAllowance`, `append_withinAllowance`, `run_withinAllowance` | every node's `spent ≤ allowance` is preserved |
| `Ledger.spend_bounded`, `refill_bounded` | every allowance `≤ amountMax` is preserved |
| `Ledger.append_bounded` | `l.Bounded → x ≤ amountMax → (l.append p x).2.Bounded` |
| `Ledger.spend_parentsFirst`, `refill_parentsFirst`, `append_parentsFirst`, `run_parentsFirst` | `ParentsFirst` is preserved |
| `Ledger.run_extends` | a run keeps every node and every existing node's parent link |
| `Ledger.parentOf_run`, `spentUnder_run` | a run without appends changes no parent link, so `spentUnder` over its final ledger is `spentUnder` over its starting one |
| `Ledger.within_of_walk` | a successful walk's chain is the same in every ledger that keeps the walked ledger's parent links |
| `Ledger.spent_run` | after a run, each node's spent is its starting spent (`0` for an appended node) plus `spentUnder` over the final ledger |
| `Ledger.spentUnder_le_allowance` | from a ledger with nothing spent, after any run, `spentUnder l' log a ≤` node `a`'s allowance, where `(l', log) = l.run ops` |

`spentUnder_le_allowance` has no hypothesis on the allowances, so it holds
however much a node's children oversubscribe it, and covers runs that append
nodes. It measures each logged spend against the final tree: an append adds a
node and changes no existing parent link (`run_extends`), and a successful
spend's chain lies inside the ledger it was made on (`within_of_walk`), so a
spend is under `a` in the final tree exactly when it charged `a`. On a run
without appends the final tree is the starting one (`spentUnder_run`).

`example`s at the end of the module check by `rfl`: a root of 10 with two
children of 8 each; after the first child spends 8, the second child's spend
of 3 fails as `.overdrawn 0`, and its spend of 2 succeeds. The first child then
delegates 20, more than its own 8, to a new node 3, whose spend of 9 fails at
the first child and whose spend of 8 succeeds, charging node 3, the first
child and the root.

The failure half of theorem 4 holds in the model by the shape of `spend` (the
error branch returns its input ledger), and in the Rust code by
`Budget.extracted_spend_error` (see [Budgets](#budgets)).

**Amounts.** The model uses unbounded `Nat`; the Rust evaluator uses `u128`.
`amountMax` is `2 ^ 128 - 1`. A refill fails when the new allowance would
exceed it, matching Rust's `checked_add`. A spend needs no bound: every Rust
allowance is at most `amountMax`, so whenever `spent + amount` overflows a
`u128` it also exceeds the allowance, and both the model and the code fail as
overdrawn at the same node. On ledgers whose fields fit in `u128` (which
`spend_bounded`, `refill_bounded` and `spend_withinAllowance` keep true) every
model value is a `u128` value, so the equivalence can relate the two by each
scalar's value as a `Nat`, with no wrapped or saturated case. Indices are `Nat` in the
model and `usize` in Rust.

**Termination.** `walk` recurses on its fuel, the ledger's length, matching
the Rust loop bound. Every step moves to a strictly earlier node, so the fuel
runs out only on an empty ledger.

All names are in the `AttenuatingGrants` namespace.

## Extracted evaluator

The proof runs from the Rust code back to the model:

1. `crates/grant-eval` is the evaluator, in the restricted Rust subset its
   README describes.
2. `scripts/extract.sh` translates it to Lean: Charon compiles the crate to
   LLBC and Aeneas translates the LLBC to `AttenuatingGrants/Extracted/GrantEval.lean`
   (generated; never edited by hand).
3. `AttenuatingGrants/Equiv/` proves that the translation computes the model.
4. The same Rust compiles to `wasm32v1-none` for both boundaries.

### Pinned tools

| Tool | Version |
|---|---|
| Aeneas | commit `ab34bd28458a08c150b7cbf1873e59af74588138` (release tag `nightly-2026.10.31-ab34bd2`) |
| Charon | commit `7b462d9159db2ed3015162352183906a30bfafc6` (`0.1.304`), the commit Aeneas's `charon-pin` and `flake.lock` name |
| Charon's Rust | `nightly-2026-09-17`, from Charon's `rust-toolchain` |
| Aeneas's Lean library | the same Aeneas commit, as a Lake dependency (`lakefile.toml`) |

`scripts/extract.sh` takes Charon and Aeneas from Aeneas's Nix flake at the
pinned commit (`nix shell github:AeneasVerif/aeneas/<rev>#aeneas`), whose
lock fixes Charon and its Rust toolchain, and runs:

```sh
charon cargo --preset=aeneas --error-on-warnings   # in crates/grant-eval
aeneas -backend lean -warnings-as-errors -abort-on-error grant_eval.llbc
```

To regenerate after changing the Rust, from the repository root:

```sh
formal/scripts/extract.sh            # needs Nix with flakes
# or, without Nix:
docker run --rm -v "$PWD":/src -w /src nixos/nix:2.28.3 formal/scripts/extract.sh
```

`formal/scripts/extract.sh --check` regenerates into a temporary directory
and fails if the result differs from the committed files; CI runs it.

### Denotation

Each `Equiv/V.lean` maps the extracted types to the readable ones:
`denoteAction`, `denoteCaveat`, and `denoteGrant g = V.grant (g.val.map denoteCaveat)`
for a Rust caveat slice `g`. Byte strings map by `Extraction.bytesOf`, each
`u8` to the `UInt8` with the same bit vector; `i128` to its `BitVec 128`;
`u16`/`u64` to the `UInt16`/`UInt64` with the same bit vector; a `u32`
argument index to its value; enums constructor for constructor.

### Equivalence

For each vocabulary `V` (`Chain`, `Files`, `Network`, `Signing`), with
`grant_eval.v` the extracted module:

| Lean name | Statement |
|---|---|
| `V.extracted_allows` | `grant_eval.v.allows g a = ok ((denoteGrant g).allows (denoteAction a))` |
| `V.extracted_allowsAll` | `grant_eval.v.allows_all g acts = ok ((denoteGrant g).allowsAll (acts.val.map denoteAction))` |
| `V.holds_eq` | `grant_eval.v.holds c a = ok ((denoteCaveat c).holds (denoteAction a))` |
| `Chain.extracted_denies_createContract` | `g.val ≠ [] → grant_eval.chain.allows g (.CreateContract h) = ok false` |
| `Chain.extracted_val_eq_kind` | `grant_eval.chain.val_eq a b = ok true → (denoteVal a).kind = (denoteVal b).kind` |
| `Chain.extracted_val_eq_other_bytes` | `grant_eval.chain.val_eq (.Other x) (.Bytes y) = ok false` for every `x`, `y` |

Each holds for every input, so the extracted functions return `ok`: they
neither fail nor diverge. The building blocks are in `Equiv/`:
`Loop.lean` (`loop_any` and `loop_all`, the two loop shapes of the
evaluator, proven by induction on the elements left), `Bytes.lean`
(`bytes_eq_eq`, `bytes_in_eq`) and `Eval.lean` (`eval_allows_eq`,
`eval_allows_all_eq` for the generic evaluator over any `Check` instance).
`Files.is_prefix_eq` relates the Rust path-prefix loop to the model's
`isPrefix`, and `Chain.val_eq_eq` the Rust value comparison to equality of
denoted values.

### Budgets

`Equiv/Budget.lean` relates `grant_eval::budget` to `Budget.lean`.
`denoteLedger` maps each Rust node to `⟨parent.map val, allowance.val,
spent.val⟩`; it is injective (`denoteLedger_injective`), so the denotation of
a returned ledger determines it. Every Rust ledger denotes a model ledger
whose fields fit in `u128`, so the theorems hold for every Rust ledger, with
`L = denoteLedger s.val`:

| Lean name | Statement |
|---|---|
| `Budget.extracted_check_spend` | `check_spend s i x = ok r` with `r` denoting `(L.chargePath i x).map (fun _ => ())` |
| `Budget.extracted_spend` | `spend s i x = ok (r, s')` with `denoteSpend r = (L.spend i x).1` and `denoteLedger s'.val = (L.spend i x).2` |
| `Budget.extracted_spend_error` | `spend s i x = ok (.Err e, s') → s' = s` |
| `Budget.extracted_refill`, `extracted_refill_error` | the same for `refill` |
| `Budget.extracted_append` | `v.length < Usize.max →` `append v p x = ok (r, v')` with `r` and `v'` denoting `L.append (p.map val) x` |
| `Budget.extracted_append_error` | `append v p x = ok (.Err e, v') → v' = v` |
| `Budget.fits_eq` | `fits n x = ok (decide (n.spent.val + x.val ≤ n.allowance.val))` |
| `Budget.check_spend_loop_eq` | the checking loop after `step` steps is `L.walk x (s.length - step)` |
| `Budget.charge_loop_eq` | after `L.walk x fuel i = .ok path`, the charging loop returns `ok s'` with `denoteLedger s'.val = L.charge path x` |

Each returns `ok` on every input (for `append`, on every vector below
`Usize.max` nodes), so the extracted functions neither fail nor diverge. In
particular the charging loop's plain `spent += amount` never overflows:
`charge_loop_eq` discharges it from the walk, which found
`spent + amount ≤ allowance ≤ u128::MAX` at each node of the path, and the
path visits each node once. That loop follows the parent links of the ledger
it is charging, which charging leaves unchanged, so it visits exactly the
chain `check_spend` accepted.

Budget safety restated about the extracted code:

| Lean name | Statement |
|---|---|
| `Budget.extracted_spend_ok_charges` | `spend s i x = ok (.Ok (), s') → L.Within i a → (denoteLedger s'.val)[a]? = L[a]?.map (spent + x)` |
| `Budget.extracted_spend_ok_unchanged` | `spend s i x = ok (.Ok (), s') → ¬ L.Within i a → s'.val[a]? = s.val[a]?` |
| `Budget.extracted_spend_ok_length` | `spend s i x = ok (.Ok (), s') → s'.length = s.length` |
| `Budget.extracted_spend_overdrawn` | `.Err (.Overdrawn a)` names a node with `L.Within i a` and `allowance < spent + x` |
| `Budget.extracted_spend_withinAllowance`, `extracted_refill_withinAllowance`, `extracted_append_withinAllowance` | `∀ n ∈ s.val, n.spent.val ≤ n.allowance.val` is preserved |
| `Budget.extracted_run` | `v.length + ops.length ≤ Usize.max →` `runExtracted v ops = ok (v', log)` with `v'` and `log` denoting `L.run (ops.map denote)` |
| `Budget.extracted_run_withinAllowance` | the same bound, and spent within allowance at the start, keep it at the end |
| `Budget.extracted_spentUnder_le_allowance` | the same bound, and nothing spent at the start: `runExtracted v ops = ok (v', log)` with `spentUnder (denoteLedger v'.val) log a ≤` node `a`'s allowance for every node of `v'` |

`runExtracted` applies a list of `RustOp`s (spend, refill, append with Rust
arguments) by calling the extracted functions as a Rust caller holding the
ledger in a `Vec` does: `spend` and `refill` on the vector's slice
(`Vec::deref_mut`), `append` on the vector. It is a Lean definition over the
extracted functions, not extracted code.

`Vec::push` is the one call in `budget` that Aeneas's model lets fail: it
fails once a vector holds `Usize.max` elements. The append and run theorems
assume the ledger stays below that many nodes. A real `Vec<Node>` cannot reach
it (allocation fails long before, and a failed allocation aborts), but the
model has no allocator, so the bound is stated rather than proven.

### Attenuation and chaining on Rust caveat slices

`Extraction.Narrower allows g h` holds when every action the extracted
`allows` accepts under the slice `g` it accepts under `h`; it is stated on the
extracted function's results alone. `Extraction.Delegates root g` holds when
`g` is reached from `root` by zero or more pushes of one caveat each. For each
vocabulary `V`:

| Lean name | Statement |
|---|---|
| `V.extracted_narrower_push` | `g'.val = g.val ++ [c] → Narrower grant_eval.v.allows g' g` |
| `V.extracted_narrower_of_subset` | `(∀ c ∈ g.val, c ∈ g'.val) → Narrower grant_eval.v.allows g' g` |
| `V.extracted_delegates_narrower` | `Delegates root g → Narrower grant_eval.v.allows g root` |
| `V.extracted_allowsAll_of_delegates` | `Delegates root g → allows_all g acts = ok true → allows_all root acts = ok true` |
| `Extraction.Narrower.trans` | `Narrower` is transitive |

They follow from the equivalence through `Extraction.Implements` (an
extracted `allows` computes `Grant.allows` of a denoted grant) and the generic
`Implements.narrower_of_subset`, `narrower_push`, `narrower_of_delegates` and
`ImplementsAll.allows_all_of_narrower`.

### Trusted base

Proven: the Lean translation agrees with the model. Trusted, not proven:

- **rustc**, which compiles the same source to the host and to
  `wasm32v1-none`;
- **Charon and Aeneas**, that the Lean translation has the Rust code's
  semantics;
- **Aeneas's Lean library**, its models of the Rust core and alloc items the
  translation calls (`Slice`, `Vec`, `Vec::deref`, `Vec::deref_mut`,
  `Vec::len`, `Vec::push`, slice indexing, `get` and `get_mut`, `len`,
  checked `usize` addition, checked and unchecked `u128` addition,
  `u32 as usize`, scalar comparison);
- the **Soroban SDK** and the **host wiring** that builds actions, as for the
  model.

## Axioms

Every theorem above depends on at most Lean's built-in axioms `propext`,
`Quot.sound` and `Classical.choice` (`spentUnder` decides `Within`
classically); none depends on an axiom declared by Aeneas's Lean library.
`AttenuatingGrants/Axioms.lean` records each theorem's `#print axioms` output
under `#guard_msgs`, so `lake build` fails if any of them gains a dependency
(such as `sorryAx`).

## Proven and unproven

Proven, and checked by `lake build`: every theorem in the tables above, the
totality of every evaluation function, the cost bounds
`V.AllowsCostBound` and `V.AllowsAllCostBound` for all four vocabularies, and
the agreement of the Charon + Aeneas translation of `crates/grant-eval` with
the model, with attenuation and chaining carried over to Rust caveat slices
and budget safety (theorem 4, spent within allowance, and total spent under a
node within its allowance, over runs that grow the tree) carried over to the
Rust budget code.

Stated but unproven, or not yet stated:

- **Cost of the deployed evaluator**: the bound is proven for the counted Lean
  evaluators. That the Rust evaluator's work is proportional to these step
  counts is not proven; it is to be cross-checked against Soroban CPU
  instruction counts.
- **Translation and compilation**: that the Lean translation has the Rust
  code's semantics (Charon, Aeneas and Aeneas's Lean library) and that rustc
  compiles that code faithfully are trusted, not proven
  ([Trusted base](#trusted-base)).
- **Ledger size**: the append and run theorems about the extracted code
  assume the ledger holds fewer than `Usize.max` nodes, where Aeneas's model
  of `Vec::push` fails ([Budgets](#budgets)). That a real ledger stays below
  it is a property of the allocator, not proven here.
- **Callers of the budget code**: `runExtracted` is a Lean definition of how a
  caller sequences the extracted functions. That the deployed wiring calls
  them that way, passes the node of the grant being spent under, and exposes
  `refill` and root issuing only to the admin document is not proven.
- **Ledger storage and approval**: where the ledger is stored (for example a
  Soroban contract) and how a refill request reaches its approver are outside
  this package.
