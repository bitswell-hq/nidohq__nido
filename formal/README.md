# Attenuating Grants: Lean model

The readable Lean specification of attenuating grants, its first three
theorems, and a step-counting evaluator with a proven cost bound. An AI
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
(`backends/lean/lean-toolchain` in AeneasVerif/aeneas) uses, so the
equivalence proofs can import this package and Aeneas's translation together.
The package has no Lake dependencies. Install Lean with
[elan](https://github.com/leanprover/elan); it reads `lean-toolchain` and
fetches the pinned release on the first `lake` call.

CI (`.github/workflows/formal.yml`) runs `lake build` on every pull request
that touches `formal/**` and on every push to `main`, after rejecting any
`partial`, `unsafe`, `sorry`, `admit`, `native_decide`, `implemented_by`,
`extern` or `axiom` in the sources.

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
compared as a signed integer (`BitVec.toInt`), `u64` is `UInt64`. Host
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
| `Chain.holds_createContract` | every Chain caveat is false on `createContract` |
| `Chain.restricted_denies_createContract` | `cs ≠ [] → (grant cs).allows (.createContract h) = false` |
| `Files.isPrefix_iff`, `Files.pathUnder_iff` | `pathUnder p` holds iff `p <+: a.path` (`List.IsPrefix`) |
| `Files.home_a_not_prefix_home_ab` | `¬ ["home", "a"] <+: ["home", "ab"]` |
| `Files.home_a_not_under_home_ab` | `pathUnder ["home", "a"]` is false on `["home", "ab"]` |
| `Files.modeIn_iff`, `Files.readOnly_denies_write` | `modeIn` is membership; read-only denies writes |
| `Network.hostIn_iff`, `portIn_iff`, `schemeIn_iff` | each Network caveat is membership of its field |
| `Signing.keyIn_iff`, `networkIn_iff`, `payloadIn_iff` | each Signing caveat is membership of its field |

All names are in the `AttenuatingGrants` namespace.

## Axioms

Every theorem above depends on at most Lean's built-in axioms `propext`,
`Quot.sound` and `Classical.choice`. `AttenuatingGrants/Axioms.lean` records
each theorem's `#print axioms` output under `#guard_msgs`, so `lake build`
fails if any of them gains a dependency (such as `sorryAx`).

## Proven and unproven

Proven, and checked by `lake build`: every theorem in the tables above, the
totality of every evaluation function, and the cost bounds
`V.AllowsCostBound` and `V.AllowsAllCostBound` for all four vocabularies.

Stated but unproven, or not yet stated:

- **Cost of the deployed evaluator**: the bound is proven for the counted Lean
  evaluators. That the Rust evaluator's work is proportional to these step
  counts is not proven; it is to be cross-checked against Soroban CPU
  instruction counts.
- **Evaluator equivalence**: the Rust evaluator, its Charon + Aeneas
  translation, and the proof that the translation agrees with this model
  (including that it never diverges) are not in this package. Until that
  proof exists, these theorems are about the model, not the deployed
  evaluator.
- **Budgets** (theorem 4): not in this package.
