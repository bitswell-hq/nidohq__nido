# Attenuating Grants: Lean model

The readable Lean specification of attenuating grants and its first three
theorems. An AI agent's authority is a grant: a list of caveats over actions.
A grant holder can only add caveats and pass narrower copies to sub-agents;
issuing, revoking and key rotation live in a separate admin document that
agents never hold. One evaluator enforces grants at two boundaries, the
agent's WebAssembly host and the Soroban smart account, and this package is
the specification that evaluator is proven against.

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

## Theorems

### 1. Termination

Evaluation is total. `Grant.allows`, `Grant.allowsAll` and every
vocabulary's `Caveat.holds` (and `Files.isPrefix`) are ordinary Lean
definitions by structural recursion or `List.all`, with no `partial` or
`unsafe` anywhere in the package, so Lean's kernel checks that each one
terminates on every input.

The cost bound on evaluation is **stated later**: it is not in this package.

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

Proven, and checked by `lake build`: every theorem in the tables above, and the
totality of every evaluation function.

Stated but unproven, or not yet stated:

- **Cost bound** (theorem 1): stated later.
- **Evaluator equivalence**: the Rust evaluator, its Charon + Aeneas
  translation, and the proof that the translation agrees with this model are
  not in this package. Until that proof exists, these theorems are about the
  model, not the deployed evaluator.
- **Budgets** (theorem 4): not in this package.
