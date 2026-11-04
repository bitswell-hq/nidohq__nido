# grant-signer

The Soroban boundary of attenuating grants. An AI agent's authority over a
Nido account is a grant held in this contract: a `rule-eval` rule set (the
agent's scoped rules, narrowed by each delegation's attenuation steps), the
holder's ed25519 key, and a budget node. Every authorization an agent gives
for the account passes through this contract's `__check_auth`, which checks
every context with `rule_eval::authorize` over the grant's rule set and
charges every transfer of the budget asset with `rule_eval::spend`, the rule
check and budget tree of
[rule-core](https://github.com/bitswell/soroban-rule-core).

One instance serves one account and is deployed with that account's address.
The account is the Perch account Nido's factory mints, unchanged.

## How an agent authorizes

The owner gives agents their rules in a scoped document, applied with the
account's `apply_scope(scope, doc)` through its admin rule. The document
declares this instance as a delegated signer and names it as the signer of
the rules agents act through:

```json
{
  "version": 1,
  "network": "<network passphrase>",
  "signers": [{"id": "grants", "address": "<this contract>"}],
  "rules": [
    {"name": "a-token", "scope": {"type": "contract", "address": "<token>"}, "principals": {"type": "all", "signers": ["grants"]}}
  ]
}
```

The account lowers it to `rule-eval` rules, each carrying the scope
generation it was applied under, and returns them from its
`scope_rule_set(scope)` view. The owner issues a grant with exactly those
rules: `issue(key, scope_rule_set(scope), asset, allowance)`.

An agent's authorization is one `AddressWithDelegates` entry for the account.
The account's signature is an OZ `AuthPayload` whose only signer is
`Signer::Delegated(<this contract>)` and whose rule ids select the scoped
rules (their OZ ids are in the account's `scope(scope)` view); the delegate
signature is a [`GrantSignature`](src/lib.rs): the grant id and the holder's
ed25519 signature over the host's signature payload.

1. The account's `__check_auth` runs Perch's reserved-name guard and freeze,
   refuses a scoped rule of another scope generation (`StaleScope`) or one
   chosen for a call on its recovery controller or ZK contracts, then
   decides with `rule_eval::authorize` over the chosen rules, under every
   payload signer, and only then authenticates each signer: this contract
   through CAP-0071 `delegate_account_auth`.
2. The host calls this contract's `__check_auth` with the account's signature
   payload, the grant signature, and every context of the account's
   authorization.
3. This contract refuses unless all of its checks pass (below), and a refusal
   fails the account's authorization.

So every context this contract sees has already passed the account's check
against the scoped rule chosen for it, generation included, and this
contract's check of the grant comes on top: the composition rule-core proves
as `Account.chain` (milestone 4 of its `ARCHITECTURE.md`), under which
anything a grant attenuated from a scope's rules authorizes is allowed by the
scoped document, touches no excluded contract, and is made in the generation
the scope was applied under.

## Why a delegated signer and not a policy contract

A Perch account checks its documents' rules itself, with `rule-eval` in its
own `__check_auth`; its policy-document schema
(`vendor/perch/packages/perch-js/schemas/policy.schema.json`, `rule`) has no
member that names a policy contract, and the account exports none of OZ's
rule, signer or policy mutation entry points
(`vendor/perch/crates/perch-account/src/lib.rs`). `ARCHITECTURE.md` records
the same for Nido's existing OZ policies.

The same schema does declare delegated signers (`signerDecl` with an
`address`), which Perch's compiler lowers to `Signer::Delegated` and OZ
authenticates through `delegate_account_auth`. That host function calls the
delegate's `__check_auth` with the delegating account's signature payload and
its whole context list (`soroban-env-host` 29, `auth.rs`,
`delegate_account_auth`; Perch pins this as C2 in
`vendor/perch/crates/integration-tests/tests/cap71_semantics.rs`). So:

- This contract sees every context of the authorization tree, including
  contexts the submitter routed to other rules. Its guarantee does not depend
  on rule selection, which no signature binds for a delegated signer (Perch
  C4): it chooses its own rule for each context.
- For `AddressWithDelegates` credentials the payload preimage is
  `HashIdPreimageSorobanAuthorizationWithAddress`, which names the account
  (`auth.rs`, `get_signature_payload`). A holder's signature authorizes for
  that one account.
- Nothing in Perch or OpenZeppelin changes. Adding agents to an account is a
  scoped document plus one deployment.

## Grants

| Function | Authorized by | Effect |
| --- | --- | --- |
| `issue(key, rules, asset, allowance)` | the account | a root grant with rule set `rules`; `asset` must be a Stellar Asset Contract and `allowance` at most `i128::MAX` |
| `revoke(id)` | the account | marks `id` revoked, and with it every grant delegated from it |
| `rotate(id, key)` | the account | replaces `id`'s holder key |
| `refill(id, extra)` | the account | raises `id`'s allowance with `rule_eval::refill`, to at most `i128::MAX` |
| `delegate(parent, key, steps, allowance)` | this contract, for `parent`'s holder | a child grant whose rule set is `parent`'s with `steps` applied; `allowance` at most `i128::MAX` |
| `grant(id)`, `rules(id)`, `account()`, `overdrawn_at(id, amount)` | anyone | views; `rules(id)` is grant `id`'s rule set |

The account authorizes the admin functions by calling them itself: its
`execute(<this contract>, "issue", args)`, authorized by the owner's passkey
through the admin rule, makes the account the invoker, so the functions'
`account.require_auth()` passes.

A root grant's rules are stored as given, in Perch's `StoredRule` form (an
address as an `Address`, a function as a `Symbol`), the form the account's
`scope_rule_set` returns. `issue` refuses (`InvalidRules`) a rule with more
than one cap, a cap whose limit is not positive or whose period is 0
(`rule_eval::authorize` leaves cap validity to the shell that installs a
root), and rules of different generations.

A delegated grant stores its [`Step`](src/lib.rs)s, `rule-eval`'s ten
attenuation steps (`drop_rule`, `add_cond`, `restrict_functions`,
`remove_functions`, `add_cap`, `lower_cap_limit`, `lengthen_cap_period`,
`lower_valid_until`, `remove_signers`, `raise_threshold`), and its asset is
its parent's. Its rule set is its root's rules with every step on its
lineage replayed in order; `delegate` replays the parent's and applies the new
steps, refusing (`InvalidStep`) one `rule-eval` refuses. Every step narrows,
so a holder can only narrow: rule-core proves that a rule set any chain of
steps derives allows no context, under any signers, that its root does not
(`Derives.narrower`), and accepts no run of authorizations from empty records
that its root does not accept from its own (`attenuateAll_traceNarrower`). A
parent's id is smaller than its children's.

`rule-eval` has no rule that matches every contract, so a grant names the
contracts it allows.

`delegate` requires this contract's own authorization. Its `__check_auth`
accepts a context on this contract only if it is `delegate` whose `parent`
is the signing grant. A holder delegates by authorizing the contract's own
address; the host allows a contract's `require_auth` of itself to call its
own `__check_auth` (immediate re-entry, `host/frame.rs`), and refuses any
other re-entry. So `__check_auth` is also the check of this contract's own
address ([below](#the-two-roles-of-__check_auth)).

## `__check_auth`

In order, returning the first failure ([`GrantError`](src/error.rs)):

1. Load the signing grant and its ancestors: `NoSuchGrant`, or `Revoked` if
   any of them is revoked.
2. Verify the holder's ed25519 signature over the payload (a failure traps).
3. For each context:
   - a contract creation, with or without constructor arguments:
     `ContractCreation`;
   - a call on this contract other than the holder's own delegation:
     `NotHolder`;
   - a call on the account: `AccountCall`;
   - a call on the budget asset other than `transfer(from, to, amount)` with
     a non-negative `i128` amount: `UnmeteredCall`.
4. Read every other context, a contract call, through `soroban-facade`
   (`perch_rule_eval::convert::calls`: a contract and an address argument by
   its `ScAddress` XDR, a function and a symbol by its bytes, a string by its
   bytes, `i128`, `u64`, `bool` and bytes by value, any other argument as
   `Other` of its full `ScVal` XDR), replay the grant's rule set, and choose
   for each context the first rule that allows it (`rule_eval::rule_allows`)
   with this contract as the one authenticated signer: `NotAllowed` if a
   context holds a value the facade does not read or no rule allows it. Then
   `rule_eval::authorize` with those choices, the grant's spending records,
   the current ledger and the generation the grant's rules carry: `Expired`
   if a chosen rule has passed its last ledger, `CapExceeded` if a cap
   refuses a charge, `NotAllowed` for any other refusal.
5. Charge each budget-asset transfer to the grant and every ancestor with
   `rule_eval::spend` over the lineage's budget tree: `Overdrawn` if any
   node would pass its allowance.

Only when every check passes are the records `authorize` returned (when a
charge changed them) and the new `spent` values stored. A batch with no
context left after step 3 (only the holder's own delegation) is accepted
without a rule check, as nothing in it acts for anyone.

The generation `authorize` gets is the one the grant's rules carry, so it
refuses none of them as stale here. This contract cannot read the account's
scope generation: the account's `__check_auth` is on the call stack, and the
host refuses a call into it. The account holds that check (`StaleScope`,
step 1 of [How an agent authorizes](#how-an-agent-authorizes)).

A grant's caps are charged to that grant's own records, from empty when it
is issued or delegated: a child's charges do not reach its parent's records.
A scope's own caps are the account's, charged on its scoped rule by every
authorization whichever grant gives it, and rule-core proves that every run
a grant accepts from empty records, the scope's rules accept
(`Account.chain_trace`).

The contract writes nothing before it refuses. A refused authorization fails
the call that asked for it; a calling contract can catch that failure with
`try_invoke_contract` and go on, so the transaction need not fail. The host
then rolls back the failed call's storage writes and authorization state.
The charge is written during the `require_auth` of the authorization's root,
inside the call that encloses every call the authorization allows, so if
that call fails, caught or not, the charge is rolled back with it, and a
charge stays only with the root call it was made in.
`a_caught_refusal_or_failure_leaves_the_budget_as_if_the_call_never_ran`
(`crates/integration-tests/tests/it/grant_signer.rs`) catches a refusal and a
failure after the charge, and finds the budget unchanged both times.

## The two roles of `__check_auth`

The host calls this contract's `__check_auth` in two roles, with the same
three arguments (a signature payload, a `GrantSignature`, the contexts), so
the contract cannot tell which role it is in:

1. **The account's delegated signer.** OZ authenticates a delegated signer
   only through `delegate_account_auth` (`stellar-accounts`,
   `smart_account/storage.rs`, `authenticate`), which passes the account's
   payload, whose preimage names the account, and the account's contexts
   (`soroban-env-host` 29, `auth.rs`, `delegate_account_auth`).
2. **The check of this contract's own address**, whenever a call needs that
   address's authorization: this contract's `delegate`, any other contract
   that calls `require_auth` on this address, and a deployment with this
   address as deployer. The payload is that address's and the contexts are
   what it authorizes.

The checks are the same in both roles. In the second, a holder authorizes
only as this contract's address, and only within its grant: the guards
refuse every contract creation, every call on this contract but the holder's
own delegation, every call on the account and every unmetered call on the
budget asset; the rule set bounds every other call; and transfers of the
budget asset are charged to the grant. This gives no authority over the
account: the account accepts this contract only through
`delegate_account_auth`, so this address's own authorization never stands
in for the account's. Besides this contract's own `delegate`, the deployment
asks for this address's authorization only for calls that act on the address
itself, such as a transfer from its own balance.

Two consequences are stated, not enforced:

- Any contract can call `require_auth` on an address it is given. A holder
  whose grant allows a contract can have it ask for this address's
  authorization, and authorize whatever that contract does as this address
  within the grant's rules, including moving what the address holds. A
  transfer of the budget asset is still charged to the grant; one of any
  other asset is bounded only by the rules.
- The deployment gives the address no balance: its balance in a Stellar
  Asset Contract, the native one included, is a contract-data entry that is
  absent until something is sent, and storage rent is paid in fees by each
  transaction's submitter. But the address is published in the account's
  document, and whatever anyone sends to it can be moved this way, by any
  holder whose grant allows the transfer. So nothing should be sent to it.

No rule allows a contract creation, and the guard refuses one first with
`ContractCreation` whatever the grant, in both roles.

## Threat model coverage

The adversary is an agent the owner authorized, trying to widen its own
authority.

| Attempt | What refuses it |
| --- | --- |
| `issue`, `revoke`, `rotate` or `refill` its grant | They need the account's authorization. No agent rule is scoped to this contract, so the account has no rule that allows the call (`RuleEvalRefused`). If a document did scope one, the account would ask this contract while its admin function runs, and the host refuses the re-entry. Asked directly, the contract refuses every call on itself but the holder's own delegation (`NotHolder`). |
| Delegate from an ancestor's grant (dropping its own steps) or a grant it does not hold | `NotHolder` |
| Change its rule or policies (`apply_doc`, `apply_scope`), call the account's `execute`, schedule or cancel upgrades | No agent rule is scoped to the account: a scoped document cannot have one (`ScopeEscalation`), and the admin document's rules are the owner's (`RuleEvalRefused`). A document that gives agents a rule for the account still meets `AccountCall`. |
| A call the grant allows that makes a disallowed call inside the same authorization | Every context is checked; one disallowed context refuses the whole authorization. A nested call the signed tree leaves out is refused by the host. |
| Deploy a contract | `ContractCreation`, under every grant and in both roles of `__check_auth`. Perch documents have no creation scope, so through the account the account refuses it first. |
| Hand off the budget asset (`approve`, `burn`, `transfer_from`) | `UnmeteredCall` |
| Overspend through siblings or nested transfers | Every transfer in the authorization is charged to the spender and every ancestor; the first overdrawn node fails the spend and nothing is stored. |
| Keep acting after the owner recovers the account | A completed recovery advances the account's scope generation, so the account refuses every scoped rule applied before it (`StaleScope`), and Perch's credential index refuses any later document that names this contract (`WipedCredential`). |

## Budgets

A root grant names one Stellar Asset Contract (the native asset's or any
other's); `issue` refuses any other contract. Every grant under the root
meters the same asset. Allowances are cumulative: they do not reset with
time. Children's allowances may sum to more than their parent's, because
every ancestor is charged in the same authorization. Transfers of other
assets are bounded by the rule set: a condition such as
`ArgI128AtMost(2, n)` per call, a spending cap per window of ledgers, or a
rule set that leaves the asset out.

Grant ids index one ledger, `formal/AttenuatingGrants/Budget.lean`'s
`Ledger`: a grant's `parent`, `allowance` and `spent` are its node. The
contract never holds that ledger whole. [`src/budget.rs`](src/budget.rs)
runs each step on `rule_eval`'s budget tree:

- `issue` stores a root and `delegate` a grant under the delegator's, at the
  next id with nothing spent, which is `append` on the whole ledger.
- `refill` calls `rule_eval::refill` on a tree of the one grant and stores the
  new allowance.
- An authorization builds the tree of the signing grant's lineage alone
  (root first, each node's parent the one before it), calls
  `rule_eval::spend` on it at the last node once per metered transfer,
  stopping at the first failure, and only if every spend succeeds stores each
  node's `spent` into its grant.

Grants store `u128` amounts and `rule_eval` counts in `i128`. `issue`,
`delegate` and `refill` refuse an allowance, a refill or a raised allowance
above `i128::MAX` (`AllowanceTooLarge`), so every stored amount converts. No
Stellar Asset Contract transfer moves more than `i128::MAX`, so the bound
refuses no transfer a grant could otherwise pay for.

`formal/AttenuatingGrants/Signer.lean` follows these steps and proves that
they compute the whole ledger's result: a spend or a check on the lineage
ledger has the whole ledger's outcome at the signing grant, with node `k`
of the lineage ledger standing for the lineage's `k`th grant, and storing the
lineage ledger after an authorization's spends leaves the whole ledger after
them
(`Ledger.spend_lineage`, `spendAll_lineage`, `writeBack_spendAll`;
`Ledger.refillGrant_eq` for `refill`). The spends of one authorization are
all or nothing, so every sequence of this contract's calls is a run of the
whole ledger (`Signer.Run.exists_run`), and the total spent at or under any
grant never exceeds its allowance (`Signer.spentUnder_le_allowance`).

The calls go to `rule_eval::spend` and `refill`, which rule-core proves
compute its own budget model (`formal/RuleCore/Model/Budget.lean` there,
milestone 3 of its `ARCHITECTURE.md`). `formal/` here proves the same for
`grant_eval::budget`, whose extracted `spend` and `check_spend` compute this
ledger (`Budget.extracted_spendAll_lineage`, `extracted_check_spend_lineage`).
That rule-core's budget model is this ledger is not proven. It is tested:
[`src/budget/tests.rs`](src/budget/tests.rs) runs this contract's budget path
and `grant_eval::budget` on 200,000 random lineage ledgers and finds the same
spend outcome, overdrawn grant and ledger at every step, the one difference
being the refusal above `i128::MAX`. What else remains trusted is that the
code below is those definitions ([Trusted wiring](#trusted-wiring)).

`overdrawn_at(id, amount)` names the nearest grant on `id`'s lineage that
cannot take `amount`: where a refill request goes. `refill` is the account's.

## Requirements on the account's document

Stated, and met by the documents the tests apply; nothing on-chain checks
them:

- A holder key reaches the account only through this contract. Registering
  it as a signer by another route (an ed25519 verifier on some rule) lets it
  authorize without its grant.
- The document names its own account's instance. This contract cannot see
  which account delegated to it, so a document naming another account's
  instance lets that account's grant holders sign for this one, with the
  `AccountCall` guard protecting the other account instead.
- Agents' rules are in a scoped document, and grants are issued with its
  rules. A rule for agents in the admin document is not ended by a recovery
  whose target keeps it, and a grant issued with rules other than a scope's
  is bounded by the account's own check only through whichever rule the
  agent's payload chooses there.

## Trusted wiring

`rule-eval` and `soroban-facade` are rule-core's, proven against its Lean
model there, and the vectors of the pinned rev run here
([Tests](#tests)). What connects them to Soroban is not proven:

- `src/rules.rs` reads stored rules with `perch_rule_eval`'s reading of a
  `StoredRule` and a step's values, symbols and signers with its
  conversions of host values (`perch_rule_eval::convert`), replays a
  lineage's steps, and chooses the first rule that allows each context.
- `src/contract.rs` reads contexts through `perch_rule_eval::convert::calls`
  (soroban-facade), applies the guards, calls `rule_eval::authorize`, keeps
  each grant's records, and holds the budget path that `formal/` follows:
  its storage holds grants `0` to `NextId - 1`, none ever removed, and they
  are the ledger; `issue` and `delegate` store at `NextId`; `lineage`,
  `ledger`, the spend loop (`budget::spend_all`) and the store loop are
  `Ledger.IsLineage`, `Ledger.chain`, `Ledger.spendAll` and
  `Ledger.writeBack` of `formal/AttenuatingGrants/Signer.lean`; `refill` is
  `Ledger.refillGrant`.
- `src/actions.rs` reads what a call on the budget asset spends.
- `src/budget.rs` converts stored `u128` amounts to `rule_eval`'s `i128`
  and back, and calls `rule_eval`; its unit tests check it against
  `grant_eval::budget` ([Budgets](#budgets)).
- `crates/grant-relay` reads a call's XDR through soroban-facade the same
  way; a test checks the two readings agree on every argument type.
- The host's CAP-0071 behaviour, which Perch's `cap71_semantics.rs` pins for
  the pinned `soroban-env-host` and OZ fork.

## Tests

`crates/integration-tests/tests/it/grant_signer.rs`, on a factory-minted
Perch account under enforcing authorization (`set_auths`), with grants
written as caveat lists and lowered to rule sets and steps by
`nido_integration_tests::grants`: allowed calls, disallowed functions,
contracts and arguments, a disallowed transfer nested inside an allowed call,
contract deployment in both roles of `__check_auth`, what a holder can and
cannot authorize as this contract's own address, every escalation in the
table above (including documents that wrongly scope agent rules to the
account or to this contract), delegation that narrows and cannot widen,
oversubscribed siblings with an overdrawn ancestor changing nothing, a
refused authorization and one failing after its charge, both caught by a
calling contract, leaving the budget unchanged, transfers charged across one
authorization, cascading revocation, key rotation, and the agreement of this
contract's reading of contexts with the relay's. On rule sets: a grant
issued with an account's scoped rules acting until a recovery completes, a
cap added by delegation bounding spending per window, a last ledger ending a
rule, the signer steps, and what `issue` and `delegate` refuse. Each refusal
is asserted by the contract that refused and its error, read from the host's
event log.

`crates/integration-tests/tests/it/grant_signer_corpus.rs` replays a
recorded corpus: 160 generated scenarios whose outcomes a grant signer that
stored caveat lists and checked them with `grant_eval::chain::allows_all`
recorded (1,462 authorizations and every grant's state after each step),
with each grant's caveats lowered to its rule set and steps; every outcome
and state is the same.

```sh
just build-contracts
cargo test -p nido-integration-tests --test it grant_signer
```

`crates/grant-eval/tests/rule_eval.rs` and `chain.rs` check that
`rule_eval::allows_all` over a grant's lowering agrees with
`grant_eval::chain::allows_all` on its caveats, for every grant that names
its contracts: on 200,000 generated grants and batches, on chain.rs's
exhaustive universe of grants of up to three caveats, and on every case of
chain.rs.

`src/budget/tests.rs` checks the budget path against `grant_eval::budget` on
random lineage ledgers ([Budgets](#budgets)) and at the `i128::MAX` bound.
`tests/rule_eval_vectors.rs` checks the linked `rule_eval` and
`soroban-facade` against every rule and attenuation vector, cap trace,
authorization trace and budget trace rule-core's Lean model generates at the
pinned rev, and against its Soroban value and context vectors (through
`rule-eval-conformance`).

```sh
cargo test -p nido-grant-signer
cargo test -p grant-eval
```

## Costs

`enforce_costs` measures this contract's `__check_auth` from the wasm
`just build-contracts` produces (62,873 bytes; `soroban-env-host` 29.0.1
metering, the grant at depth 0, every rule's condition holding so each is
evaluated). A grant of `n` caveats is the one rule on the target its caveats
lower to, with a condition for each argument caveat:

| Caveats | 1 context: CPU instructions | 1 context: memory bytes | Each further context: CPU instructions | Each further context: memory bytes |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 1,459,759 | 560,607 | 203,291 | 3,030 |
| 4 | 1,545,050 | 573,391 | 214,808 | 2,979 |
| 16 | 1,811,513 | 616,791 | 254,594 | 2,928 |

One context includes the VM instantiation, the grant load and the signature
check; each further context is the difference between five contexts and one,
divided by four. A metered transfer (one context, charged and stored) costs
1,657,481, 1,679,191 and 1,683,728 instructions for 1, 4 and 16 caveats. A
whole agent transaction, `protected` authorized through the account with a
4-caveat grant, costs 3,021,451 instructions and 873,150 memory bytes,
against a per-transaction limit of 400,000,000 instructions.

```sh
cargo test -p nido-integration-tests --test it grant_signer::enforce_costs -- --nocapture
```

## Open questions

- Budget allowances never reset; a per-window bound is a cap on a rule,
  charged to the grant that holds it.
- Each context is checked against the first rule of the grant that allows
  it. A grant with two rules that allow one context, the first capped or
  expiring, refuses what a choice of the second would accept.
- Grants and their spending records live in persistent storage, extended to
  the network maximum on every write. An archived grant or record fails
  authorization until restored.
- Holder keys are ed25519 only.
