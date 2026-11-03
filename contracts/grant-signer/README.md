# grant-signer

The Soroban boundary of attenuating grants. An AI agent's authority over a
Nido account is a grant held in this contract: a list of chain caveats, the
holder's ed25519 key, and a budget node. Every authorization an agent gives
for the account passes through this contract's `__check_auth`, which checks
every context of the authorization with `grant_eval::chain::allows_all` and
charges every transfer of the budget asset with `rule_eval::spend`, the
budget tree of [rule-core](https://github.com/bitswell/soroban-rule-core).

One instance serves one account and is deployed with that account's address.
The account is the Perch account Nido's factory mints, unchanged.

## How an agent authorizes

The account's policy document declares the instance as a delegated signer
and names it as the signer of the rules agents act through:

```json
"signers": [
  {"id": "owner", "verifier": "<WebAuthn verifier>", "key": "<passkey>"},
  {"id": "grants", "address": "<this contract>"}
],
"rules": [
  {"name": "admin", "scope": {"type": "self-admin"}, "principals": {"type": "all", "signers": ["owner"]}},
  {"name": "a-token", "scope": {"type": "contract", "address": "<token>"}, "principals": {"type": "all", "signers": ["grants"]}}
]
```

An agent's authorization is one `AddressWithDelegates` entry for the account.
The account's signature is an OZ `AuthPayload` whose only signer is
`Signer::Delegated(<this contract>)`; the delegate signature is a
[`GrantSignature`](src/lib.rs): the grant id and the holder's ed25519
signature over the host's signature payload.

1. The account's `__check_auth` runs Perch's reserved-name guard and freeze,
   then OZ's `do_check_auth`: each context must match the rule the entry
   selects for it, and the rule's signer, this contract, is authenticated by
   CAP-0071 `delegate_account_auth`.
2. The host calls this contract's `__check_auth` with the account's signature
   payload, the grant signature, and every context of the account's
   authorization.
3. This contract refuses unless all of its checks pass (below), and a refusal
   fails the account's authorization.

## Why a delegated signer and not a policy contract

An OZ `Policy` attached to an agent's context rule is the usual way to add a
check to an OZ smart account. Accounts the factory mints cannot take one:

- The Perch account is document-only. It exports none of OZ's rule, signer
  or policy mutation entry points (`vendor/perch/crates/perch-account/src/lib.rs`);
  `apply_doc` is its only write path for authorization data.
- A document's rules lower onto OZ context rules carrying only Perch's
  interpreter or its spending-limit policy. The policy-document schema
  (`vendor/perch/packages/perch-js/schemas/policy.schema.json`, `rule`) has
  no member that names another policy contract. `ARCHITECTURE.md` records
  the same for Nido's existing OZ policies.

The same schema does declare delegated signers (`signerDecl` with an
`address`), which Perch's compiler lowers to `Signer::Delegated` and OZ
authenticates through `delegate_account_auth`. That host function calls the
delegate's `__check_auth` with the delegating account's signature payload and
its whole context list (`soroban-env-host` 27, `auth.rs`,
`delegate_account_auth`; Perch pins this as C2 in
`vendor/perch/crates/integration-tests/tests/cap71_semantics.rs`). So:

- This contract sees every context of the authorization tree, including
  contexts the submitter routed to other rules. The guarantee does not depend
  on rule selection, which no signature binds for a delegated signer (Perch
  C4).
- For `AddressWithDelegates` credentials the payload preimage is
  `HashIdPreimageSorobanAuthorizationWithAddress`, which names the account
  (`auth.rs`, `get_signature_payload`). A holder's signature authorizes for
  that one account.
- Nothing in Perch or OpenZeppelin changes. Adding agents to an account is a
  document change plus one deployment.

A policy contract on an account that could attach it would be asked only
about the contexts routed to its rule, and each other context's rule would
have to be shown unsatisfiable by an agent. The delegate checks them all in
one call.

## Grants

| Function | Authorized by | Effect |
| --- | --- | --- |
| `issue(key, caveats, asset, allowance)` | the account | a root grant; `asset` must be a Stellar Asset Contract and `allowance` at most `i128::MAX` |
| `revoke(id)` | the account | marks `id` revoked, and with it every grant delegated from it |
| `rotate(id, key)` | the account | replaces `id`'s holder key |
| `refill(id, extra)` | the account | raises `id`'s allowance with `rule_eval::refill`, to at most `i128::MAX` |
| `delegate(parent, key, caveats, allowance)` | this contract, for `parent`'s holder | a child grant; `allowance` at most `i128::MAX` |
| `grant(id)`, `account()`, `overdrawn_at(id, amount)` | anyone | views |

The account authorizes the admin functions by calling them itself: its
`execute(<this contract>, "issue", args)`, authorized by the owner's passkey
through the admin rule, makes the account the invoker, so the functions'
`account.require_auth()` passes.

A child grant's caveats are its parent's followed by the added ones, and its
asset is its parent's. A holder can only add caveats: this is
`Grant.attenuateAll` of `formal/AttenuatingGrants/Grant.lean`, and on the
evaluator's input the stored list is reached from the parent's by pushes, the
case `formal/` proves narrows what is allowed (`V.extracted_delegates_narrower`,
`V.extracted_allowsAll_of_delegates`). A parent's id is smaller than its
children's. An empty caveat list allows every context the guards below let
through.

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
4. Map every other context, a contract call, to a `grant_eval::chain::Action`
   with its arguments and require `grant_eval::chain::allows_all` over the
   grant's caveats: `NotAllowed`.
5. Charge each budget-asset transfer to the grant and every ancestor with
   `rule_eval::spend` over the lineage's budget tree: `Overdrawn` if any
   node would pass its allowance. Only if every spend succeeds are the new
   `spent` values stored.

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
   (`soroban-env-host` 27, `auth.rs`, `delegate_account_auth`).
2. **The check of this contract's own address**, whenever a call needs that
   address's authorization: this contract's `delegate`, any other contract
   that calls `require_auth` on this address, and a deployment with this
   address as deployer. The payload is that address's and the contexts are
   what it authorizes.

The checks are the same in both roles. In the second, a holder authorizes
only as this contract's address, and only within its grant: the guards
refuse every contract creation, every call on this contract but the holder's
own delegation, every call on the account and every unmetered call on the
budget asset; the caveats bound every other call; and transfers of the
budget asset are charged to the grant. This gives no authority over the
account: the account accepts this contract only through
`delegate_account_auth`, so this address's own authorization never stands
in for the account's. Besides this contract's own `delegate`, the deployment
asks for this address's authorization only for calls that act on the address
itself, such as a transfer from its own balance.

Two consequences are stated, not enforced:

- Any contract can call `require_auth` on an address it is given. Under an
  empty grant, which allows every context the guards let through, a holder
  can have any contract it can call ask for this address's authorization,
  and authorize whatever that contract does as this address, including
  moving what the address holds. A transfer of the budget asset is still
  charged to the grant; one of any other asset is bounded by nothing.
- The deployment gives the address no balance: its balance in a Stellar
  Asset Contract, the native one included, is a contract-data entry that is
  absent until something is sent, and storage rent is paid in fees by each
  transaction's submitter. But the address is published in the account's
  document, and whatever anyone sends to it can be moved this way, by any
  holder whose grant allows the transfer. So nothing should be sent to it.

Contract creation is refused whatever the grant because in the second role
no account document applies, so under the empty grant no other check would
refuse a deployment with this address as deployer.

## Threat model coverage

The adversary is an agent the owner authorized, trying to widen its own
authority.

| Attempt | What refuses it |
| --- | --- |
| `issue`, `revoke`, `rotate` or `refill` its grant | They need the account's authorization. No agent rule is scoped to this contract, so the account has no rule to select (`UnvalidatedContext`). If a document did scope one, the account would ask this contract while its admin function runs, and the host refuses the re-entry. Asked directly, the contract refuses every call on itself but the holder's own delegation (`NotHolder`). |
| Delegate from an ancestor's grant (dropping its own caveats) or a grant it does not hold | `NotHolder` |
| Change its rule or policies (`apply_doc`), call the account's `execute`, schedule or cancel upgrades | No agent rule is scoped to the account (`UnvalidatedContext`). A document that gives agents a rule for the account still meets `AccountCall`. |
| A call the grant allows that makes a disallowed call inside the same authorization | Every context is checked; one disallowed context refuses the whole authorization. A nested call the signed tree leaves out is refused by the host. |
| Deploy a contract | `ContractCreation`, under every grant and in both roles of `__check_auth`. Perch documents have no creation scope, so through the account the account refuses it first. |
| Hand off the budget asset (`approve`, `burn`, `transfer_from`) | `UnmeteredCall` |
| Overspend through siblings or nested transfers | Every transfer in the authorization is charged to the spender and every ancestor; the first overdrawn node fails the spend and nothing is stored. |

## Budgets

A root grant names one Stellar Asset Contract (the native asset's or any
other's); `issue` refuses any other contract. Every grant under the root
meters the same asset. Allowances are cumulative: they do not reset with
time. Children's allowances may sum to more than their parent's, because
every ancestor is charged in the same authorization. Transfers of other
assets are bounded only by caveats, for example `ArgI128AtMost(2, n)` per
call or a `ContractIn` that leaves the asset out.

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

## Trusted wiring

The evaluator is verified in `formal/`; what connects it to Soroban is not:

- `src/actions.rs` turns contract-call contexts and stored caveats into the
  evaluator's types with `crates/grant-relay`'s encoding: a contract by its
  strkey, a function by its symbol's bytes, an address argument by its
  strkey, `i128`, `u64`, `bool`, `Bytes` and `Symbol` arguments by value, and
  any other argument as `Other` with its full `ScVal` XDR. A test checks the two
  mappings agree on every argument type.
- `src/contract.rs` applies the guards, and holds the budget path that
  `formal/` follows: its storage holds grants `0` to `NextId - 1`, none ever
  removed, and they are the ledger; `issue` and `delegate` store at
  `NextId`; `lineage`, `ledger`, the spend loop (`budget::spend_all`) and the
  store loop are `Ledger.IsLineage`, `Ledger.chain`, `Ledger.spendAll` and
  `Ledger.writeBack` of `formal/AttenuatingGrants/Signer.lean`; `refill` is
  `Ledger.refillGrant`.
- `src/budget.rs` converts stored `u128` amounts to `rule_eval`'s `i128`
  and back, and calls `rule_eval`; its unit tests check it against
  `grant_eval::budget` ([Budgets](#budgets)).
- The host's CAP-0071 behaviour, which Perch's `cap71_semantics.rs` pins for
  the pinned `soroban-env-host` and OZ fork.

## Tests

`crates/integration-tests/tests/it/grant_signer.rs`, on a factory-minted
Perch account under enforcing authorization (`set_auths`): allowed calls,
disallowed functions, contracts and arguments, a disallowed transfer nested
inside an allowed call, contract deployment under a restricted and an empty
grant in both roles of `__check_auth`, what a holder can and cannot
authorize as this contract's own address, every escalation in the table
above (including documents that wrongly scope agent rules to the account or
to this contract), delegation that narrows and cannot widen, oversubscribed
siblings with an overdrawn ancestor changing nothing, a refused
authorization and one failing after its charge, both caught by a calling
contract, leaving the budget unchanged, transfers charged across one
authorization, cascading revocation, key rotation, and the
agreement of this contract's mapping with the relay's. Each refusal is
asserted by the contract that refused and its error, read from the host's
event log.

```sh
just build-contracts
cargo test -p nido-integration-tests --test it grant_signer
```

`src/budget/tests.rs` checks the budget path against `grant_eval::budget` on
random lineage ledgers ([Budgets](#budgets)) and at the `i128::MAX` bound.
`tests/rule_eval_budget_vectors.rs` checks the linked `rule_eval` against
every budget trace rule-core's Lean model generates at the pinned rev
(`conformance/vectors/budget`, through `rule-eval-conformance`).

```sh
cargo test -p nido-grant-signer
```

## Costs

`enforce_costs` measures this contract's `__check_auth` from the wasm
`just build-contracts` produces (`soroban-env-host` 27.0.1 metering, the
grant at depth 0, every caveat holding so each is evaluated):

| Caveats | 1 context: CPU instructions | 1 context: memory bytes | Each further context: CPU instructions | Each further context: memory bytes |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 1,016,298 | 426,174 | 71,248 | 542 |
| 4 | 1,158,253 | 439,915 | 89,064 | 542 |
| 16 | 1,727,343 | 494,471 | 160,328 | 542 |

One context includes the VM instantiation, the grant load and the signature
check; each further context is the difference between five contexts and one,
divided by four. A metered transfer (one context, charged and stored) costs 1,138,581,
1,288,119 and 1,909,360 instructions for 1, 4 and 16 caveats. A whole agent
transaction, `protected` authorized through the account with a 4-caveat
grant, costs 2,253,104 instructions and 650,086 memory bytes, against a
per-transaction limit of 400,000,000 instructions.

```sh
cargo test -p nido-integration-tests --test it grant_signer::enforce_costs -- --nocapture
```

## Open questions

- Allowances never reset; a periodic budget would need a time model in the
  budget tree, in rule-core's model and in `formal/`.
- Grants live in persistent storage, extended to the network maximum on every
  write. An archived grant fails authorization until restored.
- Holder keys are ed25519 only.
