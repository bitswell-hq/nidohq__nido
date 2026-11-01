# grant-signer

The Soroban boundary of attenuating grants. An AI agent's authority over a
Nido account is a grant held in this contract: a list of chain caveats, the
holder's ed25519 key, and a budget node. Every authorization an agent gives
for the account passes through this contract's `__check_auth`, which checks
every context of the authorization with `grant_eval::chain::allows_all` and
charges every transfer of the budget asset with `grant_eval::budget::spend`.

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
| `issue(key, caveats, asset, allowance)` | the account | a root grant; `asset` must be a Stellar Asset Contract |
| `revoke(id)` | the account | marks `id` revoked, and with it every grant delegated from it |
| `rotate(id, key)` | the account | replaces `id`'s holder key |
| `refill(id, extra)` | the account | raises `id`'s allowance with `grant_eval::budget::refill` |
| `delegate(parent, key, caveats, allowance)` | this contract, for `parent`'s holder | a child grant |
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
other re-entry. The contract's own address holds nothing; a holder's
authorization of it for anything but a delegation is checked like any other
context.

## `__check_auth`

In order, returning the first failure ([`GrantError`](src/error.rs)):

1. Load the signing grant and its ancestors: `NoSuchGrant`, or `Revoked` if
   any of them is revoked.
2. Verify the holder's ed25519 signature over the payload (a failure traps).
3. For each context:
   - a call on this contract other than the holder's own delegation:
     `NotHolder`;
   - a call on the account: `AccountCall`;
   - a call on the budget asset other than `transfer(from, to, amount)` with
     a non-negative `i128` amount: `UnmeteredCall`.
4. Map every other context to a `grant_eval::chain::Action` (contract calls
   with their arguments, contract creation with its wasm hash) and require
   `grant_eval::chain::allows_all` over the grant's caveats: `NotAllowed`.
5. Charge each budget-asset transfer to the grant and every ancestor with
   `grant_eval::budget::spend` over the lineage's ledger: `Overdrawn` if any
   node would pass its allowance. Only if every spend succeeds are the new
   `spent` values stored.

A refused authorization fails the transaction, so no state changes.

## Threat model coverage

The adversary is an agent the owner authorized, trying to widen its own
authority.

| Attempt | What refuses it |
| --- | --- |
| `issue`, `revoke`, `rotate` or `refill` its grant | They need the account's authorization. No agent rule is scoped to this contract, so the account has no rule to select (`UnvalidatedContext`). If a document did scope one, the account would ask this contract while its admin function runs, and the host refuses the re-entry. Asked directly, the contract refuses every call on itself but the holder's own delegation (`NotHolder`). |
| Delegate from an ancestor's grant (dropping its own caveats) or a grant it does not hold | `NotHolder` |
| Change its rule or policies (`apply_doc`), call the account's `execute`, schedule or cancel upgrades | No agent rule is scoped to the account (`UnvalidatedContext`). A document that gives agents a rule for the account still meets `AccountCall`. |
| A call the grant allows that makes a disallowed call inside the same authorization | Every context is checked; one disallowed context refuses the whole authorization. A nested call the signed tree leaves out is refused by the host. |
| Deploy a contract | Every chain caveat is false on contract creation, so any grant with a caveat refuses it. Perch documents have no creation scope, so the account refuses it first. |
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

Grant ids index one `grant_eval::budget` ledger: a grant's `parent`,
`allowance` and `spent` are its node. `issue` adds a root and `delegate` a
node under the delegator's with nothing spent, as `budget::append` does, and
`refill` calls `budget::refill` on the node. An authorization calls
`budget::spend` on the signing grant's lineage (root first, each node's parent
the one before it), which holds every node `spend` reads or writes on the
whole ledger, so it returns the same result and charges the same nodes.
`formal/` proves, about the extracted `spend`, `refill` and `append`, that a
spend charges the spender and every ancestor or fails changing nothing, and
that the total spent under any node stays within its allowance
(`Budget.extracted_spend`, `extracted_spend_error`,
`extracted_spentUnder_le_allowance`). That this contract's storage and the
lineage are that ledger is wiring (below).

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

- `src/actions.rs` turns contexts and stored caveats into the evaluator's
  types with `crates/grant-relay`'s encoding: a contract by its strkey, a
  function by its symbol's bytes, an address argument by its strkey, `i128`,
  `u64`, `bool`, `Bytes` and `Symbol` arguments by value, and any other
  argument as `Other` with its full `ScVal` XDR. A test checks the two
  mappings agree on every argument type.
- `src/contract.rs` builds the lineage and its budget ledger, applies the
  guards, and stores the charged `spent` values.
- The host's CAP-0071 behaviour, which Perch's `cap71_semantics.rs` pins for
  the pinned `soroban-env-host` and OZ fork.

## Tests

`crates/integration-tests/tests/it/grant_signer.rs`, on a factory-minted
Perch account under enforcing authorization (`set_auths`): allowed calls,
disallowed functions, contracts and arguments, a disallowed transfer nested
inside an allowed call, contract deployment, every escalation in the table
above (including documents that wrongly scope agent rules to the account or
to this contract), delegation that narrows and cannot widen, oversubscribed
siblings with an overdrawn ancestor changing nothing, transfers charged
across one authorization, cascading revocation, key rotation, and the
agreement of this contract's mapping with the relay's. Each refusal is
asserted by the contract that refused and its error, read from the host's
event log.

```sh
just build-contracts
cargo test -p nido-integration-tests --test it grant_signer
```

## Costs

`enforce_costs` measures this contract's `__check_auth` from the wasm
`just build-contracts` produces (`soroban-env-host` 27.0.1 metering, the
grant at depth 0, every caveat holding so each is evaluated):

| Caveats | 1 context: CPU instructions | 1 context: memory bytes | Each further context: CPU instructions | Each further context: memory bytes |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 1,018,572 | 418,924 | 72,015 | 542 |
| 4 | 1,160,739 | 432,665 | 89,831 | 542 |
| 16 | 1,734,245 | 487,221 | 161,095 | 542 |

One context includes the VM instantiation, the grant load and the signature
check; each further context is the difference between five contexts and one,
divided by four. A metered transfer (one context, charged and stored) costs 1,123,054,
1,279,904 and 1,909,151 instructions for 1, 4 and 16 caveats. A whole agent
transaction, `protected` authorized through the account with a 4-caveat
grant, costs 2,270,304 instructions and 655,437 memory bytes, against a
per-transaction limit of 400,000,000 instructions.

```sh
cargo test -p nido-integration-tests --test it grant_signer::enforce_costs -- --nocapture
```

## Open questions

- Allowances never reset; a periodic budget would need a time model in
  `grant_eval::budget` and in `formal/`.
- Grants live in persistent storage, extended to the network maximum on every
  write. An archived grant fails authorization until restored.
- Holder keys are ed25519 only.
