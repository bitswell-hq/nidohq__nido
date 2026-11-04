# grant-relay

A `/relay` service for agents that hold no keys. It accepts the request Nido's
browser client sends to `/relay` (a Soroban host function and its signed
authorization entries), checks the requesting agent's grants against every
context of the call's authorization trees, and only then has a key keeper sign
the transaction with the custody key. Transactions go out from a pool of
channel accounts whose only signer is the custody key.

A deployment changes only the frontend's relay URL (`PUBLIC_RELAYER_URL`); the
browser code is unchanged.

```sh
cargo run -p grant-relay --bin grant-relay -- --config relay.json --listen 127.0.0.1:8090
```

## Protocol

The protocol is the one `packages/passkey-sdk/src/relayer.ts` speaks to the
Channels plugin behind `infra/relayer`.

**Routes.**

| Route | |
| - | - |
| `POST /relay` | The agent's API key in the `x-api-key` header (the header the Caddy front of the Channels plugin injects). |
| `POST /agents/{apiKey}/relay` | The API key in the path, for a client configured with a base URL only: set `PUBLIC_RELAYER_URL` to `https://<host>/agents/<apiKey>`. If the header is also present, the two must match. |
| `OPTIONS` on either | `204` with `Access-Control-Allow-Origin: *`, `Allow-Methods: POST, OPTIONS`, `Allow-Headers: Content-Type`, `Max-Age: 86400`, as the Caddyfile answers it. |
| `GET /api/v1/health` | `200 {"status":"ok"}`. |

Every response carries `Access-Control-Allow-Origin: *`. Bodies over 256 KiB
get `413`.

**Requests.** The body is `JSON.stringify({ params })`:

```json
{"params": {"func": "<HostFunction XDR, base64>", "auth": ["<SorobanAuthorizationEntry XDR, base64>"], "skipWait": true}}
{"params": {"getTransaction": {"transactionId": "<id>"}}}
```

Unknown keys are refused, as the Channels plugin refuses them. `skipWait`
defaults to `false`; the browser always sends `true`. Signed-XDR submission
(`{"params": {"xdr": …}}`), which the plugin also accepts, is refused: the
browser does not use it, and a pre-built transaction has no grant check.

**Responses.**

```json
{"success": true, "data": {"transactionId": "<id>", "hash": "<hex>", "status": "submitted"}, "error": null}
{"success": false, "data": {"code": "GRANT_DENIED", "details": {…}}, "error": "<message>"}
```

`status` is `submitted` until the transaction settles, then `confirmed`,
`failed` or `expired`, which are the terminal statuses `waitForConfirmation`
polls for. With `skipWait: false` the submit response is the settled status.
A transaction's status is readable only with the API key that submitted it,
for at least an hour after it settles.

The client turns `success: false` into `RelayerError(error, code, details)`.
The codes:

| Status | Code | When |
| - | - | - |
| 400 | `INVALID_PARAMS` | Not one of the two request shapes; undecodable XDR; an authorization entry with `SourceAccount` credentials. |
| 400 | `UNSUPPORTED_HOST_FUNCTION` | `UploadContractWasm`. |
| 400 | `SIMULATION_FAILED` | A simulation failed. `details.error` is the host's message and `details.authMode` the simulation's: `record` (step 6 below) or `enforce` (step 7). The enforcing simulation runs each account's `__check_auth`, so a bad signature lands here. |
| 400 | `AUTH_EXPIRY_TOO_SHORT` | An entry expires before the latest ledger plus `min_auth_expiry_ledgers`. |
| 400 | `FEE_TOO_HIGH` | Inclusion fee plus resource fee exceeds `max_fee`. |
| 400 | `SUBMIT_FAILED` | `sendTransaction` answered `ERROR`. `details.errorResultXdr` is the result. |
| 401 | `UNAUTHORIZED` | No API key, an unknown one, or a header and path that disagree. |
| 403 | `GRANT_DENIED` | A grant denies the request. `details`: `grant` (`chain` or `signing`); for `chain`, `tree` (`supplied` or `recorded`) and `actionIndex`. |
| 403 | `CHANNEL_AUTH_REQUIRED` | The recording simulation shows the call asks for the channel account's own authorization. |
| 404 | `NOT_FOUND` | Unknown `transactionId`, or another agent's. |
| 502 | `RPC_UNAVAILABLE`, `CHANNEL_MISSING`, `SIGNING_FAILED` | Soroban RPC gave no usable answer; a channel account does not exist; the keeper refused, failed, or returned a signature that does not verify against the custody key. |
| 503 | `CHANNELS_BUSY`, `TRY_AGAIN_LATER` | Every channel is in use; `sendTransaction` answered `TRY_AGAIN_LATER`. |

## The grant check

Each agent has two grants: a **chain** grant over the contexts of the
authorization tree and a **signing** grant over the custody signature, each
written as a list of caveats. The chain grant is checked as the `rule-eval`
rule set it lowers to (`config::chain_rules`): one rule per contract every
`contract_in` caveat names, matching the functions every `function_in`
caveat names (every function when there is none), with every argument caveat
as a condition, no signers and a threshold of 0. So it allows a context
exactly when every caveat holds for it, which `crates/grant-eval/tests`
checks against `grant_eval::chain` on the same caveats. A chain grant names
the contracts it allows: `rule-eval` has no rule that matches every
contract, and a grant without `contract_in` is refused at load. The signing
grant is `grant-eval`'s signing vocabulary. A request is answered by the
first of these that fails, in order:

1. The API key names an agent.
2. No supplied entry has `SourceAccount` credentials. The transaction source is
   a channel account, and such an entry would be authorized by the custody
   signature on the transaction.
3. `rule_eval::allows_all(chain grant's rules, contexts, [])`, where
   `contexts` is the host function itself followed by every context of every
   supplied tree (root invocations, every sub-invocation, and
   contract-creation contexts), depth first.
4. `signing::allows(signing grant, {key: custody key id, network: network
   passphrase, payload: Transaction})`.
5. A channel is free. It is leased.
6. A recording simulation of the bare host function, from the leased channel,
   succeeds; none of the trees it records has `SourceAccount` credentials (the
   call would need the channel's authorization); and `rule_eval::allows_all`
   holds over every context it records.
7. An enforcing simulation with the supplied entries succeeds, and every entry
   stays valid for `min_auth_expiry_ledgers` past the latest ledger.
8. The fee is at most `max_fee`.

Only then is the key keeper called. Steps 1 to 4 need no network: a denial
there leases nothing, simulates nothing and never reaches the keeper.

The supplied trees are what the user's signatures authorize: the Soroban host
matches each `require_auth` to a node of an entry's tree, so a nested call the
agent leaves out of the tree fails on chain. The recorded trees are what the
execution asks for. Checking both means a call is relayed only when the grant
allows every context in either.

Every credential kind but `SourceAccount` is judged by its tree, including
`AddressWithDelegates`, whose delegates sign the same tree.

What the chain grant does not see: contract calls that ask for no
authorization (they appear in no tree), calls a contract makes inside its own
`__check_auth`, and the transaction fee (capped by `max_fee` instead).

## Submission

- **Channels.** Each channel account has master weight 0 and the custody key
  as its only signer, with a weight that meets the account's low and medium
  thresholds. The binary checks this for every channel at start and refuses
  to serve otherwise (`Relay::check_channels`).
- **Leases.** A request leases a free channel (round robin) after the static
  checks and holds it until its transaction settles. Concurrent requests get
  distinct channels; when all are leased the request gets `CHANNELS_BUSY`.
  The lease is released when it is dropped, so every failure before
  submission frees the channel.
- **Sequence numbers.** The relay keeps no sequence cache. It reads the
  channel's sequence number from the ledger after leasing it and builds with
  that plus one. Because a channel is leased until its last transaction is
  included or can no longer be, that read is never stale for the relay's own
  transactions. A failure before `sendTransaction`, an `ERROR`, or a
  `TRY_AGAIN_LATER` uses no sequence number; the next transaction on that
  channel reuses it.
- **Validity.** Each transaction has time bounds `[0, now + validity_seconds]`.
  The relay looks it up by hash every `poll_interval_ms`: `SUCCESS` is
  `confirmed`, `FAILED` is `failed` (its sequence number is used), and
  `NOT_FOUND` once a ledger has closed after `maxTime` is `expired` (no ledger
  can include it any more). The channel is freed at that point.
- **Unanswered sends.** When `sendTransaction` gives no answer, the transaction
  may have reached the network. The relay answers `submitted`, keeps the
  channel leased, and settles it by hash like any other.
- **Fees.** The channel pays its own fee: `inclusion_fee` plus a resource fee
  of the simulated minimum and `resource_fee_margin_percent` of it, the total
  capped at `max_fee` (`FEE_TOO_HIGH` when the minimum alone exceeds it). The
  margin covers rent that grows between simulation and the ledger that
  includes the transaction: a contract that extends an entry's TTL to the
  maximum on every write pays rent for every ledger since its last write, so
  two writes a ledger apart can need more than the simulation priced, and the
  transaction would fail with `INSUFFICIENT_REFUNDABLE_FEE`. The refundable
  part not used is refunded. No fund account fee-bumps. One request is
  one transaction and one custody signature, so there is one signing action to
  check and one keeper call. A fee bump would add a second envelope and a
  second signature to buy only the consolidation of funds in one account. The
  cost is that every channel holds its own XLM; a channel that cannot pay is
  refused at submission (`SUBMIT_FAILED`, `txInsufficientBalance`) without
  using a sequence number.
- **Signing.** The keeper signs the transaction hash as a `Payload::Hash` (Dfns
  `Hash`), which works for any network passphrase, including a local network's.
  The relay verifies the returned signature against the custody key before
  attaching it.

## Configuration

A JSON file (`relay.example.json` is a complete one for a local network):

```json
{
  "network_passphrase": "Test SDF Network ; September 2015",
  "rpc_url": "https://soroban-testnet.stellar.org",
  "custody": { "key_id": "key-…", "public_key": "G…" },
  "channels": ["G…", "G…"],
  "inclusion_fee": 100,
  "max_fee": 10000000,
  "resource_fee_margin_percent": 20,
  "validity_seconds": 60,
  "min_auth_expiry_ledgers": 2,
  "poll_interval_ms": 1000,
  "agents": [
    {
      "name": "wallet",
      "api_key_sha256": "<hex SHA-256 of the agent's API key>",
      "chain": [
        { "contract_in": ["C…"] },
        { "function_in": ["transfer"] },
        { "arg_i128_at_most": [2, "1000"] },
        { "arg_eq": [0, { "address": "G…" }] }
      ],
      "signing": [
        { "key_in": ["key-…"] },
        { "network_in": ["Test SDF Network ; September 2015"] },
        { "payload_in": ["transaction"] }
      ]
    }
  ],
  "keeper": {
    "dfns": {
      "base_url": "https://api.dfns.io",
      "token_env": "DFNS_TOKEN",
      "credential_id": "cr-…",
      "credential_seed_env": "DFNS_CREDENTIAL_SEED"
    }
  }
}
```

- The fields after `channels` are optional, with the defaults shown.
- `api_key_sha256` is the hex SHA-256 of the key (`grant_relay::config::api_key_sha256`); the file holds no API keys.
- Caveats are one key each. `arg_eq` values are `{"i128": "…"}`, `{"u64": n}`,
  `{"bool": b}`, `{"bytes": "<hex>"}`, `{"address": "G…|C…"}`,
  `{"symbol": "…"}` or `{"other": "<hex>"}`; `i128` bounds and values are
  integers or decimal strings. `other` is the `ScVal` XDR of an argument
  whose type has no value form of its own (`u32`, `string`, `vec`, …); XDR of
  a type that has one (`{"other": "<u64 XDR>"}`) is refused at load.
- `keeper` names the Dfns Generate Signature endpoint (or the local
  `dfns-mock`) and the environment variables holding the bearer token and the
  hex seed of the `Key` credential that signs user action challenges. The
  binary needs it; library callers pass their own keeper to `Relay::new`.
- Unknown fields, malformed addresses, a chain grant with no `contract_in`,
  a duplicate channel or a duplicate API key are refused at load.

The admin document that issues, revokes and rotates grants is not part of the
relay; the file is its output.

## The trusted wiring

Trusted, not checked by the evaluator:

- **XDR to contexts** (`src/actions.rs`), the grant signer's reading: every
  value crosses as its XDR through `soroban-facade`, and the facade's
  `val_to_rule_eval` gives what `rule-eval` reads of it. A contract is its
  `ScAddress` XDR and a function its symbol's bytes. `ScVal::I128`, `U64`,
  `Bool`, `Bytes`, `String` and `Symbol` map to the `rule_eval::Val`
  constructor of the same name, and an `Address` argument to `Address` of
  its `ScAddress` XDR. Any other argument type (`u32`, `i64`, `vec`, `map`,
  …) becomes `Other` of its full `ScVal` XDR, discriminant included, keeping
  its position. The evaluator never equates values of two constructors, so
  an `arg_eq` caveat with a `bytes` value never matches a `u32` or `vec`
  argument whose XDR is those bytes; `{"other": "<hex>"}` pins such an
  argument, and a string by its `ScVal` XDR. Contract creation is `Create`
  with the `Wasm` hash, or empty bytes for the Stellar Asset Contract
  executable. A call holding a value the facade does not read (a
  claimable-balance or liquidity-pool address, a ledger key) is allowed by no
  grant. `grant_signer::the_account_and_the_relay_read_contexts_alike` in
  `crates/integration-tests` checks this reading against the grant signer's
  on every argument type.
- **The configuration's caveats** (`src/config.rs`): a `contract_in` strkey
  and an `address` value become their `ScAddress` XDR, and the chain grant
  becomes its rule set ([The grant check](#the-grant-check)).
- **The configuration.** Whoever writes the file decides every agent's grants
  and holds the custody key's keeper credentials. Agents send requests; they
  never see the file.
- **Soroban RPC.** The recorded trees, the resource fee, the sequence number
  and the settled status come from the RPC server. The supplied-tree check
  (steps 2 to 4) does not depend on it, and `max_fee` caps what a wrong fee
  costs. Sequence reads and status lookups assume one consistent server: a
  server that lags behind an earlier answer makes a transaction fail with a
  bad sequence number at submission, which uses no sequence number.
- **The key keeper.** It signs whatever reaches it; the grant check is the
  gate. Dfns's own policies remain a second check behind it, but they see
  only a 32-byte hash (see `crates/key-keeper/README.md`).

## Running it locally

```sh
# A local network with Soroban RPC on :8000.
docker run --rm -p 8000:8000 \
  stellar/quickstart@sha256:487fe637ba48c972d5be0ed8965f8df1dcbc3e8e1ee53d24d915b25b6f2b6d99 \
  --local --enable rpc

# The Dfns mock, holding the custody key of relay.example.json.
cargo run -p nido-key-keeper --bin dfns-mock -- \
  --config crates/grant-relay/dfns-mock.example.json --listen 127.0.0.1:8787

# Fund the two channel accounts, set each one's master weight to 0 and add the
# custody key as signer (weight 1), then:
DFNS_TOKEN=dev-token \
DFNS_CREDENTIAL_SEED=2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a \
cargo run -p grant-relay --bin grant-relay -- --config crates/grant-relay/relay.example.json
```

The example's channel seeds are `0b…0b` and `0c…0c` (32 bytes each) and its
agent's API key is `dev-agent-key`; the frontend's relay URL for it is
`http://127.0.0.1:8090/agents/dev-agent-key`. These keys are public and for a
local network only. `grant_relay::local` (`src/local.rs`) performs the
channel setup in code (`hand_to_custody`), with the pinned quickstart image
and the setup transactions that `tests/local_network.rs` and the evaluation's
local-network stage (`evaluation/README.md`) use.

## Tests

```sh
cargo test -p grant-relay                                              # in-process
cargo test -p grant-relay --test frontend_client -- --ignored          # needs Node 22.6+
cargo test -p grant-relay --test local_network -- --ignored --nocapture  # needs Docker
```

| Test | What it runs against |
| - | - |
| `tests/relay.rs` | The pipeline over an in-process network (`tests/common`) and a `MemoryKeyKeeper`: allowed calls are signed, submitted and confirmed; denials of the root, a nested call, a second tree, a recorded-only call, contract creation, an amount cap and the signing grant never reach the keeper; every failure frees its channel and keeps its sequence number; concurrent requests take distinct channels; expiry and unanswered sends. |
| `tests/protocol.rs` | The HTTP server with the request bodies the browser builds, responses judged by a port of `relayer.ts`'s `call()` and `waitForConfirmation`. |
| `tests/frontend_client.rs` | `relayer.ts` itself, run by Node with only its base URL pointed at the relay. |
| `tests/actions_and_config.rs` | The XDR-to-context mapping, the chain grant's lowering, and the configuration file. |
| `tests/local_network.rs` | A local network (`stellar/quickstart`, core and RPC v29, protocol 28) and the Dfns client against `dfns-mock`. It hands two channels to the custody key, deploys the native asset contract and the forwarder (`tests/fixtures/forwarder`, a call whose tree nests a token transfer), and relays: an allowed transfer to confirmation; a transfer over the cap and a forward whose nested transfer the grant denies, neither signed; the forward with both contexts allowed, confirmed; a tampered entry, refused at simulation with no sequence number used; two requests at once on two channels. |

The ignored tests are not part of `cargo test --workspace`.

## Status

Run: every test above, including the two ignored suites, and the binary
with the example configuration up to its channel check (it builds the Dfns
keeper from the environment and stops when no network answers).

Stated, not proven:

- That the XDR-to-`Val` mapping keeps distinct arguments distinct: two
  `ScVal` arguments map to equal `Val`s only when they are equal. Values of
  different constructors are never equal (`rule-eval`'s `val_eq`); within
  `Other` this rests on XDR encoding being injective, and within `Address`
  on an `ScAddress` naming one address. rule-core's Soroban vectors check
  the facade's reading against its model, and the tests check it for `u32`,
  `i64`, `string` and `vec` arguments; neither proves it.
- That the supplied and recorded trees cover every context the transaction's
  signatures authorize. This rests on the Soroban host matching each
  `require_auth` against an entry's tree; the tests exercise it on a local
  network but do not prove it.
- That `NOT_FOUND` after a ledger closes past `maxTime` means the transaction
  can never be included. This rests on ledger close times never decreasing
  and on the RPC server holding every ledger since submission.

Not run: real Dfns (the keeper is `DfnsKeyKeeper` against `dfns-mock`; whether
real Dfns signs a `Hash` payload's 32 bytes directly as the Ed25519 message is
unknown, per `crates/key-keeper/README.md`), testnet, and RPC v30. Simulations
the Stellar CLI 27.0.0 built failed with `HostError: Error(Context,
InternalError)` against the quickstart image with core and RPC v30; this crate
was not run against that image.
