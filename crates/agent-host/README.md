# agent-host

The agent-side boundary for attenuating grants. An agent's tool calls reach
the file system, the network and the key keeper only through this host, and
the host checks each one against the agent's grant with the grant evaluator
compiled to a WebAssembly component. That component is `crates/grant-eval`,
the evaluator the Soroban smart account runs in `__check_auth`, built for the
same `wasm32v1-none` target.

```sh
cargo run --release -- run workload.json   # replay a scripted workload
cargo run --release -- bench               # per-check cost, component vs native
cargo test
```

This crate is its own Cargo workspace, so run these from `crates/agent-host/`
(or pass `--manifest-path crates/agent-host/Cargo.toml`). Wasmtime's
Cranelift needs `arbitrary` 1.4 and soroban-sdk's test utilities pin
`arbitrary` ~1.3, and one lockfile can hold only one of them. Building needs
the `wasm32v1-none` target (`rustup target add wasm32v1-none`; the
repository's `rust-toolchain.toml` lists it).

## The evaluator component

`crates/grant-component` wraps `grant-eval` behind the WIT interface in
`crates/grant-component/wit/grant-eval.wit`: one interface per vocabulary
(`files`, `network`, `signing`, `chain`), each with `allows(grant, action)`
and `allows-all(grant, actions)`. Each export converts its arguments to
`grant-eval` values and calls that vocabulary's function. The component
imports nothing and keeps no state between calls.

`build.rs` builds `grant-component` for `wasm32v1-none` (`no_std`, with
`dlmalloc` as its allocator), wraps the core module as a component with
`wit-component`, and embeds it. `Evaluator::new` compiles and instantiates
it in Wasmtime with an empty linker. The host holds the grant and passes it,
with the action, on every call; the verdict is the component's.

## Grants are the host's

The host has two interfaces:

- **Admin**: `Host::issue(grants)` starts a root agent with a grant;
  `Host::revoke(agent)` revokes an agent and every agent under it. Issuing,
  revoking and key rotation are admin actions. Agents never hold this
  interface.
- **Agent**: `Host::call(agent, tool_call)`. The tool calls are `read_file`,
  `write_file`, `fetch`, `sign` and `delegate`. None of them reads or edits a
  grant. `delegate { add }` starts a sub-agent whose grant is the caller's
  caveats followed by `add`, so it allows only what the caller's grant
  allows, whatever `add` says.

A grant is one caveat list per vocabulary, in the JSON form `grant-relay`
uses:

```json
{
  "files":   [{"path_under": "/srv/work"}, {"mode_in": ["read"]}],
  "network": [{"host_in": ["api.example.com"]}, {"port_in": [443]}, {"scheme_in": ["https"]}],
  "signing": [{"key_in": ["key-a"]}, {"network_in": ["Test SDF Network ; September 2015"]}, {"payload_in": ["transaction"]}],
  "chain":   [{"contract_in": ["C…"]}, {"function_in": ["transfer"]}, {"arg_i128_at_most": [2, "1000"]}]
}
```

The chain list is the one `grant-relay` checks, parsed by its code: it is
checked when the agent asks for a transaction or an authorization entry to be
signed (see Signing below). An empty list allows every action of that
vocabulary, as an empty grant does in the evaluator, so a grant whose signing
list allows `transaction` or `auth_entry` and whose chain list is empty lets
the agent have its key authorize any contract call.

## Wiring

The wiring turns a tool call into the action the evaluator checks. It is the
trusted part of this crate, kept to three modules.

### Files (`src/fs.rs`)

- **Canonical path.** A requested path must be absolute. Each existing prefix
  is canonicalized with `realpath`, which follows symlinks, applies `..` to
  the directory a symlink led to (as the kernel does, not lexically) and
  returns the names stored on disk. Components past the last existing one
  are appended as given (`.` dropped, `..` removing the previous appended
  name). `path_under` prefixes in a grant go through the same resolution
  when the grant is issued or delegated, so on macOS `/tmp/x` in a grant
  names `/private/tmp/x`.
- **Case.** On a case-insensitive file system (macOS APFS by default) a
  differently cased path names the same file. The check sees the stored
  name, so a variant is allowed exactly when the stored path is. A variant
  of a path outside the grant is still outside it.
- **Check, open, check the opened file.** The canonical path and mode are
  checked; the file is opened with `O_NOFOLLOW` on its last component; then
  the path of the open descriptor itself (`F_GETPATH` on macOS,
  `/proc/self/fd` on Linux) is checked again, and the data goes through that
  descriptor. A component swapped for a symlink between the two steps is
  caught by the second check. A write to a new file checks its directory's
  descriptor path joined with the file name and creates the file under that
  descriptor with `O_CREAT | O_EXCL | O_NOFOLLOW`. Only regular files are
  read or written.
- **Not covered.** A file or directory renamed by another process after it
  was opened and checked: the descriptor follows the inode, not the path.
  Hard links: a grant names paths, so a hard link inside the grant to a file
  outside it is allowed. The agent's tools create neither renames nor links.
  An error while resolving (a directory the host cannot search, a dangling
  symlink) is reported before the check, so it can tell an agent that
  something exists at a path its grant does not cover. A file that does not
  exist is checked like one that does, and a denied path reports a denial,
  not "not found".

### Network (`src/net.rs`)

- **The action is the requested name.** The agent gives a URL. The action is
  its host as the URL parser normalizes it (lower-cased ASCII, IDNA names in
  `xn--` form, IPv4 dotted, IPv6 in brackets; a trailing dot is kept, so
  `example.com.` is another host), its port (the scheme's default if none is
  given) and its scheme. Only `http` and `https` are fetched.
- **The host resolves and connects.** After the check, the host's HTTP client
  does the DNS lookup and connects directly, with no proxy. The agent never
  supplies an address for a name. What a name resolves to is trusted.
- **Every redirect is a new action.** The client follows no redirects. A
  `301`, `302`, `303`, `307` or `308` with a `Location` is resolved against
  the current URL and checked like the first request before it is made (at
  most five hops). `303`, and `301`/`302` after a `POST`, continue as a
  `GET`.

### Signing (`src/sign.rs`)

The agent names a key, a network passphrase and a payload. The host checks
the signing action (key id, passphrase, payload kind) against the signing
grant and, for a transaction or an authorization entry, every context the
signature authorizes against the chain grant with `allows_all`. Only then
does it call the `KeyKeeper`. The agent holds no key. A denied or refused
request never reaches the keeper.

| Payload | Agent supplies | Chain actions checked | Keeper signs |
| - | - | - | - |
| `transaction` | `TransactionEnvelope` XDR (base64) | the operation's host function, and every context of every authorization entry it carries | the transaction hash on the named network, so the signature is valid there only |
| `auth_entry` | `HashIdPreimage` XDR (base64), type `SorobanAuthorization`, or `SorobanAuthorizationWithAddress` for a delegated signer such as a grant signer holder | every context of the preimage's invocation tree | `SHA-256` of the preimage, after the host checks the preimage's network id is `SHA-256` of the named passphrase |
| `message` | UTF-8 text | none | the SEP-53 hash `SHA-256("Stellar Signed Message:\n" ‖ message)` |

- **Only what the chain vocabulary describes is signed.** A transaction must
  be a `Tx` envelope with exactly one operation, an `InvokeHostFunction`.
  The host refuses fee-bump and `TxV0` envelopes, every other operation (a
  payment, a new account, a new signer, a trustline, …), a second operation
  beside the contract call, and an `UploadContractWasm` host function. An
  authorization preimage of any other type is refused.
- **The mapping is the relay's.** Host functions and authorization contexts
  become chain actions through `grant_relay::actions`, the code `grant-relay`
  checks with: a contract by its strkey, a function by its symbol, arguments
  as `I128`, `U64`, `Bool`, `Bytes`, `Address`, `Symbol` or `Other` (the
  full `ScVal` XDR), and a deployment as `CreateContract`, which every chain
  caveat denies.
- **Every authorization entry is checked.** That includes entries with
  `Address` credentials, which other addresses sign: the transaction carries
  them, and its execution runs the calls they authorize. Under enforcing
  authorization, a call that requires the authorization of the account the
  transaction's signature stands for fails unless it matches a node of a
  `SourceAccount` entry, so a call the transaction signature authorizes
  cannot sit outside the checked trees.
- **The keeper gets the checked value.** The host decodes the payload,
  checks the decoded value, and gives the keeper that value's XDR encoding
  (the envelope for `StellarTransaction`, the preimage's hash for an
  authorization entry). The bytes signed are the bytes checked.

A message signature is not bound to a network: for `message`, a
`network_in` caveat restricts only the label the agent gives. The SEP-53
prefix keeps a message signature from being a transaction or
authorization-entry signature, whose signed hashes begin from a network id
and an envelope type. The host never offers the keeper's raw `Hash` payload
to an agent.

**Not bound by a grant.** No caveat covers the transaction's fee, sequence
number, time bounds, memo or source account, an authorization entry's nonce
or expiration ledger, or which account a key id stands for. An agent allowed
to sign transactions can have its key pay any fee the network charges for an
allowed call. Calls a contract makes that need no authorization from anyone
are the contract's own and are not checked.

## Trusted, not proven

- `rustc`, `wit-bindgen`, `wit-component` and Wasmtime: that the component is
  `grant-eval` compiled faithfully, and that values cross the component
  boundary unchanged. The tests check agreement with `grant-eval` called
  natively on every grant of up to three caveats from a small universe per
  vocabulary; they do not prove it.
- The Charon/Aeneas translation that `formal/` proves its theorems about
  (see `crates/grant-eval/README.md`).
- The wiring above: path resolution, the descriptor-path check, URL parsing
  and redirect handling, payload decoding and the mapping from Soroban XDR
  to chain actions (`grant_relay::actions`), and the operating system calls
  they rely on (`realpath`, `F_GETPATH`, `/proc/self/fd`, DNS).
- The Soroban host's enforcing authorization: that a call requiring an
  account's authorization succeeds only when it matches a checked tree.
- The key keeper's own refusals and its signing.

**Grants control access, not information flow.** A grant decides which
actions an agent may take. It does not track what the agent learns from an
allowed action or where that data goes next through other allowed actions:
an agent allowed to read a file and to reach a host can send the file's
contents to that host.

## Workloads

`agent-host run <workload.json>` replays admin steps and tool calls through
one host, printing one JSON result per step (`step`, `outcome` =
`allowed` | `denied` | `failed`, `detail`, `micros`). Keys go to an in-process
`MemoryKeyKeeper`; agents name keys by id only.

```json
{
  "keys": {"key-a": "<Ed25519 seed, 64 hex digits>"},
  "steps": [
    {"admin": {"issue": {"name": "root", "grants": {"files": [{"path_under": "/srv/work"}]}}}},
    {"agent": {"name": "root", "call": {"read_file": {"path": "/srv/work/notes.txt"}}}},
    {"agent": {"name": "root", "call": {"delegate": {"add": {"files": [{"mode_in": ["read"]}]}}}, "as": "reader"}},
    {"agent": {"name": "reader", "call": {"write_file": {"path": "/srv/work/out.txt", "contents": "x"}}}},
    {"agent": {"name": "root", "call": {"fetch": {"url": "https://api.example.com/v1", "method": "POST", "body": "{}"}}}},
    {"agent": {"name": "root", "call": {"sign": {"key": "key-a", "network": "Test SDF Network ; September 2015", "message": "hello"}}}},
    {"admin": {"revoke": "root"}}
  ]
}
```

## Per-check cost

`agent-host bench` (`src/bench.rs`) times each check three ways: `grant-eval`
called natively on values built once; the host's WIT values converted to
`grant-eval` values in the host and then evaluated, which is the check
without WebAssembly; and the component, whose time includes copying the
grant and action into its memory, the guest's conversion, the evaluation and
the return. Each case is a three-caveat grant and an action it allows, so
every caveat is evaluated; the chain case checks a three-context
authorization tree with `allows_all`. It also times compiling and
instantiating the component.

Every operation is warmed up, then timed in batches long enough for the
clock's resolution not to matter, over interleaved rounds whose order of
variants rotates, so a change in the machine's load reaches every variant
alike; ratios are taken within a round. The report gives the median with a
95% confidence interval, the 10th and 90th percentiles and the extremes.
Absolute times depend on the machine's load and on which cores the
scheduler picks. `evaluation/README.md` reports a recorded run with the
machine's state (`evaluation/results/agent-host-bench.json`, from
`just eval`).

## Tests

`tests/component.rs` checks allowed and denied cases for each vocabulary
through the component, and agreement with native `grant-eval` on every grant
of up to three caveats from a small universe per vocabulary, over a set of
actions (for chain, every authorization tree of up to two contexts).
`tests/files.rs` covers `..` and symlink escapes (including `..` after a
symlink), case variants on a case-insensitive file system (and on a
case-sensitive one), `/home/a` against `/home/ab`, a dangling symlink, and a
component swapped for a symlink between the check and the open.
`tests/network.rs` runs local HTTP servers: host, port and scheme denials
before any connection, a redirect to a disallowed host or port denied with
the target never contacted, an allowed redirect followed, and a redirect
loop stopped. `tests/signing.rs` signs with `MemoryKeyKeeper` and checks
that a disallowed key, network or payload kind is denied before the keeper
is called, and that a transaction or authorization entry is denied, with
nothing reaching the keeper, when it calls a contract or function the chain
grant does not allow, exceeds an amount bound, hides a disallowed call
inside an authorization tree (of a source-account entry, another entry, or a
preimage), deploys a contract, or comes from a sub-agent whose inherited
caveats exclude it. It also checks that fee-bump envelopes, classic
operations (a new signer, a new account, a payment), a second operation and
code uploads are refused, and that the keeper signs exactly the envelope that
was checked. `tests/delegation.rs` checks that delegation narrows, that a
sub-agent asking for more gets nothing more, that every child allows a
subset of its parent over every pair of caveat lists from a small universe,
that revocation reaches sub-agents, and that no tool call reads or edits a
grant. `tests/workload.rs` replays a workload through the binary.
