# Evaluation

Agent workloads and an attack suite run against two of the boundaries that
enforce attenuating grants, with the cost, throughput and clean-failure
measurements the paper reports, and the Lean cost bound checked against
measured Soroban CPU instruction counts:

- **The Soroban boundary, in simulation**: the grant signer
  (`contracts/grant-signer`) as the delegated signer of a Perch account minted
  by Nido's factory, in `soroban-env-host` under enforcing authorization. Every
  contract runs from its wasm: Perch's account, `WebAuthn` verifier, doc
  compiler and interpreter as deployed on testnet (`just perch-infra`), Nido's
  factory and grant signer (`just build-contracts`), and the evaluation's dApp
  (`fixtures/dapp`).
- **The agent host** (`crates/agent-host`): the evaluator component behind the
  host that is an agent's only path to files, the network and the key keeper.
- **The Lean model** (`formal/`): the step-counting chain evaluator and its
  proven bound, evaluated on every grant and action the simulation measures.

The relay and a local Stellar network are not part of this evaluation yet;
[Not measured](#not-measured) lists what that leaves out.

## Running it

```sh
git submodule update --init
just perch-infra
just build-contracts
(cd formal && lake exe cache get)
just eval
```

`just eval` runs `scripts/eval.sh`, which writes every file in `results/` and
rewrites the tables under [Results](#results):

| Step | Command | Writes |
| - | - | - |
| The dApp fixture | `cargo build --release --target wasm32v1-none --manifest-path evaluation/fixtures/dapp/Cargo.toml` | `target/eval-fixtures/…/nido_eval_dapp.wasm` |
| Machine and versions | `scripts/eval.sh` | `machine.json` |
| Soroban simulation | `cargo run -p nido-evaluation -- soroban --dapp <wasm> --out evaluation/results` | `soroban-costs.json` and `.csv`, `lean-cases.json`, `soroban-attacks.json`, `soroban-workloads.json` |
| Lean step counts | `cd formal && lake env lean --run ../evaluation/cost-bound/Steps.lean ../evaluation/results/lean-cases.json` | `lean-steps.jsonl` |
| Agent host | `cargo run --release --manifest-path evaluation/agent-host/Cargo.toml -- --out evaluation/results` | `agent-host-workload.json`, `agent-host-attacks.json`, `agent-host-bench.json`, `agent-host-throughput.json` |
| Report | `cargo run -p nido-evaluation -- report --results evaluation/results --readme evaluation/README.md` | `cost-bound.json` and `.csv`, the tables below |

Soroban CPU instructions and memory bytes are the host's metered costs, so
they are the same on every machine and every run. Agent-host times are wall
clock on the machine in `machine.json` and vary with its load; each is
reported as the range over three runs.

## The Soroban simulation

`harness/src/soroban/fixture.rs` builds one account per scenario on the world
of `crates/integration-tests` (`world.rs`): the factory mints the account with
an owner passkey, the grant signer is deployed for it, and the owner's passkey
applies a document that declares the grant signer as the delegated signer
`grants` and gives agents one rule per contract they call, signed by
`grants`. Two Stellar Asset Contracts stand for the budget asset and a second
token; the account holds 1,000,000 of each. The owner issues, revokes, rotates
and refills grants through the account's `execute`, signed by the passkey
through the admin rule. Every agent call is one `AddressWithDelegates`
authorization entry carrying the holder's ed25519 signature over the host's
payload, installed with `set_auths`, so every account's `__check_auth` runs.

A refused call reports only the host's outer error, so the harness reads the
refusal from the host's event log (`harness/src/outcome.rs`), in order: the
grant signer's own error event; a failed holder signature in the grant
signer; a refusal the host's diagnostics name (no authorization entry covers
the call, a reused nonce, contract re-entry); the account's authentication
failure with its OpenZeppelin error; otherwise the host's first error.

### Cost per check

`harness/src/soroban/costs.rs` calls the grant signer's `__check_auth`
directly on contexts of `dapp.probe(account, data)` and reads the host's CPU
instruction and memory meters. Five sweeps vary one thing each: the number of
caveats; the length of the byte-string argument, once compared by an `ArgEq`
and once not compared; the number of contexts; and the length of a
`ContractIn` list the called contract is last in.

Every point is measured twice on the same stored grant: `pass`, where every
caveat holds for every context, and `fail`, where the first context calls
another instance of the dApp (an address of the same length), so the first
caveat, a `ContractIn`, fails and the evaluator stops. Loading the grant,
verifying the signature and mapping the contexts cost the same in both, so the
difference is the evaluator's own work.

### The cost-bound cross-check

`formal/` proves, for the step-counting chain evaluator, that checking
`actions` against caveats `cs` takes at most
`2 * (cs.length + Σ c.size + 1) * Σ (a.size + 1)` steps
(`Chain.AllowsAllCostBound`), and leaves open whether the Rust evaluator's
work is proportional to those steps. For every measured point the harness
writes the grant and the actions in the evaluator's form (`lean-cases.json`;
caveats mapped as the grant signer maps them, actions with
`grant_relay::actions`, the mapping the grant signer is tested to agree
with). `cost-bound/Steps.lean` imports the formal package and evaluates
`Chain.allowsAllCounted` and the bound's expression on each case: the
model's own definitions, not a reimplementation.

The report then:

- checks that the contract, the native evaluator and Lean give the same
  verdict on every point;
- fits the CPU instructions per Lean step: the least-squares slope, through
  the origin, of the `pass − fail` instruction difference on the `pass − fail`
  step difference, over every pair;
- gives each sweep's range of that ratio over the pairs whose step counts are
  at least 10 apart (in the `ContractIn` sweep at length 64 both checks scan
  the whole list, so the two differ by a few steps and the ratio is noise);
- divides each `pass` point's total cost, less the zero-caveat check, by the
  bound for its grant and actions.

### Attack suite

The adversary is an agent the owner authorized. Every attempt is made by such
an agent, and records the component that refused it and its error. Before and
after every attempt the harness snapshots the balances of the account, the
recipients, the attacker's address and the dApp instances in both assets;
every grant (holder key, caveats, allowance, spent, revoked); and the
account's revision, document hash and pending upgrade. A refusal passes only
if the two snapshots are equal. Control rows are allowed calls of the same
shape as the attack next to them.

| Category | At the Soroban boundary | At the agent host |
| - | - | - |
| Self-escalation | `issue`, `refill` and `rotate` on the grant signer, through the account and as the grant signer; the account's `apply_doc`, `execute` and `schedule_upgrade`; an agent call through the owner's admin rule; delegating from a parent's grant, from a grant not held, or with a forged parent signature; documents that wrongly scope an agent rule to the account or to the grant signer | tool calls that issue, revoke or replace a grant; a sub-agent delegated a wider grant using it for files, mode, network and signing; revoked agents and their sub-agents |
| Nested-call smuggling | a transfer to the attacker at depth 2 to 5 behind allowed calls; an allowed call nesting a transfer of a token the grant leaves out; nested transfers left out of the signed tree at depths 2 and 3; a nested transfer over the allowance | not applicable: a tool call has no nested calls |
| Delegation workarounds | deploying a contract with the account as deployer; paying a Nido account the attacker minted; `approve` and `burn` of the budget asset, `approve` of another token; a sub-agent delegated no extra caveats and a larger allowance paying another recipient or more per call; arguments of another type with the same bytes (a muxed recipient, a `u64` amount, a `u32` for bytes of its XDR, a string for a symbol, an address for bytes of its strkey); a revoked grant and a revoked ancestor; a rotated-out key; a replayed entry | paths that name the work directory and reach outside it (`..`, symlinks, `..` after a symlink, a string prefix, another case, a relative path, a write through a symlink, a write under read-only); URLs that name the allowed host and reach another (another port or scheme, the address literal, a decimal IPv4 literal, a trailing dot, userinfo, redirects to another port or to the address literal); signing with another key, for another network, for a preimage of another network than named, a transaction, and by a sub-agent restricted to messages |
| Allowance oversubscription | a sibling spending past what is left of the root; a sibling over its own allowance; a grandchild under an exhausted parent | not applicable: the agent host has no budget vocabulary |

### Workloads

`harness/src/workloads.rs` scripts two agent sessions with sub-agents,
replayed in the simulation (`harness/src/soroban/workloads.rs`), each call
one transaction through the account:

- **payments**: a per-call cap of 100 and an allowance of 400, a payroll
  sub-agent pinned to one payee with an allowance of 150;
- **defi-router**: calls that nest the account's transfers up to four contexts
  deep (`forward`, and `hop` through two and three dApp instances), a swapper
  sub-agent narrowed to the direct router with an allowance of 100.

The agent host replays one session (`agent-host/src/main.rs`): a research
agent reads and writes its work directory, calls an API on `localhost` over
HTTP (one allowed redirect), signs a message and a delegated signer's
authorization preimage on the local network passphrase, then starts a
summarizer that may only read, reach no host and sign messages; the
summarizer's write, fetch and authorization-entry signature are denied, and
after the owner revokes the research agent so is its read.

### Agent host

`agent-host/src/main.rs` runs the host with an in-process `MemoryKeyKeeper`,
a file tree in a fresh temporary directory (`work/`, `secret/`, `workshop/`,
and `work/link`, a symlink to `secret/`), and two HTTP servers on 127.0.0.1:
the API the grant allows by the name `localhost` on its port, and a second
server on another port. Clean failure there means: the file tree (every
file's SHA-256 and every symlink's target), the second server's request
count, the keeper's signature log and every agent's verdicts on reading two
probe files are unchanged. The per-check rows are `agent_host::bench` (a
three-caveat grant and an action it allows, through the component and
natively); the tool-call rows time one agent's calls in sequence through the
whole host, file system, keeper and loopback HTTP included. The results
write the temporary directory as `$SANDBOX` and the two servers' ports as
`$API_PORT` and `$OTHER_PORT`.

## Results

<!-- results:begin (generated by `nido-eval report`; do not edit) -->

### Machine and versions

|  |  |
| - | - |
| cpu | Apple M5 Max |
| lean | leanprover/lean4:v4.35.0 |
| memory | 128 GiB |
| nido_eval_dapp.wasm sha256 | d8d01d8e8af6e10a237080335c2984e82a9e094b1a2c827adf0fad481db34cbd |
| nido_grant_signer.wasm sha256 | 023f6b1791e6de332f93d26063c112c24a47df0a15332dfcb4fb796b00d6212a |
| os | macOS 26.5.2 |
| perch_account.wasm sha256 | d99d56fc2d07a14c2259f0994d97316d23ae90db26835f4c977939c2b3b593aa |
| rustc | rustc 1.96.0 (ac68faa20 2026-05-25) |
| soroban-env-host | 27.0.1 |
| soroban-sdk | 27.0.5 |
| wasmtime | 49.0.5 |

### Cost per check and the Lean bound

**Caveats** (`caveats`)

| Caveats | CPU instructions | Memory bytes | CPU, first caveat failing | Lean steps | Lean bound |
| - | - | - | - | - | - |
| 0 | 974,554 | 415,988 | – | 1 | 308 |
| 1 | 1,026,909 | 420,172 | 1,020,241 | 60 | 18,172 |
| 2 | 1,072,078 | 424,403 | 1,062,718 | 68 | 20,328 |
| 4 | 1,172,252 | 434,033 | 1,148,152 | 188 | 56,364 |
| 8 | 1,360,082 | 451,853 | 1,315,858 | 324 | 96,712 |
| 16 | 1,742,264 | 488,661 | 1,648,436 | 700 | 209,132 |
| 32 | 2,500,738 | 560,837 | 2,317,058 | 1,348 | 402,248 |
| 64 | 4,024,716 | 706,357 | 3,651,976 | 2,748 | 820,204 |

**Argument bytes, compared by an `ArgEq`** (`arg_bytes_compared`)

| Argument bytes, compared by an `ArgEq` | CPU instructions | Memory bytes | CPU, first caveat failing | Lean steps | Lean bound |
| - | - | - | - | - | - |
| 0 | 1,114,102 | 430,199 | 1,102,966 | 74 | 16,836 |
| 64 | 1,124,200 | 430,969 | 1,106,920 | 138 | 49,476 |
| 256 | 1,146,014 | 432,009 | 1,110,302 | 330 | 245,700 |
| 1024 | 1,236,592 | 435,353 | 1,127,152 | 1,098 | 2,505,156 |
| 4096 | 1,602,918 | 447,913 | 1,198,566 | 4,170 | 35,135,940 |
| 16384 | 3,061,898 | 497,337 | 1,477,898 | 16,458 | 543,146,436 |

**Argument bytes, not compared** (`arg_bytes_uncompared`)

| Argument bytes, not compared | CPU instructions | Memory bytes | CPU, first caveat failing | Lean steps | Lean bound |
| - | - | - | - | - | - |
| 0 | 1,075,164 | 425,355 | 1,065,804 | 68 | 16,104 |
| 64 | 1,075,134 | 425,627 | 1,065,774 | 68 | 24,552 |
| 256 | 1,076,666 | 425,899 | 1,067,306 | 68 | 49,896 |
| 1024 | 1,086,808 | 426,171 | 1,077,448 | 68 | 151,272 |
| 4096 | 1,121,052 | 426,443 | 1,111,692 | 68 | 556,776 |
| 16384 | 1,257,700 | 426,715 | 1,248,340 | 68 | 2,178,792 |

**Contexts (4 caveats)** (`contexts`)

| Contexts (4 caveats) | CPU instructions | Memory bytes | CPU, first caveat failing | Lean steps | Lean bound |
| - | - | - | - | - | - |
| 1 | 1,173,344 | 436,345 | 1,149,244 | 188 | 56,364 |
| 2 | 1,271,758 | 437,047 | 1,220,890 | 376 | 112,728 |
| 4 | 1,465,808 | 438,315 | 1,361,404 | 752 | 225,456 |
| 8 | 1,858,228 | 440,715 | 1,646,752 | 1,504 | 450,912 |
| 16 | 2,642,342 | 445,379 | 2,216,722 | 3,008 | 901,824 |

**`ContractIn` list length** (`contract_list`)

| `ContractIn` list length | CPU instructions | Memory bytes | CPU, first caveat failing | Lean steps | Lean bound |
| - | - | - | - | - | - |
| 1 | 1,031,011 | 423,436 | 1,024,343 | 60 | 18,172 |
| 4 | 1,060,304 | 426,878 | 1,053,924 | 69 | 70,840 |
| 16 | 1,178,746 | 440,238 | 1,173,518 | 105 | 281,512 |
| 64 | 1,646,924 | 493,270 | 1,646,304 | 249 | 1,124,200 |

**Fit**

Over 28 pairs: 99.4 CPU instructions per Lean step (least squares through the origin, R² = 0.9856). Lean, the native evaluator and the contract agree on every verdict. The zero-caveat check costs 974,554 instructions. Over every point with a caveat, the whole check's cost above that, as a share of the bound priced at the fitted constant (`(CPU − 974,554) / (99.4 × bound)`), is at most 0.083.

| Sweep | CPU instructions per Lean step (pairs ≥ 10 steps apart) | Share of the bound, smallest parameter | Share of the bound, largest parameter | Largest share of the bound |
| - | - | - | - | - |
| `caveats` | 123.5–151.0 | 0.029 | 0.037 | 0.048 |
| `arg_bytes_compared` | 96.3–163.8 | 0.083 | 0.000 | 0.083 |
| `arg_bytes_uncompared` | 151.0 | 0.063 | 0.001 | 0.063 |
| `contexts` | 132.4–141.8 | 0.035 | 0.019 | 0.035 |
| `contract_list` | 123.5–134.1 | 0.031 | 0.006 | 0.031 |

### Attack suite

| Boundary | Category | Attacks | Refused | State unchanged | Allowed controls |
| - | - | - | - | - | - |
| Soroban simulation | allowance oversubscription | 3 | 3 | 3 | 2 |
| Soroban simulation | delegation workarounds | 18 | 18 | 18 | 6 |
| Soroban simulation | nested-call smuggling | 8 | 8 | 8 | 1 |
| Soroban simulation | self-escalation | 16 | 16 | 16 | 0 |
| Agent host | delegation workarounds | 21 | 21 | 21 | 3 |
| Agent host | self-escalation | 10 | 10 | 10 | 0 |

**Soroban simulation: the grant signer on a factory-minted Perch account**

| Attempt | What the agent tries | Refused by | Error | State unchanged |
| - | - | - | - | - |
| `se-issue-through-account` | issue on the grant signer, authorized for the account by the agent's grant | account | UnvalidatedContext (#3002) | yes |
| `se-issue-as-grant-signer` | issue on the grant signer, authorized by the agent as the grant signer itself | host | Error(Auth, InvalidAction): no authorization entry covers the call | yes |
| `se-refill-through-account` | refill on the grant signer, authorized for the account by the agent's grant | account | UnvalidatedContext (#3002) | yes |
| `se-refill-as-grant-signer` | refill on the grant signer, authorized by the agent as the grant signer itself | host | Error(Auth, InvalidAction): no authorization entry covers the call | yes |
| `se-rotate-through-account` | rotate on the grant signer, authorized for the account by the agent's grant | account | UnvalidatedContext (#3002) | yes |
| `se-rotate-as-grant-signer` | rotate on the grant signer, authorized by the agent as the grant signer itself | host | Error(Auth, InvalidAction): no authorization entry covers the call | yes |
| `se-account-apply_doc` | the account's own apply_doc, authorized by an agent grant with no caveats | account | UnvalidatedContext (#3002) | yes |
| `se-account-execute` | the account's own execute, authorized by an agent grant with no caveats | account | UnvalidatedContext (#3002) | yes |
| `se-account-schedule_upgrade` | the account's own schedule_upgrade, authorized by an agent grant with no caveats | account | UnvalidatedContext (#3002) | yes |
| `se-select-admin-rule` | a transfer authorized by the agent through the owner's admin rule | account | UnvalidatedContext (#3002) | yes |
| `se-delegate-from-parent` | a sub-agent delegates from its parent's grant, dropping its own caveats | grant-signer | NotHolder (#3) | yes |
| `se-delegate-unheld` | a sub-agent delegates from a grant it does not hold | grant-signer | NotHolder (#3) | yes |
| `se-delegate-forged-signature` | a sub-agent signs as its parent's grant with its own key | grant-signer | Error(Crypto, InvalidInput): holder signature does not verify | yes |
| `se-account-execute-agent-rule-on-account` | the account's own execute, with a document that scopes an agent rule to the account | grant-signer | AccountCall (#4) | yes |
| `se-account-schedule_upgrade-agent-rule-on-account` | the account's own schedule_upgrade, with a document that scopes an agent rule to the account | grant-signer | AccountCall (#4) | yes |
| `se-refill-agent-rule-on-grant-signer` | refill on the grant signer, with a document that scopes an agent rule to the grant signer | host | Error(Context, InvalidAction): contract re-entry | yes |
| `ns-transfer-at-depth-2` | a grant for hop on the dApp; the hop chain (1 call(s)) transfers the account's asset to the attacker at depth 2 | grant-signer | NotAllowed (#6) | yes |
| `ns-transfer-at-depth-3` | a grant for hop on the dApp; the hop chain (2 call(s)) transfers the account's asset to the attacker at depth 3 | grant-signer | NotAllowed (#6) | yes |
| `ns-transfer-at-depth-4` | a grant for hop on the dApp; the hop chain (3 call(s)) transfers the account's asset to the attacker at depth 4 | grant-signer | NotAllowed (#6) | yes |
| `ns-transfer-at-depth-5` | a grant for hop on the dApp; the hop chain (4 call(s)) transfers the account's asset to the attacker at depth 5 | grant-signer | NotAllowed (#6) | yes |
| `ns-forward-other-token` | an allowed forward whose nested transfer is of a token the grant leaves out | grant-signer | NotAllowed (#6) | yes |
| `ns-forward-transfer-left-out-of-tree` | an allowed forward whose nested transfer the agent leaves out of the signed tree | host | Error(Auth, InvalidAction): no authorization entry covers the call | yes |
| `ns-control-transfer-at-depth-3` | control: a grant for hop and transfer authorizes the depth-3 transfer | allowed (control) |  | – |
| `ns-transfer-at-depth-3-left-out-of-tree` | the same depth-3 transfer with the transfer left out of the signed tree | host | Error(Auth, InvalidAction): no authorization entry covers the call | yes |
| `ns-transfer-at-depth-4-over-allowance` | a depth-4 transfer the caveats allow, larger than what is left of the allowance | grant-signer | Overdrawn (#7) | yes |
| `dw-deploy-contract` | deploy a contract with the account as deployer, under a grant with no caveats | account | UnvalidatedContext (#3002) | yes |
| `dw-deploy-contract-grant-signer-verdict` | the grant signer's own verdict on a contract-creation context, for a one-caveat grant | grant-signer | NotAllowed (#6) | yes |
| `dw-new-account-pinned-recipient` | move the budget asset to a Nido account the attacker minted, under a grant that pins the recipient | grant-signer | NotAllowed (#6) | yes |
| `dw-new-account-over-allowance` | move more than the allowance to the attacker's new account, under a grant with no caveats | grant-signer | Overdrawn (#7) | yes |
| `dw-approve-budget-asset` | approve the attacker to spend the budget asset, under a grant with no caveats | grant-signer | UnmeteredCall (#5) | yes |
| `dw-burn-budget-asset` | burn the budget asset, under a grant with no caveats | grant-signer | UnmeteredCall (#5) | yes |
| `dw-approve-other-token` | approve the attacker on a token the grant allows only transfer of | grant-signer | NotAllowed (#6) | yes |
| `dw-sub-agent-wider-recipient` | a sub-agent delegated with no added caveats and a larger allowance pays a recipient its parent's grant excludes | grant-signer | NotAllowed (#6) | yes |
| `dw-sub-agent-wider-amount` | the same sub-agent pays more per call than its parent's grant allows | grant-signer | NotAllowed (#6) | yes |
| `dw-type-muxed-recipient` | pay a muxed form (M…) of the one recipient the grant pins (G…) | grant-signer | NotAllowed (#6) | yes |
| `dw-type-control-pinned-recipient` | control: the grant signer's verdict on a payment to the pinned recipient | allowed (control) |  | – |
| `dw-type-u64-for-i128-bound` | an amount bound on an i128 argument, given a u64 | grant-signer | NotAllowed (#6) | yes |
| `dw-type-control-u64-for-i128-bound` | control: the same caveat given the value of the pinned type | allowed (control) |  | – |
| `dw-type-u32-for-bytes-of-its-xdr` | a bytes value pinned, given a u32 whose XDR is those bytes | grant-signer | NotAllowed (#6) | yes |
| `dw-type-control-u32-for-bytes-of-its-xdr` | control: the same caveat given the value of the pinned type | allowed (control) |  | – |
| `dw-type-string-for-symbol` | a symbol pinned, given a string with the same text | grant-signer | NotAllowed (#6) | yes |
| `dw-type-control-string-for-symbol` | control: the same caveat given the value of the pinned type | allowed (control) |  | – |
| `dw-type-address-for-bytes-of-its-strkey` | a bytes value pinned to an address's strkey, given that address | grant-signer | NotAllowed (#6) | yes |
| `dw-type-control-address-for-bytes-of-its-strkey` | control: the same caveat given the value of the pinned type | allowed (control) |  | – |
| `dw-revoked-grant` | spend under a revoked grant | grant-signer | Revoked (#2) | yes |
| `dw-revoked-ancestor` | spend under a grant whose parent was revoked | grant-signer | Revoked (#2) | yes |
| `dw-rotated-old-key` | sign with the holder key the owner rotated out | grant-signer | Error(Crypto, InvalidInput): holder signature does not verify | yes |
| `dw-control-signed-payment` | control: one signed payment | allowed (control) |  | – |
| `dw-replay-signed-payment` | replay the same signed authorization entry | host | Error(Auth, ExistingValue): the entry's nonce was already used | yes |
| `ao-control-first-sibling` | control: the first of two siblings (allowance 80 each, root 100) spends 80 | allowed (control) |  | – |
| `ao-second-sibling-over-root` | the second sibling spends 80 of its own 80, past what is left of the root's 100 | grant-signer | Overdrawn (#7) | yes |
| `ao-child-over-own` | a sibling with allowance 5 spends 10 | grant-signer | Overdrawn (#7) | yes |
| `ao-grandchild-over-exhausted-parent` | a grandchild with allowance 1,000,000 spends 1 under its exhausted parent | grant-signer | Overdrawn (#7) | yes |
| `ao-control-second-sibling-within-root` | control: the second sibling spends what is left of the root | allowed (control) |  | – |

**Agent host**

| Attempt | What the agent tries | Refused by | Error | State unchanged |
| - | - | - | - | - |
| `ah-se-tool-call-issue` | an agent sends a tool call that issues a grant | agent-host tool interface | unknown variant `issue`, expected one of `read_file`, `write_file`, `fetch`, `sign`, `delegate` | yes |
| `ah-se-tool-call-revoke` | an agent sends a tool call that revokes another agent | agent-host tool interface | unknown variant `revoke`, expected one of `read_file`, `write_file`, `fetch`, `sign`, `delegate` | yes |
| `ah-se-tool-call-edit-grant` | an agent sends a tool call that replaces its own grant | agent-host tool interface | unknown variant `set_grant`, expected one of `read_file`, `write_file`, `fetch`, `sign`, `delegate` | yes |
| `ah-se-sub-agent-wider-files` | a sub-agent of the read-only summarizer, delegated a grant naming `/` with read and write, reads a file outside the work directory | agent-host | Files grant denies $SANDBOX/secret/key.txt | yes |
| `ah-se-sub-agent-wider-mode` | the same sub-agent writes inside the work directory | agent-host | Files grant denies $SANDBOX/work/out/wide.txt | yes |
| `ah-se-sub-agent-wider-network` | the same sub-agent, delegated `localhost` after its parent was given no host, fetches the API | agent-host | Network grant denies http://localhost:$API_PORT/v1 | yes |
| `ah-se-sub-agent-wider-signing` | the same sub-agent, delegated every payload kind, signs an authorization entry | agent-host | Signing grant denies AuthEntry signature by research-key on "Standalone Network ; February 2017" | yes |
| `ah-se-revoked-agent` | a revoked agent reads its own work file | agent-host | agent revoked | yes |
| `ah-se-revoked-agent-delegates` | a revoked agent starts a sub-agent | agent-host | agent revoked | yes |
| `ah-se-sub-agent-of-revoked` | a sub-agent of a revoked agent reads a work file | agent-host | agent revoked | yes |
| `ah-dw-path-dotdot` | read `work/../secret/key.txt` | agent-host | Files grant denies $SANDBOX/secret/key.txt | yes |
| `ah-dw-path-symlink` | read through `work/link`, a symlink to `secret/` | agent-host | Files grant denies $SANDBOX/secret/key.txt | yes |
| `ah-dw-path-symlink-dotdot` | read `work/link/../secret/key.txt` (`..` after a symlink) | agent-host | Files grant denies $SANDBOX/secret/key.txt | yes |
| `ah-dw-path-string-prefix` | read `workshop/plan.txt`, whose path has the grant's as a string prefix | agent-host | Files grant denies $SANDBOX/workshop/plan.txt | yes |
| `ah-dw-path-case` | read `Secret/key.txt`, another case of a path outside the grant | agent-host | Files grant denies $SANDBOX/secret/key.txt | yes |
| `ah-dw-path-relative` | read a relative path | agent-host | failed: secret/key.txt is not an absolute path | yes |
| `ah-dw-path-control` | control: read a work file | allowed (control) |  | – |
| `ah-dw-write-through-symlink` | create a file through `work/link` | agent-host | Files grant denies $SANDBOX/secret/planted.txt | yes |
| `ah-dw-write-read-only` | the read-only summarizer overwrites a work file | agent-host | Files grant denies $SANDBOX/work/notes.txt | yes |
| `ah-dw-url-port` | fetch the allowed name on a port the grant leaves out | agent-host | Network grant denies http://localhost:$OTHER_PORT/v1 | yes |
| `ah-dw-url-scheme` | fetch the API over HTTPS, a scheme the grant leaves out | agent-host | Network grant denies https://localhost:$API_PORT/v1 | yes |
| `ah-dw-url-address-literal` | fetch the API by the address its name resolves to | agent-host | Network grant denies http://127.0.0.1:$API_PORT/v1 | yes |
| `ah-dw-url-decimal-address` | fetch the API by a decimal IPv4 literal | agent-host | Network grant denies http://127.0.0.1:$API_PORT/v1 | yes |
| `ah-dw-url-trailing-dot` | fetch the allowed name with a trailing dot | agent-host | Network grant denies http://localhost.:$API_PORT/v1 | yes |
| `ah-dw-url-userinfo` | fetch a URL whose userinfo is the allowed name | agent-host | Network grant denies http://localhost:$API_PORT@127.0.0.1:$OTHER_PORT/v1 | yes |
| `ah-dw-url-redirect-port` | an allowed request whose redirect goes to a port the grant leaves out | agent-host | Network grant denies http://localhost:$OTHER_PORT/v1 (redirect 1) | yes |
| `ah-dw-url-redirect-address` | an allowed request whose redirect goes to the API's address literal | agent-host | Network grant denies http://127.0.0.1:$API_PORT/v1 (redirect 1) | yes |
| `ah-dw-url-control` | control: an allowed request with an allowed redirect | allowed (control) |  | – |
| `ah-dw-sign-other-key` | sign with a key the keeper holds and the grant does not name | agent-host | Signing grant denies Message signature by other-key on "Standalone Network ; February 2017" | yes |
| `ah-dw-sign-other-network` | sign an authorization entry for testnet | agent-host | Signing grant denies AuthEntry signature by research-key on "Test SDF Network ; September 2015" | yes |
| `ah-dw-sign-preimage-network` | name the allowed network for an authorization entry built for testnet | agent-host | failed: the preimage's network id is not that of "Standalone Network ; February 2017" | yes |
| `ah-dw-sign-testnet-transaction` | sign a testnet transaction (a network and a payload kind the grant leaves out) | agent-host | Signing grant denies Transaction signature by research-key on "Test SDF Network ; September 2015" | yes |
| `ah-dw-sign-summarizer-auth-entry` | the summarizer signs an authorization entry | agent-host | Signing grant denies AuthEntry signature by research-key on "Standalone Network ; February 2017" | yes |
| `ah-dw-sign-control` | control: sign an authorization entry for the local network | allowed (control) |  | – |

### Workloads

**Soroban simulation** (each call is one transaction through the account)

| Workload | Agent | Call | Expected | Outcome | Contexts | CPU instructions | Unchanged if refused |
| - | - | - | - | - | - | - | - |
| payments | payments | transfer 50 to Bob | Allowed | allowed | 1 | 2,500,465 | – |
| payments | payments | transfer 80 to Carol | Allowed | allowed | 1 | 2,501,825 | – |
| payments | payments | transfer 120 to Bob | NotAllowed | NotAllowed (#6) | 1 | 2,175,243 | yes |
| payments | payroll | transfer 60 to Bob | Allowed | allowed | 1 | 2,695,733 | – |
| payments | payroll | transfer 60 to Bob | Allowed | allowed | 1 | 2,694,945 | – |
| payments | payroll | transfer 60 to Bob | Overdrawn | Overdrawn (#7) | 1 | 2,276,804 | yes |
| payments | payroll | transfer 10 to Carol | NotAllowed | NotAllowed (#6) | 1 | 2,270,632 | yes |
| payments | payments | transfer 100 to Bob | Allowed | allowed | 1 | 2,503,124 | – |
| payments | payments | transfer 100 to Bob | Overdrawn | Overdrawn (#7) | 1 | 2,180,379 | yes |
| defi-router | router | forward 40 of Asset to Bob | Allowed | allowed | 2 | 3,327,210 | – |
| defi-router | router | hop through [0, 1], 30 to Bob | Allowed | allowed | 3 | 4,196,094 | – |
| defi-router | router | hop through [0, 1, 2], 20 to Carol | Allowed | allowed | 4 | 5,044,867 | – |
| defi-router | swapper | forward 50 of Asset to Bob | Allowed | allowed | 2 | 3,606,282 | – |
| defi-router | swapper | hop through [0, 1], 10 to Bob | NotAllowed | NotAllowed (#6) | 3 | 3,578,670 | yes |
| defi-router | swapper | forward 60 of Asset to Bob | Overdrawn | Overdrawn (#7) | 2 | 3,100,561 | yes |
| defi-router | swapper | forward 5 of Other to Bob | NotAllowed | NotAllowed (#6) | 2 | 3,058,971 | yes |
| defi-router | router | forward 200 of Asset to Carol | Overdrawn | Overdrawn (#7) | 2 | 2,926,102 | yes |

**Agent host** (the research agent and its summarizer)

| Step | Expected | Outcome | Detail | µs |
| - | - | - | - | - |
| 0 | allowed | allowed | issued research | 221 |
| 1 | allowed | allowed | read 15 bytes | 387 |
| 2 | allowed | allowed | 200 from http://localhost:$API_PORT/v1 (11 bytes) | 6136 |
| 3 | allowed | allowed | 200 from http://localhost:$API_PORT/v1 (11 bytes) | 5378 |
| 4 | allowed | allowed | written | 947 |
| 5 | allowed | allowed | signature 0b8b1c536cfe93bfaee6cb21e32c8738d44c2f7f41d14720077f35b25e067075f699d4 | 96 |
| 6 | allowed | allowed | signature 4e0aeea0c935f12139df595b08ac0aea1234ea1b550c08eab5509990f962fe7a39fc1c | 190 |
| 7 | allowed | allowed | started summarizer | 10 |
| 8 | allowed | allowed | read 8 bytes | 444 |
| 9 | denied | denied | Files grant denies $SANDBOX/work/out/summary.md | 187 |
| 10 | denied | denied | Network grant denies http://localhost:$API_PORT/v1 | 13 |
| 11 | allowed | allowed | signature 8a441020a1aec76957d66375a9e7f86d15646d40b97f8161e2f36f11bff855cd91aef5 | 62 |
| 12 | denied | denied | Signing grant denies AuthEntry signature by research-key on "Standalone Network  | 15 |
| 13 | allowed | allowed | revoked research | 0 |
| 14 | denied | denied | agent revoked | 0 |

### Agent host: cost per check and throughput

**Per check, native `grant-eval` against the evaluator component** (3 runs of 500,000 iterations; range over the runs; compiling and instantiating the component took 87–101 ms)

| Case | Native | Component | Ratio | Component checks per second |
| - | - | - | - | - |
| files | 40.4–41.3 ns | 2.30–2.41 µs | 57–58x | 414,885–435,366 |
| network | 23.4–25.2 ns | 1.18–1.21 µs | 48–51x | 823,574–846,840 |
| signing | 51.5–52.2 ns | 1.54–1.58 µs | 30–31x | 632,772–648,720 |
| chain (3 contexts) | 219.3–235.8 ns | 4.16–5.33 µs | 18–24x | 187,510–240,203 |

**Agent-host tool calls** (one agent, calls in sequence; 3 runs; range over the runs)

| Tool call | Calls per run | Calls per second | µs per call |
| - | - | - | - |
| denied fetch (check only) | 20,000 | 340,078–353,633 | 2.83–2.94 |
| denied read outside the grant (resolve and check) | 20,000 | 5,093–6,414 | 155.90–196.35 |
| allowed read of a 15-byte file | 5,000 | 2,745–5,015 | 199.41–364.30 |
| allowed message signature | 5,000 | 19,934–21,452 | 46.62–50.17 |
| allowed authorization-entry signature | 5,000 | 19,445–20,209 | 49.48–51.43 |
| allowed fetch from the local API | 1,000 | 1,721–2,187 | 457.26–581.06 |

<!-- results:end -->

## Findings

- **The deployed evaluator's work tracks the Lean step count.** On every
  measured point the evaluator's own instructions (the `pass − fail`
  difference) are 96 to 164 per counted step: about 96 per byte when an
  `ArgEq` compares a 16 KiB byte string, and 123 to 164 on every other pair.
  The least-squares constant is 99.4 instructions per step (R² = 0.986). Priced at that constant, the bound covers the whole check
  above the zero-caveat cost with room to spare: that cost is at most 8.3% of
  `99.4 × bound` on any point, 2.9% to 4.8% as caveats grow from 1 to 64, and
  it falls as arguments, contexts and lists grow, because the bound grows with
  the product of grant and action sizes and the measured cost with their sum.
  The zero-caveat check itself (VM instantiation, loading the grant, the
  signature) is 974,554 instructions, which the model counts as zero.
- **Defect fixed: the agent host could not sign for a grant signer.** Its
  `auth_entry` payload accepted only `SorobanAuthorization` preimages. A grant
  signer holder authorizes with `AddressWithDelegates` credentials, whose
  payload is the `SorobanAuthorizationWithAddress` preimage, so an agent whose
  holder key the host's keeper held could not authorize through its grant
  signer. `crates/agent-host/src/sign.rs` now signs both, with the same
  network-id check; the regression test is
  `tests/signing.rs::a_delegated_signers_auth_entry_is_signed_over_the_preimage_hash`,
  which fails without the change. The research agent's workload signs such a
  preimage.
- **Caveats apply to every context alike.** `ArgI128AtMost(i, n)` reads
  argument `i` of every context of a tree, and calls nest contexts whose
  amounts sit at different positions (`forward`'s at 3, the nested
  `transfer`'s at 2), so a grant cannot cap per-call amounts for both; the
  defi-router session bounds amounts by its allowance alone. Expressing
  per-function caveats would need a caveat that applies only to contexts of
  one function, which the model does not have.
- **Recipients pinned by `ArgEq` are exact.** A muxed form (`M…`) of a pinned
  `G…` recipient is refused, though a muxed address is that account's key with
  an id attached.
- **Where self-escalation stops.** Under a document whose agent rules
  are scoped to contracts, the account has no rule for a call on itself or
  on the grant signer (`UnvalidatedContext`), and the grant signer's admin
  functions signed as the grant signer itself fail for want of the account's
  authorization (the host). Under documents that wrongly scope an agent rule
  to the account or to the grant signer, the grant signer's own guard
  (`AccountCall`) or the host's re-entry refusal stops the same calls.
  Delegating from a grant the agent does not hold is the grant signer's
  (`NotHolder`, or a failed holder signature).

## Not measured

Not measured in this change:

- **The local Stellar network**: the Perch stack, a factory-minted account and
  its grant signer deployed on `stellar/quickstart` in local mode with Soroban
  RPC. `scripts/local-stack.sh` builds the Perch account for such a network:
  the account source at the submodule's commit with `stateless.id` set to the
  evaluation's stateless deployer (`fixtures/stateless-deployer`, at the
  address `nido-eval local-registry` derives), and Nido's factory around that
  account. `just eval` does not run it.
- **The relay**: the workloads and the attack suite sent through
  `crates/grant-relay`, with the relay's grant mirroring the on-chain grant
  and with a relay grant that lets every call through to the grant signer.
- **Relay throughput** against the size of the channel-account swarm.
- **The concurrent overspend race**: sibling spends past an ancestor's
  allowance submitted at once through the channel swarm. The simulation runs
  sibling spends one after another.
- **Channel sequence numbers** in the clean-failure checks.
- **Instruction counts from a network's simulation**, against this host's.
- **The agent host signing for a transaction on chain**: the host now signs
  the delegated preimage; that its signature authorizes a call through the
  grant signer is not exercised.

## Stated, not proven

- That the deployed evaluator's work is proportional to the Lean step count.
  The fit and the ratios to the bound are measurements on the points above;
  `formal/` proves the bound only for the counted Lean evaluator.
- That the simulation's costs are the network's: the simulation runs
  `soroban-env-host` 27.0.1 (`machine.json`), the crate a network built from
  that version runs; no network was measured.
- That the evaluator's actions are what the grant signer sees: the Lean cases
  map contexts with `grant_relay::actions`, which the grant signer's mapping
  is tested to agree with on every argument type
  (`grant_signer::the_account_and_the_relay_map_actions_alike`); on every
  measured point the contract, the native evaluator and Lean agree.
- That a refusal changes nothing beyond what the snapshots read: they cover
  the balances, grants and account configuration listed above, not every
  ledger entry.

`testnet-channel/` is a separate check on Stellar testnet: channel-sourced
transactions signed only by a custody key.
