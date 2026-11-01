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
clock, from one recorded run whose method and conditions
`agent-host-bench.json` records (see [Agent host](#agent-host)).

Every number under [Results](#results) is generated from a file in
`results/`, and every file there is written by one of the commands above.

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
probe files are unchanged. The results write the temporary directory as
`$SANDBOX` and the two servers' ports as `$API_PORT` and `$OTHER_PORT`.

Timing (`agent_host::bench`, the method `agent-host bench` also runs):

- **What is timed.** Each check case is a three-caveat grant and an action
  it allows, so every caveat is evaluated (the chain case checks a
  three-context tree), timed three ways: `grant-eval` on values built once
  (native); the host's WIT values converted to `grant-eval` values in the
  host and then evaluated (the check without WebAssembly); and the evaluator
  component through Wasmtime. Compiling and instantiating the component is
  timed separately. The tool-call rows time one agent's calls in sequence
  through the whole host, file system, keeper and loopback HTTP included.
- **How.** Every operation is warmed up, then timed in batches whose size
  doubles until one batch is long enough for the clock's resolution not to
  matter. The three variants of a check case are sampled in interleaved
  rounds whose order rotates each round, so a change in load during the run
  reaches all three alike, and each ratio is taken within a round; the
  results section states the warm-up, batch length and round counts from the
  result file. Each cell is the
  median with a distribution-free 95% confidence interval (binomial order
  statistics), and the files keep the 10th and 90th percentiles and the
  extremes.
- **Conditions.** The evaluation's timing thread asks for the
  `QOS_CLASS_USER_INTERACTIVE` scheduling class, under which macOS runs it on
  its fastest cores when they are free; macOS cannot pin a thread to a core.
  The run records the build profile, the CPU and its cores by performance
  level, the OS, the power source and power mode, the thermal notes, and the
  load average before and after. Other processes may run during it; the
  intervals and the load averages show how much that moved the result.

## Results

<!-- results:begin (generated by `nido-eval report`; do not edit) -->

### Summary

- Soroban simulation: 45 attacks, 45 refused, 45 with state unchanged; 9 controls.
- Agent host: 31 attacks, 31 refused, 31 with state unchanged; 3 controls.
- Cost bound: verdicts agree on every point; 96–164 CPU instructions per Lean step over the pairs ≥ 10 steps apart; least squares 99.4 (R² = 0.986); the whole check above the zero-caveat cost (972,392 instructions) is at most 8.3% of the bound priced at that constant.
- Agent host, per check (medians): 0.30–1.01 µs through the component, 15–47x native `grant-eval`, 3.0–3.3x the host-side check without Wasm; the component compiles and instantiates in 22.0 ms.

### Machine and versions

|  |  |
| - | - |
| cpu | Apple M5 Max |
| lean | leanprover/lean4:v4.35.0 |
| memory | 128 GiB |
| nido_eval_dapp.wasm sha256 | d8d01d8e8af6e10a237080335c2984e82a9e094b1a2c827adf0fad481db34cbd |
| nido_grant_signer.wasm sha256 | c4214c4c8172c2e69b55b7602e72f5260fdafe0aaf4df1468ebd186a61fe704a |
| os | macOS 26.5.2 |
| perch_account.wasm sha256 | d99d56fc2d07a14c2259f0994d97316d23ae90db26835f4c977939c2b3b593aa |
| rustc | rustc 1.96.0 (ac68faa20 2026-05-25) |
| soroban-env-host | 27.0.1 |
| soroban-sdk | 27.0.6 |
| wasmtime | 49.0.5 |

### Cost per check and the Lean bound

**Caveats** (`caveats`)

| Caveats | CPU instructions | Memory bytes | CPU, first caveat failing | Lean steps | Lean bound |
| - | - | - | - | - | - |
| 0 | 972,392 | 416,582 | – | 1 | 308 |
| 1 | 1,024,459 | 420,766 | 1,017,791 | 60 | 18,172 |
| 2 | 1,069,340 | 424,997 | 1,059,980 | 68 | 20,328 |
| 4 | 1,168,746 | 434,627 | 1,144,646 | 188 | 56,364 |
| 8 | 1,355,424 | 452,447 | 1,311,200 | 324 | 96,712 |
| 16 | 1,735,302 | 489,255 | 1,641,474 | 700 | 209,132 |
| 32 | 2,489,168 | 561,431 | 2,305,488 | 1,348 | 402,248 |
| 64 | 4,003,738 | 706,951 | 3,630,998 | 2,748 | 820,204 |

**Argument bytes, compared by an `ArgEq`** (`arg_bytes_compared`)

| Argument bytes, compared by an `ArgEq` | CPU instructions | Memory bytes | CPU, first caveat failing | Lean steps | Lean bound |
| - | - | - | - | - | - |
| 0 | 1,110,692 | 430,793 | 1,099,556 | 74 | 16,836 |
| 64 | 1,120,790 | 431,563 | 1,103,510 | 138 | 49,476 |
| 256 | 1,142,604 | 432,603 | 1,106,892 | 330 | 245,700 |
| 1024 | 1,233,182 | 435,947 | 1,123,742 | 1,098 | 2,505,156 |
| 4096 | 1,600,276 | 448,507 | 1,195,924 | 4,170 | 35,135,940 |
| 16384 | 3,059,256 | 497,931 | 1,475,256 | 16,458 | 543,146,436 |

**Argument bytes, not compared** (`arg_bytes_uncompared`)

| Argument bytes, not compared | CPU instructions | Memory bytes | CPU, first caveat failing | Lean steps | Lean bound |
| - | - | - | - | - | - |
| 0 | 1,072,042 | 425,949 | 1,062,682 | 68 | 16,104 |
| 64 | 1,072,012 | 426,221 | 1,062,652 | 68 | 24,552 |
| 256 | 1,073,544 | 426,493 | 1,064,184 | 68 | 49,896 |
| 1024 | 1,084,454 | 426,765 | 1,075,094 | 68 | 151,272 |
| 4096 | 1,118,698 | 427,037 | 1,109,338 | 68 | 556,776 |
| 16384 | 1,254,578 | 427,309 | 1,245,218 | 68 | 2,178,792 |

**Contexts (4 caveats)** (`contexts`)

| Contexts (4 caveats) | CPU instructions | Memory bytes | CPU, first caveat failing | Lean steps | Lean bound |
| - | - | - | - | - | - |
| 1 | 1,169,646 | 436,939 | 1,145,546 | 188 | 56,364 |
| 2 | 1,266,912 | 437,641 | 1,216,044 | 376 | 112,728 |
| 4 | 1,458,666 | 438,909 | 1,354,262 | 752 | 225,456 |
| 8 | 1,846,494 | 441,309 | 1,635,018 | 1,504 | 450,912 |
| 16 | 2,621,424 | 445,973 | 2,195,804 | 3,008 | 901,824 |

**`ContractIn` list length** (`contract_list`)

| `ContractIn` list length | CPU instructions | Memory bytes | CPU, first caveat failing | Lean steps | Lean bound |
| - | - | - | - | - | - |
| 1 | 1,028,177 | 424,030 | 1,021,509 | 60 | 18,172 |
| 4 | 1,056,606 | 427,472 | 1,050,226 | 69 | 70,840 |
| 16 | 1,171,592 | 440,832 | 1,166,364 | 105 | 281,512 |
| 64 | 1,625,946 | 493,864 | 1,625,326 | 249 | 1,124,200 |

**Fit**

Over 28 pairs: 99.4 CPU instructions per Lean step (least squares through the origin, R² = 0.9856). Lean, the native evaluator and the contract agree on every verdict. The zero-caveat check costs 972,392 instructions. Over every point with a caveat, the whole check's cost above that, as a share of the bound priced at the fitted constant (`(CPU − 972,392) / (99.4 × bound)`), is at most 0.083.

| Sweep | CPU instructions per Lean step (pairs ≥ 10 steps apart) | Share of the bound, smallest parameter | Share of the bound, largest parameter | Largest share of the bound |
| - | - | - | - | - |
| `caveats` | 123.5–151.0 | 0.029 | 0.037 | 0.048 |
| `arg_bytes_compared` | 96.3–163.8 | 0.083 | 0.000 | 0.083 |
| `arg_bytes_uncompared` | 151.0 | 0.062 | 0.001 | 0.062 |
| `contexts` | 132.4–141.8 | 0.035 | 0.018 | 0.035 |
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
| `dw-deploy-contract-grant-signer-verdict` | the grant signer's own verdict on a contract-creation context, for a one-caveat grant | grant-signer | ContractCreation (#10) | yes |
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
| payments | payments | transfer 50 to Bob | Allowed | allowed | 1 | 2,497,586 | – |
| payments | payments | transfer 80 to Carol | Allowed | allowed | 1 | 2,498,946 | – |
| payments | payments | transfer 120 to Bob | NotAllowed | NotAllowed (#6) | 1 | 2,172,356 | yes |
| payments | payroll | transfer 60 to Bob | Allowed | allowed | 1 | 2,692,566 | – |
| payments | payroll | transfer 60 to Bob | Allowed | allowed | 1 | 2,691,778 | – |
| payments | payroll | transfer 60 to Bob | Overdrawn | Overdrawn (#7) | 1 | 2,273,637 | yes |
| payments | payroll | transfer 10 to Carol | NotAllowed | NotAllowed (#6) | 1 | 2,267,457 | yes |
| payments | payments | transfer 100 to Bob | Allowed | allowed | 1 | 2,500,245 | – |
| payments | payments | transfer 100 to Bob | Overdrawn | Overdrawn (#7) | 1 | 2,177,500 | yes |
| defi-router | router | forward 40 of Asset to Bob | Allowed | allowed | 2 | 3,322,031 | – |
| defi-router | router | hop through [0, 1], 30 to Bob | Allowed | allowed | 3 | 4,189,479 | – |
| defi-router | router | hop through [0, 1, 2], 20 to Carol | Allowed | allowed | 4 | 5,037,104 | – |
| defi-router | swapper | forward 50 of Asset to Bob | Allowed | allowed | 2 | 3,599,951 | – |
| defi-router | swapper | hop through [0, 1], 10 to Bob | NotAllowed | NotAllowed (#6) | 3 | 3,570,895 | yes |
| defi-router | swapper | forward 60 of Asset to Bob | Overdrawn | Overdrawn (#7) | 2 | 3,094,230 | yes |
| defi-router | swapper | forward 5 of Other to Bob | NotAllowed | NotAllowed (#6) | 2 | 3,052,632 | yes |
| defi-router | router | forward 200 of Asset to Carol | Overdrawn | Overdrawn (#7) | 2 | 2,920,923 | yes |

**Agent host** (the research agent and its summarizer)

| Step | Expected | Outcome | Detail | µs |
| - | - | - | - | - |
| 0 | allowed | allowed | issued research | 90 |
| 1 | allowed | allowed | read 15 bytes | 101 |
| 2 | allowed | allowed | 200 from http://localhost:$API_PORT/v1 (11 bytes) | 2789 |
| 3 | allowed | allowed | 200 from http://localhost:$API_PORT/v1 (11 bytes) | 989 |
| 4 | allowed | allowed | written | 182 |
| 5 | allowed | allowed | signature 0b8b1c536cfe93bfaee6cb21e32c8738d44c2f7f41d14720077f35b25e067075f699d4 | 22 |
| 6 | allowed | allowed | signature 4e0aeea0c935f12139df595b08ac0aea1234ea1b550c08eab5509990f962fe7a39fc1c | 14 |
| 7 | allowed | allowed | started summarizer | 3 |
| 8 | allowed | allowed | read 8 bytes | 75 |
| 9 | denied | denied | Files grant denies $SANDBOX/work/out/summary.md | 44 |
| 10 | denied | denied | Network grant denies http://localhost:$API_PORT/v1 | 3 |
| 11 | allowed | allowed | signature 8a441020a1aec76957d66375a9e7f86d15646d40b97f8161e2f36f11bff855cd91aef5 | 12 |
| 12 | denied | denied | Signing grant denies AuthEntry signature by research-key on "Standalone Network  | 3 |
| 13 | allowed | allowed | revoked research | 0 |
| 14 | denied | denied | agent revoked | 0 |

### Agent host: cost per check and throughput

One recorded run (`agent-host-bench.json`, `agent-host-throughput.json`). Build: release with overflow checks, `aarch64-macos`. Scheduling: the timing thread asked for `QOS_CLASS_USER_INTERACTIVE` (granted); macOS cannot pin a thread to a core. Every operation is warmed up for 200 ms and timed in batches of at least 2 ms. Check cases: 101 interleaved rounds, the variants' order rotating each round; ratios are taken within a round. Each cell is the median with its 95% confidence interval.

| Machine during the run |  |
| - | - |
| CPU | Apple M5 Max |
| Cores by performance level | 6 × Super, 12 × Performance |
| OS | macOS 26.5.2 (25F84) |
| Power source | Now drawing from 'AC Power' |
| Power mode | powermode            0 |
| Thermal | Note: No thermal warning level has been recorded; Note: No performance warning level has been recorded; Note: No CPU power status has been recorded |
| Load average (1, 5, 15 min) before / after | { 5.78 4.88 5.65 } / { 5.42 4.83 5.63 } |

**Per check** (ns). *Native*: `grant-eval` on values built once. *Host-side, no Wasm*: the host's WIT values converted to `grant-eval` values natively, then evaluated. *Component*: the evaluator component through Wasmtime.

| Case | Native | Host-side, no Wasm | Component | Component / native | Component / host-side | Component checks per second |
| - | - | - | - | - | - | - |
| files | 12.5 (12.4–12.6) | 182.5 (180.7–183.6) | 579.9 (579.1–581.2) | 46.5 (45.9–46.9) | 3.19 (3.17–3.22) | 1,724,481 |
| network | 7.6 (7.5–7.6) | 90.4 (89.9–90.7) | 298.6 (298.0–299.2) | 39.6 (39.2–39.9) | 3.31 (3.28–3.33) | 3,348,686 |
| signing | 15.9 (15.8–16.0) | 127.7 (126.8–128.3) | 391.5 (390.8–392.3) | 24.6 (24.6–24.8) | 3.07 (3.06–3.09) | 2,554,512 |
| chain (3 contexts) | 67.9 (67.4–68.2) | 341.6 (341.0–342.8) | 1006.7 (1003.8–1009.2) | 14.9 (14.8–15.0) | 2.96 (2.94–2.97) | 993,311 |

Compiling and instantiating the component: 22.0 (21.9–22.2) ms over 21 runs.

**Tool calls through the whole host** (µs per call; one agent, calls in sequence; 31 rounds)

| Tool call | Median (95% CI) | 10th–90th percentile | Calls per second at the median | Calls per batch |
| - | - | - | - | - |
| denied fetch (check only) | 0.68 (0.67–0.68) | 0.67–0.69 | 1,475,482 | 4096 |
| denied read outside the grant (resolve and check) | 36.88 (36.73–37.32) | 36.58–37.65 | 27,112 | 64 |
| allowed read of a 15-byte file | 46.97 (46.74–47.18) | 46.32–47.76 | 21,292 | 64 |
| allowed message signature | 10.41 (10.37–10.45) | 10.35–10.50 | 96,057 | 256 |
| allowed authorization-entry signature | 10.88 (10.87–10.92) | 10.83–10.98 | 91,880 | 256 |
| allowed fetch from the local API | 160.46 (158.22–161.78) | 154.89–166.34 | 6,232 | 16 |

<!-- results:end -->

## Findings

- **The deployed evaluator's work tracks the Lean step count.** The
  evaluator's own instructions per counted step (the `pass − fail`
  difference) stay in a narrow band on every pair, lowest where an `ArgEq`
  compares a long byte string, one byte per step; the least-squares constant
  and its R² are in [Summary](#summary). Priced at that constant, the bound
  covers the whole check above the zero-caveat cost on every point, and the
  share falls as arguments, contexts and lists grow, because the bound grows
  with the product of grant and action sizes and the measured cost with
  their sum. That share's numerator includes loading the grant and mapping
  the contexts, which the model does not count; the per-step constant comes
  from the `pass − fail` differences, which exclude them. The zero-caveat
  check itself (VM instantiation, loading the grant, the signature) is cost
  the model counts as zero.
- **At the agent host, most of the cost above native evaluation is in
  turning WIT values into evaluator values, and the component adds a
  constant factor over that.** The check without WebAssembly, which only
  converts the host's values and evaluates natively, already costs a
  multiple of the native evaluation, and the component's cost over the check
  without WebAssembly is nearly the same factor in every case (the per-check
  table).
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
- That the agent host's absolute times hold beyond the recorded run: they are
  one run on the machine and under the conditions it records; the ratios
  between variants, taken within each round, depend less on those
  conditions.

`testnet-channel/` is a separate check on Stellar testnet: channel-sourced
transactions signed only by a custody key.
