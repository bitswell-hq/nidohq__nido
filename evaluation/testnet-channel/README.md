# Testnet check: channel-sourced transactions signed by a custody key

**Question.** Does the custody signer accept transactions whose source is a
channel account?

**Answer, for the Stellar protocol with the Dfns mock as signer: yes.** On
Stellar testnet, a channel account whose master key has weight 0 and whose
only weighted signer is the custody key accepts a transaction that carries
the custody key's signature and nothing else. This held for a classic
payment, a Soroban `InvokeHostFunction`, and a fee bump of a Soroban call with
a separate fee-source account configured the same way, with the signature
obtained through both Dfns payload kinds that sign a Stellar transaction
(`Hash` and `Transaction`). The same transactions signed by the channel's
zeroed master key or by an unrelated key were refused with `txBAD_AUTH`.

**Not established.** Whether real Dfns signs these transactions. No call to
Dfns was made: the custody key lived in the local Dfns mock
(`crates/key-keeper`, `dfns-mock`), which signs whatever envelope it is given.
Whether Dfns's `Transaction` kind checks the envelope's source account (or an
operation's) against the key's own address is not stated by the Dfns
reference. See [Open questions](#open-questions).

## What was run

[`crates/key-keeper/examples/testnet_channel.rs`](../../crates/key-keeper/examples/testnet_channel.rs):

```sh
cargo run -p nido-key-keeper --example testnet_channel -- --out run.json
```

It prints the tables below as Markdown and writes the same data as JSON;
[`run.json`](run.json) is the output of the run recorded here. It exits
non-zero if any case differs from its expectation. Each run creates new
accounts and keys, so hashes and addresses differ between runs.

1. **Keys.** The program starts the Dfns mock in process with one bearer
   token and its `Key` credential. Through `DfnsKeyKeeper` (the Dfns client,
   user action signing flow included) it calls Create Key (`POST /keys`,
   `{"scheme":"EdDSA","curve":"ed25519"}`) twice: `custody`, and `unrelated`
   for the negative cases. The mock generates each key from OS randomness and
   returns only its id and public key.
2. **Accounts.** Three fresh accounts, each funded by friendbot: `fund` (the
   fee-bump fee source) and `channel-1`, `channel-2` (transaction sources).
   This is the relay's layout of one fee-bumping account and a pool of
   channels. Each account's throwaway master key signs one `SetOptions`:
   custody key as signer with weight 1, master weight 0, low, medium and high
   thresholds 1. The program then reads each account's signers and thresholds
   back from Horizon.
3. **Custody-signed cases.** For each Dfns payload kind, `Hash` (the 32-byte
   transaction hash) and `Transaction` (the envelope XDR with
   `network: "StellarTestnet"`), with a channel as transaction source and the
   custody key as the only signer:
   - (a) a classic payment of 1 XLM to `fund`;
   - (b) a Soroban `InvokeHostFunction`: `transfer(channel, fund, 1 XLM)` on
     the native asset's Stellar Asset Contract, simulated with Stellar RPC
     `simulateTransaction` for its resources, resource fee and authorization
     entry (a source-account credential, since `from` is the transaction
     source);
   - (c) the same Soroban transfer from `channel-1`, signed by the custody
     key, wrapped in a fee bump whose fee source is `fund`, and the fee bump
     signed by the custody key. Inner fee: 100 stroops plus the simulated
     resource fee; outer fee: the inner fee plus 200 stroops.
4. **Negative cases**, each expected to be refused:
   - n1: payment from `channel-1` signed by `channel-1`'s master key;
   - n2: the same payment signed by the unrelated key (`Hash`);
   - n3: Soroban transfer from `channel-2` signed by the unrelated key
     (`Transaction`);
   - n4: a fee bump whose inner transaction the custody key signed and whose
     outer signature is `fund`'s master key.
5. **Read-back.** Every transaction is submitted with Stellar RPC
   `sendTransaction` and, when admitted, followed with `getTransaction`. After
   the last case, the program fetches each case from Horizon
   (`/transactions/{hash}`), checks the recorded source and fee accounts, and
   verifies every recorded signature (outer and, for a fee bump, inner)
   under the custody public key over the hash Horizon reports for it. It then
   reads the three accounts back again.

The program uses its own accounts only. The relay's accounts (`channels-fund`,
`channel-001`, `channel-002` in [`infra/relayer/README.md`](../../infra/relayer/README.md))
and their signers are not referenced. The custody key existed only in the mock
process, so after the run the three accounts have no usable signer.

## Results

Run on 2026-11-01 at about 06:25 UTC against `Test SDF Network ; September 2015`, protocol
29 as reported by `getNetwork` on `https://soroban-testnet.stellar.org`; accounts and
transactions read from `https://horizon-testnet.stellar.org`.

| Key | Dfns mock key id | Address |
| - | - | - |
| custody | `key-cqyir-j4bir-5287lmgwkb5gn0xc` | `GDDSXOOHU4J47O57GF2474LWBZOQCEQGSDISIHYYV7NLSOPFXFOXMRK5` |
| unrelated | `key-oti8k-uj1g1-2v5u7lty8vnzbppb` | `GCA2RXDNE4XZHN6W2QMGAS2JWXQOIWQ34TB4MXKWKNPIBP6JKK4ONDKH` |

### Accounts

| Account | Address | `SetOptions` transaction | Result |
| - | - | - | - |
| fund | [`GDZIANBSF5YR7UMCV4QX2EPHAR3H6VH44ZKNFPAX77USZWG32ETPEU37`](https://stellar.expert/explorer/testnet/account/GDZIANBSF5YR7UMCV4QX2EPHAR3H6VH44ZKNFPAX77USZWG32ETPEU37) | [`22ba75a3b7823d678d2ac2866f835c68bb82711245a0f891d5101003d0a84cce`](https://stellar.expert/explorer/testnet/tx/22ba75a3b7823d678d2ac2866f835c68bb82711245a0f891d5101003d0a84cce) | `TxSuccess` |
| channel-1 | [`GAYV7XGB7HYIJ7FQEQUKLPGYW22VT6CPCGB5RRIU5OLAIJJL4HVXQOBU`](https://stellar.expert/explorer/testnet/account/GAYV7XGB7HYIJ7FQEQUKLPGYW22VT6CPCGB5RRIU5OLAIJJL4HVXQOBU) | [`c8437feeddd5bab8fbf60f3ee432e85d65bdc4c67f8bdd0f75bc24ca8208e586`](https://stellar.expert/explorer/testnet/tx/c8437feeddd5bab8fbf60f3ee432e85d65bdc4c67f8bdd0f75bc24ca8208e586) | `TxSuccess` |
| channel-2 | [`GCXPKHEF3FNKRX46BNDUFYSVDBXXYZVZWLHXWPVUMHOCHAURKSCXHMQJ`](https://stellar.expert/explorer/testnet/account/GCXPKHEF3FNKRX46BNDUFYSVDBXXYZVZWLHXWPVUMHOCHAURKSCXHMQJ) | [`e745bb5483b24705d4dc51be08e7b780122f6f750d300b5ac533ec174f8419a1`](https://stellar.expert/explorer/testnet/tx/e745bb5483b24705d4dc51be08e7b780122f6f750d300b5ac533ec174f8419a1) | `TxSuccess` |

Signers and thresholds as Horizon reported them after setup:

| Account | Signer | Weight | Thresholds low / med / high | Sequence |
| - | - | - | - | - |
| fund | `GDDSXOOHU4J47O57GF2474LWBZOQCEQGSDISIHYYV7NLSOPFXFOXMRK5` (custody key) | 1 | 1 / 1 / 1 | 23614340078764033 |
|  | `GDZIANBSF5YR7UMCV4QX2EPHAR3H6VH44ZKNFPAX77USZWG32ETPEU37` (master key) | 0 |  |  |
| channel-1 | `GDDSXOOHU4J47O57GF2474LWBZOQCEQGSDISIHYYV7NLSOPFXFOXMRK5` (custody key) | 1 | 1 / 1 / 1 | 23614348668698625 |
|  | `GAYV7XGB7HYIJ7FQEQUKLPGYW22VT6CPCGB5RRIU5OLAIJJL4HVXQOBU` (master key) | 0 |  |  |
| channel-2 | `GDDSXOOHU4J47O57GF2474LWBZOQCEQGSDISIHYYV7NLSOPFXFOXMRK5` (custody key) | 1 | 1 / 1 / 1 | 23614357258633217 |
|  | `GCXPKHEF3FNKRX46BNDUFYSVDBXXYZVZWLHXWPVUMHOCHAURKSCXHMQJ` (master key) | 0 |  |  |

### Cases

The result is the `TransactionResultCode` from the transaction result XDR
(`getTransaction` for admitted transactions, the `errorResultXdr` of
`sendTransaction` for refused ones), under its `stellar-xdr` name: `TxBadAuth`
is the protocol's `txBAD_AUTH`. n1 and n2 have the same hash: they are
the same transaction with different signatures, and a Stellar transaction hash
does not cover signatures.

| Case | Transaction | Source | Signed by | Hash | Ledger | Result |
| - | - | - | - | - | - | - |
| a-hash | classic payment, 1 XLM to fund | channel-1 | custody via Dfns `Hash` | [`0465c828fb3946c53abd2ee25d1e62d9e471eb3840c9fb02665ca14c73eb8997`](https://stellar.expert/explorer/testnet/tx/0465c828fb3946c53abd2ee25d1e62d9e471eb3840c9fb02665ca14c73eb8997) | 5498148 | `TxSuccess` |
| b-hash | Soroban InvokeHostFunction: native contract `transfer`, 1 XLM to fund | channel-2 | custody via Dfns `Hash` | [`4e4e8d1e6e3c8f5221dbb530ad37879b89fb043bca91c84ef6d8e2748489c317`](https://stellar.expert/explorer/testnet/tx/4e4e8d1e6e3c8f5221dbb530ad37879b89fb043bca91c84ef6d8e2748489c317) | 5498149 | `TxSuccess` |
| c-hash | fee bump (fee source fund) of a Soroban native `transfer`, 1 XLM to fund | channel-1 | inner and outer: custody via Dfns `Hash` | [`71d6270a5f4e96ac7850364bbb51812eedd0df468431d7e971566e336ae0c6b7`](https://stellar.expert/explorer/testnet/tx/71d6270a5f4e96ac7850364bbb51812eedd0df468431d7e971566e336ae0c6b7) | 5498150 | `TxFeeBumpInnerSuccess (inner TxSuccess)` |
| a-transaction | classic payment, 1 XLM to fund | channel-1 | custody via Dfns `Transaction` | [`1c97c776e6cbd078ab5c84b73f9fd273f3f84dafb1b0d4b86181d1fe6f13ee47`](https://stellar.expert/explorer/testnet/tx/1c97c776e6cbd078ab5c84b73f9fd273f3f84dafb1b0d4b86181d1fe6f13ee47) | 5498151 | `TxSuccess` |
| b-transaction | Soroban InvokeHostFunction: native contract `transfer`, 1 XLM to fund | channel-2 | custody via Dfns `Transaction` | [`9ee5c66eb6af1c9fca5959c6dd91828e59eeeed7a951ae28b39d3fab0a6ce164`](https://stellar.expert/explorer/testnet/tx/9ee5c66eb6af1c9fca5959c6dd91828e59eeeed7a951ae28b39d3fab0a6ce164) | 5498152 | `TxSuccess` |
| c-transaction | fee bump (fee source fund) of a Soroban native `transfer`, 1 XLM to fund | channel-1 | inner and outer: custody via Dfns `Transaction` | [`fe1e655088f93d5496ba49b1d8972b0886e05abad5330853a16eb7b05920f374`](https://stellar.expert/explorer/testnet/tx/fe1e655088f93d5496ba49b1d8972b0886e05abad5330853a16eb7b05920f374) | 5498153 | `TxFeeBumpInnerSuccess (inner TxSuccess)` |
| n1 | classic payment, 1 XLM to fund | channel-1 | channel-1 master key (weight 0) | `149ca07d3ab3e44cff6315b64a9043e48caed683692cf3628d48b85c1d9d295f` | not in a ledger | `TxBadAuth` |
| n2 | classic payment, 1 XLM to fund | channel-1 | unrelated via Dfns `Hash` | `149ca07d3ab3e44cff6315b64a9043e48caed683692cf3628d48b85c1d9d295f` | not in a ledger | `TxBadAuth` |
| n3 | Soroban InvokeHostFunction: native contract `transfer`, 1 XLM to fund | channel-2 | unrelated via Dfns `Transaction` | `e9a381cb8ad51829d2f0a31f415219aba9535b1d7a382a4891e9b5fdc6e31072` | not in a ledger | `TxBadAuth` |
| n4 | fee bump (fee source fund) of a Soroban native `transfer`, 1 XLM to fund | channel-1 | inner: custody via Dfns `Hash`; outer: fund master key (weight 0) | `4c7fc6bbc244c6b9f319d4856c9bb75d34cd9b356482107f330c4a111fed4c31` | not in a ledger | `TxBadAuth` |

Each case as Horizon recorded it:

| Case | Successful | Source account | Fee account | Signatures (outer / inner) | Every signature verifies under the custody key |
| - | - | - | - | - | - |
| a-hash | true | channel-1 | channel-1 | 1 | yes |
| b-hash | true | channel-2 | channel-2 | 1 | yes |
| c-hash | true | channel-1 | fund | 1 / 1 | yes |
| a-transaction | true | channel-1 | channel-1 | 1 | yes |
| b-transaction | true | channel-2 | channel-2 | 1 | yes |
| c-transaction | true | channel-1 | fund | 1 / 1 | yes |
| n1 | no record (404) | | | | |
| n2 | no record (404) | | | | |
| n3 | no record (404) | | | | |
| n4 | no record (404) | | | | |

After the run, the refused cases had consumed no sequence numbers, and a
fee-bump fee source consumes none:

| Account | Sequence after setup | Sequence after the run | Signers and thresholds |
| - | - | - | - |
| fund | 23614340078764033 | 23614340078764033 | unchanged |
| channel-1 | 23614348668698625 | 23614348668698629 | unchanged |
| channel-2 | 23614357258633217 | 23614357258633219 | unchanged |
True 29 {'address': 'GDDSXOOHU4J47O57GF2474LWBZOQCEQGSDISIHYYV7NLSOPFXFOXMRK5', 'dfnsKeyId': 'key-cqyir-j4bir-5287lmgwkb5gn0xc'} {'address': 'GCA2RXDNE4XZHN6W2QMGAS2JWXQOIWQ34TB4MXKWKNPIBP6JKK4ONDKH', 'dfnsKeyId': 'key-oti8k-uj1g1-2v5u7lty8vnzbppb'}

## What this shows and what it does not

Shown, by running:

- Stellar accepts a transaction whose source is a channel account when the
  only signature is the custody key's, for classic, Soroban and fee-bump
  transactions. For the fee bump, the custody key's one signature on each
  layer satisfied both the channel's and the fee source's thresholds.
- A signature from the zeroed master key, or from a key that is not a signer,
  is refused at admission (`txBAD_AUTH`), so these transactions never reached
  a ledger and consumed no sequence number.
- A signature obtained through the mock's `Hash` kind and through its
  `Transaction` kind are equally valid to the network: both are Ed25519
  signatures over the transaction hash.

Not covered:

- The Soroban call here authorizes through the transaction source (the
  channel transfers its own XLM). In the relay, the channel is only the
  transaction source, and the account being acted on (a smart account)
  authorizes through its own authorization entry. That entry's signature is
  checked by the smart account, not by the channel's signers, and is not
  exercised here.
- The `/relay` service, real Dfns calls and mainnet are out of scope.

## Open questions

Stated, not established:

- **Does Dfns's `Transaction` kind check the source account?** The Dfns
  reference does not say whether a `Transaction` signature request on a
  Stellar key checks the envelope's source account, or any operation's,
  against the key's own address. If it checks and refuses a mismatch, every
  channel-sourced envelope would be refused under `Transaction`, since a
  channel's address is not the custody key's. The `Hash` kind carries no
  transaction for Dfns to inspect, and cases a-hash, b-hash and c-hash show
  the network accepts a signature made that way. Dfns policies "don't
  introspect raw serialized signature payloads", so a `Hash` request gives
  them nothing to evaluate ([key-keeper README](../../crates/key-keeper/README.md#dfns-signature-kinds-for-ed25519--stellar-keys)).
- **Fee bumps under Dfns.** Dfns documents a separate
  `StellarFeeBumpTransaction` kind (`innerTransaction`,
  `transactionReference`) without saying what it signs. Whether its
  `Transaction` kind accepts a fee-bump envelope, as the mock does, is unknown.
- **`Hash` on an EdDSA key.** Whether Dfns signs the 32 bytes of a `Hash`
  request directly as the Ed25519 message, as the mock does and as a Stellar
  signature requires, is not stated by the reference.
