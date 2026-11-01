# nido-key-keeper

Agents hold no keys. When an agent's grant allows a signature, the agent asks a
key keeper to sign a payload with key `K`. This crate defines that interface and
three implementations. The grant check runs before the keeper is called and is
not part of this crate.

```rust
pub trait KeyKeeper {
    fn sign(&self, key: &KeyId, payload: &Payload) -> Result<Signature, SignError>;
}

pub enum Payload {
    Hash([u8; 32]),                                    // Dfns `Hash`
    Message(Vec<u8>),                                  // Dfns `Message`
    StellarTransaction { network, envelope_xdr },      // Dfns `Transaction`
}
```

`Signature` is the signature in the key's network encoding (Ed25519: the 64-byte
`R || S`). `SignError` says why no signature was produced: unknown key,
unsupported payload, unauthorized caller, pending policy approval, rejected,
failed, invalid request, another backend status, a transport failure, or a
malformed response.

| Implementation | What it is |
| - | - |
| `MemoryKeyKeeper` | Ed25519 keys in process. It records every request it receives, refused ones included, so tests of later components can check what reached the keeper. |
| `dfns::DfnsKeyKeeper` | A client for the Dfns Keys API [Generate Signature][generate-signature] and [Create Key][create-key] endpoints, with the user action signing flow both require. |
| `dfns::mock` and the `dfns-mock` binary | A local HTTP server for the same endpoints, signing with Ed25519 keys it holds. The client's tests run against it. |

`stellar` has the helpers they share: the transaction hash (`stellar-xdr`'s
`TransactionEnvelope::hash` over the network id), `decorated_signature` (hint =
last four bytes of the public key), `verify_decorated_signature`, and `G…`
strkey conversion.

## The Dfns client

Generate Signature is `POST /keys/{keyId}/signatures`. It needs two headers
([Required headers][auth-headers]):

- `Authorization: Bearer <token>`: a service account token, personal access
  token or login token.
- `X-DFNS-USERACTION: <token>`: a one-time token for this exact request. The
  client gets one through the [asymmetric-key signing flow][signing-flows]:
  1. `POST /auth/action/init` with `userActionHttpMethod`, `userActionHttpPath`,
     `userActionPayload` (the exact body string it will send) and
     `userActionServerKind: "Api"`.
  2. Sign the client data `{"type":"key.get","challenge":"<challenge>"}` with
     the `Key` credential's Ed25519 private key.
  3. `POST /auth/action` with `challengeIdentifier` and
     `firstFactor: {kind: "Key", credentialAssertion: {credId, clientData, signature}}`
     (base64url). The response's `userAction` is the header value.

Create Key is `POST /keys` with the same two headers. `DfnsKeyKeeper::create_key`
sends a `CreateKeyRequest` (`CreateKeyRequest::ed25519` gives
`{"scheme": "EdDSA", "curve": "ed25519"}`) and returns the `Key`: `id`,
`publicKey` (hex), `status`, `custodial`, `dateCreated`. The private key stays
with Dfns.

Generate Signature request bodies by payload:

```json
{"kind": "Hash", "hash": "0x<32 bytes>"}
{"kind": "Message", "message": "0x<bytes>"}
{"kind": "Transaction", "transaction": "0x<TransactionEnvelope XDR>", "network": "Stellar" | "StellarTestnet"}
```

The response is a `SignatureRequest`. `Signed` and `Confirmed` return the
signature: `encoded` when present, otherwise `r || s`. A `Pending` or
`Executing` request with no `approvalId` is read back with
`GET /keys/{keyId}/signatures/{signatureId}` until it settles, up to
`poll_attempts` reads. With an `approvalId` it is `SignError::PendingApproval`.
`Rejected` and `Failed` carry `reason`.

The client's `Debug` output leaves out the token and the credential key.

The reference gives two shapes for the client data: the signing-flows page has
`{type, challenge, origin, crossOrigin}`, and [Credentials data][credentials-data]
says keys must be sorted (`{"challenge":…,"type":"key.get"}`). The client uses
the shape Dfns's TypeScript `AsymmetricKeySigner` signs
([`packages/sdk-keysigner/index.ts`][ts-keysigner]). It has not been tried
against the real Dfns service.

## The Dfns mock

```sh
cargo run -p nido-key-keeper --bin dfns-mock -- --config mock.json --listen 127.0.0.1:8787
```

```json
{
  "tokens": [{
    "token": "dev-token",
    "userId": "us-aaaaa-bbbbb-cccccccccccccccc",
    "credentials": [{ "credId": "cr-aaaaa-bbbbb-cccccccccccccccc", "publicKey": "<Ed25519 public key, hex>" }]
  }],
  "keys": [{ "keyId": "key-aaaaa-bbbbb-cccccccccccccccc", "seed": "<Ed25519 secret seed, hex>" }]
}
```

On start it prints its URL and each configured key's `G…` address. `keys` may
be empty: Create Key adds keys the mock generates itself. Tests start it in
process with `MockServer::start(&config, "127.0.0.1:0")`.

| Route | Auth |
| - | - |
| `POST /auth/action/init` | bearer |
| `POST /auth/action` | bearer |
| `POST /keys` | bearer + `X-DFNS-USERACTION` |
| `POST /keys/{keyId}/signatures` | bearer + `X-DFNS-USERACTION` |
| `GET /keys/{keyId}/signatures/{signatureId}` | bearer |

What follows the reference:

- Request bodies must match the [OpenAPI document][openapi] (version 2.0.368)
  exactly. Unknown fields (`additionalProperties: false`), missing required
  fields, wrong types, the hex patterns, the `externalId` length (1 to 50) and
  the `Network` / `BlockchainKind` enums are all checked; any violation is
  `400`.
- Errors use the documented body `{"error": {"id", "status", "message", "details"}}`
  ([API Errors][errors]).
- `401` for a missing, malformed or unknown bearer token. `403` with "User
  action signature is missing" when `X-DFNS-USERACTION` is absent
  ([Required headers][auth-headers]).
- `404` for an unknown key or signature. `409` when an `externalId` is reused
  with a different body or key. The identical request returns the original
  record with `200` ([Idempotency][idempotency]).
- A user action token authorizes one request: the bearer token, method, path
  and exact body named at `/auth/action/init`.
- Create Key bodies are checked against the documented schema the same way
  (`scheme` and `curve` enums, `name` at most 100 characters, no unknown
  fields), and the response carries the documented `Key` fields.
- Responses carry the documented `SignatureRequest` fields: `id`, `keyId`,
  `requester`, `requestBody`, `status`, `signature {r, s, encoded}`, `network`,
  `externalId`, `dateRequested`, `dateSigned`.

Where the reference is silent, the mock does the following. None of this is
evidence of how Dfns behaves:

- An invalid, mismatched or already-used user action token gets `403`. The
  reference names `403` only for a missing token or missing permission.
- A credential signature that does not verify at `/auth/action` gets `401`
  "Unable to verify signature". The reference names the message, not the
  status. An unregistered credential also gets `401`, and an unknown or spent
  `challengeIdentifier` gets `400`. Client data is accepted in any key order;
  only `type` and `challenge` are read.
- The keys are Stellar keys. `network` must be `Stellar` or `StellarTestnet`,
  and `blockchainKind` must be `Stellar`, when present. A `Transaction` without
  `network` gets `400`.
- `Hash` signs the 32 bytes as the Ed25519 message, `Message` signs the bytes,
  and `Transaction` signs the envelope's transaction hash for `network`. The
  envelope's source account is not checked.
- Create Key creates only `EdDSA` / `ed25519` keys, from OS randomness, and
  answers any other documented scheme and curve with `400`. `masterKey: true`,
  `deriveFrom`, `storeId`, `delegateTo` and `delayDelegation` also get `400`.
  `publicKey` is bare hex, like the reference's one `publicKey` example.
- A `Transaction` request may carry a fee-bump envelope; the mock signs the
  fee-bump transaction hash. Whether Dfns accepts one under `Transaction` is
  not stated.
- Documented kinds that are not EdDSA kinds (`Eip191`, `Psbt`, …) get `400`.
  `StellarFeeBumpTransaction` is parsed and then refused with `400`, because the
  reference gives its fields (`innerTransaction`, `transactionReference`) but
  not their meaning.
- Every request is signed at once (`Signed`). The mock has no policies,
  approvals, permissions (`Keys:Signatures:Create`), per-token key ownership or
  webhooks, and it omits `signedData`.
- Hex response fields carry a `0x` prefix. The reference has no
  Generate Signature response example to copy.

## Testnet check

`examples/testnet_channel.rs` creates a custody key in the mock with Create
Key, makes it the sole signer of fresh testnet channel accounts, and submits
channel-sourced classic, Soroban and fee-bump transactions signed only through
`DfnsKeyKeeper`. The recorded run and what it shows are in
[`evaluation/testnet-channel`](../../evaluation/testnet-channel/README.md).

## Dfns signature kinds for Ed25519 / Stellar keys

Everything in this section comes from reading the Dfns reference (sources
below). "Unknown" means the reference does not say.

**Kinds.** Stellar keys are EdDSA/ed25519 ([Supported key formats][key-formats]).
Generate Signature takes:

| Kind | Source | What it signs |
| - | - | - |
| `Transaction` | The only kind on the [Stellar signing][sign-stellar] page | An unsigned hex `TransactionEnvelope` XDR. `network` picks the passphrase. |
| `Hash` | [Generate Signature][generate-signature]: "All cryptographic scheme support hash signing" | A 32-byte hash. Whether an EdDSA key signs those bytes directly as the Ed25519 message is unknown. |
| `Message` | [Generate Signature][generate-signature]; [Sign][sign-index]: "EdDSA Message signing (arbitrary length)" | Arbitrary hex bytes. |
| `StellarFeeBumpTransaction` | [Generate Signature][generate-signature] request schema | `innerTransaction` and `transactionReference` (strings). The meaning of these fields and the result are unknown. |

For EdDSA, `signature.encoded` is "the raw 64-byte `r || s`". The reference
gives Solana as the example and does not name Stellar ([Generate
Signature][generate-signature]). What `signedData` holds for a Stellar
`Transaction` is unknown.

**Source-account binding.** `Hash` and `Message` carry bytes, not a
transaction, so Dfns has no source account to inspect, and its policies "don't
introspect raw serialized signature payloads" ([Policies for signature
requests][signing-policies]). For `Transaction` and `StellarFeeBumpTransaction`,
whether Dfns checks the source account (the envelope's or any operation's)
against the key's own address is unknown.

**Policy evaluation.** All four kinds go through Generate Signature, which
creates a Signature Request. That is a `Wallets:Sign` activity, evaluated
"before the MPC signing ceremony begins" ([Policies API][policies-api]). The
reference does not separate policy behavior by signature kind:

| Rule | Applies to Generate Signature |
| - | - |
| `AlwaysTrigger` | Yes: any activity kind ([Policies API][policies-api]). |
| `TransactionAmountLimit`, `TransactionAmountLimitNominal`, `TransactionRecipientWhitelist` | They "fail closed and trigger" when the amount or recipient cannot be inferred, a raw signature request among the cases named ([Policies][policies]). JSON transaction objects, the evaluable form, exist only for EVM, Concordium and Starknet ([Generate Signature][generate-signature]), so a Stellar signature request always triggers them. |
| `TransactionCountVelocity`, `TransactionAmountVelocity` | Both are measured per wallet. Whether signatures made directly with a key count toward them is unknown. |
| `ChainalysisTransactionPrescreening`, `GlobalLedgerTransactionPrescreening` | Unknown for signature requests. |
| `TravelRuleTransactionPrescreening` | No: it applies only to Transfer Asset calls ([Policies API][policies-api]). |

Scoping: the `keyId` filter applies "to signatures made directly with these
keys", and `keyStoreId` to "wallets and signatures whose key lives in one of
these key stores". Whether `walletId` and `walletTags` filters match a direct key
signature is unknown ([Policies API][policies-api]). A triggered policy blocks
or requests approval. `Block` wins, and there is no `Allow`
([Policies][policies]). Delegated wallets bypass policies entirely. The
Generate Signature response schema documents only `200` with a `status`,
`approvalId` and `datePolicyResolved`. The errors page describes `202` for a
policy hold in general ([API Errors][errors]). Which one a held signature
request returns is unknown, so the client accepts either.

## References

The Dfns reference this crate follows (`OpenAPI` version 2.0.368):

- Keys API: [Create Key][create-key], [Generate Signature][generate-signature], [Get Signature][get-signature], [OpenAPI document][openapi]
- Signing: [Sign][sign-index], [Stellar signing][sign-stellar], [Supported key formats][key-formats]
- Authentication: [Required headers][auth-headers], [User Action Signing flows][signing-flows], [Credentials data][credentials-data], [Create User Action Challenge][user-action-challenge], [Create User Action Signature][user-action-signature]
- Behavior: [API Errors][errors], [Idempotency][idempotency]
- Policies: [Policies][policies], [Policies API][policies-api], [Policies for signature requests][signing-policies]
- SDK: [TypeScript `AsymmetricKeySigner`][ts-keysigner]

[create-key]: https://docs.dfns.co/api-reference/keys/create-key
[generate-signature]: https://docs.dfns.co/api-reference/keys/generate-signature
[get-signature]: https://docs.dfns.co/api-reference/keys/get-signature
[user-action-challenge]: https://docs.dfns.co/api-reference/auth/create-user-action-challenge
[user-action-signature]: https://docs.dfns.co/api-reference/auth/create-user-action-signature
[sign-stellar]: https://docs.dfns.co/api-reference/sign/stellar
[sign-index]: https://docs.dfns.co/api-reference/sign
[key-formats]: https://docs.dfns.co/networks/supported-key-formats
[auth-headers]: https://docs.dfns.co/api-reference/auth
[signing-flows]: https://docs.dfns.co/api-reference/auth/signing-flows
[credentials-data]: https://docs.dfns.co/api-reference/auth/credentials-data
[errors]: https://docs.dfns.co/api-reference/error-codes
[idempotency]: https://docs.dfns.co/api-reference/idempotency
[policies]: https://docs.dfns.co/core-concepts/policies
[policies-api]: https://docs.dfns.co/api-reference/policies
[signing-policies]: https://docs.dfns.co/guides/signing-policies
[openapi]: https://docs.dfns.co/openapi.yaml
[ts-keysigner]: https://github.com/dfns/dfns-sdk-ts/blob/m/packages/sdk-keysigner/index.ts
