# @nidohq/email-alerts

Recovery alerts for Nido accounts: when an account's Perch recovery state
changes, when its email guardian approves an attempt that still needs other
approvals, a cancellation or a change, or when many attempts are open at
once, the people who registered an alert contact for it get an email and,
when the account's recovery lists an email guardian, a Web Push message on
each device they set up. The specification is `docs/email-recovery/spec.md` §10.

Two components, with a hard line between them:

| Component | Holds | Code |
| --- | --- | --- |
| **Host** (untrusted) | The RPC cursors (events, transactions), the alert queue, the sealed blobs the vault hands it; it finds email-guardian votes in the network's transactions, reconciles from the controller's state, and raises a lag alarm | `src/service.ts`, `src/votes.ts`, `src/rpc.ts`, `src/store.ts`, `src/events.ts` |
| **Vault** (the enclave application) | `K` and everything derived from it, every address, push subscription and `k_code` | `src/vault/` |

The host never receives an address. It relays sealed wallet requests and
public chain state to the vault, and stores what the vault seals.

The vault also receives the mail sent to the recovery address (spec §4.6):
a recovering browser registers the Subject value it will send, sealed to
the vault's attested key (`POST /v1/inbound`); the vault seals each matching
message to that browser's device key (`src/vault/inbound.ts`); the host keeps
the sealed copy for the browser to fetch (`GET /v1/inbound/<id>`). Browsers
on the wallet's origins may call the HTTP API (`allowOrigin`, CORS).

Each push device a contact has carries the public half of a device key the
wallet's service worker made (spec §10.3, §10.6). The vault probes each
device monthly; a tap on the probe notification makes the worker post the
probe id signed by that key (`POST /v1/ack`), and a device that answered
none of two probes is unacknowledged, which the wallet treats like a lapsed
one. The owner adds a device at once with an account passkey (`push`).

A Nido passkey's relying party is its account's own subdomain; with
`rp.accountApex` set, the vault checks each assertion against the rpId and
origin of the account the request names (`relyingPartyFor`).

## What is built and what is mocked

| Piece | Here | Production |
| --- | --- | --- |
| Watcher, retry queue, email votes from transactions, the open-attempt count, reconciliation, lag alarm, contact relay, HTTP API with its sealed-inbound and acknowledgement rate limits | Built | Same code; an outside monitor of `GET /v1/health` is not built |
| Vault: custody, sealed records, owner authorization, alert code, email and Web Push to each device, monthly acknowledged push probes, `status` and `push` (add a device) requests | Built | Same code, inside a Nitro enclave |
| Nitro NSM and its attestation PKI | TEST-ONLY mock (`@nidohq/email-mocks`, AWS's published format) | `/dev/nsm`; not built here |
| Host to vault channel | A separate Node process over IPC (`ProcessVault`) | vsock, with TLS to the outside terminating inside the enclave; not built here |
| Recovery address MX | TEST-ONLY mock (`InboundMx` of `@nidohq/email-mocks`), handing the octets to the vault process (`ProcessVault.mail`) | An MX inside the enclave, SMTP TLS terminating there; not built here |
| Key custodians | TEST-ONLY mocks | Three independent organizations; not named |
| Lettermint, Scaleway TEM, push service, Stellar RPC | TEST-ONLY mocks of the published APIs | The real services |
| Enclave-image registry | Soroban contract `contracts/enclave-image-registry`, run on the integration-test host | Not deployed |

## Running

```sh
npm run build -w @nidohq/email-recovery -w @nidohq/email-mocks -w @nidohq/email-alerts
npx tsc -p infra/email-alerts/tsconfig.test.json
npx vitest run --root infra/email-alerts
```

The end-to-end test (`test/e2e.test.ts`) forks the built vault
(`dist/vault/main.js`), so build first. It replays
`test/fixtures/chain.json`, the events and views recorded on Nido's
integration-test host by `crates/integration-tests/tests/it/email_alerts.rs`
(`cargo test -p nido-integration-tests --test it email_alerts` checks the
record still matches the chain; `NIDO_ALERT_FIXTURE=write` rewrites it).
`NIDO_ALERT_MEASUREMENTS=<file>` writes the latency and size figures of one
run.

## Tests

| File | Shows |
| --- | --- |
| `test/contacts.test.ts` | A third party cannot register, replace or remove a contact; replays, swapped envelopes, wrong relying party, type or flags are refused; alerts start only after the email confirmation; a replacement or removal takes 14 days, notifies the old contact at once, and is dropped if the authorizing passkey stopped being a signer; removal is refused, and maturity postponed, while a recovery is authorized; §9.3 rule 2 |
| `test/alerts.test.ts` | One email and one push for `attempt_authorized` with the code the wallet computes, the push leading with cancelling and every required alert pre-empting a caller; `attempt_begun` sends nothing by default, and by email at most once a day when configured to; at most one send per alert, contact and channel; Lettermint to Scaleway failover; the retry queue; cursor recovery after a restart and after a crash mid-page; RPC outages; gone push subscriptions; no address in the host's state |
| `test/liveness.test.ts` | Email votes found per vote in transactions (on an attempt under forty newer ones, nested under another contract's call, on a cancellation, on a change); the many-attempts alert; reconciliation after the events aged out of retention, paging through every open attempt and sharing delivery ids with the stream; the lag alarm; the monthly probe, its signed acknowledgement, an unacknowledged or lapsed device and its notice; `status` per device and `push` adding one at once; `chainReads` against the RPC mock |
| `test/custody.test.ts` | Genesis and restore through the custodians; two of three shares suffice, one does not, a wrong share is detected; custodians refuse an unapproved image, an image still inside its timelock, a revoked image, and a debug-mode enclave |
| `test/crypto.test.ts` | Web Push encryption reproduces RFC 8291's example byte for byte; VAPID accepted by the push-service mock |
| `test/e2e.test.ts` | The whole path above with the vault in its own process, and that no message, HTTP body, log line or stored byte of the host, and nothing the RPC, the custodians or the push service received, contains the address |
| `test/inbound.test.ts` | The sealed inbound path: a recovery email sealed to the registering browser and opened only by it, a second registration of the same value refused, mail for an unregistered value and expired registrations dropped, a bounded number of messages, foreign or malformed envelopes refused; the host routes with CORS, holding only sealed copies, and their per-client rate limit; the account-subdomain relying party |
