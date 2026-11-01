# @nidohq/email-alerts

Recovery alerts for Nido accounts: when an account's Perch recovery state
changes, the people who registered an alert contact for it get an email and,
when the account's recovery lists an email guardian, a Web Push message. The
specification is `docs/email-recovery/spec.md` §10.

Two components, with a hard line between them:

| Component | Holds | Code |
| --- | --- | --- |
| **Host** (untrusted) | The RPC cursor, the alert queue, the sealed blobs the vault hands it | `src/service.ts`, `src/rpc.ts`, `src/store.ts`, `src/events.ts` |
| **Vault** (the enclave application) | `K` and everything derived from it, every address, push subscription and `k_code` | `src/vault/` |

The host never receives an address. It relays sealed wallet requests and
public chain state to the vault, and stores what the vault seals.

## What is built and what is mocked

| Piece | Here | Production |
| --- | --- | --- |
| Watcher, retry queue, rate limit, contact relay, HTTP API | Built | Same code |
| Vault: custody, sealed records, owner authorization, alert code, email and Web Push | Built | Same code, inside a Nitro enclave |
| Nitro NSM and its attestation PKI | TEST-ONLY mock (`@nidohq/email-mocks`, AWS's published format) | `/dev/nsm`; not built here |
| Host to vault channel | A separate Node process over IPC (`ProcessVault`) | vsock, with TLS to the outside terminating inside the enclave; not built here |
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
| `test/alerts.test.ts` | One email and one push for `attempt_authorized` with the code the wallet computes; informational events by email only; at most one send per event, contact and channel; Lettermint to Scaleway failover; the retry queue; `attempt_begun` rate limiting; cursor recovery after a restart and after a crash mid-page; RPC outages; gone push subscriptions; no address in the host's state |
| `test/custody.test.ts` | Genesis and restore through the custodians; two of three shares suffice, one does not, a wrong share is detected; custodians refuse an unapproved image, an image still inside its timelock, a revoked image, and a debug-mode enclave |
| `test/crypto.test.ts` | Web Push encryption reproduces RFC 8291's example byte for byte; VAPID accepted by the push-service mock |
| `test/e2e.test.ts` | The whole path above with the vault in its own process, and that no message, HTTP body, log line or stored byte of the host, and nothing the RPC, the custodians or the push service received, contains the address |
