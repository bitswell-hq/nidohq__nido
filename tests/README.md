# Tests

Three tiers:

- **Unit (TestAuthenticator):** `just test-support` — Vitest, Node, validates
  the passkey shim crypto against the SDK parsers.
- **Fast UI e2e (`@fast`):** `just test-e2e` — Playwright on
  chromium/firefox/webkit using the in-page shim. No chain. Builds the
  frontend first.
- **Chromium CDP fidelity lane:** `just test-e2e-cdp` — real virtual
  authenticator; `*.cdp.spec.ts`.

The shim (`tests/support/auth/`) overrides `navigator.credentials` with a
deterministic P-256 vault keyed by credentialId.

## Testnet tier (`@testnet`, quarantined)

`just test-e2e-testnet` runs every spec in `tests/e2e/testnet/` against real
Stellar testnet and `perch.TESTNET`, using the shim for passkey signatures
(the synthetic P-256 signatures verify on chain). It runs under the
`testnet-chromium` / `testnet-webkit` projects (retries: 2), kept out of
`@fast` so chain flakiness never blocks routine runs. The recovery and policy
specs SECURITY_INVARIANTS W8 records, and how to run them without the hosted
relayer, are in [RUNBOOKS §1](../docs/RUNBOOKS.md#1-build-and-test-from-source).

- Slow (~15s–3min/test) and dependent on testnet + friendbot availability.
- The recipe sources `tests/.env.testnet` if present. Set
  `NIDO_TEST_BANK_SECRET=<funded testnet G-account secret>` there to pre-seed the
  name-tx fee-payer (`localStorage['nido:name-keypair']`) and skip friendbot;
  without it the app funds its own submitter via friendbot. That file is
  gitignored — never commit the secret.
- Names are unique per run (timestamped). On-chain release is not in the UI and
  is deferred — names are not cleaned up.
