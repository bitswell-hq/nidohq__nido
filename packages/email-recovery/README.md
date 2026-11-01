# @nidohq/email-recovery

The wallet-side pieces of email recovery that run in the browser
(`docs/email-recovery/spec.md`). WebCrypto, plus bb.js for Poseidon2, so the
same code runs in browsers and in Node 20+.

| Module | What it does | Spec |
| --- | --- | --- |
| `dkimHeader.ts` | Parses a raw `.eml`, canonicalizes header fields (RFC 6376 §3.4), selects the DKIM-Signature aligned with the From domain, and builds the signed header block `H` exactly as a verifier does (§3.7, §5.4.2) | §4.3 |
| `recoveryInputs.ts` | The recovery circuit's inputs from a raw recovery email plus `(account_code, rho, statement, key path)`: `encodeRecoveryEmail` checks the signature, the Subject opening, the key path and the header bound first, then returns the witness as a noir_js input map (`noirInputs`) or a `Prover.toml` (`proverToml`); also the spec's `P2` hashes (`C`, `T`, key hash, leaf, Merkle path, pin salt) and `recoverySubject` for the `mailto:` link | §4.2, §5.3, §6, §7 |
| `alertCode.ts` | The 6-digit verification code an alert carries: `k_code = HKDF(account_code)`, then `HMAC(k_code, network, controller, account, subject)` | §10.1 |
| `attestation.ts`, `x509.ts` | Verifies an AWS Nitro Enclaves attestation document as AWS's attestation process document prescribes (COSE_Sign1 ES384, CBOR field rules, certificate path to a pinned root), plus freshness, a non-debug enclave, and an allowed image measurement | §10.5 |
| `hpke.ts` | HPKE (RFC 9180) base mode, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, through `@hpke/core` | §10.3 |
| `enrollment.ts` | Sealed alert-contact requests (register, replace, remove, confirm), the WebAuthn challenge an account passkey signs, and §9.3 rule 2 | §10.3 |
| `strkey.ts` | `C...` addresses to and from 32-byte contract ids | |

A contact change in the browser:

```ts
const nonce = attestationNonce();
const vault = await attestedVaultKey(await fetchAttestation(nonce), {
  roots: [NITRO_ROOT_DER],            // the attestation root the wallet pins
  allowedMeasurements: activeImages,  // read from the enclave-image registry
  nonce,
});
const sub = await registration.pushManager.subscribe({ applicationServerKey: vault.vapid, userVisibleOnly: true });
const request = await contactRequest({ account, address, accountCode, emailGuardian: true, push: sub.toJSON(), purposes: 1, consentVersion: 1 });
const { challenge, finish } = await prepareContactChange(vault, request, await fetchVaultNonce());
const a = await navigator.credentials.get({ publicKey: { challenge, rpId, userVerification: 'required' } });
await postContact(encodeContactRequest(finish({ publicKey: accountSignerKey, ...assertionFields(a) })));
```

The wallet UI around this (subscribing the service worker, showing codes,
reading the registry) is not part of this package.

The circuit's inputs for a recovery email, as the browser prover will build
them:

```ts
await initHashes();                                   // bb.js's Poseidon2
const subject = recoverySubject(digest, rho);         // for the mailto: link
// ... the user sends the email; the wallet receives its raw octets ...
const { witness } = await encodeRecoveryEmail({ eml, accountCode, rho, statement, modulus, keyPath });
const solved = await new Noir(recoveryCircuit).execute(noirInputs(witness));
```

`recoveryCircuit` is `circuits/email-recovery/artifacts/recovery.json`;
`modulus` and `keyPath` come from the DKIM key registry (its `key_proposed`
event carries the modulus; `leaf`, `siblings` and `root` the path) or from
the guardian's pin tree.

```sh
npm run build -w @nidohq/email-recovery
npx tsc -p packages/email-recovery/tsconfig.test.json
npx vitest run --root packages/email-recovery
```

The tests check the alert code against an independent `node:crypto`
computation and a pinned vector, HPKE against RFC 9180 Appendix A.3.1, the
StrKey codec against the Stellar SDK, and the attestation verifier against
the Nitro mock of `@nidohq/email-mocks` across 25 refusal cases.

For the circuit's inputs (`test/recoveryInputs.test.ts`): the `P2` hashes
against the values the circuit's Noir tests and the DKIM key registry pin;
the signed header block against the octets every mock provider's key signed
(all signatures, every domain, with and without a display name); and the
committed circuit (`noir_js`) accepting an honest recovery email from every
domain the mocks sign for. `test/attacks.test.ts` runs every adversarial email
of `@nidohq/email-mocks` through the circuit with the strongest witness for
its claim (`test/attackHarness.ts`) and pins the assertion that refuses it.

## Scripts

| Script | What it does |
| --- | --- |
| `scripts/email-fixture.mjs` | TEST-ONLY: the provider keys the integration tests' registry admits, and the recovery email and `Prover.toml` for one approval (`just gen-email-proofs` runs it) |
| `scripts/measure-bbjs.mjs` | Proves a committed fixture with bb.js and prints its time and peak memory (`circuits/email-recovery/scripts/measure.sh` runs it) |

Both need the package built first.
