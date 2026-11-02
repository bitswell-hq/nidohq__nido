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
| `enrollment.ts` | Sealed alert-contact requests (register, replace, remove, add a push device, status, confirm), the WebAuthn challenge an account passkey signs, the message a device key signs to acknowledge a probe, and §9.3 rule 2 | §10.3, §10.6 |
| `strkey.ts` | `C...` addresses to and from 32-byte contract ids | |
| `prover/` | The browser prover: `RecoveryProver` starts a Web Worker per proof (`worker.ts`, serving `serve.ts`'s protocol), which downloads and caches the artifact, key and CRS (`assets.ts`, pinned CRS digests), solves the witness with noir_js, proves with Barretenberg on threads when the page is cross-origin isolated, verifies the proof under the circuit's key, and reports each stage (`protocol.ts`) | §6.5 |
| `enrollmentEmail.ts` | The enrollment Subject (`E`), the wallet's check of the enrollment email with the circuit's rules, and the salted key pin tree | §5.4, §7.4 |
| `backup.ts`, `effWordlist.ts` | The `account_code` backups: the passphrase-encrypted block (Argon2id, AES-256-GCM) and the recovery kit's 26 characters | §5.6 |
| `dkimKey.ts` | The key list, DKIM key records, and DNS-over-HTTPS JSON answers | §7.7 |
| `inbound.ts` | The sealed inbound path: a browser's sealed registration for a Subject value, and opening the message the vault sealed to it | §4.6 |

A contact change in the browser:

```ts
const nonce = attestationNonce();
const vault = await attestedVaultKey(await fetchAttestation(nonce), {
  roots: [NITRO_ROOT_DER],            // the attestation root the wallet pins
  allowedMeasurements: activeImages,  // read from the enclave-image registry
  nonce,
});
const sub = await registration.pushManager.subscribe({ applicationServerKey: vault.vapid, userVisibleOnly: true });
const deviceKey = await serviceWorkerDeviceKey();      // the P-256 key that signs probe acknowledgements
const request = await contactRequest({ account, address, accountCode, emailGuardian: true, push: sub.toJSON(), deviceKey, purposes: 1, consentVersion: 3 });
const { challenge, finish } = await prepareContactChange(vault, request, await fetchVaultNonce());
const a = await navigator.credentials.get({ publicKey: { challenge, rpId, userVerification: 'required' } });
await postContact(encodeContactRequest(finish({ publicKey: accountSignerKey, ...assertionFields(a) })));
```

The wallet UI around this (subscribing the service worker, showing codes,
reading the registry) is `packages/frontend/src/lib/recovery/`.

The circuit's inputs for a recovery email, as the browser prover builds
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

Proving it in the browser, with progress:

```ts
const prover = new RecoveryProver({ circuitUrl, vkUrl, circuitId });   // circuitId = sha256(vk)
const proof = await prover.prove(
  { eml, accountCode, rho, statement, modulus, keyPath },
  { onProgress: (e) => show(e.stage, e.elapsedMs, e.loaded, e.total) },
);
// proof.proof and proof.publicInputs go into the guardian's approval (spec §8.1)
```

The worker is `dist/prover/worker.js`, started as a module worker; a
bundler that understands `new Worker(new URL(...), { type: 'module' })`
(Vite, which the wallet uses) emits it. The page and every worker script
need cross-origin isolation for threads (spec §6.5).

```sh
npm run build -w @nidohq/email-recovery
npx tsc -p packages/email-recovery/tsconfig.test.json
npx vitest run --root packages/email-recovery
```

The tests check the alert code against an independent `node:crypto`
computation and a pinned vector, HPKE against RFC 9180 Appendix A.3.1, the
StrKey codec against the Stellar SDK, and the attestation verifier against
the Nitro mock of `@nidohq/email-mocks` across 25 refusal cases.

`test/prover.test.ts` checks the prover's protocol, cache and stages with
Barretenberg stood in, and proves the Gmail fixture for real through the
same code; `test/enrollmentEmail.test.ts` the enrollment check, the pin tree
(against the registry's vector) and the backups (Argon2id against RFC 9106);
`test/dkimKey.test.ts` the key records and the key list.

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
| `scripts/dkim-key-list.mjs` | Writes the key list (spec §7.7) from a DKIM key registry over RPC |

Both need the package built first.
