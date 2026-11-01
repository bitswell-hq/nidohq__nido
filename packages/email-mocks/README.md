# @nidohq/email-mocks

TEST-ONLY mocks of the third parties an email-recovery proof depends on:
the launch mail providers that DKIM-sign the user's recovery email, the DNS
that publishes their keys, and the MX that receives mail at the fixed
recovery address; and of the third parties of the recovery alert service
(see "Alert-service mocks"). It generates deterministic DKIM-signed `.eml`
fixtures in each provider's signing format, adversarial variants with the
verdict a sound circuit must reach, and checks every fixture with an
independent DKIM verifier.

> **Test-only.** Every signing key under `keys/` is a `TEST-ONLY-*` key
> generated for this package; none is, or derives from, a real provider key.
> Every message is synthetic. The provider formats were matched to public
> sources, listed with dates in [`PROVIDERS.md`](PROVIDERS.md). No private
> mail was used.

## What each mock mirrors

| Mock | Mirrors | Where |
|---|---|---|
| Provider signers | Gmail (gmail.com, googlemail.com), Outlook.com (outlook.com, hotmail.com), iCloud Mail (icloud.com, me.com), Yahoo Mail (yahoo.com), Proton Mail (proton.me, protonmail.com), Fastmail (fastmail.com), GMX/WEB.DE (gmx.net, gmx.de, web.de): each provider's `DKIM-Signature` tag set and order, `t=`/`x=` behaviour, `h=` list and oversigning, selector, extra signatures (Gmail's `X-Google-DKIM-Signature`, Yahoo's `X-SONIC-DKIM-SIGN`, Fastmail's `d=messagingengine.com`), folding, and the header block of a new plain-text message (order, From, Date, Message-ID, MIME) | `src/providers/`, [`PROVIDERS.md`](PROVIDERS.md) |
| DKIM signer | RFC 6376 relaxed and simple canonicalization (section 3.4), `bh=` over the canonical body, bottom-up `h=` selection with oversigning (section 5.4.2), rsa-sha256 (RFC 8301), optional `l=` | `src/canon.ts`, `src/dkim.ts`, `src/layout.ts` |
| DNS | `TXT` at `<selector>._domainkey.<domain>` in each provider's published record format, split into 255-octet character-strings; the rotated-out selectors providers leave with `p=` blanked (Gmail `20230601`/`20221208`/`20210112`, Fastmail `fm1`/`fm3`); a resolver with the `dns.promises.resolve` signature | `src/dns.ts`, `launchDns()` |
| Key rotation | Gmail's live and previous selectors both published; the previous one then blanked in place | `src/rotation.ts` |
| DNS over HTTPS | A resolver's JSON API (`application/dns-json`, the format Cloudflare and Google publish) over the DNS mock: quoted character-strings per TXT answer, `Status` 3 for an unknown name, `Access-Control-Allow-Origin: *` | `src/doh.ts` |
| Inbound MX | The receiving MX for the fixed recovery address: accepts only that recipient, refuses bare CR/LF and lines over 998 octets, undoes SMTP dot-stuffing, prepends `Return-Path` and `Received` (RFC 5321 section 4.4), and hands on every submitted octet unchanged | `src/inbound.ts` |

### Alert-service mocks

The third parties of the recovery alert service
(`docs/email-recovery/spec.md` §10), each matched to its published format:

| Mock | Mirrors | Where |
|---|---|---|
| Stellar RPC `getEvents` and `simulateTransaction` | The OpenRPC description in stellar/stellar-docs (`openrpc/src/stellar-rpc/methods/getEvents.json`, read 2026-11-01): parameters, filters, segment matchers, pagination limits, retention, result fields. The 10,000-ledger scan per request and the end-of-scan cursor follow what `soroban-testnet.stellar.org` returned on 2026-11-01 | `src/stellarRpc.ts` |
| AWS Nitro Enclaves NSM and attestation PKI | AWS's attestation process document (aws/aws-nitro-enclaves-nsm-api `docs/attestation_process.md`) and "Cryptographic attestation" in the Nitro Enclaves user guide: COSE_Sign1 tag 18, ES384, the CBOR fields in NSM order, 16 SHA-384 PCRs (PCR3/PCR4 as `SHA384(0^48 \|\| value)`, all zero in debug mode), a root-first CA bundle. The chain is TEST-ONLY (`keys/nitro/`, `scripts/generate-nitro-test-ca.sh`) and does not chain to AWS | `src/nitro.ts` |
| Vault key custodians | The custody protocol of spec §10.5; shares sealed to the attested `public_key`, the shape of AWS KMS's attested recipients | `src/custodian.ts` |
| Lettermint Sending API | `https://lettermint.co/docs/api-reference/sending/0.0.1/lettermint-sending-openapi.json` (version 0.0.1, read 2026-11-01): `POST /v1/send`, `x-lettermint-token`, `Idempotency-Key`, `SendMailRequest`, `202` pending response, `ErrorMessage` / `ApiError` / `ValidationError` | `src/sending.ts` |
| Scaleway Transactional Email | Scaleway's generated Go SDK, `api/tem/v1alpha1/tem_sdk.go` at scaleway-sdk-go commit `e27899944eebbe6b7c39b19d1a336cf6bcc9d577`: `POST /transactional-email/v1alpha1/regions/fr-par/emails`, `X-Auth-Token`, `CreateEmailRequest`, `CreateEmailResponse`, `ResponseError` | `src/sending.ts` |
| Web Push service and browser | RFC 8030 (push request, `TTL`, `Urgency`, `Topic` replacement, `201` with `Location`, `413`), RFC 8292 (VAPID JWT `aud`/`exp` rules, `k=` restricted to the subscription's key), RFC 8291 (decryption, checked against the RFC's example) | `src/webpush.ts` |
| Platform authenticator | W3C WebAuthn Level 3: `authenticatorData`, `clientDataJSON`, a DER ES256 signature | `src/webauthn.ts` |

`test/alert-mocks.test.ts` checks each against its source's rules.

The CNAME hops some providers publish their keys behind, ARC sets, and
Fastmail's experimental DKIM2 fields are not modeled; `PROVIDERS.md` lists
every field that could not be established and what the mock does instead.

## Generating fixtures

```ts
import { InboundMx, RECOVERY_ADDRESS, generateEmail, launchDns } from '@nidohq/email-mocks';

const email = generateEmail({
  provider: 'proton',
  from: 'test.user@proton.me',
  displayName: 'Test User',
  subject: '<the recovery Subject, per docs/email-recovery/spec.md>',
  body: 'Plain text.\n',
  date: new Date('2026-10-15T09:30:00Z'), // default; fixtures are deterministic
});
email.eml;          // raw RFC 5322 octets, CRLF
email.signatures;   // per signature: d=, s=, key file, h= list, the field as written, bh, b, signed octets
email.dnsRecords;   // the TXT records the signatures need

const dns = launchDns();                                   // every launch key, plus blanked selectors
const mx = new InboundMx({ recipient: RECOVERY_ADDRESS }); // recover@recovery.test
const delivered = mx.receive(email.eml, { mailFrom: 'test.user@proton.me', rcptTo: RECOVERY_ADDRESS });
```

The Subject is a free parameter; this package does not define the recovery
Subject format.

The CLI writes the standard set (one honest message per launch domain, with
and without a display name, every attack case, the rotation scenario, the
DNS zone and a `manifest.json` of metadata):

```sh
npm run fixtures -w @nidohq/email-mocks -- ./email-fixtures
```

## Adversarial cases

`buildAttacks(input)` (`src/attacks/`) takes the Subject's fixed phrase and
the values a proof would bind (`AttackInput`; `defaultAttackInput()` uses a
placeholder phrase), and returns each case as an email, the claim a
forged or replayed proof would make (sender address, recovery value,
account), the expected result of a standard DKIM verifier for each
signature, a one-line description, and, where the issue class is publicly
documented in open-source email circuits, the public source. Verdicts:

- `valid-dkim-but-must-be-rejected-by-circuit`: a standard verifier passes a
  signature, but a proof of the claim must not verify;
- `invalid-dkim`: no signature verifies;
- `valid-dkim-and-must-be-accepted`: a form whose relaxed-canonical signed
  octets carry the claim exactly (a fold at existing whitespace, runs of
  whitespace), so refusing it would only make the circuit over-strict.

Covered: display-name spoofing (address-looking names, an angle-address in
the name, Outlook's `< addr>` form, a 400-octet name, a quoted local part,
comments), `From` folded under relaxed and under simple canonicalization,
`From` absent from `h=`, a second unsigned `From` or `Subject` above or below
the signed one for every provider, `l=` with appended text, several
signatures where only a non-aligned one verifies, misaligned `d=`
(`*.gappssmtp.com`, `*.onmicrosoft.com`), an RSA-1024 key, `b=` replaced by
σ + N, a wrong `bh=`, encoded-word Subjects (including the folded form the
iCloud web client was observed to send), a folded Subject, a value split by a
fold, a phrase split by whitespace, the recovery value in the display name or
the body, and replay of an honest email for another statement or account.

The circuit accepts the statement only as the literal ASCII octets of the
relaxed-canonical Subject, so every encoded-word Subject is a reject case.

## Verification

```sh
npm test -w @nidohq/email-mocks        # vitest; no network
npm run typecheck -w @nidohq/email-mocks
```

The tests verify every honest fixture with
[mailauth](https://github.com/postalsys/mailauth) 8.0.4 (pinned, `strict`
mode) against the mock DNS, check every attack case's per-signature result
against the case's expectation (so every `invalid-dkim` case fails it), check
the rotation scenario before and after the previous selector is blanked,
replay the 28 provider signatures observed in public archives
(`test/observed-signature-layouts.json`) through the layouts and require the
same line breaks, and test the canonicalization against the RFC 6376 section
3.4.6 example.

## Keys

`scripts/generate-test-keys.sh` writes any missing `keys/TEST-ONLY-*.pem`
with OpenSSL. The committed keys are the fixtures' keys: regenerating one
changes every fixture signed with it. Where providers share a key across
domains (gmail.com and googlemail.com, outlook.com and hotmail.com, gmx.net
and gmx.de) the mock shares a test key; where they publish separate keys
(icloud.com and me.com, proton.me and protonmail.com, web.de) it uses
separate test keys.
