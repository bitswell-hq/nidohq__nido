#!/usr/bin/env node
// TEST-ONLY fixture generation for the email-recovery proofs the integration
// tests replay (crates/integration-tests/src/email_proof.rs; `just
// gen-email-proofs`). Every key and message comes from @nidohq/email-mocks.
// Needs both packages built (`npm run build -w @nidohq/email-mocks -w
// @nidohq/email-recovery`).
//
//   email-fixture.mjs keys
//     Prints, as JSON, each launch domain's DKIM key record as the mock DNS
//     publishes it (the provider's aligned signer), then Gmail's key at its
//     previous selector, which the mock still publishes.
//
//   email-fixture.mjs email <request.json> <out-dir>
//     Generates the recovery email the request describes (provider, From,
//     display name, signer, and the Subject for sha256(statement) and rho),
//     and writes <out-dir>/message.eml, the circuit's <out-dir>/Prover.toml
//     (encodeRecoveryEmail, which checks the signature, the Subject and the
//     key path first), and <out-dir>/encoded.json with the public inputs.
//
//   email-fixture.mjs toml <fixture-dir> [<header-max>]
//     Prints the Prover.toml of a committed fixture
//     (crates/integration-tests/fixtures/email/<name>/), re-encoded from its
//     message.eml and fixture.json, with the header padded to <header-max>
//     (default: the circuit's HEADER_MAX).
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import {
  GMAIL_PREVIOUS_SELECTOR,
  PROVIDERS,
  generateEmail,
  gmailPreviousSigner,
  googleInternalSigner,
  keyRecordName,
  launchDns,
} from '@nidohq/email-mocks';
import {
  HEADER_MAX,
  LAUNCH_DOMAINS,
  encodeRecoveryEmail,
  initHashes,
  proverToml,
  publicInputBytes,
  recoverySubject,
} from '@nidohq/email-recovery';

const BODY = 'Approving the recovery of my account.\r\n';
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const unhex = (s) => Uint8Array.from(Buffer.from(s.replace(/^0x/, ''), 'hex'));

function providerOf(domain) {
  const p = Object.values(PROVIDERS).find((x) => x.domains.includes(domain));
  if (!p) throw new Error(`no mock provider sends for ${domain}`);
  return p;
}

function alignedSelector(domain) {
  const signer = providerOf(domain).signers.find((s) => s.fieldName.toLowerCase() === 'dkim-signature' && s.domain(domain) === domain);
  return signer.selector(domain);
}

function keys() {
  const dns = launchDns();
  const entry = (domain, signer, selector) => ({
    domain,
    provider: providerOf(domain).id,
    signer,
    selector,
    record: dns.lookup(keyRecordName(selector, domain)).join(''),
  });
  return [
    ...LAUNCH_DOMAINS.map((d) => entry(d, 'current', alignedSelector(d))),
    entry('gmail.com', 'gmail-previous', GMAIL_PREVIOUS_SELECTOR),
  ];
}

async function email(requestPath, out) {
  const r = JSON.parse(readFileSync(requestPath, 'utf8'));
  await initHashes();
  const statement = unhex(r.statement);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', statement));
  const rho = BigInt(r.rho);
  const generated = generateEmail({
    provider: r.provider,
    from: r.from,
    displayName: r.displayName ?? undefined,
    subject: recoverySubject(digest, rho),
    body: BODY,
    signers: r.signer === 'gmail-previous' ? [googleInternalSigner, gmailPreviousSigner] : undefined,
  });
  const encoded = await encodeRecoveryEmail({
    eml: generated.eml,
    accountCode: BigInt(r.accountCode),
    rho,
    statement,
    modulus: BigInt(r.modulus),
    keyPath: { root: BigInt(r.keyPath.root), index: r.keyPath.index, siblings: r.keyPath.siblings.map(BigInt) },
  });
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'message.eml'), generated.eml);
  writeFileSync(join(out, 'Prover.toml'), proverToml(encoded.witness));
  const pub = publicInputBytes(encoded.witness);
  writeFileSync(
    join(out, 'encoded.json'),
    `${JSON.stringify(
      {
        publicInputs: [0, 1, 2, 3].map((i) => `0x${hex(pub.subarray(32 * i, 32 * i + 32))}`),
        address: encoded.address,
        domain: encoded.domain,
        selector: encoded.selector,
        headerLength: encoded.witness.header.length,
      },
      null,
      2,
    )}\n`,
  );
}

async function toml(dir, headerMax) {
  const meta = JSON.parse(readFileSync(join(dir, 'fixture.json'), 'utf8'));
  const encoded = await encodeRecoveryEmail({
    eml: readFileSync(join(dir, 'message.eml')),
    accountCode: BigInt(meta.account_code),
    rho: BigInt(meta.rho),
    statement: unhex(meta.statement),
    modulus: BigInt(meta.modulus),
    keyPath: { root: BigInt(meta.key_root), index: meta.key_index, siblings: meta.key_siblings.map(BigInt) },
  });
  process.stdout.write(proverToml(encoded.witness, headerMax));
}

const [command, ...args] = process.argv.slice(2);
if (command === 'keys') {
  process.stdout.write(`${JSON.stringify(keys(), null, 2)}\n`);
} else if (command === 'email' && args.length === 2) {
  await email(args[0], args[1]);
} else if (command === 'toml' && (args.length === 1 || args.length === 2)) {
  await toml(args[0], args[1] ? Number(args[1]) : HEADER_MAX);
} else {
  console.error('usage: email-fixture.mjs keys | email <request.json> <out-dir> | toml <fixture-dir> [<header-max>]');
  process.exit(2);
}
