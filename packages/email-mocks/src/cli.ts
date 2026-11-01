#!/usr/bin/env node
/**
 * Writes the standard fixture set to a directory:
 *
 *   honest/<id>.eml     one per launch domain, with and without display name
 *   attacks/<id>.eml    the adversarial cases
 *   rotation/*.eml      the key-rotation scenario
 *   dns.zone            the mock DNS (launch keys, rotated selector blanked)
 *   manifest.json       per-fixture metadata: signatures, verdicts, claims, sources
 *
 * Usage: email-mocks [out-dir]   (default ./email-fixtures)
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fixtureSet, launchDns } from './fixtures.js';
import type { GeneratedEmail } from './generate.js';

function describe(email: GeneratedEmail) {
  return {
    provider: email.provider,
    from: email.input.from,
    displayName: email.input.displayName ?? null,
    to: email.input.to,
    subject: email.input.subject,
    date: email.input.date.toISOString(),
    signatures: email.signatures.map(({ field: _field, signedHeaderData: _data, ...rest }) => rest),
    dnsRecords: email.dnsRecords,
  };
}

const out = process.argv[2] ?? 'email-fixtures';
const set = fixtureSet();
for (const dir of ['honest', 'attacks', 'rotation']) mkdirSync(join(out, dir), { recursive: true });

const manifest = {
  note: 'TEST-ONLY keys and messages; provider formats per PROVIDERS.md.',
  honest: set.honest.map(({ id, email }) => {
    writeFileSync(join(out, 'honest', `${id}.eml`), email.eml);
    return { id, file: `honest/${id}.eml`, ...describe(email) };
  }),
  attacks: set.attacks.map(({ email, ...attack }) => {
    writeFileSync(join(out, 'attacks', `${attack.id}.eml`), email.eml);
    return { ...attack, file: `attacks/${attack.id}.eml`, ...describe(email) };
  }),
  rotation: set.rotation.cases.map(({ id, email, description, dnsBefore, dnsAfter }) => {
    writeFileSync(join(out, 'rotation', `${id}.eml`), email.eml);
    writeFileSync(join(out, 'rotation', `${id}.before.zone`), dnsBefore.zoneFile());
    writeFileSync(join(out, 'rotation', `${id}.after.zone`), dnsAfter.zoneFile());
    return { id, description, file: `rotation/${id}.eml`, ...describe(email) };
  }),
};
writeFileSync(join(out, 'dns.zone'), launchDns().zoneFile());
writeFileSync(join(out, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
console.log(
  `wrote ${manifest.honest.length} honest, ${manifest.attacks.length} attack and ${manifest.rotation.length} rotation fixtures to ${out}`,
);
