#!/usr/bin/env node
// The open From-grammar finding (README.md, "Findings"), end to end on the
// committed recovery artifact.
//
// For each From value below, a recovery email is built with the real
// recovery Subject for a statement, signed with @nidohq/email-mocks'
// TEST-ONLY Yahoo key over the octets the reference verifier selects, encoded
// by the wallet's encoder (`encodeRecoveryEmail`) with an account code and a
// key-tree path, and executed with noir_js against
// circuits/email-recovery/artifacts/recovery.json. Each row records the
// address whose commitment the circuit opens and how the two RFC 5322
// readers read the same From value.
//
//   node from-finding.mjs          writes results/from-finding.json

import { createHash, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { Noir } from '@noir-lang/noir_js';
import { testKey } from '@nidohq/email-mocks';
import { encodeRecoveryEmail, initHashes, keyHash, merkleRoot, noirInputs, recoverySubject, registryLeaf, treePath } from '@nidohq/email-recovery';

import { RECOVERY } from './lib/circuit.mjs';
import { closeReferences, readFrom, referenceSignatures } from './lib/reference.mjs';

const here = new URL('.', import.meta.url).pathname;
const FROM_VALUES = [
  'Ann Lee <t5w6.i9otz@yahoo.com>',
  'b4ionwm6.ajw@yahoo.com, x <t5w6.i9otz@yahoo.com>',
  'b4ionwm6.ajw@yahoo.com <t5w6.i9otz@yahoo.com>',
  '"q97" b4ionwm6.ajw@yahoo.com <t5w6.i9otz@yahoo.com>',
  '"x <t5w6.i9otz@yahoo.com>',
];

await initHashes();
const key = testKey('yahoo');
const statement = new TextEncoder().encode('a recovery statement');
const digest = createHash('sha256').update(statement).digest();
const rho = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdn;
const accountCode = 0x1234567890abcdef1234567890abcdefn;
const leaf = registryLeaf('yahoo.com', keyHash(key.modulus));
const siblings = treePath([leaf], 0);
const keyPath = { root: merkleRoot(leaf, 0, siblings), index: 0, siblings };
const recovery = new Noir(JSON.parse(readFileSync(RECOVERY, 'utf8')));
const bh = createHash('sha256').update('hi\r\n').digest('base64');

const rows = [];
for (const from of FROM_VALUES) {
  const head = [`From: ${from}`, 'To: recover@recovery.test', `Subject: ${recoverySubject(digest, rho)}`, 'Date: Mon, 2 Nov 2026 10:00:00 +0000', 'Message-ID: <finding@mail.yahoo.com>'];
  const field = (b) => `DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=yahoo.com; s=s2048; t=1793613600; h=from:to:subject:date:message-id; bh=${bh}; b=${b}`;
  const message = (b) => Buffer.from(`${[field(b), ...head].join('\r\n')}\r\n\r\nhi\r\n`, 'latin1');
  const [unsigned] = await referenceSignatures(message(''));
  const eml = message(sign('sha256', unsigned.signedData, key.privateKey).toString('base64'));
  const [sig] = await referenceSignatures(eml);
  const readers = await readFrom(sig.signedFroms[0]);
  let circuit;
  try {
    const encoded = await encodeRecoveryEmail({ eml, accountCode, rho, statement, modulus: key.modulus, keyPath });
    await recovery.execute(noirInputs(encoded.witness));
    circuit = { accepts: true, opensCommitmentWith: encoded.address };
  } catch (err) {
    circuit = { accepts: false, refusal: String(err.message).replace(/^Circuit execution failed: /, '') };
  }
  rows.push({ from, python: readers.python.mailboxes, pythonDefects: readers.python.defects, mailauth: readers.mailauth, circuit });
  console.log(`${JSON.stringify(from)}: Python ${JSON.stringify(readers.python.mailboxes)}, mailauth ${JSON.stringify(readers.mailauth)}, circuit ${JSON.stringify(circuit)}`);
}
closeReferences();
writeFileSync(join(here, 'results/from-finding.json'), `${JSON.stringify({ key: 'TEST-ONLY-yahoo', artifact: 'circuits/email-recovery/artifacts/recovery.json', rows }, null, 1)}\n`);
