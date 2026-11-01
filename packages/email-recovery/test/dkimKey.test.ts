import { generateEmail, launchDns, dohJson, testKey } from '@nidohq/email-mocks';
import { beforeAll, describe, expect, test } from 'vitest';
import {
  DkimKeyError,
  alignedSignedBlock,
  dohTxtRecords,
  initHashes,
  keyCandidates,
  keyHash,
  parseDkimKeyRecord,
  parseKeyList,
  recoverySubject,
} from '../src/index.js';

const hex = (x: bigint) => `0x${x.toString(16)}`;
const hash = (x: bigint) => `0x${keyHash(x).toString(16).padStart(64, '0')}`;

beforeAll(initHashes);

describe('DKIM key records (RFC 6376 §3.6.1)', () => {
  test('every launch key the DNS mock publishes, read back through the DoH JSON format, verifies its provider’s mail', async () => {
    const dns = launchDns();
    const subject = recoverySubject(new Uint8Array(32).fill(1), 1n);
    for (const [provider, from] of [
      ['gmail', 'a.b@gmail.com'],
      ['outlook', 'a.b@outlook.com'],
      ['icloud', 'a.b@icloud.com'],
      ['yahoo', 'a.b@yahoo.com'],
      ['proton', 'a.b@proton.me'],
      ['fastmail', 'a.b@fastmail.com'],
      ['gmx', 'a.b@gmx.net'],
    ] as const) {
      const email = generateEmail({ provider, from, subject, body: 'x\r\n' });
      const sig = email.signatures.find((s) => s.standard && s.domain === from.split('@')[1])!;
      const answer = await dohJson(dns, `${sig.selector}._domainkey.${sig.domain}`, 'TXT');
      const [record] = dohTxtRecords(JSON.parse(JSON.stringify(answer)));
      const modulus = parseDkimKeyRecord(record!);
      expect(modulus).toBe(testKey(sig.keyName).modulus);
      await expect(alignedSignedBlock(new Uint8Array(email.eml), modulus)).resolves.toBeDefined();
    }
  });

  test('a record holding a bare RSAPublicKey (the RFC text’s form) reads the same as SubjectPublicKeyInfo', () => {
    const key = testKey('gmail');
    const spki = key.publicKey.export({ format: 'der', type: 'spki' });
    const pkcs1 = key.publicKey.export({ format: 'der', type: 'pkcs1' });
    expect(parseDkimKeyRecord(`v=DKIM1; k=rsa; p=${spki.toString('base64')}`)).toBe(key.modulus);
    expect(parseDkimKeyRecord(`k=rsa;p=${pkcs1.toString('base64').replace(/(.{60})/g, '$1 ')}`)).toBe(key.modulus);
  });

  test('revoked, non-RSA, short, duplicated and malformed records are refused', () => {
    expect(() => parseDkimKeyRecord('v=DKIM1; k=rsa; p=')).toThrow(/revoked/);
    expect(() => parseDkimKeyRecord('v=DKIM1; k=ed25519; p=AAAA')).toThrow(/not an RSA key/);
    const weak = testKey('weak').publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
    expect(() => parseDkimKeyRecord(`v=DKIM1; p=${weak}`)).toThrow(/not RSA-2048/);
    expect(() => parseDkimKeyRecord('p=AAAA; p=BBBB')).toThrow(/duplicate/);
    expect(() => parseDkimKeyRecord('v=DKIM2; p=AAAA')).toThrow(DkimKeyError);
  });

  test('DoH answers: CNAME hops are skipped and quoted strings joined; NXDOMAIN has no records', async () => {
    const cname = { Status: 0, Answer: [{ type: 5, data: 'x.example.' }, { type: 16, data: '"v=DKIM1; k=rsa; " "p=AB" "CD"' }] };
    expect(dohTxtRecords(cname)).toEqual(['v=DKIM1; k=rsa; p=ABCD']);
    expect(dohTxtRecords(await dohJson(launchDns(), 'nothing._domainkey.gmail.com', 'TXT'))).toEqual([]);
  });
});

describe('the key list (spec §7.7)', () => {
  const a = testKey('gmail').modulus;
  const b = testKey('gmail-previous').modulus;
  const makeList = () => ({
    version: 1,
    network: 'Standalone Network ; February 2017',
    registry: 'C'.padEnd(56, 'A'),
    ledger: 100,
    keys: [
      { domain: 'gmail.com', selectors: ['20251104'], modulus: hex(b), keyHash: hash(b), status: 'active' },
      { domain: 'gmail.com', selectors: ['20260707'], modulus: hex(a), keyHash: hash(a), status: 'pending' },
    ],
  });

  test('candidates for a domain, the email’s selector first', async () => {
    const l = await parseKeyList(makeList());
    expect(keyCandidates(l, 'Gmail.com', '20260707').map((k) => k.selectors[0])).toEqual(['20260707', '20251104']);
    expect(keyCandidates(l, 'outlook.com')).toEqual([]);
  });

  test('a key hash that is not its modulus’s is refused', async () => {
    const bad = makeList();
    bad.keys[1]!.keyHash = hash(b);
    await expect(parseKeyList(bad)).rejects.toThrow(/not its modulus/);
    await expect(parseKeyList({ version: 2 })).rejects.toThrow(DkimKeyError);
  });
});
