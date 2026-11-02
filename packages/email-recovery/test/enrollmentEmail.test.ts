import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { argon2id } from '@noble/hashes/argon2.js';
import { PROVIDERS, type SignerProfile, generateEmail, testKey } from '@nidohq/email-mocks';
import { beforeAll, describe, expect, test } from 'vitest';
import {
  BACKUP_BEGIN,
  BackupError,
  DOM_ENROLL,
  DkimHeaderError,
  type CompiledCircuit,
  EFF_LARGE_WORDLIST,
  ENROLL_PHRASE,
  FIELD_MODULUS,
  HEADER_MAX,
  addressCommitment,
  checkEnrollmentEmail,
  alignedSignedBlock,
  backupPayload,
  circuitAcceptsHeader,
  decryptBackup,
  encryptBackup,
  openBackup,
  enrollmentSubject,
  fromGrammarOk,
  generatePassphrase,
  initHashes,
  keyHash,
  merkleRoot,
  parseRecoveryKitCode,
  pinTree,
  recoveryKitCode,
  recoverySubject,
  registryLeaf,
} from '../src/index.js';

const ACCOUNT_CODE = 0x0102030405060708090a0b0c0d0e0f10n;
const ACCOUNT = Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + (i % 16));
const OTHER_ACCOUNT = Uint8Array.from({ length: 32 }, (_, i) => 0xb0 + (i % 16));
const RHO_E = 0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeen;

/** The committed recovery artifact, the one the wallet proves with. */
const CIRCUIT = JSON.parse(readFileSync(new URL('../../../circuits/email-recovery/artifacts/recovery.json', import.meta.url), 'utf8')) as CompiledCircuit;

const vectors = readFileSync(new URL('../../../circuits/email-recovery/tests/src/vectors.nr', import.meta.url), 'utf8');
function vectorModulus(name: string): bigint {
  const m = new RegExp(`pub global ${name}: \\[u128; 18\\] = \\[([^\\]]+)\\]`).exec(vectors)!;
  return m[1]!
    .split(',')
    .map((x) => BigInt(x.trim()))
    .reduce((acc, limb, i) => acc + (limb << (120n * BigInt(i))), 0n);
}

/** The enrollment email Gmail's mock signs for `from`, and its aligned key; `signers` re-signs it with other tags. */
function enrollmentEmail(
  subject: string,
  from = 'first.last@gmail.com',
  provider: 'gmail' | 'outlook' = 'gmail',
  signers?: SignerProfile[],
  displayName = 'First Last',
) {
  const email = generateEmail({ provider, from, displayName, subject, body: 'Enrollment.\r\n', signers });
  const domain = from.slice(from.indexOf('@') + 1);
  const aligned = email.signatures.find((s) => s.standard && s.domain === domain)!;
  return { eml: new Uint8Array(email.eml), modulus: testKey(aligned.keyName).modulus };
}

beforeAll(initHashes);

describe('enrollment email (spec §5.4)', () => {
  test('DOM_ENROLL follows the label rule and E opens with the account and rho_e', () => {
    const label = BigInt(`0x${createHash('sha256').update('nido/email-recovery/v1/enroll').digest('hex')}`) % FIELD_MODULUS;
    expect(DOM_ENROLL).toBe(label);
    const subject = enrollmentSubject(ACCOUNT, RHO_E);
    expect(subject).toMatch(new RegExp(`^${ENROLL_PHRASE}[0-9a-f]{64}$`));
    expect(enrollmentSubject(OTHER_ACCOUNT, RHO_E)).not.toBe(subject);
    expect(enrollmentSubject(ACCOUNT, RHO_E + 1n)).not.toBe(subject);
  });

  test('an honest enrollment email is accepted, and C is the commitment to its signed From address', async () => {
    const { eml, modulus } = enrollmentEmail(enrollmentSubject(ACCOUNT, RHO_E));
    const checked = await checkEnrollmentEmail({ circuit: CIRCUIT, eml, accountId: ACCOUNT, rhoE: RHO_E, accountCode: ACCOUNT_CODE, modulus });
    expect(checked.address).toBe('first.last@gmail.com');
    expect(checked.domain).toBe('gmail.com');
    expect(checked.commitment).toBe(addressCommitment('first.last@gmail.com', ACCOUNT_CODE));
    expect(checked.keyLeaf).toBe(registryLeaf('gmail.com', keyHash(modulus)));
  });

  test('another account, another rho_e, or the recovery phrase is refused', async () => {
    const check = (subject: string) => {
      const { eml, modulus } = enrollmentEmail(subject);
      return checkEnrollmentEmail({ circuit: CIRCUIT, eml, accountId: ACCOUNT, rhoE: RHO_E, accountCode: ACCOUNT_CODE, modulus });
    };
    await expect(check(enrollmentSubject(OTHER_ACCOUNT, RHO_E))).rejects.toThrow(/enrollment’s Subject/);
    await expect(check(enrollmentSubject(ACCOUNT, RHO_E + 1n))).rejects.toThrow(/enrollment’s Subject/);
    await expect(check(recoverySubject(new Uint8Array(32), RHO_E))).rejects.toThrow(/enrollment’s Subject/);
  });

  test('a key that did not sign it is refused', async () => {
    const { eml } = enrollmentEmail(enrollmentSubject(ACCOUNT, RHO_E));
    await expect(
      checkEnrollmentEmail({ circuit: CIRCUIT, eml, accountId: ACCOUNT, rhoE: RHO_E, accountCode: ACCOUNT_CODE, modulus: testKey('weak').modulus }),
    ).rejects.toThrow(DkimHeaderError);
  });

  test('a provider domain outside the allowlist is refused', async () => {
    const { eml, modulus } = enrollmentEmail(enrollmentSubject(ACCOUNT, RHO_E));
    await expect(
      checkEnrollmentEmail({ circuit: CIRCUIT, eml, accountId: ACCOUNT, rhoE: RHO_E, accountCode: ACCOUNT_CODE, modulus, allowedDomains: ['outlook.com'] }),
    ).rejects.toThrow(/not one of the providers/);
  });

  /** Gmail's signers, with `edit` applied to each signer's tags. */
  const gmailSigners = (edit: (tags: Array<[string, string]>) => Array<[string, string]>): SignerProfile[] =>
    PROVIDERS.gmail.signers.map((signer) => ({ ...signer, tags: (ctx, dsh) => edit(signer.tags(ctx, dsh)) }));
  const setTag = (name: string, value: string) => (tags: Array<[string, string]>) =>
    tags.map(([n, v]): [string, string] => (n === name ? [n, value] : [n, v]));

  test('the recovery circuit itself refuses signatures it cannot prove: c=relaxed, c=Relaxed/Relaxed, a=RSA-SHA256, a space in d=', async () => {
    const subject = enrollmentSubject(ACCOUNT, RHO_E);
    const check = (signers?: SignerProfile[]) => {
      const { eml, modulus } = enrollmentEmail(subject, 'first.last@gmail.com', 'gmail', signers);
      return checkEnrollmentEmail({ circuit: CIRCUIT, eml, accountId: ACCOUNT, rhoE: RHO_E, accountCode: ACCOUNT_CODE, modulus });
    };
    await expect(check()).resolves.toMatchObject({ address: 'first.last@gmail.com' });
    for (const [edit, refusal] of [
      [setTag('c', 'relaxed'), 'DKIM: header canonicalization must be relaxed'],
      [setTag('c', 'Relaxed/Relaxed'), 'DKIM: header canonicalization must be relaxed'],
      [setTag('a', 'RSA-SHA256'), 'DKIM: a= must be rsa-sha256'],
      [setTag('d', ' gmail.com'), 'the recovery circuit refuses how this email is signed'],
    ] as const) {
      await expect(check(gmailSigners(edit))).rejects.toThrow(refusal);
    }
  }, 60_000);

  test('circuitAcceptsHeader accepts a header only where the circuit stops at the recovery phrase', async () => {
    const { eml, modulus } = enrollmentEmail(enrollmentSubject(ACCOUNT, RHO_E));
    const { block, value } = await alignedSignedBlock(eml, modulus);
    await expect(circuitAcceptsHeader(CIRCUIT, block, modulus, value)).resolves.toBeUndefined();
    // A recovery Subject gets past the phrase, so the circuit refuses at a later assertion.
    const recovery = enrollmentEmail(recoverySubject(new Uint8Array(32), RHO_E));
    const signed = await alignedSignedBlock(recovery.eml, recovery.modulus);
    await expect(circuitAcceptsHeader(CIRCUIT, signed.block, recovery.modulus, signed.value)).rejects.toThrow(DkimHeaderError);
    // Another provider's key fails the circuit's RSA check; a 1024-bit key does not fit its limbs.
    await expect(circuitAcceptsHeader(CIRCUIT, block, testKey('outlook').modulus, value)).rejects.toThrow(DkimHeaderError);
    await expect(circuitAcceptsHeader(CIRCUIT, block, testKey('weak').modulus, value)).rejects.toThrow(DkimHeaderError);
  }, 60_000);

  test('an enrollment block with no room for the recovery Subject’s extra octet is refused', async () => {
    const subject = enrollmentSubject(ACCOUNT, RHO_E);
    const base = enrollmentEmail(subject);
    const { block } = await alignedSignedBlock(base.eml, base.modulus);
    const name = 'N'.repeat(10 + HEADER_MAX - block.length);
    const { eml, modulus } = enrollmentEmail(subject, 'first.last@gmail.com', 'gmail', undefined, name);
    expect((await alignedSignedBlock(eml, modulus)).block.length).toBe(HEADER_MAX);
    await expect(
      checkEnrollmentEmail({ circuit: CIRCUIT, eml, accountId: ACCOUNT, rhoE: RHO_E, accountCode: ACCOUNT_CODE, modulus }),
    ).rejects.toThrow(/would exceed/);
  });

  test('the From grammar is the circuit’s (spec §4.5)', () => {
    expect(fromGrammarOk('first.last@gmail.com')).toBe(true);
    expect(fromGrammarOk('First Last <first.last+tag@gmail.com>')).toBe(true);
    expect(fromGrammarOk('<a@123mail.org>')).toBe(true);
    expect(fromGrammarOk('"First" <first@gmail.com>')).toBe(true);
    expect(fromGrammarOk('"first last"@gmail.com')).toBe(false);
    expect(fromGrammarOk('First <a@gmail.com> (comment)')).toBe(false);
    expect(fromGrammarOk('a@gmail.com, b@gmail.com')).toBe(false);
    expect(fromGrammarOk('a..b@gmail.com')).toBe(false);
    expect(fromGrammarOk('a@localhost')).toBe(false);
    expect(fromGrammarOk('a@-gmail.com')).toBe(false);
    expect(fromGrammarOk(`${'a'.repeat(115)}@gmail.com`)).toBe(false);
  });

  test('the display name is a phrase: atoms, dots and closed quoted strings (spec §4.5)', () => {
    for (const ok of [
      '"Doe, John (x) a@b; c:d \\"JD\\" \\\\" <a@gmail.com>',
      '=?UTF-8?B?Wm/DqyBFeGFtcGxl?= <a@gmail.com>',
      '=?UTF-8?Q?Zo=C3=AB_Example?= <a@gmail.com>',
      'Alice "the Great" Q. Example <a@gmail.com>',
      '"" <a@gmail.com>',
    ]) {
      expect(fromGrammarOk(ok), ok).toBe(true);
    }
    for (const bad of [
      'b4ionwm6.ajw@yahoo.com, x <t5w6.i9otz@yahoo.com>',
      'b4ionwm6.ajw@yahoo.com <t5w6.i9otz@yahoo.com>',
      '"q97" b4ionwm6.ajw@yahoo.com <t5w6.i9otz@yahoo.com>',
      '"x <t5w6.i9otz@yahoo.com>',
      'Doe, John <a@gmail.com>',
      'a;b <a@gmail.com>',
      'friends: x <a@gmail.com>',
      'a\\b <a@gmail.com>',
      'x (y) <a@gmail.com>',
      '"x\\" <a@gmail.com>',
      '"x <y>" <a@gmail.com>',
      'a>b <a@gmail.com>',
      '<b@gmail.com> <a@gmail.com>',
      'Zo\u00c3\u00ab <a@gmail.com>',
    ]) {
      expect(fromGrammarOk(bad), bad).toBe(false);
    }
  });
});

describe('key pin (spec §7.4)', () => {
  test('the pin root is the DKIM key registry vector, and each path opens to it', () => {
    const modulus = vectorModulus('REGISTRY_MODULUS_A');
    const pin = pinTree(ACCOUNT_CODE, [{ domain: 'gmail.com', modulus }]);
    // Pinned in test/recoveryInputs.test.ts and contracts/dkim-registry/vectors.
    expect(pin.root).toBe(0x06809f5b34b6b7e95400ba494bbf58b9e2e7e5c9457bbc537560af4b3cb36a1fn);
    const path = pin.path(0);
    expect(path.index).toBe(1);
    expect(merkleRoot(registryLeaf('gmail.com', keyHash(modulus)), path.index, path.siblings)).toBe(pin.root);
    expect(pinTree(ACCOUNT_CODE + 1n, [{ domain: 'gmail.com', modulus }]).root).not.toBe(pin.root);
    expect(() => pinTree(ACCOUNT_CODE, [])).toThrow(RangeError);
  });
});

describe('account_code backups (spec §5.6)', () => {
  const code = Uint8Array.from({ length: 16 }, (_, i) => i + 1);

  test('Argon2id is RFC 9106’s (§5.3 test vector)', () => {
    const tag = argon2id(new Uint8Array(32).fill(1), new Uint8Array(16).fill(2), {
      t: 3,
      m: 32,
      p: 4,
      dkLen: 32,
      key: new Uint8Array(8).fill(3),
      personalization: new Uint8Array(12).fill(4),
    });
    expect(Buffer.from(tag).toString('hex')).toBe('0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659');
  });

  test('a passphrase is five words of the EFF large wordlist', () => {
    expect(EFF_LARGE_WORDLIST).toHaveLength(7776);
    expect(new Set(EFF_LARGE_WORDLIST).size).toBe(7776);
    const p = generatePassphrase();
    expect(p.split(' ')).toHaveLength(5);
    for (const w of p.split(' ')) expect(EFF_LARGE_WORDLIST).toContain(w);
  });

  test(
    'the passphrase-encrypted block opens only with its passphrase and account',
    async () => {
      const passphrase = 'abacus zoom tidal unpack sphere';
      const block = await encryptBackup(code, passphrase, ACCOUNT);
      expect(block.startsWith(BACKUP_BEGIN)).toBe(true);
      const payload = block.split('\n')[1]!;
      // salt (16) || nonce (12) || AES-GCM(account_code (16) || account (32)) with its tag (16): 92 octets.
      expect(payload).toMatch(/^v2\.[A-Za-z0-9_-]{123}$/);
      // Found inside a whole email body; the passphrase as a user might retype it.
      expect(await decryptBackup(`Keep this.\r\n\r\n${block}\r\n-- \r\n`, ' Abacus  ZOOM tidal unpack sphere ', ACCOUNT)).toEqual(code);
      await expect(decryptBackup(block, 'abacus zoom tidal unpack spheres', ACCOUNT)).rejects.toThrow(BackupError);
      await expect(decryptBackup(block, passphrase, OTHER_ACCOUNT)).rejects.toThrow(BackupError);
    },
    60_000,
  );

  test(
    'a version 2 block names its account once opened; the account is nowhere in the block itself',
    async () => {
      const passphrase = 'abacus zoom tidal unpack sphere';
      const block = await encryptBackup(code, passphrase, ACCOUNT);
      const opened = await openBackup(block, passphrase);
      expect(opened).toEqual({ accountCode: code, accountId: ACCOUNT, version: 2 });
      const { payload } = backupPayload(block);
      expect(Buffer.from(payload).includes(Buffer.from(ACCOUNT))).toBe(false);
      await expect(openBackup(block, 'abacus zoom tidal unpack spheres')).rejects.toThrow(BackupError);
    },
    60_000,
  );

  test(
    'a version 1 block still opens with its account, and only with it',
    async () => {
      const passphrase = 'abacus zoom tidal unpack sphere';
      const v1 = await encryptBackup(code, passphrase, ACCOUNT, { version: 1 });
      expect(v1.split('\n')[1]).toMatch(/^v1\.[A-Za-z0-9_-]{80}$/);
      expect(backupPayload(v1).version).toBe(1);
      expect(await decryptBackup(v1, passphrase, ACCOUNT)).toEqual(code);
      expect(await openBackup(v1, passphrase, ACCOUNT)).toEqual({ accountCode: code, accountId: ACCOUNT, version: 1 });
      await expect(openBackup(v1, passphrase)).rejects.toThrow(/older recovery code block/);
      await expect(decryptBackup(v1, passphrase, OTHER_ACCOUNT)).rejects.toThrow(BackupError);
      // The layouts cannot be confused: a v1 payload relabelled as v2 is refused for its length.
      expect(() => backupPayload(v1.replace('\nv1.', '\nv2.'))).toThrow(/damaged/);
    },
    60_000,
  );

  test('the recovery kit is 26 base32 characters that round-trip', () => {
    const kit = recoveryKitCode(code);
    expect(kit.replace(/ /g, '')).toMatch(/^[A-Z2-7]{26}$/);
    expect(kit.split(' ').map((g) => g.length)).toEqual([4, 4, 4, 4, 4, 4, 2]);
    expect(parseRecoveryKitCode(kit.toLowerCase().replace(/ /g, '-'))).toEqual(code);
    for (let i = 0; i < 20; i++) {
      const c = crypto.getRandomValues(new Uint8Array(16));
      expect(parseRecoveryKitCode(recoveryKitCode(c))).toEqual(c);
    }
    expect(() => parseRecoveryKitCode(kit.slice(0, -1) + '7')).toThrow(/typo/);
    expect(() => parseRecoveryKitCode('AAAA')).toThrow(BackupError);
  });
});
