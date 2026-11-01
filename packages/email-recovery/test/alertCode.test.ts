import { createHash, createHmac, hkdfSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { alertCode, deriveAlertCodeKey, formatAlertCode, subjectBytes } from '../src/alertCode.js';

const accountCode = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
const networkId = new Uint8Array(createHash('sha256').update('Test SDF Network ; September 2015').digest());
const controller = new Uint8Array(32).fill(0xc1);
const account = new Uint8Array(32).fill(0xa1);

/** The spec §10.1 derivation, written again with node:crypto. */
function reference(subject: Buffer): string {
  const key = Buffer.from(hkdfSync('sha256', accountCode, Buffer.alloc(0), 'nido/email-recovery/v1/alert-code-key', 32));
  const mac = createHmac('sha256', key)
    .update('nido/email-recovery/v1/alert-code')
    .update(networkId)
    .update(controller)
    .update(account)
    .update(subject)
    .digest();
  return (mac.readBigUInt64BE(0) % 1_000_000n).toString().padStart(6, '0');
}

describe('alert code (spec §10.1)', () => {
  it('matches an independent computation for every subject kind', async () => {
    const key = await deriveAlertCodeKey(accountCode);
    const attempt = Buffer.alloc(9);
    attempt[0] = 1;
    attempt.writeBigUInt64BE(7n, 1);
    const epoch = Buffer.alloc(9);
    epoch[0] = 2;
    epoch.writeBigUInt64BE(3n, 1);
    const digest = new Uint8Array(32).fill(0xdd);
    const cases = [
      [{ kind: 'attempt', attemptId: 7n }, attempt],
      [{ kind: 'epoch', epoch: 3n }, epoch],
      [{ kind: 'change', digest }, Buffer.concat([Buffer.of(3), digest])],
    ] as const;
    for (const [subject, bytes] of cases) {
      expect(Buffer.from(subjectBytes(subject))).toEqual(bytes);
      expect(await alertCode({ key, networkId, controller, account, subject })).toBe(reference(bytes));
    }
  });

  it('is pinned for the vector in the spec', async () => {
    const key = await deriveAlertCodeKey(accountCode);
    expect(Buffer.from(key).toString('hex')).toMatchInlineSnapshot(`"a9045e1ee8c9fd6654033c8148a2569407441e29fefa90dc3ce38b35e03398e0"`);
    expect(await alertCode({ key, networkId, controller, account, subject: { kind: 'attempt', attemptId: 1n } })).toMatchInlineSnapshot(`"169328"`);
  });

  it('depends on the key, the network, the controller, the account, and the attempt', async () => {
    const key = await deriveAlertCodeKey(accountCode);
    const base = { key, networkId, controller, account, subject: { kind: 'attempt', attemptId: 1n } as const };
    const codes = new Set<string>([await alertCode(base)]);
    const flip = (b: Uint8Array) => Uint8Array.from(b, (x, i) => (i === 0 ? x ^ 1 : x));
    codes.add(await alertCode({ ...base, key: await deriveAlertCodeKey(flip(accountCode)) }));
    codes.add(await alertCode({ ...base, networkId: flip(networkId) }));
    codes.add(await alertCode({ ...base, controller: flip(controller) }));
    codes.add(await alertCode({ ...base, account: flip(account) }));
    codes.add(await alertCode({ ...base, subject: { kind: 'attempt', attemptId: 2n } }));
    codes.add(await alertCode({ ...base, subject: { kind: 'epoch', epoch: 1n } }));
    expect(codes.size).toBe(7);
  });

  it('is six digits, shown in two groups', async () => {
    const key = await deriveAlertCodeKey(accountCode);
    for (let i = 0n; i < 50n; i++) {
      const code = await alertCode({ key, networkId, controller, account, subject: { kind: 'attempt', attemptId: i } });
      expect(code).toMatch(/^\d{6}$/);
      expect(formatAlertCode(code)).toBe(`${code.slice(0, 3)} ${code.slice(3)}`);
    }
  });

  it('refuses malformed inputs', async () => {
    await expect(deriveAlertCodeKey(new Uint8Array(15))).rejects.toThrow();
    const key = await deriveAlertCodeKey(accountCode);
    await expect(
      alertCode({ key, networkId, controller, account: new Uint8Array(31), subject: { kind: 'attempt', attemptId: 1n } }),
    ).rejects.toThrow();
    expect(() => subjectBytes({ kind: 'attempt', attemptId: -1n })).toThrow();
    expect(() => subjectBytes({ kind: 'change', digest: new Uint8Array(31) })).toThrow();
  });
});
