import { createPublicKey, verify } from 'node:crypto';
import { AuthenticatorMock } from '@nidohq/email-mocks';
import { describe, expect, it } from 'vitest';
import { deriveAlertCodeKey } from '../src/alertCode.js';
import { sha256 } from '../src/bytes.js';
import {
  PURPOSE_PRODUCT_UPDATES,
  PURPOSE_SECURITY_ALERTS,
  type SealedRequest,
  authorizationChallenge,
  checkChannels,
  confirmationRequest,
  contactRequest,
  decodeContactRequest,
  decodeSealedRequest,
  encodeContactRequest,
  encodeSealedRequest,
  openRequest,
  prepareContactChange,
  rawLowS,
  removalRequest,
} from '../src/enrollment.js';
import { hpkeSuite } from '../src/hpke.js';
import { strkeyFromContractId } from '../src/strkey.js';

const account = strkeyFromContractId(new Uint8Array(32).fill(0xa1));
const accountCode = Uint8Array.from({ length: 16 }, (_, i) => i);
const push = {
  endpoint: 'https://push.example/abc',
  expirationTime: null,
  keys: {
    p256dh: Buffer.concat([Buffer.of(4), Buffer.alloc(64, 7)]).toString('base64url'),
    auth: Buffer.alloc(16, 3).toString('base64url'),
  },
};
const base = {
  account,
  address: 'Test.User+tag@proton.me',
  accountCode,
  emailGuardian: true,
  push,
  purposes: PURPOSE_SECURITY_ALERTS,
  consentVersion: 1,
};

async function vault() {
  const suite = hpkeSuite();
  const kp = await suite.kem.generateKeyPair();
  return {
    kp,
    key: {
      publicKey: new Uint8Array(await suite.kem.serializePublicKey(kp.publicKey)),
      vapid: new Uint8Array(65),
      measurement: '',
    },
  };
}

describe('alert contact requests', () => {
  it('needs Web Push whenever the account has an email guardian (spec §9.3 rule 2)', async () => {
    expect(() => checkChannels({ emailGuardian: true })).toThrow(/Web Push/);
    expect(() => checkChannels({ emailGuardian: false })).not.toThrow();
    const { push: _, ...noPush } = base;
    await expect(contactRequest(noPush)).rejects.toThrow(/Web Push/);
    await expect(contactRequest({ ...noPush, emailGuardian: false })).resolves.toBeTruthy();
  });

  it('carries k_code, never account_code, and round-trips through CBOR and HPKE', async () => {
    const r = await contactRequest(base);
    expect(r.op).toBe('register');
    if (r.op !== 'register') throw new Error();
    expect(r.kCode).toEqual(await deriveAlertCodeKey(accountCode));
    expect(Buffer.from(encodeSealedRequest(r)).includes(Buffer.from(accountCode))).toBe(false);
    expect(decodeSealedRequest(encodeSealedRequest(r))).toEqual(r);
    const v = await vault();
    const prepared = await prepareContactChange(v.key, r, new Uint8Array(32).fill(9));
    const auth = new AuthenticatorMock('nido.test', 'https://nido.test');
    const a = auth.assert(prepared.challenge);
    const req = prepared.finish({ publicKey: auth.publicKey, ...a });
    expect(await openRequest(v.kp, req.envelope)).toEqual(r);
    expect(decodeContactRequest(encodeContactRequest(req))).toEqual(req);
    expect(encodeContactRequest(req)).not.toContain('proton');
  });

  it('round-trips replacement, removal, and confirmation requests', async () => {
    const old = new Uint8Array(16).fill(1);
    const reqs: SealedRequest[] = [
      await contactRequest({ ...base, purposes: PURPOSE_SECURITY_ALERTS | PURPOSE_PRODUCT_UPDATES }, old),
      removalRequest(account, old),
      confirmationRequest(account, old, '012345'),
    ];
    for (const r of reqs) expect(decodeSealedRequest(encodeSealedRequest(r))).toEqual(r);
    expect(reqs[0]!.op).toBe('replace');
  });

  it('refuses bad inputs', async () => {
    await expect(contactRequest({ ...base, address: 'no-at-sign' })).rejects.toThrow();
    await expect(contactRequest({ ...base, purposes: PURPOSE_PRODUCT_UPDATES })).rejects.toThrow(/purposes/);
    await expect(contactRequest({ ...base, consentVersion: 0 })).rejects.toThrow(/consent/);
    await expect(contactRequest({ ...base, push: { ...push, endpoint: 'http://push.example/x' } })).rejects.toThrow(/https/);
    await expect(
      contactRequest({ ...base, push: { ...push, endpoint: 'http://127.0.0.1:9/x' }, allowLoopbackPush: true }),
    ).resolves.toBeTruthy();
    expect(() => confirmationRequest(account, new Uint8Array(16), '12345')).toThrow();
    expect(() => decodeSealedRequest(encodeSealedRequest(removalRequest(account, new Uint8Array(16))).slice(0, -1))).toThrow();
  });

  it('binds every authorized field into the challenge', async () => {
    const c = {
      op: 'register' as const,
      account: new Uint8Array(32).fill(1),
      contact: new Uint8Array(16).fill(2),
      envelope: Uint8Array.of(1, 2, 3),
      purposes: 1,
      consentVersion: 4,
      nonce: new Uint8Array(32).fill(5),
    };
    const ref = Buffer.from(await authorizationChallenge(c)).toString('hex');
    const variants = [
      { ...c, op: 'replace' as const },
      { ...c, account: new Uint8Array(32).fill(9) },
      { ...c, contact: new Uint8Array(16).fill(9) },
      { ...c, envelope: Uint8Array.of(1, 2, 4) },
      { ...c, purposes: 3 },
      { ...c, consentVersion: 5 },
      { ...c, nonce: new Uint8Array(32).fill(9) },
    ];
    const seen = new Set([ref]);
    for (const v of variants) seen.add(Buffer.from(await authorizationChallenge(v)).toString('hex'));
    expect(seen.size).toBe(variants.length + 1);
  });

  it('normalizes the authenticator signature to low-S r || s that still verifies', async () => {
    const auth = new AuthenticatorMock('nido.test', 'https://nido.test');
    const pub = createPublicKey({
      key: {
        kty: 'EC',
        crv: 'P-256',
        x: Buffer.from(auth.publicKey.subarray(1, 33)).toString('base64url'),
        y: Buffer.from(auth.publicKey.subarray(33)).toString('base64url'),
      },
      format: 'jwk',
    });
    const half = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n / 2n;
    for (let i = 0; i < 16; i++) {
      const a = auth.assert(Uint8Array.of(i));
      const raw = rawLowS(a.signature);
      expect(BigInt('0x' + Buffer.from(raw.subarray(32)).toString('hex')) <= half).toBe(true);
      const signed = Buffer.concat([a.authenticatorData, await sha256(a.clientDataJSON)]);
      expect(verify('sha256', signed, { key: pub, dsaEncoding: 'ieee-p1363' }, raw)).toBe(true);
    }
  });
});
