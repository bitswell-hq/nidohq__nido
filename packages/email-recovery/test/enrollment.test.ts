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
  probeAckMessage,
  pushUpdateRequest,
  rawLowS,
  removalRequest,
  statusRequest,
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
const deviceKey = Uint8Array.from([4, ...Array(64).fill(5)]);
const base = {
  account,
  address: 'Test.User+tag@proton.me',
  accountCode,
  emailGuardian: true,
  push,
  deviceKey,
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

  it('round-trips push updates and status reads, which sign purposes and consent version 0', async () => {
    const id = new Uint8Array(16).fill(4);
    const update = pushUpdateRequest(account, id, push, deviceKey);
    expect(update.op === 'push' && update.push.deviceKey).toEqual(deviceKey);
    const status = statusRequest(account);
    for (const r of [update, status]) expect(decodeSealedRequest(encodeSealedRequest(r))).toEqual(r);
    expect(status.contact).toEqual(new Uint8Array(16));
    expect(() => pushUpdateRequest(account, id, { ...push, endpoint: 'http://push.example/x' }, deviceKey)).toThrow(/https/);
    expect(() => pushUpdateRequest(account, new Uint8Array(15), push, deviceKey)).toThrow(/16 octets/);
    expect(() => pushUpdateRequest(account, id, push, new Uint8Array(33))).toThrow(/device key/);
    // A status read names no contact.
    const named = encodeSealedRequest({ ...status, contact: id });
    expect(() => decodeSealedRequest(named)).toThrow(/names no contact/);
    const v = await vault();
    const nonce = new Uint8Array(32).fill(9);
    for (const r of [update, status] as Extract<SealedRequest, { op: 'push' | 'status' }>[]) {
      const prepared = await prepareContactChange(v.key, r, nonce);
      const req = prepared.finish({ publicKey: new Uint8Array(65), authenticatorData: new Uint8Array(37), clientDataJSON: new Uint8Array(1), signature: Uint8Array.of(0x30, 6, 2, 1, 1, 2, 1, 1) });
      expect(prepared.challenge).toEqual(
        await authorizationChallenge({ op: r.op, account: r.account, contact: r.contact, envelope: req.envelope, purposes: 0, consentVersion: 0, nonce }),
      );
      expect(decodeContactRequest(encodeContactRequest(req)).op).toBe(r.op);
    }
  });

  it('refuses bad inputs', async () => {
    await expect(contactRequest({ ...base, address: 'no-at-sign' })).rejects.toThrow();
    await expect(contactRequest({ ...base, purposes: PURPOSE_PRODUCT_UPDATES })).rejects.toThrow(/purposes/);
    await expect(contactRequest({ ...base, consentVersion: 0 })).rejects.toThrow(/consent/);
    await expect(contactRequest({ ...base, push: { ...push, endpoint: 'http://push.example/x' } })).rejects.toThrow(/https/);
    const { deviceKey: _, ...noDeviceKey } = base;
    await expect(contactRequest(noDeviceKey)).rejects.toThrow(/device key/);
    await expect(
      contactRequest({ ...base, push: { ...push, endpoint: 'http://127.0.0.1:9/x' }, allowLoopbackPush: true }),
    ).resolves.toBeTruthy();
    expect(() => confirmationRequest(account, new Uint8Array(16), '12345')).toThrow();
    expect(() => decodeSealedRequest(encodeSealedRequest(removalRequest(account, new Uint8Array(16))).slice(0, -1))).toThrow();
  });

  it('a probe acknowledgement signs the label and the 16-octet probe id', () => {
    const id = new Uint8Array(16).fill(0x7e);
    const m = probeAckMessage(id);
    expect(Buffer.from(m).toString('latin1')).toBe(`nido/email-recovery/v1/probe-ack${Buffer.from(id).toString('latin1')}`);
    expect(() => probeAckMessage(new Uint8Array(15))).toThrow(/16 octets/);
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
