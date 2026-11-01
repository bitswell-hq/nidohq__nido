import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from '../src/bytes.js';
import { HPKE_SUITE, hpkeSuite, open, rawPublicKeyFromSpki, seal, spkiFromRawPublicKey } from '../src/hpke.js';

/** RFC 9180 Appendix A.3.1: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode. */
const A31 = {
  info: '4f6465206f6e2061204772656369616e2055726e',
  ikmE: '4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e',
  ikmR: '668b37171f1072f3cf12ea8a236a45df23fc13b82af3609ad1e354f6ef817550',
  pkRm:
    '04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0',
  enc: '04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4',
  pt: '4265617574792069732074727574682c20747275746820626561757479',
  aad0: '436f756e742d30',
  ct0: '5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434',
};

describe('HPKE suite (RFC 9180)', () => {
  it('is KEM 0x0010, KDF 0x0001, AEAD 0x0001', () => {
    expect(HPKE_SUITE).toEqual({ kem: 0x10, kdf: 1, aead: 1 });
  });

  it('reproduces RFC 9180 A.3.1 (keys, enc, first ciphertext)', async () => {
    const suite = hpkeSuite();
    const recipient = await suite.kem.deriveKeyPair(fromHex(A31.ikmR));
    expect(toHex(new Uint8Array(await suite.kem.serializePublicKey(recipient.publicKey)))).toBe(A31.pkRm);
    const sender = await suite.createSenderContext({
      recipientPublicKey: recipient.publicKey,
      info: fromHex(A31.info),
      ekm: fromHex(A31.ikmE),
    });
    expect(toHex(new Uint8Array(sender.enc))).toBe(A31.enc);
    expect(toHex(new Uint8Array(await sender.seal(fromHex(A31.pt), fromHex(A31.aad0))))).toBe(A31.ct0);
    const opened = await open(recipient, fromHex(A31.info), fromHex(A31.aad0), { enc: fromHex(A31.enc), ct: fromHex(A31.ct0) });
    expect(toHex(opened)).toBe(A31.pt);
  });

  it('round-trips and refuses a wrong info, aad, or ciphertext', async () => {
    const suite = hpkeSuite();
    const kp = await suite.kem.generateKeyPair();
    const pk = new Uint8Array(await suite.kem.serializePublicKey(kp.publicKey));
    const info = new TextEncoder().encode('info');
    const aad = Uint8Array.of(1, 2);
    const sealed = await seal(pk, info, aad, Uint8Array.of(9, 9, 9));
    expect(Array.from(await open(kp, info, aad, sealed))).toEqual([9, 9, 9]);
    await expect(open(kp, new TextEncoder().encode('other'), aad, sealed)).rejects.toThrow();
    await expect(open(kp, info, Uint8Array.of(1), sealed)).rejects.toThrow();
    const ct = sealed.ct.slice();
    ct[0]! ^= 1;
    await expect(open(kp, info, aad, { enc: sealed.enc, ct })).rejects.toThrow();
  });

  it('converts P-256 keys between SPKI and uncompressed points', async () => {
    const pk = fromHex(A31.pkRm);
    const spki = await spkiFromRawPublicKey(pk);
    expect(spki.length).toBe(91);
    expect(toHex(await rawPublicKeyFromSpki(spki))).toBe(A31.pkRm);
  });
});
