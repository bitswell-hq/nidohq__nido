import { createPrivateKey, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  type NitroChain,
  NitroHypervisorMock,
  imageMeasurement,
  nitroTestRoot,
  rogueTestRoot,
  testImage,
  verifyAttestationNode,
} from '@nidohq/email-mocks';
import { decode, encode } from 'cborg';
import { describe, expect, it } from 'vitest';
import { enclaveMeasurement, verifyAttestation } from '../src/attestation.js';
import { toHex } from '../src/bytes.js';

const image = testImage('vault-v1');
const measurement = toHex(imageMeasurement(image));
const nonce = new Uint8Array(32).fill(5);
const publicKey = new Uint8Array(91).fill(1);
const roots = [nitroTestRoot()];
const opts = { roots, allowedMeasurements: [measurement], nonce };

function attest(over: { chain?: NitroChain; debug?: boolean; clock?: () => number } = {}) {
  const hv = new NitroHypervisorMock({ chain: over.chain ?? 'nitro', clock: over.clock ?? Date.now });
  return hv.launch(image, { debug: over.debug ?? false }).attest({ publicKey, nonce, userData: Uint8Array.of(1) });
}

const leafKey = createPrivateKey(
  readFileSync(fileURLToPath(new URL('../../email-mocks/keys/nitro/TEST-ONLY-nitro-enclave.key.pem', import.meta.url)), 'utf8'),
);

/** Re-sign a document whose payload `edit` changed, so only the edit can fail it. */
function resigned(edit: (doc: Map<string, unknown>) => void, protectedHeader = encode(new Map([[1, -35]]))): Uint8Array {
  const tags: { [n: number]: (d: () => unknown) => unknown } = [];
  tags[18] = (d) => d();
  const [, , payload] = decode(attest(), { useMaps: true, tags }) as [Uint8Array, unknown, Uint8Array];
  const doc = decode(payload, { useMaps: true }) as Map<string, unknown>;
  edit(doc);
  const p = encode(doc, { mapSorter: () => 0 });
  const sig = sign('sha384', encode(['Signature1', protectedHeader, new Uint8Array(0), p]), { key: leafKey, dsaEncoding: 'ieee-p1363' });
  return encode([protectedHeader, new Map(), p, new Uint8Array(sig)]);
}

describe('Nitro attestation verification', () => {
  it('accepts a fresh document from an allowed image, tagged or untagged', async () => {
    const doc = attest();
    expect(doc[0]).toBe(0xd2);
    const v = await verifyAttestation(doc, opts);
    expect(v.measurement).toBe(measurement);
    expect(v.measurement).toBe(toHex(await enclaveMeasurement(v.document.pcrs)));
    expect(v.publicKey).toEqual(publicKey);
    expect(v.document.pcrs.size).toBe(16);
    expect(v.document.cabundle).toHaveLength(3);
    // As the NSM writes it: an absent optional field is null.
    const plain = new NitroHypervisorMock().launch(image).attest({ publicKey, nonce });
    expect((await verifyAttestation(plain, opts)).userData).toEqual(new Uint8Array(0));
    await expect(verifyAttestation(doc.subarray(1), opts)).resolves.toBeTruthy();
    expect(Buffer.from(verifyAttestationNode(doc, { roots, nonce, now: Date.now() }).measurement).toString('hex')).toBe(measurement);
  });

  const refusals: [string, () => Uint8Array | Promise<Uint8Array>, RegExp, Partial<typeof opts & { now: Date }>?][] = [
    ['a chain to another root', () => attest({ chain: 'rogue' }), /untrusted root/],
    ['an expired enclave certificate', () => attest({ chain: 'expired-enclave' }), /outside its validity/],
    ['an enclave certificate without digitalSignature', () => attest({ chain: 'enclave-without-digital-signature' }), /digitalSignature/],
    ['any certificate after its notAfter', () => attest(), /outside its validity/, { now: new Date('2127-01-01') }],
    ['a different nonce', () => attest(), /nonce/, { nonce: new Uint8Array(32).fill(6) }],
    ['a stale timestamp', () => attest({ clock: () => Date.now() - 10 * 60_000 }), /stale/],
    ['a timestamp from the future', () => attest({ clock: () => Date.now() + 10 * 60_000 }), /stale/],
    ['a debug-mode enclave', () => attest({ debug: true }), /debug-mode/],
    ['an image not on the allowlist', () => attest(), /measurement not allowed/, { allowedMeasurements: ['00'.repeat(32)] }],
    ['a flipped payload byte', () => {
      const d = attest();
      d[200]! ^= 1;
      return d;
    }, /attestation|CBOR|signature|Unexpected|unsupported|DER|X\.509/],
    ['a flipped signature byte', () => {
      const d = attest();
      d[d.length - 1]! ^= 1;
      return d;
    }, /COSE signature invalid/],
    ['a payload signed by another key', () => {
      const tags: { [n: number]: (d: () => unknown) => unknown } = [];
      tags[18] = (d) => d();
      const [p, u, , s] = decode(attest(), { useMaps: true, tags }) as unknown[];
      const [, , other] = decode(attest({ chain: 'rogue' }), { useMaps: true, tags }) as unknown[];
      return encode([p, u, other, s]);
    }, /COSE signature invalid|untrusted root/],
    ['a protected header other than ES384', () => resigned(() => {}, encode(new Map([[1, -7]]))), /ES384/],
    ['a digest other than SHA384', () => resigned((d) => d.set('digest', 'SHA256')), /digest/],
    ['an empty module id', () => resigned((d) => d.set('module_id', '')), /module_id/],
    ['a 47-byte PCR', () => resigned((d) => (d.get('pcrs') as Map<number, Uint8Array>).set(5, new Uint8Array(47))), /PCR value/],
    ['a PCR index of 32', () => resigned((d) => (d.get('pcrs') as Map<number, Uint8Array>).set(32, new Uint8Array(48))), /PCR index/],
    ['an unknown field', () => resigned((d) => d.set('extra', 1)), /unexpected field/],
    ['user_data over 512 bytes', () => resigned((d) => d.set('user_data', new Uint8Array(513))), /user_data/],
    ['no public key', () => resigned((d) => d.delete('public_key')), /no public key/],
    ['a null public key', () => resigned((d) => d.set('public_key', null)), /no public key/],
    ['a null mandatory field', () => resigned((d) => d.set('certificate', null)), /null certificate/],
    ['an empty CA bundle', () => resigned((d) => d.set('cabundle', [])), /cabundle/],
    ['a CA bundle in the wrong order', () => resigned((d) => d.set('cabundle', [...(d.get('cabundle') as Uint8Array[])].reverse())), /untrusted root/],
    ['a missing intermediate', () => resigned((d) => d.set('cabundle', (d.get('cabundle') as Uint8Array[]).slice(0, 2))), /issuer mismatch/],
  ];

  for (const [what, make, why, extra] of refusals) {
    it(`refuses ${what}`, async () => {
      await expect(verifyAttestation(await make(), { ...opts, ...extra })).rejects.toThrow(why);
    });
  }

  it('the independent verifier refuses the same chain, freshness, and debug cases', () => {
    const now = Date.now();
    expect(() => verifyAttestationNode(attest({ chain: 'rogue' }), { roots, nonce, now })).toThrow(/untrusted root/);
    expect(() => verifyAttestationNode(attest({ chain: 'expired-enclave' }), { roots, nonce, now })).toThrow(/expired/);
    expect(() => verifyAttestationNode(attest({ debug: true }), { roots, nonce, now })).toThrow(/debug/);
    expect(() => verifyAttestationNode(attest(), { roots: [rogueTestRoot()], nonce, now })).toThrow(/untrusted root/);
    expect(() => verifyAttestationNode(attest(), { roots, nonce: new Uint8Array(32), now })).toThrow(/nonce/);
  });
});
