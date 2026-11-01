/**
 * HPKE (RFC 9180) as the alert vault uses it: base mode with
 * DHKEM(P-256, HKDF-SHA256) (KEM 0x0010), HKDF-SHA256 (KDF 0x0001), and
 * AES-128-GCM (AEAD 0x0001), the suite of RFC 9180 Appendix A.3, built on
 * WebCrypto through `@hpke/core`.
 */

import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '@hpke/core';
import { buf } from './bytes.js';

export const HPKE_SUITE = { kem: 0x0010, kdf: 0x0001, aead: 0x0001 } as const;

export function hpkeSuite(): CipherSuite {
  return new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
}

/** P-256 public key: DER SubjectPublicKeyInfo → uncompressed point (65 bytes). */
export async function rawPublicKeyFromSpki(spki: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('spki', buf(spki), { name: 'ECDH', namedCurve: 'P-256' }, true, []);
  return new Uint8Array(await crypto.subtle.exportKey('raw', k));
}

/** P-256 public key: uncompressed point → DER SubjectPublicKeyInfo. */
export async function spkiFromRawPublicKey(raw: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', buf(raw), { name: 'ECDH', namedCurve: 'P-256' }, true, []);
  return new Uint8Array(await crypto.subtle.exportKey('spki', k));
}

export interface Sealed {
  /** The encapsulated key (65 bytes). */
  enc: Uint8Array;
  ct: Uint8Array;
}

export async function seal(
  recipientPublicKey: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Promise<Sealed> {
  const suite = hpkeSuite();
  const pk = await suite.kem.deserializePublicKey(buf(recipientPublicKey));
  const { enc, ct } = await suite.seal({ recipientPublicKey: pk, info: buf(info) }, buf(plaintext), buf(aad));
  return { enc: new Uint8Array(enc), ct: new Uint8Array(ct) };
}

export async function open(
  recipientKey: CryptoKeyPair,
  info: Uint8Array,
  aad: Uint8Array,
  sealed: Sealed,
): Promise<Uint8Array> {
  const suite = hpkeSuite();
  const pt = await suite.open({ recipientKey, enc: buf(sealed.enc), info: buf(info) }, buf(sealed.ct), buf(aad));
  return new Uint8Array(pt);
}
