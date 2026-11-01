/**
 * The committed TEST-ONLY signing keys (keys/, written by
 * scripts/generate-test-keys.sh). None of them is, or derives from, a real
 * provider key; they exist only so fixtures verify against the mock DNS.
 */
import { createPrivateKey, createPublicKey, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export type KeyName =
  | 'gmail'
  | 'gmail-previous'
  | 'google-1e100'
  | 'outlook'
  | 'icloud'
  | 'icloud-me'
  | 'yahoo'
  | 'proton'
  | 'protonmail'
  | 'fastmail'
  | 'messagingengine'
  | 'gmx'
  | 'webde'
  | 'gappssmtp'
  | 'onmicrosoft'
  | 'attacker'
  | 'weak';

export interface TestKey {
  name: KeyName;
  /** Path of the PEM relative to the package root. */
  file: string;
  bits: number;
  privateKey: KeyObject;
  publicKey: KeyObject;
  /** The modulus N, for building out-of-range signatures. */
  modulus: bigint;
}

const cache = new Map<KeyName, TestKey>();

export function testKey(name: KeyName): TestKey {
  const hit = cache.get(name);
  if (hit) return hit;
  const bits = name === 'weak' ? 1024 : 2048;
  const file = `keys/TEST-ONLY-${name}-rsa${bits}.pem`;
  const pem = readFileSync(fileURLToPath(new URL(`../${file}`, import.meta.url)));
  const privateKey = createPrivateKey(pem);
  const publicKey = createPublicKey(privateKey);
  const jwk = publicKey.export({ format: 'jwk' });
  const modulus = BigInt(`0x${Buffer.from(jwk.n!, 'base64url').toString('hex')}`);
  const key: TestKey = { name, file, bits, privateKey, publicKey, modulus };
  cache.set(name, key);
  return key;
}

/** The base64 SubjectPublicKeyInfo that goes in a key record's `p=`. */
export function publicKeyBase64(key: TestKey): string {
  return key.publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
}
