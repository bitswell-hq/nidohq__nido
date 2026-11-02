// DKIM public keys from public sources: the live DNS key record
// (RFC 6376 section 3.6.2.2, `<selector>._domainkey.<domain>` TXT) and, for
// keys no longer published, zkEmail's public DKIM key archive
// (https://archive.zk.email, `GET /api/key?domain=<domain>`), which records
// each key record it observed with the dates it was seen.
//
// Every candidate key for a (domain, selector) is kept, because a selector
// can carry different keys over time; the reference verifier tries each and
// records which one verified.

import { createPublicKey } from 'node:crypto';
import { Resolver } from 'node:dns/promises';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { CACHE, politeGet, sha256hex } from './archive.mjs';

/** The tags of a key record (RFC 6376 section 3.6.1), whitespace removed. */
export function keyRecordTags(txt) {
  const tags = {};
  for (const spec of txt.split(';')) {
    const eq = spec.indexOf('=');
    if (eq > 0) tags[spec.slice(0, eq).trim()] = spec.slice(eq + 1).replace(/[ \t\r\n]+/g, '');
  }
  return tags;
}

/**
 * The RSA public key of a key record's `p=` (a DER SubjectPublicKeyInfo, or a
 * bare PKCS#1 RSAPublicKey as some records publish), or null for an empty
 * (revoked) or non-RSA record.
 */
export function rsaKey(p) {
  if (!p) return null;
  const der = Buffer.from(p, 'base64');
  for (const type of ['spki', 'pkcs1']) {
    try {
      const key = createPublicKey({ key: der, format: 'der', type });
      if (key.asymmetricKeyType !== 'rsa') return null;
      const jwk = key.export({ format: 'jwk' });
      const modulus = BigInt(`0x${Buffer.from(jwk.n, 'base64url').toString('hex')}`);
      const exponent = BigInt(`0x${Buffer.from(jwk.e, 'base64url').toString('hex')}`);
      return { key, modulus, exponent, bits: modulus.toString(2).length };
    } catch {
      // try the next encoding
    }
  }
  return null;
}

/** A short identifier of a key: the first 16 hex digits of SHA-256 over its `p=` octets. */
export const keyId = (p) => sha256hex(Buffer.from(p, 'base64')).slice(0, 16);

const resolver = new Resolver({ timeout: 5000, tries: 2 });

/** The TXT records at `<selector>._domainkey.<domain>` (CNAMEs followed by the resolver), or []. */
export async function dnsKeyRecords(domain, selector) {
  try {
    return (await resolver.resolveTxt(`${selector}._domainkey.${domain}`)).map((chunks) => chunks.join(''));
  } catch {
    return [];
  }
}

/**
 * Every record zkEmail's archive holds for `domain`, fetched at the same
 * polite pace as the mail archives and kept under target/ once fetched.
 */
export async function archiveKeyRecords(domain, opts = {}) {
  const file = join(CACHE, 'archive.zk.email', `${domain}.json`);
  if (existsSync(file)) return JSON.parse(readFileSync(file, 'utf8'));
  const bytes = await politeGet(`https://archive.zk.email/api/key?domain=${encodeURIComponent(domain)}`, opts);
  const records = bytes ? JSON.parse(Buffer.from(bytes).toString('utf8')) : [];
  mkdirSync(join(CACHE, 'archive.zk.email'), { recursive: true });
  writeFileSync(file, JSON.stringify(records));
  return records;
}
