/**
 * Where the wallet gets the RSA modulus that signed an email
 * (`docs/email-recovery/spec.md` §7.7):
 *
 * 1. The key list: one static file on the wallet's origin listing every
 *    launch-provider key the DKIM key registry knows, the same file for
 *    every user, so fetching it says nothing about which provider a user
 *    has. A modulus from the list is used only after the chain confirms it
 *    (its leaf is in the guardian's pin or under a root the registry
 *    accepts), so whoever serves the file cannot substitute a key.
 * 2. DNS, through a DNS-over-HTTPS resolver's JSON API, only for a key the
 *    list does not have, and only after the user is told the resolver will
 *    learn which provider they use.
 *
 * This module parses both; fetching is the wallet's.
 */

import { initHashes, keyHash } from './recoveryInputs.js';

export class DkimKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DkimKeyError';
  }
}

/** A DER element: tag, content, and where the next element starts. */
function der(b: Uint8Array, at: number): { tag: number; start: number; end: number } {
  const tag = b[at];
  let len = b[at + 1];
  if (tag === undefined || len === undefined) throw new DkimKeyError('truncated DER');
  let start = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 3) throw new DkimKeyError('unsupported DER length');
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | b[start + i]!;
    start += n;
  }
  if (start + len > b.length) throw new DkimKeyError('truncated DER');
  return { tag, start, end: start + len };
}

function integer(b: Uint8Array, at: number): { value: bigint; end: number } {
  const e = der(b, at);
  if (e.tag !== 0x02) throw new DkimKeyError('expected a DER INTEGER');
  let v = 0n;
  for (let i = e.start; i < e.end; i++) v = (v << 8n) | BigInt(b[i]!);
  return { value: v, end: e.end };
}

/**
 * The RSA public key in a DKIM `p=` value: a DER `RSAPublicKey` (RFC 6376
 * §3.6.1's text) or a DER `SubjectPublicKeyInfo` wrapping one (what the RFC's
 * own example procedure produces, RFC 6376 erratum 6674).
 */
export function rsaPublicKeyFromDer(b: Uint8Array): { modulus: bigint; exponent: bigint } {
  const outer = der(b, 0);
  if (outer.tag !== 0x30) throw new DkimKeyError('expected a DER SEQUENCE');
  const first = der(b, outer.start);
  let body = outer.start;
  if (first.tag === 0x30) {
    // SubjectPublicKeyInfo: AlgorithmIdentifier, then BIT STRING (unused bits 0) around RSAPublicKey.
    const bits = der(b, first.end);
    if (bits.tag !== 0x03 || b[bits.start] !== 0) throw new DkimKeyError('expected a BIT STRING');
    const inner = der(b, bits.start + 1);
    if (inner.tag !== 0x30) throw new DkimKeyError('expected an RSAPublicKey');
    body = inner.start;
  }
  const n = integer(b, body);
  const e = integer(b, n.end);
  return { modulus: n.value, exponent: e.value };
}

/**
 * The RSA-2048 key a DKIM key record (RFC 6376 §3.6.1) publishes, from its
 * TXT strings concatenated (§3.6.2.2). Refuses a revoked key (empty `p=`),
 * a non-RSA key, and any key the circuit cannot use (not 2048 bits, or an
 * exponent other than 65537).
 */
export function parseDkimKeyRecord(txt: string): bigint {
  const tags = new Map<string, string>();
  for (const spec of txt.split(';')) {
    if (!spec.trim()) continue;
    const eq = spec.indexOf('=');
    if (eq < 0) throw new DkimKeyError('malformed DKIM key record');
    const name = spec.slice(0, eq).trim();
    if (tags.has(name)) throw new DkimKeyError(`duplicate ${name}= tag`);
    tags.set(name, spec.slice(eq + 1).replace(/\s+/g, ''));
  }
  if (tags.has('v') && tags.get('v') !== 'DKIM1') throw new DkimKeyError('not a DKIM1 key record');
  if ((tags.get('k') ?? 'rsa') !== 'rsa') throw new DkimKeyError('not an RSA key');
  const p = tags.get('p');
  if (p === undefined) throw new DkimKeyError('the record has no p= tag');
  if (p === '') throw new DkimKeyError('the provider has revoked this key (empty p=)');
  const raw = Uint8Array.from(atob(p), (c) => c.charCodeAt(0));
  const { modulus, exponent } = rsaPublicKeyFromDer(raw);
  if (exponent !== 65537n) throw new DkimKeyError('the key’s exponent is not 65537');
  if (modulus >> 2047n !== 1n) throw new DkimKeyError('the key is not RSA-2048');
  return modulus;
}

/**
 * The TXT records in a DNS-over-HTTPS JSON answer (the `application/dns-json`
 * format Cloudflare and Google publish): each answer of type 16, its quoted
 * character-strings concatenated.
 */
export function dohTxtRecords(answer: unknown): string[] {
  const a = answer as { Status?: number; Answer?: { type?: number; data?: string }[] };
  if (a.Status !== 0) return [];
  return (a.Answer ?? [])
    .filter((x) => x.type === 16 && typeof x.data === 'string')
    .map((x) => {
      const strings = [...x.data!.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]!.replace(/\\(.)/g, '$1'));
      return strings.length ? strings.join('') : x.data!;
    });
}

/** One key of the list. */
export interface KeyListEntry {
  /** The `d=` the key signs for, lowercase. */
  domain: string;
  /** Selectors the registry's attesters saw it published under. */
  selectors: string[];
  /** The 2048-bit modulus, `0x`-prefixed hex. */
  modulus: string;
  /** `key_hash` (spec §7.1), `0x`-prefixed hex. */
  keyHash: string;
  /** `active`: a leaf of the registry's current tree; `pending`: an addition waiting for its timelock. */
  status: 'active' | 'pending';
}

export interface KeyList {
  version: 1;
  /** The network passphrase and registry contract the list was read from. */
  network: string;
  registry: string;
  /** The ledger the registry state was read at. */
  ledger: number;
  keys: KeyListEntry[];
}

/** A key list, checked: every `keyHash` is recomputed from its modulus. */
export async function parseKeyList(json: unknown): Promise<KeyList> {
  await initHashes();
  const l = json as KeyList;
  if (l?.version !== 1 || !Array.isArray(l.keys) || typeof l.registry !== 'string' || typeof l.network !== 'string') {
    throw new DkimKeyError('not a version 1 key list');
  }
  for (const k of l.keys) {
    if (!/^[a-z0-9.-]{1,62}$/.test(k.domain) || !/^0x[0-9a-f]+$/.test(k.modulus) || !Array.isArray(k.selectors)) {
      throw new DkimKeyError('a key list entry is malformed');
    }
    if (`0x${keyHash(BigInt(k.modulus)).toString(16).padStart(64, '0')}` !== k.keyHash) {
      throw new DkimKeyError(`the key list's hash for a ${k.domain} key is not its modulus's`);
    }
  }
  return l;
}

/** The list's keys for `domain`, those published under `selector` first. */
export function keyCandidates(list: KeyList, domain: string, selector?: string): KeyListEntry[] {
  const mine = list.keys.filter((k) => k.domain === domain.toLowerCase());
  return [...mine.filter((k) => selector && k.selectors.includes(selector)), ...mine.filter((k) => !selector || !k.selectors.includes(selector))];
}
