/**
 * The X.509 (RFC 5280) subset an attestation chain needs: a strict DER
 * reader, certificate fields, and path validation as AWS's attestation
 * process document prescribes (validity, basic constraints, key usage,
 * signatures up to a pinned root; no revocation). ECDSA over P-256 or P-384
 * only, verified with WebCrypto, so it runs in browsers.
 */

import { buf, equal } from './bytes.js';

interface Tlv {
  tag: number;
  /** The whole element: tag, length and value. */
  raw: Uint8Array;
  value: Uint8Array;
}

function readTlv(b: Uint8Array, at: number): { tlv: Tlv; next: number } {
  if (at + 2 > b.length) throw new Error('DER: truncated');
  const tag = b[at]!;
  if ((tag & 0x1f) === 0x1f) throw new Error('DER: multi-byte tags are not used here');
  let len = b[at + 1]!;
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 3) throw new Error('DER: bad length');
    if (at + 2 + n > b.length) throw new Error('DER: truncated');
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | b[at + 2 + i]!;
    if (len < 0x80 || (n > 1 && b[at + 2]! === 0)) throw new Error('DER: non-minimal length');
    hdr += n;
  }
  const end = at + hdr + len;
  if (end > b.length) throw new Error('DER: truncated');
  return { tlv: { tag, raw: b.subarray(at, end), value: b.subarray(at + hdr, end) }, next: end };
}

function children(t: Tlv): Tlv[] {
  if ((t.tag & 0x20) === 0) throw new Error('DER: not constructed');
  const out: Tlv[] = [];
  let at = 0;
  while (at < t.value.length) {
    const { tlv, next } = readTlv(t.value, at);
    out.push(tlv);
    at = next;
  }
  return out;
}

function single(b: Uint8Array): Tlv {
  const { tlv, next } = readTlv(b, 0);
  if (next !== b.length) throw new Error('DER: trailing bytes');
  return tlv;
}

function expect(t: Tlv | undefined, tag: number, what: string): Tlv {
  if (!t || t.tag !== tag) throw new Error(`X.509: expected ${what}`);
  return t;
}

const SEQUENCE = 0x30;
const OID = 0x06;
const BIT_STRING = 0x03;
const OCTET_STRING = 0x04;
const BOOLEAN = 0x01;
const INTEGER = 0x02;
const UTC_TIME = 0x17;
const GENERALIZED_TIME = 0x18;

function oid(t: Tlv): string {
  const v = expect(t, OID, 'OID').value;
  const parts: number[] = [];
  let n = 0;
  for (const x of v) {
    n = n * 128 + (x & 0x7f);
    if (!(x & 0x80)) {
      if (parts.length === 0) parts.push(n < 80 ? Math.floor(n / 40) : 2, n < 80 ? n % 40 : n - 80);
      else parts.push(n);
      n = 0;
    }
  }
  return parts.join('.');
}

function time(t: Tlv): Date {
  const s = new TextDecoder().decode(t.value);
  let m: RegExpMatchArray | null;
  if (t.tag === UTC_TIME && (m = s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/))) {
    const yy = Number(m[1]);
    return new Date(Date.UTC(yy < 50 ? 2000 + yy : 1900 + yy, +m[2]! - 1, +m[3]!, +m[4]!, +m[5]!, +m[6]!));
  }
  if (t.tag === GENERALIZED_TIME && (m = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/))) {
    return new Date(Date.UTC(+m[1]!, +m[2]! - 1, +m[3]!, +m[4]!, +m[5]!, +m[6]!));
  }
  throw new Error('X.509: bad time');
}

function bitString(t: Tlv): Uint8Array {
  const v = expect(t, BIT_STRING, 'BIT STRING').value;
  if (v.length === 0 || v[0]! > 7) throw new Error('X.509: bad BIT STRING');
  return v.subarray(1);
}

const OID_BASIC_CONSTRAINTS = '2.5.29.19';
const OID_KEY_USAGE = '2.5.29.15';
const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
const CURVES: Record<string, { name: 'P-256' | 'P-384'; size: number }> = {
  '1.2.840.10045.3.1.7': { name: 'P-256', size: 32 },
  '1.3.132.0.34': { name: 'P-384', size: 48 },
};
const SIG_HASHES: Record<string, 'SHA-256' | 'SHA-384'> = {
  '1.2.840.10045.4.3.2': 'SHA-256',
  '1.2.840.10045.4.3.3': 'SHA-384',
};

/** KeyUsage bit numbers (RFC 5280 §4.2.1.3). */
export const DIGITAL_SIGNATURE = 0;
export const KEY_CERT_SIGN = 5;

export interface Certificate {
  der: Uint8Array;
  tbs: Uint8Array;
  signatureAlgorithm: string;
  signature: Uint8Array;
  issuer: Uint8Array;
  subject: Uint8Array;
  notBefore: Date;
  notAfter: Date;
  /** The DER `SubjectPublicKeyInfo`. */
  spki: Uint8Array;
  curve: 'P-256' | 'P-384';
  basicConstraints?: { ca: boolean; pathLen?: number; critical: boolean };
  /** Set bits of the key usage extension, if present. */
  keyUsage?: Set<number>;
  /** OIDs of critical extensions this module does not interpret. */
  unknownCritical: string[];
}

export function parseCertificate(der: Uint8Array): Certificate {
  const [tbsT, algT, sigT, ...rest] = children(expect(single(der), SEQUENCE, 'Certificate'));
  if (rest.length) throw new Error('X.509: extra fields');
  const tbs = children(expect(tbsT, SEQUENCE, 'TBSCertificate'));
  let i = 0;
  if (tbs[i]?.tag === 0xa0) i++; // [0] version
  expect(tbs[i++], INTEGER, 'serialNumber');
  const innerAlg = oid(children(expect(tbs[i++], SEQUENCE, 'signature'))[0]!);
  const issuer = expect(tbs[i++], SEQUENCE, 'issuer').raw;
  const [nb, na] = children(expect(tbs[i++], SEQUENCE, 'validity'));
  const subject = expect(tbs[i++], SEQUENCE, 'subject').raw;
  const spkiT = expect(tbs[i++], SEQUENCE, 'subjectPublicKeyInfo');
  const [spkiAlg] = children(spkiT);
  const [keyAlg, curveOid] = children(expect(spkiAlg, SEQUENCE, 'AlgorithmIdentifier'));
  if (oid(keyAlg!) !== OID_EC_PUBLIC_KEY) throw new Error('X.509: not an EC key');
  const curve = CURVES[oid(curveOid!)];
  if (!curve) throw new Error('X.509: unsupported curve');

  const cert: Certificate = {
    der,
    tbs: tbsT!.raw,
    signatureAlgorithm: oid(children(expect(algT, SEQUENCE, 'signatureAlgorithm'))[0]!),
    signature: bitString(sigT!),
    issuer,
    subject,
    notBefore: time(nb!),
    notAfter: time(na!),
    spki: spkiT.raw,
    curve: curve.name,
    unknownCritical: [],
  };
  if (cert.signatureAlgorithm !== innerAlg) throw new Error('X.509: signature algorithms differ');
  while (i < tbs.length && tbs[i]!.tag !== 0xa3) i++; // skip [1], [2] unique ids
  if (i < tbs.length) {
    for (const ext of children(expect(children(tbs[i]!)[0], SEQUENCE, 'Extensions'))) {
      const f = children(ext);
      const id = oid(f[0]!);
      let critical = false;
      let k = 1;
      if (f[k]?.tag === BOOLEAN) critical = f[k++]!.value[0] === 0xff;
      const value = expect(f[k], OCTET_STRING, 'extnValue').value;
      if (id === OID_BASIC_CONSTRAINTS) {
        const bc = children(expect(single(value), SEQUENCE, 'BasicConstraints'));
        let j = 0;
        let ca = false;
        if (bc[j]?.tag === BOOLEAN) ca = bc[j++]!.value[0] === 0xff;
        let pathLen: number | undefined;
        if (bc[j]?.tag === INTEGER) pathLen = bc[j]!.value.reduce((n, x) => n * 256 + x, 0);
        cert.basicConstraints = { ca, ...(pathLen === undefined ? {} : { pathLen }), critical };
      } else if (id === OID_KEY_USAGE) {
        const bits = bitString(single(value));
        const set = new Set<number>();
        bits.forEach((byte, n) => {
          for (let b = 0; b < 8; b++) if (byte & (0x80 >> b)) set.add(n * 8 + b);
        });
        cert.keyUsage = set;
      } else if (critical) {
        cert.unknownCritical.push(id);
      }
    }
  }
  return cert;
}

/** ECDSA-Sig-Value (DER) to the fixed-width `r || s` WebCrypto verifies. */
function rawSignature(der: Uint8Array, size: number): Uint8Array {
  const [r, s] = children(expect(single(der), SEQUENCE, 'ECDSA-Sig-Value')).map((t) => {
    let v = expect(t, INTEGER, 'INTEGER').value;
    while (v.length > size && v[0] === 0) v = v.subarray(1);
    if (v.length > size) throw new Error('X.509: signature integer too large');
    const out = new Uint8Array(size);
    out.set(v, size - v.length);
    return out;
  });
  const out = new Uint8Array(2 * size);
  out.set(r!);
  out.set(s!, size);
  return out;
}

export async function importEcdsaKey(spki: Uint8Array, curve: 'P-256' | 'P-384'): Promise<CryptoKey> {
  return crypto.subtle.importKey('spki', buf(spki), { name: 'ECDSA', namedCurve: curve }, false, ['verify']);
}

async function signedBy(cert: Certificate, issuer: Certificate): Promise<boolean> {
  const hash = SIG_HASHES[cert.signatureAlgorithm];
  if (!hash) return false;
  const size = issuer.curve === 'P-256' ? 32 : 48;
  let sig: Uint8Array;
  try {
    sig = rawSignature(cert.signature, size);
  } catch {
    return false;
  }
  const key = await importEcdsaKey(issuer.spki, issuer.curve);
  return crypto.subtle.verify({ name: 'ECDSA', hash }, key, buf(sig), buf(cert.tbs));
}

/**
 * Validates `[target, ...cabundle reversed]` up to a pinned root, as AWS's
 * attestation process document (§3.2.3) prescribes: `cabundle[0]` must be
 * byte-identical to a trusted root; every certificate within its validity
 * at `now`; each signed by the next and the root by itself; issuer and
 * subject names chained; every CA certificate with a critical
 * `cA = TRUE` basic constraints extension, `keyCertSign`, and a path length
 * that admits the certificates below it; the target with
 * `digitalSignature` and not a CA; no unrecognized critical extension.
 * Returns the parsed target certificate.
 */
export async function validateChain(
  targetDer: Uint8Array,
  cabundle: Uint8Array[],
  trustedRoots: Uint8Array[],
  now: Date,
): Promise<Certificate> {
  if (cabundle.length === 0) throw new Error('attestation: empty CA bundle');
  if (!trustedRoots.some((r) => equal(r, cabundle[0]!))) throw new Error('attestation: untrusted root');
  const chain = [targetDer, ...[...cabundle].reverse()].map(parseCertificate);
  for (const [i, c] of chain.entries()) {
    if (now < c.notBefore || now > c.notAfter) throw new Error(`attestation: certificate ${i} outside its validity`);
    if (c.unknownCritical.length) throw new Error(`attestation: unknown critical extension in certificate ${i}`);
    const issuer = chain[Math.min(i + 1, chain.length - 1)]!;
    if (!equal(c.issuer, issuer.subject)) throw new Error(`attestation: certificate ${i} issuer mismatch`);
    if (!(await signedBy(c, issuer))) throw new Error(`attestation: certificate ${i} signature invalid`);
    if (i === 0) {
      if (c.basicConstraints?.ca) throw new Error('attestation: target certificate is a CA');
      if (!c.keyUsage?.has(DIGITAL_SIGNATURE)) throw new Error('attestation: target lacks digitalSignature');
    } else {
      const bc = c.basicConstraints;
      if (!bc?.ca || !bc.critical) throw new Error(`attestation: certificate ${i} is not a CA`);
      if (!c.keyUsage?.has(KEY_CERT_SIGN)) throw new Error(`attestation: certificate ${i} lacks keyCertSign`);
      if (bc.pathLen !== undefined && i - 1 > bc.pathLen) {
        throw new Error(`attestation: certificate ${i} path length exceeded`);
      }
    }
  }
  return chain[0]!;
}
