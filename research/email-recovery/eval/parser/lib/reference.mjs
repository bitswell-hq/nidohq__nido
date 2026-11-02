// The reference side of the comparison, independent of the circuit and of
// @nidohq/email-recovery's encoder:
//
// - DKIM: mailauth 8.0.4 in its strict mode (RFC 6376 tag-list syntax,
//   required tags, v=, i=, q=, From signed) selects and canonicalizes the
//   signed header fields (RFC 6376 sections 3.4.2, 3.7, 5.4.2). The RSA
//   signature over those octets is checked with node:crypto against each
//   candidate key. mailauth checks the body hash before the signature and
//   reports no RSA verdict when it differs, and a list archive's copy often
//   has a changed body, so the header signature is checked here directly; the
//   body is not part of the recovery proof (spec section 4.4). Expiry (t=,
//   x=) is not a rejection either: spec section 4.4 does not bind them.
// - From: Python's standard-library RFC 5322 parser (lib/from_ref.py) reads
//   the From field the signature covers; its address is the one the
//   circuit's must equal. mailauth's own RFC 5322 From reader (the one its
//   DMARC check uses) gives a second reading, reported where it differs.
// - The spec's profile (sections 4.3, 4.5, 6.3): the rules the circuit is
//   specified to enforce on top of a valid signature, evaluated here from the
//   reference's own parse, so that every refusal by the circuit is either
//   explained by a stated rule or reported as a completeness gap.

import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { verify as rsaVerify } from 'node:crypto';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { dkimVerify } from 'mailauth/lib/dkim/verify.js';
import { parseFromHeader } from 'mailauth/lib/dmarc/author-domain.js';

import { rsaKey } from './keys.mjs';

export const HEADER_MAX = 1536;
export const DKIM_FIELD_MAX = 512;
export const DKIM_TAGS_MAX = 16;
export const ADDR_MAX = 124;
export const DOMAIN_MAX = 62;

/** mailauth's strict-mode reasons for ignoring a signature (RFC 6376 sections 3.2, 3.5, 6.1.1). */
const SIGNATURE_INVALID = new Set([
  'signature syntax error',
  'signature missing required tag',
  'incompatible version',
  'unsupported query method',
  'domain mismatch',
  'From field not signed',
  'unknown algorithm',
  'unknown canonicalization',
]);
/** Time-related reasons, not rejections here (spec section 4.4). */
const TIME_ONLY = new Set(['invalid expiration', 'expired']);

/** The tags of a DKIM-Signature field value (RFC 6376 section 3.2), unfolded, FWS around names and values removed. */
export function tagList(value) {
  const tags = [];
  for (const spec of value.replace(/\r\n(?=[ \t])/g, '').split(';')) {
    if (spec.trim() === '') continue;
    const eq = spec.indexOf('=');
    tags.push(eq === -1 ? { name: spec.trim(), value: null } : { name: spec.slice(0, eq).trim(), value: spec.slice(eq + 1).trim() });
  }
  return tags;
}

const noKey = async () => {
  const err = new Error('no key here; the RSA check is done separately');
  err.code = 'ENOTFOUND';
  throw err;
};

/**
 * Every DKIM-Signature field of `eml` (CRLF octets) as the reference reads
 * it, top-most first: its raw tags, mailauth's strict-mode verdict on its
 * syntax, the exact octets it signs, the raw From and Subject fields among
 * them, and its signature value.
 */
export async function referenceSignatures(eml) {
  const text = Buffer.from(eml).toString('latin1');
  const head = text.slice(0, text.indexOf('\r\n\r\n') === -1 ? text.length : text.indexOf('\r\n\r\n'));
  // RFC 6376 section 3.5 makes an l= longer than the body invalid, which
  // mailauth's strict mode reports as a syntax error. That is a property of
  // the body, which the recovery proof does not read (spec section 4.4), so
  // the reference reads the header block over a body long enough for any l=.
  const longestL = Math.max(0, ...[...head.matchAll(/(?:^|[;:])[ \t\r\n]*l[ \t\r\n]*=[ \t\r\n]*(\d{1,7})[ \t\r\n]*(?=;|$)/gim)].map((m) => Number(m[1])));
  const padded = longestL > 0 && text.includes('\r\n\r\n') ? Buffer.concat([Buffer.from(eml), Buffer.from(`${'x'.repeat(76)}\r\n`.repeat(Math.ceil(longestL / 78) + 1))]) : Buffer.from(eml);
  const res = await dkimVerify(padded, { resolver: noKey, strict: true, curTime: new Date(0) });
  const fields = head.split(/\r\n(?![ \t])/).filter((l) => /^dkim-signature[ \t]*:/i.test(l));
  const results = [...res.results];
  return fields.map((raw, position) => {
    const tags = tagList(raw.slice(raw.indexOf(':') + 1));
    const b = (tags.find((t) => t.name === 'b')?.value ?? '').replace(/[ \t\r\n]/g, '');
    // mailauth reports one result per DKIM-Signature field, in field order
    // when all are processed (strict mode reports skipped ones too); match on
    // b= so a reordering cannot pair a field with another's result.
    const at = results.findIndex((r) => (r.signature ?? '').replace(/[ \t\r\n]/g, '') === b);
    const r = at === -1 ? undefined : results.splice(at, 1)[0];
    const comment = r?.status?.comment;
    const signedLines = r?.signingHeaders?.headers ?? [];
    const named = (n) => signedLines.filter((l) => l.slice(0, l.indexOf(':')).trim().toLowerCase() === n);
    return {
      position,
      raw,
      tags,
      d: (tags.find((t) => t.name === 'd')?.value ?? '').toLowerCase(),
      s: tags.find((t) => t.name === 's')?.value ?? '',
      syntax: !r ? 'not reported by mailauth' : SIGNATURE_INVALID.has(comment) ? comment : 'ok',
      timeNote: TIME_ONLY.has(comment) ? comment : null,
      signedData: r?.signingHeaders?.canonicalizedHeader ? Buffer.from(r.signingHeaders.canonicalizedHeader, 'base64') : null,
      signedFroms: named('from').map((l) => l.slice(l.indexOf(':') + 1)),
      signedSubjects: named('subject').length,
      signature: Buffer.from(b, 'base64'),
      hashAlgo: /sha1/i.test(tags.find((t) => t.name === 'a')?.value ?? '') ? 'sha1' : 'sha256',
    };
  });
}

/** The first candidate key under which `sig`'s RSA signature over its signed octets verifies, or null. */
export function verifyingKey(sig, candidates) {
  if (sig.syntax !== 'ok' || !sig.signedData) return null;
  for (const c of candidates) {
    const k = rsaKey(c.p);
    if (k && rsaVerify(sig.hashAlgo, sig.signedData, k.key, sig.signature)) return { ...c, ...k };
  }
  return null;
}

// Python's RFC 5322 reader, one long-lived process, holding the event loop
// open only while an answer is pending.
let python;
const pending = new Map();
let nextId = 0;
function hold(on) {
  for (const handle of [python, python?.stdout]) on ? handle?.ref?.() : handle?.unref?.();
}
function pythonReader() {
  if (python) return python;
  const script = join(fileURLToPath(new URL('.', import.meta.url)), 'from_ref.py');
  python = spawn(process.env.PYTHON ?? 'python3', [script], { stdio: ['pipe', 'pipe', 'inherit'] });
  createInterface({ input: python.stdout }).on('line', (line) => {
    const res = JSON.parse(line);
    pending.get(res.id)?.(res);
    pending.delete(res.id);
    if (pending.size === 0) hold(false);
  });
  return python;
}

/** Python's reading of a From field value. */
export function pythonFrom(value) {
  const id = nextId++;
  const p = new Promise((resolve) => pending.set(id, resolve));
  pythonReader().stdin.write(`${JSON.stringify({ id, value })}\n`);
  hold(true);
  return p;
}

export function closeReferences() {
  python?.stdin.end();
  python = undefined;
}

/** Both reference readings of the From field a signature covers, after unfolding (RFC 5322 section 2.2.3). */
export async function readFrom(rawValue) {
  const py = await pythonFrom(rawValue.replace(/\r\n(?=[ \t])/g, ''));
  const ma = parseFromHeader(rawValue);
  return {
    python: { mailboxes: py.mailboxes.map((m) => m.addr_spec), groups: py.groups, defects: py.defects, version: py.python },
    mailauth: { addresses: ma.addresses, syntax: ma.syntax },
  };
}

const ATEXT = "A-Za-z0-9!#$%&'*+\\-/=?^_`{|}~";
const ADDR_SPEC = new RegExp(`^[${ATEXT}]+(\\.[${ATEXT}]+)*@([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`);

/**
 * The spec's rules a signature and its From must meet for the circuit to
 * accept it, beyond a valid signature: the first one that fails, or null.
 * `address` is the reference's reading of the covered From.
 */
export function profileViolation(sig, key, from) {
  const tag = (n) => sig.tags.filter((t) => t.name === n);
  const one = (n) => (tag(n).length === 1 ? tag(n)[0].value : undefined);
  if (key.bits !== 2048) return `4.3 rule 2: RSA modulus of ${key.bits} bits`;
  if (key.exponent !== 65537n) return '4.3 rule 2: public exponent is not 65537';
  if (one('v') !== '1') return '4.3 rule 2: v= is not 1';
  if (one('a') !== 'rsa-sha256') return '4.3 rule 2: a= is not rsa-sha256';
  if (!['relaxed/relaxed', 'relaxed/simple'].includes(one('c') ?? 'simple/simple')) return '4.3 rule 3: header canonicalization is not relaxed';
  const h = (one('h') ?? '').split(':').map((x) => x.replace(/[ \t\r\n]/g, '').toLowerCase());
  if (!h.includes('from') || !h.includes('subject')) return '4.3 rule 4: h= does not name from and subject';
  const lines = sig.signedData.toString('latin1').split('\r\n');
  if (lines.filter((l) => l.startsWith('from:')).length !== 1) return '4.3 rule 6: the signed data has no single from field';
  if (lines.filter((l) => l.startsWith('subject:')).length !== 1) return '4.3 rule 6: the signed data has no single subject field';
  if (sig.signedData.length > HEADER_MAX) return `6.3: the signed data is ${sig.signedData.length} octets, above ${HEADER_MAX}`;
  if (lines.at(-1).length > DKIM_FIELD_MAX) return `6.3: the DKIM-Signature field is ${lines.at(-1).length} octets, above ${DKIM_FIELD_MAX}`;
  if (sig.tags.length > DKIM_TAGS_MAX) return `6.3: ${sig.tags.length} tags, above ${DKIM_TAGS_MAX}`;
  // Section 4.5 on the reference's reading. The section's display name is
  // any printable ASCII but "<" and ">", wider than RFC 5322's phrase, so a
  // defect Python records is not by itself a violation; the reading is.
  const mbx = from.python.mailboxes;
  if (from.python.groups !== 0 || mbx.length !== 1) return `4.5: From names ${mbx.length} mailboxes (${from.python.groups} groups)`;
  const address = mbx[0];
  if (!ADDR_SPEC.test(address)) return '4.5: the address is not a dot-atom at RFC 1123 labels';
  if (address.length > ADDR_MAX) return `4.5: the address is ${address.length} octets, above ${ADDR_MAX}`;
  const value = lines.find((l) => l.startsWith('from:')).slice(5);
  if (!/^[\x20-\x7e]*$/.test(value)) return '4.5: the From value is not printable ASCII';
  const named = value.endsWith(`<${address}>`) && !/[<>]/.test(value.slice(0, -address.length - 2));
  if (value !== address && !named) return '4.5: the From value is neither the address nor a display name and the address in angle brackets';
  const domain = address.slice(address.lastIndexOf('@') + 1).toLowerCase();
  if ((one('d') ?? '').toLowerCase() !== domain) return '4.3 rule 7: d= is not the From domain';
  if (domain.length > DOMAIN_MAX) return `7.2: the domain is ${domain.length} octets, above ${DOMAIN_MAX}`;
  return null;
}
