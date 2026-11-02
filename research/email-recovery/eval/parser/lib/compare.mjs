// One message through both sides, signature by signature.
//
// For each DKIM-Signature field (aligned with the From domain or not, so the
// circuit's alignment rule is exercised on real signatures too):
//
// - the reference verdict: mailauth's strict syntax check, the RSA signature
//   over mailauth's signed octets under a candidate key, then the spec's
//   profile (reference.mjs);
// - the circuit verdict: the harness run on the signed octets the reference
//   built and, when they differ, also on the ones the wallet's encoder builds
//   (`signedHeaderBlock`), under each candidate key; the circuit accepts the
//   signature if any run accepts.
//
// Classification of a signature:
//   agree-accept    both accept, the circuit's address is the one Python
//                   reads, and its domain is the lowercase d=;
//   agree-refuse    both refuse;
//   soundness       the circuit accepts and either the reference DKIM
//                   verifier refuses the signature (kind "dkim"), or Python
//                   does not read exactly one mailbox equal to the circuit's
//                   address (kind "from"), or the circuit's domain is not the
//                   lowercase d= and the address's domain (kind "domain");
//   spec-deviation  the circuit accepts and binds the address Python reads,
//                   but a rule the spec states (section 4.3, 4.5, 6.3) refuses
//                   the signature;
//   completeness    the reference accepts, the spec's rules allow, and the
//                   circuit refuses;
//   no-key          no candidate key is known, so neither verdict is possible.

import { deflateRawSync, inflateRawSync } from 'node:zlib';

import { dkimSignatures, parseMessage, signedHeaderBlock } from '@nidohq/email-recovery';

import { crossCheckAgrees } from './circuit.mjs';
import { rsaKey } from './keys.mjs';
import { profileViolation, readFrom, referenceSignatures, verifyingKey } from './reference.mjs';

/** The value of the from line of a relaxed-canonical signed block. */
const blockFrom = (block) => block.toString('latin1').split('\r\n').find((l) => l.startsWith('from:'))?.slice(5) ?? null;

const big = (bytes) => (bytes.length ? BigInt(`0x${Buffer.from(bytes).toString('hex')}`) : 0n);

/**
 * Compares one message. `keysFor(d, s)` lists candidate keys `{ id, p }`.
 * Resolves to one row per DKIM-Signature field, top-most first.
 */
export async function compareMessage(eml, keysFor, pool) {
  const sigs = await referenceSignatures(eml);
  let parsed;
  let encoded = [];
  let encoderError = null;
  try {
    parsed = parseMessage(eml);
    encoded = dkimSignatures(parsed);
  } catch (err) {
    encoderError = err.message;
  }

  const rows = [];
  for (const sig of sigs) {
    const candidates = keysFor(sig.d, sig.s).filter((c) => rsaKey(c.p));
    const key = verifyingKey(sig, candidates);
    const from = sig.signedFroms.length === 1 ? await readFrom(sig.signedFroms[0]) : null;
    let dkim = null;
    if (sig.syntax !== 'ok') dkim = sig.syntax;
    else if (!sig.signedData) dkim = 'no signed data';
    else if (!key) dkim = candidates.length ? 'the signature does not verify under any candidate key' : 'no key';
    let violation;
    if (dkim) violation = `reference: ${dkim}`;
    else if (!from) violation = `4.3 rule 6: the signature covers ${sig.signedFroms.length} From fields`;
    else violation = profileViolation(sig, key, from);
    const expected = violation === null;

    // The circuit's inputs: both blocks, each candidate key.
    const blocks = [];
    if (sig.signedData) blocks.push({ via: 'reference', bytes: sig.signedData });
    let encoderBlock = null;
    const enc = encoded[sig.position];
    if (enc && parsed) {
      try {
        encoderBlock = Buffer.from(signedHeaderBlock(parsed, enc));
      } catch (err) {
        encoderError ??= err.message;
      }
    }
    const blocksAgree = encoderBlock && sig.signedData ? encoderBlock.equals(sig.signedData) : null;
    if (encoderBlock && !blocksAgree) blocks.push({ via: 'encoder', bytes: encoderBlock });
    const moduli = key ? [key.modulus] : candidates.map((c) => rsaKey(c.p).modulus);

    const runs = [];
    for (const b of blocks) {
      for (const modulus of moduli) {
        const res = await pool.run(b.bytes, modulus, big(sig.signature));
        runs.push({ via: b.via, ...res, crossCheck: crossCheckAgrees(res) });
      }
    }
    const accepted = runs.filter((r) => r.harness.accepted);
    const pyMailboxes = from?.python.mailboxes ?? [];

    let verdict;
    let kind = null;
    let detail = null;
    if (candidates.length === 0) verdict = 'no-key';
    else if (accepted.length) {
      const a = accepted[0].harness;
      verdict = 'soundness';
      if (dkim) {
        kind = 'dkim';
        detail = `circuit accepts; the reference refuses the signature: ${dkim}`;
      } else if (pyMailboxes.length !== 1 || accepted.some((r) => r.harness.address !== pyMailboxes[0])) {
        kind = 'from';
        detail = `circuit binds ${JSON.stringify(a.address)}; Python reads ${JSON.stringify(pyMailboxes)}`;
      } else if (accepted.some((r) => r.harness.domain !== sig.d || r.harness.domain !== pyMailboxes[0].slice(pyMailboxes[0].lastIndexOf('@') + 1).toLowerCase())) {
        kind = 'domain';
        detail = `circuit binds domain ${a.domain}; d=${sig.d}, From ${pyMailboxes[0]}`;
      } else if (!expected) {
        verdict = 'spec-deviation';
        detail = `circuit accepts the address both read; the spec's rule refuses it: ${violation}`;
      } else verdict = 'agree-accept';
    } else {
      verdict = expected ? 'completeness' : 'agree-refuse';
      if (expected) detail = runs.map((r) => `${r.via}: ${r.harness.refusal}`).join('; ') || 'not run';
    }

    rows.push({
      position: sig.position,
      d: sig.d,
      s: sig.s,
      key: key?.id ?? null,
      candidates: candidates.length,
      reference: { syntax: sig.syntax, verifies: Boolean(key), violation, expected, timeNote: sig.timeNote },
      from: from && {
        python: from.python.mailboxes,
        pythonDefects: from.python.defects,
        mailauth: from.mailauth.addresses,
        mailauthSyntax: from.mailauth.syntax,
      },
      blocksAgree,
      encoderError,
      circuit: {
        accepted: accepted.length > 0,
        address: accepted[0]?.harness.address ?? null,
        fromValue: accepted.length ? blockFrom(blocks.find((b) => b.via === accepted[0].via).bytes) : null,
        domain: accepted[0]?.harness.domain ?? null,
        refusals: [...new Set(runs.filter((r) => !r.harness.accepted).map((r) => r.harness.refusal))],
        runs: runs.length,
        crossCheck: runs.every((r) => r.crossCheck),
        artifactRefusals: [...new Set(runs.filter((r) => r.artifact).map((r) => r.artifact.refusal))],
      },
      verdict,
      kind,
      detail,
    });
  }
  return rows;
}

/** One letter per verdict, for the compact records check.sh --ci compares. */
export const VERDICT_CODES = { 'agree-accept': 'A', 'agree-refuse': 'R', soundness: 'S', 'spec-deviation': 'D', completeness: 'C', 'no-key': 'N' };

/** Rows of many messages (null for one not available) as a deflated, base64 string of verdict letters. */
export function encodeVerdicts(messages) {
  const text = messages.map((rows) => (rows === null ? '?' : rows.map((r) => VERDICT_CODES[r.verdict]).join(''))).join('|');
  return deflateRawSync(Buffer.from(text)).toString('base64');
}

export function decodeVerdicts(codes) {
  return inflateRawSync(Buffer.from(codes, 'base64')).toString().split('|');
}

/**
 * The display-name feature of a From value that makes RFC 5322 readers read
 * it differently from the circuit (outside quoted strings), or 'other'.
 */
export function fromClass(value) {
  const v = value ?? '';
  const name = v.endsWith('>') && v.includes('<') ? v.slice(0, v.lastIndexOf('<')) : v;
  const outside = name.replace(/"(?:[^"\\]|\\.)*"/g, '');
  if (outside.includes('"')) return 'unbalanced `"` in the display name';
  for (const [ch, label] of [
    [',', 'unquoted `,` (an address list)'],
    ['@', 'unquoted `@` (an address in the display name)'],
    [';', 'unquoted `;`'],
    [':', 'unquoted `:` (a group)'],
    ['\\', 'unquoted `\\`'],
    ['(', 'unquoted `(`'],
    [')', 'unquoted `)`'],
  ]) {
    if (outside.includes(ch)) return label;
  }
  return 'other';
}
