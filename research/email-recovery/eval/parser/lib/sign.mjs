// Signs a generated case with a TEST-ONLY key from @nidohq/email-mocks.
//
// The signer computes the octets to sign the way a verifier will: the
// message is assembled with an empty b=, mailauth (strict mode) selects and
// canonicalizes the signed fields for that DKIM-Signature field (RFC 6376
// sections 3.4, 3.7, 5.4.2), and the RSA PKCS#1 v1.5 signature over those
// octets becomes the b= value. Where mailauth does not process the field at
// all (an algorithm, canonicalization, d= or s= it does not support), the
// octets the wallet's encoder builds are signed instead, so the circuit still
// sees a valid signature over the block it is given and has to refuse the
// field on its own.

import { createHash, sign as rsaSign } from 'node:crypto';

import { testKey } from '@nidohq/email-mocks';
import { dkimSignatures, parseMessage, signedHeaderBlock } from '@nidohq/email-recovery';
import { dkimVerify } from 'mailauth/lib/dkim/verify.js';

import { signatureValue } from './grammar.mjs';

export const BODY = 'hello\r\n';
/** The body hash of BODY under either body canonicalization (RFC 6376 section 3.4.3, 3.4.4). */
export const BH = createHash('sha256').update(BODY).digest('base64');

const noKey = async () => {
  const err = new Error('no key');
  err.code = 'ENOTFOUND';
  throw err;
};

/** The message octets of a case, with `b` as the b= value. */
export function assemble(c, b) {
  const sigLine = `${c.signatureName ?? 'DKIM-Signature'}:${signatureValue(c, b, BH)}`;
  const lines = c.fields.map(([n, v]) => `${n}:${v}`);
  lines.splice(c.signatureAt, 0, sigLine);
  return Buffer.from(`${lines.join('\r\n')}\r\n\r\n${BODY}`, 'latin1');
}

/** The signed message of a case: `{ eml, signedVia }`, `signedVia` 'mailauth', 'encoder' or null (nothing to sign). */
export async function signCase(c) {
  const key = testKey(c.keyName);
  const unsigned = assemble(c, '');
  const text = unsigned.toString('latin1');
  const head = text.slice(0, text.indexOf('\r\n\r\n'));
  const names = head.split(/\r\n(?![ \t])/).map((l) => l.slice(0, Math.max(0, l.indexOf(':'))).replace(/[ \t]+$/, '').toLowerCase());
  const position = names.slice(0, c.signatureAt).filter((n) => n === 'dkim-signature').length;
  if (names[c.signatureAt] !== 'dkim-signature') return { eml: unsigned, signedVia: null };

  let data = null;
  let signedVia = null;
  const res = await dkimVerify(unsigned, { resolver: noKey, strict: true, curTime: new Date(0) });
  const mine = res.results.filter((r) => r.status?.result !== 'none')[position];
  if (mine?.signingHeaders?.canonicalizedHeader) {
    data = Buffer.from(mine.signingHeaders.canonicalizedHeader, 'base64');
    signedVia = 'mailauth';
  } else {
    try {
      const parsed = parseMessage(unsigned);
      data = Buffer.from(signedHeaderBlock(parsed, dkimSignatures(parsed)[position]));
      signedVia = 'encoder';
    } catch {
      return { eml: unsigned, signedVia: null };
    }
  }
  const a = c.signature.find((t) => t.name === 'a')?.value ?? '';
  const b = rsaSign(/sha1/i.test(a) ? 'sha1' : 'sha256', data, key.privateKey).toString('base64');
  return { eml: assemble(c, b), signedVia, signedData: data };
}
