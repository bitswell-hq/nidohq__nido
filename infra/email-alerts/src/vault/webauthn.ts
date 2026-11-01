/**
 * Checking an account passkey's authorization of a contact change
 * (`docs/email-recovery/spec.md` §10.3): a WebAuthn assertion (W3C WebAuthn
 * Level 3 §7.2) over the change's challenge, by a key in the account's
 * signer set.
 *
 * The checks mirror the WebAuthn verifier Perch accounts use on chain
 * (`stellar-accounts` `verifiers::webauthn`: type `webauthn.get`, the
 * challenge, UP and UV set, BS only with BE, P-256 over
 * `authenticatorData || SHA-256(clientDataJSON)`, low-S), and add the relying
 * party: `rpIdHash` must be `SHA-256(rpId)` and the origin one of the
 * wallet's.
 */
import { createPublicKey, verify } from 'node:crypto';
import { bytes, type Authorization } from '@nidohq/email-recovery';

const { equal, sha256, toBase64Url, utf8 } = bytes;

const P256_HALF_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n / 2n;
const UP = 0x01;
const UV = 0x04;
const BE = 0x08;
const BS = 0x10;

export interface RelyingParty {
  rpId: string;
  origins: string[];
}

function p256Key(raw: Uint8Array) {
  return createPublicKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: Buffer.from(raw.subarray(1, 33)).toString('base64url'),
      y: Buffer.from(raw.subarray(33, 65)).toString('base64url'),
    },
    format: 'jwk',
  });
}

/** Throws unless `a` is a valid assertion over `challenge` by a key in `signers`. */
export async function checkAuthorization(
  a: Authorization,
  challenge: Uint8Array,
  signers: Uint8Array[],
  rp: RelyingParty,
): Promise<void> {
  if (a.publicKey.length !== 65 || a.publicKey[0] !== 4) throw new Error('authorization: bad public key');
  if (!signers.some((s) => equal(s, a.publicKey))) throw new Error('authorization: not a signer of the account');
  let client: { type?: unknown; challenge?: unknown; origin?: unknown };
  try {
    client = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(a.clientDataJSON));
  } catch {
    throw new Error('authorization: bad clientDataJSON');
  }
  if (client.type !== 'webauthn.get') throw new Error('authorization: not webauthn.get');
  if (client.challenge !== toBase64Url(challenge)) throw new Error('authorization: challenge mismatch');
  if (typeof client.origin !== 'string' || !rp.origins.includes(client.origin)) {
    throw new Error('authorization: origin not allowed');
  }
  const ad = a.authenticatorData;
  if (ad.length < 37) throw new Error('authorization: short authenticatorData');
  if (!equal(ad.subarray(0, 32), await sha256(utf8(rp.rpId)))) throw new Error('authorization: rpIdHash mismatch');
  const flags = ad[32]!;
  if (!(flags & UP)) throw new Error('authorization: user not present');
  if (!(flags & UV)) throw new Error('authorization: user not verified');
  if (flags & BS && !(flags & BE)) throw new Error('authorization: backup state without eligibility');
  if (a.signature.length !== 64) throw new Error('authorization: signature is not r || s');
  if (BigInt('0x' + Buffer.from(a.signature.subarray(32)).toString('hex')) > P256_HALF_N) {
    throw new Error('authorization: high-S signature');
  }
  const signed = Buffer.concat([ad, await sha256(a.clientDataJSON)]);
  if (!verify('sha256', signed, { key: p256Key(a.publicKey), dsaEncoding: 'ieee-p1363' }, a.signature)) {
    throw new Error('authorization: signature invalid');
  }
}
