/**
 * Web Push from the vault: RFC 8291 message encryption (`aes128gcm`, one
 * RFC 8188 record), RFC 8292 VAPID (an ES256 JWT for the push service's
 * origin, valid 12 hours), and an RFC 8030 push request.
 */
import { createCipheriv, createECDH, createHmac, createPrivateKey, randomBytes, sign } from 'node:crypto';

const ascii = (s: string) => Buffer.from(s, 'latin1');
const hmac = (key: Uint8Array, ...data: Uint8Array[]) => {
  const h = createHmac('sha256', key);
  for (const d of data) h.update(d);
  return h.digest();
};

export interface PushTarget {
  endpoint: string;
  /** The subscription's `p256dh` (uncompressed P-256). */
  p256dh: Uint8Array;
  /** The subscription's 16-byte `auth` secret. */
  auth: Uint8Array;
}

/** RFC 8291 §3.4: `salt || rs || idlen || as_public || AES-128-GCM(cek, nonce, plaintext || 0x02)`. */
export function encryptWebPush(
  target: Pick<PushTarget, 'p256dh' | 'auth'>,
  plaintext: Uint8Array,
  fixed?: { asPrivate: Uint8Array; salt: Uint8Array },
): Uint8Array<ArrayBuffer> {
  const ecdh = createECDH('prime256v1');
  if (fixed) ecdh.setPrivateKey(fixed.asPrivate);
  else ecdh.generateKeys();
  const asPublic = ecdh.getPublicKey();
  const salt = fixed?.salt ?? randomBytes(16);
  const secret = ecdh.computeSecret(target.p256dh);
  const prkKey = hmac(target.auth, secret);
  const ikm = hmac(prkKey, ascii('WebPush: info\0'), target.p256dh, asPublic, Uint8Array.of(1));
  const prk = hmac(salt, ikm);
  const cek = hmac(prk, ascii('Content-Encoding: aes128gcm\0'), Uint8Array.of(1)).subarray(0, 16);
  const nonce = hmac(prk, ascii('Content-Encoding: nonce\0'), Uint8Array.of(1)).subarray(0, 12);
  const c = createCipheriv('aes-128-gcm', cek, nonce);
  const ct = Buffer.concat([c.update(plaintext), c.update(Uint8Array.of(2)), c.final(), c.getAuthTag()]);
  const rs = 4096;
  if (ct.length > rs) throw new Error('push payload larger than one record');
  const header = Buffer.alloc(21);
  Buffer.from(salt).copy(header, 0);
  header.writeUInt32BE(rs, 16);
  header[20] = asPublic.length;
  return new Uint8Array(Buffer.concat([header, asPublic, ct]));
}

/** RFC 8292 §3: `vapid t=<ES256 JWT>, k=<public key>`. */
export function vapidAuthorization(
  endpoint: string,
  key: { privateKey: Uint8Array; publicKey: Uint8Array },
  subject: string,
  now = Date.now(),
): string {
  const aud = new URL(endpoint).origin;
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const unsigned = `${b64({ typ: 'JWT', alg: 'ES256' })}.${b64({ aud, exp: Math.floor(now / 1000) + 12 * 3600, sub: subject })}`;
  const pk = createPrivateKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      d: Buffer.from(key.privateKey).toString('base64url'),
      x: Buffer.from(key.publicKey.subarray(1, 33)).toString('base64url'),
      y: Buffer.from(key.publicKey.subarray(33, 65)).toString('base64url'),
    },
    format: 'jwk',
  });
  const sig = sign('sha256', ascii(unsigned), { key: pk, dsaEncoding: 'ieee-p1363' });
  return `vapid t=${unsigned}.${sig.toString('base64url')}, k=${Buffer.from(key.publicKey).toString('base64url')}`;
}

export type PushOutcome = 'accepted' | 'gone' | 'retry';

/** RFC 8030 §5: one push; `gone` for 404/410 (the subscription no longer exists). */
export async function pushMessage(
  target: PushTarget,
  payload: Uint8Array,
  opts: { vapid: { privateKey: Uint8Array; publicKey: Uint8Array }; subject: string; ttl: number; urgency: string; topic: string },
  fetchImpl: typeof fetch = fetch,
): Promise<{ outcome: PushOutcome; status?: number }> {
  try {
    const r = await fetchImpl(target.endpoint, {
      method: 'POST',
      headers: {
        authorization: vapidAuthorization(target.endpoint, opts.vapid, opts.subject),
        ttl: String(opts.ttl),
        urgency: opts.urgency,
        topic: opts.topic,
        'content-encoding': 'aes128gcm',
        'content-type': 'application/octet-stream',
      },
      body: new Uint8Array(encryptWebPush(target, payload)),
      signal: AbortSignal.timeout(10_000),
    });
    if (r.status === 201 || r.status === 202) return { outcome: 'accepted', status: r.status };
    if (r.status === 404 || r.status === 410) return { outcome: 'gone', status: r.status };
    return { outcome: 'retry', status: r.status };
  } catch {
    return { outcome: 'retry' };
  }
}
