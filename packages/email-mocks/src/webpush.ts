/**
 * TEST-ONLY mock of Web Push: a push service and the user agent (browser)
 * it delivers to.
 *
 * - The push service accepts RFC 8030 push requests (`POST` to the
 *   subscription's push resource with a required `TTL` header, optional
 *   `Urgency` and `Topic`; `201 Created` with a `Location`; a newer message
 *   with the same `Topic` replaces an undelivered one, §5.4; `413` above
 *   4096 octets), requires RFC 8292 VAPID (`Authorization: vapid t=<JWT>,
 *   k=<key>`, an ES256 JWT whose `aud` is the push service's origin and
 *   whose `exp` is at most 24 hours away; a subscription created with an
 *   application server key accepts only that key, §4.2) and RFC 8291
 *   payloads (`Content-Encoding: aes128gcm`). It cannot read payloads.
 * - The user agent holds the subscription's P-256 key pair and 16-byte
 *   authentication secret and decrypts RFC 8291 messages (one RFC 8188
 *   record).
 */
import {
  createECDH,
  createHmac,
  createDecipheriv,
  createPublicKey,
  randomBytes,
  randomUUID,
  verify,
} from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');
const unb64u = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
const hmac = (key: Uint8Array, ...data: Uint8Array[]) => {
  const h = createHmac('sha256', key);
  for (const d of data) h.update(d);
  return new Uint8Array(h.digest());
};
const ascii = (s: string) => new Uint8Array(Buffer.from(s, 'latin1'));

/** A P-256 public key (uncompressed point) as a `KeyObject`. */
function p256Public(raw: Uint8Array) {
  return createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: b64u(raw.subarray(1, 33)), y: b64u(raw.subarray(33, 65)) },
    format: 'jwk',
  });
}

export interface PushMessage {
  id: string;
  subscription: string;
  ttl: number;
  urgency?: string;
  topic?: string;
  body: Uint8Array;
  receivedAt: number;
  /** The VAPID `sub` claim. */
  sender?: string;
}

interface Subscription {
  applicationServerKey: Uint8Array;
  queue: PushMessage[];
}

export class PushServiceMock {
  /** Every accepted message, in arrival order (including replaced ones). */
  readonly accepted: PushMessage[] = [];
  readonly rejected: { status: number; reason: string }[] = [];
  private readonly subscriptions = new Map<string, Subscription>();
  private failures: number[] = [];
  private server?: Server;
  origin = '';

  /** What a browser's `PushManager.subscribe` asks the push service for. */
  subscribe(applicationServerKey: Uint8Array): string {
    if (!this.origin) throw new Error('push service not listening');
    const id = randomUUID();
    this.subscriptions.set(id, { applicationServerKey, queue: [] });
    return `${this.origin}/push/${id}`;
  }

  /** Delivers (and removes) the undelivered messages of a subscription. */
  deliver(endpoint: string): PushMessage[] {
    const id = endpoint.slice(endpoint.lastIndexOf('/') + 1);
    const sub = this.subscriptions.get(id);
    if (!sub) return [];
    return sub.queue.splice(0);
  }

  failNext(status: number, count = 1): void {
    for (let i = 0; i < count; i++) this.failures.push(status);
  }

  private check(headers: Record<string, string | string[] | undefined>, sub: Subscription): string | undefined {
    const auth = headers.authorization;
    const m = typeof auth === 'string' ? auth.match(/^vapid t=([A-Za-z0-9_.-]+),\s*k=([A-Za-z0-9_-]+)$/) : null;
    if (!m) return 'missing or malformed VAPID authorization';
    const [header, claims, sig] = m[1]!.split('.');
    if (!header || !claims || !sig) return 'malformed JWT';
    const h = JSON.parse(Buffer.from(header, 'base64url').toString('utf8'));
    if (h.alg !== 'ES256' || h.typ !== 'JWT') return 'JWT header is not ES256';
    const key = unb64u(m[2]!);
    if (key.length !== 65 || key[0] !== 4) return 'bad VAPID key';
    if (!verify('sha256', ascii(`${header}.${claims}`), { key: p256Public(key), dsaEncoding: 'ieee-p1363' }, unb64u(sig))) {
      return 'JWT signature invalid';
    }
    const c = JSON.parse(Buffer.from(claims, 'base64url').toString('utf8'));
    const now = Math.floor(Date.now() / 1000);
    if (c.aud !== this.origin) return 'aud is not the push service origin';
    if (typeof c.exp !== 'number' || c.exp <= now || c.exp > now + 24 * 3600) return 'exp outside (now, now + 24h]';
    if (Buffer.compare(Buffer.from(key), Buffer.from(sub.applicationServerKey)) !== 0) return 'restricted:key';
    return undefined;
  }

  async listen(): Promise<string> {
    this.server = createServer(async (req, res) => {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const body = new Uint8Array(Buffer.concat(chunks));
      const reject = (status: number, reason: string) => {
        this.rejected.push({ status, reason });
        res.writeHead(status, { 'content-type': 'text/plain' });
        res.end(reason);
      };
      const m = req.method === 'POST' ? req.url?.match(/^\/push\/([0-9a-f-]+)$/) : null;
      const sub = m ? this.subscriptions.get(m[1]!) : undefined;
      if (!m || !sub) return reject(404, 'no such subscription');
      const failure = this.failures.shift();
      if (failure) return reject(failure, 'injected failure');
      const why = this.check(req.headers, sub);
      if (why === 'restricted:key') return reject(403, 'VAPID key does not match the subscription');
      if (why) return reject(401, why);
      const ttl = req.headers.ttl;
      if (typeof ttl !== 'string' || !/^\d+$/.test(ttl)) return reject(400, 'TTL header required');
      if (req.headers['content-encoding'] !== 'aes128gcm') return reject(415, 'Content-Encoding must be aes128gcm');
      if (body.length > 4096) return reject(413, 'payload too large');
      const urgency = req.headers.urgency;
      if (urgency !== undefined && !['very-low', 'low', 'normal', 'high'].includes(String(urgency))) {
        return reject(400, 'bad Urgency');
      }
      const topic = req.headers.topic;
      if (topic !== undefined && !/^[A-Za-z0-9_-]{1,32}$/.test(String(topic))) return reject(400, 'bad Topic');
      const claims = JSON.parse(
        Buffer.from(String(req.headers.authorization).split('t=')[1]!.split('.')[1]!, 'base64url').toString('utf8'),
      );
      const msg: PushMessage = {
        id: randomUUID(),
        subscription: m[1]!,
        ttl: Number(ttl),
        ...(urgency ? { urgency: String(urgency) } : {}),
        ...(topic ? { topic: String(topic) } : {}),
        body,
        receivedAt: Date.now(),
        ...(typeof claims.sub === 'string' ? { sender: claims.sub } : {}),
      };
      if (msg.topic) sub.queue = sub.queue.filter((q) => q.topic !== msg.topic);
      sub.queue.push(msg);
      this.accepted.push(msg);
      res.writeHead(201, { location: `/message/${msg.id}` });
      res.end();
    });
    await new Promise<void>((r) => this.server!.listen(0, '127.0.0.1', r));
    this.origin = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
    return this.origin;
  }

  async close(): Promise<void> {
    if (this.server) await new Promise<void>((r) => this.server!.close(() => r()));
  }
}

/** RFC 8291 §3.4 decryption of one `aes128gcm` message. */
export function decryptWebPush(
  body: Uint8Array,
  ua: { privateKey: Uint8Array; publicKey: Uint8Array; authSecret: Uint8Array },
): Uint8Array {
  const salt = body.subarray(0, 16);
  const rs = new DataView(body.buffer, body.byteOffset + 16, 4).getUint32(0);
  const idlen = body[20]!;
  const asPublic = body.subarray(21, 21 + idlen);
  const ciphertext = body.subarray(21 + idlen);
  if (idlen !== 65 || rs < 18 || ciphertext.length > rs) throw new Error('not a single-record aes128gcm message');
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(ua.privateKey);
  const secret = new Uint8Array(ecdh.computeSecret(asPublic));
  const prkKey = hmac(ua.authSecret, secret);
  const ikm = hmac(prkKey, ascii('WebPush: info\0'), ua.publicKey, asPublic, Uint8Array.of(1));
  const prk = hmac(salt, ikm);
  const cek = hmac(prk, ascii('Content-Encoding: aes128gcm\0'), Uint8Array.of(1)).subarray(0, 16);
  const nonce = hmac(prk, ascii('Content-Encoding: nonce\0'), Uint8Array.of(1)).subarray(0, 12);
  const d = createDecipheriv('aes-128-gcm', cek, nonce);
  d.setAuthTag(ciphertext.subarray(ciphertext.length - 16));
  const padded = Buffer.concat([d.update(ciphertext.subarray(0, ciphertext.length - 16)), d.final()]);
  let end = padded.length - 1;
  while (end >= 0 && padded[end] === 0) end--;
  if (end < 0 || padded[end] !== 2) throw new Error('missing last-record delimiter');
  return new Uint8Array(padded.subarray(0, end));
}

/** The browser side of a subscription. */
export class PushUserAgentMock {
  readonly publicKey: Uint8Array;
  endpoint = '';

  constructor(
    private readonly service: PushServiceMock,
    readonly privateKey: Uint8Array = new Uint8Array(randomBytes(32)),
    readonly authSecret: Uint8Array = new Uint8Array(randomBytes(16)),
  ) {
    const ecdh = createECDH('prime256v1');
    ecdh.setPrivateKey(privateKey);
    this.publicKey = new Uint8Array(ecdh.getPublicKey());
  }

  /** `PushManager.subscribe({applicationServerKey})` then `toJSON()`. */
  subscribe(applicationServerKey: Uint8Array): {
    endpoint: string;
    expirationTime: null;
    keys: { p256dh: string; auth: string };
  } {
    this.endpoint = this.service.subscribe(applicationServerKey);
    return { endpoint: this.endpoint, expirationTime: null, keys: { p256dh: b64u(this.publicKey), auth: b64u(this.authSecret) } };
  }

  /** Decrypted payloads of every message delivered since the last call. */
  receive(): { message: PushMessage; payload: Uint8Array }[] {
    return this.service.deliver(this.endpoint).map((message) => ({
      message,
      payload: decryptWebPush(message.body, this),
    }));
  }
}
