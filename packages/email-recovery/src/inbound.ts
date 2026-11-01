/**
 * The sealed inbound path (`docs/email-recovery/spec.md` §4.6): how the
 * email the user sent to `RECOVERY_INBOX` comes back to the browser that
 * proves it, without the alert service's host reading it.
 *
 * 1. The browser draws a device key pair (from a 32-octet seed it keeps)
 *    and a 16-octet inbox id, and seals `{value, id, device key}` to the
 *    vault's attested HPKE key. `value` is the 32 octets whose hex ends the
 *    Subject (`T` for a recovery email, `E` for an enrollment email).
 * 2. The vault receives the mail (its MX runs inside the enclave), finds the
 *    registration whose value the Subject ends with, and seals the raw
 *    message octets to the device key with the inbox id as associated data.
 * 3. The host stores that blob under the inbox id; the browser fetches it
 *    and opens it.
 *
 * The host sees the inbox id, sizes and times; never the value, the
 * address, or the message.
 */

import { decode, encode } from 'cborg';
import { fromHex, randomBytes, toHex, utf8 } from './bytes.js';
import { hpkeSuite, open, seal } from './hpke.js';

export const INBOUND_REQUEST_INFO = 'nido/email-recovery/v1/inbound-request';
export const INBOUND_MESSAGE_INFO = 'nido/email-recovery/v1/inbound-message';
export const INBOUND_VERSION = 1;

/** What the vault opens. */
export interface InboundRequest {
  /** The 32 octets the Subject ends with, in hex. */
  value: Uint8Array;
  /** Where the host keeps what the vault seals for this registration. */
  id: Uint8Array;
  /** The device's HPKE public key (uncompressed P-256). */
  deviceKey: Uint8Array;
}

/** What the browser keeps to fetch and open the message: never sent anywhere. */
export interface InboxSecret {
  /** Inbox id, hex. */
  id: string;
  /** Seed of the device key pair (RFC 9180 DeriveKeyPair), hex. */
  seed: string;
}

async function deviceKeys(seed: Uint8Array): Promise<{ pair: CryptoKeyPair; publicKey: Uint8Array }> {
  const suite = hpkeSuite();
  const pair = await suite.kem.deriveKeyPair(new Uint8Array(seed).buffer as ArrayBuffer);
  return { pair, publicKey: new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey)) };
}

export function encodeInboundRequest(r: InboundRequest): Uint8Array {
  return encode(
    new Map<string, unknown>([
      ['v', INBOUND_VERSION],
      ['value', r.value],
      ['id', r.id],
      ['device_key', r.deviceKey],
    ]),
  );
}

export function decodeInboundRequest(bytes: Uint8Array): InboundRequest {
  const m = decode(bytes, { useMaps: true, strict: true, rejectDuplicateMapKeys: true });
  if (!(m instanceof Map) || m.get('v') !== INBOUND_VERSION || m.size !== 4) throw new Error('inbound request: bad version');
  const get = (k: string, n: number) => {
    const v = m.get(k);
    if (!(v instanceof Uint8Array) || v.length !== n) throw new Error(`inbound request: bad ${k}`);
    return v;
  };
  const deviceKey = get('device_key', 65);
  if (deviceKey[0] !== 4) throw new Error('inbound request: bad device_key');
  return { value: get('value', 32), id: get('id', 16), deviceKey };
}

/**
 * A registration for the email whose Subject ends with `valueHex`, sealed
 * to the vault's key: the envelope to post, and the secret to keep.
 */
export async function inboundRegistration(vaultPublicKey: Uint8Array, valueHex: string): Promise<{ envelope: Uint8Array; secret: InboxSecret }> {
  if (!/^[0-9a-f]{64}$/.test(valueHex)) throw new Error('the Subject value is 64 lowercase hex characters');
  const seed = randomBytes(32);
  const id = randomBytes(16);
  const { publicKey } = await deviceKeys(seed);
  const { enc, ct } = await seal(vaultPublicKey, utf8(INBOUND_REQUEST_INFO), new Uint8Array(0), encodeInboundRequest({ value: fromHex(valueHex), id, deviceKey: publicKey }));
  const envelope = encode(
    new Map<string, unknown>([
      ['v', INBOUND_VERSION],
      ['enc', enc],
      ['ct', ct],
    ]),
  );
  return { envelope, secret: { id: toHex(id), seed: toHex(seed) } };
}

/** The vault's side of step 1: open a registration envelope. */
export async function openInboundRegistration(vaultKey: CryptoKeyPair, envelope: Uint8Array): Promise<InboundRequest> {
  const m = decode(envelope, { useMaps: true, strict: true, rejectDuplicateMapKeys: true });
  const enc = m instanceof Map ? m.get('enc') : undefined;
  const ct = m instanceof Map ? m.get('ct') : undefined;
  if (!(m instanceof Map) || m.get('v') !== INBOUND_VERSION || !(enc instanceof Uint8Array) || enc.length !== 65 || !(ct instanceof Uint8Array)) {
    throw new Error('inbound envelope: malformed');
  }
  return decodeInboundRequest(await open(vaultKey, utf8(INBOUND_REQUEST_INFO), new Uint8Array(0), { enc, ct }));
}

/** The vault's side of step 2: the raw message sealed to the device, bound to the inbox id. */
export async function sealInboundMessage(req: InboundRequest, raw: Uint8Array): Promise<Uint8Array> {
  const { enc, ct } = await seal(req.deviceKey, utf8(INBOUND_MESSAGE_INFO), req.id, raw);
  const out = new Uint8Array(enc.length + ct.length);
  out.set(enc);
  out.set(ct, enc.length);
  return out;
}

/** Step 3: the raw message from a sealed blob the host served for `secret.id`. */
export async function openInboundMessage(secret: InboxSecret, sealed: Uint8Array): Promise<Uint8Array> {
  if (sealed.length < 65 + 16) throw new Error('inbound message: too short');
  const { pair } = await deviceKeys(fromHex(secret.seed));
  return open(pair, utf8(INBOUND_MESSAGE_INFO), fromHex(secret.id), { enc: sealed.subarray(0, 65), ct: sealed.subarray(65) });
}

/** The Subject values a raw message's `Subject` fields end with (any of them; the circuit decides which is signed). */
export function subjectValues(raw: Uint8Array): string[] {
  const text = new TextDecoder('latin1').decode(raw);
  const head = text.split(/\r\n\r\n/, 1)[0] ?? '';
  const unfolded = head.replace(/\r\n[ \t]+/g, ' ');
  const out: string[] = [];
  for (const line of unfolded.split('\r\n')) {
    const m = /^subject\s*:(.*)$/i.exec(line);
    const v = m && /(?:APPROVE|ENROLL) NIDO ACCOUNT RECOVERY ([0-9a-f]{64})\s*$/.exec(m[1]!);
    if (v) out.push(v[1]!);
  }
  return out;
}
