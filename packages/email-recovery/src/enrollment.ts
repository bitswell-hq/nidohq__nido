/**
 * The wallet's side of alert contacts (`docs/email-recovery/spec.md`
 * §10.3): verify the vault's attestation, seal the contact to the attested
 * key, and have an account passkey authorize the change.
 *
 * Every registration, replacement, removal, push update, and status read
 * is a [`ContactRequest`]: an HPKE envelope only the vault opens, plus a
 * WebAuthn assertion by one of the account's passkeys over
 * [`authorizationChallenge`], which binds the operation, the account, the
 * contact reference, the envelope's hash, the purposes, the consent-text
 * version, and a single-use vault nonce. The host that relays the request
 * sees the account and the operation, never the address.
 */

import { decode, encode } from 'cborg';
import { deriveAlertCodeKey } from './alertCode.js';
import { decodeVaultUserData, verifyAttestation, type VerifyOptions } from './attestation.js';
import { fromBase64Url, randomBytes, sha256, toBase64Url, utf8 } from './bytes.js';
import { open, rawPublicKeyFromSpki, seal } from './hpke.js';
import { contractIdFromStrkey, strkeyFromContractId } from './strkey.js';

/** HPKE `info` for every wallet-to-vault envelope. */
export const VAULT_REQUEST_INFO = 'nido/email-recovery/v1/vault-request';
export const AUTHORIZATION_LABEL = 'nido/email-recovery/v1/alert-contact/';
export const ENVELOPE_VERSION = 1;

/** Purpose bits a contact is registered for. Security alerts are always on. */
export const PURPOSE_SECURITY_ALERTS = 1;
export const PURPOSE_PRODUCT_UPDATES = 2;

/**
 * `push` gives an existing contact a new Web Push subscription (the vault
 * applies it at once only when the current one is gone); `status` reads the
 * account's channels (spec §10.3).
 */
export type ContactOp = 'register' | 'replace' | 'remove' | 'push' | 'status';

/** A `PushSubscription.toJSON()` (W3C Push API) the vault pushes to. */
export interface PushSubscriptionJSON {
  endpoint: string;
  expirationTime?: number | null;
  keys: { p256dh: string; auth: string };
}

export interface VaultKey {
  /** The vault's HPKE public key (uncompressed P-256). */
  publicKey: Uint8Array;
  /** The VAPID key a push subscription for the vault must be created with. */
  vapid: Uint8Array;
  /** Hex image measurement the key was attested under. */
  measurement: string;
}

/**
 * Verify a vault attestation fetched for `opts.nonce` (which the wallet
 * drew for this fetch) and return the key to seal to.
 */
export async function attestedVaultKey(attestation: Uint8Array, opts: VerifyOptions): Promise<VaultKey> {
  const v = await verifyAttestation(attestation, opts);
  const { vapid } = decodeVaultUserData(v.userData);
  return { publicKey: await rawPublicKeyFromSpki(v.publicKey), vapid, measurement: v.measurement };
}

/** A nonce for one attestation fetch: 32 random bytes. */
export const attestationNonce = (): Uint8Array => randomBytes(32);

export interface PushChannel {
  endpoint: string;
  p256dh: Uint8Array;
  auth: Uint8Array;
}

/** What the vault decrypts. */
export type SealedRequest =
  | {
      op: 'register' | 'replace';
      account: Uint8Array;
      contact: Uint8Array;
      /** The contact this one replaces (`replace` only). */
      replaces?: Uint8Array;
      address: string;
      kCode: Uint8Array;
      emailGuardian: boolean;
      push?: PushChannel;
      purposes: number;
      consentVersion: number;
    }
  | { op: 'remove'; account: Uint8Array; contact: Uint8Array }
  | { op: 'push'; account: Uint8Array; contact: Uint8Array; push: PushChannel }
  /** `contact` is 16 zero octets: a status read names no contact. */
  | { op: 'status'; account: Uint8Array; contact: Uint8Array }
  | { op: 'confirm'; account: Uint8Array; contact: Uint8Array; code: string };

/** The assertion fields a vault needs, from `navigator.credentials.get`. */
export interface Authorization {
  /** The signing passkey's public key (uncompressed P-256), as the account lists it. */
  publicKey: Uint8Array;
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  /** `r || s`, 64 bytes, `s` in the lower half of the order. */
  signature: Uint8Array;
}

/** What the host relays to the vault. */
export interface ContactRequest {
  op: ContactOp | 'confirm';
  /** `C...` address. */
  account: string;
  /** The vault-issued nonce the authorization signs (absent for `confirm`). */
  nonce?: Uint8Array;
  envelope: Uint8Array;
  authorization?: Authorization;
}

/** §9.3 rule 2: an email guardian needs the Web Push channel as well. */
export function checkChannels(input: { emailGuardian: boolean; push?: unknown }): void {
  if (input.emailGuardian && !input.push) {
    throw new Error('an account with an email guardian needs a Web Push channel as well');
  }
}

const ADDRESS_MAX = 254;

export interface ContactInput {
  /** `C...` address of the account. */
  account: string;
  /** The address alerts go to. */
  address: string;
  /** The account's `account_code` (16 bytes); only `k_code` leaves the wallet. */
  accountCode: Uint8Array;
  /** Whether the account's recovery lists an email guardian. */
  emailGuardian: boolean;
  /** Required when `emailGuardian` (spec §9.3 rule 2). */
  push?: PushSubscriptionJSON;
  /** [`PURPOSE_SECURITY_ALERTS`], optionally with [`PURPOSE_PRODUCT_UPDATES`]. */
  purposes: number;
  /** Version of the consent text the user was shown. */
  consentVersion: number;
  /** Accept `http://127.0.0.1` push endpoints (local test push services only). */
  allowLoopbackPush?: boolean;
}

/** A registration (`replaces` absent) or replacement request, with a fresh contact id. */
export async function contactRequest(input: ContactInput, replaces?: Uint8Array): Promise<SealedRequest> {
  checkChannels(input);
  if (!/^[\x21-\x3f\x41-\x7e]+@[\x21-\x3f\x41-\x7e]+$/.test(input.address) || input.address.length > ADDRESS_MAX) {
    throw new Error('not an email address');
  }
  if ((input.purposes & PURPOSE_SECURITY_ALERTS) === 0 || input.purposes & ~3) throw new Error('bad purposes');
  if (!Number.isInteger(input.consentVersion) || input.consentVersion < 1) throw new Error('bad consent version');
  const req: SealedRequest = {
    op: replaces ? 'replace' : 'register',
    account: contractIdFromStrkey(input.account),
    contact: randomBytes(16),
    ...(replaces ? { replaces } : {}),
    address: input.address,
    kCode: await deriveAlertCodeKey(input.accountCode),
    emailGuardian: input.emailGuardian,
    purposes: input.purposes,
    consentVersion: input.consentVersion,
  };
  if (input.push) req.push = pushChannel(input.push, input.allowLoopbackPush);
  return req;
}

/** A subscription as the vault keeps it, checked: P-256 keys, a 16-octet secret, an https endpoint. */
function pushChannel(sub: PushSubscriptionJSON, allowLoopbackPush?: boolean): PushChannel {
  const p256dh = fromBase64Url(sub.keys.p256dh);
  const auth = fromBase64Url(sub.keys.auth);
  if (p256dh.length !== 65 || p256dh[0] !== 4 || auth.length !== 16) throw new Error('bad push subscription keys');
  const loopback = allowLoopbackPush && sub.endpoint.startsWith('http://127.0.0.1:');
  if (!sub.endpoint.startsWith('https://') && !loopback) throw new Error('push endpoint must be https');
  return { endpoint: sub.endpoint, p256dh, auth };
}

export function removalRequest(account: string, contact: Uint8Array): SealedRequest {
  return { op: 'remove', account: contractIdFromStrkey(account), contact };
}

/** A new Web Push subscription for the existing contact `contact`. */
export function pushUpdateRequest(
  account: string,
  contact: Uint8Array,
  push: PushSubscriptionJSON,
  opts: { allowLoopbackPush?: boolean } = {},
): SealedRequest {
  if (contact.length !== 16) throw new Error('a contact id is 16 octets');
  return { op: 'push', account: contractIdFromStrkey(account), contact, push: pushChannel(push, opts.allowLoopbackPush) };
}

/** A read of the account's alert channels. */
export function statusRequest(account: string): SealedRequest {
  return { op: 'status', account: contractIdFromStrkey(account), contact: new Uint8Array(16) };
}

export function confirmationRequest(account: string, contact: Uint8Array, code: string): SealedRequest {
  if (!/^\d{6}$/.test(code)) throw new Error('confirmation code is 6 digits');
  return { op: 'confirm', account: contractIdFromStrkey(account), contact, code };
}

const encodePush = (p: PushChannel) =>
  new Map<string, unknown>([
    ['endpoint', p.endpoint],
    ['p256dh', p.p256dh],
    ['auth', p.auth],
  ]);

export function encodeSealedRequest(r: SealedRequest): Uint8Array {
  const m = new Map<string, unknown>([
    ['v', ENVELOPE_VERSION],
    ['op', r.op],
    ['account', r.account],
    ['contact', r.contact],
  ]);
  if (r.op === 'register' || r.op === 'replace') {
    if (r.replaces) m.set('replaces', r.replaces);
    m.set('address', r.address);
    m.set('k_code', r.kCode);
    m.set('email_guardian', r.emailGuardian);
    if (r.push) m.set('push', encodePush(r.push));
    m.set('purposes', r.purposes);
    m.set('consent_version', r.consentVersion);
  } else if (r.op === 'push') {
    m.set('push', encodePush(r.push));
  } else if (r.op === 'confirm') {
    m.set('code', r.code);
  }
  return encode(m);
}

function field<T>(m: Map<unknown, unknown>, k: string, check: (v: unknown) => v is T): T {
  const v = m.get(k);
  if (!check(v)) throw new Error(`vault request: bad ${k}`);
  return v;
}
const isBytes =
  (n: number) =>
  (v: unknown): v is Uint8Array =>
    v instanceof Uint8Array && v.length === n;
const isString = (v: unknown): v is string => typeof v === 'string';
const isBool = (v: unknown): v is boolean => typeof v === 'boolean';
const isMap = (v: unknown): v is Map<unknown, unknown> => v instanceof Map;
const isU32 = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v < 2 ** 32;

export function decodeSealedRequest(bytes: Uint8Array): SealedRequest {
  const m = decode(bytes, { useMaps: true, strict: true, rejectDuplicateMapKeys: true });
  if (!(m instanceof Map) || m.get('v') !== ENVELOPE_VERSION) throw new Error('vault request: bad version');
  const account = field(m, 'account', isBytes(32));
  const contact = field(m, 'contact', isBytes(16));
  const op = m.get('op');
  if (op === 'remove') return { op, account, contact };
  if (op === 'status') {
    if (contact.some((b) => b !== 0)) throw new Error('vault request: a status read names no contact');
    return { op, account, contact };
  }
  if (op === 'push') return { op, account, contact, push: decodePush(field(m, 'push', isMap)) };
  if (op === 'confirm') {
    const code = field(m, 'code', isString);
    if (!/^\d{6}$/.test(code)) throw new Error('vault request: bad code');
    return { op, account, contact, code };
  }
  if (op !== 'register' && op !== 'replace') throw new Error('vault request: bad op');
  const req: SealedRequest = {
    op,
    account,
    contact,
    address: field(m, 'address', isString),
    kCode: field(m, 'k_code', isBytes(32)),
    emailGuardian: field(m, 'email_guardian', isBool),
    purposes: field(m, 'purposes', isU32),
    consentVersion: field(m, 'consent_version', isU32),
  };
  if (op === 'replace') req.replaces = field(m, 'replaces', isBytes(16));
  else if (m.has('replaces')) throw new Error('vault request: replaces on a registration');
  if (m.has('push')) req.push = decodePush(field(m, 'push', isMap));
  return req;
}

const decodePush = (p: Map<unknown, unknown>): PushChannel => ({
  endpoint: field(p, 'endpoint', isString),
  p256dh: field(p, 'p256dh', isBytes(65)),
  auth: field(p, 'auth', isBytes(16)),
});

/** The envelope: CBOR `{v, enc, ct}` around the HPKE-sealed request. */
export async function sealRequest(vaultPublicKey: Uint8Array, r: SealedRequest): Promise<Uint8Array> {
  const { enc, ct } = await seal(vaultPublicKey, utf8(VAULT_REQUEST_INFO), new Uint8Array(0), encodeSealedRequest(r));
  return encode(
    new Map<string, unknown>([
      ['v', ENVELOPE_VERSION],
      ['enc', enc],
      ['ct', ct],
    ]),
  );
}

export async function openRequest(vaultKey: CryptoKeyPair, envelope: Uint8Array): Promise<SealedRequest> {
  const m = decode(envelope, { useMaps: true, strict: true, rejectDuplicateMapKeys: true });
  if (!(m instanceof Map) || m.get('v') !== ENVELOPE_VERSION) throw new Error('vault envelope: bad version');
  const enc = field(m, 'enc', isBytes(65));
  const ct = m.get('ct');
  if (!(ct instanceof Uint8Array)) throw new Error('vault envelope: bad ct');
  return decodeSealedRequest(await open(vaultKey, utf8(VAULT_REQUEST_INFO), new Uint8Array(0), { enc, ct }));
}

const u32 = (n: number) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
};

/**
 * The WebAuthn challenge an account passkey signs for a contact request:
 * `sha256(label || op || account || contact || sha256(envelope) ||
 * BE32(purposes) || BE32(consent_version) || nonce)`. `remove`, `push` and
 * `status` sign purposes and consent version 0.
 */
export async function authorizationChallenge(c: {
  op: ContactOp;
  account: Uint8Array;
  contact: Uint8Array;
  envelope: Uint8Array;
  purposes: number;
  consentVersion: number;
  nonce: Uint8Array;
}): Promise<Uint8Array> {
  if (c.account.length !== 32 || c.contact.length !== 16 || c.nonce.length !== 32) throw new Error('bad challenge input');
  return sha256(
    utf8(AUTHORIZATION_LABEL + c.op),
    c.account,
    c.contact,
    await sha256(c.envelope),
    u32(c.purposes),
    u32(c.consentVersion),
    c.nonce,
  );
}

const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

/** A WebAuthn ES256 signature (DER) as `r || s` with `s ≤ n/2`. */
export function rawLowS(der: Uint8Array): Uint8Array {
  if (der[0] !== 0x30 || der[1] !== der.length - 2) throw new Error('not a DER ECDSA signature');
  const ints: bigint[] = [];
  let at = 2;
  for (let i = 0; i < 2; i++) {
    if (der[at] !== 0x02) throw new Error('not a DER ECDSA signature');
    const len = der[at + 1]!;
    let v = 0n;
    for (const b of der.subarray(at + 2, at + 2 + len)) v = (v << 8n) | BigInt(b);
    ints.push(v);
    at += 2 + len;
  }
  if (at !== der.length) throw new Error('not a DER ECDSA signature');
  let [r, s] = ints as [bigint, bigint];
  if (s > P256_N / 2n) s = P256_N - s;
  const out = new Uint8Array(64);
  for (let i = 0; i < 32; i++) {
    out[31 - i] = Number((r >> BigInt(8 * i)) & 0xffn);
    out[63 - i] = Number((s >> BigInt(8 * i)) & 0xffn);
  }
  return out;
}

/** The request body the host accepts (JSON, base64url bytes). */
export function encodeContactRequest(r: ContactRequest): string {
  return JSON.stringify({
    op: r.op,
    account: r.account,
    ...(r.nonce ? { nonce: toBase64Url(r.nonce) } : {}),
    envelope: toBase64Url(r.envelope),
    ...(r.authorization
      ? {
          authorization: {
            public_key: toBase64Url(r.authorization.publicKey),
            authenticator_data: toBase64Url(r.authorization.authenticatorData),
            client_data_json: toBase64Url(r.authorization.clientDataJSON),
            signature: toBase64Url(r.authorization.signature),
          },
        }
      : {}),
  });
}

export function decodeContactRequest(json: string): ContactRequest {
  const b = JSON.parse(json) as Record<string, unknown>;
  if (!['register', 'replace', 'remove', 'push', 'status', 'confirm'].includes(b.op as string)) throw new Error('bad op');
  contractIdFromStrkey(String(b.account));
  const r: ContactRequest = {
    op: b.op as ContactRequest['op'],
    account: String(b.account),
    envelope: fromBase64Url(String(b.envelope)),
  };
  if (b.nonce !== undefined) r.nonce = fromBase64Url(String(b.nonce));
  if (b.authorization !== undefined) {
    const a = b.authorization as Record<string, unknown>;
    r.authorization = {
      publicKey: fromBase64Url(String(a.public_key)),
      authenticatorData: fromBase64Url(String(a.authenticator_data)),
      clientDataJSON: fromBase64Url(String(a.client_data_json)),
      signature: fromBase64Url(String(a.signature)),
    };
  }
  return r;
}

/**
 * Seal `request` and compute the challenge for the passkey; `finish` turns
 * the browser's assertion into the request the host relays.
 */
export async function prepareContactChange(
  vault: VaultKey,
  request: Extract<SealedRequest, { op: ContactOp }>,
  nonce: Uint8Array,
): Promise<{
  challenge: Uint8Array;
  finish(a: { publicKey: Uint8Array; authenticatorData: Uint8Array; clientDataJSON: Uint8Array; signature: Uint8Array }): ContactRequest;
}> {
  const envelope = await sealRequest(vault.publicKey, request);
  const purposes = request.op === 'register' || request.op === 'replace' ? request.purposes : 0;
  const consentVersion = request.op === 'register' || request.op === 'replace' ? request.consentVersion : 0;
  const challenge = await authorizationChallenge({
    op: request.op,
    account: request.account,
    contact: request.contact,
    envelope,
    purposes,
    consentVersion,
    nonce,
  });
  return {
    challenge,
    finish: (a) => ({
      op: request.op,
      account: strkeyFromContractId(request.account),
      nonce,
      envelope,
      authorization: { ...a, signature: rawLowS(a.signature) },
    }),
  };
}

/** A confirmation needs no passkey: the code proves the inbox. */
export async function prepareConfirmation(vault: VaultKey, request: Extract<SealedRequest, { op: 'confirm' }>): Promise<ContactRequest> {
  return { op: 'confirm', account: strkeyFromContractId(request.account), envelope: await sealRequest(vault.publicKey, request) };
}

