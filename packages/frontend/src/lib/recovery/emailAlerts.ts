/**
 * The account's alert contact at the alert vault
 * (`docs/email-recovery/spec.md` §10.3): registering the address alerts go
 * to and the Web Push subscription that is the required second channel when
 * email is a recovery factor (§9.3 rule 2), reading which devices receive
 * and confirm it, and adding this device at once. Each request is sealed to
 * the vault's attested key and authorized by this browser's passkey for the
 * account; the alert service's host relays it and never sees the address.
 *
 * With each subscription the wallet's service worker (`public/sw.js`)
 * creates a device key (ECDSA P-256, not extractable, kept in its
 * IndexedDB); the vault stores its public half and accepts a probe
 * acknowledgement only signed by it (§10.6).
 */

import {
  PURPOSE_SECURITY_ALERTS,
  bytes,
  confirmationRequest,
  contactRequest,
  encodeContactRequest,
  prepareConfirmation,
  prepareContactChange,
  pushUpdateRequest,
  statusRequest,
  type ContactOp,
  type PushSubscriptionJSON,
  type SealedRequest,
  type VaultKey,
} from '@nidohq/email-recovery';
import { loadCredential, nidoKey } from '@nidohq/passkey-sdk';
import { requireEmailRecovery } from './emailConfig.js';
import { CONSENT_VERSION, type DeviceChannel, type ThisDevice } from './emailModel.js';

const { fromBase64Url, fromHex, toHex, toBase64Url } = bytes;

export { CONSENT_TEXT, CONSENT_VERSION } from './emailModel.js';

/** Ask the wallet's service worker `message`; its answer on a `MessageChannel`. */
async function askWorker<T>(message: Record<string, unknown>): Promise<T> {
  const reg = await navigator.serviceWorker.ready;
  if (!reg.active) throw new Error('The wallet’s service worker is not running.');
  return new Promise<T>((resolve, reject) => {
    const channel = new MessageChannel();
    const timer = setTimeout(() => reject(new Error('The wallet’s service worker did not answer.')), 10_000);
    channel.port1.onmessage = (e) => {
      clearTimeout(timer);
      const d = e.data as T & { error?: string };
      if (d.error) reject(new Error(d.error));
      else resolve(d);
    };
    reg.active!.postMessage(message, [channel.port2]);
  });
}

/**
 * This device's Web Push subscription for the vault's VAPID key and the
 * device key its service worker made for it (the key is created once per
 * origin and kept; the worker also keeps where to post acknowledgements).
 */
export async function pushSubscription(vapid: Uint8Array): Promise<{ push: PushSubscriptionJSON; deviceKey: Uint8Array }> {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    throw new Error('This browser cannot receive push notifications. On an iPhone, add Nido to your Home Screen first.');
  }
  if ((await Notification.requestPermission()) !== 'granted') throw new Error('Notifications were not allowed.');
  const reg = await navigator.serviceWorker.register('/sw.js', { scope: '/' });
  await navigator.serviceWorker.ready;
  const existing = await reg.pushManager.getSubscription();
  if (existing) await existing.unsubscribe();
  const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: new Uint8Array(vapid) });
  const { deviceKey } = await askWorker<{ deviceKey: string }>({ type: 'nido-device-key', alertService: requireEmailRecovery().alertService });
  return { push: sub.toJSON() as PushSubscriptionJSON, deviceKey: fromBase64Url(deviceKey) };
}

/** A device's id in the vault's `status` answer: hex of the first 8 octets of `sha256(endpoint)`. */
export async function deviceIdOf(endpoint: string): Promise<string> {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(new TextEncoder().encode(endpoint))));
  return toHex(h.subarray(0, 8));
}

/** One contact's channels as the vault reports them (no address). */
export interface ChannelStatus {
  contact: string;
  state: 'unconfirmed' | 'active';
  push: 'live' | 'unacknowledged' | 'lapsed' | 'none';
  devices: DeviceChannel[];
}

/** This device's push registration for an account, kept where the browser registered it. */
interface DeviceRecord {
  endpoint: string;
  contact: string;
}
const deviceKey = (account: string) => nidoKey(`alert-device:${account}`);

export function rememberAlertDevice(account: string, r: DeviceRecord): void {
  try {
    localStorage.setItem(deviceKey(account), JSON.stringify(r));
  } catch {
    /* storage unavailable: the vault's status read still works */
  }
}

/**
 * This device's push registration for the account: `gone` when
 * notifications were turned off or the subscription changed, `live` when it
 * is still there, with when its service worker last acknowledged a probe;
 * `undefined` when this device registered none.
 */
export async function deviceChannel(account: string): Promise<ThisDevice | undefined> {
  let r: DeviceRecord | undefined;
  try {
    const raw = localStorage.getItem(deviceKey(account));
    r = raw ? (JSON.parse(raw) as DeviceRecord) : undefined;
  } catch {
    return undefined;
  }
  if (!r) return undefined;
  const id = await deviceIdOf(r.endpoint);
  if (typeof Notification === 'undefined' || Notification.permission !== 'granted' || !('serviceWorker' in navigator)) return { state: 'gone', id };
  const reg = await navigator.serviceWorker.getRegistration('/');
  const sub = await reg?.pushManager.getSubscription();
  if (sub?.endpoint !== r.endpoint) return { state: 'gone', id };
  const ackedAt = await askWorker<{ ackedAt: number | null }>({ type: 'nido-device-state' }).then((x) => x.ackedAt ?? undefined, () => undefined);
  return { state: 'live', id, ...(ackedAt !== undefined ? { ackedAt } : {}) };
}

async function post(path: string, body: string): Promise<{ ok: boolean; status?: string; error?: string; channels?: ChannelStatus[] }> {
  const res = await fetch(`${requireEmailRecovery().alertService}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
    credentials: 'omit',
  });
  return (await res.json()) as { ok: boolean; status?: string; error?: string; channels?: ChannelStatus[] };
}

/**
 * Register `address` and `push` for `account`, authorized by this browser's
 * passkey. Resolves with the new contact's id; the vault then emails a
 * six-digit confirmation code to the address.
 */
export async function registerAlertContact(p: {
  account: string;
  address: string;
  accountCode: Uint8Array;
  push: PushSubscriptionJSON;
  deviceKey: Uint8Array;
  vault: VaultKey;
}): Promise<Uint8Array> {
  const d = requireEmailRecovery();
  const request = await contactRequest({
    account: p.account,
    address: p.address,
    accountCode: p.accountCode,
    emailGuardian: true,
    push: p.push,
    deviceKey: p.deviceKey,
    purposes: PURPOSE_SECURITY_ALERTS,
    consentVersion: CONSENT_VERSION,
    allowLoopbackPush: d.testOnlyLoopbackPush === true,
  });
  const result = await authorized(p.account, p.vault, request as Extract<SealedRequest, { op: ContactOp }>);
  if (!result.ok) throw new Error(`The alert service refused the contact: ${result.error ?? 'unknown reason'}`);
  rememberAlertDevice(p.account, { endpoint: p.push.endpoint, contact: bytes.toHex(request.contact) });
  return request.contact;
}

/** Seal `request`, have this browser's passkey for `account` authorize it, and post it. */
async function authorized(
  account: string,
  vault: VaultKey,
  request: Extract<SealedRequest, { op: ContactOp }>,
): Promise<{ ok: boolean; status?: string; error?: string; channels?: ChannelStatus[] }> {
  const cred = loadCredential(account);
  if (!cred) throw new Error('This browser has no passkey for this Nido.');
  const d = requireEmailRecovery();
  const nonce = await fetch(`${d.alertService}/v1/nonce`, { method: 'POST', credentials: 'omit' }).then(async (r) => fromBase64Url(((await r.json()) as { nonce: string }).nonce));
  const { challenge, finish } = await prepareContactChange(vault, request, nonce);
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: new Uint8Array(challenge),
      rpId: window.location.hostname,
      allowCredentials: [{ type: 'public-key', id: new Uint8Array(cred.credentialId) }],
      userVerification: 'required',
      timeout: 60_000,
    },
  })) as PublicKeyCredential | null;
  if (!assertion) throw new Error('The passkey prompt was cancelled.');
  const r = assertion.response as AuthenticatorAssertionResponse;
  const req = finish({
    publicKey: fromHex(cred.publicKey),
    authenticatorData: new Uint8Array(r.authenticatorData),
    clientDataJSON: new Uint8Array(r.clientDataJSON),
    signature: new Uint8Array(r.signature),
  });
  return post('/v1/contact', encodeContactRequest(req));
}

/** The account's alert channels, read from the vault with this browser's passkey (spec §10.3 `status`). */
export async function alertChannels(account: string, vault: VaultKey): Promise<ChannelStatus[]> {
  const r = await authorized(account, vault, statusRequest(account) as Extract<SealedRequest, { op: ContactOp }>);
  if (!r.ok || !r.channels) throw new Error(`The alert service did not answer: ${r.error ?? 'unknown reason'}`);
  return r.channels;
}

/**
 * Add this device to contact `contact`'s notifications (spec §10.3 `push`):
 * at once, whatever its other devices do; the address is told.
 */
export async function addThisDevice(account: string, contact: string, vault: VaultKey): Promise<void> {
  const { push, deviceKey } = await pushSubscription(vault.vapid);
  const request = pushUpdateRequest(account, bytes.fromHex(contact), push, deviceKey, { allowLoopbackPush: requireEmailRecovery().testOnlyLoopbackPush === true });
  const r = await authorized(account, vault, request as Extract<SealedRequest, { op: ContactOp }>);
  if (!r.ok) throw new Error(`The alert service refused: ${r.error ?? 'unknown reason'}`);
  rememberAlertDevice(account, { endpoint: push.endpoint, contact });
}

/** Confirm the contact with the code the vault emailed it. */
export async function confirmAlertContact(p: { account: string; contact: Uint8Array; code: string; vault: VaultKey }): Promise<void> {
  const sealed = confirmationRequest(p.account, p.contact, p.code.replace(/\s+/g, '')) as Extract<SealedRequest, { op: 'confirm' }>;
  const req = await prepareConfirmation(p.vault, sealed);
  const result = await post('/v1/contact', encodeContactRequest(req));
  if (!result.ok || result.status !== 'confirmed') throw new Error(`The code was not accepted: ${result.error ?? result.status ?? 'unknown reason'}`);
}

export { toBase64Url };
