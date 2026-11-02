/**
 * The account's alert contact at the alert vault
 * (`docs/email-recovery/spec.md` §10.3): registering the address alerts go
 * to and the Web Push subscription that is the required second channel when
 * email is a recovery factor (§9.3 rule 2), reading whether that channel
 * still works, and moving a lapsed one to this device. Each request is
 * sealed to the vault's attested key and authorized by this browser's
 * passkey for the account; the alert service's host relays it and never
 * sees the address.
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

const { fromBase64Url, fromHex, toBase64Url } = bytes;

/** The version of the consent text below; the vault records which one the user saw. */
export const CONSENT_VERSION = 2;
export const CONSENT_TEXT =
  'Nido will email this address and send a notification to this device whenever your Nido’s recovery needs your attention: ' +
  'when a recovery is approved or completes, when your recovery email approves one, or when the recovery settings change. ' +
  'Alerts carry a six-digit code and never name your Nido or contain a link. Recovery attempts that are only opened, ' +
  'which anyone can do, show in your wallet instead. About once a week this device shows a quiet notification that ' +
  'notifications still work.';

/** This device's Web Push subscription for the vault's VAPID key, through the wallet's service worker. */
export async function pushSubscription(vapid: Uint8Array): Promise<PushSubscriptionJSON> {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    throw new Error('This browser cannot receive push notifications. On an iPhone, add Nido to your Home Screen first.');
  }
  if ((await Notification.requestPermission()) !== 'granted') throw new Error('Notifications were not allowed.');
  const reg = await navigator.serviceWorker.register('/sw.js', { scope: '/' });
  await navigator.serviceWorker.ready;
  const existing = await reg.pushManager.getSubscription();
  if (existing) await existing.unsubscribe();
  const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: new Uint8Array(vapid) });
  return sub.toJSON() as PushSubscriptionJSON;
}

/** One contact's channels as the vault reports them (no address). */
export interface ChannelStatus {
  contact: string;
  state: 'unconfirmed' | 'active';
  push: 'live' | 'lapsed' | 'none';
  lapsedAt?: number;
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
 * Whether this device still holds the subscription it registered for the
 * account: `gone` when notifications were turned off or the subscription
 * changed, `live` when it is still there, `undefined` when this device
 * registered none (another device holds the account's notifications).
 */
export async function deviceChannel(account: string): Promise<'live' | 'gone' | undefined> {
  let r: DeviceRecord | undefined;
  try {
    const raw = localStorage.getItem(deviceKey(account));
    r = raw ? (JSON.parse(raw) as DeviceRecord) : undefined;
  } catch {
    return undefined;
  }
  if (!r) return undefined;
  if (typeof Notification === 'undefined' || Notification.permission !== 'granted' || !('serviceWorker' in navigator)) return 'gone';
  const reg = await navigator.serviceWorker.getRegistration('/');
  const sub = await reg?.pushManager.getSubscription();
  return sub?.endpoint === r.endpoint ? 'live' : 'gone';
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
  vault: VaultKey;
}): Promise<Uint8Array> {
  const d = requireEmailRecovery();
  const request = await contactRequest({
    account: p.account,
    address: p.address,
    accountCode: p.accountCode,
    emailGuardian: true,
    push: p.push,
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
 * Move contact `contact`'s notifications to this device (spec §10.3 `push`).
 * The vault applies it only when the current subscription is gone.
 */
export async function moveNotificationsHere(account: string, contact: string, vault: VaultKey): Promise<void> {
  const push = await pushSubscription(vault.vapid);
  const request = pushUpdateRequest(account, bytes.fromHex(contact), push, { allowLoopbackPush: requireEmailRecovery().testOnlyLoopbackPush === true });
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
