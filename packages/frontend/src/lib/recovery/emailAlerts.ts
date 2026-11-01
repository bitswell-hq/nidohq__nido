/**
 * Registering the account's alert contact with the alert vault
 * (`docs/email-recovery/spec.md` §10.3): the address alerts go to and the
 * Web Push subscription that is the required second channel when email is
 * a recovery factor (§9.3 rule 2). The request is sealed to the vault's
 * attested key and authorized by this browser's passkey for the account;
 * the alert service's host relays it and never sees the address.
 */

import {
  PURPOSE_SECURITY_ALERTS,
  bytes,
  confirmationRequest,
  contactRequest,
  encodeContactRequest,
  prepareConfirmation,
  prepareContactChange,
  type PushSubscriptionJSON,
  type SealedRequest,
  type VaultKey,
} from '@nidohq/email-recovery';
import { loadCredential } from '@nidohq/passkey-sdk';
import { requireEmailRecovery } from './emailConfig.js';

const { fromBase64Url, fromHex, toBase64Url } = bytes;

/** The version of the consent text below; the vault records which one the user saw. */
export const CONSENT_VERSION = 1;
export const CONSENT_TEXT =
  'Nido will email this address and send a notification to this device whenever your Nido’s recovery changes: ' +
  'when someone starts or completes a recovery, or when its settings change. Alerts carry a six-digit code and ' +
  'never name your Nido or contain a link.';

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

async function post(path: string, body: string): Promise<{ ok: boolean; status?: string; error?: string }> {
  const res = await fetch(`${requireEmailRecovery().alertService}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
    credentials: 'omit',
  });
  return (await res.json()) as { ok: boolean; status?: string; error?: string };
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
  const cred = loadCredential(p.account);
  if (!cred) throw new Error('This browser has no passkey for this Nido.');
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
  if (request.op === 'remove' || request.op === 'confirm') throw new Error('unreachable');
  const nonce = await fetch(`${d.alertService}/v1/nonce`, { method: 'POST', credentials: 'omit' }).then(async (r) => fromBase64Url(((await r.json()) as { nonce: string }).nonce));
  const { challenge, finish } = await prepareContactChange(p.vault, request, nonce);
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: new Uint8Array(challenge),
      rpId: location.hostname,
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
  const result = await post('/v1/contact', encodeContactRequest(req));
  if (!result.ok) throw new Error(`The alert service refused the contact: ${result.error ?? 'unknown reason'}`);
  return request.contact;
}

/** Confirm the contact with the code the vault emailed it. */
export async function confirmAlertContact(p: { account: string; contact: Uint8Array; code: string; vault: VaultKey }): Promise<void> {
  const sealed = confirmationRequest(p.account, p.contact, p.code.replace(/\s+/g, '')) as Extract<SealedRequest, { op: 'confirm' }>;
  const req = await prepareConfirmation(p.vault, sealed);
  const result = await post('/v1/contact', encodeContactRequest(req));
  if (!result.ok || result.status !== 'confirmed') throw new Error(`The code was not accepted: ${result.error ?? result.status ?? 'unknown reason'}`);
}

export { toBase64Url };
