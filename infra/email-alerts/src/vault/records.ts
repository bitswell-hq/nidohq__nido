/**
 * What the vault keeps per account, and how it is sealed for the host to
 * store: `nonce(12) || AES-256-GCM(k_store, nonce, CBOR(record), aad)`, with
 * `aad = label || lookup`, so a sealed record cannot be moved to another
 * lookup.
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { PushChannel } from '@nidohq/email-recovery';
import { decode, encode } from 'cborg';

export const RECORD_AAD = 'nido/email-recovery/v1/record';
export const DELIVERIES_AAD = 'nido/email-recovery/v1/deliveries';

/** One device's Web Push subscription for a contact, and its probes (spec §10.3, §10.6). */
export interface PushDevice {
  /** The subscription and the device key that acknowledges probes. */
  channel: PushChannel;
  /** When it was added (ms). */
  addedAt: number;
  /** The push service answered 404/410: the subscription is gone (lapsed). */
  gone?: boolean;
  /** When it was found gone (ms). */
  lapsedAt?: number;
  /** When the device last acknowledged a probe, or was added (ms). */
  ackedAt: number;
  /** When the next probe is due (ms). */
  nextProbeAt: number;
  /** The probe awaiting acknowledgement. */
  probe?: { id: Uint8Array; sentAt: number };
  /** Probes the push service accepted since the device last acknowledged one. */
  unanswered: number;
  /** Two probe intervals went unacknowledged: rule 2 treats it like lapsed until the device acknowledges again. */
  unacknowledged?: boolean;
}

export interface Contact {
  id: Uint8Array;
  address: string;
  /** The devices that receive this contact's push alerts; empty without Web Push. */
  pushes: PushDevice[];
  kCode: Uint8Array;
  emailGuardian: boolean;
  purposes: number;
  consentVersion: number;
  state: 'unconfirmed' | 'active';
  confirm?: { codeHash: Uint8Array; expiresAt: number; attempts: number };
  /** The passkey that authorized this contact. */
  authorizer: Uint8Array;
  createdLedger: number;
}

export interface PendingChange {
  kind: 'replace' | 'remove';
  /** The contact being replaced or removed. */
  target: Uint8Array;
  /** The replacement contact (`replace` only). */
  replacement?: Uint8Array;
  requestedLedger: number;
  /** Close time (Unix seconds) of the latest ledger when the change was requested. */
  requestedAt?: number;
  /** The close time from which the change applies: `requestedAt` plus 14 days. */
  maturesAt?: number;
  /** A ledger number from which the change applies, for a change sealed
   *  without `maturesAt`; such a change keeps maturing by ledger. */
  maturesLedger?: number;
  /** The passkey that authorized the change; re-checked at maturity. */
  authorizer: Uint8Array;
}

export interface AccountRecord {
  account: Uint8Array;
  contacts: Contact[];
  change?: PendingChange;
}

function seal(key: Uint8Array, aad: Uint8Array, value: unknown): Uint8Array {
  const nonce = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, nonce);
  c.setAAD(aad);
  return new Uint8Array(Buffer.concat([nonce, c.update(encode(value, { ignoreUndefinedProperties: true })), c.final(), c.getAuthTag()]));
}

function unseal(key: Uint8Array, aad: Uint8Array, blob: Uint8Array): unknown {
  const d = createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12));
  d.setAAD(aad);
  d.setAuthTag(blob.subarray(blob.length - 16));
  return decode(Buffer.concat([d.update(blob.subarray(12, blob.length - 16)), d.final()]));
}

const aad = (label: string, lookup?: Uint8Array) =>
  lookup ? Buffer.concat([Buffer.from(label), lookup]) : Buffer.from(label);

export const sealRecord = (kStore: Uint8Array, lookup: Uint8Array, r: AccountRecord): Uint8Array =>
  seal(kStore, aad(RECORD_AAD, lookup), r);

export const unsealRecord = (kStore: Uint8Array, lookup: Uint8Array, blob: Uint8Array): AccountRecord =>
  unseal(kStore, aad(RECORD_AAD, lookup), blob) as AccountRecord;

/** Delivery log: `"<event id>|<contact hex>|<channel>"` → ms when sent. */
export type Deliveries = Record<string, number>;

export const sealDeliveries = (kStore: Uint8Array, d: Deliveries): Uint8Array => seal(kStore, aad(DELIVERIES_AAD), d);

export const unsealDeliveries = (kStore: Uint8Array, blob: Uint8Array): Deliveries =>
  unseal(kStore, aad(DELIVERIES_AAD), blob) as Deliveries;
