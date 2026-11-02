/**
 * The enclave application (`docs/email-recovery/spec.md` §10.2-§10.6): the
 * only code that ever holds a plaintext address.
 *
 * It answers the host's requests and returns, with each answer, the sealed
 * blobs the host must persist (`writes`). It reaches custodians, the
 * sending services, and push services itself (in production through the
 * enclave's vsock proxy, with TLS terminating inside the enclave). The host
 * never receives an address, a push subscription, `k_code`, `k_alert`, or a
 * verification code.
 */
import { createHash, createPublicKey, randomBytes, randomInt, timingSafeEqual, verify } from 'node:crypto';
import {
  type AlertSubject,
  type ContactRequest,
  MANY_OPEN_ATTEMPTS,
  type PushChannel,
  type SealedRequest,
  alertCode,
  authorizationChallenge,
  bytes,
  contractIdFromStrkey,
  encodeVaultUserData,
  openRequest,
  probeAckMessage,
  spkiFromRawPublicKey,
  strkeyFromContractId,
} from '@nidohq/email-recovery';
import type { AlertClass, AlertName } from '../events.js';
import {
  alertText,
  confirmationText,
  contactChangeNotice,
  pushAddedNotice,
  pushLapsedNotice,
  pushUnconfirmedNotice,
  type AlertText,
} from './content.js';
import { type CustodianEndpoint, type Nsm, genesis, restore } from './custody.js';
import { InboundBox, type InboundResult } from './inbound.js';
import { alertLookup, type VaultKeys } from './keys.js';
import {
  type AccountRecord,
  type Contact,
  type Deliveries,
  type PendingChange,
  type PushDevice,
  sealDeliveries,
  sealRecord,
  unsealDeliveries,
  unsealRecord,
} from './records.js';
import { type SendingConfig, sendEmail } from './send.js';
import { type RelyingParty, checkAuthorization, relyingPartyFor } from './webauthn.js';
import { type PushOutcome, pushMessage } from './webpush.js';

const { equal, toHex, fromHex, toBase64Url } = bytes;

/** Replacing or removing a contact waits this long, in seconds of ledger
 *  close time: 14 days, whatever the network's target ledger close time. */
export const CONTACT_CHANGE_DELAY_SECONDS = 14 * 86_400;
export const CONFIRMATION_TTL_MS = 72 * 3600_000;
export const CONFIRMATION_ATTEMPTS = 5;
export const NONCE_TTL_MS = 10 * 60_000;
const DELIVERY_LOG_RETENTION_MS = 30 * 24 * 3600_000;
/**
 * How often each push subscription is probed (spec §10.6): the default of
 * `VaultConfig.probeIntervalMs`, 30 days. Each probe shows one notification
 * that asks to be tapped; a longer interval shows fewer of them and finds
 * an unreachable device later.
 */
export const PROBE_INTERVAL_MS = 30 * 24 * 3600_000;
/** After a probe the push service could not answer, the next one is due this much later. */
export const PROBE_RETRY_MS = 3600_000;
/**
 * A subscription whose device acknowledged none of this many probes, each
 * given a full interval, is unacknowledged: rule 2 treats it like lapsed
 * until the device acknowledges again.
 */
export const ACK_MISSED_PROBES = 2;
/** Devices one contact's push alerts go to at most. */
export const MAX_PUSH_DEVICES = 4;
/** `attempts_many` goes to an account at most once in this long. */
export const MANY_ALERT_EVERY_MS = 24 * 3600_000;

export interface VaultConfig {
  /** `sha256(network passphrase)`. */
  networkId: Uint8Array;
  rp: RelyingParty;
  /** The wallet's canonical origin, named in alert texts. */
  walletOrigin: string;
  sending: SendingConfig;
  /** VAPID `sub` claim, e.g. `mailto:alerts@nido.fyi`. */
  pushSubject: string;
  /** How often each push subscription is probed (default [`PROBE_INTERVAL_MS`], 30 days). */
  probeIntervalMs?: number;
  /** Accept `http://127.0.0.1` push endpoints (local test push services only). */
  allowLoopbackPush?: boolean;
  custodians: CustodianEndpoint[];
}

/** Chain state the host relays for one account (spec §10.3). */
export interface ChainView {
  ledger: number;
  /** The latest ledger's close time, Unix seconds: the clock contact changes mature on. */
  closeTime: number;
  /** P-256 keys (uncompressed) of the account's passkey signers. */
  signers: Uint8Array[];
  /** Whether a recovery attempt is authorized for the account. */
  authorized: boolean;
}

/** Where the chain is: the latest ledger and its close time (Unix seconds). */
export type ChainTime = Pick<ChainView, 'ledger' | 'closeTime'>;

/** A pending change is due once the close time reaches `maturesAt`. A change
 *  sealed with only `maturesLedger` (a ledger number) is due once that
 *  ledger has closed. */
export function changeDue(ch: PendingChange, at: ChainTime): boolean {
  if (ch.maturesAt !== undefined) return ch.maturesAt <= at.closeTime;
  return ch.maturesLedger !== undefined && ch.maturesLedger <= at.ledger;
}

/** Sealed blobs to persist: lookup hex → record (or `null` to delete), and the delivery log. */
export interface Writes {
  records?: Record<string, Uint8Array | null>;
  deliveries?: Uint8Array;
}

export interface SealedState {
  records: Record<string, Uint8Array>;
  deliveries?: Uint8Array;
}

export interface DispatchRequest {
  eventId: string;
  name: AlertName;
  class: Exclude<AlertClass, 'none'>;
  controller: Uint8Array;
  account: Uint8Array;
  subject: AlertSubject;
  /** For rate-limited events: how many were suppressed since the last one sent. */
  suppressed?: number;
  /**
   * For `attempt_begun`: the attempt's evidence deadline and the latest
   * ledger, which the host read, so the vault counts it while it is open.
   */
  open?: { until: number; ledger: number };
}

/** A push device's state: `live`, `unacknowledged` (two probe intervals without a tap), or `lapsed` (the push service answered 404 or 410). */
export type DeviceState = 'live' | 'unacknowledged' | 'lapsed';

/** One contact's channels, as a `status` read answers (no address: the host relays the answer). */
export interface ChannelStatus {
  /** The contact id, hex. */
  contact: string;
  state: 'unconfirmed' | 'active';
  /** The best of its devices: `live` when any is, then `unacknowledged`, then `lapsed`; `none` without one. */
  push: DeviceState | 'none';
  /** Each device: `id` is hex of the first 8 octets of `sha256(endpoint)`, which the device computes for itself. */
  devices: { id: string; state: DeviceState; addedAt: number; ackedAt: number; lapsedAt?: number }[];
  /** A pending replacement or removal of this contact: from when it applies, a
   *  close time (`maturesAt`), or a ledger number for a change sealed with
   *  only `maturesLedger`. */
  change?: { kind: 'replace' | 'remove'; maturesAt?: number; maturesLedger?: number };
}

export type ContactResult =
  | { ok: true; status: 'pending-confirmation' | 'change-pending' | 'confirmed' | 'push-added'; maturesAt?: number }
  | { ok: true; status: 'channels'; channels: ChannelStatus[] }
  | { ok: false; error: string };

export class ContactRefused extends Error {}

const sha256 = (b: Uint8Array | string) => new Uint8Array(createHash('sha256').update(b).digest());

/** A device's id in a `status` answer: hex of the first 8 octets of `sha256(endpoint)`. */
export const deviceId = (endpoint: string): string => toHex(sha256(endpoint).subarray(0, 8));

function deviceState(d: PushDevice): DeviceState {
  return d.gone ? 'lapsed' : d.unacknowledged ? 'unacknowledged' : 'live';
}

/** Whether a device key signed the acknowledgement of probe `probeId`. */
function acknowledged(deviceKey: Uint8Array, probeId: Uint8Array, signature: Uint8Array): boolean {
  if (signature.length !== 64) return false;
  const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');
  const key = createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: b64u(deviceKey.subarray(1, 33)), y: b64u(deviceKey.subarray(33, 65)) },
    format: 'jwk',
  });
  return verify('sha256', probeAckMessage(probeId), { key, dsaEncoding: 'ieee-p1363' }, signature);
}

export class Vault {
  private readonly records = new Map<string, AccountRecord>();
  private deliveries: Deliveries = {};
  private readonly nonces = new Map<string, number>();
  /** Outstanding probe id (hex) → the lookup of the record holding it. */
  private readonly probes = new Map<string, string>();
  private readonly inboundBox: InboundBox;

  private constructor(
    private readonly cfg: VaultConfig,
    private readonly nsm: Nsm,
    readonly keys: VaultKeys,
    private readonly fetchImpl: typeof fetch,
    private readonly now: () => number,
  ) {
    this.inboundBox = new InboundBox(keys.hpke, now);
  }

  /** A browser's sealed registration for the email its Subject value names (spec §4.6). */
  inbound(envelope: Uint8Array): Promise<InboundResult> {
    return this.inboundBox.register(envelope);
  }

  /**
   * Mail the MX received for `RECOVERY_INBOX` (inside the enclave): the
   * sealed copies to store, by inbox id.
   */
  mail(raw: Uint8Array): Promise<Record<string, Uint8Array>> {
    return this.inboundBox.deliver(raw);
  }

  /**
   * Start the vault: create `K` (no `vaultId`) or recover it from the
   * custodians, then open the host's sealed state.
   */
  static async boot(opts: {
    cfg: VaultConfig;
    nsm: Nsm;
    vaultId?: Uint8Array;
    state?: SealedState;
    fetch?: typeof fetch;
    now?: () => number;
  }): Promise<Vault> {
    const f = opts.fetch ?? fetch;
    const keys = opts.vaultId
      ? (await restore(opts.nsm, opts.cfg.custodians, opts.vaultId, f)).keys
      : await genesis(opts.nsm, opts.cfg.custodians, f);
    const v = new Vault(opts.cfg, opts.nsm, keys, f, opts.now ?? Date.now);
    for (const [lookup, blob] of Object.entries(opts.state?.records ?? {})) {
      const r = unsealRecord(keys.kStore, fromHex(lookup), blob);
      v.records.set(lookup, r);
      for (const c of r.contacts) for (const d of c.pushes) if (d.probe) v.probes.set(toHex(d.probe.id), lookup);
    }
    if (opts.state?.deliveries) v.deliveries = unsealDeliveries(keys.kStore, opts.state.deliveries);
    return v;
  }

  get vaultId(): Uint8Array {
    return this.keys.vaultId;
  }

  /** A vault attestation for a wallet's `nonce`: the HPKE key and the VAPID key, attested. */
  async attest(nonce: Uint8Array): Promise<Uint8Array> {
    if (nonce.length < 16 || nonce.length > 64) throw new Error('nonce must be 16 to 64 bytes');
    return this.nsm.attest({
      nonce,
      publicKey: await spkiFromRawPublicKey(this.keys.hpkePublic),
      userData: encodeVaultUserData({ purpose: 'nido-alert-vault/v1', vapid: this.keys.vapidPublic }),
    });
  }

  /** A single-use nonce a contact change must sign. */
  issueNonce(): Uint8Array {
    const n = new Uint8Array(randomBytes(32));
    const now = this.now();
    for (const [k, exp] of this.nonces) if (exp < now) this.nonces.delete(k);
    this.nonces.set(toHex(n), now + NONCE_TTL_MS);
    return n;
  }

  private takeNonce(n: Uint8Array | undefined): void {
    const exp = n ? this.nonces.get(toHex(n)) : undefined;
    if (!n || exp === undefined || exp < this.now()) throw new ContactRefused('unknown, used, or expired nonce');
    this.nonces.delete(toHex(n));
  }

  private async lookup(account: Uint8Array): Promise<string> {
    return toHex(await alertLookup(this.keys.kAlert, account));
  }

  private async write(account: Uint8Array, record: AccountRecord | undefined, w: Writes): Promise<void> {
    const lookup = await this.lookup(account);
    w.records ??= {};
    if (record) {
      this.records.set(lookup, record);
      w.records[lookup] = sealRecord(this.keys.kStore, fromHex(lookup), record);
    } else {
      this.records.delete(lookup);
      w.records[lookup] = null;
    }
  }

  /** Register, replace, remove, or confirm a contact. */
  async contact(req: ContactRequest, chain: ChainView): Promise<{ result: ContactResult; writes: Writes }> {
    const writes: Writes = {};
    try {
      const status = await this.contactInner(req, chain, writes);
      return { result: { ok: true, ...status } as ContactResult, writes };
    } catch (e) {
      if (e instanceof ContactRefused) return { result: { ok: false, error: e.message }, writes: {} };
      throw e;
    }
  }

  private async contactInner(
    req: ContactRequest,
    chain: ChainView,
    writes: Writes,
  ): Promise<
    | { status: 'pending-confirmation' | 'change-pending' | 'confirmed' | 'push-added'; maturesAt?: number }
    | { status: 'channels'; channels: ChannelStatus[] }
  > {
    const account = contractIdFromStrkey(req.account);
    let inner: SealedRequest;
    try {
      inner = await openRequest(this.keys.hpke, req.envelope);
    } catch {
      throw new ContactRefused('envelope does not open');
    }
    if (inner.op !== req.op || !equal(inner.account, account)) throw new ContactRefused('envelope does not match the request');
    const record = this.records.get(await this.lookup(account));

    if (inner.op === 'confirm') return this.confirm(record, inner.contact, inner.code, writes);

    this.takeNonce(req.nonce);
    if (!req.authorization) throw new ContactRefused('an account passkey must authorize the change');
    const purposes = inner.op === 'register' || inner.op === 'replace' ? inner.purposes : 0;
    const consentVersion = inner.op === 'register' || inner.op === 'replace' ? inner.consentVersion : 0;
    const challenge = await authorizationChallenge({
      op: inner.op,
      account,
      contact: inner.contact,
      envelope: req.envelope,
      purposes,
      consentVersion,
      nonce: req.nonce!,
    });
    try {
      await checkAuthorization(req.authorization, challenge, chain.signers, relyingPartyFor(this.cfg.rp, req.account));
    } catch (e) {
      throw new ContactRefused((e as Error).message);
    }
    const authorizer = req.authorization.publicKey;

    if (inner.op === 'status') return { status: 'channels', channels: channelStatus(record) };
    if (inner.op === 'push') return this.addPush(record, inner.contact, inner.push, writes);

    if (inner.op === 'remove') {
      const target = record?.contacts.find((c) => equal(c.id, inner.contact) && c.state === 'active');
      if (!record || !target) throw new ContactRefused('no such active contact');
      if (record.change) throw new ContactRefused('another change is pending');
      if (chain.authorized) throw new ContactRefused('removal is refused while a recovery attempt is authorized');
      const maturesAt = chain.closeTime + CONTACT_CHANGE_DELAY_SECONDS;
      await this.notifyChange(record, 'remove');
      record.change = { kind: 'remove', target: inner.contact, requestedLedger: chain.ledger, requestedAt: chain.closeTime, maturesAt, authorizer };
      await this.write(account, record, writes);
      return { status: 'change-pending', maturesAt };
    }

    if (inner.emailGuardian && !inner.push) {
      throw new ContactRefused('an account with an email guardian needs a Web Push channel as well');
    }
    if (inner.push) this.checkEndpoint(inner.push);
    if (!(inner.purposes & 1)) throw new ContactRefused('security alerts are always a purpose');
    const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
    const contact: Contact = {
      id: inner.contact,
      address: inner.address,
      // The browser created the subscription for this request: it is live now.
      pushes: inner.push ? [this.newDevice(inner.push)] : [],
      kCode: inner.kCode,
      emailGuardian: inner.emailGuardian,
      purposes: inner.purposes,
      consentVersion: inner.consentVersion,
      state: 'unconfirmed',
      confirm: { codeHash: sha256(code), expiresAt: this.now() + CONFIRMATION_TTL_MS, attempts: 0 },
      authorizer,
      createdLedger: chain.ledger,
    };

    if (inner.op === 'register') {
      const live = record?.contacts.some((c) => c.state === 'active' || (c.confirm?.expiresAt ?? 0) > this.now());
      if (record && live) throw new ContactRefused('the account already has alert contacts; replace them instead');
      await this.sendConfirmation(contact, code, inner.contact);
      await this.write(account, { account, contacts: [contact] }, writes);
      return { status: 'pending-confirmation' };
    }

    // replace
    if (!record) throw new ContactRefused('the account has no alert contacts to replace');
    if (record.change) throw new ContactRefused('another change is pending');
    if (!record.contacts.some((c) => equal(c.id, inner.replaces!) && c.state === 'active')) {
      throw new ContactRefused('no such active contact to replace');
    }
    if (record.contacts.some((c) => equal(c.id, inner.contact))) throw new ContactRefused('contact id in use');
    const maturesAt = chain.closeTime + CONTACT_CHANGE_DELAY_SECONDS;
    await this.notifyChange(record, 'replace');
    await this.sendConfirmation(contact, code, inner.contact);
    record.contacts.push(contact);
    record.change = {
      kind: 'replace',
      target: inner.replaces!,
      replacement: inner.contact,
      requestedLedger: chain.ledger,
      requestedAt: chain.closeTime,
      maturesAt,
      authorizer,
    };
    await this.write(account, record, writes);
    return { status: 'change-pending', maturesAt };
  }

  private async confirm(record: AccountRecord | undefined, id: Uint8Array, code: string, writes: Writes) {
    const c = record?.contacts.find((x) => equal(x.id, id));
    if (!record || !c || c.state !== 'unconfirmed' || !c.confirm) throw new ContactRefused('nothing to confirm');
    if (c.confirm.expiresAt < this.now()) throw new ContactRefused('confirmation code expired');
    if (c.confirm.attempts >= CONFIRMATION_ATTEMPTS) throw new ContactRefused('too many attempts');
    if (!timingSafeEqual(sha256(code), c.confirm.codeHash)) {
      c.confirm.attempts++;
      await this.write(record.account, record, writes);
      throw new ContactRefused('wrong confirmation code');
    }
    c.state = 'active';
    delete c.confirm;
    await this.write(record.account, record, writes);
    return { status: 'confirmed' as const };
  }

  private async sendConfirmation(c: Contact, code: string, id: Uint8Array): Promise<void> {
    const t = confirmationText(code, this.cfg.walletOrigin);
    const r = await sendEmail(
      this.cfg.sending,
      { to: c.address, subject: t.subject, text: t.body, idempotencyKey: toHex(sha256(`confirm|${toHex(id)}|${code}`)) },
      this.fetchImpl,
    );
    if (!r.provider) throw new ContactRefused('the confirmation email could not be sent');
  }

  /** Tell every active contact, on every channel, that a change was requested. */
  private async notifyChange(record: AccountRecord, kind: 'replace' | 'remove'): Promise<void> {
    const t = contactChangeNotice(kind, this.cfg.walletOrigin);
    const key = toHex(sha256(`change|${toHex(record.account)}|${randomBytes(8).toString('hex')}`));
    for (const c of record.contacts.filter((x) => x.state === 'active')) {
      const sent = await sendEmail(this.cfg.sending, { to: c.address, subject: t.subject, text: t.body, idempotencyKey: key }, this.fetchImpl);
      if (!sent.provider) throw new ContactRefused('the existing contact could not be notified');
      await this.pushAll(c, t, { kind: 'contact_change', code: '' }, key);
    }
  }

  private checkEndpoint(push: PushChannel): void {
    const loopback = this.cfg.allowLoopbackPush && push.endpoint.startsWith('http://127.0.0.1:');
    if (!push.endpoint.startsWith('https://') && !loopback) throw new ContactRefused('push endpoint must be https');
  }

  /** A device the owner's browser subscribed just now: live, acknowledged, first probe one interval away. */
  private newDevice(channel: PushChannel): PushDevice {
    const now = this.now();
    return { channel, addedAt: now, ackedAt: now, nextProbeAt: now + (this.cfg.probeIntervalMs ?? PROBE_INTERVAL_MS), unanswered: 0 };
  }

  /** A push to every device of `c` whose subscription is not gone. */
  private async pushAll(c: Contact, t: AlertText, extra: { kind: string; code: string }, topicSeed: string): Promise<void> {
    for (const d of c.pushes) if (!d.gone) await this.push(c, d, t, extra, topicSeed);
  }

  private async push(c: Contact, d: PushDevice, t: AlertText, extra: { kind: string; code: string }, topicSeed: string): Promise<PushOutcome> {
    const payload = new TextEncoder().encode(JSON.stringify({ v: 1, kind: extra.kind, title: t.title, body: t.push, code: extra.code }));
    const outcome = await this.send(d, payload, { ttl: 7 * 86_400, urgency: 'high', topic: toBase64Url(sha256(topicSeed).subarray(0, 24)) });
    if (outcome === 'gone') await this.lapse(c, d, true);
    return outcome;
  }

  /** One push to device `d`. */
  private async send(d: PushDevice, payload: Uint8Array, o: { ttl: number; urgency: string; topic: string }): Promise<PushOutcome> {
    const r = await pushMessage(
      d.channel,
      payload,
      { vapid: { privateKey: this.keys.vapidPrivate, publicKey: this.keys.vapidPublic }, subject: this.cfg.pushSubject, ...o },
      this.fetchImpl,
    );
    return r.outcome;
  }

  /**
   * The liveness probe (spec §10.6): an RFC 8030 push kept a week for a
   * device that is offline (`TTL`), `Urgency: low`, and one `Topic`, so a
   * newer probe replaces an undelivered one, carrying a fresh 16-octet probe
   * id. The service worker shows a
   * notification that asks to be tapped (WebKit revokes a subscription whose
   * pushes show nothing); a tap posts the id signed by the device key
   * ([`ack`]).
   */
  private probeOne(d: PushDevice, lookup: string): Promise<PushOutcome> {
    if (d.probe) this.probes.delete(toHex(d.probe.id));
    const id = new Uint8Array(randomBytes(16));
    d.probe = { id, sentAt: this.now() };
    this.probes.set(toHex(id), lookup);
    const payload = new TextEncoder().encode(JSON.stringify({ v: 1, kind: 'probe', probe: toBase64Url(id) }));
    return this.send(d, payload, { ttl: 7 * 86_400, urgency: 'low', topic: 'probe' });
  }

  /** Device `d`'s subscription is gone: mark it, and tell the contact's address once. */
  private async lapse(c: Contact, d: PushDevice, notify: boolean): Promise<void> {
    if (d.gone) return;
    d.gone = true;
    d.lapsedAt = this.now();
    if (d.probe) this.probes.delete(toHex(d.probe.id));
    delete d.probe;
    if (!notify) return;
    const t = pushLapsedNotice(this.cfg.walletOrigin);
    const key = toHex(sha256(`lapsed|${toHex(c.id)}|${d.channel.endpoint}`));
    await sendEmail(this.cfg.sending, { to: c.address, subject: t.subject, text: t.body, idempotencyKey: key }, this.fetchImpl);
  }

  /**
   * `push`: add this device's subscription to an existing contact, at once
   * (spec §10.3 rule 8). Adding a device cannot take alerts away from the
   * owner, and whoever holds an administrative passkey controls the account
   * anyway; only replacing or removing the contact waits 14 days. A device
   * already listed (the same endpoint) gets its new keys. Lapsed devices
   * make room first; past [`MAX_PUSH_DEVICES`] the request is refused. The
   * address is told.
   */
  private async addPush(
    record: AccountRecord | undefined,
    id: Uint8Array,
    push: PushChannel,
    writes: Writes,
  ): Promise<{ status: 'push-added' }> {
    const c = record?.contacts.find((x) => equal(x.id, id));
    if (!record || !c) throw new ContactRefused('no such contact');
    this.checkEndpoint(push);
    const device = this.newDevice(push);
    const same = c.pushes.findIndex((d) => d.channel.endpoint === push.endpoint);
    for (const d of same >= 0 ? [c.pushes[same]!] : []) if (d.probe) this.probes.delete(toHex(d.probe.id));
    if (same >= 0) c.pushes[same] = device;
    else {
      if (c.pushes.length >= MAX_PUSH_DEVICES) c.pushes = c.pushes.filter((d) => !d.gone);
      if (c.pushes.length >= MAX_PUSH_DEVICES) {
        throw new ContactRefused(`this alert contact already has ${MAX_PUSH_DEVICES} devices; replace the contact to start over`);
      }
      c.pushes.push(device);
    }
    const t = pushAddedNotice(this.cfg.walletOrigin);
    await sendEmail(
      this.cfg.sending,
      { to: c.address, subject: t.subject, text: t.body, idempotencyKey: toHex(sha256(`added|${toHex(c.id)}|${push.endpoint}`)) },
      this.fetchImpl,
    );
    await this.write(record.account, record, writes);
    return { status: 'push-added' };
  }

  /**
   * A device's acknowledgement of probe `probeId` (spec §10.6): its device
   * key's signature over [`probeAckMessage`]. Single use. It makes the
   * device acknowledged again. The host relays it and learns nothing but
   * that some probe was acknowledged.
   */
  async ack(probeId: Uint8Array, signature: Uint8Array): Promise<{ ok: boolean; writes: Writes }> {
    const writes: Writes = {};
    const lookup = probeId.length === 16 ? this.probes.get(toHex(probeId)) : undefined;
    const r = lookup ? this.records.get(lookup) : undefined;
    const d = r?.contacts.flatMap((c) => c.pushes).find((x) => x.probe && equal(x.probe.id, probeId));
    if (!r || !d || !acknowledged(d.channel.deviceKey, probeId, signature)) return { ok: false, writes };
    this.probes.delete(toHex(probeId));
    delete d.probe;
    d.ackedAt = this.now();
    d.unanswered = 0;
    delete d.unacknowledged;
    await this.write(r.account, r, writes);
    return { ok: true, writes };
  }

  /**
   * Probe every active device whose probe is due. A 404 or 410 marks it
   * lapsed and emails the contact; a device that acknowledged none of
   * [`ACK_MISSED_PROBES`] probes the push service accepted is marked
   * unacknowledged, and the contact emailed once (spec §10.6). Counts only:
   * the host learns no account.
   */
  async probe(): Promise<{ probed: number; lapsed: number; unacknowledged: number; writes: Writes }> {
    const writes: Writes = {};
    const out = { probed: 0, lapsed: 0, unacknowledged: 0 };
    const now = this.now();
    const interval = this.cfg.probeIntervalMs ?? PROBE_INTERVAL_MS;
    for (const [lookup, r] of [...this.records.entries()]) {
      let changed = false;
      for (const c of r.contacts) {
        if (c.state !== 'active') continue;
        for (const d of c.pushes) {
          if (d.gone || now < d.nextProbeAt) continue;
          changed = true;
          if (d.unanswered >= ACK_MISSED_PROBES && !d.unacknowledged) {
            d.unacknowledged = true;
            out.unacknowledged++;
            const t = pushUnconfirmedNotice(this.cfg.walletOrigin);
            const key = toHex(sha256(`unacknowledged|${toHex(c.id)}|${d.channel.endpoint}|${d.ackedAt}`));
            await sendEmail(this.cfg.sending, { to: c.address, subject: t.subject, text: t.body, idempotencyKey: key }, this.fetchImpl);
          }
          out.probed++;
          const outcome = await this.probeOne(d, lookup);
          if (outcome === 'gone') {
            await this.lapse(c, d, true);
            out.lapsed++;
          } else if (outcome === 'retry') d.nextProbeAt = now + PROBE_RETRY_MS;
          else {
            d.unanswered++;
            d.nextProbeAt = now + interval;
          }
        }
      }
      if (changed) await this.write(r.account, r, writes);
    }
    return { ...out, writes };
  }

  /** Accounts with an active contact, for the host to reconcile from controller state (spec §10.2). */
  accounts(): string[] {
    return [...this.records.values()]
      .filter((r) => r.contacts.some((c) => c.state === 'active'))
      .map((r) => strkeyFromContractId(r.account));
  }

  /**
   * Count an open attempt (`attempt_begun`, or one reconciliation found)
   * among the account's; whether more than `MANY_OPEN_ATTEMPTS` are open
   * at `open.ledger`.
   */
  private count(r: AccountRecord, attemptId: string, open: { until: number; ledger: number }): boolean {
    const list = (r.open ?? []).filter((a) => a.until >= open.ledger && a.attemptId !== attemptId);
    if (open.until >= open.ledger) list.push({ attemptId, until: open.until });
    list.sort((a, b) => b.until - a.until);
    r.open = list.slice(0, MANY_OPEN_ATTEMPTS + 1);
    if (!r.open.length) delete r.open;
    return (r.open?.length ?? 0) > MANY_OPEN_ATTEMPTS;
  }

  /**
   * Send the alert for one event to every active contact of its account:
   * email always, Web Push to every device too for required alerts. Each
   * (event, contact, channel) is sent at most once (the sealed delivery
   * log); a failed channel makes the answer `retry`, and only that channel
   * is tried again. A counted attempt (`attempt_begun` with `open`) sends
   * nothing itself; while more than `MANY_OPEN_ATTEMPTS` are open it sends
   * `attempts_many`, under one delivery id per account and
   * [`MANY_ALERT_EVERY_MS`] window, so at most once per window.
   */
  async dispatch(ev: DispatchRequest): Promise<{ status: 'done' | 'retry'; writes: Writes }> {
    const writes: Writes = {};
    const record = this.records.get(await this.lookup(ev.account));
    let retry = false;
    if (record && ev.open && ev.subject.kind === 'attempt') {
      const many = this.count(record, ev.subject.attemptId.toString(), ev.open);
      await this.write(record.account, record, writes);
      if (many) {
        const window = Math.floor(this.now() / MANY_ALERT_EVERY_MS);
        const eventId = `attempts_many:${strkeyFromContractId(ev.account)}:${window}`;
        retry = await this.deliver({ ...ev, eventId, name: 'attempts_many', class: 'required' }, record, writes);
      }
    }
    if (ev.class !== 'count') retry = (await this.deliver(ev, record, writes)) || retry;
    return { status: retry ? 'retry' : 'done', writes };
  }

  /** `dispatch`'s sending; `true` when a channel must be retried. */
  private async deliver(ev: DispatchRequest, record: AccountRecord | undefined, writes: Writes): Promise<boolean> {
    const contacts = record?.contacts.filter((c) => c.state === 'active') ?? [];
    let retry = false;
    let logged = false;
    let lapsed = false;
    for (const c of contacts) {
      const code = await alertCode({
        key: c.kCode,
        networkId: this.cfg.networkId,
        controller: ev.controller,
        account: ev.account,
        subject: ev.subject,
      });
      const t = alertText(ev.name, code, this.cfg.walletOrigin, ev.suppressed ?? 0, ev.class === 'required');
      const base = `${ev.eventId}|${toHex(c.id)}`;
      if (!(`${base}|email` in this.deliveries)) {
        const r = await sendEmail(
          this.cfg.sending,
          { to: c.address, subject: t.subject, text: t.body, idempotencyKey: toHex(sha256(`${base}|email`)) },
          this.fetchImpl,
        );
        if (r.provider) {
          this.deliveries[`${base}|email`] = this.now();
          logged = true;
        } else retry = true;
      }
      if (ev.class !== 'required') continue;
      for (const d of c.pushes) {
        const slot = `${base}|push|${deviceId(d.channel.endpoint)}`;
        if (d.gone || slot in this.deliveries) continue;
        const outcome = await this.push(c, d, t, { kind: ev.name, code }, ev.eventId);
        if (outcome === 'accepted') {
          this.deliveries[slot] = this.now();
          logged = true;
        } else if (outcome === 'gone') lapsed = true;
        else retry = true;
      }
    }
    if (lapsed && record) await this.write(record.account, record, writes);
    if (logged) {
      const cutoff = this.now() - DELIVERY_LOG_RETENTION_MS;
      for (const [k, at] of Object.entries(this.deliveries)) if (at < cutoff) delete this.deliveries[k];
      writes.deliveries = sealDeliveries(this.keys.kStore, this.deliveries);
    }
    return retry;
  }

  /** Accounts (C... addresses) whose pending change is due at `at`. */
  due(at: ChainTime): string[] {
    return [...this.records.values()]
      .filter((r) => r.change && changeDue(r.change, at))
      .map((r) => strkeyFromContractId(r.account));
  }

  /**
   * Apply due changes. A change applies only if the passkey that authorized
   * it is still a signer of the account; otherwise it is dropped (with its
   * replacement contact). A replacement whose new contact was never
   * confirmed is dropped. A removal waits while a recovery is authorized.
   */
  async mature(
    views: Record<string, ChainView>,
  ): Promise<{ applied: string[]; dropped: string[]; postponed: string[]; writes: Writes }> {
    const out = { applied: [] as string[], dropped: [] as string[], postponed: [] as string[], writes: {} as Writes };
    for (const r of [...this.records.values()]) {
      const strkey = strkeyFromContractId(r.account);
      const view = views[strkey];
      const ch = r.change;
      if (!ch || !view || !changeDue(ch, view)) continue;
      const stillSigner = view.signers.some((s) => equal(s, ch.authorizer));
      const replacement = ch.replacement ? r.contacts.find((c) => equal(c.id, ch.replacement!)) : undefined;
      if (!stillSigner || (ch.kind === 'replace' && replacement?.state !== 'active')) {
        if (ch.replacement) r.contacts = r.contacts.filter((c) => !equal(c.id, ch.replacement!));
        delete r.change;
        await this.write(r.account, r, out.writes);
        out.dropped.push(strkey);
        continue;
      }
      if (ch.kind === 'remove' && view.authorized) {
        out.postponed.push(strkey);
        continue;
      }
      r.contacts = r.contacts.filter((c) => !equal(c.id, ch.target));
      delete r.change;
      await this.write(r.account, r.contacts.length ? r : undefined, out.writes);
      out.applied.push(strkey);
    }
    return out;
  }
}

/** Each contact's channels, without its address. */
function channelStatus(record: AccountRecord | undefined): ChannelStatus[] {
  return (record?.contacts ?? []).map((c) => ({
    contact: toHex(c.id),
    state: c.state,
    push: (['live', 'unacknowledged', 'lapsed'] as const).find((s) => c.pushes.some((d) => deviceState(d) === s)) ?? 'none',
    devices: c.pushes.map((d) => ({
      id: deviceId(d.channel.endpoint),
      state: deviceState(d),
      addedAt: d.addedAt,
      ackedAt: d.ackedAt,
      ...(d.lapsedAt !== undefined ? { lapsedAt: d.lapsedAt } : {}),
    })),
    ...(record?.change && equal(record.change.target, c.id)
      ? {
          change: {
            kind: record.change.kind,
            ...(record.change.maturesAt !== undefined ? { maturesAt: record.change.maturesAt } : {}),
            ...(record.change.maturesLedger !== undefined ? { maturesLedger: record.change.maturesLedger } : {}),
          },
        }
      : {}),
  }));
}
