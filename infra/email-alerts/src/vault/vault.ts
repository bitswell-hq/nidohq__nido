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
import { createHash, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import {
  type AlertSubject,
  type ContactRequest,
  type SealedRequest,
  alertCode,
  authorizationChallenge,
  bytes,
  contractIdFromStrkey,
  encodeVaultUserData,
  openRequest,
  spkiFromRawPublicKey,
  strkeyFromContractId,
} from '@nidohq/email-recovery';
import type { AlertClass, AlertName } from '../events.js';
import {
  alertText,
  confirmationText,
  contactChangeNotice,
  pushLapsedNotice,
  pushMovedNotice,
  type AlertText,
} from './content.js';
import { type CustodianEndpoint, type Nsm, genesis, restore } from './custody.js';
import { InboundBox, type InboundResult } from './inbound.js';
import { alertLookup, type VaultKeys } from './keys.js';
import {
  type AccountRecord,
  type Contact,
  type Deliveries,
  type WatchedAttempt,
  type PendingChange,
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
 * A push subscription is probed when the push service has accepted nothing
 * for it this long (spec §10.6): the default of `VaultConfig.probeIntervalMs`.
 * Each probe shows one quiet notification; a longer interval finds a lapse
 * later.
 */
export const PROBE_INTERVAL_MS = 7 * 24 * 3600_000;
/** After a probe the push service could not answer, the next one is due this much later. */
export const PROBE_RETRY_MS = 3600_000;
/** Open attempts watched per account at once; opening one is permissionless, so the list is bounded. */
export const WATCH_MAX = 32;

export interface VaultConfig {
  /** `sha256(network passphrase)`. */
  networkId: Uint8Array;
  rp: RelyingParty;
  /** The wallet's canonical origin, named in alert texts. */
  walletOrigin: string;
  sending: SendingConfig;
  /** VAPID `sub` claim, e.g. `mailto:alerts@nido.fyi`. */
  pushSubject: string;
  /** How long a subscription may go without an accepted push before it is probed (default [`PROBE_INTERVAL_MS`], a week). */
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
}

/** One contact's channels, as a `status` read answers (no address: the host relays the answer). */
export interface ChannelStatus {
  /** The contact id, hex. */
  contact: string;
  state: 'unconfirmed' | 'active';
  /** `lapsed`: the push service answered 404 or 410 for the subscription. */
  push: 'live' | 'lapsed' | 'none';
  /** When the push service last accepted a push or probe for it (ms). */
  pushCheckedAt?: number;
  lapsedAt?: number;
  /** A pending replacement or removal of this contact: from when it applies, a
   *  close time (`maturesAt`), or a ledger number for a change sealed with
   *  only `maturesLedger`. */
  change?: { kind: 'replace' | 'remove'; maturesAt?: number; maturesLedger?: number };
}

export type ContactResult =
  | { ok: true; status: 'pending-confirmation' | 'change-pending' | 'confirmed' | 'push-updated'; maturesAt?: number }
  | { ok: true; status: 'channels'; channels: ChannelStatus[] }
  | { ok: false; error: string };

export class ContactRefused extends Error {}

const sha256 = (b: Uint8Array | string) => new Uint8Array(createHash('sha256').update(b).digest());

export class Vault {
  private readonly records = new Map<string, AccountRecord>();
  private deliveries: Deliveries = {};
  private readonly nonces = new Map<string, number>();
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
      v.records.set(lookup, unsealRecord(keys.kStore, fromHex(lookup), blob));
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
    | { status: 'pending-confirmation' | 'change-pending' | 'confirmed' | 'push-updated'; maturesAt?: number }
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
    if (inner.op === 'push') return this.updatePush(record, inner.contact, inner.push, writes);

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
    if (inner.push) {
      const loopback = this.cfg.allowLoopbackPush && inner.push.endpoint.startsWith('http://127.0.0.1:');
      if (!inner.push.endpoint.startsWith('https://') && !loopback) throw new ContactRefused('push endpoint must be https');
    }
    if (!(inner.purposes & 1)) throw new ContactRefused('security alerts are always a purpose');
    const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
    const contact: Contact = {
      id: inner.contact,
      address: inner.address,
      ...(inner.push ? { push: inner.push } : {}),
      kCode: inner.kCode,
      emailGuardian: inner.emailGuardian,
      purposes: inner.purposes,
      consentVersion: inner.consentVersion,
      state: 'unconfirmed',
      confirm: { codeHash: sha256(code), expiresAt: this.now() + CONFIRMATION_TTL_MS, attempts: 0 },
      authorizer,
      createdLedger: chain.ledger,
      // The browser created the subscription for this request: it is live now.
      ...(inner.push ? { pushCheckedAt: this.now() } : {}),
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
      if (c.push && !c.pushGone) await this.push(c, t, { kind: 'contact_change', code: '' }, key, true);
    }
  }

  private async push(
    c: Contact,
    t: AlertText,
    extra: { kind: string; code: string },
    topicSeed: string,
    required: boolean,
  ): Promise<PushOutcome> {
    const payload = new TextEncoder().encode(JSON.stringify({ v: 1, kind: extra.kind, title: t.title, body: t.push, code: extra.code }));
    return this.send(c, payload, {
      ttl: required ? 7 * 86_400 : 86_400,
      urgency: required ? 'high' : 'normal',
      topic: toBase64Url(sha256(topicSeed).subarray(0, 24)),
    });
  }

  /** One push to `c`'s subscription; an accepted one records that the subscription is live. */
  private async send(c: Contact, payload: Uint8Array, o: { ttl: number; urgency: string; topic: string }): Promise<PushOutcome> {
    const r = await pushMessage(
      c.push!,
      payload,
      { vapid: { privateKey: this.keys.vapidPrivate, publicKey: this.keys.vapidPublic }, subject: this.cfg.pushSubject, ...o },
      this.fetchImpl,
    );
    if (r.outcome === 'accepted') c.pushCheckedAt = this.now();
    return r.outcome;
  }

  /**
   * The liveness probe (spec §10.6): an RFC 8030 push with `TTL: 0` and
   * `Urgency: very-low`, one `Topic` so a newer probe replaces an
   * undelivered one. The service worker shows it as a quiet status
   * notification under one tag (WebKit revokes a subscription whose pushes
   * show nothing).
   */
  private probeOne(c: Contact): Promise<PushOutcome> {
    const payload = new TextEncoder().encode(JSON.stringify({ v: 1, kind: 'probe' }));
    return this.send(c, payload, { ttl: 0, urgency: 'very-low', topic: 'probe' });
  }

  /** The subscription is gone: mark it, and tell the contact's address once. */
  private async lapse(c: Contact, notify: boolean): Promise<void> {
    if (c.pushGone) return;
    c.pushGone = true;
    c.lapsedAt = this.now();
    if (!notify) return;
    const t = pushLapsedNotice(this.cfg.walletOrigin);
    const key = toHex(sha256(`lapsed|${toHex(c.id)}|${c.push?.endpoint ?? ''}`));
    await sendEmail(this.cfg.sending, { to: c.address, subject: t.subject, text: t.body, idempotencyKey: key }, this.fetchImpl);
  }

  /**
   * `push`: a new subscription for an existing contact. It applies at once
   * only when the contact has none or the current one is gone, checked by a
   * probe now; a contact whose notifications still work moves them only by
   * a replacement, under its 14-day delay. The address is told.
   */
  private async updatePush(
    record: AccountRecord | undefined,
    id: Uint8Array,
    push: NonNullable<Contact['push']>,
    writes: Writes,
  ): Promise<{ status: 'push-updated' }> {
    const c = record?.contacts.find((x) => equal(x.id, id));
    if (!record || !c) throw new ContactRefused('no such contact');
    const loopback = this.cfg.allowLoopbackPush && push.endpoint.startsWith('http://127.0.0.1:');
    if (!push.endpoint.startsWith('https://') && !loopback) throw new ContactRefused('push endpoint must be https');
    if (c.push && !c.pushGone) {
      const now = await this.probeOne(c);
      if (now === 'accepted') {
        await this.write(record.account, record, writes);
        throw new ContactRefused('the current notifications still reach their device; replace the contact to move them');
      }
      if (now === 'retry') throw new ContactRefused('the current notifications could not be checked; try again');
      await this.lapse(c, false);
    }
    c.push = push;
    delete c.pushGone;
    delete c.lapsedAt;
    c.pushCheckedAt = this.now();
    const t = pushMovedNotice(this.cfg.walletOrigin);
    await sendEmail(
      this.cfg.sending,
      { to: c.address, subject: t.subject, text: t.body, idempotencyKey: toHex(sha256(`moved|${toHex(c.id)}|${push.endpoint}`)) },
      this.fetchImpl,
    );
    await this.write(record.account, record, writes);
    return { status: 'push-updated' };
  }

  /**
   * Probe every active subscription the push service has accepted nothing
   * for in the probe interval. A 404 or 410 marks it lapsed and emails the
   * contact (spec §10.6). Counts only: the host learns no account.
   */
  async probe(): Promise<{ probed: number; lapsed: number; writes: Writes }> {
    const writes: Writes = {};
    let probed = 0;
    let lapsed = 0;
    const now = this.now();
    const interval = this.cfg.probeIntervalMs ?? PROBE_INTERVAL_MS;
    for (const r of [...this.records.values()]) {
      let changed = false;
      for (const c of r.contacts) {
        if (c.state !== 'active' || !c.push || c.pushGone || now - (c.pushCheckedAt ?? 0) < interval) continue;
        probed++;
        changed = true;
        const outcome = await this.probeOne(c);
        if (outcome === 'gone') {
          await this.lapse(c, true);
          lapsed++;
        } else if (outcome === 'retry') c.pushCheckedAt = now - interval + PROBE_RETRY_MS;
      }
      if (changed) await this.write(r.account, r, writes);
    }
    return { probed, lapsed, writes };
  }

  /** Accounts with an active contact, for the host to reconcile from controller state (spec §10.2). */
  accounts(): string[] {
    return [...this.records.values()]
      .filter((r) => r.contacts.some((c) => c.state === 'active'))
      .map((r) => strkeyFromContractId(r.account));
  }

  /** Every watched attempt, for the host to read (spec §10.2). */
  watched(): { account: string; attemptId: string }[] {
    return [...this.records.values()].flatMap((r) =>
      (r.watch ?? []).map((w) => ({ account: strkeyFromContractId(r.account), attemptId: w.attemptId })),
    );
  }

  /** Stop watching an attempt: it left `Collecting`, its evidence deadline passed, or its email vote was alerted. */
  async unwatch(account: string, attemptId: string): Promise<{ writes: Writes }> {
    const writes: Writes = {};
    const id = contractIdFromStrkey(account);
    const r = this.records.get(await this.lookup(id));
    if (r?.watch?.some((w) => w.attemptId === attemptId)) {
      r.watch = r.watch.filter((w) => w.attemptId !== attemptId);
      if (!r.watch.length) delete r.watch;
      await this.write(r.account, r, writes);
    }
    return { writes };
  }

  /** `attempt_begun` on an account with an email-guardian contact: watch the attempt. */
  private watch(r: AccountRecord, attemptId: string): boolean {
    if (!r.contacts.some((c) => c.state === 'active' && c.emailGuardian)) return false;
    const list = (r.watch ??= []);
    if (list.some((w: WatchedAttempt) => w.attemptId === attemptId)) return false;
    list.push({ attemptId, since: this.now() });
    if (list.length > WATCH_MAX) list.splice(0, list.length - WATCH_MAX);
    return true;
  }

  /**
   * Send the alert for one event to every active contact of its account:
   * email always, Web Push too for required alerts. Each (event, contact,
   * channel) is sent at most once (the sealed delivery log); a failed
   * channel makes the answer `retry`, and only that channel is tried again.
   */
  async dispatch(ev: DispatchRequest): Promise<{ status: 'done' | 'retry'; writes: Writes }> {
    const writes: Writes = {};
    const record = this.records.get(await this.lookup(ev.account));
    let recordChanged = false;
    const attemptId = ev.subject.kind === 'attempt' ? ev.subject.attemptId.toString() : undefined;
    if (record && attemptId !== undefined) {
      if (ev.name === 'attempt_begun') recordChanged = this.watch(record, attemptId);
      if (ev.name === 'email_vote_recorded' && record.watch?.some((w) => w.attemptId === attemptId)) {
        record.watch = record.watch.filter((w) => w.attemptId !== attemptId);
        if (!record.watch.length) delete record.watch;
        recordChanged = true;
      }
    }
    if (ev.class === 'watch') {
      if (recordChanged && record) await this.write(record.account, record, writes);
      return { status: 'done', writes };
    }
    const contacts = record?.contacts.filter((c) => c.state === 'active') ?? [];
    let retry = false;
    let logged = false;
    for (const c of contacts) {
      const code = await alertCode({
        key: c.kCode,
        networkId: this.cfg.networkId,
        controller: ev.controller,
        account: ev.account,
        subject: ev.subject,
      });
      const t = alertText(ev.name, code, this.cfg.walletOrigin, ev.suppressed ?? 0);
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
      if (ev.class === 'required' && c.push && !c.pushGone && !(`${base}|push` in this.deliveries)) {
        const outcome = await this.push(c, t, { kind: ev.name, code }, ev.eventId, true);
        if (outcome === 'accepted') {
          this.deliveries[`${base}|push`] = this.now();
          logged = true;
          recordChanged = true;
        } else if (outcome === 'gone') {
          await this.lapse(c, true);
          recordChanged = true;
        } else retry = true;
      }
    }
    if (recordChanged && record) await this.write(record.account, record, writes);
    if (logged) {
      const cutoff = this.now() - DELIVERY_LOG_RETENTION_MS;
      for (const [k, at] of Object.entries(this.deliveries)) if (at < cutoff) delete this.deliveries[k];
      writes.deliveries = sealDeliveries(this.keys.kStore, this.deliveries);
    }
    return { status: retry ? 'retry' : 'done', writes };
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
    push: !c.push ? 'none' : c.pushGone ? 'lapsed' : 'live',
    ...(c.pushCheckedAt !== undefined ? { pushCheckedAt: c.pushCheckedAt } : {}),
    ...(c.lapsedAt !== undefined ? { lapsedAt: c.lapsedAt } : {}),
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
