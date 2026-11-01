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
import type { AlertClass, PerchEventName } from '../events.js';
import { alertText, confirmationText, contactChangeNotice, type AlertText } from './content.js';
import { type CustodianEndpoint, type Nsm, genesis, restore } from './custody.js';
import { InboundBox, type InboundResult } from './inbound.js';
import { alertLookup, type VaultKeys } from './keys.js';
import {
  type AccountRecord,
  type Contact,
  type Deliveries,
  sealDeliveries,
  sealRecord,
  unsealDeliveries,
  unsealRecord,
} from './records.js';
import { type SendingConfig, sendEmail } from './send.js';
import { type RelyingParty, checkAuthorization, relyingPartyFor } from './webauthn.js';
import { pushMessage } from './webpush.js';

const { equal, toHex, fromHex, toBase64Url } = bytes;

/** 14 days at 5-second ledgers: replacing or removing a contact waits this long. */
export const CONTACT_CHANGE_DELAY_LEDGERS = 241_920;
export const CONFIRMATION_TTL_MS = 72 * 3600_000;
export const CONFIRMATION_ATTEMPTS = 5;
export const NONCE_TTL_MS = 10 * 60_000;
const DELIVERY_LOG_RETENTION_MS = 30 * 24 * 3600_000;

export interface VaultConfig {
  /** `sha256(network passphrase)`. */
  networkId: Uint8Array;
  rp: RelyingParty;
  /** The wallet's canonical origin, named in alert texts. */
  walletOrigin: string;
  sending: SendingConfig;
  /** VAPID `sub` claim, e.g. `mailto:alerts@nido.fyi`. */
  pushSubject: string;
  /** Accept `http://127.0.0.1` push endpoints (local test push services only). */
  allowLoopbackPush?: boolean;
  custodians: CustodianEndpoint[];
}

/** Chain state the host relays for one account (spec §10.3). */
export interface ChainView {
  ledger: number;
  /** P-256 keys (uncompressed) of the account's passkey signers. */
  signers: Uint8Array[];
  /** Whether a recovery attempt is authorized for the account. */
  authorized: boolean;
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
  name: Exclude<PerchEventName, 'attempt_invalidated'>;
  class: Exclude<AlertClass, 'none'>;
  controller: Uint8Array;
  account: Uint8Array;
  subject: AlertSubject;
  /** For rate-limited events: how many were suppressed since the last one sent. */
  suppressed?: number;
}

export type ContactResult =
  | { ok: true; status: 'pending-confirmation' | 'change-pending' | 'confirmed'; maturesLedger?: number }
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
      return { result: { ok: true, ...status }, writes };
    } catch (e) {
      if (e instanceof ContactRefused) return { result: { ok: false, error: e.message }, writes: {} };
      throw e;
    }
  }

  private async contactInner(
    req: ContactRequest,
    chain: ChainView,
    writes: Writes,
  ): Promise<{ status: 'pending-confirmation' | 'change-pending' | 'confirmed'; maturesLedger?: number }> {
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
    const purposes = inner.op === 'remove' ? 0 : inner.purposes;
    const consentVersion = inner.op === 'remove' ? 0 : inner.consentVersion;
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

    if (inner.op === 'remove') {
      const target = record?.contacts.find((c) => equal(c.id, inner.contact) && c.state === 'active');
      if (!record || !target) throw new ContactRefused('no such active contact');
      if (record.change) throw new ContactRefused('another change is pending');
      if (chain.authorized) throw new ContactRefused('removal is refused while a recovery attempt is authorized');
      const maturesLedger = chain.ledger + CONTACT_CHANGE_DELAY_LEDGERS;
      await this.notifyChange(record, 'remove');
      record.change = { kind: 'remove', target: inner.contact, requestedLedger: chain.ledger, maturesLedger, authorizer };
      await this.write(account, record, writes);
      return { status: 'change-pending', maturesLedger };
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
    const maturesLedger = chain.ledger + CONTACT_CHANGE_DELAY_LEDGERS;
    await this.notifyChange(record, 'replace');
    await this.sendConfirmation(contact, code, inner.contact);
    record.contacts.push(contact);
    record.change = {
      kind: 'replace',
      target: inner.replaces!,
      replacement: inner.contact,
      requestedLedger: chain.ledger,
      maturesLedger,
      authorizer,
    };
    await this.write(account, record, writes);
    return { status: 'change-pending', maturesLedger };
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
  ): Promise<'accepted' | 'gone' | 'retry'> {
    const payload = new TextEncoder().encode(JSON.stringify({ v: 1, kind: extra.kind, title: t.title, body: t.body, code: extra.code }));
    const r = await pushMessage(
      c.push!,
      payload,
      {
        vapid: { privateKey: this.keys.vapidPrivate, publicKey: this.keys.vapidPublic },
        subject: this.cfg.pushSubject,
        ttl: required ? 7 * 86_400 : 86_400,
        urgency: required ? 'high' : 'normal',
        topic: toBase64Url(sha256(topicSeed).subarray(0, 24)),
      },
      this.fetchImpl,
    );
    return r.outcome;
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
    const contacts = record?.contacts.filter((c) => c.state === 'active') ?? [];
    let retry = false;
    let logged = false;
    let recordChanged = false;
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
        } else if (outcome === 'gone') {
          c.pushGone = true;
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

  /** Accounts (C... addresses) whose pending change is due at `ledger`. */
  due(ledger: number): string[] {
    return [...this.records.values()]
      .filter((r) => r.change && r.change.maturesLedger <= ledger)
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
      if (!ch || !view || ch.maturesLedger > view.ledger) continue;
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
