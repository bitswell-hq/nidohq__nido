/**
 * The alert service host (`docs/email-recovery/spec.md` §10.2): an untrusted
 * process that watches the Perch controller, relays wallet requests and
 * chain state to the vault, and persists what the vault seals. It never
 * holds an address.
 *
 * **Events.** Each poll reads the next page of the controller's events with
 * the stored cursor (bulk, filtered only by contract), handles them in
 * order, and only then moves the cursor. An event is handled once: its id
 * is recorded as handled in the same atomic write that stores the vault's
 * sealed output, and the vault's delivery log refuses a second send of the
 * same (event, contact, channel). An alert that fails is queued for retry
 * with backoff without holding back later events.
 *
 * **Email votes.** Perch emits no event when a guardian's vote is recorded
 * below quorum. The vault keeps, sealed, the open attempts of accounts with
 * an email-guardian contact (from `attempt_begun`); each poll the host
 * reads those attempts with the controller's `attempt` view and, when the
 * account's email guardian (the contract running the email guardian's
 * wasm) is among the votes of a still-collecting attempt, has the vault
 * alert every channel. The alert follows the vote by at most one polling
 * interval plus the reads.
 *
 * **Reconciliation.** On its first poll, every [`RECONCILE_EVERY_MS`], and
 * after the RPC refuses its cursor (the events aged out of retention), the
 * host reads, for each account the vault holds contacts for, the
 * controller's persistent state: the authorized attempt (`activity_gate`)
 * and the latest [`RECONCILE_SCAN`] attempts. An authorized attempt, and an
 * email vote on a collecting one, are alerted under the same delivery id
 * the event stream uses, so nothing is sent twice; collecting attempts are
 * watched. A completed recovery is not re-alerted: reconciliation restores
 * the alerts that can still change the outcome.
 *
 * **Lag alarm.** A watcher whose cursor is more than `lagAlarmLedgers`
 * behind the chain, or whose cursor the RPC refused, raises an alarm
 * (`onAlarm`, the log, and `GET /v1/health`). A stopped watcher cannot
 * raise one; `GET /v1/health` reports the last poll for an outside monitor.
 *
 * **Liveness.** Each poll asks the vault to probe the push subscriptions
 * that are due (at most one probe a week each).
 */
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { type AlertSubject, bytes, contractIdFromStrkey, decodeContactRequest } from '@nidohq/email-recovery';
import type { VaultApi } from './channel.js';
import { ALERTS, type AlertName, type PerchEvent, alertEventId, alertSubject, decodePerchEvent } from './events.js';
import { type ChainReads, RpcError, type StellarRpc } from './rpc.js';
import { type HostState, type SerializedDispatch, loadState, saveState } from './store.js';
import type { ChainView, DispatchRequest, Writes } from './vault/vault.js';

const { toHex, fromHex, toBase64Url, fromBase64Url } = bytes;

export interface ServiceConfig {
  rpc: StellarRpc;
  /** The Perch controller (`C...`) whose events drive alerts. */
  controller: string;
  statePath: string;
  /** First ledger to read when there is no cursor. */
  startLedger: number;
  /** The account's passkey signer keys, read from chain. */
  signers: (account: string) => Promise<Uint8Array[]>;
  log?: (line: string) => void;
  /**
   * Email `attempt_begun` (at most one per account per `begunWindowMs`).
   * Off by default: opening an attempt is permissionless, and the wallet
   * shows open attempts itself.
   */
  emailOnAttemptBegun?: boolean;
  /** `attempt_begun` alerts per account: at most one per this window (ledger close time). */
  begunWindowMs?: number;
  /** Controller reads (`chainReads`); without them, no email-vote alerts and no reconciliation. */
  reads?: ChainReads;
  /** How often to reconcile from controller state (default [`RECONCILE_EVERY_MS`]). */
  reconcileEveryMs?: number;
  /** Alarm when the cursor is this many ledgers behind the chain (default 720, an hour). */
  lagAlarmLedgers?: number;
  /** Called with each alarm, for an operator's pager. */
  onAlarm?: (reason: string) => void;
  /** `POST /v1/inbound` registrations per client and window (default [`INBOUND_LIMIT`]). */
  inboundLimit?: { perClient: number; windowMs: number };
  /** The client a request counts against (default: its address, IPv6 by /64). */
  clientKey?: (req: IncomingMessage) => string;
  pageLimit?: number;
  retryBaseMs?: number;
  now?: () => number;
  /** Wallet origins allowed to call the HTTP API from a browser (CORS). */
  allowOrigin?: (origin: string) => boolean;
}

/** How long the host keeps a sealed inbound message for the browser to fetch. */
export const INBOUND_KEEP_MS = 24 * 3600_000;

/** How often the host reconciles from controller state. */
export const RECONCILE_EVERY_MS = 6 * 3600_000;
/** How many of an account's latest attempts reconciliation reads. */
export const RECONCILE_SCAN = 32;

/**
 * Sealed-inbound registrations one client may make per hour. A recovery or
 * an enrollment needs one, a retry after the 24-hour window another. With
 * registrations held 24 hours, one client holds at most 240 at once, so
 * filling the vault's 100,000 (`INBOUND_MAX_REGISTRATIONS`) takes at least
 * 417 distinct IPv4 addresses or IPv6 /64 prefixes.
 */
export const INBOUND_LIMIT = { perClient: 10, windowMs: 3600_000 } as const;

/** The client an address counts as: an IPv4 address itself, an IPv6 address by its /64 prefix. */
export function clientPrefix(address: string): string {
  const v4 = /^(?:::ffff:)?(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(address);
  if (v4) return v4[1]!;
  const [head, tail] = address.toLowerCase().split('::') as [string, string | undefined];
  const left = head ? head.split(':') : [];
  const right = tail ? tail.split(':') : [];
  const groups = tail === undefined ? left : [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
  return `${groups.slice(0, 4).map((g) => g.replace(/^0+(?=.)/, '')).join(':')}::/64`;
}

/** A fixed-window count per key. */
export class WindowLimiter {
  private readonly seen = new Map<string, { start: number; n: number }>();

  constructor(
    readonly max: number,
    readonly windowMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  /** `0` if `key` may go now (and counts it), else the milliseconds until it may. */
  take(key: string): number {
    const now = this.now();
    if (this.seen.size > 10_000) for (const [k, v] of this.seen) if (now - v.start >= this.windowMs) this.seen.delete(k);
    const w = this.seen.get(key);
    if (!w || now - w.start >= this.windowMs) {
      this.seen.set(key, { start: now, n: 1 });
      return 0;
    }
    if (w.n >= this.max) return w.start + this.windowMs - now;
    w.n++;
    return 0;
  }
}

export interface PollReport {
  /** The cursor reached the latest ledger and the page was not full. */
  caughtUp: boolean;
  events: number;
  dispatched: number;
  suppressed: number;
  retriesQueued: number;
  retriesDone: number;
  matured: { applied: string[]; dropped: string[]; postponed: string[] };
  /** Email-vote alerts dispatched. */
  votes: number;
  /** Accounts reconciled from controller state, and the alerts that found (`undefined` when not run). */
  reconciled?: { accounts: number; found: number };
  /** Ledgers between the cursor and the chain's latest. */
  lagLedgers: number;
  /** Why the watcher raised an alarm this poll. */
  alarm?: string;
  /** Push subscriptions probed, and how many of them were gone. */
  probes: { probed: number; lapsed: number };
  /** Event id → ms between reading its page (or, for an email vote, its attempt) and the vault's answer. */
  latencyMs: Record<string, number>;
}

/** Serializes the async sections that touch state. */
class Lock {
  private tail: Promise<void> = Promise.resolve();
  run<T>(f: () => Promise<T>): Promise<T> {
    const r = this.tail.then(f);
    this.tail = r.then(
      () => undefined,
      () => undefined,
    );
    return r;
  }
}

function serialize(d: DispatchRequest): SerializedDispatch {
  const s = d.subject;
  return {
    eventId: d.eventId,
    name: d.name,
    class: d.class,
    controller: toHex(d.controller),
    account: toHex(d.account),
    subject: {
      kind: s.kind,
      value: s.kind === 'attempt' ? String(s.attemptId) : s.kind === 'epoch' ? String(s.epoch) : toHex(s.digest),
    },
    ...(d.suppressed !== undefined ? { suppressed: d.suppressed } : {}),
  };
}

function deserialize(s: SerializedDispatch): DispatchRequest {
  const subject: AlertSubject =
    s.subject.kind === 'attempt'
      ? { kind: 'attempt', attemptId: BigInt(s.subject.value) }
      : s.subject.kind === 'epoch'
        ? { kind: 'epoch', epoch: BigInt(s.subject.value) }
        : { kind: 'change', digest: fromHex(s.subject.value) };
  return {
    eventId: s.eventId,
    name: s.name as AlertName,
    class: s.class as DispatchRequest['class'],
    controller: fromHex(s.controller),
    account: fromHex(s.account),
    subject,
    ...(s.suppressed !== undefined ? { suppressed: s.suppressed } : {}),
  };
}

export class AlertService {
  state: HostState;
  private readonly lock = new Lock();
  private server?: Server;
  private readonly log: (line: string) => void;
  private readonly now: () => number;
  private readonly inboundLimiter: WindowLimiter;
  /** Guardian address → whether it is an email guardian (its wasm cannot change). */
  private readonly guardianKinds = new Map<string, boolean>();
  /** When reconciliation last ran (ms), and each account's `next_attempt_id` then. */
  private reconciledAt = 0;
  private readonly reconciledNext = new Map<string, bigint>();
  /** The last alarm and the last completed poll, for `GET /v1/health`. */
  private alarm?: { at: number; reason: string };
  private lastPollAt?: number;

  constructor(
    private readonly cfg: ServiceConfig,
    private readonly vault: VaultApi,
  ) {
    this.state = loadState(cfg.statePath, cfg.startLedger);
    this.log = cfg.log ?? ((l) => console.log(l));
    this.now = cfg.now ?? Date.now;
    const limit = cfg.inboundLimit ?? INBOUND_LIMIT;
    this.inboundLimiter = new WindowLimiter(limit.perClient, limit.windowMs, this.now);
  }

  private persist(writes?: Writes): void {
    for (const [lookup, blob] of Object.entries(writes?.records ?? {})) {
      if (blob) this.state.sealed.records[lookup] = Buffer.from(blob).toString('base64');
      else delete this.state.sealed.records[lookup];
    }
    if (writes?.deliveries) this.state.sealed.deliveries = Buffer.from(writes.deliveries).toString('base64');
    saveState(this.cfg.statePath, this.state);
  }

  /** The sealed blobs, as a booting vault takes them. */
  static sealedState(state: HostState): { records: Record<string, Uint8Array>; deliveries?: Uint8Array } {
    const records: Record<string, Uint8Array> = {};
    for (const [k, v] of Object.entries(state.sealed.records)) records[k] = new Uint8Array(Buffer.from(v, 'base64'));
    return {
      records,
      ...(state.sealed.deliveries ? { deliveries: new Uint8Array(Buffer.from(state.sealed.deliveries, 'base64')) } : {}),
    };
  }

  isAuthorized(account: string): boolean {
    const a = this.state.authorized[account];
    return a !== undefined && a.expiresAt > this.state.latestLedger;
  }

  private track(ev: PerchEvent): void {
    const id = String(ev.data.attempt_id ?? '');
    if (ev.name === 'attempt_authorized') {
      this.state.authorized[ev.accountStrkey] = { attemptId: id, expiresAt: Number(ev.data.expires_at) };
    } else if (
      (ev.name === 'attempt_cancelled' || ev.name === 'recovery_completed') &&
      this.state.authorized[ev.accountStrkey]?.attemptId === id
    ) {
      delete this.state.authorized[ev.accountStrkey];
    }
  }

  /** The dispatch for `ev`, or why there is none. */
  private plan(ev: PerchEvent): DispatchRequest | 'none' | 'suppressed' {
    let cls = ALERTS[ev.name];
    if (cls === 'watch' && this.cfg.emailOnAttemptBegun) cls = 'rate-limited';
    if (cls === 'none' || ev.name === 'attempt_invalidated') return 'none';
    let suppressed: number | undefined;
    if (cls === 'rate-limited') {
      const window = this.cfg.begunWindowMs ?? 24 * 3600_000;
      const r = this.state.begun[ev.accountStrkey];
      if (r && ev.closedAt - r.lastSent < window) {
        r.suppressed++;
        return 'suppressed';
      }
      suppressed = r?.suppressed ?? 0;
      this.state.begun[ev.accountStrkey] = { lastSent: ev.closedAt, suppressed: 0 };
    }
    const subject = alertSubject(ev);
    return {
      eventId: alertEventId(ev.name, ev.accountStrkey, subject, ev.id),
      name: ev.name,
      class: cls,
      controller: ev.controller,
      account: ev.account,
      subject,
      ...(suppressed !== undefined ? { suppressed } : {}),
    };
  }

  private queueRetry(d: DispatchRequest, attempts: number): void {
    const base = this.cfg.retryBaseMs ?? 30_000;
    this.state.retries[d.eventId] = {
      request: serialize(d),
      attempts,
      nextAt: this.now() + Math.min(base * 2 ** (attempts - 1), 3600_000),
    };
  }

  /** One page of events, due retries, and due contact changes. */
  pollOnce(): Promise<PollReport> {
    return this.lock.run(async () => {
      const report: PollReport = {
        caughtUp: false,
        events: 0,
        dispatched: 0,
        suppressed: 0,
        retriesQueued: 0,
        retriesDone: 0,
        matured: { applied: [], dropped: [], postponed: [] },
        votes: 0,
        lagLedgers: 0,
        probes: { probed: 0, lapsed: 0 },
        latencyMs: {},
      };
      const from = this.state.cursor ? { cursor: this.state.cursor } : { startLedger: this.state.startLedger };
      let page;
      try {
        page = await this.cfg.rpc.getEvents(this.cfg.controller, from, this.cfg.pageLimit ?? 200);
      } catch (e) {
        if (!(e instanceof RpcError && e.code === -32600)) throw e;
        // The events after the cursor aged out of the RPC's retention: start
        // again from the oldest ledger it keeps and reconcile what was lost
        // from controller state.
        const health = await this.cfg.rpc.call<{ oldestLedger: number; latestLedger: number }>('getHealth', {});
        report.alarm = this.raise(`events aged out of RPC retention (${e.message}); resuming at ledger ${health.oldestLedger} and reconciling from controller state`);
        this.state.cursor = undefined;
        this.state.startLedger = health.oldestLedger;
        this.state.handled = [];
        this.state.latestLedger = Math.max(this.state.latestLedger, health.latestLedger);
        this.persist();
        this.reconciledAt = 0;
        this.reconciledNext.clear();
        await this.afterEvents(report);
        return report;
      }
      const readAt = performance.now();
      this.state.latestLedger = Math.max(this.state.latestLedger, page.latestLedger);
      const handled = new Set(this.state.handled);
      for (const raw of page.events) {
        if (handled.has(raw.id)) continue;
        report.events++;
        const ev = decodePerchEvent(raw);
        if (ev) {
          this.track(ev);
          const plan = this.plan(ev);
          if (plan === 'suppressed') report.suppressed++;
          if (typeof plan === 'object') {
            const r = await this.vault.dispatch(plan);
            report.latencyMs[ev.id] = performance.now() - readAt;
            if (r.status === 'retry') {
              this.queueRetry(plan, 1);
              report.retriesQueued++;
            } else report.dispatched++;
            this.log(`event ${ev.id} ${ev.name} ${ev.accountStrkey}: ${r.status}`);
            this.state.handled.push(raw.id);
            handled.add(raw.id);
            this.persist(r.writes);
            continue;
          }
          this.log(`event ${ev.id} ${ev.name} ${ev.accountStrkey}: ${plan}`);
        }
        this.state.handled.push(raw.id);
        handled.add(raw.id);
        this.persist();
      }
      this.state.cursor = page.cursor;
      this.state.handled = [];
      this.persist();
      // A page can be short without reaching the chain's head: one request
      // scans a bounded ledger range.
      const cursorLedger = Number(BigInt(page.cursor.slice(0, 19)) >> 32n);
      report.caughtUp = page.events.length < (this.cfg.pageLimit ?? 200) && cursorLedger >= page.latestLedger;
      report.lagLedgers = Math.max(0, page.latestLedger - cursorLedger);
      if (report.lagLedgers > (this.cfg.lagAlarmLedgers ?? 720)) {
        // One alarm per episode: a watcher catching up stays behind for several polls.
        report.alarm = this.alarm?.reason ?? this.raise(`the watcher is ${report.lagLedgers} ledgers behind the chain`);
      } else if (report.caughtUp && this.alarm) {
        this.log(`watcher: caught up; alarm cleared (${this.alarm.reason})`);
        this.alarm = undefined;
      }
      await this.afterEvents(report);
      return report;
    });
  }

  /** Raise an alarm: the log, `onAlarm`, and `GET /v1/health`. */
  private raise(reason: string): string {
    this.alarm = { at: this.now(), reason };
    this.log(`ALARM watcher: ${reason}`);
    this.cfg.onAlarm?.(reason);
    return reason;
  }

  /** Retries, email votes, reconciliation, probes, and contact changes: every poll, after its events. */
  private async afterEvents(report: PollReport): Promise<void> {
    for (const [id, r] of Object.entries(this.state.retries)) {
      if (r.nextAt > this.now()) continue;
      const res = await this.vault.dispatch(deserialize(r.request));
      if (res.status === 'done') {
        delete this.state.retries[id];
        report.retriesDone++;
      } else {
        this.queueRetry(deserialize(r.request), r.attempts + 1);
      }
      this.log(`retry ${id} (attempt ${r.attempts + 1}): ${res.status}`);
      this.persist(res.writes);
    }

    if (this.cfg.reads && this.now() - this.reconciledAt >= (this.cfg.reconcileEveryMs ?? RECONCILE_EVERY_MS)) {
      report.reconciled = await this.reconcile(this.cfg.reads);
      this.reconciledAt = this.now();
    }
    await this.watchVotes(report);
    const probes = await this.vault.probe();
    report.probes = { probed: probes.probed, lapsed: probes.lapsed };
    if (probes.probed) this.log(`push probes: ${probes.probed} sent, ${probes.lapsed} gone`);
    this.persist(probes.writes);

    const due = await this.vault.due(this.state.latestLedger);
    if (due.length) {
      const views: Record<string, ChainView> = {};
      for (const account of due) views[account] = await this.chainView(account);
      const m = await this.vault.mature(views);
      report.matured = { applied: m.applied, dropped: m.dropped, postponed: m.postponed };
      for (const a of m.applied) this.log(`contact change applied for ${a}`);
      for (const a of m.dropped) this.log(`contact change dropped for ${a}`);
      this.persist(m.writes);
    }
    this.lastPollAt = this.now();
  }

  private async emailGuardian(reads: ChainReads, address: string): Promise<boolean> {
    let known = this.guardianKinds.get(address);
    if (known === undefined) {
      known = await reads.isEmailGuardian(address);
      this.guardianKinds.set(address, known);
    }
    return known;
  }

  /** Dispatch an alert the host found itself (an email vote, a reconciled one); queue a retry if needed. */
  private async dispatchFound(report: PollReport, d: DispatchRequest, readAt: number): Promise<void> {
    const r = await this.vault.dispatch(d);
    report.latencyMs[d.eventId] = performance.now() - readAt;
    if (r.status === 'retry') {
      this.queueRetry(d, 1);
      report.retriesQueued++;
    }
    this.log(`${d.eventId}: ${r.status}`);
    this.persist(r.writes);
  }

  private found(name: AlertName, cls: DispatchRequest['class'], account: string, attemptId: bigint): DispatchRequest {
    const subject: AlertSubject = { kind: 'attempt', attemptId };
    return {
      eventId: alertEventId(name, account, subject),
      name,
      class: cls,
      controller: contractIdFromStrkey(this.cfg.controller),
      account: contractIdFromStrkey(account),
      subject,
    };
  }

  /** Whether the email guardian is among an attempt's votes. */
  private async hasEmailVote(reads: ChainReads, guardians: string[]): Promise<boolean> {
    for (const g of guardians) if (await this.emailGuardian(reads, g)) return true;
    return false;
  }

  /**
   * Read each watched attempt: stop watching one that left `Collecting` or
   * whose evidence deadline passed; alert one whose votes include the email
   * guardian.
   */
  private async watchVotes(report: PollReport): Promise<void> {
    const reads = this.cfg.reads;
    if (!reads) return;
    for (const { account, attemptId } of await this.vault.watched()) {
      const readAt = performance.now();
      let view;
      try {
        view = await reads.attempt(account, BigInt(attemptId));
      } catch (e) {
        this.log(`watch ${account} attempt ${attemptId}: read failed (${(e as Error).message}); next poll`);
        continue;
      }
      if (!view || view.state !== 'Collecting' || this.state.latestLedger > view.evidenceDeadline) {
        this.persist((await this.vault.unwatch(account, attemptId)).writes);
        continue;
      }
      if (!(await this.hasEmailVote(reads, view.guardians))) continue;
      await this.dispatchFound(report, this.found('email_vote_recorded', 'required', account, BigInt(attemptId)), readAt);
      report.votes++;
    }
  }

  /**
   * Alert from controller state what the event stream may have missed, for
   * every account with contacts: its authorized attempt, and email votes on
   * its collecting attempts, which are watched from then on.
   */
  private async reconcile(reads: ChainReads): Promise<{ accounts: number; found: number }> {
    const report = { accounts: 0, found: 0 };
    const sink = { latencyMs: {} as Record<string, number>, retriesQueued: 0 } as PollReport;
    for (const account of await this.vault.accounts()) {
      const readAt = performance.now();
      try {
        report.accounts++;
        const authorized = await reads.authorizedAttempt(account);
        if (authorized !== undefined) {
          await this.dispatchFound(sink, this.found('attempt_authorized', 'required', account, authorized), readAt);
          report.found++;
        }
        const next = await reads.nextAttemptId(account);
        if (this.reconciledNext.get(account) === next) continue;
        const oldest = next > BigInt(RECONCILE_SCAN) ? next - BigInt(RECONCILE_SCAN) : 0n;
        for (let id = next - 1n; id >= oldest; id--) {
          const view = await reads.attempt(account, id);
          if (!view || view.state !== 'Collecting' || this.state.latestLedger > view.evidenceDeadline) continue;
          await this.dispatchFound(sink, this.found('attempt_begun', 'watch', account, id), readAt);
          if (await this.hasEmailVote(reads, view.guardians)) {
            await this.dispatchFound(sink, this.found('email_vote_recorded', 'required', account, id), readAt);
            report.found++;
          }
        }
        this.reconciledNext.set(account, next);
      } catch (e) {
        this.log(`reconcile ${account}: read failed (${(e as Error).message}); next time`);
      }
    }
    this.log(`reconciled ${report.accounts} accounts from controller state: ${report.found} alerts found (each sent at most once)`);
    return report;
  }

  /** Poll until caught up with the chain's latest ledger. */
  async drain(): Promise<PollReport[]> {
    const out: PollReport[] = [];
    for (;;) {
      const r = await this.pollOnce();
      out.push(r);
      if (r.caughtUp) return out;
    }
  }

  async chainView(account: string): Promise<ChainView> {
    return {
      ledger: this.state.latestLedger,
      signers: await this.cfg.signers(account),
      authorized: this.isAuthorized(account),
    };
  }

  // --- the wallet-facing API --------------------------------------------

  attestation(nonce: Uint8Array): Promise<Uint8Array> {
    return this.lock.run(() => this.vault.attest(nonce));
  }

  nonce(): Promise<Uint8Array> {
    return this.lock.run(() => this.vault.nonce());
  }

  /** Relay a contact request with the account's chain state; persist the outcome. */
  contact(body: string) {
    return this.lock.run(async () => {
      const req = decodeContactRequest(body);
      // A confirmation is proven by the emailed code, not by a passkey: no chain read.
      const view =
        req.op === 'confirm'
          ? { ledger: this.state.latestLedger, signers: [], authorized: this.isAuthorized(req.account) }
          : await this.chainView(req.account);
      const { result, writes } = await this.vault.contact(req, view);
      this.log(`contact ${req.op} ${req.account}: ${result.ok ? result.status : `refused (${result.error})`}`);
      this.persist(writes);
      return result;
    });
  }

  /** Relay a browser's sealed inbound registration to the vault (spec §4.6). */
  inbound(envelope: Uint8Array) {
    return this.lock.run(() => this.vault.inbound(envelope));
  }

  /** Keep what the vault sealed for inbound mail, by inbox id, until the browser fetches it. */
  storeInbound(sealed: Record<string, Uint8Array>): void {
    const now = this.now();
    const inbound = (this.state.inbound ??= {});
    for (const [id, at] of Object.entries(inbound)) if (at.at + INBOUND_KEEP_MS < now) delete inbound[id];
    for (const [id, blob] of Object.entries(sealed)) {
      const slot = (inbound[id] ??= { at: now, messages: [] });
      slot.messages.push(toBase64Url(blob));
    }
    saveState(this.cfg.statePath, this.state);
  }

  /**
   * `GET /v1/attestation?nonce=`, `POST /v1/nonce`, `POST /v1/contact`,
   * `POST /v1/inbound` (rate-limited per client, [`INBOUND_LIMIT`]),
   * `GET /v1/inbound/<id>`, `GET /v1/health`. Browsers on an allowed origin
   * may call it (CORS).
   */
  async listen(port = 0): Promise<string> {
    this.server = createServer(async (req, res) => {
      const origin = req.headers.origin;
      const cors: Record<string, string> =
        origin && this.cfg.allowOrigin?.(origin) ? { 'access-control-allow-origin': origin, vary: 'Origin' } : {};
      const reply = (status: number, body: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...cors });
        res.end(JSON.stringify(body));
      };
      try {
        const url = new URL(req.url ?? '/', 'http://host');
        if (req.method === 'OPTIONS') {
          res.writeHead(204, {
            ...cors,
            'access-control-allow-methods': 'GET, POST',
            'access-control-allow-headers': 'content-type',
            'access-control-max-age': '600',
          });
          return res.end();
        }
        if (req.method === 'POST' && url.pathname === '/v1/inbound') {
          const client = this.cfg.clientKey?.(req) ?? clientPrefix(req.socket.remoteAddress ?? '');
          const wait = this.inboundLimiter.take(client);
          if (wait > 0) {
            res.writeHead(429, {
              'content-type': 'application/json',
              'cache-control': 'no-store',
              'retry-after': String(Math.ceil(wait / 1000)),
              ...cors,
            });
            return res.end(JSON.stringify({ ok: false, error: 'too many registrations from this network; try again later' }));
          }
          const chunks: Buffer[] = [];
          for await (const c of req) chunks.push(c as Buffer);
          if (Buffer.concat(chunks).length > 4096) return reply(413, { error: 'request too large' });
          const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { envelope?: string };
          const result = await this.inbound(fromBase64Url(String(body.envelope ?? '')));
          return reply(result.ok ? 200 : 409, result);
        }
        const inboxPath = /^\/v1\/inbound\/([0-9a-f]{32})$/.exec(url.pathname);
        if (req.method === 'GET' && inboxPath) {
          return reply(200, { messages: this.state.inbound?.[inboxPath[1]!]?.messages ?? [] });
        }
        if (req.method === 'GET' && url.pathname === '/v1/attestation') {
          const nonce = fromBase64Url(url.searchParams.get('nonce') ?? '');
          return reply(200, { attestation: toBase64Url(await this.attestation(nonce)) });
        }
        if (req.method === 'POST' && url.pathname === '/v1/nonce') return reply(200, { nonce: toBase64Url(await this.nonce()) });
        if (req.method === 'POST' && url.pathname === '/v1/contact') {
          const chunks: Buffer[] = [];
          for await (const c of req) chunks.push(c as Buffer);
          if (Buffer.concat(chunks).length > 16_384) return reply(413, { error: 'request too large' });
          const result = await this.contact(Buffer.concat(chunks).toString('utf8'));
          return reply(result.ok ? 200 : 403, result);
        }
        if (req.method === 'GET' && url.pathname === '/v1/health') {
          return reply(200, {
            cursor: this.state.cursor ?? null,
            latestLedger: this.state.latestLedger,
            retries: Object.keys(this.state.retries).length,
            lastPollAt: this.lastPollAt ?? null,
            alarm: this.alarm ?? null,
          });
        }
        return reply(404, { error: 'not found' });
      } catch (e) {
        return reply(400, { error: (e as Error).message });
      }
    });
    await new Promise<void>((r) => this.server!.listen(port, '127.0.0.1', r));
    return `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
  }

  async close(): Promise<void> {
    if (this.server) await new Promise<void>((r) => this.server!.close(() => r()));
  }
}
