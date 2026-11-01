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
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { type AlertSubject, bytes, decodeContactRequest } from '@nidohq/email-recovery';
import type { VaultApi } from './channel.js';
import { ALERTS, type PerchEvent, alertSubject, decodePerchEvent } from './events.js';
import { RpcError, type StellarRpc } from './rpc.js';
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
  /** `attempt_begun` alerts per account: at most one per this window (ledger close time). */
  begunWindowMs?: number;
  pageLimit?: number;
  retryBaseMs?: number;
  now?: () => number;
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
  /** Event id → ms between reading its page and the vault's answer. */
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
    name: s.name as DispatchRequest['name'],
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

  constructor(
    private readonly cfg: ServiceConfig,
    private readonly vault: VaultApi,
  ) {
    this.state = loadState(cfg.statePath, cfg.startLedger);
    this.log = cfg.log ?? ((l) => console.log(l));
    this.now = cfg.now ?? Date.now;
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
    const cls = ALERTS[ev.name];
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
    return {
      eventId: ev.id,
      name: ev.name,
      class: cls,
      controller: ev.controller,
      account: ev.account,
      subject: alertSubject(ev),
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
        latencyMs: {},
      };
      const from = this.state.cursor ? { cursor: this.state.cursor } : { startLedger: this.state.startLedger };
      let page;
      try {
        page = await this.cfg.rpc.getEvents(this.cfg.controller, from, this.cfg.pageLimit ?? 200);
      } catch (e) {
        if (e instanceof RpcError && e.code === -32600) {
          this.log(`watcher: RPC refuses the stored position (${e.message}); events may have aged out of retention`);
        }
        throw e;
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
      report.caughtUp =
        page.events.length < (this.cfg.pageLimit ?? 200) &&
        Number(BigInt(page.cursor.slice(0, 19)) >> 32n) >= page.latestLedger;

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
      return report;
    });
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

  /** `GET /v1/attestation?nonce=`, `POST /v1/nonce`, `POST /v1/contact`, `GET /v1/health`. */
  async listen(port = 0): Promise<string> {
    this.server = createServer(async (req, res) => {
      const reply = (status: number, body: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
        res.end(JSON.stringify(body));
      };
      try {
        const url = new URL(req.url ?? '/', 'http://host');
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
          return reply(200, { cursor: this.state.cursor ?? null, latestLedger: this.state.latestLedger, retries: Object.keys(this.state.retries).length });
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
