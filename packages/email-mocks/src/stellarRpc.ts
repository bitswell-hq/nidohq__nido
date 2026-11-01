/**
 * TEST-ONLY mock of Stellar RPC's `getEvents`, as its OpenRPC description
 * specifies it (stellar/stellar-docs `openrpc/src/stellar-rpc/methods/getEvents.json`
 * and its schemas, read 2026-11-01): JSON-RPC 2.0 by name; `startLedger`
 * (inclusive) or `pagination.cursor`, never both; optional `endLedger`
 * (exclusive, not with a cursor); up to 5 `filters`, each with `type`,
 * `contractIds`, and up to 5 topic filters of 1 to 4 segment matchers (a
 * base64 ScVal, `*` for one segment, `**` as the last for any rest);
 * `pagination.limit` 1 to 10000, default 100. The result carries `events`
 * (`type`, `ledger`, `ledgerClosedAt`, `contractId`, `id`,
 * `operationIndex`, `transactionIndex`, `topic`, `value`, `txHash`),
 * `latestLedger`, `oldestLedger`, their close times, and `cursor`.
 *
 * Two behaviours follow what `soroban-testnet.stellar.org` was observed to do
 * on 2026-11-01 (the OpenRPC description does not state them): one request
 * scans at most 10,000 ledgers, so a short page does not mean the caller has
 * caught up; and a page that ends before `limit` events carries the cursor
 * `TOID(next ledger to scan) - 1` with event index `4294967295`.
 *
 * The mock serves a fixed list of events (for example those recorded from
 * Nido's integration-test host), keeps a retention window like the real
 * service's `history-retention-window`, and can be told to fail. Its
 * `simulateTransaction` answers with a value the test supplies (the result
 * shape: `latestLedger`, `minResourceFee`, `results: [{auth, xdr}]`,
 * `transactionData`).
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface RpcEvent {
  type: 'contract' | 'system';
  ledger: number;
  ledgerClosedAt: string;
  contractId: string;
  id: string;
  operationIndex: number;
  transactionIndex: number;
  topic: string[];
  value: string;
  txHash: string;
}

/** TOID (SEP-35): ledger in the top 32 bits, then 20 bits of transaction order, then 12 of operation. */
export function toid(ledger: number, tx: number, op: number): bigint {
  return (BigInt(ledger) << 32n) | (BigInt(tx) << 12n) | BigInt(op);
}

/** An event id: the 19-digit TOID, a hyphen, the 10-digit event index. */
export function eventId(ledger: number, tx: number, op: number, index: number): string {
  return `${toid(ledger, tx, op).toString().padStart(19, '0')}-${String(index).padStart(10, '0')}`;
}

const CLOSE_EPOCH_MS = Date.UTC(2026, 9, 1);

/** Ledgers one `getEvents` request scans at most (observed). */
export const SCAN_WINDOW_LEDGERS = 10_000;

/** The ledger a `getEvents` cursor points into. */
export const cursorLedger = (cursor: string): number => Number(BigInt(cursor.slice(0, 19)) >> 32n);

/** Close time the mock reports for `ledger`: 5 seconds per ledger from a fixed epoch. */
export function ledgerCloseTime(ledger: number): Date {
  return new Date(CLOSE_EPOCH_MS + ledger * 5000);
}

class RpcError extends Error {
  constructor(
    readonly code: number,
    message: string,
  ) {
    super(message);
  }
}

export class StellarRpcMock {
  readonly calls: { method: string; params: unknown }[] = [];
  private events: RpcEvent[] = [];
  private failures = 0;
  private server?: Server;
  latestLedger: number;
  /**
   * Answers `simulateTransaction`: given the base64 `TransactionEnvelope`,
   * the base64 `ScVal` the invoked function returns. Unset: method not found.
   */
  onSimulate?: (transaction: string) => string;
  url = '';

  constructor(
    events: RpcEvent[] = [],
    /** Ledgers kept, like the service's `history-retention-window` (default 120960). */
    readonly retention = 120_960,
  ) {
    this.latestLedger = 0;
    this.add(events);
  }

  add(events: RpcEvent[]): void {
    this.events = [...this.events, ...events].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    for (const e of events) this.latestLedger = Math.max(this.latestLedger, e.ledger);
  }

  get oldestLedger(): number {
    return Math.max(1, this.latestLedger - this.retention + 1);
  }

  /** The next `count` requests answer HTTP 503. */
  failNext(count = 1): void {
    this.failures += count;
  }

  private matches(e: RpcEvent, filters: { type?: string; contractIds?: string[]; topics?: string[][] }[]): boolean {
    if (filters.length === 0) return true;
    return filters.some((f) => {
      if (f.type && f.type !== e.type) return false;
      if (f.contractIds && f.contractIds.length && !f.contractIds.includes(e.contractId)) return false;
      if (!f.topics || f.topics.length === 0) return true;
      return f.topics.some((t) => {
        const rest = t[t.length - 1] === '**';
        const segs = rest ? t.slice(0, -1) : t;
        if (rest ? e.topic.length < segs.length : e.topic.length !== segs.length) return false;
        return segs.every((s, i) => s === '*' || s === e.topic[i]);
      });
    });
  }

  getEvents(params: Record<string, unknown>): unknown {
    const pagination = (params.pagination ?? {}) as { cursor?: string; limit?: number };
    const filters = (params.filters ?? []) as { type?: string; contractIds?: string[]; topics?: string[][] }[];
    if (filters.length > 5) throw new RpcError(-32602, 'maximum 5 filters per request');
    for (const f of filters) {
      if ((f.topics?.length ?? 0) > 5) throw new RpcError(-32602, 'maximum 5 topic filters per filter');
      for (const t of f.topics ?? []) {
        const n = t[t.length - 1] === '**' ? t.length - 1 : t.length;
        if (n < 1 && t.length !== 1) throw new RpcError(-32602, 'topic filter must have 1 to 4 segments');
        if (n > 4) throw new RpcError(-32602, 'topic filter must have 1 to 4 segments');
      }
    }
    const limit = pagination.limit ?? 100;
    if (!Number.isInteger(limit) || limit < 1 || limit > 10_000) throw new RpcError(-32602, 'limit must be in [1, 10000]');
    const start = params.startLedger as number | undefined;
    const end = params.endLedger as number | undefined;
    let after: string;
    let scanFrom: number;
    if (pagination.cursor !== undefined) {
      if (start !== undefined || end !== undefined) {
        throw new RpcError(-32602, 'startLedger and endLedger must be omitted when a cursor is given');
      }
      if (!/^\d{19}-\d{10}$/.test(pagination.cursor)) throw new RpcError(-32602, 'invalid cursor');
      after = pagination.cursor;
      scanFrom = cursorLedger(after);
      if (scanFrom + 1 < this.oldestLedger) {
        throw new RpcError(-32600, `cursor is before the oldest ledger stored (${this.oldestLedger})`);
      }
    } else {
      if (start === undefined) throw new RpcError(-32602, 'startLedger or cursor required');
      if (start < this.oldestLedger || start > this.latestLedger) {
        throw new RpcError(
          -32600,
          `startLedger must be between the oldest ledger: ${this.oldestLedger} and the latest ledger: ${this.latestLedger}`,
        );
      }
      after = `${(toid(start, 0, 0) - 1n).toString().padStart(19, '0')}-4294967295`;
      scanFrom = start;
    }
    const endExclusive = Math.min(end ?? this.latestLedger + 1, scanFrom + SCAN_WINDOW_LEDGERS, this.latestLedger + 1);
    const scanned = this.events.filter(
      (e) => e.id > after && e.ledger >= this.oldestLedger && e.ledger < endExclusive,
    );
    const page = scanned.filter((e) => this.matches(e, filters)).slice(0, limit);
    const cursor =
      page.length === limit
        ? page[page.length - 1]!.id
        : `${(toid(endExclusive, 0, 0) - 1n).toString().padStart(19, '0')}-4294967295`;
    return {
      events: page,
      latestLedger: this.latestLedger,
      oldestLedger: this.oldestLedger,
      latestLedgerCloseTime: String(Math.floor(ledgerCloseTime(this.latestLedger).getTime() / 1000)),
      oldestLedgerCloseTime: String(Math.floor(ledgerCloseTime(this.oldestLedger).getTime() / 1000)),
      cursor,
    };
  }

  async listen(): Promise<string> {
    this.server = createServer(async (req, res) => {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      if (this.failures > 0) {
        this.failures--;
        res.writeHead(503);
        res.end();
        return;
      }
      let id: unknown = null;
      const reply = (body: unknown) => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id, ...(body as object) }));
      };
      try {
        const msg = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        id = msg.id ?? null;
        this.calls.push({ method: msg.method, params: msg.params });
        if (msg.method === 'getEvents') return reply({ result: this.getEvents(msg.params ?? {}) });
        if (msg.method === 'simulateTransaction' && this.onSimulate) {
          const value = this.onSimulate(String(msg.params?.transaction ?? ''));
          return reply({
            result: {
              latestLedger: this.latestLedger,
              minResourceFee: '0',
              results: [{ auth: [], xdr: value }],
              transactionData: '',
            },
          });
        }
        if (msg.method === 'getLatestLedger') {
          return reply({ result: { id: '0'.repeat(64), protocolVersion: 25, sequence: this.latestLedger } });
        }
        return reply({ error: { code: -32601, message: 'method not found' } });
      } catch (e) {
        if (e instanceof RpcError) return reply({ error: { code: e.code, message: e.message } });
        return reply({ error: { code: -32700, message: 'parse error' } });
      }
    });
    await new Promise<void>((r) => this.server!.listen(0, '127.0.0.1', r));
    this.url = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
    return this.url;
  }

  async close(): Promise<void> {
    if (this.server) await new Promise<void>((r) => this.server!.close(() => r()));
  }
}
