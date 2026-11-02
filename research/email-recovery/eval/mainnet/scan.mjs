// What the alert host's transaction scan (docs/email-recovery/spec.md §10.2)
// costs at mainnet volume: it reads every transaction of a window of
// consecutive mainnet ledgers with Stellar RPC `getTransactions`, as the host
// does (`xdrFormat: "json"`, pages of 200, each page from the previous page's
// cursor), and records per page the transactions, the ledgers they span, the
// bytes on the wire (gzip, which the RPC serves when asked) and decoded, the
// time to the last byte, and the time to parse the JSON and walk every
// transaction for guardian votes (`guardianVotes`, the host's own code). The
// first ledgers of the window are read again in base64 to compare sizes.
// Read-only: it sends `getHealth`, `getVersionInfo` and `getTransactions`.
//
//   node research/email-recovery/eval/mainnet/scan.mjs [--rpc URL] [--ledgers N] [--base64-ledgers N] [--raw DIR] [--out FILE]
//
// Defaults: a public mainnet RPC, 720 ledgers (an hour at 5-second ledgers)
// ending 20 ledgers behind the latest, 60 of them in base64 too, results in
// eval/results/mainnet-scan.json. With --raw, every JSON page is kept
// gzipped in DIR (`<cursor>.json.gz`) for re-analysis.
import { mkdirSync, writeFileSync } from 'node:fs';
import { request } from 'node:https';
import { dirname, join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { guardianVotes } from '@nidohq/email-alerts';

const here = dirname(fileURLToPath(import.meta.url));
const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith('--') ? [...acc, [a.slice(2), all[i + 1]]] : acc), []),
);
const RPC = args.rpc ?? 'https://mainnet.sorobanrpc.com';
const LEDGERS = Number(args.ledgers ?? 720);
const BASE64_LEDGERS = Number(args['base64-ledgers'] ?? 60);
const OUT = args.out ?? join(here, '../results/mainnet-scan.json');
const RAW = args.raw;
const LIMIT = 200;
// Any contract address: the walk visits every node of every envelope whatever it is.
const CONTROLLER = 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC';

let id = 0;
/** One JSON-RPC call: the raw body's bytes on the wire and decoded, the time to its last byte. */
function call(method, params) {
  const body = JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params });
  const url = new URL(RPC);
  return new Promise((resolve, reject) => {
    const t0 = performance.now();
    const req = request(
      { hostname: url.hostname, path: url.pathname || '/', port: url.port || 443, method: 'POST', headers: { 'content-type': 'application/json', 'accept-encoding': 'gzip', 'content-length': Buffer.byteLength(body) } },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const ms = performance.now() - t0;
          const wire = Buffer.concat(chunks);
          const raw = res.headers['content-encoding'] === 'gzip' ? gunzipSync(wire) : wire;
          if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}: ${raw.toString('utf8').slice(0, 200)}`));
          resolve({ wire, raw, wireBytes: wire.length, rawBytes: raw.length, ms, gzip: res.headers['content-encoding'] === 'gzip' });
        });
        res.on('error', reject);
      },
    );
    req.on('error', reject);
    req.setTimeout(60_000, () => req.destroy(new Error('timeout')));
    req.end(body);
  });
}

async function rpc(method, params, attempt = 1) {
  try {
    const r = await call(method, params);
    const t0 = performance.now();
    const json = JSON.parse(r.raw.toString('utf8'));
    const parseMs = performance.now() - t0;
    if (json.error) throw new Error(`${method}: ${json.error.code} ${json.error.message}`);
    return { ...r, result: json.result, parseMs };
  } catch (e) {
    if (attempt >= 5) throw e;
    const wait = 2_000 * 2 ** (attempt - 1);
    console.error(`${method} failed (${e.message}); again in ${wait} ms`);
    await new Promise((r) => setTimeout(r, wait));
    return rpc(method, params, attempt + 1);
  }
}

const ledgerOf = (cursor) => Number(BigInt(cursor) >> 32n);
const isSoroban = (tx) => JSON.stringify(tx.envelopeJson ?? '').includes('"invoke_host_function"');

/** Read every transaction of ledgers [first, first + count) in `format`; one row per page. */
async function scan(first, count, format, keep) {
  const end = first + count;
  const pages = [];
  const perLedger = new Map();
  let from = { startLedger: first };
  for (;;) {
    const r = await rpc('getTransactions', { ...from, xdrFormat: format, pagination: { ...('cursor' in from ? { cursor: from.cursor } : {}), limit: LIMIT } });
    const txs = r.result.transactions.filter((t) => t.ledger < end);
    const t0 = performance.now();
    let votes = 0;
    if (format === 'json') for (const tx of txs) votes += guardianVotes(tx, CONTROLLER).length;
    const scanMs = performance.now() - t0;
    for (const tx of txs) {
      const l = perLedger.get(tx.ledger) ?? { txs: 0, success: 0, soroban: 0 };
      l.txs++;
      if (tx.status === 'SUCCESS') l.success++;
      if (format === 'json' && isSoroban(tx)) l.soroban++;
      perLedger.set(tx.ledger, l);
    }
    pages.push({
      txs: r.result.transactions.length,
      inWindow: txs.length,
      firstLedger: r.result.transactions[0]?.ledger ?? null,
      lastLedger: r.result.transactions.at(-1)?.ledger ?? null,
      cursor: r.result.cursor,
      cursorLedger: ledgerOf(r.result.cursor),
      wireBytes: r.wireBytes,
      rawBytes: r.rawBytes,
      gzip: r.gzip,
      requestMs: Math.round(r.ms),
      parseMs: Math.round(r.parseMs * 10) / 10,
      scanMs: Math.round(scanMs * 10) / 10,
      votes,
    });
    if (keep && RAW) writeFileSync(join(RAW, `${r.result.cursor}.json.gz`), r.gzip ? r.wire : r.raw);
    process.stderr.write(`\r${format}: ${pages.length} pages, ledger ${ledgerOf(r.result.cursor)} of ${end - 1}   `);
    if (r.result.transactions.length < LIMIT || txs.length < r.result.transactions.length) break;
    from = { cursor: r.result.cursor };
  }
  process.stderr.write('\n');
  return { pages, perLedger };
}

const sum = (xs) => xs.reduce((a, b) => a + b, 0);
const pct = (xs, p) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))];
};
const stats = (xs) => ({ mean: Math.round((sum(xs) / xs.length) * 10) / 10, median: pct(xs, 50), p95: pct(xs, 95), max: Math.max(...xs), min: Math.min(...xs) });

if (RAW) mkdirSync(RAW, { recursive: true });
const version = await rpc('getVersionInfo', {});
const health = await rpc('getHealth', {});
const last = health.result.latestLedger - 20;
const first = last - LEDGERS + 1;
console.error(`${RPC}: latest ${health.result.latestLedger}, reading ledgers ${first}..${last}`);
const startedAt = new Date().toISOString();
const t0 = performance.now();
const json = await scan(first, LEDGERS, 'json', true);
const jsonWallMs = performance.now() - t0;
const b64 = BASE64_LEDGERS > 0 ? await scan(first, BASE64_LEDGERS, 'base64', false) : undefined;

const ledgers = [...json.perLedger.values()];
const txs = ledgers.map((l) => l.txs);
const pages = json.pages;
const window = (p, n) => p.filter((x) => x.firstLedger !== null && x.firstLedger < first + n);
const jsonFirst = window(pages, BASE64_LEDGERS);
const result = {
  what: 'Every transaction of consecutive mainnet ledgers read with getTransactions as the alert host reads them (xdrFormat json, pages of 200 from the previous cursor); read-only',
  rpc: RPC,
  rpcVersion: version.result,
  startedAt,
  ledgers: { first, last, count: LEDGERS, withTransactions: json.perLedger.size },
  transactions: {
    total: sum(txs),
    success: sum(ledgers.map((l) => l.success)),
    soroban: sum(ledgers.map((l) => l.soroban)),
    perLedger: stats(txs),
  },
  json: {
    pages: pages.length,
    pagesPerLedger: Math.round((pages.length / LEDGERS) * 100) / 100,
    wireBytes: sum(pages.map((p) => p.wireBytes)),
    rawBytes: sum(pages.map((p) => p.rawBytes)),
    wireBytesPerLedger: Math.round(sum(pages.map((p) => p.wireBytes)) / LEDGERS),
    rawBytesPerLedger: Math.round(sum(pages.map((p) => p.rawBytes)) / LEDGERS),
    rawBytesPerTransaction: Math.round(sum(pages.map((p) => p.rawBytes)) / sum(txs)),
    pageRawBytes: stats(pages.map((p) => p.rawBytes)),
    pageWireBytes: stats(pages.map((p) => p.wireBytes)),
    requestMs: stats(pages.map((p) => p.requestMs)),
    parseMs: stats(pages.map((p) => p.parseMs)),
    scanMs: stats(pages.map((p) => p.scanMs)),
    hostMsPerLedger: Math.round((sum(pages.map((p) => p.parseMs + p.scanMs)) / LEDGERS) * 10) / 10,
    requestMsPerLedger: Math.round(sum(pages.map((p) => p.requestMs)) / LEDGERS),
    wallMs: Math.round(jsonWallMs),
    votesFound: sum(pages.map((p) => p.votes)),
  },
  ...(b64
    ? {
        base64: {
          ledgers: BASE64_LEDGERS,
          pages: b64.pages.length,
          rawBytes: sum(b64.pages.map((p) => p.rawBytes)),
          wireBytes: sum(b64.pages.map((p) => p.wireBytes)),
          jsonRawBytesSameLedgers: sum(jsonFirst.map((p) => p.rawBytes)),
          jsonWireBytesSameLedgers: sum(jsonFirst.map((p) => p.wireBytes)),
        },
      }
    : {}),
  cursor: {
    rule: 'a getTransactions cursor is a TOID: its ledger is cursor >> 32',
    fullPagesWhoseCursorIsTheirLastTransactionsLedger: pages.filter((p) => p.txs === LIMIT && p.cursorLedger === p.lastLedger).length,
    fullPages: pages.filter((p) => p.txs === LIMIT).length,
  },
  pages,
};
mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, `${JSON.stringify(result, null, 1)}\n`);
console.error(JSON.stringify({ ...result, pages: undefined }, null, 1));
