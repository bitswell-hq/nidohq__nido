#!/usr/bin/env node
// What the alert service's watcher reads to find email votes on mainnet
// (infra/email-alerts/src/votes.ts): every transaction, through Stellar RPC
// `getTransactions` with `xdrFormat: "json"`, 200 a page, as the watcher
// pages. Samples `ledgers` consecutive closed mainnet ledgers through one
// public RPC and writes results/watcher-load-mainnet.json: the transactions
// and Soroban transactions per ledger, the octets of JSON the RPC sent, and
// the time it took to fetch them against the chain time they span. Read-only.
//
//   NIDO_MAINNET_RPC=<url> node research/email-recovery/eval/watcher-load.mjs [ledgers]   (default 24)
import { writeFileSync } from 'node:fs';
import { loadavg } from 'node:os';

const RPC = process.env.NIDO_MAINNET_RPC ?? 'https://mainnet.sorobanrpc.com';
const ledgers = Number(process.argv[2] ?? 24);
const LEDGER_SECONDS = 5;

async function call(method, params) {
  const res = await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  const text = await res.text();
  const body = JSON.parse(text);
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return { result: body.result, octets: Buffer.byteLength(text) };
}

const { result: latest } = await call('getLatestLedger', {});
// Closed ledgers only, a little behind the tip.
const start = latest.sequence - ledgers - 2;
const end = start + ledgers; // exclusive
let cursor;
let octets = 0;
let pages = 0;
const perLedger = new Map();
const t0 = performance.now();
for (;;) {
  const { result, octets: n } = await call('getTransactions', { xdrFormat: 'json', pagination: cursor ? { cursor, limit: 200 } : { limit: 200 }, ...(cursor ? {} : { startLedger: start }) });
  octets += n;
  pages++;
  let done = result.transactions.length === 0;
  for (const tx of result.transactions) {
    if (tx.ledger >= end) {
      done = true;
      break;
    }
    const soroban = /"(invoke_host_function|extend_footprint_ttl|restore_footprint)"/.test(JSON.stringify(tx.envelopeJson));
    const l = perLedger.get(tx.ledger) ?? { transactions: 0, soroban: 0 };
    l.transactions++;
    if (soroban) l.soroban++;
    perLedger.set(tx.ledger, l);
  }
  if (done) break;
  cursor = result.cursor;
}
const fetchMs = performance.now() - t0;
const txs = [...perLedger.values()].reduce((a, l) => a + l.transactions, 0);
const soroban = [...perLedger.values()].reduce((a, l) => a + l.soroban, 0);
const round = (x, d = 2) => Math.round(x * 10 ** d) / 10 ** d;
const out = {
  generated: new Date().toISOString(),
  rpc: RPC,
  ledgers: { first: start, last: end - 1, count: ledgers },
  pages,
  transactions: txs,
  sorobanTransactions: soroban,
  jsonOctets: octets,
  octetsPerLedger: Math.round(octets / ledgers),
  octetsPerDayAtLedgerTarget: Math.round((octets / ledgers) * (86_400 / LEDGER_SECONDS)),
  fetchSeconds: round(fetchMs / 1000),
  chainSeconds: ledgers * LEDGER_SECONDS,
  fetchMarginOverChainTime: round((ledgers * LEDGER_SECONDS) / (fetchMs / 1000)),
  loadAverageAtEnd: round(loadavg()[0], 1),
};
writeFileSync(new URL('./results/watcher-load-mainnet.json', import.meta.url), `${JSON.stringify(out, null, 2)}\n`);
console.log(JSON.stringify(out));
