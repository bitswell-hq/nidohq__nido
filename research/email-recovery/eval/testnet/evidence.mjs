#!/usr/bin/env node
// The raw testnet evidence behind results/testnet.json,
// results/testnet-votes.json and results/testnet-restorations.json: for
// every transaction they record, its signed envelope, its result and its
// metadata as base64 XDR, read back from Stellar RPC while it still holds
// them; and for each run, its commit, the wasm it deployed and the circuit id
// its verifier reports, read back from the network. With them a reader can
// re-check every fee against the archived settings (fees/model.mjs) and
// re-verify each proof against its circuit after testnet is reset. Writes
// results/testnet-xdr.json. Read-only.
//
// `--check` instead fetches every transaction the file records again and
// compares it: the envelope and the result byte for byte, and the metadata
// after normalizing it. A ledger's hash covers its transactions and their
// results but not their metadata, which each RPC node's core writes as it
// applies the ledger, so two nodes may answer one transaction with metadata
// that differs: in its diagnostic events (the `core_metrics` event carries
// the answering node's own readings) and in the order in which an
// operation's ledger-entry changes are listed. The normalized form drops the
// diagnostic events and sorts each operation's changes; anything else that
// differs fails the check.
//
//   node research/email-recovery/eval/testnet/evidence.mjs [--check]
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { Networks, xdr } from '@stellar/stellar-sdk';
import { Chain } from '../network/lib/chain.mjs';

/** Base64 metadata XDR without its diagnostic events, each operation's ledger-entry changes sorted. */
export function normalizedMeta(metaXdr) {
  const meta = xdr.TransactionMeta.fromXDR(metaXdr, 'base64');
  const v = meta.switch() === 4 ? meta.v4() : meta.switch() === 3 ? meta.v3() : undefined;
  if (meta.switch() === 4) v.diagnosticEvents([]);
  else if (meta.switch() === 3) v.sorobanMeta()?.diagnosticEvents([]);
  for (const op of v?.operations() ?? []) {
    const sorted = op.changes().map((c) => [c.toXDR('base64'), c]).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    op.changes(sorted.map(([, c]) => c));
  }
  return meta.toXDR('base64');
}

const repo = new URL('../../../../', import.meta.url).pathname;
const RPC = process.env.NIDO_TESTNET_RPC ?? 'https://soroban-testnet.stellar.org';
const results = `${repo}research/email-recovery/eval/results/`;
const chain = new Chain({ rpcUrl: RPC, passphrase: Networks.TESTNET });

if (process.argv.includes('--check')) {
  const recorded = JSON.parse(readFileSync(`${results}testnet-xdr.json`, 'utf8')).transactions;
  const counts = { envelope: 0, result: 0, metaExact: 0, metaNormalized: 0, total: 0 };
  for (const [hash, t] of Object.entries(recorded)) {
    const got = await chain.call('getTransaction', { hash });
    counts.total++;
    if (got.envelopeXdr === t.envelopeXdr) counts.envelope++;
    if (got.resultXdr === t.resultXdr) counts.result++;
    if (got.resultMetaXdr === t.resultMetaXdr) counts.metaExact++;
    if (normalizedMeta(got.resultMetaXdr) === normalizedMeta(t.resultMetaXdr)) counts.metaNormalized++;
  }
  console.log(JSON.stringify(counts));
  const ok = counts.envelope === counts.total && counts.result === counts.total && counts.metaNormalized === counts.total;
  process.exit(ok ? 0 : 1);
}

const runs = {};
const transactions = {};
for (const [name, file] of [['recovery', 'testnet.json'], ['votes', 'testnet-votes.json'], ['restorations', 'testnet-restorations.json']]) {
  if (!existsSync(results + file)) continue;
  const r = JSON.parse(readFileSync(results + file, 'utf8'));
  const txs = r.transactions ?? [...(r.restores ?? []), ...(r.recovery ?? [])];
  const verifier = r.contracts?.['nido-email-verifier']?.address;
  runs[name] = {
    file: `research/email-recovery/eval/results/${file}`,
    generated: r.generated,
    commit: r.commit,
    wasm: r.contracts ? Object.fromEntries(Object.entries(r.contracts).map(([k, v]) => [k, { sha256: v.sha256, bytes: v.bytes, address: v.address }])) : undefined,
    verifier,
    circuitId: verifier ? Buffer.from(await chain.read(verifier, 'circuit_id')).toString('hex') : undefined,
    transactions: txs.map((t) => t.hash),
  };
  for (const t of txs) {
    if (transactions[t.hash]) continue;
    const got = await chain.call('getTransaction', { hash: t.hash });
    if (got.status !== 'SUCCESS' && got.status !== 'FAILED') throw new Error(`${t.hash}: ${got.status} (outside the RPC's retention?)`);
    transactions[t.hash] = { label: t.label, status: got.status, ledger: got.ledger, createdAt: got.createdAt, envelopeXdr: got.envelopeXdr, resultXdr: got.resultXdr, resultMetaXdr: got.resultMetaXdr };
  }
  console.error(`${name}: ${txs.length} transactions`);
}
writeFileSync(`${results}testnet-xdr.json`, JSON.stringify({ fetched: new Date().toISOString(), rpc: RPC, network: Networks.TESTNET, runs, transactions }, null, 1) + '\n');
