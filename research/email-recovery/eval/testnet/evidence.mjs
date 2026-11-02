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
//   node research/email-recovery/eval/testnet/evidence.mjs
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { Networks } from '@stellar/stellar-sdk';
import { Chain } from '../network/lib/chain.mjs';

const repo = new URL('../../../../', import.meta.url).pathname;
const RPC = process.env.NIDO_TESTNET_RPC ?? 'https://soroban-testnet.stellar.org';
const results = `${repo}research/email-recovery/eval/results/`;
const chain = new Chain({ rpcUrl: RPC, passphrase: Networks.TESTNET });
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
