#!/usr/bin/env node
// Writes the key list (docs/email-recovery/spec.md §7.7): every DKIM key the
// registry knows, active or waiting in its timelock, with the selectors its
// attesters saw it under. The wallet serves the file from its own origin
// and checks every key in it against the chain before using it, so the file
// carries no trust; it only spares each user a lookup that would reveal
// their provider.
//
//   dkim-key-list.mjs --rpc <url> --registry <C...> --network <passphrase>
//                     [--start-ledger N] [--previous keys.json] [--out keys.json]
//
// It reads the registry's `key_proposed` and `dns_attested` events from
// --start-ledger (an RPC keeps a bounded history, so a scheduled job passes
// its previous output as --previous to keep keys proposed before that), then
// asks the registry about each key: a key whose leaf is present is `active`;
// an approved addition that has not executed or lapsed is `pending`;
// anything else (revoked, retired, refused) is left out.
import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { Account, Contract, TransactionBuilder, rpc, scValToNative, xdr } from '@stellar/stellar-sdk';
import { initHashes, keyHash } from '@nidohq/email-recovery';

const { values } = parseArgs({
  options: {
    rpc: { type: 'string' },
    registry: { type: 'string' },
    network: { type: 'string' },
    'start-ledger': { type: 'string' },
    previous: { type: 'string' },
    out: { type: 'string' },
  },
});
if (!values.rpc || !values.registry || !values.network) {
  console.error('usage: dkim-key-list.mjs --rpc <url> --registry <C...> --network <passphrase> [--start-ledger N] [--previous f] [--out f]');
  process.exit(2);
}
const server = new rpc.Server(values.rpc, { allowHttp: values.rpc.startsWith('http://') });
const hex = (b) => Buffer.from(b).toString('hex');
const text = (b) => Buffer.from(b).toString('latin1');
await initHashes();

async function view(fn, args) {
  const tx = new TransactionBuilder(new Account('GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF', '0'), { fee: '100', networkPassphrase: values.network })
    .addOperation(new Contract(values.registry).call(fn, ...args))
    .setTimeout(0)
    .build();
  const sim = await server.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim)) throw new Error(`${fn}: ${sim.error}`);
  return sim.result ? scValToNative(sim.result.retval) : undefined;
}

// Events, in pages.
const latest = (await server.getLatestLedger()).sequence;
// No earlier than the oldest ledger the RPC still holds.
const oldest = (await server.getHealth()).oldestLedger ?? 1;
const startLedger = Math.max(oldest, Number(values['start-ledger'] ?? latest - 17_280));
const proposals = new Map(); // id -> { domain, modulus, keyHash }
const selectors = new Map(); // id -> Set
let cursor;
for (;;) {
  const page = await server.getEvents(
    cursor
      ? { cursor, filters: [{ type: 'contract', contractIds: [values.registry] }], limit: 200 }
      : { startLedger, filters: [{ type: 'contract', contractIds: [values.registry] }], limit: 200 },
  );
  for (const e of page.events) {
    const name = scValToNative(e.topic[0]);
    const data = scValToNative(e.value);
    if (name === 'key_proposed' && Number(data.kind) === 1) {
      proposals.set(Number(data.id), { domain: text(scValToNative(e.topic[1])), modulus: BigInt(`0x${hex(data.modulus)}`), keyHash: hex(data.key_hash) });
    }
    if (name === 'dns_attested' && data.observed_live) {
      const s = selectors.get(Number(data.id)) ?? new Set();
      s.add(text(data.selector));
      selectors.set(Number(data.id), s);
    }
  }
  if (page.events.length < 200) break;
  cursor = page.cursor;
}

// Candidates: this run's proposals and the previous list.
const candidates = new Map();
for (const [id, p] of proposals) candidates.set(`${p.domain}/${p.keyHash}`, { ...p, id, selectors: [...(selectors.get(id) ?? [])] });
if (values.previous) {
  for (const k of JSON.parse(readFileSync(values.previous, 'utf8')).keys) {
    const key = `${k.domain}/${k.keyHash.replace(/^0x/, '')}`;
    if (!candidates.has(key)) candidates.set(key, { domain: k.domain, modulus: BigInt(k.modulus), keyHash: k.keyHash.replace(/^0x/, ''), selectors: k.selectors });
  }
}

const keys = [];
for (const c of candidates.values()) {
  if (keyHash(c.modulus).toString(16).padStart(64, '0') !== c.keyHash) throw new Error(`a ${c.domain} key's hash is not its modulus's`);
  const leaf = await view('leaf', [xdr.ScVal.scvBytes(Buffer.from(c.domain)), xdr.ScVal.scvBytes(Buffer.from(c.keyHash, 'hex'))]);
  let status;
  if (leaf?.present) status = 'active';
  else if (c.id !== undefined && !leaf?.revoked_by) {
    const p = await view('proposal', [xdr.ScVal.scvU32(c.id)]).catch(() => undefined);
    if (p && !p.executed && p.approved_at !== undefined && p.approved_at !== null) status = 'pending';
  }
  if (!status) continue;
  keys.push({ domain: c.domain, selectors: c.selectors, modulus: `0x${c.modulus.toString(16)}`, keyHash: `0x${c.keyHash}`, status });
}
keys.sort((a, b) => (a.domain + a.keyHash).localeCompare(b.domain + b.keyHash));
const list = { version: 1, network: values.network, registry: values.registry, ledger: latest, keys };
const out = JSON.stringify(list, null, 2) + '\n';
if (values.out) writeFileSync(values.out, out);
else process.stdout.write(out);
