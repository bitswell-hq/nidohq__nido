#!/usr/bin/env node
// Rewrites the generated blocks of research/email-recovery/eval/README.md
// from the result files in results/:
//
// - `attacks`: attacks-local.json (network/attacks.mjs) and
//   attacks-test-host.jsonl (the registry scenarios of
//   crates/integration-tests/tests/it/email_guardian.rs);
// - `cost`: the email votes' transactions in attacks-local.json, and the
//   testnet run in testnet.json when present;
// - `proving`: proving.json (proving/measure.mjs) when present.
//
//   node research/email-recovery/eval/report.mjs
import { existsSync, readFileSync, writeFileSync } from 'node:fs';

const here = new URL('./', import.meta.url).pathname;
const results = `${here}results/`;
const readme = `${here}README.md`;
const json = (f) => (existsSync(results + f) ? JSON.parse(readFileSync(results + f, 'utf8')) : undefined);
const jsonl = (f) => (existsSync(results + f) ? readFileSync(results + f, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []);
const n = (x) => (x === undefined || x === null || Number.isNaN(Number(x)) ? '—' : Number(x).toLocaleString('en-US'));
const median = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length ? (s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2) : undefined;
};
const range = (xs) => (xs.length ? `${n(Math.min(...xs))} to ${n(Math.max(...xs))}` : '—');
const cell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');

const CLASSES = {
  forged: 'Forged emails',
  replay: 'Replayed emails and proofs',
  statement: 'Wrong account or new key in the statement',
  registry: 'Stale or malicious registry keys',
  inbox: 'Compromised inbox',
  quirks: 'Provider header quirks',
  'front-running': 'Front-running',
  privacy: 'Privacy on chain',
};
const FILES = {
  local: 'research/email-recovery/eval/network/attacks.mjs',
  'test host': 'crates/integration-tests/tests/it/email_guardian.rs',
};

function attacks() {
  const local = json('attacks-local.json');
  if (!local) return 'No local-network run is recorded.';
  const host = jsonl('attacks-test-host.jsonl');
  const rows = [...local.rows, ...host];
  const out = [];
  out.push(
    `Local network: \`${local.network.kind}\` (${local.network.image}), protocol ${local.network.protocolVersion ?? '?'}, ` +
      `Stellar RPC ${local.network.rpc?.version ?? '?'} with captive core ${(local.network.rpc?.captiveCoreVersion ?? '?').replace(/^stellar-core /, '').split(' ')[0]}; ` +
      `run of ${local.generated.slice(0, 16).replace('T', ' ')} UTC, ${Math.round(local.durationSeconds / 60)} minutes, ${local.transactions.length} transactions.`,
  );
  out.push(host.length ? `Test host: ${host.length} rows from \`${FILES['test host']}\` (\`registry_*\`).` : 'Test host: not run.');
  out.push('');
  out.push('| Class | Scenario | Expected | Observed | Refusing layer | Test | Property | Where |');
  out.push('| --- | --- | --- | --- | --- | --- | --- | --- |');
  const order = Object.keys(CLASSES);
  rows.sort((a, b) => order.indexOf(a.class) - order.indexOf(b.class));
  for (const r of rows) {
    out.push(
      `| ${CLASSES[r.class] ?? r.class} | ${cell(r.scenario)}${r.note ? `: ${cell(r.note)}` : ''} | ${cell(r.expected)} | ${cell(r.observed)} | ${cell(r.layer)} | \`${r.network === 'local' ? 'attacks.mjs' : 'email_guardian.rs'}\` ${cell(r.test)} | ${r.property} | ${r.network} |`,
    );
  }
  const failed = rows.filter((r) => r.observed !== r.expected);
  out.push('');
  out.push(failed.length ? `**${failed.length} rows differ from their expectation.**` : `Every row's observed outcome is its expected one (${rows.length} rows).`);
  out.push('');
  out.push('<details><summary>The circuit\'s verdict on each adversarial email of the mocks, built for a live attempt (forged-emails-circuit)</summary>');
  out.push('');
  out.push('| Case | Mocks\' verdict | Key tree | Outcome | Same as `attacks.test.ts` |');
  out.push('| --- | --- | --- | --- | --- |');
  for (const c of local.circuitCases) out.push(`| ${c.id} | ${c.verdict} | ${c.tree} | ${cell(c.outcome)} | ${c.outcome === c.pinned ? 'yes' : `no (${cell(c.pinned)})`} |`);
  out.push('');
  out.push('</details>');
  return out.join('\n');
}

function votes(local) {
  return local.transactions.filter((t) => t.status === 'SUCCESS' && /^submit_guardian \(email/.test(t.label) && t.metered);
}

function cost() {
  const local = json('attacks-local.json');
  const out = [];
  if (local) {
    const all = votes(local);
    const plain = all.filter((t) => !/authorizes/.test(t.label));
    const auth = all.filter((t) => /authorizes/.test(t.label));
    out.push(`Local network: every accepted email vote of the attack run, each \`submit_guardian\` with a real proof, simulated with its authorization entry enforced and sent; figures read from each transaction's result and the host's \`core_metrics\` events. ${plain.length} votes leave their attempt collecting (a 2-of-n quorum); ${auth.length} authorizes its attempt (the email-plus-delay account, quorum 1, delay 120,960 ledgers), which also writes the authorized attempt.`);
    out.push('');
    out.push(`| Figure | Vote, attempt still collecting: median (range), ${plain.length} | Vote that authorizes the attempt |`);
    out.push('| --- | --- | --- |');
    const row = (label, f) => {
      const xs = plain.map(f).filter((x) => x !== undefined);
      const ys = auth.map(f).filter((x) => x !== undefined);
      out.push(`| ${label} | ${n(Math.round(median(xs) ?? NaN))} (${range(xs)}) | ${ys.map(n).join(', ') || '—'} |`);
    };
    row('Instructions (metered)', (t) => t.metered.cpu_insn);
    row('Instructions (declared in the transaction)', (t) => t.declared?.instructions);
    row('Memory bytes (metered)', (t) => t.metered.mem_byte);
    row('Ledger entries read (metered)', (t) => t.metered.read_entry);
    row('Ledger entries written (metered)', (t) => t.metered.write_entry);
    row('Ledger bytes read from disk (metered)', (t) => t.metered.ledger_read_byte);
    row('Ledger bytes written (metered)', (t) => t.metered.ledger_write_byte);
    row('Footprint entries (read-only + read-write)', (t) => (t.declared ? t.declared.readOnly + t.declared.readWrite : undefined));
    row('Signed envelope bytes', (t) => t.envelopeBytes);
    row('Authorization entry bytes', (t) => t.authEntryBytes);
    row('Fee charged (stroops)', (t) => t.feeCharged);
    row('of which rent (stroops)', (t) => t.feeSplit?.rent);
    row('Resource fee declared (stroops)', (t) => t.declared?.resourceFee);
    row('Wall clock, simulation to confirmation (ms)', (t) => t.ms?.total);
  }
  // The same call in each environment, per launch domain.
  const host = existsSync(`${here}onchain.md`)
    ? readFileSync(`${here}onchain.md`, 'utf8').split('\n').filter((l) => l.startsWith('{"address_bytes"')).map((l) => JSON.parse(l))
    : [];
  const testnetRun = json('testnet.json');
  if (local && host.length) {
    const byDomain = Object.fromEntries(votes(local).map((t) => [/, ([a-z.]+)\)$/.exec(t.label)?.[1], t]).filter(([d]) => d));
    const tvote = testnetRun?.transactions.find((t) => t.hash === testnetRun.votes?.email);
    out.push('');
    out.push('The same call, the email vote with a real proof, in each environment (instructions; footprint as read-only + read-write entries). Test host from `onchain.md`; local network from this run; testnet from `results/testnet.json` (Gmail only).');
    out.push('');
    out.push('| Domain | Test host invocation | Test host transaction | Test host footprint | Local network, metered | Local network, declared | Local footprint | Testnet, metered |');
    out.push('| --- | --- | --- | --- | --- | --- | --- | --- |');
    for (const h of host.filter((x) => x.label.startsWith('provider-'))) {
      const l = byDomain[h.domain];
      const fp = l?.declared ? `${l.declared.readOnly} + ${l.declared.readWrite}` : '—';
      const tn = h.domain === 'gmail.com' && tvote ? n(tvote.metered?.cpu_insn ?? tvote.simulated?.instructions) : '';
      out.push(`| ${h.domain} | ${n(h.host.instructions)} | ${n(h.tx.instructions)} | ${h.tx.read_only} + ${h.tx.read_write} | ${n(l?.metered?.cpu_insn)} | ${n(l?.declared?.instructions)} | ${fp} | ${tn} |`);
    }
    const registry = local.contracts?.registry;
    const withFp = votes(local).filter((t) => t.footprint);
    if (registry && withFp.length) {
      const reads = withFp.filter((t) => [...t.footprint.readOnly, ...t.footprint.readWrite].some((k) => k.startsWith(`data ${registry.slice(0, 6)} `))).length;
      out.push('');
      out.push(`The registry is in the footprint of ${reads} of the ${withFp.length} local votes: each local approval is proven against its guardian's key pin (no registry key activates during a local run), so the guardian accepts the root without calling the registry. The test host's approvals use a registry root, and its footprints include the registry's instance and code.`);
    }
  }
  const testnet = testnetRun;
  if (testnet) {
    out.push('');
    out.push(testnet.table ?? '');
  } else {
    out.push('');
    out.push('Testnet: not yet run.');
  }
  return out.join('\n');
}

function proving() {
  const p = json('proving.json');
  if (!p) return 'Not yet run.';
  return p.table;
}

let text = readFileSync(readme, 'utf8');
for (const [name, body] of Object.entries({ attacks: attacks(), cost: cost(), proving: proving() })) {
  const re = new RegExp(`(<!-- BEGIN GENERATED ${name} by report\\.mjs; do not edit -->)[\\s\\S]*?(<!-- END GENERATED ${name} -->)`);
  if (!re.test(text)) throw new Error(`README.md has no generated block "${name}"`);
  text = text.replace(re, (_, begin, end) => `${begin}\n${body}\n${end}`);
}
writeFileSync(readme, text);
console.log('rewrote', readme);
