#!/usr/bin/env node
// Rewrites the generated blocks of research/email-recovery/eval/README.md
// from the result files in results/:
//
// - `settings`: settings/{mainnet,testnet,local}.json (fees/settings.mjs),
//   each network's Soroban settings, beside the SDK's fee snapshot the test
//   host prices with;
// - `attacks`: attacks-local.json (network/attacks.mjs) and
//   attacks-test-host.jsonl (the registry scenarios of
//   crates/integration-tests/tests/it/email_guardian.rs);
// - `cost`: the email votes on the local network (attacks-local.json,
//   registry-root-local.json) and testnet (testnet.json, testnet-votes.json),
//   the test host's readings (onchain.md, archival-test-host.json), each
//   vote's fee by component under its network's settings (fees/model.mjs),
//   and what one ledger of mainnet holds;
// - `archival`: the testnet run's restorations, the recovery with every
//   entry archived (archival-test-host.json) as transactions under mainnet's
//   limits and fees (fees/archival.mjs), and the keeper's rent
//   (keeper-local.json, code-entries.json);
// - `proving`: proving.json (proving/measure.mjs) when present.
//
// Every fee a network charged in these files is recomputed from that
// network's archived settings; one the model does not reproduce stops the
// report.
//
//   node research/email-recovery/eval/report.mjs
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { SDK_SNAPSHOT, breakdown, codeRentBytes, rentFee, resourceFee, resourcesOf, schedule, averageStateSize } from './fees/model.mjs';
import { limits, plan } from './fees/archival.mjs';

const here = new URL('./', import.meta.url).pathname;
const results = `${here}results/`;
const readme = `${here}README.md`;
const json = (f) => (existsSync(results + f) ? JSON.parse(readFileSync(results + f, 'utf8')) : undefined);
const jsonl = (f) => (existsSync(results + f) ? readFileSync(results + f, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []);
const n = (x) => (x === undefined || x === null || Number.isNaN(Number(x)) ? '—' : Number(x).toLocaleString('en-US'));
const xlm = (stroops) => `${(stroops / 1e7).toLocaleString('en-US', { maximumFractionDigits: stroops < 1e7 ? 4 : 1 })} XLM`;
const median = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length ? (s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2) : undefined;
};
const range = (xs) => (xs.length ? `${n(Math.min(...xs))} to ${n(Math.max(...xs))}` : '—');
const stat = (xs) => (xs.length ? `${n(Math.round(median(xs)))} (${range(xs)})` : '—');
const cell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
const day = (iso) => iso.slice(0, 16).replace('T', ' ');

const S = Object.fromEntries(['mainnet', 'testnet', 'local'].map((k) => [k, json(`settings/${k}.json`)]));
const YEAR_LEDGERS = 6_307_200; // 365 days at 5-second ledgers

const CLASSES = {
  forged: 'Forged emails',
  replay: 'Replayed emails and proofs',
  statement: 'Wrong account or new key in the statement',
  registry: 'Stale or malicious registry keys',
  inbox: 'Compromised inbox',
  alerts: 'Alert path',
  social: 'Phishing and social engineering',
  griefing: 'Repeated attempts',
  quirks: 'Provider header quirks',
  'front-running': 'Front-running',
  privacy: 'Privacy on chain',
};
const FILES = {
  local: 'research/email-recovery/eval/network/attacks.mjs',
  'test host': 'crates/integration-tests/tests/it/email_guardian.rs',
};

/** Every recorded network transaction against its network's settings. */
function validate() {
  const sets = [
    ['attacks-local.json', 'local'],
    ['registry-root-local.json', 'local'],
    ['keeper-local.json', 'local'],
    ['testnet.json', 'testnet'],
    ['testnet-votes.json', 'testnet'],
  ];
  const counts = {};
  for (const [file, net] of sets) {
    const r = json(file);
    if (!r || !S[net]) continue;
    const txs = r.transactions.filter((t) => t.feeSplit && t.declared);
    for (const t of txs) {
      const b = breakdown(t, S[net].settings);
      if (!b.matches) throw new Error(`${file}: ${t.label} (${t.hash}) charged ${JSON.stringify(t.feeSplit)}, the model gives ${b.nonRefundable} + ${b.events} + rent`);
    }
    counts[net] = (counts[net] ?? 0) + txs.length;
  }
  return counts;
}

function settingsTable() {
  if (!S.mainnet) return 'No settings are archived.';
  const env = ['mainnet', 'testnet', 'local'].filter((k) => S[k]);
  const out = [];
  for (const k of env) {
    const s = S[k];
    out.push(`- **${k}**: \`${s.passphrase}\`, protocol ${s.protocolVersion}, ${s.coreVersion}, Stellar RPC ${s.rpcVersion.split('-')[0]}; read from ${s.rpc} at ledger ${n(s.ledger.sequence)}, ${day(s.fetched)} UTC.`);
  }
  out.push('');
  const row = (label, f, sdk = '') => out.push(`| ${label} | ${env.map((k) => f(S[k].settings)).join(' | ')} | ${sdk} |`);
  out.push(`| Setting | ${env.join(' | ')} | SDK snapshot (test host) |`);
  out.push(`| --- | ${env.map(() => '---').join(' | ')} | --- |`);
  row('Fee per 10,000 instructions', (s) => n(s.contract_compute_v0.fee_rate_per_instructions_increment), n(SDK_SNAPSHOT.instructionIncrement));
  row('Fee per entry read from disk', (s) => n(s.contract_ledger_cost_v0.fee_disk_read_ledger_entry), n(SDK_SNAPSHOT.diskReadEntry));
  row('Fee per KB read from disk', (s) => n(s.contract_ledger_cost_v0.fee_disk_read1_kb), n(SDK_SNAPSHOT.diskRead1kb));
  row('Fee per entry written', (s) => n(s.contract_ledger_cost_v0.fee_write_ledger_entry), n(SDK_SNAPSHOT.writeEntry));
  row('Fee per KB written', (s) => n(s.contract_ledger_cost_ext_v0.fee_write1_kb), n(SDK_SNAPSHOT.write1kb));
  row('Fee per KB of history (transaction + 300)', (s) => n(s.contract_historical_data_v0.fee_historical1_kb), n(SDK_SNAPSHOT.historical1kb));
  row('Fee per KB of transaction size', (s) => n(s.contract_bandwidth_v0.fee_tx_size1_kb), n(SDK_SNAPSHOT.txSize1kb));
  row('Fee per KB of events', (s) => n(s.contract_events_v0.fee_contract_events1_kb), n(SDK_SNAPSHOT.events1kb));
  row('Rent per KB, effective (average state size)', (s) => `${n(schedule(s).rent1kb)} (${n(averageStateSize(s))} B)`, `${n(SDK_SNAPSHOT.rent1kb)} (fixed)`);
  row('Rent denominators, persistent / temporary', (s) => `${n(s.state_archival.persistent_rent_rate_denominator)} / ${n(s.state_archival.temp_rent_rate_denominator)}`, `${n(SDK_SNAPSHOT.persistentRentDenominator)} / ${n(SDK_SNAPSHOT.temporaryRentDenominator)}`);
  row('Minimum persistent / temporary lifetime (ledgers)', (s) => `${n(s.state_archival.min_persistent_ttl)} / ${n(s.state_archival.min_temporary_ttl)}`);
  row('Maximum entry lifetime (ledgers)', (s) => n(s.state_archival.max_entry_ttl));
  row('Instructions per transaction / per ledger cluster', (s) => `${n(s.contract_compute_v0.tx_max_instructions)} / ${n(s.contract_compute_v0.ledger_max_instructions)}`);
  row('Dependent transaction clusters per stage', (s) => n(s.contract_parallel_compute_v0.ledger_max_dependent_tx_clusters));
  row('Bytes read from disk / written per transaction', (s) => `${n(s.contract_ledger_cost_v0.tx_max_disk_read_bytes)} / ${n(s.contract_ledger_cost_v0.tx_max_write_bytes)}`);
  row('Transaction size / ledger transactions size (bytes)', (s) => `${n(s.contract_bandwidth_v0.tx_max_size_bytes)} / ${n(s.contract_bandwidth_v0.ledger_max_txs_size_bytes)}`);
  out.push(`| Ledger target close time (ms) | ${env.map((k) => `${n(S[k].settings.scp_timing.ledger_target_close_time_milliseconds)}${k === 'local' ? ' (local mode closes about one ledger a second)' : ''}`).join(' | ')} |  |`);
  const differ = (a, b) => a.filter((x, i) => JSON.stringify(x) !== JSON.stringify(b[i])).length;
  if (S.testnet) {
    out.push('');
    out.push(`Cost models: ${S.mainnet.settings.contract_cost_params_cpu_instructions.length} cost types on each network; testnet's CPU model differs from mainnet's in ${differ(S.testnet.settings.contract_cost_params_cpu_instructions, S.mainnet.settings.contract_cost_params_cpu_instructions)} of them and its memory model in ${differ(S.testnet.settings.contract_cost_params_memory_bytes, S.mainnet.settings.contract_cost_params_memory_bytes)}${S.local ? `; the local network's models are mainnet's (${differ(S.local.settings.contract_cost_params_cpu_instructions, S.mainnet.settings.contract_cost_params_cpu_instructions)} CPU and ${differ(S.local.settings.contract_cost_params_memory_bytes, S.mainnet.settings.contract_cost_params_memory_bytes)} memory differences)` : ''}.`);
  }
  return out.join('\n');
}

function attacks() {
  const local = json('attacks-local.json');
  if (!local) return 'No local-network run is recorded.';
  const host = jsonl('attacks-test-host.jsonl');
  const rows = [...local.rows, ...host];
  const out = [];
  out.push(
    `Local network: \`${local.network.kind}\` (${local.network.image}), protocol ${local.network.protocolVersion ?? '?'}, mainnet's settings, ` +
      `Stellar RPC ${local.network.rpc?.version ?? '?'} with captive core ${(local.network.rpc?.captiveCoreVersion ?? '?').replace(/^stellar-core /, '').split(' ')[0]}; ` +
      `run of ${day(local.generated)} UTC, ${Math.round(local.durationSeconds / 60)} minutes, ${local.transactions.length} transactions.`,
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

const isVote = (t) => t.status === 'SUCCESS' && /^submit_guardian \(email/.test(t.label) && t.metered;
/** Email votes that leave their attempt collecting (no attempt record written). */
const collecting = (txs) => txs.filter((t) => isVote(t) && !/authorizes/.test(t.label));

/** One fee-breakdown column: `t`'s resources under schedule `sch`, its rent and inclusion if charged. */
function column(t, sch, { rent, charged } = {}) {
  const f = resourceFee(resourcesOf(t), sch);
  const total = f.nonRefundable + f.events + (rent ?? 0);
  return { ...f, rent, inclusion: charged !== undefined ? charged - total : undefined, total: charged ?? total };
}

/** A column priced as mainnet would charge it: its rent and the minimum inclusion fee of 100 stroops. */
function projection(c) {
  return { ...c, inclusion: 100, total: c.nonRefundable + c.events + c.rent + 100 };
}

function cost() {
  const local = json('attacks-local.json');
  const root = json('registry-root-local.json');
  const tn = json('testnet.json');
  const tv = json('testnet-votes.json');
  const archival = json('archival-test-host.json');
  const host = existsSync(`${here}onchain.md`)
    ? readFileSync(`${here}onchain.md`, 'utf8').split('\n').filter((l) => l.startsWith('{"address_bytes"')).map((l) => JSON.parse(l))
    : [];
  const counts = validate();
  const out = [];
  out.push(`Fees: fees/model.mjs reproduces every fee charged in these runs from the network's archived settings, to the stroop: ${Object.entries(counts).map(([k, v]) => `${n(v)} transactions on ${k === 'local' ? 'the local network' : k}`).join(', ')} (non-refundable and refundable resource fee as each transaction's fee split records them; the rest is the inclusion fee).`);
  if (local) {
    const plain = collecting(local.transactions);
    const auth = local.transactions.filter((t) => isVote(t) && /authorizes/.test(t.label));
    out.push('');
    out.push(`Local network, pin path: every accepted email vote of the attack run, each \`submit_guardian\` with a real proof, simulated with its authorization entry enforced and sent; figures read from each transaction's result and the host's \`core_metrics\` events. ${plain.length} votes leave their attempt collecting (a 2-of-n quorum); ${auth.length} authorizes its attempt (the email-plus-delay account, quorum 1, delay 120,960 ledgers), which also writes the authorized attempt.`);
    out.push('');
    out.push(`| Figure | Vote, attempt still collecting: median (range), ${plain.length} | Vote that authorizes the attempt |`);
    out.push('| --- | --- | --- |');
    const row = (label, f) => {
      const xs = plain.map(f).filter((x) => x !== undefined);
      const ys = auth.map(f).filter((x) => x !== undefined);
      out.push(`| ${label} | ${stat(xs)} | ${ys.map(n).join(', ') || '—'} |`);
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
  if (root) {
    const votes = (path) => root.transactions.filter((t) => isVote(t) && t.label.includes(`, ${path}, `));
    const reg = votes('registry');
    const pin = votes('pin');
    const registry = root.contracts.registry.slice(0, 6);
    const inFp = (t) => [...t.footprint.readOnly, ...t.footprint.readWrite].some((k) => k.includes(registry));
    out.push('');
    out.push(`Local network, registry root beside the pin: one run (${day(root.generated)} UTC) deployed the stack, enrolled per launch domain an account whose guardian has no pin and one with the wallet's 30-day pin, waited ${n(root.waited.ledgers)} ledgers (${(root.waited.seconds / 3600).toFixed(1)} hours) for the additions' attested 72-hour timelock (51,840 ledgers), executed each addition, and submitted one email vote per account: ${reg.length} against the registry's root, ${pin.length} against the pin, on the same network at the same time. The registry's instance and code are in the footprint of ${reg.filter(inFp).length} of the ${reg.length} registry-root votes and ${pin.filter(inFp).length} of the ${pin.length} pin votes.`);
    out.push('');
    out.push(`| Figure: median (range) | Registry root (${reg.length}) | Pin (${pin.length}) | Difference of medians |`);
    out.push('| --- | --- | --- | --- |');
    const row = (label, f) => {
      const a = reg.map(f);
      const b = pin.map(f);
      out.push(`| ${label} | ${stat(a)} | ${stat(b)} | ${n(Math.round(median(a) - median(b)))} |`);
    };
    row('Instructions (metered)', (t) => t.metered.cpu_insn);
    row('Instructions (declared)', (t) => t.declared.instructions);
    row('Ledger entries read (metered)', (t) => t.metered.read_entry);
    row('Footprint entries (read-only + read-write)', (t) => t.declared.readOnly + t.declared.readWrite);
    row('Ledger bytes written (metered)', (t) => t.metered.ledger_write_byte);
    row('Signed envelope bytes', (t) => t.envelopeBytes);
    row('Fee charged (stroops)', (t) => t.feeCharged);
    row('of which rent (stroops)', (t) => t.feeSplit.rent);
    const exec = root.transactions.filter((t) => /^registry execute/.test(t.label));
    if (exec.length) out.push(`\nThe ${exec.length} executions that activated the keys (permissionless \`execute\`, each inserting a leaf and recomputing the 16-level root): ${stat(exec.map((t) => t.metered?.cpu_insn ?? t.declared.instructions))} instructions, ${stat(exec.map((t) => t.feeCharged))} stroops charged.`);
  }
  // Testnet: the recovery run's vote and the votes run.
  const tnVotes = [...(tn ? tn.transactions.filter((t) => t.hash === tn.votes?.email) : []), ...(tv ? tv.transactions.filter(isVote) : [])];
  if (tnVotes.length) {
    const pin = tnVotes.filter((t) => !t.label.includes(', registry,'));
    const reg = tnVotes.filter((t) => t.label.includes(', registry,'));
    out.push('');
    out.push(`Testnet: ${pin.length} email votes against the guardian's pin (the recovery run's and ${pin.length - 1} of the votes run of ${tv ? day(tv.generated) : '—'} UTC)${reg.length ? ` and ${reg.length} against the registry's root` : ''}, read back from the network.`);
    out.push('');
    out.push(`| Figure: median (range) | Pin (${pin.length}) |${reg.length ? ` Registry root (${reg.length}) |` : ''}`);
    out.push(`| --- | --- |${reg.length ? ' --- |' : ''}`);
    const row = (label, f) => out.push(`| ${label} | ${stat(pin.map(f))} |${reg.length ? ` ${stat(reg.map(f))} |` : ''}`);
    row('Instructions (metered)', (t) => t.metered.cpu_insn);
    row('Instructions (declared)', (t) => t.declared.instructions);
    row('Signed envelope bytes', (t) => t.envelopeBytes);
    row('Fee charged (stroops)', (t) => t.feeCharged);
    row('of which rent (stroops)', (t) => t.feeSplit.rent);
    row('Wall clock, simulation to confirmation (ms)', (t) => t.ms?.total);
    if (tv && !reg.length) {
      const p = tv.gmailProposal;
      out.push(`\nThe votes run's registry admits the Gmail mock's TEST-ONLY key on the attested 72-hour path; the addition is eligible from ledger ${n(p.eligibleAt)}, about 72 hours after the run, and the registry-root votes follow it (\`testnet/votes.mjs vote\`).`);
    }
  }
  // The same call per launch domain.
  if (local && host.length) {
    const byDomain = Object.fromEntries(collecting(local.transactions).map((t) => [/, ([a-z.]+)\)$/.exec(t.label)?.[1], t]).filter(([d]) => d));
    const tvote = tn?.transactions.find((t) => t.hash === tn.votes?.email);
    out.push('');
    out.push('The same call, the email vote with a real proof, in each environment (instructions; footprint as read-only + read-write entries). Test host from `onchain.md`; local network from the attack run; testnet from `results/testnet.json` (Gmail only).');
    out.push('');
    out.push('| Domain | Test host invocation | Test host transaction | Test host footprint | Local network, metered | Local network, declared | Local footprint | Testnet, metered |');
    out.push('| --- | --- | --- | --- | --- | --- | --- | --- |');
    for (const h of host.filter((x) => x.label.startsWith('provider-'))) {
      const l = byDomain[h.domain];
      const fp = l?.declared ? `${l.declared.readOnly} + ${l.declared.readWrite}` : '—';
      const tnv = h.domain === 'gmail.com' && tvote ? n(tvote.metered?.cpu_insn) : '';
      out.push(`| ${h.domain} | ${n(h.host.instructions)} | ${n(h.tx.instructions)} | ${h.tx.read_only} + ${h.tx.read_write} | ${n(l?.metered?.cpu_insn)} | ${n(l?.declared?.instructions)} | ${fp} | ${tnv} |`);
    }
  }
  // The fee of one vote, by component.
  if (local && S.mainnet && host.length) {
    const gmailHost = host.find((h) => h.label === 'provider-gmail-com');
    const hostTx = { declared: { instructions: gmailHost.tx.instructions, diskReadBytes: gmailHost.tx.disk_read_bytes, writeBytes: gmailHost.tx.write_bytes, readOnly: gmailHost.tx.read_only, readWrite: gmailHost.tx.read_write }, footprint: { readOnly: [], readWrite: [] }, eventsBytes: gmailHost.tx.events_and_return_bytes, envelopeBytes: gmailHost.tx.envelope_bytes, label: 'test host' };
    const lv = local.transactions.find((t) => t.label === 'submit_guardian (email, gmail.com)');
    const rv = root?.transactions.find((t) => t.label === 'submit_guardian (email, registry, gmail.com)');
    const tvote = tn?.transactions.find((t) => t.hash === tn.votes?.email);
    const mainnet = schedule(S.mainnet.settings);
    const cols = [
      ['Test host transaction, SDK snapshot', column(hostTx, SDK_SNAPSHOT)],
      ["Test host transaction, mainnet's settings", column(hostTx, mainnet)],
      ...(lv ? [['Local network, pin: charged', column(lv, schedule(S.local.settings), { rent: lv.feeSplit.rent, charged: lv.feeCharged })]] : []),
      ...(rv ? [['Local network, registry root: charged', column(rv, schedule(S.local.settings), { rent: rv.feeSplit.rent, charged: rv.feeCharged })]] : []),
      ...(tvote ? [['Testnet, pin: charged', column(tvote, schedule(S.testnet.settings), { rent: tvote.feeSplit.rent, charged: tvote.feeCharged })]] : []),
      ...(lv ? [["Mainnet's settings, pin", projection(column(lv, mainnet, { rent: lv.feeSplit.rent }))]] : []),
      ...(rv ? [["Mainnet's settings, registry root", projection(column(rv, mainnet, { rent: rv.feeSplit.rent }))]] : []),
    ];
    if (cols[0][1].total !== gmailHost.tx.fee_no_rent) throw new Error(`the SDK snapshot gives ${cols[0][1].total}, onchain.md records ${gmailHost.tx.fee_no_rent}`);
    out.push('');
    out.push("One email vote (Gmail's) by fee component, in stroops: each column computes the components from the transaction's declared resources (instructions, entries, bytes written, envelope size, event bytes) under one schedule. The network columns' components add up to the fee each network charged, rent and inclusion fee included; the last columns price the local votes under mainnet's archived settings, with the rent the local network charged (it runs mainnet's settings, entry lifetimes included, and charges the same rent rate) and the 100-stroop inclusion fee every vote here paid. The test host's columns leave rent out.");
    out.push('');
    out.push(`| Component | ${cols.map(([h]) => h).join(' | ')} |`);
    out.push(`| --- | ${cols.map(() => '---').join(' | ')} |`);
    const row = (label, f) => out.push(`| ${label} | ${cols.map(([, c]) => n(f(c))).join(' | ')} |`);
    row('Compute (instructions)', (c) => c.compute);
    row('Entries read from disk', (c) => c.diskReadEntries);
    row('Entries written', (c) => c.writeEntries);
    row('Bytes read from disk', (c) => c.diskReadBytes);
    row('Bytes written', (c) => c.writeBytes);
    row('History (envelope + 300 bytes)', (c) => c.historical);
    row('Transaction size', (c) => c.size);
    row('Non-refundable total', (c) => c.nonRefundable);
    row('Events', (c) => c.events);
    row('Rent', (c) => c.rent);
    row('Inclusion fee', (c) => c.inclusion);
    row('**Total**', (c) => c.total);
  }
  // Metering: hosts and cost models.
  if (archival && local) {
    const m = archival.emailVoteMetering;
    const lv = collecting(local.transactions);
    const tnPin = tnVotes.filter((t) => !t.label.includes(', registry,'));
    out.push('');
    out.push("Instructions of the same email vote by host and cost model. The test host's transaction readings re-execute the vote in recording mode, the mode RPC simulation runs, with the host the Soroban SDK links; the networks' metered counts are the host's own metering as the network applied the transaction.");
    out.push('');
    out.push('| Reading | Host | Cost model | Instructions |');
    out.push('| --- | --- | --- | --- |');
    out.push(`| Test host, transaction (Gmail) | soroban-env-host 27.0.1 | the host's built-in | ${n(m.builtIn)} |`);
    out.push(`| Test host, transaction (Gmail) | soroban-env-host 27.0.1 | mainnet's | ${n(m.mainnet)} |`);
    out.push(`| Test host, transaction (Gmail) | soroban-env-host 27.0.1 | testnet's | ${n(m.testnet)} |`);
    out.push(`| Local network, applied: ${lv.length} pin votes | soroban-env-host 29.0.2 (stellar-core 30.0.0, protocol 29) | mainnet's | ${stat(lv.map((t) => t.metered.cpu_insn))} |`);
    out.push(`| Local network, declared after simulation | Stellar RPC 30.0.0 | mainnet's | ${stat(lv.map((t) => t.declared.instructions))} |`);
    const release = json('release-build-votes-local.json');
    if (release) {
      const rv = collecting(release.votes.map((v) => ({ ...v, status: 'SUCCESS' })));
      out.push(`| Local network, applied: ${rv.length} pin votes, the email contracts' release-profile build (\`release-build-votes-local.json\`) | soroban-env-host 29.0.2 (stellar-core 30.0.0, protocol 29) | mainnet's | ${stat(rv.map((t) => t.metered.cpu_insn))} |`);
    }
    if (tnPin.length) {
      out.push(`| Testnet, applied: ${tnPin.length} pin votes | soroban-env-host 29.0.2 (stellar-core 30.0.0, protocol 29) | testnet's | ${stat(tnPin.map((t) => t.metered.cpu_insn))} |`);
      out.push(`| Testnet, declared after simulation | Stellar RPC 30.0.0 | testnet's | ${stat(tnPin.map((t) => t.declared.instructions))} |`);
    }
  }
  // Capacity: one mainnet ledger.
  if (local && S.mainnet) {
    const s = S.mainnet.settings;
    const lv = collecting(local.transactions);
    const declared = Math.max(...lv.map((t) => t.declared.instructions));
    const env = Math.max(...lv.map((t) => t.envelopeBytes));
    const wb = Math.max(...lv.map((t) => t.declared.writeBytes));
    const perCluster = Math.floor(Number(s.contract_compute_v0.ledger_max_instructions) / declared);
    const clusters = s.contract_parallel_compute_v0.ledger_max_dependent_tx_clusters;
    const close = s.scp_timing.ledger_target_close_time_milliseconds / 1000;
    out.push('');
    out.push(`Capacity (mainnet's settings, CAP-0063): a ledger's Soroban transactions run in stages of at most ${clusters} clusters with no conflicting footprints, and the sum over stages of each stage's largest cluster, counted in declared instructions, must stay within ${n(s.contract_compute_v0.ledger_max_instructions)}. At ${n(declared)} declared instructions, a cluster holds ${perCluster} email votes, so one ledger holds at most ${perCluster * clusters} votes on different attempts and ${perCluster} that conflict; the ledger's other limits allow ${n(Math.floor(s.contract_bandwidth_v0.ledger_max_txs_size_bytes / env))} votes by transaction size (${n(env)} bytes each), ${n(Math.floor(s.contract_ledger_cost_v0.ledger_max_write_bytes / wb))} by bytes written and ${n(s.contract_execution_lanes.ledger_max_tx_count)} by count. That is ${(perCluster * clusters / close).toFixed(1)} votes a second at ${close}-second ledgers. Beyond that, transactions bid inclusion fees for the space (surge pricing); the resource fee stays what the settings fix, so a burst of recoveries raises only the inclusion fee.`);
  }
  if (tn) {
    out.push('');
    out.push(tn.table ?? '');
  }
  return out.join('\n');
}

function archivalBlock() {
  const out = [];
  const tn = json('testnet.json');
  if (tn) {
    const restores = tn.transactions.filter((t) => /^restore /.test(t.label));
    const restoreSum = restores.reduce((a, t) => a + t.feeCharged, 0);
    const recovery = tn.steps.filter((s) => !/^(deploy the email contracts|registry:|restore )/.test(s.step)).flatMap((s) => s.transactions);
    const recoverySum = recovery.reduce((a, h) => a + tn.transactions.find((t) => t.hash === h).feeCharged, 0);
    out.push(`Testnet run of ${day(tn.generated)} UTC: Perch's doc compiler and recovery controller, instance and code, had been archived and were restored before enrollment, one RestoreFootprint transaction per entry (testnet's minimum persistent lifetime, ${n(S.testnet?.settings.state_archival.min_persistent_ttl ?? 120_960)} ledgers, prepaid as rent).`);
    out.push('');
    out.push('| Transactions | Count | Fee charged (stroops) | of which rent |');
    out.push('| --- | --- | --- | --- |');
    for (const t of restores) out.push(`| ${t.label} | 1 | ${n(t.feeCharged)} | ${n(t.feeSplit.rent)} |`);
    out.push(`| **Restorations** | ${restores.length} | **${n(restoreSum)}** (${xlm(restoreSum)}) | ${n(restores.reduce((a, t) => a + t.feeSplit.rent, 0))} |`);
    out.push(`| The recovery, mint to completion | ${recovery.length} | ${n(recoverySum)} (${xlm(recoverySum)}) | ${n(recovery.reduce((a, h) => a + tn.transactions.find((t) => t.hash === h).feeSplit.rent, 0))} |`);
    out.push(`| **Both** | ${restores.length + recovery.length} | **${n(restoreSum + recoverySum)}** (${xlm(restoreSum + recoverySum)}) | |`);
  }
  const a = json('archival-test-host.json');
  const code = json('code-entries.json');
  if (a && S.mainnet) {
    const s = S.mainnet.settings;
    const rentSizes = {};
    if (code) {
      for (const st of [...a.steps, ...a.live]) {
        for (const r of st.restored) {
          const c = r.code && code.entries.find((e) => e.onNetwork && r.key.startsWith(`code ${e.hash.slice(0, 8)}`));
          if (c) rentSizes[r.keyXdr] = codeRentBytes(c.dataBytes, c.costInputs, s);
        }
      }
    }
    const archived = plan(a.steps, s, { rentSizes });
    const live = plan(a.live, s);
    const sum = (p) => p.reduce((x, t) => x + t.fee, 0);
    const lim = limits(s);
    out.push('');
    out.push(`Every entry archived, at mainnet's settings: the test host's recovery (\`email_archival.rs\`: begin, the email vote, the helper's vote, completion) with every one of the ${n(a.entriesAtRest)} ledger entries archived when it starts, each step re-executed under mainnet's cost model and entry lifetimes with the host restoring what it reads. A step whose restorations do not fit one transaction (mainnet allows ${n(lim.diskReadBytes)} bytes read from disk and ${n(lim.writeBytes)} written) restores its largest entries first in their own RestoreFootprint transactions. Fees are fees/model.mjs at mainnet's settings; the rent sizes of code entries are the network's (\`codeRentBytes\` over the entries testnet holds, \`results/code-entries.json\`), 2 to 20% above the test host's own.`);
    out.push('');
    out.push('| Transaction | Restores | Bytes restored | Fee (stroops) | of which rent |');
    out.push('| --- | --- | --- | --- | --- |');
    // An entry in a few words: a code entry by the contract it is, a data entry by its contract and kind.
    const name = (k) => {
      const c = k.startsWith('code ') && code?.entries.find((e) => k === `code ${e.hash.slice(0, 8)}`);
      if (c) return `${c.name} code`;
      const m = /^(.*?) (persistent|temporary) (instance|.*)$/.exec(k);
      return m ? `${m[1]} ${m[3] === 'instance' ? 'instance' : 'data'}` : k;
    };
    const names = (entries) => {
      const counts = new Map();
      for (const e of entries) counts.set(name(e.key), (counts.get(name(e.key)) ?? 0) + 1);
      return [...counts].map(([k, c]) => (c > 1 ? `${k} (${c})` : k)).join('; ');
    };
    for (const t of archived) {
      const entries = t.kind === 'restore' ? t.entries : t.restoredInline;
      const what = t.kind === 'restore' ? `RestoreFootprint before ${t.step}` : t.step;
      out.push(`| ${what} | ${entries.length ? names(entries) : '—'} | ${n(entries.reduce((x, e) => x + e.xdrBytes, 0))} | ${n(t.fee)} | ${n(t.rent)} |`);
    }
    out.push(`| **Everything archived** | ${archived.reduce((x, t) => x + (t.kind === 'restore' ? t.entries.length : t.restoredInline.length), 0)} entries | | **${n(sum(archived))}** (${xlm(sum(archived))}), ${archived.length} transactions | ${n(archived.reduce((x, t) => x + t.rent, 0))} |`);
    out.push(`| The same steps, nothing archived | — | — | ${n(sum(live))} (${xlm(sum(live))}), ${live.length} transactions | ${n(live.reduce((x, t) => x + t.rent, 0))} |`);
  }
  const k = json('keeper-local.json');
  if (k && S.mainnet && code) {
    const s = S.mainnet.settings;
    const sch = schedule(s);
    // Each entry's size for rent: the network's, from its code entry's inputs or its XDR size.
    const rows = [];
    let validated = 0;
    for (const e of k.entries) {
      const t = k.transactions.find((x) => x.hash === e.hash);
      const isCode = /code$/.test(e.label);
      const size = isCode ? (e.costInputs ? codeRentBytes(e.entryBytes, e.costInputs, S.local.settings) : undefined) : e.entryBytes + 8;
      if (size !== undefined) {
        const charged = rentFee([{ persistent: true, code: isCode, oldSize: size, newSize: size, oldLiveUntil: e.from, newLiveUntil: e.to }], schedule(S.local.settings), t.ledger);
        if (charged !== t.feeSplit.rent) throw new Error(`keeper: ${e.label} was charged ${t.feeSplit.rent} rent for ${e.to - e.from} ledgers; size ${size} gives ${charged}`);
        validated++;
      }
      const year = size === undefined ? undefined : rentFee([{ persistent: true, code: isCode, oldSize: size, newSize: size, oldLiveUntil: 1e9, newLiveUntil: 1e9 + YEAR_LEDGERS }], sch, 1);
      const restore = size === undefined ? undefined : rentFee([{ persistent: true, code: isCode, oldSize: 0, newSize: size, oldLiveUntil: 0, newLiveUntil: s.state_archival.min_persistent_ttl }], sch, 1);
      rows.push({ ...e, size, year, restore, feeCharged: t.feeCharged, nonRefundable: t.feeSplit.nonRefundableResource });
    }
    const keeperTx = median(k.transactions.map((t) => t.feeCharged - t.feeSplit.rent));
    out.push('');
    out.push(`The keeper (\`network/keeper.mjs\`), run once on the local network with mainnet's settings (\`network/keeper-costs.mjs\`, ${day(k.generated)} UTC): one ExtendFootprintTTL transaction per entry, each extending it to the maximum lifetime (${n(S.local.settings.state_archival.max_entry_ttl)} ledgers). Every extension's rent is reproduced from the entry's size for rent (${validated} of ${k.entries.length} entries: an instance's XDR size, and for code \`codeRentBytes\` over the parsing inputs the network recorded for it). A year is ${n(YEAR_LEDGERS)} ledgers at 5 seconds; a restoration prepays mainnet's minimum persistent lifetime (${n(s.state_archival.min_persistent_ttl)} ledgers, 120 days). Besides rent, each keeper transaction paid a median ${n(keeperTx)} stroops of resource and inclusion fees.`);
    out.push('');
    out.push("| Entry | Kept by | Size for rent (bytes) | Rent for a year at mainnet's settings | Restoring it on mainnet (rent) |");
    out.push('| --- | --- | --- | --- | --- |');
    const keeper = { nido: "Nido's keeper", perch: "Perch's operator", wallet: "the account's wallet" };
    for (const r of rows) out.push(`| ${r.label} | ${keeper[r.owner] ?? r.owner} | ${n(r.size)} | ${r.year === undefined ? '—' : `${n(r.year)} (${xlm(r.year)})`} | ${r.restore === undefined ? '—' : `${n(r.restore)} (${xlm(r.restore)})`} |`);
    const total = (f) => rows.filter(f).reduce((x, r) => x + (r.year ?? 0), 0);
    const nidoShared = total((r) => r.owner === 'nido' && !/guardian instance/.test(r.label));
    const perAccount = total((r) => /guardian instance/.test(r.label));
    const perch = total((r) => r.owner === 'perch');
    const wallet = total((r) => r.owner === 'wallet');
    out.push('');
    out.push(`A year of rent at mainnet's settings: ${n(nidoShared)} stroops (${xlm(nidoShared)}) for the email verifier, the DKIM key registry (instance and code) and the guardian's code, shared by every account; ${n(perAccount)} (${xlm(perAccount)}) per enrolled account for its guardian's instance; ${n(perch)} (${xlm(perch)}) for the Perch contracts a recovery runs (instances and code), which Perch's operator keeps; and ${n(wallet)} (${xlm(wallet)}) for an account's instance, without its other data entries.`);
  }
  return out.length ? out.join('\n') : 'No archival measurement is recorded.';
}

function proving() {
  const p = json('proving.json');
  if (!p) return 'Not yet run.';
  const q = json('proving-shared-load.json');
  if (!q) return p.table;
  // The same configurations in a second run on the machine under another load.
  const key = (r) => `${r.prover}/${r.threads}/${r.background_qos ?? r.efficiency_cores}`;
  const med = (r) => median(r.runs.map((x) => x.prove_ms));
  const sec = (ms) => (ms / 1000).toFixed(ms < 10_000 ? 2 : 1);
  const out = [p.table, ''];
  out.push(`Proving time against load: each configuration's median of ${p.runs_per_configuration} runs here (load average ${p.machine.load_average_at_start} at the start) beside a second run of the same circuit build on the same machine (${q.generated.slice(0, 16).replace('T', ' ')} UTC, load average ${q.machine.load_average_at_start} at its start, ${q.machine.load_average_at_end} at its end).`);
  out.push('');
  out.push(`| Configuration | Proving (s), load ${p.machine.load_average_at_start.split(' ')[0]} | Proving (s), load ${q.machine.load_average_at_start.split(' ')[0]} | Change |`);
  out.push('| --- | --- | --- | --- |');
  for (const r of p.rows) {
    const o = q.rows.find((x) => key(x) === key(r));
    if (!o) continue;
    out.push(`| ${r.label} | ${sec(med(r))} | ${sec(med(o))} | ${(((med(o) - med(r)) / med(r)) * 100).toFixed(1)}% |`);
  }
  return out.join('\n');
}

let text = readFileSync(readme, 'utf8');
for (const [name, body] of Object.entries({ settings: settingsTable(), attacks: attacks(), cost: cost(), archival: archivalBlock(), proving: proving() })) {
  const re = new RegExp(`(<!-- BEGIN GENERATED ${name} by report\\.mjs; do not edit -->)[\\s\\S]*?(<!-- END GENERATED ${name} -->)`);
  if (!re.test(text)) throw new Error(`README.md has no generated block "${name}"`);
  text = text.replace(re, (_, begin, end) => `${begin}\n${body}\n${end}`);
}
writeFileSync(readme, text);
console.log('rewrote', readme);
