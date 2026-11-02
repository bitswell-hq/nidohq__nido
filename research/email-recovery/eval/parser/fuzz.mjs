#!/usr/bin/env node
// Grammar-based fuzzing of the circuit's header parsing (README.md, part 2).
//
// Each case (lib/grammar.mjs) is a header block around the From grammar
// (spec section 4.5) or the DKIM-Signature tag list and h= (section 4.3),
// signed with a TEST-ONLY key (lib/sign.mjs). Every DKIM-Signature field of
// the message goes through lib/compare.mjs. The invariant checked on every
// case: when the circuit accepts a signature, the reference DKIM verifier
// accepts it, Python's RFC 5322 reading of the From field it covers is the
// circuit's address, and d= is the circuit's domain (no row is classified
// "soundness"). Refusals of signatures the reference accepts and the spec's
// profile allows are reported as completeness gaps.
//
// With --mutate-hints, every signature the circuit accepts is run again on
// hints an honest prover would not choose (`mutations` below: the From
// address's start, length and `@` index, the DKIM-Signature tag starts and
// counts, each moved and replaced). The hints are unconstrained, so a
// dishonest prover chooses them; the invariant is that the circuit refuses
// every mutated hint or binds the same address, domain and key hash.
//
//   node fuzz.mjs [--cases N] [--seed S] [--from I] [--jobs J] [--cross-check-every K] [--out FILE]
//   node fuzz.mjs --mutate-hints [--cases N] [--seed S] [--from I] [--jobs J] [--out FILE]
//   node fuzz.mjs --show I [--seed S]      print case I's message and its rows

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';

import { publicKeyBase64, testKey } from '@nidohq/email-mocks';

import { CircuitPool } from './lib/circuit.mjs';
import { compareMessage, encodeVerdicts, fromClass } from './lib/compare.mjs';
import { FAMILIES, generateCase, rng } from './lib/grammar.mjs';
import { closeReferences } from './lib/reference.mjs';
import { signCase } from './lib/sign.mjs';

const { values: args } = parseArgs({
  options: {
    cases: { type: 'string', default: '50000' },
    seed: { type: 'string', default: 'nido-email-recovery-parser-fuzz-v1' },
    from: { type: 'string', default: '0' },
    jobs: { type: 'string' },
    'cross-check-every': { type: 'string', default: '25' },
    out: { type: 'string' },
    show: { type: 'string' },
    'mutate-hints': { type: 'boolean', default: false },
  },
});
const results = join(new URL('.', import.meta.url).pathname, 'results');
args.out ??= join(results, args['mutate-hints'] ? 'hint-mutation.json' : 'fuzz.json');

const bump = (m, k) => m.set(k, (m.get(k) ?? 0) + 1);

const keysFor = (c) => {
  const p = publicKeyBase64(testKey(c.keyName));
  return () => [{ id: `TEST-ONLY-${c.keyName}`, p }];
};

/** The From and DKIM-Signature fields of a message, for reports, with each b= value elided. */
function describe(eml) {
  const head = eml.toString('latin1').split('\r\n\r\n')[0];
  return head
    .split(/\r\n(?![ \t])/)
    .filter((l) => /^(from|dkim-signature)\s*:/i.test(l))
    .map((l) => (/^dkim-signature/i.test(l) ? l.replace(/((?:[:;])[ \t\r\n]*b[ \t\r\n]*=)[^;]*/g, '$1…') : l));
}

/** Non-agreeing signatures by class: every case index, and the three examples with the smallest. */
class Groups {
  constructor() {
    this.map = new Map();
  }

  add(key, base, i, example) {
    if (!this.map.has(key)) this.map.set(key, { ...base, count: 0, cases: new Set(), examples: [] });
    const g = this.map.get(key);
    g.count++;
    g.cases.add(i);
    g.examples.push(example);
  }

  list() {
    return [...this.map.entries()]
      .sort((a, b) => b[1].count - a[1].count || (a[0] < b[0] ? -1 : 1))
      .map(([, g]) => ({ ...g, cases: [...g.cases].sort((a, b) => a - b), examples: g.examples.sort((a, b) => a.case - b.case).slice(0, 3) }));
  }
}

if (args.show !== undefined) {
  const c = generateCase(args.seed, Number(args.show));
  const pool = new CircuitPool({ jobs: 1, crossCheck: true });
  const signed = await signCase(c);
  process.stdout.write(`family ${c.family}, signed via ${signed.signedVia}\n\n${signed.eml.toString('latin1')}\n`);
  console.log(JSON.stringify(await compareMessage(signed.eml, keysFor(c), pool), null, 1));
  await pool.close();
  closeReferences();
  process.exit(0);
}

/**
 * The mutated hints of one accepted run, `[family, label, hints]`, each
 * different from the honest `h`: each From hint and each present tag start
 * moved by -2 to +2, set to a random position and (From) to 2^32 - 1; the
 * address window moved with its end fixed, and with its `@` fixed; the tag
 * count and the `h=` and `t=` hints moved by one.
 */
function mutations(h, headerLength, r) {
  const out = [];
  const u32 = (v) => v >>> 0;
  const put = (family, label, f) => {
    const x = structuredClone(h);
    f(x);
    if (JSON.stringify(x) !== JSON.stringify(h)) out.push([family, label, x]);
  };
  const deltas = [-2, -1, 1, 2];
  const signed = (d) => (d > 0 ? `+${d}` : `${d}`);
  for (const k of ['addr_start', 'addr_len', 'at_index']) {
    for (const d of deltas) put(`from.${k}`, `${signed(d)}`, (x) => (x.from[k] = u32(x.from[k] + d)));
    put(`from.${k}`, 'random', (x) => (x.from[k] = r.int(headerLength + 1)));
    put(`from.${k}`, '2^32 - 1', (x) => (x.from[k] = 0xffffffff));
  }
  for (const d of deltas) {
    put('from window, end fixed', signed(d), (x) => {
      x.from.addr_start = u32(x.from.addr_start + d);
      x.from.addr_len = u32(x.from.addr_len - d);
    });
    put('from window, @ fixed', signed(d), (x) => {
      x.from.addr_start = u32(x.from.addr_start + d);
      x.from.addr_len = u32(x.from.addr_len - d);
      x.from.at_index = u32(x.from.at_index - d);
    });
  }
  for (let j = 0; j < h.tags.tag_count; j++) {
    for (const d of deltas) put('tags.tag_starts', `[${j}] ${signed(d)}`, (x) => (x.tags.tag_starts[j] = u32(x.tags.tag_starts[j] + d)));
    put('tags.tag_starts', `[${j}] random`, (x) => (x.tags.tag_starts[j] = r.int(headerLength + 1)));
  }
  for (const k of ['tag_count', 'h_from', 'h_subject', 't_len']) {
    for (const d of [-1, 1]) put(`tags.${k}`, signed(d), (x) => (x.tags[k] = u32(x.tags[k] + d)));
  }
  return out;
}

if (args['mutate-hints']) {
  const total = Number(args.cases);
  const first = Number(args.from);
  const pool = new CircuitPool({ jobs: args.jobs ? Number(args.jobs) : undefined });
  const started = Date.now();
  const verdicts = { refused: 0, sameBinding: 0, otherBinding: 0 };
  const families = {};
  const refusals = new Map();
  const others = [];
  let signatures = 0;
  let honestAccepts = 0;
  const caseWork = async (i) => {
    const c = generateCase(args.seed, i);
    const signed = await signCase(c);
    const rows = await compareMessage(signed.eml, keysFor(c), pool, { keepInputs: true });
    const r = rng(`${args.seed}/hints`, i);
    for (const row of rows) {
      signatures++;
      const run = row.circuit.acceptedRun;
      if (!run) continue;
      honestAccepts++;
      await Promise.all(
        mutations(run.hints, run.header.length, r).map(async ([family, label, hints]) => {
          const res = await pool.runWithHints(run.header, run.modulus, run.signature, hints);
          const f = (families[family] ??= { runs: 0, refused: 0, sameBinding: 0, otherBinding: 0 });
          f.runs++;
          let v;
          if (!res.harness.accepted) {
            v = 'refused';
            bump(refusals, res.harness.refusal.replace(/\d+/g, 'N'));
          } else if (res.harness.address === row.circuit.address && res.harness.domain === row.circuit.domain && res.harness.keyHash === run.keyHash) {
            v = 'sameBinding';
          } else {
            v = 'otherBinding';
            others.push({ case: i, family, label, hints, honest: { address: row.circuit.address, domain: row.circuit.domain }, bound: { address: res.harness.address, domain: res.harness.domain } });
          }
          verdicts[v]++;
          f[v]++;
        }),
      );
    }
  };
  let next = first;
  let done = 0;
  await Promise.all(
    Array.from({ length: pool.workers.length + 1 }, async () => {
      while (next < first + total) {
        const i = next++;
        await caseWork(i);
        if (++done % 100 === 0) process.stderr.write(`${done}/${total} cases, ${Math.round((Date.now() - started) / 1000)} s, ${JSON.stringify(verdicts)}\n`);
      }
    }),
  );
  await pool.close();
  closeReferences();
  const summary = {
    seed: args.seed,
    cases: { from: first, count: total },
    seconds: Math.round((Date.now() - started) / 1000),
    executions: pool.executions,
    signatures,
    signaturesAccepted: honestAccepts,
    mutations: verdicts.refused + verdicts.sameBinding + verdicts.otherBinding,
    verdicts,
    invariant: verdicts.otherBinding ? `violated by ${verdicts.otherBinding} mutated hints` : 'holds on every mutated hint',
    families,
    refusals: [...refusals].sort((a, b) => b[1] - a[1]).map(([k, n]) => ({ [k]: n })),
    otherBindings: others.sort((a, b) => a.case - b.case).slice(0, 20),
  };
  writeFileSync(args.out, `${JSON.stringify(summary, null, 1)}\n`);
  process.stderr.write(`${total} cases, ${honestAccepts} accepted signatures, ${summary.mutations} mutated hints in ${summary.seconds} s: ${JSON.stringify(verdicts)}; invariant ${summary.invariant}\n`);
  process.exit(verdicts.otherBinding ? 1 : 0);
}

const total = Number(args.cases);
const first = Number(args.from);
const every = Number(args['cross-check-every']);
const pool = new CircuitPool({ jobs: args.jobs ? Number(args.jobs) : undefined });
const crossPool = every > 0 ? new CircuitPool({ jobs: 1, crossCheck: true }) : null;
const started = Date.now();

const families = Object.fromEntries(FAMILIES.map(([f]) => [f, { cases: 0, signatures: 0, circuitAccepts: 0, referenceAccepts: 0, verdicts: {} }]));
const verdicts = {};
const signedVia = {};
const counterexamples = new Groups();
const gaps = new Groups();
const deviations = new Groups();
const divergences = new Groups();
const refusals = new Map();
const violations = new Map();
let crossChecked = 0;
let crossDisagree = 0;
let caseAccepts = 0;
let unsignedCases = 0;
const perCase = new Array(Number(args.cases));

async function one(i) {
  const c = generateCase(args.seed, i);
  const signed = await signCase(c);
  signedVia[signed.signedVia ?? 'none'] = (signedVia[signed.signedVia ?? 'none'] ?? 0) + 1;
  const usePool = crossPool && i % every === 0 ? crossPool : pool;
  const rows = await compareMessage(signed.eml, keysFor(c), usePool);
  perCase[i - first] = rows;
  const fam = families[c.family];
  fam.cases++;
  if (rows.length === 0) unsignedCases++;
  if (rows.some((r) => r.circuit.accepted)) caseAccepts++;
  for (const r of rows) {
    fam.signatures++;
    if (r.circuit.accepted) fam.circuitAccepts++;
    if (r.reference.expected) fam.referenceAccepts++;
    fam.verdicts[r.verdict] = (fam.verdicts[r.verdict] ?? 0) + 1;
    verdicts[r.verdict] = (verdicts[r.verdict] ?? 0) + 1;
    if (r.blocksAgree === false) {
      const verifies = r.reference.verifies ? 'the reference verifies the signature' : 'the reference does not verify the signature';
      divergences.add(verifies, { reference: verifies }, i, { case: i, family: c.family, fields: describe(signed.eml), circuit: r.circuit.refusals });
    }
    if (usePool === crossPool) {
      crossChecked++;
      if (!r.circuit.crossCheck) crossDisagree++;
    }
    if (r.verdict === 'agree-refuse') {
      bump(violations, r.reference.violation.replace(/\d+ (octets|bits|tags|mailboxes)/g, 'N $1'));
      for (const x of r.circuit.refusals) bump(refusals, x.replace(/\d+/g, 'N'));
    }
    const example = { case: i, family: c.family, fields: describe(signed.eml), from: r.from, circuit: { address: r.circuit.address, domain: r.circuit.domain, fromValue: r.circuit.fromValue, refusals: r.circuit.refusals } };
    if (r.verdict === 'soundness') {
      const cls = r.kind === 'from' ? fromClass(r.circuit.fromValue) : r.reference.violation.replace(/^reference: /, '');
      counterexamples.add(`${r.kind}: ${cls}`, { kind: r.kind, class: cls }, i, example);
    }
    if (r.verdict === 'spec-deviation') {
      const k = r.reference.violation.replace(/\d+ (octets|bits|tags|mailboxes|groups)/g, 'N $1');
      deviations.add(k, { violation: k }, i, example);
    }
    if (r.verdict === 'completeness') {
      const k = r.circuit.refusals[0] ?? 'not run';
      gaps.add(k, { refusal: k }, i, example);
    }
  }
}

let next = first;
let done = 0;
const inFlight = (pool.workers.length + 1) * 2;
await Promise.all(
  Array.from({ length: inFlight }, async () => {
    while (next < first + total) {
      const i = next++;
      await one(i);
      if (++done % 1000 === 0) process.stderr.write(`${done}/${total} cases, ${Math.round((Date.now() - started) / 1000)} s, verdicts ${JSON.stringify(verdicts)}\n`);
    }
  }),
);
await pool.close();
await crossPool?.close();
closeReferences();

const sorted = (m) => [...m].sort((a, b) => b[1] - a[1]).map(([k, n]) => ({ [k]: n }));
const summary = {
  seed: args.seed,
  cases: { from: first, count: total },
  seconds: Math.round((Date.now() - started) / 1000),
  executions: pool.executions + (crossPool?.executions ?? 0),
  python: (await import('node:child_process')).execFileSync(process.env.PYTHON ?? 'python3', ['--version']).toString().trim(),
  signedVia,
  casesWithoutSignature: unsignedCases,
  casesTheCircuitAccepts: caseAccepts,
  signatures: Object.values(verdicts).reduce((a, b) => a + b, 0),
  verdicts,
  invariant: verdicts.soundness ? `violated in ${verdicts.soundness} signatures` : 'holds on every case',
  counterexampleClasses: counterexamples.list(),
  specDeviations: deviations.list(),
  completenessGaps: gaps.list(),
  blockDivergence: divergences.list(),
  crossCheck: { signatures: crossChecked, disagreements: crossDisagree, every },
  families,
  agreedRefusals: { referenceReasons: sorted(violations), circuitRefusals: sorted(refusals) },
  // One letter per signature (lib/compare.mjs VERDICT_CODES), cases in order
  // from `cases.from`, separated by "|"; deflated and base64-encoded.
  verdictCodes: encodeVerdicts(perCase),
};
writeFileSync(args.out, `${JSON.stringify(summary, null, 1)}\n`);
process.stderr.write(`${total} cases in ${summary.seconds} s: ${JSON.stringify(verdicts)}; invariant ${summary.invariant}\n`);
