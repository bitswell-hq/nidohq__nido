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
//   node fuzz.mjs [--cases N] [--seed S] [--from I] [--jobs J] [--cross-check-every K] [--out FILE]
//   node fuzz.mjs --show I [--seed S]      print case I's message and its rows

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';

import { publicKeyBase64, testKey } from '@nidohq/email-mocks';

import { CircuitPool } from './lib/circuit.mjs';
import { compareMessage, encodeVerdicts, fromClass } from './lib/compare.mjs';
import { FAMILIES, generateCase } from './lib/grammar.mjs';
import { closeReferences } from './lib/reference.mjs';
import { signCase } from './lib/sign.mjs';

const { values: args } = parseArgs({
  options: {
    cases: { type: 'string', default: '50000' },
    seed: { type: 'string', default: 'nido-email-recovery-parser-fuzz-v1' },
    from: { type: 'string', default: '0' },
    jobs: { type: 'string' },
    'cross-check-every': { type: 'string', default: '25' },
    out: { type: 'string', default: join(new URL('.', import.meta.url).pathname, 'results/fuzz.json') },
    show: { type: 'string' },
  },
});

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
const bump = (m, k) => m.set(k, (m.get(k) ?? 0) + 1);
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
