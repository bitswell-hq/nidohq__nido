#!/usr/bin/env node
// Differential testing on real mail (README.md, part 1).
//
// Every post in corpus/manifest.json is fetched again from its public
// archive (cached under target/), checked against its SHA-256, and put
// through lib/compare.mjs signature by signature with the candidate keys of
// corpus/keys.json. Each execution also runs the committed recovery artifact
// (the cross-check in lib/circuit.mjs).
//
// The committed summary (results/differential.json) masks the letters and
// digits of every From value it quotes; the full rows, unmasked, go to
// target/email-recovery-parser/differential-rows.jsonl.
//
//   node differential.mjs [--jobs J] [--per-domain N] [--out FILE]

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';

import { CACHE, mbox, sha256hex, splitMbox, wireForm } from './lib/archive.mjs';
import { CircuitPool } from './lib/circuit.mjs';
import { compareMessage, encodeVerdicts } from './lib/compare.mjs';
import { closeReferences } from './lib/reference.mjs';

const here = new URL('.', import.meta.url).pathname;
const { values: args } = parseArgs({
  options: {
    jobs: { type: 'string' },
    'per-domain': { type: 'string' },
    'no-cross-check': { type: 'boolean', default: false },
    out: { type: 'string', default: join(here, 'results/differential.json') },
  },
});
const log = (s) => process.stderr.write(`${s}\n`);

const manifest = JSON.parse(readFileSync(join(here, 'corpus/manifest.json'), 'utf8'));
const keys = JSON.parse(readFileSync(join(here, 'corpus/keys.json'), 'utf8'));
const keyIndex = new Map(keys.keys.map((k) => [`${k.s}._domainkey.${k.d}`, k]));
const keysFor = (d, s) => keyIndex.get(`${s}._domainkey.${d}`)?.candidates ?? [];
const keySource = new Map(keys.keys.flatMap((k) => k.candidates.map((c) => [c.id, c.sources.map((x) => x.kind)])));

// Messages, in manifest order; with --per-domain N the first N per From
// domain (a smaller run that still covers every launch domain).
let messages = manifest.messages.map(([archive, index, sha256, fromDomain], n) => ({ n, archive: manifest.archives[archive], index, sha256, fromDomain }));
if (args['per-domain']) {
  const cap = Number(args['per-domain']);
  const seen = {};
  messages = messages.filter((m) => (seen[m.fromDomain] = (seen[m.fromDomain] ?? 0) + 1) <= cap);
}

/** Letters to x/X and digits to 9, so a quoted From value keeps its structure but no identity; the domain after the last "@" is kept. */
function mask(value) {
  if (value == null) return value;
  const at = value.lastIndexOf('@');
  const head = at === -1 ? value : value.slice(0, at);
  const tail = at === -1 ? '' : value.slice(at);
  return head.replace(/[a-z]/g, 'x').replace(/[A-Z]/g, 'X').replace(/[0-9]/g, '9') + tail;
}

const pool = new CircuitPool({ jobs: args.jobs ? Number(args.jobs) : undefined, crossCheck: !args['no-cross-check'] });
const started = Date.now();
const byArchive = new Map();
for (const m of messages) {
  if (!byArchive.has(m.archive)) byArchive.set(m.archive, []);
  byArchive.get(m.archive).push(m);
}

const rows = [];
let unavailable = 0;

const work = [];
for (const [archive, ms] of byArchive) {
  const [, base, list, month] = /^(.*)\/([^/]+)\/(\d{4}-\d{2})$/.exec(archive);
  const posts = splitMbox(await mbox(base, list, month, { log }));
  const byHash = new Map(posts.map((p, i) => [sha256hex(p), i]));
  for (const m of ms) {
    const at = posts[m.index] && sha256hex(posts[m.index]) === m.sha256 ? m.index : byHash.get(m.sha256);
    if (at === undefined) {
      unavailable++;
      rows.push({ ...m, unavailable: true, signatures: [] });
      continue;
    }
    work.push({ m, eml: wireForm(posts[at]) });
  }
}

let next = 0;
let done = 0;
await Promise.all(
  Array.from({ length: (pool.workers.length + 1) * 2 }, async () => {
    while (next < work.length) {
      const { m, eml } = work[next++];
      const sigs = await compareMessage(eml, keysFor, pool);
      const messageId = (/^message-id:[ \t]*(.*(?:\r\n[ \t].*)*)/im.exec(eml.toString('latin1').split('\r\n\r\n')[0])?.[1] ?? '').replace(/\r\n/g, '').trim();
      rows.push({ ...m, messageId, signatures: sigs });
      if (++done % 500 === 0) log(`${done}/${work.length} posts, ${Math.round((Date.now() - started) / 1000)} s`);
    }
  }),
);
await pool.close();
closeReferences();

mkdirSync(CACHE, { recursive: true });
writeFileSync(join(CACHE, 'differential-rows.jsonl'), rows.map((r) => JSON.stringify(r)).join('\n') + '\n');

// Aggregation.
const inc = (o, k, n = 1) => (o[k] = (o[k] ?? 0) + n);
const domains = {};
const verdicts = {};
const alignedVerdicts = {};
const referenceRefusals = {};
const profileRefusals = {};
const circuitRefusals = {};
const keysUsed = {};
const mismatches = [];
const fromDisagreements = [];
let blockDivergence = 0;
let crossChecked = 0;
let crossDisagree = 0;
rows.sort((a, b) => a.n - b.n);
for (const r of rows) {
  if (r.unavailable) continue;
  const d = (domains[r.fromDomain] ??= { posts: 0, referenceAccepts: 0, circuitAccepts: 0, agree: 0, signatures: 0, alignedSignatures: 0 });
  d.posts++;
  const refAccepts = r.signatures.some((s) => s.reference.expected);
  const circAccepts = r.signatures.some((s) => s.circuit.accepted);
  if (refAccepts) d.referenceAccepts++;
  if (circAccepts) d.circuitAccepts++;
  if (refAccepts === circAccepts && r.signatures.every((s) => ['agree-accept', 'agree-refuse', 'no-key'].includes(s.verdict))) d.agree++;
  for (const s of r.signatures) {
    d.signatures++;
    const aligned = s.d === r.fromDomain;
    if (aligned) d.alignedSignatures++;
    inc(verdicts, s.verdict);
    if (aligned) inc(alignedVerdicts, s.verdict);
    if (s.key) inc(keysUsed, (keySource.get(s.key) ?? ['unknown']).includes('dns') ? 'live DNS' : 'archive.zk.email only');
    if (s.blocksAgree === false) blockDivergence++;
    if (s.circuit.runs) {
      crossChecked++;
      if (!s.circuit.crossCheck) crossDisagree++;
    }
    const v = s.reference.violation;
    if (v?.startsWith('reference: ')) inc(referenceRefusals, v.slice(11));
    else if (v) inc(profileRefusals, v.replace(/\d+ (octets|bits|tags|mailboxes|groups|From fields)/g, 'N $1').replace(/\(.*\)$/, '').trim());
    for (const x of s.circuit.refusals) inc(circuitRefusals, x.replace(/\d+/g, 'N'));
    const ref = { archive: r.archive, index: r.index, sha256: r.sha256, messageId: r.messageId };
    if (!['agree-accept', 'agree-refuse', 'no-key'].includes(s.verdict)) {
      mismatches.push({ ...ref, d: s.d, s: s.s, verdict: s.verdict, kind: s.kind, violation: v, circuitRefusals: s.circuit.refusals, fromValue: mask(s.circuit.fromValue), python: s.from?.python.map(mask), mailauth: s.from?.mailauth.map(mask) });
    }
    if (s.from && s.verdict === 'agree-accept' && (s.from.mailauthSyntax !== 'valid' || s.from.mailauth.length !== 1 || s.from.mailauth[0] !== s.from.python[0])) {
      fromDisagreements.push({ ...ref, python: s.from.python.map(mask), mailauth: s.from.mailauth.map(mask), mailauthSyntax: s.from.mailauthSyntax });
    }
  }
}
const sortObj = (o) => Object.fromEntries(Object.entries(o).sort((a, b) => b[1] - a[1]));
const signatures = Object.values(verdicts).reduce((a, b) => a + b, 0);
const summary = {
  corpus: { built: manifest.built, archive: manifest.archive, lists: manifest.lists.length, months: manifest.months, posts: messages.length, available: rows.length - unavailable, unavailable, perDomainCap: args['per-domain'] ? Number(args['per-domain']) : null },
  seconds: Math.round((Date.now() - started) / 1000),
  executions: pool.executions,
  python: rows.flatMap((r) => r.signatures).find((s) => s.from)?.from ? (await import('node:child_process')).execFileSync(process.env.PYTHON ?? 'python3', ['--version']).toString().trim() : null,
  signatures,
  verdicts,
  alignedVerdicts,
  result: mismatches.length ? `${mismatches.length} mismatching signatures` : 'the circuit accepts exactly the signatures the reference accepts, and binds the address Python reads',
  domains: Object.fromEntries(Object.entries(domains).sort()),
  keysUsed,
  blockDivergence,
  crossCheck: { signatures: crossChecked, disagreements: crossDisagree },
  referenceRefusals: sortObj(referenceRefusals),
  profileRefusals: sortObj(profileRefusals),
  circuitRefusals: sortObj(circuitRefusals),
  mismatches,
  fromDisagreements,
  // One letter per signature (lib/compare.mjs VERDICT_CODES), posts in
  // manifest order separated by "|", "?" for a post the archive no longer
  // serves; deflated and base64-encoded. check.sh --ci compares against it.
  verdicts: { posts: rows.map((r) => r.n), codes: encodeVerdicts(rows.map((r) => (r.unavailable ? null : r.signatures))) },
};
writeFileSync(args.out, `${JSON.stringify(summary, null, 1)}\n`);
log(`${rows.length} posts, ${signatures} signatures in ${summary.seconds} s: ${JSON.stringify(verdicts)}; ${summary.result}`);
