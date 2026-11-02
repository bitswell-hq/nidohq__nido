#!/usr/bin/env node
// Rewrites the generated tables of README.md from results/.
//
//   node report.mjs

import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const here = new URL('.', import.meta.url).pathname;
const read = (f) => JSON.parse(readFileSync(join(here, 'results', f), 'utf8'));
const diff = read('differential.json');
const fuzz = read('fuzz.json');
const finding = read('from-finding.json');

const n = (x) => Number(x ?? 0).toLocaleString('en-US');
const cell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\r\n/g, '␍␊').replace(/\t/g, '␉');
const code = (s) => (s == null || s === '' ? '—' : `\`${cell(s).replace(/`/g, "'")}\``);
const table = (head, rows) => [`| ${head.join(' | ')} |`, `| ${head.map(() => '---').join(' | ')} |`, ...rows.map((r) => `| ${r.join(' | ')} |`)].join('\n');

const sections = {};

// Part 1.
{
  const domains = Object.entries(diff.domains);
  const sum = (k) => domains.reduce((a, [, d]) => a + d[k], 0);
  sections['real-mail'] = [
    `Corpus: ${n(diff.corpus.available)} posts from ${diff.corpus.lists} lists at ${diff.corpus.archive}, months ${diff.corpus.months.join(', ')} (manifest built ${diff.corpus.built}); ${n(diff.corpus.unavailable)} no longer served. ${n(diff.signatures)} DKIM-Signature fields, ${n(diff.executions)} circuit executions (harness and recovery artifact), ${diff.seconds} s, ${diff.python}.`,
    '',
    table(
      ['From domain', 'Posts', 'Signatures (aligned)', 'Reference accepts', 'Circuit accepts', 'Posts in agreement'],
      [
        ...domains.map(([dom, d]) => [dom, n(d.posts), `${n(d.signatures)} (${n(d.alignedSignatures)})`, n(d.referenceAccepts), n(d.circuitAccepts), n(d.agree)]),
        ['**all**', n(sum('posts')), `${n(sum('signatures'))} (${n(sum('alignedSignatures'))})`, n(sum('referenceAccepts')), n(sum('circuitAccepts')), n(sum('agree'))],
      ],
    ),
    '',
    `Verdicts per signature: ${Object.entries(diff.verdicts).map(([k, v]) => `${k} ${n(v)}`).join(', ')}. Result: ${diff.result}. The recovery artifact agreed with the harness on ${n(diff.crossCheck.signatures - diff.crossCheck.disagreements)} of ${n(diff.crossCheck.signatures)} signatures; the encoder's signed block differed from the reference's on ${n(diff.blockDivergence)}; the verifying key came from the live DNS for ${n(diff.keysUsed['live DNS'])} signatures and only from zkEmail's archive for ${n(diff.keysUsed['archive.zk.email only'])}. Python and mailauth read the From of every accepted signature the same way: ${diff.fromDisagreements.length ? `no, ${diff.fromDisagreements.length} differ` : 'yes'}.`,
  ].join('\n');

  sections['real-mail-reasons'] = table(
    ['Why the reference refuses a signature', 'Signatures', 'Circuit refusal'],
    [
      ...Object.entries(diff.referenceRefusals).map(([r, c]) => [`DKIM: ${r}`, n(c), '`RSA: signature does not verify` (under every candidate key)']),
      ...Object.entries(diff.profileRefusals).map(([r, c]) => [`Spec ${r}`, n(c), r.startsWith('6.3') ? '`encoder: the signed header block is N octets; the circuit takes at most N`' : r.includes('rule 7') ? '`DKIM: d= must equal the From domain`' : '`header: exactly one signed Subject field is required`']),
    ],
  );
  sections['real-mail-mismatches'] = diff.mismatches.length
    ? table(['Archive', 'Position', 'Signature', 'Verdict', 'Detail'], diff.mismatches.map((m) => [m.archive, m.index, `d=${m.d} s=${m.s}`, m.verdict, cell(m.violation ?? m.circuitRefusals.join('; '))]))
    : 'None: no post in the corpus has a signature the circuit and the reference judge differently, and every accepted signature binds the address Python reads.';
}

// Part 2.
{
  const v = fuzz.verdicts;
  sections['fuzz'] = [
    `Seed \`${fuzz.seed}\`, cases ${n(fuzz.cases.from)} to ${n(fuzz.cases.from + fuzz.cases.count - 1)}: ${n(fuzz.cases.count)} cases, ${n(fuzz.signatures)} DKIM-Signature fields (${n(fuzz.casesWithoutSignature)} cases have none the reference recognizes), ${n(fuzz.executions)} circuit executions, ${fuzz.seconds} s, ${fuzz.python}. Signed over the reference's octets: ${n(fuzz.signedVia.mailauth)}; over the encoder's (fields the reference does not process): ${n(fuzz.signedVia.encoder)}.`,
    '',
    table(['Verdict', 'Signatures'], ['agree-accept', 'agree-refuse', 'soundness', 'spec-deviation', 'completeness'].map((k) => [k, n(v[k])])),
    '',
    `Invariant (circuit accepts ⇒ the reference DKIM verifier accepts, Python reads exactly the circuit's address, and the circuit's domain is the lowercase d=): **${fuzz.invariant}**. Every ${fuzz.crossCheck.every}th case also ran the recovery artifact: ${n(fuzz.crossCheck.signatures)} signatures, ${n(fuzz.crossCheck.disagreements)} disagreements with the harness. The encoder's signed block differed from the reference's on ${n(fuzz.blockDivergence.reduce((a, g) => a + g.count, 0))} signatures; ${fuzz.blockDivergence.map((g) => `${g.reference}: ${n(g.count)} (smallest case ${g.cases[0]})`).join('; ')}.`,
  ].join('\n');

  sections['fuzz-families'] = table(
    ['Family', 'Cases', 'Signatures', 'Circuit accepts', 'Reference and spec accept', 'Soundness', 'Spec deviation', 'Completeness'],
    Object.entries(fuzz.families).map(([f, x]) => [f, n(x.cases), n(x.signatures), n(x.circuitAccepts), n(x.referenceAccepts), n(x.verdicts.soundness), n(x.verdicts['spec-deviation']), n(x.verdicts.completeness)]),
  );

  sections['fuzz-counterexamples'] = table(
    ['Kind', 'Class', 'Signatures', 'Example case', 'Example field', 'Python reads', 'Circuit binds'],
    fuzz.counterexampleClasses.map((g) => {
      const x = g.examples[0];
      if (g.kind === 'dkim') return [g.kind, g.class, n(g.count), x.case, code(x.fields.find((f) => /^dkim-signature/i.test(f))?.slice(0, 110)), '—', code(x.circuit.address)];
      return [g.kind, g.class, n(g.count), x.case, code(`from:${x.circuit.fromValue}`), code(JSON.stringify(x.from?.python ?? [])), code(x.circuit.address)];
    }),
  );
  sections['fuzz-deviations'] = fuzz.specDeviations.length
    ? table(['Spec rule the circuit does not apply', 'Signatures', 'Example case', 'Signed From line'], fuzz.specDeviations.map((g) => [cell(g.violation), n(g.count), g.examples[0].case, code(g.examples[0].fields.filter((f) => /^from\s*:/i.test(f)).at(-1))]))
    : 'None.';
  sections['fuzz-gaps'] = fuzz.completenessGaps.length
    ? table(['Circuit refusal', 'Signatures', 'Example case', 'Example DKIM-Signature (start)'], fuzz.completenessGaps.map((g) => [code(g.refusal), n(g.count), g.examples[0].case, code(g.examples[0].fields.find((f) => /^dkim-signature/i.test(f))?.slice(0, 120))]))
    : 'None.';
}

// The finding on the recovery artifact.
sections['from-finding'] = table(
  ['Signed From value', 'Python reads', 'mailauth reads', 'Recovery artifact'],
  finding.rows.map((r) => [code(r.from), `${code(JSON.stringify(r.python))}${r.pythonDefects.length ? ' (defects)' : ''}`, `${code(JSON.stringify(r.mailauth.addresses))} (${r.mailauth.syntax})`, r.circuit.accepts ? `accepts, opens the commitment with ${code(r.circuit.opensCommitmentWith)}` : `refuses: ${code(r.circuit.refusal)}`]),
);

let readme = readFileSync(join(here, 'README.md'), 'utf8');
for (const [name, body] of Object.entries(sections)) {
  const re = new RegExp(`(<!-- BEGIN GENERATED ${name} by report.mjs; do not edit -->)[\\s\\S]*?(<!-- END GENERATED ${name} -->)`);
  if (!re.test(readme)) throw new Error(`README.md has no generated section ${name}`);
  readme = readme.replace(re, (_, a, b) => `${a}\n${body}\n${b}`);
}
writeFileSync(join(here, 'README.md'), readme);
