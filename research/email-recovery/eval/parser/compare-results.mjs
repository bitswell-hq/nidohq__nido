#!/usr/bin/env node
// check.sh --ci: the verdicts of a partial run must be exactly the ones the
// committed full run (results/) records for the same posts and cases, and the
// recovery artifact must agree with the harness on every execution.
//
//   node compare-results.mjs <differential.json> <fuzz.json>

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { decodeVerdicts } from './lib/compare.mjs';

const here = new URL('.', import.meta.url).pathname;
const read = (f) => JSON.parse(readFileSync(f, 'utf8'));
const [diffFile, fuzzFile] = process.argv.slice(2);
const problems = [];

const diff = read(diffFile);
const diffRef = read(join(here, 'results/differential.json'));
const refCodes = decodeVerdicts(diffRef.verdicts.codes);
const refByPost = new Map(diffRef.verdicts.posts.map((n, i) => [n, refCodes[i]]));
decodeVerdicts(diff.verdicts.codes).forEach((codes, i) => {
  const n = diff.verdicts.posts[i];
  if (refByPost.get(n) !== codes) problems.push(`manifest post ${n}: verdicts ${codes}, results/ records ${refByPost.get(n)}`);
});
if (diff.crossCheck.disagreements) problems.push(`real mail: the recovery artifact disagreed with the harness on ${diff.crossCheck.disagreements} signatures`);

const fuzz = read(fuzzFile);
const fuzzRef = read(join(here, 'results/fuzz.json'));
if (fuzz.seed !== fuzzRef.seed) problems.push(`fuzz seed ${fuzz.seed} differs from results/ (${fuzzRef.seed})`);
const fuzzCodes = decodeVerdicts(fuzz.verdictCodes);
const fuzzRefCodes = decodeVerdicts(fuzzRef.verdictCodes);
fuzzCodes.forEach((codes, i) => {
  const at = fuzz.cases.from + i - fuzzRef.cases.from;
  if (fuzzRefCodes[at] !== codes) problems.push(`fuzz case ${fuzz.cases.from + i}: verdicts ${codes}, results/ records ${fuzzRefCodes[at]}`);
});
if (fuzz.crossCheck.disagreements) problems.push(`fuzz: the recovery artifact disagreed with the harness on ${fuzz.crossCheck.disagreements} signatures`);

if (problems.length) {
  for (const p of problems.slice(0, 50)) console.error(p);
  console.error(`${problems.length} difference(s) from results/; if the change is intended, rerun check.sh without --ci and commit results/`);
  process.exit(1);
}
console.log(`${diff.verdicts.posts.length} posts and ${fuzzCodes.length} fuzz cases reproduce results/ exactly`);
