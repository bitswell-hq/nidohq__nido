#!/usr/bin/env node
// The attack suite's figures across runs of one build: appends a run's
// figures (results/figures.json, as report.mjs wrote it) with its run time
// (results/attacks-local.json) to results/attack-reruns.json, and recomputes
// each figure's minimum, maximum and spread over the recorded runs. The
// build is the sha256 of the email contracts' wasm the suite deploys
// (`just build-contracts`' output, which the source reproduces byte for
// byte); a run recorded beside another build is refused, so the spread is
// what each run's new keys and proofs alone move.
//
//   node research/email-recovery/eval/reruns.mjs [figures.json attacks-local.json]
//   (defaults: the current results)
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';

const results = new URL('./results/', import.meta.url).pathname;
const [figuresFile = `${results}figures.json`, attacksFile = `${results}attacks-local.json`] = process.argv.slice(2);
const out = `${results}attack-reruns.json`;

const figures = JSON.parse(readFileSync(figuresFile, 'utf8')).figures;
const attacks = JSON.parse(readFileSync(attacksFile, 'utf8'));
const wasm = new URL('../../../target/wasm32v1-none/contract/', import.meta.url).pathname;
const build = Object.fromEntries(
  ['nido_dkim_registry', 'nido_email_guardian', 'nido_email_verifier'].map((name) => [
    name,
    createHash('sha256').update(readFileSync(`${wasm}${name}.wasm`)).digest('hex'),
  ]),
);
const doc = existsSync(out) ? JSON.parse(readFileSync(out, 'utf8')) : { build, runs: [] };
if (JSON.stringify(doc.build) !== JSON.stringify(build)) throw new Error('the run is of another build than the recorded runs');
if (!doc.runs.some((r) => r.generated === attacks.generated)) doc.runs.push({ generated: attacks.generated, figures });
doc.runs.sort((a, b) => a.generated.localeCompare(b.generated));
doc.spread = Object.fromEntries(
  Object.keys(doc.runs[0].figures)
    .sort()
    .map((name) => {
      const xs = doc.runs.map((r) => r.figures[name]);
      return [name, { min: Math.min(...xs), max: Math.max(...xs), spread: Math.max(...xs) - Math.min(...xs) }];
    }),
);
writeFileSync(out, `${JSON.stringify(doc, null, 2)}\n`);
console.log(`${doc.runs.length} runs in ${out}`);
