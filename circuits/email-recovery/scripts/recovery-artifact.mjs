#!/usr/bin/env node
// Writes artifacts/recovery.json from nargo's target/recovery.json, keeping
// only what execution and proving need (noir_version, hash, abi, bytecode):
// the debug symbols and file map hold machine-specific paths. With --check,
// fails instead if the committed artifact differs from the compiled one.
// Run after `nargo compile --package recovery` with Perch's pinned nargo.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const compiled = JSON.parse(readFileSync(join(root, 'target/recovery.json'), 'utf8'));
const { noir_version, hash, abi, bytecode } = compiled;
const text = `${JSON.stringify({ noir_version, hash, abi, bytecode }, null, 1)}\n`;
const out = join(root, 'artifacts/recovery.json');
if (process.argv.includes('--check')) {
  let committed = '';
  try {
    committed = readFileSync(out, 'utf8');
  } catch {}
  if (committed !== text) {
    console.error('artifacts/recovery.json differs from the compiled circuit; run `just gen-email-proofs`');
    process.exit(1);
  }
  console.log('artifacts/recovery.json matches the compiled circuit');
} else {
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, text);
  console.log(`wrote ${out}`);
}
