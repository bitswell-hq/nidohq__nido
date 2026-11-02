#!/usr/bin/env node
// A self-contained build of the wallet's prover benchmark page
// (/security/recover/bench/) for opening on a phone: the built page, the
// build's assets (the prover worker, bb.js and noir_js with their wasm, the
// circuit artifact, its verification key, the TEST-ONLY Gmail fixture), and
// the prefix of Barretenberg's BN254 CRS the circuit needs, fetched once from
// Barretenberg's host and checked against the prover's pinned SHA-256
// digests (CRS_G1_SHA256, CRS_G2_SHA256), so the page needs nothing but this
// directory. Writes target/email-bench-phone/ and its build.json.
//
//   npx astro build --root packages/frontend
//   node research/email-recovery/eval/phone/build.mjs
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { CRS_G1_SHA256, CRS_G2_SHA256, RECOVERY_CRS_POINTS, fetchCrs, memoryCache } from '@nidohq/email-recovery';

const repo = new URL('../../../../', import.meta.url).pathname;
const dist = join(repo, 'packages/frontend/dist');
const out = join(repo, 'target/email-bench-phone');
if (!existsSync(join(dist, 'security/recover/bench/index.html'))) {
  console.error('build the frontend first: npx astro build --root packages/frontend');
  process.exit(2);
}
rmSync(out, { recursive: true, force: true });
mkdirSync(join(out, 'security/recover/bench'), { recursive: true });
cpSync(join(dist, 'security/recover/bench/index.html'), join(out, 'security/recover/bench/index.html'));
cpSync(join(dist, '_astro'), join(out, '_astro'), { recursive: true });
cpSync(join(dist, '_headers'), join(out, '_headers'));
// Root files the page links (icons, the manifest).
const html = readFileSync(join(out, 'security/recover/bench/index.html'), 'utf8');
for (const m of html.matchAll(/(?:href|src)="\/([^"/?#][^"?#]*)"/g)) {
  const f = join(dist, m[1]);
  if (!m[1].startsWith('_astro/') && existsSync(f) && statSync(f).isFile()) {
    mkdirSync(join(out, m[1], '..'), { recursive: true });
    cpSync(f, join(out, m[1]));
  }
}
const crs = await fetchCrs(RECOVERY_CRS_POINTS, { cache: memoryCache() });
const sha = (b) => createHash('sha256').update(b).digest('hex');
if (sha(crs.g1) !== CRS_G1_SHA256 || sha(crs.g2) !== CRS_G2_SHA256) throw new Error('the CRS does not match the pinned digests');
mkdirSync(join(out, 'crs'), { recursive: true });
writeFileSync(join(out, 'crs/g1.dat'), crs.g1);
writeFileSync(join(out, 'crs/g2.dat'), crs.g2);
writeFileSync(join(out, 'index.html'), '<!doctype html><meta charset="utf-8"><title>Nido prover benchmark</title><meta http-equiv="refresh" content="0; url=/security/recover/bench/?crs=/crs/">\n');
const files = [];
const walk = (d) => readdirSync(d).forEach((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)) : files.push(join(d, f))));
walk(out);
const manifest = {
  built: new Date().toISOString(),
  page: '/security/recover/bench/?crs=/crs/',
  crs: { points: RECOVERY_CRS_POINTS, g1_sha256: CRS_G1_SHA256, g2_sha256: CRS_G2_SHA256 },
  files: files.length,
  bytes: files.reduce((n, f) => n + statSync(f).size, 0),
};
writeFileSync(join(out, 'build.json'), JSON.stringify(manifest, null, 1) + '\n');
console.log(`${relative(repo, out)}: ${manifest.files} files, ${(manifest.bytes / 1e6).toFixed(1)} MB`);
