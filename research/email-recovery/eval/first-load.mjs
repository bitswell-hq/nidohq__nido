#!/usr/bin/env node
// Everything a first proof transfers: the prover benchmark page
// (/security/recover/bench/, the wallet's own prover) loaded once in a
// fresh headless Chrome with an empty cache, one thread, behind a proxy that
// counts every response body the site server sends, whether the page or a
// worker fetched it: the page's own files, the prover's code (its worker,
// bb.js with Barretenberg's wasm, noir_js and its wasm) and the circuit
// artifact. The proving inputs (the artifact, its key and the CRS prefix,
// which the worker fetches from crs.aztec.network) are counted as the
// prover reports them, and what other origins send from Chrome's network
// log. Writes results/first-load.json. The test server sends files
// uncompressed; a deployment's compression would transfer less.
//
//   npx astro build --root packages/frontend
//   CHROME=<Chrome for Testing> node research/email-recovery/eval/first-load.mjs
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { request, createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium } from '@playwright/test';

const repo = new URL('../../../', import.meta.url).pathname;
const SITE = 4421;
const PROXY = 4422;
const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms));

const site = spawn(process.execPath, [join(repo, 'tests/support/server.mjs')], { env: { ...process.env, E2E_PORT: String(SITE) }, stdio: 'ignore' });
const responses = [];
const proxy = createServer((req, res) => {
  const up = request({ host: '127.0.0.1', port: SITE, path: req.url, method: req.method, headers: { ...req.headers, 'accept-encoding': 'identity' } }, (r) => {
    res.writeHead(r.statusCode, r.headers);
    let bytes = 0;
    r.on('data', (c) => {
      bytes += c.length;
      res.write(c);
    });
    r.on('end', () => {
      res.end();
      responses.push({ path: req.url.split('?')[0], status: r.statusCode, type: r.headers['content-type'] ?? '', bytes });
    });
  });
  req.pipe(up);
});
await new Promise((ok) => proxy.listen(PROXY, '127.0.0.1', ok));
for (let i = 0; i < 100; i++) {
  if (await fetch(`http://127.0.0.1:${SITE}/`).then(() => true, () => false)) break;
  await sleep(200);
}

const profile = mkdtempSync(join(tmpdir(), 'nido-first-load-'));
const context = await chromium.launchPersistentContext(profile, { executablePath: process.env.CHROME, headless: true });
let result;
// Chrome's own record of every request, the page's and its workers', with the bytes each response body took.
const network = [];
context.on('requestfinished', async (req) => {
  const sizes = await req.sizes().catch(() => undefined);
  network.push({ url: req.url().split('?')[0], origin: new URL(req.url()).origin, type: req.resourceType(), bytes: sizes?.responseBodySize ?? 0 });
});
try {
  const page = context.pages()[0] ?? (await context.newPage());
  await page.goto(`http://localhost:${PROXY}/security/recover/bench/?threads=1&runs=1&cold=1&auto=1`);
  for (;;) {
    const text = await page.locator('#out').textContent();
    if (text?.startsWith('ERROR')) throw new Error(text);
    if (text?.startsWith('DONE ')) {
      result = JSON.parse(text.slice(5));
      break;
    }
    await sleep(1000);
  }
} finally {
  await context.close();
  rmSync(profile, { recursive: true, force: true });
  proxy.close();
  site.kill();
}

const kind = (r) => (/\.wasm$/.test(r.path) || /wasm/.test(r.type) ? 'wasm' : /\.(m?js)$/.test(r.path) || /javascript/.test(r.type) ? 'script' : /\.(json|bin|vk|gz)$/.test(r.path) || /octet-stream|json/.test(r.type) ? 'data' : /html|css|svg|font|image/.test(r.type) ? 'page' : 'other');
const byKind = {};
for (const r of responses) {
  const k = kind(r);
  byKind[k] ??= { requests: 0, bytes: 0 };
  byKind[k].requests++;
  byKind[k].bytes += r.bytes;
}
const out = {
  generated: new Date().toISOString(),
  page: '/security/recover/bench/?threads=1&runs=1&cold=1 (packages/frontend build), fresh profile, empty cache',
  crossOriginIsolated: result?.crossOriginIsolated,
  proverReportedBytes: result?.results?.[0]?.downloaded_bytes,
  total: { requests: responses.length, bytes: responses.reduce((n, r) => n + r.bytes, 0) },
  byKind,
  responses: responses.sort((a, b) => b.bytes - a.bytes),
  // Chrome's network log: what the site sent and what came from other origins.
  browserLog: {
    requests: network.length,
    bytes: network.reduce((n, r) => n + r.bytes, 0),
    byOrigin: Object.entries(network.reduce((m, r) => ((m[r.origin] = (m[r.origin] ?? 0) + r.bytes), m), {})).map(([origin, bytes]) => ({ origin, bytes })),
    requestsLogged: network.sort((a, b) => b.bytes - a.bytes),
  },
};
// A first proof's whole transfer: the site's own files and the prover's code
// (everything the site sent except the circuit artifact), the proving inputs
// as the prover counts them (the artifact, its key and the CRS prefix, part
// of it from another origin), and what other origins sent the page.
const artifact = responses.filter((r) => /\/recovery\.[^/]*\.json$/.test(r.path)).reduce((n, r) => n + r.bytes, 0);
const siteOrigin = new URL(`http://localhost:${PROXY}`).origin;
const others = out.browserLog.byOrigin.filter((o) => o.origin !== siteOrigin && !/crs\.aztec\.network/.test(o.origin)).reduce((n, o) => n + o.bytes, 0);
out.firstProof = { code: out.total.bytes - artifact, inputs: out.proverReportedBytes, otherOrigins: others, total: out.total.bytes - artifact + out.proverReportedBytes + others };
writeFileSync(join(repo, 'research/email-recovery/eval/results/first-load.json'), JSON.stringify(out, null, 1) + '\n');
console.log(JSON.stringify({ firstProof: out.firstProof, total: out.total, byKind, browser: { requests: out.browserLog.requests, bytes: out.browserLog.bytes, byOrigin: out.browserLog.byOrigin }, proverReportedBytes: out.proverReportedBytes, crossOriginIsolated: out.crossOriginIsolated }));
