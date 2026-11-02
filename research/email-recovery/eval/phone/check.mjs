#!/usr/bin/env node
// Opens the self-contained benchmark build (phone/build.mjs, served by
// phone/serve.mjs) in headless Chrome over HTTPS and runs one cold proof on
// one thread and one on every core, as a phone would: the page must be
// cross-origin isolated, read the CRS from the build, and verify its proofs.
// Prints the page's reports. A check of the build, not a phone measurement.
//
//   node research/email-recovery/eval/phone/check.mjs [--port 8543]
import { spawn } from 'node:child_process';
import { parseArgs } from 'node:util';
import { chromium } from '@playwright/test';

const { values } = parseArgs({ options: { port: { type: 'string' } } });
const port = Number(values.port ?? 8543);
const here = new URL('./', import.meta.url).pathname;
const server = spawn(process.execPath, [`${here}serve.mjs`, '--port', String(port)], { stdio: ['ignore', 'pipe', 'inherit'] });
await new Promise((ok) => server.stdout.on('data', (d) => String(d).includes('Open on') && ok()));
const browser = await chromium.launch({ executablePath: process.env.CHROME, args: ['--ignore-certificate-errors'] });
try {
  const page = await (await browser.newContext({ ignoreHTTPSErrors: true })).newPage();
  for (const threads of ['1', 'max']) {
    await page.goto(`https://localhost:${port}/security/recover/bench/?crs=/crs/&threads=${threads}&runs=1&cold=1&auto=1`);
    await page.waitForFunction(() => /^(DONE|ERROR)/.test(document.getElementById('out')?.textContent ?? ''), null, { timeout: 300_000 });
    const text = await page.locator('#out').textContent();
    if (!text.startsWith('DONE')) throw new Error(text);
    const r = JSON.parse(text.slice(5));
    console.log(JSON.stringify({ threads: r.results[0].threads, crossOriginIsolated: r.crossOriginIsolated, crsBaseUrl: r.crsBaseUrl, downloaded_bytes: r.results[0].downloaded_bytes, wall_ms: r.results[0].wall_ms, proving_ms: r.results[0].stage_ms.proving }));
  }
} finally {
  await browser.close();
  server.kill();
}
