#!/usr/bin/env node
// Times the email recovery prover in Chrome through chrome-devtools-axi, on
// the wallet's own benchmark page (/security/recover/bench/, served with the
// recovery routes' COOP/COEP headers), and rewrites browser-prover.json and
// the generated table of browser-prover.md.
//
//   npx astro build --root packages/frontend      # the page; no chain needed
//   node research/email-recovery/eval/measure-browser.mjs [--runs 3]
//
// Needs chrome-devtools-axi on PATH and Chrome for Testing as Playwright
// installs it (`npx playwright install chromium`), or $CHROME. Each browser
// is started headless on a throwaway profile with remote debugging, and
// chrome-devtools-axi attaches to it (CHROME_DEVTOOLS_AXI_BROWSER_URL).
//
// Configurations:
// - DevTools CPU throttling: `chrome-devtools-axi emulate --cpu 1|4|6`
//   (Emulation.setCPUThrottlingRate), with one Barretenberg thread and with
//   navigator.hardwareConcurrency threads. Chrome applies it to the page
//   only ("Operation is only supported for pages, not workers"), so it slows
//   the page's main thread (the page's probe loop shows by how much) and not
//   the prover, which runs in workers.
// - Efficiency cores: a second Chrome started under macOS's background QoS
//   clamp (`taskpolicy -c background`), which confines its threads to the
//   efficiency cores, with one and four threads. A desktop's efficiency
//   cores, not a phone.
// Each configuration is a cold run (the prover's cache emptied, so it
// downloads everything) and then --runs warm runs.
//
// Peak memory: the largest resident set size among the browser's renderer
// processes, sampled with `ps` every 200 ms while a configuration runs (the
// page, the prover's worker and Barretenberg's workers share the page's
// renderer); and Barretenberg's wasm linear memory after proving, which the
// page reports.
import { execFile, spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs, promisify } from 'node:util';
import { chromium } from '@playwright/test';

const exec = promisify(execFile);
const { values } = parseArgs({ options: { runs: { type: 'string' } } });
const RUNS = Number(values.runs ?? 3);
const repo = new URL('../../../', import.meta.url).pathname;
const here = new URL('./', import.meta.url).pathname;
const SITE_PORT = 4411;
const page = (q) => `http://localhost:${SITE_PORT}/security/recover/bench/?${q}&auto=1`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

if (!existsSync(join(repo, 'packages/frontend/dist/security/recover/bench/index.html'))) {
  console.error('build the frontend first: npx astro build --root packages/frontend');
  process.exit(2);
}

const sysctl = async (name) => (await exec('sysctl', ['-n', name]).catch(() => ({ stdout: '' }))).stdout.trim();
const host = {
  cpu: await sysctl('machdep.cpu.brand_string'),
  logical_cpus: Number(await sysctl('hw.ncpu')),
  performance_cores: Number(await sysctl('hw.perflevel0.physicalcpu')) || null,
  efficiency_cores: Number(await sysctl('hw.perflevel1.physicalcpu')) || null,
  memory_gib: Math.round(Number(await sysctl('hw.memsize')) / 2 ** 30),
  os: (await exec('sw_vers', ['-productVersion']).catch(() => ({ stdout: process.platform }))).stdout.trim(),
  load_average_at_start: (await sysctl('vm.loadavg')).replace(/[{}]/g, '').trim(),
};

const site = spawn(process.execPath, [join(repo, 'tests/support/server.mjs')], {
  env: { ...process.env, E2E_PORT: String(SITE_PORT) },
  stdio: 'ignore',
});

/** A headless Chrome on a throwaway profile, driven through its own chrome-devtools-axi session. */
async function browser(name, port, wrap = []) {
  const profile = mkdtempSync(join(tmpdir(), `nido-prover-${name}-`));
  const bin = process.env.CHROME ?? chromium.executablePath();
  const args = ['--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check', 'about:blank'];
  const proc = wrap.length ? spawn(wrap[0], [...wrap.slice(1), bin, ...args], { stdio: 'ignore' }) : spawn(bin, args, { stdio: 'ignore' });
  let version;
  for (let i = 0; i < 150 && !version; i++) {
    version = await fetch(`http://127.0.0.1:${port}/json/version`).then((r) => r.json(), () => undefined);
    if (!version) await sleep(200);
  }
  if (!version) throw new Error(`${name}: Chrome did not start`);
  const env = { ...process.env, CHROME_DEVTOOLS_AXI_SESSION: `email-prover-${name}`, CHROME_DEVTOOLS_AXI_BROWSER_URL: `http://127.0.0.1:${port}` };
  const axi = async (...a) => (await exec('chrome-devtools-axi', a, { env, maxBuffer: 1 << 24 })).stdout;
  // Attached to a running browser, a session selects no tab until told to.
  await axi('stop').catch(() => undefined);
  await axi('pages');
  await axi('selectpage', '1');
  return {
    version,
    profile,
    axi,
    async close() {
      await axi('stop').catch(() => undefined);
      proc.kill();
      await sleep(500);
      rmSync(profile, { recursive: true, force: true });
    },
  };
}

/** The value `chrome-devtools-axi eval` printed. */
function evalResult(out) {
  const m = /^result: (.*)$/m.exec(out);
  if (!m) return '';
  let v = JSON.parse(m[1]);
  while (typeof v === 'string' && v.startsWith('"')) v = JSON.parse(v);
  return v;
}

async function rendererRss(profile) {
  const { stdout } = await exec('ps', ['-axo', 'pid=,rss=,command=']);
  return stdout
    .split('\n')
    .filter((l) => l.includes('--type=renderer') && l.includes(profile))
    .map((l) => Number(l.trim().split(/\s+/)[1]) * 1024);
}

/** One configuration: a cold run and RUNS warm runs, with the renderer's peak RSS. */
async function configuration(b, { label, threads, cpu }) {
  // Configurations run in rising throttling order, so a browser starts unthrottled.
  if (cpu > 1) await b.axi('emulate', '--cpu', String(cpu));
  let peak = 0;
  let sampling = true;
  const sampler = (async () => {
    while (sampling) {
      for (const rss of await rendererRss(b.profile)) peak = Math.max(peak, rss);
      await sleep(200);
    }
  })();
  const docs = [];
  try {
    for (const [cold, runs] of [[1, 1], [0, RUNS]]) {
      await b.axi('open', page(`threads=${threads}&runs=${runs}&cold=${cold}`));
      for (;;) {
        const text = evalResult(await b.axi('eval', "document.getElementById('out').textContent"));
        if (typeof text === 'string' && text.startsWith('ERROR')) throw new Error(`${label}: ${text}`);
        if (typeof text === 'string' && text.startsWith('DONE ')) {
          docs.push(JSON.parse(text.slice(5)));
          break;
        }
        await sleep(2000);
      }
    }
  } finally {
    sampling = false;
    await sampler;
  }
  const [cold, warm] = docs;
  const median = (f) => warm.results.map(f).sort((x, y) => x - y)[Math.floor(warm.results.length / 2)];
  const out = {
    label,
    cpu_throttling: cpu,
    threads: cold.results[0].threads,
    cross_origin_isolated: cold.crossOriginIsolated,
    main_thread_probe_ms: cold.mainThreadProbeMs,
    cold_run: cold.results[0],
    warm_runs: warm.results,
    warm_median_ms: { total: median((r) => r.wall_ms), witness: median((r) => r.stage_ms.witness), proving: median((r) => r.stage_ms.proving) },
    peak_renderer_rss_mib: Math.round(peak / 2 ** 20),
    bb_wasm_memory_mib: Math.max(...warm.results.map((r) => r.bb_wasm_memory_mib)),
  };
  console.error(JSON.stringify({ label, threads: out.threads, cpu, ...out.warm_median_ms, rss: out.peak_renderer_rss_mib }));
  return out;
}

const results = [];
let chromeVersion;
try {
  for (let i = 0; i < 50; i++) {
    if (await fetch(page('x=1')).then((r) => r.ok, () => false)) break;
    await sleep(200);
  }
  const desktop = await browser('desktop', 9341);
  chromeVersion = desktop.version.Browser;
  try {
    for (const cpu of [1, 4, 6]) {
      for (const threads of ['1', 'max']) {
        results.push(await configuration(desktop, { label: 'desktop', threads, cpu }));
      }
    }
  } finally {
    await desktop.close();
  }
  if (process.platform === 'darwin') {
    const ecores = await browser('ecores', 9342, ['taskpolicy', '-c', 'background']);
    try {
      for (const threads of ['1', '4']) {
        results.push(await configuration(ecores, { label: 'efficiency-cores', threads, cpu: 1 }));
      }
    } finally {
      await ecores.close();
    }
  }
} finally {
  site.kill();
}

const doc = {
  generated: new Date().toISOString(),
  browser: chromeVersion,
  host,
  page: '/security/recover/bench/ (packages/frontend), the Gmail fixture of crates/integration-tests/fixtures/email/provider-gmail-com',
  warm_runs_per_configuration: RUNS,
  results,
};
writeFileSync(join(here, 'browser-prover.json'), JSON.stringify(doc, null, 2) + '\n');

const s = (ms) => (ms / 1000).toFixed(1);
const row = (r) => {
  const what =
    r.label === 'efficiency-cores'
      ? 'Desktop efficiency cores (background QoS)'
      : r.cpu_throttling === 1
        ? 'Desktop'
        : `Desktop, DevTools ${r.cpu_throttling}x CPU throttling (page only)`;
  return `| ${what} | ${r.threads} | ${s(r.warm_median_ms.proving)} | ${s(r.warm_median_ms.witness)} | ${s(r.warm_median_ms.total)} | ${s(r.cold_run.wall_ms)} | ${r.bb_wasm_memory_mib} | ${r.peak_renderer_rss_mib} | ${r.main_thread_probe_ms} |`;
};
const table = [
  `Generated by \`research/email-recovery/eval/measure-browser.mjs\` on ${doc.generated.slice(0, 16).replace('T', ' ')} UTC.`,
  `${chromeVersion} (Chrome for Testing, headless) on ${host.cpu}, ${host.logical_cpus} logical CPUs (${host.performance_cores} performance and ${host.efficiency_cores} efficiency cores), ${host.memory_gib} GiB, macOS ${host.os}; load average at start ${host.load_average_at_start}.`,
  `Times are medians of ${RUNS} warm runs (everything read from the prover's cache); "cold" is one run with an empty cache, downloading ${(results[0].cold_run.downloaded_bytes / 1e6).toFixed(1)} MB.`,
  '',
  '| Configuration | Threads | Proving (s) | Witness (s) | Total (s) | Cold total (s) | Barretenberg memory (MiB) | Peak renderer RSS (MiB) | Main-thread probe (ms) |',
  '| --- | --- | --- | --- | --- | --- | --- | --- | --- |',
  ...results.map(row),
].join('\n');
const md = join(here, 'browser-prover.md');
const text = readFileSync(md, 'utf8');
const begin = '<!-- BEGIN GENERATED by measure-browser.mjs; do not edit -->';
const end = '<!-- END GENERATED -->';
writeFileSync(md, text.slice(0, text.indexOf(begin) + begin.length) + '\n' + table + '\n' + text.slice(text.indexOf(end)));
console.log(table);
