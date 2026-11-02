#!/usr/bin/env node
// The alert path's latency on loopback mocks: runs the alert service's
// end-to-end test (infra/email-alerts/test/e2e.test.ts) `runs` times, each
// with NIDO_ALERT_MEASUREMENTS set, and writes results/alert-latency.json
// with every run's readings and, per figure, the minimum, median and maximum.
// The figures: an `attempt_authorized` event to the email the sending mock
// accepts and to the push the push-service mock accepts, and a restarted
// vault restoring its key from two custodians. Builds the service first.
//
//   node research/email-recovery/eval/alert-latency.mjs [runs]   (default 10)
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { cpus, loadavg, tmpdir } from 'node:os';
import { join } from 'node:path';

const repo = new URL('../../../', import.meta.url).pathname;
const runs = Number(process.argv[2] ?? 10);
const FIGURES = ['eventsPollToEmailAcceptedMs', 'eventsPollToPushAcceptedMs', 'vaultRestoreMs'];

execFileSync('npm', ['run', 'build', '-w', '@nidohq/email-alerts'], { cwd: repo, stdio: 'inherit' });
const dir = mkdtempSync(join(tmpdir(), 'alert-latency-'));
const loadAtStart = loadavg()[0];
const readings = [];
for (let i = 0; i < runs; i++) {
  const file = join(dir, `run-${i}.json`);
  execFileSync('npx', ['vitest', 'run', '--root', 'infra/email-alerts', 'test/e2e.test.ts'], {
    cwd: repo,
    stdio: 'inherit',
    env: { ...process.env, NIDO_ALERT_MEASUREMENTS: file },
  });
  readings.push(JSON.parse(readFileSync(file, 'utf8')));
}
rmSync(dir, { recursive: true, force: true });

const median = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
};
const round = (x) => Math.round(x * 10) / 10;
const summary = Object.fromEntries(
  FIGURES.map((f) => {
    const xs = readings.map((r) => r[f]);
    return [f, { min: round(Math.min(...xs)), median: round(median(xs)), max: round(Math.max(...xs)) }];
  }),
);
const out = {
  generated: new Date().toISOString(),
  test: 'infra/email-alerts/test/e2e.test.ts',
  machine: { cpus: cpus().length, loadAverageAtStart: round(loadAtStart), loadAverageAtEnd: round(loadavg()[0]) },
  runs,
  summary,
  readings,
};
const path = join(repo, 'research/email-recovery/eval/results/alert-latency.json');
writeFileSync(path, `${JSON.stringify(out, null, 2)}\n`);
console.log(JSON.stringify(summary));
