#!/usr/bin/env node
// Proving one recovery email on this machine, with one circuit build for
// every prover: the committed artifact circuits/email-recovery/artifacts/
// recovery.json (its sha256 recorded), whose verification key must hash to
// the circuit id the on-chain verifier embeds.
//
// - Native: `nargo execute` (Perch's pinned nargo, after checking its
//   compiled bytecode is the artifact's) and `bb prove --scheme ultra_honk
//   --oracle_hash keccak --zk` (Perch's pinned bb) on the artifact, every
//   proof checked with `bb verify`; all cores, one thread
//   (`HARDWARE_CONCURRENCY=1`), and the slower core tier.
// - Node: packages/email-recovery/scripts/measure-bbjs.mjs (noir_js and
//   bb.js 0.87.0, the browser's prover) in a fresh process per run; one
//   thread and one per logical CPU, and the slower core tier.
// - Browser: the runs research/email-recovery/eval/measure-browser.mjs
//   recorded in browser-prover.json (the wallet's prover worker in Chrome).
//
// The slower core tier runs the process under macOS's background QoS clamp
// (`taskpolicy -c background`), which confines its threads to the lower of
// the machine's two core tiers (`hw.perflevel1`, named as macOS names it):
// a desktop's slower cores, not a phone's.
//
// Every configuration runs RUNS times (default 5); the table gives the
// median and the range. Writes research/email-recovery/eval/results/proving.json.
//
//   research/email-recovery/eval/proving/measure.sh      # toolchain, compile, then this
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { cpus, loadavg, tmpdir } from 'node:os';
import { join } from 'node:path';

const repo = new URL('../../../../', import.meta.url).pathname;
const RUNS = Number(process.env.RUNS ?? 5);
const BB = process.env.BB;
const NARGO = process.env.NARGO;
if (!BB || !NARGO) throw new Error('run through proving/measure.sh (it selects Perch\'s pinned nargo and bb)');
const sha = (f) => createHash('sha256').update(readFileSync(f)).digest('hex');
const ARTIFACT = join(repo, 'circuits/email-recovery/artifacts/recovery.json');
const VK = join(repo, 'contracts/email-verifier/vk/email_recovery.vk');
const FIXTURE = join(repo, 'crates/integration-tests/fixtures/email/provider-gmail-com');
const SCHEME = ['--scheme', 'ultra_honk', '--oracle_hash', 'keccak'];
const N = cpus().length;
const sysctl = (k) => {
  try {
    return execFileSync('sysctl', ['-n', k], { encoding: 'utf8' }).trim();
  } catch {
    return '';
  }
};
const machine = {
  cpu: sysctl('machdep.cpu.brand_string'),
  logical_cpus: N,
  // The core tiers as macOS names them, fastest first.
  core_tiers: [0, 1].map((i) => ({ name: sysctl(`hw.perflevel${i}.name`), logical: Number(sysctl(`hw.perflevel${i}.logicalcpu`)) || null })),
  memory_gib: Math.round(Number(sysctl('hw.memsize')) / 2 ** 30),
  os: (() => {
    try {
      return `macOS ${execFileSync('sw_vers', ['-productVersion'], { encoding: 'utf8' }).trim()}`;
    } catch {
      return process.platform;
    }
  })(),
  node: process.version,
  load_average_at_start: loadavg().map((x) => x.toFixed(2)).join(' '),
};
/** The slower tier, under background QoS, as the table names it. */
const SLOW = `${machine.core_tiers[1].name || 'slower'}-tier cores (background QoS)`;

// One circuit build.
const compiled = JSON.parse(readFileSync(join(repo, 'circuits/email-recovery/target/recovery.json'), 'utf8'));
const artifact = JSON.parse(readFileSync(ARTIFACT, 'utf8'));
if (compiled.bytecode !== artifact.bytecode) throw new Error('nargo compiled other bytecode than the committed artifact');
const work = mkdtempSync(join(tmpdir(), 'nido-proving-'));
execFileSync(BB, ['write_vk', ...SCHEME, '-b', ARTIFACT, '-o', work], { stdio: 'ignore' });
if (sha(join(work, 'vk')) !== sha(VK)) throw new Error('the artifact\'s verification key is not the verifier\'s');
const circuit = {
  artifact: 'circuits/email-recovery/artifacts/recovery.json',
  artifact_sha256: sha(ARTIFACT),
  vk_sha256: sha(VK),
  nargo: execFileSync(NARGO, ['--version'], { encoding: 'utf8' }).split('\n')[0],
  bb: execFileSync(BB, ['--version'], { encoding: 'utf8' }).trim(),
  fixture: 'crates/integration-tests/fixtures/email/provider-gmail-com',
};

/** `cmd` under `/usr/bin/time -l`: wall seconds and peak RSS bytes. */
function timed(cmd, args, { env = {}, cwd = repo, background = false } = {}) {
  const argv = background ? ['taskpolicy', '-c', 'background', cmd, ...args] : [cmd, ...args];
  const r = spawnSync('/usr/bin/time', ['-l', ...argv], { cwd, env: { ...process.env, ...env }, encoding: 'utf8', maxBuffer: 1 << 26 });
  if (r.status !== 0) throw new Error(`${argv.join(' ')}: ${r.stderr.slice(-2000)}`);
  const real = Number(/([\d.]+) real/.exec(r.stderr)[1]);
  const rss = Number(/(\d+)\s+maximum resident set size/.exec(r.stderr)[1]);
  return { seconds: real, rss, stdout: r.stdout };
}

const stats = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  const median = s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
  return { median, min: s[0], max: s[s.length - 1], n: s.length };
};

const rows = [];

function native(label, { threads, background = false }) {
  const env = threads ? { HARDWARE_CONCURRENCY: String(threads) } : {};
  const runs = [];
  for (let i = 0; i < RUNS; i++) {
    const w = timed(NARGO, ['execute', '--package', 'recovery', 'measure'], { cwd: join(repo, 'circuits/email-recovery'), env, background });
    const out = join(work, `native-${rows.length}-${i}`);
    mkdirSync(out, { recursive: true });
    const p = timed(BB, ['prove', ...SCHEME, '--zk', '-b', ARTIFACT, '-w', join(repo, 'circuits/email-recovery/target/measure.gz'), '-o', out], { env, background });
    execFileSync(BB, ['verify', ...SCHEME, '--zk', '-k', VK, '-p', join(out, 'proof'), '-i', join(out, 'public_inputs')], { stdio: 'ignore' });
    runs.push({ witness_ms: Math.round(w.seconds * 1000), prove_ms: Math.round(p.seconds * 1000), peak_rss_mib: Math.round(p.rss / 2 ** 20) });
  }
  rows.push({ prover: 'native', label, threads: threads ?? N, background_qos: background, runs });
  console.error(`${label}: ${JSON.stringify(stats(runs.map((r) => r.prove_ms)))}`);
}

function node(label, { threads, background = false }) {
  const runs = [];
  for (let i = 0; i < RUNS; i++) {
    const r = timed(process.execPath, [join(repo, 'packages/email-recovery/scripts/measure-bbjs.mjs'), FIXTURE, String(threads)], { background });
    const j = JSON.parse(r.stdout.trim().split('\n').at(-1));
    runs.push({ witness_ms: j.encode_ms + j.execute_ms, prove_ms: j.prove_ms, peak_rss_mib: j.peak_rss_mib });
  }
  rows.push({ prover: 'node', label, threads, background_qos: background, runs });
  console.error(`${label}: ${JSON.stringify(stats(runs.map((r) => r.prove_ms)))}`);
}

native('Native bb, every core', {});
native('Native bb, one thread', { threads: 1 });
native(`Native bb, ${SLOW}, one thread`, { threads: 1, background: true });
native(`Native bb, ${SLOW}, four threads`, { threads: 4, background: true });
node('bb.js in Node, one thread', { threads: 1 });
node(`bb.js in Node, ${N} threads`, { threads: N });
node(`bb.js in Node, ${SLOW}, one thread`, { threads: 1, background: true });
node(`bb.js in Node, ${SLOW}, four threads`, { threads: 4, background: true });

// The browser's runs, as measure-browser.mjs recorded them.
const browser = JSON.parse(readFileSync(join(repo, 'research/email-recovery/eval/browser-prover.json'), 'utf8'));
for (const r of browser.results.filter((x) => x.cpu_throttling === 1)) {
  rows.push({
    prover: 'browser',
    label: `${browser.browser} (headless), ${r.label === 'desktop' ? '' : `${SLOW}, `}${r.threads === 1 ? 'one thread' : `${r.threads} threads`}`,
    threads: r.threads,
    background_qos: r.label !== 'desktop',
    runs: r.warm_runs.map((w) => ({ witness_ms: w.stage_ms.witness, prove_ms: w.stage_ms.proving, total_ms: w.wall_ms, bb_wasm_mib: w.bb_wasm_memory_mib })),
    peak_renderer_rss_mib: r.peak_renderer_rss_mib,
    recorded: browser.generated,
  });
}
machine.load_average_at_end = loadavg().map((x) => x.toFixed(2)).join(' ');

const s = (ms) => (ms / 1000).toFixed(ms < 10_000 ? 2 : 1);
const fmt = (xs) => {
  const t = stats(xs);
  return `${s(t.median)} (${s(t.min)} to ${s(t.max)})`;
};
const lines = [];
lines.push(`Generated by \`research/email-recovery/eval/proving/measure.mjs\` on ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC (browser rows: \`measure-browser.mjs\`, ${browser.generated}).`);
lines.push(`Machine: ${machine.cpu}, ${machine.logical_cpus} logical CPUs (${machine.core_tiers.map((t) => `${t.logical} ${t.name}`).join(' and ')}, as macOS names its core tiers), ${machine.memory_gib} GiB, ${machine.os}, Node ${machine.node}; load average ${machine.load_average_at_start} at the start and ${machine.load_average_at_end} at the end; browser rows on the same machine, load average ${browser.host.load_average_at_start} at their start.`);
lines.push(`Circuit build: \`${circuit.artifact}\` (sha256 \`${circuit.artifact_sha256.slice(0, 16)}…\`), verification key sha256 \`${circuit.vk_sha256.slice(0, 16)}…\` (the verifier's circuit id); ${circuit.nargo}, bb ${circuit.bb}; the Gmail fixture's recovery email. Times in seconds: median (minimum to maximum) of ${RUNS} runs (browser: ${browser.warm_runs_per_configuration} warm runs).`);
lines.push('');
lines.push('| Prover | Threads | Witness (s) | Proving (s) | Total (s) | Peak memory | Runs |');
lines.push('| --- | --- | --- | --- | --- | --- | --- |');
for (const r of rows) {
  const w = fmt(r.runs.map((x) => x.witness_ms));
  const p = fmt(r.runs.map((x) => x.prove_ms));
  const total = r.prover === 'browser' ? fmt(r.runs.map((x) => x.total_ms)) : fmt(r.runs.map((x) => x.witness_ms + x.prove_ms));
  const mem =
    r.prover === 'native'
      ? `${Math.max(...r.runs.map((x) => x.peak_rss_mib)).toLocaleString('en-US')} MiB (\`bb prove\` RSS)`
      : r.prover === 'node'
        ? `${Math.max(...r.runs.map((x) => x.peak_rss_mib)).toLocaleString('en-US')} MiB (process RSS)`
        : `${r.peak_renderer_rss_mib.toLocaleString('en-US')} MiB (renderer RSS); ${Math.max(...r.runs.map((x) => x.bb_wasm_mib))} MiB Barretenberg memory`;
  lines.push(`| ${r.label} | ${r.threads} | ${w} | ${p} | ${total} | ${mem} | ${r.runs.length} |`);
}
lines.push('| Phone-class device | — | not measured | not measured | not measured | not measured | 0 |');
lines.push('');
lines.push('Witness: native `nargo execute`; Node the encoder and noir_js; browser the encoder and noir_js in the prover worker. Total: native and Node witness plus proving; browser from the page\'s request to the locally verified proof (cached assets, Barretenberg\'s start and the verification included).');

mkdirSync(join(repo, 'research/email-recovery/eval/results'), { recursive: true });
writeFileSync(
  join(repo, 'research/email-recovery/eval/results/proving.json'),
  JSON.stringify({ generated: new Date().toISOString(), machine, circuit, runs_per_configuration: RUNS, rows, table: lines.join('\n') }, null, 1) + '\n',
);
console.log(lines.join('\n'));
