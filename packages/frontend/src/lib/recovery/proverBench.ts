/**
 * `/security/recover/bench/`: the email recovery prover timed in this
 * browser, on the recovery route's headers, with no wallet state. It proves
 * a TEST-ONLY synthetic recovery email (the Gmail fixture of
 * `crates/integration-tests/fixtures/email/provider-gmail-com`, signed by
 * the provider mock's test key) with exactly the prover the recover page
 * uses, and prints the timings as JSON to copy.
 *
 * Parameters: `?threads=1|max&runs=N&cold=1&auto=1`. `cold` empties the
 * prover's cache first, so the first run downloads everything; `auto` starts
 * at load. `research/email-recovery/eval/measure-browser.mjs` drives it.
 */

import { CACHE_NAME, type ProofResult } from '@nidohq/email-recovery';
import emlUrl from '../../../../../crates/integration-tests/fixtures/email/provider-gmail-com/message.eml?url';
import fixture from '../../../../../crates/integration-tests/fixtures/email/provider-gmail-com/fixture.json';
import { emailProver } from './emailProver.js';

export interface BenchRun {
  run: number;
  threads: number;
  wall_ms: number;
  stage_ms: Record<string, number>;
  downloaded_bytes: number;
  cached_bytes: number;
  bb_wasm_memory_mib: number;
  proof_bytes: number;
}

export interface BenchReport {
  userAgent: string;
  crossOriginIsolated: boolean;
  hardwareConcurrency: number;
  deviceMemoryGiB: number | null;
  requestedThreads: number;
  /** A fixed loop on the page's main thread: shows whether the page itself is slowed (DevTools CPU throttling). */
  mainThreadProbeMs: number;
  results: BenchRun[];
}

const unhex = (s: string) => Uint8Array.from(s.replace(/^0x/, '').match(/../g)!.map((x) => parseInt(x, 16)));

export function mainThreadProbe(): number {
  const t = performance.now();
  let x = 0;
  for (let i = 0; i < 50_000_000; i++) x = (x + i * 2654435761) >>> 0;
  if (x === 42) console.log(x);
  return Math.round(performance.now() - t);
}

export function benchRun(run: number, r: ProofResult, wallMs: number): BenchRun {
  return {
    run,
    threads: r.threads,
    wall_ms: Math.round(wallMs),
    stage_ms: Object.fromEntries(Object.entries(r.timings).map(([k, v]) => [k, Math.round(v)])),
    downloaded_bytes: r.downloaded,
    cached_bytes: r.fromCache,
    bb_wasm_memory_mib: Math.round(r.wasmMemory / 2 ** 20),
    proof_bytes: r.proof.length,
  };
}

export async function runBench(
  opts: { threads: number; runs: number; cold: boolean },
  onStatus: (line: string) => void,
): Promise<BenchReport> {
  if (opts.cold && typeof caches !== 'undefined') await caches.delete(CACHE_NAME);
  const mainThreadProbeMs = mainThreadProbe();
  const eml = new Uint8Array(await (await fetch(emlUrl)).arrayBuffer());
  const input = {
    eml,
    accountCode: BigInt(fixture.account_code),
    rho: BigInt(fixture.rho),
    statement: unhex(fixture.statement),
    modulus: BigInt(fixture.modulus),
    keyPath: { root: BigInt(fixture.key_root), index: fixture.key_index, siblings: fixture.key_siblings.map(BigInt) },
  };
  const expected = fixture.public_inputs.map((x: string) => x.replace(/^0x/, '')).join('');
  const prover = emailProver();
  const results: BenchRun[] = [];
  for (let i = 1; i <= opts.runs; i++) {
    const t0 = performance.now();
    const r = await prover.prove(input, {
      threads: opts.threads,
      onProgress: (e) =>
        onStatus(
          `Run ${i} of ${opts.runs}: ${e.stage}, ${(e.elapsedMs / 1000).toFixed(1)} s` +
            (e.loaded !== undefined ? ` (${(e.loaded / 1e6).toFixed(1)} of ${((e.total ?? e.loaded) / 1e6).toFixed(1)} MB${e.cached ? ', cached' : ''})` : ''),
        ),
    });
    const got = Array.from(r.publicInputs, (b) => b.toString(16).padStart(2, '0')).join('');
    if (got !== expected) throw new Error('The proof commits to other public inputs than the fixture’s.');
    results.push(benchRun(i, r, performance.now() - t0));
  }
  return {
    userAgent: navigator.userAgent,
    crossOriginIsolated: globalThis.crossOriginIsolated === true,
    hardwareConcurrency: navigator.hardwareConcurrency,
    deviceMemoryGiB: (navigator as { deviceMemory?: number }).deviceMemory ?? null,
    requestedThreads: opts.threads,
    mainThreadProbeMs,
    results,
  };
}

/** Wire the page: buttons, URL parameters, the JSON output and its copy button. */
export function mountBench(root: HTMLElement): void {
  const params = new URLSearchParams(location.search);
  const status = root.querySelector<HTMLElement>('[data-status]')!;
  const out = root.querySelector<HTMLPreElement>('#out')!;
  const copy = root.querySelector<HTMLButtonElement>('[data-copy]')!;
  const runsInput = root.querySelector<HTMLInputElement>('[name="runs"]')!;
  const cores = navigator.hardwareConcurrency || 1;
  root.querySelector<HTMLElement>('[data-env]')!.textContent =
    `${globalThis.crossOriginIsolated ? 'Cross-origin isolated' : 'Not cross-origin isolated (one thread only)'} · ${cores} logical cores`;
  const buttons = [...root.querySelectorAll<HTMLButtonElement>('[data-threads]')];
  const start = async (threads: number, runs: number, cold: boolean) => {
    buttons.forEach((b) => (b.disabled = true));
    copy.hidden = true;
    out.textContent = 'RUNNING';
    try {
      const report = await runBench({ threads, runs, cold }, (line) => (status.textContent = line));
      out.textContent = `DONE ${JSON.stringify(report)}`;
      status.textContent = 'Done. Copy the JSON below.';
      copy.hidden = false;
    } catch (e) {
      out.textContent = `ERROR ${(e as Error).message}`;
      status.textContent = 'The benchmark failed.';
    } finally {
      buttons.forEach((b) => (b.disabled = false));
    }
  };
  for (const b of buttons) {
    b.addEventListener('click', () => {
      const t = b.dataset.threads === 'max' ? cores : Number(b.dataset.threads);
      void start(t, Math.max(1, Number(runsInput.value) || 1), root.querySelector<HTMLInputElement>('[name="cold"]')!.checked);
    });
  }
  copy.addEventListener('click', () => void navigator.clipboard.writeText(out.textContent!.replace(/^DONE /, '')));
  if (params.get('auto') === '1') {
    const t = params.get('threads');
    void start(t === 'max' || t === null ? cores : Number(t), Number(params.get('runs') ?? 3), params.get('cold') === '1');
  }
}
