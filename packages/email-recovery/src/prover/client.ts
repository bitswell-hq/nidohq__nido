/**
 * The page's handle on the prover: start a worker, send it one request,
 * relay its progress, and resolve with the checked proof. Each proof gets a
 * fresh worker, terminated afterwards, so Barretenberg's memory (about a
 * gigabyte while proving) is returned to the browser when it is done.
 */

import {
  type ProgressEvent,
  type ProofResult,
  type ProveInput,
  type ProverAssets,
  ProverError,
  type ProverEvent,
  isProverEvent,
  proverThreads,
} from './protocol.js';

/** What a `Worker` offers that the client uses. */
export interface WorkerLike {
  postMessage(message: unknown): void;
  addEventListener(type: 'message' | 'error' | 'messageerror', listener: (event: { data?: unknown; message?: string }) => void): void;
  terminate(): void;
}

/** The package's own worker, as a module worker. */
export function moduleWorker(): WorkerLike {
  return new Worker(new URL('./worker.js', import.meta.url), { type: 'module', name: 'nido-email-prover' });
}

export interface ProveOptions {
  onProgress?: (e: ProgressEvent) => void;
  /** Threads to ask for; the logical cores when the page is cross-origin isolated, else one. */
  threads?: number;
}

/** This page's isolation, as `proverThreads` reads it. */
export function pageEnvironment() {
  const g = globalThis as { crossOriginIsolated?: boolean; navigator?: { hardwareConcurrency?: number } };
  return {
    crossOriginIsolated: g.crossOriginIsolated,
    hardwareConcurrency: g.navigator?.hardwareConcurrency,
    sharedArrayBuffer: typeof SharedArrayBuffer !== 'undefined',
  };
}

let nextId = 1;

export class RecoveryProver {
  constructor(
    private readonly assets: ProverAssets,
    private readonly createWorker: () => WorkerLike = moduleWorker,
  ) {}

  /** Threads a proof here would use. */
  threads(requested?: number): number {
    return proverThreads(pageEnvironment(), requested);
  }

  prove(input: ProveInput, opts: ProveOptions = {}): Promise<ProofResult> {
    const id = nextId++;
    const worker = this.createWorker();
    return new Promise<ProofResult>((resolve, reject) => {
      let settled = false;
      const settle = (f: () => void) => {
        if (settled) return;
        settled = true;
        worker.terminate();
        f();
      };
      worker.addEventListener('message', (event) => {
        const e = event.data as ProverEvent;
        if (!isProverEvent(e, id)) return;
        if (e.type === 'progress') opts.onProgress?.(e);
        else if (e.type === 'done') settle(() => resolve(e.result));
        else settle(() => reject(new ProverError(e.code, e.stage, e.message)));
      });
      worker.addEventListener('error', (event) =>
        settle(() => reject(new ProverError('prover', 'download', `the prover could not start: ${event.message ?? 'worker error'}`))),
      );
      worker.addEventListener('messageerror', () =>
        settle(() => reject(new ProverError('prover', 'download', 'the prover sent a message that could not be read'))),
      );
      worker.postMessage({ type: 'prove', id, input, assets: this.assets, threads: this.threads(opts.threads) });
    });
  }
}
