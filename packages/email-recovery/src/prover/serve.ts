/**
 * The worker side of the prover protocol (`protocol.ts`): answer each
 * `prove` request on `port` with progress events and one `done` or
 * `error`. `worker.ts` serves the worker's global scope; tests serve one end
 * of a `MessageChannel`.
 */

import { type AssetCache, defaultCache } from './assets.js';
import { type ProveDeps, proveRecoveryEmail } from './prove.js';
import {
  ProgressReporter,
  type ProveRequest,
  ProverError,
  type ProverEvent,
  isProveRequest,
  proverThreads,
} from './protocol.js';

export interface ProverPort {
  postMessage(message: ProverEvent): void;
  addEventListener(type: 'message', listener: (event: { data: unknown }) => void): void;
}

export interface ServeOptions extends Partial<Omit<ProveDeps, 'cache'>> {
  cache?: AssetCache;
  /** The environment's isolation, for the thread count; this global scope's by default. */
  env?: { crossOriginIsolated?: boolean; hardwareConcurrency?: number; sharedArrayBuffer: boolean };
  now?: () => number;
}

function environment() {
  const g = globalThis as { crossOriginIsolated?: boolean; navigator?: { hardwareConcurrency?: number } };
  return {
    crossOriginIsolated: g.crossOriginIsolated,
    hardwareConcurrency: g.navigator?.hardwareConcurrency,
    sharedArrayBuffer: typeof SharedArrayBuffer !== 'undefined',
  };
}

/** Run one request, emitting its events. */
export async function runRequest(req: ProveRequest, emit: (e: ProverEvent) => void, opts: ServeOptions = {}): Promise<void> {
  const progress = new ProgressReporter(req.id, emit, opts.now);
  try {
    const cache = opts.cache ?? (await defaultCache());
    const threads = proverThreads(opts.env ?? environment(), req.threads);
    const result = await proveRecoveryEmail(req.input, req.assets, threads, progress, { ...opts, cache });
    emit({ type: 'done', id: req.id, result });
  } catch (e) {
    const err =
      e instanceof ProverError ? e : new ProverError('prover', progress.stage, e instanceof Error ? e.message : String(e));
    emit({ type: 'error', id: req.id, code: err.code, stage: err.stage, message: err.message });
  }
}

/** Serve requests on `port`, one at a time, in arrival order. */
export function serveProver(port: ProverPort, opts: ServeOptions = {}): void {
  let queue = Promise.resolve();
  port.addEventListener('message', (event) => {
    const req = event.data;
    if (!isProveRequest(req)) {
      const id = typeof (req as { id?: unknown })?.id === 'number' ? (req as { id: number }).id : -1;
      port.postMessage({ type: 'error', id, code: 'input', stage: 'download', message: 'malformed prove request' });
      return;
    }
    queue = queue.then(() => runRequest(req, (e) => port.postMessage(e), opts));
  });
}
