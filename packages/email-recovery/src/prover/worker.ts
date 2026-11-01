/**
 * The recovery prover's Web Worker entry point. Start it as a module worker
 * (`RecoveryProver` does): `new Worker(new URL('./worker.js',
 * import.meta.url), { type: 'module' })`. Barretenberg uses threads only
 * when the page that started it is cross-origin isolated.
 */

import { type ProverPort, serveProver } from './serve.js';

serveProver(globalThis as unknown as ProverPort);
