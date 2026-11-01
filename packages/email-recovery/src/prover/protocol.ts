/**
 * The messages between a page and the recovery prover's Web Worker
 * (`worker.ts`). Everything that crosses is structured-clone data: octets
 * as `Uint8Array`, integers as `bigint`.
 *
 * A page sends one `prove` request per proof. The worker answers with
 * `progress` events in stage order and then exactly one `done` or `error`
 * with the same `id`.
 *
 * | Stage | What runs |
 * | --- | --- |
 * | `download` | The circuit artifact, its verification key, and the CRS points its size needs: from the browser's cache when a previous run stored them, else from the network (bytes reported as they arrive) |
 * | `witness` | `encodeRecoveryEmail` (signature, Subject and key-path checks) and noir_js solving the circuit |
 * | `proving` | Barretenberg's UltraHonk prover, zero-knowledge flavor with the keccak transcript |
 * | `verifying` | The proof checked against the verification key whose `sha256` is the circuit id the guardian's verifier reports |
 */

import type { KeyPath } from '../recoveryInputs.js';

export const STAGES = ['download', 'witness', 'proving', 'verifying'] as const;
export type Stage = (typeof STAGES)[number];

/** Where the worker finds what it downloads. */
export interface ProverAssets {
  /** `circuits/email-recovery/artifacts/recovery.json`, as served. */
  circuitUrl: string;
  /** `contracts/email-verifier/vk/email_recovery.vk`, as served. */
  vkUrl: string;
  /** `sha256(vk)`, 64 lowercase hex: what `verifier.circuit_id()` reports. */
  circuitId: string;
  /** Base of `g1.dat` and `g2.dat`; Barretenberg's own host unless set. */
  crsBaseUrl?: string;
}

/** The recovery email and everything its witness needs (`encodeRecoveryEmail`). */
export interface ProveInput {
  eml: Uint8Array;
  accountCode: bigint;
  rho: bigint;
  statement: Uint8Array;
  modulus: bigint;
  keyPath: KeyPath;
}

export interface ProveRequest {
  type: 'prove';
  id: number;
  input: ProveInput;
  assets: ProverAssets;
  /** Barretenberg threads. The worker uses one when shared memory is unavailable. */
  threads: number;
}

export interface ProgressEvent {
  type: 'progress';
  id: number;
  stage: Stage;
  /** Milliseconds since the worker received the request. */
  elapsedMs: number;
  /** Octets downloaded so far in this stage, and how many it needs (download only). */
  loaded?: number;
  total?: number;
  /** Whether the octets came from the browser's cache (download only). */
  cached?: boolean;
}

export interface ProofResult {
  /** The 16,224-octet zero-knowledge UltraHonk proof the verifier takes. */
  proof: Uint8Array;
  /** `C || digest_hi || digest_lo || key_root`, 128 octets: the guardian's public inputs. */
  publicInputs: Uint8Array;
  /** The From address exactly as signed, and the signing domain. */
  address: string;
  domain: string;
  /** Threads Barretenberg actually ran with. */
  threads: number;
  /** Milliseconds spent in each stage. */
  timings: Record<Stage, number>;
  /** Octets fetched from the network this run, and read from the cache. */
  downloaded: number;
  fromCache: number;
  /** Barretenberg's linear memory after proving, in octets. It only grows, so this is its peak. */
  wasmMemory: number;
}

export interface DoneEvent {
  type: 'done';
  id: number;
  result: ProofResult;
}

/** Why a proof was not produced. `input` means the email or its key path is wrong; `asset` a download or integrity failure. */
export type ProverErrorCode = 'input' | 'asset' | 'prover' | 'verify';

export interface ErrorEvent {
  type: 'error';
  id: number;
  code: ProverErrorCode;
  message: string;
  stage: Stage;
}

export type ProverEvent = ProgressEvent | DoneEvent | ErrorEvent;

/** A failure the worker reports with its code and stage. */
export class ProverError extends Error {
  constructor(
    readonly code: ProverErrorCode,
    readonly stage: Stage,
    message: string,
  ) {
    super(message);
    this.name = 'ProverError';
  }
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null;

/** Whether `v` is a well-formed event for request `id`. */
export function isProverEvent(v: unknown, id: number): v is ProverEvent {
  if (!isRecord(v) || v.id !== id) return false;
  switch (v.type) {
    case 'progress':
      return STAGES.includes(v.stage as Stage) && typeof v.elapsedMs === 'number';
    case 'done':
      return isRecord(v.result) && v.result.proof instanceof Uint8Array && v.result.publicInputs instanceof Uint8Array;
    case 'error':
      return typeof v.message === 'string' && STAGES.includes(v.stage as Stage);
    default:
      return false;
  }
}

/** Whether `v` is a well-formed prove request. */
export function isProveRequest(v: unknown): v is ProveRequest {
  if (!isRecord(v) || v.type !== 'prove' || typeof v.id !== 'number') return false;
  const i = v.input;
  const a = v.assets;
  return (
    isRecord(i) &&
    i.eml instanceof Uint8Array &&
    typeof i.accountCode === 'bigint' &&
    typeof i.rho === 'bigint' &&
    i.statement instanceof Uint8Array &&
    typeof i.modulus === 'bigint' &&
    isRecord(i.keyPath) &&
    isRecord(a) &&
    typeof a.circuitUrl === 'string' &&
    typeof a.vkUrl === 'string' &&
    /^[0-9a-f]{64}$/.test(String(a.circuitId)) &&
    Number.isInteger(v.threads) &&
    (v.threads as number) >= 1
  );
}

/**
 * Tracks stage order and elapsed time for one request and emits its
 * events. `now` is injectable so the order and timing rules can be tested.
 */
export class ProgressReporter {
  private readonly start: number;
  private current: Stage | undefined;
  private stageStart = 0;
  readonly timings: Record<Stage, number> = { download: 0, witness: 0, proving: 0, verifying: 0 };

  constructor(
    private readonly id: number,
    private readonly emit: (e: ProverEvent) => void,
    private readonly now: () => number = () => performance.now(),
  ) {
    this.start = now();
  }

  get stage(): Stage {
    return this.current ?? 'download';
  }

  /** Enter `stage`. Stages only move forward. */
  enter(stage: Stage): void {
    if (this.current !== undefined) {
      if (STAGES.indexOf(stage) <= STAGES.indexOf(this.current)) {
        throw new Error(`prover: stage ${stage} after ${this.current}`);
      }
      this.timings[this.current] = this.now() - this.stageStart;
    }
    this.current = stage;
    this.stageStart = this.now();
    this.emit({ type: 'progress', id: this.id, stage, elapsedMs: this.now() - this.start });
  }

  /** Report download progress within the current stage. */
  bytes(loaded: number, total: number, cached: boolean): void {
    this.emit({ type: 'progress', id: this.id, stage: this.stage, elapsedMs: this.now() - this.start, loaded, total, cached });
  }

  /** Close the current stage and return every stage's duration. */
  finish(): Record<Stage, number> {
    if (this.current !== undefined) this.timings[this.current] = this.now() - this.stageStart;
    return { ...this.timings };
  }
}

/**
 * Barretenberg threads for this environment: one without cross-origin
 * isolation (no `SharedArrayBuffer`), else the requested count, or the
 * logical cores, capped at Barretenberg's 32.
 */
export function proverThreads(env: { crossOriginIsolated?: boolean; hardwareConcurrency?: number; sharedArrayBuffer: boolean }, requested?: number): number {
  if (!env.crossOriginIsolated || !env.sharedArrayBuffer) return 1;
  const cores = Math.max(1, env.hardwareConcurrency ?? 1);
  return Math.max(1, Math.min(requested ?? cores, cores, 32));
}
