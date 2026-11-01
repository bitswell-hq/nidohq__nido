/**
 * One recovery proof, start to finish: what the Web Worker runs
 * (`worker.ts`), and what tests and scripts run in Node.
 *
 * The prover is Barretenberg 0.87.0 through bb.js's `Barretenberg` API
 * rather than its `UltraHonkBackend` wrapper, so that the CRS comes from
 * `assets.ts` (pinned digests, the browser cache, progress) and the proof is
 * verified against the verification key the on-chain verifier embeds, not
 * one recomputed from the artifact. The flavor is UltraHonk with the keccak
 * transcript in its zero-knowledge variant (`bb prove --zk`), the one
 * Perch's verifier implements.
 */

import { Barretenberg, RawBuffer } from '@aztec/bb.js';
import { Noir } from '@noir-lang/noir_js';
import { equal, toHex } from '../bytes.js';
import { DkimHeaderError } from '../dkimHeader.js';
import { encodeRecoveryEmail, noirInputs, publicInputBytes } from '../recoveryInputs.js';
import { type AssetCache, AssetError, type Crs, fetchAsset, fetchCrs } from './assets.js';
import {
  type ProgressReporter,
  type ProofResult,
  type ProveInput,
  type ProverAssets,
  ProverError,
  type Stage,
} from './protocol.js';

/** Octets of the zero-knowledge proof the verifier takes (507 field elements). */
export const PROOF_BYTES = 16_224;
/** Octets of the public inputs: four field elements. */
export const PUBLIC_INPUTS_BYTES = 128;

/** A compiled Noir program as nargo writes it (`circuits/email-recovery/artifacts/recovery.json`). */
export interface CompiledCircuit {
  noir_version: string;
  hash: string | number;
  abi: unknown;
  bytecode: string;
}

/** The UltraHonk operations a proof needs. */
export interface UltraHonk {
  /** The circuit's padded (subgroup) size. */
  subgroupSize(acir: Uint8Array): Promise<number>;
  loadCrs(crs: Crs): Promise<void>;
  /** `public inputs || proof`. */
  prove(acir: Uint8Array, witness: Uint8Array): Promise<Uint8Array>;
  verify(proofWithInputs: Uint8Array, vk: Uint8Array): Promise<boolean>;
  threads(): Promise<number>;
  /** Linear memory in octets. */
  memory(): Promise<number>;
  destroy(): Promise<void>;
}

/** Barretenberg with `threads` threads (one when shared memory is unavailable). */
export async function barretenberg(threads: number): Promise<UltraHonk> {
  const api = await Barretenberg.new({ threads });
  return {
    subgroupSize: async (acir) => (await api.acirGetCircuitSizes(acir, false, true))[1],
    loadCrs: (crs) => api.srsInitSrs(new RawBuffer(crs.g1), crs.points, new RawBuffer(crs.g2)),
    prove: (acir, witness) => api.acirProveUltraKeccakZKHonk(acir, witness),
    verify: (proof, vk) => api.acirVerifyUltraKeccakZKHonk(proof, new RawBuffer(vk)),
    threads: () => api.getNumThreads(),
    memory: async () => Number(await (api.getWasm() as unknown as { memSize(): number | Promise<number> }).memSize()),
    destroy: () => api.destroy(),
  };
}

/** The witness noir_js solves for `inputs`, gzip-compressed as noir_js returns it. */
export async function solveWitness(circuit: CompiledCircuit, inputs: Record<string, unknown>): Promise<Uint8Array> {
  // The committed artifact has no debug info; noir_js only needs the ABI and bytecode.
  const noir = new Noir({ ...circuit, debug_symbols: '', file_map: {} } as unknown as ConstructorParameters<typeof Noir>[0]);
  return (await noir.execute(inputs as Parameters<Noir['execute']>[0])).witness;
}

export async function gunzip(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([new Uint8Array(bytes)]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

function base64(s: string): Uint8Array {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

export interface ProveDeps {
  cache: AssetCache;
  fetch?: typeof fetch;
  backend?: (threads: number) => Promise<UltraHonk>;
  solve?: typeof solveWitness;
}

function fail(code: ProverError['code'], stage: Stage, e: unknown): never {
  if (e instanceof ProverError) throw e;
  throw new ProverError(code, stage, e instanceof Error ? e.message : String(e));
}

/**
 * Prove `input` with `threads` Barretenberg threads, reporting each stage
 * through `progress`. The proof is returned only if its public inputs are
 * the ones the guardian will build and it verifies under the key whose
 * SHA-256 is `assets.circuitId`.
 */
export async function proveRecoveryEmail(
  input: ProveInput,
  assets: ProverAssets,
  threads: number,
  progress: ProgressReporter,
  deps: ProveDeps,
): Promise<ProofResult> {
  const backend = deps.backend ?? barretenberg;
  const solve = deps.solve ?? solveWitness;
  let downloaded = 0;
  let fromCache = 0;
  const count = (f: { bytes: Uint8Array; cached: boolean }) => {
    if (f.cached) fromCache += f.bytes.length;
    else downloaded += f.bytes.length;
    return f.bytes;
  };

  // download: the artifact, the key, Barretenberg, and the CRS.
  progress.enter('download');
  let circuit: CompiledCircuit;
  let vk: Uint8Array;
  let acir: Uint8Array;
  let bb: UltraHonk;
  try {
    const onBytes = (loaded: number, total: number | undefined, cached: boolean) => progress.bytes(loaded, total ?? loaded, cached);
    const artifact = count(await fetchAsset(assets.circuitUrl, { cache: deps.cache, fetch: deps.fetch, onBytes }));
    circuit = JSON.parse(new TextDecoder().decode(artifact)) as CompiledCircuit;
    vk = count(await fetchAsset(assets.vkUrl, { cache: deps.cache, fetch: deps.fetch, sha256: assets.circuitId }));
    acir = await gunzip(base64(circuit.bytecode));
  } catch (e) {
    fail('asset', 'download', e);
  }
  try {
    bb = await backend(threads);
  } catch (e) {
    fail('prover', 'download', e);
  }
  try {
    try {
      const points = (await bb.subgroupSize(acir)) + 1;
      const crs = await fetchCrs(points, {
        cache: deps.cache,
        fetch: deps.fetch,
        baseUrl: assets.crsBaseUrl,
        onBytes: (loaded, total, cached) => progress.bytes(loaded, total ?? loaded, cached),
      });
      downloaded += crs.downloaded;
      fromCache += crs.fromCache;
      await bb.loadCrs(crs);
    } catch (e) {
      fail(e instanceof AssetError ? 'asset' : 'prover', 'download', e);
    }

    // witness: the encoder's checks, then noir_js.
    progress.enter('witness');
    let expected: Uint8Array;
    let witness: Uint8Array;
    let address: string;
    let domain: string;
    try {
      const encoded = await encodeRecoveryEmail(input);
      expected = publicInputBytes(encoded.witness);
      address = encoded.address;
      domain = encoded.domain;
      witness = await gunzip(await solve(circuit, noirInputs(encoded.witness)));
    } catch (e) {
      fail(e instanceof DkimHeaderError || e instanceof RangeError ? 'input' : 'prover', 'witness', e);
    }

    // proving
    progress.enter('proving');
    let out: Uint8Array;
    try {
      out = await bb.prove(acir, witness);
    } catch (e) {
      fail('prover', 'proving', e);
    }
    const wasmMemory = await bb.memory().catch(() => 0);
    const usedThreads = await bb.threads().catch(() => threads);

    // verifying: the shape, the public inputs, and the key the verifier embeds.
    progress.enter('verifying');
    if (out.length !== PUBLIC_INPUTS_BYTES + PROOF_BYTES) {
      throw new ProverError('verify', 'verifying', `the prover wrote ${out.length} octets, not ${PUBLIC_INPUTS_BYTES + PROOF_BYTES}`);
    }
    const publicInputs = out.slice(0, PUBLIC_INPUTS_BYTES);
    const proof = out.slice(PUBLIC_INPUTS_BYTES);
    if (!equal(publicInputs, expected)) {
      throw new ProverError('verify', 'verifying', 'the proof commits to other public inputs than the guardian will build');
    }
    let ok: boolean;
    try {
      ok = await bb.verify(out, vk);
    } catch (e) {
      fail('verify', 'verifying', e);
    }
    if (!ok) throw new ProverError('verify', 'verifying', 'the proof does not verify under the circuit’s verification key');
    return {
      proof,
      publicInputs,
      address,
      domain,
      threads: usedThreads,
      timings: progress.finish(),
      downloaded,
      fromCache,
      wasmMemory,
    };
  } finally {
    await bb.destroy().catch(() => undefined);
  }
}

/** `sha256(vk)` as lowercase hex: a verification key's circuit id. */
export async function circuitIdOf(vk: Uint8Array): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(vk))));
}
