import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { MessageChannel } from 'node:worker_threads';
import { UltraHonkBackend } from '@aztec/bb.js';
import { describe, expect, test } from 'vitest';
import {
  AssetError,
  CRS_G2_SHA256,
  PROOF_BYTES,
  ProgressReporter,
  type ProgressEvent,
  type ProveInput,
  type ProverAssets,
  ProverError,
  type ProverEvent,
  RECOVERY_CRS_POINTS,
  RecoveryProver,
  type UltraHonk,
  type WorkerLike,
  cacheKey,
  encodeRecoveryEmail,
  fetchAsset,
  fetchCrs,
  isProveRequest,
  isProverEvent,
  memoryCache,
  proverThreads,
  publicInputBytes,
  runRequest,
  serveProver,
} from '../src/index.js';

const repo = (path: string) => new URL(`../../../${path}`, import.meta.url);
const sha256 = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
const unhex = (s: string) => Uint8Array.from(Buffer.from(s.replace(/^0x/, ''), 'hex'));

const ARTIFACT = new Uint8Array(readFileSync(repo('circuits/email-recovery/artifacts/recovery.json')));
const VK = new Uint8Array(readFileSync(repo('contracts/email-verifier/vk/email_recovery.vk')));
const CIRCUIT_ID = sha256(VK);
/** `g2.dat` from Barretenberg's CRS host: one G2 point, public setup data. */
const G2 = unhex(
  '0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1' +
    '22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e5504fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4',
);

const FIXTURE = 'crates/integration-tests/fixtures/email/provider-gmail-com/';
const meta = JSON.parse(readFileSync(repo(`${FIXTURE}fixture.json`), 'utf8'));
const INPUT: ProveInput = {
  eml: new Uint8Array(readFileSync(repo(`${FIXTURE}message.eml`))),
  accountCode: BigInt(meta.account_code),
  rho: BigInt(meta.rho),
  statement: unhex(meta.statement),
  modulus: BigInt(meta.modulus),
  keyPath: { root: BigInt(meta.key_root), index: meta.key_index, siblings: meta.key_siblings.map(BigInt) },
};
const EXPECTED_PUBLIC = unhex(meta.public_inputs.map((x: string) => x.replace(/^0x/, '')).join(''));

const ASSETS: ProverAssets = {
  circuitUrl: 'https://wallet.test/assets/recovery.json',
  vkUrl: 'https://wallet.test/assets/email_recovery.vk',
  circuitId: CIRCUIT_ID,
  crsBaseUrl: 'https://crs.test',
};

/** A fetch over fixed resources that honours `Range: bytes=0-N`, and counts requests. */
function fakeFetch(files: Record<string, Uint8Array>, opts: { ignoreRange?: boolean } = {}) {
  const calls: string[] = [];
  const f = (async (url: string, init?: RequestInit) => {
    calls.push(String(url));
    const body = files[String(url)];
    if (!body) return new Response('missing', { status: 404 });
    const range = (init?.headers as Record<string, string> | undefined)?.Range;
    const m = range && !opts.ignoreRange ? /^bytes=0-(\d+)$/.exec(range) : null;
    const out = m ? body.subarray(0, Number(m[1]) + 1) : body;
    return new Response(new Uint8Array(out), { status: m ? 206 : 200, headers: { 'content-length': String(out.length) } });
  }) as typeof fetch;
  return { fetch: f, calls };
}

/** A G1 file longer than the recovery circuit needs (the real one is 6.4 GB). */
const G1 = new Uint8Array(RECOVERY_CRS_POINTS * 64 + 640).map((_, i) => i & 0xff);
const FILES = {
  [ASSETS.circuitUrl]: ARTIFACT,
  [ASSETS.vkUrl]: VK,
  'https://crs.test/g1.dat': G1,
  'https://crs.test/g2.dat': G2,
};

/** Points the stand-in circuit needs: few, and without a pinned digest. */
const FAKE_POINTS = 1000;

/** Barretenberg stand-in: the proof is the expected public inputs and zero octets; `verify` says `verdict`. */
function fakeBackend(opts: { publicInputs?: Uint8Array; verdict?: boolean; loaded?: { points: number } } = {}) {
  return async (threads: number): Promise<UltraHonk> => ({
    subgroupSize: async () => FAKE_POINTS - 1,
    loadCrs: async (crs) => {
      if (opts.loaded) opts.loaded.points = crs.points;
    },
    prove: async () => {
      const out = new Uint8Array(128 + PROOF_BYTES);
      out.set(opts.publicInputs ?? EXPECTED_PUBLIC);
      return out;
    },
    verify: async () => opts.verdict ?? true,
    threads: async () => threads,
    memory: async () => 1 << 20,
    destroy: async () => undefined,
  });
}
const gzipEmpty = async () => new Uint8Array(await new Response(new Blob([new Uint8Array(0)]).stream().pipeThrough(new CompressionStream('gzip'))).arrayBuffer());

describe('prover protocol', () => {
  test('requests and events are checked before use', () => {
    const req = { type: 'prove', id: 7, input: INPUT, assets: ASSETS, threads: 1 };
    expect(isProveRequest(req)).toBe(true);
    expect(isProveRequest({ ...req, threads: 0 })).toBe(false);
    expect(isProveRequest({ ...req, assets: { ...ASSETS, circuitId: 'nope' } })).toBe(false);
    expect(isProveRequest({ ...req, input: { ...INPUT, accountCode: 1 } })).toBe(false);
    expect(isProverEvent({ type: 'progress', id: 7, stage: 'witness', elapsedMs: 3 }, 7)).toBe(true);
    expect(isProverEvent({ type: 'progress', id: 8, stage: 'witness', elapsedMs: 3 }, 7)).toBe(false);
    expect(isProverEvent({ type: 'progress', id: 7, stage: 'thinking', elapsedMs: 3 }, 7)).toBe(false);
    expect(isProverEvent({ type: 'done', id: 7, result: { proof: 'x' } }, 7)).toBe(false);
  });

  test('threads: one without cross-origin isolation, else the cores, capped at 32', () => {
    expect(proverThreads({ crossOriginIsolated: false, hardwareConcurrency: 8, sharedArrayBuffer: true })).toBe(1);
    expect(proverThreads({ crossOriginIsolated: true, hardwareConcurrency: 8, sharedArrayBuffer: false })).toBe(1);
    expect(proverThreads({ crossOriginIsolated: true, hardwareConcurrency: 8, sharedArrayBuffer: true })).toBe(8);
    expect(proverThreads({ crossOriginIsolated: true, hardwareConcurrency: 8, sharedArrayBuffer: true }, 2)).toBe(2);
    expect(proverThreads({ crossOriginIsolated: true, hardwareConcurrency: 8, sharedArrayBuffer: true }, 64)).toBe(8);
    expect(proverThreads({ crossOriginIsolated: true, hardwareConcurrency: 96, sharedArrayBuffer: true })).toBe(32);
  });

  test('stages only move forward and each is timed', () => {
    let t = 0;
    const events: ProverEvent[] = [];
    const p = new ProgressReporter(1, (e) => events.push(e), () => t);
    p.enter('download');
    t = 100;
    p.bytes(50, 200, false);
    t = 300;
    p.enter('witness');
    t = 1300;
    p.enter('proving');
    expect(() => p.enter('witness')).toThrow(/after proving/);
    t = 4300;
    p.enter('verifying');
    t = 4310;
    expect(p.finish()).toEqual({ download: 300, witness: 1000, proving: 3000, verifying: 10 });
    expect(events.map((e) => (e.type === 'progress' ? [e.stage, e.elapsedMs, e.loaded ?? null] : e.type))).toEqual([
      ['download', 0, null],
      ['download', 100, 50],
      ['witness', 300, null],
      ['proving', 1300, null],
      ['verifying', 4300, null],
    ]);
  });
});

describe('prover assets', () => {
  test('a download is checked, cached, and read from the cache next time', async () => {
    const cache = memoryCache();
    const net = fakeFetch(FILES);
    const seen: [number, number | undefined, boolean][] = [];
    const first = await fetchAsset(ASSETS.vkUrl, { cache, fetch: net.fetch, sha256: CIRCUIT_ID, onBytes: (...a) => seen.push(a) });
    expect(first.cached).toBe(false);
    expect(first.bytes).toEqual(VK);
    expect(seen.at(-1)).toEqual([VK.length, VK.length, false]);
    const again = await fetchAsset(ASSETS.vkUrl, { cache, fetch: net.fetch, sha256: CIRCUIT_ID });
    expect(again).toEqual({ bytes: VK, cached: true });
    expect(net.calls).toEqual([ASSETS.vkUrl]);
  });

  test('octets with the wrong digest are refused and not cached', async () => {
    const cache = memoryCache();
    const net = fakeFetch({ [ASSETS.vkUrl]: VK.map((b, i) => (i === 9 ? b ^ 1 : b)) });
    await expect(fetchAsset(ASSETS.vkUrl, { cache, fetch: net.fetch, sha256: CIRCUIT_ID })).rejects.toThrow(AssetError);
    expect(cache.keys()).toEqual([]);
  });

  test('a corrupted cache entry is downloaded again', async () => {
    const cache = memoryCache();
    await cache.put(ASSETS.vkUrl, new Uint8Array(VK.length));
    const net = fakeFetch(FILES);
    const got = await fetchAsset(ASSETS.vkUrl, { cache, fetch: net.fetch, sha256: CIRCUIT_ID });
    expect(got.cached).toBe(false);
    expect(await cache.match(ASSETS.vkUrl)).toEqual(VK);
  });

  test('a range request answered with the whole file is cut at the length asked for', async () => {
    const cache = memoryCache();
    const net = fakeFetch(FILES, { ignoreRange: true });
    const got = await fetchAsset('https://crs.test/g1.dat', { cache, fetch: net.fetch, length: 640 });
    expect(got.bytes).toEqual(G1.subarray(0, 640));
    expect(cache.keys()).toEqual([cacheKey('https://crs.test/g1.dat', 640)]);
  });

  test('a body shorter than asked for is refused', async () => {
    const net = fakeFetch({ 'https://crs.test/g1.dat': G1.subarray(0, 100) });
    await expect(fetchAsset('https://crs.test/g1.dat', { cache: memoryCache(), fetch: net.fetch, length: 640 })).rejects.toThrow(/got 100 of 640/);
  });

  test('HTTP failures are asset errors', async () => {
    const net = fakeFetch({});
    await expect(fetchAsset(ASSETS.vkUrl, { cache: memoryCache(), fetch: net.fetch })).rejects.toThrow(/HTTP 404/);
  });

  test('the CRS: the G1 prefix the circuit needs and the pinned G2 point', async () => {
    expect(sha256(G2)).toBe(CRS_G2_SHA256);
    const cache = memoryCache();
    const net = fakeFetch(FILES);
    const crs = await fetchCrs(1000, { cache, fetch: net.fetch, baseUrl: 'https://crs.test' });
    expect(crs.g1).toEqual(G1.subarray(0, 64_000));
    expect(crs.g2).toEqual(G2);
    expect(crs.downloaded).toBe(64_000 + 128);
    const again = await fetchCrs(1000, { cache, fetch: net.fetch, baseUrl: 'https://crs.test' });
    expect([again.downloaded, again.fromCache]).toEqual([0, 64_128]);
    // The recovery circuit's own prefix has a pinned digest, which synthetic points do not have.
    await expect(fetchCrs(RECOVERY_CRS_POINTS, { cache, fetch: net.fetch, baseUrl: 'https://crs.test' })).rejects.toThrow(/expected SHA-256/);
  });
});

/** Run one request against the fakes and collect its events. */
async function run(opts: {
  input?: ProveInput;
  assets?: ProverAssets;
  backend?: ReturnType<typeof fakeBackend>;
  cache?: ReturnType<typeof memoryCache>;
  net?: ReturnType<typeof fakeFetch>;
}) {
  const events: ProverEvent[] = [];
  const net = opts.net ?? fakeFetch(FILES);
  const cache = opts.cache ?? memoryCache();
  await runRequest(
    { type: 'prove', id: 1, input: opts.input ?? INPUT, assets: opts.assets ?? ASSETS, threads: 4 },
    (e) => events.push(e),
    { cache, fetch: net.fetch, backend: opts.backend ?? fakeBackend(), solve: gzipEmpty, env: { crossOriginIsolated: true, hardwareConcurrency: 4, sharedArrayBuffer: true } },
  );
  return { events, net, cache, last: events.at(-1)! };
}

describe('prover orchestration (fake Barretenberg)', () => {
  test('stages in order, then the checked proof; a retry reads every asset from the cache', async () => {
    const loaded = { points: 0 };
    const cache = memoryCache();
    const first = await run({ cache, backend: fakeBackend({ loaded }) });
    const stages = first.events.filter((e): e is ProgressEvent => e.type === 'progress' && e.loaded === undefined).map((e) => e.stage);
    expect(stages).toEqual(['download', 'witness', 'proving', 'verifying']);
    expect(first.last.type).toBe('done');
    const result = (first.last as Extract<ProverEvent, { type: 'done' }>).result;
    expect(result.publicInputs).toEqual(EXPECTED_PUBLIC);
    expect(result.address).toBe('first.last@gmail.com');
    expect(result.threads).toBe(4);
    expect(result.downloaded).toBe(ARTIFACT.length + VK.length + FAKE_POINTS * 64 + 128);
    expect(loaded.points).toBe(FAKE_POINTS);
    // Download progress reports octets as they arrive.
    const bytes = first.events.filter((e): e is ProgressEvent => e.type === 'progress' && e.loaded !== undefined);
    expect(bytes.at(0)!.total).toBe(ARTIFACT.length);

    const retry = await run({ cache, net: fakeFetch(FILES) });
    const done = (retry.last as Extract<ProverEvent, { type: 'done' }>).result;
    expect(retry.net.calls).toEqual([]);
    expect(done.downloaded).toBe(0);
    expect(done.fromCache).toBe(ARTIFACT.length + VK.length + FAKE_POINTS * 64 + 128);
  });

  test('a verification key that is not the circuit id’s is an asset error at download', async () => {
    const { last } = await run({ assets: { ...ASSETS, circuitId: '00'.repeat(32) } });
    expect(last).toMatchObject({ type: 'error', code: 'asset', stage: 'download' });
  });

  test('an email for another statement is an input error at witness', async () => {
    const { last } = await run({ input: { ...INPUT, statement: new TextEncoder().encode('another statement') } });
    expect(last).toMatchObject({ type: 'error', code: 'input', stage: 'witness' });
    expect((last as { message: string }).message).toMatch(/recovery Subject/);
  });

  test('a proof for other public inputs, or one that does not verify, is refused', async () => {
    const other = EXPECTED_PUBLIC.slice();
    other[5] = other[5]! ^ 1;
    expect((await run({ backend: fakeBackend({ publicInputs: other }) })).last).toMatchObject({ type: 'error', code: 'verify', stage: 'verifying' });
    expect((await run({ backend: fakeBackend({ verdict: false }) })).last).toMatchObject({ type: 'error', code: 'verify', stage: 'verifying' });
  });

  test('the client and the worker over a MessageChannel (structured clone)', async () => {
    const cache = memoryCache();
    let terminated = 0;
    const worker = (): WorkerLike => {
      const { port1, port2 } = new MessageChannel();
      serveProver(
        { postMessage: (m) => port2.postMessage(m), addEventListener: (_t, l) => port2.on('message', (data) => l({ data })) },
        { cache, fetch: fakeFetch(FILES).fetch, backend: fakeBackend(), solve: gzipEmpty },
      );
      return {
        postMessage: (m) => port1.postMessage(m),
        addEventListener: (type, l) => {
          if (type === 'message') port1.on('message', (data) => l({ data }));
        },
        terminate: () => {
          terminated++;
          port1.close();
        },
      };
    };
    const prover = new RecoveryProver(ASSETS, worker);
    const progress: string[] = [];
    const result = await prover.prove(INPUT, { onProgress: (e) => e.loaded === undefined && progress.push(e.stage) });
    expect(progress).toEqual(['download', 'witness', 'proving', 'verifying']);
    expect(result.publicInputs).toEqual(EXPECTED_PUBLIC);
    expect(terminated).toBe(1);
    await expect(prover.prove({ ...INPUT, rho: INPUT.rho + 1n })).rejects.toMatchObject({ code: 'input', stage: 'witness' });
    expect(terminated).toBe(2);
    await expect(prover.prove({ ...INPUT, rho: 1n })).rejects.toBeInstanceOf(ProverError);
  });
});

describe('prover (real Barretenberg)', () => {
  test(
    'proves the Gmail fixture, and bb.js’s own verifier accepts the proof',
    async () => {
      const encoded = await encodeRecoveryEmail(INPUT);
      expect(publicInputBytes(encoded.witness)).toEqual(EXPECTED_PUBLIC);
      const events: ProverEvent[] = [];
      await runRequest(
        { type: 'prove', id: 1, input: INPUT, assets: { ...ASSETS, crsBaseUrl: undefined }, threads: 4 },
        (e) => events.push(e),
        {
          cache: memoryCache(),
          // The artifact and key from the stand-in origin, the CRS from Barretenberg's host.
          fetch: ((url: string, init?: RequestInit) =>
            String(url).startsWith('https://wallet.test/') ? fakeFetch(FILES).fetch(url, init) : fetch(url, init)) as typeof fetch,
          env: { crossOriginIsolated: true, hardwareConcurrency: 4, sharedArrayBuffer: true },
        },
      );
      const last = events.at(-1)!;
      if (last.type === 'error') throw new Error(`${last.code} at ${last.stage}: ${last.message}`);
      expect(last.type).toBe('done');
      const result = (last as Extract<ProverEvent, { type: 'done' }>).result;
      expect(result.proof.length).toBe(PROOF_BYTES);
      expect(result.publicInputs).toEqual(EXPECTED_PUBLIC);
      const circuit = JSON.parse(new TextDecoder().decode(ARTIFACT));
      const backend = new UltraHonkBackend(circuit.bytecode, { threads: 4 });
      const publicInputs = meta.public_inputs.map((x: string) => `0x${x.replace(/^0x/, '').padStart(64, '0')}`);
      expect(await backend.verifyProof({ proof: result.proof, publicInputs }, { keccakZK: true })).toBe(true);
      const tampered = result.proof.slice();
      tampered[200] = tampered[200]! ^ 1;
      expect(await backend.verifyProof({ proof: tampered, publicInputs }, { keccakZK: true })).toBe(false);
      await backend.destroy();
    },
    300_000,
  );
});
