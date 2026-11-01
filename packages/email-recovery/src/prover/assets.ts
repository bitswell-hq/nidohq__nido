/**
 * What the prover downloads, and the browser cache that keeps it for the
 * next attempt.
 *
 * Three things come over the network: the circuit artifact (about 2 MB of
 * JSON around the gzipped ACIR), its 1,760-octet verification key, and the
 * prefix of Barretenberg's BN254 CRS that a 2^18 circuit needs (262,145 G1
 * points, 16,777,280 octets, plus the 128-octet G2 point). Every one is
 * stored in the Cache API under its URL once it has been checked, so a retry
 * after a failed or abandoned proof reads it locally.
 *
 * Integrity: the CRS comes from a third party, so each slice is checked
 * against the SHA-256 pinned below before it is used or stored. The
 * verification key is checked against the circuit id (`sha256(vk)`) the
 * guardian's verifier reports; the artifact is checked by the local
 * verification of every proof made with it.
 */

import { toHex } from '../bytes.js';

/** Barretenberg's CRS host, the one bb.js 0.87.0 reads. */
export const CRS_BASE_URL = 'https://crs.aztec.network';

/** Points the recovery circuit's proving key needs: its 2^18 subgroup plus one. */
export const RECOVERY_CRS_POINTS = 262_145;

/** SHA-256 of the first `RECOVERY_CRS_POINTS` G1 points of `g1.dat` (64 octets each). */
export const CRS_G1_SHA256 = '8f5cd75519c2e995fa47aa7ecd7b213b9ae13824bc4b0f15025a63acd8c139eb';
/** SHA-256 of `g2.dat` (128 octets). */
export const CRS_G2_SHA256 = '01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f';

/** The Cache API cache the prover stores into. */
export const CACHE_NAME = 'nido-email-recovery-v1';

/** A byte store keyed by URL. */
export interface AssetCache {
  match(key: string): Promise<Uint8Array | undefined>;
  put(key: string, bytes: Uint8Array): Promise<void>;
}

/** The Cache API store (`caches`, in pages and workers on secure origins). */
export function cacheStorage(storage: CacheStorage = caches, name = CACHE_NAME): AssetCache {
  const open = () => storage.open(name);
  return {
    async match(key) {
      const hit = await (await open()).match(key);
      return hit ? new Uint8Array(await hit.arrayBuffer()) : undefined;
    },
    async put(key, bytes) {
      const body = new Uint8Array(bytes);
      await (await open()).put(key, new Response(body, { headers: { 'content-length': String(body.length) } }));
    },
  };
}

/** An in-memory store: where no Cache API is available, and in tests. */
export function memoryCache(): AssetCache & { keys(): string[] } {
  const m = new Map<string, Uint8Array>();
  return {
    match: async (k) => m.get(k),
    put: async (k, b) => void m.set(k, new Uint8Array(b)),
    keys: () => [...m.keys()],
  };
}

/** The cache in this environment, or memory when the Cache API is missing or refuses (opaque origins, some private modes). */
export async function defaultCache(): Promise<AssetCache> {
  if (typeof caches === 'undefined') return memoryCache();
  try {
    await caches.open(CACHE_NAME);
    return cacheStorage();
  } catch {
    return memoryCache();
  }
}

export class AssetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AssetError';
  }
}

export interface FetchOptions {
  cache: AssetCache;
  fetch?: typeof fetch;
  /** Read only the first `length` octets (an HTTP range request). */
  length?: number;
  /** Lowercase hex SHA-256 the octets must have; checked before they are used or cached. */
  sha256?: string;
  /** Called as octets arrive (and once with every octet for a cache hit). */
  onBytes?: (loaded: number, total: number | undefined, cached: boolean) => void;
}

export interface Fetched {
  bytes: Uint8Array;
  cached: boolean;
}

async function digestHex(bytes: Uint8Array): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(bytes))));
}

/** The cache key of a URL read in full, or of its first `length` octets. */
export function cacheKey(url: string, length?: number): string {
  return length === undefined ? url : `${url}#octets=0-${length - 1}`;
}

/**
 * `url`'s octets from the cache, else from the network (streamed, with
 * progress), checked against `sha256` and then cached. A range request a
 * server answers with the whole resource is cut at `length` octets; a body
 * shorter than `length` is refused.
 */
export async function fetchAsset(url: string, opts: FetchOptions): Promise<Fetched> {
  const key = cacheKey(url, opts.length);
  const hit = await opts.cache.match(key);
  if (hit && (!opts.sha256 || (await digestHex(hit)) === opts.sha256)) {
    opts.onBytes?.(hit.length, hit.length, true);
    return { bytes: hit, cached: true };
  }

  const doFetch = opts.fetch ?? fetch;
  const headers: Record<string, string> = opts.length !== undefined ? { Range: `bytes=0-${opts.length - 1}` } : {};
  let res: Response;
  try {
    res = await doFetch(url, { headers, mode: 'cors', credentials: 'omit' });
  } catch (e) {
    throw new AssetError(`could not download ${url}: ${(e as Error).message}`);
  }
  if (!res.ok) throw new AssetError(`could not download ${url}: HTTP ${res.status}`);
  const declared = Number(res.headers.get('content-length') ?? NaN);
  const total = opts.length ?? (Number.isFinite(declared) ? declared : undefined);

  const chunks: Uint8Array[] = [];
  let loaded = 0;
  const want = opts.length ?? Infinity;
  if (res.body) {
    const reader = res.body.getReader();
    while (loaded < want) {
      const { done, value } = await reader.read();
      if (done) break;
      const take = value.subarray(0, Math.min(value.length, want - loaded));
      chunks.push(take);
      loaded += take.length;
      opts.onBytes?.(loaded, total, false);
    }
    if (loaded >= want) await reader.cancel().catch(() => undefined);
  } else {
    const all = new Uint8Array(await res.arrayBuffer()).subarray(0, want);
    chunks.push(all);
    loaded = all.length;
    opts.onBytes?.(loaded, total, false);
  }
  if (opts.length !== undefined && loaded < opts.length) {
    throw new AssetError(`${url}: got ${loaded} of ${opts.length} octets`);
  }
  const bytes = new Uint8Array(loaded);
  let at = 0;
  for (const c of chunks) {
    bytes.set(c, at);
    at += c.length;
  }
  if (opts.sha256 && (await digestHex(bytes)) !== opts.sha256) {
    throw new AssetError(`${url}: the downloaded octets do not have the expected SHA-256`);
  }
  await opts.cache.put(key, bytes).catch(() => undefined);
  return { bytes, cached: false };
}

/** The CRS for `points` points: the G1 prefix and the G2 point. */
export interface Crs {
  points: number;
  g1: Uint8Array;
  g2: Uint8Array;
}

/**
 * The CRS the recovery circuit needs, from `baseUrl` (Barretenberg's host
 * by default), checked against the pinned digests. `points` other than
 * `RECOVERY_CRS_POINTS` has no pinned G1 digest and is accepted unchecked.
 */
export async function fetchCrs(
  points: number,
  opts: Omit<FetchOptions, 'length' | 'sha256'> & { baseUrl?: string },
): Promise<Crs & { downloaded: number; fromCache: number }> {
  const base = (opts.baseUrl ?? CRS_BASE_URL).replace(/\/+$/, '');
  const g1 = await fetchAsset(`${base}/g1.dat`, {
    ...opts,
    length: points * 64,
    sha256: points === RECOVERY_CRS_POINTS ? CRS_G1_SHA256 : undefined,
  });
  const g2 = await fetchAsset(`${base}/g2.dat`, { ...opts, onBytes: undefined, sha256: CRS_G2_SHA256 });
  const net = (f: Fetched) => (f.cached ? 0 : f.bytes.length);
  const local = (f: Fetched) => (f.cached ? f.bytes.length : 0);
  return {
    points,
    g1: g1.bytes,
    g2: g2.bytes,
    downloaded: net(g1) + net(g2),
    fromCache: local(g1) + local(g2),
  };
}
