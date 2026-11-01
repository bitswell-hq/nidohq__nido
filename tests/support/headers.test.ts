import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, test, vi } from 'vitest';
// @ts-expect-error -- a plain ES module without type declarations
import { headersFor, parseHeaders } from './headers.mjs';
// @ts-expect-error -- the Cloudflare worker is plain JavaScript
import proxy, { isolatedPath } from '../../frontend/worker-proxy-nido/index.js';

// The two places the frontend's headers are set: the static origin's
// `_headers` and the *.nido.fyi worker proxy. Their header comments require
// them to stay in sync; this pins it for the security headers and for the
// recovery routes' cross-origin isolation.
const rules = parseHeaders(readFileSync(new URL('../../packages/frontend/public/_headers', import.meta.url), 'utf8'));

const PATHS = [
  '/',
  '/account/',
  '/security/',
  '/security/guardian/',
  '/security/recover',
  '/security/recover/',
  '/security/recover/bench/',
  '/security/recovery/',
  '/security/recovery',
  '/security/recoverx/',
  '/nido-storage-bridge/',
  '/_astro/worker-DWSmb-j5.js',
  '/_astro/index.abc123.js',
];
const SYNCED = [
  'X-Frame-Options',
  'X-Content-Type-Options',
  'Referrer-Policy',
  'Content-Security-Policy-Report-Only',
  'Cross-Origin-Opener-Policy',
  'Cross-Origin-Embedder-Policy',
];

async function proxied(path: string): Promise<Headers> {
  vi.stubGlobal('fetch', async () => new Response('<!doctype html>', { status: 200 }));
  const res: Response = await proxy.fetch(new Request(`https://cabc.nido.fyi${path}`));
  return res.headers;
}

afterEach(() => vi.unstubAllGlobals());

describe('frontend headers', () => {
  test('the recovery routes, and only they, are cross-origin isolated; the build’s assets (worker scripts) carry COEP', () => {
    for (const path of PATHS) {
      const h = headersFor(rules, path);
      const isolated = /^\/security\/(recover|recovery)(\/|$)/.test(path);
      const asset = path.startsWith('/_astro/');
      expect([path, h['Cross-Origin-Opener-Policy'], h['Cross-Origin-Embedder-Policy']]).toEqual([
        path,
        isolated ? 'same-origin' : undefined,
        isolated || asset ? 'require-corp' : undefined,
      ]);
      expect([path, isolatedPath(path)]).toEqual([path, isolated]);
    }
  });

  test('the static origin and the worker proxy send the same security headers', async () => {
    for (const path of PATHS) {
      const fromProxy = await proxied(path);
      const fromStatic = headersFor(rules, path);
      for (const name of SYNCED) {
        const norm = (v: string | null | undefined) => (v ?? null)?.replace(/\s+/g, ' ');
        expect([path, name, norm(fromProxy.get(name))]).toEqual([path, name, norm(fromStatic[name])]);
      }
    }
  });
});
