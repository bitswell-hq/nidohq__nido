#!/usr/bin/env node
// Serves target/email-bench-phone/ (phone/build.mjs) on every interface, with
// the cross-origin isolation headers the build's `_headers` gives the
// recovery routes, so a phone on the same network can open the prover
// benchmark with Barretenberg threads. Cross-origin isolation needs a secure
// context, so it serves HTTPS with a throwaway self-signed certificate for
// this machine's addresses (the phone shows a certificate warning to accept
// once); `--http` serves plain HTTP, which a phone treats as insecure (one
// thread, and no Cache API, so every run downloads again).
//
//   node research/email-recovery/eval/phone/serve.mjs [--port 8443] [--http]
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { createServer as createHttp } from 'node:http';
import { createServer as createHttps } from 'node:https';
import { networkInterfaces } from 'node:os';
import { extname, join, normalize } from 'node:path';
import { parseArgs } from 'node:util';
import { headersFor, loadHeaders } from '../../../../tests/support/headers.mjs';

const { values } = parseArgs({ options: { port: { type: 'string' }, http: { type: 'boolean' } } });
const repo = new URL('../../../../', import.meta.url).pathname;
const root = join(repo, 'target/email-bench-phone/');
if (!existsSync(join(root, 'build.json'))) {
  console.error('build it first: node research/email-recovery/eval/phone/build.mjs');
  process.exit(2);
}
const ISOLATION = new Set(['Cross-Origin-Opener-Policy', 'Cross-Origin-Embedder-Policy', 'Cross-Origin-Resource-Policy']);
const rules = loadHeaders(join(root, '_headers')).map((r) => ({ ...r, headers: r.headers.filter(([k]) => ISOLATION.has(k)) }));
const TYPES = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json', '.wasm': 'application/wasm', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.vk': 'application/octet-stream', '.dat': 'application/octet-stream', '.eml': 'message/rfc822', '.webmanifest': 'application/manifest+json' };
const addresses = Object.values(networkInterfaces()).flat().filter((a) => a && a.family === 'IPv4' && !a.internal).map((a) => a.address);

function handler(req, res) {
  const path = decodeURIComponent((req.url || '/').split('?')[0]);
  let file = normalize(join(root, path));
  if (!file.startsWith(root)) return res.writeHead(404).end('Not found');
  if (!extname(file)) file = join(file, 'index.html');
  try {
    const body = readFileSync(file);
    res.writeHead(200, { ...headersFor(rules, path), 'Content-Type': TYPES[extname(file)] ?? 'application/octet-stream', 'Cache-Control': 'no-store' });
    res.end(body);
  } catch {
    res.writeHead(404).end('Not found');
  }
}

const port = Number(values.port ?? (values.http ? 8080 : 8443));
let server;
if (values.http) server = createHttp(handler);
else {
  const dir = join(repo, 'target/email-bench-phone-tls');
  mkdirSync(dir, { recursive: true });
  const san = ['DNS:localhost', 'IP:127.0.0.1', ...addresses.map((a) => `IP:${a}`)].join(',');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '7', '-subj', '/CN=nido-bench', '-addext', `subjectAltName=${san}`, '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem')], { stdio: 'ignore' });
  server = createHttps({ key: readFileSync(join(dir, 'key.pem')), cert: readFileSync(join(dir, 'cert.pem')) }, handler);
}
server.listen(port, '0.0.0.0', () => {
  const scheme = values.http ? 'http' : 'https';
  console.log('Open on the phone (same network), then "Run with 1 thread" and "Run with every core", and copy the JSON:');
  for (const a of ['localhost', ...addresses]) console.log(`  ${scheme}://${a}:${port}/security/recover/bench/?crs=/crs/`);
});
