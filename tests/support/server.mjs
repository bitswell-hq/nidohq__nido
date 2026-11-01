import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { join, extname } from 'node:path';
import { headersFor, loadHeaders } from './headers.mjs';

const DIST_DIR = new URL('../../packages/frontend/dist/', import.meta.url).pathname;
const PORT = Number(process.env.E2E_PORT || 4399);

const TYPES = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.map': 'application/json',
  '.svg': 'image/svg+xml',
  '.json': 'application/json',
  '.woff2': 'font/woff2',
  '.wasm': 'application/wasm',
  '.webmanifest': 'application/manifest+json',
};

// The cross-origin isolation headers the built site's `_headers` gives each
// path, as Cloudflare Pages serves them, so the recovery routes are isolated
// here too. The other security headers are left out, as this server always
// has (the UI tiers' account switcher reads the apex's storage bridge in a
// frame).
const ISOLATION = new Set(['Cross-Origin-Opener-Policy', 'Cross-Origin-Embedder-Policy']);
const RULES = loadHeaders(join(DIST_DIR, '_headers')).map((r) => ({ ...r, headers: r.headers.filter(([k]) => ISOLATION.has(k)) }));

createServer((req, res) => {
  const urlPath = (req.url || '/').split('?')[0];
  let filePath = join(DIST_DIR, urlPath === '/' ? '/index.html' : urlPath);
  if (!extname(filePath)) filePath = join(filePath, 'index.html');
  // Reject path traversal: this server binds 0.0.0.0 (reachable over Tailscale),
  // so a `..` URL must not escape DIST_DIR and serve arbitrary repo files.
  if (!filePath.startsWith(DIST_DIR)) {
    res.writeHead(404);
    res.end('Not found');
    return;
  }
  try {
    const content = readFileSync(filePath);
    res.writeHead(200, {
      ...headersFor(RULES, urlPath),
      'Content-Type': TYPES[extname(filePath)] || 'application/octet-stream',
    });
    res.end(content);
  } catch {
    res.writeHead(404);
    res.end('Not found');
  }
}).listen(PORT, '0.0.0.0', () => console.log(`e2e static server on ${PORT}`));
