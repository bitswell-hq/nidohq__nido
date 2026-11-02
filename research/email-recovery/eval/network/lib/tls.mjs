// TLS in front of the local network's RPC and friendbot: the Stellar SDK's
// contract clients talk to RPC servers over https only. The certificate is a
// throwaway self-signed one for 127.0.0.1 that the runner writes and passes
// to Node with NODE_EXTRA_CA_CERTS (see `cert`).
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { createServer } from 'node:https';
import { join } from 'node:path';

/** Write `dir/{key,cert}.pem` for 127.0.0.1 unless present. */
export function cert(dir) {
  mkdirSync(dir, { recursive: true });
  if (!existsSync(join(dir, 'cert.pem'))) {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '30', '-subj', '/CN=127.0.0.1',
      '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost', '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem')], { stdio: 'ignore' });
  }
  return join(dir, 'cert.pem');
}

/** An https proxy to `base` (http) on 127.0.0.1; resolves to its https base URL. */
export function proxy(base, dir) {
  const server = createServer({ key: readFileSync(join(dir, 'key.pem')), cert: readFileSync(join(dir, 'cert.pem')) }, async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    try {
      const upstream = await fetch(`${base}${req.url}`, {
        method: req.method,
        headers: { 'content-type': req.headers['content-type'] ?? 'application/json' },
        body: req.method === 'GET' ? undefined : Buffer.concat(chunks),
      });
      res.writeHead(upstream.status, { 'content-type': upstream.headers.get('content-type') ?? 'application/json' });
      res.end(Buffer.from(await upstream.arrayBuffer()));
    } catch (e) {
      res.writeHead(502).end(String(e.message));
    }
  });
  return new Promise((ok) => server.listen(0, '127.0.0.1', () => { server.unref(); ok({ url: `https://127.0.0.1:${server.address().port}`, server }); }));
}
