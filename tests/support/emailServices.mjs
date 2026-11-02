#!/usr/bin/env node
// The services the email recovery end-to-end test runs beside the wallet,
// every third party a TEST-ONLY mock of its published format
// (packages/email-mocks):
//
// - the alert service (infra/email-alerts): its host, watching the local
//   network's recovery controller, and its vault in its own process with the
//   Nitro NSM mock, three custodian mocks that read image activation from the
//   chain, Lettermint and Scaleway mocks, and a Web Push service mock;
// - the user's mail provider and the recovery address's MX: `POST
//   /test/mail` has the Gmail mock sign an email from the user's inbox, the
//   MX mock receive it for the recovery address, and the vault seal it to the
//   browser that registered its Subject value (spec §4.6);
// - a DNS-over-HTTPS resolver over the provider mocks' DNS;
// - TLS in front of the local network's RPC and friendbot, since the
//   wallet's Stellar SDK talks to RPC servers over https only.
//
// It prints one JSON line of its URLs, then runs until killed. Test hooks
// (`/test/...`) read what the mocks received.
import { createServer as createHttps } from 'node:https';
import { createServer } from 'node:http';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import {
  CustodianMock,
  InboundMx,
  LettermintMock,
  PushServiceMock,
  PushUserAgentMock,
  RECOVERY_ADDRESS,
  ScalewayTemMock,
  dohHandler,
  generateEmail,
  launchDns,
  nitroTestRoot,
} from '@nidohq/email-mocks';
import { AlertService, ProcessVault, StellarRpc, accountSigners, chainReads } from '@nidohq/email-alerts';
import { xdr } from '@stellar/stellar-sdk';

const stack = JSON.parse(readFileSync(new URL('../../target/email-e2e/stack.json', import.meta.url), 'utf8'));
const WALLET_PORT = Number(process.env.E2E_PORT || 4399);
const PASSPHRASE = stack.deployment.network;
const rpcUrl = `${stack.base}/rpc`;
const rpc = new StellarRpc(rpcUrl);
const dir = mkdtempSync(join(tmpdir(), 'nido-email-e2e-'));

// TLS for the RPC proxy: a throwaway self-signed certificate for localhost.
execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '2', '-subj', '/CN=localhost',
  '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem')], { stdio: 'ignore' });

const listen = (srv, port = 0) => new Promise((r) => srv.listen(port, '127.0.0.1', () => r(srv.address().port)));
const cors = { 'access-control-allow-origin': '*', 'access-control-allow-headers': '*', 'access-control-allow-methods': 'GET, POST, OPTIONS' };

const rpcProxy = createHttps({ key: readFileSync(join(dir, 'key.pem')), cert: readFileSync(join(dir, 'cert.pem')) }, async (req, res) => {
  if (req.method === 'OPTIONS') return res.writeHead(204, cors).end();
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const upstream = await fetch(`${stack.base}${req.url}`, {
    method: req.method,
    headers: { 'content-type': req.headers['content-type'] ?? 'application/json' },
    body: req.method === 'GET' ? undefined : Buffer.concat(chunks),
  });
  res.writeHead(upstream.status, { ...cors, 'content-type': upstream.headers.get('content-type') ?? 'application/json' });
  res.end(Buffer.from(await upstream.arrayBuffer()));
});
const rpcPort = await listen(rpcProxy, Number(process.env.E2E_RPC_PORT || 0));

// The image-activation view custodians and wallet share: the chain's answer.
const isActive = async (m) =>
  (await rpc.view(stack.email.enclaveImageRegistry, 'is_active', [xdr.ScVal.scvBytes(Buffer.from(m, 'hex'))], PASSPHRASE)) === true;
const custodians = await Promise.all([0, 1, 2].map((i) => CustodianMock.create({ name: `custodian-${i}`, roots: [nitroTestRoot()], registry: { isActive } })));
const custodianUrls = await Promise.all(custodians.map((c) => c.listen()));
const lettermint = new LettermintMock();
const scaleway = new ScalewayTemMock();
const push = new PushServiceMock();
await Promise.all([lettermint.listen(), scaleway.listen(), push.listen()]);
const device = new PushUserAgentMock(push);
let subscription;
const pushes = [];

const { vault, boot } = await ProcessVault.start({
  nsm: { kind: 'mock', image: 'nido-alert-vault-v1' },
  cfg: {
    networkId: new Uint8Array(createHash('sha256').update(PASSPHRASE).digest()),
    rp: { rpId: '', origins: [], accountApex: 'localhost', accountOrigin: { scheme: 'http:', port: WALLET_PORT } },
    walletOrigin: `http://localhost:${WALLET_PORT}`,
    sending: {
      from: { email: 'alerts@alerts.nido.test', name: 'Nido' },
      lettermint: { url: lettermint.url, token: 'lm_test_only_token' },
      scaleway: { url: scaleway.url, token: 'scw-test-only-secret-key', projectId: scaleway.projectId },
    },
    pushSubject: 'mailto:alerts@nido.test',
    allowLoopbackPush: true,
    custodians: custodians.map((c, i) => ({ url: custodianUrls[i], publicKey: c.publicKey })),
  },
});
const latest = (await rpc.call('getLatestLedger', {})).sequence;
const svc = new AlertService(
  {
    rpc,
    controller: stack.deployment.recoveryController,
    statePath: join(dir, 'host.json'),
    startLedger: latest,
    signers: (account) => accountSigners(rpc, account, PASSPHRASE),
    reads: chainReads(rpc, stack.deployment.recoveryController, PASSPHRASE, stack.email.guardianWasmHash),
    allowOrigin: (o) => /^http:\/\/([a-z0-9]+\.)?localhost:\d+$/.test(o),
    log: (l) => console.error(`[alerts] ${l}`),
    pageLimit: 100,
  },
  vault,
);
const alertUrl = await svc.listen(Number(process.env.E2E_ALERT_PORT || 0));
let polling = true;
(async () => {
  while (polling) {
    await svc.pollOnce().catch((e) => console.error(`[alerts] poll: ${e.message}`));
    await new Promise((r) => setTimeout(r, 1_500));
  }
})();

const dns = launchDns();
const doh = dohHandler(dns);
const mx = new InboundMx({ recipient: RECOVERY_ADDRESS });
const json = (res, status, body) => res.writeHead(status, { ...cors, 'content-type': 'application/json' }).end(JSON.stringify(body));
const control = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://control');
  if (req.method === 'OPTIONS') return res.writeHead(204, cors).end();
  if (url.pathname === '/dns-query') return doh(req, res);
  try {
    if (req.method === 'POST' && url.pathname === '/test/mail') {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const m = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      // The user's provider signs the email; the recovery address's MX receives it; the vault seals it.
      const email = generateEmail({ provider: m.provider ?? 'gmail', from: m.from, displayName: m.displayName, subject: m.subject, body: m.body ?? 'Sent from my phone.\r\n', date: new Date() });
      const delivered = mx.receive(email.eml, { mailFrom: m.from, rcptTo: RECOVERY_ADDRESS });
      const sealed = await vault.mail(delivered.bytes);
      svc.storeInbound(sealed);
      return json(res, 200, { delivered: Object.keys(sealed).length, eml: Buffer.from(email.eml).toString('base64') });
    }
    if (url.pathname === '/test/emails') {
      const to = url.searchParams.get('to') ?? '';
      return json(res, 200, [...lettermint.sent, ...scaleway.sent].filter((e) => e.to.includes(to)).map((e) => ({ subject: e.subject, text: e.text })));
    }
    if (url.pathname === '/test/push-subscription') return json(res, 200, (subscription ??= device.subscribe(boot.vapidPublic)));
    if (url.pathname === '/test/pushes') {
      pushes.push(...device.receive().map((r) => JSON.parse(Buffer.from(r.payload).toString('utf8'))));
      return json(res, 200, pushes);
    }
    return json(res, 404, { error: 'not found' });
  } catch (e) {
    return json(res, 500, { error: e.message });
  }
});
const controlPort = await listen(control, Number(process.env.E2E_CONTROL_PORT || 0));

console.log(
  JSON.stringify({
    rpc: `https://localhost:${rpcPort}/rpc`,
    friendbot: `https://localhost:${rpcPort}/friendbot`,
    alertService: alertUrl,
    control: `http://127.0.0.1:${controlPort}`,
    doh: `http://127.0.0.1:${controlPort}/dns-query`,
    attestationRoot: Buffer.from(nitroTestRoot()).toString('base64'),
    recoveryInbox: RECOVERY_ADDRESS,
  }),
);

const stop = async () => {
  polling = false;
  await Promise.allSettled([svc.close(), vault.close(), lettermint.close(), scaleway.close(), push.close(), ...custodians.map((c) => c.close())]);
  process.exit(0);
};
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
