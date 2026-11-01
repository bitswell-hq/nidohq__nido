import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { InboundMx, RECOVERY_ADDRESS, generateEmail } from '@nidohq/email-mocks';
import {
  bytes,
  hpkeSuite,
  inboundRegistration,
  initHashes,
  openInboundMessage,
  recoverySubject,
} from '@nidohq/email-recovery';
import { afterEach, beforeAll, describe, expect, test } from 'vitest';
import type { VaultApi } from '../src/channel.js';
import { AlertService } from '../src/service.js';
import { INBOUND_MAX_MESSAGES, INBOUND_TTL_MS, InboundBox } from '../src/vault/inbound.js';

const { toHex, toBase64Url, fromBase64Url } = bytes;
const DIGEST = new Uint8Array(32).fill(7);
const RHO = 0x1234n;
const ADDRESS = 'first.last@gmail.com';

async function vaultKeys() {
  const suite = hpkeSuite();
  const pair = await suite.kem.generateKeyPair();
  return { pair, publicKey: new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey)) };
}

/** The recovery email Gmail's mock signs, as the recovery address's MX receives it. */
function delivered(subject: string): Uint8Array {
  const email = generateEmail({ provider: 'gmail', from: ADDRESS, displayName: 'First Last', subject, body: 'Recovery.\r\n' });
  const mx = new InboundMx({ recipient: RECOVERY_ADDRESS, now: () => new Date('2026-10-15T09:30:05Z') });
  return new Uint8Array(mx.receive(email.eml, { mailFrom: ADDRESS, rcptTo: RECOVERY_ADDRESS }).bytes);
}

beforeAll(initHashes);

describe('sealed inbound path (spec §4.6)', () => {
  test('the vault seals a recovery email to the device that registered its Subject value, and only it opens it', async () => {
    const vault = await vaultKeys();
    let t = 1_000;
    const box = new InboundBox(vault.pair, () => t);
    const subject = recoverySubject(DIGEST, RHO);
    const value = subject.slice(-64);
    const { envelope, secret } = await inboundRegistration(vault.publicKey, value);
    expect(await box.register(envelope)).toEqual({ ok: true, expiresAt: 1_000 + INBOUND_TTL_MS });

    // Someone who later learns the value cannot take it over.
    const late = await inboundRegistration(vault.publicKey, value);
    expect(await box.register(late.envelope)).toEqual({ ok: false, error: 'this Subject value is already registered' });

    const raw = delivered(subject);
    const out = await box.deliver(raw);
    expect(Object.keys(out)).toEqual([secret.id]);
    const sealed = out[secret.id]!;
    expect(Buffer.from(sealed).includes(Buffer.from(ADDRESS))).toBe(false);
    expect(await openInboundMessage(secret, sealed)).toEqual(raw);
    await expect(openInboundMessage(late.secret, sealed)).rejects.toThrow();
    await expect(openInboundMessage({ ...secret, id: late.secret.id }, sealed)).rejects.toThrow();

    // Mail for a value nobody registered is not kept.
    expect(await box.deliver(delivered(recoverySubject(DIGEST, RHO + 1n)))).toEqual({});
    t += INBOUND_TTL_MS + 1;
    expect(await box.deliver(raw)).toEqual({});
  });

  test('a registration takes a bounded number of messages', async () => {
    const vault = await vaultKeys();
    const box = new InboundBox(vault.pair);
    const subject = recoverySubject(DIGEST, 99n);
    const { envelope, secret } = await inboundRegistration(vault.publicKey, subject.slice(-64));
    await box.register(envelope);
    const raw = delivered(subject);
    for (let i = 0; i < INBOUND_MAX_MESSAGES; i++) expect(Object.keys(await box.deliver(raw))).toEqual([secret.id]);
    expect(await box.deliver(raw)).toEqual({});
  });

  test('envelopes not sealed to the vault, or malformed, are refused', async () => {
    const vault = await vaultKeys();
    const other = await vaultKeys();
    const box = new InboundBox(vault.pair);
    const { envelope } = await inboundRegistration(other.publicKey, 'ab'.repeat(32));
    expect((await box.register(envelope)).ok).toBe(false);
    expect((await box.register(new Uint8Array([1, 2, 3]))).ok).toBe(false);
    await expect(inboundRegistration(vault.publicKey, 'AB'.repeat(32))).rejects.toThrow(/64 lowercase hex/);
  });
});

describe('the host’s inbound routes', () => {
  let svc: AlertService | undefined;
  afterEach(async () => svc?.close());

  test('relays registrations, stores and serves only sealed copies, with CORS for wallet origins', async () => {
    const vault = await vaultKeys();
    const box = new InboundBox(vault.pair);
    const stub = { inbound: (e: Uint8Array) => box.register(e) } as unknown as VaultApi;
    svc = new AlertService(
      {
        rpc: {} as never,
        controller: 'C'.padEnd(56, 'A'),
        statePath: join(mkdtempSync(join(tmpdir(), 'inbound-')), 'state.json'),
        startLedger: 1,
        signers: async () => [],
        log: () => undefined,
        allowOrigin: (o) => o === 'https://cabc.nido.test',
      },
      stub,
    );
    const base = await svc.listen();
    const subject = recoverySubject(DIGEST, 5n);
    const { envelope, secret } = await inboundRegistration(vault.publicKey, subject.slice(-64));

    const pre = await fetch(`${base}/v1/inbound`, { method: 'OPTIONS', headers: { origin: 'https://cabc.nido.test' } });
    expect(pre.status).toBe(204);
    expect(pre.headers.get('access-control-allow-origin')).toBe('https://cabc.nido.test');
    const posted = await fetch(`${base}/v1/inbound`, {
      method: 'POST',
      headers: { origin: 'https://cabc.nido.test', 'content-type': 'application/json' },
      body: JSON.stringify({ envelope: toBase64Url(envelope) }),
    });
    expect(posted.status).toBe(200);
    expect(posted.headers.get('access-control-allow-origin')).toBe('https://cabc.nido.test');
    const foreign = await fetch(`${base}/v1/inbound/${secret.id}`, { headers: { origin: 'https://evil.test' } });
    expect(foreign.headers.get('access-control-allow-origin')).toBeNull();

    // The MX inside the vault receives the mail; the host gets only the sealed copy.
    const raw = delivered(subject);
    svc.storeInbound(await box.deliver(raw));
    expect(JSON.stringify(svc.state)).not.toContain(ADDRESS);
    const got = (await (await fetch(`${base}/v1/inbound/${secret.id}`)).json()) as { messages: string[] };
    expect(got.messages).toHaveLength(1);
    expect(await openInboundMessage(secret, fromBase64Url(got.messages[0]!))).toEqual(raw);
    expect(((await (await fetch(`${base}/v1/inbound/${toHex(new Uint8Array(16))}`)).json()) as { messages: string[] }).messages).toEqual([]);
  });
});

describe('the relying party of an account passkey', () => {
  test('is the account’s own subdomain when the vault knows the wallet’s apex', async () => {
    const { relyingPartyFor } = await import('../src/vault/webauthn.js');
    const account = 'CDLZFC2SYJYDZT7K7VJRL2CU7LQV6AFZ2K2QJLY7QV53KIGWXJOANPYY';
    expect(relyingPartyFor({ rpId: 'nido.test', origins: ['https://nido.test'] }, account)).toEqual({ rpId: 'nido.test', origins: ['https://nido.test'] });
    expect(relyingPartyFor({ rpId: '', origins: [], accountApex: 'nido.fyi' }, account)).toEqual({
      rpId: `${account.toLowerCase()}.nido.fyi`,
      origins: [`https://${account.toLowerCase()}.nido.fyi`],
    });
    expect(relyingPartyFor({ rpId: '', origins: [], accountApex: 'localhost', accountOrigin: { scheme: 'http:', port: 4399 } }, account).origins).toEqual([
      `http://${account.toLowerCase()}.localhost:4399`,
    ]);
  });
});
