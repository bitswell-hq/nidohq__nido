import { createECDH, createPrivateKey, createPublicKey, randomBytes, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { encode as xdrFromJson, initSync } from '@stellar/stellar-xdr-json';
import { encode } from 'cborg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { CustodianMock, DEPOSIT_PURPOSE, RELEASE_PURPOSE } from '../src/custodian.js';
import { NitroHypervisorMock, imageMeasurement, nitroTestRoot, testImage } from '../src/nitro.js';
import { LettermintMock, SCALEWAY_PATH, ScalewayTemMock } from '../src/sending.js';
import { type RpcEvent, type RpcTransaction, StellarRpcMock, eventId, ledgerCloseTime } from '../src/stellarRpc.js';
import { PushServiceMock, PushUserAgentMock, decryptWebPush } from '../src/webpush.js';

const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');
const unb64u = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));

/** RFC 8291 §5 and Appendix A. */
const RFC8291 = {
  uaPrivate: 'q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94',
  uaPublic: 'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4',
  auth: 'BTBZMqHH6r4Tts7J_aSIgg',
  header: 'DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8',
  ciphertext: '8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ',
  plaintext: 'When I grow up, I want to be a watermelon',
};

describe('Web Push mocks', () => {
  it('the user agent decrypts the RFC 8291 example', () => {
    const body = new Uint8Array(Buffer.concat([unb64u(RFC8291.header), unb64u(RFC8291.ciphertext)]));
    expect(body.length).toBe(86 + 58);
    const pt = decryptWebPush(body, {
      privateKey: unb64u(RFC8291.uaPrivate),
      publicKey: unb64u(RFC8291.uaPublic),
      authSecret: unb64u(RFC8291.auth),
    });
    expect(Buffer.from(pt).toString('utf8')).toBe(RFC8291.plaintext);
  });

  it('the device key signs a probe acknowledgement over the label and the probe id', () => {
    const ua = new PushUserAgentMock(new PushServiceMock());
    expect(ua.deviceKey).toHaveLength(65);
    expect(ua.deviceKey[0]).toBe(4);
    const probe = new Uint8Array(randomBytes(16));
    const sig = ua.acknowledge(probe);
    expect(sig).toHaveLength(64);
    const key = createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: b64u(ua.deviceKey.subarray(1, 33)), y: b64u(ua.deviceKey.subarray(33)) }, format: 'jwk' });
    const message = Buffer.concat([Buffer.from('nido/email-recovery/v1/probe-ack'), probe]);
    expect(verify('sha256', message, { key, dsaEncoding: 'ieee-p1363' }, sig)).toBe(true);
    expect(verify('sha256', Buffer.concat([message, Buffer.of(0)]), { key, dsaEncoding: 'ieee-p1363' }, sig)).toBe(false);
  });

  describe('the push service checks RFC 8030 and RFC 8292', () => {
    const service = new PushServiceMock();
    const ec = createECDH('prime256v1');
    ec.setPrivateKey(Buffer.alloc(32, 0x11));
    const vapidPublic = new Uint8Array(ec.getPublicKey());
    const vapidKey = createPrivateKey({
      key: { kty: 'EC', crv: 'P-256', d: b64u(Buffer.alloc(32, 0x11)), x: b64u(vapidPublic.subarray(1, 33)), y: b64u(vapidPublic.subarray(33)) },
      format: 'jwk',
    });
    const jwt = (claims: object) => {
      const h = b64u(Buffer.from(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
      const c = b64u(Buffer.from(JSON.stringify(claims)));
      const s = sign('sha256', Buffer.from(`${h}.${c}`), { key: vapidKey, dsaEncoding: 'ieee-p1363' });
      return `${h}.${c}.${b64u(s)}`;
    };
    let endpoint = '';
    const post = (headers: Record<string, string>, body: Uint8Array<ArrayBuffer> = new Uint8Array(100)) =>
      fetch(endpoint, { method: 'POST', headers, body });
    const good = () => ({
      authorization: `vapid t=${jwt({ aud: service.origin, exp: Math.floor(Date.now() / 1000) + 3600, sub: 'mailto:alerts@nido.test' })}, k=${b64u(vapidPublic)}`,
      ttl: '86400',
      'content-encoding': 'aes128gcm',
    });
    beforeAll(async () => {
      await service.listen();
      endpoint = new PushUserAgentMock(service).subscribe(vapidPublic).endpoint;
    });
    afterAll(() => service.close());

    it('accepts a well-formed push with 201 and a Location', async () => {
      const r = await post({ ...good(), urgency: 'high', topic: 'attempt-1' });
      expect(r.status).toBe(201);
      expect(r.headers.get('location')).toMatch(/^\/message\//);
    });
    it('replaces an undelivered message with the same Topic', async () => {
      await post({ ...good(), topic: 'same' });
      await post({ ...good(), topic: 'same' });
      const queued = service.deliver(endpoint);
      expect(queued.filter((m) => m.topic === 'same')).toHaveLength(1);
    });
    const cases: [string, () => Record<string, string>, number, Uint8Array<ArrayBuffer>?][] = [
      ['no Authorization', () => { const { authorization: _, ...h } = good(); return h; }, 401],
      ['an aud of another origin', () => ({ ...good(), authorization: `vapid t=${jwt({ aud: 'https://other.example', exp: Math.floor(Date.now() / 1000) + 60 })}, k=${b64u(vapidPublic)}` }), 401],
      ['an exp more than 24 hours away', () => ({ ...good(), authorization: `vapid t=${jwt({ aud: service.origin, exp: Math.floor(Date.now() / 1000) + 25 * 3600 })}, k=${b64u(vapidPublic)}` }), 401],
      ['an expired JWT', () => ({ ...good(), authorization: `vapid t=${jwt({ aud: service.origin, exp: Math.floor(Date.now() / 1000) - 1 })}, k=${b64u(vapidPublic)}` }), 401],
      ['a key other than the subscription\'s', () => {
        const other = createECDH('prime256v1');
        other.generateKeys();
        return { ...good(), authorization: good().authorization.replace(/k=.*$/, `k=${b64u(other.getPublicKey())}`) };
      }, 401],
      ['no TTL', () => { const { ttl: _, ...h } = good(); return h; }, 400],
      ['another Content-Encoding', () => ({ ...good(), 'content-encoding': 'aesgcm' }), 415],
      ['a bad Urgency', () => ({ ...good(), urgency: 'urgent' }), 400],
      ['a payload over 4096 octets', good, 413, new Uint8Array(4097)],
    ];
    for (const [what, headers, status, body] of cases) {
      it(`refuses ${what} with ${status}`, async () => {
        expect((await post(headers(), body)).status).toBe(status);
      });
    }
  });
});

describe('EU sending service mocks', () => {
  const lm = new LettermintMock();
  const scw = new ScalewayTemMock();
  beforeAll(async () => {
    await lm.listen();
    await scw.listen();
  });
  afterAll(async () => {
    await lm.close();
    await scw.close();
  });
  const send = (body: unknown, headers: Record<string, string> = {}) =>
    fetch(`${lm.url}/v1/send`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-lettermint-token': 'lm_test_only_token', ...headers },
      body: JSON.stringify(body),
    });
  const mail = { from: 'Nido <alerts@nido.test>', to: ['user@proton.me'], subject: 'Nido security alert', text: 'Body text.' };

  it('Lettermint: 202 {message_id, status: pending}; 401 without the token; 422 on a bad body', async () => {
    const r = await send(mail);
    expect(r.status).toBe(202);
    const b = await r.json();
    expect(b).toEqual({ message_id: expect.any(String), status: 'pending' });
    expect((await send(mail, { 'x-lettermint-token': 'wrong' })).status).toBe(401);
    const bad = await send({ ...mail, to: [] });
    expect(bad.status).toBe(422);
    expect(((await bad.json()) as { errors: Record<string, unknown> }).errors.to).toBeDefined();
  });

  it('Lettermint: the same Idempotency-Key and body returns the original response, sends once', async () => {
    const before = lm.sent.length;
    const a = await (await send(mail, { 'idempotency-key': 'evt-1' })).json();
    const b = await (await send(mail, { 'idempotency-key': 'evt-1' })).json();
    expect(b).toEqual(a);
    expect(lm.sent.length).toBe(before + 1);
    expect((await send({ ...mail, subject: 'other' }, { 'idempotency-key': 'evt-1' })).status).toBe(409);
    expect((await send(mail, { 'idempotency-key': 'x'.repeat(256) })).status).toBe(422);
  });

  it('Lettermint: injected failures answer with the published error shapes', async () => {
    lm.failNext({ status: 500 });
    const r = await send(mail);
    expect(r.status).toBe(500);
    expect(await r.json()).toEqual({ error: { code: 'INTERNAL_ERROR', message: expect.any(String) } });
    lm.failNext({ status: 429, retryAfter: 2 });
    const t = await send(mail);
    expect(t.status).toBe(429);
    expect(t.headers.get('retry-after')).toBe('2');
  });

  it('Scaleway: 200 {emails: [Email]}; 401 without X-Auth-Token; 400 on a bad body', async () => {
    const body = {
      from: { email: 'alerts@nido.test', name: 'Nido' },
      to: [{ email: 'user@proton.me', name: null }],
      subject: 'Nido security alert',
      text: 'Body text.',
      html: '<p>Body text.</p>',
      project_id: scw.projectId,
      additional_headers: [{ key: 'X-Entity-Ref-ID', value: 'abc' }],
    };
    const post = (b: unknown, token = 'scw-test-only-secret-key') =>
      fetch(scw.url + SCALEWAY_PATH, { method: 'POST', headers: { 'x-auth-token': token, 'content-type': 'application/json' }, body: JSON.stringify(b) });
    const r = await post(body);
    expect(r.status).toBe(200);
    const { emails } = (await r.json()) as { emails: Record<string, unknown>[] };
    expect(emails[0]).toMatchObject({ mail_rcpt: 'user@proton.me', rcpt_type: 'to', status: 'new', try_count: 0, project_id: scw.projectId });
    expect((await post(body, 'wrong')).status).toBe(401);
    expect((await post({ ...body, project_id: 'other' })).status).toBe(400);
  });
});

describe('Stellar RPC getEvents mock', () => {
  const ev = (ledger: number, tx: number, index: number, contractId = 'CA', topic = ['AAAADwAAAAF4AAAA']): RpcEvent => ({
    type: 'contract',
    ledger,
    ledgerClosedAt: ledgerCloseTime(ledger).toISOString(),
    contractId,
    id: eventId(ledger, tx, 0, index),
    operationIndex: 0,
    transactionIndex: tx - 1,
    topic,
    value: 'AAAAAQ==',
    txHash: '00'.repeat(32),
  });
  const rpc = new StellarRpcMock([ev(100, 1, 0), ev(100, 1, 1), ev(101, 1, 0, 'CB'), ev(150, 2, 0)], 100);

  it('pages by limit and resumes from the cursor without gaps or repeats', () => {
    const p1 = rpc.getEvents({ startLedger: 100, pagination: { limit: 2 } }) as { events: RpcEvent[]; cursor: string };
    expect(p1.events.map((e) => e.id)).toEqual([eventId(100, 1, 0, 0), eventId(100, 1, 0, 1)]);
    const p2 = rpc.getEvents({ pagination: { cursor: p1.cursor, limit: 2 } }) as { events: RpcEvent[]; cursor: string };
    expect(p2.events.map((e) => e.ledger)).toEqual([101, 150]);
    const p3 = rpc.getEvents({ pagination: { cursor: p2.cursor } }) as { events: RpcEvent[]; cursor: string };
    expect(p3.events).toEqual([]);
    rpc.add([ev(151, 1, 0)]);
    const p4 = rpc.getEvents({ pagination: { cursor: p3.cursor } }) as { events: RpcEvent[] };
    expect(p4.events.map((e) => e.ledger)).toEqual([151]);
  });

  it('filters by contract and topic', () => {
    const r = rpc.getEvents({ startLedger: 100, filters: [{ type: 'contract', contractIds: ['CB'] }] }) as { events: RpcEvent[] };
    expect(r.events.map((e) => e.contractId)).toEqual(['CB']);
    const two = rpc.getEvents({ startLedger: 100, filters: [{ topics: [['*', '*']] }] }) as { events: RpcEvent[] };
    expect(two.events).toHaveLength(0);
    const rest = rpc.getEvents({ startLedger: 100, filters: [{ topics: [['*', '**']] }] }) as { events: RpcEvent[] };
    expect(rest.events).toHaveLength(5);
    const exact = rpc.getEvents({ startLedger: 100, filters: [{ topics: [['AAAADwAAAAF4AAAA']] }] }) as { events: RpcEvent[] };
    expect(exact.events).toHaveLength(5);
  });

  it('refuses a cursor with startLedger, and starts outside the retention window', () => {
    expect(() => rpc.getEvents({ startLedger: 100, pagination: { cursor: eventId(100, 1, 0, 0) } })).toThrow(/omitted/);
    expect(() => rpc.getEvents({ startLedger: 10 })).toThrow(/oldest ledger/);
    expect(() => rpc.getEvents({ pagination: { cursor: eventId(10, 1, 0, 0) } })).toThrow(/oldest ledger/);
    expect(() => rpc.getEvents({ startLedger: 100, pagination: { limit: 10_001 } })).toThrow(/limit/);
  });
});

describe('Stellar RPC getTransactions mock', () => {
  initSync(readFileSync(createRequire(import.meta.url).resolve('@stellar/stellar-xdr-json/stellar_xdr_json_bg.wasm')));
  const envelope = (fn: string) => ({
    tx: {
      tx: {
        source_account: 'GDSZJUBQ4JO2YZOID7S4HLEPGVST3Z2USQEFJGZG5MDNLCN25LDCXX6P',
        fee: 100,
        seq_num: '1',
        cond: 'none',
        memo: 'none',
        operations: [
          {
            source_account: null,
            body: { invoke_host_function: { host_function: { invoke_contract: { contract_address: 'CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE', function_name: fn, args: [] } }, auth: [] } },
          },
        ],
        ext: 'v0',
      },
      signatures: [],
    },
  });
  const tx = (ledger: number, applicationOrder: number, fn = 'f'): RpcTransaction => ({
    status: 'SUCCESS',
    txHash: `${ledger}`.padStart(64, '0'),
    applicationOrder,
    feeBump: false,
    envelopeXdr: xdrFromJson('TransactionEnvelope', JSON.stringify(envelope(fn))),
    resultXdr: xdrFromJson('TransactionResult', JSON.stringify({ fee_charged: '100', result: { tx_success: [] }, ext: 'v0' })),
    resultMetaXdr: xdrFromJson('TransactionMeta', JSON.stringify({ v0: [] })),
    ledger,
  });
  const rpc = new StellarRpcMock([], 100);
  rpc.addTransactions([tx(101, 1), tx(100, 2), tx(100, 1, 'g'), tx(150, 1)]);
  type Page = { transactions: Record<string, unknown>[]; cursor: string; latestLedger: number; oldestLedgerCloseTimestamp: number };

  it('pages in ledger and application order and resumes from the cursor', () => {
    const p1 = rpc.getTransactions({ startLedger: 100, pagination: { limit: 2 } }) as Page;
    expect(p1.transactions.map((t) => [t.ledger, t.applicationOrder])).toEqual([[100, 1], [100, 2]]);
    expect(p1.latestLedger).toBe(150);
    expect(p1.oldestLedgerCloseTimestamp).toBe(Math.floor(ledgerCloseTime(51).getTime() / 1000));
    const p2 = rpc.getTransactions({ pagination: { cursor: p1.cursor } }) as Page;
    expect(p2.transactions.map((t) => t.ledger)).toEqual([101, 150]);
    const p3 = rpc.getTransactions({ pagination: { cursor: p2.cursor } }) as Page;
    expect(p3.transactions).toEqual([]);
    rpc.addTransactions([tx(151, 1)]);
    expect((rpc.getTransactions({ pagination: { cursor: p3.cursor } }) as Page).transactions.map((t) => t.ledger)).toEqual([151]);
  });

  it('scans at most 10,000 ledgers a request: a sparse range answers short pages whose cursor is behind the latest ledger', () => {
    const sparse = new StellarRpcMock([], 100_000);
    sparse.addTransactions([tx(1_000, 1), tx(25_000, 1)]);
    const ledgerOf = (p: Page) => Number(BigInt(p.cursor) >> 32n);
    const p1 = sparse.getTransactions({ startLedger: 1_000, pagination: { limit: 200 } }) as Page;
    expect(p1.transactions.map((t) => t.ledger)).toEqual([1_000]);
    expect(ledgerOf(p1)).toBe(10_999);
    const p2 = sparse.getTransactions({ pagination: { cursor: p1.cursor } }) as Page;
    expect(p2.transactions).toEqual([]);
    expect(ledgerOf(p2)).toBe(20_999);
    const p3 = sparse.getTransactions({ pagination: { cursor: p2.cursor } }) as Page;
    expect(p3.transactions.map((t) => t.ledger)).toEqual([25_000]);
    expect(ledgerOf(p3)).toBe(p3.latestLedger);
  });

  it('answers in base64 by default and in stellar-xdr JSON on request', () => {
    const b = (rpc.getTransactions({ startLedger: 100, pagination: { limit: 1 } }) as Page).transactions[0]!;
    expect(Object.keys(b)).toEqual(['status', 'txHash', 'applicationOrder', 'feeBump', 'envelopeXdr', 'resultXdr', 'resultMetaXdr', 'ledger', 'createdAt']);
    const j = (rpc.getTransactions({ startLedger: 100, xdrFormat: 'json', pagination: { limit: 1 } }) as Page).transactions[0]!;
    expect(j.envelopeJson).toEqual(envelope('g'));
    expect(j.resultMetaJson).toEqual({ v0: [] });
    expect(j.envelopeXdr).toBeUndefined();
  });

  it('refuses a cursor with startLedger, a start outside the retention window, and a limit above 200', () => {
    expect(() => rpc.getTransactions({ startLedger: 100, pagination: { cursor: '1' } })).toThrow(/omitted/);
    expect(() => rpc.getTransactions({ startLedger: 10 })).toThrow(/must be between the oldest ledger/);
    expect(() => rpc.getTransactions({ startLedger: 100, pagination: { limit: 201 } })).toThrow(/limit/);
  });
});

describe('custodian mock', () => {
  const image = testImage('vault');
  const measurement = Buffer.from(imageMeasurement(image)).toString('hex');
  const vaultId = new Uint8Array(32).fill(0x0a);
  const active = new Set<string>();
  const hv = new NitroHypervisorMock();
  const nsm = hv.launch(image);

  async function custodian() {
    return CustodianMock.create({ name: 'c1', roots: [nitroTestRoot()], registry: { isActive: (m) => active.has(m) } });
  }
  async function sealShare(c: CustodianMock, share: Uint8Array) {
    const { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } = await import('@hpke/core');
    const s = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
    const pk = await s.kem.deserializePublicKey(c.publicKey);
    const r = await s.seal({ recipientPublicKey: pk, info: new TextEncoder().encode('nido/email-recovery/v1/share-deposit') }, share, vaultId);
    return { enc: new Uint8Array(r.enc), ct: new Uint8Array(r.ct) };
  }
  const userData = (purpose: string, vault = vaultId) => encode(new Map<string, unknown>([['purpose', purpose], ['vault', vault]]));

  it('refuses a measurement that is not active, then serves it once active', async () => {
    const c = await custodian();
    const share = new Uint8Array(randomBytes(33));
    const deposit = async () =>
      c.deposit({ vault: vaultId, attestation: nsm.attest({ nonce: c.challenge(), userData: userData(DEPOSIT_PURPOSE) }), share: await sealShare(c, share) });
    await expect(deposit()).rejects.toThrow(/not active/);
    expect(c.decisions.at(-1)).toMatchObject({ op: 'deposit', outcome: 'refused', measurement });
    active.add(measurement);
    await deposit();
    expect(c.holds(vaultId)).toBe(true);
    await expect(deposit()).rejects.toThrow(/already held/);

    const spki = new Uint8Array(91);
    const release = (nonce: Uint8Array, ud = userData(RELEASE_PURPOSE)) =>
      c.release({ vault: vaultId, attestation: nsm.attest({ nonce, userData: ud, publicKey: spki }) });
    await expect(release(new Uint8Array(32))).rejects.toThrow(/challenge/);
    await expect(release(c.challenge(), userData(RELEASE_PURPOSE, new Uint8Array(32)))).rejects.toThrow(/vault/);
    await expect(release(c.challenge(), userData(DEPOSIT_PURPOSE))).rejects.toThrow(/purpose/);
    active.delete(measurement);
    await expect(release(c.challenge())).rejects.toThrow(/not active/);
  });

  it('never accepts a challenge twice', async () => {
    const c = await custodian();
    active.add(measurement);
    const n = c.challenge();
    const att = nsm.attest({ nonce: n, userData: userData(DEPOSIT_PURPOSE) });
    await c.deposit({ vault: vaultId, attestation: att, share: await sealShare(c, new Uint8Array(33)) });
    const other = new Uint8Array(32).fill(0x0b);
    await expect(
      c.deposit({ vault: other, attestation: att, share: await sealShare(c, new Uint8Array(33)) }),
    ).rejects.toThrow(/challenge/);
  });
});
