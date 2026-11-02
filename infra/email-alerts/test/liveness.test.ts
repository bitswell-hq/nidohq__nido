/**
 * The alert path's own liveness (spec §10.2, §10.3, §10.6): the email-vote
 * alert Perch has no event for, reconciliation from controller state after
 * the events aged out of the RPC's retention, the lag alarm, the weekly push
 * probe and the lapsed channel it finds, and the owner's `status` and `push`
 * requests. Controller reads go through a fake [`ChainReads`]; `chainReads`
 * itself is checked against the RPC mock in Stellar RPC's encodings.
 */
import { join } from 'node:path';
import { NitroHypervisorMock, PushUserAgentMock, testImage } from '@nidohq/email-mocks';
import { alertCode, contractIdFromStrkey, deriveAlertCodeKey } from '@nidohq/email-recovery';
import { Address, StrKey, nativeToScVal, xdr } from '@stellar/stellar-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { InProcessVault } from '../src/channel.js';
import { type AttemptView, type ChainReads, accountSigners, chainReads } from '../src/rpc.js';
import { AlertService, RECONCILE_EVERY_MS } from '../src/service.js';
import { PASSKEY_DEVICE_LEAD } from '../src/vault/content.js';
import { PROBE_INTERVAL_MS, Vault } from '../src/vault/vault.js';
import { IMAGE, Wallet, type World, alertsTo, networkId, startWorld, loadFixture } from './harness.js';
import { attemptAuthorized, attemptBegun } from './synthetic.js';

const contract = (n: number) => StrKey.encodeContract(Buffer.alloc(32, n));
const EMAIL_GUARDIAN = contract(0xe1);
const HELPER = contract(0xe2);
const ADDRESS = 'owner@proton.me';
const DAY = 24 * 3600_000;

/** The controller's state as the reads see it. */
class FakeController implements ChainReads {
  readonly attempts = new Map<string, AttemptView>();
  readonly authorized = new Map<string, bigint>();
  readonly next = new Map<string, bigint>();
  async attempt(account: string, id: bigint) {
    return this.attempts.get(`${account}:${id}`);
  }
  async authorizedAttempt(account: string) {
    return this.authorized.get(account);
  }
  async nextAttemptId(account: string) {
    return this.next.get(account) ?? 0n;
  }
  async isEmailGuardian(address: string) {
    return address === EMAIL_GUARDIAN;
  }
  set(account: string, id: number, view: Partial<AttemptView>) {
    this.attempts.set(`${account}:${id}`, { state: 'Collecting', guardians: [], evidenceDeadline: 10_000_000, ...view });
    if ((this.next.get(account) ?? 0n) <= BigInt(id)) this.next.set(account, BigInt(id + 1));
  }
}

let w: World;
let vault: Vault;
let service: AlertService;
let owner: Wallet;
let chain: FakeController;
let clock: number;
let alarms: string[];

function newService() {
  return new AlertService(
    {
      rpc: w.rpc,
      controller: w.fixture.controller,
      statePath: join(w.dir, 'state.json'),
      startLedger: w.rpcMock.oldestLedger,
      signers: (a) => accountSigners(w.rpc, a, w.fixture.networkPassphrase),
      reads: chain,
      log: () => {},
      retryBaseMs: 0,
      now: () => clock,
      onAlarm: (r) => alarms.push(r),
    },
    new InProcessVault(vault),
  );
}

beforeEach(async () => {
  clock = Date.now();
  alarms = [];
  chain = new FakeController();
  w = await startWorld(loadFixture().setupEvents);
  vault = await Vault.boot({ cfg: w.cfg, nsm: new NitroHypervisorMock().launch(testImage(IMAGE)), now: () => clock });
  service = newService();
  // The recorded fixture spans 290,000 ledgers: catching up to it raises (and clears) a lag alarm.
  await service.drain();
  alarms = [];
  owner = new Wallet(w, { attestation: (n) => service.attestation(n), nonce: () => service.nonce(), contact: (b) => service.contact(b) });
  const c = await owner.contact(ADDRESS);
  await owner.confirm(c.id, ADDRESS);
});
afterEach(async () => {
  await service.close();
  await w.close();
});

const { controller, account } = loadFixture();
const codeFor = async (attemptId: number) =>
  alertCode({
    key: await deriveAlertCodeKey(owner.accountCode),
    networkId: networkId(w.fixture.networkPassphrase),
    controller: contractIdFromStrkey(controller),
    account: contractIdFromStrkey(account),
    subject: { kind: 'attempt', attemptId: BigInt(attemptId) },
  });
const pushes = () => owner.device.receive().map((r) => JSON.parse(Buffer.from(r.payload).toString('utf8')));
const begin = (id: number) => w.rpcMock.add([attemptBegun(controller, account, w.rpcMock.latestLedger + 1, id)]);

describe('the email vote', () => {
  it('a vote by the email guardian on a collecting attempt alerts every channel once, with the attempt code', async () => {
    begin(70);
    chain.set(account, 70, {});
    await service.drain();
    expect(await vault.watched()).toEqual([{ account, attemptId: '70' }]);
    expect(alertsTo(w, ADDRESS)).toEqual([]);

    chain.set(account, 70, { guardians: [EMAIL_GUARDIAN] });
    const r = await service.pollOnce();
    expect(r.votes).toBe(1);
    const code = await codeFor(70);
    const mail = alertsTo(w, ADDRESS);
    expect(mail.map((m) => m.subject)).toEqual(['Nido security alert: your email approved a recovery']);
    expect(mail[0]!.text).toContain(`Verification code: ${code.slice(0, 3)} ${code.slice(3)}`);
    expect(mail[0]!.text).not.toContain(account);
    const [p] = pushes();
    expect(p).toMatchObject({ kind: 'email_vote_recorded', code });
    expect(p.body.startsWith(PASSKEY_DEVICE_LEAD)).toBe(true);
    expect(r.latencyMs[`email_vote_recorded:${account}:70`]).toBeGreaterThan(0);

    expect((await service.pollOnce()).votes).toBe(0);
    expect(await vault.watched()).toEqual([]);
    expect(alertsTo(w, ADDRESS)).toHaveLength(1);
  });

  it('another guardian vote alerts nothing; an attempt that left Collecting or passed its deadline is no longer read', async () => {
    for (const id of [71, 72, 73]) begin(id);
    chain.set(account, 71, { guardians: [HELPER] });
    chain.set(account, 72, { state: 'Authorized', guardians: [EMAIL_GUARDIAN] });
    chain.set(account, 73, { evidenceDeadline: 1 });
    await service.drain();
    expect(await vault.watched()).toEqual([{ account, attemptId: '71' }]);
    expect(alertsTo(w, ADDRESS).filter((m) => /your email approved/.test(m.subject))).toEqual([]);
  });

  it('only accounts with an email-guardian contact are watched', async () => {
    const other = contractIdFromStrkey(contract(0x0a));
    await vault.dispatch({ eventId: 'x', name: 'attempt_begun', class: 'watch', controller: contractIdFromStrkey(controller), account: other, subject: { kind: 'attempt', attemptId: 1n } });
    expect(await vault.watched()).toEqual([]);
  });
});

describe('reconciliation from controller state', () => {
  it('after the events aged out of retention, the restarted watcher alarms, resumes, and alerts the authorized attempt once', async () => {
    await service.close();
    const L = w.rpcMock.latestLedger;
    // An attempt opened and authorized while the watcher was down…
    w.rpcMock.add([attemptBegun(controller, account, L + 1, 80), attemptAuthorized(controller, account, L + 2, 80, L + 400_000)]);
    chain.set(account, 80, { state: 'Authorized', guardians: [EMAIL_GUARDIAN] });
    chain.authorized.set(account, 80n);
    // …and the chain moved past the RPC's retention, so its events are gone.
    w.rpcMock.add([attemptBegun(controller, account, L + 130_000, 81)]);
    chain.set(account, 81, {});
    expect(w.rpcMock.oldestLedger).toBeGreaterThan(L + 2);
    service = newService();
    const [first] = await service.drain();
    expect(first!.alarm).toMatch(/aged out of RPC retention/);
    expect(alarms).toHaveLength(1);
    expect(first!.reconciled).toEqual({ accounts: 1, found: 1 });
    const code = await codeFor(80);
    const approved = alertsTo(w, ADDRESS).filter((m) => /approved/.test(m.subject));
    expect(approved).toHaveLength(1);
    expect(approved[0]!.text).toContain(`${code.slice(0, 3)} ${code.slice(3)}`);
    expect(pushes().filter((p) => p.kind === 'attempt_authorized')).toHaveLength(1);
    // The collecting attempt it found is watched from then on.
    expect(await vault.watched()).toContainEqual({ account, attemptId: '81' });
  });

  it('an alert found by reconciliation and the same one from the event stream are one delivery', async () => {
    const L = w.rpcMock.latestLedger;
    w.rpcMock.add([attemptBegun(controller, account, L + 1, 90), attemptAuthorized(controller, account, L + 2, 90, L + 400_000)]);
    chain.set(account, 90, { state: 'Authorized' });
    chain.authorized.set(account, 90n);
    clock += RECONCILE_EVERY_MS;
    const reports = await service.drain();
    expect(reports.some((r) => r.reconciled?.found === 1)).toBe(true);
    expect(alertsTo(w, ADDRESS).filter((m) => /approved/.test(m.subject))).toHaveLength(1);
    expect(pushes().filter((p) => p.kind === 'attempt_authorized')).toHaveLength(1);
    clock += RECONCILE_EVERY_MS;
    await service.pollOnce();
    expect(alertsTo(w, ADDRESS).filter((m) => /approved/.test(m.subject))).toHaveLength(1);
  });
});

describe('the lag alarm', () => {
  it('a watcher more than an hour of ledgers behind alarms, in GET /v1/health too, and clears once caught up', async () => {
    const url = await service.listen(0);
    w.rpcMock.add([attemptBegun(controller, account, w.rpcMock.latestLedger + 20_000, 95)]);
    const r = await service.pollOnce();
    expect(r.lagLedgers).toBeGreaterThan(720);
    expect(r.alarm).toMatch(/ledgers behind the chain/);
    expect(alarms).toHaveLength(1);
    expect(((await (await fetch(`${url}/v1/health`)).json()) as { alarm: { reason: string } }).alarm.reason).toMatch(/behind/);
    await service.drain();
    const health = (await (await fetch(`${url}/v1/health`)).json()) as { alarm: unknown; lastPollAt: number };
    expect(health.alarm).toBeNull();
    expect(health.lastPollAt).toBe(clock);
  });
});

describe('push liveness', () => {
  it('probes a subscription weekly; a gone one is marked lapsed, the address is told, and alerts go by email only', async () => {
    expect((await service.pollOnce()).probes.probed).toBe(0);
    clock += PROBE_INTERVAL_MS;
    expect((await service.pollOnce()).probes).toEqual({ probed: 1, lapsed: 0 });
    const probe = w.push.accepted.at(-1)!;
    expect(probe).toMatchObject({ ttl: 0, urgency: 'very-low', topic: 'probe' });
    expect(pushes()).toEqual([{ v: 1, kind: 'probe' }]);
    expect((await service.pollOnce()).probes.probed).toBe(0);

    clock += PROBE_INTERVAL_MS;
    w.push.expire(owner.device.endpoint);
    expect((await service.pollOnce()).probes).toEqual({ probed: 1, lapsed: 1 });
    expect(alertsTo(w, ADDRESS).map((m) => m.subject)).toEqual(['Nido security alert: notifications stopped']);
    const status = await owner.status();
    expect(status).toMatchObject({ ok: true, status: 'channels', channels: [{ state: 'active', push: 'lapsed', lapsedAt: clock }] });
    expect(JSON.stringify(status)).not.toContain(ADDRESS);

    const rejectedBefore = w.push.rejected.length;
    w.rpcMock.add([attemptAuthorized(controller, account, w.rpcMock.latestLedger + 1, 96, w.rpcMock.latestLedger + 400_000)]);
    await service.drain();
    expect(alertsTo(w, ADDRESS).filter((m) => /approved/.test(m.subject))).toHaveLength(1);
    expect(w.push.rejected.length).toBe(rejectedBefore);
  });

  it('the probe interval is one configuration value', async () => {
    const daily = await Vault.boot({ cfg: { ...w.cfg, probeIntervalMs: DAY }, nsm: new NitroHypervisorMock().launch(testImage(IMAGE)), vaultId: vault.vaultId, state: AlertService.sealedState(service.state), now: () => clock });
    clock += DAY;
    expect((await daily.probe()).probed).toBe(1);
    expect((await vault.probe()).probed).toBe(0);
  });

  it('status reads the channels; push moves notifications at once only from a gone subscription, and tells the address', async () => {
    const before = await owner.status();
    expect(before).toMatchObject({ ok: true, status: 'channels', channels: [{ push: 'live' }] });
    const id = Buffer.from((before as { channels: { contact: string }[] }).channels[0]!.contact, 'hex');
    const phone = new PushUserAgentMock(w.push);
    expect(await owner.pushUpdate(id, phone)).toEqual({
      ok: false,
      error: 'the current notifications still reach their device; replace the contact to move them',
    });
    w.push.expire(owner.device.endpoint);
    expect(await owner.pushUpdate(id, phone)).toEqual({ ok: true, status: 'push-updated' });
    expect(alertsTo(w, ADDRESS).map((m) => m.subject)).toEqual(['Nido security alert: notifications moved']);
    expect(await owner.status()).toMatchObject({ channels: [{ push: 'live' }] });
    owner.device.receive();
    w.rpcMock.add([attemptAuthorized(controller, account, w.rpcMock.latestLedger + 1, 97, w.rpcMock.latestLedger + 400_000)]);
    await service.drain();
    expect(phone.receive().map((m) => JSON.parse(Buffer.from(m.payload).toString('utf8')).kind)).toEqual(['attempt_authorized']);
  });
});

describe('chainReads', () => {
  it('reads an attempt, the authorized attempt, the next id, and a guardian wasm hash in Stellar RPC encodings', async () => {
    const wasm = Buffer.alloc(32, 0x5e);
    const sym = (k: string) => xdr.ScVal.scvSymbol(k);
    const map = (o: [string, xdr.ScVal][]) =>
      xdr.ScVal.scvMap(o.sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, v]) => new xdr.ScMapEntry({ key: sym(k), val: v })));
    const answers: Record<string, xdr.ScVal> = {
      // Perch's Attempt (perch-recovery/src/types.rs), the fields the host reads among others.
      attempt: map([
        ['id', nativeToScVal(4n, { type: 'u64' })],
        ['state', xdr.ScVal.scvVec([sym('Collecting')])],
        ['guardians', xdr.ScVal.scvVec([new Address(EMAIL_GUARDIAN).toScVal()])],
        ['evidence_deadline', nativeToScVal(1234, { type: 'u32' })],
        ['epoch', nativeToScVal(2n, { type: 'u64' })],
      ]),
      activity_gate: map([
        ['authorized_attempt', nativeToScVal(4n, { type: 'u64' })],
        ['frozen', xdr.ScVal.scvBool(false)],
        ['until', nativeToScVal(99, { type: 'u32' })],
      ]),
      next_attempt_id: nativeToScVal(5n, { type: 'u64' }),
    };
    w.rpcMock.onSimulate = (tx) => {
      const env = xdr.TransactionEnvelope.fromXDR(tx, 'base64');
      const fn = env.v1().tx().operations()[0]!.body().invokeHostFunctionOp().hostFunction().invokeContract().functionName().toString();
      return answers[fn]!.toXDR('base64');
    };
    w.rpcMock.onLedgerEntry = (key) => {
      const k = xdr.LedgerKey.fromXDR(key, 'base64').contractData();
      if (Address.fromScAddress(k.contract()).toString() !== EMAIL_GUARDIAN) return undefined;
      return xdr.LedgerEntryData.contractData(
        new xdr.ContractDataEntry({
          ext: new xdr.ExtensionPoint(0),
          contract: k.contract(),
          key: xdr.ScVal.scvLedgerKeyContractInstance(),
          durability: xdr.ContractDataDurability.persistent(),
          val: xdr.ScVal.scvContractInstance(new xdr.ScContractInstance({ executable: xdr.ContractExecutable.contractExecutableWasm(wasm), storage: null })),
        }),
      ).toXDR('base64');
    };
    const reads = chainReads(w.rpc, controller, w.fixture.networkPassphrase, wasm.toString('hex'));
    expect(await reads.attempt(account, 4n)).toEqual({ state: 'Collecting', guardians: [EMAIL_GUARDIAN], evidenceDeadline: 1234 });
    expect(await reads.authorizedAttempt(account)).toBe(4n);
    expect(await reads.nextAttemptId(account)).toBe(5n);
    expect(await reads.isEmailGuardian(EMAIL_GUARDIAN)).toBe(true);
    expect(await reads.isEmailGuardian(HELPER)).toBe(false);
    answers.attempt = xdr.ScVal.scvVoid();
    answers.activity_gate = map([['authorized_attempt', xdr.ScVal.scvVoid()], ['frozen', xdr.ScVal.scvBool(false)], ['until', nativeToScVal(0, { type: 'u32' })]]);
    expect(await reads.attempt(account, 9n)).toBeUndefined();
    expect(await reads.authorizedAttempt(account)).toBeUndefined();
  });
});
