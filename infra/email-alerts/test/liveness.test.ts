/**
 * The alert path's own liveness (spec §10, §10.2, §10.3, §10.6): the
 * email-guardian votes Perch has no event for, found per vote in the
 * network's transactions however many attempts are open (on an attempt, on
 * a cancellation, on a change); the many-attempts alert; reconciliation
 * from controller state, which pages through every open attempt, after the
 * events aged out of the RPC's retention; the lag alarm; the monthly push
 * probe, its signed acknowledgement, and the unacknowledged or lapsed
 * device it finds; and the owner's `status` and `push` requests, which add
 * a device at once. Controller reads go through a fake [`ChainReads`];
 * `chainReads` itself is checked against the RPC mock in Stellar RPC's
 * encodings, and transactions are served by the RPC mock's
 * `getTransactions` in stellar-xdr JSON.
 */
import { join } from 'node:path';
import { NitroHypervisorMock, PushUserAgentMock, testImage } from '@nidohq/email-mocks';
import { MANY_OPEN_ATTEMPTS, alertCode, bytes, contractIdFromStrkey, deriveAlertCodeKey } from '@nidohq/email-recovery';
import { Address, StrKey, nativeToScVal, xdr } from '@stellar/stellar-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { InProcessVault } from '../src/channel.js';
import { type AttemptView, type ChainReads, accountSigners, chainReads } from '../src/rpc.js';
import { AlertService, RECONCILE_EVERY_MS } from '../src/service.js';
import { PASSKEY_DEVICE_LEAD, PREEMPT } from '../src/vault/content.js';
import { ACK_MISSED_PROBES, PROBE_INTERVAL_MS, Vault, deviceId } from '../src/vault/vault.js';
import { IMAGE, Wallet, type World, alertsTo, networkId, startWorld, loadFixture } from './harness.js';
import { type SyntheticAttempt, attemptAuthorized, attemptBegun, voteTransaction } from './synthetic.js';

const contract = (n: number) => StrKey.encodeContract(Buffer.alloc(32, n));
const EMAIL_GUARDIAN = contract(0xe1);
const HELPER = contract(0xe2);
const RELAY = contract(0xe3);
const ADDRESS = 'owner@proton.me';
const DAY = 24 * 3600_000;

/** The controller's state as the reads see it. */
class FakeController implements ChainReads {
  readonly attempts = new Map<string, AttemptView>();
  readonly authorized = new Map<string, bigint>();
  readonly next = new Map<string, bigint>();
  reads = 0;
  async attempt(account: string, id: bigint) {
    this.reads++;
    return this.attempts.get(`${account}:${id}`);
  }
  async authorizedAttempt(account: string) {
    return this.authorized.get(account);
  }
  async nextAttemptId(account: string) {
    return this.next.get(account) ?? 0n;
  }
  async epoch() {
    return 1n;
  }
  async isEmailGuardian(address: string) {
    return address === EMAIL_GUARDIAN;
  }
  async guardianAccount(address: string) {
    if (address !== EMAIL_GUARDIAN) throw new Error('not an email guardian');
    return { account, controller };
  }
  set(account: string, id: number, view: Partial<AttemptView>) {
    this.attempts.set(`${account}:${id}`, { state: 'Collecting', guardians: [], cancelGuardians: [], evidenceDeadline: 10_000_000, epoch: 1n, ...view });
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
const decode = (d: PushUserAgentMock) => d.receive().map((r) => JSON.parse(Buffer.from(r.payload).toString('utf8')));
const pushes = () => decode(owner.device);
const next = () => w.rpcMock.latestLedger + 1;
/** `attempt_begun` for `id`, with the attempt in the controller's state. */
const begin = (id: number, view: Partial<AttemptView> = {}) => {
  chain.set(account, id, view);
  w.rpcMock.add([attemptBegun(controller, account, next(), id)]);
};
/** The email guardian's vote on `id` (or another `guardian`'s), the attempt after it in the meta. */
const vote = (id: number, after: Partial<SyntheticAttempt>, o: Partial<Parameters<typeof voteTransaction>[0]> = {}) =>
  w.rpcMock.addTransactions([voteTransaction({ controller, account, guardian: EMAIL_GUARDIAN, ledger: next(), before: { id }, after: { id, ...after }, ...o })]);
const subjects = () => alertsTo(w, ADDRESS).map((m) => m.subject);

describe('email votes, found per vote', () => {
  it('a vote by the email guardian on a collecting attempt alerts every channel once, with the attempt code', async () => {
    begin(70);
    await service.drain();
    expect(alertsTo(w, ADDRESS)).toEqual([]);

    vote(70, { guardians: [EMAIL_GUARDIAN] });
    const [r] = await service.drain();
    expect(r!.votes).toBe(1);
    const code = await codeFor(70);
    const mail = alertsTo(w, ADDRESS);
    expect(mail.map((m) => m.subject)).toEqual(['Nido security alert: your email approved a recovery']);
    expect(mail[0]!.text).toContain(`Verification code: ${code.slice(0, 3)} ${code.slice(3)}`);
    expect(mail[0]!.text).toContain(PREEMPT);
    expect(mail[0]!.text).not.toContain(account);
    const [p] = pushes();
    expect(p).toMatchObject({ kind: 'email_vote_recorded', code });
    expect(p.body.startsWith(PASSKEY_DEVICE_LEAD)).toBe(true);
    expect(r!.latencyMs[`email_vote_recorded:${account}:70`]).toBeGreaterThan(0);

    // The same vote read again (a restarted scan) is the same delivery.
    w.rpcMock.addTransactions([voteTransaction({ controller, account, guardian: EMAIL_GUARDIAN, ledger: next(), after: { id: 70, guardians: [EMAIL_GUARDIAN] } })]);
    await service.drain();
    expect(alertsTo(w, ADDRESS)).toHaveLength(1);
  });

  it('griefing-then-vote: forty attempts opened after the target do not hide the vote on it', async () => {
    begin(100);
    for (let id = 101; id <= 140; id++) begin(id);
    await service.drain();
    const many = alertsTo(w, ADDRESS).filter((m) => /many recovery attempts/.test(m.subject));
    expect(many).toHaveLength(1);
    expect(many[0]!.text).toContain(`More than ${MANY_OPEN_ATTEMPTS} recovery attempts are open`);
    expect(pushes().map((p) => p.kind)).toEqual(['attempts_many']);

    const readsBefore = chain.reads;
    vote(100, { guardians: [EMAIL_GUARDIAN] });
    const [r] = await service.drain();
    // No attempt was read to find it: the transaction carried the vote.
    expect(chain.reads).toBe(readsBefore);
    expect(r!.votes).toBe(1);
    const code = await codeFor(100);
    expect(alertsTo(w, ADDRESS).filter((m) => /your email approved a recovery/.test(m.subject) && m.text!.includes(`${code.slice(0, 3)} ${code.slice(3)}`))).toHaveLength(1);
    expect(pushes()).toMatchObject([{ kind: 'email_vote_recorded', code }]);
  });

  it("another guardian's vote, a failed transaction, and a vote that authorizes are not email votes below quorum", async () => {
    for (const id of [71, 72, 73]) begin(id);
    await service.drain();
    w.rpcMock.addTransactions([
      voteTransaction({ controller, account, guardian: HELPER, ledger: next(), before: { id: 71 }, after: { id: 71, guardians: [HELPER] } }),
      voteTransaction({ controller, account, guardian: EMAIL_GUARDIAN, ledger: next(), before: { id: 72 }, after: { id: 72, guardians: [EMAIL_GUARDIAN] }, status: 'FAILED' }),
      voteTransaction({ controller, account, guardian: EMAIL_GUARDIAN, ledger: next(), before: { id: 73 }, after: { id: 73, state: 'Authorized', guardians: [EMAIL_GUARDIAN] } }),
    ]);
    const reports = await service.drain();
    expect(reports.reduce((n, r) => n + r.transactions, 0)).toBe(3);
    expect(subjects().filter((s) => /your email approved/.test(s))).toEqual([]);
  });

  it("the guardian's authorization nested under another contract's call still counts", async () => {
    begin(74);
    await service.drain();
    vote(74, { guardians: [EMAIL_GUARDIAN] }, { wrappedBy: RELAY });
    await service.drain();
    expect(subjects()).toEqual(['Nido security alert: your email approved a recovery']);
  });

  it('an email vote to cancel, and an email approval of a change, alert every channel', async () => {
    begin(75);
    await service.drain();
    vote(75, { cancelGuardians: [EMAIL_GUARDIAN] }, { domain: 1 });
    const digest = Buffer.alloc(32, 0xc4);
    w.rpcMock.addTransactions([voteTransaction({ controller, account, guardian: EMAIL_GUARDIAN, ledger: next(), fn: 'approve_change', digest })]);
    await service.drain();
    expect(subjects()).toEqual(['Nido security alert: your email approved cancelling a recovery', 'Nido security alert: your email approved a settings change']);
    const changeCode = await alertCode({
      key: await deriveAlertCodeKey(owner.accountCode),
      networkId: networkId(w.fixture.networkPassphrase),
      controller: contractIdFromStrkey(controller),
      account: contractIdFromStrkey(account),
      subject: { kind: 'change', digest },
    });
    expect(pushes()).toMatchObject([{ kind: 'email_cancel_recorded', code: await codeFor(75) }, { kind: 'email_change_recorded', code: changeCode }]);
  });

  it('a vote the meta does not place has the account reconciled from controller state', async () => {
    chain.set(account, 76, { guardians: [EMAIL_GUARDIAN] });
    await service.drain();
    expect(subjects()).toEqual([]);
    w.rpcMock.addTransactions([voteTransaction({ controller, account, guardian: EMAIL_GUARDIAN, ledger: next() })]);
    await service.drain();
    expect(subjects()).toEqual(['Nido security alert: your email approved a recovery']);
  });
});

describe('many open attempts', () => {
  it(`more than ${MANY_OPEN_ATTEMPTS} open attempts alert every channel at most once a day; closed ones do not count`, async () => {
    for (let id = 1; id <= MANY_OPEN_ATTEMPTS; id++) begin(id);
    begin(MANY_OPEN_ATTEMPTS + 1, { evidenceDeadline: 1 });
    await service.drain();
    expect(subjects()).toEqual([]);
    begin(MANY_OPEN_ATTEMPTS + 2);
    begin(MANY_OPEN_ATTEMPTS + 3);
    await service.drain();
    expect(subjects()).toEqual(['Nido security alert: many recovery attempts opened']);
    expect(alertsTo(w, ADDRESS)[0]!.text).toContain(PREEMPT);
    clock += DAY;
    begin(MANY_OPEN_ATTEMPTS + 4);
    await service.drain();
    expect(subjects()).toHaveLength(2);
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
  });

  it('pages through every open attempt: an email vote under forty newer attempts is found', async () => {
    await service.close();
    chain.set(account, 200, { guardians: [EMAIL_GUARDIAN] });
    for (let id = 201; id <= 240; id++) chain.set(account, id, {});
    clock += RECONCILE_EVERY_MS;
    service = newService();
    const reports = await service.drain();
    expect(reports.find((r) => r.reconciled)!.reconciled).toEqual({ accounts: 1, found: 1 });
    const code = await codeFor(200);
    expect(alertsTo(w, ADDRESS).filter((m) => /your email approved a recovery/.test(m.subject) && m.text!.includes(`${code.slice(0, 3)} ${code.slice(3)}`))).toHaveLength(1);
    expect(subjects()).toContain('Nido security alert: many recovery attempts opened');
  });

  it('stops paging at the first attempt past its evidence deadline', async () => {
    await service.close();
    chain.set(account, 300, { guardians: [EMAIL_GUARDIAN] });
    chain.set(account, 301, { evidenceDeadline: 1 });
    chain.set(account, 302, {});
    clock += RECONCILE_EVERY_MS;
    service = newService();
    const reports = await service.drain();
    expect(reports.find((r) => r.reconciled)!.reconciled).toEqual({ accounts: 1, found: 0 });
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

/** The probe the device received last, and its id. */
const lastProbe = (d: PushUserAgentMock) => {
  const p = decode(d).filter((x) => x.kind === 'probe').at(-1);
  return p ? bytes.fromBase64Url(p.probe as string) : undefined;
};
const channels = async () => ((await owner.status()) as { channels: { contact: string; push: string; devices: { id: string; state: string; ackedAt: number }[] }[] }).channels;

describe('push liveness', () => {
  it('probes each device monthly; a tap acknowledges it; two probes without one mark it unacknowledged and tell the address', async () => {
    expect((await service.pollOnce()).probes.probed).toBe(0);
    clock += PROBE_INTERVAL_MS;
    expect((await service.pollOnce()).probes).toEqual({ probed: 1, lapsed: 0, unacknowledged: 0 });
    expect(w.push.accepted.at(-1)).toMatchObject({ ttl: 7 * 86_400, urgency: 'low', topic: 'probe' });
    const id = lastProbe(owner.device)!;
    expect(id).toHaveLength(16);
    expect((await service.pollOnce()).probes.probed).toBe(0);

    // The tap: the device key signs the probe id; the service relays it to the vault.
    const url = await service.listen(0);
    const post = (probe: Uint8Array, signature: Uint8Array) =>
      fetch(`${url}/v1/ack`, { method: 'POST', body: JSON.stringify({ probe: bytes.toBase64Url(probe), signature: bytes.toBase64Url(signature) }) });
    expect((await post(id, new Uint8Array(64))).status).toBe(404);
    expect((await post(id, owner.device.acknowledge(id))).status).toBe(200);
    expect((await post(id, owner.device.acknowledge(id))).status).toBe(404);
    expect((await channels())[0]).toMatchObject({ push: 'live', devices: [{ state: 'live', ackedAt: clock }] });

    // Two probes the device never acknowledges (it is off, or nobody taps).
    for (let i = 0; i < ACK_MISSED_PROBES; i++) {
      clock += PROBE_INTERVAL_MS;
      expect((await service.pollOnce()).probes.unacknowledged).toBe(0);
    }
    expect(subjects()).toEqual([]);
    clock += PROBE_INTERVAL_MS;
    expect((await service.pollOnce()).probes).toEqual({ probed: 1, lapsed: 0, unacknowledged: 1 });
    expect(subjects()).toEqual(['Nido security alert: notifications not confirmed']);
    expect((await channels())[0]).toMatchObject({ push: 'unacknowledged', devices: [{ state: 'unacknowledged' }] });
    // Alerts still go to it; a later tap makes it live again.
    const again = lastProbe(owner.device)!;
    expect((await post(again, owner.device.acknowledge(again))).status).toBe(200);
    expect((await channels())[0]).toMatchObject({ push: 'live' });
  });

  it('a gone subscription is marked lapsed, the address is told, and alerts go by email only', async () => {
    clock += PROBE_INTERVAL_MS;
    w.push.expire(owner.device.endpoint);
    expect((await service.pollOnce()).probes).toEqual({ probed: 1, lapsed: 1, unacknowledged: 0 });
    expect(subjects()).toEqual(['Nido security alert: notifications stopped']);
    const status = await owner.status();
    expect(status).toMatchObject({ ok: true, status: 'channels', channels: [{ state: 'active', push: 'lapsed', devices: [{ state: 'lapsed', lapsedAt: clock }] }] });
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
    expect((await daily.probe()).probed).toBe(0);
    expect((await vault.probe()).probed).toBe(0);
    clock += PROBE_INTERVAL_MS;
    expect((await vault.probe()).probed).toBe(1);
  });

  it('status names each device; push adds a device at once, whatever the others do, and tells the address', async () => {
    const before = await channels();
    expect(before).toMatchObject([{ push: 'live', devices: [{ id: deviceId(owner.device.endpoint), state: 'live' }] }]);
    const id = Buffer.from(before[0]!.contact, 'hex');
    const phone = new PushUserAgentMock(w.push);
    expect(await owner.pushUpdate(id, phone)).toEqual({ ok: true, status: 'push-added' });
    expect(subjects()).toEqual(['Nido security alert: notifications added to a device']);
    expect((await channels())[0]!.devices.map((d) => d.id)).toEqual([deviceId(owner.device.endpoint), deviceId(phone.endpoint)]);
    owner.device.receive();
    w.rpcMock.add([attemptAuthorized(controller, account, w.rpcMock.latestLedger + 1, 97, w.rpcMock.latestLedger + 400_000)]);
    await service.drain();
    expect(decode(phone).map((m) => m.kind)).toEqual(['attempt_authorized']);
    expect(pushes().map((m) => m.kind)).toEqual(['attempt_authorized']);
  });

  it('the owner switched phones, the old one off but subscribed: unacknowledged after the window; the new phone is added at once', async () => {
    const id = Buffer.from((await channels())[0]!.contact, 'hex');
    // The old phone is in a drawer: the push service accepts every probe, nobody taps.
    for (let i = 0; i <= ACK_MISSED_PROBES; i++) {
      clock += PROBE_INTERVAL_MS;
      await service.pollOnce();
    }
    expect(w.push.rejected).toEqual([]);
    expect((await channels())[0]).toMatchObject({ push: 'unacknowledged' });
    const phone = new PushUserAgentMock(w.push);
    expect(await owner.pushUpdate(id, phone)).toMatchObject({ ok: true, status: 'push-added' });
    expect((await channels())[0]).toMatchObject({ push: 'live', devices: [{ state: 'unacknowledged' }, { state: 'live' }] });
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
    expect(await reads.attempt(account, 4n)).toEqual({ state: 'Collecting', guardians: [EMAIL_GUARDIAN], cancelGuardians: [], evidenceDeadline: 1234, epoch: 2n });
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
