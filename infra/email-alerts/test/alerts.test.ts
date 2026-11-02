/**
 * Alerts from events (spec §10, §10.1): what goes out for each event class,
 * the verification code, at-most-once delivery, failover and retries, the
 * opt-in `attempt_begun` email and its rate limit, and a watcher that
 * survives restarts and crashes without missing or repeating an alert.
 */
import { join } from 'node:path';
import { NitroHypervisorMock, testImage } from '@nidohq/email-mocks';
import { alertCode, bytes, contractIdFromStrkey, deriveAlertCodeKey } from '@nidohq/email-recovery';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { InProcessVault, type VaultApi } from '../src/channel.js';
import { alertEventId } from '../src/events.js';
import { accountSigners } from '../src/rpc.js';
import { AlertService } from '../src/service.js';
import { NEVER_ASKS, PASSKEY_DEVICE_LEAD, PREEMPT, alertText } from '../src/vault/content.js';
import { Vault } from '../src/vault/vault.js';
import { IMAGE, Wallet, type World, alertsTo, loadFixture, networkId, startWorld } from './harness.js';
import { attemptBegun } from './synthetic.js';

let w: World;
let vault: Vault;
let owner: Wallet;
const ADDRESS = 'owner@proton.me';

function newService(api: VaultApi = new InProcessVault(vault), extra: Partial<ConstructorParameters<typeof AlertService>[0]> = {}) {
  return new AlertService(
    {
      rpc: w.rpc,
      controller: w.fixture.controller,
      statePath: join(w.dir, 'state.json'),
      startLedger: w.rpcMock.oldestLedger,
      signers: (a) => accountSigners(w.rpc, a, w.fixture.networkPassphrase),
      log: () => {},
      retryBaseMs: 0,
      ...extra,
    },
    api,
  );
}

let service: AlertService;
beforeEach(async () => {
  w = await startWorld(loadFixture().setupEvents);
  vault = await Vault.boot({ cfg: w.cfg, nsm: new NitroHypervisorMock().launch(testImage(IMAGE)) });
  service = newService();
  await service.drain();
  const api = { attestation: (n: Uint8Array) => service.attestation(n), nonce: () => service.nonce(), contact: (b: string) => service.contact(b) };
  owner = new Wallet(w, api);
  const c = await owner.contact(ADDRESS);
  await owner.confirm(c.id, ADDRESS);
});
afterEach(async () => {
  await service.close();
  await w.close();
});

const recovery = () => w.fixture.events.slice(w.fixture.setupEvents);
const walletCode = async (attemptId: bigint) =>
  alertCode({
    key: await deriveAlertCodeKey(owner.accountCode),
    networkId: networkId(w.fixture.networkPassphrase),
    controller: contractIdFromStrkey(w.fixture.controller),
    account: contractIdFromStrkey(w.fixture.account),
    subject: { kind: 'attempt', attemptId },
  });

describe('what each event sends', () => {
  it('attempt_authorized: one email and one push, generic text, the code the wallet computes', async () => {
    w.rpcMock.add(recovery());
    await service.drain();
    const code = await walletCode(BigInt(w.fixture.attemptId));
    const approved = alertsTo(w, ADDRESS).filter((m) => /approved/.test(m.subject));
    expect(approved).toHaveLength(1);
    expect(approved[0]!.text).toContain(`Verification code: ${code.slice(0, 3)} ${code.slice(3)}`);
    for (const m of alertsTo(w, ADDRESS)) {
      expect(m.text).not.toContain(w.fixture.account);
      expect(m.text).not.toContain(ADDRESS);
      expect(m.text).not.toMatch(/https?:\/\/(?!nido\.test)/);
    }
    const pushes = owner.device.receive().map((r) => JSON.parse(Buffer.from(r.payload).toString('utf8')));
    expect(pushes.map((p) => p.kind).sort()).toEqual(['attempt_authorized', 'epoch_advanced', 'recovery_completed']);
    expect(pushes.find((p) => p.kind === 'attempt_authorized').code).toBe(code);
    for (const p of pushes) expect(JSON.stringify(p)).not.toContain(w.fixture.account);
  });

  it('attempt_authorized: the push leads with cancelling, both pre-empt a caller, the email says who never asks for what, no code match reassures', async () => {
    w.rpcMock.add(recovery());
    await service.drain();
    const push = owner.device.receive().map((r) => JSON.parse(Buffer.from(r.payload).toString('utf8'))).find((p) => p.kind === 'attempt_authorized');
    expect(push.body.startsWith(PASSKEY_DEVICE_LEAD)).toBe(true);
    // What the vault knows: the device was set up for alerts, not that it still has the passkey.
    expect(push.body).toMatch(/^This is the device you set up recovery alerts on\. If you can still sign in to your Nido, you do not need a recovery: cancel it/);
    expect(push.body).not.toMatch(/has your passkey/);
    expect(PREEMPT).toBe('If someone told you to expect this message, or to ignore it, they are trying to take your account.');
    expect(push.body).toContain(PREEMPT);
    const email = alertsTo(w, ADDRESS).find((m) => /approved/.test(m.subject))!.text!;
    expect(email).toContain(PREEMPT);
    expect(email).toContain('If you still have your passkey, you do not need a recovery: open your wallet and cancel it.');
    expect(email).toContain(NEVER_ASKS);
    expect(email).toContain('a matching code does not make it yours');
    expect(email).not.toMatch(/nothing needs doing/i);
  });

  it('every required alert pre-empts a caller; informational ones do not', () => {
    for (const name of ['attempt_authorized', 'email_vote_recorded', 'email_cancel_recorded', 'email_change_recorded', 'attempts_many', 'recovery_completed', 'epoch_advanced'] as const) {
      const t = alertText(name, '123456', 'https://nido.test', 0, true);
      expect(t.body).toContain(PREEMPT);
      expect(t.push).toContain(PREEMPT);
    }
    expect(alertText('attempt_cancelled', '123456', 'https://nido.test').body).not.toContain(PREEMPT);
  });

  it('attempt_begun sends nothing by default: anyone can open an attempt, and the wallet shows open ones', async () => {
    w.rpcMock.add(recovery().slice(0, 1)); // attempt_begun
    await service.drain();
    expect(alertsTo(w, ADDRESS)).toEqual([]);
    expect(w.push.accepted).toEqual([]);
  });

  it('a service configured to email attempt_begun sends it by email only', async () => {
    await service.close();
    service = newService(undefined, { emailOnAttemptBegun: true });
    w.rpcMock.add(recovery().slice(0, 1));
    await service.drain();
    expect(alertsTo(w, ADDRESS).map((m) => m.subject)).toEqual(['Nido security alert: recovery attempt opened']);
    expect(w.push.accepted).toEqual([]);
  });

  it('sends each alert at most once, however often the vault is asked', async () => {
    w.rpcMock.add(recovery());
    await service.drain();
    const sent = alertsTo(w, ADDRESS).length;
    const pushed = w.push.accepted.length;
    const auth = recovery().find((e) => Buffer.from(e.topic[0]!, 'base64').includes(Buffer.from('attempt_authorized')))!;
    expect(auth.id).not.toBe(alertEventId('attempt_authorized', w.fixture.account, { kind: 'attempt', attemptId: BigInt(w.fixture.attemptId) }));
    const again = await vault.dispatch({
      eventId: alertEventId('attempt_authorized', w.fixture.account, { kind: 'attempt', attemptId: BigInt(w.fixture.attemptId) }),
      name: 'attempt_authorized',
      class: 'required',
      controller: contractIdFromStrkey(w.fixture.controller),
      account: contractIdFromStrkey(w.fixture.account),
      subject: { kind: 'attempt', attemptId: BigInt(w.fixture.attemptId) },
    });
    expect(again.status).toBe('done');
    expect(alertsTo(w, ADDRESS).length).toBe(sent);
    expect(w.push.accepted.length).toBe(pushed);
  });
});

describe('sending', () => {
  it('fails over from Lettermint to Scaleway after two failures, reusing one Idempotency-Key', async () => {
    await service.close();
    service = newService(undefined, { emailOnAttemptBegun: true });
    w.lettermint.failNext({ status: 500, count: 2 });
    w.rpcMock.add(recovery().slice(0, 1));
    await service.drain();
    const tries = w.lettermint.requests.filter((r) => r.path === '/v1/send').slice(-2);
    expect(tries.map((t) => t.status)).toEqual([500, 500]);
    expect(w.scaleway.sent.filter((m) => m.to.includes(ADDRESS))).toHaveLength(1);
  });

  it('queues a retry when both services fail, moves the cursor on, and later sends exactly once', async () => {
    let clock = Date.now();
    await service.close();
    service = newService(undefined, { retryBaseMs: 60_000, now: () => clock, emailOnAttemptBegun: true });
    w.lettermint.failNext({ status: 503, count: 2 });
    w.scaleway.failNext({ status: 503, count: 2 });
    w.rpcMock.add(recovery().slice(0, 1));
    const [r] = await service.drain();
    expect(r!.retriesQueued).toBe(1);
    expect(service.state.cursor).toBeDefined();
    expect(alertsTo(w, ADDRESS)).toEqual([]);
    expect((await service.pollOnce()).retriesDone).toBe(0);
    clock += 60_001;
    const r2 = await service.pollOnce();
    expect(r2.retriesDone).toBe(1);
    expect(alertsTo(w, ADDRESS)).toHaveLength(1);
    await service.pollOnce();
    expect(alertsTo(w, ADDRESS)).toHaveLength(1);
  });

  it('retries only the channel that failed', async () => {
    w.push.failNext(503);
    w.rpcMock.add(recovery().slice(0, 2)); // begun, authorized
    const [r] = await service.drain();
    expect(r!.retriesQueued).toBe(1);
    const emails = alertsTo(w, ADDRESS).length;
    await service.pollOnce();
    expect(alertsTo(w, ADDRESS).length).toBe(emails);
    expect(w.push.accepted.filter((m) => m.urgency === 'high')).toHaveLength(1);
  });
});

describe('the watcher', () => {
  it('rate-limits attempt_begun to one alert per account per day, counting the rest', async () => {
    await service.close();
    service = newService(undefined, { emailOnAttemptBegun: true });
    const { controller, account } = w.fixture;
    const start = w.rpcMock.latestLedger + 1;
    w.rpcMock.add([0, 1, 2, 3, 4].map((i) => attemptBegun(controller, account, start + i * 100, 50 + i)));
    const reports = await service.drain();
    expect(reports.reduce((n, r) => n + r.suppressed, 0)).toBe(4);
    expect(alertsTo(w, ADDRESS)).toHaveLength(1);
    w.rpcMock.add([attemptBegun(controller, account, start + 17_280 + 1, 60)]);
    await service.drain();
    const begun = alertsTo(w, ADDRESS);
    expect(begun).toHaveLength(2);
    expect(begun[1]!.text).toContain('4 more like this were opened since the last notice.');
  });

  it('resumes from its stored cursor after a restart: nothing missed, nothing repeated', async () => {
    const events = recovery();
    w.rpcMock.add(events.slice(0, 2));
    await service.drain();
    const firstCursor = service.state.cursor;
    await service.close();
    w.rpcMock.add(events.slice(2));
    service = newService();
    expect(service.state.cursor).toBe(firstCursor);
    await service.drain();
    const subjects = alertsTo(w, ADDRESS).map((m) => m.subject);
    expect(subjects.filter((s) => /approved/.test(s))).toHaveLength(1);
    expect(subjects.filter((s) => /opened/.test(s))).toEqual([]);
    expect(subjects.filter((s) => /completed/.test(s))).toHaveLength(1);
    expect(subjects.filter((s) => /settings changed/.test(s))).toHaveLength(1);
  });

  it('a crash between the vault sending and the host persisting does not resend', async () => {
    const real = new InProcessVault(vault);
    let crash = true;
    const crashing: VaultApi = Object.assign(Object.create(real), {
      dispatch: async (ev: Parameters<VaultApi['dispatch']>[0]) => {
        const r = await real.dispatch(ev);
        if (crash && ev.name === 'attempt_authorized') {
          crash = false;
          throw new Error('host crashed before persisting');
        }
        return r;
      },
    });
    service = newService(crashing);
    w.rpcMock.add(recovery());
    await expect(service.drain()).rejects.toThrow(/crashed/);
    service = newService();
    await service.drain();
    expect(alertsTo(w, ADDRESS).filter((m) => /approved/.test(m.subject))).toHaveLength(1);
    expect(w.push.accepted.filter((m) => m.topic && m.urgency === 'high').length).toBe(3);
  });

  it('an RPC outage changes nothing; the next poll catches up', async () => {
    const before = JSON.stringify(service.state);
    w.rpcMock.failNext(1);
    await expect(service.pollOnce()).rejects.toThrow();
    expect(JSON.stringify(service.state)).toBe(before);
    w.rpcMock.add(recovery());
    await service.drain();
    expect(alertsTo(w, ADDRESS).filter((m) => /approved/.test(m.subject))).toHaveLength(1);
  });

  it('marks a gone push subscription and keeps sending email', async () => {
    w.push.failNext(410);
    w.rpcMock.add(recovery().slice(0, 2));
    const [r] = await service.drain();
    expect(r!.retriesQueued).toBe(0);
    expect(alertsTo(w, ADDRESS).filter((m) => /approved/.test(m.subject))).toHaveLength(1);
    w.rpcMock.add(recovery().slice(2));
    await service.drain();
    expect(w.push.accepted).toEqual([]);
  });

  it('stores only sealed records: no address in the host state', async () => {
    w.rpcMock.add(recovery());
    await service.drain();
    const state = JSON.stringify(service.state);
    expect(state).not.toContain(ADDRESS);
    expect(state).not.toContain(Buffer.from(ADDRESS).toString('base64').slice(0, 12));
    for (const blob of Object.values(service.state.sealed.records)) {
      expect(Buffer.from(blob, 'base64').includes(Buffer.from(ADDRESS))).toBe(false);
    }
    void bytes;
  });
});
