/**
 * End to end (spec §10): an account whose recovery lists an email guardian
 * goes through a lost-key recovery on Nido's integration-test host
 * (`fixtures/chain.json`); the host watches those events through the
 * Stellar RPC mock; the vault runs in its own process, booted from the
 * custodians; one email (Lettermint mock) and one Web Push (push-service
 * mock) go out for `attempt_authorized`, with generic text and the code the
 * wallet computes. Every byte the host received, sent, logged, or stored is
 * checked for the address, and so is everything the RPC, the custodians,
 * and the push service received.
 *
 * Set `NIDO_ALERT_MEASUREMENTS=<file>` to write the latency and size figures.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { alertCode, bytes, contractIdFromStrkey, deriveAlertCodeKey } from '@nidohq/email-recovery';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
// The built package: the vault process is `dist/vault/main.js`.
import { AlertService, ProcessVault, StellarRpc, accountSigners } from '../dist/index.js';
import { IMAGE, Wallet, type WalletApi, type World, alertsTo, httpApi, networkId, startWorld, loadFixture } from './harness.js';
import { attemptAuthorized } from './synthetic.js';

const ADDRESS = 'Ada.Lovelace+nido@proton.me';

let w: World;
let vault: ProcessVault;
let service: AlertService;
let api: WalletApi;
const hostLog: string[] = [];
/** Everything the host's HTTP API received and answered. */
const http: string[] = [];
const measured: Record<string, number> = {};

/** Every way the address could appear in bytes or text. */
function contains(haystack: unknown, needle = ADDRESS): boolean {
  const seen = new Set<unknown>();
  const visit = (v: unknown): boolean => {
    if (v === null || v === undefined || seen.has(v)) return false;
    if (typeof v === 'string') return v.includes(needle) || v.toLowerCase().includes(needle.toLowerCase());
    if (v instanceof Uint8Array) return Buffer.from(v).includes(Buffer.from(needle)) || visit(Buffer.from(v).toString('base64'));
    if (typeof v === 'object') {
      seen.add(v);
      return Object.values(v as object).some(visit) || (v instanceof Map && [...v.entries()].some(([k, x]) => visit(k) || visit(x)));
    }
    return false;
  };
  return visit(haystack);
}

beforeAll(async () => {
  w = await startWorld(loadFixture().setupEvents);
  const started = await ProcessVault.start({ cfg: w.cfg, nsm: { kind: 'mock', image: IMAGE } });
  vault = started.vault;
  service = new AlertService(
    {
      rpc: new StellarRpc(w.rpc.url),
      controller: w.fixture.controller,
      statePath: join(w.dir, 'state.json'),
      startLedger: w.rpcMock.oldestLedger,
      signers: (a) => accountSigners(new StellarRpc(w.rpc.url), a, w.fixture.networkPassphrase),
      log: (l) => hostLog.push(l),
      retryBaseMs: 0,
    },
    vault,
  );
  service.state.vaultId = bytes.toHex(started.boot.vaultId);
  const base = await service.listen();
  const inner = httpApi(base);
  api = {
    attestation: (n) => inner.attestation(n),
    nonce: () => inner.nonce(),
    contact: async (body) => {
      http.push(body);
      const r = await inner.contact(body);
      http.push(JSON.stringify(r));
      return r;
    },
  };
  await service.drain();
});

afterAll(async () => {
  await service?.close();
  await vault?.close();
  await w?.close();
  if (process.env.NIDO_ALERT_MEASUREMENTS) writeFileSync(process.env.NIDO_ALERT_MEASUREMENTS, JSON.stringify(measured, null, 2));
});

describe('an account with an email guardian enters recovery', () => {
  let owner: Wallet;

  it('the wallet verifies the vault attestation and registers a confirmed contact with Web Push', async () => {
    owner = new Wallet(w, api);
    const key = await owner.attest();
    expect(key.measurement).toBe(w.fixture.measurement);
    measured.attestationDocumentBytes = owner.attestationBytes;
    const c = await owner.contact(ADDRESS);
    expect(c.result).toEqual({ ok: true, status: 'pending-confirmation' });
    measured.registrationRequestBytes = owner.requestBytes;
    expect(await owner.confirm(c.id, ADDRESS)).toEqual({ ok: true, status: 'confirmed' });
  });

  it('attempt_authorized sends exactly one email and one push, generic, with the wallet\'s code', async () => {
    const recovery = w.fixture.events.slice(w.fixture.setupEvents);
    const upTo = recovery.findIndex((e) => Buffer.from(e.topic[0]!, 'base64').includes(Buffer.from('attempt_authorized')));
    const sentBefore = w.lettermint.sent.length;
    w.rpcMock.add(recovery.slice(0, upTo + 1));
    const t0 = Date.now();
    const reports = await service.drain();
    const authId = recovery[upTo]!.id;

    const code = await alertCode({
      key: await deriveAlertCodeKey(owner.accountCode),
      networkId: networkId(w.fixture.networkPassphrase),
      controller: contractIdFromStrkey(w.fixture.controller),
      account: contractIdFromStrkey(w.fixture.account),
      subject: { kind: 'attempt', attemptId: BigInt(w.fixture.attemptId) },
    });
    const approved = alertsTo(w, ADDRESS).filter((m) => /approved/.test(m.subject));
    expect(approved).toHaveLength(1);
    expect(approved[0]!.provider).toBe('lettermint');
    expect(approved[0]!.text).toContain(`Verification code: ${code.slice(0, 3)} ${code.slice(3)}`);
    expect(approved[0]!.text).not.toContain(w.fixture.account);
    const pushes = owner.device.receive();
    expect(pushes).toHaveLength(1);
    const payload = JSON.parse(Buffer.from(pushes[0]!.payload).toString('utf8'));
    expect(payload).toMatchObject({ v: 1, kind: 'attempt_authorized', code });
    expect(JSON.stringify(payload)).not.toContain(w.fixture.account);
    expect(w.lettermint.sent.length - sentBefore).toBe(1); // attempt_authorized; attempt_begun sends nothing by default

    measured.eventToVaultAnswerMs = reports.map((r) => r.latencyMs[authId]).find((x) => x !== undefined)!;
    measured.eventsPollToEmailAcceptedMs = approved[0]!.receivedAt - t0;
    measured.eventsPollToPushAcceptedMs = pushes[0]!.message.receivedAt - t0;
    measured.pushBodyBytes = pushes[0]!.message.body.length;
    measured.emailRequestBytes = Buffer.byteLength(approved[0]!.body);
  });

  it('the rest of the recovery alerts every channel once', async () => {
    w.rpcMock.add(w.fixture.events.slice(w.fixture.setupEvents).filter((e) => e.ledger > w.rpcMock.latestLedger));
    await service.drain();
    const subjects = alertsTo(w, ADDRESS).map((m) => m.subject);
    expect(subjects.filter((s) => /completed/.test(s))).toHaveLength(1);
    expect(subjects.filter((s) => /settings changed/.test(s))).toHaveLength(1);
    expect(owner.device.receive().map((r) => JSON.parse(Buffer.from(r.payload).toString()).kind).sort()).toEqual([
      'epoch_advanced',
      'recovery_completed',
    ]);
  });

  it('a restarted vault recovers its key from two custodians and its sealed records from the host', async () => {
    await vault.close();
    await w.custodians[2]!.close();
    const t0 = performance.now();
    const restarted = await ProcessVault.start({
      cfg: w.cfg,
      nsm: { kind: 'mock', image: IMAGE },
      vaultId: bytes.fromHex(service.state.vaultId!),
      state: AlertService.sealedState(service.state),
    });
    measured.vaultRestoreMs = performance.now() - t0;
    expect(bytes.toHex(restarted.boot.vaultId)).toBe(service.state.vaultId);
    await service.close();
    const hostTranscript = vault.transcript;
    vault = restarted.vault;
    service = new AlertService(
      {
        rpc: new StellarRpc(w.rpc.url),
        controller: w.fixture.controller,
        statePath: join(w.dir, 'state.json'),
        startLedger: w.rpcMock.oldestLedger,
        signers: (a) => accountSigners(new StellarRpc(w.rpc.url), a, w.fixture.networkPassphrase),
        log: (l) => hostLog.push(l),
      },
      vault,
    );
    w.rpcMock.add([attemptAuthorized(w.fixture.controller, w.fixture.account, w.rpcMock.latestLedger + 5, 1, w.rpcMock.latestLedger + 500)]);
    await service.drain();
    expect(alertsTo(w, ADDRESS).filter((m) => /approved/.test(m.subject))).toHaveLength(2);
    vault.transcript.unshift(...hostTranscript);
  });

  it('no party other than the vault and the sending service ever held the address', async () => {
    // The host: every message to and from the vault, its HTTP traffic, its log, its state file.
    expect(contains(vault.transcript)).toBe(false);
    expect(contains(http)).toBe(false);
    expect(contains(hostLog)).toBe(false);
    expect(readFileSync(join(w.dir, 'state.json'), 'utf8').toLowerCase()).not.toContain(ADDRESS.toLowerCase());
    expect(vault.console.join('')).toBe('');
    // The RPC, the custodians, the push service.
    expect(contains(w.rpcMock.calls)).toBe(false);
    expect(contains(w.custodians.map((c) => c.decisions))).toBe(false);
    expect(contains(w.push.accepted.map((m) => m.body))).toBe(false);
    // The sending service is the one place it is meant to go.
    expect(w.lettermint.sent.every((m) => m.to.includes(ADDRESS))).toBe(true);
    // And the test's needle works: the sending service's record does contain it.
    expect(contains(w.lettermint.sent)).toBe(true);
    measured.hostMessagesScanned = vault.transcript.length + http.length + hostLog.length;
  });
});
