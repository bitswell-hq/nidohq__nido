/**
 * Alert contacts (spec §10.3): owner authorization, email confirmation, the
 * 14-day replacement and removal with immediate notice, removal refused
 * during an authorized recovery, and the re-check of the authorizing
 * passkey when a change matures.
 */
import { join } from 'node:path';
import { FLAG_UP, NitroHypervisorMock, testImage } from '@nidohq/email-mocks';
import {
  PURPOSE_SECURITY_ALERTS,
  type SealedRequest,
  confirmationRequest,
  contactRequest,
  encodeContactRequest,
  prepareConfirmation,
  prepareContactChange,
  sealRequest,
} from '@nidohq/email-recovery';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { InProcessVault } from '../src/channel.js';
import { accountSigners } from '../src/rpc.js';
import { AlertService } from '../src/service.js';
import { CONTACT_CHANGE_DELAY_LEDGERS, Vault } from '../src/vault/vault.js';
import { IMAGE, Wallet, type WalletApi, type World, alertsTo, loadFixture, startWorld } from './harness.js';
import { attemptAuthorized } from './synthetic.js';

let w: World;
let service: AlertService;
let api: WalletApi;
let served = 0;

beforeEach(async () => {
  served = loadFixture().setupEvents;
  w = await startWorld(served);
  const vault = await Vault.boot({ cfg: w.cfg, nsm: new NitroHypervisorMock().launch(testImage(IMAGE)) });
  service = new AlertService(
    {
      rpc: w.rpc,
      controller: w.fixture.controller,
      statePath: join(w.dir, 'state.json'),
      startLedger: w.rpcMock.oldestLedger,
      signers: (a) => accountSigners(w.rpc, a, w.fixture.networkPassphrase),
      log: () => {},
    },
    new InProcessVault(vault),
  );
  api = { attestation: (n) => service.attestation(n), nonce: () => service.nonce(), contact: (b) => service.contact(b) };
  await service.drain();
});
afterEach(async () => {
  await service.close();
  await w.close();
});

/** Serve the recorded recovery up to and including the event named `name`, and catch up. */
async function upTo(name: string) {
  const at = w.fixture.events.findIndex(
    (e, i) => i >= served && Buffer.from(e.topic[0]!, 'base64').includes(Buffer.from(name)),
  );
  if (at < 0) throw new Error(`no ${name} left`);
  w.rpcMock.add(w.fixture.events.slice(served, at + 1));
  served = at + 1;
  await service.drain();
}

/** The chain moves on with no events, polled as a running service would (well inside retention). */
async function advanceTo(ledger: number) {
  const matured = { applied: [] as string[], dropped: [] as string[], postponed: [] as string[] };
  while (w.rpcMock.latestLedger < ledger) {
    w.rpcMock.latestLedger = Math.min(ledger, w.rpcMock.latestLedger + 50_000);
    for (const r of await service.drain()) {
      matured.applied.push(...r.matured.applied);
      matured.dropped.push(...r.matured.dropped);
      matured.postponed.push(...r.matured.postponed);
    }
  }
  return { matured };
}

async function confirmed(owner: Wallet, address: string) {
  const c = await owner.contact(address);
  expect(c.result).toEqual({ ok: true, status: 'pending-confirmation' });
  expect(await owner.confirm(c.id, address)).toEqual({ ok: true, status: 'confirmed' });
  return c.id;
}

describe('registration', () => {
  it('needs an account passkey, and alerts start only after the email confirmation', async () => {
    const owner = new Wallet(w, api);
    const { id, result } = await owner.contact('owner@proton.me');
    expect(result).toEqual({ ok: true, status: 'pending-confirmation' });
    await upTo('attempt_authorized');
    expect(alertsTo(w, 'owner@proton.me')).toEqual([]);
    expect(w.push.accepted).toEqual([]);
    expect(await owner.confirm(id, 'owner@proton.me')).toEqual({ ok: true, status: 'confirmed' });
    await upTo('recovery_completed');
    expect(alertsTo(w, 'owner@proton.me').length).toBeGreaterThan(0);
  });

  it('refuses a third party enrolling, replacing, or removing the account\'s contact', async () => {
    const attacker = new Wallet(w, api, new Uint8Array(32).fill(7));
    expect((await attacker.contact('attacker@gmail.com')).result).toEqual({
      ok: false,
      error: 'authorization: not a signer of the account',
    });
    const owner = new Wallet(w, api);
    const mine = await confirmed(owner, 'owner@proton.me');
    expect((await attacker.contact('attacker@gmail.com', { replaces: mine })).result).toEqual({
      ok: false,
      error: 'authorization: not a signer of the account',
    });
    expect(await attacker.remove(mine)).toEqual({ ok: false, error: 'authorization: not a signer of the account' });
    expect([...w.lettermint.sent, ...w.scaleway.sent].some((m) => m.to.includes('attacker@gmail.com'))).toBe(false);
  });

  it('refuses a second registration: an existing contact can only be replaced', async () => {
    const owner = new Wallet(w, api);
    await confirmed(owner, 'owner@proton.me');
    expect((await owner.contact('other@proton.me')).result).toEqual({
      ok: false,
      error: 'the account already has alert contacts; replace them instead',
    });
  });

  it('refuses a replayed request, a swapped envelope, and a wrong relying party, type, or flags', async () => {
    const owner = new Wallet(w, api);
    const vault = await owner.attest();
    const inner = (await contactRequest({
      account: w.fixture.account,
      address: 'owner@proton.me',
      accountCode: owner.accountCode,
      emailGuardian: false,
      purposes: PURPOSE_SECURITY_ALERTS,
      consentVersion: 1,
    })) as SealedRequest & { op: 'register' };
    const signed = async (opts?: Parameters<typeof owner.passkey.assert>[1]) => {
      const p = await prepareContactChange(vault, inner, await api.nonce());
      return p.finish({ publicKey: owner.passkey.publicKey, ...owner.passkey.assert(p.challenge, opts) });
    };

    // The owner's authorization moved onto another envelope (another address).
    const other = await sealRequest(vault.publicKey, { ...inner, address: 'attacker@gmail.com' });
    expect(await api.contact(encodeContactRequest({ ...(await signed()), envelope: other }))).toEqual({
      ok: false,
      error: 'authorization: challenge mismatch',
    });
    expect(await api.contact(encodeContactRequest(await signed({ rpId: 'evil.test' })))).toMatchObject({
      error: 'authorization: rpIdHash mismatch',
    });
    expect(await api.contact(encodeContactRequest(await signed({ origin: 'https://evil.test' })))).toMatchObject({
      error: 'authorization: origin not allowed',
    });
    expect(await api.contact(encodeContactRequest(await signed({ flags: FLAG_UP })))).toMatchObject({
      error: 'authorization: user not verified',
    });
    expect(await api.contact(encodeContactRequest(await signed({ type: 'webauthn.create' })))).toMatchObject({
      error: 'authorization: not webauthn.get',
    });

    // The genuine request works once, and only once.
    const body = encodeContactRequest(await signed());
    expect(await api.contact(body)).toEqual({ ok: true, status: 'pending-confirmation' });
    expect(await api.contact(body)).toEqual({ ok: false, error: 'unknown, used, or expired nonce' });
  });

  it('refuses an email-guardian account without Web Push (spec §9.3 rule 2), even past the wallet helper', async () => {
    const owner = new Wallet(w, api);
    const vault = await owner.attest();
    const inner = {
      ...((await contactRequest({
        account: w.fixture.account,
        address: 'owner@proton.me',
        accountCode: owner.accountCode,
        emailGuardian: false,
        purposes: PURPOSE_SECURITY_ALERTS,
        consentVersion: 1,
      })) as SealedRequest & { op: 'register' }),
      emailGuardian: true,
    };
    const p = await prepareContactChange(vault, inner, await api.nonce());
    const r = await api.contact(encodeContactRequest(p.finish({ publicKey: owner.passkey.publicKey, ...owner.passkey.assert(p.challenge) })));
    expect(r).toEqual({ ok: false, error: 'an account with an email guardian needs a Web Push channel as well' });
  });

  it('caps confirmation attempts at five', async () => {
    const owner = new Wallet(w, api);
    const vault = await owner.attest();
    const { id } = await owner.contact('owner@proton.me');
    const wrong = async () =>
      api.contact(encodeContactRequest(await prepareConfirmation(vault, confirmationRequest(w.fixture.account, id, '000000') as never)));
    for (let i = 0; i < 5; i++) {
      const r = await wrong();
      // One in a million: the drawn code is 000000.
      expect(r).toMatchObject({ ok: false });
    }
    expect(await owner.confirm(id, 'owner@proton.me')).toEqual({ ok: false, error: 'too many attempts' });
  });
});

describe('replacement and removal', () => {
  it('replacing: the old contact is told at once and keeps alerts for 14 days; the new one receives once confirmed', async () => {
    const owner = new Wallet(w, api);
    const oldId = await confirmed(owner, 'old@proton.me');
    const requestedAt = service.state.latestLedger;
    const r = await owner.contact('new@proton.me', { replaces: oldId });
    expect(r.result).toEqual({ ok: true, status: 'change-pending', maturesLedger: requestedAt + CONTACT_CHANGE_DELAY_LEDGERS });
    const notice = alertsTo(w, 'old@proton.me');
    expect(notice).toHaveLength(1);
    expect(notice[0]!.text).toMatch(/being moved to another address\. The change takes effect in 14 days/);
    expect(w.push.accepted).toHaveLength(1);

    await upTo('attempt_begun');
    expect(alertsTo(w, 'new@proton.me')).toEqual([]);
    expect(await owner.confirm(r.id, 'new@proton.me')).toEqual({ ok: true, status: 'confirmed' });
    await upTo('attempt_authorized');
    // The notice and attempt_authorized (attempt_begun sends nothing by default).
    expect(alertsTo(w, 'old@proton.me')).toHaveLength(2);
    expect(alertsTo(w, 'new@proton.me')).toHaveLength(1);

    expect((await advanceTo(requestedAt + CONTACT_CHANGE_DELAY_LEDGERS - 1)).matured.applied).toEqual([]);
    const maturity = requestedAt + CONTACT_CHANGE_DELAY_LEDGERS;
    expect((await advanceTo(maturity)).matured.applied).toEqual([w.fixture.account]);
    w.rpcMock.add([attemptAuthorized(w.fixture.controller, w.fixture.account, maturity + 1, 8, maturity + 200)]);
    await service.drain();
    expect(alertsTo(w, 'old@proton.me')).toHaveLength(2);
    expect(alertsTo(w, 'new@proton.me')).toHaveLength(2);
  });

  it('a change authorized by a passkey a recovery has since removed is dropped when it matures', async () => {
    const owner = new Wallet(w, api);
    const oldId = await confirmed(owner, 'old@proton.me');
    const r = await owner.contact('thief@gmail.com', { replaces: oldId });
    await owner.confirm(r.id, 'thief@gmail.com');
    w.rules.stage = 'after';
    const report = await advanceTo(service.state.latestLedger + CONTACT_CHANGE_DELAY_LEDGERS);
    expect(report.matured.dropped).toEqual([w.fixture.account]);
    const record = Object.keys(service.state.sealed.records);
    expect(record).toHaveLength(1);
  });

  it('a replacement never confirmed is dropped when it matures', async () => {
    const owner = new Wallet(w, api);
    const oldId = await confirmed(owner, 'old@proton.me');
    await owner.contact('typo@proton.me', { replaces: oldId });
    const report = await advanceTo(service.state.latestLedger + CONTACT_CHANGE_DELAY_LEDGERS);
    expect(report.matured.dropped).toEqual([w.fixture.account]);
  });

  it('removal is refused while a recovery is authorized; afterwards the replaced passkey cannot remove', async () => {
    const owner = new Wallet(w, api);
    const id = await confirmed(owner, 'owner@proton.me');
    await upTo('attempt_authorized');
    expect(service.isAuthorized(w.fixture.account)).toBe(true);
    expect(await owner.remove(id)).toEqual({ ok: false, error: 'removal is refused while a recovery attempt is authorized' });
    await upTo('recovery_completed');
    expect(service.isAuthorized(w.fixture.account)).toBe(false);
    w.rules.stage = 'after';
    expect(await owner.remove(id)).toEqual({ ok: false, error: 'authorization: not a signer of the account' });
  });

  it('removal takes 14 days with notice, and waits while a recovery is authorized at maturity', async () => {
    const owner = new Wallet(w, api);
    const id = await confirmed(owner, 'owner@proton.me');
    const requestedAt = service.state.latestLedger;
    expect(await owner.remove(id)).toEqual({
      ok: true,
      status: 'change-pending',
      maturesLedger: requestedAt + CONTACT_CHANGE_DELAY_LEDGERS,
    });
    expect(alertsTo(w, 'owner@proton.me').at(-1)!.text).toMatch(/being turned off\. The change takes effect in 14 days/);

    const maturity = requestedAt + CONTACT_CHANGE_DELAY_LEDGERS;
    expect((await advanceTo(maturity - 10)).matured).toEqual({ applied: [], dropped: [], postponed: [] });
    w.rpcMock.add([attemptAuthorized(w.fixture.controller, w.fixture.account, maturity - 5, 7, maturity + 100)]);
    await service.drain();
    expect(service.isAuthorized(w.fixture.account)).toBe(true);
    expect((await advanceTo(maturity)).matured.postponed).toContain(w.fixture.account);
    expect(Object.keys(service.state.sealed.records)).toHaveLength(1);
    expect((await advanceTo(maturity + 100)).matured.applied).toEqual([w.fixture.account]);
    expect(Object.keys(service.state.sealed.records)).toHaveLength(0);
  });
});
