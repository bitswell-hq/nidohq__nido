/**
 * Key custody (spec §10.5): genesis splits the vault key 2-of-3 across the
 * custodians; a restarted or upgraded enclave gets it back only with an
 * attested measurement the registry holds as active; two shares reconstruct
 * it, one does not, a wrong one is detected.
 */
import { createHmac, randomBytes } from 'node:crypto';
import { NitroHypervisorMock, imageMeasurement, testImage } from '@nidohq/email-mocks';
import { bytes } from '@nidohq/email-recovery';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { genesis, restore } from '../src/vault/custody.js';
import { alertLookup, combineShares, deriveVaultKeys, splitSecret } from '../src/vault/keys.js';
import { IMAGE, type World, loadFixture, startWorld } from './harness.js';
import { controllerEvent } from './synthetic.js';

let w: World;
afterEach(async () => w?.close());

const nsm = (image = IMAGE, debug = false) => new NitroHypervisorMock().launch(testImage(image), { debug });

describe('Shamir 2-of-3 (shamir-secret-sharing)', () => {
  it('any two shares reconstruct the key; one does not; a wrong share is detected', async () => {
    const k = new Uint8Array(randomBytes(32));
    const { vaultId } = await deriveVaultKeys(k);
    const shares = await splitSecret(k);
    expect(shares).toHaveLength(3);
    for (const [a, b] of [
      [0, 1],
      [0, 2],
      [1, 2],
    ] as const) {
      expect((await combineShares([shares[a]!, shares[b]!], vaultId)).k).toEqual(k);
    }
    await expect(combineShares([shares[0]!], vaultId)).rejects.toThrow(/need 2 shares/);
    const bad = shares[1]!.slice();
    bad[0]! ^= 1;
    await expect(combineShares([shares[0]!, bad], vaultId)).rejects.toThrow(/does not match the vault id/);
  });

  it('derives every vault key from K alone', async () => {
    const k = new Uint8Array(32).fill(1);
    const a = await deriveVaultKeys(k);
    const b = await deriveVaultKeys(k);
    expect(a.hpkePublic).toEqual(b.hpkePublic);
    expect(a.vapidPublic).toEqual(b.vapidPublic);
    expect(a.kAlert).toEqual(b.kAlert);
    expect(a.kAlert).not.toEqual(a.kStore);
  });

  it('computes the spec §10 lookup', async () => {
    const kAlert = new Uint8Array(32).fill(2);
    const account = new Uint8Array(32).fill(3);
    const want = createHmac('sha256', kAlert).update('nido/email-recovery/v1/alert-lookup').update(account).digest();
    expect(Buffer.from(await alertLookup(kAlert, account))).toEqual(want);
  });
});

describe('custodians and the enclave-image registry', () => {
  beforeEach(async () => {
    w = await startWorld(loadFixture().setupEvents);
  });

  it('genesis deposits one share per custodian; a restarted enclave restores the same key', async () => {
    const keys = await genesis(nsm(), w.cfg.custodians);
    for (const c of w.custodians) expect(c.holds(keys.vaultId)).toBe(true);
    const r = await restore(nsm(), w.cfg.custodians, keys.vaultId);
    expect(r.keys.hpkePublic).toEqual(keys.hpkePublic);
    expect(r.outcomes.filter((o) => o.ok)).toHaveLength(2);
  });

  it('restores with one custodian down; not with two down', async () => {
    const keys = await genesis(nsm(), w.cfg.custodians);
    await w.custodians[0]!.close();
    const r = await restore(nsm(), w.cfg.custodians, keys.vaultId);
    expect(r.keys.vaultId).toEqual(keys.vaultId);
    expect(r.outcomes[0]!.ok).toBe(false);
    await w.custodians[1]!.close();
    await expect(restore(nsm(), w.cfg.custodians, keys.vaultId)).rejects.toThrow(/fewer than two/);
  });

  it('refuses an image the registry never approved, and a debug-mode enclave', async () => {
    const keys = await genesis(nsm(), w.cfg.custodians);
    await expect(restore(nsm('nido-alert-vault-v2'), w.cfg.custodians, keys.vaultId)).rejects.toThrow(/fewer than two/);
    const why = w.custodians.flatMap((c) => c.decisions.filter((d) => d.outcome === 'refused').map((d) => d.reason));
    expect(why).toContain('measurement not active in the registry');
    await expect(restore(nsm(IMAGE, true), w.cfg.custodians, keys.vaultId)).rejects.toThrow(/fewer than two/);
    expect(w.custodians[0]!.decisions.at(-1)!.reason).toMatch(/debug-mode/);
  });

  it('refuses genesis while the image is approved but still inside its 14-day timelock', async () => {
    const queuedOnly = await startWorld(4); // proposed, approved twice, queued; not activated
    try {
      await expect(genesis(nsm(), queuedOnly.cfg.custodians)).rejects.toThrow(/not active/);
      expect(queuedOnly.custodians[0]!.decisions.at(-1)).toMatchObject({
        outcome: 'refused',
        measurement: bytes.toHex(imageMeasurement(testImage(IMAGE))),
      });
    } finally {
      await queuedOnly.close();
    }
  });

  it('stops releasing shares once the registry revokes the image', async () => {
    const keys = await genesis(nsm(), w.cfg.custodians);
    const m = bytes.toHex(imageMeasurement(testImage(IMAGE)));
    const { xdr } = await import('@stellar/stellar-sdk');
    w.rpcMock.add([
      { ...controllerEvent(w.fixture.registry, w.fixture.account, 'x', w.rpcMock.latestLedger + 1, []),
        topic: [xdr.ScVal.scvSymbol('measurement_revoked').toXDR('base64'), xdr.ScVal.scvBytes(Buffer.from(m, 'hex')).toXDR('base64')],
        value: xdr.ScVal.scvMap([]).toXDR('base64') },
    ]);
    await expect(restore(nsm(), w.cfg.custodians, keys.vaultId)).rejects.toThrow(/fewer than two/);
  });
});
