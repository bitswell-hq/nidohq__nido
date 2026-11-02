// The alert path on the network (docs/email-recovery/spec.md §10): the
// alert service's host watching the network's recovery controller, its vault
// in its own process (the Nitro NSM mock), three custodian mocks that read
// image activation from the chain, the Lettermint and Scaleway sending mocks
// and a Web Push service mock, every third party a TEST-ONLY mock of its
// published format (`@nidohq/email-mocks`), started as the end-to-end test
// starts them (`tests/support/emailServices.mjs`). `register` enrolls an
// account's alert contact as the wallet does: the vault's attestation
// verified, the contact sealed to it with a Web Push subscription, the
// owner's passkey authorizing it, the emailed code confirming it.
import { createHash } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CustodianMock, LettermintMock, PushServiceMock, PushUserAgentMock, ScalewayTemMock, nitroTestRoot } from '@nidohq/email-mocks';
import { AlertService, ProcessVault, StellarRpc, accountSigners } from '@nidohq/email-alerts';
import {
  PURPOSE_SECURITY_ALERTS,
  alertCode,
  attestationNonce,
  attestedVaultKey,
  bigIntToBytes,
  bytes,
  confirmationRequest,
  contactRequest,
  contractIdFromStrkey,
  deriveAlertCodeKey,
  encodeContactRequest,
  prepareConfirmation,
  prepareContactChange,
} from '@nidohq/email-recovery';
import { xdr } from '@stellar/stellar-sdk';

export class Alerts {
  static async start({ rpcUrl, passphrase, controller, imageRegistry, measurement, apex }) {
    const rpc = new StellarRpc(rpcUrl);
    const dir = mkdtempSync(join(tmpdir(), 'nido-email-attacks-alerts-'));
    const isActive = async (m) => (await rpc.view(imageRegistry, 'is_active', [xdr.ScVal.scvBytes(Buffer.from(m, 'hex'))], passphrase)) === true;
    const custodians = await Promise.all([0, 1, 2].map((i) => CustodianMock.create({ name: `custodian-${i}`, roots: [nitroTestRoot()], registry: { isActive } })));
    const custodianUrls = await Promise.all(custodians.map((c) => c.listen()));
    const lettermint = new LettermintMock();
    const scaleway = new ScalewayTemMock();
    const push = new PushServiceMock();
    await Promise.all([lettermint.listen(), scaleway.listen(), push.listen()]);
    const { vault, boot } = await ProcessVault.start({
      nsm: { kind: 'mock', image: 'nido-alert-vault-v1' },
      cfg: {
        networkId: new Uint8Array(createHash('sha256').update(passphrase).digest()),
        rp: { rpId: '', origins: [], accountApex: apex.host, accountOrigin: { scheme: apex.scheme, port: apex.port } },
        walletOrigin: `${apex.scheme}//${apex.host}:${apex.port}`,
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
    const svc = new AlertService(
      {
        rpc,
        controller,
        statePath: join(dir, 'host.json'),
        startLedger: (await rpc.call('getLatestLedger', {})).sequence,
        signers: (account) => accountSigners(rpc, account, passphrase),
        log: () => {},
        pageLimit: 100,
        retryBaseMs: 0,
      },
      vault,
    );
    const url = await svc.listen(0);
    return new Alerts({ svc, vault, boot, url, custodians, lettermint, scaleway, push, measurement, passphrase });
  }

  constructor(o) {
    Object.assign(this, o);
  }

  /** Read the controller's events up to the tip and send what they require. */
  drain() {
    return this.svc.drain();
  }

  async api(path, init) {
    const r = await fetch(`${this.url}${path}`, init);
    return r.json();
  }

  /** Register and confirm `address` as `enrolled`'s alert contact, with a Web Push device. */
  async register(enrolled, address) {
    const nonce = attestationNonce();
    const { attestation } = await this.api(`/v1/attestation?nonce=${bytes.toBase64Url(nonce)}`);
    const vault = await attestedVaultKey(bytes.fromBase64Url(attestation), { roots: [nitroTestRoot()], allowedMeasurements: [this.measurement], nonce });
    const device = new PushUserAgentMock(this.push);
    const sub = device.subscribe(vault.vapid);
    const accountCode = bigIntToBytes(enrolled.inbox.accountCode, 16);
    const inner = await contactRequest({
      account: enrolled.account.address,
      address,
      accountCode,
      emailGuardian: true,
      push: sub,
      purposes: PURPOSE_SECURITY_ALERTS,
      consentVersion: 1,
      allowLoopbackPush: true,
    });
    const { nonce: vaultNonce } = await this.api('/v1/nonce', { method: 'POST' });
    const prepared = await prepareContactChange(vault, inner, bytes.fromBase64Url(vaultNonce));
    const a = enrolled.owner.assert(prepared.challenge, enrolled.account.rp);
    const body = encodeContactRequest(prepared.finish({ publicKey: enrolled.owner.publicKey, ...a }));
    const registered = await this.api('/v1/contact', { method: 'POST', body, headers: { 'content-type': 'application/json' } });
    const code = this.sentTo(address).map((m) => m.text?.match(/confirmation code for Nido recovery alerts is (\d{6})/)?.[1]).filter(Boolean).at(-1);
    const conf = await prepareConfirmation(vault, confirmationRequest(enrolled.account.address, inner.contact, code));
    const confirmed = await this.api('/v1/contact', { method: 'POST', body: encodeContactRequest(conf), headers: { 'content-type': 'application/json' } });
    return { registered, confirmed, device, accountCode };
  }

  /** Every email the sending mocks accepted for `address`. */
  sentTo(address) {
    return [...this.lettermint.sent, ...this.scaleway.sent].filter((m) => m.to.includes(address));
  }

  /** The code every alert about `attemptId` carries (spec §10.1). */
  async attemptCode(enrolled, accountCode, attemptId) {
    return alertCode({
      key: await deriveAlertCodeKey(accountCode),
      networkId: new Uint8Array(createHash('sha256').update(this.passphrase).digest()),
      controller: contractIdFromStrkey(enrolled.controller),
      account: contractIdFromStrkey(enrolled.account.address),
      subject: { kind: 'attempt', attemptId },
    });
  }

  async close() {
    await Promise.allSettled([this.svc.close(), this.vault.close(), this.lettermint.close(), this.scaleway.close(), this.push.close(), ...this.custodians.map((c) => c.close())]);
  }
}

