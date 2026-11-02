// The alert path on the network (docs/email-recovery/spec.md §10): the
// alert service's host watching the network's recovery controller, its vault
// in its own process (the Nitro NSM mock), three custodian mocks that read
// image activation from the chain, the Lettermint and Scaleway sending mocks
// and a Web Push service mock, every third party a TEST-ONLY mock of its
// published format (`@nidohq/email-mocks`), started as the end-to-end test
// starts them (`tests/support/emailServices.mjs`). `register` enrolls an
// account's alert contact as the wallet does: the vault's attestation
// verified, the contact sealed to it with a Web Push subscription, the
// owner's passkey authorizing it, the emailed code confirming it. The host
// reads the network's transactions for email votes and the controller
// (`chainReads`) for attempt deadlines and reconciliation. `addDevice` adds
// a second device to a contact, `status` reads its devices, and `ack` posts
// a device's signed acknowledgement of a probe, as the wallet's service
// worker does when the probe is tapped.
import { createHash } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CustodianMock, LettermintMock, PushServiceMock, PushUserAgentMock, ScalewayTemMock, nitroTestRoot } from '@nidohq/email-mocks';
import { AlertService, ProcessVault, StellarRpc, accountSigners, chainReads } from '@nidohq/email-alerts';
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
  pushUpdateRequest,
  statusRequest,
} from '@nidohq/email-recovery';
import { xdr } from '@stellar/stellar-sdk';

export class Alerts {
  static async start({ rpcUrl, passphrase, controller, imageRegistry, measurement, apex, guardianWasmHash, probeIntervalMs }) {
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
        ...(probeIntervalMs ? { probeIntervalMs } : {}),
      },
    });
    const host = (startLedger, statePath) =>
      new AlertService(
        {
          rpc,
          controller,
          statePath,
          startLedger,
          signers: (account) => accountSigners(rpc, account, passphrase),
          reads: chainReads(rpc, controller, passphrase, guardianWasmHash),
          log: () => {},
          pageLimit: 100,
          retryBaseMs: 0,
        },
        vault,
      );
    const svc = host((await rpc.call('getLatestLedger', {})).sequence, join(dir, 'host.json'));
    const url = await svc.listen(0);
    return new Alerts({ svc, vault, boot, url, custodians, lettermint, scaleway, push, measurement, passphrase, rpc, host, dir });
  }

  /**
   * A host restarted after an outage whose events left the RPC's
   * retention: it starts reading at `ledger` with a fresh state file (the
   * vault keeps its sealed records), so the missed events are never read
   * and only reconciliation from controller state can find them.
   */
  async restartAfterOutage(ledger) {
    await this.svc.close();
    this.svc = this.host(ledger, join(this.dir, `host-${ledger}.json`));
    this.url = await this.svc.listen(0);
    return this.svc.drain();
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

  /** The vault's attested key, verified as the wallet verifies it. */
  async vaultKey() {
    const nonce = attestationNonce();
    const { attestation } = await this.api(`/v1/attestation?nonce=${bytes.toBase64Url(nonce)}`);
    return attestedVaultKey(bytes.fromBase64Url(attestation), { roots: [nitroTestRoot()], allowedMeasurements: [this.measurement], nonce });
  }

  /** Seal `inner`, have `enrolled`'s owner passkey authorize it, and post it. */
  async authorized(enrolled, vault, inner) {
    const { nonce: vaultNonce } = await this.api('/v1/nonce', { method: 'POST' });
    const prepared = await prepareContactChange(vault, inner, bytes.fromBase64Url(vaultNonce));
    const a = enrolled.owner.assert(prepared.challenge, enrolled.account.rp);
    const body = encodeContactRequest(prepared.finish({ publicKey: enrolled.owner.publicKey, ...a }));
    return this.api('/v1/contact', { method: 'POST', body, headers: { 'content-type': 'application/json' } });
  }

  /** Register and confirm `address` as `enrolled`'s alert contact, with a Web Push device and its device key. */
  async register(enrolled, address) {
    const vault = await this.vaultKey();
    const device = new PushUserAgentMock(this.push);
    const sub = device.subscribe(vault.vapid);
    const accountCode = bigIntToBytes(enrolled.inbox.accountCode, 16);
    const inner = await contactRequest({
      account: enrolled.account.address,
      address,
      accountCode,
      emailGuardian: true,
      push: sub,
      deviceKey: device.deviceKey,
      purposes: PURPOSE_SECURITY_ALERTS,
      consentVersion: 4,
      allowLoopbackPush: true,
    });
    const registered = await this.authorized(enrolled, vault, inner);
    const code = this.sentTo(address).map((m) => m.text?.match(/confirmation code for Nido recovery alerts is (\d{6})/)?.[1]).filter(Boolean).at(-1);
    const conf = await prepareConfirmation(vault, confirmationRequest(enrolled.account.address, inner.contact, code));
    const confirmed = await this.api('/v1/contact', { method: 'POST', body: encodeContactRequest(conf), headers: { 'content-type': 'application/json' } });
    return { registered, confirmed, device, accountCode, contact: inner.contact };
  }

  /** Add a new device to contact `contact` of `enrolled`, with the owner's passkey (the `push` request). */
  async addDevice(enrolled, contact) {
    const vault = await this.vaultKey();
    const device = new PushUserAgentMock(this.push);
    const inner = pushUpdateRequest(enrolled.account.address, contact, device.subscribe(vault.vapid), device.deviceKey, { allowLoopbackPush: true });
    return { device, result: await this.authorized(enrolled, vault, inner) };
  }

  /** `enrolled`'s alert channels, read with the owner's passkey (the `status` request). */
  async status(enrolled) {
    return this.authorized(enrolled, await this.vaultKey(), statusRequest(enrolled.account.address));
  }

  /** What the wallet's service worker posts when `device`'s notification for probe `probe` (base64url) is tapped. */
  async ack(device, probe) {
    const signature = device.acknowledge(bytes.fromBase64Url(probe));
    const r = await fetch(`${this.url}/v1/ack`, { method: 'POST', body: JSON.stringify({ probe, signature: bytes.toBase64Url(signature) }) });
    return r.status;
  }

  /** Every email the sending mocks accepted for `address`. */
  sentTo(address) {
    return [...this.lettermint.sent, ...this.scaleway.sent].filter((m) => m.to.includes(address));
  }

  /** The alerts (not confirmations) that reach the owner at `address`: none when an inbox thief controls it and deletes them. */
  reaching(address, { thiefControls = [] } = {}) {
    if (thiefControls.includes(address)) return [];
    return this.sentTo(address).filter((m) => !/confirmation code/.test(m.text ?? ''));
  }

  /** The decrypted pushes a device received since the last call. */
  static pushes(device) {
    return device.receive().map((x) => JSON.parse(Buffer.from(x.payload).toString('utf8')));
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

