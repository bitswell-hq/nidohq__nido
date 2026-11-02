/**
 * The mocked world the alert tests run in: the chain record of
 * `fixtures/chain.json` (recorded on Nido's integration-test host by
 * `crates/integration-tests/tests/it/email_alerts.rs`) served through a
 * Stellar RPC mock, three custodians reading the enclave-image registry
 * from those events, both EU sending services, a push service, and a
 * wallet that verifies attestations and has the account owner's passkey.
 */
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  AuthenticatorMock,
  CustodianMock,
  LettermintMock,
  PushServiceMock,
  PushUserAgentMock,
  type RpcEvent,
  ScalewayTemMock,
  StellarRpcMock,
  ledgerCloseTime,
  nitroTestRoot,
} from '@nidohq/email-mocks';
import {
  PURPOSE_SECURITY_ALERTS,
  attestationNonce,
  attestedVaultKey,
  bytes,
  confirmationRequest,
  contactRequest,
  encodeContactRequest,
  prepareConfirmation,
  prepareContactChange,
  pushUpdateRequest,
  removalRequest,
  statusRequest,
  type VaultKey,
} from '@nidohq/email-recovery';
import { TransactionBuilder } from '@stellar/stellar-sdk';
import { RegistryEventsView } from '../src/registryView.js';
import { StellarRpc } from '../src/rpc.js';
import type { ContactResult, VaultConfig } from '../src/vault/vault.js';

export const IMAGE = 'nido-alert-vault-v1';
export const RP = { rpId: 'nido.test', origins: ['https://nido.test'] };

export interface ChainFixture {
  networkPassphrase: string;
  controller: string;
  registry: string;
  account: string;
  measurement: string;
  ownerPrivateKey: string;
  ownerPublicKey: string;
  newOwnerPublicKey: string;
  attemptId: string;
  authorizedAtLedger: number;
  setupEvents: number;
  events: RpcEvent[];
  installedRules: { before: string; after: string };
}

export function loadFixture(): ChainFixture {
  const f = JSON.parse(readFileSync(new URL('./fixtures/chain.json', import.meta.url), 'utf8')) as ChainFixture;
  f.events = f.events.map((e) => ({ ...e, ledgerClosedAt: ledgerCloseTime(e.ledger).toISOString() }));
  return f;
}

export const networkId = (passphrase: string) => new Uint8Array(createHash('sha256').update(passphrase).digest());

export interface World {
  fixture: ChainFixture;
  rpcMock: StellarRpcMock;
  rpc: StellarRpc;
  /** Which recorded `installed_rules()` the account answers with. */
  rules: { stage: 'before' | 'after' };
  custodians: CustodianMock[];
  lettermint: LettermintMock;
  scaleway: ScalewayTemMock;
  push: PushServiceMock;
  cfg: VaultConfig;
  dir: string;
  close(): Promise<void>;
}

/** Start every mock; the RPC serves the fixture's first `served` events. */
export async function startWorld(served?: number): Promise<World> {
  const fixture = loadFixture();
  const rpcMock = new StellarRpcMock(fixture.events.slice(0, served ?? fixture.events.length));
  const rules = { stage: 'before' as 'before' | 'after' };
  rpcMock.onSimulate = (tx) => {
    const t = TransactionBuilder.fromXDR(tx, fixture.networkPassphrase);
    const call = (t as { operations: { func: { invokeContract(): { functionName(): Buffer } } }[] }).operations[0]!.func.invokeContract();
    if (call.functionName().toString() !== 'installed_rules') throw new Error('unexpected simulation');
    return fixture.installedRules[rules.stage];
  };
  const rpcUrl = await rpcMock.listen();
  const rpc = new StellarRpc(rpcUrl);
  const view = new RegistryEventsView(rpc, fixture.registry, rpcMock.oldestLedger);
  const custodians = await Promise.all(
    [0, 1, 2].map((i) => CustodianMock.create({ name: `custodian-${i}`, roots: [nitroTestRoot()], registry: view })),
  );
  const custodianUrls = await Promise.all(custodians.map((c) => c.listen()));
  const lettermint = new LettermintMock();
  const scaleway = new ScalewayTemMock();
  const push = new PushServiceMock();
  await Promise.all([lettermint.listen(), scaleway.listen(), push.listen()]);
  const cfg: VaultConfig = {
    networkId: networkId(fixture.networkPassphrase),
    rp: RP,
    walletOrigin: 'https://nido.test',
    sending: {
      from: { email: 'alerts@alerts.nido.test', name: 'Nido' },
      lettermint: { url: lettermint.url, token: 'lm_test_only_token' },
      scaleway: { url: scaleway.url, token: 'scw-test-only-secret-key', projectId: scaleway.projectId },
    },
    pushSubject: 'mailto:alerts@nido.test',
    allowLoopbackPush: true,
    custodians: custodians.map((c, i) => ({ url: custodianUrls[i]!, publicKey: c.publicKey })),
  };
  return {
    fixture,
    rpcMock,
    rpc,
    rules,
    custodians,
    lettermint,
    scaleway,
    push,
    cfg,
    dir: mkdtempSync(join(tmpdir(), 'nido-alerts-')),
    async close() {
      await Promise.all([rpcMock.close(), lettermint.close(), scaleway.close(), push.close(), ...custodians.map((c) => c.close())]);
    },
  };
}

/** What a wallet talks to: the service's API, in-process or over HTTP. */
export interface WalletApi {
  attestation(nonce: Uint8Array): Promise<Uint8Array>;
  nonce(): Promise<Uint8Array>;
  contact(body: string): Promise<ContactResult>;
}

export function httpApi(base: string): WalletApi {
  return {
    async attestation(nonce) {
      const r = await fetch(`${base}/v1/attestation?nonce=${bytes.toBase64Url(nonce)}`);
      return bytes.fromBase64Url(((await r.json()) as { attestation: string }).attestation);
    },
    async nonce() {
      const r = await fetch(`${base}/v1/nonce`, { method: 'POST' });
      return bytes.fromBase64Url(((await r.json()) as { nonce: string }).nonce);
    },
    async contact(body) {
      const r = await fetch(`${base}/v1/contact`, { method: 'POST', body, headers: { 'content-type': 'application/json' } });
      return (await r.json()) as ContactResult;
    },
  };
}

/** The wallet: account owner's passkey, `account_code`, a push subscription. */
export class Wallet {
  readonly accountCode = new Uint8Array(randomBytes(16));
  readonly passkey: AuthenticatorMock;
  readonly device: PushUserAgentMock;
  vault?: VaultKey;
  /** The size of the last attestation document fetched. */
  attestationBytes = 0;
  /** The size of the last request body sent. */
  requestBytes = 0;

  constructor(
    readonly w: World,
    readonly api: WalletApi,
    privateKey = bytes.fromHex(w.fixture.ownerPrivateKey),
  ) {
    this.passkey = new AuthenticatorMock(RP.rpId, RP.origins[0]!, privateKey);
    this.device = new PushUserAgentMock(w.push);
  }

  async attest(): Promise<VaultKey> {
    const nonce = attestationNonce();
    const att = await this.api.attestation(nonce);
    this.attestationBytes = att.length;
    this.vault = await attestedVaultKey(att, {
      roots: [nitroTestRoot()],
      allowedMeasurements: [this.w.fixture.measurement],
      nonce,
    });
    return this.vault;
  }

  /** Register (or, with `replaces`, replace) a contact; returns its id and the vault's answer. */
  async contact(
    address: string,
    opts: { replaces?: Uint8Array; push?: boolean; emailGuardian?: boolean; account?: string } = {},
  ): Promise<{ id: Uint8Array; result: ContactResult }> {
    const vault = this.vault ?? (await this.attest());
    const sub = opts.push === false ? undefined : this.device.subscribe(vault.vapid);
    const inner = await contactRequest(
      {
        account: opts.account ?? this.w.fixture.account,
        address,
        accountCode: this.accountCode,
        emailGuardian: opts.emailGuardian ?? true,
        ...(sub ? { push: sub } : {}),
        purposes: PURPOSE_SECURITY_ALERTS,
        consentVersion: 1,
        allowLoopbackPush: true,
      },
      opts.replaces,
    );
    const prepared = await prepareContactChange(vault, inner as never, await this.api.nonce());
    const body = encodeContactRequest(prepared.finish({ publicKey: this.passkey.publicKey, ...this.passkey.assert(prepared.challenge) }));
    this.requestBytes = body.length;
    return { id: inner.contact, result: await this.api.contact(body) };
  }

  /** Read the account's alert channels (a passkey-authorized `status`). */
  async status(): Promise<ContactResult> {
    const vault = this.vault ?? (await this.attest());
    const prepared = await prepareContactChange(vault, statusRequest(this.w.fixture.account) as never, await this.api.nonce());
    return this.api.contact(encodeContactRequest(prepared.finish({ publicKey: this.passkey.publicKey, ...this.passkey.assert(prepared.challenge) })));
  }

  /** Give contact `id` a new subscription from `device` (a passkey-authorized `push`). */
  async pushUpdate(id: Uint8Array, device: PushUserAgentMock): Promise<ContactResult> {
    const vault = this.vault ?? (await this.attest());
    const sub = device.subscribe(vault.vapid);
    const req = pushUpdateRequest(this.w.fixture.account, id, sub, { allowLoopbackPush: true });
    const prepared = await prepareContactChange(vault, req as never, await this.api.nonce());
    return this.api.contact(encodeContactRequest(prepared.finish({ publicKey: this.passkey.publicKey, ...this.passkey.assert(prepared.challenge) })));
  }

  async remove(id: Uint8Array): Promise<ContactResult> {
    const vault = this.vault ?? (await this.attest());
    const prepared = await prepareContactChange(vault, removalRequest(this.w.fixture.account, id) as never, await this.api.nonce());
    return this.api.contact(encodeContactRequest(prepared.finish({ publicKey: this.passkey.publicKey, ...this.passkey.assert(prepared.challenge) })));
  }

  /** Confirm with the code the vault emailed to `address`. */
  async confirm(id: Uint8Array, address: string): Promise<ContactResult> {
    const vault = this.vault ?? (await this.attest());
    const code = confirmationCode(this.w, address);
    const req = await prepareConfirmation(vault, confirmationRequest(this.w.fixture.account, id, code) as never);
    return this.api.contact(encodeContactRequest(req));
  }
}

/** The 6-digit code in the latest confirmation email to `address`. */
export function confirmationCode(w: World, address: string): string {
  const mails = [...w.lettermint.sent, ...w.scaleway.sent].filter((m) => m.to.includes(address) && /confirmation code/.test(m.text ?? ''));
  const m = mails.at(-1)?.text?.match(/confirmation code for Nido recovery alerts is (\d{6})/);
  if (!m) throw new Error(`no confirmation email to ${address}`);
  return m[1]!;
}

/** Every email to `address` that is not a confirmation. */
export const alertsTo = (w: World, address: string) =>
  [...w.lettermint.sent, ...w.scaleway.sent].filter((m) => m.to.includes(address) && !/confirmation code/.test(m.text ?? ''));
