/**
 * Entry point of the vault process ([`ProcessVault`] forks it): one
 * request at a time from the host over IPC, one answer each.
 *
 * The NSM here is the TEST-ONLY Nitro mock (`@nidohq/email-mocks`); a
 * deployment binds the enclave's `/dev/nsm` instead, which this repository
 * does not build.
 */
import type { NsmSpec } from '../channel.js';
import type { Nsm } from './custody.js';
import { Vault } from './vault.js';

let vault: Vault | undefined;

async function nsmFor(spec: NsmSpec): Promise<Nsm> {
  if (spec.kind !== 'mock') throw new Error('only the mock NSM is available');
  const mocks = await import('@nidohq/email-mocks');
  return new mocks.NitroHypervisorMock({ chain: spec.chain ?? 'nitro' }).launch(mocks.testImage(spec.image));
}

async function handle(method: string, p: Record<string, unknown>): Promise<unknown> {
  if (method === 'boot') {
    vault = await Vault.boot({
      cfg: p.cfg as never,
      nsm: await nsmFor(p.nsm as NsmSpec),
      ...(p.vaultId ? { vaultId: p.vaultId as Uint8Array } : {}),
      ...(p.state ? { state: p.state as never } : {}),
    });
    return { vaultId: vault.vaultId, hpkePublic: vault.keys.hpkePublic, vapidPublic: vault.keys.vapidPublic };
  }
  if (!vault) throw new Error('vault not booted');
  switch (method) {
    case 'attest':
      return vault.attest(p.nonce as Uint8Array);
    case 'nonce':
      return vault.issueNonce();
    case 'contact':
      return vault.contact(p.req as never, p.chain as never);
    case 'dispatch':
      return vault.dispatch(p as never);
    case 'due':
      return vault.due(p.at as never);
    case 'mature':
      return vault.mature(p.views as never);
    case 'inbound':
      return vault.inbound(p.envelope as Uint8Array);
    case 'mail':
      return vault.mail(p.raw as Uint8Array);
    case 'accounts':
      return vault.accounts();
    case 'watched':
      return vault.watched();
    case 'unwatch':
      return vault.unwatch(p.account as string, p.attemptId as string);
    case 'probe':
      return vault.probe();
    default:
      throw new Error(`unknown method ${method}`);
  }
}

// One request at a time: the vault's state changes in the order requests arrive.
let queue: Promise<void> = Promise.resolve();
process.on('message', (m: { id: number; method: string; params: Record<string, unknown> }) => {
  queue = queue.then(() =>
    handle(m.method, m.params).then(
      (result) => void process.send!({ id: m.id, result }),
      (e: unknown) => void process.send!({ id: m.id, error: e instanceof Error ? e.message : String(e) }),
    ),
  );
});
