/**
 * How the host talks to the vault. In production the vault is a Nitro
 * enclave reached over vsock; here it is either an object in the same
 * process (unit tests) or a separate Node process reached over IPC
 * ([`ProcessVault`]), which keeps the address out of the host process
 * entirely. Every message crossing the boundary is recorded in
 * `transcript`, so tests can show what the host ever held.
 */
import { type ChildProcess, fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import type { ContactRequest } from '@nidohq/email-recovery';
import type { InboundResult } from './vault/inbound.js';
import type {
  ChainTime,
  ChainView,
  ContactResult,
  DispatchRequest,
  SealedState,
  Vault,
  VaultConfig,
  Writes,
} from './vault/vault.js';

export interface BootInfo {
  vaultId: Uint8Array;
  hpkePublic: Uint8Array;
  vapidPublic: Uint8Array;
}

/** Which NSM the vault process uses. Only the TEST-ONLY mock exists here. */
export type NsmSpec = { kind: 'mock'; image: string; chain?: 'nitro' | 'rogue' };

export interface VaultApi {
  attest(nonce: Uint8Array): Promise<Uint8Array>;
  nonce(): Promise<Uint8Array>;
  contact(req: ContactRequest, chain: ChainView): Promise<{ result: ContactResult; writes: Writes }>;
  dispatch(ev: DispatchRequest): Promise<{ status: 'done' | 'retry'; writes: Writes }>;
  due(at: ChainTime): Promise<string[]>;
  mature(views: Record<string, ChainView>): Promise<{ applied: string[]; dropped: string[]; postponed: string[]; writes: Writes }>;
  /** A browser's sealed inbound registration (spec §4.6). */
  inbound(envelope: Uint8Array): Promise<InboundResult>;
  /** Accounts with an active contact, to reconcile from controller state (spec §10.2). */
  accounts(): Promise<string[]>;
  /** Probe the push subscriptions that are due (spec §10.6). */
  probe(): Promise<{ probed: number; lapsed: number; unacknowledged: number; writes: Writes }>;
  /** A device's signed acknowledgement of a probe (spec §10.6). */
  ack(probeId: Uint8Array, signature: Uint8Array): Promise<{ ok: boolean; writes: Writes }>;
  close(): Promise<void>;
}

export class InProcessVault implements VaultApi {
  constructor(readonly vault: Vault) {}
  attest(nonce: Uint8Array) {
    return this.vault.attest(nonce);
  }
  async nonce() {
    return this.vault.issueNonce();
  }
  contact(req: ContactRequest, chain: ChainView) {
    return this.vault.contact(req, chain);
  }
  dispatch(ev: DispatchRequest) {
    return this.vault.dispatch(ev);
  }
  async due(at: ChainTime) {
    return this.vault.due(at);
  }
  mature(views: Record<string, ChainView>) {
    return this.vault.mature(views);
  }
  inbound(envelope: Uint8Array) {
    return this.vault.inbound(envelope);
  }
  async accounts() {
    return this.vault.accounts();
  }
  probe() {
    return this.vault.probe();
  }
  ack(probeId: Uint8Array, signature: Uint8Array) {
    return this.vault.ack(probeId, signature);
  }
  async close() {}
}

export interface TranscriptEntry {
  direction: 'to-vault' | 'from-vault';
  message: unknown;
}

/** The vault in its own process (`dist/vault/main.js`), over structured-clone IPC. */
export class ProcessVault implements VaultApi {
  readonly transcript: TranscriptEntry[] = [];
  /** The vault process's own stdout and stderr (an enclave's console). */
  readonly console: string[] = [];
  private next = 0;
  private readonly pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();

  private constructor(private readonly child: ChildProcess) {
    child.on('message', (m: { id: number; result?: unknown; error?: string }) => {
      this.transcript.push({ direction: 'from-vault', message: m });
      const p = this.pending.get(m.id);
      if (!p) return;
      this.pending.delete(m.id);
      if (m.error !== undefined) p.reject(new Error(m.error));
      else p.resolve(m.result);
    });
    child.stdout?.on('data', (d: Buffer) => this.console.push(d.toString('utf8')));
    child.stderr?.on('data', (d: Buffer) => this.console.push(d.toString('utf8')));
    child.on('exit', (code, signal) => {
      const why = `vault process exited (${signal ?? code}): ${this.console.join('').slice(-2000)}`;
      for (const p of this.pending.values()) p.reject(new Error(why));
      this.pending.clear();
    });
  }

  static async start(opts: {
    cfg: VaultConfig;
    nsm: NsmSpec;
    vaultId?: Uint8Array;
    state?: SealedState;
  }): Promise<{ vault: ProcessVault; boot: BootInfo }> {
    const main = fileURLToPath(new URL('./vault/main.js', import.meta.url));
    const child = fork(main, [], { execArgv: [], serialization: 'advanced', stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
    const v = new ProcessVault(child);
    const boot = (await v.request('boot', opts)) as BootInfo;
    return { vault: v, boot };
  }

  private request(method: string, params: unknown): Promise<unknown> {
    const id = ++this.next;
    const message = { id, method, params };
    this.transcript.push({ direction: 'to-vault', message });
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.child.send(message);
    });
  }

  attest(nonce: Uint8Array) {
    return this.request('attest', { nonce }) as Promise<Uint8Array>;
  }
  nonce() {
    return this.request('nonce', {}) as Promise<Uint8Array>;
  }
  contact(req: ContactRequest, chain: ChainView) {
    return this.request('contact', { req, chain }) as Promise<{ result: ContactResult; writes: Writes }>;
  }
  dispatch(ev: DispatchRequest) {
    return this.request('dispatch', ev) as Promise<{ status: 'done' | 'retry'; writes: Writes }>;
  }
  due(at: ChainTime) {
    return this.request('due', { at }) as Promise<string[]>;
  }
  mature(views: Record<string, ChainView>) {
    return this.request('mature', { views }) as Promise<{ applied: string[]; dropped: string[]; postponed: string[]; writes: Writes }>;
  }
  inbound(envelope: Uint8Array) {
    return this.request('inbound', { envelope }) as Promise<InboundResult>;
  }
  accounts() {
    return this.request('accounts', {}) as Promise<string[]>;
  }
  probe() {
    return this.request('probe', {}) as Promise<{ probed: number; lapsed: number; unacknowledged: number; writes: Writes }>;
  }
  ack(probeId: Uint8Array, signature: Uint8Array) {
    return this.request('ack', { probeId, signature }) as Promise<{ ok: boolean; writes: Writes }>;
  }
  /**
   * Mail for `RECOVERY_INBOX`, handed to the vault's MX. In a deployment the
   * MX runs in the enclave and SMTP's TLS terminates there, so the host
   * never holds these octets; here they cross the test's own channel to the
   * vault process, and the host only receives the sealed copies.
   */
  mail(raw: Uint8Array) {
    return this.request('mail', { raw }) as Promise<Record<string, Uint8Array>>;
  }
  async close() {
    this.child.kill();
    await new Promise((r) => (this.child.exitCode !== null ? r(undefined) : this.child.once('exit', r)));
  }
}
