/**
 * Stellar RPC as the host uses it: `getEvents` for the controller's events
 * (filtered only by contract, so the query never singles out an account),
 * and `simulateTransaction` to read contract views (an account's installed
 * rules). Request and result shapes follow Stellar RPC's OpenRPC
 * description.
 */
import {
  Account,
  Contract,
  Keypair,
  type Networks,
  TransactionBuilder,
  scValToNative,
  xdr,
} from '@stellar/stellar-sdk';
import type { RpcEvent } from './events.js';

export interface GetEventsResult {
  events: RpcEvent[];
  latestLedger: number;
  oldestLedger?: number;
  cursor: string;
}

export class RpcError extends Error {
  constructor(
    readonly code: number | undefined,
    message: string,
  ) {
    super(message);
  }
}

export class StellarRpc {
  private id = 0;

  constructor(
    readonly url: string,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  async call<T>(method: string, params: unknown): Promise<T> {
    const r = await this.fetchImpl(this.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++this.id, method, params }),
      signal: AbortSignal.timeout(20_000),
    });
    if (!r.ok) throw new RpcError(undefined, `RPC HTTP ${r.status}`);
    const b = (await r.json()) as { result?: T; error?: { code: number; message: string } };
    if (b.error) throw new RpcError(b.error.code, b.error.message);
    return b.result as T;
  }

  getEvents(contractId: string, from: { cursor: string } | { startLedger: number }, limit = 200): Promise<GetEventsResult> {
    return this.call('getEvents', {
      ...('startLedger' in from ? { startLedger: from.startLedger } : {}),
      filters: [{ type: 'contract', contractIds: [contractId] }],
      pagination: { ...('cursor' in from ? { cursor: from.cursor } : {}), limit },
    });
  }

  /** Simulate a read-only call and return its native value. */
  async view(contractId: string, fn: string, args: xdr.ScVal[], networkPassphrase: Networks | string): Promise<unknown> {
    const source = new Account(Keypair.random().publicKey(), '0');
    const tx = new TransactionBuilder(source, { fee: '100', networkPassphrase })
      .addOperation(new Contract(contractId).call(fn, ...args))
      .setTimeout(30)
      .build();
    const r = await this.call<{ results?: { xdr: string }[]; error?: string }>('simulateTransaction', {
      transaction: tx.toXDR(),
    });
    if (r.error || !r.results?.[0]) throw new RpcError(undefined, `simulation failed: ${r.error ?? 'no result'}`);
    return scValToNative(xdr.ScVal.fromXDR(r.results[0].xdr, 'base64'));
  }
}

const WEBAUTHN_KEY_LEN = 65;

/**
 * The account's administrative passkeys: the 65-byte P-256 keys of every
 * `External` signer on a rule that covers calls to the account itself (a
 * `Default` rule, or a `CallContract` rule naming the account), other than
 * the recovery rule, read from Perch's `installed_rules()` view. These are
 * the keys that could reconfigure the account's recovery, so they are the
 * keys that may change its alert contacts.
 */
export async function accountSigners(rpc: StellarRpc, account: string, networkPassphrase: string): Promise<Uint8Array[]> {
  const rules = (await rpc.view(account, 'installed_rules', [], networkPassphrase)) as {
    recovery: boolean;
    context_type: unknown[];
    signers: unknown[][];
  }[];
  const keys = new Map<string, Uint8Array>();
  for (const rule of rules) {
    const [kind, target] = rule.context_type;
    if (rule.recovery || !(kind === 'Default' || (kind === 'CallContract' && target === account))) continue;
    for (const s of rule.signers) {
      if (s[0] !== 'External') continue;
      const key = s[2] as Uint8Array;
      if (key.length === WEBAUTHN_KEY_LEN && key[0] === 4) keys.set(Buffer.from(key).toString('hex'), new Uint8Array(key));
    }
  }
  return [...keys.values()];
}

