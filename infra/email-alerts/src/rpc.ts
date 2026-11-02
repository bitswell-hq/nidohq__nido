/**
 * Stellar RPC as the host uses it: `getEvents` for the controller's events
 * (filtered only by contract, so the query never singles out an account),
 * `simulateTransaction` to read contract views (an account's installed
 * rules, a watched attempt), and `getLedgerEntries` for a contract's
 * instance (its wasm hash). Request and result shapes follow Stellar RPC's
 * OpenRPC description.
 */
import {
  Account,
  Address,
  Contract,
  Keypair,
  type Networks,
  TransactionBuilder,
  nativeToScVal,
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

/** What the host reads of a watched attempt (Perch's `Attempt`, `perch-recovery/src/types.rs`). */
export interface AttemptView {
  /** `Collecting`, `Authorized`, `Completed`, `Cancelled`, or `Invalidated`. */
  state: string;
  /** Distinct enrolled guardians that approved the initiation statement. */
  guardians: string[];
  /** The last ledger initiation evidence is accepted. */
  evidenceDeadline: number;
}

/** The controller's `attempt(account, attempt_id)` view, or `undefined` when there is no such attempt. */
export async function attemptView(
  rpc: StellarRpc,
  controller: string,
  account: string,
  attemptId: bigint,
  networkPassphrase: string,
): Promise<AttemptView | undefined> {
  const v = (await rpc.view(
    controller,
    'attempt',
    [new Address(account).toScVal(), nativeToScVal(attemptId, { type: 'u64' })],
    networkPassphrase,
  )) as { state: unknown; guardians: unknown[]; evidence_deadline: unknown } | null | undefined;
  if (!v) return undefined;
  return {
    state: String(Array.isArray(v.state) ? v.state[0] : v.state),
    guardians: v.guardians.map(String),
    evidenceDeadline: Number(v.evidence_deadline),
  };
}

/** The wasm hash (hex) a contract instance runs, from its instance entry; `undefined` if none. */
export async function contractWasmHash(rpc: StellarRpc, contract: string): Promise<string | undefined> {
  const key = xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: new Address(contract).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
    }),
  );
  const r = await rpc.call<{ entries?: { xdr: string }[] | null }>('getLedgerEntries', { keys: [key.toXDR('base64')] });
  const entry = r.entries?.[0];
  if (!entry) return undefined;
  const exe = xdr.LedgerEntryData.fromXDR(entry.xdr, 'base64').contractData().val().instance().executable();
  return exe.switch() === xdr.ContractExecutableType.contractExecutableWasm() ? Buffer.from(exe.wasmHash()).toString('hex') : undefined;
}

/** The controller reads the host makes for email votes and reconciliation (spec §10.2). */
export interface ChainReads {
  attempt(account: string, attemptId: bigint): Promise<AttemptView | undefined>;
  /** The account's authorized attempt, from the controller's `activity_gate`. */
  authorizedAttempt(account: string): Promise<bigint | undefined>;
  /** The id the account's next attempt will get (`next_attempt_id`). */
  nextAttemptId(account: string): Promise<bigint>;
  /** Whether a guardian runs the email guardian's wasm. */
  isEmailGuardian(address: string): Promise<boolean>;
}

/** [`ChainReads`] through Stellar RPC, for `controller` on the network `networkPassphrase`. */
export function chainReads(rpc: StellarRpc, controller: string, networkPassphrase: string, emailGuardianWasmHash: string): ChainReads {
  const acct = (a: string) => new Address(a).toScVal();
  return {
    attempt: (account, attemptId) => attemptView(rpc, controller, account, attemptId, networkPassphrase),
    async authorizedAttempt(account) {
      const g = (await rpc.view(controller, 'activity_gate', [acct(account)], networkPassphrase)) as { authorized_attempt?: unknown } | null;
      return g?.authorized_attempt === undefined || g.authorized_attempt === null ? undefined : BigInt(g.authorized_attempt as bigint);
    },
    async nextAttemptId(account) {
      return BigInt((await rpc.view(controller, 'next_attempt_id', [acct(account)], networkPassphrase)) as bigint);
    },
    async isEmailGuardian(address) {
      return address.startsWith('C') && (await contractWasmHash(rpc, address)) === emailGuardianWasmHash;
    },
  };
}
