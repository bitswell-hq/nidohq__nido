/**
 * Perch controller events and the alert each one triggers
 * (`docs/email-recovery/spec.md` §10): topic 0 is the event name in snake
 * case, topic 1 the account, and the data is the event struct's remaining
 * fields as a map (`#[contractevent]`, `perch-recovery/src/contract.rs`).
 */
import { type AlertSubject, contractIdFromStrkey } from '@nidohq/email-recovery';
import { Address, scValToNative, xdr } from '@stellar/stellar-sdk';

export type PerchEventName =
  | 'attempt_begun'
  | 'attempt_authorized'
  | 'attempt_invalidated'
  | 'attempt_cancelled'
  | 'recovery_completed'
  | 'epoch_advanced'
  | 'change_evidence_recorded';

export type AlertClass = 'required' | 'informational' | 'rate-limited' | 'none';

/** The §10 table. `required` goes to every channel; the others to email only. */
export const ALERTS: Record<PerchEventName, AlertClass> = {
  attempt_authorized: 'required',
  recovery_completed: 'required',
  epoch_advanced: 'required',
  attempt_cancelled: 'informational',
  change_evidence_recorded: 'informational',
  attempt_begun: 'rate-limited',
  attempt_invalidated: 'none',
};

/** One event as Stellar RPC's `getEvents` returns it. */
export interface RpcEvent {
  type: string;
  ledger: number;
  ledgerClosedAt: string;
  contractId: string;
  id: string;
  topic: string[];
  value: string;
  txHash?: string;
}

export interface PerchEvent {
  id: string;
  ledger: number;
  /** Ledger close time, ms since the epoch. */
  closedAt: number;
  name: PerchEventName;
  /** The emitting controller's contract id. */
  controller: Uint8Array;
  /** The account (topic 1). */
  account: Uint8Array;
  accountStrkey: string;
  data: Record<string, unknown>;
}

/** Decodes a controller event; `undefined` for anything else (other names, malformed). */
export function decodePerchEvent(e: RpcEvent): PerchEvent | undefined {
  if (e.type !== 'contract' || e.topic.length !== 2) return undefined;
  try {
    const t0 = xdr.ScVal.fromXDR(e.topic[0]!, 'base64');
    if (t0.switch() !== xdr.ScValType.scvSymbol()) return undefined;
    const name = t0.sym().toString() as PerchEventName;
    if (!(name in ALERTS)) return undefined;
    const account = Address.fromScVal(xdr.ScVal.fromXDR(e.topic[1]!, 'base64')).toString();
    if (!account.startsWith('C')) return undefined;
    const data = scValToNative(xdr.ScVal.fromXDR(e.value, 'base64')) as Record<string, unknown>;
    if (typeof data !== 'object' || data === null) return undefined;
    return {
      id: e.id,
      ledger: e.ledger,
      closedAt: Date.parse(e.ledgerClosedAt),
      name,
      controller: contractIdFromStrkey(e.contractId),
      account: contractIdFromStrkey(account),
      accountStrkey: account,
      data,
    };
  } catch {
    return undefined;
  }
}

/** What the alert is about, for its verification code (spec §10.1). */
export function alertSubject(ev: PerchEvent): AlertSubject {
  switch (ev.name) {
    case 'epoch_advanced':
      return { kind: 'epoch', epoch: BigInt(ev.data.epoch as bigint) };
    case 'change_evidence_recorded':
      return { kind: 'change', digest: new Uint8Array(ev.data.digest as Uint8Array) };
    default:
      return { kind: 'attempt', attemptId: BigInt(ev.data.attempt_id as bigint) };
  }
}
