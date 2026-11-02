/**
 * Perch controller events and the alert each one triggers
 * (`docs/email-recovery/spec.md` §10): topic 0 is the event name in snake
 * case, topic 1 the account, and the data is the event struct's remaining
 * fields as a map (`#[contractevent]`, `perch-recovery/src/contract.rs`).
 */
import { type AlertSubject, bytes, contractIdFromStrkey } from '@nidohq/email-recovery';
import { Address, scValToNative, xdr } from '@stellar/stellar-sdk';

export type PerchEventName =
  | 'attempt_begun'
  | 'attempt_authorized'
  | 'attempt_invalidated'
  | 'attempt_cancelled'
  | 'recovery_completed'
  | 'epoch_advanced'
  | 'change_evidence_recorded';

/** `required` goes to every channel, `informational` and `rate-limited` to email only. */
export type AlertClass = 'required' | 'informational' | 'rate-limited' | 'none';

/**
 * The §10 table. `attempt_begun` sends nothing by default: anyone can open
 * an attempt, so any notice of openings is one a stranger can trigger, and
 * the wallet lists open attempts itself. A service configured with
 * `emailOnAttemptBegun` emails it, `rate-limited`.
 */
export const ALERTS: Record<PerchEventName, AlertClass> = {
  attempt_authorized: 'required',
  recovery_completed: 'required',
  epoch_advanced: 'required',
  attempt_cancelled: 'informational',
  change_evidence_recorded: 'informational',
  attempt_begun: 'none',
  attempt_invalidated: 'none',
};

/**
 * What an alert is about: a controller event, or one no event carries. The
 * host finds the email guardian's votes in the network's transactions
 * (spec §10.2): on an attempt that is still collecting
 * (`email_vote_recorded`), on an attempt's cancellation
 * (`email_cancel_recorded`), and on a change to the recovery settings or
 * an upgrade (`email_change_recorded`).
 */
export type AlertName =
  | Exclude<PerchEventName, 'attempt_invalidated'>
  | 'email_vote_recorded'
  | 'email_cancel_recorded'
  | 'email_change_recorded';

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

/**
 * The id an alert is delivered under: what it is about (`name:account:attempt`
 * or `:epoch`), not the RPC event that reported it, so an alert found by
 * reconciling controller state and the same alert from the event stream
 * are one delivery. Attempt ids and epochs never repeat per account.
 * `change_evidence_recorded`, emitted once per recorded approval of the
 * same change, keeps its RPC event id. `email_change_recorded` is about the
 * change's digest, which the email guardian approves at most once.
 */
export function alertEventId(name: AlertName, account: string, subject: AlertSubject, rpcEventId?: string): string {
  if (name === 'change_evidence_recorded' && rpcEventId) return rpcEventId;
  const key =
    subject.kind === 'attempt' ? subject.attemptId.toString() : subject.kind === 'epoch' ? subject.epoch.toString() : bytes.toHex(subject.digest);
  return `${name}:${account}:${key}`;
}
