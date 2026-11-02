/**
 * The host's durable state: one JSON file, replaced atomically (write a
 * temporary file, fsync it, rename over the old one, fsync the directory),
 * so a crash leaves either the previous state or the new one.
 */
import { closeSync, fsyncSync, openSync, readFileSync, renameSync, writeSync } from 'node:fs';
import { dirname } from 'node:path';

export interface HostState {
  v: 1;
  /** The vault this host serves (hex), once genesis has run. */
  vaultId?: string;
  /** Stellar RPC `getEvents` cursor: every event up to it is handled. */
  cursor?: string;
  /** Where to start when there is no cursor yet. */
  startLedger: number;
  /** Stellar RPC `getTransactions` cursor: every transaction up to it was read for votes. */
  txCursor?: string;
  /** Where the transaction scan starts when there is no `txCursor` (default `startLedger`). */
  txStartLedger?: number;
  /** Events after the cursor already handled (cleared when the cursor moves). */
  handled: string[];
  /** Events whose alert is waiting for a retry. */
  retries: Record<string, { request: SerializedDispatch; attempts: number; nextAt: number }>;
  /** `attempt_begun` rate limit per account: last sent (ledger close ms), suppressed since. */
  begun: Record<string, { lastSent: number; suppressed: number }>;
  /** Authorized attempts per account, from `attempt_authorized` until it ends. */
  authorized: Record<string, { attemptId: string; expiresAt: number }>;
  latestLedger: number;
  /** The latest ledger's close time, Unix seconds, as `getEvents` reports it
   *  (`latestLedgerCloseTime`); `0` until the first page, and in state files
   *  that predate the field. */
  latestCloseTime?: number;
  /** The vault's sealed blobs (base64): records under their lookup, and the delivery log. */
  sealed: { records: Record<string, string>; deliveries?: string };
  /** Inbound mail the vault sealed to a browser's device key (base64), by inbox id, with when it was stored. */
  inbound?: Record<string, { at: number; messages: string[] }>;
}

/** A dispatch request with bytes as hex and bigints as strings, for JSON. */
export interface SerializedDispatch {
  eventId: string;
  name: string;
  class: string;
  controller: string;
  account: string;
  subject: { kind: string; value: string };
  suppressed?: number;
}

export function emptyState(startLedger: number): HostState {
  return { v: 1, startLedger, handled: [], retries: {}, begun: {}, authorized: {}, latestLedger: 0, latestCloseTime: 0, sealed: { records: {} } };
}

export function loadState(path: string, startLedger: number): HostState {
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as HostState;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return emptyState(startLedger);
    throw e;
  }
}

export function saveState(path: string, state: HostState): void {
  const tmp = `${path}.tmp`;
  const fd = openSync(tmp, 'w');
  try {
    writeSync(fd, JSON.stringify(state));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
  const dir = openSync(dirname(path), 'r');
  try {
    fsyncSync(dir);
  } finally {
    closeSync(dir);
  }
}
