/**
 * Wall-clock time from ledger counts.
 *
 * Perch's recovery delay and statement expiry are ledger counts, and Perch
 * is used unchanged, so a wallet rule stated in days has to pick a ledger
 * count for it. The count depends on the network's target ledger close
 * time, `scp_timing.ledger_target_close_time_milliseconds`, a network
 * configuration setting (CAP-0070) that validators can change by vote:
 * 5,000 ms on testnet and mainnet. The wallet reads it from the network
 * when it builds a recovery member and sizes the count from it, so a lower
 * target never shortens the wall-clock window (docs/email-recovery/spec.md
 * §9.3, §11.1).
 */

import { xdr } from '@stellar/stellar-sdk';
import type { rpc } from '@stellar/stellar-sdk';

/** The shortest delay under which the email vote alone may authorize an
 *  attempt: seven days. */
export const EMAIL_ONLY_MIN_DELAY_SECONDS = 7 * 86_400;

/** The ledger key of the network's SCP timing setting. */
export function scpTimingKey(): xdr.LedgerKey {
  return xdr.LedgerKey.configSetting(
    new xdr.LedgerKeyConfigSetting({ configSettingId: xdr.ConfigSettingId.configSettingScpTiming() }),
  );
}

/** The network's target ledger close time, in milliseconds, read through
 *  Stellar RPC `getLedgerEntries`. Throws when the network does not
 *  publish it. */
export async function ledgerTargetCloseMs(server: Pick<rpc.Server, 'getLedgerEntries'>): Promise<number> {
  const { entries } = await server.getLedgerEntries(scpTimingKey());
  const entry = entries[0];
  if (entry === undefined) throw new Error('the network publishes no SCP timing setting');
  return checkCloseMs(entry.val.configSetting().contractScpTiming().ledgerTargetCloseTimeMilliseconds());
}

function checkCloseMs(ms: number): number {
  if (!Number.isSafeInteger(ms) || ms <= 0) throw new Error(`not a ledger close time: ${ms} ms`);
  return ms;
}

/** The fewest ledgers that last at least `seconds` when ledgers close every
 *  `closeMs` milliseconds. */
export function ledgersFor(seconds: number, closeMs: number): number {
  return Math.ceil((seconds * 1000) / checkCloseMs(closeMs));
}

/** The email-plus-delay floor as a Perch delay: seven days of ledgers at
 *  `closeMs` (120,960 at 5,000 ms). */
export function emailOnlyMinDelayLedgers(closeMs: number): number {
  return ledgersFor(EMAIL_ONLY_MIN_DELAY_SECONDS, closeMs);
}
