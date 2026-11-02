// The network's target ledger close time as the wallet reads it, and the
// ledger counts it turns wall-clock windows into.

import { describe, expect, it } from 'vitest';
import { xdr } from '@stellar/stellar-sdk';
import type { rpc } from '@stellar/stellar-sdk';
import { EMAIL_ONLY_MIN_DELAY_SECONDS, emailOnlyMinDelayLedgers, ledgerTargetCloseMs, ledgersFor, scpTimingKey } from './ledgerTiming.js';

/** A `getLedgerEntries` answer carrying `ms` as the SCP timing setting. */
function server(ms: number | undefined): Pick<rpc.Server, 'getLedgerEntries'> & { asked: xdr.LedgerKey[] } {
  const asked: xdr.LedgerKey[] = [];
  return {
    asked,
    async getLedgerEntries(...keys: xdr.LedgerKey[]) {
      asked.push(...keys);
      const timing = new xdr.ConfigSettingScpTiming({
        ledgerTargetCloseTimeMilliseconds: ms ?? 0,
        nominationTimeoutInitialMilliseconds: 1000,
        nominationTimeoutIncrementMilliseconds: 1000,
        ballotTimeoutInitialMilliseconds: 1000,
        ballotTimeoutIncrementMilliseconds: 1000,
      });
      const val = xdr.LedgerEntryData.configSetting(xdr.ConfigSettingEntry.configSettingScpTiming(timing));
      return {
        latestLedger: 1,
        entries: ms === undefined ? [] : [{ key: keys[0]!, val, lastModifiedLedgerSeq: 1 }],
      } as unknown as rpc.Api.GetLedgerEntriesResponse;
    },
  };
}

describe('the network target ledger close time', () => {
  it('asks for the SCP timing config setting', async () => {
    const s = server(5_000);
    expect(await ledgerTargetCloseMs(s)).toBe(5_000);
    expect(s.asked.map((k) => k.toXDR('base64'))).toEqual([scpTimingKey().toXDR('base64')]);
    // The key testnet and mainnet RPC echo back for this setting.
    expect(scpTimingKey().toXDR('base64')).toBe('AAAACAAAABA=');
  });

  it('refuses a network without the setting, or a nonsensical value', async () => {
    await expect(ledgerTargetCloseMs(server(undefined))).rejects.toThrow(/no SCP timing setting/);
    await expect(ledgerTargetCloseMs(server(0))).rejects.toThrow(/not a ledger close time/);
  });
});

describe('ledger counts for wall-clock windows', () => {
  it('sizes the email-plus-delay floor to seven days', () => {
    expect(EMAIL_ONLY_MIN_DELAY_SECONDS).toBe(604_800);
    expect(emailOnlyMinDelayLedgers(5_000)).toBe(120_960);
    expect(emailOnlyMinDelayLedgers(4_000)).toBe(151_200);
    expect(emailOnlyMinDelayLedgers(1_000)).toBe(604_800);
  });

  it('rounds up, so the count never lasts less than the window', () => {
    expect(ledgersFor(604_800, 4_096)).toBe(147_657);
    expect(147_657 * 4_096).toBeGreaterThanOrEqual(604_800_000);
    expect(147_656 * 4_096).toBeLessThan(604_800_000);
    expect(ledgersFor(1, 5_000)).toBe(1);
  });
});
