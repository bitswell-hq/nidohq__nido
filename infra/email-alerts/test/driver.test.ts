/**
 * The host's poll driver (spec §10.2, `src/driver.ts`): it polls again at
 * once while behind, waits one interval once caught up or when a poll read
 * nothing, backs off exponentially on failures, raises one alarm once polls
 * have failed for five minutes, and stops when aborted. The service is a
 * script of poll outcomes; the clock and the sleep are the test's.
 */
import { describe, expect, it } from 'vitest';
import { BACKOFF_MS, FAILING_ALARM_MS, MAX_BACKOFF_MS, POLL_INTERVAL_MS, nextPollIn, runWatcher, sleep } from '../src/driver.js';
import type { PollReport } from '../src/service.js';

const report = (o: Partial<PollReport>): PollReport => ({
  caughtUp: false,
  events: 0,
  dispatched: 0,
  suppressed: 0,
  retriesQueued: 0,
  retriesDone: 0,
  matured: { applied: [], dropped: [], postponed: [] },
  transactions: 0,
  txPages: 0,
  votes: 0,
  lagLedgers: 0,
  lag: { events: 0, transactions: 0 },
  probes: { probed: 0, lapsed: 0, unacknowledged: 0 },
  latencyMs: {},
  ...o,
});

/** Run the driver over `script` (a report, or an error to throw), recording each wait. */
async function drive(script: (PollReport | Error)[]) {
  const stop = new AbortController();
  let clock = 0;
  const waits: number[] = [];
  const alarms: string[] = [];
  let i = 0;
  await runWatcher(
    {
      async pollOnce() {
        const step = script[i++];
        if (i >= script.length) stop.abort();
        if (step instanceof Error) throw step;
        return step!;
      },
      raise(reason: string) {
        alarms.push(reason);
        return reason;
      },
    },
    {
      signal: stop.signal,
      now: () => clock,
      sleep: async (ms) => {
        waits.push(ms);
        clock += ms;
      },
    },
  );
  return { waits, alarms, polls: i };
}

describe('the poll driver', () => {
  it('polls again at once while behind and waits one ledger once caught up', async () => {
    const behind = report({ transactions: 200, txPages: 8 });
    const { waits } = await drive([behind, behind, behind, report({ caughtUp: true, transactions: 37 }), report({ caughtUp: true })]);
    expect(waits).toEqual([POLL_INTERVAL_MS, POLL_INTERVAL_MS]);
    expect(POLL_INTERVAL_MS).toBe(5_000);
  });

  it('waits one interval after a poll that read nothing, so a cursor short of the head is not read in a tight loop', () => {
    expect(nextPollIn(report({}))).toBe(POLL_INTERVAL_MS);
    expect(nextPollIn(report({ events: 1 }))).toBe(0);
    expect(nextPollIn(report({ caughtUp: true, events: 3 }), 1_500)).toBe(1_500);
  });

  it('backs off exponentially on failures, to at most a minute, and resets after a poll succeeds', async () => {
    const fail = new Error('RPC HTTP 429');
    const { waits } = await drive([fail, fail, fail, fail, fail, fail, fail, fail, report({ caughtUp: true }), fail]);
    expect(waits).toEqual([1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000, POLL_INTERVAL_MS, BACKOFF_MS]);
    expect(MAX_BACKOFF_MS).toBe(60_000);
  });

  it('raises one alarm once polls have failed for five minutes', async () => {
    const fail = new Error('fetch failed');
    const script: Error[] = Array.from({ length: 12 }, () => fail);
    const { waits, alarms } = await drive(script);
    const failedFor = waits.reduce<number[]>((acc, w) => [...acc, (acc.at(-1) ?? 0) + w], []);
    expect(alarms).toHaveLength(1);
    expect(alarms[0]).toMatch(/^polls have failed for \d+ s \(fetch failed\)$/);
    // The first failure at 0 ms; the alarm on the first failure at or past five minutes.
    expect(Number(/for (\d+) s/.exec(alarms[0]!)![1]) * 1000).toBe(failedFor.find((t) => t >= FAILING_ALARM_MS));
  });

  it('a sleep returns at once when the driver is stopped', async () => {
    const stop = new AbortController();
    const t0 = Date.now();
    const waiting = sleep(60_000, stop.signal);
    stop.abort();
    await waiting;
    expect(Date.now() - t0).toBeLessThan(1_000);
  });
});
