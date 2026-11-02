// The wallet's own read of live recovery attempts (independent of alerts):
// which attempts it finds, however many are open, the order it lists them
// in, and what a device with the passkey is told.
import { describe, expect, it } from 'vitest';
import { MANY_OPEN_ATTEMPTS } from '@nidohq/email-recovery';
import { type perch } from '@nidohq/passkey-sdk';
import { type LiveAttempt, type LiveAttemptReader, liveAttemptView, manyAttemptsWarning, orderLiveAttempts, readLiveAttempts } from './liveAttempts';
import { PASSKEY_DEVICE_CANCEL } from './emailModel';

const EMAIL = 'CEMAIL';
const HELPER = 'CHELPER';

function reader(attempts: Record<string, { tag: string; guardians?: string[]; cancel?: string[]; live?: boolean }>, next: bigint): LiveAttemptReader & { reads: bigint[] } {
  const reads: bigint[] = [];
  return {
    reads,
    async nextAttemptId() {
      return next;
    },
    async attempt(_account, id) {
      reads.push(id);
      const a = attempts[String(id)];
      return a ? ({ state: { tag: a.tag, values: undefined }, guardians: a.guardians ?? [], cancel_guardians: a.cancel ?? [], executable_after: 500 } as unknown as perch.Attempt) : undefined;
    },
    async attemptLive(_account, id) {
      return attempts[String(id)]?.live ?? true;
    },
  };
}

describe('live attempts', () => {
  it('finds collecting and authorized attempts that are live, newest first, stops at the first closed one, and reads the authorized one', async () => {
    const r = reader(
      {
        '2': { tag: 'Authorized', guardians: [EMAIL] },
        '40': { tag: 'Collecting' },
        '39': { tag: 'Cancelled' },
        '38': { tag: 'Collecting', live: false },
        '37': { tag: 'Collecting' },
      },
      41n,
    );
    const live = await readLiveAttempts(r, 'CACCOUNT', { authorized: 2n });
    expect(live.map((a) => [a.attemptId, a.state])).toEqual([
      [2n, 'Authorized'],
      [40n, 'Collecting'],
    ]);
    // A collecting attempt that is not live closes the scan: 37 is older than it, so it is not live either.
    expect(live.some((a) => a.attemptId === 37n)).toBe(false);
  });

  it('pages through every open attempt: an email vote under forty newer attempts is found and listed first', async () => {
    const attempts: Record<string, { tag: string; guardians?: string[] }> = { '100': { tag: 'Collecting', guardians: [EMAIL] } };
    for (let id = 101; id <= 140; id++) attempts[String(id)] = { tag: 'Collecting' };
    const live = await readLiveAttempts(reader(attempts, 141n), 'CACCOUNT');
    expect(live).toHaveLength(41);
    const ordered = orderLiveAttempts(live, EMAIL);
    expect(ordered[0]).toMatchObject({ attemptId: 100n, approvals: [EMAIL] });
    expect(ordered[1]!.attemptId).toBe(140n);
    expect(manyAttemptsWarning(ordered)).toMatch(/^41 recovery attempts are open for this Nido\. .* any your email or your helpers approved are listed first\.$/);
  });

  it(`warns above the list only when more than ${MANY_OPEN_ATTEMPTS} attempts collect; orders votes, then authorized, then approved`, () => {
    const a = (id: number, o: Partial<LiveAttempt> = {}): LiveAttempt => ({ attemptId: BigInt(id), state: 'Collecting', approvals: [], cancelApprovals: [], executableAfter: 0, ...o });
    expect(manyAttemptsWarning(Array.from({ length: MANY_OPEN_ATTEMPTS }, (_, i) => a(i)))).toBeUndefined();
    expect(manyAttemptsWarning(Array.from({ length: MANY_OPEN_ATTEMPTS + 1 }, (_, i) => a(i)))).toBeDefined();
    const order = orderLiveAttempts([a(5), a(4, { approvals: [HELPER] }), a(3, { state: 'Authorized' }), a(2, { cancelApprovals: [EMAIL] }), a(1)], EMAIL);
    expect(order.map((x) => Number(x.attemptId))).toEqual([2, 3, 4, 5, 1]);
  });

  it('a device with the passkey is told it needs no recovery and offered the cancel; an email vote is called out', () => {
    const authorized = liveAttemptView({ attemptId: 2n, state: 'Authorized', approvals: [EMAIL], cancelApprovals: [], executableAfter: 9 }, { holdsPasskey: true, profile: 'loss', emailGuardian: EMAIL });
    expect(authorized).toMatchObject({ tone: 'danger', cancel: true });
    expect(authorized.text.startsWith(PASSKEY_DEVICE_CANCEL)).toBe(true);
    const voted = liveAttemptView({ attemptId: 3n, state: 'Collecting', approvals: [EMAIL], cancelApprovals: [], executableAfter: 0 }, { holdsPasskey: true, profile: 'loss', emailGuardian: EMAIL });
    expect(voted).toMatchObject({ tone: 'danger', cancel: true });
    expect(voted.text).toMatch(/Your recovery email has approved recovery attempt 3/);
    const opened = liveAttemptView({ attemptId: 4n, state: 'Collecting', approvals: [HELPER], cancelApprovals: [], executableAfter: 0 }, { holdsPasskey: true, profile: 'loss', emailGuardian: EMAIL });
    expect(opened).toMatchObject({ tone: 'note', cancel: true });
    expect(opened.text).toMatch(/Anyone can open one, and it grants nothing/);
    const cancelled = liveAttemptView({ attemptId: 5n, state: 'Collecting', approvals: [], cancelApprovals: [EMAIL], executableAfter: 0 }, { holdsPasskey: true, profile: 'loss', emailGuardian: EMAIL });
    expect(cancelled).toMatchObject({ tone: 'danger' });
    expect(cancelled.text).toMatch(/Your recovery email has approved cancelling recovery attempt 5/);
  });

  it('without the passkey, or under protected, there is no owner cancel', () => {
    const a = { attemptId: 2n, state: 'Authorized' as const, approvals: [], cancelApprovals: [], executableAfter: 9 };
    expect(liveAttemptView(a, { holdsPasskey: false, profile: 'loss' })).toMatchObject({ cancel: false });
    expect(liveAttemptView(a, { holdsPasskey: false, profile: 'loss' }).text.startsWith(PASSKEY_DEVICE_CANCEL)).toBe(false);
    expect(liveAttemptView(a, { holdsPasskey: true, profile: 'protected' })).toMatchObject({ cancel: false });
  });
});
