// The wallet's own read of live recovery attempts (independent of alerts):
// which attempts it finds, and what a device with the passkey is told.
import { describe, expect, it } from 'vitest';
import type { perch } from '@nidohq/passkey-sdk';
import { LIVE_ATTEMPT_SCAN, type LiveAttemptReader, liveAttemptView, readLiveAttempts } from './liveAttempts';
import { PASSKEY_DEVICE_CANCEL } from './emailModel';

const EMAIL = 'CEMAIL';
const HELPER = 'CHELPER';

function reader(attempts: Record<string, { tag: string; guardians?: string[]; live?: boolean }>, next: bigint): LiveAttemptReader & { reads: bigint[] } {
  const reads: bigint[] = [];
  return {
    reads,
    async nextAttemptId() {
      return next;
    },
    async attempt(_account, id) {
      reads.push(id);
      const a = attempts[String(id)];
      return a ? ({ state: { tag: a.tag, values: undefined }, guardians: a.guardians ?? [], executable_after: 500 } as unknown as perch.Attempt) : undefined;
    },
    async attemptLive(_account, id) {
      return attempts[String(id)]?.live ?? true;
    },
  };
}

describe('live attempts', () => {
  it('finds collecting and authorized attempts that are live, newest first, and the authorized one beyond the scan', async () => {
    const r = reader(
      {
        '2': { tag: 'Authorized', guardians: [EMAIL] },
        '40': { tag: 'Collecting' },
        '39': { tag: 'Cancelled' },
        '38': { tag: 'Collecting', live: false },
        '37': { tag: 'Completed' },
      },
      41n,
    );
    const live = await readLiveAttempts(r, 'CACCOUNT', 2n);
    expect(live.map((a) => [a.attemptId, a.state])).toEqual([
      [2n, 'Authorized'],
      [40n, 'Collecting'],
    ]);
    expect(r.reads).toHaveLength(LIVE_ATTEMPT_SCAN + 1);
  });

  it('a device with the passkey is told it needs no recovery and offered the cancel; an email vote is called out', () => {
    const authorized = liveAttemptView({ attemptId: 2n, state: 'Authorized', approvals: [EMAIL], executableAfter: 9 }, { holdsPasskey: true, profile: 'loss', emailGuardian: EMAIL });
    expect(authorized).toMatchObject({ tone: 'danger', cancel: true });
    expect(authorized.text.startsWith(PASSKEY_DEVICE_CANCEL)).toBe(true);
    const voted = liveAttemptView({ attemptId: 3n, state: 'Collecting', approvals: [EMAIL], executableAfter: 0 }, { holdsPasskey: true, profile: 'loss', emailGuardian: EMAIL });
    expect(voted).toMatchObject({ tone: 'danger', cancel: true });
    expect(voted.text).toMatch(/Your recovery email has approved recovery attempt 3/);
    const opened = liveAttemptView({ attemptId: 4n, state: 'Collecting', approvals: [HELPER], executableAfter: 0 }, { holdsPasskey: true, profile: 'loss', emailGuardian: EMAIL });
    expect(opened).toMatchObject({ tone: 'note', cancel: true });
    expect(opened.text).toMatch(/Anyone can open one, and it grants nothing/);
  });

  it('without the passkey, or under protected, there is no owner cancel', () => {
    const a = { attemptId: 2n, state: 'Authorized' as const, approvals: [], executableAfter: 9 };
    expect(liveAttemptView(a, { holdsPasskey: false, profile: 'loss' })).toMatchObject({ cancel: false });
    expect(liveAttemptView(a, { holdsPasskey: false, profile: 'loss' }).text.startsWith(PASSKEY_DEVICE_CANCEL)).toBe(false);
    expect(liveAttemptView(a, { holdsPasskey: true, profile: 'protected' })).toMatchObject({ cancel: false });
  });
});
