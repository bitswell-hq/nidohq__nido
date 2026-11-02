/**
 * An account's live recovery attempts, read from its Perch controller: what
 * a wallet shows whenever it opens, independent of any alert service
 * (`docs/email-recovery/spec.md` §10.2).
 *
 * The authorized attempt comes by id (from the activity gate); collecting
 * ones by paging down from the newest. Within one configuration epoch an
 * attempt's evidence window closes in id order, an attempt of an earlier
 * epoch is dead, and attempts below an authorized sibling are invalidated,
 * so the first collecting attempt that is not live, or a missing one, ends
 * the scan: no older one can be live. Opening attempts is permissionless;
 * how many are open bounds the reads, nothing else does.
 */

import type { Attempt } from './recovery.js';

/** Attempts read at once, in parallel, while paging. */
export const LIVE_ATTEMPT_PAGE = 16;

/** The reads this needs (a `PerchRecovery`). */
export interface LiveAttemptReader {
  nextAttemptId(account: string): Promise<bigint>;
  attempt(account: string, attemptId: bigint): Promise<Attempt | undefined>;
  attemptLive(account: string, attemptId: bigint): Promise<boolean>;
}

export interface LiveAttempt {
  attemptId: bigint;
  state: 'Collecting' | 'Authorized';
  /** Guardians that approved it. */
  approvals: string[];
  /** Guardians that approved cancelling it. */
  cancelApprovals: string[];
  executableAfter: number;
}

/**
 * The account's live attempts, newest first: the authorized one
 * (`authorized`, read even when it is older than every open one), and every
 * collecting one that is still live.
 */
export async function readLiveAttempts(
  reader: LiveAttemptReader,
  account: string,
  opts: { authorized?: bigint } = {},
): Promise<LiveAttempt[]> {
  const read = async (id: bigint) => {
    const a = await reader.attempt(account, id);
    return { id, a, live: a ? await reader.attemptLive(account, id) : false };
  };
  const view = ({ id, a }: { id: bigint; a: Attempt }, state: LiveAttempt['state']): LiveAttempt => ({
    attemptId: id,
    state,
    approvals: a.guardians,
    cancelApprovals: a.cancel_guardians ?? [],
    executableAfter: a.executable_after,
  });
  const out: LiveAttempt[] = [];
  let next = await reader.nextAttemptId(account);
  let done = false;
  while (!done && next > 0n) {
    const ids: bigint[] = [];
    for (let id = next - 1n; id >= 0n && ids.length < LIVE_ATTEMPT_PAGE; id--) ids.push(id);
    next -= BigInt(ids.length);
    for (const r of await Promise.all(ids.map(read))) {
      const tag = r.a?.state.tag;
      if (!r.a || (tag === 'Collecting' && !r.live)) {
        done = true;
        break;
      }
      if (r.live && (tag === 'Collecting' || tag === 'Authorized')) out.push(view({ id: r.id, a: r.a }, tag));
    }
  }
  if (opts.authorized !== undefined && !out.some((a) => a.attemptId === opts.authorized)) {
    const r = await read(opts.authorized);
    if (r.a && r.live && r.a.state.tag === 'Authorized') out.unshift(view({ id: r.id, a: r.a }, 'Authorized'));
  }
  return out;
}
