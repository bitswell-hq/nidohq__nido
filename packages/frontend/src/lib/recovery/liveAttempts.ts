/**
 * Live recovery attempts, read straight from the account's controller
 * whenever the wallet opens (the home page) and on the recovery settings
 * page, independent of the alert service: a stopped or lagging alert
 * service cannot hide an attempt from a wallet that is opened
 * (`docs/email-recovery/spec.md` §10).
 *
 * The authorized attempt comes from the controller's activity gate; the
 * collecting ones from its latest [`LIVE_ATTEMPT_SCAN`] attempts. A device
 * holding the account's passkey is told it does not need a recovery and is
 * offered the owner's cancellation (`Loss`); an attempt that only collects
 * shows as a quiet notice, since opening one is permissionless and grants
 * nothing.
 */

import { loadCredential, perch } from '@nidohq/passkey-sdk';
import { esc } from '../html.js';
import { toast } from '../toast.js';
import { readRecoveryState, recoveryClient, submitAsOwner } from './chain.js';
import { perchDeployment } from './deployment.js';
import { emailRecoveryDeployment } from './emailConfig.js';
import { PASSKEY_DEVICE_CANCEL } from './emailModel.js';
import { findEmailGuardian } from './emailRecovery.js';
import { busy, el, errorText } from './ui.js';

/** How many of the account's latest attempts are read for collecting ones. */
export const LIVE_ATTEMPT_SCAN = 16;

/** The attempt reads this needs (a `perch.PerchRecovery`). */
export interface LiveAttemptReader {
  nextAttemptId(account: string): Promise<bigint>;
  attempt(account: string, attemptId: bigint): Promise<perch.Attempt | undefined>;
  attemptLive(account: string, attemptId: bigint): Promise<boolean>;
}

export interface LiveAttempt {
  attemptId: bigint;
  state: 'Collecting' | 'Authorized';
  /** Guardians that approved it. */
  approvals: string[];
  executableAfter: number;
}

/** The account's live attempts, newest first: the authorized one, and collecting ones among the latest. */
export async function readLiveAttempts(reader: LiveAttemptReader, account: string, authorized?: bigint): Promise<LiveAttempt[]> {
  const next = await reader.nextAttemptId(account);
  const oldest = next > BigInt(LIVE_ATTEMPT_SCAN) ? next - BigInt(LIVE_ATTEMPT_SCAN) : 0n;
  const ids: bigint[] = [];
  for (let id = next - 1n; id >= oldest; id--) ids.push(id);
  if (authorized !== undefined && !ids.includes(authorized)) ids.unshift(authorized);
  const out: LiveAttempt[] = [];
  for (const id of ids) {
    const a = await reader.attempt(account, id);
    const tag = a?.state.tag;
    if (!a || (tag !== 'Collecting' && tag !== 'Authorized') || !(await reader.attemptLive(account, id))) continue;
    out.push({ attemptId: id, state: tag, approvals: a.guardians, executableAfter: a.executable_after });
  }
  return out;
}

/** How the wallet shows one live attempt. */
export function liveAttemptView(
  a: LiveAttempt,
  o: { holdsPasskey: boolean; profile: 'loss' | 'protected'; emailGuardian?: string },
): { tone: 'danger' | 'note'; text: string; cancel: boolean } {
  const emailVoted = o.emailGuardian !== undefined && a.approvals.includes(o.emailGuardian);
  const cancel = o.profile === 'loss' && o.holdsPasskey;
  const lead = o.holdsPasskey ? `${PASSKEY_DEVICE_CANCEL} ` : '';
  if (a.state === 'Authorized') {
    return { tone: 'danger', cancel, text: `${lead}A recovery of this Nido (attempt ${a.attemptId}) was approved and finishes after its waiting period unless it is cancelled.` };
  }
  if (emailVoted) {
    return {
      tone: 'danger',
      cancel,
      text: `${lead}Your recovery email has approved recovery attempt ${a.attemptId}. That takes your inbox and your recovery code: if you did not send it yourself, someone has both, or talked you into sending it.`,
    };
  }
  return {
    tone: 'note',
    cancel,
    text: `Recovery attempt ${a.attemptId} was opened for this Nido. Anyone can open one, and it grants nothing until your helpers approve it; you are alerted if it gathers an approval.`,
  };
}

/**
 * The live attempts of `account` as a section to put on a page, or
 * `undefined` when there are none (or recovery is not set up).
 */
export async function liveAttemptsSection(account: string): Promise<HTMLElement | undefined> {
  const state = await readRecoveryState(account);
  const s = state.summary;
  if (!s) return undefined;
  const client = recoveryClient();
  const authorized = state.gate?.authorized_attempt;
  const live = await readLiveAttempts(client, account, authorized == null ? undefined : BigInt(authorized));
  if (!live.length) return undefined;
  const email =
    emailRecoveryDeployment() && live.some((a) => a.approvals.length) ? await findEmailGuardian(s.guardians).catch(() => undefined) : undefined;
  const holdsPasskey = Boolean(loadCredential(account));
  const wrap = el('div', { style: 'display:grid;gap:8px;', 'data-live-attempts': '' });
  for (const a of live) {
    const v = liveAttemptView(a, { holdsPasskey, profile: s.profile, emailGuardian: email?.address });
    const box = el('div', { class: `alert ${v.tone === 'danger' ? 'danger' : ''}`.trim(), role: v.tone === 'danger' ? 'alert' : 'status', 'data-attempt': String(a.attemptId) }, `<div style="font-size:13.5px;line-height:1.45;">${esc(v.text)}</div>`);
    const status = el('div', { class: 'mut', style: 'font-size:12.5px;' });
    if (v.cancel) {
      const btn = el('button', { class: `btn ${v.tone === 'danger' ? 'primary' : 'soft'} sm`, type: 'button', 'data-cancel-attempt': String(a.attemptId) }, 'Cancel this recovery') as HTMLButtonElement;
      btn.addEventListener('click', () =>
        busy(btn, status, 'Cancelling…', async () => {
          const op = await recoveryClient().ownerCancel(account, a.attemptId);
          await submitAsOwner(account, op.operations[0]!);
          status.textContent = 'Cancelled.';
          btn.remove();
          toast({ msg: 'Recovery cancelled', icon: 'check' });
        }),
      );
      box.append(btn, status);
    } else if (s.profile === 'protected' && v.tone === 'danger') {
      box.append(el('a', { class: 'btn soft sm', href: '/security/recovery/' }, 'Ask your helpers to cancel it'));
    }
    wrap.append(box);
  }
  return wrap;
}

/** The wallet's own check on opening: show any live attempt in `container`, independent of alerts. */
export async function mountLiveAttempts(container: HTMLElement, account: string): Promise<void> {
  if (!perchDeployment()) return;
  try {
    const section = await liveAttemptsSection(account);
    if (!section) return;
    container.replaceChildren(section);
    container.hidden = false;
  } catch (e) {
    // A failed read must not break the page that opened; the next open reads again.
    console.warn(`recovery attempts: ${errorText(e)}`);
  }
}
