/**
 * Live recovery attempts, read straight from the account's controller
 * whenever the wallet opens (the home page) and on the recovery settings
 * page, independent of the alert service: a stopped or lagging alert
 * service cannot hide an attempt from a wallet that is opened
 * (`docs/email-recovery/spec.md` §10).
 *
 * The authorized attempt comes from the controller's activity gate; the
 * collecting ones from paging through every attempt still open
 * (`perch.readLiveAttempts`), so opening many cannot push one out of view.
 * Approved attempts come first, those the email helper approved before the
 * rest, and more than `MANY_OPEN_ATTEMPTS` open ones draw a warning above
 * them. A device holding the account's passkey is told it does not need a
 * recovery and is offered the owner's cancellation (`Loss`); an attempt that
 * only collects shows as a quiet notice, since opening one is permissionless
 * and grants nothing.
 */

import { MANY_OPEN_ATTEMPTS } from '@nidohq/email-recovery';
import { loadCredential, perch } from '@nidohq/passkey-sdk';
import { esc } from '../html.js';
import { toast } from '../toast.js';
import { readRecoveryState, recoveryClient, submitAsOwner } from './chain.js';
import { perchDeployment } from './deployment.js';
import { emailRecoveryDeployment } from './emailConfig.js';
import { PASSKEY_DEVICE_CANCEL } from './emailModel.js';
import { findEmailGuardian } from './emailRecovery.js';
import { busy, el, errorText } from './ui.js';

export type LiveAttempt = perch.LiveAttempt;
export type LiveAttemptReader = perch.LiveAttemptReader;
export const readLiveAttempts = perch.readLiveAttempts;

/**
 * The order the wallet lists live attempts in: the email helper's votes
 * (on the attempt or on its cancellation) first, then authorized ones, then
 * any with an approval, then the rest, newest first within each.
 */
export function orderLiveAttempts(live: readonly LiveAttempt[], emailGuardian?: string): LiveAttempt[] {
  const rank = (a: LiveAttempt) =>
    emailGuardian !== undefined && (a.approvals.includes(emailGuardian) || a.cancelApprovals.includes(emailGuardian))
      ? 0
      : a.state === 'Authorized'
        ? 1
        : a.approvals.length
          ? 2
          : 3;
  return [...live].sort((a, b) => rank(a) - rank(b) || (b.attemptId > a.attemptId ? 1 : b.attemptId < a.attemptId ? -1 : 0));
}

/** The warning above the list when more than `MANY_OPEN_ATTEMPTS` attempts collect at once, or `undefined`. */
export function manyAttemptsWarning(live: readonly LiveAttempt[]): string | undefined {
  const open = live.filter((a) => a.state === 'Collecting').length;
  if (open <= MANY_OPEN_ATTEMPTS) return undefined;
  return (
    `${open} recovery attempts are open for this Nido. Anyone can open one, and each grants nothing on its own, ` +
    'but this many can hide the one that matters: any your email or your helpers approved are listed first.'
  );
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
  if (o.emailGuardian !== undefined && a.cancelApprovals.includes(o.emailGuardian)) {
    return {
      tone: 'danger',
      cancel,
      text: `Your recovery email has approved cancelling recovery attempt ${a.attemptId}. That takes your inbox and your recovery code: if you did not send it yourself, someone has both, or talked you into sending it.`,
    };
  }
  // Alerts go out for the email helper's votes and for an approved recovery, not for another helper's vote.
  const alerted = o.emailGuardian !== undefined ? ' You are alerted if your email approves it, or once a recovery is approved.' : '';
  return {
    tone: 'note',
    cancel,
    text: `Recovery attempt ${a.attemptId} was opened for this Nido. Anyone can open one, and it grants nothing until your helpers approve it.${alerted}`,
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
  const read = await readLiveAttempts(client, account, authorized == null ? {} : { authorized: BigInt(authorized) });
  if (!read.length) return undefined;
  const email =
    emailRecoveryDeployment() && read.some((a) => a.approvals.length || a.cancelApprovals.length)
      ? await findEmailGuardian(s.guardians).catch(() => undefined)
      : undefined;
  const live = orderLiveAttempts(read, email?.address);
  const holdsPasskey = Boolean(loadCredential(account));
  const wrap = el('div', { style: 'display:grid;gap:8px;', 'data-live-attempts': '' });
  const many = manyAttemptsWarning(live);
  if (many) wrap.append(el('div', { class: 'alert danger', role: 'alert', 'data-many-attempts': '' }, `<div style="font-size:13.5px;line-height:1.45;">${esc(many)}</div>`));
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
