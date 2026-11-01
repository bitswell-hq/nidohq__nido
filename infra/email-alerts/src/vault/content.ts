/**
 * What alerts say. Every text is generic: it never names the account, the
 * address, or the attempt; it carries only the verification code
 * (`docs/email-recovery/spec.md` §10.1) and points to the wallet's canonical
 * origin as plain text. No message carries a link to act on.
 */
import { formatAlertCode } from '@nidohq/email-recovery';
import type { PerchEventName } from '../events.js';

export interface AlertText {
  subject: string;
  /** Short title for a push notification. */
  title: string;
  body: string;
}

const LEADS: Record<Exclude<PerchEventName, 'attempt_invalidated'>, { title: string; lead: string }> = {
  attempt_authorized: {
    title: 'Account recovery approved',
    lead:
      'A recovery of one of your Nido accounts has been approved and is now in its waiting period. ' +
      'If you started it, the code below matches the one your wallet shows for it and nothing needs doing. ' +
      'If you did not, open your wallet and cancel it before the waiting period ends.',
  },
  recovery_completed: {
    title: 'Account recovery completed',
    lead:
      'A recovery of one of your Nido accounts has completed and the keys that control it changed. ' +
      'If this was not you, open your wallet now.',
  },
  epoch_advanced: {
    title: 'Recovery settings changed',
    lead:
      'The recovery settings of one of your Nido accounts changed (its guardians, its timing, or its email guardian). ' +
      'If this was not you, open your wallet now.',
  },
  attempt_cancelled: {
    title: 'Recovery attempt cancelled',
    lead: 'A recovery attempt on one of your Nido accounts was cancelled.',
  },
  change_evidence_recorded: {
    title: 'Approvals being collected',
    lead:
      'Approvals are being collected for a change to the recovery settings or the code of one of your Nido accounts.',
  },
  attempt_begun: {
    title: 'Recovery attempt opened',
    lead:
      'A recovery attempt was opened for one of your Nido accounts. Anyone can open one, and opening one grants nothing; ' +
      'you will be alerted again if it is approved.',
  },
};

const footer = (walletOrigin: string) =>
  `Open your wallet yourself at ${walletOrigin} to see the details. ` +
  'Nido alerts never contain links to act on and never ask for your passkey or recovery code.';

export function alertText(
  name: Exclude<PerchEventName, 'attempt_invalidated'>,
  code: string,
  walletOrigin: string,
  suppressed = 0,
): AlertText {
  const { title, lead } = LEADS[name];
  const more = suppressed > 0 ? `\n\n${suppressed} more like this were opened since the last notice.` : '';
  return {
    subject: `Nido security alert: ${title.toLowerCase()}`,
    title,
    body: `${lead}${more}\n\nVerification code: ${formatAlertCode(code)}\n\n${footer(walletOrigin)}`,
  };
}

export function contactChangeNotice(kind: 'replace' | 'remove', walletOrigin: string): AlertText {
  const what = kind === 'replace' ? 'moved to another address' : 'turned off';
  return {
    subject: 'Nido security alert: alert settings changing',
    title: 'Alert settings changing',
    body:
      `The recovery alerts of one of your Nido accounts are being ${what}. The change takes effect in 14 days; ` +
      'until then alerts keep coming here. If you did not ask for this, open your wallet and recover the account: ' +
      `a completed recovery cancels the change.\n\n${footer(walletOrigin)}`,
  };
}

export function confirmationText(code: string, walletOrigin: string): AlertText {
  return {
    subject: 'Confirm your Nido recovery alerts',
    title: 'Confirm your alerts',
    body:
      `Your confirmation code for Nido recovery alerts is ${code}. Enter it in your wallet within 72 hours; ` +
      'alerts start once it is confirmed. If you did not ask for alerts, ignore this message.\n\n' +
      footer(walletOrigin),
  };
}
