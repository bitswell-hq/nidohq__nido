/**
 * What alerts say. Every text is generic: it never names the account, the
 * address, or the attempt; it carries only the verification code
 * (`docs/email-recovery/spec.md` §10.1) and points to the wallet's canonical
 * origin as plain text. No message carries a link to act on.
 *
 * A push goes only to the device registered with the account's passkey, so
 * its text can say that device has the passkey and lead with cancelling: a
 * device that still holds the passkey never needs a recovery. The code
 * identifies an attempt; it does not show that the attempt is the reader's
 * own, because anyone holding the recovery code computes the same one.
 */
import { formatAlertCode } from '@nidohq/email-recovery';
import type { AlertName } from '../events.js';

export interface AlertText {
  subject: string;
  /** Short title for a push notification. */
  title: string;
  /** The email's body. */
  body: string;
  /** The push notification's body (the service worker appends the code). */
  push: string;
}

/** What only a passkey device reads first: it does not need a recovery. */
export const PASSKEY_DEVICE_LEAD =
  'This device has your passkey, so you do not need a recovery. Cancel it unless you are deliberately replacing this passkey.';

/** The one statement every alert makes about who asks for what. */
export const NEVER_ASKS =
  'Nido never asks anyone to send a recovery email, to approve a recovery, or to read out a code. ' +
  'Your recovery code is typed only into your own Nido’s recovery page, by you, after you have lost every device with your passkey.';

const LEADS: Record<AlertName, { title: string; email: string; push?: string }> = {
  attempt_authorized: {
    title: 'Account recovery approved',
    email:
      'A recovery of one of your Nido accounts has been approved and is in its waiting period. When the waiting period ends, ' +
      'whoever started it controls the account. If you still have your passkey, you do not need a recovery: open your wallet and cancel it. ' +
      'Let it finish only if you started it yourself because you lost every device with your passkey. ' +
      'The code below identifies this recovery; anyone who has your recovery code sees the same code, so a matching code does not make it yours.',
    push: `${PASSKEY_DEVICE_LEAD} Open Nido, Security, Recovery.`,
  },
  email_vote_recorded: {
    title: 'Your email approved a recovery',
    email:
      'The email address set up to help recover one of your Nido accounts has just approved a recovery attempt. That needs your inbox and your recovery code. ' +
      'If you did not send that email yourself because you lost your passkey, someone else has both, or talked you into sending it: ' +
      'open your wallet on a device with your passkey and cancel the attempt, then change your email password and set up email recovery again with a new recovery code.',
    push: `${PASSKEY_DEVICE_LEAD} Your recovery email just approved one. Open Nido, Security, Recovery.`,
  },
  recovery_completed: {
    title: 'Account recovery completed',
    email:
      'A recovery of one of your Nido accounts has completed and the keys that control it changed. ' +
      'If this was not you, open your wallet now.',
  },
  epoch_advanced: {
    title: 'Recovery settings changed',
    email:
      'The recovery settings of one of your Nido accounts changed (its guardians, its timing, or its email guardian). ' +
      'If this was not you, open your wallet now.',
  },
  attempt_cancelled: {
    title: 'Recovery attempt cancelled',
    email: 'A recovery attempt on one of your Nido accounts was cancelled.',
  },
  change_evidence_recorded: {
    title: 'Approvals being collected',
    email:
      'Approvals are being collected for a change to the recovery settings or the code of one of your Nido accounts.',
  },
  attempt_begun: {
    title: 'Recovery attempt opened',
    email:
      'A recovery attempt was opened for one of your Nido accounts. Anyone can open one, and opening one grants nothing; ' +
      'you will be alerted again if it is approved.',
  },
};

const footer = (walletOrigin: string) =>
  `Open your wallet yourself at ${walletOrigin} to see the details. Nido alerts never contain links to act on. ${NEVER_ASKS}`;

export function alertText(name: AlertName, code: string, walletOrigin: string, suppressed = 0): AlertText {
  const { title, email, push } = LEADS[name];
  const more = suppressed > 0 ? `\n\n${suppressed} more like this were opened since the last notice.` : '';
  return {
    subject: `Nido security alert: ${title.toLowerCase()}`,
    title,
    body: `${email}${more}\n\nVerification code: ${formatAlertCode(code)}\n\n${footer(walletOrigin)}`,
    push: push ?? email,
  };
}

export function contactChangeNotice(kind: 'replace' | 'remove', walletOrigin: string): AlertText {
  const what = kind === 'replace' ? 'moved to another address' : 'turned off';
  const body =
    `The recovery alerts of one of your Nido accounts are being ${what}. The change takes effect in 14 days; ` +
    'until then alerts keep coming here. If you did not ask for this, open your wallet and recover the account: ' +
    'a completed recovery cancels the change.';
  return {
    subject: 'Nido security alert: alert settings changing',
    title: 'Alert settings changing',
    body: `${body}\n\n${footer(walletOrigin)}`,
    push: body,
  };
}

/** Told to the contact's address when the vault finds its push subscription gone (spec §10.6). */
export function pushLapsedNotice(walletOrigin: string): AlertText {
  const body =
    'Notifications for the recovery alerts of one of your Nido accounts no longer reach the device they were set up on, ' +
    'so recovery alerts now come only to this address. Email can help recover a Nido only while a second alert channel works: ' +
    'open your wallet on a device with your passkey, go to Security, Recovery, and turn notifications on again.';
  return {
    subject: 'Nido security alert: notifications stopped',
    title: 'Notifications stopped',
    body: `${body}\n\n${footer(walletOrigin)}`,
    push: body,
  };
}

/** Told to the contact's address when a new device takes over its notifications. */
export function pushMovedNotice(walletOrigin: string): AlertText {
  const body =
    'Notifications for the recovery alerts of one of your Nido accounts now go to a new device, set up with the account’s passkey ' +
    'after the previous device stopped receiving them. If you did not do this, open your wallet now.';
  return {
    subject: 'Nido security alert: notifications moved',
    title: 'Notifications moved',
    body: `${body}\n\n${footer(walletOrigin)}`,
    push: body,
  };
}

export function confirmationText(code: string, walletOrigin: string): AlertText {
  const body =
    `Your confirmation code for Nido recovery alerts is ${code}. Enter it in your wallet within 72 hours; ` +
    'alerts start once it is confirmed. If you did not ask for alerts, ignore this message.';
  return {
    subject: 'Confirm your Nido recovery alerts',
    title: 'Confirm your alerts',
    body: `${body}\n\n${footer(walletOrigin)}`,
    push: body,
  };
}
