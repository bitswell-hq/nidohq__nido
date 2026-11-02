/**
 * What alerts say. Every text is generic: it never names the account, the
 * address, or the attempt; it carries only the verification code
 * (`docs/email-recovery/spec.md` §10.1) and points to the wallet's canonical
 * origin as plain text. No message carries a link to act on.
 *
 * A push goes only to devices the owner set up for alerts, each added with
 * an account passkey, so its lead says that and that whoever can still sign
 * in needs no recovery; the vault cannot know whether a device still holds
 * the passkey. Every required alert also pre-empts the caller who prepared
 * its reader for it ([`PREEMPT`]). The code identifies an attempt; it does
 * not show that the attempt is the reader's own, because anyone holding the
 * recovery code computes the same one.
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

/** What a device set up for alerts reads first: whoever can still sign in needs no recovery. */
export const PASSKEY_DEVICE_LEAD =
  'This is the device you set up recovery alerts on. If you can still sign in to your Nido, you do not need a recovery: ' +
  'cancel it unless you are deliberately replacing your passkey.';

/** What every required alert says about whoever prepared its reader for it. */
export const PREEMPT = 'If someone told you to expect this message, or to ignore it, they are trying to take your account.';

/** The one statement every alert makes about who asks for what. */
export const NEVER_ASKS =
  'Nido never asks anyone to send a recovery email, to approve a recovery, or to read out a code. ' +
  'Your recovery code is typed only into your own Nido’s recovery page, by you, after you have lost every device with your passkey.';

const INBOX_AND_CODE =
  'That needs your inbox and your recovery code. If you did not send that email yourself because you lost your passkey, someone else has both, or talked you into sending it: ';

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
  email_cancel_recorded: {
    title: 'Your email approved cancelling a recovery',
    email:
      'The email address set up to help recover one of your Nido accounts has just approved cancelling a recovery attempt. ' +
      INBOX_AND_CODE +
      'they can stop your own recoveries. Open your wallet on a device with your passkey, then change your email password and set up email recovery again with a new recovery code.',
    push: 'Your recovery email just approved cancelling a recovery of your Nido. If you did not send it, someone has your inbox and your recovery code. Open Nido, Security, Recovery.',
  },
  email_change_recorded: {
    title: 'Your email approved a settings change',
    email:
      'The email address set up to help recover one of your Nido accounts has just approved a change to its recovery settings, or an upgrade. ' +
      INBOX_AND_CODE +
      'open your wallet on a device with your passkey and check its recovery settings, then change your email password and set up email recovery again with a new recovery code.',
    push: 'Your recovery email just approved a change to your Nido’s recovery settings. If you did not send it, someone has your inbox and your recovery code. Open Nido, Security, Recovery.',
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

/**
 * The alert for `name`. A `required` one (every channel) carries
 * [`PREEMPT`] in the email and the push.
 */
export function alertText(name: AlertName, code: string, walletOrigin: string, suppressed = 0, required = false): AlertText {
  const { title, email, push } = LEADS[name];
  const more = suppressed > 0 ? `\n\n${suppressed} more like this were opened since the last notice.` : '';
  const pre = required ? ` ${PREEMPT}` : '';
  return {
    subject: `Nido security alert: ${title.toLowerCase()}`,
    title,
    body: `${email}${pre}${more}\n\nVerification code: ${formatAlertCode(code)}\n\n${footer(walletOrigin)}`,
    push: `${push ?? email}${pre}`,
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

/** What the channel's state leaves exposed (spec §9.3 rule 2): nothing on chain changed when it broke. */
export interface ChannelLeft {
  /** Another device of the contact still receives and confirms the notifications. */
  othersLive: boolean;
  /** The account's recovery lists an email guardian. */
  emailGuardian: boolean;
}

const ADD_DEVICE = 'open your wallet on the device you use now, with your passkey, go to Security, Recovery, and add that device';

/** What a notice about one device says about the rest. */
function exposure(left: ChannelLeft, fix: string): string {
  if (left.othersLive) return `Your other devices still receive them. If you no longer use this one, ${fix}.`;
  if (!left.emailGuardian) return `No device is known to receive them now: ${fix}.`;
  return (
    'No device is known to receive them now, so your second alert channel is not working. Nothing changed on chain: your email helper still counts, ' +
    'and if it is the only approval your Nido needs, it can still approve a recovery alone, which finishes after the waiting period unless you cancel it. ' +
    `Fix the channel now (${fix}), or add another helper.`
  );
}

/** Told to the contact's address when the vault finds a push subscription gone (spec §10.6). */
export function pushLapsedNotice(walletOrigin: string, left: ChannelLeft): AlertText {
  const body =
    'Notifications for the recovery alerts of one of your Nido accounts no longer reach a device they were set up on: its browser dropped them. ' +
    exposure(left, ADD_DEVICE);
  return {
    subject: 'Nido security alert: notifications stopped',
    title: 'Notifications stopped',
    body: `${body}\n\n${footer(walletOrigin)}`,
    push: body,
  };
}

/** Told to the contact's address when a device's subscription went unconfirmed for two probe intervals (spec §10.6). */
export function pushUnconfirmedNotice(walletOrigin: string, left: ChannelLeft): AlertText {
  const body =
    'Nido could not confirm that the recovery notifications of one of your Nido accounts reach you: a device they go to has not confirmed ' +
    'the last two checks, which ask you to tap a notification. ' +
    exposure(left, `tap the next check on that device, or ${ADD_DEVICE}`);
  return {
    subject: 'Nido security alert: notifications not confirmed',
    title: 'Notifications not confirmed',
    body: `${body}\n\n${footer(walletOrigin)}`,
    push: body,
  };
}

/** Told to the contact's address when a device is added to its notifications (spec §10.3 rule 8). */
export function pushAddedNotice(walletOrigin: string): AlertText {
  const body =
    'A new device now also receives the recovery notifications of one of your Nido accounts. It was added with the account’s passkey. ' +
    'If you did not do this, open your wallet now.';
  return {
    subject: 'Nido security alert: notifications added to a device',
    title: 'Notifications added to a device',
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
