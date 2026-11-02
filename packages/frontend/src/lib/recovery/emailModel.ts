/**
 * The pure rules of email recovery in the wallet
 * (`docs/email-recovery/spec.md`): which email to send and how to show it,
 * which key path a proof uses, what is still needed after the email
 * approval, and the copy the pages show. Chain reads and DOM live in
 * `emailRecovery.ts` and the pages; this module is what the unit tests pin.
 */

import { bytes, fieldHex, recoverySubject } from '@nidohq/email-recovery';
import { StrKey } from '@stellar/stellar-sdk';
import { PIN_LIFETIME_LEDGERS } from './emailConfig.js';
import { ledgersToText, SECONDS_PER_LEDGER } from './model.js';

/** The privacy claim the pages make, scoped as the spec states it (§10.7). */
export const PRIVACY_CLAIM = 'Nido’s servers and staff can’t read your address.';

/** What the user sends, from their own inbox (spec §4.1). */
export interface EmailToSend {
  to: string;
  subject: string;
  /** Body text: unconstrained for recovery; the backup block for enrollment. */
  body: string;
}

/** A `mailto:` link that fills in everything (RFC 6068). */
export function mailtoLink(e: EmailToSend): string {
  const q = [`subject=${encodeURIComponent(e.subject)}`];
  if (e.body) q.push(`body=${encodeURIComponent(e.body.replace(/\r?\n/g, '\r\n'))}`);
  return `mailto:${encodeURIComponent(e.to).replace(/%40/g, '@')}?${q.join('&')}`;
}

/** The line every recovery email's body starts with: whoever asked for this email is the attacker. */
export const NOBODY_ASKS_LINE = 'If anyone asked you to send this email, stop. Nido never asks for this.';

/** The recovery email for a statement digest and `rho` (spec §4.2). The body is unconstrained (§4.4): it warns. */
export function recoveryEmail(inbox: string, digest: Uint8Array, rho: bigint): EmailToSend {
  return {
    to: inbox,
    subject: recoverySubject(digest, rho),
    body: `${NOBODY_ASKS_LINE}\n\nI lost every device with my passkey and I am recovering my own Nido.`,
  };
}

/** What a device holding the account's passkey reads first about a recovery: it does not need one. */
export const PASSKEY_DEVICE_CANCEL =
  'This device has your passkey, so you do not need a recovery. Cancel it unless you are deliberately replacing this passkey.';

/** Where the recovery code is typed: nobody asks for it, and how to tell this page is the user's own. */
export function codeEntryWarning(host: string, account: string): string {
  const a = account.toLowerCase();
  return (
    'Nobody from Nido will ask for this code, and nobody else should either: type it only here, yourself, after losing every device with your passkey. ' +
    `Check the address bar first: it must show ${host}. Compare its first characters (${a.slice(0, 6)}…) and last characters (…${a.slice(-6)}) ` +
    'with the Nido address in your recovery kit; if they differ, close this page.'
  );
}

/** The warning enrollment shows when alerts would go to the inbox being enrolled (spec §5.4). */
export function alertAddressWarning(alertAddress: string, factorAddress: string): string | undefined {
  if (alertAddress.trim().toLowerCase() !== factorAddress.trim().toLowerCase()) return undefined;
  return (
    'This is the inbox you are setting up for recovery. Someone who takes over that inbox can delete the alerts sent to it before you see them. ' +
    'Use an address at another provider (a work or family address, for example), so a recovery attempt reaches you even if this inbox is taken.'
  );
}

/** Where to keep the recovery kit: anywhere but the account behind the inbox. */
export const KIT_STORAGE_ADVICE =
  'Keep it outside the account behind the inbox you will use: not in that provider’s password manager or cloud drive ' +
  '(for a Gmail address, not in Google Password Manager or Drive; for iCloud Mail, not in iCloud Keychain or Files). ' +
  'Whoever takes over that account would then have both your inbox and this code.';

/** The groups of the kit code (of seven) enrollment asks to have typed back: two distinct ones. */
export function kitCheckGroups(random: () => number = Math.random): [number, number] {
  const a = Math.floor(random() * 7);
  const b = (a + 1 + Math.floor(random() * 6)) % 7;
  return a < b ? [a, b] : [b, a];
}

/** Whether `typed` holds kit groups `groups` (case and spaces forgiven). */
export function kitCheckMatches(kit: string, groups: readonly number[], typed: readonly string[]): boolean {
  const parts = kit.split(' ');
  return groups.every((g, i) => (typed[i] ?? '').replace(/\s+/g, '').toUpperCase() === parts[g]);
}

/** The recovery kit file: the code, the Nido it recovers, and where recovery starts (spec §5.6). */
export function recoveryKitText(o: { kit: string; account: string; recoverUrl: string }): string {
  return [
    'Nido recovery kit',
    '',
    `Recovery code: ${o.kit}`,
    `Nido: ${o.account}`,
    `Recovery page: ${o.recoverUrl}`,
    '',
    'If you lose every device with your passkey, open the recovery page (or paste the Nido address above at the start of',
    'Nido’s recovery page) and follow the email step. Nobody from Nido will ask for this code.',
    '',
    KIT_STORAGE_ADVICE,
    '',
  ].join('\n');
}

/** What the apex recovery page makes of an address pasted from a recovery kit: an account address, or a name. */
export function accountFromKitInput(text: string): { account: string } | { name: string } | undefined {
  const t = text.trim();
  const c = /\b(C[A-Z2-7]{55})\b/i.exec(t);
  if (c && StrKey.isValidContract(c[1]!.toUpperCase())) return { account: c[1]!.toUpperCase() };
  const host = /^(?:https?:\/\/)?([a-z0-9-]+)\./i.exec(t);
  const label = host?.[1] ?? (/^[a-z][a-z0-9]*$/i.test(t) ? t : undefined);
  if (label && StrKey.isValidContract(label.toUpperCase())) return { account: label.toUpperCase() };
  if (label && /^[a-z][a-z0-9]{0,14}$/i.test(label)) return { name: label.toLowerCase() };
  return undefined;
}

/** The sealed-inbound registration's deadline (spec §4.6), as the recovery page shows it. */
export function inboundDeadline(expiresAt: number, now: number): { expired: boolean; text: string } {
  const left = expiresAt - now;
  if (left <= 0) {
    return { expired: true, text: 'The 24 hours for this email are over, so an email sent now is no longer picked up. Get a new email to send.' };
  }
  const hours = Math.floor(left / 3600_000);
  const minutes = Math.ceil((left % 3600_000) / 60_000);
  const span = hours > 0 ? `${hours} h ${minutes} min` : `${minutes} min`;
  return {
    expired: false,
    text: `This page picks up the email until ${new Date(expiresAt).toLocaleString()} (${span} left). If you need longer, get a new email to send then.`,
  };
}

/** The second alert channel at runtime (spec §9.3 rule 2): the vault's answer first, then this device's own subscription. */
export type SecondChannel = 'live' | 'lapsed' | 'unknown';
export function secondChannel(o: { vault?: 'live' | 'lapsed' | 'none'; device?: 'live' | 'gone' }): SecondChannel {
  if (o.vault === 'lapsed' || o.vault === 'none' || o.device === 'gone') return 'lapsed';
  return o.vault === 'live' ? 'live' : 'unknown';
}

/** What the wallet says when the second channel lapsed: email recovery breaks rule 2 until it is back. */
export const SECOND_CHANNEL_LAPSED =
  'Notifications for your recovery alerts no longer reach your device. Email can help recover this Nido only while a second alert channel works, ' +
  'so until you turn them on again Nido treats your email helper as not allowed (rule 2) and will not save recovery settings that keep it. ' +
  'Turn notifications on again on this device.';

/** The result of the recovery-code check (spec §5.6): the code against the guardian's pin root. */
export function codeCheckText(r: 'match' | 'mismatch' | 'no-pin'): string {
  switch (r) {
    case 'match':
      return 'This is the recovery code of your email helper. Keep it where you found it.';
    case 'mismatch':
      return 'This code does not match your email helper. Look for another copy (your recovery kit, or the encrypted block in your Sent folder with its passphrase). ' +
        'If you cannot find the right one, set up email recovery again now, while you still have your passkey: that makes a new code.';
    case 'no-pin':
      return 'Your email helper keeps no fingerprint this check can compare against, so it cannot tell. Set up email recovery again to get a helper it can check.';
  }
}

/**
 * Check a typed recovery code against the guardian's pin (spec §7.4): the
 * pin's leaf 0 is `P2(DOM_PIN_SALT, account_code)` and its other leaves the
 * pinned keys, so the code is right exactly when, with some key the wallet
 * knows, it rebuilds the pin root on chain. Nothing new is stored.
 */
export function checkCodeAgainstPin(o: {
  accountCode: bigint;
  pinRoot: bigint | undefined;
  keys: { domain: string; modulus: bigint }[];
  root: (accountCode: bigint, key: { domain: string; modulus: bigint }) => bigint;
}): 'match' | 'mismatch' | 'no-pin' {
  if (o.pinRoot === undefined) return 'no-pin';
  return o.keys.some((k) => o.root(o.accountCode, k) === o.pinRoot) ? 'match' : 'mismatch';
}

/** The 64 hex characters that end a recovery or enrollment Subject: what the sealed inbound path routes by. */
export function subjectValue(subject: string): string {
  const m = /(?:APPROVE|ENROLL) NIDO ACCOUNT RECOVERY ([0-9a-f]{64})$/.exec(subject);
  if (!m) throw new Error('not a Nido recovery or enrollment Subject');
  return m[1]!;
}

/** What the page keeps between reloads for one email approval: never `account_code`. */
export interface PendingEmailApproval {
  /** When the sealed inbound registration stops accepting the email (ms), as the vault answered. */
  inboxExpiresAt?: number;
  /** The attempt the approval is for. */
  attemptId: string;
  /** `sha256(statement)` when the Subject was built, hex. */
  digest: string;
  /** `rho`, hex. It never leaves this browser. */
  rho: string;
  /** The sealed inbound registration (spec §4.6): the inbox id and the device key's seed. */
  inbox?: { id: string; seed: string };
}

export function newPendingApproval(attemptId: bigint, digest: Uint8Array, rho: bigint): PendingEmailApproval {
  return { attemptId: attemptId.toString(), digest: bytes.toHex(digest), rho: fieldHex(rho) };
}

/** Why a saved approval no longer fits the attempt's current statement, or `undefined` when it does. */
export function pendingApprovalProblem(p: PendingEmailApproval, attemptId: bigint, digest: Uint8Array): string | undefined {
  if (p.attemptId !== attemptId.toString()) return 'That email was for an earlier recovery attempt. Send a new one.';
  if (p.digest !== bytes.toHex(digest)) {
    return 'The recovery attempt changed since you sent the email (for example its settings moved on), so the email no longer matches. Send a new one.';
  }
  return undefined;
}

/** How the proof shows that the signing key is trusted (spec §7.3, §7.4). */
export type KeyPathChoice =
  | { kind: 'pin'; root: bigint; index: number; siblings: bigint[] }
  | { kind: 'registry'; root: bigint; index: number; siblings: bigint[] };

/**
 * The key path a proof should use: the guardian's pin when it holds this
 * key and has not expired at `ledger` (the pin is accepted without asking
 * the registry), else the registry's current tree when the key is a leaf of
 * a root the registry accepts.
 */
export function chooseKeyPath(opts: {
  ledger: number;
  pin?: { root: bigint; validUntilLedger: number; path?: { index: number; siblings: bigint[]; root: bigint } };
  registry?: { root: bigint; accepted: boolean; path?: { index: number; siblings: bigint[]; root: bigint } };
}): KeyPathChoice | { kind: 'none'; why: string } {
  const pin = opts.pin;
  if (pin?.path && pin.path.root === pin.root && opts.ledger <= pin.validUntilLedger) {
    return { kind: 'pin', ...pin.path };
  }
  const reg = opts.registry;
  if (reg?.path && reg.accepted && reg.path.root === reg.root) return { kind: 'registry', ...reg.path };
  if (pin?.path && opts.ledger > pin.validUntilLedger && !reg?.path) {
    return { kind: 'none', why: 'Your email guardian’s key pin has expired and the key registry does not list your provider’s key yet.' };
  }
  return {
    kind: 'none',
    why: 'Your mail provider signed this email with a key that neither your email guardian nor the key registry trusts yet. If your provider changed its key recently, try again after the registry adds it.',
  };
}

/** Progress copy for each prover stage, in plain language. */
export function stageText(stage: 'download' | 'witness' | 'proving' | 'verifying', p: { loaded?: number; total?: number; cached?: boolean }): string {
  switch (stage) {
    case 'download':
      if (p.loaded !== undefined && p.total) {
        return p.cached ? 'Loading the prover from this browser…' : `Downloading the prover (${(p.loaded / 1e6).toFixed(1)} of ${(p.total / 1e6).toFixed(1)} MB)…`;
      }
      return 'Getting the prover ready…';
    case 'witness':
      return 'Reading your email…';
    case 'proving':
      return 'Proving it came from your inbox. This can take up to two minutes on a phone.';
    case 'verifying':
      return 'Checking the proof…';
  }
}

/** "1:05" for a duration in milliseconds. */
export function clock(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}

/** What an attempt still needs once the email has voted (the email guardian is one of `guardians`). */
export function remainingFactors(opts: {
  quorum: number;
  approvals: string[];
  guardians: string[];
  emailGuardian: string;
  zkNeeded: boolean;
  zkRecorded: boolean;
}): { emailApproved: boolean; othersNeeded: number; zkNeeded: boolean; text: string } {
  const emailApproved = opts.approvals.includes(opts.emailGuardian);
  const counted = opts.approvals.filter((a) => opts.guardians.includes(a)).length;
  const othersNeeded = Math.max(0, opts.quorum - counted - (emailApproved ? 0 : 1));
  const zkNeeded = opts.zkNeeded && !opts.zkRecorded;
  const parts: string[] = [emailApproved ? 'Your email approval is recorded.' : 'Your email approval is not recorded yet.'];
  if (othersNeeded > 0) parts.push(`${othersNeeded} more ${othersNeeded === 1 ? 'helper needs' : 'helpers need'} to approve.`);
  if (zkNeeded) parts.push('Your recovery kit still needs to prove it is you.');
  if (othersNeeded === 0 && !zkNeeded && emailApproved) parts.push('Nothing else is needed: the waiting period starts now.');
  return { emailApproved, othersNeeded, zkNeeded, text: parts.join(' ') };
}

/** The countdown until `executableAfter`, from the latest ledger and when it was read. */
export function delayCountdown(executableAfter: number, ledger: number, readAtMs: number, nowMs: number): { remainingMs: number; text: string } {
  const remainingMs = Math.max(0, (executableAfter - ledger) * SECONDS_PER_LEDGER * 1000 - (nowMs - readAtMs));
  const ledgers = Math.ceil(remainingMs / (SECONDS_PER_LEDGER * 1000));
  return {
    remainingMs,
    text: remainingMs === 0 ? 'The waiting period is over.' : `About ${ledgersToText(ledgers)} left (${clock(remainingMs)} at five seconds a ledger).`,
  };
}

/** The verification code as alerts print it: "169 328". */
export function spacedCode(code: string): string {
  return `${code.slice(0, 3)} ${code.slice(3)}`;
}

/** The enrollment steps, in order; each needs the ones before it. */
export const ENROLL_STEPS = ['code', 'email', 'check', 'alerts', 'deploy', 'apply'] as const;
export type EnrollStep = (typeof ENROLL_STEPS)[number];

export function nextEnrollStep(done: Partial<Record<EnrollStep, boolean>>): EnrollStep | 'done' {
  for (const s of ENROLL_STEPS) if (!done[s]) return s;
  return 'done';
}

/** The `valid_until_ledger` of a pin the wallet deploys at `ledger` (spec §7.4, §13 question 2). */
export function pinValidUntil(ledger: number): number {
  return ledger + PIN_LIFETIME_LEDGERS;
}
