/**
 * The pure rules of email recovery in the wallet
 * (`docs/email-recovery/spec.md`): which email to send and how to show it,
 * which key path a proof uses, what is still needed after the email
 * approval, and the copy the pages show. Chain reads and DOM live in
 * `emailRecovery.ts` and the pages; this module is what the unit tests pin.
 */

import { bytes, fieldHex, recoverySubject } from '@nidohq/email-recovery';
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

/** The recovery email for a statement digest and `rho` (spec §4.2). */
export function recoveryEmail(inbox: string, digest: Uint8Array, rho: bigint): EmailToSend {
  return {
    to: inbox,
    subject: recoverySubject(digest, rho),
    body: 'I am approving the recovery of my Nido. (Nothing in this message needs changing.)',
  };
}

/** The 64 hex characters that end a recovery or enrollment Subject: what the sealed inbound path routes by. */
export function subjectValue(subject: string): string {
  const m = /(?:APPROVE|ENROLL) NIDO ACCOUNT RECOVERY ([0-9a-f]{64})$/.exec(subject);
  if (!m) throw new Error('not a Nido recovery or enrollment Subject');
  return m[1]!;
}

/** What the page keeps between reloads for one email approval: never `account_code`. */
export interface PendingEmailApproval {
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
