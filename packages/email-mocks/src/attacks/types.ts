import type { GeneratedEmail } from '../generate.js';

/**
 * - `valid-dkim-but-must-be-rejected-by-circuit`: a standard DKIM verifier
 *   passes at least one signature, yet a proof of `claim` must not verify.
 * - `invalid-dkim`: no signature on the message verifies.
 * - `valid-dkim-and-must-be-accepted`: a form a provider may legitimately
 *   emit whose canonical signed bytes carry `claim`; a circuit that refuses
 *   it is over-strict, not sound-er.
 */
export type Verdict =
  | 'valid-dkim-but-must-be-rejected-by-circuit'
  | 'invalid-dkim'
  | 'valid-dkim-and-must-be-accepted';

/** What a forged proof would assert about the email. */
export interface Claim {
  /** The sender address the proof would bind (the victim's, for spoofing). */
  from: string;
  /** The recovery value the proof would read from the Subject. */
  recoveryValue: string;
  /** The account the proof would be for, where the case is about the account. */
  account?: string;
}

export interface AttackCase {
  id: string;
  description: string;
  verdict: Verdict;
  email: GeneratedEmail;
  claim: Claim;
  /** Each signature's expected standard-verifier result, top-most first. */
  dkim: Array<'pass' | 'fail'>;
  /** A public report of this issue class, in open-source email circuits or in mail providers. */
  source?: string;
}

/** Inputs every builder shares: the honest message the attack starts from. */
export interface AttackInput {
  /** The victim's enrolled address. */
  victim: string;
  /** An address the attacker controls at a launch provider. */
  attacker: string;
  /** The Subject's fixed phrase, without the space before the value. */
  phrase: string;
  /** The honest recovery Subject: `phrase`, one space, and `recoveryValue`. */
  subject: string;
  /** The value inside `subject` that a proof binds. */
  recoveryValue: string;
  /** A different value, for replay cases. */
  otherRecoveryValue: string;
  /** Opaque account identifiers, for replay cases. */
  account: string;
  otherAccount: string;
  body: string;
  date?: Date;
}
