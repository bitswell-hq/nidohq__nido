/**
 * The verification code an alert carries (`docs/email-recovery/spec.md`
 * §10.1).
 *
 * The code is a 6-digit HMAC of the event's subject (an attempt id, an
 * epoch, or a change digest) under `k_code`, a key derived from the
 * account's `account_code`. The vault holds `k_code` (registered sealed at
 * alert enrollment); every wallet that holds `account_code` (which the email
 * factor needs anyway) computes the same code. Without `k_code` the code is
 * unpredictable, so a mail provider that sees an alert cannot match it to an
 * on-chain attempt, and nobody can choose a statement to produce a given
 * code.
 */

import { concat, hkdfSha256, hmacSha256, u64be, utf8 } from './bytes.js';

export const ALERT_CODE_KEY_LABEL = 'nido/email-recovery/v1/alert-code-key';
export const ALERT_CODE_LABEL = 'nido/email-recovery/v1/alert-code';
export const ALERT_CODE_DIGITS = 6;

/** What an alert is about. Each event of spec §10 maps to one subject. */
export type AlertSubject =
  | { kind: 'attempt'; attemptId: bigint }
  | { kind: 'epoch'; epoch: bigint }
  | { kind: 'change'; digest: Uint8Array };

/** `k_code = HKDF-SHA-256(ikm = account_code, salt = "", info = label, L = 32)`. */
export async function deriveAlertCodeKey(accountCode: Uint8Array): Promise<Uint8Array> {
  if (accountCode.length !== 16) throw new Error('account_code is 16 bytes');
  return hkdfSha256(accountCode, new Uint8Array(0), utf8(ALERT_CODE_KEY_LABEL), 32);
}

export function subjectBytes(subject: AlertSubject): Uint8Array {
  switch (subject.kind) {
    case 'attempt':
      return concat(Uint8Array.of(1), u64be(subject.attemptId));
    case 'epoch':
      return concat(Uint8Array.of(2), u64be(subject.epoch));
    case 'change':
      if (subject.digest.length !== 32) throw new Error('change digest is 32 bytes');
      return concat(Uint8Array.of(3), subject.digest);
  }
}

export interface AlertCodeInput {
  /** `k_code` ([`deriveAlertCodeKey`]). */
  key: Uint8Array;
  /** `sha256(network passphrase)`. */
  networkId: Uint8Array;
  /** 32-byte contract id of the Perch controller that emitted the event. */
  controller: Uint8Array;
  /** 32-byte contract id of the account (the event's topic 1). */
  account: Uint8Array;
  subject: AlertSubject;
}

/**
 * The code as 6 decimal digits:
 * `BE_u64(HMAC-SHA-256(k_code, label || network_id || controller || account || subject)[0..8]) mod 10^6`.
 */
export async function alertCode(input: AlertCodeInput): Promise<string> {
  for (const [name, v] of [
    ['key', input.key],
    ['networkId', input.networkId],
    ['controller', input.controller],
    ['account', input.account],
  ] as const) {
    if (v.length !== 32) throw new Error(`${name} is 32 bytes`);
  }
  const mac = await hmacSha256(
    input.key,
    utf8(ALERT_CODE_LABEL),
    input.networkId,
    input.controller,
    input.account,
    subjectBytes(input.subject),
  );
  const n = new DataView(mac.buffer, mac.byteOffset, 8).getBigUint64(0) % 10n ** BigInt(ALERT_CODE_DIGITS);
  return n.toString().padStart(ALERT_CODE_DIGITS, '0');
}

/** `"123456"` as shown to people: `"123 456"`. */
export function formatAlertCode(code: string): string {
  if (!/^\d{6}$/.test(code)) throw new Error('not a 6-digit code');
  return `${code.slice(0, 3)} ${code.slice(3)}`;
}
