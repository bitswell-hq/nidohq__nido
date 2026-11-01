/**
 * Recovery configuration as a document change.
 *
 * A Perch account has one write path, `apply_doc`. Enrolling recovery,
 * reconfiguring it (guardians, threshold, mode, timing), and disabling it
 * are all a new document whose `recovery` member changed; the account's
 * controller classifies the change in the same invocation (`rcv_sync`) and,
 * for a new ZK credential, the account inserts its leaf into the pool before
 * returning. Onboarding is the same thing: the factory mints the account
 * with only its passkey admin rule, and the wallet's first `apply_doc`
 * carries the full document, recovery included.
 *
 * Atomicity: those steps are one invocation, and the pool insertion is not
 * a `try_` call, so a failure anywhere (compile, controller, rules, pool)
 * reverts all of it. The account is then exactly as it was, and retrying
 * with a fresh enrollment id is safe. Between the factory's `create_account`
 * and the first `apply_doc` the account has only its admin rule and no
 * recovery; nothing else can change it in that window.
 */

import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { configHash as perchConfigHash, parsePolicyDoc } from '@stellar-registry/perch';
import type { PolicyDoc, RecoverySpec, ZkFactorSpec } from '@stellar-registry/perch';
import type { PerchDeployment } from './deployment.js';
import type { Bytes32 } from './statement.js';

export type RecoveryProfile = 'loss' | 'protected';
export type RecoveryMode = 'guardian-only' | 'zk-only' | 'combined';

/** Nido's defaults, in ledgers (about five seconds each). */
export const RECOVERY_DEFAULTS = {
  /** Seven days between authorization and completion: the window an owner
   *  (Loss) or the condition (Protected) has to cancel. */
  delayLedgers: 120_960,
  /** Fourteen days to collect evidence, and then to complete. */
  expiryLedgers: 241_920,
  maxCancels: 3,
} as const;

/** A ZK credential as a document names it: never the secret. */
export interface ZkEnrollmentSpec {
  enrollmentId: Bytes32;
  commitment: Bytes32;
}

/** The email guardian's `allowed_actions` bits: bit (action code - 1)
 *  (docs/email-recovery/spec.md §8.1). */
export const EMAIL_GUARDIAN_ALLOW = {
  lostKey: 1,
  compromise: 2,
  cancel: 4,
  reconfigure: 8,
  upgrade: 16,
  all: 31,
} as const;

/** A guardian the wallet deployed as the account's email guardian. The
 *  wallet sets this marker when it deploys the guardian; the builder never
 *  infers it from an address. */
export interface EmailGuardian {
  kind: 'email';
  address: string;
  /** The guardian's `allowed_actions`, as fixed at its construction. */
  allowedActions: number;
}

/** A guardian address (G… or C…), or the account's email guardian. */
export type GuardianChoice = string | EmailGuardian;

export interface RecoveryChoice {
  profile: RecoveryProfile;
  mode: RecoveryMode;
  /** Guardians, for guardian-only and combined. */
  guardians?: GuardianChoice[];
  quorum?: number;
  /** The second alert channel registered with the alert service for this
   *  account. Required when a guardian is an email guardian. */
  secondAlertChannel?: 'web-push';
  /** The credential to enroll, for zk-only and combined. */
  zk?: ZkEnrollmentSpec;
  /** Signer ids a recovery may replace: the document's admin signers. No
   *  default, since the founder's id differs between documents (`admin`
   *  now, `owner` in early ones) and an undeclared id fails to compile. */
  replaceable: string[];
  /** Hash of the enrolled baseline (compromise recovery); omit to enroll
   *  lost-key recovery only. Perch states that `Protected` without a
   *  baseline is not theft-resistant (spec §2, nidohq/nido#220). */
  baselineDocHash?: string;
  delayLedgers?: number;
  expiryLedgers?: number;
  maxCancels?: number;
}

/** The `recovery` member for `choice` against `deployment`. Throws when the
 *  mode's required parts are missing, before the compiler would. */
export function recoverySpec(deployment: PerchDeployment, choice: RecoveryChoice): RecoverySpec {
  const needsGuardians = choice.mode !== 'zk-only';
  const needsZk = choice.mode !== 'guardian-only';
  if (needsGuardians && !(choice.guardians?.length && choice.quorum)) {
    throw new Error(`${choice.mode} recovery needs guardians and a quorum`);
  }
  if (needsGuardians && choice.quorum! > choice.guardians!.length) {
    throw new Error(
      `${choice.mode} recovery quorum ${choice.quorum} exceeds its ${choice.guardians!.length} guardians`,
    );
  }
  if (needsZk && choice.zk === undefined) {
    throw new Error(`${choice.mode} recovery needs a ZK enrollment`);
  }
  if (!choice.replaceable?.length) {
    throw new Error('recovery needs at least one replaceable signer');
  }
  if (needsGuardians) checkEmailGuardian(choice);
  const zk = () => ({
    adapter: deployment.zkAdapter,
    circuitId: deployment.circuitId,
    pool: deployment.zkPool,
    enrollmentId: bytesToHex(choice.zk!.enrollmentId),
    commitment: bytesToHex(choice.zk!.commitment),
  });
  const guardians = {
    guardians: (choice.guardians ?? []).map((g) => (typeof g === 'string' ? g : g.address)),
    quorum: choice.quorum ?? 0,
  };
  return {
    profile: choice.profile,
    mode:
      choice.mode === 'guardian-only'
        ? { kind: 'guardian-only', ...guardians }
        : choice.mode === 'zk-only'
          ? { kind: 'zk-only', ...zk() }
          : { kind: 'combined', ...guardians, ...zk() },
    controller: deployment.recoveryController,
    ...(choice.baselineDocHash !== undefined
      ? { baseline: { docHash: choice.baselineDocHash } }
      : {}),
    replaceable: choice.replaceable,
    delayLedgers: choice.delayLedgers ?? RECOVERY_DEFAULTS.delayLedgers,
    expiryLedgers: choice.expiryLedgers ?? RECOVERY_DEFAULTS.expiryLedgers,
    maxCancels: choice.maxCancels ?? RECOVERY_DEFAULTS.maxCancels,
  };
}

/** The shortest delay under which the email vote alone may authorize an
 *  attempt: seven days. */
export const EMAIL_ONLY_MIN_DELAY_LEDGERS = 120_960;

/** The wallet's email-recovery rules (docs/email-recovery/spec.md §9.3).
 *  Perch's validator accepts every configuration these refuse; the rules
 *  keep the email factor one factor in what Nido builds. */
function checkEmailGuardian(choice: RecoveryChoice): void {
  const email = choice.guardians!.filter((g): g is EmailGuardian => typeof g !== 'string');
  if (email.length === 0) return;
  // Rule 1: a second guardian for the same inbox would be a second vote for it.
  if (email.length > 1) {
    throw new Error(`recovery lists ${email.length} email guardians; at most one is allowed`);
  }
  // Rule 2.
  if (choice.secondAlertChannel === undefined) {
    throw new Error('an email guardian needs a second alert channel registered');
  }
  // Rule 3: in combined mode the ZK factor is always needed as well.
  const quorum = choice.quorum!;
  if (choice.mode === 'guardian-only' && quorum === 1) {
    const delay = choice.delayLedgers ?? RECOVERY_DEFAULTS.delayLedgers;
    if (choice.profile !== 'loss' || delay < EMAIL_ONLY_MIN_DELAY_LEDGERS) {
      throw new Error(
        `the email vote alone authorizes this recovery, so it needs the loss profile and a delay of at least ${EMAIL_ONLY_MIN_DELAY_LEDGERS} ledgers`,
      );
    }
  }
  // Rule 4: a Protected account whose quorum needs the email vote could
  // otherwise never reconfigure or upgrade.
  const others = choice.guardians!.length - 1;
  if (email[0]!.allowedActions !== EMAIL_GUARDIAN_ALLOW.all && others < quorum) {
    throw new Error(
      'the quorum needs the email vote, so the email guardian must allow every action',
    );
  }
}

function zkToWire(zk: ZkFactorSpec): Record<string, unknown> {
  return {
    adapter: zk.adapter,
    'circuit-id': zk.circuitId,
    pool: zk.pool,
    'enrollment-id': zk.enrollmentId,
    commitment: zk.commitment,
  };
}

/** perch-ir's wire shape for a recovery member. Mirrors perch-js's
 *  `recoverySpecToWire`, which its entry point does not export at the pinned
 *  revision. */
export function recoveryToWire(spec: RecoverySpec): Record<string, unknown> {
  const m = spec.mode;
  const mode =
    m.kind === 'guardian-only'
      ? { type: 'guardian-only', guardians: m.guardians, quorum: m.quorum }
      : m.kind === 'zk-only'
        ? { type: 'zk-only', ...zkToWire(m) }
        : { type: 'combined', guardians: m.guardians, quorum: m.quorum, ...zkToWire(m) };
  return {
    profile: spec.profile,
    mode,
    controller: spec.controller,
    ...(spec.baseline !== undefined ? { baseline: { 'doc-hash': spec.baseline.docHash } } : {}),
    replaceable: spec.replaceable,
    'delay-ledgers': spec.delayLedgers,
    'expiry-ledgers': spec.expiryLedgers,
    'max-cancels': spec.maxCancels,
  };
}

/** `doc` with its recovery member set to `spec` (or removed), validated.
 *  Throws when `spec` may replace a signer `doc` does not declare, which the
 *  compiler would refuse. */
export function withRecovery(doc: PolicyDoc, spec: RecoverySpec | undefined): PolicyDoc {
  const { recovery: _previous, ...rest } = doc;
  const declared = new Set(doc.signers.map((s) => s.id));
  const undeclared = spec?.replaceable.filter((id) => !declared.has(id)) ?? [];
  if (undeclared.length > 0) {
    throw new Error(`recovery may replace undeclared signer(s): ${undeclared.join(', ')}`);
  }
  return parsePolicyDoc(spec === undefined ? rest : { ...rest, recovery: recoveryToWire(spec) });
}

/** The recovery `config_hash` a document compiles to (perch-js
 *  `configHash`), as bytes, or undefined without a recovery member. What a
 *  `Protected` reconfiguration's evidence approves. */
export function configHash(doc: PolicyDoc): Bytes32 | undefined {
  return doc.recovery === undefined ? undefined : hexToBytes(perchConfigHash(doc));
}

/** How `next` changes `current`'s recovery configuration, for deciding what
 *  evidence a `Protected` account needs before applying it. */
export type RecoveryChange =
  | { kind: 'none' }
  | { kind: 'set'; configHash: Bytes32 }
  | { kind: 'remove' };

export function recoveryChange(current: PolicyDoc, next: PolicyDoc): RecoveryChange {
  const before = configHash(current);
  const after = configHash(next);
  if (after === undefined) return before === undefined ? { kind: 'none' } : { kind: 'remove' };
  if (before !== undefined && bytesToHex(before) === bytesToHex(after)) return { kind: 'none' };
  return { kind: 'set', configHash: after };
}
