// `recoverySpec` and `withRecovery` refuse locally what the document
// compiler would refuse: a quorum larger than the guardian set, no
// replaceable signer, or a replaceable id the document does not declare.

import { describe, expect, it } from 'vitest';
import { StrKey } from '@stellar/stellar-sdk';
import { buildPolicyDoc } from '../policyDoc/index.js';
import { TESTNET } from './deployment.js';
import { EMAIL_GUARDIAN_ALLOW, RECOVERY_DEFAULTS, recoverySpec, withRecovery } from './doc.js';
import type { EmailGuardian, RecoveryChoice } from './doc.js';

const VERIFIER = 'CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN';
const GUARDIANS = [1, 2].map((n) => StrKey.encodeContract(new Uint8Array(32).fill(n)));

const doc = buildPolicyDoc({
  signers: [{ id: 'admin', kind: 'passkey', verifier: VERIFIER, publicKey: new Uint8Array(65).fill(7) }],
  permissions: [{ name: 'admin', on: 'self-admin', by: ['admin'] }],
});

const choice = (over: Partial<RecoveryChoice> = {}): RecoveryChoice => ({
  profile: 'loss',
  mode: 'guardian-only',
  guardians: GUARDIANS,
  quorum: 2,
  replaceable: ['admin'],
  ...over,
});

describe('recovery document pre-checks', () => {
  it('accepts a quorum equal to the guardian count and a declared replaceable signer', () => {
    const next = withRecovery(doc, recoverySpec(TESTNET, choice()));
    expect(next.recovery?.replaceable).toEqual(['admin']);
  });

  it('refuses a quorum larger than the guardian set', () => {
    expect(() => recoverySpec(TESTNET, choice({ quorum: 3 }))).toThrow(/quorum 3 exceeds/);
  });

  it('refuses a recovery that may replace no signer', () => {
    expect(() => recoverySpec(TESTNET, choice({ replaceable: [] }))).toThrow(/replaceable/);
  });

  it('refuses a replaceable signer the document does not declare', () => {
    const spec = recoverySpec(TESTNET, choice({ replaceable: ['owner'] }));
    expect(() => withRecovery(doc, spec)).toThrow(/undeclared signer\(s\): owner/);
  });
});

// The wallet's email-recovery rules (docs/email-recovery/spec.md §9.3). Each
// rule is pinned at its accept and refuse boundary.
describe('email guardian rules', () => {
  const EMAIL = StrKey.encodeContract(new Uint8Array(32).fill(9));
  const email = (allowedActions: number = EMAIL_GUARDIAN_ALLOW.all): EmailGuardian => ({
    kind: 'email',
    address: EMAIL,
    allowedActions,
  });
  const NARROW = EMAIL_GUARDIAN_ALLOW.lostKey | EMAIL_GUARDIAN_ALLOW.cancel;
  const zk = { enrollmentId: new Uint8Array(32).fill(3), commitment: new Uint8Array(32).fill(4) };
  const withEmail = (over: Partial<RecoveryChoice> = {}): RecoveryChoice =>
    choice({ guardians: [email(), ...GUARDIANS], secondAlertChannel: 'web-push', ...over });

  it('lists the email guardian by its address', () => {
    const spec = recoverySpec(TESTNET, withEmail());
    expect(spec.mode).toMatchObject({ guardians: [EMAIL, ...GUARDIANS], quorum: 2 });
  });

  it('rule 1: accepts one email guardian and refuses a second', () => {
    expect(recoverySpec(TESTNET, withEmail()).mode.kind).toBe('guardian-only');
    const twice = withEmail({ guardians: [email(), { ...email(), address: GUARDIANS[0]! }] });
    expect(() => recoverySpec(TESTNET, twice)).toThrow(/2 email guardians/);
  });

  it('rule 2: an email guardian needs a second alert channel', () => {
    expect(recoverySpec(TESTNET, withEmail({ secondAlertChannel: 'web-push' }))).toBeDefined();
    expect(() => recoverySpec(TESTNET, withEmail({ secondAlertChannel: undefined }))).toThrow(
      /second alert channel/,
    );
  });

  it('rule 3: email alone needs the loss profile and a delay of at least 120960 ledgers', () => {
    const alone = (over: Partial<RecoveryChoice>) =>
      withEmail({ guardians: [email()], quorum: 1, ...over });
    expect(() => recoverySpec(TESTNET, alone({ delayLedgers: 120_959 }))).toThrow(
      /at least 120960/,
    );
    expect(recoverySpec(TESTNET, alone({ delayLedgers: 120_960 })).delayLedgers).toBe(120_960);
    expect(recoverySpec(TESTNET, alone({})).delayLedgers).toBe(RECOVERY_DEFAULTS.delayLedgers);
    expect(() => recoverySpec(TESTNET, alone({ profile: 'protected' }))).toThrow(/loss profile/);
    // Quorum 1 with other guardians listed: the email vote still suffices.
    expect(() => recoverySpec(TESTNET, withEmail({ quorum: 1, delayLedgers: 120_959 }))).toThrow(
      /at least 120960/,
    );
  });

  it('rule 3: does not apply when the email vote alone cannot authorize', () => {
    const short = { profile: 'protected' as const, delayLedgers: 24 };
    expect(recoverySpec(TESTNET, withEmail({ quorum: 2, ...short })).delayLedgers).toBe(24);
    const combined = withEmail({ mode: 'combined', guardians: [email()], quorum: 1, zk, ...short });
    expect(recoverySpec(TESTNET, combined).mode.kind).toBe('combined');
  });

  it('rule 4: refuses narrower allowed actions when the quorum needs the email vote', () => {
    const narrow = (over: Partial<RecoveryChoice>) =>
      withEmail({ guardians: [email(NARROW), ...GUARDIANS], ...over });
    // Two other guardians, quorum 3: the email vote is needed.
    expect(() => recoverySpec(TESTNET, narrow({ quorum: 3 }))).toThrow(/must allow every action/);
    expect(() =>
      recoverySpec(
        TESTNET,
        narrow({ mode: 'combined', guardians: [email(NARROW)], quorum: 1, zk }),
      ),
    ).toThrow(/must allow every action/);
    // Two other guardians, quorum 2: they reach it without the email vote.
    expect(recoverySpec(TESTNET, narrow({ quorum: 2 })).mode).toMatchObject({ quorum: 2 });
    // Every action allowed: accepted whatever the quorum needs.
    expect(recoverySpec(TESTNET, withEmail({ quorum: 3 })).mode).toMatchObject({ quorum: 3 });
  });

  it('leaves configurations without an email guardian unaffected', () => {
    const plain = choice({ quorum: 1, profile: 'protected', delayLedgers: 24 });
    const spec = recoverySpec(TESTNET, plain);
    expect(spec).toMatchObject({ profile: 'protected', delayLedgers: 24 });
    expect(spec.mode).toMatchObject({ guardians: GUARDIANS, quorum: 1 });
    expect(
      recoverySpec(
        TESTNET,
        choice({ mode: 'zk-only', guardians: undefined, quorum: undefined, zk }),
      ).mode.kind,
    ).toBe('zk-only');
  });
});
