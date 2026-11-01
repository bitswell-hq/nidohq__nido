/**
 * Every adversarial email of `@nidohq/email-mocks` (`buildAttacks`, with the
 * spec's recovery Subject) against the committed recovery circuit, through
 * `attackHarness.ts`'s strongest witness for the case's claim.
 *
 * Each case pins the circuit's outcome: the assertion that refuses it, or
 * `accepted`. Every `valid-dkim-but-must-be-rejected-by-circuit` case must be
 * refused, every `valid-dkim-and-must-be-accepted` case accepted. Of the
 * `invalid-dkim` cases (no signature verifies for a standard verifier), all
 * are refused except `wrong-body-hash`: its header signature is the
 * provider's own over a header block that names its `bh=`, and the recovery
 * proof does not bind the body (spec §4.4), so accepting it proves exactly
 * what the provider signed.
 *
 * `tree` is the key tree the witness used: `registry` when the signing key
 * is a launch key the registry holds, `planted` when it is not and the
 * attacker is granted a tree holding it anyway, so that the refusal comes
 * from the email's own checks.
 */
import { buildAttacks } from '@nidohq/email-mocks';
import { describe, expect, test } from 'vitest';
import { initHashes } from '../src/index.js';
import { type Outcome, prove, specAttackInput } from './attackHarness.js';

type Expected = { tree: Outcome['tree']; outcome: 'accepted' | string };

const EXPECTED: Record<string, Expected> = {
  'from-display-name-is-address': { tree: 'registry', outcome: 'recovery: the From address does not open the commitment' },
  'from-display-name-holds-angle-address': { tree: 'registry', outcome: 'From: the field must hold exactly one angle-addr' },
  'from-angle-addr-with-space': { tree: 'registry', outcome: 'From: the field must hold exactly one angle-addr' },
  'from-display-name-overlong': { tree: 'registry', outcome: 'From: the field must hold exactly one angle-addr' },
  'from-quoted-local-part': { tree: 'registry', outcome: 'From: invalid character in the local part' },
  'from-comment-before-address': { tree: 'registry', outcome: 'From: invalid character in the local part' },
  'from-comment-after-address': { tree: 'registry', outcome: 'From: the field must hold exactly one angle-addr' },
  'from-folded-relaxed': { tree: 'registry', outcome: 'recovery: the From address does not open the commitment' },
  'from-folded-simple-canonicalization': { tree: 'registry', outcome: 'header: folded header line' },
  'unsigned-subject-prepended-gmail': { tree: 'registry', outcome: 'header: exactly one signed Subject field is required' },
  'unsigned-subject-appended-gmail': { tree: 'registry', outcome: 'header: exactly one signed Subject field is required' },
  'unsigned-from-prepended-gmail': { tree: 'registry', outcome: 'header: exactly one signed From field is required' },
  'unsigned-from-appended-gmail': { tree: 'registry', outcome: 'header: exactly one signed From field is required' },
  'unsigned-subject-prepended-outlook': { tree: 'registry', outcome: 'Subject: value does not open to the statement digest' },
  'unsigned-subject-appended-outlook': { tree: 'registry', outcome: 'RSA: signature does not verify' },
  'unsigned-from-prepended-outlook': { tree: 'registry', outcome: 'recovery: the From address does not open the commitment' },
  'unsigned-from-appended-outlook': { tree: 'registry', outcome: 'RSA: signature does not verify' },
  'unsigned-subject-prepended-icloud': { tree: 'registry', outcome: 'Subject: value does not open to the statement digest' },
  'unsigned-subject-appended-icloud': { tree: 'registry', outcome: 'RSA: signature does not verify' },
  'unsigned-from-prepended-icloud': { tree: 'registry', outcome: 'recovery: the From address does not open the commitment' },
  'unsigned-from-appended-icloud': { tree: 'registry', outcome: 'RSA: signature does not verify' },
  'unsigned-subject-prepended-yahoo': { tree: 'registry', outcome: 'header: exactly one signed Subject field is required' },
  'unsigned-subject-appended-yahoo': { tree: 'registry', outcome: 'header: exactly one signed Subject field is required' },
  'unsigned-from-prepended-yahoo': { tree: 'registry', outcome: 'header: exactly one signed From field is required' },
  'unsigned-from-appended-yahoo': { tree: 'registry', outcome: 'header: exactly one signed From field is required' },
  'unsigned-subject-prepended-proton': { tree: 'registry', outcome: 'header: exactly one signed Subject field is required' },
  'unsigned-subject-appended-proton': { tree: 'registry', outcome: 'header: exactly one signed Subject field is required' },
  'unsigned-from-prepended-proton': { tree: 'registry', outcome: 'header: exactly one signed From field is required' },
  'unsigned-from-appended-proton': { tree: 'registry', outcome: 'header: exactly one signed From field is required' },
  'unsigned-subject-prepended-fastmail': { tree: 'registry', outcome: 'header: exactly one signed Subject field is required' },
  'unsigned-subject-appended-fastmail': { tree: 'registry', outcome: 'header: exactly one signed Subject field is required' },
  'unsigned-from-prepended-fastmail': { tree: 'registry', outcome: 'header: exactly one signed From field is required' },
  'unsigned-from-appended-fastmail': { tree: 'registry', outcome: 'header: exactly one signed From field is required' },
  'unsigned-subject-prepended-gmx': { tree: 'registry', outcome: 'header: exactly one signed Subject field is required' },
  'unsigned-subject-appended-gmx': { tree: 'registry', outcome: 'header: exactly one signed Subject field is required' },
  'unsigned-from-prepended-gmx': { tree: 'registry', outcome: 'header: exactly one signed From field is required' },
  'unsigned-from-appended-gmx': { tree: 'registry', outcome: 'header: exactly one signed From field is required' },
  'multiple-signatures-one-valid': { tree: 'planted', outcome: 'DKIM: d= must equal the From domain' },
  'misaligned-d-gappssmtp': { tree: 'planted', outcome: 'DKIM: d= must equal the From domain' },
  'misaligned-d-onmicrosoft': { tree: 'planted', outcome: 'DKIM: d= must equal the From domain' },
  'weak-key-rsa1024': { tree: 'planted', outcome: 'RSA: modulus is shorter than 2048 bits' },
  'signature-plus-modulus': { tree: 'registry', outcome: 'RSA: signature is not below the modulus' },
  'wrong-body-hash': { tree: 'registry', outcome: 'accepted' },
  'from-not-signed': { tree: 'registry', outcome: 'header: exactly one signed From field is required' },
  'body-length-tag': { tree: 'registry', outcome: 'Subject: value does not open to the statement digest' },
  'subject-encoded-word-b': { tree: 'registry', outcome: 'Subject: must start with the recovery phrase' },
  'subject-encoded-word-icloud-web': { tree: 'registry', outcome: 'Subject: must start with the recovery phrase' },
  'subject-encoded-word-q': { tree: 'registry', outcome: 'Subject: must start with the recovery phrase' },
  'subject-folded-at-space': { tree: 'registry', outcome: 'accepted' },
  'subject-extra-whitespace': { tree: 'registry', outcome: 'accepted' },
  'subject-value-split-by-fold': { tree: 'registry', outcome: 'Subject: value must be lowercase hex' },
  'subject-phrase-split-by-whitespace': { tree: 'registry', outcome: 'Subject: must start with the recovery phrase' },
  'recovery-value-in-display-name': { tree: 'registry', outcome: 'Subject: must start with the recovery phrase' },
  'recovery-value-in-body': { tree: 'registry', outcome: 'Subject: must start with the recovery phrase' },
  'replay-other-statement': { tree: 'registry', outcome: 'Subject: value does not open to the statement digest' },
  'replay-other-account': { tree: 'registry', outcome: 'Subject: value does not open to the statement digest' },
};

// The cases are built while tests are collected; the Subject values need P2.
await initHashes();
const cases = buildAttacks(specAttackInput());

test('every attack case has a pinned outcome', () => {
  expect(cases.map((c) => c.id).sort()).toEqual(Object.keys(EXPECTED).sort());
});

describe.each(['valid-dkim-but-must-be-rejected-by-circuit', 'invalid-dkim', 'valid-dkim-and-must-be-accepted'] as const)('%s', (verdict) => {
  const of = cases.filter((c) => c.verdict === verdict);
  test.each(of.map((c) => [c.id, c] as const))('%s', async (_id, c) => {
    const want = EXPECTED[c.id]!;
    if (verdict === 'valid-dkim-but-must-be-rejected-by-circuit') expect(want.outcome).not.toBe('accepted');
    if (verdict === 'valid-dkim-and-must-be-accepted') expect(want.outcome).toBe('accepted');
    const got = await prove(c);
    expect(got.tree).toBe(want.tree);
    expect(got.accepted ? 'accepted' : got.reason).toBe(want.outcome);
  }, 60_000);
});
