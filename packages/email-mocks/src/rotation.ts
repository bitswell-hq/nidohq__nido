/**
 * Key rotation as Gmail publishes it. The live selector and the previous
 * one are both published; an older selector stays in DNS with `p=` blanked
 * (RFC 6376 section 3.6.1: "An empty value means that this public key has
 * been revoked"), as 20230601 is today. The scenario blanks the previous
 * selector the same way.
 */
import type { MockDns } from './dns.js';
import { type GeneratedEmail, generateEmail, launchDns } from './generate.js';
import { GMAIL_PREVIOUS_SELECTOR, gmailPreviousSigner, googleInternalSigner } from './providers/gmail.js';
import { PROVIDERS } from './providers/index.js';

export interface RotationCase {
  id: string;
  description: string;
  email: GeneratedEmail;
  /** DNS before the rotation: both selectors live. */
  dnsBefore: MockDns;
  /** DNS after it: the previous selector blanked. */
  dnsAfter: MockDns;
  expected: { before: 'pass' | 'fail'; after: 'pass' | 'fail' };
}

/** `launchDns()` with Gmail's previous selector blanked on every Gmail domain. */
export function postRotationDns(): MockDns {
  const dns = launchDns();
  for (const domain of PROVIDERS.gmail.domains) dns.revokeKey(GMAIL_PREVIOUS_SELECTOR, domain);
  return dns;
}

export function rotationScenario(): { cases: RotationCase[] } {
  const base = {
    provider: 'gmail' as const,
    from: 'test.user@gmail.com',
    subject: 'Account recovery TEST-ONLY-rotation',
    body: 'Rotation fixture.\r\n',
    date: new Date('2026-09-01T08:00:00Z'),
  };
  return {
    cases: [
      {
        id: 'gmail-previous-selector',
        description: `Signed under the previous selector ${GMAIL_PREVIOUS_SELECTOR}: verifies while it is live, not once p= is blanked.`,
        email: generateEmail({ ...base, signers: [googleInternalSigner, gmailPreviousSigner] }),
        dnsBefore: launchDns(),
        dnsAfter: postRotationDns(),
        expected: { before: 'pass', after: 'fail' },
      },
      {
        id: 'gmail-live-selector',
        description: 'Signed under the live selector: verifies before and after the previous one is blanked.',
        email: generateEmail(base),
        dnsBefore: launchDns(),
        dnsAfter: postRotationDns(),
        expected: { before: 'pass', after: 'pass' },
      },
    ],
  };
}
