/**
 * The standard fixture set: one honest message per launch domain, with and
 * without a display name, plus every adversarial case.
 */
import { buildAttacks, defaultAttackInput } from './attacks/index.js';
import type { AttackCase, AttackInput } from './attacks/types.js';
import { type GeneratedEmail, generateEmail, launchDns } from './generate.js';
import { PROVIDERS } from './providers/index.js';
import { rotationScenario } from './rotation.js';

export interface HonestFixture {
  id: string;
  email: GeneratedEmail;
}

export interface FixtureSet {
  honest: HonestFixture[];
  attacks: AttackCase[];
  rotation: ReturnType<typeof rotationScenario>;
}

export const HONEST_SUBJECT = 'Account recovery TEST-ONLY-0123456789abcdef';
export const HONEST_BODY = 'This message is a test fixture.\r\n';

export function honestFixtures(subject = HONEST_SUBJECT, body = HONEST_BODY): HonestFixture[] {
  return Object.values(PROVIDERS).flatMap((profile) =>
    profile.domains.flatMap((domain) =>
      [undefined, 'Test User'].map((displayName) => ({
        id: `${profile.id}-${domain}${displayName ? '-named' : ''}`,
        email: generateEmail({ provider: profile.id, from: `test.user@${domain}`, displayName, subject, body }),
      })),
    ),
  );
}

export function fixtureSet(input: AttackInput = defaultAttackInput()): FixtureSet {
  return { honest: honestFixtures(), attacks: buildAttacks(input), rotation: rotationScenario() };
}

export { launchDns };
