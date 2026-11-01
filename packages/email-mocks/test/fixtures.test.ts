import { describe, expect, it } from 'vitest';
import { buildAttacks } from '../src/attacks/index.js';
import { honestFixtures } from '../src/fixtures.js';
import { generateEmail, launchDns } from '../src/generate.js';
import { rotationScenario } from '../src/rotation.js';
import { dnsFor, verify, verifyTime } from './verify.js';

describe('honest fixtures verify under mailauth (strict) against the mock DNS', () => {
  for (const { id, email } of honestFixtures()) {
    it(id, async () => {
      const results = await verify(email.eml, launchDns(), verifyTime(email));
      const standard = email.signatures.filter((s) => s.standard);
      expect(results.map((r) => [r.domain, r.selector, r.result])).toEqual(
        standard.map((s) => [s.domain, s.selector, 'pass']),
      );
    });
  }
});

describe('attack cases match their expected standard-verifier results', () => {
  for (const attack of buildAttacks()) {
    it(`${attack.id} (${attack.verdict})`, async () => {
      const results = await verify(attack.email.eml, dnsFor(attack.email), verifyTime(attack.email));
      const got = results.map((r) => (r.result === 'pass' ? 'pass' : 'fail'));
      expect(got, JSON.stringify(results)).toEqual(attack.dkim);
      if (attack.verdict === 'invalid-dkim') expect(got).not.toContain('pass');
      else expect(got).toContain('pass');
    });
  }
});

describe('key rotation', () => {
  for (const c of rotationScenario().cases) {
    it(c.id, async () => {
      const at = verifyTime(c.email);
      const before = await verify(c.email.eml, c.dnsBefore, at);
      const after = await verify(c.email.eml, c.dnsAfter, at);
      expect(before.map((r) => r.result === 'pass' ? 'pass' : 'fail')).toEqual([c.expected.before]);
      expect(after.map((r) => r.result === 'pass' ? 'pass' : 'fail')).toEqual([c.expected.after]);
    });
  }
});

describe('determinism', () => {
  it('the same inputs give the same octets', () => {
    const opts = { provider: 'fastmail' as const, from: 'a@fastmail.com', subject: 's', body: 'b\r\n' };
    expect(Buffer.from(generateEmail(opts).eml).equals(Buffer.from(generateEmail(opts).eml))).toBe(true);
  });
});
