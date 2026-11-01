/**
 * The independent check: mailauth's DKIM verifier (pinned in package.json),
 * strict mode, resolving keys only from a mock DNS.
 */
import { dkimVerify } from 'mailauth/lib/dkim/verify';
import type { MockDns } from '../src/dns.js';
import type { GeneratedEmail } from '../src/generate.js';
import { launchDns } from '../src/generate.js';

export interface VerifierResult {
  domain: string;
  selector: string;
  result: string;
  comment?: string;
}

export function dnsFor(email: GeneratedEmail, base: MockDns = launchDns()): MockDns {
  for (const [name, value] of email.dnsRecords) if (!base.lookup(name)) base.publish(name, value);
  return base;
}

export async function verify(eml: Uint8Array, dns: MockDns, at: Date): Promise<VerifierResult[]> {
  const res = await dkimVerify(Buffer.from(eml), { resolver: dns.resolver, strict: true, curTime: at });
  return res.results.map((r) => ({
    domain: r.signingDomain ?? '',
    selector: r.selector ?? '',
    result: r.status.result,
    comment: r.status.comment,
  }));
}

/** Verification time: one minute after sending, inside every provider's x= window. */
export function verifyTime(email: GeneratedEmail): Date {
  return new Date(email.input.date.getTime() + 60_000);
}
