/**
 * Adversarial emails for the circuit's attack suite. Each case is an email
 * plus the claim a forged or replayed proof would make about it and the
 * verdict a sound circuit must reach (see `Verdict`).
 *
 * The attacker is anyone with a mailbox at a launch provider: they control
 * every header and body octet their client submits, and the provider signs
 * whatever it receives. A case with an unsigned field was altered after
 * signing (in transit, or by the prover feeding the circuit).
 */
import { type Tag, parseTags } from '../dkim.js';
import { encodedWordB, encodedWordQ } from '../format.js';
import type { GeneratedEmail } from '../generate.js';
import { testKey } from '../keys.js';
import type { Message } from '../message.js';
import { gmailSigner } from '../providers/gmail.js';
import { PROVIDERS } from '../providers/index.js';
import { type ProviderId, type SignerProfile, isStandardSignature } from '../providers/types.js';
import type { KeyName } from '../keys.js';
import { appendHeader, buildEmail, prependHeader, replaceHeader, survivesInsertion } from './build.js';
import type { AttackCase, AttackInput, Claim } from './types.js';

export type { AttackCase, AttackInput, Claim, Verdict } from './types.js';

/** Public reports of each issue class in open-source email circuits. */
export const SOURCES = {
  matterLabs: 'https://docs.zk.email/files/matterlabs-zkemail-audit-report.pdf',
  zellic: 'https://docs.zk.email/files/zkemail-zellic-audit-report.pdf',
  consensys: 'https://github.com/zkemail/zkemail.nr/blob/main/audits/v1/consensys_diligence_v1.pdf',
  veridise: 'https://github.com/zkemail/zkemail.nr/blob/main/audits/v1/veridise_v1.pdf',
  zkemailNrIssue57: 'https://github.com/zkemail/zkemail.nr/issues/57',
  rfc6376: 'https://www.rfc-editor.org/rfc/rfc6376',
  rfc8301: 'https://www.rfc-editor.org/rfc/rfc8301',
} as const;

export function defaultAttackInput(): AttackInput {
  const recoveryValue = 'TEST-ONLY-0123456789abcdef';
  const phrase = 'Account recovery';
  return {
    victim: 'victim@gmail.com',
    attacker: 'attacker@gmail.com',
    phrase,
    subject: `${phrase} ${recoveryValue}`,
    recoveryValue,
    otherRecoveryValue: 'TEST-ONLY-fedcba9876543210',
    account: 'TEST-ACCOUNT-A',
    otherAccount: 'TEST-ACCOUNT-B',
    body: 'This message is a test fixture.\r\n',
  };
}

function domainOf(address: string): string {
  return address.slice(address.lastIndexOf('@') + 1);
}

function localOf(address: string): string {
  return address.slice(0, address.lastIndexOf('@'));
}

/** The first launch provider that sends for `address`. */
function providerFor(address: string): ProviderId {
  const domain = domainOf(address).toLowerCase();
  const hit = Object.values(PROVIDERS).find((p) => p.domains.includes(domain));
  if (!hit) throw new Error(`no launch provider for ${domain}`);
  return hit.id;
}

/** A signer with the same format as `base` but another key and identity. */
function rebrand(base: SignerProfile, key: KeyName, domain: string, selector: string): SignerProfile {
  return { ...base, key: () => key, domain: () => domain, selector: () => selector };
}

/** The provider's signature that DKIM verifiers read and that aligns with the From domain. */
export function alignedSigner(provider: ProviderId): SignerProfile {
  const hit = PROVIDERS[provider].signers.find((s) => isStandardSignature(s.fieldName) && s.domain('x.test') === 'x.test');
  if (!hit) throw new Error(`${provider} has no aligned signer`);
  return hit;
}

/** The provider's signers with the aligned one replaced by `replacement` (in order). */
function replaceAligned(provider: ProviderId, ...replacement: SignerProfile[]): SignerProfile[] {
  const aligned = alignedSigner(provider);
  return PROVIDERS[provider].signers.flatMap((s) => (s === aligned ? replacement : [s]));
}

/** Expected standard-verifier results, given the aligned signature's result; the others pass. */
function standardResults(email: GeneratedEmail, aligned: 'pass' | 'fail'): Array<'pass' | 'fail'> {
  const d = domainOf(email.input.from).toLowerCase();
  return email.signatures.filter((s) => s.standard).map((s) => (s.domain === d ? aligned : 'pass'));
}

function fromSpoofing(input: AttackInput): AttackCase[] {
  const provider = providerFor(input.attacker);
  const send = { provider, from: input.attacker, subject: input.subject, body: input.body, date: input.date };
  const claim: Claim = { from: input.victim, recoveryValue: input.recoveryValue };
  const withFrom = (raw: string) => (m: Message) => replaceHeader(m, 'From', raw);
  const valid = (id: string, description: string, from: string, source?: string): AttackCase => ({
    id,
    description,
    verdict: 'valid-dkim-but-must-be-rejected-by-circuit',
    email: buildEmail(send, { beforeSign: withFrom(from) }),
    claim,
    dkim: ['pass'],
    source,
  });

  const outlookAttacker = `${localOf(input.attacker)}@outlook.com`;
  const cases: AttackCase[] = [
    valid(
      'from-display-name-is-address',
      'Display name is the victim address; the addr-spec is the attacker.',
      `From: "${input.victim}" <${input.attacker}>`,
      SOURCES.matterLabs,
    ),
    valid(
      'from-display-name-holds-angle-address',
      'Display name holds "<victim>"; only the last angle-addr is the sender.',
      `From: "Some name <${input.victim}>" <${input.attacker}>`,
      SOURCES.matterLabs,
    ),
    {
      id: 'from-angle-addr-with-space',
      description: 'Outlook.com accepts "< attacker>" with a space after "<"; a parser anchored on "<" without the space finds the display name\'s address.',
      verdict: 'valid-dkim-but-must-be-rejected-by-circuit',
      email: buildEmail(
        { ...send, provider: 'outlook', from: outlookAttacker },
        { beforeSign: withFrom(`From: "Some name <${input.victim}>" < ${outlookAttacker}>`) },
      ),
      claim,
      dkim: ['pass'],
      source: SOURCES.matterLabs,
    },
    valid(
      'from-display-name-overlong',
      'A 400-octet display name carrying "<victim>" pushes the real address past a fixed-size From buffer.',
      `From: "x <${input.victim}> ${'A'.repeat(360)}" <${input.attacker}>`,
      SOURCES.consensys,
    ),
    valid(
      'from-quoted-local-part',
      'Quoted local part containing the victim address; the sender is the whole quoted string at the attacker domain.',
      `From: "${input.victim}"@${domainOf(input.attacker)}`,
      SOURCES.zellic,
    ),
    valid(
      'from-comment-before-address',
      'RFC 5322 comment holding the victim address before the real addr-spec.',
      `From: (${input.victim}) ${input.attacker}`,
    ),
    valid(
      'from-comment-after-address',
      'RFC 5322 comment holding the victim address after the real angle-addr.',
      `From: <${input.attacker}> (${input.victim})`,
    ),
    valid(
      'from-folded-relaxed',
      'From folded after an address-like display name; relaxed canonicalization unfolds it to one line.',
      `From: "${input.victim}"\r\n <${input.attacker}>`,
    ),
    {
      id: 'from-folded-simple-canonicalization',
      description: 'c=simple/simple keeps the fold in the signed bytes: the first physical line ends after the victim address.',
      verdict: 'valid-dkim-but-must-be-rejected-by-circuit',
      email: buildEmail(send, {
        beforeSign: withFrom(`From: "x <${input.victim}>"\r\n <${input.attacker}>`),
        signers: replaceAligned(provider, simpleCanonSigner()),
      }),
      claim,
      dkim: ['pass'],
      source: SOURCES.consensys,
    },
  ];
  return cases;
}

/** Gmail's format with c=simple/simple, which no launch provider uses. */
function simpleCanonSigner(): SignerProfile {
  return {
    ...gmailSigner,
    canon: { header: 'simple', body: 'simple' },
    tags: (ctx, id) =>
      gmailSigner.tags(ctx, id).map(([n, v]): Tag => (n === 'c' ? ['c', 'simple/simple'] : [n, v])),
  };
}

/**
 * An unsigned second Subject or From added above (prepended) or below
 * (appended) the signed one, per provider: whether DKIM still passes
 * depends on how often the provider lists the name in `h=`.
 */
function unsignedInsertions(input: AttackInput): AttackCase[] {
  const cases: AttackCase[] = [];
  for (const profile of Object.values(PROVIDERS)) {
    const from = `${localOf(input.attacker)}@${profile.domains[0]}`;
    const send = { provider: profile.id, from, subject: input.subject, body: input.body, date: input.date };
    const injections: Array<[string, string, Claim]> = [
      ['subject', `Subject: ${input.phrase} ${input.otherRecoveryValue}`, { from, recoveryValue: input.otherRecoveryValue }],
      ['from', `From: <${input.victim}>`, { from: input.victim, recoveryValue: input.recoveryValue }],
    ];
    for (const [name, raw, claim] of injections) {
      for (const where of ['top', 'bottom'] as const) {
        const email = buildEmail(send, {
          afterSign: (m) => (where === 'top' ? prependHeader(m, raw) : appendHeader(m, raw)),
        });
        const results = email.signatures.filter((sig) => sig.standard).map((sig) =>
          survivesInsertion(sig.signedHeaders, 1, name, where) ? ('pass' as const) : ('fail' as const),
        );
        const passes = results.includes('pass');
        cases.push({
          id: `unsigned-${name}-${where === 'top' ? 'prepended' : 'appended'}-${profile.id}`,
          description: `A second, unsigned ${name === 'subject' ? 'Subject' : 'From'} ${
            where === 'top' ? 'above' : 'below'
          } the signed one on a ${profile.name} message; ${
            passes ? 'DKIM still passes, so the circuit must use the signed instance' : 'oversigning in h= breaks the signature'
          }.`,
          verdict: passes ? 'valid-dkim-but-must-be-rejected-by-circuit' : 'invalid-dkim',
          email,
          claim,
          dkim: results,
          source: SOURCES.rfc6376,
        });
      }
    }
  }
  return cases;
}

function keepRecords(email: GeneratedEmail, keep: (name: string) => boolean): GeneratedEmail {
  return { ...email, dnsRecords: email.dnsRecords.filter(([name]) => keep(name)) };
}

function signatureCases(input: AttackInput): AttackCase[] {
  const provider = providerFor(input.victim);
  const victimSend = { provider, from: input.victim, subject: input.subject, body: input.body, date: input.date };
  const claim: Claim = { from: input.victim, recoveryValue: input.recoveryValue };
  const victimDomain = domainOf(input.victim);
  const signer = alignedSigner(provider);
  const selector = signer.selector(victimDomain);

  const forgedOnTop = rebrand(signer, 'attacker', victimDomain, selector);
  const attackerOwn = rebrand(signer, 'attacker', 'attacker.test', 'mail');
  const gappsDomain = `${victimDomain.replace(/\./g, '-')}.${selector}.gappssmtp.com`;
  const only = (...signers: SignerProfile[]) => ({ signers: replaceAligned(provider, ...signers) });

  return [
    {
      id: 'multiple-signatures-one-valid',
      description: `A valid signature by attacker.test under a forged d=${victimDomain} signature made with the wrong key; only the d=${victimDomain} one may count.`,
      verdict: 'valid-dkim-but-must-be-rejected-by-circuit',
      // The forged signature names the provider's real selector, whose
      // record is the provider's key, not the attacker's.
      email: keepRecords(buildEmail(victimSend, only(attackerOwn, forgedOnTop)), (name) => name.endsWith('.attacker.test')),
      claim,
      dkim: ['fail', 'pass'],
      source: SOURCES.veridise,
    },
    {
      id: 'misaligned-d-gappssmtp',
      description: `Signed only by Google's shared Workspace key (d=${gappsDomain}), not by ${victimDomain}.`,
      verdict: 'valid-dkim-but-must-be-rejected-by-circuit',
      email: buildEmail(victimSend, only(rebrand(signer, 'gappssmtp', gappsDomain, selector))),
      claim,
      dkim: ['pass'],
      source: SOURCES.veridise,
    },
    {
      id: 'misaligned-d-onmicrosoft',
      description: `Signed only by a Microsoft 365 tenant's default domain (d=attacker.onmicrosoft.com), not by ${victimDomain}.`,
      verdict: 'valid-dkim-but-must-be-rejected-by-circuit',
      email: buildEmail(victimSend, {
        ...only(rebrand(signer, 'onmicrosoft', 'attacker.onmicrosoft.com', `selector1-${victimDomain.replace(/\./g, '-')}`)),
      }),
      claim,
      dkim: ['pass'],
      source: SOURCES.veridise,
    },
    {
      id: 'weak-key-rsa1024',
      description: 'Aligned signature under a 1024-bit key: RFC 8301 verifiers accept it, the registry and circuit require 2048 bits.',
      verdict: 'valid-dkim-but-must-be-rejected-by-circuit',
      email: buildEmail(victimSend, only(rebrand(signer, 'weak', victimDomain, 's1024'))),
      claim,
      dkim: ['pass'],
      source: SOURCES.rfc8301,
    },
    signaturePlusModulus(victimSend, claim),
    {
      id: 'wrong-body-hash',
      description: 'bh= is the hash of a different body; the header signature is valid over that bh=.',
      verdict: 'invalid-dkim',
      email: buildEmail(victimSend, {
        overrides: {
          signer: (_i, signInput, s) => (s === signer ? { ...signInput, bodyHashOverride: Buffer.alloc(32, 7).toString('base64') } : signInput),
        },
      }),
      claim,
      dkim: ['fail'],
    },
    {
      id: 'from-not-signed',
      description: 'h= omits From; RFC 6376 section 6.1.1 makes such a signature unusable.',
      verdict: 'invalid-dkim',
      email: buildEmail(victimSend, {
        ...only({ ...signer, signedHeaders: (headers) => signer.signedHeaders(headers).filter((n) => n.toLowerCase() !== 'from') }),
      }),
      claim,
      dkim: ['fail'],
      source: SOURCES.rfc6376,
    },
    {
      id: 'body-length-tag',
      description: 'l= covers the original body only; text appended after signing carries another recovery value.',
      verdict: 'valid-dkim-but-must-be-rejected-by-circuit',
      email: buildEmail(victimSend, {
        overrides: {
          signer: (_i, signInput, s) =>
            s === signer ? { ...signInput, bodyLength: Buffer.byteLength(input.body.replace(/\r?\n/g, '\r\n')) } : signInput,
        },
        afterSign: (m) => ({ ...m, body: `${m.body}\r\n${input.phrase} ${input.otherRecoveryValue}\r\n` }),
      }),
      claim: { from: input.victim, recoveryValue: input.otherRecoveryValue },
      dkim: ['pass'],
      source: SOURCES.veridise,
    },
  ];
}

/**
 * b= replaced by sigma + N. A verifier that checks sigma < N (RFC 8017
 * section 5.2.2) rejects it; one that only checks bit length accepts a
 * second encoding of the same signature. The message's Date is nudged
 * until sigma + N still fits in the key's 256 octets.
 */
function signaturePlusModulus(
  send: { provider: ProviderId; from: string; subject: string; body: string; date?: Date },
  claim: Claim,
): AttackCase {
  const key = testKey(alignedSigner(send.provider).key(domainOf(send.from)));
  const limit = 1n << BigInt(key.bits);
  for (let attempt = 0; attempt < 64; attempt++) {
    const date = new Date((send.date ?? new Date('2026-10-15T09:30:00Z')).getTime() + attempt * 1000);
    let plus: string | undefined;
    const email = buildEmail(
      { ...send, date },
      {
        afterSign: (m) => {
          const domain = domainOf(send.from);
          const at = m.headers.findIndex(
            (h) => isStandardSignature(h.name) && parseTags(h.raw.slice(h.raw.indexOf(':') + 1)).get('d') === domain,
          );
          const raw = m.headers[at]!.raw;
          const b = parseTags(raw.slice(raw.indexOf(':') + 1)).get('b')!;
          const sigma = BigInt(`0x${Buffer.from(b, 'base64').toString('hex')}`);
          const malleated = sigma + key.modulus;
          if (malleated >= limit) return m;
          plus = Buffer.from(malleated.toString(16).padStart(key.bits / 4, '0'), 'hex').toString('base64');
          const headers = [...m.headers];
          headers[at] = { ...headers[at]!, raw: raw.replace(/b=[A-Za-z0-9+/=\s]+$/, `b=${plus}`) };
          return { ...m, headers };
        },
      },
    );
    if (plus) {
      return {
        id: 'signature-plus-modulus',
        description: 'b= is sigma + N, a non-reduced second encoding of a valid signature, still 256 octets.',
        verdict: 'invalid-dkim',
        email,
        claim,
        dkim: ['fail'],
        source: SOURCES.veridise,
      };
    }
  }
  throw new Error('no date gave sigma + N below 2^bits');
}

function subjectCases(input: AttackInput): AttackCase[] {
  const provider = providerFor(input.victim);
  const send = { provider, from: input.victim, body: input.body, date: input.date };
  const claim: Claim = { from: input.victim, recoveryValue: input.recoveryValue };
  const withSubject = (raw: string) => (m: Message) => replaceHeader(m, 'Subject', raw);
  const value = input.recoveryValue;
  const half = Math.floor(value.length / 2);
  const phraseOnly = input.phrase;
  const at = input.subject.indexOf(' ');
  const firstWord = input.subject.slice(0, at);

  const valid = (id: string, description: string, verdict: AttackCase['verdict'], email: AttackCase['email'], source?: string): AttackCase => ({
    id,
    description,
    verdict,
    email,
    claim,
    dkim: ['pass'],
    source,
  });
  return [
    valid(
      'subject-encoded-word-b',
      'Subject as one RFC 2047 B encoded-word; it decodes to the recovery Subject but its octets are not that Subject.',
      'valid-dkim-but-must-be-rejected-by-circuit',
      buildEmail({ ...send, subject: input.subject }, { beforeSign: withSubject(`Subject: ${encodedWordB(input.subject).join(' ')}`) }),
    ),
    {
      id: 'subject-encoded-word-icloud-web',
      description:
        'The form the iCloud web client was observed to send: a pure-ASCII Subject as folded RFC 2047 B encoded-words, signed by iCloud.',
      verdict: 'valid-dkim-but-must-be-rejected-by-circuit',
      email: buildEmail(
        { provider: 'icloud', from: `${localOf(input.victim)}@icloud.com`, subject: input.subject, body: input.body, date: input.date },
        { beforeSign: withSubject(`Subject: ${encodedWordB(input.subject, 'utf-8').join('\r\n ')}`) },
      ),
      claim: { from: `${localOf(input.victim)}@icloud.com`, recoveryValue: input.recoveryValue },
      dkim: ['pass'],
    },
    valid(
      'subject-encoded-word-q',
      'Subject as one RFC 2047 Q encoded-word.',
      'valid-dkim-but-must-be-rejected-by-circuit',
      buildEmail({ ...send, subject: input.subject }, { beforeSign: withSubject(`Subject: ${encodedWordQ(input.subject)}`) }),
    ),
    valid(
      'subject-folded-at-space',
      'Subject folded at an existing space; relaxed canonicalization restores the same signed octets.',
      'valid-dkim-and-must-be-accepted',
      buildEmail({ ...send, subject: input.subject }, {
        beforeSign: withSubject(`Subject: ${input.subject.slice(0, at)}\r\n ${input.subject.slice(at + 1)}`),
      }),
    ),
    valid(
      'subject-extra-whitespace',
      'Runs of spaces and tabs between Subject words; relaxed canonicalization collapses them to the same octets.',
      'valid-dkim-and-must-be-accepted',
      buildEmail({ ...send, subject: input.subject }, {
        beforeSign: withSubject(`Subject:  ${input.subject.split(' ').join(' \t ')}  `),
      }),
    ),
    valid(
      'subject-value-split-by-fold',
      'Recovery value folded mid-token: unfolding leaves a space inside the value.',
      'valid-dkim-but-must-be-rejected-by-circuit',
      buildEmail({ ...send, subject: input.subject }, {
        beforeSign: withSubject(
          `Subject: ${input.subject.slice(0, input.subject.length - value.length)}${value.slice(0, half)}\r\n ${value.slice(half)}`,
        ),
      }),
    ),
    valid(
      'subject-phrase-split-by-whitespace',
      'Whitespace inside a word of the fixed phrase.',
      'valid-dkim-but-must-be-rejected-by-circuit',
      buildEmail({ ...send, subject: input.subject }, {
        beforeSign: withSubject(`Subject: ${firstWord.slice(0, 2)} ${firstWord.slice(2)}${input.subject.slice(at)}`),
      }),
    ),
    valid(
      'recovery-value-in-display-name',
      'Subject has the phrase only; the recovery value is the display name.',
      'valid-dkim-but-must-be-rejected-by-circuit',
      buildEmail({ ...send, subject: phraseOnly, displayName: value }),
    ),
    valid(
      'recovery-value-in-body',
      'Subject has the phrase only; the recovery value is in the body.',
      'valid-dkim-but-must-be-rejected-by-circuit',
      buildEmail({ ...send, subject: phraseOnly, body: `${value}\r\n` }),
    ),
  ];
}

function replayCases(input: AttackInput): AttackCase[] {
  const provider = providerFor(input.victim);
  const email = buildEmail({ provider, from: input.victim, subject: input.subject, body: input.body, date: input.date });
  return [
    {
      id: 'replay-other-statement',
      description: 'An honest recovery email presented for a different recovery value.',
      verdict: 'valid-dkim-but-must-be-rejected-by-circuit',
      email,
      claim: { from: input.victim, recoveryValue: input.otherRecoveryValue, account: input.account },
      dkim: ['pass'],
      source: SOURCES.zellic,
    },
    {
      id: 'replay-other-account',
      description: 'An honest recovery email presented for a different account with the same address.',
      verdict: 'valid-dkim-but-must-be-rejected-by-circuit',
      email,
      claim: { from: input.victim, recoveryValue: input.recoveryValue, account: input.otherAccount },
      dkim: ['pass'],
    },
  ];
}

export function buildAttacks(input: AttackInput = defaultAttackInput()): AttackCase[] {
  // A case written with one result means the aligned signature's; the
  // provider's other standard signatures (Fastmail's second one) pass.
  return [
    ...fromSpoofing(input),
    ...unsignedInsertions(input),
    ...signatureCases(input),
    ...subjectCases(input),
    ...replayCases(input),
  ].map((c) => (c.dkim.length === 1 ? { ...c, dkim: standardResults(c.email, c.dkim[0]!) } : c));
}

