/**
 * Yahoo Mail (yahoo.com), a new message from the web client. Observed
 * format and sources: PROVIDERS.md.
 */
import type { HeaderField } from '../canon.js';
import { formatRfc5322Date } from '../format.js';
import { singleLine } from '../layout.js';
import { BASE_TAGS, RELAXED, digits, field, fromValue, opaque, plainBody, presentIn, timeTags, uuid, withBodyHashBeforeH } from './common.js';
import type { ComposeInput, ProviderProfile, SignerProfile } from './types.js';

/** Signed when present, in message order, then the fixed tail. */
const SIGNED = ['date', 'from', 'reply-to', 'to', 'cc', 'subject', 'references', 'in-reply-to'];
const TAIL = ['From', 'Subject', 'Reply-To'];

/** v a c d s t bh h b: `t=` but no `x=`, `bh=` before `h=`. */
function yahooTags(ctx: Parameters<SignerProfile['tags']>[0], d: string, s: string, h: string[]) {
  return [...BASE_TAGS, ['d', d], ['s', s], ...timeTags(ctx), ['h', h.join(':')]] as Array<[string, string]>;
}


export const yahooSigner: SignerProfile = {
  fieldName: 'DKIM-Signature',
  key: () => 'yahoo',
  domain: (fromDomain) => fromDomain,
  selector: () => 's2048',
  canon: RELAXED,
  tags: (ctx, { d, s, h }) => yahooTags(ctx, d, s, h),
  signedHeaders: (headers: HeaderField[]) => [...presentIn(headers, SIGNED), ...TAIL],
  layout: (tags) => singleLine()(withBodyHashBeforeH(tags)),
};

/** Yahoo's internal copy with the same key; DKIM verifiers do not read this field name. */
export const yahooInternalSigner: SignerProfile = {
  ...yahooSigner,
  fieldName: 'X-SONIC-DKIM-SIGN',
  signedHeaders: (headers) => ['X-Sonic-MF', ...presentIn(headers, ['date', 'from', 'to', 'cc', 'subject']), 'From', 'Subject'],
};

function compose(input: ComposeInput) {
  const { body, encoded } = plainBody(input);
  const id = `${digits(input, 'mid1', 10)}.${digits(input, 'mid2', 7)}.${input.date.getTime()}`;
  const headers = [
    field('X-YMail-OSG', ` ${opaque(input, 'osg', 1200, undefined, { width: 76, indent: ' ' })}`),
    field('X-Sonic-MF', ` <${input.from}>`),
    field('X-Sonic-ID', ` ${uuid(input, 'sonic-id')}`),
    field(
      'Received',
      ` from sonic.gate.mail.ne1.yahoo.com by sonic${digits(input, 'sonic', 3)}.consmr.mail.ne1.yahoo.com with HTTP; ${formatRfc5322Date(input.date)}`,
    ),
    field('Date', ` ${formatRfc5322Date(input.date, { comment: '(UTC)' })}`),
    field('From', ` ${fromValue(input)}`),
    field('To', ` ${input.to}`),
    field('Message-ID', ` <${id}@mail.yahoo.com>`),
    // Yahoo adds References naming the message's own ID with `.ref` before the `@`.
    field('References', ` <${id}.ref@mail.yahoo.com>`),
    field('Subject', ` ${input.subject}`),
    field('MIME-Version', ' 1.0'),
    field('Content-Type', ' text/plain; charset=UTF-8'),
    field('Content-Transfer-Encoding', encoded ? ' quoted-printable' : ' 7bit'),
    field('X-Mailer', ' WebService/1.1.26541 YMailNorrin'),
    field('Content-Length', ` ${Buffer.byteLength(body, 'latin1')}`),
  ];
  return { headers, body };
}

export const yahoo: ProviderProfile = {
  id: 'yahoo',
  name: 'Yahoo Mail',
  domains: ['yahoo.com'],
  signers: [yahooInternalSigner, yahooSigner],
  keyRecord: (p) => `k=rsa; p=${p};`,
  compose,
};
