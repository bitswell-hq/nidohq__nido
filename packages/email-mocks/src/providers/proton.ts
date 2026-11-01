/**
 * Proton Mail (proton.me, protonmail.com), a new plain-text message from
 * the web client. Observed format and sources: PROVIDERS.md.
 */
import { crlf, formatRfc5322Date, quotedPrintable } from '../format.js';
import { tabLayout } from '../layout.js';
import { BASE64URL, BASE_TAGS, RELAXED, digits, field, fromValue, opaque, presentIn, timeTags, withBodyHashBeforeH } from './common.js';
import type { ComposeInput, ProviderProfile, SignerProfile } from './types.js';

/** Signed when present, in message order, then the fixed oversigned tail. */
const SIGNED = ['date', 'to', 'from', 'cc', 'subject', 'message-id', 'in-reply-to', 'references', 'feedback-id'];
const TAIL = ['From', 'To', 'Cc', 'Date', 'Subject', 'Reply-To', 'Feedback-ID', 'Message-ID', 'BIMI-Selector'];

export const protonSigner: SignerProfile = {
  fieldName: 'DKIM-Signature',
  key: (fromDomain) => (fromDomain === 'protonmail.com' ? 'protonmail' : 'proton'),
  domain: (fromDomain) => fromDomain,
  selector: (fromDomain) => (fromDomain === 'protonmail.com' ? 'protonmail3' : 'protonmail2'),
  canon: RELAXED,
  tags: (ctx, { d, s, h }) => [...BASE_TAGS, ['d', d], ['s', s], ...timeTags(ctx, 259200), ['h', h.join(':')]],
  signedHeaders: (headers) => [...presentIn(headers, SIGNED), ...TAIL],
  // v a c d s t x bh h b.
  layout: (tags) => protonLayout(withBodyHashBeforeH(tags)),
};

const protonLayout = tabLayout({ lines: [['v', 'a', 'c', 'd'], ['s', 't', 'x'], ['bh'], ['h'], ['b']], hWidth: 68, bWidth: 68 });

function compose(input: ComposeInput) {
  const domain = input.from.slice(input.from.lastIndexOf('@') + 1);
  const headers = [
    field('Date', ` ${formatRfc5322Date(input.date, { padDay: true })}`),
    field('To', ` ${input.to}`),
    field('From', ` ${fromValue(input)}`),
    field('Subject', ` ${input.subject}`),
    field('Message-ID', ` <${opaque(input, 'message-id', 107, BASE64URL)}=@${domain}>`),
    field('Feedback-ID', ` ${digits(input, 'feedback', 8)}:user:proton`),
    field('X-Pm-Message-ID', ` ${opaque(input, 'pm-message-id', 40)}`),
    field('MIME-Version', ' 1.0'),
    field('Content-Type', ' text/plain; charset=utf-8'),
    field('Content-Transfer-Encoding', ' quoted-printable'),
  ];
  return { headers, body: quotedPrintable(crlf(input.body)) };
}

export const proton: ProviderProfile = {
  id: 'proton',
  name: 'Proton Mail',
  domains: ['proton.me', 'protonmail.com'],
  signers: [protonSigner],
  keyRecord: (p) => `v=DKIM1; k=rsa; p=${p}`,
  compose,
};
