/**
 * GMX and WEB.DE (gmx.net, gmx.de, web.de), a new message from the web
 * client. Observed format and sources: PROVIDERS.md.
 */
import { crlf, formatRfc5322Date, isAscii, prngHex, quotedPrintable } from '../format.js';
import { tabLayout } from '../layout.js';
import { BASE64, BASE_TAGS, RELAXED, digits, field, fromValue, opaque, presentIn, seeded, timeTags, uuid, withBodyHashBeforeH } from './common.js';
import type { ComposeInput, ProviderProfile, SignerProfile } from './types.js';

/** Signed when present, in message order with original case, then the fixed tail. */
const SIGNED = [
  'from', 'to', 'cc', 'subject', 'date', 'message-id', 'in-reply-to', 'references', 'mime-version',
  'content-type', 'content-transfer-encoding',
];
const TAIL = [
  'cc', 'content-transfer-encoding', 'content-type', 'date', 'from', 'message-id', 'mime-version', 'reply-to',
  'subject', 'to',
];

const isWebDe = (domain: string) => domain === 'web.de';

/** A constant per brand, signed first. */
const SENDER_CLASS = {
  gmx: '724b4f7f-cbec-4199-ad4e-598c01a50d3a',
  webde: '814a7b36-bfc1-4dae-8640-3722d8ec6cd6',
};

const layout = tabLayout({
  lines: [['v', 'a', 'c', 'd'], ['s', 't', 'x'], ['i'], ['bh'], ['h'], ['b']],
  hWidth: 68,
  bWidth: 67,
  optional: { tag: 'i', width: 68 },
});

export const gmxSigner: SignerProfile = {
  fieldName: 'DKIM-Signature',
  key: (fromDomain) => (isWebDe(fromDomain) ? 'webde' : 'gmx'),
  domain: (fromDomain) => fromDomain,
  selector: (fromDomain) => (isWebDe(fromDomain) ? 's29768273' : 's31663417'),
  canon: RELAXED,
  // v a c d s t x i bh h b; i= is the From address.
  tags: (ctx, { d, s, h }) => [
    ...BASE_TAGS,
    ['d', d],
    ['s', s],
    ...timeTags(ctx, 604800),
    ['i', ctx.input.from],
    ['h', h.join(':')],
  ],
  signedHeaders: (headers) => ['X-UI-Sender-Class', ...presentIn(headers, SIGNED), ...TAIL],
  layout: (tags) => layout(withBodyHashBeforeH(tags)),
};

function compose(input: ComposeInput) {
  const domain = input.from.slice(input.from.lastIndexOf('@') + 1).toLowerCase();
  const brand = isWebDe(domain) ? 'webde' : 'gmx';
  const pod = `${prngHex(seeded(input, 'pod'), 10)}-${opaque(input, 'pod2', 5, BASE64.slice(26, 62))}`;
  const host = `trinity-msg-rest-${brand}-${brand}-live-${pod}`;
  const text = crlf(input.body);
  const eightBit = !isAscii(text);
  const headers = [
    field('X-UI-Sender-Class', ` ${SENDER_CLASS[brand]}`),
    field('Received', ` from [192.0.2.${Number(digits(input, 'ip', 2))}] ([192.0.2.${Number(digits(input, 'ip', 2))}]) by\r\n ${host}\r\n (via HTTP); ${formatRfc5322Date(input.date, { offsetMinutes: 0 })}`),
    field('MIME-Version', ' 1.0'),
    field('Message-ID', ` <trinity-${uuid(input, 'message-id')}-${input.date.getTime()}@${host}>`),
    field('From', ` ${fromValue(input)}`),
    field('To', ` ${input.to}`),
    field('Subject', ` ${input.subject}`),
    field('Content-Type', ' text/plain; charset=UTF-8'),
    field('Date', ` ${formatRfc5322Date(input.date, { offsetMinutes: 0 })}`),
    field('X-UI-CLIENT-META-MAIL-DROP', ' W10='),
    field('X-Provags-ID', ` V03:K1:${opaque(input, 'provags', 120, BASE64, { width: 70, indent: ' ' })}`),
    field('UI-OutboundReport', ` notjunk:1;M01:P0:${opaque(input, 'outbound', 900, BASE64, { width: 76, indent: ' ' })}`),
    // Appended when an 8-bit body is re-encoded; it is then signed.
    ...(eightBit ? [field('Content-Transfer-Encoding', ' quoted-printable')] : []),
  ];
  return { headers, body: eightBit ? quotedPrintable(text) : text };
}

export const gmx: ProviderProfile = {
  id: 'gmx',
  name: 'GMX / WEB.DE',
  domains: ['gmx.net', 'gmx.de', 'web.de'],
  signers: [gmxSigner],
  keyRecord: (p) => `v=DKIM1; p=${p}`,
  compose,
};
