/**
 * Gmail (gmail.com, googlemail.com), a new message from the web client in
 * plain-text mode. Observed format and sources: PROVIDERS.md.
 */
import type { HeaderField } from '../canon.js';
import { formatRfc5322Date, prngHex, usZone } from '../format.js';
import { publicKeyBase64, testKey } from '../keys.js';
import { lineLayout } from '../layout.js';
import { BASE64, BASE_TAGS, RELAXED, digits, field, fromValue, opaque, plainBody, seeded, timeTags } from './common.js';
import type { ComposeInput, ProviderProfile, SignerProfile } from './types.js';

export const GMAIL_SELECTOR = '20260707';
/** The previous selector, still published with a live key. */
export const GMAIL_PREVIOUS_SELECTOR = '20251104';
/** Older selectors Google leaves published with `p=` blanked. */
export const GMAIL_REVOKED_SELECTORS = ['20230601', '20221208', '20210112'] as const;

/** Signed when present; listed bottom-up, then the fixed oversigned tail. */
const SIGNED = [
  'from', 'to', 'cc', 'subject', 'date', 'message-id', 'in-reply-to', 'references', 'mime-version',
  'content-type', 'content-transfer-encoding',
];
const TAIL = ['from', 'to', 'cc', 'subject', 'date', 'message-id', 'reply-to', 'content-type'];

function bottomUp(headers: HeaderField[]): string[] {
  return headers
    .filter((h) => SIGNED.includes(h.name.toLowerCase()))
    .map((h) => h.name.toLowerCase())
    .reverse();
}

const layout = lineLayout({
  lead: ' ',
  indent: '        ',
  lines: [['v', 'a', 'c'], ['d', 's', 't', 'x', 'darn'], ['h'], ['bh'], ['b']],
  wrap: {
    h: { at: 'before-colon', width: 77, indent: '         ' },
    b: { at: 'chunk', size: 68, indent: '         ' },
  },
});

function recipientDomain(input: ComposeInput): string {
  return input.to.slice(input.to.lastIndexOf('@') + 1).toLowerCase();
}

export const gmailSigner: SignerProfile = {
  fieldName: 'DKIM-Signature',
  key: () => 'gmail',
  domain: (fromDomain) => fromDomain,
  selector: () => GMAIL_SELECTOR,
  canon: RELAXED,
  tags: (ctx, { d, s, h }) => [
    ...BASE_TAGS,
    ['d', d],
    ['s', s],
    ...timeTags(ctx, 604800),
    ['darn', recipientDomain(ctx.input)],
    ['h', h.join(':')],
  ],
  signedHeaders: (headers) => [...bottomUp(headers), ...TAIL],
  layout,
};

/** Google's internal copy, d=1e100.net; DKIM verifiers do not read this field name. */
export const googleInternalSigner: SignerProfile = {
  fieldName: 'X-Google-DKIM-Signature',
  key: () => 'google-1e100',
  domain: () => '1e100.net',
  selector: () => GMAIL_SELECTOR,
  canon: RELAXED,
  tags: (ctx, { d, s, h }) => [...BASE_TAGS, ['d', d], ['s', s], ...timeTags(ctx, 604800), ['h', h.join(':')]],
  signedHeaders: (headers) => [...bottomUp(headers), 'x-gm-gg', 'x-gm-message-state', ...TAIL],
  layout,
};

/** Signs as Gmail did under the previous selector, for the rotation scenario. */
export const gmailPreviousSigner: SignerProfile = {
  ...gmailSigner,
  key: () => 'gmail-previous',
  selector: () => GMAIL_PREVIOUS_SELECTOR,
};

function compose(input: ComposeInput) {
  const { body, encoded } = plainBody(input);
  const date = formatRfc5322Date(input.date, { offsetMinutes: input.utcOffsetMinutes });
  const local = opaque(input, 'message-id', 49, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+_=-');
  const headers = [
    field('X-Gm-Message-State', ` AOJu0Y${opaque(input, 'gm-state', 66)}`),
    field('X-Gm-Gg', ` ${opaque(input, 'gm-gg', 60)}\r\n\t${opaque(input, 'gm-gg-2', 60)}`),
    field(
      'X-Received',
      ` by 2002:a05:6512:${prngHex(seeded(input, 'xr1'), 4)}:b0:${prngHex(seeded(input, 'xr2'), 3)}:${prngHex(seeded(input, 'xr3'), 4)} with SMTP id\r\n` +
        ` 2adb3069b0e04-${prngHex(seeded(input, 'xr4'), 11)}mr${digits(input, 'xr5', 7)}e87.${digits(input, 'xr6', 2)}.${digits(input, 'xr7', 13)}; ${date}`,
    ),
    field('MIME-Version', ' 1.0'),
    field('From', ` ${fromValue(input)}`),
    field('Date', ` ${date}`),
    field('X-Gm-Features', ` AWmQ_b${opaque(input, 'gm-features', 57, `${BASE64.slice(0, 62)}-_`)}`),
    field('Message-ID', ` <CA${local}@mail.gmail.com>`),
    field('Subject', ` ${input.subject}`),
    field('To', ` ${input.to}`),
    field('Content-Type', ' text/plain; charset="UTF-8"'),
    ...(encoded ? [field('Content-Transfer-Encoding', ' quoted-printable')] : []),
  ];
  return { headers, body };
}

/** The outbound hop Google writes above its signatures. */
function trace(input: ComposeInput): HeaderField[] {
  return [
    field(
      'Received',
      ` by mail-lf1-f${digits(input, 'pool', 2)}.google.com with SMTP id 2adb3069b0e04-${prngHex(seeded(input, 'rcv'), 11)}\r\n` +
        `        for <${input.to}>; ${formatRfc5322Date(input.date, usZone(input.date, 'pacific'))}`,
    ),
  ];
}

const keyRecord = (p: string) => `v=DKIM1; k=rsa; p=${p}`;

export const gmail: ProviderProfile = {
  id: 'gmail',
  name: 'Gmail',
  domains: ['gmail.com', 'googlemail.com'],
  signers: [googleInternalSigner, gmailSigner],
  keyRecord,
  extraRecords: ['gmail.com', 'googlemail.com'].flatMap((domain): Array<[string, string]> => [
    [`${GMAIL_PREVIOUS_SELECTOR}._domainkey.${domain}`, keyRecord(publicKeyBase64(testKey('gmail-previous')))],
    ...GMAIL_REVOKED_SELECTORS.map((s): [string, string] => [`${s}._domainkey.${domain}`, keyRecord('')]),
  ]),
  compose,
  trace,
};
