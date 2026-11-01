/**
 * Fastmail (fastmail.com), a new plain-text message from the web client.
 * Two signatures: one aligned with the From domain, one by
 * messagingengine.com. Observed format and sources: PROVIDERS.md.
 */
import type { HeaderField } from '../canon.js';
import { crlf, formatRfc5322Date, isAscii, prngHex, quotedPrintable, usZone } from '../format.js';
import { mailDkimLayout } from '../layout.js';
import { BASE_TAGS, RELAXED, countOf, field, fromValue, opaque, seeded, timeTags, uuid } from './common.js';
import type { ComposeInput, ProviderProfile, SignerProfile } from './types.js';

export const FASTMAIL_SELECTOR = 'fm2';
/** Rotated-out selectors, published blanked. */
export const FASTMAIL_REVOKED_SELECTORS = ['fm1', 'fm3'] as const;

/** Listed once more than they occur, so a later instance breaks the signature. */
const OVERSIGNED = ['cc', 'content-type', 'date', 'from', 'in-reply-to', 'reply-to', 'subject', 'to'];
/** Listed once if present. */
const ONCE = ['content-transfer-encoding', 'message-id', 'mime-version', 'references'];

function fastmailHeaders(headers: HeaderField[], oversigned: string[], once: string[], always: string[] = []): string[] {
  const names: string[] = [];
  for (const n of oversigned) for (let i = 0; i <= countOf(headers, n); i++) names.push(n);
  for (const n of once) if (countOf(headers, n) > 0) names.push(n);
  names.push(...always);
  return names.sort();
}

const tags: SignerProfile['tags'] = (ctx, { d, s, h }) => [
  ...BASE_TAGS,
  ['d', d],
  ['h', h.join(':')],
  ['s', s],
  ...timeTags(ctx, 86400),
];

export const fastmailSigner: SignerProfile = {
  fieldName: 'DKIM-Signature',
  key: () => 'fastmail',
  domain: (fromDomain) => fromDomain,
  selector: () => FASTMAIL_SELECTOR,
  canon: RELAXED,
  tags,
  signedHeaders: (headers) => fastmailHeaders(headers, OVERSIGNED, ONCE),
  layout: mailDkimLayout(),
};

export const messagingEngineSigner: SignerProfile = {
  fieldName: 'DKIM-Signature',
  key: () => 'messagingengine',
  domain: () => 'messagingengine.com',
  selector: () => FASTMAIL_SELECTOR,
  canon: RELAXED,
  tags,
  // x-sasl-enc is listed once and normally absent.
  signedHeaders: (headers) =>
    fastmailHeaders(headers, [...OVERSIGNED, 'feedback-id', 'x-me-sender'], [...ONCE, 'x-me-proxy'], ['x-sasl-enc']),
  layout: mailDkimLayout(),
};

function compose(input: ComposeInput) {
  const text = crlf(input.body);
  const ascii = isAscii(text) && text.split('\r\n').every((l) => l.length <= 76);
  const date = formatRfc5322Date(input.date, { offsetMinutes: input.utcOffsetMinutes, padDay: true });
  const headers = [
    field('X-ME-Sender', ` <xms:${opaque(input, 'xms', 56)}>`),
    field('X-ME-Proxy-Cause', ` ${opaque(input, 'proxy-cause', 280, 'abcdefghijklmnopqrstuvwxyz', { width: 70, indent: '    ' })}`),
    field('X-ME-Proxy', ` <xmx:${opaque(input, 'xmx', 56)}>`),
    field('Feedback-ID', ` i${prngHex(seeded(input, 'feedback'), 8)}:Fastmail`),
    field('Received', ` by mailuser.phl.internal (Postfix, from userid 501)\r\n\tid ${prngHex(seeded(input, 'qid'), 10).toUpperCase()}; ${formatRfc5322Date(input.date, usZone(input.date, 'eastern'))}`),
    field('X-Mailer', ' MessagingEngine.com Webmail Interface'),
    field('MIME-Version', ' 1.0'),
    field('Date', ` ${date}`),
    field('From', ` ${fromValue(input, 'always')}`),
    field('To', ` ${input.to}`),
    field('Message-Id', ` <${uuid(input, 'message-id')}@app.fastmail.com>`),
    field('Subject', ` ${input.subject}`),
    field('Content-Type', ascii ? ' text/plain' : ' text/plain;charset=utf-8'),
    field('Content-Transfer-Encoding', ascii ? ' 7bit' : ' quoted-printable'),
  ];
  return { headers, body: ascii ? text : quotedPrintable(text) };
}

/** The two internal hops Fastmail writes above its signatures. */
function trace(input: ComposeInput) {
  const edt = formatRfc5322Date(input.date, usZone(input.date, 'eastern'));
  return [
    field('Received', ` from phl-compute-05.internal (phl-compute-05.internal [10.202.2.45])\r\n\tby mailfout.phl.internal (Postfix) with ESMTP id ${prngHex(seeded(input, 'qid2'), 10).toUpperCase()}\r\n\tfor <${input.to}>; ${edt}`),
    field('Received', ` from phl-imap-12 ([10.202.2.86])\r\n  by phl-compute-05.internal (MEProxy); ${edt}`),
  ];
}

export const fastmail: ProviderProfile = {
  id: 'fastmail',
  name: 'Fastmail',
  domains: ['fastmail.com'],
  // messagingengine.com is signed first, so the aligned signature is on top.
  signers: [messagingEngineSigner, fastmailSigner],
  keyRecord: (p) => `v=DKIM1; k=rsa; p=${p}`,
  extraRecords: ['fastmail.com', 'messagingengine.com'].flatMap((domain) =>
    FASTMAIL_REVOKED_SELECTORS.map((s): [string, string] => [
      `${s}._domainkey.${domain}`,
      'v=DKIM1; k=rsa; n=Intentionally_Left_Blank_As_Per_DKIM_Rotation_BCP; p=',
    ]),
  ),
  compose,
  trace,
};
