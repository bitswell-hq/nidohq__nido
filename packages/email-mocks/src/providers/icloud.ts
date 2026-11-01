/**
 * iCloud Mail (icloud.com, me.com), a new plain-text message from Apple
 * Mail on macOS. Observed format and sources: PROVIDERS.md.
 */
import { crlf, formatRfc5322Date, prngHex, quotedPrintable } from '../format.js';
import { singleLine } from '../layout.js';
import { BASE64, BASE_TAGS, RELAXED, digits, field, fromValue, opaque, presentIn, seeded, timeTags, uuid, withBodyHashBeforeH } from './common.js';
import type { ComposeInput, ProviderProfile, SignerProfile } from './types.js';

/** Signed when present, in message order with the client's capitalisation. */
const SIGNED = ['from', 'to', 'subject', 'date', 'message-id', 'mime-version', 'content-type'];
const APPLE_MAIL = '2.3826.400.131.1.6';

export const icloudSigner: SignerProfile = {
  fieldName: 'Dkim-Signature',
  key: (fromDomain) => (fromDomain === 'me.com' ? 'icloud-me' : 'icloud'),
  domain: (fromDomain) => fromDomain,
  selector: () => '1a1hai',
  canon: RELAXED,
  tags: (ctx, { d, s, h }) => [
    ...BASE_TAGS,
    ['d', d],
    ['s', s],
    ...timeTags(ctx, 31536000),
    ['h', h.join(':')],
  ],
  // `x-icloud-hme` is never present: it signs that absence.
  signedHeaders: (headers) => [...presentIn(headers, SIGNED), 'x-icloud-hme'],
  // bh= comes before h=: the tag order is v a c d s t x bh h b.
  layout: (tags) => singleLine()(withBodyHashBeforeH(tags)),
};


function compose(input: ComposeInput) {
  const date = formatRfc5322Date(input.date, { offsetMinutes: input.utcOffsetMinutes });
  const headers = [
    field('Received', ` from smtpclient.apple (localhost [127.0.0.1])\r\n\tby p00-icloudmta-asmtp-us-west-2a-100-percent-${digits(input, 'pod', 1)} (Postfix) with ESMTPSA id ${prngHex(seeded(input, 'qid'), 11).toUpperCase()}\r\n\tfor <${input.to}>; ${formatRfc5322Date(input.date, { offsetMinutes: 0, comment: '(UTC)' })}`),
    field('From', ` ${fromValue(input)}`),
    field('Content-Type', ' text/plain;\r\n\tcharset=utf-8'),
    field('Content-Transfer-Encoding', ' quoted-printable'),
    field('Mime-Version', ` 1.0 (Mac OS X Mail 16.0 \\(${APPLE_MAIL.slice(2)}\\))`),
    field('Subject', ` ${input.subject}`),
    field('Message-Id', ` <${uuid(input, 'message-id', true)}@${input.from.slice(input.from.lastIndexOf('@') + 1)}>`),
    field('Date', ` ${date}`),
    field('To', ` ${input.to}`),
    field('X-Mailer', ` Apple Mail (${APPLE_MAIL})`),
    field('X-Proofpoint-Spam-Details-Enc', ` ${opaque(input, 'pp-enc', 210)}`),
    field('X-Proofpoint-GUID', ` ${opaque(input, 'pp-guid', 32, BASE64.slice(0, 62))}`),
    field('X-Proofpoint-ORIG-GUID', ` ${opaque(input, 'pp-guid', 32, BASE64.slice(0, 62))}`),
    field('X-Proofpoint-Virus-Version', ' vendor=baseguard\r\n engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49\r\n definitions=2026-10-15_03,2026-10-14_01,2026-10-15_01 signatures=0'),
  ];
  return { headers, body: quotedPrintable(crlf(input.body)) };
}

/** The outbound hop and iCloud's opaque tracking field above the signature. */
function trace(input: ComposeInput) {
  return [
    field('Received', ` from outbound.qs.icloud.com (unknown [127.0.0.2])\r\n\tby p00-icloudmta-asmtp-us-west-2a-100-percent-${digits(input, 'pod', 1)} (Postfix) with ESMTPS id ${prngHex(seeded(input, 'qid2'), 11).toUpperCase()}\r\n\tfor <${input.to}>; ${formatRfc5322Date(input.date, { offsetMinutes: 0, comment: '(UTC)' })}`),
    field('X-ICL-Out-Info', ` ${opaque(input, 'icl-out', 248)}`),
  ];
}

export const icloud: ProviderProfile = {
  id: 'icloud',
  name: 'iCloud Mail',
  domains: ['icloud.com', 'me.com'],
  signers: [icloudSigner],
  keyRecord: (p) => `v=DKIM1; k=rsa; p=${p}`,
  compose,
  trace,
};
