/**
 * Outlook.com / Hotmail, a new plain-text message from Outlook on the web
 * (Exchange Online). Observed format and sources: PROVIDERS.md.
 */
import { formatRfc5322Date, isAscii, prngHex, quotedPrintable, crlf } from '../format.js';
import { exchangeLayout } from '../layout.js';
import { BASE64, BASE_TAGS, RELAXED, digits, field, fromValue, opaque, seeded, uuid } from './common.js';
import type { ComposeInput, ProviderProfile, SignerProfile } from './types.js';

/** A fixed list, fixed case; the last name is never present, so it signs its absence. */
export const OUTLOOK_SIGNED_HEADERS = [
  'From', 'Date', 'Subject', 'Message-ID', 'Content-Type', 'MIME-Version', 'X-MS-Exchange-SenderADCheck',
];

export const outlookSigner: SignerProfile = {
  fieldName: 'DKIM-Signature',
  key: () => 'outlook',
  domain: (fromDomain) => fromDomain,
  selector: () => 'selector1',
  canon: RELAXED,
  // No t= and no x=.
  tags: (_ctx, { d, s, h }) => [...BASE_TAGS, ['d', d], ['s', s], ['h', h.join(':')]],
  signedHeaders: () => [...OUTLOOK_SIGNED_HEADERS],
  layout: exchangeLayout(),
};

/** Mailbox server and region names in Exchange Online's shape. */
function server(input: ComposeInput) {
  const mbx = `AM9PR02MB${digits(input, 'mbx', 4)}`;
  return { mbx, host: `${mbx}.eurprd02.prod.outlook.com` };
}

function compose(input: ComposeInput) {
  const { mbx, host } = server(input);
  const date = formatRfc5322Date(input.date, { offsetMinutes: 0 });
  const text = crlf(input.body);
  const charset = isAscii(text) ? 'us-ascii' : 'utf-8';
  const arrival = `${input.date.getUTCDate()} ${input.date.toUTCString().slice(8, 16)} ${input.date.toISOString().slice(11, 19)}.${digits(input, 'arr', 4)} (UTC)`;
  const network = uuid(input, 'network');
  const ip = `fe80::${prngHex(seeded(input, 'ip1'), 4)}:${prngHex(seeded(input, 'ip2'), 4)}:${prngHex(seeded(input, 'ip3'), 4)}:${prngHex(seeded(input, 'ip4'), 4)}`;
  const headers = [
    field(
      'Received',
      ` from ${host} (2603:10a6:20b:${prngHex(seeded(input, 'ip5'), 3)}::${prngHex(seeded(input, 'ip6'), 2)})\r\n by ${host} (2603:10a6:20b:${prngHex(seeded(input, 'ip5'), 3)}::${prngHex(seeded(input, 'ip6'), 2)}) with\r\n Microsoft SMTP Server (version=TLS1_2,\r\n cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9253.17; ${date}`,
    ),
    field('Received', ` from ${host} ([${ip}]) by\r\n ${host} ([${ip}%5]) with mapi id\r\n 15.20.9253.017; ${date}`),
    field('From', ` ${fromValue(input)}`),
    field('To', ` ${input.to}`),
    field('Subject', ` ${input.subject}`),
    field('Thread-Topic', ` ${input.subject}`),
    field('Thread-Index', ` AQHc${opaque(input, 'thread-index', 28)}==`),
    field('Date', ` ${date}`),
    field('Message-ID', ` <${mbx}${prngHex(seeded(input, 'msgid'), 25).toUpperCase()}@${host}>`),
    field('Accept-Language', ' en-US'),
    field('Content-Language', ' en-US'),
    field('X-MS-Has-Attach', ''),
    field('X-MS-TNEF-Correlator', ''),
    field('x-ms-exchange-messagesentrepresentingtype', ' 1'),
    field('x-ms-publictraffictype', ' Email'),
    field('x-ms-traffictypediagnostic', ` ${mbx}:EE_|${mbx.replace('02', '01')}:EE_`),
    field('x-ms-office365-filtering-correlation-id', ` ${network}`),
    field('x-microsoft-antispam', ` BCL:0;ARA:14566002|8060799015|15080799012|19110799012|${digits(input, 'ara', 10)};`),
    field('x-microsoft-antispam-message-info', `\r\n ${opaque(input, 'ams', 600, BASE64, { width: 76, indent: ' ' })}`),
    field('x-ms-exchange-antispam-messagedata-chunkcount', ' 1'),
    field('x-ms-exchange-antispam-messagedata-0', `\r\n ${opaque(input, 'amd', 900, BASE64, { width: 76, indent: ' ' })}`),
    field('Content-Type', ` text/plain; charset="${charset}"`),
    field('Content-Transfer-Encoding', ' quoted-printable'),
    field('MIME-Version', ' 1.0'),
    field('X-OriginatorOrg', ` ${input.from.slice(input.from.lastIndexOf('@') + 1).toLowerCase()}`),
    field('X-MS-Exchange-CrossTenant-AuthAs', ' Internal'),
    field('X-MS-Exchange-CrossTenant-AuthSource', ` ${host}`),
    field('X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg', ' 00000000-0000-0000-0000-000000000000'),
    field('X-MS-Exchange-CrossTenant-Network-Message-Id', ` ${network}`),
    field('X-MS-Exchange-CrossTenant-originalarrivaltime', ` ${arrival}`),
    field('X-MS-Exchange-CrossTenant-fromentityheader', ' Hosted'),
    field('X-MS-Exchange-CrossTenant-id', ' 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa'),
    field('X-MS-Exchange-Transport-CrossTenantHeadersStamped', ` ${mbx}`),
  ];
  return { headers, body: quotedPrintable(text) };
}

export const outlook: ProviderProfile = {
  id: 'outlook',
  name: 'Outlook.com',
  domains: ['outlook.com', 'hotmail.com'],
  signers: [outlookSigner],
  keyRecord: (p) => `v=DKIM1;k=rsa;p=${p};n=2048,1452627113,1468351913`,
  compose,
};
