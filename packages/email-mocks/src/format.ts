/** Header value formats shared by the provider profiles. */
import { createHash } from 'node:crypto';

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

export interface DateStyle {
  /** The sender's UTC offset in minutes (e.g. 60 for +0100). */
  offsetMinutes?: number;
  /** Write the optional day-of-week (RFC 5322 section 3.3). */
  weekday?: boolean;
  /** Two-digit day (`01`) rather than `1`. */
  padDay?: boolean;
  /** A trailing comment such as `(UTC)` or `(CET)`. */
  comment?: string;
}

/** RFC 5322 section 3.3 `date-time`. */
export function formatRfc5322Date(date: Date, style: DateStyle = {}): string {
  const offset = style.offsetMinutes ?? 0;
  const local = new Date(date.getTime() + offset * 60_000);
  const day = local.getUTCDate();
  const two = (n: number) => String(n).padStart(2, '0');
  const sign = offset < 0 ? '-' : '+';
  const abs = Math.abs(offset);
  const zone = `${sign}${two(Math.floor(abs / 60))}${two(abs % 60)}`;
  const parts = [
    style.weekday === false ? '' : `${DAYS[local.getUTCDay()]}, `,
    style.padDay ? two(day) : String(day),
    ` ${MONTHS[local.getUTCMonth()]} ${local.getUTCFullYear()} `,
    `${two(local.getUTCHours())}:${two(local.getUTCMinutes())}:${two(local.getUTCSeconds())} ${zone}`,
    style.comment ? ` ${style.comment}` : '',
  ];
  return parts.join('');
}

/**
 * A US time zone's offset and comment on `date`: daylight time from the
 * second Sunday of March to the first Sunday of November, 2:00 local.
 */
export function usZone(date: Date, zone: 'eastern' | 'pacific'): DateStyle {
  const standard = zone === 'eastern' ? -300 : -480;
  const names = zone === 'eastern' ? ['(EST)', '(EDT)'] : ['(PST)', '(PDT)'];
  const y = date.getUTCFullYear();
  const sunday = (month: number, nth: number, offset: number) => {
    const first = new Date(Date.UTC(y, month, 1)).getUTCDay();
    return Date.UTC(y, month, 1 + ((7 - first) % 7) + 7 * (nth - 1), 2) - offset * 60_000;
  };
  const t = date.getTime();
  const dst = t >= sunday(2, 2, standard) && t < sunday(10, 1, standard + 60);
  return { offsetMinutes: dst ? standard + 60 : standard, comment: names[dst ? 1 : 0] };
}

/**
 * Deterministic pseudo-random octets for Message-IDs and MIME boundaries:
 * SHA-256 in counter mode over a label, so a fixture's bytes depend only on
 * its inputs.
 */
export function prng(label: string, length: number): Buffer {
  const out: Buffer[] = [];
  for (let i = 0; out.length * 32 < length; i++) {
    out.push(createHash('sha256').update(`${label}\u0000${i}`).digest());
  }
  return Buffer.concat(out).subarray(0, length);
}

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/** `length` characters drawn from `alphabet` (default alphanumeric). */
export function prngString(label: string, length: number, alphabet = ALNUM): string {
  const bytes = prng(label, length);
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('');
}

/** Lower-case hex of `length` characters. */
export function prngHex(label: string, length: number): string {
  return prng(label, Math.ceil(length / 2)).toString('hex').slice(0, length);
}

/** The RFC 5322 `phrase` form of a display name: atoms as-is, otherwise quoted. */
export function displayNamePhrase(name: string): string {
  if (/^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~ ]+$/.test(name) && !/^ | $|  /.test(name)) return name;
  return `"${name.replace(/(["\\])/g, '\\$1')}"`;
}

/** RFC 2047 `B` encoded-words of at most 75 characters each, for non-ASCII text. */
export function encodedWordB(text: string, charset = 'UTF-8'): string[] {
  const prefix = `=?${charset}?B?`;
  const maxPayload = Math.floor((75 - prefix.length - 2) / 4) * 3;
  const words: string[] = [];
  let chunk: number[] = [];
  const flush = () => {
    if (chunk.length) words.push(`${prefix}${Buffer.from(chunk).toString('base64')}?=`);
    chunk = [];
  };
  for (const ch of text) {
    const bytes = [...Buffer.from(ch, 'utf8')];
    if (chunk.length + bytes.length > maxPayload) flush();
    chunk.push(...bytes);
  }
  flush();
  return words;
}

/** RFC 2047 `Q` encoding of `text` as one encoded-word (no length limit applied). */
export function encodedWordQ(text: string, charset = 'UTF-8'): string {
  const encoded = Array.from(Buffer.from(text, 'utf8'), (b) => {
    if (b === 0x20) return '_';
    const c = String.fromCharCode(b);
    return /[A-Za-z0-9!*+\-/]/.test(c) ? c : `=${b.toString(16).toUpperCase().padStart(2, '0')}`;
  }).join('');
  return `=?${charset}?Q?${encoded}?=`;
}

export function isAscii(s: string): boolean {
  return /^[\x00-\x7f]*$/.test(s);
}

/** RFC 2045 section 6.7 quoted-printable of UTF-8 text with CRLF line breaks. */
export function quotedPrintable(text: string): string {
  return text
    .split('\r\n')
    .map((line) => {
      const bytes = Buffer.from(line, 'utf8');
      let out = '';
      let width = 0;
      bytes.forEach((b, i) => {
        const last = i === bytes.length - 1;
        const literal = (b >= 33 && b <= 126 && b !== 61) || ((b === 32 || b === 9) && !last);
        const tok = literal ? String.fromCharCode(b) : `=${b.toString(16).toUpperCase().padStart(2, '0')}`;
        if (width + tok.length > 75) {
          out += '=\r\n';
          width = 0;
        }
        out += tok;
        width += tok.length;
      });
      return out;
    })
    .join('\r\n');
}

/** Normalizes any line ending to CRLF. */
export function crlf(text: string): string {
  return text.replace(/\r\n|\r|\n/g, '\r\n');
}
