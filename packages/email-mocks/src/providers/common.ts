/** Pieces the provider profiles share. */
import type { HeaderField } from '../canon.js';
import type { Tag } from '../dkim.js';
import { crlf, displayNamePhrase, isAscii, prngHex, prngString, quotedPrintable } from '../format.js';
import { field } from '../message.js';
import type { ComposeInput, SignContext } from './types.js';

export const RELAXED = { header: 'relaxed', body: 'relaxed' } as const;

/** v, a, c in the order every launch provider starts with. */
export const BASE_TAGS: Tag[] = [
  ['v', '1'],
  ['a', 'rsa-sha256'],
  ['c', 'relaxed/relaxed'],
];

/**
 * `From` as a client writes it: bare addr-spec without a name; with one,
 * the name as an RFC 5322 phrase (quoted only when it must be, or always).
 */
export function fromValue(input: ComposeInput, quote: 'when-needed' | 'always' = 'when-needed'): string {
  if (input.displayName === undefined) return input.from;
  const name = quote === 'always' ? `"${input.displayName.replace(/(["\\])/g, '\\$1')}"` : displayNamePhrase(input.displayName);
  return `${name} <${input.from}>`;
}

/** Names of the fields in `headers` whose lower-case name is in `set`, in message order. */
export function presentIn(headers: HeaderField[], set: readonly string[]): string[] {
  const wanted = new Set(set.map((s) => s.toLowerCase()));
  return headers.filter((h) => wanted.has(h.name.toLowerCase())).map((h) => h.name);
}

export function countOf(headers: HeaderField[], name: string): number {
  return headers.filter((h) => h.name.toLowerCase() === name.toLowerCase()).length;
}

/** `t=` and, when the provider writes one, `x=` that many seconds later. */
export function timeTags(ctx: SignContext, validity?: number): Tag[] {
  const tags: Tag[] = [['t', String(ctx.time)]];
  if (validity !== undefined) tags.push(['x', String(ctx.time + validity)]);
  return tags;
}

export function seeded(input: ComposeInput, label: string): string {
  return `${input.seed}\u0000${label}`;
}

/** A version-4-shaped UUID drawn from the seed. */
export function uuid(input: ComposeInput, label: string, upper = false): string {
  const h = prngHex(seeded(input, label), 32).split('');
  h[12] = '4';
  h[16] = '89ab'[parseInt(h[16]!, 16) % 4]!;
  const s = h.join('');
  const out = `${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-${s.slice(16, 20)}-${s.slice(20)}`;
  return upper ? out.toUpperCase() : out;
}

export const BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
export const BASE64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** Opaque provider data of a given length, folded at `width` with `indent` when given. */
export function opaque(input: ComposeInput, label: string, length: number, alphabet = BASE64, fold?: { width: number; indent: string }): string {
  const s = prngString(seeded(input, label), length, alphabet);
  if (!fold) return s;
  const parts: string[] = [];
  for (let i = 0; i < s.length; i += fold.width) parts.push(s.slice(i, i + fold.width));
  return parts.join(`\r\n${fold.indent}`);
}

export function digits(input: ComposeInput, label: string, length: number): string {
  const s = prngString(seeded(input, label), length, '0123456789');
  return s[0] === '0' ? `1${s.slice(1)}` : s;
}

/** A text/plain body: 7bit when ASCII with short lines, else quoted-printable UTF-8. */
export function plainBody(input: ComposeInput): { body: string; encoded: boolean } {
  const text = crlf(input.body);
  const short = text.split('\r\n').every((l) => l.length <= 76);
  if (isAscii(text) && short) return { body: text, encoded: false };
  return { body: quotedPrintable(text), encoded: true };
}

/** Moves `bh=` in front of `h=`, for signers whose order is `... bh h b`. */
export function withBodyHashBeforeH(tags: Tag[]): Tag[] {
  const bh = tags.find(([n]) => n === 'bh');
  if (!bh) return tags;
  const rest = tags.filter(([n]) => n !== 'bh');
  const at = rest.findIndex(([n]) => n === 'h');
  return [...rest.slice(0, at), bh, ...rest.slice(at)];
}

export { field };
