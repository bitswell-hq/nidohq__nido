/**
 * A DKIM signer (RFC 6376) for rsa-sha256 (RFC 8301), producing the
 * `DKIM-Signature` field in whatever tag order and folding a provider uses.
 */
import { createHash, sign as rsaSign, type KeyObject } from 'node:crypto';
import { type Canon, type HeaderField, canonBody, canonHeader } from './canon.js';
import type { Message } from './message.js';

/** Tag name and value, in the order they are written. */
export type Tag = [name: string, value: string];

/**
 * Lays tags out as the field value that follows `DKIM-Signature:`. Given an
 * empty `b=` value it must end in `b=` with nothing after it, which is the
 * form the signature covers (RFC 6376 section 3.7).
 */
export type SignatureLayout = (tags: Tag[]) => string;

export interface SignInput {
  key: KeyObject;
  /** Tags other than `bh=` and `b=`, in order, e.g. v, a, c, d, s, t, x, h. */
  tags: Tag[];
  /** Header field names exactly as they go into `h=`, repeats allowed. */
  signedHeaders: string[];
  canon: { header: Canon; body: Canon };
  layout: SignatureLayout;
  /** Hash only this many canonical body octets and write `l=` after `h=`. */
  bodyLength?: number;
  /** Write this `bh=` instead of the real body hash (a negative case). */
  bodyHashOverride?: string;
  /** Defaults to `DKIM-Signature`. */
  fieldName?: string;
}

export interface Signed {
  field: HeaderField;
  bh: string;
  b: string;
  /** The exact octets the RSA signature is over (header hash input). */
  signedHeaderData: string;
}

export const DKIM_FIELD = 'DKIM-Signature';

/**
 * RFC 6376 section 5.4.2: for each name in `h=`, take the bottom-most
 * instance not yet used; a name with no instance left signs nothing.
 */
export function selectSignedHeaders(headers: HeaderField[], names: string[]): HeaderField[] {
  const used = new Set<number>();
  const out: HeaderField[] = [];
  for (const name of names) {
    const lower = name.toLowerCase();
    for (let i = headers.length - 1; i >= 0; i--) {
      if (!used.has(i) && headers[i]!.name.toLowerCase() === lower) {
        used.add(i);
        out.push(headers[i]!);
        break;
      }
    }
  }
  return out;
}

export function bodyHash(body: string, canon: Canon, length?: number): string {
  let canonical = canonBody(body, canon);
  if (length !== undefined) canonical = canonical.slice(0, length);
  return createHash('sha256').update(Buffer.from(canonical, 'latin1')).digest('base64');
}

/** Signs `message` and returns the new field; the caller decides where it goes. */
export function signMessage(message: Message, input: SignInput): Signed {
  const bh = input.bodyHashOverride ?? bodyHash(message.body, input.canon.body, input.bodyLength);
  const tags: Tag[] = [...input.tags];
  if (input.bodyLength !== undefined) {
    const at = tags.findIndex(([n]) => n === 'h');
    tags.splice(at + 1, 0, ['l', String(input.bodyLength)]);
  }
  tags.push(['bh', bh]);

  const name = input.fieldName ?? DKIM_FIELD;
  const unsignedValue = input.layout([...tags, ['b', '']]);
  if (!unsignedValue.endsWith('b=')) throw new Error('layout must end with an empty b= tag');
  const unsignedField: HeaderField = { name, raw: `${name}:${unsignedValue}` };

  const selected = selectSignedHeaders(message.headers, input.signedHeaders);
  const sigHeader = canonHeader(unsignedField, input.canon.header).replace(/\r\n$/, '');
  const signedHeaderData = selected.map((h) => canonHeader(h, input.canon.header)).join('') + sigHeader;
  const b = rsaSign('sha256', Buffer.from(signedHeaderData, 'latin1'), input.key).toString('base64');

  const raw = `${name}:${input.layout([...tags, ['b', b]])}`;
  return { field: { name, raw }, bh, b, signedHeaderData };
}

/** Parses a `DKIM-Signature` value into its tags (whitespace removed from values). */
export function parseTags(value: string): Map<string, string> {
  const tags = new Map<string, string>();
  for (const part of value.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const name = part.slice(0, eq).replace(/\s+/g, '');
    tags.set(name, part.slice(eq + 1).replace(/\s+/g, ''));
  }
  return tags;
}
