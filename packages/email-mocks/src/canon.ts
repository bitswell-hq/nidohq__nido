/**
 * DKIM canonicalization (RFC 6376 section 3.4).
 *
 * Messages are handled as binary strings: one JS char per octet
 * (`Buffer.from(s, 'latin1')` round-trips them), so byte lengths and hashes
 * are exact even for 8-bit content.
 */

export type Canon = 'simple' | 'relaxed';

/** One header field as it appears in the message, without its final CRLF. */
export interface HeaderField {
  /** Field name exactly as written (case kept). */
  name: string;
  /** The whole field: `name:value`, folding (CRLF WSP) kept. */
  raw: string;
}

const WSP_RUN = /[ \t]+/g;

/** RFC 6376 section 3.4.1: the field unchanged, CRLF-terminated. */
export function simpleHeader(field: HeaderField): string {
  return `${field.raw}\r\n`;
}

/**
 * RFC 6376 section 3.4.2: lower-case the name, unfold, collapse each WSP run
 * to one SP, drop WSP at the end of the value and around the colon.
 */
export function relaxedHeader(field: HeaderField): string {
  const colon = field.raw.indexOf(':');
  const name = field.raw.slice(0, colon).replace(/[ \t]+$/, '').toLowerCase();
  const value = field.raw
    .slice(colon + 1)
    .replace(/\r\n(?=[ \t])/g, '')
    .replace(WSP_RUN, ' ')
    .replace(/^ /, '')
    .replace(/ $/, '');
  return `${name}:${value}\r\n`;
}

export function canonHeader(field: HeaderField, canon: Canon): string {
  return canon === 'simple' ? simpleHeader(field) : relaxedHeader(field);
}

/**
 * RFC 6376 sections 3.4.3 and 3.4.4. `body` is everything after the blank
 * line that ends the header block, CRLF line endings.
 */
export function canonBody(body: string, canon: Canon): string {
  if (canon === 'simple') {
    const trimmed = body.replace(/(\r\n)*$/, '');
    return `${trimmed}\r\n`;
  }
  const lines = body.split('\r\n');
  // A body that ends in CRLF splits into a trailing "" that is not a line.
  if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
  const reduced = lines.map((line) => line.replace(WSP_RUN, ' ').replace(/ $/, ''));
  while (reduced.length > 0 && reduced[reduced.length - 1] === '') reduced.pop();
  return reduced.length === 0 ? '' : `${reduced.join('\r\n')}\r\n`;
}
