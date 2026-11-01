import type { HeaderField } from './canon.js';

/** An RFC 5322 message split into its header fields and body. */
export interface Message {
  headers: HeaderField[];
  /** Everything after the CRLF CRLF that ends the header block. */
  body: string;
}

/** Bytes to the binary-string form the signer works on. */
export function toBinary(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('latin1');
}

export function fromBinary(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'latin1'));
}

/** `name:value` with the value's folding kept as given. */
export function field(name: string, value: string): HeaderField {
  return { name, raw: `${name}:${value}` };
}

/**
 * Splits a CRLF message. A line starting with WSP continues the previous
 * field; anything else up to the first empty line starts a new one.
 */
export function parseMessage(raw: string): Message {
  const end = raw.indexOf('\r\n\r\n');
  const head = end === -1 ? raw : raw.slice(0, end);
  const body = end === -1 ? '' : raw.slice(end + 4);
  const headers: HeaderField[] = [];
  for (const line of head.split('\r\n')) {
    if (/^[ \t]/.test(line) && headers.length > 0) {
      headers[headers.length - 1]!.raw += `\r\n${line}`;
    } else if (line.length > 0) {
      const colon = line.indexOf(':');
      const name = (colon === -1 ? line : line.slice(0, colon)).replace(/[ \t]+$/, '');
      headers.push({ name, raw: line });
    }
  }
  return { headers, body };
}

export function serializeMessage(message: Message): string {
  return `${message.headers.map((h) => `${h.raw}\r\n`).join('')}\r\n${message.body}`;
}

export function headerValues(message: Message, name: string): string[] {
  const lower = name.toLowerCase();
  return message.headers
    .filter((h) => h.name.toLowerCase() === lower)
    .map((h) => h.raw.slice(h.raw.indexOf(':') + 1));
}
