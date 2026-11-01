/**
 * The signed header block of a DKIM-signed message: the exact octets an
 * RSA DKIM signature covers (RFC 6376 section 3.7), which the recovery
 * circuit takes as its input `H` (`docs/email-recovery/spec.md` §4.3,
 * §6.2 C2).
 *
 * `H` is built as a verifier builds it: the fields `h=` names, each taken
 * from the bottom of the header block upward and canonicalized (RFC 6376
 * section 5.4.2), each ended by CRLF, then the DKIM-Signature field itself,
 * canonicalized, with its `b=` value deleted and no trailing CRLF. A name
 * listed in `h=` more often than it occurs contributes nothing for the
 * missing instances.
 *
 * Messages are handled as binary strings, one JS char per octet, so 8-bit
 * content round-trips and lengths are octet counts.
 */

/** One header field: the name as written and the whole field without its final CRLF. */
export interface HeaderField {
  name: string;
  /** `name:value` exactly as written, folding (CRLF followed by WSP) kept. */
  raw: string;
}

export interface ParsedMessage {
  fields: HeaderField[];
}

/** One DKIM-Signature field of a message. */
export interface DkimSignatureField {
  /** Index of the field in `ParsedMessage.fields`, top-most first. */
  index: number;
  tags: Map<string, string>;
}

export class DkimHeaderError extends Error {
  override name = 'DkimHeaderError';
}

/** Octets to a binary string, one char per octet. */
export function binary(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return s;
}

/** A binary string back to octets. */
export function octets(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

/**
 * Splits the header block of `eml` into fields. The header block ends at
 * the first empty line. Lines must end in CRLF (RFC 5322 section 2.1); a bare
 * CR or LF is refused.
 */
export function parseMessage(eml: Uint8Array): ParsedMessage {
  const text = binary(eml);
  const end = text.indexOf('\r\n\r\n');
  const head = end === -1 ? text : text.slice(0, end);
  if (/\r(?!\n)|(?<!\r)\n/.test(head)) throw new DkimHeaderError('header block has a bare CR or LF');
  const fields: HeaderField[] = [];
  for (const line of head.split('\r\n')) {
    if (line === '') continue;
    if (line[0] === ' ' || line[0] === '\t') {
      const last = fields[fields.length - 1];
      if (!last) throw new DkimHeaderError('header block starts with a continuation line');
      last.raw += `\r\n${line}`;
      continue;
    }
    const colon = line.indexOf(':');
    if (colon < 1) throw new DkimHeaderError(`header line without a field name: ${JSON.stringify(line.slice(0, 40))}`);
    fields.push({ name: line.slice(0, colon).replace(/[ \t]+$/, ''), raw: line });
  }
  return { fields };
}

/** The field's name for matching: lowercase, as relaxed canonicalization writes it. */
export function fieldKey(field: HeaderField): string {
  return field.name.toLowerCase();
}

/**
 * RFC 6376 section 3.4.2, without the final CRLF: lowercase the name,
 * unfold, collapse each run of WSP to one SP, delete WSP at the end of the
 * value and around the colon.
 */
export function relaxedField(raw: string): string {
  const colon = raw.indexOf(':');
  const name = raw.slice(0, colon).replace(/[ \t]+$/, '').toLowerCase();
  const value = raw
    .slice(colon + 1)
    .replace(/\r\n(?=[ \t])/g, '')
    .replace(/[ \t]+/g, ' ')
    .replace(/^ /, '')
    .replace(/ $/, '');
  return `${name}:${value}`;
}

/** RFC 6376 section 3.4.1, without the final CRLF: the field unchanged. */
export function simpleField(raw: string): string {
  return raw;
}

/**
 * The tag list of a DKIM-Signature field (RFC 6376 section 3.2). Values are
 * unfolded with surrounding whitespace removed; `b=` and `bh=` lose all
 * whitespace (it is not part of base64). A duplicate tag invalidates the
 * list.
 */
export function parseTagList(value: string): Map<string, string> {
  const tags = new Map<string, string>();
  for (const spec of value.replace(/\r\n(?=[ \t])/g, '').split(';')) {
    if (spec.trim() === '') continue;
    const eq = spec.indexOf('=');
    if (eq === -1) throw new DkimHeaderError(`DKIM tag without "=": ${JSON.stringify(spec.trim())}`);
    const name = spec.slice(0, eq).trim();
    let v = spec.slice(eq + 1).trim();
    if (name === 'b' || name === 'bh') v = v.replace(/[ \t]/g, '');
    if (tags.has(name)) throw new DkimHeaderError(`duplicate DKIM tag ${name}=`);
    tags.set(name, v);
  }
  return tags;
}

function fieldValue(field: HeaderField): string {
  return field.raw.slice(field.raw.indexOf(':') + 1);
}

/** Every `DKIM-Signature` field (any case), top-most first. */
export function dkimSignatures(message: ParsedMessage): DkimSignatureField[] {
  const out: DkimSignatureField[] = [];
  message.fields.forEach((field, index) => {
    if (fieldKey(field) === 'dkim-signature') out.push({ index, tags: parseTagList(fieldValue(field)) });
  });
  return out;
}

/**
 * The field with its `b=` value, and the whitespace around it, deleted
 * (RFC 6376 section 3.7). The tag name is matched exactly, so `bh=` is kept.
 */
export function withEmptyB(raw: string): string {
  const colon = raw.indexOf(':');
  const specs = raw.slice(colon + 1).split(';');
  let found = 0;
  const kept = specs.map((spec) => {
    const m = /^([ \t\r\n]*b[ \t\r\n]*=)/.exec(spec);
    if (!m) return spec;
    found++;
    return m[1]!;
  });
  if (found !== 1) throw new DkimHeaderError(`DKIM-Signature has ${found} b= tags`);
  return raw.slice(0, colon + 1) + kept.join(';');
}

/** The header canonicalization named by `c=` (RFC 6376 section 3.5; default `simple`). */
export function headerCanonicalization(tags: Map<string, string>): 'simple' | 'relaxed' {
  const c = (tags.get('c') ?? 'simple').split('/')[0]!.toLowerCase();
  if (c !== 'simple' && c !== 'relaxed') throw new DkimHeaderError(`unknown header canonicalization ${c}`);
  return c;
}

/** The fields `h=` selects for `signature`, bottom-up, in `h=` order. */
export function selectSignedFields(message: ParsedMessage, signature: DkimSignatureField): HeaderField[] {
  const h = signature.tags.get('h');
  if (h === undefined) throw new DkimHeaderError('DKIM-Signature has no h= tag');
  const used = new Set<number>([signature.index]);
  const out: HeaderField[] = [];
  for (const name of h.split(':').map((n) => n.trim().toLowerCase())) {
    for (let i = message.fields.length - 1; i >= 0; i--) {
      if (!used.has(i) && fieldKey(message.fields[i]!) === name) {
        used.add(i);
        out.push(message.fields[i]!);
        break;
      }
    }
  }
  return out;
}

/** The octets `signature` covers: the circuit's `H`. */
export function signedHeaderBlock(message: ParsedMessage, signature: DkimSignatureField): Uint8Array {
  const canon = headerCanonicalization(signature.tags) === 'relaxed' ? relaxedField : simpleField;
  const field = message.fields[signature.index]!;
  let block = '';
  for (const f of selectSignedFields(message, signature)) block += `${canon(f.raw)}\r\n`;
  block += canon(withEmptyB(field.raw));
  return octets(block);
}

/**
 * The address a relaxed-canonical `from` value names under spec §4.5: the
 * bytes between its only `<` and the `>` that ends it, or the whole value.
 * Refuses a value the circuit's grammar refuses on its shape (more than one
 * angle-addr, text after the `>`); the circuit checks the rest.
 */
export function fromAddress(relaxedValue: string): string {
  const lt = relaxedValue.split('<').length - 1;
  const gt = relaxedValue.split('>').length - 1;
  if (lt === 0 && gt === 0) return relaxedValue;
  if (lt !== 1 || gt !== 1 || !relaxedValue.endsWith('>')) {
    throw new DkimHeaderError('From must hold one angle-addr that ends the field');
  }
  return relaxedValue.slice(relaxedValue.indexOf('<') + 1, -1);
}

/** The domain of an address: everything after its last `@`. */
export function domainOf(address: string): string {
  const at = address.lastIndexOf('@');
  if (at < 1 || at === address.length - 1) throw new DkimHeaderError(`not an address: ${JSON.stringify(address)}`);
  return address.slice(at + 1);
}

/** The value of the one field called `name` in a relaxed-canonical block `H`. */
export function blockFieldValue(block: Uint8Array, name: string): string {
  const prefix = `${name}:`;
  const lines = binary(block).split('\r\n').filter((l) => l.startsWith(prefix));
  if (lines.length !== 1) throw new DkimHeaderError(`the signed block has ${lines.length} ${name} fields`);
  return lines[0]!.slice(prefix.length);
}

/**
 * The DKIM-Signature fields whose `d=` equals the domain of the bottom-most
 * From address when both are lowercased (spec §4.3 rules 1 and 7), top-most
 * first.
 */
export function alignedSignatures(message: ParsedMessage): DkimSignatureField[] {
  const from = [...message.fields].reverse().find((f) => fieldKey(f) === 'from');
  if (!from) throw new DkimHeaderError('the message has no From field');
  const domain = domainOf(fromAddress(relaxedField(from.raw).slice('from:'.length))).toLowerCase();
  return dkimSignatures(message).filter((s) => (s.tags.get('d') ?? '').toLowerCase() === domain);
}

/** The RSA signature value of `b=`, big-endian. */
export function signatureValue(signature: DkimSignatureField): bigint {
  const b = signature.tags.get('b');
  if (!b) throw new DkimHeaderError('DKIM-Signature has an empty b= tag');
  const bytes = Uint8Array.from(atob(b), (c) => c.charCodeAt(0));
  let v = 0n;
  for (const x of bytes) v = (v << 8n) | BigInt(x);
  return v;
}
