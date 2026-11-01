/**
 * A mock of the DNS that serves DKIM key records (RFC 6376 section 3.6.2):
 * `TXT` at `<selector>._domainkey.<domain>`, split into character-strings of
 * at most 255 octets as RFC 1035 section 3.3.14 requires and as providers
 * publish 2048-bit keys.
 */

export interface KeyRecordTags {
  /** Base64 SubjectPublicKeyInfo; empty for a revoked key (section 3.6.1). */
  p: string;
  /** Tags in the order they are written; `v=DKIM1` first (section 3.6.1). */
  order?: string[];
  extra?: Record<string, string>;
}

/** `v=DKIM1; k=rsa; p=...` with the provider's tag order and spacing. */
export function keyRecord(tags: KeyRecordTags, separator = '; '): string {
  const values: Record<string, string> = { v: 'DKIM1', k: 'rsa', ...tags.extra, p: tags.p };
  const order = tags.order ?? ['v', 'k', 'p'];
  return order.map((t) => `${t}=${values[t] ?? ''}`).join(separator);
}

export function keyRecordName(selector: string, domain: string): string {
  return `${selector}._domainkey.${domain}`.toLowerCase();
}

function dnsError(code: 'ENOTFOUND' | 'ENODATA', name: string): Error {
  return Object.assign(new Error(`queryTxt ${code} ${name}`), { code, hostname: name });
}

/** A TXT zone, queried like `dns.promises.resolve(name, 'TXT')`. */
export class MockDns {
  private readonly txt = new Map<string, string[]>();

  /** Publishes `value` as one TXT record, replacing what was there. */
  publish(name: string, value: string): void {
    this.txt.set(name.toLowerCase(), [value]);
  }

  publishKey(selector: string, domain: string, record: string): void {
    this.publish(keyRecordName(selector, domain), record);
  }

  /** Blanks `p=` in place, keeping every other tag, as a rotated-out key is published. */
  revokeKey(selector: string, domain: string): void {
    const name = keyRecordName(selector, domain);
    const values = this.txt.get(name);
    if (!values) throw new Error(`no record at ${name}`);
    this.txt.set(name, values.map((v) => v.replace(/p=[^;]*/, 'p=')));
  }

  remove(name: string): void {
    this.txt.delete(name.toLowerCase());
  }

  lookup(name: string): string[] | undefined {
    return this.txt.get(name.toLowerCase());
  }

  /** `dns.promises.resolve` signature; each record is its 255-octet chunks. */
  readonly resolver = async (name: string, rrtype = 'A'): Promise<string[][]> => {
    const values = this.txt.get(name.toLowerCase().replace(/\.$/, ''));
    if (!values) throw dnsError('ENOTFOUND', name);
    if (rrtype !== 'TXT') throw dnsError('ENODATA', name);
    return values.map(chunk255);
  };

  /** The zone in master-file form (RFC 1035 section 5), for inspection. */
  zoneFile(): string {
    return [...this.txt.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .flatMap(([name, values]) =>
        values.map((v) => `${name}. 3600 IN TXT ${chunk255(v).map((c) => `"${c}"`).join(' ')}`),
      )
      .join('\n')
      .concat('\n');
  }
}

function chunk255(value: string): string[] {
  const chunks: string[] = [];
  for (let i = 0; i < value.length; i += 255) chunks.push(value.slice(i, i + 255));
  return chunks.length ? chunks : [''];
}
