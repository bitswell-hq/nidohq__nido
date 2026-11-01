/**
 * TEST-ONLY: a DNS-over-HTTPS resolver's JSON API over a `MockDns` zone, in
 * the `application/dns-json` format Cloudflare publishes
 * (<https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/>,
 * read 2026-11-01) and Google's Public DNS JSON API shares
 * (<https://developers.google.com/speed/public-dns/docs/doh/json>):
 * `GET /dns-query?name=<name>&type=TXT` answers `{Status, TC, RD, RA, AD,
 * CD, Question, Answer}`, each TXT answer's `data` its character-strings,
 * each quoted, separated by one space (as `cloudflare-dns.com` answered for
 * `20260707._domainkey.gmail.com` on 2026-11-01), `Status` 3 (NXDOMAIN) for
 * a name with no records, and `Access-Control-Allow-Origin: *`.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import type { MockDns } from './dns.js';

const TXT = 16;

/** The JSON answer for `name` and `type` (`TXT` or `16`). */
export async function dohJson(dns: MockDns, name: string, type: string): Promise<Record<string, unknown>> {
  const qtype = type === 'TXT' || type === '16' ? TXT : Number(type) || 1;
  const question = [{ name: name.replace(/\.$/, ''), type: qtype }];
  const base = { TC: false, RD: true, RA: true, AD: false, CD: false, Question: question };
  let records: string[][];
  try {
    records = await dns.resolver(name, qtype === TXT ? 'TXT' : 'A');
  } catch (e) {
    return { Status: (e as { code?: string }).code === 'ENODATA' ? 0 : 3, ...base };
  }
  return {
    Status: 0,
    ...base,
    Answer: records.map((chunks) => ({
      name: question[0]!.name,
      type: TXT,
      TTL: 300,
      data: chunks.map((c) => `"${c.replace(/(["\\])/g, '\\$1')}"`).join(' '),
    })),
  };
}

/** An HTTP handler serving `GET /dns-query` from `dns`. */
export function dohHandler(dns: MockDns): (req: IncomingMessage, res: ServerResponse) => void {
  return (req, res) => {
    const url = new URL(req.url ?? '/', 'http://doh');
    if (req.method !== 'GET' || url.pathname !== '/dns-query' || !url.searchParams.get('name')) {
      res.writeHead(400, { 'access-control-allow-origin': '*' });
      res.end();
      return;
    }
    void dohJson(dns, url.searchParams.get('name')!, url.searchParams.get('type') ?? 'A').then((body) => {
      res.writeHead(200, { 'content-type': 'application/dns-json', 'access-control-allow-origin': '*' });
      res.end(JSON.stringify(body));
    });
  };
}
