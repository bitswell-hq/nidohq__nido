// Public mailing-list archives: polite downloads with a local cache, mbox
// splitting, and each message's identity (the SHA-256 of its octets as the
// archive stores them).
//
// The GNU Mailman archives (lists.gnu.org, lists.nongnu.org) serve one mbox
// per list and month. Their robots.txt asks for 10 seconds between requests;
// downloads here wait at least that long between any two requests to the
// same host, and a month already in the cache is never fetched again (a past
// month's mbox does not change). Nothing fetched is written inside the
// repository's tracked files: the cache lives under target/.

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO = join(dirname(fileURLToPath(import.meta.url)), '../../../../..');
export const CACHE = process.env.PARSER_CHECK_CACHE ?? join(REPO, 'target/email-recovery-parser');
export const USER_AGENT = 'nido-email-recovery-parser-check/1 (+https://github.com/bitswell-hq/nidohq__nido)';
const DELAY_MS = 10_500;

const lastRequest = new Map();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * GET `url` as octets, at most one request per host every 10.5 seconds,
 * retrying transient failures. A 404 (a month without posts) is null.
 */
export async function politeGet(url, { log = () => {} } = {}) {
  const host = new URL(url).host;
  for (let attempt = 1; ; attempt++) {
    const wait = (lastRequest.get(host) ?? 0) + DELAY_MS - Date.now();
    if (wait > 0) await sleep(wait);
    lastRequest.set(host, Date.now());
    log(`GET ${url}`);
    try {
      const res = await fetch(url, { headers: { 'user-agent': USER_AGENT } });
      if (res.ok) return new Uint8Array(await res.arrayBuffer());
      if (res.status === 404) return null;
      if (res.status !== 429 && res.status < 500) throw new Error(`${url}: HTTP ${res.status}`);
      if (attempt >= 4) throw new Error(`${url}: HTTP ${res.status} after ${attempt} attempts`);
    } catch (err) {
      if (attempt >= 4 || /HTTP 4\d\d/.test(err.message)) throw err;
    }
    await sleep(30_000 * attempt);
  }
}

/** The mbox of `list` for `month` (YYYY-MM) from `base`, from the cache or the archive. */
export async function mbox(base, list, month, opts = {}) {
  const file = join(CACHE, 'mbox', new URL(base).host, list, month);
  if (existsSync(file)) return readFileSync(file);
  const bytes = (await politeGet(`${base}/${list}/${month}`, opts)) ?? new Uint8Array(0);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(`${file}.part`, bytes);
  renameSync(`${file}.part`, file);
  return Buffer.from(bytes);
}

export const mboxUrl = (base, list, month) => `${base}/${list}/${month}`;

/**
 * The messages of an mbox, in archive order. Mailman writes a line starting
 * with "From " before each message and escapes such lines inside messages
 * as ">From ", so every "From " at a line start is a separator. A message is
 * the octets after its separator line up to the next separator, without the
 * one LF that ends the message in the mbox.
 */
export function splitMbox(buf) {
  const text = buf.toString('latin1');
  const starts = [];
  const re = /(?:^|\n)From [^\n]*\n/g;
  for (let m; (m = re.exec(text)); ) starts.push({ at: m.index + (m[0].startsWith('\n') ? 1 : 0), body: m.index + m[0].length });
  return starts.map((s, i) => {
    let end = i + 1 < starts.length ? starts[i + 1].at : text.length;
    if (text[end - 1] === '\n') end -= 1;
    return Buffer.from(text.slice(s.body, end), 'latin1');
  });
}

export const sha256hex = (bytes) => createHash('sha256').update(bytes).digest('hex');

/** The wire form of an archived message: every line ending CRLF (RFC 5322 section 2.1). */
export function wireForm(stored) {
  return Buffer.from(stored.toString('latin1').replace(/\r?\n/g, '\r\n'), 'latin1');
}

/** The header block of a message as fields, unfolded, each `{ name, value }` (value without the colon). */
export function headerFields(message) {
  const text = message.toString('latin1');
  const end = text.search(/\r?\n\r?\n/);
  const head = end === -1 ? text : text.slice(0, end);
  const fields = [];
  for (const line of head.split(/\r?\n/)) {
    if (/^[ \t]/.test(line) && fields.length) fields[fields.length - 1].value += line;
    else {
      const colon = line.indexOf(':');
      if (colon > 0) fields.push({ name: line.slice(0, colon).trim(), value: line.slice(colon + 1) });
    }
  }
  return fields;
}

/** Tag values of a DKIM-Signature value, leniently (for selecting messages and keys, not for verdicts). */
export function looseTags(value) {
  const tags = {};
  for (const spec of value.split(';')) {
    const eq = spec.indexOf('=');
    if (eq > 0) tags[spec.slice(0, eq).trim()] ??= spec.slice(eq + 1).replace(/\s+/g, '');
  }
  return tags;
}
