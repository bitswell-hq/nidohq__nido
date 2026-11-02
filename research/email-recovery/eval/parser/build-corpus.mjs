#!/usr/bin/env node
// Assembles the real-mail corpus: downloads every mbox named by
// corpus/sources.json (politely, cached under target/), keeps each post whose
// From domain is a launch domain and that carries a DKIM-Signature field, and
// writes
//
//   corpus/manifest.json  one row per post: its archive (an index into
//                         `archives`, the mbox URLs), its position there, the
//                         SHA-256 of its octets as stored, its From domain, and
//                         the d= and s= of each DKIM-Signature field;
//   corpus/keys.json      every candidate public key for each (d=, s=) seen,
//                         from the live DNS and from zkEmail's key archive,
//                         with where and when each was observed.
//
// No message content is written to the repository: run.mjs fetches the
// posts again from the archive and checks each against its hash.
//
//   node research/email-recovery/eval/parser/build-corpus.mjs

import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { headerFields, looseTags, mbox, mboxUrl, sha256hex, splitMbox } from './lib/archive.mjs';
import { archiveKeyRecords, dnsKeyRecords, keyId, keyRecordTags, rsaKey } from './lib/keys.mjs';

const here = new URL('.', import.meta.url).pathname;
const sources = JSON.parse(readFileSync(join(here, 'corpus/sources.json'), 'utf8'));
const launch = new Set(sources.launchDomains);
const log = (s) => process.stderr.write(`${s}\n`);

/** The launch domain of a post's From fields, if any address in them is at one. */
function launchFromDomain(fields) {
  for (const f of fields.filter((f) => f.name.toLowerCase() === 'from')) {
    for (const m of f.value.matchAll(/@([A-Za-z0-9.-]+)/g)) {
      const d = m[1].replace(/\.$/, '').toLowerCase();
      if (launch.has(d)) return d;
    }
  }
  return null;
}

const messages = [];
for (const month of sources.months) {
  for (const list of sources.lists) {
    const buf = await mbox(sources.archive, list, month, { log });
    const posts = splitMbox(buf);
    let kept = 0;
    posts.forEach((stored, index) => {
      const fields = headerFields(stored);
      const sigs = fields.filter((f) => f.name.toLowerCase() === 'dkim-signature');
      const fromDomain = launchFromDomain(fields);
      if (!fromDomain || sigs.length === 0) return;
      messages.push({
        sha256: sha256hex(stored),
        archive: mboxUrl(sources.archive, list, month),
        index,
        fromDomain,
        signatures: sigs.map((f) => {
          const t = looseTags(f.value);
          return { d: (t.d ?? '').toLowerCase(), s: t.s ?? '' };
        }),
      });
      kept++;
    });
    log(`${list} ${month}: ${posts.length} posts, ${kept} kept`);
  }
}

// Candidate keys for every (d=, s=) the kept posts carry.
const pairs = new Map();
for (const m of messages) for (const s of m.signatures) if (s.d && s.s) pairs.set(`${s.s}._domainkey.${s.d}`, s);
const archive = new Map();
const checked = new Date().toISOString().slice(0, 10);
const keys = [];
for (const [name, { d, s }] of [...pairs].sort()) {
  const candidates = new Map();
  const add = (p, source) => {
    if (!rsaKey(p)) return;
    const id = keyId(p);
    if (!candidates.has(id)) candidates.set(id, { id, p, bits: rsaKey(p).bits, sources: [] });
    candidates.get(id).sources.push(source);
  };
  const live = await dnsKeyRecords(d, s);
  for (const txt of live) add(keyRecordTags(txt).p, { kind: 'dns', name, checked });
  if (!archive.has(d)) {
    try {
      archive.set(d, await archiveKeyRecords(d, { log }));
    } catch (err) {
      throw new Error(`archive.zk.email ${d}: ${err.message}; the key list would be incomplete`);
    }
  }
  for (const rec of archive.get(d).filter((r) => r.selector === s)) {
    add(keyRecordTags(rec.value).p, {
      kind: 'archive.zk.email',
      url: `https://archive.zk.email/api/key?domain=${d}`,
      recordId: rec.id,
      firstSeenAt: rec.firstSeenAt,
      lastSeenAt: rec.lastSeenAt,
      observations: (rec.observations ?? []).map((o) => o.source),
    });
  }
  const published = live.map((txt) => keyRecordTags(txt).p ?? '');
  keys.push({
    name,
    d,
    s,
    dns: live.length === 0 ? 'absent' : published.some((p) => p) ? 'published' : 'revoked (empty p=)',
    candidates: [...candidates.values()],
  });
  log(`${name}: ${candidates.size} candidate key(s), DNS ${keys.at(-1).dns}`);
}

const counts = {};
for (const m of messages) counts[m.fromDomain] = (counts[m.fromDomain] ?? 0) + 1;
const archives = [...new Set(messages.map((m) => m.archive))];
const rows = messages.map((m) => JSON.stringify([archives.indexOf(m.archive), m.index, m.sha256, m.fromDomain, m.signatures.map((s) => `${s.d}/${s.s}`)]));
const head = { built: checked, archive: sources.archive, lists: sources.lists, months: sources.months, counts, rowFormat: ['archive', 'position', 'sha256', 'fromDomain', 'signatures (d=/s=)'], archives };
writeFileSync(join(here, 'corpus/manifest.json'), `${JSON.stringify(head, null, 1).slice(0, -2)},\n "messages": [\n  ${rows.join(',\n  ')}\n ]\n}\n`);
writeFileSync(join(here, 'corpus/keys.json'), `${JSON.stringify({ checked, keys }, null, 1)}\n`);
log(`${messages.length} posts, ${keys.length} (d=, s=) pairs; per From domain ${JSON.stringify(counts)}`);
