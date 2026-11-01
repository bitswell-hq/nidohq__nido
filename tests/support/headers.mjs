// Cloudflare Pages' `_headers` rules (https://developers.cloudflare.com/pages/configuration/headers/),
// read from the built site so the e2e server answers with the headers
// production sends: one or more URL patterns, each followed by indented
// `Name: value` lines; `*` matches any run of characters, and every
// matching rule applies (a header two rules set gets both values, joined by
// a comma).
import { readFileSync } from 'node:fs';

/** The rules in a `_headers` file: `{ pattern, headers: [name, value][] }[]`. */
export function parseHeaders(text) {
  const rules = [];
  let current;
  for (const raw of text.split('\n')) {
    if (!raw.trim() || raw.trim().startsWith('#')) continue;
    if (/^\s/.test(raw)) {
      const at = raw.indexOf(':');
      if (!current || at < 0) throw new Error(`_headers: header outside a rule: ${raw}`);
      current.headers.push([raw.slice(0, at).trim(), raw.slice(at + 1).trim()]);
    } else {
      current = { pattern: raw.trim(), headers: [] };
      rules.push(current);
    }
  }
  return rules;
}

function matches(pattern, path) {
  const re = new RegExp(`^${pattern.split('*').map((p) => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`);
  return re.test(path);
}

/** Every header the rules give `path`, in rule order. */
export function headersFor(rules, path) {
  const out = {};
  for (const r of rules) {
    if (!matches(r.pattern, path)) continue;
    for (const [k, v] of r.headers) out[k] = out[k] === undefined ? v : `${out[k]}, ${v}`;
  }
  return out;
}

export function loadHeaders(file) {
  try {
    return parseHeaders(readFileSync(file, 'utf8'));
  } catch {
    return [];
  }
}
