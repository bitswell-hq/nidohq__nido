#!/usr/bin/env node
// Check that what the documents on the reading path point at exists:
//
//   - relative links resolve to a file in this tree, and a `#heading` anchor
//     to a heading in it;
//   - commit-pinned Perch links (`github.com/stellar-registry/perch/blob/<sha>/…`)
//     name the vendor/perch gitlink, a path that exists at that commit, and a
//     heading that exists in it, and carry no line anchor (a re-pin moves the
//     lines without moving the anchor);
//   - a repository path in backticks (`packages/…`, `vendor/perch/…`) exists;
//   - a cited Rust test (`file.rs::name`, brace groups expanded, or a bare
//     name in SECURITY_INVARIANTS' Evidence column) is a `fn` in that file
//     or tree;
//   - a cited TypeScript test (`x.test.ts` ("title", …)) has that title;
//   - a cited invariant (`SECURITY_INVARIANTS X1`), gate
//     (`MAINNET_READINESS X1`), or limit (`THREAT_MODEL L1`) is defined.
//
// It reads only this tree and the vendor/perch submodule at its gitlink, so
// it needs no network and no build. Usage: node scripts/check-doc-refs.mjs

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, normalize, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
process.chdir(root);

// The audit reading path (docs/AUDIT_SCOPE.md "Reading order") plus the
// documents it links. docs/APPLICATION.md and docs/REQUIREMENTS.md are
// historical records, outside the reading order.
const DOCS = [
  'README.md',
  'ARCHITECTURE.md',
  'DEPLOYED.md',
  'docs/ADD-NIDO-TO-DAPP.md',
  'docs/AUDIT_SCOPE.md',
  'docs/DEFERRED.md',
  'docs/MAINNET_READINESS.md',
  'docs/RUNBOOKS.md',
  'docs/SECURITY_INVARIANTS.md',
  'docs/STRIDE_THREAT_MODEL.md',
  'docs/SUPPLY_CHAIN.md',
  'docs/THREAT_MODEL.md',
  'infra/relayer/README.md',
  'tests/README.md',
];

const git = (...args) => execFileSync('git', args, { encoding: 'utf8', maxBuffer: 1 << 28 });

const perchSha = git('rev-parse', ':vendor/perch').trim();
const perchFiles = new Set(
  git('-C', 'vendor/perch', 'ls-tree', '-r', '--name-only', perchSha).split('\n').filter(Boolean),
);
const perchDirs = new Set();
for (const f of perchFiles) {
  for (let d = dirname(f); d !== '.'; d = dirname(d)) perchDirs.add(d);
}
const nidoFiles = git('ls-files').split('\n').filter((f) => f && !f.startsWith('vendor/'));

const problems = [];
const problem = (file, line, msg) => problems.push(`${file}:${line}: ${msg}`);

// GitHub's heading anchor: the heading's text, lower-cased, without
// punctuation, spaces as hyphens; a repeated anchor gets -1, -2, ….
function anchors(markdown) {
  const out = new Set();
  const seen = new Map();
  let fence = false;
  for (const line of markdown.split('\n')) {
    if (/^\s*(```|~~~)/.test(line)) fence = !fence;
    if (fence) continue;
    const m = /^#{1,6}\s+(.*?)\s*#*\s*$/.exec(line);
    if (!m) continue;
    const text = m[1].replace(/\[([^\]]*)\]\([^)]*\)/g, '$1');
    const base = text
      .toLowerCase()
      .replace(/[^\p{L}\p{N}\s_-]/gu, '')
      .replace(/\s/g, '-');
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    out.add(n === 0 ? base : `${base}-${n}`);
  }
  return out;
}

const anchorCache = new Map();
function nidoAnchors(path) {
  if (!anchorCache.has(path)) anchorCache.set(path, anchors(readFileSync(path, 'utf8')));
  return anchorCache.get(path);
}
function perchAnchors(path) {
  const key = `perch:${path}`;
  if (!anchorCache.has(key)) {
    anchorCache.set(key, anchors(git('-C', 'vendor/perch', 'show', `${perchSha}:${path}`)));
  }
  return anchorCache.get(key);
}

const perchExists = (path) => {
  const p = path.replace(/\/$/, '');
  return p === '' || perchFiles.has(p) || perchDirs.has(p);
};

// The lines of a document outside fenced code blocks, with their numbers.
function proseLines(text) {
  const out = [];
  let fence = false;
  text.split('\n').forEach((line, i) => {
    if (/^\s*(```|~~~)/.test(line)) {
      fence = !fence;
      return;
    }
    if (!fence) out.push([i + 1, line]);
  });
  return out;
}

// --- links ---------------------------------------------------------------

const PERCH_LINK = /^https:\/\/github\.com\/stellar-registry\/perch\/(blob|tree)\/([^/]+)\/([^#]*)(?:#(.*))?$/;

function checkLink(file, line, target) {
  const perch = PERCH_LINK.exec(target);
  if (perch) {
    const [, , ref, path, anchor] = perch;
    if (ref !== perchSha) {
      problem(file, line, `Perch link at ${ref}, not the vendor/perch gitlink ${perchSha.slice(0, 7)}: ${target}`);
      return;
    }
    if (!perchExists(path)) {
      problem(file, line, `no ${path} in Perch at ${perchSha.slice(0, 7)}: ${target}`);
      return;
    }
    if (anchor === undefined) return;
    if (/^L\d/.test(anchor)) {
      problem(file, line, `line anchor on a Perch link (a re-pin moves the lines, not the anchor): ${target}`);
    } else if (path.endsWith('.md') && !perchAnchors(path).has(anchor)) {
      problem(file, line, `no heading #${anchor} in Perch's ${path}`);
    }
    return;
  }
  if (/^[a-z][a-z0-9+.-]*:/i.test(target)) return; // other URLs: not checked offline
  const [rawPath, anchor] = target.split('#');
  const path = rawPath === '' ? file : normalize(join(dirname(file), decodeURIComponent(rawPath)));
  if (relative(root, join(root, path)).startsWith('..')) {
    problem(file, line, `link leaves the repository: ${target}`);
    return;
  }
  if (!existsSync(path)) {
    problem(file, line, `no such file: ${target}`);
    return;
  }
  if (anchor !== undefined && path.endsWith('.md') && !nidoAnchors(path).has(anchor)) {
    problem(file, line, `no heading #${anchor} in ${path}`);
  }
}

// --- paths in backticks --------------------------------------------------

const REPO_PATH = /^(?:\.github|contracts|crates|docs|examples|frontend|infra|packages|scripts|tests|vendor\/perch)\/[\w./@-]*$/;

function checkPath(file, line, path) {
  if (path.startsWith('vendor/perch/')) {
    if (!perchExists(path.slice('vendor/perch/'.length))) {
      problem(file, line, `no ${path} in Perch at ${perchSha.slice(0, 7)}`);
    }
    return;
  }
  // A path can also be relative to the document (a README's own `scripts/`),
  // name a file Git ignores on purpose (a local `.env`), or name the Perch
  // checkout without its `vendor/perch/` prefix when the sentence says so.
  if (existsSync(path) || existsSync(join(dirname(file), path)) || perchExists(path)) return;
  try {
    git('check-ignore', '-q', path);
  } catch {
    problem(file, line, `no such path: ${path}`);
  }
}

// --- tests ---------------------------------------------------------------

function expandBraces(s) {
  const m = /\{([^{}]*)\}/.exec(s);
  if (!m) return [s];
  return m[1]
    .split(',')
    .flatMap((alt) => expandBraces(s.slice(0, m.index) + alt.trim() + s.slice(m.index + m[0].length)));
}

const sourceCache = new Map();
const source = (where, path) => {
  const key = `${where}:${path}`;
  if (!sourceCache.has(key)) {
    sourceCache.set(
      key,
      where === 'perch' ? git('-C', 'vendor/perch', 'show', `${perchSha}:${path}`) : readFileSync(path, 'utf8'),
    );
  }
  return sourceCache.get(key);
};

// Where a bare file name (`account.rs`, `model.test.ts`) lives: Nido's
// integration suites first, then anywhere in Nido, then anywhere in Perch.
function locate(name) {
  if (name.includes('/')) {
    if (existsSync(name)) return [['nido', name]];
    const p = name.replace(/^vendor\/perch\//, '');
    return perchFiles.has(p) ? [['perch', p]] : [];
  }
  const it = `crates/integration-tests/tests/it/${name}`;
  if (existsSync(it)) return [['nido', it]];
  const nido = nidoFiles.filter((f) => f.endsWith(`/${name}`));
  if (nido.length) return nido.map((f) => ['nido', f]);
  return [...perchFiles].filter((f) => f.endsWith(`/${name}`)).map((f) => ['perch', f]);
}

const hasFn = (text, name) => new RegExp(`\\bfn\\s+${name}\\s*[(<]`).test(text);

let nidoRust;
function nidoRustFns() {
  if (!nidoRust) {
    nidoRust = nidoFiles
      .filter((f) => f.endsWith('.rs') && (f.startsWith('contracts/') || f.startsWith('crates/')))
      .map((f) => readFileSync(f, 'utf8'))
      .join('\n');
  }
  return nidoRust;
}

function checkRustTest(file, line, rsFile, spec) {
  const homes = locate(rsFile);
  if (!homes.length) {
    problem(file, line, `no test file ${rsFile}`);
    return;
  }
  for (const name of expandBraces(spec)) {
    if (!homes.some(([where, p]) => hasFn(source(where, p), name))) {
      problem(file, line, `no test ${name} in ${rsFile}`);
    }
  }
}

function checkTsTitles(file, line, tsFile, titles) {
  const homes = locate(tsFile);
  if (!homes.length) {
    problem(file, line, `no test file ${tsFile}`);
    return;
  }
  for (const title of titles) {
    if (!homes.some(([where, p]) => source(where, p).includes(title))) {
      problem(file, line, `no test "${title}" in ${tsFile}`);
    }
  }
}

// --- identifiers ---------------------------------------------------------

const invariantIds = new Set(
  [...readFileSync('docs/SECURITY_INVARIANTS.md', 'utf8').matchAll(/^\| ([A-Z]\d+) \|/gm)].map((m) => m[1]),
);
const gateIds = new Set(
  [...readFileSync('docs/MAINNET_READINESS.md', 'utf8').matchAll(/\*\*([A-Z]\d+)\./g)].map((m) => m[1]),
);
const limitIds = new Set(
  [...readFileSync('docs/THREAT_MODEL.md', 'utf8').matchAll(/\*\*(L\d+)\./g)].map((m) => m[1]),
);
const ID_REFS = [
  ['SECURITY_INVARIANTS', invariantIds, 'invariant'],
  ['MAINNET_READINESS', gateIds, 'gate'],
  ['THREAT_MODEL', limitIds, 'limit'],
];

// --- per document --------------------------------------------------------

for (const file of DOCS) {
  const text = readFileSync(file, 'utf8');
  let evidenceColumn = -1;
  for (const [n, line] of proseLines(text)) {
    for (const m of line.matchAll(/(?<!!)\[(?:[^\]`]|`[^`]*`)*\]\(([^)\s]+)\)/g)) checkLink(file, n, m[1]);
    for (const m of line.matchAll(/<(https?:\/\/[^>]+)>/g)) checkLink(file, n, m[1]);

    for (const m of line.matchAll(/`([^`\n]+)`/g)) {
      const code = m[1];
      if (REPO_PATH.test(code) && !/[*<>{}]/.test(code)) checkPath(file, n, code);
      const rs = /^([\w./-]+\.rs)::(.+)$/.exec(code);
      if (rs) checkRustTest(file, n, rs[1], rs[2]);
    }

    for (const m of line.matchAll(/`([\w./-]+\.(?:test|spec)\.ts)`\s*\(((?:"[^"]*"(?:,\s*)?)+)\)/g)) {
      checkTsTitles(file, n, m[1], [...m[2].matchAll(/"([^"]*)"/g)].map((t) => t[1]));
    }

    for (const [doc, ids, kind] of ID_REFS) {
      for (const m of line.matchAll(new RegExp(`${doc}\\s+((?:[A-Z]\\d+)(?:(?:,\\s*|\\s+and\\s+)[A-Z]\\d+)*)`, 'g'))) {
        for (const id of m[1].split(/,\s*|\s+and\s+/)) {
          if (!ids.has(id)) problem(file, n, `no ${kind} ${id} in ${doc}.md`);
        }
      }
    }

    // SECURITY_INVARIANTS: every bare test name in the Evidence column.
    if (file === 'docs/SECURITY_INVARIANTS.md' && line.startsWith('|')) {
      const cells = line.split('|').map((c) => c.trim());
      if (cells.includes('Evidence')) evidenceColumn = cells.indexOf('Evidence');
      else if (evidenceColumn > 0 && !/^-+$/.test(cells[1] ?? '')) {
        const cell = cells[evidenceColumn] ?? '';
        for (const m of cell.matchAll(/`([a-z][a-z0-9]*(?:_[a-z0-9]+){2,})`/g)) {
          if (!hasFn(nidoRustFns(), m[1])) problem(file, n, `no Rust test ${m[1]} in Nido`);
        }
      }
    } else if (!line.startsWith('|')) {
      evidenceColumn = -1;
    }
  }
}

if (problems.length) {
  console.error(problems.join('\n'));
  console.error(`\n${problems.length} broken reference(s) in the documents.`);
  process.exit(1);
}
console.log(`${DOCS.length} documents: every link, path, test, and ID resolves (Perch at ${perchSha.slice(0, 7)}).`);
