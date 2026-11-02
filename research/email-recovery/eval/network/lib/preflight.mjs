// Before the attack suite: the installed packages are the locked ones. A
// stale install (an older @stellar-registry/perch, say) fails deep inside a
// scenario with an error that does not name the cause; this names it.
//
//   node research/email-recovery/eval/network/lib/preflight.mjs
import { existsSync, readFileSync } from 'node:fs';

const repo = new URL('../../../../../', import.meta.url);
const lock = JSON.parse(readFileSync(new URL('package-lock.json', repo), 'utf8'));
const stale = [];
for (const [path, entry] of Object.entries(lock.packages ?? {})) {
  // Top-level registry installs only: workspace links and nested copies are not what `npm ci` drifts on.
  if (!/^node_modules\/(@[^/]+\/)?[^/]+$/.test(path) || entry.link || !entry.version) continue;
  const manifest = new URL(`${path}/package.json`, repo);
  if (!existsSync(manifest)) {
    if (!entry.optional && !entry.dev) stale.push(`${path.slice(13)}: missing (locked ${entry.version})`);
    continue;
  }
  const installed = JSON.parse(readFileSync(manifest, 'utf8')).version;
  if (installed !== entry.version) stale.push(`${path.slice(13)}: installed ${installed}, locked ${entry.version}`);
}
if (stale.length) {
  console.error(`node_modules does not match package-lock.json; run \`npm ci\` first:\n  ${stale.slice(0, 20).join('\n  ')}${stale.length > 20 ? `\n  … and ${stale.length - 20} more` : ''}`);
  process.exit(1);
}
console.error('node_modules matches package-lock.json');
