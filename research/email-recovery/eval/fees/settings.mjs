#!/usr/bin/env node
// Archive a network's Soroban configuration (its `ConfigSettings` ledger
// entries) with the time it was read, the network's protocol and latest
// ledger, and the RPC that answered: results/settings/<name>.json. Read-only:
// `stellar network settings --internal` and Stellar RPC's getNetwork,
// getVersionInfo and getLatestLedger.
//
// `--limits` also writes network/limits/mainnet.json from the mainnet
// archive: the upgradeable settings the local network loads at start
// (network/run-attacks.sh, `--limits mainnet`), leaving out the settings that
// name mainnet's own ledger entries (`frozen_ledger_keys`,
// `freeze_bypass_txs`) and those the network maintains itself
// (`live_soroban_state_size_window`, `eviction_iterator`).
//
//   node research/email-recovery/eval/fees/settings.mjs mainnet testnet [local=http://127.0.0.1:8000/rpc] [--limits]
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';

const here = new URL('../', import.meta.url).pathname;

export const NETWORKS = {
  mainnet: { rpc: 'https://mainnet.sorobanrpc.com', passphrase: 'Public Global Stellar Network ; September 2015' },
  testnet: { rpc: 'https://soroban-testnet.stellar.org', passphrase: 'Test SDF Network ; September 2015' },
  local: { rpc: 'http://127.0.0.1:8000/rpc', passphrase: 'Standalone Network ; February 2017' },
};

/** Settings the local network does not take from mainnet's archive. */
export const NOT_LOADED = ['frozen_ledger_keys', 'freeze_bypass_txs', 'live_soroban_state_size_window', 'eviction_iterator'];

async function rpc(url, method) {
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method }) });
  const body = await r.json();
  if (body.error) throw new Error(`${url} ${method}: ${body.error.message}`);
  return body.result;
}

function cli(rpcUrl, passphrase, output) {
  return execFileSync('stellar', ['network', 'settings', '--internal', '--rpc-url', rpcUrl, '--network-passphrase', passphrase, '--output', output], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  }).trim();
}

/** Read `name`'s settings and network state; the record results/settings/<name>.json holds. */
export async function fetchSettings(name, rpcUrl = NETWORKS[name].rpc) {
  const { passphrase } = NETWORKS[name];
  const network = await rpc(rpcUrl, 'getNetwork');
  if (network.passphrase !== passphrase) throw new Error(`${rpcUrl} serves "${network.passphrase}", not ${name}`);
  const before = await rpc(rpcUrl, 'getLatestLedger');
  const settings = JSON.parse(cli(rpcUrl, passphrase, 'json'));
  const xdr = cli(rpcUrl, passphrase, 'xdr');
  const after = await rpc(rpcUrl, 'getLatestLedger');
  const version = await rpc(rpcUrl, 'getVersionInfo');
  return {
    network: name,
    passphrase,
    rpc: rpcUrl,
    fetched: new Date().toISOString(),
    protocolVersion: network.protocolVersion,
    ledger: { sequence: after.sequence, closeTime: Number(after.closeTime), readBetween: [before.sequence, after.sequence] },
    rpcVersion: version.version,
    coreVersion: version.captiveCoreVersion,
    stellarCli: execFileSync('stellar', ['--version'], { encoding: 'utf8' }).split('\n')[0],
    settings: Object.fromEntries(settings.updated_entry.map((e) => Object.entries(e)[0])),
    configUpgradeSetXdr: xdr,
  };
}

/** The quickstart limits file (a `ConfigUpgradeSet` as JSON) holding `archive`'s upgradeable settings. */
export function limitsFrom(archive) {
  return {
    updated_entry: Object.entries(archive.settings)
      .filter(([k]) => !NOT_LOADED.includes(k))
      .map(([k, v]) => ({ [k]: v })),
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  mkdirSync(`${here}results/settings`, { recursive: true });
  for (const a of args.filter((x) => !x.startsWith('--'))) {
    const [name, url] = a.split('=');
    const record = await fetchSettings(name, url);
    writeFileSync(`${here}results/settings/${name}.json`, JSON.stringify(record, null, 1) + '\n');
    console.error(`${name}: protocol ${record.protocolVersion}, ledger ${record.ledger.sequence}, ${Object.keys(record.settings).length} settings`);
  }
  if (args.includes('--limits')) {
    const { readFileSync } = await import('node:fs');
    const archive = JSON.parse(readFileSync(`${here}results/settings/mainnet.json`, 'utf8'));
    mkdirSync(`${here}network/limits`, { recursive: true });
    writeFileSync(`${here}network/limits/mainnet.json`, JSON.stringify(limitsFrom(archive), null, 1) + '\n');
    console.error(`network/limits/mainnet.json: mainnet's settings of ${archive.fetched}, without ${NOT_LOADED.join(', ')}`);
  }
}
