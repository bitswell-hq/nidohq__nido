#!/usr/bin/env node
// What keeping the email factor's contracts live costs, measured on the
// local network with mainnet's settings (research/email-recovery/eval/
// README.md, "Archival and the keeper"). Deploys the stack as the attack
// suite does (lib/stack.mjs) and enrolls one account as the wallet does,
// then runs the keeper (keeper.mjs) once, forced and one transaction per
// entry, over every contract entry an email recovery on the pin or the
// registry path reads: the email verifier, the DKIM key registry, the email
// guardian (its code and the account's instance), and Perch's recovery
// controller, doc compiler, WebAuthn verifier and account (its code and the
// account's instance). Each extension is read back from the network: the
// entry, the ledgers it was extended by, and the fee and rent charged.
// Writes results/keeper-local.json.
//
//   NODE_EXTRA_CA_CERTS=target/email-attacks/tls/cert.pem NIDO_EVAL_QUICKSTART_URL=http://127.0.0.1:8002 \
//     node research/email-recovery/eval/network/keeper-costs.mjs
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { Keypair } from '@stellar/stellar-sdk';
import { Chain } from './lib/chain.mjs';
import { Inbox, launchKeys } from './lib/email.mjs';
import { enroll } from './lib/recovery.mjs';
import { deployLocal } from './lib/stack.mjs';
import { proxy } from './lib/tls.mjs';
import { contractKeys, keep } from './keeper.mjs';

const repo = new URL('../../../../', import.meta.url).pathname;
const BASE = process.env.NIDO_EVAL_QUICKSTART_URL ?? 'http://127.0.0.1:8002';
const PASSPHRASE = 'Standalone Network ; February 2017';
const LIMITS = `${repo}research/email-recovery/eval/network/limits/mainnet.json`;
const OUT = `${repo}research/email-recovery/eval/results/keeper-local.json`;

const tls = await proxy(BASE, `${repo}target/email-attacks/tls`);
const chain = new Chain({ rpcUrl: `${tls.url}/rpc`, passphrase: PASSPHRASE, friendbot: `${tls.url}/friendbot` });
const stack = await deployLocal(chain, BASE);
const gmail = launchKeys().find((k) => k.domain === 'gmail.com');
const e = await enroll({ chain, stack, label: 'keeper', inbox: new Inbox('first.last@gmail.com'), key: gmail, helpers: 1, quorum: 2, delayLedgers: 20, expiryLedgers: 2_000 });
const d = stack.deployment;
const contracts = [
  ['email verifier', stack.email.verifier, 'nido'],
  ['DKIM key registry', stack.registry.address, 'nido'],
  ['email guardian', e.guardian, 'nido'],
  ['recovery controller', d.recoveryController, 'perch'],
  ['doc compiler', d.docCompiler, 'perch'],
  ['WebAuthn verifier', d.webauthnVerifier, 'perch'],
  // The account's instance is its wallet's to keep; its code is Perch's account wasm.
  ['account', e.account.address, 'wallet', 'perch'],
];
const groups = [];
for (const [name, address, owner, codeOwner = owner] of contracts) {
  const [instance, code] = await contractKeys(chain, address);
  groups.push({ label: `${name} instance`, owner, keys: [instance] });
  if (code) groups.push({ label: `${name} code`, owner: codeOwner, keys: [code] });
}
// Each code entry's parsing inputs, which size it for rent (fees/model.mjs, `codeRentBytes`).
const inputs = {};
for (const g of groups.filter((x) => x.keys[0].switch().name === 'contractCode')) {
  const [entry] = await chain.entries(g.keys);
  const ci = entry.value.contractCode().ext().v1().costInputs();
  inputs[g.label] = Object.fromEntries(['nInstructions', 'nFunctions', 'nGlobals', 'nTableEntries', 'nTypes', 'nDataSegments', 'nElemSegments', 'nImports', 'nExports', 'nDataSegmentBytes'].map((k) => [k, ci[k]()]));
}
const keeper = await chain.funded(Keypair.random());
const before = chain.log.length;
const done = await keep(chain, keeper, groups, { force: true });
const network = await chain.call('getNetwork');
const version = await chain.call('getVersionInfo');
const out = {
  generated: new Date().toISOString(),
  network: {
    kind: 'stellar/quickstart --local',
    image: process.env.NIDO_EVAL_QUICKSTART_IMAGE ?? 'unknown',
    passphrase: PASSPHRASE,
    protocolVersion: network.protocolVersion,
    rpc: version,
    settings: { file: 'research/email-recovery/eval/network/limits/mainnet.json', sha256: createHash('sha256').update(readFileSync(LIMITS)).digest('hex') },
  },
  entries: done.map((x) => ({
    label: x.label.replace(/^keeper extend /, ''),
    owner: groups.find((g) => `keeper extend ${g.label}` === x.label || g.label === x.label)?.owner,
    action: x.action,
    key: x.keys[0],
    entryBytes: x.entryBytes?.[0],
    costInputs: inputs[x.label.replace(/^keeper (extend|restore) /, '')],
    from: x.from?.[0],
    to: x.to?.[0],
    hash: x.hash,
  })),
  transactions: chain.log.slice(before),
};
mkdirSync(`${repo}research/email-recovery/eval/results`, { recursive: true });
writeFileSync(OUT, JSON.stringify(out, null, 1) + '\n');
console.error(`wrote ${OUT}: ${done.length} keeper transactions`);
process.exit(0);
