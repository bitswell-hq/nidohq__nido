#!/usr/bin/env node
// Archive the contract code entries an email recovery reads, as a network
// holds them (results/code-entries.json): for each wasm `just perch-infra`
// and `just build-contracts` write that the recovery runs, its hash, its
// entry's XDR size and the parsing inputs (`ContractCodeCostInputs`) the
// network's host recorded when the code was uploaded. fees/model.mjs
// (`codeRentBytes`) turns them into the entry's size for rent under any
// network's cost model; and the optimized size and sha256 of each
// email-recovery contract's wasm in this build. Read-only: Stellar RPC's
// getLedgerEntries.
//
//   node research/email-recovery/eval/fees/code-entries.mjs [RPC]
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { rpc, xdr } from '@stellar/stellar-sdk';

const repo = new URL('../../../../', import.meta.url).pathname;
const RPC = process.argv[2] ?? 'https://soroban-testnet.stellar.org';
const FILES = {
  'perch_doc_compiler.wasm': 'Perch doc compiler',
  'perch_recovery.wasm': 'Perch recovery controller',
  'perch_webauthn_verifier.wasm': 'Perch WebAuthn verifier',
  'perch_account.wasm': 'Perch account',
  'nido_email_verifier.wasm': 'email verifier',
  'nido_email_guardian.wasm': 'email guardian',
  'nido_dkim_registry.wasm': 'DKIM key registry',
};
const server = new rpc.Server(RPC);
const network = await (await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getNetwork' }) })).json();
const entries = [];
for (const [file, name] of Object.entries(FILES)) {
  const hash = createHash('sha256').update(readFileSync(`${repo}target/wasm32v1-none/contract/${file}`)).digest();
  const r = await server.getLedgerEntries(xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash })));
  const e = r.entries[0];
  if (!e) {
    entries.push({ name, file, hash: hash.toString('hex'), onNetwork: false });
    continue;
  }
  const ci = e.val.contractCode().ext().v1().costInputs();
  const costInputs = Object.fromEntries(['nInstructions', 'nFunctions', 'nGlobals', 'nTableEntries', 'nTypes', 'nDataSegments', 'nElemSegments', 'nImports', 'nExports', 'nDataSegmentBytes'].map((k) => [k, ci[k]()]));
  entries.push({ name, file, hash: hash.toString('hex'), onNetwork: true, dataBytes: e.val.toXDR().length, costInputs });
}
// The build these entries come from: each email-recovery contract's wasm as `just build-contracts` writes it.
const build = Object.fromEntries(
  ['nido_email_guardian', 'nido_dkim_registry', 'nido_email_verifier', 'nido_enclave_image_registry'].map((w) => {
    const b = readFileSync(`${repo}target/wasm32v1-none/contract/${w}.wasm`);
    return [w, { bytes: b.length, sha256: createHash('sha256').update(b).digest('hex') }];
  }),
);
const out = { fetched: new Date().toISOString(), rpc: RPC, passphrase: network.result.passphrase, protocolVersion: network.result.protocolVersion, build, entries };
writeFileSync(`${repo}research/email-recovery/eval/results/code-entries.json`, JSON.stringify(out, null, 1) + '\n');
for (const e of entries) console.error(`${e.name}: ${e.onNetwork ? `${e.dataBytes} bytes` : 'not on this network'}`);
