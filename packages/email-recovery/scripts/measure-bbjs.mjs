#!/usr/bin/env node
// Proves one committed recovery email with bb.js (the prover a browser runs)
// and prints one JSON line of timings and memory. Needs the package built
// (`npm run build -w @nidohq/email-mocks -w @nidohq/email-recovery`).
//
//   measure-bbjs.mjs <fixture-dir> <threads> [--proof-out <dir>]
//                    [--circuit <artifact.json> --header-max <n>]
//
// <fixture-dir> is a crates/integration-tests/fixtures/email/<name>/
// directory: its message.eml is re-encoded with encodeRecoveryEmail from the
// account code, rho, statement, modulus and key path its fixture.json
// records, the witness is solved with noir_js 1.0.0-beta.9 against
// circuits/email-recovery/artifacts/recovery.json (or --circuit, a build of
// the same relation with header bound --header-max), and bb.js 0.87.0 proves
// it in the zero-knowledge keccak flavor (`keccakZK`, what `bb prove --zk`
// writes and the on-chain verifier takes) with <threads> worker threads, then
// verifies it. The public inputs must be the fixture's. With --proof-out, the
// proof and public inputs are written there for `bb verify`.
//
// Peak memory is this process's maximum resident set size (bb.js's workers
// run in it); run one thread setting per process.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { parseArgs } from 'node:util';
import { UltraHonkBackend } from '@aztec/bb.js';
import { Noir } from '@noir-lang/noir_js';
import { HEADER_MAX, encodeRecoveryEmail, noirInputs, publicInputBytes } from '@nidohq/email-recovery';

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: { 'proof-out': { type: 'string' }, circuit: { type: 'string' }, 'header-max': { type: 'string' } },
});
const [dir, threadsArg] = positionals;
if (!dir || !threadsArg) {
  console.error('usage: measure-bbjs.mjs <fixture-dir> <threads> [--proof-out <dir>] [--circuit <artifact.json> --header-max <n>]');
  process.exit(2);
}
const threads = Number(threadsArg);
const proofOut = values['proof-out'];
const headerMax = values['header-max'] ? Number(values['header-max']) : HEADER_MAX;
const repo = new URL('../../../', import.meta.url);
const circuit = JSON.parse(
  readFileSync(values.circuit ?? new URL('circuits/email-recovery/artifacts/recovery.json', repo), 'utf8'),
);
const meta = JSON.parse(readFileSync(join(dir, 'fixture.json'), 'utf8'));
const unhex = (s) => Uint8Array.from(Buffer.from(s.replace(/^0x/, ''), 'hex'));
const hex = (b) => `0x${Buffer.from(b).toString('hex')}`;

const t0 = performance.now();
const encoded = await encodeRecoveryEmail({
  eml: readFileSync(join(dir, 'message.eml')),
  accountCode: BigInt(meta.account_code),
  rho: BigInt(meta.rho),
  statement: unhex(meta.statement),
  modulus: BigInt(meta.modulus),
  keyPath: { root: BigInt(meta.key_root), index: meta.key_index, siblings: meta.key_siblings.map(BigInt) },
});
const pub = publicInputBytes(encoded.witness);
const expected = meta.public_inputs.join('').replace(/0x/g, '');
if (Buffer.from(pub).toString('hex') !== expected) throw new Error('re-encoded public inputs differ from the fixture');
const t1 = performance.now();
const { witness } = await new Noir(circuit).execute(noirInputs(encoded.witness, headerMax));
const t2 = performance.now();
const backend = new UltraHonkBackend(circuit.bytecode, { threads });
const proof = await backend.generateProof(witness, { keccakZK: true });
const t3 = performance.now();
const ok = await backend.verifyProof(proof, { keccakZK: true });
await backend.destroy();
if (!ok) throw new Error('bb.js did not verify its own proof');
const got = proof.publicInputs.map((v) => BigInt(v).toString(16).padStart(64, '0')).join('');
if (got !== expected) throw new Error('bb.js committed to other public inputs');
if (proofOut) {
  mkdirSync(proofOut, { recursive: true });
  writeFileSync(join(proofOut, 'proof'), proof.proof);
  writeFileSync(join(proofOut, 'public_inputs'), pub);
}
console.log(
  JSON.stringify({
    fixture: dir.replace(/\/$/, '').split('/').pop(),
    threads,
    header_max: headerMax,
    header_bytes: encoded.witness.header.length,
    encode_ms: Math.round(t1 - t0),
    execute_ms: Math.round(t2 - t1),
    prove_ms: Math.round(t3 - t2),
    proof_bytes: proof.proof.length,
    peak_rss_mib: Math.round(process.resourceUsage().maxRSS / 1024),
    public_inputs: meta.public_inputs.map((x) => hex(unhex(x))),
  }),
);
