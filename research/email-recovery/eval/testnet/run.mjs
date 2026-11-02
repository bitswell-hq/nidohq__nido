#!/usr/bin/env node
// The email-recovery contracts on Stellar testnet, and one complete
// email-factor recovery through them (research/email-recovery/eval/README.md,
// "Testnet"):
//
// 1. deploys, from the wasm `just build-contracts` writes, the email
//    verifier, the DKIM key registry (spec §7.6's proposed governance, with
//    throwaway testnet members and the TEST-ONLY DNS attester mock's keys),
//    the enclave-image registry (one throwaway signer), and uploads the email
//    guardian's wasm; the registry admits the Gmail mock's TEST-ONLY key
//    through a proposal, approvals and attestations, which then waits in its
//    72-hour timelock;
// 2. on Perch's testnet deployment and Nido's testnet factory (the wallet's
//    `perch.TESTNET`), mints an account with a TEST-ONLY owner passkey,
//    deploys its email guardian with a key pin over that key, and enrolls
//    recovery with the guardian and one helper, quorum 2, a 12-ledger delay;
// 3. opens a lost-key attempt, has the Gmail mock sign the recovery email for
//    the statement the controller built, proves it with bb.js in Node,
//    submits the email vote, the helper's vote, waits out the delay, and
//    completes the recovery;
// 4. reads every transaction back from the network: hash, ledger, metered
//    resources (when the RPC returns the host's `core_metrics` events),
//    declared resources, envelope size, the fee charged with its rent part,
//    and the wall clock of each step; writes results/testnet.json and its
//    table.
//
// Third parties stay mocked: the mail provider (the Gmail mock signs with
// its TEST-ONLY key) and DNS (the attester mock). Throwaway keys are written
// to target/email-testnet/keys.json, which is not committed.
//
//   node research/email-recovery/eval/testnet/run.mjs
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { perch } from '@nidohq/passkey-sdk';
import { Address, Keypair, Networks, Operation, xdr } from '@stellar/stellar-sdk';
import { Passkey } from '../network/lib/account.mjs';
import { Chain, sc } from '../network/lib/chain.mjs';
import { CIRCUIT_ID, Inbox, closeProver, launchKeys } from '../network/lib/email.mjs';
import { enroll } from '../network/lib/recovery.mjs';
import { Attester, REGISTRY, Registry, admitThroughTimelock } from '../network/lib/stack.mjs';

const repo = new URL('../../../../', import.meta.url).pathname;
const RPC = process.env.NIDO_TESTNET_RPC ?? 'https://soroban-testnet.stellar.org';
const FRIENDBOT = process.env.NIDO_TESTNET_FRIENDBOT ?? 'https://friendbot.stellar.org';
const WASM = `${repo}target/wasm32v1-none/contract/`;
const sha256 = (b) => createHash('sha256').update(b).digest();
const t0 = Date.now();

const chain = new Chain({ rpcUrl: RPC, passphrase: Networks.TESTNET, friendbot: FRIENDBOT, settleMs: 3_000 });
const d = perch.TESTNET;
const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' }).trim();
const cli = execFileSync('stellar', ['--version'], { encoding: 'utf8' }).split('\n')[0];
const steps = [];
/** Run `f` as the named step: its transactions and its wall clock. */
async function step(name, f) {
  const before = chain.log.length;
  const s = Date.now();
  const value = await f();
  steps.push({ step: name, ms: Date.now() - s, transactions: chain.log.slice(before).map((t) => t.hash) });
  console.error(`${name}: ${Date.now() - s} ms, ${chain.log.length - before} transactions`);
  return value;
}

// --- 1. the contracts -------------------------------------------------------
const deployer = await chain.funded(Keypair.random());
const members = [];
for (let i = 0; i < REGISTRY.members; i++) members.push(await chain.funded(Keypair.random()));
const imageSigner = await chain.funded(Keypair.random());
const attesters = [0, 1, 2].map((i) => new Attester(i));
Attester.ensureBuilt();
mkdirSync(`${repo}target/email-testnet`, { recursive: true });
writeFileSync(
  `${repo}target/email-testnet/keys.json`,
  JSON.stringify({ deployer: deployer.secret(), members: members.map((m) => m.secret()), imageSigner: imageSigner.secret() }, null, 1),
);

const wasm = {};
async function upload(name) {
  const bytes = readFileSync(`${WASM}${name}.wasm`);
  await chain.send(deployer, Operation.uploadContractWasm({ wasm: bytes }), { label: `upload ${name}` });
  wasm[name] = { sha256: sha256(bytes).toString('hex'), bytes: bytes.length };
  return sha256(bytes);
}
async function create(name, args = []) {
  const r = await chain.send(
    deployer,
    Operation.createCustomContract({ address: Address.fromString(deployer.publicKey()), wasmHash: await upload(name), salt: sha256(`nido/email-recovery/testnet/${name}/${t0}`), constructorArgs: args }),
    { label: `deploy ${name}` },
  );
  return Address.fromScVal(r.scVal).toString();
}
const deployed = await step('deploy the email contracts', async () => {
  const verifier = await create('nido_email_verifier');
  const registry = await create('nido_dkim_registry', [Registry.configScVal({ members, attesters })]);
  const imageRegistry = await create('nido_enclave_image_registry', [sc.vec([sc.address(imageSigner.publicKey())]), sc.u32(1)]);
  const guardianWasmHash = (await upload('nido_email_guardian')).toString('hex');
  return { verifier, registry, imageRegistry, guardianWasmHash };
});
const reportedCircuit = Buffer.from(await chain.read(deployed.verifier, 'circuit_id')).toString('hex');
if (reportedCircuit !== CIRCUIT_ID.toString('hex')) throw new Error('the deployed verifier reports another circuit id');
const registry = new Registry(chain, deployed.registry, members, attesters, deployer);
const gmail = launchKeys().find((k) => k.domain === 'gmail.com');
const proposal = await step('registry: propose, approve and attest the Gmail mock key', () => admitThroughTimelock(registry, gmail));
const eligibleAt = Number(await registry.eligibleAt(proposal));

// --- 2. an account with email recovery --------------------------------------
// Perch's contracts an enrollment's apply_doc reaches (the doc compiler and
// the recovery controller, instance and code) can be archived on testnet;
// restoring them inside the apply_doc would exceed the per-transaction write
// limit, so each archived entry is restored first, in its own transaction.
const codeKey = (file) => xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: sha256(readFileSync(`${WASM}${file}`)) }));
const instanceKey = (c) => xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({ contract: Address.fromString(c).toScAddress(), key: xdr.ScVal.scvLedgerKeyContractInstance(), durability: xdr.ContractDataDurability.persistent() }));
const perchKeys = [
  ['doc compiler instance', instanceKey(d.docCompiler)],
  ['doc compiler code', codeKey('perch_doc_compiler.wasm')],
  ['recovery controller instance', instanceKey(d.recoveryController)],
  ['recovery controller code', codeKey('perch_recovery.wasm')],
];
const archived = await chain.archived(perchKeys.map((k) => k[1]));
const restored = perchKeys.filter(([, k]) => archived.some((a) => a.toXDR('base64') === k.toXDR('base64'))).map(([name]) => name);
if (restored.length) {
  await step(`restore Perch's archived entries (${restored.join(', ')})`, async () => {
    for (const [name, k] of perchKeys) if (restored.includes(name)) await chain.restore(deployer, [k], { label: `restore ${name}` });
  });
}

const stack = { deployment: d, email: { guardianWasmHash: deployed.guardianWasmHash, verifier: deployed.verifier }, registry };
const inbox = new Inbox('first.last@gmail.com');
const e = await step('enroll: mint, deploy the guardian, apply the recovery document', () =>
  enroll({ chain, stack, label: 'testnet', inbox, key: gmail, helpers: 1, quorum: 2, delayLedgers: 12, expiryLedgers: 2_000, apex: { scheme: 'https:', host: 'nido.example', port: 0 } }),
);

// --- 3. one complete email-factor recovery ----------------------------------
const newOwner = new Passkey(`testnet/new-device/${t0}`);
const { attemptId, replacements } = await step('begin_lost_key', () => e.beginLostKey(e.payer, newOwner));
const st = await e.statement(attemptId);
const prove = Date.now();
const { rho, email } = e.recoveryEmail(st.bytes);
const p = await e.prove({ eml: email.eml, rho, statementBytes: st.bytes });
const proveMs = Date.now() - prove;
const vote = await step('submit_guardian (email vote, real proof)', async () => {
  const r = await e.submitEmail(e.payer, { attemptId, approval: { statement: st.bytes, keyRoot: p.keyRoot, proof: p.proof }, digest: st.digest });
  if (!r.ok) throw new Error(`the email vote was refused: ${r.refused.message}`);
  return r;
});
const helper = await step('submit_guardian (helper vote)', async () => {
  const r = await e.submitHelper(e.helpers[0], attemptId);
  if (!r.ok) throw new Error(`the helper vote was refused: ${r.refused.message}`);
  return r;
});
const authorized = await e.attempt(attemptId);
if (authorized.state.tag !== 'Authorized') throw new Error(`the attempt is ${authorized.state.tag}`);
await step('the delay', () => chain.untilLedger(Number(authorized.executable_after), { pollMs: 2_000 }));
const done = await step('complete (apply_doc through the recovery rule)', async () => {
  const r = await e.complete(e.payer, replacements);
  if (!r.ok) throw new Error(`completion was refused: ${r.refused.message}`);
  return r;
});
// The account's admin signer is now the new device's passkey.
const applied = await e.client.appliedDoc(e.account.address);
if (!applied?.includes(Buffer.from(newOwner.publicKey).toString('hex'))) throw new Error('the completed document does not hold the new passkey');
if (applied.includes(Buffer.from(e.owner.publicKey).toString('hex'))) throw new Error('the completed document still holds the lost passkey');
await closeProver();

// --- 4. the record ----------------------------------------------------------
const out = {
  generated: new Date().toISOString(),
  network: Networks.TESTNET,
  rpc: RPC,
  rpcVersion: await chain.call('getVersionInfo').catch(() => ({})),
  commit,
  stellarCli: cli,
  perch: d,
  contracts: {
    'nido-email-verifier': { address: deployed.verifier, ...wasm.nido_email_verifier },
    'nido-dkim-registry': { address: deployed.registry, ...wasm.nido_dkim_registry },
    'nido-enclave-image-registry': { address: deployed.imageRegistry, ...wasm.nido_enclave_image_registry },
    'nido-email-guardian': { uploaded: true, ...wasm.nido_email_guardian, instance: e.guardian },
  },
  deployer: deployer.publicKey(),
  registryConfig: { members: members.map((m) => m.publicKey()), threshold: REGISTRY.threshold, revokeThreshold: REGISTRY.revokeThreshold, attesters: attesters.map((a) => a.publicKey.toString('hex')), attestThreshold: REGISTRY.attestThreshold, graceSeconds: REGISTRY.graceSeconds },
  imageRegistryConfig: { signers: [imageSigner.publicKey()], threshold: 1 },
  gmailProposal: { id: proposal, eligibleAt },
  restoredPerchEntries: restored,
  account: e.account.address,
  guardian: e.guardian,
  attemptId: Number(attemptId),
  proving: { witnessMs: p.witnessMs, proveMs: p.proveMs, totalMs: proveMs },
  completed: { hash: done.hash, newOwnerInstalled: true },
  votes: { email: vote.hash, helper: helper.hash },
  steps,
  transactions: chain.log,
  durationSeconds: Math.round((Date.now() - t0) / 1000),
};
const n = (x) => (x === undefined || x === null ? '—' : Number(x).toLocaleString('en-US'));
const tx = (h) => chain.log.find((t) => t.hash === h);
const lines = [
  `Testnet (\`${Networks.TESTNET}\`, ${RPC}, ${out.rpcVersion?.version ? `Stellar RPC ${out.rpcVersion.version}` : 'RPC version not reported'}), run of ${out.generated.slice(0, 16).replace('T', ' ')} UTC: one complete email-factor recovery, ${chain.log.length} transactions. Proving (bb.js in Node, on the machine of the proving table): ${(p.witnessMs / 1000).toFixed(1)} s witness, ${(p.proveMs / 1000).toFixed(1)} s proving.`,
  '',
  '| Step | Transaction | Instructions (metered) | Instructions (declared) | Read / write entries | Bytes written | Envelope bytes | Fee charged (stroops) | of which rent | Wall clock (ms) |',
  '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |',
];
for (const s of steps) {
  for (const h of s.transactions) {
    const t = tx(h);
    lines.push(
      `| ${s.step}${s.transactions.length > 1 ? ` (${t.label})` : ''} | [\`${h.slice(0, 12)}…\`](https://stellar.expert/explorer/testnet/tx/${h}) | ${n(t.metered?.cpu_insn)} | ${n(t.declared?.instructions)} | ${t.metered ? `${t.metered.read_entry} / ${t.metered.write_entry}` : t.declared ? `${t.declared.readOnly + t.declared.readWrite} (footprint)` : '—'} | ${n(t.metered?.ledger_write_byte ?? t.declared?.writeBytes)} | ${n(t.envelopeBytes)} | ${n(t.feeCharged)} | ${n(t.feeSplit?.rent)} | ${n(t.ms?.total)} |`,
    );
  }
  if (!s.transactions.length) lines.push(`| ${s.step} | — | | | | | | | | ${n(s.ms)} |`);
}
out.table = lines.join('\n');
// The DEPLOYED.md section for this deployment.
const short = (h) => `\`${h.slice(0, 8)}…\``;
out.deployedMd = [
  '## Email recovery (evaluation, TEST-ONLY)',
  '',
  `The email-recovery contracts as \`research/email-recovery/eval/testnet/run.mjs\` deployed them for the evaluation (research/email-recovery/eval/README.md, "Testnet"), around Perch's deployment and Nido's factory above. Built from Nido commit \`${commit}\` with \`just build-contracts\`; deployed ${out.generated.slice(0, 10)} with ${cli}. Every governing key is a throwaway testnet key, and the registry's only key is the Gmail provider mock's TEST-ONLY key: these contracts are not for real accounts.`,
  '',
  '| Contract | Address | Wasm sha256 | Configuration |',
  '| --- | --- | --- | --- |',
  `| \`nido-email-verifier\` | \`${deployed.verifier}\` | ${short(wasm.nido_email_verifier.sha256)} | Constructorless; reports circuit id \`${reportedCircuit.slice(0, 16)}…\` (read back) |`,
  `| \`nido-dkim-registry\` | \`${deployed.registry}\` | ${short(wasm.nido_dkim_registry.sha256)} | ${REGISTRY.members} members, threshold ${REGISTRY.threshold}, revocation ${REGISTRY.revokeThreshold}; the DNS attester mock's ${attesters.length} TEST-ONLY keys, threshold ${REGISTRY.attestThreshold}; grace ${(REGISTRY.graceSeconds / 3_600).toLocaleString('en-US')} hours of close time; the launch allowlist. Proposal ${proposal} (the Gmail mock's key) approved and attested, eligible from close time ${eligibleAt} (Unix seconds) |`,
  `| \`nido-enclave-image-registry\` | \`${deployed.imageRegistry}\` | ${short(wasm.nido_enclave_image_registry.sha256)} | One signer \`${imageSigner.publicKey()}\`, threshold 1; no measurement approved |`,
  `| \`nido-email-guardian\` | wasm uploaded; one instance per account (the run's: \`${e.guardian}\`) | ${short(wasm.nido_email_guardian.sha256)} | — |`,
  '',
  `Deployer \`${deployer.publicKey()}\`. Members: ${members.map((m) => `\`${m.publicKey()}\``).join(', ')}.`,
].join('\n');
mkdirSync(`${repo}research/email-recovery/eval/results`, { recursive: true });
writeFileSync(`${repo}research/email-recovery/eval/results/testnet.json`, JSON.stringify(out, null, 1) + '\n');
console.log(out.table);
