#!/usr/bin/env node
// Email votes on Stellar testnet on both key paths
// (research/email-recovery/eval/README.md, "Testnet").
//
// `setup` deploys a new email verifier and DKIM key registry (spec §7.6's
// proposed governance with throwaway members and the TEST-ONLY DNS attester
// mock's keys), admits the Gmail mock's TEST-ONLY key through the attested
// 72-hour path (a proposal, three approvals, two attestations that DNS
// publishes it), and enrolls accounts on Perch's testnet deployment and
// Nido's testnet factory, each with an email guardian pinning that key, one
// helper and a 2-of-2 quorum. Each account opens a lost-key attempt and
// submits its email vote with a real proof against its pin. The run's
// throwaway keys go to the state file (NIDO_TESTNET_STATE, default
// target/email-testnet/votes-state.json; never committed).
//
// Run again with the state file present, `setup` continues that run (an
// account it has not enrolled, a vote it has not submitted).
//
// `vote`, once the addition is eligible (its `eligible_at`, about 72 hours
// of testnet ledgers after setup), executes it and has accounts submit
// email votes proven against the registry's root.
//
// Both write results/testnet-votes.json.
//
//   node research/email-recovery/eval/testnet/votes.mjs setup [accounts]
//   node research/email-recovery/eval/testnet/votes.mjs vote [accounts]
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { perch } from '@nidohq/passkey-sdk';
import { Address, Keypair, Networks, Operation, xdr } from '@stellar/stellar-sdk';
import { Passkey } from '../network/lib/account.mjs';
import { Chain, sc } from '../network/lib/chain.mjs';
import { CIRCUIT_ID, Inbox, closeProver, launchKeys } from '../network/lib/email.mjs';
import { enroll, enrolledFromJson, enrolledJson } from '../network/lib/recovery.mjs';
import { Attester, REGISTRY, Registry, admitThroughTimelock } from '../network/lib/stack.mjs';

const repo = new URL('../../../../', import.meta.url).pathname;
const RPC = process.env.NIDO_TESTNET_RPC ?? 'https://soroban-testnet.stellar.org';
const FRIENDBOT = process.env.NIDO_TESTNET_FRIENDBOT ?? 'https://friendbot.stellar.org';
const WASM = `${repo}target/wasm32v1-none/contract/`;
const STATE = process.env.NIDO_TESTNET_STATE ?? `${repo}target/email-testnet/votes-state.json`;
const OUT = `${repo}research/email-recovery/eval/results/testnet-votes.json`;
const APEX = { scheme: 'https:', host: 'nido.example', port: 0 };
const sha256 = (b) => createHash('sha256').update(b).digest();
const log = (s) => console.error(`${new Date().toISOString()} ${s}`);
const [phase = 'setup', n] = process.argv.slice(2);

const chain = new Chain({ rpcUrl: RPC, passphrase: Networks.TESTNET, friendbot: FRIENDBOT, settleMs: 3_000 });
const d = perch.TESTNET;
const keys = launchKeys();
const gmail = keys.find((k) => k.domain === 'gmail.com');
const attesters = [0, 1, 2].map((i) => new Attester(i));

function save(s) {
  mkdirSync(dirname(STATE), { recursive: true });
  writeFileSync(STATE, JSON.stringify(s, null, 1));
}

/** Restore Perch's entries an enrollment or a vote reaches, when testnet has archived them. */
async function restorePerch(payer) {
  const codeKey = (file) => xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: sha256(readFileSync(`${WASM}${file}`)) }));
  const instanceKey = (c) => xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({ contract: Address.fromString(c).toScAddress(), key: xdr.ScVal.scvLedgerKeyContractInstance(), durability: xdr.ContractDataDurability.persistent() }));
  const perchKeys = [
    ['doc compiler instance', instanceKey(d.docCompiler)],
    ['doc compiler code', codeKey('perch_doc_compiler.wasm')],
    ['recovery controller instance', instanceKey(d.recoveryController)],
    ['recovery controller code', codeKey('perch_recovery.wasm')],
  ];
  const archived = await chain.archived(perchKeys.map((k) => k[1]));
  const restored = [];
  for (const [name, k] of perchKeys) {
    if (archived.some((a) => a.toXDR('base64') === k.toXDR('base64'))) {
      await chain.restore(payer, [k], { label: `restore ${name}` });
      restored.push(name);
    }
  }
  return restored;
}

async function deploy(deployer, t0) {
  const wasm = {};
  const upload = async (name) => {
    const bytes = readFileSync(`${WASM}${name}.wasm`);
    await chain.send(deployer, Operation.uploadContractWasm({ wasm: bytes }), { label: `upload ${name}` });
    wasm[name] = { sha256: sha256(bytes).toString('hex'), bytes: bytes.length };
    return sha256(bytes);
  };
  const create = async (name, args = []) => {
    const r = await chain.send(
      deployer,
      Operation.createCustomContract({ address: Address.fromString(deployer.publicKey()), wasmHash: await upload(name), salt: sha256(`nido/email-recovery/testnet-votes/${name}/${t0}`), constructorArgs: args }),
      { label: `deploy ${name}` },
    );
    return Address.fromScVal(r.scVal).toString();
  };
  const members = [];
  for (let i = 0; i < REGISTRY.members; i++) members.push(await chain.funded(Keypair.random()));
  const verifier = await create('nido_email_verifier');
  const reported = Buffer.from(await chain.read(verifier, 'circuit_id')).toString('hex');
  if (reported !== CIRCUIT_ID.toString('hex')) throw new Error('the deployed verifier reports another circuit id');
  const registry = await create('nido_dkim_registry', [Registry.configScVal({ members, attesters })]);
  const guardianWasmHash = (await upload('nido_email_guardian')).toString('hex');
  return { verifier, registry, guardianWasmHash, members, wasm };
}

function write(s) {
  const out = {
    generated: new Date().toISOString(),
    network: Networks.TESTNET,
    rpc: RPC,
    rpcVersion: s.rpcVersion,
    commit: s.commit,
    stellarCli: s.stellarCli,
    perch: d,
    contracts: s.contracts,
    deployer: s.deployer,
    gmailProposal: s.proposal,
    restoredPerchEntries: s.restored,
    accounts: s.accounts.map(({ label, account, guardian, pinValidUntil }) => ({ label, account, guardian, pinValidUntil })),
    votes: s.votes,
    transactions: s.log,
  };
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, JSON.stringify(out, null, 1) + '\n');
  log(`wrote ${OUT}`);
}

/** One lost-key attempt on `e` and its email vote, against `keyPath` (the pin by default). */
async function voteOn(e, path, keyPath) {
  const { attemptId } = await e.beginLostKey(e.payer, new Passkey(`${e.label}/new-device/${Date.now()}`), `begin_lost_key (${path}, ${e.label})`);
  const st = await e.statement(attemptId);
  const { rho, email } = e.recoveryEmail(st.bytes);
  const p = await e.prove({ eml: email.eml, rho, statementBytes: st.bytes, ...(keyPath ? { keyPath } : {}) });
  const r = await e.submitEmail(e.payer, { attemptId, approval: { statement: st.bytes, keyRoot: p.keyRoot, proof: p.proof }, digest: st.digest, label: `submit_guardian (email, ${path}, ${e.label})` });
  if (!r.ok) throw new Error(`${e.label}: the ${path} vote was refused: ${r.refused.message}`);
  log(`${e.label}: ${path} vote ${r.hash} in ledger ${r.ledger}, ${r.metered?.cpu_insn} instructions, ${r.feeCharged} stroops`);
  return { path, label: e.label, hash: r.hash, ledger: r.ledger, provingMs: p.proveMs };
}

async function setup(count, s) {
  if (!s) {
    const t0 = Date.now();
    Attester.ensureBuilt();
    const deployer = await chain.funded(Keypair.random());
    const restored = await restorePerch(deployer);
    const c = await deploy(deployer, t0);
    const registry = new Registry(chain, c.registry, c.members, attesters, deployer);
    const id = await admitThroughTimelock(registry, gmail);
    s = {
      commit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' }).trim(),
      stellarCli: execFileSync('stellar', ['--version'], { encoding: 'utf8' }).split('\n')[0],
      rpcVersion: await chain.call('getVersionInfo').catch(() => ({})),
      deployer: deployer.publicKey(),
      secrets: { deployer: deployer.secret(), members: c.members.map((m) => m.secret()) },
      contracts: {
        'nido-email-verifier': { address: c.verifier, ...c.wasm.nido_email_verifier },
        'nido-dkim-registry': { address: c.registry, ...c.wasm.nido_dkim_registry },
        'nido-email-guardian': { uploaded: true, ...c.wasm.nido_email_guardian },
      },
      stack: { guardianWasmHash: c.guardianWasmHash, verifier: c.verifier, registry: c.registry },
      proposal: { id, eligibleAt: Number(await registry.eligibleAt(id)) },
      restored,
      accounts: [],
      votes: [],
    };
    s.log = chain.log;
    save(s);
  } else {
    chain.log.push(...s.log);
    s.log = chain.log;
  }
  const deployer = Keypair.fromSecret(s.secrets.deployer);
  const registry = new Registry(chain, s.stack.registry, s.secrets.members.map((m) => Keypair.fromSecret(m)), attesters, deployer);
  const stack = { deployment: d, email: { guardianWasmHash: s.stack.guardianWasmHash, verifier: s.stack.verifier }, registry };
  for (let i = 0; i < count; i++) {
    const label = `testnet-${i}`;
    let j = s.accounts.find((a) => a.label === label);
    if (!j) {
      const e = await enroll({ chain, stack, label, inbox: new Inbox(`first.last.${i}@gmail.com`), key: gmail, helpers: 1, quorum: 2, delayLedgers: 12, expiryLedgers: 2_000, apex: APEX });
      j = enrolledJson(e);
      s.accounts.push(j);
      save(s);
    }
    if (!s.votes.some((v) => v.path === 'pin' && v.label === label)) {
      s.votes.push(await voteOn(enrolledFromJson({ chain, stack, keys }, j), 'pin'));
      save(s);
    }
  }
  await closeProver();
  log(`registry ${s.stack.registry}: the Gmail key's addition is eligible from ledger ${s.proposal.eligibleAt}`);
  write(s);
}

async function vote(s, count) {
  const deployer = Keypair.fromSecret(s.secrets.deployer);
  const registry = new Registry(chain, s.stack.registry, s.secrets.members.map((m) => Keypair.fromSecret(m)), attesters, deployer);
  const stack = { deployment: d, email: { guardianWasmHash: s.stack.guardianWasmHash, verifier: s.stack.verifier }, registry };
  chain.log.push(...s.log);
  const at = await chain.ledger();
  if (at < s.proposal.eligibleAt) throw new Error(`the addition is eligible from ledger ${s.proposal.eligibleAt}; testnet is at ${at}`);
  s.restored = [...s.restored, ...(await restorePerch(deployer))];
  if (!s.proposal.executed) {
    const r = await registry.execute(s.proposal.id);
    s.proposal.executed = { hash: r.hash, ledger: r.ledger };
    s.log = chain.log;
    save(s);
  }
  const keyPath = await registry.keyPath(gmail);
  for (const a of s.accounts.slice(0, count)) {
    const e = enrolledFromJson({ chain, stack, keys }, a);
    s.votes.push(await voteOn(e, 'registry', keyPath));
    s.log = chain.log;
    save(s);
  }
  await closeProver();
  write(s);
}

if (phase === 'setup') {
  // An existing state file continues its run's setup.
  await setup(Number(n ?? 6), existsSync(STATE) ? JSON.parse(readFileSync(STATE, 'utf8')) : undefined);
} else if (phase === 'vote') {
  await vote(JSON.parse(readFileSync(STATE, 'utf8')), Number(n ?? 3));
} else {
  throw new Error(`unknown phase ${phase}`);
}
process.exit(0);
