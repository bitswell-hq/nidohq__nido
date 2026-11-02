#!/usr/bin/env node
// Email votes proven against a root the DKIM key registry accepts, on a
// local network (research/email-recovery/eval/README.md, "The registry-root
// path"). A key reaches a registry root only after its addition's timelock:
// 72 hours of ledger close time on the attested path, which the local
// network's close times, the wall clock, make 72 hours of waiting.
//
// 1. `setup` deploys the stack as the attack suite does (lib/stack.mjs: each
//    launch domain's TEST-ONLY key proposed, approved by three members and
//    attested live in DNS by two attesters), and enrolls, per launch domain,
//    two accounts with one helper each and a 2-of-2 quorum: one whose
//    guardian has no key pin, so it accepts registry roots only, and one with
//    the wallet's 30-day pin. It saves the run to
//    target/email-registry-root/state.json (TEST-ONLY keys; not committed).
// 2. `wait` waits until every addition is eligible.
// 3. `vote` executes each addition (permissionless), then opens a lost-key
//    attempt on every account and submits its email vote with a real proof,
//    against the registry's root (the key's leaf index and siblings read
//    from the registry, the path checked against its root) or against the
//    pin, and writes results/registry-root-local.json.
//
// Setup and the votes read the deployed verifier's circuit id back and
// refuse one that is not this tree's artifact's (its proofs would fail the
// guardian's check 12); the state and the results record the build: the
// commit, each email contract's wasm sha256 and the circuit id.
//
// With no phase named it runs all three, resuming from the state file when
// one exists. network/run-registry-root.sh starts the network and runs it.
//
//   NODE_EXTRA_CA_CERTS=target/email-attacks/tls/cert.pem NIDO_EVAL_QUICKSTART_URL=http://127.0.0.1:8001 \
//     node research/email-recovery/eval/network/registry-root.mjs [setup|wait|vote]
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { Passkey } from './lib/account.mjs';
import { Chain } from './lib/chain.mjs';
import { CIRCUIT_ID, Inbox, closeProver, launchKeys } from './lib/email.mjs';
import { enroll, enrolledFromJson, enrolledJson } from './lib/recovery.mjs';
import { EMAIL_WASM, LAUNCH_DOMAINS, deployLocal, stackFromJson, stackJson } from './lib/stack.mjs';
import { proxy } from './lib/tls.mjs';

const repo = new URL('../../../../', import.meta.url).pathname;
const BASE = process.env.NIDO_EVAL_QUICKSTART_URL ?? 'http://127.0.0.1:8001';
const PASSPHRASE = 'Standalone Network ; February 2017';
const STATE = `${repo}target/email-registry-root/state.json`;
const OUT = `${repo}research/email-recovery/eval/results/registry-root-local.json`;
const LIMITS = `${repo}research/email-recovery/eval/network/limits/mainnet.json`;
const APEX = { scheme: 'http:', host: 'localhost', port: 4399 };
const phase = process.argv[2] ?? 'all';
const log = (s) => console.error(`${new Date().toISOString()} ${s}`);

const tls = await proxy(BASE, `${repo}target/email-attacks/tls`);
const chain = new Chain({ rpcUrl: `${tls.url}/rpc`, passphrase: PASSPHRASE, friendbot: `${tls.url}/friendbot` });
const keys = launchKeys();
const keyOf = (d) => keys.find((k) => k.domain === d);

/**
 * The deployed verifier's circuit id, refusing one that is not this tree's:
 * a proof of another circuit fails the guardian's check 12.
 */
async function checkCircuit(verifier) {
  const deployed = Buffer.from(await chain.read(verifier, 'circuit_id')).toString('hex');
  const local = CIRCUIT_ID.toString('hex');
  if (deployed !== local) throw new Error(`the verifier ${verifier} checks circuit ${deployed.slice(0, 16)}…, this tree's artifact is ${local.slice(0, 16)}…: its proofs would fail the guardian's check 12; run the setup again from this build`);
  return deployed;
}

/** The build the run deploys: the commit, each email contract's wasm, and the circuit id. */
function build() {
  const wasm = Object.fromEntries(['nido_email_verifier', 'nido_email_guardian', 'nido_dkim_registry'].map((w) => {
    const b = readFileSync(`${EMAIL_WASM}${w}.wasm`);
    return [w, { bytes: b.length, sha256: createHash('sha256').update(b).digest('hex') }];
  }));
  return { commit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' }).trim(), wasm, circuitId: CIRCUIT_ID.toString('hex') };
}

function save(s) {
  mkdirSync(`${repo}target/email-registry-root`, { recursive: true });
  writeFileSync(STATE, JSON.stringify({ ...s, log: chain.log }, null, 1));
}

async function setup() {
  const t0 = Date.now();
  const stack = await deployLocal(chain, BASE);
  log(`stack deployed; registry ${stack.registry.address}`);
  const accounts = [];
  for (const domain of LAUNCH_DOMAINS) {
    for (const path of ['registry', 'pin']) {
      const e = await enroll({
        chain,
        stack,
        apex: APEX,
        label: `${path}-${domain}`,
        inbox: new Inbox(`first.last@${domain}`),
        key: keyOf(domain),
        helpers: 1,
        quorum: 2,
        delayLedgers: 20,
        expiryLedgers: 2_000,
        pinSeconds: path === 'pin' ? 30 * 86_400 : null,
      });
      accounts.push({ path, domain, ...enrolledJson(e) });
    }
  }
  const proposals = {};
  for (const [domain, id] of Object.entries(stack.proposals)) {
    const p = await stack.registry.proposal(id);
    proposals[domain] = { id, approvedAt: Number(p.approved_at), attestedAt: Number(p.attested_at), eligibleAt: Number(await stack.registry.eligibleAt(id)) };
  }
  const at = await chain.call('getLatestLedger');
  const s = { build: { ...build(), verifierCircuitId: await checkCircuit(stack.email.verifier) }, stack: stackJson(stack), accounts, proposals, setup: { ledger: at.sequence, closeTime: Number(at.closeTime), seconds: Math.round((Date.now() - t0) / 1000) } };
  save(s);
  log(`${accounts.length} accounts enrolled; eligible from close time ${new Date(1000 * Math.max(...Object.values(proposals).map((p) => p.eligibleAt))).toISOString()}`);
  return s;
}

async function wait(s) {
  // Eligibility is a ledger close time (Unix seconds).
  const eligible = Math.max(...Object.values(s.proposals).map((p) => p.eligibleAt));
  for (;;) {
    const at = await chain.closeTime();
    if (at >= eligible) break;
    log(`close time ${at}, eligible at ${eligible} (${((eligible - at) / 3600).toFixed(1)} hours to go)`);
    await new Promise((ok) => setTimeout(ok, Math.min(600_000, Math.max(5_000, (eligible - at) * 1_000))));
  }
}

async function vote(s) {
  const stack = stackFromJson(chain, s.stack);
  await checkCircuit(stack.email.verifier);
  const ctx = { chain, stack, keys };
  for (const [domain, p] of Object.entries(s.proposals)) {
    if (p.executed) continue;
    const r = await stack.registry.execute(p.id);
    p.executed = { hash: r.hash, ledger: r.ledger };
    log(`executed ${domain}'s addition in ledger ${r.ledger}`);
  }
  save(s);
  const votes = [];
  for (const a of s.accounts) {
    const e = enrolledFromJson(ctx, a);
    const { attemptId } = await e.beginLostKey(e.payer, new Passkey(`${a.label}/new-device/${Date.now()}`), `begin_lost_key (${a.path}, ${a.domain})`);
    const st = await e.statement(attemptId);
    const { rho, email } = e.recoveryEmail(st.bytes);
    const keyPath = a.path === 'registry' ? await stack.registry.keyPath(e.key) : e.pinPath();
    const p = await e.prove({ eml: email.eml, rho, statementBytes: st.bytes, keyPath });
    const r = await e.submitEmail(e.payer, {
      attemptId,
      approval: { statement: st.bytes, keyRoot: p.keyRoot, proof: p.proof },
      digest: st.digest,
      label: `submit_guardian (email, ${a.path}, ${a.domain})`,
    });
    if (!r.ok) throw new Error(`${a.label}: the email vote was refused: ${r.refused.message}`);
    votes.push({ path: a.path, domain: a.domain, hash: r.hash, provingMs: p.proveMs });
    log(`${a.label}: vote in ledger ${r.ledger}, ${r.metered?.cpu_insn} instructions, ${r.feeCharged} stroops`);
  }
  await closeProver();
  const at = await chain.call('getLatestLedger');
  const version = await chain.call('getVersionInfo');
  const network = await chain.call('getNetwork');
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
    build: s.build,
    contracts: { controller: s.stack.deployment.recoveryController, registry: s.stack.registry.address, verifier: s.stack.email.verifier },
    setup: s.setup,
    voted: { ledger: at.sequence, closeTime: Number(at.closeTime) },
    waited: { ledgers: at.sequence - s.setup.ledger, seconds: Number(at.closeTime) - s.setup.closeTime },
    proposals: s.proposals,
    accounts: s.accounts.map(({ path, domain, account, guardian, pinValidUntil }) => ({ path, domain, account, guardian, pinValidUntil })),
    votes,
    transactions: chain.log.map(({ label, hash, status, ledger, ms, declared, metered, feeCharged, feeSplit, envelopeBytes, authEntryBytes, footprint }) => ({ label, hash, status, ledger, ms, declared, metered, feeCharged, feeSplit, envelopeBytes, authEntryBytes, footprint })),
  };
  mkdirSync(`${repo}research/email-recovery/eval/results`, { recursive: true });
  writeFileSync(OUT, JSON.stringify(out, null, 1) + '\n');
  log(`wrote ${OUT}`);
}

let s = existsSync(STATE) ? JSON.parse(readFileSync(STATE, 'utf8')) : undefined;
if (s) chain.log.push(...s.log);
if (phase === 'setup' || (phase === 'all' && !s)) s = await setup();
if (!s) throw new Error(`no ${STATE}: run the setup phase first`);
if (phase === 'wait' || phase === 'all') await wait(s);
if (phase === 'vote' || phase === 'all') await vote(s);
process.exit(0);
