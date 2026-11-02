// The email factor's attack suite on a local Stellar network
// (`stellar/quickstart --local`): every scenario runs against Perch's
// controller and account and Nido's guardian, verifier and DKIM key
// registry as deployed there (lib/stack.mjs), with the real recovery
// circuit (noir_js) and real proofs (bb.js in Node). Each scenario asserts
// its outcome and records the layer that refused it, decoded from the
// network's own answer (lib/layers.mjs), into
// research/email-recovery/eval/results/attacks-local.json.
//
//   NODE_EXTRA_CA_CERTS=target/email-attacks/tls/cert.pem node --test-concurrency=1 --test research/email-recovery/eval/network/attacks.mjs
//
// research/email-recovery/eval/network/run-attacks.sh (`just
// email-recovery-attacks`) starts the network, builds what it needs and
// runs this. Three registry scenarios whose precondition is a registry
// timelock having elapsed (72 hours or 7 days of ledger close time) run on the
// integration-test host instead, where the ledger can be advanced
// (crates/integration-tests/tests/it/email_guardian.rs, `registry_*`).
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { after, before, describe, test } from 'node:test';
import { buildAttacks, gmailSigner, testKey } from '@nidohq/email-mocks';
import { NEVER_ASKS, PASSKEY_DEVICE_LEAD } from '@nidohq/email-alerts';
import { blindedDigest, decryptBackup, encryptBackup, fieldHex, generatePassphrase, keyHash, merkleRoot, registryLeaf } from '@nidohq/email-recovery';
import { perch } from '@nidohq/passkey-sdk';
import { Address, Keypair, Operation, xdr } from '@stellar/stellar-sdk';
import { Passkey } from './lib/account.mjs';
import { Alerts } from './lib/alerts.mjs';
import { Chain, sc } from './lib/chain.mjs';
import { Inbox, approvalEntry, closeProver, launchKeys, proveWitness, sha256 } from './lib/email.mjs';
import { circuitVerdict } from './lib/forge.mjs';
import { layerOf } from './lib/layers.mjs';
import { EvidenceDomain, enroll } from './lib/recovery.mjs';
import { LAUNCH_DOMAINS, closeTime, deployLocal, stackFromJson, stackJson } from './lib/stack.mjs';
import { proxy } from './lib/tls.mjs';

const repo = new URL('../../../../', import.meta.url).pathname;
const BASE = process.env.NIDO_EVAL_QUICKSTART_URL ?? 'http://127.0.0.1:8000';
const PASSPHRASE = 'Standalone Network ; February 2017';
const OUT = process.env.NIDO_EVAL_ATTACKS_OUT ?? `${repo}research/email-recovery/eval/results/attacks-local.json`;
const PHRASE = 'APPROVE NIDO ACCOUNT RECOVERY';
const APEX = { scheme: 'http:', host: 'localhost', port: 4399 };
const TESTNET_ID = sha256('Test SDF Network ; September 2015');

/** One row of the results table. */
const rows = [];
/** The test that is running: each row names the test that produced it. */
let current;
const scenario = (name, fn) => test(name, (t) => ((current = name), fn(t)));
/** The circuit's verdict on each adversarial email of the mocks. */
const cases = [];
let chain, stack, roles, alerts, gmail;
const t0 = Date.now();

/**
 * Record a scenario's outcome. `property` is the §11.2 property it
 * exercises (1 soundness, 2 privacy, 3 replay, 4 one-factor safety).
 */
function record(cls, id, property, expected, observed, layer, detail = {}) {
  rows.push({ class: cls, scenario: id, test: current, property, expected, observed, layer, network: 'local', ...detail });
  assert.equal(observed, expected, `${id}: expected ${expected}, observed ${observed}`);
}

/** A transaction's outcome: `accepted`, or `refused: <error>` with the layer that raised it. */
function outcome(r) {
  if (r.ok) return { observed: 'accepted', layer: '—', hash: r.hash };
  const { layer, error } = layerOf(r.refused, roles);
  return { observed: `refused: ${error}`, layer, stage: r.refused.stage };
}

const value = (digest, rho) => fieldHex(blindedDigest(digest, rho));
const approvalOf = (st, p) => ({ statement: st.bytes, keyRoot: p.keyRoot, proof: p.proof });

/** An honest approval of `e`'s attempt: the recovery email from its inbox, proved against its pin. */
async function honest(e, attemptId, opts = {}) {
  const st = await e.statement(attemptId, opts.domain);
  const { rho, email } = e.recoveryEmail(st.bytes, opts);
  const p = await e.prove({ eml: email.eml, rho, statementBytes: st.bytes });
  return { st, rho, email, p, approval: approvalOf(st, p) };
}

/** The target `strongestWitness` needs for `e`'s attempt with `rho`. */
const targetOf = (e, st, rho, accountCode = e.inbox.accountCode) => ({ accountCode, digest: st.digest, rho, pinLeaves: e.pin.leaves });

let A, B, L, E, P, Q;
/** V: an email vote below quorum; S1-S3: phishing; G: repeated attempts; O: a watcher outage; L2: a lapsed push. */
/**
 * The label of the votes that authorize an attempt in those scenarios: not
 * `submit_guardian (email…`, so the cost tables keep to the collecting votes
 * and the email-plus-delay account L's authorizing vote.
 */
const ALERT_VOTE = 'email vote that authorizes (alert-path scenario)';
let V, S1, S2, S3, G, O, L2;
const providers = {};
const newOwner = (label) => new Passkey(`${label}/new-device/${Date.now()}`);

before(async () => {
  const tls = await proxy(BASE, `${repo}target/email-attacks/tls`);
  chain = new Chain({ rpcUrl: `${tls.url}/rpc`, passphrase: PASSPHRASE, friendbot: `${tls.url}/friendbot` });
  const file = `${repo}target/email-attacks/stack.json`;
  const reuse = existsSync(file) && process.env.NIDO_EVAL_REUSE_STACK === '1';
  if (reuse) stack = stackFromJson(chain, JSON.parse(readFileSync(file, 'utf8')));
  else {
    stack = await deployLocal(chain, BASE);
    mkdirSync(`${repo}target/email-attacks`, { recursive: true });
    writeFileSync(file, JSON.stringify(stackJson(stack), null, 1));
  }
  const keys = launchKeys();
  gmail = keys.find((k) => k.domain === 'gmail.com');
  const enrollAll = (specs) => Promise.all(specs.map((s) => enroll({ chain, stack, apex: APEX, ...s })));
  [A, B, E, Q] = await enrollAll([
    // A: the victim; two helpers, a 2-of-3 quorum.
    { label: 'A', inbox: new Inbox('first.last@gmail.com'), key: gmail, helpers: 2, quorum: 2, delayLedgers: 20, expiryLedgers: 2_000 },
    // B: another account of the same address, with its own account code.
    { label: 'B', inbox: new Inbox('first.last@gmail.com'), key: gmail, helpers: 1, quorum: 2, delayLedgers: 20, expiryLedgers: 2_000 },
    // E: an evidence window of 12 ledgers.
    { label: 'E', inbox: new Inbox('e.short@gmail.com'), key: gmail, helpers: 1, quorum: 2, delayLedgers: 20, expiryLedgers: 12 },
    // Q: accepted header variants, each on its own attempt.
    { label: 'Q', inbox: new Inbox('q.quirks@gmail.com'), key: gmail, helpers: 1, quorum: 2, delayLedgers: 20, expiryLedgers: 2_000 },
  ]);
  // L: the lost-key profile with email plus delay: the email guardian is the only guardian,
  // quorum 1, so the wallet requires the loss profile and seven days of ledgers at the
  // network's target close time (120,960 at the 5,000 ms this network reports).
  L = await enroll({ chain, stack, apex: APEX, label: 'L', inbox: new Inbox('ada.lovelace@proton.me'), key: keys.find((k) => k.domain === 'proton.me'), helpers: 0, quorum: 1, delayLedgers: 120_960 });
  const proton = keys.find((k) => k.domain === 'proton.me');
  const lossDelay = { key: proton, helpers: 0, quorum: 1, delayLedgers: 120_960 };
  [V, S1, S2, S3] = await enrollAll([
    // V: email plus one helper, a 2-of-2 quorum: the email vote alone leaves the attempt collecting.
    { label: 'V', inbox: new Inbox('v.vote@gmail.com'), key: gmail, helpers: 1, quorum: 2, delayLedgers: 20, expiryLedgers: 2_000 },
    // S1: email plus delay, as the wallet builds it.
    { label: 'S1', inbox: new Inbox('s1.phished@proton.me'), ...lossDelay },
    // S2: email plus a delay of 20 ledgers, outside the wallet's policy (it requires 120,960), so the delay elapses in the run.
    { label: 'S2', inbox: new Inbox('s2.phished@proton.me'), key: proton, helpers: 0, quorum: 1, delayLedgers: 20, expiryLedgers: 2_000, walletPolicy: false },
    // S3: email plus a second helper.
    { label: 'S3', inbox: new Inbox('s3.phished@gmail.com'), key: gmail, helpers: 1, quorum: 2, delayLedgers: 20, expiryLedgers: 2_000 },
  ]);
  [G, O, L2] = await enrollAll([
    { label: 'G', inbox: new Inbox('g.grief@gmail.com'), key: gmail, helpers: 1, quorum: 2, delayLedgers: 20, expiryLedgers: 2_000 },
    { label: 'O', inbox: new Inbox('o.outage@proton.me'), ...lossDelay },
    { label: 'L2', inbox: new Inbox('l2.lapsed@proton.me'), ...lossDelay },
  ]);
  for (let i = 0; i < LAUNCH_DOMAINS.length; i += 4) {
    const batch = LAUNCH_DOMAINS.slice(i, i + 4);
    const enrolled = await enrollAll(batch.map((d) => ({ label: `provider-${d}`, inbox: new Inbox(`first.last@${d}`), key: keys.find((k) => k.domain === d), helpers: 1, quorum: 2, delayLedgers: 20, expiryLedgers: 2_000 })));
    batch.forEach((d, j) => (providers[d] = enrolled[j]));
  }
  roles = new Map([[stack.deployment.recoveryController, 'controller'], [stack.registry.address, 'registry'], [stack.email.verifier, 'verifier']]);
  for (const e of [A, B, E, Q, L, V, S1, S2, S3, G, O, L2, ...Object.values(providers)]) {
    roles.set(e.guardian, 'guardian');
    roles.set(e.account.address, 'account');
  }
  alerts = await Alerts.start({
    rpcUrl: `${BASE}/rpc`,
    passphrase: PASSPHRASE,
    controller: stack.deployment.recoveryController,
    imageRegistry: stack.email.enclaveImageRegistry,
    measurement: stack.measurement,
    apex: APEX,
    guardianWasmHash: stack.email.guardianWasmHash,
  });
});

after(async () => {
  await closeProver();
  await alerts?.close();
  const version = await chain.call('getVersionInfo').catch(() => ({}));
  const network = await chain.call('getNetwork').catch(() => ({}));
  mkdirSync(`${repo}research/email-recovery/eval/results`, { recursive: true });
  writeFileSync(
    OUT,
    JSON.stringify(
      {
        generated: new Date().toISOString(),
        network: { kind: 'stellar/quickstart --local', image: process.env.NIDO_EVAL_QUICKSTART_IMAGE ?? 'unknown', passphrase: PASSPHRASE, protocolVersion: network.protocolVersion, rpc: version },
        contracts: { controller: stack.deployment.recoveryController, registry: stack.registry.address, verifier: stack.email.verifier },
        durationSeconds: Math.round((Date.now() - t0) / 1000),
        rows,
        circuitCases: cases,
        transactions: chain.log.map(({ label, hash, status, ledger, ms, declared, metered, feeCharged, feeSplit, envelopeBytes, authEntryBytes, footprint }) => ({ label, hash, status, ledger, ms, declared, metered, feeCharged, feeSplit, envelopeBytes, authEntryBytes, ...(/^submit_guardian \(email/.test(label) ? { footprint } : {}) })),
      },
      null,
      1,
    ) + '\n',
  );
});

// --- the attempts the scenarios share --------------------------------------

/** A's attempts: a1 the owner's, a2 a second one, a3 an attacker's new key, a4 a later one of the owner's. */
const a = {};
let a1;

describe('replayed emails and proofs', () => {
  scenario('replay-same-attempt-twice', async () => {
    a.a1 = await A.beginLostKey(A.payer, newOwner('A'));
    a1 = await honest(A, a.a1.attemptId);
    const first = outcome(await A.submitEmail(A.payer, { attemptId: a.a1.attemptId, approval: a1.approval, digest: a1.st.digest }));
    assert.equal(first.observed, 'accepted');
    const again = outcome(await A.submitEmail(A.payer, { attemptId: a.a1.attemptId, approval: a1.approval, digest: a1.st.digest }));
    record('replay', 'replay-same-attempt-twice', 3, 'refused: AlreadyCounted', again.observed, again.layer, { note: 'The first submission counted one vote; the same approval in a fresh authorization entry is refused.' });
  });

  scenario('replay-another-attempt', async () => {
    a.a2 = await A.beginLostKey(A.payer, newOwner('A2'));
    const st2 = await A.statement(a.a2.attemptId);
    const asIs = outcome(await A.submitEmail(A.payer, { attemptId: a.a2.attemptId, approval: a1.approval, digest: st2.digest }));
    record('replay', 'replay-another-attempt', 3, 'refused: DigestMismatch', asIs.observed, asIs.layer, { note: "a1's approval with its own statement, in a2's context" });
    const spliced = outcome(await A.submitEmail(A.payer, { attemptId: a.a2.attemptId, approval: { ...a1.approval, statement: st2.bytes }, digest: st2.digest }));
    record('replay', 'replay-another-attempt-spliced', 3, 'refused: ProofRejected', spliced.observed, spliced.layer, { note: "a2's statement with a1's proof" });
  });

  scenario('replay-another-account', async () => {
    const b1 = await B.beginLostKey(B.payer, newOwner('B'));
    a.b1 = b1;
    const stb = await B.statement(b1.attemptId);
    const asIs = outcome(await B.submitEmail(B.payer, { attemptId: b1.attemptId, approval: a1.approval, digest: stb.digest }));
    record('replay', 'replay-another-account', 3, 'refused: DigestMismatch', asIs.observed, asIs.layer, { note: "A's approval through B's guardian (same address, B's own account code)" });
    const spliced = outcome(await B.submitEmail(B.payer, { attemptId: b1.attemptId, approval: { ...a1.approval, statement: stb.bytes }, digest: stb.digest }));
    record('replay', 'replay-another-account-spliced', 3, 'refused: UnknownRoot', spliced.observed, spliced.layer, { note: "B's statement with A's proof and key root: A's root is A's own salted pin, which B's guardian does not accept" });
    const bRoot = Buffer.from(B.pin.root.toString(16).padStart(64, '0'), 'hex');
    const rooted = outcome(await B.submitEmail(B.payer, { attemptId: b1.attemptId, approval: { ...a1.approval, statement: stb.bytes, keyRoot: bRoot }, digest: stb.digest }));
    record('replay', 'replay-another-account-rooted', 3, 'refused: ProofRejected', rooted.observed, rooted.layer, { note: "B's statement and B's pin root with A's proof" });
    const viaA = outcome(await B.submitEmail(B.payer, { attemptId: b1.attemptId, approval: a1.approval, digest: stb.digest, guardian: A.guardian }));
    record('replay', 'replay-another-account-guardian', 3, 'refused: NotAGuardian', viaA.observed, viaA.layer, { note: "A's guardian named for B's attempt" });
  });

  scenario('replay-another-network', async () => {
    // The same inbox approving a2's statement as another network (testnet's id) would build it.
    // (a2 has no email vote yet: the controller refuses a guardian that already voted before asking it.)
    const st2 = await A.statement(a.a2.attemptId);
    const foreign = Uint8Array.from(st2.bytes);
    foreign.set(TESTNET_ID, 26);
    const { rho, email } = A.recoveryEmail(foreign);
    const p = await A.prove({ eml: email.eml, rho, statementBytes: foreign });
    const asIs = outcome(await A.submitEmail(A.payer, { attemptId: a.a2.attemptId, approval: { statement: foreign, keyRoot: p.keyRoot, proof: p.proof }, digest: st2.digest }));
    record('replay', 'replay-another-network', 3, 'refused: DigestMismatch', asIs.observed, asIs.layer, { note: 'an approval of the statement with the testnet network id' });
    const spliced = outcome(await A.submitEmail(A.payer, { attemptId: a.a2.attemptId, approval: { statement: st2.bytes, keyRoot: p.keyRoot, proof: p.proof }, digest: st2.digest }));
    record('replay', 'replay-another-network-spliced', 3, 'refused: ProofRejected', spliced.observed, spliced.layer, { note: "this network's statement with that proof" });
  });

  scenario('replay-another-controller', async () => {
    const op = Operation.uploadContractWasm({ wasm: readFileSync(`${repo}target/email-attacks/wasm/nido_eval_foreign_controller.wasm`) });
    const wasmHash = sha256(op.body().invokeHostFunctionOp().hostFunction().wasm());
    await chain.send(stack.operator, op, { label: 'upload foreign controller' });
    const created = await chain.send(
      stack.operator,
      Operation.createCustomContract({ address: Address.fromString(stack.operator.publicKey()), wasmHash: Buffer.from(wasmHash), salt: Buffer.from(sha256(`foreign/${Date.now()}`)) }),
      { label: 'deploy foreign controller' },
    );
    const foreign = Address.fromScVal(created.scVal).toString();
    roles.set(foreign, 'foreign');
    const entry = approvalEntry({ guardian: A.guardian, controller: foreign, digest: a1.st.digest, approval: a1.approval, expirationLedger: (await chain.ledger()) + 1_000 });
    const call = Operation.invokeHostFunction({
      func: xdr.HostFunction.hostFunctionTypeInvokeContract(new xdr.InvokeContractArgs({ contractAddress: Address.fromString(foreign).toScAddress(), functionName: 'submit_guardian', args: [sc.address(A.guardian), sc.bytes(a1.st.digest)] })),
      auth: [entry],
    });
    const r = outcome(await chain.attempt(A.payer, call, { authMode: 'enforce', label: 'foreign controller asks the guardian' }));
    record('replay', 'replay-another-controller', 3, 'refused: UnexpectedContext', r.observed, r.layer, { note: "A's approval, asked for by a contract that is not A's controller" });
  });

  scenario('replay-expired-statement', async () => {
    const e1 = await E.beginLostKey(E.payer, newOwner('E'));
    const h = await honest(E, e1.attemptId);
    const att = await E.attempt(e1.attemptId);
    await chain.untilLedger(Number(att.evidence_deadline) + 1);
    const r = outcome(await E.submitEmail(E.payer, { attemptId: e1.attemptId, approval: h.approval, digest: h.st.digest }));
    record('replay', 'replay-expired-statement', 3, 'refused: AttemptNotLive', r.observed, r.layer, { note: `proved before, submitted after the evidence deadline (ledger ${att.evidence_deadline}, the statement's valid_until_ledger)` });
  });
});

describe('wrong account or new key in the statement', () => {
  scenario('statement-other-new-key', async () => {
    // An attacker opens an attempt that installs their own key.
    a.a3 = await A.beginLostKey(A.payer, newOwner('attacker'));
    const st3 = await A.statement(a.a3.attemptId);
    assert.notDeepEqual(Buffer.from(st3.bytes.subarray(246, 278)), Buffer.from(a1.st.bytes.subarray(246, 278)), 'the replacement hashes differ');
    const asIs = outcome(await A.submitEmail(A.payer, { attemptId: a.a3.attemptId, approval: a1.approval, digest: st3.digest }));
    record('statement', 'statement-other-new-key', 1, 'refused: DigestMismatch', asIs.observed, asIs.layer, { note: "the owner's approval (owner's new key) presented for the attacker's attempt (attacker's key)" });
    const spliced = outcome(await A.submitEmail(A.payer, { attemptId: a.a3.attemptId, approval: { ...a1.approval, statement: st3.bytes }, digest: st3.digest }));
    record('statement', 'statement-other-new-key-spliced', 1, 'refused: ProofRejected', spliced.observed, spliced.layer, { note: "the attacker's statement with the owner's proof" });
  });

  scenario('statement-other-account', async () => {
    // A valid approval of B's attempt (B's owner approving B's own recovery) presented to A's guardian.
    const hb = await honest(B, a.b1.attemptId);
    const okB = outcome(await B.submitEmail(B.payer, { attemptId: a.b1.attemptId, approval: hb.approval, digest: hb.st.digest }));
    assert.equal(okB.observed, 'accepted');
    const st3 = await A.statement(a.a3.attemptId);
    const r = outcome(await A.submitEmail(A.payer, { attemptId: a.a3.attemptId, approval: hb.approval, digest: st3.digest }));
    record('statement', 'statement-other-account', 1, 'refused: DigestMismatch', r.observed, r.layer, { note: "B's approval presented to A's guardian for A's attempt" });
    const spliced = outcome(await A.submitEmail(A.payer, { attemptId: a.a3.attemptId, approval: { ...hb.approval, statement: st3.bytes }, digest: st3.digest }));
    record('statement', 'statement-other-account-spliced', 1, 'refused: UnknownRoot', spliced.observed, spliced.layer, { note: "A's statement with B's proof and key root: B's salted pin root, which A's guardian does not accept" });
    const aRoot = Buffer.from(A.pin.root.toString(16).padStart(64, '0'), 'hex');
    const rooted = outcome(await A.submitEmail(A.payer, { attemptId: a.a3.attemptId, approval: { ...hb.approval, statement: st3.bytes, keyRoot: aRoot }, digest: st3.digest }));
    record('statement', 'statement-other-account-rooted', 1, 'refused: ProofRejected', rooted.observed, rooted.layer, { note: "A's statement and A's pin root with B's proof (another commitment)" });
  });
});

describe('forged emails', () => {
  scenario('forged-emails-circuit', async () => {
    // Every adversarial email of the mocks, built for A's live attempt a1
    // (and a2, and B's attempt b1), with the attacker's strongest witness.
    const stb = await B.statement(a.b1.attemptId);
    const st2 = await A.statement(a.a2.attemptId);
    const rho2 = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0bn;
    const rhoB = 0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0cn;
    const input = {
      victim: A.inbox.address,
      attacker: 'attacker@gmail.com',
      phrase: PHRASE,
      subject: `${PHRASE} ${value(a1.st.digest, a1.rho)}`,
      recoveryValue: value(a1.st.digest, a1.rho),
      otherRecoveryValue: value(st2.digest, rho2),
      account: 'account-a',
      otherAccount: 'account-b',
      body: 'This message is a test fixture.\r\n',
    };
    const pinned = pinnedOutcomes();
    for (const c of buildAttacks(input)) {
      const isB = c.claim.account === 'account-b';
      const target = isB
        ? targetOf(B, stb, rhoB)
        : c.claim.recoveryValue === input.otherRecoveryValue
          ? targetOf(A, st2, rho2)
          : targetOf(A, a1.st, a1.rho);
      if (isB) target.digest = stb.digest;
      const v = await circuitVerdict({ eml: c.email.eml, claimFrom: c.claim.from, target, dnsRecords: c.email.dnsRecords });
      const got = v.accepted ? 'accepted' : v.reason;
      cases.push({ id: c.id, verdict: c.verdict, tree: v.tree, outcome: got, pinned: pinned[c.id] });
      if (c.verdict === 'valid-dkim-but-must-be-rejected-by-circuit') assert.notEqual(got, 'accepted', c.id);
      if (c.verdict === 'valid-dkim-and-must-be-accepted') assert.equal(got, 'accepted', c.id);
      if (c.verdict === 'invalid-dkim' && c.id !== 'wrong-body-hash') assert.notEqual(got, 'accepted', c.id);
      assert.equal(got, pinned[c.id], `${c.id}: the network run's verdict matches packages/email-recovery/test/attacks.test.ts`);
    }
    const group = (cls, id, ids, note) => {
      const of = cases.filter((x) => ids.some((p) => (p instanceof RegExp ? p.test(x.id) : x.id === p)));
      const refused = of.filter((x) => x.outcome !== 'accepted');
      record(cls, id, 1, `refused: ${of.length} of ${of.length}`, `refused: ${refused.length} of ${of.length}`, 'circuit', { cases: of.map((x) => `${x.id}: ${x.outcome}`), note });
    };
    group('forged', 'forged-unsigned-or-duplicated-headers', [/^unsigned-/, 'from-not-signed'], 'a second, unsigned From or Subject above or below the signed one, at every provider format; h= without From');
    group('forged', 'forged-display-name-spoofing', [/^from-/, 'recovery-value-in-display-name'].filter((p) => p !== 'from-not-signed'), 'the victim address in the display name, an address list or unclosed quote before it, a comment, a quoted local part, a fold');
    group('forged', 'forged-misaligned-d', [/^misaligned-d-/, 'multiple-signatures-one-valid'], 'a signature by another domain, alone or under a forged one for the claimed domain');
    group('forged', 'forged-weak-key', ['weak-key-rsa1024'], 'an aligned signature under a 1024-bit key');
    group('forged', 'forged-signature-plus-modulus', ['signature-plus-modulus'], 'b= is σ + N');
    group('forged', 'forged-body-and-length', ['body-length-tag', 'recovery-value-in-body'], 'l= with appended text; the value only in the body');
    group('replay', 'replay-email-circuit', ['replay-other-statement', 'replay-other-account'], 'an honest email presented for another statement of A, and for B');
    group('quirks', 'quirks-encoded-word-subject', [/^subject-encoded-word-/], 'RFC 2047 B and Q encoded-word Subjects, and the iCloud web form');
    group('quirks', 'quirks-split-subject', ['subject-value-split-by-fold', 'subject-phrase-split-by-whitespace'], 'a fold inside the value, whitespace inside the phrase');
  });

  scenario('forged-bad-signature', async () => {
    const { email } = A.recoveryEmail(a1.st.bytes, { rho: a1.rho });
    const text = Buffer.from(email.eml).toString('latin1');
    const b = email.signatures.find((s) => s.domain === 'gmail.com' && s.standard).b;
    const at = text.indexOf(`b=${b.slice(0, 24)}`);
    assert.ok(at > 0);
    const flip = b[0] === 'A' ? 'B' : 'A';
    const forged = Buffer.from(text.slice(0, at + 2) + flip + text.slice(at + 3), 'latin1');
    const v = await circuitVerdict({ eml: forged, claimFrom: A.inbox.address, target: targetOf(A, a1.st, a1.rho) });
    record('forged', 'forged-bad-signature', 1, 'refused: RSA: signature does not verify', v.accepted ? 'accepted' : `refused: ${v.reason}`, 'circuit', { note: "the provider's own email with one character of b= changed" });
  });

  scenario('forged-wrong-key', async () => {
    // A Gmail-format email for A's address signed with the attacker's own key,
    // the attacker holding A's account code: the circuit accepts it against a
    // tree holding the attacker's key, and the guardian refuses that root.
    const signers = [{ ...gmailSigner, key: () => 'attacker', selector: () => 'attacker-2026' }];
    const { email } = A.recoveryEmail(a1.st.bytes, { rho: a1.rho, signers });
    const v = await circuitVerdict({ eml: email.eml, claimFrom: A.inbox.address, target: targetOf(A, a1.st, a1.rho), dnsRecords: email.dnsRecords });
    assert.equal(v.accepted, true);
    assert.equal(v.tree, 'planted');
    const p = await proveWitness(v.solved);
    a.a4 = await A.beginLostKey(A.payer, newOwner('A4'));
    const st4 = await A.statement(a.a4.attemptId);
    // Proved for a4's statement so that nothing but the root differs from an honest approval.
    const { email: e4 } = A.recoveryEmail(st4.bytes, { rho: a1.rho, signers });
    const v4 = await circuitVerdict({ eml: e4.eml, claimFrom: A.inbox.address, target: targetOf(A, st4, a1.rho), dnsRecords: e4.dnsRecords });
    const p4 = await proveWitness(v4.solved);
    const root = Buffer.from(p4.publicInputs.subarray(96, 128));
    const r = outcome(await A.submitEmail(A.payer, { attemptId: a.a4.attemptId, approval: { statement: st4.bytes, keyRoot: root, proof: p4.proof }, digest: st4.digest }));
    record('forged', 'forged-wrong-key', 1, 'refused: UnknownRoot', r.observed, r.layer, { note: 'a real proof under a key no registry or pin holds', proofBytes: p.proof.length });
  });

  scenario('forged-weak-key-registry', async () => {
    const r = await chain.attempt(stack.registry.member(0), Operation.invokeContractFunction({ contract: stack.registry.address, function: 'propose_add', args: [sc.address(stack.registry.member(0).publicKey()), sc.bytes(Buffer.from('gmail.com')), sc.bytes(Buffer.from(testKey('weak').modulus.toString(16).padStart(256, '0'), 'hex'))] }), { label: 'propose RSA-1024' });
    const o = outcome(r);
    record('forged', 'forged-weak-key-registry', 1, 'refused: KeyNotRsa2048', o.observed, o.layer, { note: 'a registry addition of a 1024-bit key' });
  });

  scenario('forged-misaligned-d-registry', async () => {
    const r = await chain.attempt(stack.registry.member(0), Operation.invokeContractFunction({ contract: stack.registry.address, function: 'propose_add', args: [sc.address(stack.registry.member(0).publicKey()), sc.bytes(Buffer.from('gmail-com.20260707.gappssmtp.com')), sc.bytes(Buffer.from(testKey('gappssmtp').modulus.toString(16).padStart(512, '0'), 'hex'))] }), { label: 'propose a gappssmtp key' });
    const o = outcome(r);
    record('forged', 'forged-misaligned-d-registry', 1, 'refused: DomainNotAllowed', o.observed, o.layer, { note: "a registry addition for Google's shared Workspace signing domain" });
  });

  scenario('forged-wrong-body-hash', async () => {
    // Accepted by design: the header signature is the provider's own and the proof does not bind the body (spec §4.4).
    const q = await Q.beginLostKey(Q.payer, newOwner('Q-body'));
    const r = await quirkOnChain(q, 'wrong-body-hash');
    record('forged', 'forged-wrong-body-hash', 1, 'accepted', r.observed, r.layer, { note: 'bh= of another body: counts one vote, as the provider signed the header block' });
  });
});

describe('stale or malicious registry keys', () => {
  scenario('registry-planted-key-in-timelock', async () => {
    const reg = stack.registry;
    const attacker = testKey('attacker');
    // A threshold of members colludes to add an attacker's key for gmail.com.
    const id = await reg.proposeAdd(0, 'gmail.com', attacker.modulus);
    await reg.approve(1, id);
    await reg.approve(2, id);
    // The honest attesters look it up and do not find it in DNS.
    const at = await closeTime(chain);
    const kh = Buffer.from(keyHash(attacker.modulus).toString(16).padStart(64, '0'), 'hex');
    for (const att of reg.attesters.slice(0, 2)) await reg.attest(id, att, att.observe({ registry: reg.address, domain: 'gmail.com', selector: 'attacker-2026', record: undefined, keyHashHex: kh.toString('hex'), observedAt: at }));
    const proposal = await reg.proposal(id);
    const eligible = await reg.eligibleAt(id);
    const approvedAt = Number(proposal.approved_at ?? proposal.approved);
    const exec = outcome(await chain.attempt(reg.submitter, Operation.invokeContractFunction({ contract: reg.address, function: 'execute', args: [sc.u32(id)] }), { label: 'execute planted key' }));
    record('registry', 'registry-planted-key-timelock', 1, 'refused: TimelockActive', exec.observed, exec.layer, { note: `not seen in DNS: the 72-hour path is closed, eligible at close time ${eligible} (approved at ${approvedAt}, +604,800 s)`, eligibleAt: Number(eligible), approvedAt });
    assert.equal(Number(eligible) - approvedAt, 604_800);
    // The attacker, holding A's address and account code, proves against the root the addition would produce.
    const leaf = registryLeaf('gmail.com', keyHash(attacker.modulus));
    // Its path: the current tree's siblings at the index the addition would take.
    const index = Number((await chain.read(reg.address, 'state')).next_index);
    const siblings = (await chain.read(reg.address, 'siblings', [sc.u32(index)])).map((b) => BigInt(`0x${Buffer.from(b).toString('hex')}`));
    const path = { root: merkleRoot(leaf, index, siblings), index, siblings };
    const signers = [{ ...gmailSigner, key: () => 'attacker', selector: () => 'attacker-2026' }];
    const st4 = await A.statement(a.a4.attemptId);
    const { rho, email } = A.recoveryEmail(st4.bytes, { signers });
    const p = await A.prove({ eml: email.eml, rho, statementBytes: st4.bytes, keyPath: path, modulus: attacker.modulus });
    const r = outcome(await A.submitEmail(A.payer, { attemptId: a.a4.attemptId, approval: approvalOf(st4, p), digest: st4.digest }));
    record('registry', 'registry-planted-key-proof', 1, 'refused: UnknownRoot', r.observed, r.layer, { note: 'a real proof against the root the planted addition would produce, during its timelock' });
    // Two honest members revoke the pending key; the addition can never execute.
    const rid = await reg.proposeRevoke(3, 'gmail.com', kh);
    await reg.approve(4, rid);
    const after = outcome(await chain.attempt(reg.submitter, Operation.invokeContractFunction({ contract: reg.address, function: 'execute', args: [sc.u32(id)] }), { label: 'execute revoked planted key' }));
    record('registry', 'registry-planted-key-revoked', 1, 'refused: KeyRevoked', after.observed, after.layer, { note: 'revoke_threshold (2) members stop the pending addition' });
  });

  scenario('registry-pin-expiry', async () => {
    // Within the pin's window an approval counts; after it, the pin root is refused and the registry has not admitted the key.
    P = await enroll({ chain, stack, apex: APEX, label: 'P', inbox: new Inbox('p.pinned@gmail.com'), key: gmail, helpers: 1, quorum: 2, delayLedgers: 20, expiryLedgers: 2_000, pinSeconds: 90 });
    roles.set(P.guardian, 'guardian');
    roles.set(P.account.address, 'account');
    const p1 = await P.beginLostKey(P.payer, newOwner('P1'));
    const h1 = await honest(P, p1.attemptId);
    const before = outcome(await P.submitEmail(P.payer, { attemptId: p1.attemptId, approval: h1.approval, digest: h1.st.digest }));
    assert.ok((await chain.closeTime()) <= P.pinValidUntil, 'the first approval landed inside the pin window');
    record('registry', 'registry-pin-live', 1, 'accepted', before.observed, before.layer, { note: `pin valid until close time ${P.pinValidUntil}` });
    const p2 = await P.beginLostKey(P.payer, newOwner('P2'));
    const h2 = await honest(P, p2.attemptId);
    await chain.untilCloseTime(P.pinValidUntil + 1);
    const r = outcome(await P.submitEmail(P.payer, { attemptId: p2.attemptId, approval: h2.approval, digest: h2.st.digest }));
    record('registry', 'registry-pin-expiry', 1, 'refused: UnknownRoot', r.observed, r.layer, { note: 'proved inside the pin window, submitted after it; the registry still holds the key only as a pending addition' });
  });
});

describe('compromised inbox', () => {
  scenario('inbox-without-account-code', async () => {
    // The attacker sends from the inbox (the provider signs) but holds no account code.
    const st3 = await A.statement(a.a3.attemptId);
    const { rho, email } = A.recoveryEmail(st3.bytes);
    const guess = 0x1234n;
    const v = await circuitVerdict({ eml: email.eml, claimFrom: A.inbox.address, target: { ...targetOf(A, st3, rho, guess), commitment: A.inbox.commitment } });
    record('inbox', 'inbox-without-account-code', 4, 'refused: recovery: the From address does not open the commitment', v.accepted ? 'accepted' : `refused: ${v.reason}`, 'circuit', { note: "a provider-signed email from A's inbox for the attacker's attempt, A's commitment, a guessed account code" });
    // What the attacker can prove: the same email under its own guess, against a tree it builds; the pin's path needs the code.
    const own = await circuitVerdict({ eml: email.eml, claimFrom: A.inbox.address, target: { ...targetOf(A, st3, rho, guess), pinLeaves: [] } });
    assert.equal(own.accepted, true);
    const p = await proveWitness(own.solved);
    const r = outcome(await A.submitEmail(A.payer, { attemptId: a.a3.attemptId, approval: { statement: st3.bytes, keyRoot: Buffer.from(p.publicInputs.subarray(96, 128)), proof: p.proof }, digest: st3.digest }));
    record('inbox', 'inbox-without-account-code-proof', 4, 'refused: UnknownRoot', r.observed, r.layer, { note: "the attacker's real proof for its own guess; without the code it cannot build the salted pin's path, and the registry has no accepted root yet" });
    // The code's backup in the enrollment email opens only with its passphrase.
    const accountId = perch.contractId(A.account.address);
    const block = await encryptBackup(Buffer.from(A.inbox.accountCode.toString(16).padStart(32, '0'), 'hex'), generatePassphrase(), accountId);
    let opened = 'accepted';
    try {
      await decryptBackup(block, generatePassphrase(), accountId);
    } catch (e) {
      opened = `refused: ${e.name}`;
    }
    record('inbox', 'inbox-backup-without-passphrase', 4, 'refused: BackupError', opened, 'account code backup (Argon2id, AES-256-GCM)', { note: 'the backup block in the Sent folder, opened with another passphrase' });
  });

  scenario('inbox-with-account-code-quorum', async () => {
    // Worst case: the attacker also holds the account code. One vote of a 2-of-3 quorum.
    const st3 = await A.statement(a.a3.attemptId);
    const { rho, email } = A.recoveryEmail(st3.bytes);
    const p = await A.prove({ eml: email.eml, rho, statementBytes: st3.bytes });
    const vote = outcome(await A.submitEmail(A.payer, { attemptId: a.a3.attemptId, approval: approvalOf(st3, p), digest: st3.digest }));
    assert.equal(vote.observed, 'accepted');
    const att = await A.attempt(a.a3.attemptId);
    assert.equal(att.state.tag, 'Collecting');
    const r = outcome(await A.complete(A.payer, a.a3.replacements));
    record('inbox', 'inbox-with-code-quorum', 4, 'refused: AttemptNotLive', r.observed, r.layer, { note: `the email vote counted (attempt still ${att.state.tag}, ${att.guardians.length} of 2 votes); completion refused: no authorized attempt` });
  });

  scenario('inbox-email-plus-delay', async () => {
    // The lost-key profile with email plus delay, with the weakest alert setup the wallet allows: alerts to the
    // enrolled inbox itself (enrollment warns, it does not block). The thief holds the inbox and the account code and
    // deletes everything sent to that inbox, so only the push to the owner's passkey device reaches the owner.
    const inbox = L.inbox.address;
    const reg = await alerts.register(L, inbox);
    assert.equal(reg.confirmed.status ?? reg.confirmed.result?.status, 'confirmed');
    await alerts.drain();
    Alerts.pushes(reg.device);
    const l1 = await L.beginLostKey(L.payer, newOwner('L-attacker'));
    const h = await honest(L, l1.attemptId);
    const vote = outcome(await L.submitEmail(L.payer, { attemptId: l1.attemptId, approval: h.approval, digest: h.st.digest, label: 'submit_guardian (email, authorizes)' }));
    const att = await L.attempt(l1.attemptId);
    record('inbox', 'inbox-email-plus-delay-authorizes', 4, 'accepted', vote.observed, '—', { note: `quorum 1, delay 120,960 ledgers: the attempt is ${att.state.tag}, executable after ledger ${att.executable_after}` });
    assert.equal(att.state.tag, 'Authorized');
    const early = outcome(await L.complete(L.payer, l1.replacements));
    record('inbox', 'inbox-email-plus-delay-completion', 4, 'refused: NotExecutableYet', early.observed, early.layer, { note: 'completion inside the delay' });
    await alerts.drain();
    const code = await alerts.attemptCode(L, reg.accountCode, l1.attemptId);
    const sent = alerts.sentTo(inbox).filter((m) => m.text?.includes(`${code.slice(0, 3)} ${code.slice(3)}`)).length;
    const emails = alerts.reaching(inbox, { thiefControls: [inbox] }).length;
    const pushed = Alerts.pushes(reg.device).filter((x) => x.kind === 'attempt_authorized' && x.code === code && x.body.startsWith(PASSKEY_DEVICE_LEAD));
    const reached = emails && pushed.length ? 'email and push' : pushed.length ? 'push only' : emails ? 'email only' : 'nothing';
    record('inbox', 'inbox-email-plus-delay-alerts', 4, 'owner alerted: push only', `owner alerted: ${reached}`, 'alert path', {
      note: `attempt_authorized: ${sent} email to the enrolled inbox, deleted by the thief; the push carries the code ${code.slice(0, 3)} ${code.slice(3)} and leads with cancelling`,
    });
    // The mechanism: a cancellation by the owner's passkey within the delay succeeds (here on the push alone).
    const cancel = await L.ownerCancel(L.payer, l1.attemptId);
    record('inbox', 'inbox-email-plus-delay-owner-cancels', 4, 'accepted', cancel.ok ? 'accepted' : `refused: ${layerOf(cancel.refused, roles).error}`, cancel.ok ? '—' : layerOf(cancel.refused, roles).layer, { note: "the owner's passkey cancels within the delay" });
    const late = outcome(await L.complete(L.payer, l1.replacements));
    record('inbox', 'inbox-email-plus-delay-cancelled', 4, 'refused: AttemptNotLive', late.observed, late.layer, { note: 'completion of the cancelled attempt' });
    const l2 = await L.beginLostKey(L.payer, newOwner('L-attacker-2'));
    const st2 = await L.statement(l2.attemptId);
    const again = outcome(await L.submitEmail(L.payer, { attemptId: l2.attemptId, approval: h.approval, digest: st2.digest }));
    record('inbox', 'inbox-email-plus-delay-new-attempt', 4, 'refused: DigestMismatch', again.observed, again.layer, { note: 'a new attempt needs a new email' });
  });

  scenario('inbox-email-vote-alerted', async () => {
    // Email plus a helper, 2 of 2: the thief's email vote alone leaves the attempt collecting. Perch emits no
    // event for it; the alert service reads the watched attempt and alerts every channel.
    const contact = 'v.alerts@posteo.de';
    const reg = await alerts.register(V, contact);
    await alerts.drain();
    Alerts.pushes(reg.device);
    const v1 = await V.beginLostKey(V.payer, newOwner('V-thief'));
    await alerts.drain();
    const h = await honest(V, v1.attemptId);
    const vote = outcome(await V.submitEmail(V.payer, { attemptId: v1.attemptId, approval: h.approval, digest: h.st.digest }));
    assert.equal(vote.observed, 'accepted');
    assert.equal((await V.attempt(v1.attemptId)).state.tag, 'Collecting');
    const reports = await alerts.drain();
    const code = await alerts.attemptCode(V, reg.accountCode, v1.attemptId);
    const emails = alerts.reaching(contact).filter((m) => /your email approved a recovery/.test(m.subject) && m.text?.includes(`${code.slice(0, 3)} ${code.slice(3)}`)).length;
    const pushed = Alerts.pushes(reg.device).filter((x) => x.kind === 'email_vote_recorded' && x.code === code).length;
    const latency = reports.map((r) => r.latencyMs[`email_vote_recorded:${V.account.address}:${v1.attemptId}`]).find((x) => x !== undefined);
    record('inbox', 'inbox-email-vote-alerted', 4, 'alerted: email and push', emails && pushed ? 'alerted: email and push' : `alerted: ${emails} email, ${pushed} push`, 'alert path', {
      note: `the email vote recorded below quorum (attempt Collecting, 1 of 2): read from the watched attempt, alerted in ${latency?.toFixed(0)} ms after the read`,
      latencyMs: latency,
    });
    const cancel = await V.ownerCancel(V.payer, v1.attemptId);
    record('inbox', 'inbox-email-vote-owner-cancels', 4, 'accepted', cancel.ok ? 'accepted' : `refused: ${layerOf(cancel.refused, roles).error}`, '—', { note: "the owner's passkey cancels the collecting attempt" });
  });
});

describe('alert path', () => {
  scenario('alerts-watcher-outage', async () => {
    // The watcher is down while the thief authorizes an attempt, and restarts after those events left the RPC's
    // retention (modelled by a host that starts reading after them; the vault keeps its sealed records).
    const contact = 'o.alerts@posteo.de';
    const reg = await alerts.register(O, contact);
    await alerts.drain();
    Alerts.pushes(reg.device);
    const o1 = await O.beginLostKey(O.payer, newOwner('O-thief'));
    const h = await honest(O, o1.attemptId);
    assert.equal(outcome(await O.submitEmail(O.payer, { attemptId: o1.attemptId, approval: h.approval, digest: h.st.digest, label: ALERT_VOTE })).observed, 'accepted');
    assert.equal((await O.attempt(o1.attemptId)).state.tag, 'Authorized');
    const reports = await alerts.restartAfterOutage(await chain.ledger());
    const code = await alerts.attemptCode(O, reg.accountCode, o1.attemptId);
    const emails = alerts.reaching(contact).filter((m) => /approved/.test(m.subject) && m.text?.includes(`${code.slice(0, 3)} ${code.slice(3)}`)).length;
    const pushed = Alerts.pushes(reg.device).filter((x) => x.kind === 'attempt_authorized' && x.code === code).length;
    const reconciled = reports.find((r) => r.reconciled);
    record('alerts', 'alerts-watcher-outage', 4, 'alerted after the restart: email and push', emails && pushed ? 'alerted after the restart: email and push' : `alerted after the restart: ${emails} email, ${pushed} push`, 'alert path (reconciliation)', {
      note: `attempt_authorized never read from the event stream; reconciliation from the controller's state found it (${reconciled?.reconciled.accounts} accounts read, ${reconciled?.reconciled.found} ${reconciled?.reconciled.found === 1 ? 'alert' : 'alerts'} found)`,
    });
    await O.ownerCancel(O.payer, o1.attemptId);
  });

  scenario('alerts-lapsed-push', async () => {
    // The residual risk: alerts to the enrolled inbox (the thief deletes them) and a push subscription that
    // expired. The vault finds it gone and emails the same inbox. Nothing reaches the owner.
    const inbox = L2.inbox.address;
    const reg = await alerts.register(L2, inbox);
    await alerts.drain();
    alerts.push.expire(reg.device.endpoint);
    const x = await L2.beginLostKey(L2.payer, newOwner('L2-thief'));
    const h = await honest(L2, x.attemptId);
    assert.equal(outcome(await L2.submitEmail(L2.payer, { attemptId: x.attemptId, approval: h.approval, digest: h.st.digest, label: ALERT_VOTE })).observed, 'accepted');
    await alerts.drain();
    const emails = alerts.reaching(inbox, { thiefControls: [inbox] }).length;
    const pushed = Alerts.pushes(reg.device).filter((p) => p.kind === 'attempt_authorized').length;
    const notice = alerts.sentTo(inbox).some((m) => /notifications stopped/.test(m.subject));
    record('alerts', 'alerts-lapsed-push', 4, 'owner alerted: nothing', emails || pushed ? `owner alerted: ${emails} email, ${pushed} push` : 'owner alerted: nothing', 'alert path', {
      note: `residual risk: the push service answers 404 for the expired subscription, the vault marks it lapsed${notice ? ' and emails the enrolled inbox' : ''}, which the thief deletes; unless the owner opens the wallet, the attempt completes after the delay`,
    });
    const gate = await L2.client.activityGate(L2.account.address);
    const shown = gate.authorized_attempt != null && BigInt(gate.authorized_attempt) === x.attemptId;
    record('alerts', 'alerts-lapsed-push-wallet-reads', 4, 'the controller names the attempt', shown ? 'the controller names the attempt' : 'not found', '—', {
      note: "what a wallet opened during the delay reads, independent of alerts (its activity gate's authorized attempt), and offers to cancel",
    });
    await L2.ownerCancel(L2.payer, x.attemptId);
  });
});

describe('phishing and social engineering', () => {
  scenario('social-phished-holds-passkey', async () => {
    // A phisher opens a lost-key attempt for its own new key, as the real recovery page would on its own device,
    // collects the victim's recovery code, and talks the victim into sending the Subject it shows from the victim's
    // own inbox. The victim still holds the passkey.
    const contact = 's1.alerts@posteo.de';
    const reg = await alerts.register(S1, contact);
    await alerts.drain();
    Alerts.pushes(reg.device);
    const s = await S1.beginLostKey(S1.payer, newOwner('S1-phisher'));
    const h = await honest(S1, s.attemptId);
    const vote = outcome(await S1.submitEmail(S1.payer, { attemptId: s.attemptId, approval: h.approval, digest: h.st.digest, label: ALERT_VOTE }));
    record('social', 'social-phished-email-counts', 1, 'accepted', vote.observed, '—', { note: "the victim's own email for the phisher's statement is a valid approval: the proof binds the statement, not the sender's intent" });
    await alerts.drain();
    const code = await alerts.attemptCode(S1, reg.accountCode, s.attemptId);
    const push = Alerts.pushes(reg.device).find((x) => x.kind === 'attempt_authorized' && x.code === code);
    const mail = alerts.reaching(contact).find((m) => /approved/.test(m.subject));
    const leads = push?.body.startsWith(PASSKEY_DEVICE_LEAD) && mail?.text?.includes(NEVER_ASKS);
    record('social', 'social-phished-alerts-say-cancel', 4, 'push leads with cancelling; email says Nido never asks', leads ? 'push leads with cancelling; email says Nido never asks' : 'copy missing', 'alert path', {
      note: `push: "${PASSKEY_DEVICE_LEAD}"`,
    });
    const cancel = await S1.ownerCancel(S1.payer, s.attemptId);
    record('social', 'social-phished-owner-cancels', 4, 'accepted', cancel.ok ? 'accepted' : `refused: ${layerOf(cancel.refused, roles).error}`, '—', { note: "the victim's passkey cancels within the delay" });
    const late = outcome(await S1.complete(S1.payer, s.replacements));
    record('social', 'social-phished-cancelled', 4, 'refused: AttemptNotLive', late.observed, late.layer, { note: "the phisher's completion of the cancelled attempt" });
  });

  scenario('social-phished-lost-devices', async () => {
    // The same phishing of a victim who has lost every device: nobody cancels.
    const s = await S2.beginLostKey(S2.payer, newOwner('S2-phisher'));
    const h = await honest(S2, s.attemptId);
    assert.equal(outcome(await S2.submitEmail(S2.payer, { attemptId: s.attemptId, approval: h.approval, digest: h.st.digest, label: ALERT_VOTE })).observed, 'accepted');
    const att = await S2.attempt(s.attemptId);
    await chain.untilLedger(Number(att.executable_after));
    const done = outcome(await S2.complete(S2.payer, s.replacements));
    record('social', 'social-lost-devices-email-plus-delay', 4, 'accepted', done.observed, '—', {
      note: "residual risk: email plus delay with nobody to cancel completes after the delay, installing the phisher's key (the delay is 20 ledgers here, outside the wallet's policy, so it elapses within the run; the wallet requires 120,960)",
    });
    const t = await S3.beginLostKey(S3.payer, newOwner('S3-phisher'));
    const h3 = await honest(S3, t.attemptId);
    assert.equal(outcome(await S3.submitEmail(S3.payer, { attemptId: t.attemptId, approval: h3.approval, digest: h3.st.digest })).observed, 'accepted');
    const blocked = outcome(await S3.complete(S3.payer, t.replacements));
    record('social', 'social-lost-devices-second-helper', 4, 'refused: AttemptNotLive', blocked.observed, blocked.layer, { note: 'with a second helper required, the phished email vote leaves the attempt collecting and it cannot complete' });
  });
});

describe('repeated attempts', () => {
  scenario('griefing-repeated-attempts', async () => {
    // Anyone may open attempts, at a transaction fee each. What the owner receives for ten of them.
    const contact = 'g.alerts@posteo.de';
    const reg = await alerts.register(G, contact);
    await alerts.drain();
    Alerts.pushes(reg.device);
    const before = alerts.reaching(contact).length;
    const griefer = await chain.funded(Keypair.random());
    for (let i = 0; i < 10; i++) await G.beginLostKey(griefer, newOwner(`G-grief-${i}`), `begin_lost_key (griefing ${i + 1})`);
    await alerts.drain();
    const emails = alerts.reaching(contact).length - before;
    const pushes = Alerts.pushes(reg.device).length;
    const next = await G.client.nextAttemptId(G.account.address);
    let open = 0;
    for (let id = 0n; id < next; id++) if ((await G.attempt(id))?.state.tag === 'Collecting') open++;
    record('griefing', 'griefing-repeated-attempts', 4, 'owner receives: 0 emails, 0 pushes; the wallet lists 10 open attempts', `owner receives: ${emails} emails, ${pushes} pushes; the wallet lists ${open} open attempts`, 'alert path', {
      note: 'attempt_begun alerts nothing by default (the vault only watches each attempt for an email vote); the wallet shows open attempts from the controller, each granting nothing',
    });
  });
});

describe('provider header quirks', () => {
  scenario('quirks-each-provider', async () => {
    const per = {};
    for (const d of LAUNCH_DOMAINS) {
      const e = providers[d];
      const at = await e.beginLostKey(e.payer, newOwner(`provider-${d}`));
      const h = await honest(e, at.attemptId);
      const r = outcome(await e.submitEmail(e.payer, { attemptId: at.attemptId, approval: h.approval, digest: h.st.digest, label: `submit_guardian (email, ${d})` }));
      per[d] = { observed: r.observed, hash: r.hash, witnessMs: h.p.witnessMs, proveMs: h.p.proveMs, signatures: h.email.signatures.length };
    }
    const accepted = Object.values(per).filter((x) => x.observed === 'accepted').length;
    record('quirks', 'quirks-each-provider', 1, `accepted: ${LAUNCH_DOMAINS.length} of ${LAUNCH_DOMAINS.length}`, `accepted: ${accepted} of ${LAUNCH_DOMAINS.length}`, '—', { perDomain: per, note: "each launch domain's recovery email in its provider's format counts one vote" });
  });

  scenario('quirks-folded-subject', async () => {
    const q = await Q.beginLostKey(Q.payer, newOwner('Q-folded'));
    const r = await quirkOnChain(q, 'subject-folded-at-space');
    record('quirks', 'quirks-folded-subject', 1, 'accepted', r.observed, r.layer, { note: 'a Subject folded at a space counts one vote' });
  });

  scenario('quirks-whitespace-subject', async () => {
    const q = await Q.beginLostKey(Q.payer, newOwner('Q-space'));
    const r = await quirkOnChain(q, 'subject-extra-whitespace');
    record('quirks', 'quirks-whitespace-subject', 1, 'accepted', r.observed, r.layer, { note: 'runs of spaces and tabs in the Subject count one vote' });
  });
});

describe('front-running', () => {
  scenario('front-running-copy-first', async () => {
    const own = await A.beginLostKey(A.payer, newOwner('A5'));
    const h = await honest(A, own.attemptId);
    // An observer copies the approval and submits it first, in an entry and a transaction of its own.
    const observer = await chain.funded(Keypair.random());
    const first = outcome(await A.submitEmail(observer, { attemptId: own.attemptId, approval: h.approval, digest: h.st.digest, label: 'observer submits the copy first' }));
    assert.equal(first.observed, 'accepted');
    const att = await A.attempt(own.attemptId);
    assert.deepEqual(att.guardians, [A.guardian]);
    const mine = outcome(await A.submitEmail(A.payer, { attemptId: own.attemptId, approval: h.approval, digest: h.st.digest }));
    record('front-running', 'front-running-copy-first', 3, 'refused: AlreadyCounted', mine.observed, mine.layer, { note: "the observer's copy recorded the guardian's single vote for the same attempt; the owner's own submission adds nothing" });
    a.a5 = { ...own, h };
  });

  scenario('front-running-redirect', async () => {
    const { h } = a.a5;
    const cancelSt = await A.statement(a.a5.attemptId, EvidenceDomain.Cancel);
    const asCancel = outcome(await A.submitEmail(A.payer, { attemptId: a.a5.attemptId, domain: EvidenceDomain.Cancel, approval: h.approval, digest: cancelSt.digest }));
    record('front-running', 'front-running-redirect-cancel', 3, 'refused: DigestMismatch', asCancel.observed, asCancel.layer, { note: 'the copy as a cancellation of the same attempt' });
    const other = await A.beginLostKey(A.payer, newOwner('attacker-2'));
    const sto = await A.statement(other.attemptId);
    const toAttacker = outcome(await A.submitEmail(A.payer, { attemptId: other.attemptId, approval: h.approval, digest: sto.digest }));
    record('front-running', 'front-running-redirect-attempt', 3, 'refused: DigestMismatch', toAttacker.observed, toAttacker.layer, { note: "the copy for an attacker's new attempt on the same account" });
    const b2 = await B.beginLostKey(B.payer, newOwner('B2'));
    const stb = await B.statement(b2.attemptId);
    const toB = outcome(await B.submitEmail(B.payer, { attemptId: b2.attemptId, approval: h.approval, digest: stb.digest }));
    record('front-running', 'front-running-redirect-account', 3, 'refused: DigestMismatch', toB.observed, toB.layer, { note: 'the copy for a new attempt on another account with the same address' });
  });
});

describe('privacy on chain', () => {
  scenario('privacy-no-address-on-chain', async () => {
    // A sanity check behind the privacy property, not evidence of hiding: every transaction the run sent, read
    // back from the network, searched for each inbox's address and account code in the renderings a leak could take.
    const inboxes = [A, B, E, P, Q, L, V, S1, S2, S3, G, O, L2, ...Object.values(providers)].map((e) => ({ inbox: e.inbox, pin: e.pin }));
    const renderings = (b) => [b, Buffer.from(b.toString('hex')), Buffer.from(b.toString('hex').toUpperCase()), Buffer.from(b.toString('base64')), Buffer.from(b.toString('base64url'))];
    const needles = inboxes.flatMap(({ inbox, pin }) => {
      const addr = Buffer.from(inbox.address);
      // pack(addr, 124): 31-byte chunks, each a field element in its own 32-byte word.
      const padded = Buffer.concat([addr, Buffer.alloc(124 - addr.length)]);
      const limbs = [0, 1, 2, 3].map((i) => padded.subarray(i * 31, i * 31 + 31)).filter((l) => l.some((x) => x !== 0)).map((l) => Buffer.concat([Buffer.alloc(1), l]));
      const code = Buffer.from(inbox.accountCode.toString(16).padStart(32, '0'), 'hex');
      const salt = Buffer.from(pin.leaves[0].toString(16).padStart(64, '0'), 'hex');
      return [
        ...renderings(addr),
        Buffer.from(inbox.address.toLowerCase()),
        Buffer.from(inbox.address.toUpperCase()),
        ...limbs.flatMap(renderings),
        ...renderings(code),
        ...renderings(salt),
      ];
    });
    let carrying = 0;
    for (const t of chain.log) {
      const got = await chain.call('getTransaction', { hash: t.hash });
      const xdrs = [got.envelopeXdr, got.resultXdr, got.resultMetaXdr].filter(Boolean);
      const bytes = Buffer.concat([...xdrs.map((x) => Buffer.from(x, 'base64')), ...xdrs.map((x) => Buffer.from(x))]);
      if (needles.some((n) => bytes.includes(n))) carrying++;
    }
    record('privacy', 'privacy-no-address-on-chain', 2, `none of ${chain.log.length}`, `${carrying ? carrying : 'none'} of ${chain.log.length}`, '—', {
      note: `a sanity check, not evidence of hiding: envelopes, results and metadata of every transaction of the run, decoded and as base64, searched for each of ${inboxes.length} inboxes' address (raw, lower and upper case, hex, base64), its packed 31-byte limbs as field words, its account code and its pin's salt leaf`,
    });
  });
});

/** Build the mocks' case `id` for Q's attempt `q`, prove it with the strongest witness, submit it. */
async function quirkOnChain(q, id) {
  const st = await Q.statement(q.attemptId);
  const rho = 0x0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0dn + q.attemptId;
  const v0 = value(st.digest, rho);
  const c = buildAttacks({ victim: Q.inbox.address, attacker: 'attacker@gmail.com', phrase: PHRASE, subject: `${PHRASE} ${v0}`, recoveryValue: v0, otherRecoveryValue: v0.replace(/^./, (x) => (x === '0' ? '1' : '0')), account: 'q', otherAccount: 'other', body: 'This message is a test fixture.\r\n' }).find((x) => x.id === id);
  const v = await circuitVerdict({ eml: c.email.eml, claimFrom: c.claim.from, target: targetOf(Q, st, rho), dnsRecords: c.email.dnsRecords });
  if (!v.accepted) return { observed: `refused: ${v.reason}`, layer: 'circuit' };
  const p = await proveWitness(v.solved);
  return outcome(await Q.submitEmail(Q.payer, { attemptId: q.attemptId, approval: { statement: st.bytes, keyRoot: Buffer.from(p.publicInputs.subarray(96, 128)), proof: p.proof }, digest: st.digest, label: `submit_guardian (email, ${id})` }));
}

/** The outcomes `packages/email-recovery/test/attacks.test.ts` pins for each case. */
function pinnedOutcomes() {
  const src = readFileSync(`${repo}packages/email-recovery/test/attacks.test.ts`, 'utf8');
  const out = {};
  for (const m of src.matchAll(/'([a-z0-9-]+)': \{ tree: '(\w+)', outcome: '([^']+)' \}/g)) out[m[1]] = m[3];
  return out;
}

