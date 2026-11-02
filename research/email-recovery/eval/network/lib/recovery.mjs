// An account enrolled in email recovery, as Nido's wallet enrolls it
// (docs/email-recovery/spec.md §5.4): its email guardian deployed with the
// commitment and a key pin, then a document whose recovery member lists the
// guardian, built by the wallet's own `recoverySpec` (so the wallet's rules
// of §9.3 apply), applied by the owner's passkey. And the recovery side:
// opening an attempt, the statement the controller builds for it, email and
// helper approvals, the owner's cancellation, completion.
import { PIN_LIFETIME_SECONDS } from '@nidohq/email-recovery';
import { buildPolicyDoc, canonicalJson, perch } from '@nidohq/passkey-sdk';
import { Keypair } from '@stellar/stellar-sdk';
import { NidoAccount, Passkey } from './account.mjs';
import { ALLOW_ALL, Inbox, approvalEntry, approve, deployGuardian, freshRho, pinFor, subjectFor, submitGuardianOp } from './email.mjs';

export const { EvidenceDomain } = perch;

/** The document the wallet applies: the owner passkey as admin, and `recovery`. */
export function documentFor({ network, verifier, owner, recovery }) {
  const base = buildPolicyDoc({
    network,
    signers: [{ id: 'admin', kind: 'passkey', verifier, publicKey: Buffer.from(owner.publicKey).toString('hex') }],
    permissions: [{ name: 'admin', on: 'self-admin', by: ['admin'] }],
  });
  return recovery ? perch.withRecovery(base, recovery) : base;
}

export class Enrolled {
  constructor(o) {
    Object.assign(this, o);
    this.client = new perch.PerchRecovery({ deployment: o.deployment, rpcUrl: o.chain.rpcUrl });
  }

  /** The key path an email signed by `key` is proven with: the pin's. */
  pinPath(index = 0) {
    return this.pin.path(index);
  }

  /** Open a lost-key attempt that installs `newOwner` (permissionless). */
  async beginLostKey(payer, newOwner, label = 'begin_lost_key') {
    const replacements = { signers: [{ signerId: 'admin', credential: { kind: 'external', verifier: this.verifier, key: newOwner.publicKey } }] };
    const build = await this.client.beginLostKey(this.account.address, replacements);
    const r = await this.chain.send(payer, build.operations[0], { label });
    return { attemptId: BigInt(r.value), replacements, tx: r };
  }

  /** The statement the controller builds for `attemptId` in `domain`, and its encoding. */
  async statement(attemptId, domain = EvidenceDomain.Initiate) {
    const s = await this.client.statement(this.account.address, attemptId, domain);
    return { statement: s, bytes: perch.encodeStatement(s), digest: perch.statementDigest(s) };
  }

  /** The recovery email for `statementBytes`, from the enrolled inbox, and its `rho`. */
  recoveryEmail(statementBytes, opts = {}) {
    const rho = opts.rho ?? freshRho();
    return { rho, email: this.inbox.send(opts.subject ?? subjectFor(statementBytes, rho), opts) };
  }

  /** Prove `eml` for `statementBytes` against the pin (or `keyPath`). */
  prove({ eml, rho, statementBytes, keyPath = this.pinPath(), modulus = this.key.modulus, accountCode }) {
    return approve({ eml, inbox: this.inbox, rho, statement: statementBytes, modulus, keyPath, accountCode });
  }

  /** `submit_guardian` for the email guardian carrying `approval` (`{statement, keyRoot, proof}`), as the wallet submits it. */
  async submitEmail(payer, { attemptId, domain = EvidenceDomain.Initiate, approval, digest, guardian = this.guardian, label = 'submit_guardian (email)', nonce }) {
    const entry = approvalEntry({ guardian, controller: this.controller, digest, approval, expirationLedger: (await this.chain.ledger()) + 1_000, nonce });
    const op = submitGuardianOp({ controller: this.controller, account: this.account.address, attemptId, domain, guardian, entry });
    return this.chain.attempt(payer, op, { authMode: 'enforce', label });
  }

  /** A helper's (`G…`) approval, signed as the transaction's source. */
  submitHelper(helper, attemptId, domain = EvidenceDomain.Initiate, label = 'submit_guardian (helper)') {
    const op = submitGuardianOp({ controller: this.controller, account: this.account.address, attemptId, domain, guardian: helper.publicKey() });
    return this.chain.attempt(helper, op, { label });
  }

  attempt(attemptId) {
    return this.client.attempt(this.account.address, attemptId);
  }

  /** The completing `apply_doc` (anyone, through the recovery rule). */
  async complete(payer, replacements, label = 'complete (apply_doc)') {
    const { target, selection } = await this.client.prepareCompletion(this.account.address, 'lost-key', replacements);
    const build = await this.client.completion(this.account.address, target, selection, await this.chain.ledger());
    return this.chain.attempt(payer, build.operations[0], { authMode: 'enforce', label });
  }

  async ownerCancel(payer, attemptId) {
    try {
      return { ok: true, ...(await this.account.cancelRecovery(payer, attemptId)) };
    } catch (e) {
      if (e.stage) return { ok: false, refused: e };
      throw e;
    }
  }
}

/** An enrolled account as JSON (its TEST-ONLY keys included), to resume a run that waits on the network. */
export function enrolledJson(e) {
  return {
    label: e.label,
    inbox: { address: e.inbox.address, displayName: e.inbox.displayName, accountCode: e.inbox.accountCode.toString() },
    key: e.key.domain,
    owner: e.owner.label,
    account: e.account.address,
    apex: e.apex,
    guardian: e.guardian,
    helpers: e.helpers.map((h) => h.secret()),
    payer: e.payer.secret(),
    pinValidUntil: e.pinValidUntil ?? null,
  };
}

/** `enrolledJson`'s account on `chain`, with `keys` (launchKeys()) for its provider key. */
export function enrolledFromJson({ chain, stack, keys }, j) {
  const d = stack.deployment;
  const inbox = new Inbox(j.inbox.address, { displayName: j.inbox.displayName, accountCode: BigInt(j.inbox.accountCode) });
  const key = keys.find((k) => k.domain === j.key);
  const owner = new Passkey(j.owner);
  return new Enrolled({
    chain,
    deployment: d,
    label: j.label,
    inbox,
    key,
    pin: pinFor(inbox.accountCode, [key]),
    pinValidUntil: j.pinValidUntil ?? undefined,
    account: new NidoAccount({ chain, address: j.account, owner, verifier: d.webauthnVerifier, apex: j.apex }),
    apex: j.apex,
    owner,
    guardian: j.guardian,
    helpers: j.helpers.map((s) => Keypair.fromSecret(s)),
    payer: Keypair.fromSecret(j.payer),
    controller: d.recoveryController,
    verifier: d.webauthnVerifier,
  });
}

/**
 * Mint an account, deploy its email guardian for `inbox` (pinning `key`
 * for `pinSeconds` of ledger close time), and enroll recovery: `helpers` more guardians (funded
 * `G…` accounts), `quorum`, `profile`, timing. `walletPolicy: false` lists
 * the guardian as a plain address, so the wallet's email rules (spec §9.3)
 * do not apply: a configuration the chain accepts and Nido's wallet refuses.
 */
export async function enroll({
  chain,
  stack,
  label,
  inbox,
  key,
  helpers = 0,
  quorum = 1,
  profile = 'loss',
  delayLedgers,
  expiryLedgers,
  pinSeconds = PIN_LIFETIME_SECONDS,
  allowedActions = ALLOW_ALL,
  registry = stack.registry.address,
  apex = { scheme: 'http:', host: 'localhost', port: 4399 },
  payer,
  walletPolicy = true,
}) {
  const d = stack.deployment;
  payer ??= await chain.funded(Keypair.random());
  const owner = new Passkey(`${label}/owner/${Date.now()}`);
  const account = await NidoAccount.mint({ chain, factory: d.factory, payer, owner, verifier: d.webauthnVerifier, apex, label });
  const pin = pinFor(inbox.accountCode, [key]);
  const deployedAt = await chain.closeTime();
  const guardian = await deployGuardian(
    chain,
    payer,
    stack.email.guardianWasmHash,
    {
      account: account.address,
      controller: d.recoveryController,
      commitment: inbox.commitment,
      registry,
      pin: pinSeconds === null ? undefined : { root: pin.root, validUntil: deployedAt + pinSeconds },
      allowedActions,
      verifier: stack.email.verifier,
    },
    label,
  );
  const helperKeys = [];
  for (let i = 0; i < helpers; i++) helperKeys.push(await chain.funded(Keypair.random()));
  const recovery = perch.recoverySpec(d, {
    profile,
    mode: 'guardian-only',
    guardians: [walletPolicy ? { kind: 'email', address: guardian, allowedActions } : guardian, ...helperKeys.map((h) => h.publicKey())],
    quorum,
    secondAlertChannel: walletPolicy ? 'web-push' : undefined,
    replaceable: ['admin'],
    delayLedgers,
    expiryLedgers,
    ledgerCloseMs: await chain.targetCloseMs(),
  });
  const doc = documentFor({ network: chain.passphrase, verifier: d.webauthnVerifier, owner, recovery });
  await account.applyDoc(payer, canonicalJson(doc), `apply_doc ${label}`);
  return new Enrolled({
    chain,
    deployment: d,
    label,
    inbox,
    key,
    pin,
    pinValidUntil: pinSeconds === null ? undefined : deployedAt + pinSeconds,
    account,
    apex,
    owner,
    guardian,
    helpers: helperKeys,
    payer,
    controller: d.recoveryController,
    verifier: d.webauthnVerifier,
    recovery,
  });
}

