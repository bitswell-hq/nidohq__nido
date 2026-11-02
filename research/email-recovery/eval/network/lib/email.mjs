// The email factor on a network: an enrolled inbox and its commitment, the
// guardian's deployment and pin, recovery emails signed by the provider
// mocks (TEST-ONLY keys in each launch provider's published format), the
// circuit's inputs (`encodeRecoveryEmail`), Node proving with bb.js 0.87.0
// (the prover a browser runs, in the zero-knowledge keccak flavor the
// on-chain verifier takes), and the email approval in the guardian's
// authorization entry (docs/email-recovery/spec.md §4 to §8).
import { createHash, createPublicKey, randomBytes } from 'node:crypto';
import { cpus } from 'node:os';
import { readFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { UltraHonkBackend } from '@aztec/bb.js';
import { Noir } from '@noir-lang/noir_js';
import { PROVIDERS, generateEmail, keyRecordName, launchDns, parseTags } from '@nidohq/email-mocks';
import {
  addressCommitment,
  bigIntToBytes,
  bytesToBigInt,
  encodeRecoveryEmail,
  initHashes,
  noirInputs,
  pinTree,
  publicInputBytes,
  recoverySubject,
} from '@nidohq/email-recovery';
import { Address, Operation, xdr } from '@stellar/stellar-sdk';
import { sc } from './chain.mjs';

const repo = new URL('../../../../../', import.meta.url);
export const CIRCUIT = JSON.parse(readFileSync(new URL('circuits/email-recovery/artifacts/recovery.json', repo), 'utf8'));
export const VK = readFileSync(new URL('contracts/email-verifier/vk/email_recovery.vk', repo));
export const CIRCUIT_ID = createHash('sha256').update(VK).digest();
export const ALLOW_ALL = 31;
export const BODY = 'Approving the recovery of my account.\r\n';

const sha256 = (b) => new Uint8Array(createHash('sha256').update(b).digest());
const u8 = (b) => new Uint8Array(b);

await initHashes();

export function providerOf(domain) {
  const p = Object.values(PROVIDERS).find((x) => x.domains.includes(domain));
  if (!p) throw new Error(`no mock provider sends for ${domain}`);
  return p;
}

/** The provider's aligned signer for `domain` (the one whose `d=` is the From domain). */
export function alignedSigner(domain) {
  return providerOf(domain).signers.find((s) => s.fieldName.toLowerCase() === 'dkim-signature' && s.domain(domain) === domain);
}

/** The RSA modulus DNS publishes for `selector._domainkey.domain`. */
export function publishedModulus(dns, domain, selector) {
  const record = dns.lookup(keyRecordName(selector, domain))?.join('');
  const p = record ? parseTags(record).get('p') : undefined;
  if (!p) throw new Error(`no key at ${selector}._domainkey.${domain}`);
  const der = Buffer.from(p, 'base64');
  const n = createPublicKey({ key: der, format: 'der', type: 'spki' }).export({ format: 'jwk' }).n;
  return BigInt(`0x${Buffer.from(n, 'base64url').toString('hex')}`);
}

/** Each launch domain's current aligned key, as the mock DNS publishes it. */
export function launchKeys() {
  const dns = launchDns();
  return Object.values(PROVIDERS).flatMap((p) =>
    p.domains.map((domain) => {
      const signer = alignedSigner(domain);
      const selector = signer.selector(domain);
      return {
        domain,
        provider: p.id,
        selector,
        record: dns.lookup(keyRecordName(selector, domain)),
        modulus: publishedModulus(dns, domain, selector),
      };
    }),
  );
}

/** An inbox at a launch provider with the wallet's `account_code` (16 random bytes). */
export class Inbox {
  constructor(address, { displayName = 'First Last', accountCode = bytesToBigInt(randomBytes(16)) } = {}) {
    this.address = address;
    this.displayName = displayName;
    this.accountCode = accountCode;
    this.domain = address.slice(address.lastIndexOf('@') + 1).toLowerCase();
    this.provider = providerOf(this.domain).id;
  }

  get commitment() {
    return addressCommitment(this.address, this.accountCode);
  }

  /** An email from this inbox with `subject`, signed as its provider signs (optionally by other signers). */
  send(subject, { signers, displayName, from, body = BODY } = {}) {
    return generateEmail({
      provider: this.provider,
      from: from ?? this.address,
      displayName: displayName ?? this.displayName,
      subject,
      body,
      date: new Date(),
      ...(signers ? { signers } : {}),
    });
  }
}

/** A fresh `rho` (31 random bytes, spec §4.2). */
export const freshRho = () => bytesToBigInt(randomBytes(31));

export function subjectFor(statement, rho) {
  return recoverySubject(sha256(statement), rho);
}

/** The guardian's `GuardianConfig` as its constructor takes it. */
export function guardianConfigScVal(c) {
  return sc.struct({
    account: sc.address(c.account),
    controller: sc.address(c.controller),
    commitment: sc.bytes(bigIntToBytes(c.commitment, 32)),
    registry: sc.address(c.registry),
    key_pin: sc.vec(c.pin ? [sc.struct({ root: sc.bytes(bigIntToBytes(c.pin.root, 32)), valid_until: sc.u64(c.pin.validUntil) })] : []),
    allowed_actions: sc.u32(c.allowedActions ?? ALLOW_ALL),
    verifier: sc.address(c.verifier),
    circuit_id: sc.bytes(CIRCUIT_ID),
  });
}

/** Deploy an email guardian from `deployer` (it pays and authorizes the creation). */
export async function deployGuardian(chain, deployer, wasmHash, config, label) {
  const salt = randomBytes(32);
  const r = await chain.send(
    deployer,
    Operation.createCustomContract({ address: Address.fromString(deployer.publicKey()), wasmHash: Buffer.from(wasmHash, 'hex'), salt, constructorArgs: [guardianConfigScVal(config)] }),
    { label: `deploy guardian ${label}` },
  );
  return Address.fromScVal(r.scVal).toString();
}

/** A pin tree over `keys` ({domain, modulus}) for `accountCode` (spec §7.4). */
export const pinFor = (accountCode, keys) => pinTree(accountCode, keys.map((k) => ({ domain: k.domain, modulus: k.modulus })));

let backend;
function prover() {
  backend ??= new UltraHonkBackend(CIRCUIT.bytecode, { threads: Math.min(cpus().length, 32) });
  return backend;
}

export async function closeProver() {
  await backend?.destroy();
  backend = undefined;
}

/**
 * The circuit's verdict on a witness: `{ ok: true, witness }` or the
 * assertion that refused it. The witness is solved with noir_js against the
 * committed circuit artifact.
 */
export async function solve(witness) {
  try {
    const { witness: w } = await new Noir(CIRCUIT).execute(noirInputs(witness));
    return { ok: true, witness: w };
  } catch (e) {
    return { ok: false, reason: String(e.message).replace(/^Circuit execution failed: /, '') };
  }
}

/** Prove a solved witness with bb.js; the proof is verified locally first, as the wallet's prover does. */
export async function proveWitness(solved) {
  const t0 = performance.now();
  const proof = await prover().generateProof(solved, { keccakZK: true });
  const t1 = performance.now();
  if (!(await prover().verifyProof(proof, { keccakZK: true }))) throw new Error('bb.js did not verify its own proof');
  return {
    proof: u8(proof.proof),
    publicInputs: Buffer.concat(proof.publicInputs.map((v) => Buffer.from(BigInt(v).toString(16).padStart(64, '0'), 'hex'))),
    proveMs: Math.round(t1 - t0),
  };
}

/**
 * An honest approval: `eml` from the enrolled inbox, encoded against the
 * statement, the key and the key path, solved and proved.
 */
export async function approve({ eml, inbox, rho, statement, modulus, keyPath, accountCode = inbox.accountCode }) {
  const t0 = performance.now();
  const encoded = await encodeRecoveryEmail({ eml, accountCode, rho, statement, modulus, keyPath });
  const solved = await solve(encoded.witness);
  const t1 = performance.now();
  if (!solved.ok) throw new Error(`the circuit refused an honest email: ${solved.reason}`);
  const p = await proveWitness(solved.witness);
  return { ...p, witnessMs: Math.round(t1 - t0), encoded, keyRoot: bigIntToBytes(keyPath.root, 32), publicInputsExpected: publicInputBytes(encoded.witness) };
}

/** A random non-negative i64 authorization nonce. */
export function randomNonce() {
  const b = randomBytes(8);
  b[0] &= 0x7f;
  return BigInt(`0x${b.toString('hex')}`);
}

/** `EmailApproval { statement, key_root, proof }` (spec §8.1). */
export const approvalScVal = (a) => sc.struct({ statement: sc.bytes(a.statement), key_root: sc.bytes(a.keyRoot), proof: sc.bytes(a.proof) });

/**
 * The guardian's authorization entry for `fn(digest)` on `controller`, its
 * signature the approval. Anyone can build one from a seen approval.
 */
export function approvalEntry({ guardian, controller, fn = 'submit_guardian', digest, approval, expirationLedger, nonce = randomNonce() }) {
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
      new xdr.SorobanAddressCredentials({
        address: Address.fromString(guardian).toScAddress(),
        nonce: xdr.Int64.fromString(nonce.toString()),
        signatureExpirationLedger: expirationLedger,
        signature: approvalScVal(approval),
      }),
    ),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({ contractAddress: Address.fromString(controller).toScAddress(), functionName: fn, args: [sc.bytes(digest)] }),
      ),
      subInvocations: [],
    }),
  });
}

/** `controller.submit_guardian(account, attempt, domain, guardian)` carrying `entry`. */
export function submitGuardianOp({ controller, account, attemptId, domain, guardian, entry }) {
  return Operation.invokeHostFunction({
    func: xdr.HostFunction.hostFunctionTypeInvokeContract(
      new xdr.InvokeContractArgs({
        contractAddress: Address.fromString(controller).toScAddress(),
        functionName: 'submit_guardian',
        args: [sc.address(account), sc.u64(attemptId), sc.u32(domain), sc.address(guardian)],
      }),
    ),
    auth: entry ? [entry] : [],
  });
}

export { sha256 };
