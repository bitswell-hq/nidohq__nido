// What the evaluation deploys on a local network (`stellar/quickstart
// --local`): Perch's stack and Nido's factory and email contracts as the
// end-to-end test deploys them (`tests/support/emailLocalStack.mjs`), and a
// DKIM key registry governed as the spec proposes (§7.6 "Parameters": five
// members, threshold 3, revocation 2, three DNS attesters, threshold 2, a
// 24-hour grace), into which every launch domain's TEST-ONLY key enters
// through a proposal, three approvals and two attestations that DNS
// publishes it, as a deployment's keys would. On a local network those
// additions stay in their 72-hour timelock for the whole run.
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { Address, Keypair, Operation } from '@stellar/stellar-sdk';
import { imageMeasurement, testImage, testKey } from '@nidohq/email-mocks';
import { keyHash, merkleRoot, registryLeaf } from '@nidohq/email-recovery';
import { deployStack } from '../../../../../tests/support/emailLocalStack.mjs';
import { sc } from './chain.mjs';
import { launchKeys } from './email.mjs';

const repo = new URL('../../../../../', import.meta.url).pathname;
const sha256 = (b) => createHash('sha256').update(b).digest();
/**
 * The email contracts the evaluation deploys: `just build-contracts`'
 * optimized wasm, the bytes testnet runs, unless NIDO_EVAL_EMAIL_WASM names
 * another build's directory.
 */
export const EMAIL_WASM = process.env.NIDO_EVAL_EMAIL_WASM ?? `${repo}target/wasm32v1-none/contract/`;

export const LAUNCH_DOMAINS = ['gmail.com', 'outlook.com', 'hotmail.com', 'icloud.com', 'yahoo.com', 'proton.me', 'protonmail.com', 'fastmail.com', 'gmx.net', 'gmx.de', 'web.de'];
export const REGISTRY = { members: 5, threshold: 3, revokeThreshold: 2, attesters: 3, attestThreshold: 2, graceSeconds: 86_400 };

/** The DNS attester mock (`crates/dns-attestation-mock`), TEST-ONLY attester `index`. */
export class Attester {
  static bin = `${repo}target/debug/dns-attestation-mock`;

  constructor(index) {
    this.index = index;
    // `TestAttester::new(index)`: the Ed25519 seed sha256(label || index).
    const seed = sha256(Buffer.concat([Buffer.from('nido/email-recovery/test-only-attester'), Buffer.of(index)]));
    const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
    this.publicKey = createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32);
  }

  static ensureBuilt() {
    if (!existsSync(Attester.bin)) execFileSync('cargo', ['build', '-q', '-p', 'nido-dns-attestation-mock'], { cwd: repo, stdio: 'inherit' });
  }

  /** A signed observation of `selector._domainkey.domain` (`record` absent: no TXT record), for the proposal's key. */
  observe({ registry, domain, selector, record, keyHashHex, observedAt, resolvers = ['8.8.8.8', '1.1.1.1'] }) {
    const args = ['attest', '--registry', registry, '--domain', domain, '--selector', selector, '--observed-at', String(observedAt), '--attester', String(this.index)];
    for (const s of record ?? []) args.push('--txt', s);
    if (!record) args.push('--absent');
    if (keyHashHex) args.push('--key-hash', keyHashHex);
    for (const r of resolvers) args.push('--resolver', r);
    return JSON.parse(execFileSync(Attester.bin, args, { encoding: 'utf8' }));
  }
}

/** The registry's governance on the network: members' proposals and approvals, attestations, execution. */
export class Registry {
  constructor(chain, address, members, attesters, submitter) {
    Object.assign(this, { chain, address, members, attesters, submitter });
  }

  static configScVal({ members, attesters, graceSeconds = REGISTRY.graceSeconds, domains = LAUNCH_DOMAINS }) {
    return sc.struct({
      attest_threshold: sc.u32(REGISTRY.attestThreshold),
      attesters: sc.vec(attesters.map((a) => sc.bytes(a.publicKey))),
      domains: sc.vec(domains.map((d) => sc.bytes(Buffer.from(d)))),
      grace_seconds: sc.u64(graceSeconds),
      members: sc.vec(members.map((m) => sc.address(m.publicKey()))),
      revoke_threshold: sc.u32(REGISTRY.revokeThreshold),
      threshold: sc.u32(REGISTRY.threshold),
    });
  }

  member(i) {
    return this.members[i];
  }

  async proposeAdd(i, domain, modulus) {
    const n = Buffer.from(modulus.toString(16).padStart(Math.ceil(modulus.toString(16).length / 2) * 2, '0'), 'hex');
    const r = await this.chain.invoke(this.members[i], this.address, 'propose_add', [sc.address(this.members[i].publicKey()), sc.bytes(Buffer.from(domain)), sc.bytes(n)], { label: `registry propose_add ${domain}` });
    return Number(r.value);
  }

  async proposeRevoke(i, domain, keyHashBytes) {
    const r = await this.chain.invoke(this.members[i], this.address, 'propose_revoke', [sc.address(this.members[i].publicKey()), sc.bytes(Buffer.from(domain)), sc.bytes(keyHashBytes)], { label: `registry propose_revoke ${domain}` });
    return Number(r.value);
  }

  approve(i, id) {
    return this.chain.invoke(this.members[i], this.address, 'approve', [sc.address(this.members[i].publicKey()), sc.u32(id)], { label: `registry approve ${id}` });
  }

  async attest(id, attester, obs) {
    return this.chain.invoke(this.submitter, this.address, 'attest', [sc.u32(id), sc.bytes(Buffer.from(obs.attester, 'hex')), sc.bytes(Buffer.from(obs.attestation, 'hex')), sc.bytes(Buffer.from(obs.signature, 'hex'))], { label: `registry attest ${id} by ${attester.index}` });
  }

  execute(id, source = this.submitter) {
    return this.chain.invoke(source, this.address, 'execute', [sc.u32(id)], { label: `registry execute ${id}` });
  }

  proposal(id) {
    return this.chain.read(this.address, 'proposal', [sc.u32(id)]);
  }

  eligibleAt(id) {
    return this.chain.read(this.address, 'eligible_at', [sc.u32(id)]);
  }

  isAcceptedRoot(root) {
    return this.chain.read(this.address, 'is_accepted_root', [sc.bytes(root)]);
  }

  /**
   * The path a proof for `key` ({domain, modulus}) is made against: the
   * key's leaf index (`leaf`), the siblings the registry stores for it, and
   * the root they reach, which must be the registry's current root.
   */
  async keyPath(key) {
    const kh = keyHash(key.modulus);
    const rec = await this.chain.read(this.address, 'leaf', [sc.bytes(Buffer.from(key.domain)), sc.bytes(Buffer.from(kh.toString(16).padStart(64, '0'), 'hex'))]);
    if (!rec?.present) throw new Error(`${key.domain}'s key is not in the registry's tree`);
    const index = Number(rec.index);
    const siblings = (await this.chain.read(this.address, 'siblings', [sc.u32(index)])).map((b) => BigInt(`0x${Buffer.from(b).toString('hex')}`));
    const root = merkleRoot(registryLeaf(key.domain, kh), index, siblings);
    const current = BigInt(`0x${Buffer.from(await this.chain.read(this.address, 'root')).toString('hex')}`);
    if (root !== current) throw new Error(`${key.domain}'s path does not reach the registry's root`);
    return { root, index, siblings };
  }
}

/** The ledger's close time, for an attestation's `observed_at`. */
export async function closeTime(chain) {
  return Number((await chain.call('getLatestLedger')).closeTime);
}

/** Propose, approve (threshold) and attest (live in DNS, threshold) one addition; returns its id. */
export async function admitThroughTimelock(reg, key) {
  const id = await reg.proposeAdd(0, key.domain, key.modulus);
  for (let m = 1; m < REGISTRY.threshold; m++) await reg.approve(m, id);
  const at = await closeTime(reg.chain);
  for (const a of reg.attesters.slice(0, REGISTRY.attestThreshold)) {
    await reg.attest(id, a, a.observe({ registry: reg.address, domain: key.domain, selector: key.selector, record: key.record, observedAt: at }));
  }
  return id;
}

/** Deploy everything on the local network at `base`. */
export async function deployLocal(chain, base) {
  Attester.ensureBuilt();
  const measurement = Buffer.from(imageMeasurement(testImage('nido-alert-vault-v1'))).toString('hex');
  const stack = await deployStack({ base, imageMeasurement: measurement, gmailModulus: testKey('gmail').modulus, emailWasm: EMAIL_WASM });
  const members = [];
  for (let i = 0; i < REGISTRY.members; i++) members.push(await chain.funded(Keypair.random()));
  const attesters = [0, 1, 2].map((i) => new Attester(i));
  const operator = await chain.funded(Keypair.random());
  const created = await chain.send(
    operator,
    Operation.createCustomContract({
      address: Address.fromString(operator.publicKey()),
      wasmHash: await uploadWasm(chain, operator, `${EMAIL_WASM}nido_dkim_registry.wasm`),
      salt: Buffer.from(sha256(`nido-eval/email-attacks/registry/${Date.now()}`)),
      constructorArgs: [Registry.configScVal({ members, attesters })],
    }),
    { label: 'deploy registry' },
  );
  const registry = new Registry(chain, Address.fromScVal(created.scVal).toString(), members, attesters, operator);
  const proposals = {};
  for (const key of launchKeys().filter((k) => LAUNCH_DOMAINS.includes(k.domain))) proposals[key.domain] = await admitThroughTimelock(registry, key);
  return { ...stack, operator, registry, proposals, measurement };
}

export async function uploadWasm(chain, source, file) {
  const wasm = readFileSync(file);
  await chain.send(source, Operation.uploadContractWasm({ wasm }), { label: `upload ${file.split('/').pop()}` });
  return sha256(wasm);
}


/** The deployed stack as JSON (TEST-ONLY local keys included), to reuse a running network. */
export function stackJson(s) {
  return {
    base: s.base,
    deployment: s.deployment,
    email: s.email,
    measurement: s.measurement,
    operator: s.operator.secret(),
    registry: { address: s.registry.address, members: s.registry.members.map((m) => m.secret()) },
    proposals: s.proposals,
  };
}

export function stackFromJson(chain, j) {
  const members = j.registry.members.map((m) => Keypair.fromSecret(m));
  const operator = Keypair.fromSecret(j.operator);
  return { ...j, operator, registry: new Registry(chain, j.registry.address, members, [0, 1, 2].map((i) => new Attester(i)), operator) };
}
