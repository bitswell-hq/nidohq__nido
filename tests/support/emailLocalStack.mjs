#!/usr/bin/env node
// Deploys the contracts the email recovery end-to-end test needs onto a
// local network (`stellar/quickstart --local`) and writes their addresses to
// target/email-e2e/stack.json:
//
// - Perch's stack as a Nido account uses it: the registry chain of
//   evaluation/fixtures/local-registry.path (each link an instance of
//   evaluation/fixtures/stateless-deployer: the root from a fixed deployer
//   key and salt, then one named deploy per path segment), Perch's tier-0
//   contracts deployed through its last registry (so the account finds them
//   where perch-registry-resolve looks: that registry and sha256(wasm)), the
//   Perch account evaluation/scripts/local-stack.sh built with that path, and
//   Nido's factory pinning that account;
// - Nido's email contracts: the verifier, the DKIM key registry (one
//   TEST-ONLY member and attester), the guardian's wasm (each enrollment
//   deploys its own instance), and, standing in for the enclave-image
//   registry, the TEST-ONLY allowlist of tests/e2e/local/fixtures/image-allowlist;
// - one key in the registry: the Gmail mock's TEST-ONLY key, proposed and
//   approved, waiting in its timelock (the pin covers that window, spec §7.4).
//
//   node tests/support/emailLocalStack.mjs [--rpc http://127.0.0.1:8000]
//
// Needs `just perch-infra`, evaluation/scripts/local-stack.sh <registry>,
// and the email contracts built into target/email-e2e/wasm
// (scripts/email-recovery-e2e.sh does all of it).
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { Address, Keypair, Operation, StrKey, TransactionBuilder, hash, nativeToScVal, rpc, scValToNative, xdr } from '@stellar/stellar-sdk';

export const PASSPHRASE = 'Standalone Network ; February 2017';
const repo = new URL('../../', import.meta.url).pathname;
const sha256 = (b) => createHash('sha256').update(b).digest();

/** The keys the stack uses, all derived from fixed labels (TEST-ONLY). */
export const seeded = (label) => Keypair.fromRawEd25519Seed(sha256(label));
export const DEPLOYER = seeded('nido-eval/deployer');
export const REGISTRY_MEMBER = seeded('nido-email-e2e/registry-member');
export const ATTESTER = seeded('nido-email-e2e/dns-attester');

/** The local registry path's fields (evaluation/fixtures/local-registry.path). */
function registryPath() {
  const text = readFileSync(repo + 'evaluation/fixtures/local-registry.path', 'utf8');
  const field = (key) => {
    const line = text.split('\n').find((l) => !l.trimStart().startsWith('#') && l.startsWith(key + ' '));
    if (!line) throw new Error(`local-registry.path has no ${key} line`);
    return line.slice(key.length + 1).trim();
  };
  return {
    rootDeployer: field('root-deployer'),
    rootSalt: sha256(field('root-salt')),
    segments: field('path').replace(/^\/+|\/+$/g, '').split('/').filter(Boolean),
  };
}

/** The contract `deployer` creates with `salt` on the local network. */
function contractId(deployer, salt) {
  const preimage = xdr.HashIdPreimage.envelopeTypeContractId(
    new xdr.HashIdPreimageContractId({
      networkId: hash(Buffer.from(PASSPHRASE)),
      contractIdPreimage: xdr.ContractIdPreimage.contractIdPreimageFromAddress(
        new xdr.ContractIdPreimageFromAddress({ address: Address.fromString(deployer).toScAddress(), salt }),
      ),
    }),
  );
  return StrKey.encodeContract(hash(preimage.toXDR()));
}

/** Every registry on the local path, root first; the last deploys the infra. */
export function registryChain() {
  const path = registryPath();
  const chain = [contractId(path.rootDeployer, path.rootSalt)];
  for (const name of path.segments) chain.push(contractId(chain.at(-1), sha256(name)));
  return chain;
}

const PERCH = repo + 'target/wasm32v1-none/contract/';
const LOCAL = repo + 'target/eval-local/wasm/';
const EMAIL = repo + 'target/email-e2e/wasm/';

export async function deployStack({ base = 'http://127.0.0.1:8000', imageMeasurement, gmailModulus, emailWasm = EMAIL }) {
  const server = new rpc.Server(`${base}/rpc`, { allowHttp: true });
  const fund = async (kp) => {
    for (let attempt = 1; ; attempt++) {
      const r = await fetch(`${base}/friendbot?addr=${kp.publicKey()}`);
      if (r.ok || (await r.text()).includes('createAccountAlreadyExist')) return;
      // Friendbot answers 502 while the network is still starting.
      if (r.status < 500 || attempt === 20) throw new Error(`friendbot: ${r.status}`);
      await new Promise((ok) => setTimeout(ok, 3_000));
    }
  };
  await fund(DEPLOYER);
  await fund(REGISTRY_MEMBER);

  async function send(signer, op) {
    const tx = new TransactionBuilder(await server.getAccount(signer.publicKey()), { fee: '10000000', networkPassphrase: PASSPHRASE })
      .addOperation(op)
      .setTimeout(120)
      .build();
    const prepared = await server.prepareTransaction(tx);
    prepared.sign(signer);
    const sent = await server.sendTransaction(prepared);
    if (sent.status === 'ERROR') throw new Error(`rejected: ${sent.errorResult?.toXDR('base64')}`);
    const done = await server.pollTransaction(sent.hash, { attempts: 180 });
    if (done.status !== 'SUCCESS') throw new Error(`${done.status}: ${sent.hash}`);
    return done.returnValue;
  }
  const upload = async (file) => {
    const wasm = readFileSync(file);
    await send(DEPLOYER, Operation.uploadContractWasm({ wasm }));
    return sha256(wasm);
  };
  const create = async (wasmHash, salt, args = []) =>
    Address.fromScVal(
      await send(DEPLOYER, Operation.createCustomContract({ address: Address.fromString(DEPLOYER.publicKey()), wasmHash, salt, constructorArgs: args })),
    ).toString();
  const invoke = (signer, contract, fn, args) =>
    send(signer, Operation.invokeContractFunction({ contract, function: fn, args }));

  // The registry chain, whose last link the local account looks in for its
  // tier-0 contracts.
  const chain = registryChain();
  const built = JSON.parse(readFileSync(repo + 'target/eval-local/build.json', 'utf8')).registry;
  if (chain.at(-1) !== built) throw new Error(`the registry path derives ${chain.at(-1)}, the account was built for ${built}`);
  const { rootDeployer, rootSalt, segments } = registryPath();
  if (rootDeployer !== DEPLOYER.publicKey()) throw new Error(`the registry root deployer is ${rootDeployer}, not the deployer key`);
  const registryWasm = await upload(EMAIL + 'nido_eval_stateless_deployer.wasm');
  const root = await create(registryWasm, rootSalt);
  if (root !== chain[0]) throw new Error(`registry root at ${root}, the path derives ${chain[0]}`);
  for (const [i, name] of segments.entries()) {
    const at = Address.fromScVal(
      await invoke(DEPLOYER, chain[i], 'deploy_named', [xdr.ScVal.scvBytes(registryWasm), xdr.ScVal.scvBytes(Buffer.from(name))]),
    ).toString();
    if (at !== chain[i + 1]) throw new Error(`registry ${name} at ${at}, the path derives ${chain[i + 1]}`);
  }
  const stateless = chain.at(-1);
  const viaDeployer = async (file) =>
    Address.fromScVal(await invoke(DEPLOYER, stateless, 'deploy', [xdr.ScVal.scvBytes(await upload(file))])).toString();
  const perch = {};
  for (const name of ['perch_doc_compiler', 'perch_interpreter', 'perch_spending_limit', 'perch_webauthn_verifier', 'perch_recovery', 'perch_zk_pool', 'perch_zk_adapter']) {
    perch[name] = await viaDeployer(PERCH + `${name}.wasm`);
  }
  const accountHash = await upload(LOCAL + 'perch_account.wasm');
  // Admin, the pinned WebAuthn verifier, no manager.
  const factory = await create(await upload(LOCAL + 'nido_factory.wasm'), Buffer.alloc(32, 1), [
    Address.fromString(DEPLOYER.publicKey()).toScVal(),
    Address.fromString(perch.perch_webauthn_verifier).toScVal(),
    xdr.ScVal.scvVoid(),
  ]);
  const pinned = Buffer.from(scValToNative(await invoke(DEPLOYER, factory, 'account_wasm_hash', [])));
  if (!pinned.equals(accountHash)) throw new Error(`the factory pins account ${pinned.toString('hex')}, not the uploaded ${accountHash.toString('hex')}`);

  // Nido's email contracts.
  const verifier = await create(await upload(emailWasm + 'nido_email_verifier.wasm'), Buffer.alloc(32, 2));
  const guardianWasmHash = await upload(emailWasm + 'nido_email_guardian.wasm');
  const domains = ['gmail.com', 'outlook.com', 'hotmail.com', 'icloud.com', 'yahoo.com', 'proton.me', 'protonmail.com', 'fastmail.com', 'gmx.net', 'gmx.de', 'web.de'];
  const config = xdr.ScVal.scvMap(
    [
      ['attest_threshold', xdr.ScVal.scvU32(1)],
      ['attesters', xdr.ScVal.scvVec([xdr.ScVal.scvBytes(ATTESTER.rawPublicKey())])],
      ['domains', xdr.ScVal.scvVec(domains.map((d) => xdr.ScVal.scvBytes(Buffer.from(d))))],
      ['grace_seconds', xdr.ScVal.scvU64(new xdr.Uint64(86_400n))],
      ['members', xdr.ScVal.scvVec([Address.fromString(REGISTRY_MEMBER.publicKey()).toScVal()])],
      ['revoke_threshold', xdr.ScVal.scvU32(1)],
      ['threshold', xdr.ScVal.scvU32(1)],
    ].map(([k, v]) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(k), val: v })),
  );
  const registry = await create(await upload(emailWasm + 'nido_dkim_registry.wasm'), Buffer.alloc(32, 3), [config]);
  const imageAllowlist = await create(await upload(EMAIL + 'nido_e2e_image_allowlist.wasm'), Buffer.alloc(32, 4), [
    xdr.ScVal.scvBytes(Buffer.from(imageMeasurement, 'hex')),
  ]);
  const modulus = Buffer.from(gmailModulus.toString(16).padStart(512, '0'), 'hex');
  const proposal = scValToNative(
    await invoke(REGISTRY_MEMBER, registry, 'propose_add', [
      Address.fromString(REGISTRY_MEMBER.publicKey()).toScVal(),
      xdr.ScVal.scvBytes(Buffer.from('gmail.com')),
      xdr.ScVal.scvBytes(modulus),
    ]),
  );

  const deployment = {
    network: PASSPHRASE,
    factory,
    webauthnVerifier: perch.perch_webauthn_verifier,
    statelessRegistry: stateless,
    docCompiler: perch.perch_doc_compiler,
    interpreter: perch.perch_interpreter,
    spendingLimit: perch.perch_spending_limit,
    recoveryController: perch.perch_recovery,
    zkPool: perch.perch_zk_pool,
    zkAdapter: perch.perch_zk_adapter,
    circuitId: JSON.parse(readFileSync(repo + 'vendor/perch/deployments/testnet.json', 'utf8')).zk.circuit_id,
    treeDepth: 32,
    accountWasmHash: accountHash.toString('hex'),
  };
  const email = {
    guardianWasmHash: guardianWasmHash.toString('hex'),
    registry,
    verifier,
    circuitId: createHash('sha256').update(readFileSync(repo + 'contracts/email-verifier/vk/email_recovery.vk')).digest('hex'),
    enclaveImageRegistry: imageAllowlist,
  };
  return { base, deployment, email, gmailProposal: proposal, deployer: DEPLOYER.publicKey() };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { values } = parseArgs({ options: { rpc: { type: 'string' } } });
  const mocks = await import('@nidohq/email-mocks');
  const measurement = Buffer.from(mocks.imageMeasurement(mocks.testImage('nido-alert-vault-v1'))).toString('hex');
  const stack = await deployStack({ base: values.rpc, imageMeasurement: measurement, gmailModulus: mocks.testKey('gmail').modulus });
  mkdirSync(repo + 'target/email-e2e', { recursive: true });
  writeFileSync(repo + 'target/email-e2e/stack.json', JSON.stringify({ ...stack, imageMeasurement: measurement }, null, 2) + '\n');
  console.log(JSON.stringify(stack, null, 2));
}

export { StrKey, hash, nativeToScVal };
